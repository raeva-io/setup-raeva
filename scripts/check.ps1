# `check.ps1 scan` runs the frozen check and the optional vulnerability scan.
# `check.ps1 gate` runs after the SARIF upload and fails the job on findings,
# so the upload happens before the job fails. The pull request lock diff and
# the relock need Linux or macOS.
param([string]$Mode = 'scan')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$raeva = if ($env:RAEVA_BIN) { $env:RAEVA_BIN } else { 'raeva' }
$workdir = if ($env:INPUT_WORKING_DIRECTORY) { $env:INPUT_WORKING_DIRECTORY } else { '.' }
# The working directory as a repository path, empty for the root.
$rel = $workdir -replace '\\', '/'
if ($rel.StartsWith('./')) { $rel = $rel.Substring(2) }
$rel = $rel -replace '(?<=.)/+$', ''
if ($rel -eq '.') { $rel = '' }
$lockPath = if ($rel) { "$rel/raeva.lock" } else { 'raeva.lock' }
$tmp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
# API requests use the tokens; raeva never sees them.
$uploadToken = "$env:UPLOAD_TOKEN"
$token = "$env:GH_TOKEN"
$checkMode = if ($env:INPUT_CHECK_MODE) { $env:INPUT_CHECK_MODE } else { 'blocking' }
$baseLock = ''
$baseMissing = $false
$committed = ''
Remove-Item Env:GH_TOKEN, Env:UPLOAD_TOKEN -ErrorAction SilentlyContinue
$api = if ($env:GITHUB_API_URL) { $env:GITHUB_API_URL } else { 'https://api.github.com' }

function Out([string]$Name, [string]$Value) {
    if ($env:GITHUB_OUTPUT) {
        if ($Value.Contains("`n") -or $Value.Contains("`r")) {
            $delimiter = [guid]::NewGuid().ToString('N')
            Add-Content -Path $env:GITHUB_OUTPUT -Value "$Name<<$delimiter`n$Value`n$delimiter" -Encoding utf8
        } else {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "$Name=$Value" -Encoding utf8
        }
    }
}
function Summary([string]$Text) {
    if ($env:GITHUB_STEP_SUMMARY) { Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value $Text -Encoding utf8 }
}
# A directory per invocation, so two roots checked in one job keep their own
# SARIF logs until the upload step reads them.
$runDir = $null
if ($Mode -ne 'gate') {
    $runDir = Join-Path $tmp ('setup-raeva.' + [guid]::NewGuid().ToString('N').Substring(0, 12))
    New-Item -ItemType Directory -Path $runDir | Out-Null
}

# The Maven options of every command that reads the configuration: -s, -P,
# and one -D per line of the properties input. The --name=value forms keep a
# value that starts with - or ! one argument.
$maven = @()
if ($env:INPUT_SETTINGS) { $maven += "--settings=$env:INPUT_SETTINGS" }
if ($env:INPUT_PROFILES) { $maven += "--activate-profiles=$env:INPUT_PROFILES" }
foreach ($line in "$env:INPUT_PROPERTIES" -split "`n") {
    $property = $line.Trim()
    if ($property) { $maven += "--define=$property" }
}

# raeva's output quotes POM and repository data, so the runner reads no
# workflow commands in it: they are off until a marker it cannot guess.
function Write-Raw([string[]]$Paths) {
    $marker = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(16))
    Write-Host "::stop-commands::$marker"
    foreach ($path in $Paths) {
        if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path | Write-Host }
    }
    Write-Host "::$marker::"
}

# Workflow commands need %, CR, and LF escaped in messages, and also : and ,
# in properties such as title.
function EscMsg([string]$s) { $s.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A') }
function EscProp([string]$s) { (EscMsg $s).Replace(':', '%3A').Replace(',', '%2C') }

# Runs raeva with stdout and stderr in files, so the bytes of a SARIF log are
# kept as raeva wrote them, and returns the exit code. ArgumentList quotes
# each argument for the Windows command line, a trailing backslash included.
function Invoke-Raeva([string[]]$Arguments, [string]$StdOut, [string]$StdErr) {
    $psi = [Diagnostics.ProcessStartInfo]::new($raeva)
    foreach ($argument in $Arguments) { $psi.ArgumentList.Add($argument) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $out = [IO.File]::Create($StdOut)
    $err = [IO.File]::Create($StdErr)
    try {
        $p = [Diagnostics.Process]::Start($psi)
        $copies = @($p.StandardOutput.BaseStream.CopyToAsync($out), $p.StandardError.BaseStream.CopyToAsync($err))
        $p.WaitForExit()
        [Threading.Tasks.Task]::WaitAll($copies)
        return $p.ExitCode
    } finally {
        $out.Dispose()
        $err.Dispose()
    }
}

# Used only when raeva gives no hints of its own.
function Hint([string]$Code) {
    switch ($Code) {
        'LOCKFILE_MISMATCH' { "Run 'raeva sync' and commit raeva.lock." }
        'PLATFORM_MISSING'  { 'Lock this platform too: raeva sync --platforms <platform>, then commit raeva.lock.' }
        'LOCKFILE_MISSING'  { "Run 'raeva sync' at the project root and commit raeva.lock." }
        'LOCKFILE_INVALID'  { "Run 'raeva sync' to write raeva.lock again, then commit it." }
        'AUTH'              { 'Give the job the repository credentials: a settings.xml <server> that reads them with ${env.NAME}.' }
        ''                  { 'raeva stopped without an error report, as after a crash, a kill, or a binary that cannot run here. The step log has its full output.' }
        default             { 'See the error codes in docs/json-output.md of raeva.' }
    }
}

# Text from raeva quotes POM and repository data, so it goes into the
# summary inside a fence it cannot close.
function Fenced([string]$Text) {
    $fence = '````'
    Summary ("`n" + $fence + "text`n" + $Text.Replace($fence, "''''") + "`n" + $fence)
}

# One annotation per warning code, as raeva's own text summary prints them:
# the first warning with its context, and how many more share the code.
# Only the job summary lists HTTP_REPO_BLOCKED, for an http: repository that
# some POM declares, and the two codes raeva's text summary omits too:
# TRANSITIVE_REPO_DROPPED and WEAK_HASH_FALLBACK.
function Write-Warnings($Envelope, [string]$Command) {
    if (-not $Envelope -or -not $Envelope.PSObject.Properties['data'] -or -not $Envelope.data -or
        -not $Envelope.data.PSObject.Properties['warnings']) { return }
    $all = @($Envelope.data.warnings)
    if ($all.Count -eq 0) { return }
    $lines = @()
    foreach ($group in ($all | Group-Object -Property code -CaseSensitive | Sort-Object -Property Name -CaseSensitive)) {
        $first = $group.Group[0]
        $text = "$($first.message)"
        if ($first.context -and $first.context -is [psobject]) {
            $pairs = @($first.context.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" })
            if ($pairs.Count -gt 0) { $text += " ($($pairs -join ', '))" }
        }
        # One line each, as a code and its text are one line in the summary.
        $text = $text -replace '[\r\n\t]+', ' '
        if ($group.Count -gt 1) { $text += "; and $($group.Count - 1) more (raeva --json $Command lists them)" }
        if ($group.Name -cnotin @('HTTP_REPO_BLOCKED', 'TRANSITIVE_REPO_DROPPED', 'WEAK_HASH_FALLBACK')) {
            Write-Output "::warning title=$(EscProp "raeva $($group.Name)")::$(EscMsg $text)"
        }
        $lines += "$($group.Name) $text"
    }
    Summary "`nWarnings:"
    Fenced ($lines -join "`n")
}

# Read schema targets as text, including both sides of a merge conflict.
# --platforms takes OS/architecture pairs; sync reads the JDKs itself.
function Get-LockPlatforms([string]$Lock) {
    if (-not (Test-Path -LiteralPath $Lock)) { return '' }
    $seen = [Collections.Generic.List[string]]::new()
    $targets = $false
    foreach ($line in [IO.File]::ReadAllLines($Lock)) {
        if ($line -cmatch '^\s*targets\s*=\s*\[') { $targets = $true }
        if ($targets -or $line -cmatch '^\s*target\s*=') {
            foreach ($match in [regex]::Matches($line, '"([A-Za-z0-9_]+-[A-Za-z0-9_]+)(?:@[A-Za-z0-9._+-]{1,32})?"')) {
                $platform = $match.Groups[1].Value
                if (-not $seen.Contains($platform)) { $seen.Add($platform) }
            }
        }
        if ($line.Contains(']')) { $targets = $false }
    }
    $seen -join ','
}

# The command a developer runs to write the lock again, with this job's
# Maven options. A settings file outside the repository, such as one the job
# writes to RUNNER_TEMP, is left out, and the summary says so.
function Get-SyncCommand {
    $words = @('raeva')
    if ($rel) { $words += @('-C', $workdir) }
    $words += 'sync'
    foreach ($arg in $maven) {
        if ($arg.StartsWith('--settings=') -and [IO.Path]::IsPathRooted($arg.Substring(11))) { continue }
        if ($arg.StartsWith('--define=')) { $arg = '--define=' + ($arg.Substring(9) -split '=', 2)[0] + '=<value>' }
        $words += $arg
    }
    if ($env:INPUT_PLATFORMS) { $words += @('--platforms', $env:INPUT_PLATFORMS) }
    # PowerShell quoting: a single-quoted word doubles its apostrophes.
    ($words | ForEach-Object { if ($_ -cmatch '^[A-Za-z0-9_./=,:+@-]+$') { $_ } else { "'" + $_.Replace("'", "''") + "'" } }) -join ' '
}

# The name of an artifact with one lock diff of this working directory.
# Jobs whose name matches write the same diff, so a later upload may replace
# an earlier one; the hash keeps other roots, options, and for the proposed
# lock JDKs apart, as services/api and services-api.
function Get-DiffArtifact([string]$Prefix, [string]$More) {
    $key = $rel
    foreach ($arg in $maven) { $key += "`n$arg" }
    $key += "`n$env:INPUT_PLATFORMS`n$More"
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($key))).Substring(0, 8).ToLowerInvariant()
    if ($rel) { "$Prefix-$($rel -replace '[^A-Za-z0-9._-]', '-')-$hash" } else { "$Prefix-$hash" }
}

# For report-only checks or a bot's stale lock, writes the lock diff that
# `raeva sync` would commit. raeva writes it in place, where a parent POM or
# file: repository outside the working directory resolves as it does for a
# developer. The committed lock goes back when this script ends, so later
# steps see it; a report-only scan in this step reads the proposed lock.
function Restore-Lock {
    if ($script:committed) { Move-Item -LiteralPath $script:committed -Destination (Join-Path $workdir 'raeva.lock') -Force }
}
function Invoke-Proposed {
    if ($checkMode -ne 'report-only') {
        if (-not ("$env:GITHUB_EVENT_NAME".StartsWith('pull_request')) -or -not $env:GITHUB_EVENT_PATH -or
            -not (Test-Path -LiteralPath $env:GITHUB_EVENT_PATH)) { return }
        $type = ''
        try { $type = "$((Get-Content -LiteralPath $env:GITHUB_EVENT_PATH -Raw | ConvertFrom-Json).pull_request.user.type)" } catch { }
        if ($type -cne 'Bot') { return }
    }
    $lock = Join-Path $workdir 'raeva.lock'
    if (-not (Test-Path -LiteralPath $lock)) { return }
    Out 'fix-command' (Get-SyncCommand)
    Copy-Item -LiteralPath $lock -Destination (Join-Path $runDir 'committed.lock')
    $script:committed = Join-Path $runDir 'committed.lock'
    $platforms = if ($env:INPUT_PLATFORMS) { $env:INPUT_PLATFORMS } else { Get-LockPlatforms $committed }
    $arguments = @('-q', '-C', $workdir, 'sync') + $maven
    if ($platforms) { $arguments += @('--platforms', $platforms) }
    $syncOut = Join-Path $runDir 'proposed.out'
    $syncErr = Join-Path $runDir 'proposed.err'
    Write-Host '::group::raeva sync, for the proposed lock'
    $code = Invoke-Raeva $arguments $syncOut $syncErr
    Write-Raw @($syncOut, $syncErr)
    Write-Host '::endgroup::'
    Summary "`n### Proposed raeva.lock, not committed"
    if ($code -ne 0) {
        Summary "`n``raeva sync`` could not write a proposed lock (exit $code); see the step log. The check cannot complete."
        if ($checkMode -eq 'report-only') { exit $code }
    } else {
        Summary "`nThis is the lock ``raeva sync`` writes for this checkout. It is not committed; later steps use the committed lock. To fix it, run this on the branch and commit raeva.lock:"
        Fenced (Get-SyncCommand)
        if ($env:INPUT_PROPERTIES) {
            Summary ("`n" + 'Replace each `<value>` with the Maven property value used by this job. Property values are omitted from this command.')
        }
        if ($env:INPUT_SETTINGS -and [IO.Path]::IsPathRooted($env:INPUT_SETTINGS)) {
            $settings = $env:INPUT_SETTINGS.Replace('`', '')
            Summary "`nThis job reads the settings file ``$settings``; run it with a settings file that has the same repositories and profiles."
        }
        $diffOut = Join-Path $runDir 'diff.out'
        $diffErr = Join-Path $runDir 'diff.err'
        $diffCode = Invoke-Raeva @('-q', '-C', $workdir, 'lock', 'diff', $committed, $lock) $diffOut $diffErr
        if ($diffCode -ne 0) { Summary "`n``raeva lock diff`` could not compare the locks (exit $diffCode)." }
        $text = (([IO.File]::ReadAllText($diffOut) + [IO.File]::ReadAllText($diffErr)) -replace "`r", '').TrimEnd("`n")
        $artifactDir = Join-Path $runDir 'proposed-diff'
        New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $artifactDir 'proposed.diff'), "$text`n", [Text.UTF8Encoding]::new($false))
        $artifact = Get-DiffArtifact 'raeva-lock-proposed' "$env:JAVA_HOME"
        Out 'proposed-diff' (Join-Path $artifactDir 'proposed.diff')
        Out 'proposed-dir' $artifactDir
        Out 'proposed-artifact' $artifact
        $lines = $text -split "`n"
        if ($lines.Count -gt 200) {
            $text = (($lines | Select-Object -First 200) -join "`n") + "`n... $($lines.Count - 200) more lines; the full diff is proposed.diff in the $artifact artifact"
        }
        Fenced $text
        if ($diffCode -ne 0 -and $checkMode -eq 'report-only') { exit $diffCode }
    }
}

function Invoke-Frozen {
    $arguments = @('--json', '-C', $workdir, 'sync', '--frozen') + $maven
    if ($env:INPUT_PLATFORMS) { $arguments += @('--platforms', $env:INPUT_PLATFORMS) }
    $json = Join-Path $runDir 'frozen.json'
    $err = Join-Path $runDir 'frozen.err'
    Write-Output "Checking raeva.lock with raeva sync --frozen; its output follows when it exits."
    $code = Invoke-Raeva $arguments $json $err
    Write-Raw @($err)
    Out 'frozen-exit-code' $code
    $envelope = $null
    try { $envelope = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json } catch { }
    if ($code -eq 0) {
        $parts = @()
        $data = if ($envelope -and $envelope.PSObject.Properties['data']) { $envelope.data } else { $null }
        $field = { param($name) if ($data -and $data.PSObject.Properties[$name]) { $data.$name } else { $null } }
        $isNumber = { param($value) $value -is [int] -or $value -is [long] -or $value -is [double] -or $value -is [decimal] -or $value -is [bigint] }
        $resolved = & $field 'resolved'
        if (& $isNumber $resolved) { $parts += "$resolved dependencies" }
        $platforms = @(& $field 'platforms' | Where-Object { $_ -is [string] -and $_ -cmatch '\A[A-Za-z0-9_.@+-]+\z' })
        if ($platforms.Count -gt 0) { $parts += $platforms -join ', ' }
        $ms = & $field 'duration_ms'
        if (& $isNumber $ms) {
            $tenths = [math]::Floor(([double]$ms + 50) / 100)
            $parts += "$([math]::Floor($tenths / 10)).$($tenths % 10) s"
        }
        $details = if ($parts.Count -gt 0) { " ($($parts -join '; '))" } else { '' }
        Write-Output "raeva.lock is current$details"
        Summary "### raeva`n`n``raeva.lock`` is current$details."
        Write-Warnings $envelope 'sync --frozen'
        return
    }
    $ecode = if ($envelope -and $envelope.PSObject.Properties['code']) { "$($envelope.code)" } else { '' }
    $message = if ($envelope -and $envelope.PSObject.Properties['error']) { "$($envelope.error)" } else { '' }
    if (-not $message) {
        $message = [IO.File]::ReadAllText($err).Replace("`r", '').TrimEnd("`n")
        if (-not $message) { $message = [IO.File]::ReadAllText($json).Replace("`r", '').TrimEnd("`n") }
        $message = if ($message) {
            "raeva wrote no JSON error. The last lines it printed:`n" + ((@($message -split "`n") | Select-Object -Last 20) -join "`n")
        } else { 'raeva wrote no JSON error and no output.' }
    }
    $hints = if ($envelope -and $envelope.PSObject.Properties['hints'] -and @($envelope.hints).Count -gt 0) { @($envelope.hints) -join "`n" } else { Hint $ecode }
    if ($ecode -ceq 'LOCKFILE_INVALID' -and $message -like '*schema version*') {
        $hints = "If a newer raeva wrote raeva.lock, raise the ``version`` input to that release.`n$hints"
    }
    $title = "raeva sync --frozen (exit $code$(if ($ecode) { ", $ecode" }))"
    # Report-only fails neither on lock changes nor on a missing lock, so a
    # project can add the workflow before it commits raeva.lock.
    $soft = $checkMode -eq 'report-only' -and ($code -eq 7 -or $ecode -ceq 'LOCKFILE_MISSING')
    $level = if ($soft) { 'warning' } else { 'error' }
    Write-Output "::$level file=$(EscProp $lockPath),title=$(EscProp $title)::$(EscMsg "$message`n$hints")"
    Summary "### raeva`n`n``raeva sync --frozen`` failed with exit $code ($(if ($ecode) { $ecode } else { 'no code' }))."
    Fenced "$message`n`n$hints"
    Write-Warnings $envelope 'sync --frozen'
    if ($soft -and $code -ne 7) {
        Summary "`nReport-only mode: a missing lock does not fail this job."
        return
    }
    if ($code -eq 7) {
        if ($checkMode -eq 'report-only') {
            Summary "`nReport-only mode: lock changes do not fail this job."
            Invoke-Proposed
            return
        }
        try { Invoke-Proposed } catch { Write-Host "No proposed lock: $_" }
    }
    exit $code
}

# The code scanning category: the input, or one per working directory so
# the alerts of two Maven roots do not replace each other.
function Get-SarifCategory {
    if ($env:INPUT_SARIF_CATEGORY) { return $env:INPUT_SARIF_CATEGORY }
    if ($rel) { "raeva/$rel" } else { 'raeva' }
}

# An upload that code scanning refuses only adds an error annotation, so ask
# first, with the token the upload uses. A 403 that says code scanning is not
# enabled, as for a private repository without GitHub Code Security, skips
# the upload, and so does one that says the job token may not read alerts:
# security-events: write would include read. Any other answer leaves the
# upload to try.
function Test-SarifUpload {
    if ($env:INPUT_SARIF_UPLOAD -ne 'true' -or -not $env:GITHUB_REPOSITORY) { return }
    $status = 0
    $why = ''
    try {
        $response = Invoke-WebRequest -UseBasicParsing -SkipHttpErrorCheck -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 60 -Uri "$api/repos/$env:GITHUB_REPOSITORY/code-scanning/alerts?per_page=1" `
            -Headers @{ Authorization = "Bearer $uploadToken"; Accept = 'application/vnd.github+json' }
        $status = [int]$response.StatusCode
        if ($status -eq 403) { try { $why = "$(($response.Content | ConvertFrom-Json).message)" } catch { } }
    } catch { }
    $cause = if ($status -ne 403) { '' }
        elseif ($why -match 'must be enabled|not enabled') { 'A private repository needs GitHub Code Security.' }
        elseif ($why -like '*Resource not accessible by integration*') { 'The upload needs security-events: write, which pull requests from forks do not get.' }
        else { '' }
    if ($cause) {
        if ($why.Length -gt 200) { $why = $why.Substring(0, 200) }
        Write-Output "::notice title=setup-raeva::The SARIF log is not uploaded: code scanning answered HTTP 403 ($(EscMsg $why)). $cause The findings are in the job summary; sarif-upload: false skips this check."
        return
    }
    Out 'sarif-upload' 'true'
}

# The findings as a Markdown table, most severe first. The cells quote
# advisory data, so Markdown characters in them are escaped.
function Format-Cell($Value) {
    $s = if ($null -eq $Value) { '' } else { "$Value" }
    ($s -replace '[\r\n]+', ' ') -replace '([\\`*_\[\]<>|!#~&])', '\$1'
}
function Write-FindingsTable($Log) {
    $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; None = 4 }
    $rows = @()
    foreach ($run in $Log.runs) {
        if (-not $run.PSObject.Properties['results']) { continue }
        foreach ($result in $run.results) {
            $props = if ($result.PSObject.Properties['properties']) { $result.properties } else { $null }
            $field = { param($name) if ($props -and $props.PSObject.Properties[$name]) { $props.$name } else { $null } }
            $severity = & $field 'severity'
            if (-not $severity) { $severity = 'Unknown' }
            $rows += [pscustomobject]@{
                Vex      = [bool]($result.PSObject.Properties['suppressions'] -and @($result.suppressions).Count -gt 0)
                Rank     = if ($rank.ContainsKey("$severity")) { $rank["$severity"] } else { 5 }
                Severity = $severity
                Id       = if ($result.PSObject.Properties['ruleId']) { "$($result.ruleId)" } else { '' }
                Purl     = & $field 'dependencyPurl'
                Fixed    = & $field 'fixedVersion'
                Baseline = if ($result.PSObject.Properties['baselineState']) {
                    switch ($result.baselineState) {
                        'new' { 'new' }
                        'unchanged' { 'existing' }
                        default { 'not compared' }
                    }
                } else { 'not compared' }
            }
        }
    }
    if ($rows.Count -eq 0) { return }
    $rows = @($rows | Sort-Object -Property Vex, Rank, Id -CaseSensitive)
    $compared = @($rows | Where-Object { $_.Baseline -ne 'not compared' }).Count -gt 0
    $lines = @('', ('| Severity | Advisory | Dependency | Fixed in | ' + $(if ($compared) { 'Baseline | ' }) + 'VEX |'),
        ('| --- | --- | --- | --- | ' + $(if ($compared) { '--- | ' }) + '--- |'))
    foreach ($row in ($rows | Select-Object -First 100)) {
        $lines += "| $(Format-Cell $row.Severity) | $(Format-Cell $row.Id) | $(Format-Cell $row.Purl) | $(Format-Cell $row.Fixed) | " + $(if ($compared) { "$($row.Baseline) | " }) + "$(if ($row.Vex) { 'suppressed' }) |"
    }
    if ($rows.Count -gt 100) { $lines += @('', "... and $($rows.Count - 100) more in the SARIF log.") }
    Summary ($lines -join "`n")
}

# The results raeva's --fail-on counted, for the summary and the gate: not
# suppressed, not in the baseline, and at the threshold or above, where an
# unknown severity meets every threshold. Returns, for example, "2 new
# findings at or above 'high' (GHSA-x, CVE-y)", with at most five advisories.
function Get-FailingFindings($Log, [string]$FailOn, [string]$New) {
    $max = switch -CaseSensitive ($FailOn) { 'any' { 4 } 'low' { 3 } 'medium' { 2 } 'high' { 1 } 'critical' { 0 } }
    $count = 0
    $best = @{}
    foreach ($run in $Log.runs) {
        if (-not $run.PSObject.Properties['results']) { continue }
        foreach ($result in $run.results) {
            if ($result.PSObject.Properties['suppressions'] -and @($result.suppressions).Count -gt 0) { continue }
            if ($result.PSObject.Properties['baselineState'] -and "$($result.baselineState)" -ceq 'unchanged') { continue }
            $severity = if ($result.PSObject.Properties['properties'] -and $result.properties -and
                $result.properties.PSObject.Properties['severity'] -and $null -ne $result.properties.severity) { "$($result.properties.severity)" } else { 'Unknown' }
            $rank = switch -CaseSensitive ($severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } 'None' { 4 } default { 5 } }
            if ($rank -ne 5 -and $rank -gt $max) { continue }
            $count++
            $id = if ($result.PSObject.Properties['ruleId'] -and $null -ne $result.ruleId) { "$($result.ruleId)" -creplace '[^A-Za-z0-9._:-]', '' } else { '' }
            if ($id.Length -gt 64) { $id = $id.Substring(0, 64) }
            if ($id -and (-not $best.ContainsKey($id) -or $best[$id] -gt $rank)) { $best[$id] = $rank }
        }
    }
    if ($count -eq 0) { return '' }
    $keys = [string[]]@($best.Keys | ForEach-Object { "$($best[$_])`t$_" })
    [Array]::Sort($keys, [StringComparer]::Ordinal)
    $ids = @($keys | ForEach-Object { $_.Substring(2) })
    $text = "$count $($New)finding$(if ($count -ne 1) { 's' }) at or above '$FailOn' (" + (($ids | Select-Object -First 5) -join ', ')
    if ($ids.Count -gt 5) { $text += ", and $($ids.Count - 5) more" }
    "$text)"
}

function Invoke-Vuln {
    $failOn = if ($env:INPUT_VULN_FAIL_ON) { $env:INPUT_VULN_FAIL_ON } else { 'high' }
    if ($failOn -notin @('any', 'low', 'medium', 'high', 'critical', 'never')) {
        Write-Output '::error title=setup-raeva::vuln-fail-on must be any, low, medium, high, critical, or never'
        exit 2
    }
    $sarif = Join-Path $runDir 'raeva.sarif'
    $err = Join-Path $runDir 'vuln.err'
    if ($baseMissing) { $failOn = 'never' }
    $arguments = @('-C', $workdir, 'vuln', '--format', 'sarif', '--fail-on', $failOn)
    if ($baseLock) { $arguments += @('--baseline', $baseLock) }
    foreach ($line in "$env:INPUT_VEX" -split "`n") {
        $path = $line.Trim()
        if ($path) { $arguments += @('--vex', $path) }
    }
    $arguments += $maven
    Write-Output "Scanning raeva.lock with raeva vuln; its output follows when it exits."
    $code = Invoke-Raeva $arguments $sarif $err
    Write-Raw @($err)
    Out 'vuln-exit-code' $code
    Summary "`n### Vulnerabilities"
    if ($baseMissing) { Summary "`nThe base commit has no ``raeva.lock`` for this root. Vulnerabilities use ``--fail-on never``; scan errors still fail." }
    if ($committed) { Summary "`nThe committed lock is stale, so the scan reads the proposed lock." }
    # An incomplete scan (exit 2 or more) still writes the findings it has, so
    # its log is uploaded; the gate step fails the job afterwards.
    $log = $null
    try { $log = Get-Content -LiteralPath $sarif -Raw | ConvertFrom-Json } catch { }
    if (-not $log -or -not $log.PSObject.Properties['runs'] -or $log.runs -isnot [array]) {
        if ($code -in 0, 1) { Write-Output '::error title=raeva vuln::the SARIF log is not valid'; exit 2 }
        Remove-Item -LiteralPath $sarif -ErrorAction SilentlyContinue
        Summary "`n``raeva vuln`` did not complete (exit $code) and wrote no SARIF log."
        return
    }
    # raeva writes result locations relative to the project root. Code scanning
    # reads them relative to the repository root, so prefix the subdirectory.
    # A result a VEX statement suppressed is not a finding.
    $count = 0
    $suppressed = 0
    foreach ($run in $log.runs) {
        if (-not $run.PSObject.Properties['results']) { continue }
        foreach ($result in $run.results) {
            if ($result.PSObject.Properties['suppressions'] -and @($result.suppressions).Count -gt 0) { $suppressed++ } else { $count++ }
            if (-not $rel -or -not $result.PSObject.Properties['locations']) { continue }
            foreach ($location in $result.locations) {
                $location.physicalLocation.artifactLocation.uri = "$rel/$($location.physicalLocation.artifactLocation.uri)"
            }
        }
    }
    if ($rel) {
        $text = $log | ConvertTo-Json -Depth 100
        [IO.File]::WriteAllText($sarif, $text, [Text.UTF8Encoding]::new($false))
    }
    Out 'sarif-file' $sarif
    Out 'sarif-category' (Get-SarifCategory)
    Out 'vuln-findings' $count
    $note = if ($suppressed -gt 0) { ", and $suppressed suppressed by VEX" } else { '' }
    $gating = if ($failOn -eq 'never') { 'findings do not fail the job (vuln-fail-on: never)' } else { "findings at $failOn or above fail the job" }
    if ($baseLock -and $failOn -ne 'never') { $gating = "new findings at $failOn or above fail the job" }
    if ($code -notin 0, 1) {
        Summary "`n``raeva vuln`` did not complete (exit $code): $count finding(s)$note in the partial SARIF log."
    } else {
        Summary "`n``raeva vuln``: $count finding(s)$note; $gating."
    }
    if ($code -eq 1 -and $failOn -ne 'never') {
        $failing = Get-FailingFindings $log $failOn $(if ($baseLock) { 'new ' } else { '' })
        if ($failing) {
            Out 'vuln-failing' $failing
            Summary "`nThe job fails on $failing."
        }
    }
    Write-FindingsTable $log
    Test-SarifUpload
}

# Read Git objects as data, without checking out or running the base tree.
function Get-BaseJson([string]$Path) {
    $response = Invoke-WebRequest -UseBasicParsing -SkipHttpErrorCheck -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 60 -MaximumRedirection 0 `
        -Uri "$api/repos/$env:GITHUB_REPOSITORY/$Path" `
        -Headers @{ Authorization = "Bearer $token"; Accept = 'application/vnd.github+json' }
    if ([int]$response.StatusCode -ne 200) { throw "HTTP $($response.StatusCode) (the job needs contents: read)" }
    # Malformed JSON fails the shape checks of the caller, as in check.sh.
    try { $response.Content | ConvertFrom-Json } catch { $null }
}
# A merge queue checks the group against its base commit, as a pull
# request is checked against its base branch.
function Read-PrBaseline {
    $mergeGroup = "$env:GITHUB_EVENT_NAME" -ceq 'merge_group'
    if (-not $mergeGroup -and -not ("$env:GITHUB_EVENT_NAME".StartsWith('pull_request'))) { return }
    try {
        if (-not $env:GITHUB_EVENT_PATH -or -not $env:GITHUB_REPOSITORY) { throw 'event metadata is missing' }
        $payload = Get-Content -LiteralPath $env:GITHUB_EVENT_PATH -Raw | ConvertFrom-Json
        $base = if ($mergeGroup) { $payload.merge_group.base_sha } else { $payload.pull_request.base.sha }
        if ($base -cnotmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') { throw 'base SHA is invalid' }
        $path = $lockPath
        if ($path.StartsWith('/') -or $path -match '(^|/)\.\.?/|//|:') { throw 'working-directory must be a path inside the repository without . or ..' }
        # The trees API reads a commit SHA as the commit's root tree.
        $tree = $base
        $parts = $path -split '/'
        for ($i = 0; $i -lt $parts.Count; $i++) {
            $part = $parts[$i]
            if ($tree -cnotmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') { throw 'invalid tree SHA' }
            $data = Get-BaseJson "git/trees/$tree"
            if ($data.truncated -ne $false -or $data.tree -isnot [array]) { throw 'invalid or truncated tree response' }
            $entries = @($data.tree | Where-Object { $_.path -ceq $part })
            if ($entries.Count -eq 0) {
                $script:baseMissing = $true
                Write-Host '::notice title=setup-raeva::The base commit has no raeva.lock for this root; vulnerability findings are report-only (--fail-on never). Scan errors still fail.'
                return
            }
            if ($entries.Count -ne 1) { throw 'duplicate tree entry' }
            $entry = $entries[0]
            if ($entry.sha -cnotmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') { throw 'invalid object SHA' }
            if ($i -eq $parts.Count - 1) {
                if ($entry.type -cne 'blob' -or $entry.mode -notin @('100644', '100755')) { throw 'raeva.lock is not a regular file' }
                $blob = Get-BaseJson "git/blobs/$($entry.sha)"
                if ($blob.encoding -cne 'base64' -or $blob.content -isnot [string]) { throw 'unreadable blob response' }
                try { $bytes = [Convert]::FromBase64String($blob.content) } catch { throw 'unreadable blob response' }
                if ($bytes.Length -eq 0) { throw 'raeva.lock is empty' }
                $script:baseLock = Join-Path $runDir 'base.lock'
                [IO.File]::WriteAllBytes($script:baseLock, $bytes)
            } else {
                if ($entry.type -cne 'tree' -or $entry.mode -cne '040000') { throw 'a parent of raeva.lock is not a directory' }
                $tree = $entry.sha
            }
        }
    } catch {
        # Name only the reasons thrown above: other exceptions may contain headers or response bodies.
        $why = if ($_.Exception -is [Management.Automation.RuntimeException] -and $_.Exception.WasThrownFromThrowStatement) { $_.Exception.Message } else { 'request failed' }
        Write-Host "::error title=setup-raeva::cannot read the vulnerability baseline of the base commit; $why"
        exit 2
    }
}

function Invoke-Gate {
    $code = if ($env:VULN_EXIT_CODE) { [int]$env:VULN_EXIT_CODE } else { 0 }
    $failOn = if ($env:INPUT_VULN_FAIL_ON) { $env:INPUT_VULN_FAIL_ON } else { 'high' }
    if ($code -eq 1 -and $failOn -ne 'never') {
        if ($env:VULN_FAILING) {
            Write-Output "::error title=raeva vuln::$(EscMsg "The job fails on $env:VULN_FAILING"); see the job summary and the scan output"
        } else {
            Write-Output "::error title=raeva vuln::findings at or above '$failOn'; see the job summary and the scan output"
        }
        exit 1
    }
    if ($code -notin 0, 1) {
        Write-Output "::error title=raeva vuln::the scan did not complete (exit $code); see the step log"
        exit $code
    }
}

try {
    switch ($Mode) {
        'scan' {
            if ($checkMode -notin @('blocking', 'report-only')) {
                Write-Output '::error title=setup-raeva::check-mode must be blocking or report-only'
                exit 2
            }
            if ($env:INPUT_VULN -eq 'true' -and $env:INPUT_LOCK_DIFF -ne 'only') { Read-PrBaseline }
            if ($env:INPUT_LOCK_DIFF -eq 'only') {
                Write-Output '::error title=setup-raeva::lock-diff: only runs on Linux and macOS runners'
                exit 1
            }
            if ($env:INPUT_CHECK -eq 'true') { Invoke-Frozen }
            if ($env:INPUT_VULN -eq 'true') { Invoke-Vuln }
        }
        'gate' { Invoke-Gate }
        default { Write-Error 'usage: check.ps1 scan|gate'; exit 2 }
    }
} finally {
    Restore-Lock
}
exit 0
