# `check.ps1 scan` runs the frozen check and the optional vulnerability scan.
# `check.ps1 gate` runs after the SARIF upload and fails the job on findings,
# so the upload happens before the job fails. The pull request lock diff and
# the relock need Linux or macOS.
param([string]$Mode = 'scan')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$raeva = if ($env:RAEVA_BIN) { $env:RAEVA_BIN } else { 'raeva' }
$workdir = if ($env:INPUT_WORKING_DIRECTORY) { $env:INPUT_WORKING_DIRECTORY } else { '.' }
$tmp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
# Only the code scanning check uses a token, the job token that the SARIF
# upload uses too; raeva never sees one.
$uploadToken = "$env:UPLOAD_TOKEN"
Remove-Item Env:GH_TOKEN, Env:UPLOAD_TOKEN -ErrorAction SilentlyContinue
$api = if ($env:GITHUB_API_URL) { $env:GITHUB_API_URL } else { 'https://api.github.com' }

function Out([string]$Name, [string]$Value) {
    if ($env:GITHUB_OUTPUT) { Add-Content -Path $env:GITHUB_OUTPUT -Value "$Name=$Value" -Encoding utf8 }
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
# HTTP_REPO_BLOCKED names an http: repository that some POM declares and is
# listed in the summary only.
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
        if ($group.Count -gt 1) { $text += "; and $($group.Count - 1) more (raeva --json $Command lists them)" }
        if ($group.Name -cne 'HTTP_REPO_BLOCKED') {
            Write-Output "::warning title=$(EscProp "raeva $($group.Name)")::$(EscMsg $text)"
        }
        $lines += "$($group.Name) $text"
    }
    Summary "`nWarnings:"
    Fenced ($lines -join "`n")
}

# The platforms a lock records, read as text, since a malformed or
# conflicted lock still names them.
function Get-LockPlatforms([string]$Lock) {
    if (-not (Test-Path -LiteralPath $Lock)) { return '' }
    $seen = [Collections.Generic.List[string]]::new()
    foreach ($line in [IO.File]::ReadAllLines($Lock)) {
        if ($line -cmatch '^platform = "([a-z0-9_-]*)"\s*$' -and -not $seen.Contains($Matches[1])) { $seen.Add($Matches[1]) }
    }
    $seen -join ','
}

# The command a developer runs to write the lock again, with this job's
# Maven options. A settings file outside the repository, such as one the job
# writes to RUNNER_TEMP, is left out, and the summary says so.
function Get-SyncCommand {
    $words = @('raeva')
    if ($workdir -ne '.' -and $workdir -ne './') { $words += @('-C', $workdir) }
    $words += 'sync'
    foreach ($arg in $maven) {
        if (-not ($arg.StartsWith('--settings=') -and [IO.Path]::IsPathRooted($arg.Substring(11)))) { $words += $arg }
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
    $dir = ($workdir -replace '\\', '/').TrimEnd('/')
    if ($dir.StartsWith('./')) { $dir = $dir.Substring(2) }
    if ($dir -eq '.') { $dir = '' }
    $key = $dir
    foreach ($arg in $maven) { $key += "`n$arg" }
    $key += "`n$env:INPUT_PLATFORMS`n$More"
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($key))).Substring(0, 8).ToLowerInvariant()
    if ($dir) { "$Prefix-$($dir -replace '[^A-Za-z0-9._-]', '-')-$hash" } else { "$Prefix-$hash" }
}

# On a bot's pull request whose lock is stale, writes the lock diff that
# `raeva sync` would commit. raeva writes it in a copy of the working
# directory that is removed afterwards, so later steps see the committed lock.
function Invoke-Proposed {
    if (-not ("$env:GITHUB_EVENT_NAME".StartsWith('pull_request')) -or -not $env:GITHUB_EVENT_PATH -or
        -not (Test-Path -LiteralPath $env:GITHUB_EVENT_PATH)) { return }
    $type = ''
    try { $type = "$((Get-Content -LiteralPath $env:GITHUB_EVENT_PATH -Raw | ConvertFrom-Json).pull_request.user.type)" } catch { }
    $lock = Join-Path $workdir 'raeva.lock'
    if ($type -cne 'Bot' -or -not (Test-Path -LiteralPath $lock)) { return }
    $copy = Join-Path $runDir 'proposed'
    New-Item -ItemType Directory -Path $copy | Out-Null
    Get-ChildItem -LiteralPath $workdir -Force | Where-Object { $_.Name -ne '.git' } | Copy-Item -Destination $copy -Recurse -Force
    $platforms = if ($env:INPUT_PLATFORMS) { $env:INPUT_PLATFORMS } else { Get-LockPlatforms (Join-Path $copy 'raeva.lock') }
    $arguments = @('-q', '-C', $copy, 'sync') + $maven
    if ($platforms) { $arguments += @('--platforms', $platforms) }
    $syncOut = Join-Path $runDir 'proposed.out'
    $syncErr = Join-Path $runDir 'proposed.err'
    Write-Host '::group::raeva sync in a copy, for the proposed lock'
    $code = Invoke-Raeva $arguments $syncOut $syncErr
    Write-Raw @($syncOut, $syncErr)
    Write-Host '::endgroup::'
    Summary "`n### Proposed raeva.lock, not committed"
    if ($code -ne 0) {
        Summary "`n``raeva sync`` could not write a proposed lock (exit $code); see the step log. The error above stands."
    } else {
        Summary "`nThis is the lock ``raeva sync`` writes for this pull request. It is not committed, later steps use the committed lock, and the check above still fails. To fix it, run this on the branch and commit raeva.lock:"
        Fenced (Get-SyncCommand)
        if ($env:INPUT_SETTINGS -and [IO.Path]::IsPathRooted($env:INPUT_SETTINGS)) {
            Summary "`nThis job reads the settings file ``$($env:INPUT_SETTINGS.Replace('``', ''))``; run it with a settings file that has the same repositories and profiles."
        }
        $diffOut = Join-Path $runDir 'diff.out'
        $diffErr = Join-Path $runDir 'diff.err'
        $diffCode = Invoke-Raeva @('-q', '-C', $workdir, 'lock', 'diff', $lock, (Join-Path $copy 'raeva.lock')) $diffOut $diffErr
        if ($diffCode -ne 0) { Summary "`n``raeva lock diff`` could not compare the locks (exit $diffCode)." }
        $text = (([IO.File]::ReadAllText($diffOut) + [IO.File]::ReadAllText($diffErr)) -replace "`r", '').TrimEnd("`n")
        $artifactDir = Join-Path $runDir 'proposed-diff'
        New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $artifactDir 'proposed.diff'), "$text`n", [Text.UTF8Encoding]::new($false))
        $artifact = Get-DiffArtifact 'raeva-lock-proposed' "$env:JAVA_HOME"
        Out 'proposed-dir' $artifactDir
        Out 'proposed-artifact' $artifact
        $lines = $text -split "`n"
        if ($lines.Count -gt 200) {
            $text = (($lines | Select-Object -First 200) -join "`n") + "`n... $($lines.Count - 200) more lines; the full diff is proposed.diff in the $artifact artifact"
        }
        Fenced $text
    }
    Remove-Item -LiteralPath $copy -Recurse -Force -ErrorAction SilentlyContinue
}

function Invoke-Frozen {
    $arguments = @('--json', '-C', $workdir, 'sync', '--frozen') + $maven
    if ($env:INPUT_PLATFORMS) { $arguments += @('--platforms', $env:INPUT_PLATFORMS) }
    $json = Join-Path $runDir 'frozen.json'
    $err = Join-Path $runDir 'frozen.err'
    $code = Invoke-Raeva $arguments $json $err
    Write-Raw @($err)
    Out 'frozen-exit-code' $code
    $envelope = $null
    try { $envelope = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json } catch { }
    if ($code -eq 0) {
        $resolved = if ($envelope -and $envelope.data.PSObject.Properties['resolved']) { " ($($envelope.data.resolved) dependencies)" } else { '' }
        Write-Output "raeva.lock is current$resolved"
        Summary "### raeva`n`n``raeva.lock`` is current."
        Write-Warnings $envelope 'sync --frozen'
        return
    }
    $ecode = if ($envelope -and $envelope.PSObject.Properties['code']) { "$($envelope.code)" } else { '' }
    $message = if ($envelope -and $envelope.PSObject.Properties['error']) { "$($envelope.error)" } else { Get-Content -LiteralPath $json -Raw }
    $hints = if ($envelope -and $envelope.PSObject.Properties['hints'] -and @($envelope.hints).Count -gt 0) { @($envelope.hints) -join "`n" } else { Hint $ecode }
    $title = "raeva sync --frozen (exit $code$(if ($ecode) { ", $ecode" }))"
    $lockPath = "$workdir/raeva.lock"
    if ($lockPath.StartsWith('./')) { $lockPath = $lockPath.Substring(2) }
    Write-Output "::error file=$(EscProp $lockPath),title=$(EscProp $title)::$(EscMsg "$message`n$hints")"
    Summary "### raeva`n`n``raeva sync --frozen`` failed with exit $code ($(if ($ecode) { $ecode } else { 'no code' }))."
    Fenced "$message`n`n$hints"
    Write-Warnings $envelope 'sync --frozen'
    if ($code -eq 7) {
        try { Invoke-Proposed } catch { Write-Host "No proposed lock: $_" }
    }
    exit $code
}

# The code scanning category: the input, or one per working directory so
# the alerts of two Maven roots do not replace each other.
function Get-SarifCategory {
    if ($env:INPUT_SARIF_CATEGORY) { return $env:INPUT_SARIF_CATEGORY }
    $dir = ($workdir -replace '\\', '/').TrimEnd('/')
    if ($dir.StartsWith('./')) { $dir = $dir.Substring(2) }
    if ($dir -eq '' -or $dir -eq '.') { 'raeva' } else { "raeva/$dir" }
}

# An upload that code scanning refuses only adds an error annotation, so ask
# first, with the token the upload uses. Only a 403 that says code scanning
# is not enabled, as for a private repository without GitHub Code Security,
# skips the upload; a token that may not read alerts can still upload.
function Test-SarifUpload {
    if ($env:INPUT_SARIF_UPLOAD -ne 'true' -or -not $env:GITHUB_REPOSITORY) { return }
    $status = 0
    $why = ''
    try {
        $response = Invoke-WebRequest -UseBasicParsing -SkipHttpErrorCheck -Uri "$api/repos/$env:GITHUB_REPOSITORY/code-scanning/alerts?per_page=1" `
            -Headers @{ Authorization = "Bearer $uploadToken"; Accept = 'application/vnd.github+json' }
        $status = [int]$response.StatusCode
        if ($status -eq 403) { try { $why = "$(($response.Content | ConvertFrom-Json).message)" } catch { } }
    } catch { }
    if ($status -eq 403 -and $why -match 'must be enabled|not enabled') {
        if ($why.Length -gt 200) { $why = $why.Substring(0, 200) }
        Write-Output "::notice title=setup-raeva::The SARIF log is not uploaded: code scanning answered HTTP 403 ($(EscMsg $why)). A private repository needs GitHub Code Security. The findings are in the job summary; sarif-upload: false skips this check."
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
            }
        }
    }
    if ($rows.Count -eq 0) { return }
    $rows = @($rows | Sort-Object -Property Vex, Rank, Id -CaseSensitive)
    $lines = @('', '| Severity | Advisory | Dependency | Fixed in | VEX |', '| --- | --- | --- | --- | --- |')
    foreach ($row in ($rows | Select-Object -First 100)) {
        $lines += "| $(Format-Cell $row.Severity) | $(Format-Cell $row.Id) | $(Format-Cell $row.Purl) | $(Format-Cell $row.Fixed) | $(if ($row.Vex) { 'suppressed' }) |"
    }
    if ($rows.Count -gt 100) { $lines += @('', "... and $($rows.Count - 100) more in the SARIF log.") }
    Summary ($lines -join "`n")
}

function Invoke-Vuln {
    $failOn = if ($env:INPUT_VULN_FAIL_ON) { $env:INPUT_VULN_FAIL_ON } else { 'high' }
    if ($failOn -notin @('any', 'low', 'medium', 'high', 'critical', 'never')) {
        Write-Output '::error title=setup-raeva::vuln-fail-on must be any, low, medium, high, critical, or never'
        exit 2
    }
    $sarif = Join-Path $runDir 'raeva.sarif'
    $err = Join-Path $runDir 'vuln.err'
    $arguments = @('-C', $workdir, 'vuln', '--format', 'sarif', '--fail-on', $failOn)
    foreach ($line in "$env:INPUT_VEX" -split "`n") {
        $path = $line.Trim()
        if ($path) { $arguments += @('--vex', $path) }
    }
    $arguments += $maven
    $code = Invoke-Raeva $arguments $sarif $err
    Write-Raw @($err)
    Out 'vuln-exit-code' $code
    Summary "`n### Vulnerabilities"
    # An incomplete scan (exit 2 or more) still writes the findings it has, so
    # its log is uploaded; the gate step fails the job afterwards.
    $log = $null
    try { $log = Get-Content -LiteralPath $sarif -Raw | ConvertFrom-Json } catch { }
    if (-not $log -or -not $log.PSObject.Properties['runs']) {
        if ($code -le 1) { Write-Output '::error title=raeva vuln::the SARIF log is not valid'; exit 2 }
        Remove-Item -LiteralPath $sarif -ErrorAction SilentlyContinue
        Summary "`n``raeva vuln`` did not complete (exit $code) and wrote no SARIF log."
        return
    }
    # raeva writes result locations relative to the project root. Code scanning
    # reads them relative to the repository root, so prefix the subdirectory.
    $prefix = ($workdir -replace '\\', '/').TrimEnd('/')
    if ($prefix.StartsWith('./')) { $prefix = $prefix.Substring(2) }
    # A result a VEX statement suppressed is not a finding.
    $count = 0
    $suppressed = 0
    foreach ($run in $log.runs) {
        if (-not $run.PSObject.Properties['results']) { continue }
        foreach ($result in $run.results) {
            if ($result.PSObject.Properties['suppressions'] -and @($result.suppressions).Count -gt 0) { $suppressed++ } else { $count++ }
            if ($prefix -eq '.' -or $prefix -eq '' -or -not $result.PSObject.Properties['locations']) { continue }
            foreach ($location in $result.locations) {
                $location.physicalLocation.artifactLocation.uri = "$prefix/$($location.physicalLocation.artifactLocation.uri)"
            }
        }
    }
    if ($prefix -ne '.' -and $prefix -ne '') {
        $text = $log | ConvertTo-Json -Depth 100
        [IO.File]::WriteAllText($sarif, $text, [Text.UTF8Encoding]::new($false))
    }
    Out 'sarif-file' $sarif
    Out 'sarif-category' (Get-SarifCategory)
    Out 'vuln-findings' $count
    $note = if ($suppressed -gt 0) { ", and $suppressed suppressed by VEX" } else { '' }
    $gating = if ($failOn -eq 'never') { 'findings do not fail the job (vuln-fail-on: never)' } else { "findings at $failOn or above fail the job" }
    if ($code -gt 1) {
        Summary "`n``raeva vuln`` did not complete (exit $code): $count finding(s)$note in the partial SARIF log."
    } else {
        Summary "`n``raeva vuln``: $count finding(s)$note; $gating."
    }
    Write-FindingsTable $log
    Test-SarifUpload
}

function Invoke-Gate {
    $code = if ($env:VULN_EXIT_CODE) { [int]$env:VULN_EXIT_CODE } else { 0 }
    $failOn = if ($env:INPUT_VULN_FAIL_ON) { $env:INPUT_VULN_FAIL_ON } else { 'high' }
    if ($code -eq 1 -and $failOn -ne 'never') {
        Write-Output "::error title=raeva vuln::findings at or above '$failOn'; see the job summary and the scan output"
        exit 1
    }
    if ($code -gt 1) {
        Write-Output "::error title=raeva vuln::the scan did not complete (exit $code); see the step log"
        exit $code
    }
}

switch ($Mode) {
    'scan' {
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
exit 0
