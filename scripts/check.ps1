# `check.ps1 scan` runs the frozen check and the optional vulnerability scan.
# `check.ps1 gate` runs after the SARIF upload and fails the job on findings,
# so the upload happens before the job fails. The lock diffs and the relock
# need Linux or macOS.
param([string]$Mode = 'scan')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$raeva = if ($env:RAEVA_BIN) { $env:RAEVA_BIN } else { 'raeva' }
$workdir = if ($env:INPUT_WORKING_DIRECTORY) { $env:INPUT_WORKING_DIRECTORY } else { '.' }
$tmp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
# Only the GitHub API request uses the token; raeva never sees it.
$token = "$env:GH_TOKEN"
Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue
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

function Invoke-Frozen {
    $arguments = @('--json', '-C', $workdir, 'sync', '--frozen') + $maven
    if ($env:INPUT_PLATFORMS) { $arguments += @('--platforms', $env:INPUT_PLATFORMS) }
    $json = Join-Path $runDir 'frozen.json'
    $err = Join-Path $runDir 'frozen.err'
    $code = Invoke-Raeva $arguments $json $err
    Get-Content -LiteralPath $err | Write-Host
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
# first. Code scanning answers 403 when a private repository has no GitHub
# Code Security or the token has no security-events access. Any other answer
# leaves the upload to try.
function Test-SarifUpload {
    if ($env:INPUT_SARIF_UPLOAD -ne 'true' -or -not $env:GITHUB_REPOSITORY) { return }
    $status = 0
    $why = ''
    try {
        $response = Invoke-WebRequest -UseBasicParsing -SkipHttpErrorCheck -Uri "$api/repos/$env:GITHUB_REPOSITORY/code-scanning/alerts?per_page=1" `
            -Headers @{ Authorization = "Bearer $token"; Accept = 'application/vnd.github+json' }
        $status = [int]$response.StatusCode
        if ($status -eq 403) { try { $why = "$(($response.Content | ConvertFrom-Json).message)" } catch { } }
    } catch { }
    if ($status -eq 403) {
        if ($why.Length -gt 200) { $why = $why.Substring(0, 200) }
        $because = if ($why) { " ($(EscMsg $why))" } else { '' }
        Write-Output "::notice title=setup-raeva::The SARIF log is not uploaded: code scanning answered HTTP 403$because. A private repository needs GitHub Code Security, and the job needs security-events: write. The findings are in the job summary; sarif-upload: false skips this check."
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
    Get-Content -LiteralPath $err | Write-Host
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
