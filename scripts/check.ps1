# `check.ps1 scan` runs the frozen check and the optional vulnerability scan.
# `check.ps1 gate` runs after the SARIF upload and fails the job on findings,
# so the upload happens before the job fails.
param([string]$Mode = 'scan')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$raeva = if ($env:RAEVA_BIN) { $env:RAEVA_BIN } else { 'raeva' }
$workdir = if ($env:INPUT_WORKING_DIRECTORY) { $env:INPUT_WORKING_DIRECTORY } else { '.' }
$lockFile = if ($env:LOCK_FILE) { $env:LOCK_FILE } else { 'raeva.lock' }
$tmp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }

function Out([string]$Name, [string]$Value) {
    if ($env:GITHUB_OUTPUT) { Add-Content -Path $env:GITHUB_OUTPUT -Value "$Name=$Value" -Encoding utf8 }
}
function Summary([string]$Text) {
    if ($env:GITHUB_STEP_SUMMARY) { Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value $Text -Encoding utf8 }
}
# Workflow commands need %, CR, and LF escaped in messages, and also : and ,
# in properties such as title.
function EscMsg([string]$s) { $s.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A') }
function EscProp([string]$s) { (EscMsg $s).Replace(':', '%3A').Replace(',', '%2C') }

# Runs raeva with stdout and stderr in files, so the bytes of a SARIF log are
# kept as raeva wrote them, and returns the exit code.
function Invoke-Raeva([string[]]$Arguments, [string]$StdOut, [string]$StdErr) {
    # Start-Process joins the list with spaces, so quote what needs it.
    $quoted = $Arguments | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }
    $p = Start-Process -FilePath $raeva -ArgumentList $quoted -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $StdOut -RedirectStandardError $StdErr
    return $p.ExitCode
}

function Hint([string]$Code) {
    switch ($Code) {
        'LOCKFILE_MISMATCH' { "Run 'raeva sync' with the same --platforms as the lock, and commit $lockFile." }
        'PLATFORM_MISSING'  { "Lock this runner's platform too: raeva sync --platforms <every platform CI uses>." }
        'LOCKFILE_MISSING'  { "Run 'raeva sync' at the project root and commit $lockFile." }
        'LOCKFILE_INVALID'  { "Run 'raeva sync' to write $lockFile again, then commit it." }
        'AUTH'              { 'Give the job the repository credentials (settings.xml or raeva.toml [[auth]] with token_env).' }
        default             { 'See the exit-code table in the raeva README.' }
    }
}

function Invoke-Frozen {
    $arguments = @('--json', '-C', $workdir, 'sync', '--frozen')
    if ($env:INPUT_PLATFORMS) { $arguments += @('--platforms', $env:INPUT_PLATFORMS) }
    $json = Join-Path $tmp 'raeva-frozen.json'
    $err = Join-Path $tmp 'raeva-frozen.err'
    $code = Invoke-Raeva $arguments $json $err
    Get-Content -LiteralPath $err | Write-Host
    Out 'frozen-exit-code' $code
    $envelope = $null
    try { $envelope = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json } catch { }
    if ($code -eq 0) {
        $resolved = if ($envelope -and $envelope.data.PSObject.Properties['resolved']) { " ($($envelope.data.resolved) dependencies)" } else { '' }
        Write-Output "$lockFile is current$resolved"
        Summary "### raeva`n`n``$lockFile`` is current for this runner."
        return
    }
    $ecode = if ($envelope -and $envelope.PSObject.Properties['code']) { "$($envelope.code)" } else { '' }
    # raeva 0.4 writes no code field. A frozen sync exits 7 only for a stale lock.
    if (-not $ecode -and $code -eq 7) { $ecode = 'LOCKFILE_MISMATCH' }
    $message = if ($envelope -and $envelope.PSObject.Properties['error']) { "$($envelope.error)" } else { Get-Content -LiteralPath $json -Raw }
    $title = "raeva sync --frozen (exit $code$(if ($ecode) { ", $ecode" }))"
    Write-Output "::error file=$(EscProp "$workdir/$lockFile"),title=$(EscProp $title)::$(EscMsg "$message. $(Hint $ecode)")"
    Summary "### raeva`n`n``raeva sync --frozen`` failed with exit $code ($(if ($ecode) { $ecode } else { 'no code' })).`n`n$(Hint $ecode)"
    exit $code
}

function Invoke-Vuln {
    $failOn = if ($env:INPUT_VULN_FAIL_ON) { $env:INPUT_VULN_FAIL_ON } else { 'high' }
    if ($failOn -notin @('any', 'low', 'medium', 'high', 'critical', 'never')) {
        Write-Output '::error title=setup-raeva::vuln-fail-on must be any, low, medium, high, critical, or never'
        exit 2
    }
    $rvFailOn = if ($failOn -eq 'never') { 'critical' } else { $failOn }
    $sarif = Join-Path $tmp 'raeva.sarif'
    $err = Join-Path $tmp 'raeva-vuln.err'
    $code = Invoke-Raeva @('-C', $workdir, 'vuln', '--format', 'sarif', '--fail-on', $rvFailOn) $sarif $err
    Get-Content -LiteralPath $err | Write-Host
    Out 'vuln-exit-code' $code
    if ($code -gt 1) {
        Remove-Item -LiteralPath $sarif -ErrorAction SilentlyContinue
        return
    }
    $log = Get-Content -LiteralPath $sarif -Raw | ConvertFrom-Json
    # rv writes result locations relative to the project root. Code scanning
    # reads them relative to the repository root, so prefix the subdirectory.
    $prefix = ($workdir -replace '\\', '/').TrimEnd('/')
    if ($prefix.StartsWith('./')) { $prefix = $prefix.Substring(2) }
    $count = 0
    foreach ($run in $log.runs) {
        if (-not $run.PSObject.Properties['results']) { continue }
        foreach ($result in $run.results) {
            $count++
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
    Out 'vuln-findings' $count
    Summary "`n``raeva vuln``: $count finding(s) in the SARIF log."
}

function Invoke-Gate {
    $code = if ($env:VULN_EXIT_CODE) { [int]$env:VULN_EXIT_CODE } else { 0 }
    $failOn = if ($env:INPUT_VULN_FAIL_ON) { $env:INPUT_VULN_FAIL_ON } else { 'high' }
    if ($code -eq 1 -and $failOn -ne 'never') {
        Write-Output "::error title=raeva vuln::findings at or above '$failOn'; see the scan output and the code scanning alerts"
        exit 1
    }
    if ($code -gt 1) {
        Write-Output "::error title=raeva vuln::the scan did not complete (exit $code); see the step log"
        exit $code
    }
}

switch ($Mode) {
    'scan' {
        if ($env:INPUT_CHECK -eq 'true') { Invoke-Frozen }
        if ($env:INPUT_VULN -eq 'true') { Invoke-Vuln }
    }
    'gate' { Invoke-Gate }
    default { Write-Error 'usage: check.ps1 scan|gate'; exit 2 }
}
exit 0
