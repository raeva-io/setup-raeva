# Installs a pinned raeva release. Used on Windows runners; it also runs
# under pwsh on Linux and macOS, which the local tests use.
#
# Inputs arrive as environment variables (INPUT_*), never as interpolated
# script text, so a crafted input cannot inject code.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version 3.0

function Fail([string]$Message) {
    Write-Output "::error title=setup-raeva::$Message"
    exit 1
}
function Out([string]$Name, [string]$Value) {
    if ($env:GITHUB_OUTPUT) { Add-Content -Path $env:GITHUB_OUTPUT -Value "$Name=$Value" -Encoding utf8 }
}
function Sha256([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }

$version = "$env:INPUT_VERSION"
$verify = if ($env:INPUT_VERIFY) { $env:INPUT_VERIFY } else { 'attestation' }
$repo = if ($env:INPUT_REPOSITORY) { $env:INPUT_REPOSITORY } else { 'raeva-io/raeva' }
$baseUrl = "$env:INPUT_DOWNLOAD_BASE_URL"
$workdir = if ($env:INPUT_WORKING_DIRECTORY) { $env:INPUT_WORKING_DIRECTORY } else { '.' }
$actionPath = if ($env:GITHUB_ACTION_PATH) { $env:GITHUB_ACTION_PATH } else { Split-Path -Parent $PSScriptRoot }
$tmpRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }

if ($repo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { Fail "repository must be OWNER/NAME, got '$repo'" }
if ($verify -notin @('attestation', 'sha256')) { Fail "verify must be 'attestation' or 'sha256', got '$verify'" }

function Get-File([string]$Url, [string]$Path) {
    if ($Url.StartsWith('file://')) {
        Copy-Item -LiteralPath ([Uri]$Url).LocalPath -Destination $Path
    } elseif ($Url.StartsWith('https://')) {
        Invoke-WebRequest -Uri $Url -OutFile $Path -MaximumRetryCount 3 -RetryIntervalSec 2 -UseBasicParsing
    } else {
        Fail "download URLs must use https, got '$Url'"
    }
}

if ($version -eq 'latest') {
    if ($baseUrl) { Fail "version 'latest' needs the GitHub release host; set an exact version with download-base-url" }
    $response = Invoke-WebRequest -Uri "https://github.com/$repo/releases/latest" -Method Head -UseBasicParsing
    $version = ($response.BaseResponse.RequestMessage.RequestUri.AbsoluteUri -split '/tag/v')[-1]
    Write-Output "::notice title=setup-raeva::version 'latest' resolved to $version; pin it to make runs repeatable"
}
if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$') { Fail "version must be X.Y.Z or 'latest', got '$version'" }
$tag = "v$version"

$os = if ($env:RUNNER_OS) { $env:RUNNER_OS } elseif ($IsWindows) { 'Windows' } elseif ($IsMacOS) { 'macOS' } else { 'Linux' }
$arch = if ($env:RUNNER_ARCH) { $env:RUNNER_ARCH } else { "$([Runtime.InteropServices.RuntimeInformation]::OSArchitecture)".ToUpperInvariant() }
$target = switch ("$os/$arch") {
    'Windows/X64'   { 'x86_64-pc-windows-msvc' }
    # Windows on Arm runs x64 binaries under emulation; there is no arm64 build.
    'Windows/ARM64' { 'x86_64-pc-windows-msvc' }
    'Linux/X64'     { 'x86_64-unknown-linux-gnu' }
    'Linux/ARM64'   { 'aarch64-unknown-linux-gnu' }
    'macOS/X64'     { 'x86_64-apple-darwin' }
    'macOS/ARM64'   { 'aarch64-apple-darwin' }
    default         { Fail "no raeva build for $os/$arch" }
}
if ("$os/$arch" -eq 'Windows/ARM64') {
    Write-Output "::notice title=setup-raeva::using the x86_64 build under emulation on Windows ARM64"
}
$exe = if ($target -like '*windows*') { '.exe' } else { '' }

if (-not $baseUrl) { $baseUrl = "https://github.com/$repo/releases/download/$tag" }
$baseUrl = $baseUrl.TrimEnd('/')
$work = Join-Path $tmpRoot ("raeva-setup." + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $sumFile = Join-Path $work 'sha256.sum'
    try { Get-File "$baseUrl/sha256.sum" $sumFile } catch { Fail "cannot download sha256.sum for $tag from ${baseUrl}: $_" }

    $pattern = '^([0-9a-f]{64}) \*?([A-Za-z0-9._-]+-' + [Regex]::Escape($target) + '\.(tar\.gz|tar\.xz|zip))$'
    $matches_ = @(Get-Content -LiteralPath $sumFile | ForEach-Object { if ($_ -match $pattern) { , @($Matches[1], $Matches[2]) } })
    if ($matches_.Count -eq 0) { Fail "release $tag has no archive for $target" }
    if ($matches_.Count -gt 1) { Fail "release $tag lists more than one archive for $target" }
    $releaseSha = $matches_[0][0]
    $asset = $matches_[0][1]

    # A checksum shipped with this action release is independent of the
    # GitHub release, so it also catches a release asset replaced later. The
    # pin is looked up by target, not by asset name, so an archive uploaded
    # under another name does not escape it.
    $knownSha = ''
    $knownAsset = ''
    $knownFile = Join-Path $actionPath 'known-checksums.txt'
    $knownPattern = '-' + [Regex]::Escape($target) + '\.(tar\.gz|tar\.xz|zip)$'
    if (Test-Path -LiteralPath $knownFile) {
        foreach ($line in Get-Content -LiteralPath $knownFile) {
            $f = -split $line
            if ($f.Count -eq 3 -and $f[0] -eq $version -and $f[1] -match $knownPattern) { $knownAsset = $f[1]; $knownSha = $f[2] }
        }
    }
    if ($knownSha -and ($knownAsset -ne $asset -or $knownSha -ne $releaseSha)) {
        Fail "sha256.sum of $tag lists $asset $releaseSha, but this action pins $knownAsset $knownSha"
    }

    $archive = Join-Path $work $asset
    try { Get-File "$baseUrl/$asset" $archive } catch { Fail "cannot download ${asset}: $_" }
    $actual = Sha256 $archive
    if ($actual -ne $releaseSha) { Fail "$asset has SHA-256 $actual, sha256.sum says $releaseSha" }
    if ($knownSha) {
        Write-Output "SHA-256 of $asset matches the checksum pinned in this action"
    } else {
        Write-Output "SHA-256 of $asset matches sha256.sum of release $tag"
    }

    if ($verify -eq 'attestation') {
        if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { Fail 'verify: attestation needs the GitHub CLI (gh); install it or set verify: sha256' }
        if (-not $env:GH_TOKEN) { Fail 'verify: attestation needs a token; pass token: ${{ github.token }}' }
        & gh attestation verify $archive --repo $repo --signer-workflow "$repo/.github/workflows/release.yml" `
            --source-ref "refs/tags/$tag" --deny-self-hosted-runners | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail "$asset has no valid build attestation from $repo release.yml at $tag" }
        Write-Output "Build attestation of $asset verified: $repo, release.yml, refs/tags/$tag"
    } elseif (-not $knownSha) {
        Write-Output "::notice title=setup-raeva::$asset was checked only against sha256.sum from the same release"
    }

    $extract = Join-Path $work 'x'
    New-Item -ItemType Directory -Path $extract | Out-Null
    if ($asset.EndsWith('.zip')) {
        Expand-Archive -LiteralPath $archive -DestinationPath $extract
    } else {
        & tar -xf $archive -C $extract
        if ($LASTEXITCODE -ne 0) { Fail "cannot extract $asset" }
    }

    # Archives from before the rename hold only rv; later ones hold raeva.
    $binary = Get-ChildItem -LiteralPath $extract -Recurse -File -Filter "raeva$exe" | Select-Object -First 1
    if (-not $binary) { $binary = Get-ChildItem -LiteralPath $extract -Recurse -File -Filter "rv$exe" | Select-Object -First 1 }
    if (-not $binary) { Fail "$asset contains neither raeva$exe nor rv$exe" }

    $binDir = Join-Path $tmpRoot "raeva-$version-$target" | Join-Path -ChildPath 'bin'
    if (Test-Path -LiteralPath $binDir) { Remove-Item -LiteralPath $binDir -Recurse -Force }
    New-Item -ItemType Directory -Path $binDir | Out-Null
    $raeva = Join-Path $binDir "raeva$exe"
    Copy-Item -LiteralPath $binary.FullName -Destination $raeva
    if ($env:INPUT_RV_ALIAS -eq 'true') {
        # In PowerShell `rv` is an alias of Remove-Variable; scripts there
        # must call rv.exe. Bash steps on Windows can call rv.
        Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $binDir "rv$exe")
    }
    if (-not $IsWindows) { & chmod 0755 $raeva }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

$reported = & $raeva --version
if ($LASTEXITCODE -ne 0) { Fail 'the installed binary does not run on this runner' }
if (($reported -split ' ')[-1] -ne $version) { Fail "installed binary reports '$reported', expected $version" }
Write-Output "Installed $reported to $binDir"

if ($env:GITHUB_PATH) { Add-Content -Path $env:GITHUB_PATH -Value $binDir -Encoding utf8 }
Out 'version' $version
Out 'bin-dir' $binDir
Out 'raeva' $raeva

# Cache inputs. The store paths follow docs/configuration.md "File locations".
# Before 0.5.0, raeva kept the store on Windows in the roaming %APPDATA%.
$beforeLocalAppData = [version]($version -replace '-.*$', '') -lt [version]'0.5.0'
$dataDir = if ($env:RAEVA_HOME) { $env:RAEVA_HOME }
    elseif ($target -like '*windows*' -and $beforeLocalAppData) { Join-Path $env:APPDATA 'raeva' }
    elseif ($target -like '*windows*') { Join-Path $env:LOCALAPPDATA 'raeva' }
    elseif ($target -like '*apple-darwin') { Join-Path $HOME 'Library/Application Support/raeva' }
    elseif ($env:XDG_DATA_HOME) { Join-Path $env:XDG_DATA_HOME 'raeva' }
    else { Join-Path $HOME '.local/share/raeva' }

$lockFile = "$env:INPUT_LOCK_FILE"
if (-not $lockFile) {
    $lockFile = 'raeva.lock'
    if (-not (Test-Path -LiteralPath (Join-Path $workdir 'raeva.lock')) -and (Test-Path -LiteralPath (Join-Path $workdir 'rv.lock'))) {
        $lockFile = 'rv.lock'
    }
}
Out 'lock-file' $lockFile

$lockPath = Join-Path $workdir $lockFile
if (Test-Path -LiteralPath $lockPath -PathType Leaf) {
    $prefix = "raeva-store-v1-$os-$arch-"
    Out 'cache-key' ($prefix + (Sha256 $lockPath))
    Out 'cache-restore-key' $prefix
    if ($env:GITHUB_OUTPUT) {
        $store = Join-Path $dataDir 'store'
        Add-Content -Path $env:GITHUB_OUTPUT -Encoding utf8 -Value @(
            'cache-paths<<RAEVA_EOF', $store, ('!' + (Join-Path $store 'tmp')), (Join-Path $dataDir 'metadata.db'), 'RAEVA_EOF')
    }
} else {
    Write-Output "No $lockFile in $workdir; the store cache is skipped"
}
