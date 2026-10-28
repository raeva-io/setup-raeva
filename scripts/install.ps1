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

function Get-File([string]$Url, [string]$Path, [int]$Retries = 3) {
    if ($Url.StartsWith('file://')) {
        Copy-Item -LiteralPath ([Uri]$Url).LocalPath -Destination $Path
    } elseif ($Url.StartsWith('https://')) {
        Invoke-WebRequest -Uri $Url -OutFile $Path -MaximumRetryCount $Retries -RetryIntervalSec 2 -UseBasicParsing
    } else {
        Fail "download URLs must use https, got '$Url'"
    }
}

if ($version -eq 'latest') {
    if ($baseUrl) { Fail "version 'latest' needs the GitHub release host; set an exact version with download-base-url" }
    try {
        $response = Invoke-WebRequest -Uri "https://github.com/$repo/releases/latest" -Method Head -UseBasicParsing
        $version = ($response.BaseResponse.RequestMessage.RequestUri.AbsoluteUri -split '/tag/v')[-1]
    } catch {
        # A private repository answers 404 without the token.
        if (-not $env:GH_TOKEN -or -not (Get-Command gh -ErrorAction SilentlyContinue)) { Fail "cannot resolve the latest release of ${repo}: $_" }
        $tagName = & gh release view --repo $repo --json tagName --jq .tagName
        if ($LASTEXITCODE -ne 0) { Fail "cannot resolve the latest release of $repo" }
        $version = "$tagName" -replace '^v', ''
    }
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
$windows = $target -like '*windows*'
$exe = if ($windows) { '.exe' } else { '' }
$asset = if ($windows) { "raeva-$target.zip" } else { "raeva-$target.tar.gz" }

$mirror = $baseUrl
if (-not $baseUrl) { $baseUrl = "https://github.com/$repo/releases/download/$tag" }
$baseUrl = $baseUrl.TrimEnd('/')
$work = Join-Path $tmpRoot ("raeva-setup." + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
# A private repository serves release assets only through the API, so a
# failed plain download is retried with gh and the token.
function Get-Asset([string]$Name) {
    # Invoke-WebRequest retries a 404 too, which a private release always
    # gives, so with gh to fall back on it tries once.
    $fallback = -not $mirror -and $env:GH_TOKEN -and (Get-Command gh -ErrorAction SilentlyContinue)
    try { Get-File "$baseUrl/$Name" (Join-Path $work $Name) $(if ($fallback) { 0 } else { 3 }); return } catch {
        if (-not $fallback) { throw }
    }
    & gh release download $tag --repo $repo --pattern $Name --dir $work --clobber
    if ($LASTEXITCODE -ne 0) { throw "gh release download failed for $Name" }
}
try {
    # A checksum shipped with this action release is independent of the
    # GitHub release, so it also catches a release asset replaced later, and
    # sha256.sum is not needed.
    $known = @()
    $knownFile = Join-Path $actionPath 'known-checksums.txt'
    if (Test-Path -LiteralPath $knownFile) {
        $known = @(Get-Content -LiteralPath $knownFile | ForEach-Object {
            $f = -split $_
            if ($f.Count -eq 3 -and $f[0] -eq $version -and $f[1] -eq $asset) { $f[2] }
        })
    }
    $knownSha = ''
    if ($known.Count -gt 0) {
        if ($known.Count -ne 1 -or $known[0] -cnotmatch '^[0-9a-f]{64}$') { Fail "known-checksums.txt has no single valid entry for $version $asset" }
        $knownSha = $sha = $known[0]
        $says = 'but this action pins'
        $source = 'the checksum pinned in this action'
    } else {
        try { Get-Asset 'sha256.sum' } catch { Fail "cannot download sha256.sum for $tag from ${baseUrl}: $_" }
        # sha256.sum lines look like "<hex> *<asset>".
        $shas = @(Get-Content -LiteralPath (Join-Path $work 'sha256.sum') | ForEach-Object {
            $f = -split $_
            if ($f.Count -eq 2 -and $f[1].TrimStart('*') -eq $asset) { $f[0] }
        })
        if ($shas.Count -ne 1 -or $shas[0] -cnotmatch '^[0-9a-f]{64}$') { Fail "sha256.sum of $tag has no single entry for $asset" }
        $sha = $shas[0]
        $says = 'sha256.sum says'
        $source = "sha256.sum of release $tag"
    }

    $archive = Join-Path $work $asset
    try { Get-Asset $asset } catch { Fail "cannot download ${asset}: $_" }
    $actual = Sha256 $archive
    if ($actual -ne $sha) { Fail "$asset has SHA-256 $actual, $says $sha" }
    Write-Output "SHA-256 of $asset matches $source"

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
    # cargo-dist puts raeva.exe at the root of the zip, and raeva in a
    # raeva-<target> directory in a tarball.
    if ($windows) {
        Expand-Archive -LiteralPath $archive -DestinationPath $extract
        $inner = 'raeva.exe'
    } else {
        & tar -xf $archive -C $extract
        if ($LASTEXITCODE -ne 0) { Fail "cannot extract $asset" }
        $inner = "raeva-$target/raeva"
    }
    $binary = Join-Path $extract $inner
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { Fail "$asset has no $inner" }

    $binDir = Join-Path $tmpRoot "raeva-$version-$target" | Join-Path -ChildPath 'bin'
    if (Test-Path -LiteralPath $binDir) { Remove-Item -LiteralPath $binDir -Recurse -Force }
    New-Item -ItemType Directory -Path $binDir | Out-Null
    $raeva = Join-Path $binDir "raeva$exe"
    Copy-Item -LiteralPath $binary -Destination $raeva
    if ($env:INPUT_RV_ALIAS -eq 'true') {
        # In PowerShell `rv` is an alias of Remove-Variable; scripts there
        # must call rv.exe. Bash steps on Windows can call rv.
        Copy-Item -LiteralPath $binary -Destination (Join-Path $binDir "rv$exe")
    }
    if (-not $IsWindows) { & chmod 0755 $raeva }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue
$reported = & $raeva --version
if ($LASTEXITCODE -ne 0) { Fail 'the installed binary does not run on this runner' }
if (($reported -split ' ')[-1] -ne $version) { Fail "installed binary reports '$reported', expected $version" }
Write-Output "Installed $reported to $binDir"

if ($env:GITHUB_PATH) { Add-Content -Path $env:GITHUB_PATH -Value $binDir -Encoding utf8 }
Out 'version' $version
Out 'bin-dir' $binDir
Out 'raeva' $raeva

# Cache inputs. The store paths follow docs/configuration.md "File locations".
$dataDir = if ($env:RAEVA_HOME) { $env:RAEVA_HOME }
    elseif ($windows) { Join-Path $env:LOCALAPPDATA 'raeva' }
    elseif ($target -like '*apple-darwin') { Join-Path $HOME 'Library/Application Support/raeva' }
    elseif ($env:XDG_DATA_HOME) { Join-Path $env:XDG_DATA_HOME 'raeva' }
    else { Join-Path $HOME '.local/share/raeva' }

$lockPath = Join-Path $workdir 'raeva.lock'
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
    Write-Output "No raeva.lock in $workdir; the store cache is skipped"
}
