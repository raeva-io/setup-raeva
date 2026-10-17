#!/usr/bin/env bash
# Installs a pinned raeva release on a Linux or macOS runner.
#
# Inputs arrive as environment variables (INPUT_*), never as interpolated
# script text, so a crafted input cannot inject shell code.
set -euo pipefail

die() { echo "::error title=setup-raeva::$*"; exit 1; }
out() { echo "$1=$2" >> "${GITHUB_OUTPUT:-/dev/null}"; }

version="${INPUT_VERSION:-}"
verify="${INPUT_VERIFY:-attestation}"
repo="${INPUT_REPOSITORY:-raeva-io/raeva}"
base_url="${INPUT_DOWNLOAD_BASE_URL:-}"
rv_alias="${INPUT_RV_ALIAS:-false}"
workdir="${INPUT_WORKING_DIRECTORY:-.}"
lock_input="${INPUT_LOCK_FILE:-}"
action_path="${GITHUB_ACTION_PATH:-$(cd "$(dirname "$0")/.." && pwd)}"
tmp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"

[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "repository must be OWNER/NAME, got '$repo'"
case "$verify" in attestation|sha256) ;; *) die "verify must be 'attestation' or 'sha256', got '$verify'" ;; esac

curl_get() {
  # HTTPS only, except for the file:// base URL that tests and mirrors use.
  local proto="=https"
  [[ "$1" == file://* ]] && proto="=file"
  curl --proto "$proto" --tlsv1.2 --fail --silent --show-error --location \
    --retry 3 --retry-delay 2 --connect-timeout 20 -o "$2" "$1"
}

if [[ "$version" == "latest" ]]; then
  [[ -z "$base_url" ]] || die "version 'latest' needs the GitHub release host; set an exact version with download-base-url"
  effective=$(curl --proto '=https' --tlsv1.2 -fsSL -o /dev/null -w '%{url_effective}' \
    "https://github.com/$repo/releases/latest") || die "cannot resolve the latest release of $repo"
  version="${effective##*/tag/v}"
  echo "::notice title=setup-raeva::version 'latest' resolved to $version; pin it to make runs repeatable"
fi
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "version must be X.Y.Z or 'latest', got '$version'"
tag="v$version"

case "${RUNNER_OS:-$(uname -s)}/${RUNNER_ARCH:-$(uname -m)}" in
  Linux/X64|Linux/x86_64)     target=x86_64-unknown-linux-gnu ;;
  Linux/ARM64|Linux/aarch64)  target=aarch64-unknown-linux-gnu ;;
  macOS/X64|Darwin/x86_64)    target=x86_64-apple-darwin ;;
  macOS/ARM64|Darwin/arm64)   target=aarch64-apple-darwin ;;
  *) die "no raeva build for ${RUNNER_OS:-?}/${RUNNER_ARCH:-?}; use install.ps1 on Windows" ;;
esac

if [[ -r /etc/alpine-release ]] || { command -v ldd >/dev/null && ldd --version 2>&1 | grep -qi musl; }; then
  die "raeva release builds need glibc; this runner or container uses musl"
fi

base_url="${base_url:-https://github.com/$repo/releases/download/$tag}"
base_url="${base_url%/}"
work=$(mktemp -d "$tmp_root/raeva-setup.XXXXXX")
trap 'rm -rf "$work"' EXIT

curl_get "$base_url/sha256.sum" "$work/sha256.sum" || die "cannot download sha256.sum for $tag from $base_url"

# sha256.sum lines look like "<hex> *<asset>". The asset name is matched by
# target, so a renamed package (rv-cli- or raeva-) needs no change here.
line=$(grep -E "^[0-9a-f]{64} \*?[A-Za-z0-9._-]+-${target}\.(tar\.gz|tar\.xz|zip)\$" "$work/sha256.sum" || true)
[[ -n "$line" ]] || die "release $tag has no archive for $target"
[[ $(printf '%s\n' "$line" | wc -l) -eq 1 ]] || die "release $tag lists more than one archive for $target"
release_sha="${line%% *}"
asset="${line#* }"; asset="${asset#\*}"

# A checksum shipped with this action release is independent of the GitHub
# release, so it also catches a release asset that was replaced later. The pin
# is looked up by target, not by asset name, so an archive uploaded under
# another name does not escape it.
known=$(awk -v v="$version" -v t="$target" \
  '$1 == v && $2 ~ ("-" t "\\.(tar\\.gz|tar\\.xz|zip)$") { print $2, $3 }' \
  "$action_path/known-checksums.txt" 2>/dev/null || true)
known_sha=""
if [[ -n "$known" ]]; then
  known_asset="${known%% *}"
  known_sha="${known##* }"
  if [[ "$known_asset" != "$asset" || "$known_sha" != "$release_sha" ]]; then
    die "sha256.sum of $tag lists $asset $release_sha, but this action pins $known_asset $known_sha"
  fi
fi

curl_get "$base_url/$asset" "$work/$asset" || die "cannot download $asset"

if command -v sha256sum >/dev/null; then
  actual=$(sha256sum "$work/$asset" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$work/$asset" | cut -d' ' -f1)
fi
[[ "$actual" == "$release_sha" ]] || die "$asset has SHA-256 $actual, sha256.sum says $release_sha"
if [[ -n "$known_sha" ]]; then
  echo "SHA-256 of $asset matches the checksum pinned in this action"
else
  echo "SHA-256 of $asset matches sha256.sum of release $tag"
fi

if [[ "$verify" == "attestation" ]]; then
  command -v gh >/dev/null || die "verify: attestation needs the GitHub CLI (gh); install it or set verify: sha256"
  [[ -n "${GH_TOKEN:-}" ]] || die "verify: attestation needs a token; pass token: \${{ github.token }}"
  gh attestation verify "$work/$asset" \
    --repo "$repo" \
    --signer-workflow "$repo/.github/workflows/release.yml" \
    --source-ref "refs/tags/$tag" \
    --deny-self-hosted-runners >/dev/null \
    || die "$asset has no valid build attestation from $repo release.yml at $tag"
  echo "Build attestation of $asset verified: $repo, release.yml, refs/tags/$tag"
elif [[ -z "$known_sha" ]]; then
  echo "::notice title=setup-raeva::$asset was checked only against sha256.sum from the same release"
fi

mkdir -p "$work/x"
case "$asset" in
  *.tar.gz) tar -xzf "$work/$asset" -C "$work/x" ;;
  *.tar.xz) tar -xJf "$work/$asset" -C "$work/x" ;;
  *.zip)    unzip -q "$work/$asset" -d "$work/x" ;;
esac

# Archives from before the rename hold only `rv`; later ones hold `raeva`.
binary=$(find "$work/x" -type f -name raeva | head -n 1)
[[ -n "$binary" ]] || binary=$(find "$work/x" -type f -name rv | head -n 1)
[[ -n "$binary" ]] || die "$asset contains neither raeva nor rv"

bin_dir="$tmp_root/raeva-$version-$target/bin"
rm -rf "$bin_dir"
mkdir -p "$bin_dir"
cp "$binary" "$bin_dir/raeva"
chmod 0755 "$bin_dir/raeva"
if [[ "$rv_alias" == "true" ]]; then
  ln -s raeva "$bin_dir/rv"
fi

reported=$("$bin_dir/raeva" --version) || die "the installed binary does not run on this runner"
[[ "${reported##* }" == "$version" ]] || die "installed binary reports '$reported', expected $version"
echo "Installed $reported to $bin_dir"

echo "$bin_dir" >> "${GITHUB_PATH:-/dev/null}"
out version "$version"
out bin-dir "$bin_dir"
out raeva "$bin_dir/raeva"

# Cache inputs. The store paths follow docs/configuration.md "File locations".
if [[ -n "${RAEVA_HOME:-}" ]]; then
  data_dir="$RAEVA_HOME"
elif [[ "$target" == *apple-darwin ]]; then
  data_dir="$HOME/Library/Application Support/raeva"
else
  data_dir="${XDG_DATA_HOME:-$HOME/.local/share}/raeva"
fi

lock_file="$lock_input"
if [[ -z "$lock_file" ]]; then
  lock_file=raeva.lock
  [[ -f "$workdir/raeva.lock" || ! -f "$workdir/rv.lock" ]] || lock_file=rv.lock
fi
out lock-file "$lock_file"

if [[ -f "$workdir/$lock_file" ]]; then
  if command -v sha256sum >/dev/null; then
    lock_hash=$(sha256sum "$workdir/$lock_file" | cut -c1-64)
  else
    lock_hash=$(shasum -a 256 "$workdir/$lock_file" | cut -c1-64)
  fi
  prefix="raeva-store-v1-${RUNNER_OS:-$(uname -s)}-${RUNNER_ARCH:-$(uname -m)}-"
  out cache-key "$prefix$lock_hash"
  out cache-restore-key "$prefix"
  {
    echo "cache-paths<<RAEVA_EOF"
    echo "$data_dir/store"
    echo "!$data_dir/store/tmp"
    echo "$data_dir/metadata.db"
    echo "RAEVA_EOF"
  } >> "${GITHUB_OUTPUT:-/dev/null}"
else
  echo "No $lock_file in $workdir; the store cache is skipped"
fi
