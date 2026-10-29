#!/usr/bin/env bash
# Installs a pinned raeva release on a Linux or macOS runner.
#
# Inputs arrive as environment variables (INPUT_*), never as interpolated
# script text, so a crafted input cannot inject shell code.
set -euo pipefail

die() { echo "::error title=setup-raeva::$*"; exit 1; }
out() { echo "$1=$2" >> "${GITHUB_OUTPUT:-/dev/null}"; }
sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -c1-64
}

version="${INPUT_VERSION:-}"
verify="${INPUT_VERIFY:-attestation}"
repo="${INPUT_REPOSITORY:-raeva-io/raeva}"
base_url="${INPUT_DOWNLOAD_BASE_URL:-}"
rv_alias="${INPUT_RV_ALIAS:-false}"
workdir="${INPUT_WORKING_DIRECTORY:-.}"
action_path="${GITHUB_ACTION_PATH:-$(cd "$(dirname "$0")/.." && pwd)}"
tmp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"

[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "repository must be OWNER/NAME, got '$repo'"
case "$verify" in attestation|sha256) ;; *) die "verify must be 'attestation' or 'sha256', got '$verify'" ;; esac

curl_get() {
  # HTTPS only, except for the file:// base URL that tests and mirrors use.
  local proto="=https"
  [[ "$1" == file://* ]] && proto="=file"
  curl --proto "$proto" --tlsv1.2 --fail --silent --show-error --location \
    --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 300 -o "$2" "$1"
}

if [[ "$version" == "latest" ]]; then
  [[ -z "$base_url" ]] || die "version 'latest' needs the GitHub release host; set an exact version with download-base-url"
  if effective=$(curl --proto '=https' --tlsv1.2 -fsSL --max-time 60 -o /dev/null -w '%{url_effective}' \
    "https://github.com/$repo/releases/latest" 2>/dev/null); then
    version="${effective##*/tag/v}"
  elif [[ -n "${GH_TOKEN:-}" ]] && command -v gh >/dev/null; then
    # A private repository answers 404 without the token.
    version=$(gh release view --repo "$repo" --json tagName --jq .tagName) \
      || die "cannot resolve the latest release of $repo"
    version="${version#v}"
  else
    die "cannot resolve the latest release of $repo"
  fi
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

if [[ "$target" == *-linux-gnu ]]; then
  # musl ldd returns a nonzero status for --version on some systems.
  libc=$(ldd --version 2>&1 || true)
  if [[ -r /etc/alpine-release || "$libc" == *musl* || "$libc" == *Musl* ]]; then
    target="${target%-gnu}-musl"
  fi
fi

mirror="$base_url"
base_url="${base_url:-https://github.com/$repo/releases/download/$tag}"
base_url="${base_url%/}"
asset="raeva-$target.tar.gz"
work=$(mktemp -d "$tmp_root/raeva-setup.XXXXXX")
trap 'rm -rf "$work"' EXIT

# A private repository serves release assets only through the API, so a
# failed plain download is retried with gh and the token.
fetch() { # <asset name>
  curl_get "$base_url/$1" "$work/$1" 2>/dev/null && return 0
  [[ -z "$mirror" && -n "${GH_TOKEN:-}" ]] && command -v gh >/dev/null || return 1
  gh release download "$tag" --repo "$repo" --pattern "$1" --dir "$work" --clobber
}

# A checksum shipped with this action release is independent of the GitHub
# release, so it also catches a release asset that was replaced later, and
# sha256.sum is not needed.
known_sha=$(awk -v v="$version" -v a="$asset" '$1 == v && $2 == a { print $3 }' \
  "$action_path/known-checksums.txt" 2>/dev/null || true)
if [[ -n "$known_sha" ]]; then
  [[ "$known_sha" =~ ^[0-9a-f]{64}$ ]] || die "known-checksums.txt has no single valid entry for $version $asset"
  sha="$known_sha" says="but this action pins" source="the checksum pinned in this action"
else
  fetch sha256.sum || die "cannot download sha256.sum for $tag from $base_url"
  # sha256.sum lines look like "<hex> *<asset>".
  sha=$(awk -v a="$asset" '$2 == a || $2 == "*" a { print $1 }' "$work/sha256.sum")
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "sha256.sum of $tag has no single entry for $asset"
  says="sha256.sum says" source="sha256.sum of release $tag"
fi

fetch "$asset" || die "cannot download $asset"

actual=$(sha256 "$work/$asset")
[[ "$actual" == "$sha" ]] || die "$asset has SHA-256 $actual, $says $sha"
echo "SHA-256 of $asset matches $source"

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

bin_dir="$tmp_root/raeva-$version-$target/bin"
rm -rf "$bin_dir"
mkdir -p "$bin_dir"
tar -xzf "$work/$asset" -C "$bin_dir" --strip-components=1 "raeva-$target/raeva" 2>/dev/null \
  && [[ -f "$bin_dir/raeva" ]] || die "$asset has no raeva-$target/raeva"
chmod 0755 "$bin_dir/raeva"
if [[ "$rv_alias" == "true" ]]; then
  ln -s raeva "$bin_dir/rv"
fi

unset GH_TOKEN
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

if [[ -f "$workdir/raeva.lock" ]]; then
  lock_hash=$(sha256 "$workdir/raeva.lock")
  prefix="raeva-store-v1-$version-${RUNNER_OS:-$(uname -s)}-${RUNNER_ARCH:-$(uname -m)}-"
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
  echo "No raeva.lock in $workdir; the store cache is skipped"
fi
