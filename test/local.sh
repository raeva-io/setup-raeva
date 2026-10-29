#!/usr/bin/env bash
# ok and bad always return 0, so "A && ok || bad" is safe here.
# shellcheck disable=SC2015
# Runs the action's scripts outside GitHub Actions, on Linux x86_64, against
# a raeva binary and two Maven projects. The Test workflow runs it with a
# release binary; it also runs with a local build.
#
#   RAEVA_BUILD=/path/to/raeva  the raeva binary to package as a fake release
#   PROJECT=/path               a project with a gson dependency and a raeva.lock
#                               for linux-x86_64, macos-aarch64, windows-x86_64
#   VULN_PROJECT=/path          a project with raeva.lock and known vulnerabilities
#   PWSH=/path/to/pwsh          optional; also runs the .ps1 scripts
#   GH_TOKEN                    optional; enables the real-release tests
#   RELEASE_VERSION             a published release for those tests
set -uo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
: "${RAEVA_BUILD:?set RAEVA_BUILD}" "${PROJECT:?set PROJECT}" "${VULN_PROJECT:?set VULN_PROJECT}"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/setup-raeva-test.XXXXXX")
trap '[[ -n "${KEEP:-}" ]] || rm -rf "$scratch"' EXIT
pass=0 fail=0
ok() { pass=$((pass + 1)); echo "PASS $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }
expect() { # expect <name> <wanted exit> <actual exit>
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (exit $3, wanted $2)"; fi
}
has() { grep -q -- "$2" "$1"; }

# Isolate raeva from the developer's own config, store, and settings.xml.
export HOME="$scratch/home" RAEVA_HOME="$scratch/raeva-home"
mkdir -p "$HOME"

# A fake release in the cargo-dist layout, served over file://.
version=$("$RAEVA_BUILD" --version | awk '{print $NF}')
target=x86_64-unknown-linux-gnu
rel="$scratch/release"
mkdir -p "$rel/raeva-$target"
cp "$RAEVA_BUILD" "$rel/raeva-$target/raeva"
tar -czf "$rel/raeva-$target.tar.gz" -C "$rel" "raeva-$target"
echo "$(sha256sum "$rel/raeva-$target.tar.gz" | cut -d' ' -f1) *raeva-$target.tar.gz" > "$rel/sha256.sum"

# The fake release has the version of a real one, so the fake-release tests
# use a copy of the action that pins no checksum for that version.
unpinned="$scratch/action-unpinned"
cp -r "$here" "$unpinned"
grep -v "^$version " "$here/known-checksums.txt" > "$unpinned/known-checksums.txt"

run_env() { # run_env <name> <script...>; sets up a fresh RUNNER_TEMP and outputs
  local name="$1"; shift
  local dir="$scratch/run-$name"
  mkdir -p "$dir/temp"
  : > "$dir/output"; : > "$dir/path"; : > "$dir/summary"
  env -u GITHUB_EVENT_NAME -u GITHUB_EVENT_PATH -u GITHUB_REPOSITORY \
    RUNNER_OS=Linux RUNNER_ARCH=X64 RUNNER_TEMP="$dir/temp" \
    GITHUB_OUTPUT="$dir/output" GITHUB_PATH="$dir/path" GITHUB_STEP_SUMMARY="$dir/summary" \
    GITHUB_ACTION_PATH="${ACTION_PATH:-$unpinned}" "$@" > "$dir/log" 2>&1
}
output_of() { sed -n "s/^$2=//p" "$scratch/run-$1/output" | head -n 1; }

# A stand-in for raeva that prints fixed answers: a frozen failure with hints
# and a warning, an incomplete scan with a partial SARIF log, and a long lock
# diff. With STUB_ARGS it appends its arguments and whether it saw GH_TOKEN.
stub="$scratch/stub/raeva"
mkdir -p "$scratch/stub"
cat > "$stub" <<'EOF'
#!/usr/bin/env bash
[[ -z "${STUB_ARGS:-}" ]] || { printf '%s\n' "$@" "GH_TOKEN=${GH_TOKEN-unset}" >> "$STUB_ARGS"; }
case " $* " in
  *" sync --frozen "*)
    printf '::error title=evil::from sync --frozen' >&2
    printf '%s\n' '{"success":false,"exit_code":7,"code":"LOCKFILE_MISMATCH","error":"dependencies would change:\n  gson  2.13.2 -> 2.13.1\n  ```` evil","hints":["Run raeva sync --platforms linux-x86_64 and commit raeva.lock"],"data":{"warnings":[{"code":"AUTH_FALLBACK","message":"central refused, mirror served","context":{"url":"https://mirror.example/"}},{"code":"AUTH_FALLBACK","message":"second","context":null},{"code":"HTTP_REPO_BLOCKED","message":"http repository in a POM","context":null}]}}'
    exit 7 ;;
  *" vuln "*" --vex "*)
    # Three results: no suppressions, an empty list, and one VEX suppressed.
    printf '%s\n' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"raeva"}},"results":[{"ruleId":"GHSA-a","message":{"text":"m"},"properties":{"severity":"High","dependencyPurl":"pkg:maven/a/b@1|`x`","fixedVersion":"2"}},{"ruleId":"GHSA-b","message":{"text":"m"},"suppressions":[]},{"ruleId":"GHSA-c","message":{"text":"m"},"properties":{"severity":"Critical"},"suppressions":[{"kind":"external","status":"accepted"}]}]}]}'
    exit 0 ;;
  *" vuln "*)
    [[ -n "${STUB_NO_SARIF:-}" ]] && { echo "error: no lock" >&2; exit 3; }
    printf '%s\n' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"raeva"}},"results":[{"ruleId":"GHSA-x","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"pom.xml"}}}]}],"invocations":[{"executionSuccessful":false}]}]}'
    exit 4 ;;
  *" lock diff "*)
    seq 1 50000
    exit 0 ;;
  *" sync "*)
    printf '::error title=evil::from raeva sync' >&2
    # A plain sync rewrites the lock in the -C directory.
    while [[ $# -gt 0 && "$1" != -C ]]; do shift; done
    printf '# written again\n' >> "${2:-.}/raeva.lock"
    exit 0 ;;
esac
exit 99
EOF
chmod +x "$stub"

# A stand-in for curl that answers every request with STUB_CURL_STATUS and
# the file STUB_CURL_BODY, and records the URL in STUB_CURL_LOG.
mkdir -p "$scratch/fake-curl"
cat > "$scratch/fake-curl/curl" <<'EOF'
#!/usr/bin/env bash
if [[ -n "${STUB_CURL_HEADERS:-}" ]]; then cat >> "$STUB_CURL_HEADERS"; else cat > /dev/null; fi
body="" url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|-H|-w|--proto|--retry|--max-time) [[ "$1" != -o ]] || body="$2"; shift ;;
    -*) ;;
    *) url="$1" ;;
  esac
  shift
done
[[ -z "${STUB_CURL_LOG:-}" ]] || echo "$url" >> "$STUB_CURL_LOG"
[[ -z "$body" || -z "${STUB_CURL_BODY:-}" ]] || cp "$STUB_CURL_BODY" "$body"
printf '%s' "${STUB_CURL_STATUS:-200}"
EOF
chmod +x "$scratch/fake-curl/curl"
fake_path="$scratch/fake-curl:$PATH"

# pwsh has no curl to replace, so a local server answers 403 as code
# scanning does for a private repository without Code Security.
api_port=""
if [[ -n "${PWSH:-}" ]]; then
  python3 -I -c '
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"{\"message\":\"Advanced Security must be enabled for this repository to use code scanning.\"}"
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
server = http.server.HTTPServer(("127.0.0.1", 0), H)
open(sys.argv[1], "w").write(str(server.server_port))
server.serve_forever()
' "$scratch/api-port" &
  api_pid=$!
  trap 'kill "$api_pid" 2>/dev/null; [[ -n "${KEEP:-}" ]] || rm -rf "$scratch"' EXIT
  for _ in $(seq 50); do
    [[ -s "$scratch/api-port" ]] && break
    python3 -c 'import time; time.sleep(0.1)'
  done
  api_port=$(cat "$scratch/api-port" 2>/dev/null)
fi

# A single module whose parent POM is one directory above it, as raeva
# reads it. A drifted parent makes the module's lock stale.
parent="$scratch/parent-project"
mkdir -p "$parent/app"
cat > "$parent/pom.xml" <<'EOF'
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>io.raeva.test</groupId>
  <artifactId>local-parent</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.google.code.gson</groupId>
        <artifactId>gson</artifactId>
        <version>2.13.2</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
EOF
cat > "$parent/app/pom.xml" <<'EOF'
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>io.raeva.test</groupId>
    <artifactId>local-parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>local-app</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.google.code.gson</groupId>
      <artifactId>gson</artifactId>
    </dependency>
  </dependencies>
</project>
EOF
"$RAEVA_BUILD" -q -C "$parent/app" sync --platforms linux-x86_64 2>/dev/null || echo "cannot lock $parent/app"
sed -i 's|<version>2.13.2</version>|<version>2.13.1</version>|' "$parent/pom.xml"

install_variants=("bash $here/scripts/install.sh")
check_variants=("bash $here/scripts/check.sh")
if [[ -n "${PWSH:-}" ]]; then
  install_variants+=("$PWSH -NoLogo -NoProfile -File $here/scripts/install.ps1")
  check_variants+=("$PWSH -NoLogo -NoProfile -File $here/scripts/check.ps1")
fi

for i in "${!install_variants[@]}"; do
  inst=${install_variants[$i]}
  chk=${check_variants[$i]}
  tag=$([[ $i -eq 0 ]] && echo bash || echo pwsh)

  # Install from the fake release, SHA-256 only.
  # shellcheck disable=SC2086
  run_env "$tag-install" env INPUT_VERSION="$version" INPUT_VERIFY=sha256 \
    INPUT_DOWNLOAD_BASE_URL="file://$rel" INPUT_WORKING_DIRECTORY="$PROJECT" $inst
  expect "$tag: install from a file:// release" 0 $?
  raeva=$(output_of "$tag-install" raeva)
  [[ -x "$raeva" && "$(basename "$raeva")" == raeva ]] && ok "$tag: binary installed as raeva" || bad "$tag: binary installed as raeva"
  [[ ! -e "$(dirname "$raeva")/rv" ]] && ok "$tag: no rv alias by default" || bad "$tag: no rv alias by default"
  # A raeva upgrade starts from an empty store.
  [[ "$(output_of "$tag-install" cache-key)" == "raeva-store-v1-$version-Linux-X64-"* \
    && "$(output_of "$tag-install" cache-restore-key)" == "raeva-store-v1-$version-Linux-X64-" ]] && ok "$tag: cache key" || bad "$tag: cache key"
  has "$scratch/run-$tag-install/output" "$RAEVA_HOME/store" && ok "$tag: cache path follows RAEVA_HOME" || bad "$tag: cache path follows RAEVA_HOME"
  has "$scratch/run-$tag-install/path" "/bin" && ok "$tag: PATH entry" || bad "$tag: PATH entry"

  # The rv alias is opt in.
  # shellcheck disable=SC2086
  run_env "$tag-alias" env INPUT_VERSION="$version" INPUT_VERIFY=sha256 INPUT_RV_ALIAS=true \
    INPUT_DOWNLOAD_BASE_URL="file://$rel" $inst
  [[ -e "$(dirname "$(output_of "$tag-alias" raeva)")/rv" ]] && ok "$tag: rv alias when asked" || bad "$tag: rv alias when asked"

  # A version the archive does not hold.
  # shellcheck disable=SC2086
  run_env "$tag-wrongver" env INPUT_VERSION=9.9.9 INPUT_VERIFY=sha256 INPUT_DOWNLOAD_BASE_URL="file://$rel" $inst
  expect "$tag: refuses a binary of another version" 1 $?
  has "$scratch/run-$tag-wrongver/log" "expected 9.9.9" && ok "$tag: says which version it got" || bad "$tag: says which version it got"

  # Inputs that try to inject.
  # shellcheck disable=SC2086
  run_env "$tag-inject" env 'INPUT_VERSION=0.5.0; touch /tmp/pwned' INPUT_VERIFY=sha256 $inst
  expect "$tag: rejects a version with shell text" 1 $?
  # shellcheck disable=SC2086
  run_env "$tag-noverify" env INPUT_VERSION="$version" INPUT_VERIFY=none $inst
  expect "$tag: rejects verify: none" 1 $?

  # A tampered archive.
  cp -r "$rel" "$scratch/rel-bad-$tag"
  printf 'x' >> "$scratch/rel-bad-$tag/raeva-$target.tar.gz"
  # shellcheck disable=SC2086
  run_env "$tag-tampered" env INPUT_VERSION="$version" INPUT_VERIFY=sha256 INPUT_DOWNLOAD_BASE_URL="file://$scratch/rel-bad-$tag" $inst
  expect "$tag: refuses a tampered archive" 1 $?
  has "$scratch/run-$tag-tampered/log" "sha256.sum says" && ok "$tag: names the checksum mismatch" || bad "$tag: names the checksum mismatch"

  # A failed download names the file and passes on no response text.
  mkdir -p "$scratch/rel-noarchive-$tag"
  cp "$rel/sha256.sum" "$scratch/rel-noarchive-$tag/"
  # shellcheck disable=SC2086
  run_env "$tag-noarchive" env INPUT_VERSION="$version" INPUT_VERIFY=sha256 INPUT_DOWNLOAD_BASE_URL="file://$scratch/rel-noarchive-$tag" $inst
  expect "$tag: fails without the archive" 1 $?
  grep -qx "::error title=setup-raeva::cannot download raeva-$target.tar.gz" "$scratch/run-$tag-noarchive/log" \
    && ok "$tag: names only the missing download" || bad "$tag: names only the missing download"

  # A release with only the archive names of raeva 0.4.
  mkdir -p "$scratch/rel-old-$tag"
  cp "$rel/raeva-$target.tar.gz" "$scratch/rel-old-$tag/rv-cli-$target.tar.gz"
  sed "s/raeva-$target/rv-cli-$target/" "$rel/sha256.sum" > "$scratch/rel-old-$tag/sha256.sum"
  # shellcheck disable=SC2086
  run_env "$tag-old" env INPUT_VERSION="$version" INPUT_VERIFY=sha256 INPUT_DOWNLOAD_BASE_URL="file://$scratch/rel-old-$tag" $inst
  expect "$tag: refuses a release without raeva-<target> archives" 1 $?
  has "$scratch/run-$tag-old/log" "no single entry for raeva-$target.tar.gz" && ok "$tag: names the missing archive" || bad "$tag: names the missing archive"

  # A version this action pins, with the release's checksum and with another.
  sha=$(awk -v a="*raeva-$target.tar.gz" '$2 == a { print $1 }' "$rel/sha256.sum")
  pinned="$scratch/action-pinned-$tag"
  cp -r "$unpinned" "$pinned"
  echo "$version raeva-$target.tar.gz $sha" >> "$pinned/known-checksums.txt"
  # shellcheck disable=SC2086
  ACTION_PATH="$pinned" run_env "$tag-pinned" env INPUT_VERSION="$version" INPUT_VERIFY=sha256 \
    INPUT_DOWNLOAD_BASE_URL="file://$rel" $inst
  expect "$tag: installs a release that matches the pinned checksum" 0 $?
  has "$scratch/run-$tag-pinned/log" "pinned in this action" && ok "$tag: uses the pinned checksum" || bad "$tag: uses the pinned checksum"
  mkdir -p "$scratch/rel-nosum-$tag"
  cp "$rel/raeva-$target.tar.gz" "$scratch/rel-nosum-$tag/"
  # shellcheck disable=SC2086
  ACTION_PATH="$pinned" run_env "$tag-pinned-nosum" env INPUT_VERSION="$version" INPUT_VERIFY=sha256 \
    INPUT_DOWNLOAD_BASE_URL="file://$scratch/rel-nosum-$tag" $inst
  expect "$tag: a pinned version does not download sha256.sum" 0 $?
  echo "$version raeva-$target.tar.gz $sha" >> "$pinned/known-checksums.txt"
  # shellcheck disable=SC2086
  ACTION_PATH="$pinned" run_env "$tag-pin-twice" env INPUT_VERSION="$version" INPUT_VERIFY=sha256 \
    INPUT_DOWNLOAD_BASE_URL="file://$rel" $inst
  expect "$tag: refuses two pins for one archive" 1 $?
  has "$scratch/run-$tag-pin-twice/log" "no single valid entry" && ok "$tag: names the ambiguous pin" || bad "$tag: names the ambiguous pin"
  sed -i '$d' "$pinned/known-checksums.txt"
  sed -i "s/ $sha\$/ $(printf '0%.0s' {1..64})/" "$pinned/known-checksums.txt"
  # shellcheck disable=SC2086
  ACTION_PATH="$pinned" run_env "$tag-pin-mismatch" env INPUT_VERSION="$version" INPUT_VERIFY=sha256 \
    INPUT_DOWNLOAD_BASE_URL="file://$rel" $inst
  expect "$tag: refuses a release that disagrees with the pinned checksum" 1 $?
  has "$scratch/run-$tag-pin-mismatch/log" "but this action pins" && ok "$tag: names the pinned checksum" || bad "$tag: names the pinned checksum"

  # The fake release has no attestation, so attestation mode must refuse it.
  if [[ -n "${GH_TOKEN:-}" ]]; then
    # shellcheck disable=SC2086
    run_env "$tag-noattest" env INPUT_VERSION="$version" INPUT_VERIFY=attestation INPUT_DOWNLOAD_BASE_URL="file://$rel" $inst
    expect "$tag: refuses an archive without an attestation" 1 $?
  fi

  # Frozen check, current lock.
  # shellcheck disable=SC2086
  run_env "$tag-frozen-ok" env RAEVA_BIN="$raeva" INPUT_CHECK=true \
    INPUT_WORKING_DIRECTORY="$PROJECT" $chk scan
  expect "$tag: frozen check passes on a current lock" 0 $?
  [[ "$(output_of "$tag-frozen-ok" frozen-exit-code)" == 0 ]] && ok "$tag: frozen-exit-code 0" || bad "$tag: frozen-exit-code 0"

  # Frozen check, three locked platforms.
  # shellcheck disable=SC2086
  run_env "$tag-frozen-plat" env RAEVA_BIN="$raeva" INPUT_CHECK=true \
    INPUT_PLATFORMS=linux-x86_64,macos-aarch64,windows-x86_64 INPUT_WORKING_DIRECTORY="$PROJECT" $chk scan
  expect "$tag: frozen check of every locked platform" 0 $?

  # Frozen check, a platform the lock lacks.
  # shellcheck disable=SC2086
  run_env "$tag-frozen-missing" env RAEVA_BIN="$raeva" INPUT_CHECK=true \
    INPUT_PLATFORMS=macos-x86_64 INPUT_WORKING_DIRECTORY="$PROJECT" $chk scan
  expect "$tag: frozen check fails on a missing platform" 3 $?
  grep -q "PLATFORM_MISSING" "$scratch/run-$tag-frozen-missing/log" && ok "$tag: annotation names the missing platform" || bad "$tag: annotation names the missing platform"

  # Frozen check after a bot-style POM bump.
  proj="$scratch/project-bumped-$tag"
  cp -r "$PROJECT" "$proj"
  # Change the version on the line after <artifactId>gson</artifactId>, as a
  # Dependabot or Renovate update would.
  sed -i '/<artifactId>gson<\/artifactId>/{n;s|<version>[^<]*</version>|<version>2.13.1</version>|}' "$proj/pom.xml"
  cmp -s "$PROJECT/pom.xml" "$proj/pom.xml" && bad "$tag: test setup changed the POM"
  # shellcheck disable=SC2086
  run_env "$tag-frozen-stale" env RAEVA_BIN="$raeva" INPUT_CHECK=true \
    INPUT_WORKING_DIRECTORY="$proj" $chk scan
  expect "$tag: frozen check fails with 7 after a POM bump" 7 $?
  if grep -q '^::error file=.*title=raeva sync --frozen (exit 7%2C LOCKFILE_MISMATCH)::' "$scratch/run-$tag-frozen-stale/log"; then
    ok "$tag: escaped error annotation"
  else
    bad "$tag: escaped error annotation"
  fi
  has "$scratch/run-$tag-frozen-stale/summary" "failed with exit 7" && ok "$tag: step summary" || bad "$tag: step summary"

  # Report-only on the stale lock: the scan reads the proposed lock, so a
  # stale lock does not fail it, and the committed lock stays.
  cp "$proj/raeva.lock" "$scratch/bumped-before-$tag.lock"
  # shellcheck disable=SC2086
  run_env "$tag-report-vuln" env RAEVA_BIN="$raeva" INPUT_CHECK=true INPUT_CHECK_MODE=report-only \
    INPUT_VULN=true INPUT_VULN_FAIL_ON=never INPUT_WORKING_DIRECTORY="$proj" $chk scan
  expect "$tag: report-only scan of a stale lock" 0 $?
  [[ "$(output_of "$tag-report-vuln" vuln-exit-code)" == 0 ]] && ok "$tag: report-only scan completes" \
    || bad "$tag: report-only scan completes (vuln-exit-code $(output_of "$tag-report-vuln" vuln-exit-code))"
  has "$scratch/run-$tag-report-vuln/summary" 'the scan reads the proposed lock' && ok "$tag: summary names the scanned lock" || bad "$tag: summary names the scanned lock"
  cmp -s "$proj/raeva.lock" "$scratch/bumped-before-$tag.lock" && ok "$tag: report-only scan keeps the committed lock" || bad "$tag: report-only scan keeps the committed lock"

  # The proposed lock resolves the parent POM above the working directory.
  cp -r "$parent" "$scratch/parent-$tag"
  # shellcheck disable=SC2086
  run_env "$tag-report-parent" env RAEVA_BIN="$raeva" INPUT_CHECK=true INPUT_CHECK_MODE=report-only \
    INPUT_WORKING_DIRECTORY="$scratch/parent-$tag/app" $chk scan
  expect "$tag: report-only with a parent POM above the root" 0 $?
  has "$(output_of "$tag-report-parent" proposed-diff)" 'gson .*2.13.2 -> 2.13.1' && ok "$tag: proposed diff from the parent change" || bad "$tag: proposed diff from the parent change"
  cmp -s "$scratch/parent-$tag/app/raeva.lock" "$parent/app/raeva.lock" && ok "$tag: parent case keeps the committed lock" || bad "$tag: parent case keeps the committed lock"

  # Vulnerability scan with findings, gated at high.
  # shellcheck disable=SC2086
  run_env "$tag-vuln" env RAEVA_BIN="$raeva" INPUT_VULN=true INPUT_VULN_FAIL_ON=high \
    INPUT_WORKING_DIRECTORY="$VULN_PROJECT" $chk scan
  expect "$tag: vuln scan step does not fail on findings" 0 $?
  vcode=$(output_of "$tag-vuln" vuln-exit-code)
  sarif=$(output_of "$tag-vuln" sarif-file)
  [[ "$vcode" == 1 ]] && ok "$tag: vuln-exit-code 1" || bad "$tag: vuln-exit-code 1 (got $vcode)"
  [[ -s "$sarif" ]] && ok "$tag: SARIF written" || bad "$tag: SARIF written"
  # The project sits outside the workspace here, so the prefix is absolute;
  # in a workflow it is the relative working-directory.
  if command -v jq >/dev/null && [[ -s "$sarif" ]]; then
    uri=$(jq -r '.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri' "$sarif")
    [[ "$uri" == "$VULN_PROJECT/pom.xml" ]] && ok "$tag: SARIF uri prefixed" || bad "$tag: SARIF uri prefixed ($uri)"
    [[ -n "${SARIF_VALIDATOR:-}" ]] && { $SARIF_VALIDATOR "$sarif" | grep -q '^errors: 0$' && ok "$tag: SARIF still valid" || bad "$tag: SARIF still valid"; }
  fi
  # shellcheck disable=SC2086
  run_env "$tag-gate-high" env VULN_EXIT_CODE="$vcode" INPUT_VULN_FAIL_ON=high $chk gate
  expect "$tag: gate fails on findings" 1 $?
  # shellcheck disable=SC2086
  run_env "$tag-gate-never" env VULN_EXIT_CODE="$vcode" INPUT_VULN_FAIL_ON=never $chk gate
  expect "$tag: gate passes with never" 0 $?
  # shellcheck disable=SC2086
  run_env "$tag-gate-err" env VULN_EXIT_CODE=4 INPUT_VULN_FAIL_ON=never $chk gate
  expect "$tag: gate fails when the scan did not complete" 4 $?
  # With never, raeva itself reports the findings and exits 0.
  # shellcheck disable=SC2086
  run_env "$tag-vuln-never" env RAEVA_BIN="$raeva" INPUT_VULN=true INPUT_VULN_FAIL_ON=never \
    INPUT_WORKING_DIRECTORY="$VULN_PROJECT" $chk scan
  [[ "$(output_of "$tag-vuln-never" vuln-exit-code)" == 0 && "$(output_of "$tag-vuln-never" vuln-findings)" -gt 0 ]] \
    && ok "$tag: raeva vuln --fail-on never reports and exits 0" || bad "$tag: raeva vuln --fail-on never reports and exits 0"
  has "$scratch/run-$tag-vuln-never/summary" '^| Critical | GHSA-' && ok "$tag: findings table from a real scan" || bad "$tag: findings table from a real scan"

  # The CLI's own hints and warnings reach the annotations and the summary.
  # shellcheck disable=SC2086
  run_env "$tag-stub-frozen" env RAEVA_BIN="$stub" INPUT_CHECK=true INPUT_WORKING_DIRECTORY=. $chk scan
  expect "$tag: stub frozen failure keeps its exit code" 7 $?
  log="$scratch/run-$tag-stub-frozen/log"
  has "$log" "Run raeva sync --platforms linux-x86_64 and commit raeva.lock" && ok "$tag: annotation keeps the CLI hint" || bad "$tag: annotation keeps the CLI hint"
  has "$log" "See the error codes" && bad "$tag: no generic hint when the CLI gave one" || ok "$tag: no generic hint when the CLI gave one"
  has "$log" "^::warning title=raeva AUTH_FALLBACK::central refused, mirror served (url=https://mirror.example/); and 1 more" && ok "$tag: one warning annotation per code" || bad "$tag: one warning annotation per code"
  [[ $(grep -c "^::warning title=raeva AUTH_FALLBACK" "$log") -eq 1 ]] && ok "$tag: no repeated warning annotation" || bad "$tag: no repeated warning annotation"
  has "$scratch/run-$tag-stub-frozen/summary" "gson  2.13.2 -> 2.13.1" && ok "$tag: summary lists the change" || bad "$tag: summary lists the change"
  has "$log" "^::warning title=raeva HTTP_REPO_BLOCKED" && bad "$tag: no HTTP_REPO_BLOCKED annotation" || ok "$tag: no HTTP_REPO_BLOCKED annotation"
  has "$scratch/run-$tag-stub-frozen/summary" "HTTP_REPO_BLOCKED http repository in a POM" && ok "$tag: HTTP_REPO_BLOCKED stays in the summary" || bad "$tag: HTTP_REPO_BLOCKED stays in the summary"
  has "$scratch/run-$tag-stub-frozen/summary" "''''" && ok "$tag: summary fence cannot be closed" || bad "$tag: summary fence cannot be closed"
  grep -qx '````text' "$scratch/run-$tag-stub-frozen/summary" && grep -qx '````' "$scratch/run-$tag-stub-frozen/summary" \
    && ok "$tag: summary text sits in a four-backtick fence" || bad "$tag: summary text sits in a four-backtick fence"

  # Each argument reaches raeva as one argument, and the token never does.
  # shellcheck disable=SC1003
  odd='dir with "quotes" and a trailing backslash\'
  # shellcheck disable=SC2086
  run_env "$tag-stub-args" env RAEVA_BIN="$stub" STUB_ARGS="$scratch/args-$tag" GH_TOKEN=not-for-raeva \
    INPUT_CHECK=true INPUT_LOCK_DIFF=false INPUT_WORKING_DIRECTORY="$odd" $chk scan
  [[ "$(sed -n '3p' "$scratch/args-$tag")" == "$odd" && "$(sed -n '4p' "$scratch/args-$tag")" == sync ]] \
    && ok "$tag: working directory passed as one argument" || bad "$tag: working directory passed as one argument"
  has "$scratch/args-$tag" '^GH_TOKEN=unset$' && ok "$tag: raeva does not see the token" || bad "$tag: raeva does not see the token"

  # The settings, profiles and properties inputs reach the frozen check and
  # the scan as one Maven option each, a value starting with ! included.
  maven_args='|--settings=ci settings.xml|--activate-profiles=!slow,ci|--define=a=1|--define=b=two words|'
  # shellcheck disable=SC2086
  run_env "$tag-stub-maven" env RAEVA_BIN="$stub" STUB_ARGS="$scratch/maven-args-$tag" \
    INPUT_CHECK=true INPUT_LOCK_DIFF=false INPUT_SETTINGS='ci settings.xml' INPUT_PROFILES='!slow,ci' \
    INPUT_PROPERTIES=$' a=1\r\n\nb=two words \n' $chk scan
  [[ "$(tr '\n' '|' < "$scratch/maven-args-$tag")" == *"|sync|--frozen$maven_args"* ]] \
    && ok "$tag: Maven options reach the frozen check" || bad "$tag: Maven options reach the frozen check ($(tr '\n' '|' < "$scratch/maven-args-$tag"))"
  # shellcheck disable=SC2086
  run_env "$tag-stub-maven-vuln" env RAEVA_BIN="$stub" STUB_ARGS="$scratch/maven-vuln-$tag" INPUT_VULN=true \
    INPUT_SETTINGS='ci settings.xml' INPUT_PROFILES='!slow,ci' INPUT_PROPERTIES=$'a=1\nb=two words' $chk scan
  [[ "$(tr '\n' '|' < "$scratch/maven-vuln-$tag")" == *"$maven_args"* ]] \
    && ok "$tag: Maven options reach the scan" || bad "$tag: Maven options reach the scan"
  # A raeva that takes them checks the lock against them.
  if "$raeva" --help | grep -q -- --activate-profiles; then
    # shellcheck disable=SC2086
    run_env "$tag-frozen-define" env RAEVA_BIN="$raeva" INPUT_CHECK=true INPUT_LOCK_DIFF=false \
      INPUT_PROPERTIES=setup.raeva.test=1 INPUT_WORKING_DIRECTORY="$PROJECT" $chk scan
    expect "$tag: frozen check ignores an unused -D" 0 $?
    # shellcheck disable=SC2086
    run_env "$tag-frozen-nosettings" env RAEVA_BIN="$raeva" INPUT_CHECK=true INPUT_LOCK_DIFF=false \
      INPUT_SETTINGS="$scratch/no-such-settings.xml" INPUT_WORKING_DIRECTORY="$PROJECT" $chk scan
    expect "$tag: frozen check fails with 3 on a missing settings file" 3 $?
    has "$scratch/run-$tag-frozen-nosettings/log" "settings file does not exist" \
      && ok "$tag: names the missing settings file" || bad "$tag: names the missing settings file"
  fi

  # An incomplete scan keeps its partial SARIF log, under a category per root.
  # shellcheck disable=SC2086
  run_env "$tag-stub-vuln" env RAEVA_BIN="$stub" INPUT_VULN=true INPUT_WORKING_DIRECTORY=sub/dir $chk scan
  expect "$tag: incomplete scan step succeeds so the upload runs" 0 $?
  [[ "$(output_of "$tag-stub-vuln" vuln-exit-code)" == 4 ]] && ok "$tag: incomplete scan exit code kept" || bad "$tag: incomplete scan exit code kept"
  psarif=$(output_of "$tag-stub-vuln" sarif-file)
  [[ -s "$psarif" ]] && ok "$tag: partial SARIF kept" || bad "$tag: partial SARIF kept"
  [[ "$(jq -r '.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri' "$psarif" 2>/dev/null)" == sub/dir/pom.xml ]] && ok "$tag: partial SARIF uri prefixed" || bad "$tag: partial SARIF uri prefixed"
  [[ "$(output_of "$tag-stub-vuln" sarif-category)" == raeva/sub/dir ]] && ok "$tag: category per working directory" || bad "$tag: category per working directory"
  # shellcheck disable=SC2086
  run_env "$tag-stub-cat" env RAEVA_BIN="$stub" INPUT_VULN=true INPUT_SARIF_CATEGORY=mine $chk scan
  [[ "$(output_of "$tag-stub-cat" sarif-category)" == mine ]] && ok "$tag: category input wins" || bad "$tag: category input wins"
  # Each line of the vex input is one --vex, and suppressed results are not
  # findings.
  # shellcheck disable=SC2086
  run_env "$tag-stub-vex" env RAEVA_BIN="$stub" STUB_ARGS="$scratch/vex-args-$tag" INPUT_VULN=true \
    INPUT_VEX=$' vex/a.json\r\n\nvex b.json \n' $chk scan
  expect "$tag: scan with VEX files" 0 $?
  [[ "$(tr '\n' '|' < "$scratch/vex-args-$tag")" == *"|--vex|vex/a.json|--vex|vex b.json|"* ]] \
    && ok "$tag: one --vex per line" || bad "$tag: one --vex per line ($(tr '\n' '|' < "$scratch/vex-args-$tag"))"
  [[ "$(output_of "$tag-stub-vex" vuln-findings)" == 2 ]] && ok "$tag: suppressed results are not findings" || bad "$tag: suppressed results are not findings ($(output_of "$tag-stub-vex" vuln-findings))"
  has "$scratch/run-$tag-stub-vex/summary" "2 finding(s), and 1 suppressed by VEX" && ok "$tag: summary counts suppressed results" || bad "$tag: summary counts suppressed results"
  # The findings table: most severe first, suppressed rows last, and the
  # cells escaped.
  vsum="$scratch/run-$tag-stub-vex/summary"
  grep -qxF '| Severity | Advisory | Dependency | Fixed in | VEX |' "$vsum" && ok "$tag: findings table" || bad "$tag: findings table"
  # shellcheck disable=SC2016
  grep -qxF '| High | GHSA-a | pkg:maven/a/b@1\|\`x\` | 2 |  |' "$vsum" && ok "$tag: table cells escaped" || bad "$tag: table cells escaped ($(grep 'GHSA-a' "$vsum"))"
  [[ "$(grep -o 'GHSA-[abc]' "$vsum" | tr -d '\n')" == GHSA-aGHSA-bGHSA-c ]] && ok "$tag: table order" || bad "$tag: table order ($(grep -o 'GHSA-[abc]' "$vsum" | tr -d '\n'))"
  grep -qxF '| Critical | GHSA-c |  |  | suppressed |' "$vsum" && ok "$tag: suppressed row marked" || bad "$tag: suppressed row marked"
  [[ "$(tr '\n' '|' < "$scratch/vex-args-$tag")" == *"|--fail-on|high|"* ]] && ok "$tag: vuln-fail-on reaches raeva" || bad "$tag: vuln-fail-on reaches raeva"
  [[ -z "$(output_of "$tag-stub-vex" sarif-upload)" ]] && ok "$tag: no upload unless asked" || bad "$tag: no upload unless asked"
  # never reaches raeva as it is, and each invocation keeps its own log.
  shared="$scratch/shared-temp-$tag"
  mkdir -p "$shared"
  # shellcheck disable=SC2086
  run_env "$tag-stub-never" env RAEVA_BIN="$stub" STUB_ARGS="$scratch/never-args-$tag" INPUT_VULN=true \
    INPUT_VULN_FAIL_ON=never INPUT_VEX=v.json RUNNER_TEMP="$shared" $chk scan
  [[ "$(tr '\n' '|' < "$scratch/never-args-$tag")" == *"|--fail-on|never|"* ]] && ok "$tag: never reaches raeva" || bad "$tag: never reaches raeva"
  has "$scratch/run-$tag-stub-never/summary" "findings do not fail the job" && ok "$tag: summary says never does not gate" || bad "$tag: summary says never does not gate"
  # shellcheck disable=SC2086
  run_env "$tag-stub-second" env RAEVA_BIN="$stub" INPUT_VULN=true INPUT_VEX=v.json RUNNER_TEMP="$shared" $chk scan
  first=$(output_of "$tag-stub-never" sarif-file)
  second=$(output_of "$tag-stub-second" sarif-file)
  [[ -s "$first" && -s "$second" && "$first" != "$second" ]] && ok "$tag: one SARIF path per invocation" || bad "$tag: one SARIF path per invocation ($first, $second)"
  # shellcheck disable=SC2086
  run_env "$tag-stub-nolog" env RAEVA_BIN="$stub" STUB_NO_SARIF=1 INPUT_VULN=true $chk scan
  [[ -z "$(output_of "$tag-stub-nolog" sarif-file)" ]] && ok "$tag: no sarif-file without a log" || bad "$tag: no sarif-file without a log"

  if [[ $tag == pwsh ]]; then
    # shellcheck disable=SC2086
    run_env "$tag-diff-only" env RAEVA_BIN="$stub" INPUT_LOCK_DIFF=only $chk scan
    expect "$tag: lock-diff: only fails on Windows" 1 $?
    has "$scratch/run-$tag-diff-only/log" "lock-diff: only runs on Linux and macOS" && ok "$tag: says why lock-diff: only failed" || bad "$tag: says why lock-diff: only failed"
    if [[ -n "$api_port" ]]; then
      # shellcheck disable=SC2086
      run_env "$tag-probe-403" env RAEVA_BIN="$stub" INPUT_VULN=true INPUT_VEX=v.json INPUT_SARIF_UPLOAD=true \
        GITHUB_REPOSITORY=o/r GITHUB_API_URL="http://127.0.0.1:$api_port" UPLOAD_TOKEN=t $chk scan
      expect "$tag: a refused probe does not fail the scan" 0 $?
      [[ -z "$(output_of "$tag-probe-403" sarif-upload)" ]] && ok "$tag: no upload after a 403" || bad "$tag: no upload after a 403"
      [[ $(grep -c '^::notice title=setup-raeva::The SARIF log is not uploaded: code scanning answered HTTP 403 (Advanced Security must be enabled' "$scratch/run-$tag-probe-403/log") -eq 1 ]] \
        && ok "$tag: one notice for a refused upload" || bad "$tag: one notice for a refused upload"
    else
      bad "$tag: local API server did not start"
    fi
  fi
done

# The SARIF upload probe: a 403 skips the upload with one notice, and any
# other answer leaves the upload to try.
printf '{"message":"Advanced Security must be enabled for this repository to use code scanning."}' > "$scratch/403.json"
run_env probe-403 env PATH="$fake_path" STUB_CURL_STATUS=403 STUB_CURL_BODY="$scratch/403.json" STUB_CURL_LOG="$scratch/probe-urls" \
  RAEVA_BIN="$stub" INPUT_VULN=true INPUT_VEX=v.json INPUT_SARIF_UPLOAD=true GITHUB_REPOSITORY=o/r GH_TOKEN=t \
  bash "$here/scripts/check.sh" scan
expect "bash: a refused probe does not fail the scan" 0 $?
[[ -z "$(output_of probe-403 sarif-upload)" ]] && ok "bash: no upload after a 403" || bad "bash: no upload after a 403"
[[ $(grep -c '^::notice title=setup-raeva::The SARIF log is not uploaded: code scanning answered HTTP 403 (Advanced Security must be enabled' "$scratch/run-probe-403/log") -eq 1 ]] \
  && ok "bash: one notice for a refused upload" || bad "bash: one notice for a refused upload"
grep -qxF 'https://api.github.com/repos/o/r/code-scanning/alerts?per_page=1' "$scratch/probe-urls" && ok "bash: the probe asks code scanning" || bad "bash: the probe asks code scanning"
has "$scratch/run-probe-403/summary" '^| High | GHSA-a ' && ok "bash: findings table without an upload" || bad "bash: findings table without an upload"
printf '{"message":"no analysis found"}' > "$scratch/404.json"
run_env probe-404 env PATH="$fake_path" STUB_CURL_STATUS=404 STUB_CURL_BODY="$scratch/404.json" \
  RAEVA_BIN="$stub" INPUT_VULN=true INPUT_VEX=v.json INPUT_SARIF_UPLOAD=true GITHUB_REPOSITORY=o/r GH_TOKEN=t \
  bash "$here/scripts/check.sh" scan
[[ "$(output_of probe-404 sarif-upload)" == true ]] && ok "bash: upload when code scanning has no analysis yet" || bad "bash: upload when code scanning has no analysis yet"
has "$scratch/run-probe-404/log" "::notice" && bad "bash: no notice when the upload can run" || ok "bash: no notice when the upload can run"

# A pull request's lock diff goes to the summary and, in full, to the
# artifact directory.
prdir="$scratch/pr-project"
mkdir -p "$prdir"
printf 'schema_version = 7\n[[platforms]]\ntargets = ["linux-x86_64"]\n' > "$prdir/raeva.lock"
printf 'schema_version = 7\n[[platforms]]\ntargets = ["macos-aarch64"]\n' > "$scratch/base.lock"
base_sha=$(printf '0%.0s' {1..40})
printf '{"pull_request":{"base":{"sha":"%s"},"user":{"login":"dependabot[bot]","type":"Bot"}}}' "$base_sha" > "$scratch/event-bot.json"
printf '{"pull_request":{"base":{"sha":"%s"},"user":{"login":"someone","type":"User"}}}' "$base_sha" > "$scratch/event-user.json"
pr_diff_in() { # <run name> <working directory under $scratch>
  run_env "$1" env -C "$scratch" PATH="$fake_path" STUB_CURL_STATUS=200 STUB_CURL_BODY="$scratch/base.lock" RAEVA_BIN="$stub" \
    GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$scratch/event-user.json" GITHUB_REPOSITORY=o/r \
    INPUT_LOCK_DIFF=only INPUT_WORKING_DIRECTORY="$2" bash "$here/scripts/check.sh" scan
}
pr_diff_in pr-diff pr-project
expect "bash: lock diff of a pull request" 0 $?
ddir=$(output_of pr-diff lock-diff-dir)
[[ $(wc -l < "$ddir/raeva.lock.diff" 2>/dev/null) -eq 50000 ]] && ok "bash: full lock diff in the artifact directory" || bad "bash: full lock diff in the artifact directory"
[[ "$(output_of pr-diff lock-diff-artifact)" =~ ^raeva-lock-diff-pr-project-[0-9a-f]{8}$ ]] \
  && ok "bash: artifact named after the working directory" || bad "bash: artifact named after the working directory ($(output_of pr-diff lock-diff-artifact))"
has "$scratch/run-pr-diff/summary" "the full diff is raeva.lock.diff in the raeva-lock-diff-pr-project-" && ok "bash: summary points to the artifact" || bad "bash: summary points to the artifact"
# Roots whose names map to the same characters keep their own artifacts.
mkdir -p "$scratch/services/api" "$scratch/services-api"
cp "$prdir/raeva.lock" "$scratch/services/api/"
cp "$prdir/raeva.lock" "$scratch/services-api/"
pr_diff_in pr-diff-a services/api
pr_diff_in pr-diff-b services-api
a=$(output_of pr-diff-a lock-diff-artifact)
b=$(output_of pr-diff-b lock-diff-artifact)
[[ -n "$a" && -n "$b" && "$a" != "$b" ]] && ok "bash: services/api and services-api keep their own artifacts" || bad "bash: services/api and services-api keep their own artifacts ($a, $b)"

# The probe asks with the job token, which the upload uses, and a 403 that
# is only about reading alerts leaves the upload to try.
printf '{"message":"Resource not accessible by integration"}' > "$scratch/403-perm.json"
run_env probe-perm env PATH="$fake_path" STUB_CURL_STATUS=403 STUB_CURL_BODY="$scratch/403-perm.json" STUB_CURL_HEADERS="$scratch/probe-headers" \
  RAEVA_BIN="$stub" INPUT_VULN=true INPUT_VEX=v.json INPUT_SARIF_UPLOAD=true GITHUB_REPOSITORY=o/r GH_TOKEN=read-token UPLOAD_TOKEN=job-token \
  bash "$here/scripts/check.sh" scan
[[ "$(output_of probe-perm sarif-upload)" == true ]] && ok "bash: upload after a 403 about alert access" || bad "bash: upload after a 403 about alert access"
grep -qxF 'Authorization: Bearer job-token' "$scratch/probe-headers" && ok "bash: the probe uses the job token" || bad "bash: the probe uses the job token"

# raeva's output reaches the log with workflow commands off.
between() { # <log> <fixed text>: the text sits between stop-commands and its marker
  awk -v text="$2" '
    /^::stop-commands::/ { marker = substr($0, 18); next }
    marker != "" && $0 == "::" marker "::" { marker = ""; next }
    index($0, text) { found = 1; inside = (marker != "") }
    END { exit !(found && inside) }' "$1"
}

# A bot's pull request with a stale lock: the check fails as before, and the
# summary also shows the lock raeva sync would write.
for i in "${!check_variants[@]}"; do
  chk=${check_variants[$i]}
  tag=$([[ $i -eq 0 ]] && echo bash || echo pwsh)
  cp "$prdir/raeva.lock" "$scratch/pr-before.lock"
  : > "$scratch/proposed-args-$tag"
  # shellcheck disable=SC2086
  run_env "$tag-proposed" env -C "$scratch" PATH="$fake_path" STUB_CURL_STATUS=404 RAEVA_BIN="$stub" STUB_ARGS="$scratch/proposed-args-$tag" \
    GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$scratch/event-bot.json" GITHUB_REPOSITORY=o/r INPUT_LOCK_DIFF=false \
    INPUT_CHECK=true INPUT_PROFILES=ci INPUT_SETTINGS=ci.xml INPUT_PROPERTIES="who=O'Brien" INPUT_WORKING_DIRECTORY=pr-project $chk scan
  expect "$tag: a stale bot lock still fails the check" 7 $?
  plog="$scratch/run-$tag-proposed/log"
  psum="$scratch/run-$tag-proposed/summary"
  has "$plog" '^::error file=.*title=raeva sync --frozen (exit 7%2C LOCKFILE_MISMATCH)::' && ok "$tag: the original error stays" || bad "$tag: the original error stays"
  has "$psum" "^### Proposed raeva.lock, not committed" && ok "$tag: proposed lock in the summary" || bad "$tag: proposed lock in the summary"
  [[ $(grep -n 'failed with exit 7' "$psum" | cut -d: -f1) -lt $(grep -n 'Proposed raeva.lock' "$psum" | cut -d: -f1) ]] \
    && ok "$tag: the error comes first" || bad "$tag: the error comes first"
  fix=$(grep '^raeva -C' "$psum")
  if [[ $tag == bash ]]; then
    words=()
    eval "words=($fix)"
    [[ "$(printf '%s|' "${words[@]}")" == "raeva|-C|pr-project|sync|--settings=ci.xml|--activate-profiles=ci|--define=who=<value>|" ]] \
      && ok "$tag: the fixing command" || bad "$tag: the fixing command ($fix)"
  else
    [[ "$fix" == "raeva -C pr-project sync --settings=ci.xml --activate-profiles=ci '--define=who=<value>'" ]] \
      && ok "$tag: the fixing command" || bad "$tag: the fixing command ($fix)"
  fi
  has "$psum" "more lines; the full diff is proposed.diff in the raeva-lock-proposed-pr-project-" && ok "$tag: proposed diff cut, with the artifact named" || bad "$tag: proposed diff cut, with the artifact named"
  [[ "$(output_of "$tag-proposed" proposed-artifact)" =~ ^raeva-lock-proposed-pr-project-[0-9a-f]{8}$ ]] && ok "$tag: proposed artifact name" || bad "$tag: proposed artifact name"
  [[ -z "$(output_of "$tag-proposed" lock-diff-dir)" ]] && ok "$tag: the proposed lock leaves the pull request diff artifact alone" || bad "$tag: the proposed lock leaves the pull request diff artifact alone"
  cmp -s "$prdir/raeva.lock" "$scratch/pr-before.lock" && ok "$tag: the committed lock is untouched" || bad "$tag: the committed lock is untouched"
  pdir=$(output_of "$tag-proposed" proposed-dir)
  [[ $(wc -l < "$pdir/proposed.diff" 2>/dev/null) -eq 50000 ]] && ok "$tag: full proposed diff in the artifact directory" || bad "$tag: full proposed diff in the artifact directory"
  [[ -n "$pdir" && ! -e "$(dirname "$pdir")/committed.lock" ]] && ok "$tag: the committed lock is put back" || bad "$tag: the committed lock is put back"
  [[ "$(tr '\n' '|' < "$scratch/proposed-args-$tag")" == *"|sync|--settings=ci.xml|--activate-profiles=ci|--define=who=O'Brien|--platforms|linux-x86_64|"* ]] \
    && ok "$tag: the proposed lock keeps the recorded platforms and options" || bad "$tag: the proposed lock keeps the recorded platforms and options"
  between "$plog" "::error title=evil::from raeva sync" && ok "$tag: raeva sync output cannot run workflow commands" || bad "$tag: raeva sync output cannot run workflow commands"
  between "$plog" "::error title=evil::from sync --frozen" && ok "$tag: frozen check output cannot run workflow commands" || bad "$tag: frozen check output cannot run workflow commands"
  grep -qx '::endgroup::' "$plog" && ok "$tag: workflow commands resume after output without a newline" || bad "$tag: workflow commands resume after output without a newline"
  # A settings file of the runner is left out of the command, and said so.
  # shellcheck disable=SC2086
  run_env "$tag-proposed-abs" env -C "$scratch" PATH="$fake_path" STUB_CURL_STATUS=404 RAEVA_BIN="$stub" \
    GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$scratch/event-bot.json" GITHUB_REPOSITORY=o/r INPUT_LOCK_DIFF=false \
    INPUT_CHECK=true INPUT_SETTINGS="$scratch/runner-settings.xml" INPUT_WORKING_DIRECTORY=pr-project $chk scan
  grep -qxF "raeva -C pr-project sync" "$scratch/run-$tag-proposed-abs/summary" && ok "$tag: runner settings left out of the command" || bad "$tag: runner settings left out of the command"
  has "$scratch/run-$tag-proposed-abs/summary" "This job reads the settings file" && ok "$tag: the summary names the settings file" || bad "$tag: the summary names the settings file"
  # shellcheck disable=SC2086
  run_env "$tag-proposed-user" env -C "$scratch" PATH="$fake_path" STUB_CURL_STATUS=404 RAEVA_BIN="$stub" \
    GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$scratch/event-user.json" GITHUB_REPOSITORY=o/r INPUT_LOCK_DIFF=false \
    INPUT_CHECK=true INPUT_WORKING_DIRECTORY=pr-project $chk scan
  expect "$tag: a stale lock from a person fails" 7 $?
  has "$scratch/run-$tag-proposed-user/summary" "Proposed raeva.lock" && bad "$tag: no proposed lock for a person's pull request" || ok "$tag: no proposed lock for a person's pull request"
done

# A relock whose lock diff is longer than a pipe buffer still succeeds, with
# the summary cut to 200 lines.
relock_dir="$scratch/relock-long"
mkdir -p "$relock_dir"
printf 'schema_version = 7\n[[platforms]]\ntargets = ["linux-x86_64"]\n' > "$relock_dir/raeva.lock"
run_env relock-long env RAEVA_BIN="$stub" INPUT_WORKING_DIRECTORY="$relock_dir" bash "$here/scripts/check.sh" relock
expect "bash: relock with a long lock diff succeeds" 0 $?
has "$scratch/run-relock-long/summary" "49800 more lines" && ok "bash: long lock diff cut to 200 lines" || bad "bash: long lock diff cut to 200 lines"

# A relock passes the Maven options to raeva sync.
printf 'schema_version = 7\n[[platforms]]\ntargets = ["linux-x86_64"]\n' > "$relock_dir/raeva.lock"
run_env relock-maven env RAEVA_BIN="$stub" STUB_ARGS="$scratch/relock-args" INPUT_WORKING_DIRECTORY="$relock_dir" \
  INPUT_PROFILES=ci INPUT_PROPERTIES=a=1 bash "$here/scripts/check.sh" relock
[[ "$(tr '\n' '|' < "$scratch/relock-args")" == *"|sync|--activate-profiles=ci|--define=a=1|--platforms|linux-x86_64|"* ]] \
  && ok "bash: Maven options reach the relock" || bad "bash: Maven options reach the relock ($(tr '\n' '|' < "$scratch/relock-args"))"

# The real release, with its build attestation and the pinned checksums.
if [[ -n "${GH_TOKEN:-}" && -n "${RELEASE_VERSION:-}" ]]; then
  for i in "${!install_variants[@]}"; do
    inst=${install_variants[$i]}
    tag=$([[ $i -eq 0 ]] && echo bash || echo pwsh)
    # shellcheck disable=SC2086
    ACTION_PATH="$here" run_env "$tag-real" env INPUT_VERSION="$RELEASE_VERSION" INPUT_VERIFY=attestation $inst
    expect "$tag: real release $RELEASE_VERSION with attestation" 0 $?
    has "$scratch/run-$tag-real/log" "pinned in this action" && ok "$tag: pinned checksum used" || bad "$tag: pinned checksum used"
    has "$scratch/run-$tag-real/log" "Build attestation of" && ok "$tag: attestation verified" || bad "$tag: attestation verified"
  done
fi

echo "passed $pass, failed $fail"
[[ $fail -eq 0 ]]
