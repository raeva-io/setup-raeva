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
  env RUNNER_OS=Linux RUNNER_ARCH=X64 RUNNER_TEMP="$dir/temp" \
    GITHUB_OUTPUT="$dir/output" GITHUB_PATH="$dir/path" GITHUB_STEP_SUMMARY="$dir/summary" \
    GITHUB_ACTION_PATH="${ACTION_PATH:-$unpinned}" "$@" > "$dir/log" 2>&1
}
output_of() { sed -n "s/^$2=//p" "$scratch/run-$1/output" | head -n 1; }

# A stand-in for raeva that prints fixed answers: a frozen failure with hints
# and a warning, an incomplete scan with a partial SARIF log, and a long lock
# diff. With STUB_ARGS it records its arguments and whether it saw GH_TOKEN.
stub="$scratch/stub/raeva"
mkdir -p "$scratch/stub"
cat > "$stub" <<'EOF'
#!/usr/bin/env bash
[[ -z "${STUB_ARGS:-}" ]] || { printf '%s\n' "$@" "GH_TOKEN=${GH_TOKEN-unset}" > "$STUB_ARGS"; }
case " $* " in
  *" sync --frozen "*)
    printf '%s\n' '{"success":false,"exit_code":7,"code":"LOCKFILE_MISMATCH","error":"dependencies would change:\n  gson  2.13.2 -> 2.13.1\n  ```` evil","hints":["Run raeva sync --platforms linux-x86_64 and commit raeva.lock"],"data":{"warnings":[{"code":"AUTH_FALLBACK","message":"central refused, mirror served","context":{"url":"https://mirror.example/"}},{"code":"AUTH_FALLBACK","message":"second","context":null}]}}'
    exit 7 ;;
  *" vuln "*" --vex "*)
    # Three results: no suppressions, an empty list, and one VEX suppressed.
    printf '%s\n' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"raeva"}},"results":[{"ruleId":"GHSA-a","message":{"text":"m"}},{"ruleId":"GHSA-b","message":{"text":"m"},"suppressions":[]},{"ruleId":"GHSA-c","message":{"text":"m"},"suppressions":[{"kind":"external","status":"accepted"}]}]}]}'
    exit 0 ;;
  *" vuln "*)
    [[ -n "${STUB_NO_SARIF:-}" ]] && { echo "error: no lock" >&2; exit 3; }
    printf '%s\n' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"raeva"}},"results":[{"ruleId":"GHSA-x","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"pom.xml"}}}]}],"invocations":[{"executionSuccessful":false}]}]}'
    exit 4 ;;
  *" lock diff "*)
    seq 1 50000
    exit 0 ;;
  *" sync "*)
    # A plain sync rewrites the lock in the -C directory.
    while [[ $# -gt 0 && "$1" != -C ]]; do shift; done
    printf '# written again\n' >> "${2:-.}/raeva.lock"
    exit 0 ;;
esac
exit 99
EOF
chmod +x "$stub"

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
  [[ "$(output_of "$tag-install" cache-key)" == raeva-store-v1-Linux-X64-* ]] && ok "$tag: cache key" || bad "$tag: cache key"
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
  has "$scratch/run-$tag-stub-frozen/summary" "''''" && ok "$tag: summary fence cannot be closed" || bad "$tag: summary fence cannot be closed"
  grep -qx '````text' "$scratch/run-$tag-stub-frozen/summary" && grep -qx '````' "$scratch/run-$tag-stub-frozen/summary" \
    && ok "$tag: summary text sits in a four-backtick fence" || bad "$tag: summary text sits in a four-backtick fence"

  # Each argument reaches raeva as one argument, and the token never does.
  odd='dir with "quotes" and a trailing backslash\'
  # shellcheck disable=SC2086
  run_env "$tag-stub-args" env RAEVA_BIN="$stub" STUB_ARGS="$scratch/args-$tag" GH_TOKEN=not-for-raeva \
    INPUT_CHECK=true INPUT_LOCK_DIFF=false INPUT_WORKING_DIRECTORY="$odd" $chk scan
  [[ "$(sed -n '3p' "$scratch/args-$tag")" == "$odd" && "$(sed -n '4p' "$scratch/args-$tag")" == sync ]] \
    && ok "$tag: working directory passed as one argument" || bad "$tag: working directory passed as one argument"
  has "$scratch/args-$tag" '^GH_TOKEN=unset$' && ok "$tag: raeva does not see the token" || bad "$tag: raeva does not see the token"

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
  # shellcheck disable=SC2086
  run_env "$tag-stub-nolog" env RAEVA_BIN="$stub" STUB_NO_SARIF=1 INPUT_VULN=true $chk scan
  [[ -z "$(output_of "$tag-stub-nolog" sarif-file)" ]] && ok "$tag: no sarif-file without a log" || bad "$tag: no sarif-file without a log"
done

# A relock whose lock diff is longer than a pipe buffer still succeeds, with
# the summary cut to 200 lines.
relock_dir="$scratch/relock-long"
mkdir -p "$relock_dir"
printf 'platform = "linux-x86_64"\n' > "$relock_dir/raeva.lock"
run_env relock-long env RAEVA_BIN="$stub" INPUT_WORKING_DIRECTORY="$relock_dir" bash "$here/scripts/check.sh" relock
expect "bash: relock with a long lock diff succeeds" 0 $?
has "$scratch/run-relock-long/summary" "49800 more lines" && ok "bash: long lock diff cut to 200 lines" || bad "bash: long lock diff cut to 200 lines"

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
