#!/usr/bin/env bash
# Local checks with fixed CLI and API replies. PWSH enables the same checks
# through PowerShell. No release downloads or advisory service are needed.
# shellcheck disable=SC2015
set -uo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
t=$(mktemp -d "${TMPDIR:-/tmp}/setup-raeva-check.XXXXXX")
trap 'rm -rf "${t:?}"' EXIT
pass=0 fail=0
ok() { pass=$((pass + 1)); echo "PASS $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; cat "$t/log"; }
expect() { [[ "$2" == "$3" ]] && ok "$1" || bad "$1 (exit $3, wanted $2)"; }
has() { grep -qF -- "$2" "$1"; }
output() { sed -n "s/^$1=//p" "$t/output"; }
export HOME="$t/home" RAEVA_HOME="$t/raeva-home"
unset GH_TOKEN UPLOAD_TOKEN GITHUB_EVENT_NAME GITHUB_EVENT_PATH GITHUB_REPOSITORY
mkdir -p "$HOME" "$t/bin" "$t/project" "$t/temp"
printf 'schema_version = 7\n[[platforms]]\ntargets = ["linux-x86_64"]\n' > "$t/project/raeva.lock"
cp "$t/project/raeva.lock" "$t/original.lock"
printf '<project/>\n' > "$t/project/pom.xml"
printf '{"pull_request":{"base":{"sha":"%040d"},"user":{"type":"User"}}}\n' 1 > "$t/event.json"
printf '{"merge_group":{"base_sha":"%040d","head_sha":"%040d"}}\n' 1 5 > "$t/merge-group.json"
printf '{"merge_group":{"base_sha":"not-a-sha"}}\n' > "$t/merge-group-invalid.json"

cat > "$t/bin/raeva" <<'SH'
#!/usr/bin/env bash
set -eu
[[ -z "${GH_TOKEN:-}${UPLOAD_TOKEN:-}" ]]
printf '%s\n' "$@" >> "$TEST_DIR/args"
work=.
while [[ $# -gt 0 ]]; do
  case "$1" in
    -C) work="$2"; shift 2 ;;
    --json|-q) shift ;;
    *) break ;;
  esac
done
case "$1" in
  sync)
    if [[ " $* " == *' --frozen '* ]]; then
      printf '{"code":"LOCKFILE_MISMATCH","error":"stale lock","data":{"warnings":[]}}\n'
      exit "${FROZEN_CODE:-7}"
    fi
    [[ "${SYNC_CODE:-0}" == 0 ]] || exit "$SYNC_CODE"
    printf '# proposed\n' >> "$work/raeva.lock" ;;
  lock)
    printf 'gson 2.13.2 -> 2.13.1\n'
    exit "${DIFF_CODE:-0}" ;;
  vuln)
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == --baseline ]]; then
        cmp "$2" "$TEST_DIR/original.lock"
        [[ -z "${BASELINE_INVALID:-}" ]] || exit 3
      fi
      shift
    done
    if [[ -n "${BASELINE_MARKS:-}" ]]; then
      printf '%s\n' '{"runs":[{"results":[{"ruleId":"CVE-new","baselineState":"new","properties":{"severity":"High"}},{"ruleId":"CVE-existing","baselineState":"unchanged","properties":{"severity":"Critical"}},{"ruleId":"CVE-suppressed","baselineState":"unchanged","properties":{"severity":"High"},"suppressions":[{"kind":"external"}]}]}]}'
    else
      printf '{"runs":[{"results":[]}]}\n'
    fi
    exit "${SCAN_CODE:-0}" ;;
esac
SH

# Both shells use the same replies. The PowerShell wrapper replaces only
# Invoke-WebRequest; the Bash script replaces only curl.
cat > "$t/api.py" <<'PY'
import base64, json, os, sys
from pathlib import Path
url = sys.argv[1]
case = os.getenv('API_CASE', '')
status = int(case) if case.isdigit() else 200
if case == 'transport':
    sys.exit(7)
if '/git/commits/' in url:
    body = {'tree': {'sha': '2' * 40}}
elif '/git/trees/' in url:
    entry = {'path': 'raeva.lock', 'type': 'blob', 'mode': '100644', 'sha': '3' * 40}
    if case == 'nested' and url.endswith('2' * 40):
        entry = {'path': 'module', 'type': 'tree', 'mode': '040000', 'sha': '4' * 40}
    if case == 'symlink':
        entry['mode'] = '120000'
    body = {'tree': [] if case == 'missing' else [entry], 'truncated': case == 'truncated'}
elif '/git/blobs/' in url:
    data = Path(os.environ['TEST_DIR'], 'original.lock').read_bytes()
    body = {'encoding': 'base64', 'content': base64.encodebytes(data).decode()}
    if case == 'malformed':
        body['content'] = '??'
    if case == 'empty':
        body['content'] = ''
    if case == 'blob404':
        status = 404
elif '/contents/' in url:
    body = 'display diff response, never a vulnerability baseline\n'
    if case == 'display500':
        status = 500
else:
    sys.exit('unexpected request')
Path(os.environ['TEST_DIR'], 'requests').open('a').write(url + '\n')
print(json.dumps({'StatusCode': status, 'Content': body if isinstance(body, str) else json.dumps(body)}))
PY
cat > "$t/bin/curl" <<'SH'
#!/usr/bin/env bash
set -eu
cat >/dev/null
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) dest="$2"; shift ;;
    -H|-w|--proto|--retry) shift ;;
    -*) ;;
    *) url="$1" ;;
  esac
  shift
done
reply=$(python3 "$TEST_DIR/api.py" "$url")
printf '%s' "$reply" | jq -r '.Content' > "$dest"
printf '%s' "$reply" | jq -r '.StatusCode'
SH
chmod +x "$t/bin/raeva" "$t/bin/curl"
cat > "$t/check.ps1" <<'PS'
function Invoke-WebRequest {
    param([switch]$UseBasicParsing, [switch]$SkipHttpErrorCheck, $MaximumRedirection, $Uri, $Headers)
    $reply = & python3 "$env:TEST_DIR/api.py" "$Uri"
    if ($LASTEXITCODE -ne 0) { throw 'request failed' }
    $reply | ConvertFrom-Json
}
& "$env:CHECK_SCRIPT" @args
exit $LASTEXITCODE
PS

run() {
  : > "$t/output"; : > "$t/summary"; : > "$t/args"; : > "$t/requests"
  env PATH="$t/bin:$PATH" TEST_DIR="$t" RAEVA_BIN="$t/bin/raeva" \
    INPUT_LOCK_DIFF=false INPUT_WORKING_DIRECTORY="$t/project" \
    RUNNER_TEMP="$t/temp" GITHUB_OUTPUT="$t/output" GITHUB_STEP_SUMMARY="$t/summary" \
    CHECK_SCRIPT="$here/scripts/check.ps1" "$@" > "$t/log" 2>&1
}

variants=(bash)
[[ -z "${PWSH:-}" ]] || variants+=(pwsh)
for tag in "${variants[@]}"; do
  check=(bash "$here/scripts/check.sh")
  [[ "$tag" != pwsh ]] || check=("$PWSH" -NoProfile -File "$t/check.ps1")
  run env INPUT_CHECK=true "${check[@]}" scan
  expect "$tag: blocking is the default" 7 $?
  run env INPUT_CHECK=true INPUT_CHECK_MODE=report-only "${check[@]}" scan
  expect "$tag: report-only passes a stale lock outside a PR" 0 $?
  [[ "$(output frozen-exit-code)" == 7 ]] && ok "$tag: keeps frozen exit code" || bad "$tag: frozen exit code"
  [[ -s "$(output proposed-diff)" ]] && has "$(output proposed-diff)" 'gson 2.13.2 -> 2.13.1' \
    && ok "$tag: proposed diff output" || bad "$tag: proposed diff output"
  has "$t/summary" 'gson 2.13.2 -> 2.13.1' && has "$t/summary" "$(output fix-command)" \
    && ok "$tag: summary has diff and fix command" || bad "$tag: summary has diff and fix command"
  cmp -s "$t/project/raeva.lock" "$t/original.lock" && ok "$tag: committed lock stays unchanged" || bad "$tag: committed lock changed"
  [[ -z "$(find "$t/temp" -type d -name proposed -print)" ]] && ok "$tag: removes proposed copy" || bad "$tag: proposed copy remains"
  for code in 3 4; do
    run env INPUT_CHECK=true INPUT_CHECK_MODE=report-only FROZEN_CODE="$code" "${check[@]}" scan
    expect "$tag: report-only preserves check error $code" "$code" $?
  done
  for error in SYNC_CODE DIFF_CODE; do
    run env INPUT_CHECK=true INPUT_CHECK_MODE=report-only "$error=4" "${check[@]}" scan
    expect "$tag: report-only preserves $error" 4 $?
  done
  run env INPUT_CHECK_MODE=wrong "${check[@]}" scan
  expect "$tag: rejects invalid check-mode" 2 $?
  run env INPUT_CHECK=true INPUT_CHECK_MODE=report-only INPUT_VULN=true SCAN_CODE=4 "${check[@]}" scan
  [[ "$(output vuln-exit-code)" == 4 ]] && ok "$tag: report-only still scans" || bad "$tag: report-only still scans"
  run env VULN_EXIT_CODE=4 INPUT_VULN_FAIL_ON=never "${check[@]}" gate
  expect "$tag: report-only scan errors fail at the gate" 4 $?

  # The JDK suffix belongs to the lock and config, never to --platforms.
  cp "$t/original.lock" "$t/saved.lock"
  sed 's/^conflict //' > "$t/project/raeva.lock" <<'LOCK'
schema_version = 7
conflict <<<<<<< ours
[[platforms]]
targets = ["linux-x86_64@17", "macos-aarch64@21"]
conflict =======
[[platforms]]
targets = [
  "macos-aarch64@17",
  "linux-x86_64@21",
]
conflict >>>>>>> theirs
[[inputs]]
target = "windows-x86_64@21"
[[inputs]]
target = "linux-x86_64@17"
LOCK
  run env INPUT_CHECK=true INPUT_CHECK_MODE=report-only INPUT_PROPERTIES=token=private-test-value "${check[@]}" scan
  expect "$tag: proposes a conflicted schema lock" 0 $?
  has "$t/args" 'linux-x86_64,macos-aarch64,windows-x86_64' \
    && ok "$tag: arrays and input targets keep every OS/architecture pair" || bad "$tag: schema platforms"
  ! grep -q '@' "$t/args" && ok "$tag: never passes JDK suffixes to --platforms" || bad "$tag: JDK suffix in CLI platforms"
  has "$t/args" '--define=token=private-test-value' && ! has "$t/summary" private-test-value \
    && ! has "$t/output" private-test-value && ! has "$t/log" private-test-value \
    && has "$t/summary" 'token=' && has "$t/summary" value && ok "$tag: fix command hides property values but sync receives them" || bad "$tag: property values"
  run env INPUT_CHECK=true INPUT_CHECK_MODE=report-only INPUT_PLATFORMS=macos-aarch64 "${check[@]}" scan
  expect "$tag: explicit platforms override recorded targets" 0 $?
  ! has "$t/args" 'linux-x86_64,macos-aarch64,windows-x86_64' \
    && has "$t/args" macos-aarch64 && ok "$tag: override reaches sync" || bad "$tag: explicit platform arguments"
  if [[ "$tag" == bash ]]; then
    run env INPUT_PROPERTIES=token=private-test-value "${check[@]}" relock
    expect "$tag: relock accepts conflicted target text" 0 $?
    ! has "$t/log" private-test-value && ok "$tag: relock does not echo property values" || bad "$tag: relock echoed property values"
  fi
  cp "$t/saved.lock" "$t/project/raeva.lock"

  for response in display display500; do
    run env -C "$t/project" INPUT_CHECK=true FROZEN_CODE=0 INPUT_LOCK_DIFF=true INPUT_VULN=true \
      INPUT_WORKING_DIRECTORY=. API_CASE="$response" BASELINE_MARKS=1 \
      GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$t/event.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
    expect "$tag: display diff $response leaves the baseline intact" 0 $?
    [[ "$(output vuln-exit-code)" == 0 ]] && ok "$tag: scan uses validated baseline after $response" || bad "$tag: overwritten baseline"
    has "$t/summary" 'Baseline |' && has "$t/summary" 'new |' && has "$t/summary" 'existing |' \
      && has "$t/summary" 'existing | suppressed |' && ok "$tag: summary marks new, existing, and suppressed results" || bad "$tag: baseline summary labels"
  done

  for root in . module; do
    api_case=normal
    [[ "$root" != module ]] || api_case=nested
    run env INPUT_VULN=true INPUT_WORKING_DIRECTORY="$root" API_CASE="$api_case" \
      GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$t/event.json" GITHUB_REPOSITORY=o/r \
      GH_TOKEN=not-a-secret "${check[@]}" scan
    expect "$tag: reads $root baseline" 0 $?
    has "$t/args" --baseline && has "$t/args" high && ! has "$t/args" never \
      && ok "$tag: $root baseline and threshold reach CLI" || bad "$tag: $root baseline arguments"
  done
  run env INPUT_VULN=true INPUT_WORKING_DIRECTORY=. \
    GITHUB_EVENT_NAME=merge_group GITHUB_EVENT_PATH="$t/merge-group.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
  expect "$tag: reads the merge group baseline" 0 $?
  has "$t/args" --baseline && has "$t/requests" "git/commits/$(printf '%040d' 1)" \
    && ok "$tag: merge group compares with its base commit" || bad "$tag: merge group baseline"
  run env INPUT_VULN=true INPUT_WORKING_DIRECTORY=. API_CASE=missing \
    GITHUB_EVENT_NAME=merge_group GITHUB_EVENT_PATH="$t/merge-group.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
  has "$t/args" never && ! has "$t/args" --baseline \
    && ok "$tag: merge group base without a lock reports only" || bad "$tag: merge group absent lock"
  run env INPUT_VULN=true INPUT_WORKING_DIRECTORY=. \
    GITHUB_EVENT_NAME=merge_group GITHUB_EVENT_PATH="$t/merge-group-invalid.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
  expect "$tag: invalid merge group base SHA fails" 2 $?
  [[ ! -s "$t/args" && ! -s "$t/requests" ]] && ok "$tag: invalid merge group base is never fetched or scanned" || bad "$tag: invalid merge group base"
  run env INPUT_VULN=true INPUT_WORKING_DIRECTORY=. API_CASE=missing SCAN_CODE=4 \
    GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$t/event.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
  expect "$tag: missing baseline permits scan upload" 0 $?
  has "$t/args" never && ! has "$t/args" --baseline && has "$t/summary" 'base commit has no' \
    && [[ "$(output vuln-exit-code)" == 4 ]] && ok "$tag: absent lock reports only and keeps scan errors" || bad "$tag: absent lock"
  for error in 403 404 500 transport malformed empty truncated symlink blob404; do
    run env INPUT_VULN=true INPUT_WORKING_DIRECTORY=. API_CASE="$error" \
      GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$t/event.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
    expect "$tag: baseline $error fails" 2 $?
    [[ ! -s "$t/args" ]] && ok "$tag: baseline $error never scans without a baseline" || bad "$tag: baseline $error scanned"
  done
  run env INPUT_VULN=true INPUT_WORKING_DIRECTORY=. BASELINE_INVALID=1 \
    GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$t/event.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
  [[ "$(output vuln-exit-code)" == 3 ]] && ok "$tag: invalid lock remains a scan error" || bad "$tag: invalid baseline lock"
  run env INPUT_VULN=true "${check[@]}" scan
  [[ ! -s "$t/requests" ]] && ! has "$t/args" --baseline && ok "$tag: non-PR scan has no baseline" || bad "$tag: non-PR baseline"
done
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
