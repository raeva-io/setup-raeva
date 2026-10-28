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
    rm -f "$TEST_DIR/scanned.lock"; [[ ! -f "$work/raeva.lock" ]] || cp "$work/raeva.lock" "$TEST_DIR/scanned.lock"
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == --baseline ]]; then
        cmp "$2" "$TEST_DIR/original.lock"
        [[ -z "${BASELINE_INVALID:-}" ]] || exit 3
      fi
      shift
    done
    if [[ -n "${SARIF_TEXT+set}" ]]; then
      printf '%s' "$SARIF_TEXT"
    elif [[ -n "${BASELINE_MARKS:-}" ]]; then
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
if '/git/trees/' in url:
    entry = {'path': 'raeva.lock', 'type': 'blob', 'mode': '100644', 'sha': '3' * 40}
    if case == 'nested' and url.endswith('1'.zfill(40)):
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
    --max-time) timeout="$2"; shift ;;
    -*) ;;
    *) url="$1" ;;
  esac
  shift
done
[[ -n "${timeout:-}" ]] || { echo "request without --max-time" >&2; exit 28; }
reply=$(python3 "$TEST_DIR/api.py" "$url")
printf '%s' "$reply" | jq -r '.Content' > "$dest"
printf '%s' "$reply" | jq -r '.StatusCode'
SH
chmod +x "$t/bin/raeva" "$t/bin/curl"
cat > "$t/check.ps1" <<'PS'
function Invoke-WebRequest {
    param([switch]$UseBasicParsing, [switch]$SkipHttpErrorCheck, $MaximumRedirection, $TimeoutSec, $Uri, $Headers)
    if (-not $TimeoutSec) { throw 'request without -TimeoutSec' }
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

# action.yml reads each output from the Bash step or the PowerShell step of
# the same job, so both must exist and the scripts must write the output.
# Lock diffs and relock are Linux and macOS only.
cat > "$t/steps.py" <<'PY'
import re, sys, yaml
from pathlib import Path
root = Path(sys.argv[1])
action = yaml.safe_load((root / 'action.yml').read_text())
steps = action['runs']['steps']
ids = {s['id'] for s in steps if 'id' in s}
pairs = {'unix': 'windows', 'scan-unix': 'scan-windows'}
pairs.update({w: u for u, w in pairs.items()})
scripts = {'unix': 'install.sh', 'windows': 'install.ps1', 'relock': 'check.sh',
           'scan-unix': 'check.sh', 'scan-windows': 'check.ps1'}
unix_only = {'lock-diff-dir', 'lock-diff-artifact'}
ref = re.compile(r'steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)')
errors = []
def strings(node):
    if isinstance(node, dict):
        for v in node.values():
            yield from strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from strings(v)
    elif isinstance(node, str):
        yield node
windows = {'windows', 'scan-windows'}
def check(text, side):
    for step, name in ref.findall(text):
        if step not in ids:
            errors.append(f'unknown step {step}')
            continue
        if step in scripts:
            src = (root / 'scripts' / scripts[step]).read_text()
            n = re.escape(name)
            if not re.search(rf"\bout {n}\b|Out '{n}'|[\"']{n}<<", src):
                errors.append(f'{scripts[step]} never writes {name}')
        other = pairs.get(step)
        if other and side and (side == 'windows') != (step in windows):
            errors.append(f'a {side} step reads steps.{step}.outputs.{name}')
        if other and not side and name not in unix_only and f'steps.{other}.outputs.{name}' not in text:
            errors.append(f'steps.{step}.outputs.{name} without steps.{other}.outputs.{name}')
for text in strings(action.get('outputs', {})):
    check(text, None)
for s in steps:
    cond = str(s.get('if', ''))
    side = 'windows' if "runner.os == 'Windows'" in cond else 'unix' if (
        "runner.os != 'Windows'" in cond or 'RUNNER_OS' in str(s.get('run', ''))) else None
    for text in strings(s):
        check(text, side)
print('\n'.join(errors))
sys.exit(1 if errors else 0)
PY
python3 -I "$t/steps.py" "$here" > "$t/log" 2>&1 && ok "action outputs read both runner paths" || bad "action outputs read both runner paths"
mkdir -p "$t/broken"
cp -r "$here/scripts" "$t/broken/"
sed 's/ || steps\.scan-windows\.outputs\.sarif-file//' "$here/action.yml" > "$t/broken/action.yml"
python3 -I "$t/steps.py" "$t/broken" > "$t/log" 2>&1 && bad "a Unix-only output is caught" || ok "a Unix-only output is caught"
sed '/sarif_file:/s/ || steps\.scan-windows\.outputs\.sarif-file//' "$here/action.yml" > "$t/broken/action.yml"
python3 -I "$t/steps.py" "$t/broken" > "$t/log" 2>&1 && bad "a Unix-only input of one step is caught" || ok "a Unix-only input of one step is caught"
sed 's/steps\.scan-windows\.outputs\.vuln-exit-code/steps.scan-unix.outputs.vuln-exit-code/' "$here/action.yml" > "$t/broken/action.yml"
python3 -I "$t/steps.py" "$t/broken" > "$t/log" 2>&1 && bad "a Windows step reading the Bash step is caught" || ok "a Windows step reading the Bash step is caught"
sed 's/steps\.windows\.outputs\.version/steps.install-win.outputs.version/' "$here/action.yml" > "$t/broken/action.yml"
python3 -I "$t/steps.py" "$t/broken" > "$t/log" 2>&1 && bad "an unknown step id is caught" || ok "an unknown step id is caught"
# shellcheck disable=SC2016
sed -i 's/Out .vuln-findings. \$count/Out "x" $count/' "$t/broken/scripts/check.ps1"
cp "$here/action.yml" "$t/broken/action.yml"
python3 -I "$t/steps.py" "$t/broken" > "$t/log" 2>&1 && bad "an output no script writes is caught" || ok "an output no script writes is caught"
rm -rf "${t:?}/broken"

# Every tool on PATH but jq.
mkdir -p "$t/nojq"
IFS=: read -ra dirs <<< "$PATH"
for d in "${dirs[@]}"; do
  for f in "$d"/*; do
    [[ -x "$f" && "${f##*/}" != jq && ! -e "$t/nojq/${f##*/}" ]] && ln -s "$f" "$t/nojq/"
  done
done
run env PATH="$t/bin:$t/nojq" INPUT_CHECK=true bash "$here/scripts/check.sh" scan
expect "bash: a scan without jq fails" 2 $?
has "$t/log" 'the check needs jq' && [[ ! -s "$t/args" ]] && ok "bash: says jq is missing and runs nothing" || bad "bash: missing jq"

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
  [[ -z "$(find "$t/temp" -name committed.lock -print)" ]] && ok "$tag: puts the committed lock back" || bad "$tag: committed lock copy remains"
  for code in 3 4; do
    run env INPUT_CHECK=true INPUT_CHECK_MODE=report-only FROZEN_CODE="$code" "${check[@]}" scan
    expect "$tag: report-only preserves check error $code" "$code" $?
  done
  for error in SYNC_CODE DIFF_CODE; do
    run env INPUT_CHECK=true INPUT_CHECK_MODE=report-only "$error=4" "${check[@]}" scan
    expect "$tag: report-only preserves $error" 4 $?
  done
  has "$t/summary" 'gson 2.13.2 -> 2.13.1' && has "$(output proposed-diff)" 'gson 2.13.2 -> 2.13.1' \
    && ok "$tag: a failed lock diff keeps its output" || bad "$tag: a failed lock diff keeps its output"
  run env INPUT_CHECK_MODE=wrong "${check[@]}" scan
  expect "$tag: rejects invalid check-mode" 2 $?
  run env INPUT_CHECK=true INPUT_CHECK_MODE=report-only INPUT_VULN=true SCAN_CODE=4 "${check[@]}" scan
  [[ "$(output vuln-exit-code)" == 4 ]] && ok "$tag: report-only still scans" || bad "$tag: report-only still scans"
  has "$t/scanned.lock" '# proposed' && has "$t/summary" 'the scan reads the proposed lock' \
    && ok "$tag: report-only scans the proposed lock" || bad "$tag: report-only scans the proposed lock"
  cmp -s "$t/project/raeva.lock" "$t/original.lock" && ok "$tag: committed lock is back after the scan" || bad "$tag: committed lock changed by the scan"
  run env INPUT_CHECK=true FROZEN_CODE=0 INPUT_VULN=true "${check[@]}" scan
  ! has "$t/scanned.lock" '# proposed' && ! has "$t/summary" 'proposed lock' \
    && ok "$tag: a current lock is scanned as committed" || bad "$tag: a current lock is scanned as committed"
  run env VULN_EXIT_CODE=4 INPUT_VULN_FAIL_ON=never "${check[@]}" gate
  expect "$tag: report-only scan errors fail at the gate" 4 $?
  # A Windows process that crashes exits with a negative NTSTATUS.
  if run env VULN_EXIT_CODE=-1073741819 INPUT_VULN_FAIL_ON=never "${check[@]}" gate; then
    bad "$tag: a negative scan exit code passed the gate"
  else
    ok "$tag: a negative scan exit code fails at the gate"
  fi
  for text in '' '{}' 'not json'; do
    for code in 0 1; do
      run env INPUT_VULN=true SARIF_TEXT="$text" SCAN_CODE="$code" "${check[@]}" scan
      expect "$tag: a scan that exits $code with SARIF '$text' fails" 2 $?
      has "$t/log" 'the SARIF log is not valid' && [[ -z "$(output sarif-file)" ]] \
        && ok "$tag: no SARIF upload after exit $code with '$text'" || bad "$tag: invalid SARIF after exit $code"
    done
  done
  run env INPUT_VULN=true SARIF_TEXT='' SCAN_CODE=4 "${check[@]}" scan
  expect "$tag: an incomplete scan without a SARIF log reaches the gate" 0 $?
  has "$t/summary" 'wrote no SARIF log' && [[ "$(output vuln-exit-code)" == 4 ]] \
    && ok "$tag: the summary says the scan wrote no SARIF log" || bad "$tag: incomplete scan without a SARIF log"

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

  for case in normal missing; do
    run env -C "$t/project" INPUT_CHECK=true FROZEN_CODE=0 INPUT_LOCK_DIFF=true INPUT_VULN=true \
      INPUT_WORKING_DIRECTORY=. API_CASE="$case" BASELINE_MARKS=1 \
      GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$t/event.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
    expect "$tag: lock diff and baseline with base $case" 0 $?
    ! has "$t/requests" /contents/ && ok "$tag: lock diff reuses the baseline read ($case)" || bad "$tag: lock diff read the base lock again ($case)"
  done
  [[ "$tag" != bash ]] || has "$t/summary" 'This pull request adds' && ok "$tag: lock diff of a base without a lock" || bad "$tag: lock diff of a base without a lock"
  run env -C "$t/project" INPUT_CHECK=true FROZEN_CODE=0 INPUT_LOCK_DIFF=true INPUT_VULN=true \
    INPUT_WORKING_DIRECTORY=. BASELINE_MARKS=1 \
    GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$t/event.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
  [[ "$(output vuln-exit-code)" == 0 ]] && ok "$tag: scan uses validated baseline" || bad "$tag: baseline scan"
  [[ "$tag" != bash ]] || has "$t/summary" '### raeva.lock' && ok "$tag: lock diff against the baseline" || bad "$tag: lock diff against the baseline"
  has "$t/summary" 'Baseline |' && has "$t/summary" 'new |' && has "$t/summary" 'existing |' \
    && has "$t/summary" 'existing | suppressed |' && ok "$tag: summary marks new, existing, and suppressed results" || bad "$tag: baseline summary labels"

  # ./ and a trailing slash name the same root as . and module.
  mkdir -p "$t/project/module"
  cp "$t/original.lock" "$t/project/module/raeva.lock"
  for root in ./ module/; do
    lock="${root%/}/raeva.lock"
    lock="${lock#./}"
    run env -C "$t/project" INPUT_CHECK=true INPUT_WORKING_DIRECTORY="$root" "${check[@]}" scan
    has "$t/log" "::error file=$lock,title=" && ok "$tag: $root annotates $lock" || bad "$tag: $root annotation path"
    api_case=normal
    [[ "$root" == ./ ]] || api_case=nested
    run env -C "$t/project" INPUT_VULN=true INPUT_WORKING_DIRECTORY="$root" API_CASE="$api_case" \
      GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$t/event.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
    has "$t/args" --baseline && ok "$tag: $root reads its baseline" || bad "$tag: $root baseline"
    if [[ "$tag" == bash ]]; then
      run env -C "$t/project" INPUT_CHECK=true FROZEN_CODE=0 INPUT_LOCK_DIFF=true INPUT_WORKING_DIRECTORY="$root" \
        GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$t/event.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
      has "$t/requests" "/contents/$lock?" && has "$t/summary" '### raeva.lock' \
        && ok "$tag: $root diffs $lock" || bad "$tag: $root lock diff"
    fi
  done
  rm -rf "${t:?}/project/module"

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
  has "$t/args" --baseline && has "$t/requests" "git/trees/$(printf '%040d' 1)" \
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
