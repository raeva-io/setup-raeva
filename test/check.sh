#!/usr/bin/env bash
# Local checks with fixed CLI and API replies. PWSH enables the same checks
# through PowerShell. No release downloads or advisory service are needed.
# Backticks in single quotes are literal Markdown.
# shellcheck disable=SC2015,SC2016
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
      if [[ -n "${FROZEN_JSON+set}" ]]; then
        printf '%s' "$FROZEN_JSON"
      else
        printf '{"code":"LOCKFILE_MISMATCH","error":"stale lock","data":{"warnings":[]}}\n'
      fi
      [[ -z "${FROZEN_STDERR:-}" ]] || printf '%s' "$FROZEN_STDERR" >&2
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
    [[ -z "${VULN_STDERR:-}" ]] || printf '%s' "$VULN_STDERR" >&2
    # More than a pipe buffer of error lines after the first.
    [[ -z "${VULN_STDERR_LONG:-}" ]] || printf 'error: first\nerror: %0200000d\nerror: %0200000d\n' 0 0 >&2
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
    if case == 'nosha':
        del entry['sha']
    body = {'tree': [] if case == 'missing' else [entry], 'truncated': case == 'truncated'}
    if case == 'garbage':
        body['tree'] = ['garbage']
    if case == 'notjson':
        body = 'not json'
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
elif '/code-scanning/alerts' in url:
    status = int(os.getenv('CS_STATUS', '200'))
    body = json.loads(os.getenv('CS_BODY') or json.dumps({'message': os.getenv('CS_MESSAGE', '')})) if status != 200 else []
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
    param([switch]$UseBasicParsing, [switch]$SkipHttpErrorCheck, $MaximumRedirection, $ConnectionTimeoutSeconds, $OperationTimeoutSeconds, $Uri, $Headers)
    # The connection timeout ends at the headers; a stalled body needs its own.
    if (-not $ConnectionTimeoutSeconds -or -not $OperationTimeoutSeconds) { throw 'request without both timeouts' }
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
sed -i 's/Out .vuln-findings. \$count/Out "x" $count/' "$t/broken/scripts/check.ps1"
cp "$here/action.yml" "$t/broken/action.yml"
python3 -I "$t/steps.py" "$t/broken" > "$t/log" 2>&1 && bad "an output no script writes is caught" || ok "an output no script writes is caught"
rm -rf "${t:?}/broken"

# Every example pins setup-raeva the same way, and every other action by a
# commit SHA with its version in a comment. The README's Renovate manager
# finds the version input of each setup-raeva step.
cat > "$t/pins.py" <<'PY'
import json, re, sys
from pathlib import Path
root = Path(sys.argv[1])
files = [root / 'README.md', root / 'action.yml', *sorted((root / 'examples').glob('*.yml'))]
readme = (root / 'README.md').read_text()
manager = json.loads(readme.split('```json\n')[1].split('```')[0])['customManagers'][0]
version = re.compile(manager['matchStrings'][0].replace('(?<', '(?P<'))
errors, own = [], set()
for f in files:
    text = f.read_text()
    steps = 0
    for name, ref in re.findall(r'(?m)^[ -]*uses: ([^@\s]+)@(.*)$', text):
        if name == 'raeva-io/setup-raeva':
            own.add(ref)
            steps += 1
        elif not re.fullmatch(r'[0-9a-f]{40} # v\d+(\.\d+)*', ref):
            errors.append(f'{f.name}: {name}@{ref} is not pinned by SHA')
    found = [m['currentValue'] for m in version.finditer(text)]
    if found != ['0.5.3'] * steps:
        errors.append(f'{f.name}: the Renovate manager finds {found} in {steps} steps')
if len(own) != 1 or not re.fullmatch(r'v\d+\.\d+\.\d+|(?!0{40})[0-9a-f]{40} # v\d+\.\d+\.\d+', next(iter(own))):
    errors.append(f'setup-raeva refs: {sorted(own)}')
print('\n'.join(errors))
sys.exit(1 if errors else 0)
PY
python3 -I "$t/pins.py" "$here" > "$t/log" 2>&1 && ok "examples pin actions and the Renovate manager finds every version" || bad "action pins"

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
  # A blocking check on a person's pull request writes no proposed lock, and
  # still names the command with this job's options.
  run env INPUT_CHECK=true INPUT_PROFILES=ci INPUT_PROPERTIES=token=private-test-value \
    GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$t/event.json" "${check[@]}" scan
  expect "$tag: a stale lock fails a person's pull request" 7 $?
  fix=$(output fix-command)
  [[ "$fix" == *' sync --activate-profiles=ci '*token=* && "$fix" != *private-test-value* ]] \
    && ok "$tag: a blocking stale lock sets fix-command" || bad "$tag: blocking fix-command is '$fix'"
  grep '^::error file=' "$t/log" | grep -qF "%0AWith this job's options: $fix" \
    && ok "$tag: the annotation names the fix command" || bad "$tag: the annotation names the fix command"
  has "$t/summary" "$fix" && has "$t/summary" 'Replace each `<value>`' && ! has "$t/summary" 'Proposed raeva.lock' \
    && ! has "$t/summary" private-test-value && ok "$tag: the summary names the fix command without a proposed lock" \
    || bad "$tag: blocking summary fix command"
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
  for text in '' '{}' 'not json' '{"runs":null}' '{"runs":{}}'; do
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
  [[ -z "$(output vuln-error)" ]] && ok "$tag: no reason without raeva's error line" || bad "$tag: reason without an error line"
  # The gate names raeva's reason, not only the exit code.
  run env INPUT_VULN=true SARIF_TEXT='' SCAN_CODE=3 \
    VULN_STDERR=$'warning: W: first\nerror: lockfile not found: raeva.lock\r\n\n  Suggestions:\nerror: second\n' "${check[@]}" scan
  expect "$tag: an incomplete scan with an error line reaches the gate" 0 $?
  [[ "$(output vuln-error)" == 'lockfile not found: raeva.lock' ]] \
    && ok "$tag: an incomplete scan keeps raeva's first error line" || bad "$tag: vuln-error is '$(output vuln-error)'"
  run env INPUT_VULN=true SARIF_TEXT='' SCAN_CODE=3 VULN_STDERR_LONG=1 "${check[@]}" scan
  expect "$tag: many long error lines still reach the gate" 0 $?
  [[ "$(output vuln-error)" == first && "$(output vuln-exit-code)" == 3 ]] \
    && ok "$tag: many long error lines keep the first reason" || bad "$tag: many long error lines keep the first reason"
  run env INPUT_VULN=true SARIF_TEXT='' SCAN_CODE=3 VULN_STDERR="error: $(printf '%0400d' 0)"$'\n' "${check[@]}" scan
  [[ "$(output vuln-error)" == "$(printf '%0300d' 0)" ]] \
    && ok "$tag: a long reason is cut to 300 characters" || bad "$tag: a long reason is cut to 300 characters"
  run env INPUT_VULN=true SARIF_TEXT='' SCAN_CODE=3 VULN_STDERR=$'error: \r\nerror: later\n' "${check[@]}" scan
  ! grep -q '^vuln-error' "$t/output" && ok "$tag: an empty first error line gives no reason" || bad "$tag: an empty first error line gives no reason"
  run env VULN_EXIT_CODE=3 VULN_ERROR='lockfile not found: raeva.lock' INPUT_VULN_FAIL_ON=high "${check[@]}" gate
  expect "$tag: the gate keeps the scan exit code" 3 $?
  has "$t/log" '::error title=raeva vuln::the scan did not complete (exit 3): lockfile not found: raeva.lock' \
    && ok "$tag: the gate annotation names raeva's reason" || bad "$tag: the gate annotation names raeva's reason"
  run env VULN_EXIT_CODE=3 VULN_ERROR=$'a%b\n::warning::c' INPUT_VULN_FAIL_ON=high "${check[@]}" gate
  has "$t/log" 'did not complete (exit 3): a%25b%0A::warning::c' && ! grep -q '^::warning::c' "$t/log" \
    && ok "$tag: the reason cannot start a workflow command" || bad "$tag: the reason cannot start a workflow command"
  run env VULN_EXIT_CODE=3 INPUT_VULN_FAIL_ON=high "${check[@]}" gate
  has "$t/log" 'the scan did not complete (exit 3); see the step log' \
    && ok "$tag: without a reason the gate points to the step log" || bad "$tag: gate without a reason"

  # The step says what runs before raeva's buffered output, and what passed.
  for case in '25349 25.3' '25350 25.4' '49 0.0'; do
    read -r ms seconds <<< "$case"
    run env INPUT_CHECK=true INPUT_VULN=true FROZEN_CODE=0 \
      FROZEN_JSON="{\"data\":{\"resolved\":727,\"platforms\":[\"linux-x86_64\",\"x\\n::error::y\",\"www.example.com\"],\"duration_ms\":$ms,\"warnings\":[]}}" "${check[@]}" scan
    expect "$tag: a current lock passes ($ms ms)" 0 $?
    line="raeva.lock is current (727 dependencies; linux-x86_64, www.example.com; $seconds s)"
    has "$t/log" "$line" && has "$t/summary" "\`raeva.lock\` is current (727 dependencies; \`linux-x86_64\`, \`www.example.com\`; $seconds s)." \
      && ok "$tag: success names the platforms and the time ($ms ms)" || bad "$tag: success line ($ms ms)"
  done
  [[ "$(head -n 1 "$t/log")" == 'Checking raeva.lock with raeva sync --frozen; its output follows when it exits.' ]] \
    && has "$t/log" 'Scanning raeva.lock with raeva vuln; its output follows when it exits.' \
    && ok "$tag: says what runs before the output" || bad "$tag: no line before the run"

  # Report-only warns on a missing lock, so the workflow can come first.
  missing='{"code":"LOCKFILE_MISSING","error":"lockfile not found: /w/raeva.lock"}'
  run env INPUT_CHECK=true INPUT_CHECK_MODE=report-only FROZEN_CODE=3 FROZEN_JSON="$missing" "${check[@]}" scan
  expect "$tag: report-only passes without a lock" 0 $?
  grep -q '^::warning file=.*,title=raeva sync --frozen (exit 3%2C LOCKFILE_MISSING)::' "$t/log" && ! has "$t/log" '::error' \
    && has "$t/summary" 'a missing lock does not fail this job' && ok "$tag: report-only warns on a missing lock" || bad "$tag: report-only missing lock"
  run env INPUT_CHECK=true INPUT_CHECK_MODE=report-only INPUT_VULN=true SCAN_CODE=3 FROZEN_CODE=3 FROZEN_JSON="$missing" "${check[@]}" scan
  expect "$tag: report-only without a lock still scans" 0 $?
  code=$(output vuln-exit-code)
  run env VULN_EXIT_CODE="$code" INPUT_VULN_FAIL_ON=high "${check[@]}" gate
  expect "$tag: a scan without a lock still fails at the gate" 3 $?
  run env INPUT_CHECK=true FROZEN_CODE=3 FROZEN_JSON="$missing" "${check[@]}" scan
  expect "$tag: blocking fails without a lock" 3 $?
  [[ -z "$(output fix-command)" ]] && ! has "$t/log" "this job's options" \
    && ok "$tag: only a stale lock gets the fix command" || bad "$tag: fix command for a missing lock"

  # Pin refusals need investigation before a lock is written again.
  pin_note="raeva.lock pins other bytes than a repository served. Find out why before relocking; raeva's hint says how."
  for refused in \
    '{"code":"CHECKSUM_MISMATCH","error":"downloaded bytes do not match their checksums in raeva.lock","hints":["Check the repository.","Ask why the bytes changed. Then run raeva sync --update."]}' \
    '{"code":"LOCKFILE_MISMATCH","error":"fetched bytes do not match their checksums in raeva.lock"}' \
    '{"code":"LOCKFILE_MISMATCH","error":"locked bytes differ","hints":["Check the repository.","Ask why the bytes changed. Then run raeva sync --update."]}'; do
    for check_mode in blocking report-only; do
      want=7
      [[ "$check_mode" != report-only ]] || want=0
      run env INPUT_CHECK=true INPUT_CHECK_MODE="$check_mode" FROZEN_JSON="$refused" "${check[@]}" scan
      expect "$tag: a pin refusal keeps $check_mode behavior" "$want" $?
      ! has "$t/output" 'fix-command=' && ! has "$t/summary" 'To fix it' \
        && ! has "$t/summary" 'Proposed raeva.lock' \
        && ! has "$t/log" "With this job's options:" && has "$t/summary" "$pin_note" \
        && ok "$tag: a pin refusal gives no plain sync fix" || bad "$tag: pin refusal fix"
      if [[ "$refused" == *hints* ]]; then
        has "$t/summary" 'Check the repository.' && has "$t/summary" 'Then run raeva sync --update.' \
          && has "$t/log" 'Check the repository.%0AAsk why the bytes changed. Then run raeva sync --update.' \
          && ok "$tag: a pin refusal keeps every hint" || bad "$tag: pin refusal hints"
      else
        ! has "$t/summary" "Run 'raeva sync'" && ! has "$t/log" "Run 'raeva sync'" \
          && ok "$tag: a pin refusal without hints gets no plain sync advice" || bad "$tag: pin refusal fallback hint"
      fi
    done
  done
  for stale in \
    '{"code":"LOCKFILE_MISMATCH","error":"stale lock","hints":["Run raeva sync."]}' \
    '{"code":"LOCKFILE_MISMATCH","error":"unpinned row","hints":["Run raeva sync --update to resolve again."]}' \
    '{"code":"PLATFORM_MISSING","error":"platform missing","hints":["Run raeva sync --update."]}'; do
    run env INPUT_CHECK=true FROZEN_JSON="$stale" "${check[@]}" scan
    expect "$tag: other exit-7 errors still fail" 7 $?
    [[ -n "$(output fix-command)" ]] && has "$t/summary" 'To fix it' && ! has "$t/summary" "$pin_note" \
      && ok "$tag: other exit-7 errors keep the sync fix" || bad "$tag: other exit-7 fix"
  done
  run env INPUT_CHECK=true FROZEN_CODE=4 FROZEN_JSON="$refused" "${check[@]}" scan
  expect "$tag: pin advice applies only to exit 7" 4 $?
  ! has "$t/summary" "$pin_note" && ok "$tag: other exits keep their advice" || bad "$tag: pin advice on another exit"

  # A crash, a kill, or a binary that cannot load writes no JSON envelope.
  # $(...) drops trailing newlines, so the blank lines that end the output
  # are added after it.
  crash=$(for i in $(seq 1 23); do echo "line $i"; done; printf '::error::not a command\r\nthread main panicked: boom')$'\n\n\n'
  run env INPUT_CHECK=true FROZEN_CODE=101 FROZEN_JSON='' FROZEN_STDERR="$crash" "${check[@]}" scan
  expect "$tag: a crash keeps its exit code" 101 $?
  annotation=$(grep '^::error file=' "$t/log")
  [[ "$annotation" == *'line 6%0A'* && "$annotation" != *'line 5%0A'* && "$annotation" == *'boom'* \
    && "$annotation" == *'%0A::error::not a command%0A'* && "$annotation" == *'step log'* \
    && $(grep -c '^::error file=' "$t/log") == 1 ]] \
    && ok "$tag: a crash annotates the last 20 lines of stderr" || bad "$tag: crash annotation"
  has "$t/summary" 'line 6' && ! has "$t/summary" 'line 5' && has "$t/summary" 'boom' \
    && ok "$tag: the summary has the end of stderr" || bad "$tag: crash summary"
  run env INPUT_CHECK=true FROZEN_CODE=137 FROZEN_JSON='' "${check[@]}" scan
  expect "$tag: a silent kill keeps its exit code" 137 $?
  has "$t/log" 'no JSON error and no output' && ok "$tag: a silent kill says so" || bad "$tag: silent kill"

  # A lock that a newer raeva wrote needs a newer version input.
  for message in 'raeva.lock has schema version 8, which a newer raeva wrote; this raeva reads schema 7' \
    'failed to parse lockfile /w/schema/raeva.lock: unclosed array'; do
    run env INPUT_CHECK=true FROZEN_CODE=3 FROZEN_JSON="{\"code\":\"LOCKFILE_INVALID\",\"error\":\"$message\",\"hints\":[\"Upgrade raeva.\"]}" "${check[@]}" scan
    expect "$tag: an invalid lock fails" 3 $?
    if [[ "$message" == *'schema version'* ]]; then
      grep '^::error file=' "$t/log" | grep -qF '%0AIf a newer raeva wrote raeva.lock, raise the `version` input to that release.%0AUpgrade raeva.' \
        && has "$t/summary" 'raise the `version` input' && ok "$tag: a newer schema asks for a newer version input" || bad "$tag: schema hint"
    else
      ! has "$t/log" 'raise the `version` input' && ok "$tag: other invalid locks keep raeva's hints" || bad "$tag: schema hint on a parse error"
    fi
  done

  # Warnings a maintainer cannot act on are listed in the summary only.
  warned='{"data":{"resolved":2,"warnings":[{"code":"TRANSITIVE_REPO_DROPPED","message":"dropped","context":null},{"code":"WEAK_HASH_FALLBACK","message":"sha1 only","context":null},{"code":"HTTP_REPO_BLOCKED","message":"http repo","context":null},{"code":"JAVA_VERSION_DEFAULTED","message":"java 17","context":null}]}}'
  run env INPUT_CHECK=true FROZEN_CODE=0 FROZEN_JSON="$warned" "${check[@]}" scan
  expect "$tag: a current lock with warnings passes" 0 $?
  has "$t/log" '::warning title=raeva JAVA_VERSION_DEFAULTED::java 17' && ! has "$t/log" 'title=raeva TRANSITIVE_REPO_DROPPED' \
    && ! has "$t/log" 'title=raeva WEAK_HASH_FALLBACK' && ! has "$t/log" 'title=raeva HTTP_REPO_BLOCKED' \
    && ok "$tag: only actionable warnings become annotations" || bad "$tag: warning annotations"
  has "$t/summary" 'TRANSITIVE_REPO_DROPPED dropped' && has "$t/summary" 'WEAK_HASH_FALLBACK sha1 only' \
    && has "$t/summary" 'HTTP_REPO_BLOCKED http repo' && has "$t/summary" 'JAVA_VERSION_DEFAULTED java 17' \
    && ok "$tag: the summary lists every warning" || bad "$tag: summary warnings"
  run env INPUT_CHECK=true FROZEN_CODE=0 FROZEN_JSON='{"data":{"warnings":[{"code":"HTTP_REPO_BLOCKED","message":"x\nJAVA_VERSION_DEFAULTED\tforged","context":{"url":"a\tb\nc"}}]}}' "${check[@]}" scan
  ! grep -q '^::warning' "$t/log" && has "$t/summary" 'HTTP_REPO_BLOCKED x JAVA_VERSION_DEFAULTED forged (url=a b c)' \
    && ok "$tag: a warning stays one line" || bad "$tag: a multi-line warning"

  # Each fallback warning stands for one skipped and serving pair, which its
  # context names even where the messages read the same.
  for wcode in REPOSITORY_FALLBACK AUTH_FALLBACK; do
    warned=$(jq -n --arg code "$wcode" '{code:"LOCKFILE_MISMATCH",error:"stale lock",data:{warnings:[
      {code:$code,message:"Skipped a; serving from b",context:{artifact:"one"}},
      {code:$code,message:"Skipped a; serving from c",context:null},
      {code:$code,message:"Skipped a; serving from b",context:{artifact:"two"}},
      {code:$code,message:"skipped a; serving from b",context:null},
      {code:$code,message:"Skipped a; serving from b\u00ad",context:null},
      {code:"JAVA_VERSION_DEFAULTED",message:"java 17",context:{module:"one"}},
      {code:"JAVA_VERSION_DEFAULTED",message:"java 21",context:null}
    ]}}')
    for code in 0 7; do
      run env INPUT_CHECK=true FROZEN_CODE="$code" FROZEN_JSON="$warned" "${check[@]}" scan
      expect "$tag: fallback warnings keep exit $code" "$code" $?
      [[ $(grep -c "^::warning title=raeva $wcode::" "$t/log") == 5 \
        && $(grep -c "^$wcode " "$t/summary") == 5 ]] \
        && ok "$tag: $wcode keeps five distinct pairs" || bad "$tag: $wcode distinct pairs"
      for message in 'Skipped a; serving from b (artifact=one)' 'Skipped a; serving from b (artifact=two)' \
        'Skipped a; serving from c' \
        'skipped a; serving from b' $'Skipped a; serving from b\u00ad'; do
        [[ $(grep -cFx "::warning title=raeva $wcode::$message" "$t/log") == 1 \
          && $(grep -cFx "$wcode $message" "$t/summary") == 1 ]] \
          && ok "$tag: $wcode lists $message once" || bad "$tag: $wcode message $message"
      done
      grouped='java 17 (module=one); and 1 more (raeva --json sync --frozen lists them)'
      has "$t/log" "::warning title=raeva JAVA_VERSION_DEFAULTED::$grouped" \
        && has "$t/summary" "JAVA_VERSION_DEFAULTED $grouped" \
        && ! has "$t/summary" 'java 21' && ok "$tag: other warning codes stay grouped" || bad "$tag: warning code grouping"
    done
  done

  # The gate names the findings that fail the job, as the summary counts them.
  r() { printf '{"ruleId":"%s","properties":{"severity":"%s"}%s}' "$1" "$2" "${3:-}"; }
  sarif="{\"runs\":[{\"results\":[$(r CVE-b High),$(r CVE-a High),$(r GHSA-c Critical),$(r GHSA-c Critical),$(r www.example.com Critical),$(r CVE-low Low),$(r CVE-unk 'Unknown (no CVSS score)'),$(r CVE-sup Critical ',"suppressions":[{"kind":"external"}]'),$(r 'bad\nid' High),$(r CVE-d High),$(r __e__ High)]}]}"
  run env INPUT_VULN=true SARIF_TEXT="$sarif" SCAN_CODE=1 "${check[@]}" scan
  expect "$tag: findings reach the gate" 0 $?
  failing="9 findings at or above 'high' (GHSA-c, www.example.com, CVE-a, CVE-b, CVE-d, and 3 more)"
  [[ "$(output vuln-failing)" == "$failing" ]] && has "$t/summary" 'The job fails on 9 findings at or above '"'high'"' (`GHSA-c`, `www.example.com`, `CVE-a`, `CVE-b`, `CVE-d`, and 3 more).' \
    && ok "$tag: the summary names the failing findings" || bad "$tag: failing findings ($(output vuln-failing))"
  run env VULN_EXIT_CODE=1 VULN_FAILING="$failing" "${check[@]}" gate
  expect "$tag: the gate fails on findings" 1 $?
  has "$t/log" "::error title=raeva vuln::The job fails on $failing; see the job summary and the scan output" \
    && ok "$tag: the gate annotation names the advisories" || bad "$tag: gate annotation"
  run env VULN_EXIT_CODE=1 "${check[@]}" gate
  has "$t/log" "::error title=raeva vuln::findings at or above 'high'; see the job summary and the scan output" \
    && ok "$tag: the gate keeps its message without a list" || bad "$tag: gate without a list"
  run env INPUT_VULN=true SARIF_TEXT="$sarif" SCAN_CODE=0 "${check[@]}" scan
  [[ -z "$(output vuln-failing)" ]] && ok "$tag: a passing scan lists no failing findings" || bad "$tag: failing list after exit 0"
  # Ids and severities that differ only in case stay apart and sort by code
  # point, as jq sorts them; a lowercase severity is unknown.
  sarif="{\"runs\":[{\"results\":[$(r GHSA-abcd-efgh-ijkl High),$(r ghsa-abcd-efgh-ijkl Critical),$(r CVE-x high),$(r b-id Medium),$(r B-id Medium),$(r a-id Medium)]}]}"
  run env INPUT_VULN=true INPUT_VULN_FAIL_ON=medium SARIF_TEXT="$sarif" SCAN_CODE=1 "${check[@]}" scan
  [[ "$(output vuln-failing)" == "6 findings at or above 'medium' (ghsa-abcd-efgh-ijkl, GHSA-abcd-efgh-ijkl, B-id, a-id, b-id, and 1 more)" ]] \
    && ok "$tag: ids that differ in case are two advisories" || bad "$tag: ids that differ in case ($(output vuln-failing))"
  [[ "$(sed -n 's/^| [^|]* | \([^|]*\) |.*/\1/p' "$t/summary" | tr '\n' ' ')" == 'Advisory --- ghsa-abcd-efgh-ijkl GHSA-abcd-efgh-ijkl B-id a-id b-id CVE-x ' ]] \
    && ok "$tag: the table orders ids and severities by code point" || bad "$tag: table order"
  # The same for characters that culture comparison ignores or orders by
  # UTF-16 code unit: a soft hyphen, NUL, U+E000 and U+10000. An id sorts
  # before the ids it begins, and equal ids keep their order, here at row 3
  # and row 10.
  p() { printf '{"ruleId":"%s","properties":{"severity":"High","dependencyPurl":"%s"}}' "$1" "$2"; }
  sarif="{\"runs\":[{\"results\":[$(p '\ud800\udc00' p5),$(p '\ue000' p4),$(p 'a\u0000' p3),$(p a p1),$(r CVE-soft 'Hi\u00adgh'),$(r CVE-u Critical ',"baselineState":"UNCHANGED"'),$(p z q),$(p z q),$(p z q),$(p z q),$(p a p2)]}]}"
  run env INPUT_VULN=true INPUT_VULN_FAIL_ON=critical SARIF_TEXT="$sarif" SCAN_CODE=1 "${check[@]}" scan
  [[ "$(output vuln-failing)" == "2 findings at or above 'critical' (CVE-u, CVE-soft)" ]] \
    && ok "$tag: severities and baseline states compare by code point" || bad "$tag: ordinal severity ($(output vuln-failing))"
  [[ "$(sed -n 's/^| [^|]* | [^|]* | \([^|]*\) |.*/\1/p' "$t/summary" | tr '\n' ' ')" == 'Dependency ---  p1 p2 p3 q q q q p4 p5  ' ]] \
    && has "$t/summary" '| CVE-u |  |  | not compared |  |' && ok "$tag: the table sorts ids by code point, stably" || bad "$tag: code point order"
  # A baseline state with a soft hyphen is not "unchanged", and an empty
  # severity shows as written.
  sarif="{\"runs\":[{\"results\":[$(r CVE-sh Critical ',"baselineState":"unch\u00adanged"'),$(r CVE-empty '')]}]}"
  run env INPUT_VULN=true INPUT_VULN_FAIL_ON=critical SARIF_TEXT="$sarif" SCAN_CODE=1 "${check[@]}" scan
  [[ "$(output vuln-failing)" == *"(CVE-sh"* ]] && has "$t/summary" '|  | CVE-empty |' \
    && ok "$tag: a soft hyphen keeps a baseline state apart, an empty severity stays empty" || bad "$tag: soft hyphen state or empty severity ($(output vuln-failing))"
  run env VULN_EXIT_CODE=1 INPUT_VULN_FAIL_ON=NEVER "${check[@]}" gate
  expect "$tag: the gate compares never exactly" 1 $?
  for input in INPUT_VULN_FAIL_ON=High INPUT_CHECK_MODE=Blocking; do
    run env INPUT_VULN=true "$input" "${check[@]}" scan
    expect "$tag: $input is refused" 2 $?
  done
  # Without a usable advisory id the line names none, and has no "()".
  sarif="{\"runs\":[{\"results\":[$(r '!!' High),{\"properties\":{\"severity\":\"Critical\"}}]}]}"
  run env INPUT_VULN=true SARIF_TEXT="$sarif" SCAN_CODE=1 "${check[@]}" scan
  failing=$(output vuln-failing)
  [[ "$failing" == "2 findings at or above 'high'" ]] && has "$t/summary" "The job fails on 2 findings at or above 'high'." \
    && ok "$tag: findings without ids are counted without parentheses" || bad "$tag: findings without ids ($failing)"
  run env VULN_EXIT_CODE=1 VULN_FAILING="$failing" "${check[@]}" gate
  has "$t/log" "::error title=raeva vuln::The job fails on 2 findings at or above 'high'; see the job summary and the scan output" \
    && ok "$tag: the gate names findings without ids" || bad "$tag: gate without ids"

  # The upload is skipped only when code scanning refuses the job token
  # outside a pull_request run, which may upload with a read-only token.
  for case in 'Resource not accessible by integration|push|skip' 'Resource not accessible by integration|pull_request|upload' \
    'API rate limit exceeded|push|upload'; do
    IFS='|' read -r message event want <<< "$case"
    run env INPUT_VULN=true INPUT_SARIF_UPLOAD=true GITHUB_REPOSITORY=o/r GITHUB_EVENT_NAME="$event" GITHUB_EVENT_PATH="$t/event.json" INPUT_WORKING_DIRECTORY=. CS_STATUS=403 CS_MESSAGE="$message" "${check[@]}" scan
    expect "$tag: a refused probe does not fail the scan ($message, $event)" 0 $?
    if [[ "$want" == skip ]]; then
      [[ -z "$(output sarif-upload)" && $(grep -c '^::notice title=setup-raeva::The SARIF log is not uploaded: code scanning answered HTTP 403 (Resource not accessible by integration). Outside a pull_request run, the upload needs security-events: write' "$t/log") == 1 ]] \
        && ok "$tag: a token without code scanning access skips the upload" || bad "$tag: token without access"
    else
      [[ "$(output sarif-upload)" == true ]] && ! has "$t/log" '::notice' && ok "$tag: a 403 ($message, $event) leaves the upload to try" || bad "$tag: 403 ($message, $event)"
    fi
  done
  # The whole message decides; the notice quotes its first 200 code points
  # without trailing newlines. A message that is not a string says nothing.
  zeros=$(printf '%0199d' 0)
  for case in "${zeros}ééé must be enabled|${zeros}é" "${zeros}😀😀 must be enabled|${zeros}😀" \
    $'Advanced Security must be enabled\n\n|Advanced Security must be enabled' '|'; do
    IFS='|' read -r message quoted <<< "${case//$'\n'/$'\r'}"
    body=""
    [[ -n "$message" ]] || body='{"message":["not enabled"]}'
    run env INPUT_VULN=true INPUT_SARIF_UPLOAD=true GITHUB_REPOSITORY=o/r GITHUB_EVENT_NAME=push INPUT_WORKING_DIRECTORY=. CS_STATUS=403 \
      CS_MESSAGE="${message//$'\r'/$'\n'}" CS_BODY="$body" "${check[@]}" scan
    if [[ -n "$message" ]]; then
      [[ -z "$(output sarif-upload)" ]] && has "$t/log" "code scanning answered HTTP 403 ($quoted). A private repository needs GitHub Code Security." \
        && ok "$tag: a 403 message is read whole and quoted in part (${quoted: -20})" || bad "$tag: 403 message (${quoted: -20})"
    else
      [[ "$(output sarif-upload)" == true ]] && ! has "$t/log" '::notice' && ok "$tag: a 403 message that is not a string leaves the upload to try" || bad "$tag: 403 message that is not a string"
    fi
  done

  run env INPUT_CHECK=true INPUT_CHECK_MODE=report-only INPUT_SETTINGS='/w/a`b``c/settings.xml' "${check[@]}" scan
  has "$t/summary" 'reads the settings file `/w/abc/settings.xml`;' && ok "$tag: a settings path cannot end its code span" || bad "$tag: settings path backticks"

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
  if [[ "$tag" == bash ]]; then
    has "$t/summary" 'This pull request adds' && ok "$tag: lock diff of a base without a lock" || bad "$tag: lock diff of a base without a lock"
  fi
  # The pull request changes the lock, so the diff runs. The fake raeva
  # fails a --baseline file other than the base commit's lock.
  printf '# changed\n' >> "$t/project/raeva.lock"
  run env -C "$t/project" INPUT_CHECK=true FROZEN_CODE=0 INPUT_LOCK_DIFF=true INPUT_VULN=true \
    INPUT_WORKING_DIRECTORY=. BASELINE_MARKS=1 \
    GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$t/event.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
  baseline=$(sed -n '/^--baseline$/{n;p;q;}' "$t/args")
  [[ "$(output vuln-exit-code)" == 0 && -n "$baseline" ]] && cmp -s "$baseline" "$t/original.lock" \
    && ok "$tag: scan uses validated baseline" || bad "$tag: baseline scan"
  if [[ "$tag" == bash ]]; then
    tr '\n' ' ' < "$t/args" | grep -qF -- " lock diff $baseline raeva.lock " && ! has "$t/requests" /contents/ \
      && has "$t/summary" '### raeva.lock changes against the base branch' && has "$t/summary" 'gson 2.13.2 -> 2.13.1' \
      && ok "$tag: lock diff against the baseline" || bad "$tag: lock diff against the baseline"
  fi
  cp "$t/original.lock" "$t/project/raeva.lock"
  has "$t/summary" 'Baseline |' && has "$t/summary" 'new |' && has "$t/summary" 'existing |' \
    && has "$t/summary" 'existing | suppressed |' && ok "$tag: summary marks new, existing, and suppressed results" || bad "$tag: baseline summary labels"
  run env -C "$t/project" INPUT_VULN=true INPUT_WORKING_DIRECTORY=. BASELINE_MARKS=1 SCAN_CODE=1 \
    GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$t/event.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
  [[ "$(output vuln-failing)" == "1 new finding at or above 'high' (CVE-new)" ]] \
    && ok "$tag: only new findings fail a pull request" || bad "$tag: failing findings with a baseline ($(output vuln-failing))"

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
  # A root outside the repository has no baseline in it.
  for root in / //; do
    run env -C "$t/project" INPUT_VULN=true INPUT_WORKING_DIRECTORY="$root" \
      GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$t/event.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
    expect "$tag: $root has no baseline" 2 $?
    ! has "$t/args" --baseline && has "$t/log" "must be a path inside the repository" \
      && ok "$tag: $root reads no baseline" || bad "$tag: $root reads no baseline"
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
  awk '/^### Vulnerabilities/ { heading = 1 } /base commit has no/ { exit !heading }' "$t/summary" \
    && ok "$tag: the absent base lock is noted under the vulnerabilities heading" || bad "$tag: absent base lock note above the heading"
  for error in 403:'HTTP 403' 404:'HTTP 404' 500:'HTTP 500' transport:'request failed' \
    malformed:'unreadable blob response' empty:'raeva.lock is empty' \
    truncated:'invalid or truncated tree response' symlink:'raeva.lock is not a regular file' blob404:'HTTP 404' \
    notjson:'invalid or truncated tree response' nosha:'invalid object SHA' garbage:'invalid tree entry'; do
    why=${error#*:} error=${error%%:*}
    run env INPUT_VULN=true INPUT_WORKING_DIRECTORY=. API_CASE="$error" \
      GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$t/event.json" GITHUB_REPOSITORY=o/r "${check[@]}" scan
    expect "$tag: baseline $error fails" 2 $?
    has "$t/log" "base commit; $why" && ok "$tag: baseline $error names the reason" || bad "$tag: baseline $error reason"
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
