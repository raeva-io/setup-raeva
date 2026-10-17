#!/usr/bin/env bash
# Markdown backticks in printf formats are literal.
# shellcheck disable=SC2016
# `check.sh scan` runs the frozen check and the optional vulnerability scan.
# `check.sh gate` runs after the SARIF upload and fails the job on findings,
# so the upload happens before the job fails. `check.sh relock` writes the
# lock again for a bot pull request; it never commits or pushes.
set -euo pipefail

mode="${1:-scan}"
raeva="${RAEVA_BIN:-raeva}"
workdir="${INPUT_WORKING_DIRECTORY:-.}"
lock_file="${LOCK_FILE:-raeva.lock}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
out() { echo "$1=$2" >> "${GITHUB_OUTPUT:-/dev/null}"; }

# Workflow commands need %, CR, and LF escaped in messages, and also : and ,
# in properties such as title.
esc_msg() { local s="${1//%/%25}"; s="${s//$'\r'/%0D}"; printf '%s' "${s//$'\n'/%0A}"; }
esc_prop() { local s; s=$(esc_msg "$1"); s="${s//:/%3A}"; printf '%s' "${s//,/%2C}"; }
annotate() { echo "::$1 file=$(esc_prop "$2"),title=$(esc_prop "$3")::$(esc_msg "$4")"; }

# Prints one field of a single-line JSON envelope. jq is on every GitHub
# hosted runner; the sed fallback reads only the plain `code` field.
json_field() {
  if command -v jq >/dev/null; then
    jq -r --arg f "$1" '.[$f] // empty' "$2" 2>/dev/null || true
  elif [[ "$1" == code ]]; then
    sed -n 's/.*"code":"\([A-Z_]*\)".*/\1/p' "$2" | head -n 1
  fi
}

hint_for() {
  case "$1" in
    LOCKFILE_MISMATCH)
      echo "Run 'raeva sync' with the same --platforms as the lock, and commit $lock_file." ;;
    PLATFORM_MISSING)
      echo "Lock this runner's platform too: raeva sync --platforms <every platform CI uses>." ;;
    LOCKFILE_MISSING)
      echo "Run 'raeva sync' at the project root and commit $lock_file." ;;
    LOCKFILE_INVALID)
      echo "Run 'raeva sync' to write $lock_file again, then commit it." ;;
    AUTH)
      echo "Give the job the repository credentials (settings.xml or raeva.toml [[auth]] with token_env)." ;;
    *) echo "See the exit-code table in the raeva README." ;;
  esac
}

frozen() {
  local args=(--json -C "$workdir" sync --frozen)
  [[ -z "${INPUT_PLATFORMS:-}" ]] || args+=(--platforms "$INPUT_PLATFORMS")
  local json="${RUNNER_TEMP:-/tmp}/raeva-frozen.json" code=0
  "$raeva" "${args[@]}" > "$json" || code=$?
  out frozen-exit-code "$code"
  if [[ $code -eq 0 ]]; then
    local resolved=""
    command -v jq >/dev/null && resolved=$(jq -r '.data.resolved // empty' "$json")
    echo "$lock_file is current${resolved:+ ($resolved dependencies)}"
    printf '### raeva\n\n`%s` is current for this runner.\n' "$lock_file" >> "$summary"
    return 0
  fi
  local err ecode
  ecode=$(json_field code "$json")
  # raeva 0.4 writes no code field. A frozen sync exits 7 only for a stale lock.
  [[ -n "$ecode" || $code -ne 7 ]] || ecode=LOCKFILE_MISMATCH
  err=$(json_field error "$json")
  [[ -n "$err" ]] || err=$(cat "$json")
  annotate error "$workdir/$lock_file" "raeva sync --frozen (exit $code${ecode:+, $ecode})" \
    "$err. $(hint_for "$ecode")"
  printf '### raeva\n\n`raeva sync --frozen` failed with exit %s (%s).\n\n%s\n' \
    "$code" "${ecode:-no code}" "$(hint_for "$ecode")" >> "$summary"
  exit "$code"
}

vuln() {
  local fail_on="${INPUT_VULN_FAIL_ON:-high}" rv_fail_on
  case "$fail_on" in
    any|low|medium|high|critical) rv_fail_on="$fail_on" ;;
    never) rv_fail_on=critical ;;
    *) echo "::error title=setup-raeva::vuln-fail-on must be any, low, medium, high, critical, or never"; exit 2 ;;
  esac
  local sarif="${RUNNER_TEMP:-/tmp}/raeva.sarif" errlog="${RUNNER_TEMP:-/tmp}/raeva-vuln.err" code=0
  "$raeva" -C "$workdir" vuln --format sarif --fail-on "$rv_fail_on" > "$sarif" 2> "$errlog" || code=$?
  cat "$errlog" >&2
  out vuln-exit-code "$code"
  if [[ $code -gt 1 ]]; then
    rm -f "$sarif"
    return 0
  fi
  # rv writes result locations relative to the project root. Code scanning
  # reads them relative to the repository root, so prefix the subdirectory.
  if [[ "$workdir" != "." ]] && command -v jq >/dev/null; then
    local prefix="${workdir%/}/" fixed="$sarif.tmp"
    prefix="${prefix#./}"
    jq --arg p "$prefix" \
      '(.runs[].results[]?.locations[]?.physicalLocation.artifactLocation.uri) |= ($p + .)' \
      "$sarif" > "$fixed" && mv "$fixed" "$sarif"
  fi
  local count=""
  command -v jq >/dev/null && count=$(jq '[.runs[].results[]?] | length' "$sarif")
  out sarif-file "$sarif"
  out vuln-findings "$count"
  printf '\n`raeva vuln`: %s finding(s) in the SARIF log.\n' "${count:-?}" >> "$summary"
}

gate() {
  local code="${VULN_EXIT_CODE:-0}" fail_on="${INPUT_VULN_FAIL_ON:-high}"
  case "$code" in
    0) ;;
    1)
      if [[ "$fail_on" != never ]]; then
        echo "::error title=raeva vuln::findings at or above '$fail_on'; see the scan output and the code scanning alerts"
        exit 1
      fi ;;
    *)
      echo "::error title=raeva vuln::the scan did not complete (exit $code); see the step log"
      exit "$code" ;;
  esac
}

# Re-locks every platform the lock records, so a bot update does not drop
# the platforms of other runners (a plain sync after a POM change keeps only
# its own platform and warns PLATFORM_DROPPED).
relock() {
  local platforms="${INPUT_PLATFORMS:-}" lock="$workdir/$lock_file"
  if [[ -z "$platforms" && -f "$lock" ]]; then
    if command -v jq >/dev/null; then
      platforms=$("$raeva" --json -C "$workdir" lock info | jq -r '[.data.platforms[].platform] | join(",")')
    else
      platforms=$(sed -n 's/^platform = "\([a-z0-9_-]*\)"$/\1/p' "$lock" | paste -sd, -)
    fi
  fi
  local args=(-C "$workdir" sync)
  [[ -z "$platforms" ]] || args+=(--platforms "$platforms")
  echo "raeva ${args[*]}"
  "$raeva" "${args[@]}"
  # Keep Maven Trusted Checksums in step when the project commits them.
  if [[ -f "$workdir/.mvn/checksums/checksums.sha256" ]]; then
    "$raeva" -C "$workdir" export-checksums
  fi
  out relocked-platforms "$platforms"
}

case "$mode" in
  relock) relock ;;
  scan)
    [[ "${INPUT_CHECK:-false}" != true ]] || frozen
    [[ "${INPUT_VULN:-false}" != true ]] || vuln
    ;;
  gate) gate ;;
  *) echo "usage: check.sh scan|gate|relock" >&2; exit 2 ;;
esac
