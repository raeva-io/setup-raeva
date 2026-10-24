#!/usr/bin/env bash
# Markdown backticks in printf formats are literal.
# shellcheck disable=SC2016
# `check.sh scan` writes the lock diff of a pull request to the job summary,
# then runs the frozen check and the optional vulnerability scan.
# `check.sh gate` runs after the SARIF upload and fails the job on findings,
# so the upload happens before the job fails. `check.sh relock` writes the
# lock again for a bot pull request; it never commits or pushes.
set -euo pipefail

mode="${1:-scan}"
raeva="${RAEVA_BIN:-raeva}"
workdir="${INPUT_WORKING_DIRECTORY:-.}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
tmp="${RUNNER_TEMP:-/tmp}"
out() { echo "$1=$2" >> "${GITHUB_OUTPUT:-/dev/null}"; }

# Workflow commands need %, CR, and LF escaped in messages, and also : and ,
# in properties such as title.
esc_msg() { local s="${1//%/%25}"; s="${s//$'\r'/%0D}"; printf '%s' "${s//$'\n'/%0A}"; }
esc_prop() { local s; s=$(esc_msg "$1"); s="${s//:/%3A}"; printf '%s' "${s//,/%2C}"; }
annotate() { echo "::$1 file=$(esc_prop "$2"),title=$(esc_prop "$3")::$(esc_msg "$4")"; }

# Text from raeva quotes POM and repository data, so it goes into the
# summary inside a fence it cannot close.
fenced() {
  local fence='````' quote="''''" s="$1"
  s="${s//"$fence"/"$quote"}"
  printf '\n%stext\n%s\n%s\n' "$fence" "$s" "$fence" >> "$summary"
}

# Prints one field of a single-line JSON envelope. jq is on every GitHub
# hosted runner; the sed fallback reads only the plain `code` field.
json_field() {
  if command -v jq >/dev/null; then
    jq -r --arg f "$1" '.[$f] // empty' "$2" 2>/dev/null || true
  elif [[ "$1" == code ]]; then
    sed -n 's/.*"code":"\([A-Z_]*\)".*/\1/p' "$2" | head -n 1
  fi
}

# Used only when raeva gives no hints of its own.
hint_for() {
  case "$1" in
    LOCKFILE_MISMATCH)
      echo "Run 'raeva sync' and commit raeva.lock." ;;
    PLATFORM_MISSING)
      echo "Lock this runner's platform too: raeva sync --platforms <platform>, then commit raeva.lock." ;;
    LOCKFILE_MISSING)
      echo "Run 'raeva sync' at the project root and commit raeva.lock." ;;
    LOCKFILE_INVALID)
      echo "Run 'raeva sync' to write raeva.lock again, then commit it." ;;
    AUTH)
      echo "Give the job the repository credentials: a settings.xml <server> that reads them with \${env.NAME}." ;;
    *) echo "See the error codes in docs/json-output.md of raeva." ;;
  esac
}

# One annotation per warning code, as raeva's own text summary prints them:
# the first warning with its context, and how many more share the code.
warnings() {
  command -v jq >/dev/null || return 0
  local lines
  lines=$(jq -r --arg cmd "$2" '
    [.data.warnings[]?] | group_by(.code)[]
    | (.[0].context | if type == "object" and length > 0
        then " (" + ([to_entries[] | "\(.key)=\(.value)"] | join(", ")) + ")" else "" end) as $ctx
    | "\(.[0].code)\t\(.[0].message)\($ctx)"
      + (if length > 1 then "; and \(length - 1) more (raeva --json \($cmd) lists them)" else "" end)
    ' "$1" 2>/dev/null) || return 0
  [[ -n "$lines" ]] || return 0
  local wcode msg
  while IFS=$'\t' read -r wcode msg; do
    echo "::warning title=$(esc_prop "raeva $wcode")::$(esc_msg "$msg")"
  done <<< "$lines"
  printf '\nWarnings:\n' >> "$summary"
  fenced "$(printf '%s\n' "$lines" | tr '\t' ' ')"
}

frozen() {
  local args=(--json -C "$workdir" sync --frozen)
  [[ -z "${INPUT_PLATFORMS:-}" ]] || args+=(--platforms "$INPUT_PLATFORMS")
  local json="$tmp/raeva-frozen.json" code=0
  "$raeva" "${args[@]}" > "$json" || code=$?
  out frozen-exit-code "$code"
  if [[ $code -eq 0 ]]; then
    local resolved=""
    command -v jq >/dev/null && resolved=$(jq -r '.data.resolved // empty' "$json")
    echo "raeva.lock is current${resolved:+ ($resolved dependencies)}"
    printf '### raeva\n\n`raeva.lock` is current for this runner.\n' >> "$summary"
    warnings "$json" "sync --frozen"
    return 0
  fi
  local err ecode hints=""
  ecode=$(json_field code "$json")
  err=$(json_field error "$json")
  [[ -n "$err" ]] || err=$(cat "$json")
  command -v jq >/dev/null && hints=$(jq -r '.hints[]?' "$json" 2>/dev/null || true)
  [[ -n "$hints" ]] || hints=$(hint_for "$ecode")
  local lock_path="$workdir/raeva.lock"
  lock_path="${lock_path#./}"
  annotate error "$lock_path" "raeva sync --frozen (exit $code${ecode:+, $ecode})" "$err"$'\n'"$hints"
  printf '### raeva\n\n`raeva sync --frozen` failed with exit %s (%s).\n' "$code" "${ecode:-no code}" >> "$summary"
  fenced "$err"$'\n\n'"$hints"
  warnings "$json" "sync --frozen"
  exit "$code"
}

# The code scanning category: the input, or one per working directory so
# the alerts of two Maven roots do not replace each other.
sarif_category() {
  if [[ -n "${INPUT_SARIF_CATEGORY:-}" ]]; then
    printf '%s' "$INPUT_SARIF_CATEGORY"
    return
  fi
  local dir="${workdir%/}"
  dir="${dir#./}"
  if [[ -z "$dir" || "$dir" == . ]]; then printf 'raeva'; else printf 'raeva/%s' "$dir"; fi
}

vuln() {
  local fail_on="${INPUT_VULN_FAIL_ON:-high}" rv_fail_on
  case "$fail_on" in
    any|low|medium|high|critical) rv_fail_on="$fail_on" ;;
    never) rv_fail_on=critical ;;
    *) echo "::error title=setup-raeva::vuln-fail-on must be any, low, medium, high, critical, or never"; exit 2 ;;
  esac
  local sarif="$tmp/raeva.sarif" errlog="$tmp/raeva-vuln.err" code=0
  "$raeva" -C "$workdir" vuln --format sarif --fail-on "$rv_fail_on" > "$sarif" 2> "$errlog" || code=$?
  cat "$errlog" >&2
  out vuln-exit-code "$code"
  # An incomplete scan (exit 2 or more) still writes the findings it has, so
  # its log is uploaded; the gate step fails the job afterwards.
  if [[ $code -gt 1 ]] && ! jq -e '.runs | type == "array"' "$sarif" >/dev/null 2>&1; then
    rm -f "$sarif"
    printf '\n`raeva vuln` did not complete (exit %s) and wrote no SARIF log.\n' "$code" >> "$summary"
    return 0
  fi
  # raeva writes result locations relative to the project root. Code scanning
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
  out sarif-category "$(sarif_category)"
  out vuln-findings "$count"
  if [[ $code -gt 1 ]]; then
    printf '\n`raeva vuln` did not complete (exit %s): %s finding(s) in the partial SARIF log.\n' "$code" "${count:-?}" >> "$summary"
  else
    printf '\n`raeva vuln`: %s finding(s) in the SARIF log.\n' "${count:-?}" >> "$summary"
  fi
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

# Writes `raeva lock diff <old> <new>` to the job summary. Never fails the
# step: the frozen check reports a lock that cannot be read.
diff_summary() { # <title> <old> <new>
  local text code=0
  text=$("$raeva" -q -C "$workdir" lock diff "$2" "$3" 2>&1) || code=$?
  printf '### %s\n' "$1" >> "$summary"
  if [[ $code -ne 0 ]]; then
    printf '\n`raeva lock diff` could not compare the locks (exit %s).\n' "$code" >> "$summary"
  fi
  local lines
  lines=$(printf '%s\n' "$text" | wc -l)
  if [[ $lines -gt 200 ]]; then
    text="$(printf '%s\n' "$text" | head -n 200)"$'\n'"... $((lines - 200)) more lines; run 'raeva lock diff' locally"
  fi
  fenced "$text"
}

# On a pull request, compares raeva.lock with the base commit's, read
# through the contents API so a shallow checkout without credentials works.
pr_diff() {
  [[ "${GITHUB_EVENT_NAME:-}" == pull_request* && -f "${GITHUB_EVENT_PATH:-}" ]] || return 0
  command -v jq >/dev/null || return 0
  local base path="$workdir/raeva.lock"
  base=$(jq -r '.pull_request.base.sha // empty' "$GITHUB_EVENT_PATH")
  [[ "$base" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ && -f "$path" ]] || return 0
  path="${path#./}"
  while [[ "$path" == *//* ]]; do path="${path//\/\///}"; done
  if [[ "$path" == /* || "/$path/" == */../* || "/$path/" == */./* ]]; then
    echo "::notice title=setup-raeva::no lock diff for working-directory '$workdir'; use a path inside the repository without . or .."
    return 0
  fi
  local encoded old="$tmp/raeva-base.lock" status
  encoded=$(jq -rn --arg p "$path" '$p | split("/") | map(@uri) | join("/")')
  status=$(curl --proto '=https' --tlsv1.2 --silent --show-error --location --retry 3 \
    -H "Authorization: Bearer ${GH_TOKEN:-}" -H 'Accept: application/vnd.github.raw+json' \
    -o "$old" -w '%{http_code}' \
    "${GITHUB_API_URL:-https://api.github.com}/repos/$GITHUB_REPOSITORY/contents/$encoded?ref=$base") || status=000
  case "$status" in
    200)
      if cmp -s "$old" "$path"; then
        printf '### raeva.lock\n\n`raeva.lock` is the same as on the base branch.\n\n' >> "$summary"
      else
        diff_summary "raeva.lock changes against the base branch" "$old" "$path"
      fi ;;
    404) printf '### raeva.lock\n\nThis pull request adds `raeva.lock`.\n\n' >> "$summary" ;;
    *) echo "::notice title=setup-raeva::cannot read raeva.lock of the base commit (HTTP $status); the job needs contents: read" ;;
  esac
}

# Re-locks exactly the platforms the lock records. A plain sync would also
# add the platform of the runner.
relock() {
  local platforms="${INPUT_PLATFORMS:-}" lock="$workdir/raeva.lock" before="$tmp/raeva-before.lock"
  rm -f "$before"
  if [[ -f "$lock" ]]; then
    cp "$lock" "$before"
    # The platform lines are read as text, since a malformed or conflicted
    # lock still names them; raeva sync writes such a lock again.
    if [[ -z "$platforms" ]]; then
      platforms=$(sed -n 's/^platform = "\([a-z0-9_-]*\)"[[:space:]]*$/\1/p' "$lock" | awk '!seen[$0]++' | paste -sd, -)
      [[ -n "$platforms" ]] || echo "::warning title=setup-raeva::raeva.lock names no platform, so only this runner's is locked; set the platforms input to keep others"
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
  if [[ -f "$before" ]] && ! cmp -s "$before" "$lock"; then
    diff_summary "raeva.lock written again" "$before" "$lock"
  fi
}

case "$mode" in
  relock) relock ;;
  scan)
    # lock-diff: only writes the diff without the check, for a job without
    # the credentials that resolution needs.
    case "${INPUT_LOCK_DIFF:-true}/${INPUT_CHECK:-false}" in
      only/*) pr_diff || true; exit 0 ;;
      true/true) pr_diff || true ;;
    esac
    [[ "${INPUT_CHECK:-false}" != true ]] || frozen
    [[ "${INPUT_VULN:-false}" != true ]] || vuln
    ;;
  gate) gate ;;
  *) echo "usage: check.sh scan|gate|relock" >&2; exit 2 ;;
esac
