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
# Only the GitHub API requests use the token; raeva never sees it.
token="${GH_TOKEN:-}"
unset GH_TOKEN
api="${GITHUB_API_URL:-https://api.github.com}"
out() { echo "$1=$2" >> "${GITHUB_OUTPUT:-/dev/null}"; }

# A directory per invocation, so two roots checked in one job keep their own
# SARIF logs and lock diffs until the upload steps read them.
run=""
[[ "$mode" == gate ]] || run=$(mktemp -d "$tmp/setup-raeva.XXXXXX")

# The Maven options of every command that reads the configuration: -s, -P,
# and one -D per line of the properties input. The --name=value forms keep a
# value that starts with - or ! one argument.
maven=()
[[ -z "${INPUT_SETTINGS:-}" ]] || maven+=("--settings=$INPUT_SETTINGS")
[[ -z "${INPUT_PROFILES:-}" ]] || maven+=("--activate-profiles=$INPUT_PROFILES")
while IFS= read -r line; do
  line="${line%$'\r'}"
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [[ -z "$line" ]] || maven+=("--define=$line")
done <<< "${INPUT_PROPERTIES:-}"

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
    sed -n '/"code":"[A-Z_]*"/{s/.*"code":"\([A-Z_]*\)".*/\1/p;q;}' "$2"
  fi
}

# Used only when raeva gives no hints of its own.
hint_for() {
  case "$1" in
    LOCKFILE_MISMATCH)
      echo "Run 'raeva sync' and commit raeva.lock." ;;
    PLATFORM_MISSING)
      echo "Lock this platform too: raeva sync --platforms <platform>, then commit raeva.lock." ;;
    LOCKFILE_MISSING)
      echo "Run 'raeva sync' at the project root and commit raeva.lock." ;;
    LOCKFILE_INVALID)
      echo "Run 'raeva sync' to write raeva.lock again, then commit it." ;;
    AUTH)
      echo "Give the job the repository credentials: a settings.xml <server> that reads them with \${env.NAME}." ;;
    *) echo "See the error codes in docs/json-output.md of raeva." ;;
  esac
}

# The command a developer runs to write the lock again, with this job's -P
# and -D options. A settings file of the runner does not apply locally.
sync_command() {
  local cmd=(raeva) arg
  [[ "$workdir" == . || "$workdir" == ./ ]] || cmd+=(-C "$workdir")
  cmd+=(sync)
  for arg in ${maven[@]+"${maven[@]}"}; do
    [[ "$arg" == --settings=* ]] || cmd+=("$arg")
  done
  [[ -z "${INPUT_PLATFORMS:-}" ]] || cmd+=(--platforms "$INPUT_PLATFORMS")
  local word line=""
  for word in "${cmd[@]}"; do
    if [[ "$word" =~ ^[A-Za-z0-9_./=,:+@-]+$ ]]; then line+="$word "; else line+="$(printf '%q' "$word") "; fi
  done
  printf '%s' "${line% }"
}

# One annotation per warning code, as raeva's own text summary prints them:
# the first warning with its context, and how many more share the code.
# HTTP_REPO_BLOCKED names an http: repository that some POM declares and is
# listed in the summary only.
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
    [[ "$wcode" == HTTP_REPO_BLOCKED ]] && continue
    echo "::warning title=$(esc_prop "raeva $wcode")::$(esc_msg "$msg")"
  done <<< "$lines"
  printf '\nWarnings:\n' >> "$summary"
  fenced "$(printf '%s\n' "$lines" | tr '\t' ' ')"
}

# The platforms a lock records, read as text, since a malformed or
# conflicted lock still names them.
lock_platforms() {
  [[ -f "$1" ]] || return 0
  sed -n 's/^platform = "\([a-z0-9_-]*\)"[[:space:]]*$/\1/p' "$1" | awk '!seen[$0]++' | paste -sd, -
}

# The artifact that holds the full lock diffs of this working directory.
diff_artifact() {
  local dir="${workdir%/}"
  dir="${dir#./}"
  if [[ -z "$dir" || "$dir" == . ]]; then
    printf 'raeva-lock-diff'
  else
    printf 'raeva-lock-diff-%s' "$(printf '%s' "$dir" | tr -c 'A-Za-z0-9._-' '-')"
  fi
}

# Writes `raeva lock diff <old> <new>` to the job summary, and with a file
# name the full text to the lock diff artifact too. Never fails the step:
# the frozen check reports a lock that cannot be read.
diff_summary() { # <title> <old> <new> [artifact file] [note]
  local text code=0 file="${4:-}" more="run 'raeva lock diff' locally"
  text=$("$raeva" -q -C "$workdir" lock diff "$2" "$3" 2>&1) || code=$?
  printf '### %s\n' "$1" >> "$summary"
  [[ -z "${5:-}" ]] || printf '\n%s\n' "$5" >> "$summary"
  if [[ $code -ne 0 ]]; then
    printf '\n`raeva lock diff` could not compare the locks (exit %s).\n' "$code" >> "$summary"
  fi
  if [[ -n "$file" ]]; then
    mkdir -p "$run/lock-diff"
    printf '%s\n' "$text" > "$run/lock-diff/$file"
    out lock-diff-dir "$run/lock-diff"
    out lock-diff-artifact "$(diff_artifact)"
    more="the full diff is $file in the $(diff_artifact) artifact"
  fi
  local lines
  lines=$(printf '%s\n' "$text" | wc -l)
  if [[ $lines -gt 200 ]]; then
    # sed reads all its input; head would exit early and fail the pipeline.
    text="$(printf '%s\n' "$text" | sed -n '1,200p')"$'\n'"... $((lines - 200)) more lines; $more"
  fi
  fenced "$text"
}

# On a bot's pull request whose lock is stale, writes the lock diff that
# `raeva sync` would commit. raeva writes it in a copy of the working
# directory that is removed afterwards, so later steps see the committed lock.
proposed() {
  [[ "${GITHUB_EVENT_NAME:-}" == pull_request* && -f "${GITHUB_EVENT_PATH:-}" ]] || return 0
  command -v jq >/dev/null || return 0
  [[ "$(jq -r '.pull_request.user.type // empty' "$GITHUB_EVENT_PATH")" == Bot ]] || return 0
  [[ -f "$workdir/raeva.lock" ]] || return 0
  local copy="$run/proposed" platforms="${INPUT_PLATFORMS:-}" code=0
  mkdir -p "$copy"
  tar -C "$workdir" --exclude=.git -cf - . | tar -C "$copy" -xf -
  [[ -n "$platforms" ]] || platforms=$(lock_platforms "$copy/raeva.lock")
  local args=(-q -C "$copy" sync ${maven[@]+"${maven[@]}"})
  [[ -z "$platforms" ]] || args+=(--platforms "$platforms")
  echo "::group::raeva sync in a copy, for the proposed lock"
  "$raeva" "${args[@]}" || code=$?
  echo "::endgroup::"
  local fix
  fix=$(sync_command)
  if [[ $code -ne 0 ]]; then
    printf '\n### Proposed raeva.lock\n\n`raeva sync` could not write a proposed lock (exit %s); see the step log. The error above stands.\n' "$code" >> "$summary"
  else
    diff_summary "Proposed raeva.lock, not committed" "$workdir/raeva.lock" "$copy/raeva.lock" proposed.diff \
      'This is the lock `raeva sync` writes for this pull request. It is not committed, later steps use the committed lock, and the check above still fails. To fix it, run this on the branch and commit raeva.lock:'
    fenced "$fix"
  fi
  rm -rf "$copy"
}

frozen() {
  local args=(--json -C "$workdir" sync --frozen ${maven[@]+"${maven[@]}"})
  [[ -z "${INPUT_PLATFORMS:-}" ]] || args+=(--platforms "$INPUT_PLATFORMS")
  local json="$run/frozen.json" code=0
  "$raeva" "${args[@]}" > "$json" || code=$?
  out frozen-exit-code "$code"
  if [[ $code -eq 0 ]]; then
    local resolved=""
    command -v jq >/dev/null && resolved=$(jq -r '.data.resolved // empty' "$json")
    echo "raeva.lock is current${resolved:+ ($resolved dependencies)}"
    printf '### raeva\n\n`raeva.lock` is current.\n' >> "$summary"
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
  [[ $code -ne 7 ]] || proposed || true
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

# An upload that code scanning refuses only adds an error annotation, so ask
# first. Code scanning answers 403 when a private repository has no GitHub
# Code Security or the token has no security-events access. Any other answer
# leaves the upload to try.
sarif_upload() {
  [[ "${INPUT_SARIF_UPLOAD:-false}" == true && -n "${GITHUB_REPOSITORY:-}" ]] || return 0
  local body="$run/code-scanning.json" status why=""
  status=$(printf 'Authorization: Bearer %s\n' "$token" | curl --proto '=https' --tlsv1.2 --silent --show-error --retry 3 \
    -H @- -H 'Accept: application/vnd.github+json' -o "$body" -w '%{http_code}' \
    "$api/repos/$GITHUB_REPOSITORY/code-scanning/alerts?per_page=1") || status=000
  if [[ "$status" == 403 ]]; then
    command -v jq >/dev/null && why=$(jq -r '.message // empty' "$body" 2>/dev/null | cut -c1-200 || true)
    echo "::notice title=setup-raeva::The SARIF log is not uploaded: code scanning answered HTTP 403${why:+ ($(esc_msg "$why"))}. A private repository needs GitHub Code Security, and the job needs security-events: write. The findings are in the job summary; sarif-upload: false skips this check."
    return 0
  fi
  out sarif-upload true
}

# The findings as a Markdown table, most severe first. The cells quote
# advisory data, so Markdown characters in them are escaped.
findings_table() {
  command -v jq >/dev/null || return 0
  jq -r '
    def cell: tostring | gsub("[\r\n]+"; " ") | gsub("(?<c>[\\\\`*_\\[\\]<>|!#~&])"; "\\\(.c)");
    def rank: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}[.] // 5;
    [.runs[].results[]?
      | {sev: (.properties.severity // "Unknown"), id: (.ruleId // ""),
         dep: (.properties.dependencyPurl // ""), fixed: (.properties.fixedVersion // ""),
         vex: ((.suppressions // []) | length > 0)}]
    | sort_by(.vex, (.sev | rank), .id)
    | if length == 0 then empty else
        "", "| Severity | Advisory | Dependency | Fixed in | VEX |", "| --- | --- | --- | --- | --- |",
        (.[:100][] | "| \(.sev | cell) | \(.id | cell) | \(.dep | cell) | \(.fixed | cell) | \(if .vex then "suppressed" else "" end) |"),
        (if length > 100 then "", "... and \(length - 100) more in the SARIF log." else empty end)
      end' "$1" >> "$summary" 2>/dev/null || true
}

vuln() {
  local fail_on="${INPUT_VULN_FAIL_ON:-high}"
  case "$fail_on" in
    any|low|medium|high|critical|never) ;;
    *) echo "::error title=setup-raeva::vuln-fail-on must be any, low, medium, high, critical, or never"; exit 2 ;;
  esac
  local sarif="$run/raeva.sarif" errlog="$run/vuln.err" code=0 vex=() line
  while IFS= read -r line; do
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] || vex+=(--vex "$line")
  done <<< "${INPUT_VEX:-}"
  "$raeva" -C "$workdir" vuln --format sarif --fail-on "$fail_on" ${vex[@]+"${vex[@]}"} ${maven[@]+"${maven[@]}"} > "$sarif" 2> "$errlog" || code=$?
  cat "$errlog" >&2
  out vuln-exit-code "$code"
  printf '\n### Vulnerabilities\n' >> "$summary"
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
  # A result a VEX statement suppressed is not a finding.
  local count="" suppressed="" note=""
  if command -v jq >/dev/null; then
    count=$(jq '[.runs[].results[]? | select((.suppressions // []) | length == 0)] | length' "$sarif")
    suppressed=$(jq '[.runs[].results[]? | select((.suppressions // []) | length > 0)] | length' "$sarif")
  fi
  [[ "${suppressed:-0}" == 0 ]] || note=", and $suppressed suppressed by VEX"
  out sarif-file "$sarif"
  out sarif-category "$(sarif_category)"
  out vuln-findings "$count"
  local gating="findings at $fail_on or above fail the job"
  [[ "$fail_on" != never ]] || gating="findings do not fail the job (vuln-fail-on: never)"
  if [[ $code -gt 1 ]]; then
    printf '\n`raeva vuln` did not complete (exit %s): %s finding(s)%s in the partial SARIF log.\n' "$code" "${count:-?}" "$note" >> "$summary"
  else
    printf '\n`raeva vuln`: %s finding(s)%s; %s.\n' "${count:-?}" "$note" "$gating" >> "$summary"
  fi
  findings_table "$sarif"
  sarif_upload
}

gate() {
  local code="${VULN_EXIT_CODE:-0}" fail_on="${INPUT_VULN_FAIL_ON:-high}"
  case "$code" in
    0) ;;
    1)
      if [[ "$fail_on" != never ]]; then
        echo "::error title=raeva vuln::findings at or above '$fail_on'; see the job summary and the scan output"
        exit 1
      fi ;;
    *)
      echo "::error title=raeva vuln::the scan did not complete (exit $code); see the step log"
      exit "$code" ;;
  esac
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
  local encoded old="$run/base.lock" status
  encoded=$(jq -rn --arg p "$path" '$p | split("/") | map(@uri) | join("/")')
  # The header comes on stdin so the token is not in curl's arguments.
  status=$(printf 'Authorization: Bearer %s\n' "$token" | curl --proto '=https' --tlsv1.2 --silent --show-error --location --retry 3 \
    -H @- -H 'Accept: application/vnd.github.raw+json' \
    -o "$old" -w '%{http_code}' \
    "$api/repos/$GITHUB_REPOSITORY/contents/$encoded?ref=$base") || status=000
  case "$status" in
    200)
      if cmp -s "$old" "$path"; then
        printf '### raeva.lock\n\n`raeva.lock` is the same as on the base branch.\n\n' >> "$summary"
      else
        diff_summary "raeva.lock changes against the base branch" "$old" "$path" raeva.lock.diff
      fi ;;
    404) printf '### raeva.lock\n\nThis pull request adds `raeva.lock`.\n\n' >> "$summary" ;;
    *) echo "::notice title=setup-raeva::cannot read raeva.lock of the base commit (HTTP $status); the job needs contents: read" ;;
  esac
}

# Writes the lock again for exactly the platforms it records, read from its
# text so a conflicted lock keeps them too.
relock() {
  local platforms="${INPUT_PLATFORMS:-}" lock="$workdir/raeva.lock" before="$run/before.lock"
  if [[ -f "$lock" ]]; then
    cp "$lock" "$before"
    if [[ -z "$platforms" ]]; then
      platforms=$(lock_platforms "$lock")
      [[ -n "$platforms" ]] || echo "::warning title=setup-raeva::raeva.lock names no platform, so only this runner's is locked; set the platforms input to keep others"
    fi
  fi
  local args=(-C "$workdir" sync ${maven[@]+"${maven[@]}"})
  [[ -z "$platforms" ]] || args+=(--platforms "$platforms")
  echo "raeva ${args[*]}"
  "$raeva" "${args[@]}"
  # Keep Maven Trusted Checksums in step when the project commits them.
  if [[ -f "$workdir/.mvn/checksums/checksums.sha256" ]]; then
    "$raeva" -C "$workdir" export-checksums ${maven[@]+"${maven[@]}"}
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
