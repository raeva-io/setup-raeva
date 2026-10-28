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
# The working directory as a repository path, empty for the root.
rel="${workdir%/}"
rel="${rel#./}"
[[ "$rel" != . ]] || rel=""
lock_path="${rel:+$rel/}raeva.lock"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
tmp="${RUNNER_TEMP:-/tmp}"
# Only the GitHub API requests use the tokens; raeva never sees them. The
# code scanning check uses the job token, which the SARIF upload uses too.
token="${GH_TOKEN:-}"
upload_token="${UPLOAD_TOKEN:-}"
unset GH_TOKEN UPLOAD_TOKEN
api="${GITHUB_API_URL:-https://api.github.com}"
out() { echo "$1=$2" >> "${GITHUB_OUTPUT:-/dev/null}"; }
check_mode="${INPUT_CHECK_MODE:-blocking}"
base_lock=""
base_missing=false
committed=""

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

# raeva's output quotes POM and repository data, so the runner reads no
# workflow commands in it: they are off until a marker it cannot guess.
raw() { # <command...>: runs it, stderr included, and keeps its exit code
  local marker code=0
  marker=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  echo "::stop-commands::$marker"
  "$@" 2>&1 || code=$?
  # The output may end without a newline; the marker must start a line.
  printf '\n::%s::\n' "$marker"
  return "$code"
}

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

# Prints one field of a JSON envelope.
json_field() { jq -r --arg f "$1" '.[$f] // empty' "$2" 2>/dev/null || true; }

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

# The command a developer runs to write the lock again, with this job's
# Maven options. A settings file outside the repository, such as one the job
# writes to RUNNER_TEMP, is left out, and the summary says so.
sync_command() {
  local cmd=(raeva) arg
  [[ -z "$rel" ]] || cmd+=(-C "$workdir")
  cmd+=(sync)
  for arg in ${maven[@]+"${maven[@]}"}; do
    case "$arg" in
      --settings=/*) continue ;;
      --define=*) arg="${arg#--define=}"; arg="--define=${arg%%=*}=<value>" ;;
    esac
    cmd+=("$arg")
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

# Read schema targets as text, including both sides of a merge conflict.
# --platforms takes OS/architecture pairs; sync reads the JDKs itself.
lock_platforms() {
  [[ -f "$1" ]] || return 0
  awk '
    /^[[:space:]]*targets[[:space:]]*=[[:space:]]*\[/ { targets = 1 }
    targets || /^[[:space:]]*target[[:space:]]*=/ {
      rest = $0
      while (match(rest, /"[^"]*"/)) {
        name = substr(rest, RSTART + 1, RLENGTH - 2)
        rest = substr(rest, RSTART + RLENGTH)
        if (name !~ /^[A-Za-z0-9_]+-[A-Za-z0-9_]+(@[A-Za-z0-9._+-]+)?$/) continue
        if (index(name, "@") && length(substr(name, index(name, "@") + 1)) > 32) continue
        sub(/@.*/, "", name)
        if (!seen[name]++) print name
      }
    }
    /\]/ { targets = 0 }
  ' "$1" | paste -sd, -
}

# The name of an artifact with one lock diff of this working directory.
# Jobs whose name matches write the same diff, so a later upload may replace
# an earlier one; the hash keeps other roots, options, and for the proposed
# lock JDKs apart, as services/api and services-api.
diff_artifact() { # <prefix> <more of the key>
  local key="$rel" hash arg
  for arg in ${maven[@]+"${maven[@]}"}; do key+=$'\n'"$arg"; done
  key+=$'\n'"${INPUT_PLATFORMS:-}"$'\n'"$2"
  if command -v sha256sum >/dev/null; then
    hash=$(printf '%s' "$key" | sha256sum | cut -c1-8)
  else
    hash=$(printf '%s' "$key" | shasum -a 256 | cut -c1-8)
  fi
  if [[ -z "$rel" ]]; then
    printf '%s-%s' "$1" "$hash"
  else
    printf '%s-%s-%s' "$1" "$(printf '%s' "$rel" | tr -c 'A-Za-z0-9._-' '-')" "$hash"
  fi
}

# Writes `raeva lock diff <old> <new>` to the job summary, and for the pull
# request diff or the proposed lock the full text to its artifact too. It
# propagates comparison errors for report-only proposed locks.
diff_summary() { # <title, or empty for none> <old> <new> [diff|proposed]
  local text code=0 file="" dir="" name="" more="run 'raeva lock diff' locally"
  case "${4:-}" in
    diff)
      file=raeva.lock.diff dir="$run/lock-diff" name=$(diff_artifact raeva-lock-diff "")
      out lock-diff-dir "$dir"
      out lock-diff-artifact "$name" ;;
    proposed)
      file=proposed.diff dir="$run/proposed-diff" name=$(diff_artifact raeva-lock-proposed "${JAVA_HOME:-}")
      out proposed-diff "$dir/$file"
      out proposed-dir "$dir"
      out proposed-artifact "$name" ;;
  esac
  text=$("$raeva" -q -C "$workdir" lock diff "$2" "$3" 2>&1) || code=$?
  [[ -z "$1" ]] || printf '### %s\n' "$1" >> "$summary"
  if [[ $code -ne 0 ]]; then
    printf '\n`raeva lock diff` could not compare the locks (exit %s).\n' "$code" >> "$summary"
  fi
  if [[ -n "$file" ]]; then
    mkdir -p "$dir" || return $?
    printf '%s\n' "$text" > "$dir/$file" || return $?
    more="the full diff is $file in the $name artifact"
  fi
  local lines
  lines=$(printf '%s\n' "$text" | wc -l)
  if [[ $lines -gt 200 ]]; then
    # sed reads all its input; head would exit early and fail the pipeline.
    text="$(printf '%s\n' "$text" | sed -n '1,200p')"$'\n'"... $((lines - 200)) more lines; $more"
  fi
  fenced "$text"
  if [[ "${4:-}" == proposed && "$check_mode" == report-only ]]; then return "$code"; fi
  return 0
}

# For report-only checks or a bot's stale lock, writes the lock diff that
# `raeva sync` would commit. raeva writes it in place, where a parent POM or
# file: repository outside the working directory resolves as it does for a
# developer. The committed lock goes back when this script exits, so later
# steps see it; a report-only scan in this step reads the proposed lock.
restore_lock() { [[ -z "$committed" ]] || mv -f "$committed" "$workdir/raeva.lock"; }
proposed() {
  if [[ "$check_mode" != report-only ]]; then
    [[ "${GITHUB_EVENT_NAME:-}" == pull_request* && -f "${GITHUB_EVENT_PATH:-}" ]] || return 0
    [[ "$(jq -r '.pull_request.user.type // empty' "$GITHUB_EVENT_PATH")" == Bot ]] || return 0
  fi
  [[ -f "$workdir/raeva.lock" ]] || return 0
  local platforms="${INPUT_PLATFORMS:-}" code=0
  out fix-command "$(sync_command)"
  cp -p "$workdir/raeva.lock" "$run/committed.lock" || return $?
  committed="$run/committed.lock"
  trap restore_lock EXIT
  [[ -n "$platforms" ]] || platforms=$(lock_platforms "$committed")
  local args=(-q -C "$workdir" sync ${maven[@]+"${maven[@]}"})
  [[ -z "$platforms" ]] || args+=(--platforms "$platforms")
  echo "::group::raeva sync, for the proposed lock"
  raw "$raeva" "${args[@]}" || code=$?
  echo "::endgroup::"
  printf '\n### Proposed raeva.lock, not committed\n' >> "$summary"
  if [[ $code -ne 0 ]]; then
    printf '\n`raeva sync` could not write a proposed lock (exit %s); see the step log. The check cannot complete.\n' "$code" >> "$summary"
  else
    printf '\nThis is the lock `raeva sync` writes for this checkout. It is not committed; later steps use the committed lock. To fix it, run this on the branch and commit raeva.lock:\n' >> "$summary"
    fenced "$(sync_command)"
    if [[ -n "${INPUT_PROPERTIES:-}" ]]; then
      printf '\nReplace each `<value>` with the Maven property value used by this job. Property values are omitted from this command.\n' >> "$summary"
    fi
    if [[ "${INPUT_SETTINGS:-}" == /* ]]; then
      printf '\nThis job reads the settings file `%s`; run it with a settings file that has the same repositories and profiles.\n' "${INPUT_SETTINGS//\`/}" >> "$summary"
    fi
    diff_summary "" "$committed" "$workdir/raeva.lock" proposed || code=$?
  fi
  return "$code"
}

frozen() {
  local args=(--json -C "$workdir" sync --frozen ${maven[@]+"${maven[@]}"})
  [[ -z "${INPUT_PLATFORMS:-}" ]] || args+=(--platforms "$INPUT_PLATFORMS")
  local json="$run/frozen.json" code=0
  "$raeva" "${args[@]}" > "$json" 2> "$run/frozen.err" || code=$?
  raw cat "$run/frozen.err"
  out frozen-exit-code "$code"
  if [[ $code -eq 0 ]]; then
    local resolved
    resolved=$(jq -r '.data.resolved // empty' "$json" 2>/dev/null || true)
    echo "raeva.lock is current${resolved:+ ($resolved dependencies)}"
    printf '### raeva\n\n`raeva.lock` is current.\n' >> "$summary"
    warnings "$json" "sync --frozen"
    return 0
  fi
  local err ecode hints=""
  ecode=$(json_field code "$json")
  err=$(json_field error "$json")
  [[ -n "$err" ]] || err=$(cat "$json")
  hints=$(jq -r '.hints[]?' "$json" 2>/dev/null || true)
  [[ -n "$hints" ]] || hints=$(hint_for "$ecode")
  local level=error
  [[ "$check_mode" != report-only || $code -ne 7 ]] || level=warning
  annotate "$level" "$lock_path" "raeva sync --frozen (exit $code${ecode:+, $ecode})" "$err"$'\n'"$hints"
  printf '### raeva\n\n`raeva sync --frozen` failed with exit %s (%s).\n' "$code" "${ecode:-no code}" >> "$summary"
  fenced "$err"$'\n\n'"$hints"
  warnings "$json" "sync --frozen"
  if [[ $code -eq 7 ]]; then
    if [[ "$check_mode" == report-only ]]; then
      printf '\nReport-only mode: lock changes do not fail this job.\n' >> "$summary"
      proposed
      return
    fi
    proposed || true
  fi
  exit "$code"
}

# The code scanning category: the input, or one per working directory so
# the alerts of two Maven roots do not replace each other.
sarif_category() {
  if [[ -n "${INPUT_SARIF_CATEGORY:-}" ]]; then
    printf '%s' "$INPUT_SARIF_CATEGORY"
    return
  fi
  printf 'raeva%s' "${rel:+/$rel}"
}

# An upload that code scanning refuses only adds an error annotation, so ask
# first, with the token the upload uses. Only a 403 that says code scanning
# is not enabled, as for a private repository without GitHub Code Security,
# skips the upload; a token that may not read alerts can still upload.
sarif_upload() {
  [[ "${INPUT_SARIF_UPLOAD:-false}" == true && -n "${GITHUB_REPOSITORY:-}" ]] || return 0
  local body="$run/code-scanning.json" status why=""
  status=$(printf 'Authorization: Bearer %s\n' "$upload_token" | curl --proto '=https' --tlsv1.2 --silent --show-error --retry 3 --max-time 60 \
    -H @- -H 'Accept: application/vnd.github+json' -o "$body" -w '%{http_code}' \
    "$api/repos/$GITHUB_REPOSITORY/code-scanning/alerts?per_page=1") || status=000
  if [[ "$status" == 403 ]]; then
    why=$(jq -r '.message // empty' "$body" 2>/dev/null | cut -c1-200 || true)
    if printf '%s' "$why" | grep -qiE 'must be enabled|not enabled'; then
      echo "::notice title=setup-raeva::The SARIF log is not uploaded: code scanning answered HTTP 403 ($(esc_msg "$why")). A private repository needs GitHub Code Security. The findings are in the job summary; sarif-upload: false skips this check."
      return 0
    fi
  fi
  out sarif-upload true
}

# The findings as a Markdown table, most severe first. The cells quote
# advisory data, so Markdown characters in them are escaped.
findings_table() {
  jq -r '
    def cell: tostring | gsub("[\r\n]+"; " ") | gsub("(?<c>[\\\\`*_\\[\\]<>|!#~&])"; "\\\(.c)");
    def rank: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}[.] // 5;
    [.runs[].results[]?
      | {sev: (.properties.severity // "Unknown"), id: (.ruleId // ""),
         dep: (.properties.dependencyPurl // ""), fixed: (.properties.fixedVersion // ""),
         state: (.baselineState // ""), vex: ((.suppressions // []) | length > 0)}]
    | sort_by(.vex, (.sev | rank), .id)
    | any(.[]; .state != "") as $compared
    | if length == 0 then empty else
        "", ("| Severity | Advisory | Dependency | Fixed in | " + (if $compared then "Baseline | " else "" end) + "VEX |"),
        ("| --- | --- | --- | --- | " + (if $compared then "--- | " else "" end) + "--- |"),
        (.[:100][] | "| \(.sev | cell) | \(.id | cell) | \(.dep | cell) | \(.fixed | cell) | "
          + (if $compared then (if .state == "new" then "new" elif .state == "unchanged" then "existing" else "not compared" end) + " | " else "" end)
          + "\(if .vex then "suppressed" else "" end) |"),
        (if length > 100 then "", "... and \(length - 100) more in the SARIF log." else empty end)
      end' "$1" >> "$summary" 2>/dev/null || true
}

vuln() {
  local fail_on="${INPUT_VULN_FAIL_ON:-high}"
  case "$fail_on" in
    any|low|medium|high|critical|never) ;;
    *) echo "::error title=setup-raeva::vuln-fail-on must be any, low, medium, high, critical, or never"; exit 2 ;;
  esac
  local baseline=()
  if [[ "$base_missing" == true ]]; then
    fail_on=never
  elif [[ -n "$base_lock" ]]; then
    baseline=(--baseline "$base_lock")
  fi
  local sarif="$run/raeva.sarif" errlog="$run/vuln.err" code=0 vex=() line
  while IFS= read -r line; do
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] || vex+=(--vex "$line")
  done <<< "${INPUT_VEX:-}"
  "$raeva" -C "$workdir" vuln --format sarif --fail-on "$fail_on" ${baseline[@]+"${baseline[@]}"} ${vex[@]+"${vex[@]}"} ${maven[@]+"${maven[@]}"} > "$sarif" 2> "$errlog" || code=$?
  raw cat "$errlog"
  out vuln-exit-code "$code"
  printf '\n### Vulnerabilities\n' >> "$summary"
  [[ -z "$committed" ]] || printf '\nThe committed lock is stale, so the scan reads the proposed lock.\n' >> "$summary"
  # An incomplete scan (exit 2 or more) still writes the findings it has, so
  # its log is uploaded; the gate step fails the job afterwards.
  if ! jq -e '.runs | type == "array"' "$sarif" >/dev/null 2>&1; then
    if [[ $code -le 1 ]]; then echo "::error title=raeva vuln::the SARIF log is not valid"; exit 2; fi
    rm -f "$sarif"
    printf '\n`raeva vuln` did not complete (exit %s) and wrote no SARIF log.\n' "$code" >> "$summary"
    return 0
  fi
  # raeva writes result locations relative to the project root. Code scanning
  # reads them relative to the repository root, so prefix the subdirectory.
  if [[ -n "$rel" ]]; then
    local fixed="$sarif.tmp"
    jq --arg p "$rel/" \
      '(.runs[].results[]?.locations[]?.physicalLocation.artifactLocation.uri) |= ($p + .)' \
      "$sarif" > "$fixed" && mv "$fixed" "$sarif"
  fi
  # A result a VEX statement suppressed is not a finding.
  local count suppressed note=""
  read -r count suppressed < <(jq -r '[.runs[].results[]? | (.suppressions // []) | length > 0]
    | "\(map(select(not)) | length) \(map(select(.)) | length)"' "$sarif")
  [[ "$suppressed" == 0 ]] || note=", and $suppressed suppressed by VEX"
  out sarif-file "$sarif"
  out sarif-category "$(sarif_category)"
  out vuln-findings "$count"
  local gating="findings at $fail_on or above fail the job"
  [[ -z "$base_lock" ]] || gating="new findings at $fail_on or above fail the job"
  [[ "$fail_on" != never ]] || gating="findings do not fail the job (vuln-fail-on: never)"
  if [[ $code -gt 1 ]]; then
    printf '\n`raeva vuln` did not complete (exit %s): %s finding(s)%s in the partial SARIF log.\n' "$code" "$count" "$note" >> "$summary"
  else
    printf '\n`raeva vuln`: %s finding(s)%s; %s.\n' "$count" "$note" "$gating" >> "$summary"
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

# Read Git objects as data, without checking out or running the base tree.
# A missing tree entry is distinct from an HTTP or malformed-response error.
baseline_error() {
  echo "::error title=setup-raeva::cannot read the vulnerability baseline of the base commit; $1"
  exit 2
}
base_json() {
  local status
  status=$(printf 'Authorization: Bearer %s\n' "$token" | curl --proto '=https' --tlsv1.2 --silent --show-error --retry 3 --max-time 60 \
    -H @- -H 'Accept: application/vnd.github+json' -o "$run/base.json" -w '%{http_code}' \
    "$api/repos/$GITHUB_REPOSITORY/$1") || baseline_error "request failed"
  [[ "$status" == 200 ]] || baseline_error "HTTP $status (the job needs contents: read)"
}
# A merge queue checks the group against its base commit, as a pull
# request is checked against its base branch.
pr_baseline() {
  local field
  case "${GITHUB_EVENT_NAME:-}" in
    pull_request*) field=.pull_request.base.sha ;;
    merge_group) field=.merge_group.base_sha ;;
    *) return 0 ;;
  esac
  [[ -f "${GITHUB_EVENT_PATH:-}" && -n "${GITHUB_REPOSITORY:-}" ]] || baseline_error "event metadata is missing"
  local base tree path="$lock_path" part entry kind sha mode
  base=$(jq -er "$field" "$GITHUB_EVENT_PATH") || baseline_error "base SHA is missing"
  [[ "$base" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || baseline_error "base SHA is invalid"
  [[ "$path" != /* && "/$path/" != */../* && "/$path/" != */./* && "$path" != *//* && "$path" != *\\* ]] || baseline_error "working-directory must be a path inside the repository without . or .."
  # The trees API reads a commit SHA as the commit's root tree.
  tree="$base"
  while [[ -n "$path" ]]; do
    part="${path%%/*}"
    base_json "git/trees/$tree"
    jq -e '.truncated == false and (.tree | type == "array")' "$run/base.json" >/dev/null || baseline_error "invalid or truncated tree response"
    entry=$(jq -cer --arg p "$part" '[.tree[] | select(.path == $p)] | if length <= 1 then . else error("duplicate entry") end' "$run/base.json") || baseline_error "invalid tree entry"
    if [[ "$entry" == '[]' ]]; then
      base_missing=true
      echo "::notice title=setup-raeva::The base commit has no raeva.lock for this root; vulnerability findings are report-only (--fail-on never). Scan errors still fail."
      printf '\nThe base commit has no `raeva.lock` for this root. Vulnerabilities use `--fail-on never`; scan errors still fail.\n' >> "$summary"
      return 0
    fi
    kind=$(jq -r '.[0].type' <<< "$entry")
    mode=$(jq -r '.[0].mode' <<< "$entry")
    sha=$(jq -er '.[0].sha | select(test("^[0-9a-f]{40}([0-9a-f]{24})?$"))' <<< "$entry") || baseline_error "invalid object SHA"
    if [[ "$path" == */* ]]; then
      [[ "$kind/$mode" == tree/040000 ]] || baseline_error "a parent of raeva.lock is not a directory"
      tree="$sha" path="${path#*/}"
    else
      [[ "$kind" == blob && "$mode" == 100644 || "$kind" == blob && "$mode" == 100755 ]] || baseline_error "raeva.lock is not a regular file"
      base_json "git/blobs/$sha"
      base_lock="$run/base.lock"
      jq -ej '. | select(.encoding == "base64" and (.content | type == "string")) | .content | gsub("[\\r\\n]"; "") | @base64d' "$run/base.json" > "$base_lock" || baseline_error "unreadable blob response"
      [[ -s "$base_lock" ]] || baseline_error "raeva.lock is empty"
      path=""
    fi
  done
}

# On a pull request, compares raeva.lock with the base commit's, read
# through the contents API so a shallow checkout without credentials works.
pr_diff() {
  [[ "${GITHUB_EVENT_NAME:-}" == pull_request* && -f "${GITHUB_EVENT_PATH:-}" ]] || return 0
  local base path="$lock_path"
  base=$(jq -r '.pull_request.base.sha // empty' "$GITHUB_EVENT_PATH")
  [[ "$base" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ && -f "$workdir/raeva.lock" ]] || return 0
  while [[ "$path" == *//* ]]; do path="${path//\/\///}"; done
  if [[ "$path" == /* || "/$path/" == */../* || "/$path/" == */./* ]]; then
    echo "::notice title=setup-raeva::no lock diff for working-directory '$workdir'; use a path inside the repository without . or .."
    return 0
  fi
  local encoded old="$run/display-base.lock" status
  # The vulnerability baseline already read the same file of the same commit.
  if [[ -n "$base_lock" ]]; then
    old="$base_lock" status=200
  elif [[ "$base_missing" == true ]]; then
    status=404
  else
    encoded=$(jq -rn --arg p "$path" '$p | split("/") | map(@uri) | join("/")')
    # The header comes on stdin so the token is not in curl's arguments.
    status=$(printf 'Authorization: Bearer %s\n' "$token" | curl --proto '=https' --tlsv1.2 --silent --show-error --location --retry 3 --max-time 60 \
      -H @- -H 'Accept: application/vnd.github.raw+json' \
      -o "$old" -w '%{http_code}' \
      "$api/repos/$GITHUB_REPOSITORY/contents/$encoded?ref=$base") || status=000
  fi
  case "$status" in
    200)
      if cmp -s "$old" "$path"; then
        printf '### raeva.lock\n\n`raeva.lock` is the same as on the base branch.\n\n' >> "$summary"
      else
        diff_summary "raeva.lock changes against the base branch" "$old" "$path" diff
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
  echo "raeva sync"
  raw "$raeva" "${args[@]}"
  # Keep Maven Trusted Checksums in step when the project commits them.
  if [[ -f "$workdir/.mvn/checksums/checksums.sha256" ]]; then
    raw "$raeva" -C "$workdir" export-checksums ${maven[@]+"${maven[@]}"}
  fi
  out relocked-platforms "$platforms"
  if [[ -f "$before" ]] && ! cmp -s "$before" "$lock"; then
    diff_summary "raeva.lock written again" "$before" "$lock"
  fi
}

case "$mode" in
  relock) relock ;;
  scan)
    command -v jq >/dev/null || { echo "::error title=setup-raeva::the check needs jq on the runner"; exit 2; }
    case "$check_mode" in
      blocking|report-only) ;;
      *) echo "::error title=setup-raeva::check-mode must be blocking or report-only"; exit 2 ;;
    esac
    if [[ "${INPUT_LOCK_DIFF:-true}" != only && "${INPUT_VULN:-false}" == true ]]; then pr_baseline; fi
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
