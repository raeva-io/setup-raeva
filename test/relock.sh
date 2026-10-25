#!/usr/bin/env bash
# Runs the `run:` blocks of examples/relock.yml against a local bare
# repository with two Maven roots: a bot branch bumps both POMs, a relock job
# per root writes its lock, and the push job commits both to the branch.
#
#   RAEVA_BUILD=/path/to/raeva  a locally built binary (required)
#   PROJECT=/path               a Maven project with a committed multi-platform raeva.lock
# ok and bad always return 0, so "A && ok || bad" is safe here.
# shellcheck disable=SC2015
set -uo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
: "${RAEVA_BUILD:?set RAEVA_BUILD}" "${PROJECT:?set PROJECT}"
t=$(mktemp -d "${TMPDIR:-/tmp}/setup-raeva-relock.XXXXXX")
trap '[[ -n "${KEEP:-}" ]] || rm -rf "$t"' EXIT
pass=0 fail=0
ok() { pass=$((pass + 1)); echo "PASS $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }
export HOME="$t/home" RAEVA_HOME="$t/raeva-home" GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME"
git config --global init.defaultBranch main
git config --global user.name bot
git config --global user.email bot@example.invalid
git config --global advice.detachedHead false

# The run: blocks, by step id or name, straight from the workflow file.
step() {
  python3 -I -c '
import sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
for step in wf["jobs"][sys.argv[2]]["steps"]:
    if sys.argv[3] in (step.get("id"), step.get("name")):
        print(step["run"])
' "$here/examples/relock.yml" "$1" "$2"
}
step relock diff > "$t/diff.sh"
step push found > "$t/found.sh"
step push "Commit and push the lock" > "$t/push.sh"
[[ -s "$t/diff.sh" && -s "$t/found.sh" && -s "$t/push.sh" ]] || { echo "cannot read run blocks"; exit 1; }

# Every leg uploads its one output file, even when nothing changed.
# shellcheck disable=SC2016
python3 -I -c '
import sys, yaml
jobs = yaml.safe_load(open(sys.argv[1]))["jobs"]
up = [s for s in jobs["relock"]["steps"] if "upload-artifact" in s.get("uses", "")]
assert len(up) == 1 and "if" not in up[0]
assert up[0]["with"]["name"] == "raeva-relock-${{ strategy.job-index }}"
assert up[0]["with"]["path"] == "${{ steps.diff.outputs.path }}"
assert up[0]["with"]["if-no-files-found"] == "error"
assert jobs["push"]["permissions"]["actions"] == "read"
found = next(s for s in jobs["push"]["steps"] if s.get("id") == "found")
assert found["env"]["GH_TOKEN"] == "${{ github.token }}"
assert found["env"]["GH_REPO"] == "${{ github.repository }}"
for step in jobs["push"]["steps"]:
    if step is not found:
        assert "steps.found.outputs.any ==" in step["if"]
' "$here/examples/relock.yml" && ok "uploads one file per leg and gates push steps on changes" \
  || bad "uploads one file per leg and gates push steps on changes"

# One exact artifact name downloads its contents directly into -D.
mkdir -p "$t/bin"
cat > "$t/bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 7 && "$1" == run && "$2" == download && "$3" == "$GITHUB_RUN_ID" && "$4" == -n && "$6" == -D ]]
[[ "$GH_TOKEN" == not-a-real-token && "$GH_REPO" == owner/repo ]]
shopt -s nullglob dotglob
entries=("$7"/*)
[[ -d "$7" && ${#entries[@]} -eq 0 ]]
printf '%s\n' "$5" >> "$ARTIFACT_STORE/requests"
[[ -d "$ARTIFACT_STORE/$5" ]] || { echo "artifact not found: $5"; exit 1; }
cp -a "$ARTIFACT_STORE/$5/." "$7/"
SH
chmod +x "$t/bin/gh"
upload_artifact() { # <store> <name> <uploaded file>
  mkdir -p "$1/$2" && cp "$3" "$1/$2/"
}

git init --quiet --bare "$t/remote.git"
git clone --quiet "$t/remote.git" "$t/dev"
rsync -a --exclude .git "$PROJECT/" "$t/dev/"
mkdir -p "$t/dev/services/api"
rsync -a --exclude .git "$PROJECT/" "$t/dev/services/api/"
(cd "$t/dev" && git add -A && git commit --quiet -m init && git push --quiet origin main)
platforms=$(cd "$t/dev" && "$RAEVA_BUILD" --json lock info | jq -r '[.data.platforms[].platform] | join(",")')
echo "locked platforms: $platforms"

# The bot's pull request: the same POM change in both roots.
branch=dependabot/maven/com.google.code.gson-gson-2.13.1
(cd "$t/dev" && git switch --quiet -c "$branch" &&
  sed -i '/<artifactId>gson<\/artifactId>/{n;s|<version>[^<]*</version>|<version>2.13.1</version>|}' pom.xml services/api/pom.xml &&
  git commit --quiet -am "Bump gson to 2.13.1" && git push --quiet origin "$branch")
head_sha=$(git -C "$t/dev" rev-parse HEAD)

run_relock_job() { # <workdir> <root> <job index>
  git clone --quiet "$t/remote.git" "$1" && git -C "$1" checkout --quiet "$head_sha"
  mkdir -p "$1.temp"
  : > "$1.out"
  (cd "$1" && env RAEVA_BIN="$RAEVA_BUILD" INPUT_WORKING_DIRECTORY="$2" GITHUB_OUTPUT="$1.out" RUNNER_TEMP="$1.temp" \
    bash "$here/scripts/check.sh" relock > "$1.log" 2>&1 &&
    env ROOT="$2" INDEX="$3" RUNNER_TEMP="$1.temp" GITHUB_OUTPUT="$1.out" bash -e "$t/diff.sh" >> "$1.log" 2>&1)
}
run_push_job() { # <workdir> <uploaded file, artifact directory, or ->...
  local dir="$1" i=0 source
  shift
  mkdir -p "$dir.store" "$dir.temp"
  : > "$dir.out"
  for source in "$@"; do
    if [[ -d "$source" ]]; then
      mkdir -p "$dir.store/raeva-relock-$i" && cp -a "$source/." "$dir.store/raeva-relock-$i/"
    elif [[ "$source" != - ]]; then
      upload_artifact "$dir.store" "raeva-relock-$i" "$source" || return 1
    fi
    i=$((i + 1))
  done
  env PATH="$t/bin:$PATH" ROOTS="${TEST_ROOTS:-[\".\", \"services/api/\"]}" \
    GITHUB_RUN_ID=123 GH_TOKEN=not-a-real-token GH_REPO=owner/repo ARTIFACT_STORE="$dir.store" \
    RUNNER_TEMP="$dir.temp" GITHUB_OUTPUT="$dir.out" bash -e "$t/found.sh" > "$dir.log" 2>&1 || return $?
  if grep -q '^any=true$' "$dir.out"; then
    git clone --quiet "$t/remote.git" "$dir" && git -C "$dir" checkout --quiet "$head_sha" || return 1
    [[ -z "${BROKEN_ORIGIN:-}" ]] || git -C "$dir" remote set-url origin "$t/missing.git"
    (cd "$dir" && env ROOTS="${TEST_ROOTS:-[\".\", \"services/api/\"]}" HEAD_REF="$branch" HEAD_SHA="$head_sha" \
      TOKEN=not-a-real-token RUNNER_TEMP="$dir.temp" bash -e "$t/push.sh" >> "$dir.log" 2>&1)
  fi
}

# A relock job per root.
run_relock_job "$t/relock" . 0
code=$?
[[ $code -eq 0 ]] && ok "relock job succeeds" || { bad "relock job succeeds (exit $code)"; cat "$t/relock.log"; }
grep -q '^changed=true$' "$t/relock.out" && ok "relock job reports a change" || bad "relock job reports a change"
grep -q "^relocked-platforms=$platforms\$" "$t/relock.out" && ok "relock keeps every locked platform" || bad "relock keeps every locked platform"
grep -q PLATFORM_DROPPED "$t/relock.log" && bad "no PLATFORM_DROPPED warning" || ok "no PLATFORM_DROPPED warning"
[[ "$(tar -tf "$t/relock.temp/relock/0/relock.tar")" == raeva.lock ]] && ok "artifact holds only raeva.lock" || bad "artifact holds only raeva.lock"
run_relock_job "$t/relock-api" services/api 1
code=$?
[[ $code -eq 0 ]] && ok "relock job of a second root succeeds" || { bad "relock job of a second root succeeds (exit $code)"; cat "$t/relock-api.log"; }
[[ "$(tar -tf "$t/relock-api.temp/relock/1/relock.tar")" == services/api/raeva.lock ]] && ok "second artifact holds only that root's lock" || bad "second artifact holds only that root's lock"

# Push job.
run_push_job "$t/push" "$t/relock.temp/relock/0/relock.tar" "$t/relock-api.temp/relock/1/relock.tar"
code=$?
[[ $code -eq 0 ]] && ok "push job succeeds" || { bad "push job succeeds (exit $code)"; cat "$t/push.log"; }
git clone --quiet --branch "$branch" "$t/remote.git" "$t/after"
[[ "$(git -C "$t/after" log -1 --format=%s)" == "Update raeva.lock [dependabot skip]" ]] && ok "commit message lets Dependabot rebase" || bad "commit message"
[[ "$(git -C "$t/after" diff --name-only HEAD~1 HEAD | tr '\n' ' ')" == "raeva.lock services/api/raeva.lock " ]] && ok "one commit changes both locks and nothing else" || bad "one commit changes both locks and nothing else"
[[ "$(git -C "$t/after" log -1 --format=%ae)" == "41898282+github-actions[bot]@users.noreply.github.com" ]] && ok "commit author is github-actions[bot]" || bad "commit author"
(cd "$t/after" && "$RAEVA_BUILD" -q sync --frozen --platforms "$platforms" >/dev/null 2>&1) && ok "branch passes --frozen for every platform" || bad "branch passes --frozen for every platform"
(cd "$t/after" && "$RAEVA_BUILD" -q -C services/api sync --frozen --platforms "$platforms" >/dev/null 2>&1) && ok "second root passes --frozen" || bad "second root passes --frozen"

# An unchanged relock still uploads its marker.
head_sha=$(git -C "$t/after" rev-parse HEAD)
run_relock_job "$t/relock-unchanged" . 0
code=$?
[[ $code -eq 0 ]] && grep -q '^changed=false$' "$t/relock-unchanged.out" \
  && [[ -f "$t/relock-unchanged.temp/relock/0/unchanged" ]] \
  && ok "unchanged relock produces a marker" || bad "unchanged relock produces a marker (exit $code)"
unchanged=$(sed -n 's/^path=//p' "$t/relock-unchanged.out")
root_tar=$(sed -n 's/^path=//p' "$t/relock.out")
api_tar=$(sed -n 's/^path=//p' "$t/relock-api.out")

# Only the second root changed; the first root must still report unchanged.
head_sha=$(git -C "$t/dev" rev-parse HEAD)
git -C "$t/remote.git" update-ref "refs/heads/$branch" "$head_sha"
run_push_job "$t/push-api" "$unchanged" "$api_tar"
code=$?
[[ $code -eq 0 ]] && [[ "$(git -C "$t/push-api" rev-list --count "$head_sha..HEAD")" == 1 ]] \
  && [[ "$(git -C "$t/push-api" diff --name-only "$head_sha" HEAD)" == services/api/raeva.lock ]] \
  && ok "only root 1 changes in one commit" || { bad "only root 1 changes in one commit (exit $code)"; cat "$t/push-api.log"; }
[[ "$(cat "$t/push-api.store/requests")" == $'raeva-relock-0\nraeva-relock-1' ]] \
  && ok "fetches both artifacts by exact name" || bad "fetches both artifacts by exact name"

# A one-root matrix uses the same file layout.
git -C "$t/remote.git" update-ref "refs/heads/$branch" "$head_sha"
TEST_ROOTS='["."]' run_push_job "$t/push-single" "$root_tar"
code=$?
[[ $code -eq 0 ]] && [[ "$(git -C "$t/push-single" rev-list --count "$head_sha..HEAD")" == 1 ]] \
  && [[ "$(git -C "$t/push-single" diff --name-only "$head_sha" HEAD)" == raeva.lock ]] \
  && ok "a single-root matrix commits its lock" || { bad "a single-root matrix commits its lock (exit $code)"; cat "$t/push-single.log"; }

git -C "$t/remote.git" update-ref "refs/heads/$branch" "$head_sha"
run_push_job "$t/push-unchanged" "$unchanged" "$unchanged"
code=$?
[[ $code -eq 0 ]] && grep -q 'All roots are unchanged.' "$t/push-unchanged.log" \
  && [[ "$(git -C "$t/remote.git" rev-parse "refs/heads/$branch")" == "$head_sha" && ! -d "$t/push-unchanged/.git" ]] \
  && ok "all unchanged succeeds without checkout or commit" || bad "all unchanged succeeds without checkout or commit (exit $code)"

# The bot pushes again before a push job for the old head runs.
git -C "$t/dev" commit --quiet --allow-empty -m "Bot update"
git -C "$t/dev" push --quiet origin "$branch"
run_push_job "$t/push-again" "$root_tar" "$unchanged"
code=$?
[[ $code -eq 0 ]] && grep -q "moved since this run started" "$t/push-again.log" && ok "a lost push race ends without an error" || { bad "a lost push race ends without an error (exit $code)"; cat "$t/push-again.log"; }

BROKEN_ORIGIN=1 run_push_job "$t/push-broken" "$root_tar" "$unchanged"
code=$?
[[ $code -ne 0 ]] && ! grep -q "moved since this run started" "$t/push-broken.log" \
  && ok "an unreachable remote fails the push job" || bad "an unreachable remote fails the push job (exit $code)"

run_push_job "$t/push-missing" "$unchanged" -
code=$?
[[ $code -ne 0 ]] && grep -q 'artifact not found: raeva-relock-1' "$t/push-missing.log" \
  && ok "refuses a missing artifact" || bad "refuses a missing artifact (exit $code)"
run_push_job "$t/push-missing-all" - -
code=$?
[[ $code -ne 0 ]] && grep -q 'artifact not found: raeva-relock-0' "$t/push-missing-all.log" \
  && ok "refuses no artifacts" || bad "refuses no artifacts (exit $code)"

# A tampered artifact: extra content next to the uploaded file.
mkdir -p "$t/extra"
cp "$root_tar" "$t/extra/"
touch "$t/extra/.injected"
run_push_job "$t/push-extra" "$t/extra" "$unchanged"
code=$?
[[ $code -ne 0 ]] && grep -q 'must hold exactly one regular file' "$t/push-extra.log" \
  && ok "refuses an artifact with an extra file" || bad "refuses an artifact with an extra file (exit $code)"

# A tampered artifact: a nested artifact directory claims another identity.
mkdir -p "$t/nested/raeva-relock-1"
cp "$api_tar" "$t/nested/raeva-relock-1/"
run_push_job "$t/push-nested" "$t/nested" "$api_tar"
code=$?
[[ $code -ne 0 ]] && grep -q 'raeva-relock-0 must hold exactly one regular file' "$t/push-nested.log" \
  && ok "refuses a nested artifact directory" || bad "refuses a nested artifact directory (exit $code)"

# A tampered artifact: a POM next to the lock inside the tar.
mkdir -p "$t/evil" && cp "$t/after/raeva.lock" "$t/after/pom.xml" "$t/evil/"
tar -cf "$t/evil/relock.tar" -C "$t/evil" raeva.lock pom.xml
run_push_job "$t/push-evil" "$t/evil/relock.tar" "$unchanged"
code=$?
[[ $code -ne 0 ]] && grep -q "unexpected file in artifact raeva-relock-0: pom.xml" "$t/push-evil.log" && ok "refuses an archive with other files" || bad "refuses an archive with other files (exit $code)"

# A tampered artifact: the first root's job writes the second root's lock.
run_push_job "$t/push-evil3" "$api_tar" "$unchanged"
code=$?
[[ $code -ne 0 ]] && grep -q "unexpected file in artifact raeva-relock-0: services/api/raeva.lock" "$t/push-evil3.log" \
  && ok "refuses another root's lock" || bad "refuses another root's lock (exit $code)"

mkdir -p "$t/empty" "$t/same"
tar -cf "$t/empty/relock.tar" --files-from /dev/null
tar -cf "$t/same/relock.tar" -C "$t/dev" raeva.lock
run_push_job "$t/push-empty" "$t/empty/relock.tar" "$unchanged"
code=$?
[[ $code -ne 0 ]] && grep -q 'holds an empty tar' "$t/push-empty.log" \
  && ok "refuses an empty tar" || bad "refuses an empty tar (exit $code)"
run_push_job "$t/push-same" "$t/same/relock.tar" "$unchanged"
code=$?
[[ $code -ne 0 ]] && grep -q 'raeva.lock claims a change but matches HEAD' "$t/push-same.log" \
  && ok "refuses a lock equal to HEAD" || bad "refuses a lock equal to HEAD (exit $code)"
run_push_job "$t/push-mixed" "$t/same/relock.tar" "$api_tar"
code=$?
[[ $code -ne 0 ]] && grep -q 'raeva.lock claims a change but matches HEAD' "$t/push-mixed.log" \
  && ok "refuses an unchanged claim even when another root changed" || bad "refuses an unchanged claim even when another root changed (exit $code)"

# A tampered artifact: a Trusted Checksums file the branch does not have.
mkdir -p "$t/evil5/.mvn/checksums" && printf 'x\n' > "$t/evil5/.mvn/checksums/checksums.sha1"
tar -cf "$t/evil5/relock.tar" -C "$t/evil5" .mvn/checksums/checksums.sha1
run_push_job "$t/push-evil5" "$t/evil5/relock.tar" "$unchanged"
code=$?
[[ $code -ne 0 ]] && grep -q "checksums.sha1 is not a committed file" "$t/push-evil5.log" && ok "refuses a file the branch does not have" || bad "refuses a file the branch does not have (exit $code)"

# Artifact names that only look like an index cannot satisfy an exact fetch.
for name in raeva-relock-00 raeva-relock-18446744073709551616 raeva-relock-+0; do
  dir="$t/push-name-$name"
  mkdir -p "$dir.store/$name"
  cp "$root_tar" "$dir.store/$name/"
  run_push_job "$dir" - "$unchanged"
  code=$?
  [[ $code -ne 0 ]] && grep -q 'artifact not found: raeva-relock-0' "$dir.log" \
    && ok "refuses artifact $name as root 0" || bad "refuses artifact $name as root 0 (exit $code)"
done

# An unrequested artifact cannot add files to a listed root.
run_push_job "$t/push-unlisted" "$unchanged" "$unchanged" "$root_tar"
code=$?
[[ $code -eq 0 ]] && [[ "$(cat "$t/push-unlisted.store/requests")" == $'raeva-relock-0\nraeva-relock-1' ]] \
  && ok "does not fetch an artifact of no listed root" || bad "does not fetch an artifact of no listed root (exit $code)"

# A tampered artifact: a path that leaves the checkout.
# GNU tar strips a leading ../ when it writes an archive, so Python writes it.
mkdir -p "$t/evil4"
python3 -I -c 'import sys, tarfile
with tarfile.open(sys.argv[1], "w") as tar: tar.add(sys.argv[2], arcname="services/../raeva.lock")' \
  "$t/evil4/relock.tar" "$t/after/raeva.lock"
run_push_job "$t/push-evil4" "$t/evil4/relock.tar" "$unchanged"
code=$?
[[ $code -ne 0 ]] && grep -q "unexpected file in artifact raeva-relock-0: services/../raeva.lock" "$t/push-evil4.log" && ok "refuses a path with .." || bad "refuses a path with .. (exit $code)"

# A tampered artifact: raeva.lock as a symlink.
mkdir -p "$t/evil2" && ln -s /etc/passwd "$t/evil2/raeva.lock"
tar -cf "$t/evil2/relock.tar" -C "$t/evil2" raeva.lock
run_push_job "$t/push-evil2" "$t/evil2/relock.tar" "$unchanged"
code=$?
[[ $code -ne 0 ]] && grep -q "not a regular file" "$t/push-evil2.log" && ok "refuses a symlink in the artifact" || bad "refuses a symlink in the artifact (exit $code)"

# A committed checksum file with no changes must stay out of the tar.
git clone --quiet "$t/remote.git" "$t/diff-checksums"
git -C "$t/diff-checksums" checkout --quiet "$head_sha"
mkdir -p "$t/diff-checksums/.mvn/checksums" "$t/diff-checksums.temp"
printf 'x\n' > "$t/diff-checksums/.mvn/checksums/checksums.sha256"
(cd "$t/diff-checksums" && git add .mvn/checksums/checksums.sha256 && git commit --quiet -m "Add checksums")
cp "$t/after/raeva.lock" "$t/diff-checksums/"
(cd "$t/diff-checksums" && env ROOT=. INDEX=0 RUNNER_TEMP="$t/diff-checksums.temp" GITHUB_OUTPUT="$t/diff-checksums.out" \
  bash -e "$t/diff.sh" > "$t/diff-checksums.log" 2>&1)
code=$?
[[ $code -eq 0 ]] && [[ "$(tar -tf "$t/diff-checksums.temp/relock/0/relock.tar")" == raeva.lock ]] \
  && ok "archives only files that changed" || bad "archives only files that changed (exit $code)"

# Relock keeps the recorded platforms and does not add the runner's own.
mkdir -p "$t/mac-only" && cp "$PROJECT/pom.xml" "$t/mac-only/"
"$RAEVA_BUILD" -q -C "$t/mac-only" sync --platforms macos-aarch64 >/dev/null 2>&1
mkdir -p "$t/mac-only.temp"
(cd "$t/mac-only" && env RAEVA_BIN="$RAEVA_BUILD" RUNNER_TEMP="$t/mac-only.temp" bash "$here/scripts/check.sh" relock > "$t/mac-only.log" 2>&1)
only=$("$RAEVA_BUILD" --json -C "$t/mac-only" lock info | jq -r '[.data.platforms[].platform] | join(",")')
[[ "$only" == macos-aarch64 ]] && ok "relock adds no platform" || bad "relock adds no platform ($only)"

relock_in() { # <dir>: runs check.sh relock there with its own outputs
  mkdir -p "$1.temp"
  : > "$1.out"; : > "$1.summary"
  (cd "$1" && env RAEVA_BIN="$RAEVA_BUILD" RUNNER_TEMP="$1.temp" GITHUB_OUTPUT="$1.out" \
    GITHUB_STEP_SUMMARY="$1.summary" bash "$here/scripts/check.sh" relock > "$1.log" 2>&1)
}

# A lock with merge conflict markers, as a rebase leaves it: relock reads the
# platforms from its text and writes it again; strict parsing would refuse it.
mkdir -p "$t/conflict" && cp "$t/after/pom.xml" "$t/conflict/"
awk 'NR == 4 { print "<<<<<<< HEAD" } { print } NR == 6 { print "======="; print "model_hash = \"0\""; print ">>>>>>> main" }' \
  "$t/after/raeva.lock" > "$t/conflict/raeva.lock"
"$RAEVA_BUILD" -q -C "$t/conflict" lock info >/dev/null 2>&1 && bad "test setup: the conflicted lock parses"
relock_in "$t/conflict"
code=$?
[[ $code -eq 0 ]] && ok "relock recovers a conflicted lock" || { bad "relock recovers a conflicted lock (exit $code)"; cat "$t/conflict.log"; }
grep -q "^relocked-platforms=$platforms\$" "$t/conflict.out" && ok "conflicted lock keeps every platform" || bad "conflicted lock keeps every platform"
(cd "$t/conflict" && "$RAEVA_BUILD" -q sync --frozen --platforms "$platforms" >/dev/null 2>&1) && ok "rewritten lock passes --frozen" || bad "rewritten lock passes --frozen"
grep -q "raeva.lock written again" "$t/conflict.summary" && ok "relock writes a summary" || bad "relock writes a summary"

# A lock that names no platform: relock locks the runner's and warns.
mkdir -p "$t/garbage" && cp "$t/after/pom.xml" "$t/garbage/" && printf 'garbage' > "$t/garbage/raeva.lock"
relock_in "$t/garbage"
code=$?
[[ $code -eq 0 ]] && grep -q "names no platform" "$t/garbage.log" && ok "relock warns when no platform is named" || bad "relock warns when no platform is named (exit $code)"

echo "passed $pass, failed $fail"
[[ $fail -eq 0 ]]
