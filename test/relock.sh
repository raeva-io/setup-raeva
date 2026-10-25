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
step push "Commit and push the lock" > "$t/push.sh"
[[ -s "$t/diff.sh" && -s "$t/push.sh" ]] || { echo "cannot read run blocks"; exit 1; }

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

run_relock_job() { # <workdir> <root>
  git clone --quiet "$t/remote.git" "$1" && git -C "$1" checkout --quiet "$head_sha"
  mkdir -p "$1.temp"
  : > "$1.out"
  (cd "$1" && env RAEVA_BIN="$RAEVA_BUILD" INPUT_WORKING_DIRECTORY="$2" GITHUB_OUTPUT="$1.out" RUNNER_TEMP="$1.temp" \
    bash "$here/scripts/check.sh" relock > "$1.log" 2>&1 &&
    env ROOT="$2" RUNNER_TEMP="$1.temp" GITHUB_OUTPUT="$1.out" bash -e "$t/diff.sh" >> "$1.log" 2>&1)
}
run_push_job() { # <workdir> <artifact tar>...: one artifact directory per tar
  local dir="$1" i=0 tarfile
  shift
  git clone --quiet "$t/remote.git" "$dir" && git -C "$dir" checkout --quiet "$head_sha"
  for tarfile in "$@"; do
    mkdir -p "$dir.temp/relock/raeva-relock-$i" && cp "$tarfile" "$dir.temp/relock/raeva-relock-$i/relock.tar"
    i=$((i + 1))
  done
  (cd "$dir" && env HEAD_REF="$branch" HEAD_SHA="$head_sha" TOKEN=not-a-real-token RUNNER_TEMP="$dir.temp" \
    bash -e "$t/push.sh" > "$dir.log" 2>&1)
}

# A relock job per root.
run_relock_job "$t/relock" .
code=$?
[[ $code -eq 0 ]] && ok "relock job succeeds" || { bad "relock job succeeds (exit $code)"; cat "$t/relock.log"; }
grep -q '^changed=true$' "$t/relock.out" && ok "relock job reports a change" || bad "relock job reports a change"
grep -q "^relocked-platforms=$platforms\$" "$t/relock.out" && ok "relock keeps every locked platform" || bad "relock keeps every locked platform"
grep -q PLATFORM_DROPPED "$t/relock.log" && bad "no PLATFORM_DROPPED warning" || ok "no PLATFORM_DROPPED warning"
[[ "$(tar -tf "$t/relock.temp/relock/relock.tar")" == raeva.lock ]] && ok "artifact holds only raeva.lock" || bad "artifact holds only raeva.lock"
run_relock_job "$t/relock-api" services/api
code=$?
[[ $code -eq 0 ]] && ok "relock job of a second root succeeds" || { bad "relock job of a second root succeeds (exit $code)"; cat "$t/relock-api.log"; }
[[ "$(tar -tf "$t/relock-api.temp/relock/relock.tar")" == services/api/raeva.lock ]] && ok "second artifact holds only that root's lock" || bad "second artifact holds only that root's lock"

# Push job.
run_push_job "$t/push" "$t/relock.temp/relock/relock.tar" "$t/relock-api.temp/relock/relock.tar"
code=$?
[[ $code -eq 0 ]] && ok "push job succeeds" || { bad "push job succeeds (exit $code)"; cat "$t/push.log"; }
git clone --quiet --branch "$branch" "$t/remote.git" "$t/after"
[[ "$(git -C "$t/after" log -1 --format=%s)" == "Update raeva.lock [dependabot skip]" ]] && ok "commit message lets Dependabot rebase" || bad "commit message"
[[ "$(git -C "$t/after" diff --name-only HEAD~1 HEAD | tr '\n' ' ')" == "raeva.lock services/api/raeva.lock " ]] && ok "one commit changes both locks and nothing else" || bad "one commit changes both locks and nothing else"
[[ "$(git -C "$t/after" log -1 --format=%ae)" == "41898282+github-actions[bot]@users.noreply.github.com" ]] && ok "commit author is github-actions[bot]" || bad "commit author"
(cd "$t/after" && "$RAEVA_BUILD" -q sync --frozen --platforms "$platforms" >/dev/null 2>&1) && ok "branch passes --frozen for every platform" || bad "branch passes --frozen for every platform"
(cd "$t/after" && "$RAEVA_BUILD" -q -C services/api sync --frozen --platforms "$platforms" >/dev/null 2>&1) && ok "second root passes --frozen" || bad "second root passes --frozen"

# The bot pushes again before a push job for the old head runs. (A rerun
# for the same head in the same second would make the identical commit and
# push nothing, so the race is set up with a new bot commit.)
(cd "$t/dev" && git pull --quiet --ff-only origin "$branch" &&
  git commit --quiet --allow-empty -m "Bot update" && git push --quiet origin "$branch")
run_push_job "$t/push-again" "$t/relock.temp/relock/relock.tar"
code=$?
[[ $code -eq 0 ]] && grep -q "moved since this run started" "$t/push-again.log" && ok "a lost push race ends without an error" || { bad "a lost push race ends without an error (exit $code)"; cat "$t/push-again.log"; }

# A tampered artifact: a POM next to the lock.
mkdir -p "$t/evil" && cp "$t/after/raeva.lock" "$t/after/pom.xml" "$t/evil/"
tar -cf "$t/evil.tar" -C "$t/evil" raeva.lock pom.xml
run_push_job "$t/push-evil" "$t/evil.tar"
code=$?
[[ $code -ne 0 ]] && grep -q "unexpected file in artifact: pom.xml" "$t/push-evil.log" && ok "refuses an artifact with other files" || bad "refuses an artifact with other files (exit $code)"

# A tampered artifact: a lock of a directory the branch has no lock in.
mkdir -p "$t/evil3/other" && cp "$t/after/raeva.lock" "$t/evil3/other/"
tar -cf "$t/evil3.tar" -C "$t/evil3" other/raeva.lock
run_push_job "$t/push-evil3" "$t/evil3.tar"
code=$?
[[ $code -ne 0 ]] && grep -q "other/raeva.lock is not a committed file" "$t/push-evil3.log" && ok "refuses a lock the branch does not have" || bad "refuses a lock the branch does not have (exit $code)"

# A tampered artifact: a path that leaves the checkout.
# GNU tar strips a leading ../ when it writes an archive, so Python writes it.
python3 -I -c 'import sys, tarfile
with tarfile.open(sys.argv[1], "w") as tar: tar.add(sys.argv[2], arcname="services/../raeva.lock")' \
  "$t/evil4.tar" "$t/after/raeva.lock"
run_push_job "$t/push-evil4" "$t/evil4.tar"
code=$?
[[ $code -ne 0 ]] && grep -q "unexpected file in artifact: services/../raeva.lock" "$t/push-evil4.log" && ok "refuses a path with .." || bad "refuses a path with .. (exit $code)"

# A tampered artifact: raeva.lock as a symlink.
mkdir -p "$t/evil2" && ln -s /etc/passwd "$t/evil2/raeva.lock"
tar -cf "$t/evil2.tar" -C "$t/evil2" raeva.lock
run_push_job "$t/push-evil2" "$t/evil2.tar"
code=$?
[[ $code -ne 0 ]] && grep -q "not a regular file" "$t/push-evil2.log" && ok "refuses a symlink in the artifact" || bad "refuses a symlink in the artifact (exit $code)"

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
