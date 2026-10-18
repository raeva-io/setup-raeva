#!/usr/bin/env bash
# Runs the `run:` blocks of examples/relock.yml against a local bare
# repository: a bot branch bumps a POM, the relock job writes the lock, and
# the push job commits it to the branch.
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
(cd "$t/dev" && git add -A && git commit --quiet -m init && git push --quiet origin main)
platforms=$(cd "$t/dev" && "$RAEVA_BUILD" --json lock info | jq -r '[.data.platforms[].platform] | join(",")')
echo "locked platforms: $platforms"

# The bot's pull request: one POM change.
branch=dependabot/maven/com.google.code.gson-gson-2.13.1
(cd "$t/dev" && git switch --quiet -c "$branch" &&
  sed -i '/<artifactId>gson<\/artifactId>/{n;s|<version>[^<]*</version>|<version>2.13.1</version>|}' pom.xml &&
  git commit --quiet -am "Bump gson to 2.13.1" && git push --quiet origin "$branch")
head_sha=$(git -C "$t/dev" rev-parse HEAD)

run_relock_job() { # <workdir>
  git clone --quiet "$t/remote.git" "$1" && git -C "$1" checkout --quiet "$head_sha"
  mkdir -p "$1.temp"
  : > "$1.out"
  (cd "$1" && env RAEVA_BIN="$RAEVA_BUILD" INPUT_WORKING_DIRECTORY=. GITHUB_OUTPUT="$1.out" \
    bash "$here/scripts/check.sh" relock > "$1.log" 2>&1 &&
    env RUNNER_TEMP="$1.temp" GITHUB_OUTPUT="$1.out" bash -e "$t/diff.sh" >> "$1.log" 2>&1)
}
run_push_job() { # <workdir> <artifact tar>
  git clone --quiet "$t/remote.git" "$1" && git -C "$1" checkout --quiet "$head_sha"
  mkdir -p "$1.temp/relock" && cp "$2" "$1.temp/relock/relock.tar"
  (cd "$1" && env HEAD_REF="$branch" HEAD_SHA="$head_sha" TOKEN=not-a-real-token RUNNER_TEMP="$1.temp" \
    bash -e "$t/push.sh" > "$1.log" 2>&1)
}

# Relock job.
run_relock_job "$t/relock"
code=$?
[[ $code -eq 0 ]] && ok "relock job succeeds" || { bad "relock job succeeds (exit $code)"; cat "$t/relock.log"; }
grep -q '^changed=true$' "$t/relock.out" && ok "relock job reports a change" || bad "relock job reports a change"
grep -q "^relocked-platforms=$platforms\$" "$t/relock.out" && ok "relock keeps every locked platform" || bad "relock keeps every locked platform"
grep -q PLATFORM_DROPPED "$t/relock.log" && bad "no PLATFORM_DROPPED warning" || ok "no PLATFORM_DROPPED warning"
[[ "$(tar -tf "$t/relock.temp/relock/relock.tar")" == raeva.lock ]] && ok "artifact holds only raeva.lock" || bad "artifact holds only raeva.lock"

# Push job.
run_push_job "$t/push" "$t/relock.temp/relock/relock.tar"
code=$?
[[ $code -eq 0 ]] && ok "push job succeeds" || { bad "push job succeeds (exit $code)"; cat "$t/push.log"; }
git clone --quiet --branch "$branch" "$t/remote.git" "$t/after"
[[ "$(git -C "$t/after" log -1 --format=%s)" == "Update raeva.lock [dependabot skip]" ]] && ok "commit message lets Dependabot rebase" || bad "commit message"
[[ "$(git -C "$t/after" diff --name-only HEAD~1 HEAD)" == raeva.lock ]] && ok "commit changes only raeva.lock" || bad "commit changes only raeva.lock"
[[ "$(git -C "$t/after" log -1 --format=%ae)" == "41898282+github-actions[bot]@users.noreply.github.com" ]] && ok "commit author is github-actions[bot]" || bad "commit author"
(cd "$t/after" && "$RAEVA_BUILD" -q sync --frozen --platforms "$platforms" >/dev/null 2>&1) && ok "branch passes --frozen for every platform" || bad "branch passes --frozen for every platform"

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

# A tampered artifact: raeva.lock as a symlink.
mkdir -p "$t/evil2" && ln -s /etc/passwd "$t/evil2/raeva.lock"
tar -cf "$t/evil2.tar" -C "$t/evil2" raeva.lock
run_push_job "$t/push-evil2" "$t/evil2.tar"
code=$?
[[ $code -ne 0 ]] && grep -q "not a regular file" "$t/push-evil2.log" && ok "refuses a symlink in the artifact" || bad "refuses a symlink in the artifact (exit $code)"

# Relock keeps the recorded platforms and does not add the runner's own.
mkdir -p "$t/mac-only" && cp "$PROJECT/pom.xml" "$t/mac-only/"
"$RAEVA_BUILD" -q -C "$t/mac-only" sync --platforms macos-aarch64 >/dev/null 2>&1
(cd "$t/mac-only" && env RAEVA_BIN="$RAEVA_BUILD" bash "$here/scripts/check.sh" relock > "$t/mac-only.log" 2>&1)
only=$("$RAEVA_BUILD" --json -C "$t/mac-only" lock info | jq -r '[.data.platforms[].platform] | join(",")')
[[ "$only" == macos-aarch64 ]] && ok "relock adds no platform" || bad "relock adds no platform ($only)"

echo "passed $pass, failed $fail"
[[ $fail -eq 0 ]]
