# setup-raeva

`raeva-io/setup-raeva` installs a pinned [raeva](https://github.com/raeva-io/raeva)
release on a GitHub Actions runner and checks the download before it runs. It
can also cache the raeva artifact store, check that `raeva.lock` is current,
show what a pull request changes in the lock, and scan the lock for known
vulnerabilities.

## Quick start

First write the lock on your machine, tell git how to merge it, and commit
both files:

```sh
raeva sync
printf 'raeva.lock -merge linguist-generated=true\n' >> .gitattributes
git add raeva.lock .gitattributes
git commit -m "Add raeva.lock"
```

With `-merge`, git keeps your side of a conflicted `raeva.lock` without
conflict markers and still reports the conflict: fix the POMs, run
`raeva sync`, and `git add raeva.lock`. `linguist-generated` folds the lock
in pull request diffs; the job summary has the readable diff.

Then keep your Maven build as it is and add a workflow that checks the lock
(`examples/ci.yml` has both jobs):

```yaml
name: raeva

on:
  push:
    branches: [main] # your default branch: only its pushes save the raeva cache
  pull_request:
  merge_group:
    types: [checks_requested]

permissions:
  contents: read

jobs:
  lock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-java@b843ebf9b913146b38da2eaa7aeddf76074ae1ad # v6.1.0
        with:
          distribution: temurin
          java-version: "21" # a JDK listed in [lock] jdks, or the JDK the lock was written with
      - uses: raeva-io/setup-raeva@v1.0.0
        with:
          version: 0.5.0
          check: true
          check-mode: report-only
```

The job runs `raeva sync --frozen`: it downloads the locked artifacts into
the store and checks whether `raeva.lock` matches the POMs. Start with
`check-mode: report-only`: stale or drifted locks produce a proposed diff and
a fix command in the job summary, and a missing lock gives a warning. The
`proposed-diff` output is the path of the full diff; `fix-command` is the
command to regenerate the lock. The committed lock stays unchanged. With
`vuln: true`, the scan reads the proposed lock, so a stale lock still gets
scanned. Check errors, such as invalid locks or failed downloads, still fail
the job.

Report-only does not fail on the lock, so it does not stop a stale lock from
merging. Use it while you adopt raeva, then remove `check-mode` so that lock
changes and a missing lock fail the job. Its default is `blocking`. The check covers every platform the lock records, whatever the
runner's OS, so one Linux job checks a lock written on a Mac. On a pull
request, the job summary lists what the pull request changes in the lock.
The `merge_group` trigger lets the check run in a merge queue. Add bot lock
commits before you make a blocking check required (see "Bot pull
requests").

Releases of this action are immutable, so `@v1.0.0` always names the same
commit; `@<commit SHA> # v1.0.0` pins it by SHA. Dependabot and Renovate update
either form.

Set `version` to an exact raeva release, 0.5.0 or newer, the one your
developers use. A lock written by a newer raeva can use a schema that an older
one refuses; the check then fails and asks you to raise `version`.

## Recipes

Add them one at a time, after the check works.

| File | What it does |
| --- | --- |
| `examples/ci.yml` | A report-only check next to an unchanged Maven build. |
| `examples/vuln.yml` | Scans the lock. Pull requests fail on new findings at `high` or above; a weekly run and pushes to main check all findings. |
| `examples/drift.yml` | For SNAPSHOT or version range dependencies only: a scheduled job that resolves again and fails when the result differs from the committed lock. |
| `examples/relock.yml` | Writes `raeva.lock` again on Dependabot pull requests and pushes it to the PR branch. |
| `examples/private.yml` | A public repository whose build reads a private Maven repository, with a credential-free job for fork pull requests. |
| `examples/enforce.yml` | Builds offline from the locked artifacts only, with Maven Trusted Checksums from `raeva export-checksums`, for a dependency graph without version ranges or SNAPSHOTs, transitive ones included. |
| `examples/renovate-self-hosted.json` | `postUpgradeTasks` for a self-hosted Renovate. |
| `examples/gitlab-ci.yml`, `examples/Jenkinsfile` | The same check on GitLab CI and Jenkins. |

## What fails the check

`raeva sync --frozen` fails with exit 7 (`LOCKFILE_MISMATCH`) when resolving
again changes the lock: a dependency, a POM pin, a parent or BOM, the module
set, the active profiles, or the `-D` and `-P` options. The error annotation
lists the changes and raeva's hint. A POM edit that resolves to the same lock
passes, and so does a version bump of the reactor's own modules, such as a
`mvn versions:set` or release commit, when nothing else changes. A broken or
conflicted lock fails with exit 3 (`LOCKFILE_INVALID`), and a platform the
`platforms` input names but the lock lacks fails with exit 3
(`PLATFORM_MISSING`).

raeva evaluates POM profiles with the runner's JDK. When a profile activates
by JDK version and CI builds on several JDKs, list them in `raeva.toml` and
run `raeva sync`:

```toml
[lock]
jdks = ["17", "21"]
```

The lock then holds one result per JDK, and the check passes on any JDK the
list names. Without `jdks`, run the check on the JDK the lock was written
with. Set `JAVA_HOME` locally too: without it, raeva assumes Java 17.

## Bot pull requests

A dependency bot changes a POM but not `raeva.lock`, so the check fails on its
pull request. The job summary then also shows the proposed lock, the diff
that `raeva sync` would write, with the command that fixes it. raeva writes
it in the working directory, and the step puts the committed lock back: the
check still fails, and later steps see the committed lock.

There are three ways to get the lock commit:

- **Tier 1: `examples/relock.yml` with an App token or a fine-grained
  token.** The workflow writes the lock and pushes it as a second commit,
  `Update raeva.lock [dependabot skip]`, and CI runs on it at once. This is
  the only unattended setup, and it is for Dependabot. Create a GitHub App
  with Contents read and write, install it on the repository, and store its
  client ID as the variable `RELOCK_APP_CLIENT_ID` and its private key as the
  secret `RELOCK_APP_PRIVATE_KEY`. A fine-grained token with Contents read and
  write on the repository, stored as the secret `RELOCK_TOKEN`, works too.
  Dependabot runs see only Dependabot secrets, so store the secret there as
  well.
- **Tier 2: `examples/relock.yml` with the default token.** The lock commit
  arrives by itself. GitHub creates the runs of a commit pushed with
  `GITHUB_TOKEN` but does not start them: they wait as `action_required` until
  someone with write access clicks "Approve and run". That happens once per
  relock, and again after each Dependabot rebase. Approve only the runs of
  the branch's latest commit: an approved Relock run of an older commit
  cancels the running one, as both are in one concurrency group.
- **Tier 3: no relock workflow.** A maintainer checks out the branch, runs
  `raeva sync`, and pushes `raeva.lock`.

`[dependabot skip]` lets Dependabot keep rebasing its branch: when the
branch conflicts after another pull request merged, Dependabot rebases its own
commit, drops the lock commit, and the workflow writes the lock again.

Hosted Renovate (the Mend app) stays at Tier 3 for now. It stops rebasing a
branch that has another author's commit. Its `gitIgnoredAuthors` setting with
the lock commit's author,
`["41898282+github-actions[bot]@users.noreply.github.com"]`, should let it
keep rebasing, but that is not yet verified through a conflict and a rebase,
so `relock.yml` runs only for Dependabot. A self-hosted Renovate writes the
lock itself with `postUpgradeTasks`, as in `examples/renovate-self-hosted.json`;
its admin installs raeva on the Renovate host and allows the command in the
global `allowedCommands`, such as `["^raeva sync$"]`.

The relock workflow never pushes to main or uses `pull_request_target`.

The relock job resolves the POMs, so a build that reads a private Maven
repository needs its credentials there too. Dependabot runs see only
Dependabot secrets: store the credentials there, and give them to raeva as
`examples/private.yml` does, with the `actions/setup-java` `server-id`,
`server-username-env-var`, and `server-password-env-var` inputs and the
`settings` input of setup-raeva. Without them, relock fails with `AUTH`.

## Dependency updates

Dependabot updates the `uses:` line of setup-raeva, but not its `version`
input. Renovate updates `version` with a regex manager in `renovate.json`:

```json
{
  "customManagers": [
    {
      "customType": "regex",
      "managerFilePatterns": ["/^\\.github/workflows/[^/]+\\.ya?ml$/"],
      "matchStrings": [
        "uses: raeva-io/setup-raeva@[^\\n]+\\n[ \\t]+with:[ \\t]*\\n(?:[ \\t]+[a-z-]+:[^\\n]*\\n)*?[ \\t]+version:[ \\t]*\"?(?<currentValue>\\d+\\.\\d+\\.\\d+)\"?"
      ],
      "depNameTemplate": "raeva-io/raeva",
      "datasourceTemplate": "github-releases",
      "extractVersionTemplate": "^v(?<version>.+)$"
    }
  ]
}
```

Every Maven update rewrites `raeva.lock`, so once one Dependabot pull
request merges, the others conflict in the lock. Group the Maven updates in
`.github/dependabot.yml`, so that one pull request per run carries them:

```yaml
version: 2
updates:
  - package-ecosystem: maven
    directory: /
    schedule:
      interval: weekly
    groups:
      maven:
        patterns: ["*"]
```

With Tier 1 or 2, Dependabot rebases a conflicted branch and the relock
workflow writes the lock again. With Tier 3, a maintainer's lock commit
stops Dependabot from rebasing that branch, so fewer pull requests mean
fewer locks to write by hand.

With `check-mode: report-only`, the check on a bot pull request passes with
a stale lock. Merging it puts the stale lock on the default branch, where
the report-only check passes too. Switch to `blocking` once a relock tier
writes the lock on bot pull requests.

## Vulnerabilities on pull requests

With `vuln: true`, a pull request scan reads `raeva.lock` from the PR base
commit and passes it as `raeva vuln --baseline <lockfile>`; a `merge_group`
run reads it from the merge group's base commit. Only new findings
at `vuln-fail-on` or above fail the job. Existing findings stay in the SARIF
log and job summary. The summary labels each compared result `new` or
`existing`, including results suppressed by VEX. Pushes and scheduled runs
check all findings.

The action reads the base commit's Git objects through the GitHub API with
`contents: read`. It neither checks out the base tree nor runs its code.
This also works with shallow checkouts and fork PRs. Each `working-directory`
uses its own base lock, independently of `lock-diff`.

If the base tree has no lock for that root, the action prints a notice and
scans with `--fail-on never`. Scan errors still fail the job. So the pull
request that adds `raeva.lock` passes by design, even with a Critical
finding. Pushes and scheduled runs after the merge apply `vuln-fail-on` to
every finding. A failed fetch,
an unreadable lock, or a symlink at the lock path fails instead of skipping
the baseline. `lock-diff: only` still skips the scan.

## SNAPSHOT dependencies

- The pull request check restores the pinned SNAPSHOT builds and checks the
  POMs against the lock. It does not look for newer builds, so a new upstream
  build does not fail open pull requests.
- `examples/drift.yml` finds them: it runs `raeva sync --update`, as
  `mvn -U` does, in its own checkout, and fails when the result differs from
  the committed lock. It reports a new SNAPSHOT build, a new version in a
  range, and a republished POM. Add it when the project has SNAPSHOT or range
  dependencies.
- Offline: `raeva sync --frozen --offline` checks the lock against the POMs
  with cached data and fails when the store lacks a pinned file. Follow it
  with `raeva lock verify --offline`, which also hashes every stored file
  against its pin.

## Several Maven roots

Use one step, or one matrix leg, per root with `working-directory`. Each
root has its own `raeva.lock`, cache key, lock diff artifact, and SARIF log.
The code scanning category defaults to `raeva` for the repository root and
`raeva/<working-directory>` otherwise, so the alerts of two roots do not
replace each other. In `examples/relock.yml`, list the roots in `ROOTS` and,
in the same order, in the `root` matrix; a relock leg fails when the two
differ. The push job accepts from each relock job only that root's files.
One commit carries every changed lock.

## Private repositories and forks

Give raeva the repository credentials through a settings file whose
`<server>` reads them with `${env.NAME}`, as `examples/private.yml` does with
`actions/setup-java` (`server-username-env-var` and
`server-password-env-var`) and the `settings` input.

The store holds every locked jar, private ones included. Every run restores
the default branch's cache, a pull request from a fork too. In a public
repository with private dependencies, set `cache: false` on the job that has
credentials, so the default branch never saves one.

A pull request from a fork gets no secrets and a read-only token, even when
the fork's author is a collaborator, unless the settings of a private
repository send them. The read-only token can still read the base commit's
`raeva.lock`, so `lock-diff: only` shows the lock diff in a job without
credentials.

## Options that change resolution

The `settings`, `profiles` and `properties` inputs pass `-s`, `-P` and `-D`
to every raeva command, as for `mvn`. Use them only for options that change
resolution, such as a CI profile or a property that a profile activation or a
version reads, and pass the same ones to `raeva sync` when you write the lock.
Only `-D` names read by the models or settings are lock inputs. An unused
build flag such as `-DskipTests` does not invalidate the lock. Keep build
flags in the Maven step.

## Other CI systems

`examples/gitlab-ci.yml` and `examples/Jenkinsfile` download the release
archive, check it against a SHA-256 pinned in the file, and run
`raeva sync --frozen` before an unchanged Maven build. Take the SHA-256 from
the release's `sha256.sum`:

```sh
curl -fsSL https://github.com/raeva-io/raeva/releases/download/v0.5.0/sha256.sum \
  | grep raeva-x86_64-unknown-linux-gnu.tar.gz
```

Check it against the release's build attestation once, where `gh` is
installed: `gh attestation verify raeva-x86_64-unknown-linux-gnu.tar.gz
--repo raeva-io/raeva`. For Alpine or another musl image, select the
`x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl` archive instead.

## What the action does

1. Downloads the archive for the runner, such as
   `raeva-x86_64-unknown-linux-gnu.tar.gz`, from the GitHub release
   `v<version>`. For a private `repository` it downloads through `gh` with
   `token`.
2. Checks the archive's SHA-256. For the versions in `known-checksums.txt` it
   must match the value pinned in this action, so a release asset replaced
   after the action release is refused. For other versions it must match the
   release's `sha256.sum`.
3. With `verify: attestation`, the default, runs `gh attestation verify` on the
   archive. The attestation must come from `raeva-io/raeva`, from
   `.github/workflows/release.yml`, at `refs/tags/v<version>`, on a
   GitHub-hosted runner.
4. Installs the binary as `raeva` into a directory under `RUNNER_TEMP` and adds
   that directory to `PATH`. With `rv-alias: true` it also installs `rv`.
5. With `cache: true`, restores the artifact store and `metadata.db` with
   `actions/cache`, keyed by the raeva version, the OS, the architecture, and
   the SHA-256 of the lock file. On a push to the default branch, a successful job saves them at
   its end when the key missed.
6. With `check: true`, runs `raeva sync --frozen`. A failure gives an error
   annotation on `raeva.lock` with the error code, the changes, and raeva's
   hints. raeva's warnings become one annotation per warning code, except
   `HTTP_REPO_BLOCKED`, `TRANSITIVE_REPO_DROPPED`, and `WEAK_HASH_FALLBACK`,
   which only the job summary lists. With `check-mode: report-only`, a stale
   or missing lock warns instead; other errors still fail. With report-only,
   and on a bot's pull request, the summary shows the proposed lock diff and
   a fix command, and the full diff goes to an artifact,
   `raeva-lock-proposed-` followed by the working directory and a hash.
7. With `lock-diff: true`, the default, on a pull request: compares the base
   commit's `raeva.lock` with this one, writes `raeva lock diff` to the job
   summary, and uploads the full diff as an artifact, `raeva-lock-diff-`
   followed by the working directory and a hash of it and the options; the
   summary names it. Linux and macOS.
8. With `vuln: true`, runs `raeva vuln --format sarif`, writes a findings
   table to the job summary, uploads the log to code scanning, and then fails
   the job if a finding meets `vuln-fail-on`. On pull requests and in merge
   queues only new findings count. The summary and the error annotation
   count the findings that fail the job and name up to five of their
   advisories. An incomplete scan uploads the findings it has and fails the
   job. When code scanning answers the job token that it is not enabled, as
   in a private repository without GitHub Code Security, the upload is
   skipped with one notice. It is also skipped when the token may not use
   code scanning, except in a `pull_request` run: code scanning takes those
   uploads from a read-only token.
9. With `relock: true`, runs `raeva sync` for every platform the lock
   records, also from a conflicted lock. JDK suffixes stay in the lock; keep
   `[lock] jdks` in `raeva.toml` for a JDK matrix. The action never commits
   or pushes; see `examples/relock.yml`.

The action has no option to skip verification, and it never runs an installer
script. The cargo-dist PowerShell installer does not check checksums, and the
shell installer skips the check when `sha256sum` is missing.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `version` | required | An exact version such as `0.5.0`, or `latest`. |
| `verify` | `attestation` | `attestation` checks the SHA-256 and the build attestation. `sha256` checks the SHA-256 only, for runners without `gh`. |
| `token` | `github.token` | Read token for the attestation, a private release download, and the base commit's lock. |
| `cache` | `true` | Restore the artifact store and metadata cache; pushes to the default branch also save them. |
| `working-directory` | `.` | The directory with the root `pom.xml` and `raeva.lock`. |
| `check` | `false` | Run `raeva sync --frozen`. |
| `check-mode` | `blocking` | With `check: true`, use `report-only` to report lock changes with a proposed diff and fix command, and a missing lock with a warning. Other check errors still fail. |
| `platforms` | empty | Platforms for `check` and `relock`, such as `linux-x86_64,macos-aarch64`. Empty means every platform the lock records. |
| `settings` | empty | A Maven settings file, relative to the workspace, that `check`, `vuln` and `relock` read in place of `~/.m2/settings.xml`, passed as `-s`. |
| `profiles` | empty | Maven profile ids, comma separated (`ci,!slow`), passed as `-P`. Only profiles that change resolution. |
| `properties` | empty | Maven user properties, one `name=value` per line, each passed as `-D`. Only properties that change resolution; see "Options that change resolution". |
| `lock-diff` | `true` | With `check`, write the pull request's lock diff to the job summary and an artifact. `only` writes the diff and skips `check` and `vuln`. Linux and macOS; `only` fails on Windows. |
| `relock` | `false` | Run `raeva sync` for every recorded platform. Linux and macOS only. |
| `vuln` | `false` | Run `raeva vuln --format sarif`. |
| `vuln-fail-on` | `high` | `any`, `low`, `medium`, `high`, `critical`, or `never`, which reports findings without failing the job. |
| `vex` | empty | OpenVEX files, one path per line relative to the workspace, passed as `--vex`. Suppressed results stay in the SARIF log but are not counted as findings. |
| `sarif-upload` | `true` | Upload the SARIF log. The job needs `security-events: write`; a private repository also needs GitHub Code Security. |
| `sarif-category` | empty | Code scanning category; empty means one per `working-directory`. |
| `rv-alias` | `false` | Also install the command as `rv`. |
| `repository` | `raeva-io/raeva` | Where releases and attestations come from. |
| `download-base-url` | empty | A mirror that serves the archives, and `sha256.sum` for versions this action does not pin. |

## Outputs

`version`, `bin-dir`, `raeva` (full path of the binary),
`relocked-platforms`, `cache-hit`, `frozen-exit-code`, `proposed-diff`,
`fix-command`, `sarif-file`, `sarif-category`, and `vuln-findings`.

`proposed-diff` is the path of `proposed.diff`, kept until the job ends and
uploaded as an artifact. `fix-command` includes the job's Maven option names.
Property values appear as `<value>` placeholders; replace them before running
the command. An absolute settings path is omitted, with a note in the
summary.
`frozen-exit-code` keeps the original check result, including 7 when
report-only mode allows lock changes.

## Runners

| Runner | Build used | Scripts |
| --- | --- | --- |
| Linux x64 and ARM64 (glibc) | `x86_64-` or `aarch64-unknown-linux-gnu` | bash |
| Linux x64 and ARM64 (musl, including Alpine) | `x86_64-` or `aarch64-unknown-linux-musl` | bash |
| macOS x64 and ARM64 | `x86_64-` or `aarch64-apple-darwin` | bash |
| Windows x64 | `x86_64-pc-windows-msvc` | pwsh |
| Windows ARM64 | `x86_64-pc-windows-msvc` under emulation | pwsh |

On Windows the action installs, caches, and runs `check`, with the proposed
lock, and `vuln`; `relock` and `lock-diff` need Linux or macOS, and
`relock: true` and `lock-diff: only` fail there. PR vulnerability baselines
and report-only lock checks work in both shells. On Linux, an Alpine release
file or a musl `ldd --version` reply selects the musl archive. Containers
need Bash, curl, tar, and jq, plus a SHA-256 tool.
`verify: attestation` needs `gh`, which every GitHub-hosted image has. On a
self-hosted runner without `gh`, set `verify: sha256`.

## The cache

The cache holds `store` and `metadata.db` from the raeva data directory:
`~/.local/share/raeva` on Linux, `~/Library/Application Support/raeva` on
macOS, `%LOCALAPPDATA%\raeva` on Windows, or `$RAEVA_HOME` when it is set. It
does not hold `config.toml` or credentials.

Only pushes to the default branch save it, including the first run with an
empty cache. Pull requests, merge queues, and scheduled runs restore it. The
examples run on pushes to `main`; when your default branch is `master` or
`develop`, put its name in `branches: [main]`, or no run saves a cache. A
push to any other branch restores the default branch's cache and saves none.
A cache that a pull request saved would serve only that pull request, and
saving takes longer than a cold check.

raeva re-hashes a stored file against its pin before `export-m2` copies it,
and an online `sync --frozen` downloads a file again when the stored copy is
missing or does not match. A warm cache therefore does not show that the
locked files can still be downloaded, and a restored `metadata.db` means
`--frozen` does not fetch verified release POMs again, so it does not see a
parent POM or BOM that was republished upstream. A scheduled job with
`cache: false`, such as the weekly run of `examples/vuln.yml`, does. A partial
match from `restore-keys` brings files that the lock no longer uses, so the
cache grows until GitHub evicts it or `version` changes: a new raeva version
starts from an empty cache.

## Security notes

- Every input reaches the scripts as an environment variable, never as script
  text.
- `token` goes to the install step, for `gh`, and to the check step, which
  reads the base commit's lock through the GitHub API. The check step also
  gets the job token, to ask code scanning whether it takes an upload. raeva
  never sees either, and neither needs a write scope from the action.
- raeva's output quotes POM and repository data, so the action replays it
  with workflow commands turned off.
- Text from raeva quotes POM and repository data, so the summary puts it in a
  fence it cannot close, and escapes Markdown in the findings table.
- The proposed lock for report-only checks and bot pull requests comes from a
  `raeva sync` in the working directory. The step puts the committed lock
  back before it ends.
- In `examples/relock.yml`, the push job gives git its token through the
  environment, not the command line, and only for the push. It writes only
  the bytes of each lock, so an artifact cannot change a file's mode, and
  the push refuses a branch that moved or was deleted during the run.
- The SARIF upload needs `security-events: write`, and in a private
  repository also `actions: read` and GitHub Code Security. A refused upload
  logs an error but does not fail the job; findings still fail it.
- `known-checksums.txt` changes only in a reviewed pull request, after the
  release's attestations were verified.

## Development

`.github/workflows/test.yml` runs the action on Linux, macOS, and Windows
runners against the raeva release in `RAEVA_VERSION`: install with
attestation and with SHA-256 only, the frozen check on a current and on a
stale lock, and the vuln scan. Its `scripts` job runs the scripts outside the
composite action:

- `test/local.sh` runs the install and check scripts, with bash and with pwsh,
  against a fake release built from a raeva binary and against the real
  release with its attestation. It needs `RAEVA_BUILD`, `PROJECT` (a project
  with a three-platform lock), and `VULN_PROJECT`; `PWSH`, `GH_TOKEN`, and
  `RELEASE_VERSION` enable more tests.
- `test/check.sh` tests report-only checks and PR baselines with fixed CLI
  and API replies. `PWSH` enables the same cases in PowerShell. It also
  checks that each action output reads both the Bash and the PowerShell step.
- `test/install.sh` tests glibc and musl selection with local release archives.
- `test/relock.sh` runs the `run:` blocks of `examples/relock.yml` against a
  local bare repository with two Maven roots, including tampered artifacts
  and a lock with merge conflict markers. It needs `RAEVA_BUILD` and
  `PROJECT`.

## License

MIT OR Apache-2.0
