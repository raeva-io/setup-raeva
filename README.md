# setup-raeva

`raeva-io/setup-raeva` installs a pinned [raeva](https://github.com/raeva-io/raeva)
release on a GitHub Actions runner and checks the download before it runs. It
can also cache the raeva artifact store, check that `raeva.lock` is current,
show what a pull request changes in the lock, and scan the lock for known
vulnerabilities.

## Quick start

Keep your Maven build as it is and add one job that checks the lock
(`examples/ci.yml`):

```yaml
raeva:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      with:
        persist-credentials: false
    - uses: actions/setup-java@b843ebf9b913146b38da2eaa7aeddf76074ae1ad # v6.1.0
      with:
        distribution: temurin
        java-version: "21"
    - uses: raeva-io/setup-raeva@v1.0.0
      with:
        version: 0.5.0
        check: true
        platforms: linux-x86_64,macos-aarch64,windows-x86_64
```

The job runs `raeva sync --frozen` on a cold runner: it downloads the locked
artifacts into the store and fails when `raeva.lock` no longer matches the
POMs. On a pull request, the job summary lists what the pull request changes
in the lock. One Linux job can check every platform the lock records.

Releases of this action are immutable, so `@v1.0.0` always names the same
commit; `@<commit SHA> # v1.0.0` pins it by SHA. Dependabot and Renovate update
either form.

Set `version` to an exact raeva release, 0.5.0 or newer, the one your
developers use. A lock written by a newer raeva can use a schema that an older
one refuses.

## Recipes

| File | What it does |
| --- | --- |
| `examples/ci.yml` | The check next to an unchanged Maven build. |
| `examples/enforce.yml` | Builds offline from the locked artifacts only, with Maven Trusted Checksums from `raeva export-checksums`, for a dependency graph without version ranges or SNAPSHOTs, transitive ones included. |
| `examples/relock.yml` | Writes `raeva.lock` again on Dependabot and Renovate pull requests and pushes it to the PR branch. |
| `examples/drift.yml` | A scheduled job that resolves again and fails when the result differs from the committed lock. |
| `examples/private.yml` | A public repository whose build reads a private Maven repository, with a credential-free job for fork pull requests. |
| `examples/vuln.yml` | Scans the lock and uploads the findings to code scanning. |
| `examples/renovate-self-hosted.json` | `postUpgradeTasks` for a self-hosted Renovate. |
| `examples/gitlab-ci.yml` | The same check on GitLab CI. |

## What fails the check

`raeva sync --frozen` fails with exit 7 (`LOCKFILE_MISMATCH`) when resolving
again changes the lock: a dependency, a SNAPSHOT build, a POM pin, a module's
coordinates (a project version bump, so a release commit needs `raeva sync`
too), or the active profiles. The error annotation lists the changes and
raeva's own hint. A POM edit that resolves to the same lock passes. A broken
or conflicted lock fails with exit 3 (`LOCKFILE_INVALID`).

raeva evaluates POM profiles with the runner's `JAVA_HOME`. A profile that
tests the JDK version gives the same lock only on a JDK with the same
outcome, so run the check on the JDK the lock was written with; other legs
of a JDK matrix build without it.

## Bot pull requests

`examples/relock.yml` runs `raeva sync` on a bot's pull request and pushes
the new lock as a second commit, `Update raeva.lock [dependabot skip]`. The
`[dependabot skip]` marker lets Dependabot keep rebasing its branch: when the
branch conflicts after another pull request merged, Dependabot rebases its own
commit, drops the lock commit, and the workflow writes the lock again.

A push made with the default `GITHUB_TOKEN` starts no `push` workflow, and
the `pull_request` runs of the new commit wait as `action_required` until
someone with write access approves them, so a required check stays pending
until then. With a GitHub App token the runs
start at once. Create an App with `contents: write` on the repository, store
its client ID as the variable `RELOCK_APP_CLIENT_ID` and its key as the
secret `RELOCK_APP_PRIVATE_KEY` (a Dependabot secret too, since Dependabot
runs see only Dependabot secrets), and the push job uses it.

Hosted Renovate (the Mend app) cannot run raeva, so use `relock.yml` there
too. Renovate stops rebasing a branch that has another author's commit, so
add the lock commit's author, which `relock.yml` sets with either token, to
`gitIgnoredAuthors` in `renovate.json`:
`["41898282+github-actions[bot]@users.noreply.github.com"]`. A self-hosted Renovate can write the lock itself with
`postUpgradeTasks`, as in `examples/renovate-self-hosted.json`; its admin must
install raeva on the Renovate host and allow the command in the global
`allowedCommands`, such as `["^raeva sync --platforms [a-z0-9_,-]+$"]`.

## SNAPSHOT dependencies

- The pull request job: an online `check` with `cache: true`. raeva checks a
  SNAPSHOT by its repository's update policy. With `always`, a new upstream
  build fails the check of every open pull request until the lock is
  written again. With `daily` or an interval, the policy is measured from the
  lock file's modification time, which a fresh checkout resets, so the check
  passes until `drift.yml` reports the new build.
- Offline: `raeva sync --frozen --offline` checks the lock against the POMs
  with cached data only. It does not check the store, so follow it with
  `raeva lock verify --offline` or `raeva export-m2 --offline`, which fail when
  a locked file is missing. A cache miss then fails the job.
- Drift: `examples/drift.yml` runs `raeva sync --update` in its own checkout,
  as `mvn -U` does, and compares the result with `raeva lock diff`. It reports
  a new SNAPSHOT build, a new version in a range, and a republished POM.

## Several Maven roots

Use one step, or one matrix leg, per root with `working-directory`. Each
root has its own `raeva.lock` and cache key. The code scanning category
defaults to `raeva` for the repository root and `raeva/<working-directory>`
otherwise, so the alerts of two roots do not replace each other.

## Private repositories and forks

Give raeva the repository credentials through a `settings.xml` `<server>`
that reads them with `${env.NAME}`, as `examples/private.yml` does with
`actions/setup-java`.

The store holds every locked jar, private ones included. A pull request
restores the cache of its base branch, and so does a pull request from a
fork. In a public repository with private dependencies, set `cache: false`
on the job that has credentials, or never save a cache there.

A pull request from a fork gets no secrets and a read-only token, even when
the fork's author is a collaborator, unless the settings of a private
repository send them. The read-only token can still read the base commit's
`raeva.lock`, so `lock-diff: only` shows the lock diff in a job without
credentials.

## What the action does

1. Downloads `sha256.sum` and the archive for the runner, such as
   `raeva-x86_64-unknown-linux-gnu.tar.gz`, from the GitHub release
   `v<version>`. For a private `repository` it downloads through `gh` with
   `token`.
2. Checks the archive's SHA-256. For the versions in `known-checksums.txt`, the
   SHA-256 must also match the value pinned in this action, so a release asset
   replaced after the action release is refused.
3. With `verify: attestation`, the default, runs `gh attestation verify` on the
   archive. The attestation must come from `raeva-io/raeva`, from
   `.github/workflows/release.yml`, at `refs/tags/v<version>`, on a
   GitHub-hosted runner.
4. Installs the binary as `raeva` into a directory under `RUNNER_TEMP` and adds
   that directory to `PATH`. With `rv-alias: true` it also installs `rv`.
5. With `cache: true`, restores the artifact store and `metadata.db` with
   `actions/cache`, keyed by the OS, the architecture, and the SHA-256 of the
   lock file. A successful job saves them when the key missed.
6. With `check: true`, runs `raeva sync --frozen`. A failure gives an error
   annotation on `raeva.lock` with the error code, the changes, and raeva's
   hints. raeva's warnings become one annotation per warning code.
7. With `lock-diff: true`, the default, on a pull request: compares the base
   commit's `raeva.lock` with this one and writes `raeva lock diff` to the job
   summary. Linux and macOS.
8. With `vuln: true`, runs `raeva vuln --format sarif`, uploads the log to code
   scanning, and then fails the job if a finding meets `vuln-fail-on`. An
   incomplete scan uploads the findings it has and fails the job.
9. With `relock: true`, runs `raeva sync` for every platform the lock records,
   read from the lock text so a conflicted lock is written again. The action
   never commits or pushes; see `examples/relock.yml`.

The action has no option to skip verification, and it never runs an installer
script. The cargo-dist PowerShell installer does not check checksums, and the
shell installer skips the check when `sha256sum` is missing.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `version` | required | An exact version such as `0.5.0`, or `latest`. |
| `verify` | `attestation` | `attestation` checks the SHA-256 and the build attestation. `sha256` checks the SHA-256 only, for runners without `gh`. |
| `token` | `github.token` | Read token for the attestation, a private release download, and the base commit's lock. |
| `cache` | `true` | Cache the artifact store and metadata cache. |
| `working-directory` | `.` | The directory with the root `pom.xml` and `raeva.lock`. |
| `check` | `false` | Run `raeva sync --frozen`. |
| `platforms` | empty | Platforms for `check` and `relock`, such as `linux-x86_64,macos-aarch64`. Empty means the runner's platform for `check` and every recorded platform for `relock`. |
| `lock-diff` | `true` | With `check`, write the pull request's lock diff to the job summary. `only` writes the diff and skips `check` and `vuln`. |
| `relock` | `false` | Run `raeva sync` for every recorded platform. Linux and macOS only. |
| `vuln` | `false` | Run `raeva vuln --format sarif`. |
| `vuln-fail-on` | `high` | `any`, `low`, `medium`, `high`, `critical`, or `never`. |
| `vex` | empty | OpenVEX files, one path per line relative to the workspace, passed as `--vex`. Suppressed results stay in the SARIF log but are not counted as findings. |
| `sarif-upload` | `true` | Upload the SARIF log. The job needs `security-events: write`. |
| `sarif-category` | empty | Code scanning category; empty means one per `working-directory`. |
| `rv-alias` | `false` | Also install the command as `rv`. |
| `repository` | `raeva-io/raeva` | Where releases and attestations come from. |
| `download-base-url` | empty | A mirror that serves `sha256.sum` and the archives. |

## Outputs

`version`, `bin-dir`, `raeva` (full path of the binary),
`relocked-platforms`, `cache-hit`, `frozen-exit-code`, `sarif-file`,
`sarif-category`, and `vuln-findings`.

## Runners

| Runner | Build used | Scripts |
| --- | --- | --- |
| Linux x64 and ARM64 | `x86_64-` or `aarch64-unknown-linux-gnu` | bash |
| macOS x64 and ARM64 | `x86_64-` or `aarch64-apple-darwin` | bash |
| Windows x64 | `x86_64-pc-windows-msvc` | pwsh |
| Windows ARM64 | `x86_64-pc-windows-msvc` under emulation | pwsh |

On Windows the action installs, caches, and runs `check` and `vuln`; `relock`
and `lock-diff` need Linux or macOS. Release builds need glibc. The action
refuses a musl system, such as an Alpine container. `verify: attestation`
needs `gh`, which every GitHub-hosted image has. On a self-hosted runner
without `gh`, set `verify: sha256`.

## The cache

The cache holds `store` and `metadata.db` from the raeva data directory:
`~/.local/share/raeva` on Linux, `~/Library/Application Support/raeva` on
macOS, `%LOCALAPPDATA%\raeva` on Windows, or `$RAEVA_HOME` when it is set. It
does not hold `config.toml` or credentials.

raeva re-hashes a stored file against its pin before `export-m2` copies it,
and an online `sync --frozen` downloads a file again when the stored copy does
not match. A partial match from `restore-keys` brings files that the lock no
longer uses, so the cache grows until GitHub evicts it.

A restored `metadata.db` means `--frozen` does not fetch verified release POMs
again, so it does not see a parent POM or BOM that was republished upstream
with other bytes. A scheduled job with `cache: false` does.

## Security notes

- Every input reaches the scripts as an environment variable, never as script
  text.
- `token` goes to the install step, for `gh`, and to the check step, which
  reads the base commit's lock through the contents API. raeva never sees it,
  and it needs no write scope.
- Text from raeva quotes POM and repository data, so the summary puts it in a
  fence it cannot close.
- The SARIF upload needs `security-events: write`, and in a private
  repository also `actions: read` and GitHub Code Security. A refused upload,
  such as one to a private repository without Code Security or from a
  Dependabot `push` with a read-only token, logs an error but does not fail
  the job; findings still fail it.
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
- `test/relock.sh` runs the `run:` blocks of `examples/relock.yml` against a
  local bare repository, including a lock with merge conflict markers. It
  needs `RAEVA_BUILD` and `PROJECT`.

## License

MIT OR Apache-2.0
