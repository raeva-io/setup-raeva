# setup-raeva

`raeva-io/setup-raeva` installs a pinned [raeva](https://github.com/raeva-io/raeva)
release on a GitHub Actions runner and checks the download before it runs. It
can also cache the raeva artifact store, check that `raeva.lock` is current,
and scan the lock for known vulnerabilities.

```yaml
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
- run: raeva export-m2
- run: mvn --batch-mode verify
```

Releases of this action are immutable, so `@v1.0.0` always names the same
commit; `@<commit SHA> # v1.0.0` pins it by SHA. Dependabot and Renovate update
either form.

Set `version` to an exact raeva release, the one your developers use. A lock
written by a newer raeva can use a schema that an older one refuses.

## What the action does

1. Downloads `sha256.sum` and the archive for the runner from the GitHub
   release `v<version>`. It picks the archive by target triple, such as
   `x86_64-unknown-linux-gnu`.
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
   lock file. The job saves them when it ends.
6. With `check: true`, runs `raeva sync --frozen`. On failure, the job log
   shows an error annotation with the error code, such as `LOCKFILE_MISMATCH`,
   and what to do.
7. With `vuln: true`, runs `raeva vuln --format sarif`, uploads the log to code
   scanning, and then fails the job if a finding meets `vuln-fail-on`.
8. With `relock: true`, runs `raeva sync` for every platform the lock records.
   The action never commits or pushes; see `examples/relock.yml`.

The action has no option to skip verification, and it never runs an installer
script. The cargo-dist PowerShell installer does not check checksums, and the
shell installer skips the check when `sha256sum` is missing.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `version` | required | An exact version such as `0.5.0`, or `latest`. |
| `verify` | `attestation` | `attestation` checks the SHA-256 and the build attestation. `sha256` checks the SHA-256 only, for runners without `gh`. |
| `token` | `github.token` | Read token for `gh attestation verify`. |
| `cache` | `true` | Cache the artifact store and metadata cache. |
| `working-directory` | `.` | The directory with the root `pom.xml` and the lock file. |
| `lock-file` | empty | The lock file name. Empty means `raeva.lock`, or `rv.lock` when only that exists. |
| `check` | `false` | Run `raeva sync --frozen`. |
| `platforms` | empty | Platforms for `check` and `relock`, such as `linux-x86_64,macos-aarch64`. Empty means the runner's platform for `check` and every recorded platform for `relock`. |
| `relock` | `false` | Run `raeva sync` for every recorded platform. Linux and macOS only. |
| `vuln` | `false` | Run `raeva vuln --format sarif`. |
| `vuln-fail-on` | `high` | `any`, `low`, `medium`, `high`, `critical`, or `never`. |
| `sarif-upload` | `true` | Upload the SARIF log. The job needs `security-events: write`. |
| `sarif-category` | `raeva` | Code scanning category. |
| `rv-alias` | `false` | Also install the command as `rv`. |
| `repository` | `raeva-io/raeva` | Where releases and attestations come from. |
| `download-base-url` | empty | A mirror that serves `sha256.sum` and the archives. |

## Outputs

`version`, `bin-dir`, `raeva` (full path of the binary), `lock-file`,
`relocked-platforms`, `cache-hit`, `frozen-exit-code`, `sarif-file`, and
`vuln-findings`.

## Runners

| Runner | Build used | Scripts |
| --- | --- | --- |
| Linux x64 and ARM64 | `x86_64-` or `aarch64-unknown-linux-gnu` | bash |
| macOS x64 and ARM64 | `x86_64-` or `aarch64-apple-darwin` | bash |
| Windows x64 | `x86_64-pc-windows-msvc` | pwsh |
| Windows ARM64 | `x86_64-pc-windows-msvc` under emulation | pwsh |

Release builds need glibc. The action refuses a musl system, such as an
Alpine container. `verify: attestation` needs `gh`, which every GitHub-hosted
image has. On a self-hosted runner without `gh`, set `verify: sha256`.

## The cache

The cache holds `store` and `metadata.db` from the raeva data directory:
`~/.local/share/raeva` on Linux, `~/Library/Application Support/raeva` on
macOS, `%LOCALAPPDATA%\raeva` on Windows, or `$RAEVA_HOME` when it is set. It
does not hold `config.toml` or credentials.

A pull request restores the cache of its base branch but saves only to its own
scope. raeva re-hashes a stored file against its pin before `export-m2` copies
it, and an online `sync --frozen` downloads a file again when the stored copy
does not match. A partial match from `restore-keys` brings files that the lock
no longer uses, so the cache grows until GitHub evicts it.

A restored `metadata.db` means `--frozen` does not fetch verified release POMs
again, so it does not see a parent POM or BOM that was republished upstream
with other bytes. A scheduled job with `cache: false` does.

## Security notes

- Every input reaches the scripts as an environment variable, never as script
  text.
- `token` is passed only to the install step, as `GH_TOKEN` for `gh`.
- A SARIF upload from a run with a read-only token, such as a Dependabot
  `push`, fails. That step has `continue-on-error`, so the job warns and
  continues.
- `known-checksums.txt` changes only in a reviewed pull request, after the
  release's attestations were verified.

## Development

`.github/workflows/test.yml` runs the action on Linux, macOS, and Windows
runners against the newest raeva release: install with attestation and with
SHA-256 only, the frozen check on a current and on a stale lock, and the vuln
scan. Its `scripts` job runs the scripts outside the composite action:

- `test/local.sh` runs the install and check scripts, with bash and with pwsh,
  against a fake release built from a raeva binary and against the real
  release with its attestation. It needs `RAEVA_BUILD`, `PROJECT` (a project
  with a three-platform lock), and `VULN_PROJECT`; `PWSH`, `GH_TOKEN`, and
  `RELEASE_VERSION` enable more tests.
- `test/relock.sh` runs the `run:` blocks of `examples/relock.yml` against a
  local bare repository. It needs `RAEVA_BUILD` and `PROJECT`.

## License

MIT OR Apache-2.0
