#!/usr/bin/env bash
# Check target selection with local archives and a fixed ldd reply.
# shellcheck disable=SC2015
set -uo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
t=$(mktemp -d "${TMPDIR:-/tmp}/setup-raeva-install.XXXXXX")
trap 'rm -rf "${t:?}"' EXIT
pass=0 fail=0
export HOME="$t/home" RAEVA_HOME="$t/raeva-home"
unset GH_TOKEN
mkdir -p "$HOME" "$t/bin" "$t/release" "$t/temp"
cat > "$t/bin/ldd" <<'SH'
#!/usr/bin/env bash
echo "${TEST_LIBC:-glibc}"
exit "${TEST_LDD_CODE:-0}"
SH
chmod +x "$t/bin/ldd"
for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-apple-darwin; do
  mkdir -p "$t/release/raeva-$target"
  printf '#!/usr/bin/env bash\necho raeva 9.9.9\n' > "$t/release/raeva-$target/raeva"
  chmod +x "$t/release/raeva-$target/raeva"
  tar -czf "$t/release/raeva-$target.tar.gz" -C "$t/release" "raeva-$target"
  (cd "$t/release" && sha256sum "raeva-$target.tar.gz") >> "$t/release/sha256.sum"
done
for case in Linux/X64/glibc/x86_64-unknown-linux-gnu Linux/ARM64/glibc/aarch64-unknown-linux-gnu Linux/X64/musl/x86_64-unknown-linux-musl Linux/ARM64/musl/aarch64-unknown-linux-musl macOS/X64/musl/x86_64-apple-darwin; do
  IFS=/ read -r os arch libc target <<< "$case"
  : > "$t/output"
  env PATH="$t/bin:$PATH" RUNNER_OS="$os" RUNNER_ARCH="$arch" RUNNER_TEMP="$t/temp" \
    TEST_LIBC="$libc" TEST_LDD_CODE=1 INPUT_VERSION=9.9.9 INPUT_VERIFY=sha256 \
    INPUT_DOWNLOAD_BASE_URL="file://$t/release" GITHUB_OUTPUT="$t/output" \
    bash "$here/scripts/install.sh" > "$t/log" 2>&1
  code=$?
  if [[ $code -eq 0 ]] && grep -q "^raeva=.*/raeva-9.9.9-$target/bin/raeva$" "$t/output"; then
    pass=$((pass + 1)); echo "PASS install $case with nonzero ldd"
  else
    fail=$((fail + 1)); echo "FAIL install $case (exit $code)"; cat "$t/log"
  fi
done
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
