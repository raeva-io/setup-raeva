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
# macOS runners extract with bsdtar.
if command -v bsdtar >/dev/null; then
  mkdir -p "$t/bsdtar"
  ln -s "$(command -v bsdtar)" "$t/bsdtar/tar"
  env PATH="$t/bsdtar:$t/bin:$PATH" RUNNER_OS=macOS RUNNER_ARCH=X64 RUNNER_TEMP="$t/temp" \
    INPUT_VERSION=9.9.9 INPUT_VERIFY=sha256 INPUT_DOWNLOAD_BASE_URL="file://$t/release" \
    bash "$here/scripts/install.sh" > "$t/log" 2>&1 \
    && [[ -x "$t/temp/raeva-9.9.9-x86_64-apple-darwin/bin/raeva" ]] \
    && { pass=$((pass + 1)); echo "PASS install with bsdtar"; } \
    || { fail=$((fail + 1)); echo "FAIL install with bsdtar"; cat "$t/log"; }
fi
# An archive without the binary at its usual path is refused.
mkdir -p "$t/odd/raeva-9.9.9"
cp "$t/release/raeva-x86_64-unknown-linux-gnu/raeva" "$t/odd/raeva-9.9.9/raeva"
tar -czf "$t/odd/raeva-x86_64-unknown-linux-gnu.tar.gz" -C "$t/odd" raeva-9.9.9
(cd "$t/odd" && sha256sum raeva-x86_64-unknown-linux-gnu.tar.gz) > "$t/odd/sha256.sum"
env PATH="$t/bin:$PATH" RUNNER_OS=Linux RUNNER_ARCH=X64 RUNNER_TEMP="$t/temp" \
  INPUT_VERSION=9.9.9 INPUT_VERIFY=sha256 INPUT_DOWNLOAD_BASE_URL="file://$t/odd" \
  bash "$here/scripts/install.sh" > "$t/log" 2>&1
code=$?
if [[ $code -eq 1 ]] && grep -q "has no raeva-x86_64-unknown-linux-gnu/raeva" "$t/log"; then
  pass=$((pass + 1)); echo "PASS refuses an archive without the binary"
else
  fail=$((fail + 1)); echo "FAIL refuses an archive without the binary (exit $code)"; cat "$t/log"
fi
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
