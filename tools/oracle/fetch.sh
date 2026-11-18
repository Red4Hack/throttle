#!/usr/bin/env bash
# Extracts the legacy binaries (minidump_stackwalk, carburetor) from the `php-final`
# tag into tools/oracle/bin/ (ignored by git). They only serve as an "oracle" to
# compare the Rust rewrite's output against; none of this ships in the runtime.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
dest=tools/oracle/bin
mkdir -p "$dest"

for b in minidump_stackwalk carburetor; do
  git show "php-final:bin/$b" > "$dest/$b"
  chmod +x "$dest/$b"
  echo "extracted: $dest/$b"
done

# minidump_stackwalk is an i386 ELF: it needs 32-bit libstdc++ (e.g. lib32-gcc-libs).
# (with no arguments it prints "Usage" and exits 1, so we capture the output
# before the grep to keep pipefail from giving a false negative.)
probe=$("$dest/minidump_stackwalk" 2>&1 || true)
if ! grep -q Usage <<<"$probe"; then
  echo "WARNING: minidump_stackwalk did not run; install the 32-bit libs." >&2
  exit 1
fi
