#!/usr/bin/env bash
# Generates (or verifies, with --check) the legacy minidump_stackwalk golden outputs
# for each dump in tests/fixtures/dumps. The output is the `-m` (machine
# readable) format used by the legacy CrashProcessCommand.php.
#
# Usage:
#   tools/oracle/golden.sh           # rewrites tests/fixtures/golden/*.txt
#   tools/oracle/golden.sh --check   # compares and fails if anything changed
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
bin=tools/oracle/bin/minidump_stackwalk
[ -x "$bin" ] || { echo "run tools/oracle/fetch.sh first" >&2; exit 1; }

mode=write
[ "${1:-}" = "--check" ] && mode=check

fail=0
for dmp in tests/fixtures/dumps/*.dmp; do
  name=$(basename "$dmp" .dmp)
  out=tests/fixtures/golden/$name.txt
  # stderr discarded: breakpad logs timestamps, which are not deterministic.
  # The exit code becomes the last line, because invalid dumps must fail the same way.
  tmp=$(mktemp)
  set +e
  "$bin" -m "$dmp" tests/fixtures/symbols >"$tmp" 2>/dev/null
  code=$?
  set -e
  echo "exit=$code" >>"$tmp"

  if [ "$mode" = write ]; then
    mv "$tmp" "$out"
    echo "golden: $out (exit=$code)"
  else
    if diff -q "$tmp" "$out" >/dev/null; then
      echo "ok:   $name"
    else
      echo "DIFF: $name"; fail=1
    fi
    rm -f "$tmp"
  fi
done
exit $fail
