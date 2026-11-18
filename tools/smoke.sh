#!/usr/bin/env bash
# End-to-end check with the real release binary and the real HTTP protocol:
# symbols -> presubmit -> upload -> processing -> crash page -> metrics.
#
#   cargo build --release && tools/smoke.sh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
target=$(cargo metadata --format-version 1 --no-deps | jq -r .target_directory)
bin="$target/release/throttle"
[ -x "$bin" ] || { echo "build first: cargo build --release" >&2; exit 1; }

port=${PORT:-18080}
base="http://127.0.0.1:$port"
work=$(mktemp -d)
token=0123456789abcdef0123456789
server=
cleanup() { [ -n "$server" ] && kill "$server" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

cat >"$work/throttle.toml" <<EOF
listen = "127.0.0.1:$port"
data_dir = "$work/data"
metrics_token = "$token"
EOF

"$bin" --config "$work/throttle.toml" serve >"$work/server.log" 2>&1 &
server=$!

for _ in $(seq 50); do
  curl -fs "$base/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fs "$base/healthz" >/dev/null || { echo "server did not start:"; cat "$work/server.log"; exit 1; }

fail() { echo "FAIL: $*" >&2; echo "--- server log"; cat "$work/server.log" >&2; exit 1; }
step() { echo "ok: $*"; }

# 1. Symbols (raw body, like the Accelerator CI does).
sym=$(echo tests/fixtures/symbols/test_app.pdb/*/test_app.sym)
out=$(curl -fsS -X POST -H 'Content-Type: text/plain' --data-binary @"$sym" "$base/symbols/submit")
[[ $out == "Stored symbols for test_app.pdb/"* ]] || fail "symbols: $out"
step "symbols stored"

# 2. Presubmit, as the Accelerator sends it (one module known to us, one not).
id=5A9832E5287241C1838ED98914E9B7FF1
sig="2|1700000000|windows|x86|1|EXCEPTION_ACCESS_VIOLATION_WRITE|45|0|M|test_app.pdb|$id|M|other.pdb|AAAABBBBCCCCDDDDEEEEFFFF000011112|F|0|3"
out=$(curl -fsS -F "CrashSignature=$sig" "$base/submit")
[[ $out == Y\|NY\|* ]] || fail "presubmit (expected Y|NY|<token>): $out"
presubmit_token=${out##*|}
step "presubmit: ${out%%|[^|]*}|<token>"

# 3. Upload (multipart, with the token the server just gave us).
out=$(curl -fsS -F "UserID=76561197960265829" -F "PresubmitToken=$presubmit_token" \
  -F "upload_file_minidump=@tests/fixtures/dumps/test.dmp" "$base/submit")
[[ $out == "Crash ID: "* ]] || fail "upload: $out"
crash=$(echo "${out#Crash ID: }" | tr -d '-' | tr '[:upper:]' '[:lower:]')
step "uploaded: $out"

# 4. Wait for the worker to process it, then read the public page.
for _ in $(seq 100); do
  page=$(curl -fsS "$base/$crash")
  grep -q "waiting to be processed\|being processed" <<<"$page" || break
  sleep 0.1
done
grep -q "CrashFunction" <<<"$page" || fail "crash page has no resolved stack"
grep -q "test_app.cc:58" <<<"$page" || fail "crash page has no source line"
grep -q "Uploaded from" <<<"$page" && fail "anonymous page shows the uploader address"
step "crash page: stack resolved with source line, uploader hidden"

# 5. The raw dump is protected.
code=$(curl -s -o /dev/null -w '%{http_code}' "$base/$crash/download")
[ "$code" = 303 ] || fail "download without a login should redirect, got $code"
step "download needs a login (HTTP $code)"

# 5b. The public statistics page lists the crash.
stats=$(curl -fsS "$base/stats")
grep -q "Top Crashers" <<<"$stats" || fail "stats page has no top crashers"
grep -q "CrashFunction" <<<"$stats" || fail "stats page does not list the crash"
step "stats page"

# 6. Unauthenticated and authenticated metrics.
code=$(curl -s -o /dev/null -w '%{http_code}' "$base/metrics")
[ "$code" = 401 ] || fail "metrics without a token: $code"
metrics=$(curl -fsS -H "Authorization: Bearer $token" "$base/metrics")
grep -q 'throttle_crashes{status="done"} 1' <<<"$metrics" || fail "metrics: crash not counted as done"
grep -q 'throttle_events_total{event="symbols:accepted"} 1' <<<"$metrics" || fail "metrics: symbol event missing"
step "metrics"

# 7. Backup and retention commands against the live database.
"$bin" --config "$work/throttle.toml" backup "$work/backup.sqlite" >/dev/null
[ -s "$work/backup.sqlite" ] || fail "backup is empty"
"$bin" --config "$work/throttle.toml" clean >/dev/null
step "backup and clean"

# 8. Reached by another name (0.0.0.0, a LAN address): login and POSTs follow it.
loc=$(curl -s -o /dev/null -D - "http://0.0.0.0:$port/login" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
[[ $loc == *"openid.return_to=http%3A%2F%2F0.0.0.0%3A$port%2Flogin%2Fcallback"* ]] || fail "login does not return to 0.0.0.0: $loc"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Origin: http://0.0.0.0:$port" "http://0.0.0.0:$port/logout")
[ "$code" = 303 ] || fail "logout from 0.0.0.0 should work, got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Origin: http://evil.example" "http://0.0.0.0:$port/logout")
[ "$code" = 403 ] || fail "logout from a foreign origin should be refused, got $code"
step "login and POSTs follow the address used (0.0.0.0)"

echo "SMOKE TEST PASSED"
