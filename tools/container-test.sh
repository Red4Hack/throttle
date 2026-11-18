#!/usr/bin/env bash
# Deploy test of the container images, the way a user runs them: build, start with a
# volume, upload dumps over the real protocol, read the pages, stop, start again.
#
# The default image has the carburetor (deep analysis page); `without-carburetor`
# does not. Everything else must work the same in both.
#
#   tools/container-test.sh               # both images
#   tools/container-test.sh with          # only the default image
#   tools/container-test.sh without       # only the image without the carburetor
#   NO_BUILD=1 tools/container-test.sh    # reuse throttle-test:with / throttle-test:without
#   ENGINE=docker tools/container-test.sh
#   EXTRA_DUMPS="/a.dmp /b.dmp" tools/container-test.sh   # more dumps (tests/local/*.dmp are always used)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
engine=${ENGINE:-podman}
work=$(mktemp -d)
owner=76561198339009339
# Presubmit as the Accelerator sends it; the server only needs a well-formed one.
# The last frame offset is the part that changes per crash: the server treats the same
# fingerprint from the same owner as a repeat, so each dump needs its own.
sig_base="2|1700000000|windows|x86|1|EXCEPTION_ACCESS_VIOLATION_WRITE|45|0|M|test_app.pdb|5A9832E5287241C1838ED98914E9B7FF1|F|0|"

containers=()
volumes=()
hostdirs=()
cleanup() {
  for c in "${containers[@]}"; do "$engine" rm -f "$c" >/dev/null 2>&1 || true; done
  for v in "${volumes[@]}"; do "$engine" volume rm -f "$v" >/dev/null 2>&1 || true; done
  for d in "${hostdirs[@]}"; do
    if [ "$engine" = podman ]; then podman unshare rm -rf "$d" 2>/dev/null || rm -rf "$d"; else rm -rf "$d"; fi
  done
  rm -rf "$work"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "ok: $*"; }

wait_up() { # base container
  for _ in $(seq 100); do
    curl -fs "$1/healthz" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  "$engine" logs "$2" 2>&1 | tail -20 >&2
  fail "$2 did not answer /healthz"
}

# Prints the crash id (12 lower-case characters) of the uploaded dump. `key` picks the
# fingerprint: the same key twice is the same crash again.
upload() { # base dump [key]
  local out token key=${3:-$(printf '%x%x' "$RANDOM" "$RANDOM")}
  out=$(curl -fsS -F "CrashSignature=$sig_base$key" "$1/submit") || return 1
  token=${out##*|}
  out=$(curl -fsS -F "UserID=$owner" -F "PresubmitToken=$token" -F "upload_file_minidump=@$2" "$1/submit") || return 1
  [[ $out == "Crash ID: "* ]] || { echo "upload answered: $out" >&2; return 1; }
  echo "${out#Crash ID: }" | tr -d '-' | tr '[:upper:]' '[:lower:]'
}

# Sets $page to the crash page once the worker is done with it.
wait_processed() { # base id
  for _ in $(seq 240); do
    page=$(curl -fsSL "$1/$2")
    grep -q "waiting to be processed\|being processed" <<<"$page" || return 0
    sleep 0.5
  done
  fail "$2 was not processed in 2 minutes"
}

# A session cookie for $owner, signed with the container's own secret.key.
session_cookie() { # container
  local body key mac
  "$engine" cp "$1:/data/secret.key" "$work/$1.key" >/dev/null
  body="$owner.$(printf '%x' "$(date +%s)")"
  key=$(xxd -p -c 256 "$work/$1.key")
  mac=$(printf 'session:%s' "$body" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$key" -hex | awk '{print $NF}' | cut -c1-32)
  echo "throttle_session=$body.$mac"
}

check() { # variant want_carburetor(yes|no) port
  local variant=$1 want=$2 port=$3
  local image="throttle-test:$variant" name="tt-$$-$variant" base="http://127.0.0.1:$3"
  echo "=== image '$variant' ==="

  if [ -z "${NO_BUILD:-}" ]; then
    local target=()
    [ "$variant" = without ] && target=(--target without-carburetor)
    "$engine" build -q "${target[@]}" -t "$image" -f Containerfile . >/dev/null || fail "build of '$variant' failed"
    step "built $image"
  fi

  containers+=("$name")
  volumes+=("$name")
  "$engine" volume create "$name" >/dev/null
  "$engine" run -d --name "$name" -p "127.0.0.1:$port:9090" -v "$name:/data" "$image" >/dev/null || fail "run"
  wait_up "$base" "$name"
  step "answers /healthz"

  local uid
  uid=$("$engine" exec "$name" id -u)
  [ "$uid" != 0 ] || fail "the container runs as root"
  step "runs as uid $uid, not root"

  local have=no
  "$engine" exec "$name" test -x /usr/local/bin/carburetor 2>/dev/null && have=yes
  [ "$have" = "$want" ] || fail "carburetor present in the image: $have (expected $want)"
  step "carburetor in the image: $have"

  # Symbols, then the dump that uses them.
  local sym out main page=""
  sym=$(echo tests/fixtures/symbols/test_app.pdb/*/test_app.sym)
  out=$(curl -fsS -X POST -H 'Content-Type: text/plain' --data-binary @"$sym" "$base/symbols/submit")
  [[ $out == "Stored symbols for test_app.pdb/"* ]] || fail "symbols: $out"
  main=$(upload "$base" tests/fixtures/dumps/test.dmp 1) || fail "upload of test.dmp"
  wait_processed "$base" "$main"
  grep -q "CrashFunction" <<<"$page" || fail "test.dmp: the stack was not resolved"
  grep -q "test_app.cc:58" <<<"$page" || fail "test.dmp: no source line"
  step "test.dmp ($main): stack resolved with its source line"

  # The public stats: the page, and the drill-down to the module of the crash just processed.
  code=$(curl -s -o /dev/null -w '%{http_code}' "$base/stats")
  [ "$code" = 200 ] || fail "/stats: HTTP $code"
  out=$(curl -fsS "$base/stats/test_app.exe") || fail "/stats/test_app.exe failed"
  grep -q "CrashFunction" <<<"$out" || fail "the stats of the module do not list its crash"
  step "stats page and the drill-down to a module work"

  # The same crash again is counted on the first one, not stored twice.
  local again
  again=$(upload "$base" tests/fixtures/dumps/test.dmp 1) || fail "second upload of test.dmp"
  [ "$again" = "$main" ] || fail "a repeat got its own crash ($again, not $main)"
  page=$(curl -fsSL "$base/$main")
  grep -q "reported again 1 time" <<<"$page" || fail "the page does not say the crash repeated"
  step "the same crash again is counted on $main"

  # Real-looking dumps without symbols: other platforms and 32/64 bits, plus whatever
  # is in tests/local (a SourceMod i686 server dump, for instance).
  local d id
  for d in tests/fixtures/dumps/{linux-mini,simple-crashpad,pipeline-inlines-macos-segv}.dmp tests/local/*.dmp ${EXTRA_DUMPS:-}; do
    [ -f "$d" ] || continue
    id=$(upload "$base" "$d") || fail "upload of $d"
    wait_processed "$base" "$id"
    grep -q "An error occurred while processing" <<<"$page" && fail "$d: processing failed ($id)"
    grep -q "Stack Trace" <<<"$page" || fail "$d: no stack trace on the page ($id)"
    step "$(basename "$d") ($id): processed, stack trace shown"
  done

  # Garbage must end as a failed crash with a reason, not hang the queue.
  printf 'this is not a minidump' >"$work/junk.dmp"
  id=$(upload "$base" "$work/junk.dmp") || fail "upload of the junk file"
  wait_processed "$base" "$id"
  grep -q "An error occurred while processing" <<<"$page" || fail "junk dump: no error shown"
  step "a file that is not a minidump ends as a failed crash with a reason"

  # Deep analysis: only with the carburetor, only for who may manage the crash.
  local cookie code
  cookie=$(session_cookie "$name")
  code=$(curl -s -o /dev/null -w '%{http_code}' "$base/$main/carburetor")
  [ "$code" != 200 ] || fail "deep analysis is open to anonymous visitors"
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: $cookie" "$base/$main/carburetor")
  if [ "$want" = yes ]; then
    [ "$code" = 200 ] || fail "deep analysis page: HTTP $code"
    out=$(curl -fsS -m 150 -H "Cookie: $cookie" "$base/$main/carburetor") || fail "View Raw page failed"
    grep -q "Found via" <<<"$out" || fail "View Raw has no stack tab"
    out=$(curl -fsS -m 150 -H "Cookie: $cookie" "$base/$main/carburetor/data")
    grep -q '"crash_reason"' <<<"$out" || fail "deep analysis data has no crash_reason"
    step "deep analysis works for the owner and is closed to visitors"
  else
    [ "$code" = 404 ] || fail "deep analysis without the carburetor: HTTP $code (expected 404)"
    step "deep analysis is off (404), the rest works"
  fi

  # The raw view is for who manages the crash; bulk delete takes ticked reports away.
  local junk=$id
  code=$(curl -s -o /dev/null -w '%{http_code}' "$base/$main/raw")
  [ "$code" != 200 ] || fail "the raw view is open to anonymous visitors"
  out=$(curl -fsS -H "Cookie: $cookie" "$base/$main/raw") || fail "raw view failed"
  grep -q "Crash reason:" <<<"$out" || fail "the raw view has no crash reason"
  step "raw view works for the owner and is closed to visitors"

  code=$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: $cookie" -H "Origin: $base" -d "id=$junk" "$base/dashboard/delete")
  [ "$code" = 303 ] || fail "bulk delete: HTTP $code"
  code=$(curl -s -o /dev/null -w '%{http_code}' "$base/$junk")
  [ "$code" = 404 ] || fail "the report deleted in bulk is still there (HTTP $code)"
  step "bulk delete removes the ticked report"

  # podman/docker stop sends SIGTERM; as PID 1 the server must handle it.
  local started took
  started=$(date +%s)
  "$engine" stop "$name" >/dev/null
  took=$(( $(date +%s) - started ))
  [ "$took" -lt 5 ] || fail "stopping took ${took}s: SIGTERM is not handled"
  "$engine" logs "$name" 2>&1 | grep -q "shutting down" || fail "no 'shutting down' in the log"
  step "stops on SIGTERM in ${took}s"

  "$engine" start "$name" >/dev/null
  wait_up "$base" "$name"
  page=$(curl -fsSL "$base/$main")
  grep -q "CrashFunction" <<<"$page" || fail "the crash is gone after a restart"
  step "data survives a restart"
}

# A host directory mounted as /data belongs to the host user; the image runs as an
# unprivileged one. It has to say so, and `:U` has to fix it (podman).
bind_mount_check() { # image
  [ "$engine" = podman ] || return 0
  local dir out name="tt-$$-bind"
  dir=$(mktemp -d)
  hostdirs+=("$dir")
  containers+=("$name")
  out=$(podman run --rm --name "$name" -v "$dir:/data" "$1" 2>&1 || true)
  if ! { grep -q "cannot create" <<<"$out" && grep -q ":U" <<<"$out"; }; then
    fail "a host directory without :U should explain itself, got: $out"
  fi
  step "host directory without :U: fails and says what to do"
  podman run -d --name "$name" -p 127.0.0.1:18319:9090 -v "$dir:/data:U" "$1" >/dev/null || fail "run with :U"
  wait_up http://127.0.0.1:18319 "$name"
  step "host directory with :U works"
}

which=${1:-both}
case $which in
  with)    check with yes 18311; first=with ;;
  without) check without no 18312; first=without ;;
  both)    check with yes 18311; check without no 18312; first=with ;;
  *) echo "usage: $0 [with|without|both]" >&2; exit 2 ;;
esac
bind_mount_check "throttle-test:$first"

echo "CONTAINER TEST PASSED"
