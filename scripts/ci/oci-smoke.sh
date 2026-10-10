#!/usr/bin/env bash
# Drive scripts/elfuse-oci.py end to end under elfuse. Usage:
# ELFUSE_OCI_STORE=<store> scripts/ci/oci-smoke.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/scripts/elfuse-oci.py"
: "${ELFUSE_OCI_STORE:?set ELFUSE_OCI_STORE to the store directory to use}"
export ELFUSE_OCI_STORE

guest=""
registry=""
work="$(mktemp -d)"
on_exit()
{
    rc=$?
    # Reap what this lane started before a persistent runner reuses it.
    [ -z "$guest" ] || kill "$guest" 2> /dev/null || true
    [ -z "$registry" ] || kill "$registry" 2> /dev/null || true
    rm -rf "$work"
    exit "$rc"
}
trap on_exit EXIT

fail()
{
    echo "FAIL: $*" >&2
    exit 1
}

# Drain stdin so pipefail does not report the producer's SIGPIPE.
expect_grep()
{
    grep -F -- "$1" > /dev/null
}

run_capture()
{
    local desc="$1" pattern="$2" out
    shift 2
    out="$("$@")"
    printf '%s: %s\n' "$desc" "$out"
    printf '%s\n' "$out" | expect_grep "$pattern"
}

# Poll a predicate without letting its failures escape set -e.
wait_for()
{
    local timeout="$1" desc="$2" i=0
    shift 2
    while ! "$@" > /dev/null; do
        i=$((i + 1))
        [ "$i" -lt $((timeout * 2)) ] || fail "timed out after ${timeout}s waiting for: $desc"
        sleep 0.5
    done
}

runs_gone()
{
    [ -z "$(ls "$ELFUSE_OCI_STORE/run" 2> /dev/null)" ]
}

# Pull an image whose /etc climbs out of the rootfs to a host directory. The
# unpack deletes the image's /etc/hosts, which must resolve inside the rootfs.
pull_hostile()
{
    local dir="$work/hostile" port up image out
    mkdir -p "$dir/host"
    echo keep > "$dir/host/hosts"
    crane registry serve --address 127.0.0.1:0 > "$dir/registry.log" 2>&1 &
    registry=$!
    wait_for 30 "local registry" grep -q 'serving on port' "$dir/registry.log"
    port="$(sed -n 's/.*serving on port //p' "$dir/registry.log")"
    image="127.0.0.1:$port/hostile:1"
    up="$(printf '../%.0s' {1..30})"
    printf '#mtree\n./etc type=link mode=0777 uid=0 gid=0 link=%s\n' \
        "${up%/}$dir/host" > "$dir/layer.mtree"
    tar -cf "$dir/layer.tar" "@$dir/layer.mtree"
    crane append --oci-empty-base -f "$dir/layer.tar" -t "$image" > /dev/null 2>&1 \
        || fail "cannot push the hostile image"

    # Without umoci the pull fails with one line and removes its build.
    mkdir "$dir/crane-only"
    ln -s "$(command -v crane)" "$dir/crane-only/crane"
    if out="$(PATH="$dir/crane-only:/usr/bin:/bin:/usr/sbin:/sbin" \
        "$BIN" pull "$image" 2>&1)"; then
        fail "a pull without umoci succeeded"
    fi
    printf '%s\n' "$out" | expect_grep "umoci not found" \
        || fail "a pull without umoci: $out"
    [ -z "$(ls "$ELFUSE_OCI_STORE/tmp")" ] || fail "a failed pull left its build"

    "$BIN" pull "$image"
    [ "$(cat "$dir/host/hosts")" = keep ] || fail "a pull changed a host file"
    kill "$registry"
    registry=""
}

"$ROOT/scripts/test-elfuse-oci.py"
"$BIN" clean > /dev/null

# A cold pull seals one private image, and a run of it does not unpack again.
out="$("$BIN" pull alpine:3 2>&1)" || fail "cold pull: $out"
printf '%s\n' "$out" | expect_grep Unpacking || fail "the cold pull did not unpack"
set -- "$ELFUSE_OCI_STORE"/images/*.dmg
[ $# -eq 1 ] && [ -f "$1" ] || fail "pull sealed $# images, want 1"
img=$1
[ "$(stat -f %Lp "$img")" = 400 ] || fail "the sealed image is mode $(stat -f %Lp "$img")"
sum=$(shasum -a 256 "$img")
out="$("$BIN" run alpine:3 /bin/echo elfuse-oci-ci-ok 2>&1)" || fail "warm run: $out"
printf 'alpine: %s\n' "$out"
printf '%s\n' "$out" | expect_grep elfuse-oci-ci-ok
if printf '%s\n' "$out" | expect_grep Unpacking; then
    fail "the warm run unpacked again"
fi

out="$("$BIN" list)"
printf 'list:\n%s\n' "$out"
printf '%s\n' "$out" | awk -v d="sha256:$(basename "$img" .dmg)" \
    '$1 == "alpine:3" && $2 == d { found = 1 } END { exit !found }' \
    || fail "list does not show alpine:3 with the sealed image's digest"

code=0
"$BIN" run alpine:3 /bin/sh -c 'exit 7' || code=$?
[ "$code" -eq 7 ] || fail "guest exit status: got $code, want 7"

# Debian's usr-merged gzip must resolve inside the image.
want=5af7b95208fdcff454bab3f5eddf567a688a3796c703d4fef91072e38645c062
got="$("$BIN" run debian:stable-slim /bin/sh -c 'set -e
  seq 1 200000 > /tmp/data.txt
  gzip -c /tmp/data.txt > /tmp/data.gz
  gunzip -c /tmp/data.gz | cmp - /tmp/data.txt
  sha256sum /tmp/data.txt | cut -d" " -f1')"
printf 'debian pipeline sha256: %s\n' "$got"
[ "$got" = "$want" ] || fail "debian pipeline sha256: got $got, want $want"

# Each run gets its own shadow, without the previous run's /tmp.
run_capture isolation isolated-ok \
    "$BIN" run debian:stable-slim /bin/sh -c 'test ! -e /tmp/data.txt && echo isolated-ok'

run_capture interpreter elfuse-interp-ok \
    "$BIN" run --entrypoint /bin/bash debian:stable-slim -c 'echo elfuse-interp-ok'

# clean refuses a non-empty directory that is not a store, and a store in use.
other="$work/other"
mkdir "$other"
touch "$other/keep"
if ELFUSE_OCI_STORE="$other" "$BIN" clean > /dev/null 2>&1; then
    fail "clean accepted a directory that is not a store"
fi
[ -f "$other/keep" ] || fail "clean removed a file outside a store"
busy="$work/busy"
"$BIN" run alpine:3 /bin/sh -c 'echo busy && sleep 60' > "$busy" 2>&1 &
guest=$!
wait_for 60 "a running guest" grep -q busy "$busy"
if "$BIN" clean > /dev/null 2>&1; then
    fail "clean ran while a run was in progress"
fi
kill "$guest"
wait "$guest" 2> /dev/null || true
guest=""

pull_hostile

# Runs leave the sealed image as pulled, their watchers detach them, and clean
# then empties the store.
[ "$(shasum -a 256 "$img")" = "$sum" ] || fail "a run changed the sealed image"
wait_for 30 "runs to detach" runs_gone
"$BIN" clean > /dev/null
[ -z "$(ls "$ELFUSE_OCI_STORE")" ] || fail "clean left $(ls "$ELFUSE_OCI_STORE")"
if hdiutil info | expect_grep "$(cd "$ELFUSE_OCI_STORE" && pwd -P)/"; then
    fail "an image under the store is still attached"
fi

echo "OCI smoke OK"
