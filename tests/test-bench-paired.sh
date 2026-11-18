#!/usr/bin/env bash
# Run scripts/bench-paired.sh against a stub suite and a stub hdiutil, so its
# round order and exits are checked in seconds instead of a 12-minute A/A run.
#
# SPDX-License-Identifier: Apache-2.0
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/bench-paired-test.XXXXXX")"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
failures=0

fail()
{
    echo "test-bench-paired: FAIL $*" >&2
    failures=$((failures + 1))
}

# Each attach adds one to $T/mounts and each detach takes one off, so a run that
# leaves a mount behind ends above zero.
cat > "$T/bin/hdiutil" << 'EOF'
#!/usr/bin/env bash
case "$1" in
    attach)
        echo $(($(cat "$STUB_DIR/mounts") + 1)) > "$STUB_DIR/mounts"
        printf '/dev/disk9s1\tApple_HFS\t/Volumes/stub-bench\n'
        ;;
    detach)
        [ -z "${STUB_DETACH_FAILS:-}" ] || exit 1
        echo $(($(cat "$STUB_DIR/mounts") - 1)) > "$STUB_DIR/mounts"
        ;;
esac
EOF

# -s stages (and leaves attached, as the real suite does); -o writes one round
# and logs which build ran it.
cat > "$T/suite.sh" << 'EOF'
case "$1" in
    -s)
        : > "$STUB_DIR/staged"
        : > "$STUB_DIR/img"
        echo $(($(cat "$STUB_DIR/mounts") + 1)) > "$STUB_DIR/mounts"
        printf '/Volumes/stub-bench\n%s\n' "$STUB_DIR/img" > "$2"
        ;;
    -o)
        basename "$ELFUSE" >> "$STUB_DIR/order"
        printf '{"meta": {"env": "elfuse-aarch64"}, "lmbench": {"x": {"median": 1.0}}}\n' > "$2"
        ;;
esac
EOF
printf '#!/bin/sh\nexit 0\n' > "$T/base"
cp "$T/base" "$T/head"
chmod +x "$T/bin/hdiutil" "$T/base" "$T/head"

# run [VAR=value ...]: one bench-paired.sh run on the stubs; sets rc.
run()
{
    rm -rf "$T/out" "$T/img" "$T/staged"
    echo "${mounts0:-0}" > "$T/mounts"
    : > "$T/order"
    rc=0
    env -u BENCH_REGRESSION_THRESHOLD -u BENCH_PAIRS PATH="$T/bin:$PATH" \
        STUB_DIR="$T" BENCH_PAIRED_SUITE="$T/suite.sh" "$@" \
        bash "$ROOT/scripts/bench-paired.sh" "$T/base" "$T/head" "$T/out" \
        > "$T/log" 2>&1 || rc=$?
}

run
order="$(tr '\n' ' ' < "$T/order")"
want="base head base head head base base head head base base head head base "
[ "$rc" = 0 ] || fail "steady run exited $rc"
[ "$order" = "$want" ] || fail "round order was '$order'"
[ "$(cat "$T/mounts")" = 0 ] || fail "steady run left a mount"
[ -s "$T/out/report.json" ] || fail "steady run wrote no report.json"

run STUB_DETACH_FAILS=1
[ "$rc" != 0 ] || fail "a failed detach did not stop the run"
grep -q 'cannot detach' "$T/log" || fail "a failed detach printed no message"

# A sysroot staged before the run, as benchmark.yml stages it under the shared
# host lock, is used without staging again, then detached and removed.
printf '/Volumes/stub-bench\n%s\n' "$T/pre.img" > "$T/pre"
: > "$T/pre.img"
mounts0=1 run BENCH_PAIRED_STAGE="$T/pre"
[ "$rc" = 0 ] || fail "a run on a staged sysroot exited $rc"
[ ! -e "$T/staged" ] || fail "a run given a staged sysroot staged another"
[ "$(cat "$T/mounts")" = 0 ] || fail "a run given a staged sysroot left a mount"
[ ! -e "$T/pre.img" ] && [ ! -e "$T/pre" ] || fail "a given staged image or its file was left behind"
run BENCH_PAIRED_STAGE="$T/missing"
[ "$rc" = 2 ] || fail "a missing BENCH_PAIRED_STAGE gave exit $rc, not 2"
[ ! -e "$T/out" ] || fail "a missing BENCH_PAIRED_STAGE created the output directory"

for pairs in 0 5 33 abc 18446744073709551622; do
    run BENCH_PAIRS="$pairs"
    [ "$rc" = 2 ] || fail "BENCH_PAIRS=$pairs gave exit $rc, not 2"
    [ ! -e "$T/out" ] || fail "BENCH_PAIRS=$pairs created the output directory"
done
run BENCH_PAIRS=08
[ "$rc" = 0 ] || fail "BENCH_PAIRS=08 gave exit $rc"
[ "$(ls "$T/out"/base-*.json 2> /dev/null | wc -l | tr -d ' ')" = 8 ] \
    || fail "BENCH_PAIRS=08 did not measure 8 pairs"

if [ "$failures" -ne 0 ]; then
    echo "test-bench-paired: $failures failed" >&2
    exit 1
fi
echo "test-bench-paired: all passed"
