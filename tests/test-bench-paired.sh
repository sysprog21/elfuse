#!/usr/bin/env bash
# Run scripts/bench-paired.sh against a stub suite, a stub hdiutil and a stub
# calibration loop, so its round order, exits, reruns and deadline are checked
# in seconds instead of an A/A run of 11 to 14 minutes. The real
# tests/bench-suite.sh runs only as far as its BENCH_METRICS check, which needs
# no elfuse build.
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
# Call N prints 1200 when N is in STUB_HIGH, otherwise STUB_CALIB_OUT.
cat > "$T/bin/calib" << 'EOF'
#!/usr/bin/env bash
n=$(($(cat "$STUB_DIR/calls") + 1))
echo "$n" > "$STUB_DIR/calls"
case " ${STUB_HIGH:-} " in
    *" $n "*) echo 1200 ;;
    *) echo "${STUB_CALIB_OUT:-1000}" ;;
esac
EOF

# -s stages (and leaves attached, as the real suite does); -o writes one round,
# logs which build ran it and takes STUB_ROUND_SECS.
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
        sleep "${STUB_ROUND_SECS:-0}"
        printf '{"meta": {"env": "elfuse-aarch64"}, "lmbench": {"x": {"median": 1.0}}}\n' > "$2"
        ;;
esac
EOF
printf '#!/bin/sh\nexit 0\n' > "$T/base"
cp "$T/base" "$T/head"
chmod +x "$T/bin/hdiutil" "$T/bin/calib" "$T/base" "$T/head"

# run [VAR=value ...]: one bench-paired.sh run on the stubs; sets rc.
run()
{
    rm -rf "$T/out" "$T/img" "$T/staged"
    echo "${mounts0:-0}" > "$T/mounts"
    echo 0 > "$T/calls"
    : > "$T/order"
    rc=0
    env -u BENCH_REGRESSION_THRESHOLD -u BENCH_PAIRS PATH="$T/bin:$PATH" \
        STUB_DIR="$T" BENCH_PAIRED_SUITE="$T/suite.sh" \
        BENCH_CALIB="$T/bin/calib" BENCH_CALIB_GAP=0 "$@" \
        bash "$ROOT/scripts/bench-paired.sh" "$T/base" "$T/head" "$T/out" \
        > "$T/log" 2>&1 || rc=$?
}

# meta FILE KEY: print meta[KEY] of a round file.
meta()
{
    python3 -I -c 'import json, sys
print(json.load(open(sys.argv[1]))["meta"][sys.argv[2]])' "$1" "$2"
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

# Calls 15 and 16 make the reading after pair 1's head round.
run STUB_HIGH="15 16"
[ "$rc" = 0 ] || fail "unsteady run exited $rc"
[ "$(grep -c 'measuring pair' "$T/log")" = 1 ] || fail "one high reading did not give exactly one rerun"
[ "$(meta "$T/out/head-1.json" reruns)" = 1 ] || fail "pair 1 meta.reruns is not 1"
[ "$(meta "$T/out/base-1.json" calib_unsteady)" = False ] || fail "a rerun pair was marked unsteady"

# One high call of the two behind a reading (15: the first after pair 1's head
# round; 18: the second before pair 2's head round) is a spike and drops out.
run STUB_HIGH="15 18"
[ "$rc" = 0 ] || fail "single-spike run exited $rc"
grep -q 'measuring pair' "$T/log" && fail "one high call of two gave a rerun"

run STUB_HIGH="15 16" BENCH_RERUN_DEADLINE=0
[ "$rc" = 0 ] || fail "deadline run exited $rc"
grep -q 'measuring pair' "$T/log" && fail "a rerun ran past the deadline"
[ "$(meta "$T/out/head-1.json" calib_unsteady)" = True ] || fail "a kept pair was not marked unsteady"
# Calls 13 and 14 make the head round's reading before, 15 and 16 after.
[ "$(meta "$T/out/head-1.json" calib_us)" = "[1000.0, 1200.0]" ] || fail "head-1 meta.calib_us is not the readings before and after its round"

# 1 s rounds: pair 1 ends near 4 s, before the 10 s deadline, but a rerun and
# the 5 pairs after it would end near 16 s.
run STUB_HIGH="15 16" STUB_ROUND_SECS=1 BENCH_RERUN_DEADLINE=10
[ "$rc" = 0 ] || fail "projected deadline run exited $rc"
grep -q 'measuring pair' "$T/log" && fail "a rerun ran although the pairs after it would end past the deadline"

# A sysroot staged before the run, as benchmark.yml stages it under the shared
# host lock, is used without staging again, then detached and removed.
printf '/Volumes/stub-bench\n%s\n' "$T/pre.img" > "$T/pre"
: > "$T/pre.img"
mounts0=1 run BENCH_PAIRED_STAGE="$T/pre"
[ "$rc" = 0 ] || fail "a run on a staged sysroot exited $rc"
[ ! -e "$T/staged" ] || fail "a run given a staged sysroot staged another"
[ "$(cat "$T/mounts")" = 0 ] || fail "a run given a staged sysroot left a mount"
[ ! -e "$T/pre.img" ] && [ ! -e "$T/pre" ] || fail "a given staged image or its file was left behind"

run STUB_CALIB_OUT=abc
[ "$rc" = 1 ] || fail "a calibration tool that prints text gave exit $rc, not 1"
[ "$(cat "$T/mounts")" = 0 ] || fail "a failed calibration left a mount"
[ ! -e "$T/img" ] || fail "a failed calibration left the staged image"

for pairs in 0 5 33 abc 18446744073709551622; do
    run BENCH_PAIRS="$pairs"
    [ "$rc" = 2 ] || fail "BENCH_PAIRS=$pairs gave exit $rc, not 2"
    [ ! -e "$T/out" ] || fail "BENCH_PAIRS=$pairs created the output directory"
done
for bad in BENCH_RERUN_DEADLINE=abc BENCH_RERUN_DEADLINE=18446744073709551616 \
    BENCH_CALIB_GAP=abc BENCH_CALIB_SPREAD=abc BENCH_CALIB="$T/missing" \
    BENCH_PAIRED_STAGE="$T/missing"; do
    run "$bad"
    [ "$rc" = 2 ] || fail "$bad gave exit $rc, not 2"
    [ ! -e "$T/out" ] || fail "$bad created the output directory"
done
run BENCH_PAIRS=08
[ "$rc" = 0 ] || fail "BENCH_PAIRS=08 gave exit $rc"
[ "$(ls "$T/out"/base-*.json 2> /dev/null | wc -l | tr -d ' ')" = 8 ] \
    || fail "BENCH_PAIRS=08 did not measure 8 pairs"

# The suite checks the BENCH_METRICS names before it looks for elfuse.
suite()
{
    rc=0
    env -u BENCH_ENV ELFUSE="$T/missing" BENCH_METRICS="$1" \
        bash "$ROOT/tests/bench-suite.sh" -o "$T/suite.json" > "$T/log" 2>&1 \
        || rc=$?
}
suite 'lmbench.lat_syscall.null lmbench.nope'
[ "$rc" = 2 ] || fail "an unknown BENCH_METRICS name gave exit $rc"
grep -q "unknown metric 'lmbench.nope'" "$T/log" || fail "an unknown BENCH_METRICS name was not named"

# Every metric of the baseline's elfuse column, so a name dropped from the
# suite's list fails here rather than in a second set on CI.
known="$(python3 - "$ROOT/tests/bench-baseline.json" << 'EOF'
import json
import sys


def names(prefix, node):
    if not isinstance(node, dict):
        return [prefix]
    return [n for key, sub in node.items() for n in names(f"{prefix}.{key}", sub)]


column = json.load(open(sys.argv[1]))["environments"]["elfuse-aarch64"]
print(" ".join(n for key, sub in column.items() for n in names(key, sub)))
EOF
)"
[ "$(wc -w <<< "$known" | tr -d ' ')" -ge 15 ] || fail "the baseline gave too few metric names: $known"
suite "$known oci.python_ms"
[ "$rc" = 1 ] || fail "known BENCH_METRICS names gave exit $rc"
grep -q 'elfuse binary missing' "$T/log" || fail "known BENCH_METRICS names did not reach the elfuse check"

# KNOWN_METRICS lists the metrics that the lmbench_metric, run_tier2_tool and
# want calls measure and no other, so a metric added through one of them without
# a line there fails here rather than in every round of its second set on CI. A
# call whose metric name it cannot read fails it too.
python3 - "$ROOT/tests/bench-suite.sh" << 'EOF' || fail "KNOWN_METRICS and the suite's metric calls differ"
import re
import sys

src = re.sub(r"^[ \t]*#.*$", "", open(sys.argv[1]).read(), flags=re.M)
src = src.replace("\\\n", " ")
helpers = {'"lmbench.$benchmark.$metric"', '"applications.$metric"', '"oci.$metric"'}
calls, unread = set(), []


def read(call, prefix, *args):
    words = [arg.strip("\"'") for arg in args]
    if all(re.fullmatch(r"[\w.]+", word) for word in words):
        calls.add(prefix + ".".join(words))
    else:
        unread.append(" ".join((call,) + args))


for args in re.findall(r"\blmbench_metric[ \t]+(\S+)[ \t]+(\S+)", src):
    read("lmbench_metric", "lmbench.", *args)
for arg in re.findall(r"\brun_tier2_tool[ \t]+(\S+)", src):
    read("run_tier2_tool", "applications.", arg)
for arg in re.findall(r"\bwant[ \t]+(\S+)", src):
    if arg not in helpers:
        read("want", "", arg)
listed = set(re.search(r"^KNOWN_METRICS=\((.*?)^\)", src, re.M | re.S)[1].split())
for name in sorted(calls ^ listed):
    where = "KNOWN_METRICS" if name in listed else "a call"
    print(f"test-bench-paired: {name} is only in {where}", file=sys.stderr)
for call in unread:
    print(f"test-bench-paired: cannot read {call}", file=sys.stderr)
sys.exit(calls != listed or bool(unread))
EOF

if [ "$failures" -ne 0 ]; then
    echo "test-bench-paired: $failures failed" >&2
    exit 1
fi
echo "test-bench-paired: all passed"
