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
# logs which build ran it and its BENCH_METRICS, and takes STUB_ROUND_SECS. A
# second-set round (BENCH_METRICS set) also takes STUB_CONFIRM_SECS and fails
# when STUB_CONFIRM_FAILS is set. The head's value is STUB_HEAD. With
# STUB_HEAD_Y set, a round also holds lmbench.y, at that value on the head,
# unless BENCH_METRICS leaves it out.
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
        echo "${BENCH_METRICS:-all}" >> "$STUB_DIR/metrics"
        sleep "${STUB_ROUND_SECS:-0}"
        if [ -n "$BENCH_METRICS" ]; then
            sleep "${STUB_CONFIRM_SECS:-0}"
            [ -z "${STUB_CONFIRM_FAILS:-}" ] || exit 1
        fi
        value=1.0
        y=1.0
        if [ "$(basename "$ELFUSE")" = head ]; then
            value="${STUB_HEAD:-1.0}"
            y="${STUB_HEAD_Y:-1.0}"
        fi
        case "${STUB_HEAD_Y:+set}/ ${BENCH_METRICS:-lmbench.y} " in
            "set/"*" lmbench.y "*) y=", \"y\": {\"median\": $y}" ;;
            *) y= ;;
        esac
        printf '{"meta": {"env": "elfuse-aarch64"}, "lmbench": {"x": {"median": %s}%s}}\n' "$value" "$y" > "$2"
        ;;
esac
EOF
printf '#!/bin/sh\nexit 0\n' > "$T/base"
cp "$T/base" "$T/head"
chmod +x "$T/bin/hdiutil" "$T/bin/calib" "$T/base" "$T/head"

# run [VAR=value ...]: one bench-paired.sh run on the stubs; sets rc.
run()
{
    rm -rf "$T/img" "$T/staged"
    [ -n "${keep_out:-}" ] || rm -rf "$T/out"
    echo "${mounts0:-0}" > "$T/mounts"
    echo 0 > "$T/calls"
    : > "$T/order"
    : > "$T/metrics"
    rc=0
    env -u BENCH_REGRESSION_THRESHOLD -u BENCH_PAIRS -u BENCH_FLAG_THRESHOLD \
        PATH="$T/bin:$PATH" \
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

# confirm_rounds: the rounds of the report's second set, or none.
confirm_rounds()
{
    python3 -I -c 'import json, sys
print(json.load(open(sys.argv[1])).get("confirm", {}).get("rounds", "none"))' \
        "$T/out/report.json"
}

# confirm_metrics: the metrics of the report's second set, or none.
confirm_metrics()
{
    python3 -I -c 'import json, sys
names = json.load(open(sys.argv[1])).get("confirm", {}).get("metrics", {})
print(" ".join(sorted(names)) or "none")' "$T/out/report.json"
}

# confirm_missing: why the report has no second set, or none.
confirm_missing()
{
    python3 -I -c 'import json, sys
print(json.load(open(sys.argv[1])).get("confirm_missing", "none"))' \
        "$T/out/report.json"
}

run
order="$(tr '\n' ' ' < "$T/order")"
want="base head base head head base base head head base base head head base "
[ "$rc" = 0 ] || fail "steady run exited $rc"
[ "$order" = "$want" ] || fail "round order was '$order'"
[ "$(cat "$T/mounts")" = 0 ] || fail "steady run left a mount"
[ -s "$T/out/report.json" ] || fail "steady run wrote no report.json"
[ "$(confirm_rounds)" = none ] || fail "an unchanged head was measured again"
[ "$(confirm_missing)" = "not flagged" ] || fail "a run with nothing flagged recorded '$(confirm_missing)'"

# A head 30% slower reads slower at a zero threshold, so with no threshold set
# its one metric is measured again in 6 more pairs of only that metric, in the
# same order.
run STUB_HEAD=1.3
[ "$rc" = 0 ] || fail "flagged run exited $rc"
[ "$(cat "$T/out/flagged")" = lmbench.x ] || fail "flagged run listed '$(cat "$T/out/flagged")'"
[ "$(grep -c '^lmbench.x$' "$T/metrics")" = 12 ] || fail "the second set did not run 12 rounds of the flagged metric alone"
order="$(tr '\n' ' ' < "$T/order")"
[ "$order" = "$want$(echo "$want" | cut -d' ' -f3-14) " ] || fail "flagged run order was '$order'"
[ "$(confirm_rounds)" = 6 ] || fail "the report's second set has $(confirm_rounds) rounds"
[ "$(cat "$T/mounts")" = 0 ] || fail "flagged run left a mount"
[ "$(confirm_missing)" = none ] || fail "a run with a second set recorded '$(confirm_missing)'"

# A run without a second set, into that output directory, keeps none of its
# files.
keep_out=1 run
[ "$rc" = 0 ] || fail "a run over an earlier output directory exited $rc"
[ ! -e "$T/out/confirm-base-1.json" ] || fail "a run kept the second set's base rounds of an earlier one"
[ ! -e "$T/out/confirm-head-1.json" ] || fail "a run kept the second set's head rounds of an earlier one"
[ ! -s "$T/out/flagged" ] || fail "a run kept the flagged list of an earlier one"
[ "$(confirm_rounds)" = none ] || fail "a run over an earlier output directory reported an earlier second set"

# The same head, flagged at 50% or not at all, is not measured again.
for limit in 0.5 none; do
    run STUB_HEAD=1.3 BENCH_FLAG_THRESHOLD="$limit"
    [ "$rc" = 0 ] || fail "BENCH_FLAG_THRESHOLD=$limit exited $rc"
    [ ! -s "$T/out/flagged" ] || fail "BENCH_FLAG_THRESHOLD=$limit flagged '$(cat "$T/out/flagged")'"
    [ "$(confirm_rounds)" = none ] || fail "BENCH_FLAG_THRESHOLD=$limit measured a 30% slower head again"
done

# At report, a threshold of .05, which the number check of the script would
# refuse, reaches bench-compare.py and flags the head.
run STUB_HEAD=1.3 BENCH_FLAG_THRESHOLD=report BENCH_REGRESSION_THRESHOLD=.05
[ "$rc" = 0 ] || fail "BENCH_FLAG_THRESHOLD=report exited $rc"
[ "$(confirm_rounds)" != none ] || fail "BENCH_FLAG_THRESHOLD=report at a 5% threshold did not measure a 30% slower head again"

# A metric past the threshold but under BENCH_FLAG_THRESHOLD stays out of the
# second set, and the flagged list stays as the first set wrote it, also when
# the second set fails or runs out of time.
for extra in "" STUB_CONFIRM_FAILS=1 BENCH_CONFIRM_DEADLINE=0; do
    run STUB_HEAD=2.0 STUB_HEAD_Y=1.3 BENCH_FLAG_THRESHOLD=0.5 \
        BENCH_REGRESSION_THRESHOLD=.1 ${extra:+"$extra"}
    [ "$rc" = 0 ] || fail "${extra:-a second set} with lmbench.y not flagged exited $rc"
    [ "$(paste -s -d ' ' - < "$T/out/flagged")" = lmbench.x ] || fail "${extra:-a second set} left the flagged list at '$(paste -s -d ' ' - < "$T/out/flagged")'"
    [ -n "$extra" ] || [ "$(confirm_metrics)" = lmbench.x ] || fail "the second set held '$(confirm_metrics)' with lmbench.y not flagged"
done

run STUB_HEAD=1.3 BENCH_CONFIRM_DEADLINE=0
[ "$rc" = 0 ] || fail "a second set past its deadline exited $rc"
grep -q 'stopped before pair 1,' "$T/log" || fail "a second set past its deadline was not stopped"
[ "$(confirm_rounds)" = none ] || fail "a second set past its deadline reached the report"
[ "$(confirm_missing)" = "out of time" ] || fail "a second set past its deadline recorded '$(confirm_missing)'"

# 2 s rounds: the first set ends near 28 s, before the 31 s deadline, and the
# second set's pair 1, taking as long as the first set's last pair, would end
# near 32 s.
run STUB_HEAD=1.3 STUB_ROUND_SECS=2 BENCH_CONFIRM_DEADLINE=31
[ "$rc" = 0 ] || fail "a second set whose pair 1 would end past its deadline exited $rc"
grep -q 'stopped before pair 1,' "$T/log" || fail "a pair 1 as long as the first set's last pair ran past the deadline"
[ "$(confirm_missing)" = "out of time" ] || fail "a second set stopped before pair 1 by its length recorded '$(confirm_missing)'"

# A failing second-set round ends the set there, not the run: the report says
# the set failed, and Tier 3 still runs.
run STUB_HEAD=1.3 STUB_CONFIRM_FAILS=1 BENCH_PAIRED_OCI=1
[ "$rc" = 0 ] || fail "a failing second-set round exited $rc"
[ "$(grep -c '^lmbench.x$' "$T/metrics")" = 1 ] || fail "a second set went on past its failing round"
[ "$(confirm_rounds)" = none ] || fail "a failing second set reached the report"
[ "$(confirm_missing)" = failed ] || fail "a failing second set recorded '$(confirm_missing)'"
[ -s "$T/out/head-oci.json" ] || fail "a failing second set skipped Tier 3"
[ "$(cat "$T/mounts")" = 0 ] || fail "a failing second set left a mount"

# Calls 63 and 64, after 14 rounds of 4 calls, make the reading after the head
# round of the second set's pair 1. Its rerun is held to BENCH_CONFIRM_DEADLINE,
# not to the first set's deadline of 0.
run STUB_HEAD=1.3 STUB_HIGH="63 64" BENCH_RERUN_DEADLINE=0
[ "$rc" = 0 ] || fail "a second set with a rerun exited $rc"
[ "$(grep -c 'measuring pair 1 again' "$T/log")" = 1 ] || fail "an unsteady pair 1 of the second set was not measured again"
[ "$(meta "$T/out/confirm-head-1.json" reruns)" = 1 ] || fail "confirm-head-1 meta.reruns is not 1"

# The same pair 1, taking 6 s: a rerun and the 5 pairs after it would end past
# 30 s, and so would pairs 2 to 6. The first set ends well before 30 s.
run STUB_HEAD=1.3 STUB_HIGH="63 64" STUB_CONFIRM_SECS=3 BENCH_CONFIRM_DEADLINE=30
[ "$rc" = 0 ] || fail "a cut second set exited $rc"
grep -q 'measuring pair 1 again' "$T/log" && fail "a second-set rerun ran past BENCH_CONFIRM_DEADLINE"
[ "$(meta "$T/out/confirm-head-1.json" calib_unsteady)" = True ] || fail "a kept second-set pair was not marked unsteady"
grep -q 'stopped before pair 2,' "$T/log" || fail "a second set that would end past its deadline went on"
[ "$(confirm_rounds)" = 1 ] || fail "a cut second set reported $(confirm_rounds) rounds, not 1"

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
    BENCH_CONFIRM_DEADLINE=abc BENCH_CONFIRM_DEADLINE=18446744073709551616 \
    BENCH_CALIB_GAP=abc BENCH_CALIB_SPREAD=abc BENCH_FLAG_THRESHOLD=abc \
    BENCH_CALIB="$T/missing" \
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
