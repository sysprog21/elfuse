#!/usr/bin/env bash
# Measure two elfuse builds in alternating rounds of tests/bench-suite.sh and
# compare them with scripts/bench-compare.py --paired.
#
# Usage: scripts/bench-paired.sh BASE_ELFUSE HEAD_ELFUSE OUTDIR
#
# One round is one suite run of Tier 1 and Tier 2 at one sample. The order is
# base, head (discarded), then BENCH_PAIRS pairs, so a slowdown of the host that
# spans both rounds of a pair cancels in the pair's ratio. Odd pairs run base
# first and even pairs head first, so an effect of running second (a warm page
# cache, a hotter host) does not move every ratio the same way. The Tier-2
# sysroot is staged once, with the head build, unless BENCH_PAIRED_STAGE names
# one staged already. Each round attaches that image with its own shadow file
# and discards it afterwards, because the Tier-2 workloads write into the
# sysroot: every round starts from the staged copy, and the image itself is
# never written. OUTDIR receives base-N.json and head-N.json per pair,
# report.json for scripts/bench-report.py, and with BENCH_PAIRED_OCI=1 also
# head-oci.json, a Tier-3-only run of the head build at the suite's default
# sample count that the comparison does not read.
#
# Around each round, BENCH_CALIB times a fixed single-threaded host loop. When
# the four readings of a pair spread by more than BENCH_CALIB_SPREAD, the host
# ran the two rounds at different speeds (a P-core slows down once three or more
# are busy), so the pair is measured again, in the same order. A pair is not
# measured again when that rerun and the pairs still to come, each taking as
# long as this pair just did, would end at or past BENCH_RERUN_DEADLINE seconds
# after the start; such a pair is kept and marked. Each round's meta records its
# two readings (calib_us), how often its pair was measured again (reruns) and
# that mark (calib_unsteady).
#
# Environment:
#   BENCH_PAIRS       pairs to measure, 6 to 32 (default 6, the fewest that
#                     bench-compare.py gives a verdict for)
#   BENCH_PAIRED_OCI  1 = also run Tier 3 on the head build; 0 = not (default)
#   BENCH_PAIRED_STAGE  a file written by tests/bench-suite.sh -s; its sysroot
#                     is used instead of staging one here, and this script
#                     detaches it and removes the image and the file
#   BENCH_PAIRED_SUITE  the suite to run (default tests/bench-suite.sh); the
#                     test in tests/test-bench-paired.sh points it at a stub
#   BENCH_CALIB       calibration loop (default build/bench-calib)
#   BENCH_CALIB_SPREAD  largest (max - min) / min of a pair's four readings
#                     (default 0.06, half the 12% step seen on the CI M4)
#   BENCH_RERUN_DEADLINE  seconds after the start by which the last pair is
#                     expected to end; no rerun is made that would reach it
#                     (default 900)
#   BENCH_CALIB_GAP   seconds between the two calls of BENCH_CALIB that make
#                     one reading (default 1)
#   BENCH_REGRESSION_THRESHOLD, and the bench-suite.sh variables
#   (BENCH_BIN_DIR, BENCH_STRICT, ELFUSE_OCI_STORE, ...), pass through.
#
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUITE="${BENCH_PAIRED_SUITE:-$ROOT/tests/bench-suite.sh}"

if [ "$#" -ne 3 ]; then
    echo "usage: $0 BASE_ELFUSE HEAD_ELFUSE OUTDIR" >&2
    exit 2
fi
BASE="$1"
HEAD="$2"
OUT="$3"
PAIRS="${BENCH_PAIRS:-6}"
case "$PAIRS" in
    '' | *[!0-9]*)
        echo "bench-paired: BENCH_PAIRS must be a number" >&2
        exit 2
        ;;
esac

# Leading zeros go, so 08 is not read as octal, and a count of more than two
# digits is refused before arithmetic could wrap it into the range.
PAIRS="${PAIRS#"${PAIRS%%[!0]*}"}"
PAIRS="${PAIRS:-0}"

# Below MIN_PAIRS in scripts/bench-compare.py no metric gets a verdict, so the
# run would be wasted, and above MAX_ROUNDS the comparison exits 2; check before
# any round runs.
if [ "${#PAIRS}" -gt 2 ] || ((PAIRS < 6 || PAIRS > 32)); then
    echo "bench-paired: BENCH_PAIRS must be 6 to 32" >&2
    exit 2
fi
CALIB="${BENCH_CALIB:-$ROOT/build/bench-calib}"
SPREAD="${BENCH_CALIB_SPREAD:-0.06}"
DEADLINE="${BENCH_RERUN_DEADLINE:-900}"
case "$DEADLINE" in
    '' | *[!0-9]*)
        echo "bench-paired: BENCH_RERUN_DEADLINE must be a number" >&2
        exit 2
        ;;
esac
# As for BENCH_PAIRS: no octal, and no value long enough to wrap.
DEADLINE="${DEADLINE#"${DEADLINE%%[!0]*}"}"
DEADLINE="${DEADLINE:-0}"
[ "${#DEADLINE}" -le 6 ] || {
    echo "bench-paired: BENCH_RERUN_DEADLINE must be at most 999999" >&2
    exit 2
}
GAP="${BENCH_CALIB_GAP:-1}"
case "$GAP" in
    '' | *[!0-9]*)
        echo "bench-paired: BENCH_CALIB_GAP must be a number" >&2
        exit 2
        ;;
esac
[[ "$SPREAD" =~ ^[0-9]+(\.[0-9]+)?$ ]] || {
    echo "bench-paired: BENCH_CALIB_SPREAD must be a number" >&2
    exit 2
}
for bin in "$BASE" "$HEAD" "$CALIB"; do
    [ -x "$bin" ] || {
        echo "bench-paired: $bin is not an executable" >&2
        exit 2
    }
done
STAGE="${BENCH_PAIRED_STAGE:-}"
if [ -n "$STAGE" ] && [ ! -f "$(sed -n 2p "$STAGE" 2> /dev/null)" ]; then
    echo "bench-paired: $STAGE names no staged image" >&2
    exit 2
fi
mkdir -p "$OUT"
# Rounds from an earlier run in OUTDIR must not join this comparison.
rm -f "$OUT"/base-*.json "$OUT"/head-*.json "$OUT/report.json"

IMG=""
MNT=""
# Each round leaves its two calibration readings in CAL_base or CAL_head.
CAL_base=""
CAL_head=""
detach_mnt()
{
    [ -n "$MNT" ] || return 0
    hdiutil detach "$MNT" -quiet > /dev/null 2>&1 \
        || hdiutil detach "$MNT" -force -quiet > /dev/null 2>&1 || {
        echo "bench-paired: cannot detach $MNT" >&2
        return 1
    }
    MNT=""
}
cleanup()
{
    detach_mnt || true
    [ -z "$IMG" ] || rm -f "$IMG" "$IMG.shadow"
    rm -f "$STAGE"
}
trap cleanup EXIT

if [ -z "$STAGE" ]; then
    STAGE="$OUT/stage"
    rm -f "$STAGE"
    ELFUSE="$HEAD" BENCH_STRICT=1 bash "$SUITE" -s "$STAGE"
fi
MNT="$(sed -n 1p "$STAGE")"
IMG="$(sed -n 2p "$STAGE")"
detach_mnt

round()
{
    local side="$1" bin="$2" out="$3"
    echo "bench-paired: $side round -> $(basename "$out")"
    rm -f "$IMG.shadow"
    MNT=$(hdiutil attach "$IMG" -shadow "$IMG.shadow" -nobrowse \
        | sed -n 's|.*[[:space:]]\(/Volumes/.*\)$|\1|p' | tail -1)
    [ -n "$MNT" ] || {
        echo "bench-paired: cannot attach $IMG with a shadow file" >&2
        exit 1
    }
    local before after
    before="$(calib)"
    ELFUSE="$bin" BENCH_SYSROOT="$MNT/rootfs" BENCH_ITERATIONS=1 \
        BENCH_WARMUP=0 BENCH_OCI=0 bash "$SUITE" -o "$out"
    after="$(calib)"
    detach_mnt
    rm -f "$IMG.shadow"
    printf -v "CAL_$side" '%s %s' "$before" "$after"
}

# A reading is the lower of two calls GAP seconds apart, so a slowdown shorter
# than GAP drops out while one long enough to move a round's numbers shows in
# both. In local A/A runs, one call per reading reran 3 of 6 pairs, each for a
# reading 7% to 9% high right after a round; two calls reran 1 of 6.
calib()
{
    local a b
    a="$("$CALIB")"
    sleep "$GAP"
    b="$("$CALIB")"
    for v in "$a" "$b"; do
        [[ "$v" =~ ^[0-9]+(\.[0-9]+)?$ ]] || {
            echo "bench-paired: $CALIB printed '$v', not a time" >&2
            exit 1
        }
    done
    awk -v a="$a" -v b="$b" 'BEGIN { print (a < b ? a : b) }'
}

# Record a round's readings, its pair's reruns and the unsteady mark in meta.
annotate()
{
    python3 -I - "$@" << 'PY'
import json, sys
path, before, after, reruns, unsteady = sys.argv[1:]
with open(path, encoding="utf-8") as f:
    doc = json.load(f)
meta = doc.setdefault("meta", {})
meta["calib_us"] = [float(before), float(after)]
meta["reruns"] = int(reruns)
meta["calib_unsteady"] = unsteady == "1"
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
}

# One pair: odd pairs run base first and even pairs head first.
pair()
{
    local i="$1"
    if ((i % 2)); then
        round base "$BASE" "$OUT/base-$i.json"
        round head "$HEAD" "$OUT/head-$i.json"
    else
        round head "$HEAD" "$OUT/head-$i.json"
        round base "$BASE" "$OUT/base-$i.json"
    fi
}

round base "$BASE" "$OUT/discard-base.json"
round head "$HEAD" "$OUT/discard-head.json"
bases=()
heads=()
for ((i = 1; i <= PAIRS; i++)); do
    reruns=0
    unsteady=0
    while :; do
        start=$SECONDS
        pair "$i"
        took=$((SECONDS - start))
        # shellcheck disable=SC2086 # each CAL_ holds two numbers
        spread="$(printf '%s\n' $CAL_base $CAL_head | awk '
            NR == 1 || $1 < lo { lo = $1 }
            NR == 1 || $1 > hi { hi = $1 }
            END { printf "%.4f", (hi - lo) / lo }')"
        echo "bench-paired: pair $i calibration base $CAL_base, head $CAL_head us, spread $spread"
        awk -v s="$spread" -v m="$SPREAD" 'BEGIN { exit !(s > m) }' || break
        # The rerun and the PAIRS - i pairs after it, each as long as this one.
        if ((SECONDS + took * (PAIRS - i + 1) >= DEADLINE)); then
            echo "bench-paired: pair $i kept unsteady, a rerun would end at or past the $DEADLINE s deadline" >&2
            unsteady=1
            break
        fi
        reruns=$((reruns + 1))
        echo "bench-paired: measuring pair $i again (rerun $reruns)"
    done
    # shellcheck disable=SC2086 # each CAL_ holds two numbers
    annotate "$OUT/base-$i.json" $CAL_base "$reruns" "$unsteady"
    # shellcheck disable=SC2086
    annotate "$OUT/head-$i.json" $CAL_head "$reruns" "$unsteady"
    bases+=("$OUT/base-$i.json")
    heads+=("$OUT/head-$i.json")
done
rm -f "$OUT"/discard-*.json

# The comparison comes first, so a failed or timed-out Tier 3 cannot cost it.
python3 "$ROOT/scripts/bench-compare.py" --paired --base "${bases[@]}" \
    --head "${heads[@]}" --report-json "$OUT/report.json"

if [ "${BENCH_PAIRED_OCI:-0}" = "1" ]; then
    ELFUSE="$HEAD" BENCH_LMBENCH=0 BENCH_APPS=0 BENCH_OCI=1 bash "$SUITE" \
        -o "$OUT/head-oci.json"
fi
