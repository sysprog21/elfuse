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
# Environment:
#   BENCH_PAIRS       pairs to measure, 6 to 32 (default 6, the fewest that
#                     bench-compare.py gives a verdict for)
#   BENCH_PAIRED_OCI  1 = also run Tier 3 on the head build; 0 = not (default)
#   BENCH_PAIRED_STAGE  a file written by tests/bench-suite.sh -s; its sysroot
#                     is used instead of staging one here, and this script
#                     detaches it and removes the image and the file
#   BENCH_PAIRED_SUITE  the suite to run (default tests/bench-suite.sh); the
#                     test in tests/test-bench-paired.sh points it at a stub
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
for bin in "$BASE" "$HEAD"; do
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
    ELFUSE="$bin" BENCH_SYSROOT="$MNT/rootfs" BENCH_ITERATIONS=1 \
        BENCH_WARMUP=0 BENCH_OCI=0 bash "$SUITE" -o "$out"
    detach_mnt
    rm -f "$IMG.shadow"
}

round base "$BASE" "$OUT/discard-base.json"
round head "$HEAD" "$OUT/discard-head.json"
bases=()
heads=()
for ((i = 1; i <= PAIRS; i++)); do
    if ((i % 2)); then
        round base "$BASE" "$OUT/base-$i.json"
        round head "$HEAD" "$OUT/head-$i.json"
    else
        round head "$HEAD" "$OUT/head-$i.json"
        round base "$BASE" "$OUT/base-$i.json"
    fi
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
