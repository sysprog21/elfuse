#!/bin/sh
# Counter-backed refill, adaptive sizing, giant-request guard, and VA recycle
# integration checks for the EL1 anonymous-mmap consumer fast path.

set -eu

ELFUSE=${1:-build/elfuse}
TEST_BIN=${2:-build/test-mmap-fastpath}
TMPDIR_CASE=$(mktemp -d "${TMPDIR:-/tmp}/elfuse-mmap-stats.XXXXXX")
trap 'rm -rf "$TMPDIR_CASE"' EXIT INT TERM

run_case()
{
    case_name=$1
    out="$TMPDIR_CASE/$case_name.out"
    err="$TMPDIR_CASE/$case_name.err"
    ELFUSE_SHIM_STATS=1 "$ELFUSE" "$TEST_BIN" "--stats-$case_name" \
        > "$out" 2> "$err"
}

counter()
{
    case_name=$1
    key=$2
    value=$(awk -v key="$key" '$1 == key { print $2; found = 1 } END { if (!found) exit 1 }' \
        "$TMPDIR_CASE/$case_name.err") || {
        printf 'missing counter %s in case %s\n' "$key" "$case_name" >&2
        return 1
    }
    printf '%s\n' "$value"
}

require_ge()
{
    case_name=$1
    key=$2
    floor=$3
    value=$(counter "$case_name" "$key")
    if [ "$value" -lt "$floor" ]; then
        printf '%s: %s=%s, expected >= %s\n' \
            "$case_name" "$key" "$value" "$floor" >&2
        return 1
    fi
}

require_eq()
{
    case_name=$1
    key=$2
    expected=$3
    value=$(counter "$case_name" "$key")
    if [ "$value" -ne "$expected" ]; then
        printf '%s: %s=%s, expected %s\n' \
            "$case_name" "$key" "$value" "$expected" >&2
        return 1
    fi
}

require_le()
{
    case_name=$1
    key=$2
    ceiling=$3
    value=$(counter "$case_name" "$key")
    if [ "$value" -gt "$ceiling" ]; then
        printf '%s: %s=%s, expected <= %s\n' \
            "$case_name" "$key" "$value" "$ceiling" >&2
        return 1
    fi
}

run_case ring-full
require_ge ring-full MMAP_HIT 32
require_ge ring-full MMAP_RING_FULL 1
printf '  32-entry ring fallback        OK\n'

run_case np2-10m
require_ge np2-10m MMAP_HIT 80
require_ge np2-10m MMAP_CAPACITY_MISS 1
printf '  sustained 10 MiB stream       OK\n'

run_case np2-48m
require_ge np2-48m MMAP_HIT 40
require_ge np2-48m MMAP_CAPACITY_MISS 1
printf '  sustained 48 MiB stream       OK\n'

run_case np2-100m
require_ge np2-100m MMAP_HIT 24
require_ge np2-100m MMAP_CAPACITY_MISS 1
printf '  sustained 100 MiB stream      OK\n'

run_case escalation
require_ge escalation MMAP_HIT 45
require_eq escalation MMAP_ARENA_CURRENT 17179869184
printf '  10 MiB -> 512 MiB escalation  OK\n'

run_case giant-guard
require_ge giant-guard MMAP_HIT 34
require_eq giant-guard MMAP_ARENA_PEAK 34359738368
printf '  2 GiB request uses fast path  OK\n'

run_case adaptive-small
require_eq adaptive-small MMAP_ARENA_CURRENT 67108864
require_eq adaptive-small MMAP_ARENA_PEAK 67108864
printf '  small-stream arena floor      OK\n'

run_case adaptive-retention
require_eq adaptive-retention MMAP_ARENA_CURRENT 17179869184
require_eq adaptive-retention MMAP_ARENA_PEAK 17179869184
printf '  large arena retained           OK\n'

run_case adaptive-rewind-growth
require_ge adaptive-rewind-growth MMAP_CAPACITY_MISS 1
require_eq adaptive-rewind-growth MMAP_ARENA_CURRENT 268435456
printf '  rewound arena grows to target  OK\n'

run_case recycle
require_ge recycle MMAP_RECYCLE 1
require_le recycle MMAP_HIGH_WATER 201326592
printf '  arena VA recycling            OK\n'

# Mixed-size churn now recycles VA through the arena rewind and the host gap
# allocator alone. MMAP_RECYCLE is the load-bearing assertion: it is nonzero
# only when a refill actually reclaimed a hole below the high-water mark, so it
# fails the moment VA recovery stops and the allocator only walks forward. The
# hit count keeps the case honest because the other two would also pass if the
# fast path stopped being taken at all. The bound catches growth that recovery
# is too slow to contain.
run_case mixed-churn
require_ge mixed-churn MMAP_HIT 100
require_ge mixed-churn MMAP_RECYCLE 1
require_le mixed-churn MMAP_HIGH_WATER 402653184
printf '  mixed-size churn recycles VA  OK\n'

# A first touch enters the host while the 32 GiB mapping is still live. Its
# arena descriptor must survive that VM exit so the following munmap remains an
# EL1 retirement instead of stranding the mapping in a speculative top-up.
run_case large-materialized
require_eq large-materialized MMAP_ARENA_PEAK 34359738368
require_le large-materialized MMAP_HIGH_WATER 38654705664
printf '  large live arena is retained  OK\n'

# Fork drains and revokes every arena. A near-empty current arena must not be
# topped up between those operations; only the initial vCPU arena is counted.
run_case fork-no-topup
require_eq fork-no-topup MMAP_HIT 1
require_eq fork-no-topup MMAP_REFILL 1
printf '  fork skips arena top-up       OK\n'

run_case prefix-hint
require_eq prefix-hint MMAP_REFILL 1
printf '  prefix hint preserves arena   OK\n'

run_case unused-altstack
require_eq unused-altstack FAULT_WINDOW_BYTES 0
run_case used-altstack
require_ge used-altstack FAULT_WINDOW_BYTES 4096
printf '  only selected altstack faults in OK\n'

run_case invalid-futex
require_eq invalid-futex FAULT_WINDOW_BYTES 0
printf '  invalid futex stays lazy      OK\n'

# The test synchronizes through atomics while sibling vCPUs retain control, so
# msync, W^X, and maps/smaps are the first host observers of fast publications
# and retirements. Keep the case counter-backed so a disabled fast path cannot
# turn the semantic checks into a false green.
run_case observer-semantics
require_ge observer-semantics MMAP_HIT 1
printf '  observer semantics under churn OK\n'

printf 'test-mmap-fastpath-stats: PASS\n'
