#!/bin/sh
# Counter-backed dirty-map materialization integration checks.

set -eu

ELFUSE=${1:-build/elfuse}
TEST_BIN=${2:-build/test-mmap-lazy}
TMPDIR_CASE=$(mktemp -d "${TMPDIR:-/tmp}/elfuse-dirty-map.XXXXXX")
trap 'rm -rf "$TMPDIR_CASE"' EXIT INT TERM

ELFUSE_SHIM_STATS=1 "$ELFUSE" "$TEST_BIN" \
    > "$TMPDIR_CASE/out" 2> "$TMPDIR_CASE/err"

counter()
{
    key=$1
    awk -v key="$key" \
        '$1 == key { print $2; found = 1 } END { if (!found) exit 1 }' \
        "$TMPDIR_CASE/err"
}

require_ge()
{
    key=$1
    floor=$2
    value=$(counter "$key") || {
        printf 'missing dirty-map counter %s\n' "$key" >&2
        return 1
    }
    if [ "$value" -lt "$floor" ]; then
        printf '%s=%s, expected >= %s\n' "$key" "$value" "$floor" >&2
        return 1
    fi
}

require_ge FAULT_CLEAN_SKIP 1
require_ge FAULT_DIRTY_MEMSET 1
require_ge FAULT_ALREADY_VALID 1
require_ge FAULT_WINDOW_BYTES 2097152

# Requests exceed the pipe payload and the two partial mprotect edge blocks.
for case_name in short-read mprotect; do
    ELFUSE_SHIM_STATS=1 "$ELFUSE" "$TEST_BIN" "--stats-$case_name" \
        > "$TMPDIR_CASE/out" 2> "$TMPDIR_CASE/err"
    value=$(counter FAULT_WINDOW_BYTES)
    if [ "$value" -gt 4194304 ]; then
        printf '%s materialized %s bytes, expected <= 4194304\n' \
            "$case_name" "$value" >&2
        exit 1
    fi
    printf '  %-28s OK\n' "$case_name bounded fault-in"
done

printf '  clean-block zero skip         OK\n'
printf '  dirty-block selective memset OK\n'
printf '  already-valid early return   OK\n'
printf '  materialized-window bytes    OK\n'
printf 'test-mmap-dirty-stats: PASS\n'
