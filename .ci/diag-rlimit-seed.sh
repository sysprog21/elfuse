#!/usr/bin/env bash
# Diagnostics for the test-rlimit-seed exit 139 seen on the CI runner under
# ulimit -v 1.5 TiB (sysprog21/elfuse#448). Not a test: every run prints its
# exit status and its stderr, and the script itself always exits 0.
#
# Usage: .ci/diag-rlimit-seed.sh <elfuse> <busybox> <test-proc-limits>

set -u

ELFUSE="$1"
BB="$2"
PROC_LIMITS="$3"

TIB=1073741824 # 1 TiB in KiB

sw_vers
uname -a
sysctl hw.memsize hw.model kern.hv_support 2> /dev/null
ulimit -a

# run <label> <ulimit -v KiB> <command...>: run under the limit, outside $(...),
# with elfuse's startup trace on.
run()
{
    local label="$1" kib="$2"
    shift 2
    printf '\n===== %s (ulimit -v %s KiB) =====\n' "$label" "$kib"
    ELFUSE_STARTUP_TRACE=1 bash -c 'ulimit -v "$0" || exit 98; exec "$@"' \
        "$kib" "$@"
    printf -- '----- %s: exit %d\n' "$label" "$?"
}

# The original test-rlimit-seed case, inside $(...) and piped to awk as the lane
# ran it.
original_in_subst()
{
    local label="$1" kib="$2" got status
    # shellcheck disable=SC2016  # The $(...) is text in the banner.
    printf '\n===== %s (ulimit -v %s KiB, inside $(...)) =====\n' "$label" "$kib"
    got="$(set -o pipefail
        bash -c 'ulimit -v "$0" || exit 98; exec "$1" "$2" cat /proc/self/limits' \
            "$kib" "$ELFUSE" "$BB" \
            | awk 'index($0, "Max resident set") == 1 {print $4, $5}')"
    status=$?
    printf -- '----- %s: exit %d, got "%s"\n' "$label" "$status" "$got"
}

for size in 1 1.5 6; do
    kib=$(awk -v s="$size" -v t="$TIB" 'BEGIN {printf "%d", s * t}')
    run "$size TiB: elfuse --version" "$kib" "$ELFUSE" --version
    run "$size TiB: elfuse busybox true" "$kib" "$ELFUSE" "$BB" true
    run "$size TiB: verbose cat /proc/self/limits" "$kib" \
        "$ELFUSE" --verbose "$BB" cat /proc/self/limits
    run "$size TiB: test-proc-limits" "$kib" "$ELFUSE" "$PROC_LIMITS"
    original_in_subst "$size TiB: original case" "$kib"
done

kib=$((TIB * 3 / 2))
for i in 1 2 3; do
    original_in_subst "1.5 TiB: original case, repeat $i" "$kib"
done
run "1.5 TiB: original case outside \$(...)" "$kib" \
    "$ELFUSE" "$BB" cat /proc/self/limits

exit 0
