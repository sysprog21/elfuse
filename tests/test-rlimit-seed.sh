#!/usr/bin/env bash

# test-rlimit-seed.sh -- Guest rlimits seeded from a host whose limits were set
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Usage: tests/test-rlimit-seed.sh <elfuse-binary> <busybox-binary>
#            <test-proc-limits>
#
# The guest table is seeded from host getrlimit at boot, so what a guest reads
# depends on the shell elfuse was started from. Each case sets host limits with
# ulimit, starts elfuse, and reads the guest's /proc/self/limits.

set -euo pipefail

ELFUSE="${1:?Usage: $0 <elfuse-binary> <busybox-binary> <test-proc-limits>}"
BB="${2:?Usage: $0 <elfuse-binary> <busybox-binary> <test-proc-limits>}"
PROC_LIMITS="${3:?Usage: $0 <elfuse-binary> <busybox-binary> <test-proc-limits>}"

# shellcheck source=tests/lib/report.sh
. "$(dirname "$0")/lib/report.sh"

# 6 TiB in KiB: finite, far above the address space elfuse takes for its 1 TiB
# guest slab and the rest of its boot, and not a power of two, which would clamp
# RLIMIT_AS onto a value test-proc-limits gives another limit.
AS_KIB=6442450944

# row <ulimit-args> <row-name>: print the soft and hard columns of the guest row
# after running ulimit with <ulimit-args> (none for the host defaults).
row()
{
    # shellcheck disable=SC2016  # Expanded by the child shell.
    bash -c 'if [ -n "$1" ]; then ulimit $1 || exit 98; fi
        exec "$2" "$3" cat /proc/self/limits' bash "$1" "$ELFUSE" "$BB" \
        | awk -v n="$2" 'index($0, n) == 1 {print $4, $5}'
}

# expect_row <desc> <ulimit-args> <row-name> <soft hard>
expect_row()
{
    local got
    got="$(row "$2" "$3")" || got="exit $?"
    if [ "$got" = "$4" ]; then
        report_pass "$1"
    else
        report_fail "$1 (got '$got', want '$4')"
    fi
}

# Linux starts RSS unlimited; macOS defines RLIMIT_RSS as RLIMIT_AS.
expect_row "RSS ignores a host AS limit" "-v $AS_KIB" "Max resident set" \
    "unlimited unlimited"
expect_row "AS follows the host AS limit" "-v $AS_KIB" "Max address space" \
    "$((AS_KIB * 1024)) $((AS_KIB * 1024))"

# 8176 KiB is the macOS default. make raises the soft limit to the hard one for
# its children, so each case sets the soft limit itself.
expect_row "the macOS default stack reads as 8 MiB" "-Ss 8176" \
    "Max stack size" "8388608 unlimited"
expect_row "a lowered soft stack limit passes through" "-Ss 2048" \
    "Max stack size" "2097152 unlimited"
expect_row "a lowered hard stack limit passes through" "-s 4096" \
    "Max stack size" "4194304 4194304"

if bash -c "ulimit -v $AS_KIB && exec \"\$0\" \"\$1\"" \
    "$ELFUSE" "$PROC_LIMITS" > /dev/null; then
    report_pass "test-proc-limits under a host AS limit"
else
    report_fail "test-proc-limits under a host AS limit"
fi

# A host RLIMIT_FSIZE limits elfuse's own writes too. Under 4 KiB, soft or hard,
# elfuse still boots rather than being killed by a host SIGXFSZ, and a guest
# that raises its soft limit above the host's soft limit writes past it, since
# elfuse lifts its own soft limit to the hard one.
if bash -c 'ulimit -S -f 4 && exec "$0" "$1" true' "$ELFUSE" "$BB"; then
    report_pass "boots under a host file size limit"
else
    report_fail "boots under a host file size limit (exit $?)"
fi
if bash -c 'ulimit -f 4 && exec "$0" "$1" true' "$ELFUSE" "$BB"; then
    report_pass "boots under a host hard file size limit"
else
    report_fail "boots under a host hard file size limit (exit $?)"
fi

XFSZ_FILE="$(mktemp "${TMPDIR:-/tmp}/elfuse-rlimit-seed.XXXXXX")"
trap 'rm -f "$XFSZ_FILE"' EXIT
# shellcheck disable=SC2016  # Expanded by the guest shell.
got="$(bash -c 'ulimit -S -f 4 && exec "$0" "$1" sh -c \
    "ulimit -S -f unlimited && $1 dd if=/dev/zero of=$2 bs=1024 count=8 2>&1"' \
    "$ELFUSE" "$BB" "$XFSZ_FILE")" && rc=0 || rc=$?
if [ "$rc" -eq 0 ] && [ "$(wc -c < "$XFSZ_FILE" | tr -d ' ')" = 8192 ]; then
    report_pass "a guest write past the host soft file size limit lands"
else
    report_fail "a guest write past the host soft file size limit lands (exit $rc: $got)"
fi

report_summary
# shellcheck disable=SC2154  # fail is incremented in tests/lib/report.sh
[ "$fail" -eq 0 ] || exit 1
