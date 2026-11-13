#!/usr/bin/env bash
# test-shim-futex-stats.sh -- the futex EL1 fast path actually runs.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# tests/test-shim-futex-fast.c asserts only Linux futex ABI, which the host path
# satisfies just as well as the shim does: delete futex_wait_fast from
# core/shim.S and it still passes. That is deliberate, because it is what lets
# the reference kernel adjudicate the same file.
#
# What that leaves unchecked is whether EL1 served any of it. The shim counters
# are the only place the difference is visible, so this reads them back:
# ELFUSE_SHIM_STATS=1 dumps every counter slot to stderr at exit.
#
# These counters describe calls that reach futex_wait_fast with attention clear.
# They catch a dispatch that silently stops reaching that path.

set -e -u -o pipefail

ELFUSE="${1:?usage: $0 <elfuse> <wait-guest> <wake-guest>}"
WAIT_GUEST="${2:?usage: $0 <elfuse> <wait-guest> <wake-guest>}"
WAKE_GUEST="${3:?usage: $0 <elfuse> <wait-guest> <wake-guest>}"

# shellcheck source=tests/lib/report.sh
. "$(dirname "$0")/lib/report.sh"
require_timeout

# report.sh keeps the tallies in these; declare them here so the counter check
# at the bottom is not reading a name shellcheck cannot see assigned.
# shellcheck disable=SC2034
pass=0
fail=0
# shellcheck disable=SC2034
skip=0

# The guest makes a blocking futex wait, so run it under the timeout: a
# regression that stops waking it would otherwise hang make check rather than
# failing it. run-lane in mk/tests.mk adds no timeout of its own. Two guests,
# because no single one produces both shapes: the wait guest never wakes
# anything, and the wake guest's waits all block rather than mismatching. Which
# counters each is expected to move is the point of splitting them. The exit
# code is captured rather than left to set -e. A regression that hangs a guest
# gets killed by $TIMEOUT and returns 124, and a bare assignment would abort the
# script right here, so the counter checks below and the final dump of $stats,
# which exist precisely to explain this failure, would never run. The lane would
# report an opaque non-zero with no reason shown.
stats=$("$TIMEOUT" 60 env ELFUSE_SHIM_STATS=1 "$ELFUSE" "$WAIT_GUEST" \
    2>&1 > /dev/null) && wait_rc=0 || wait_rc=$?
wake_stats=$("$TIMEOUT" 120 env ELFUSE_SHIM_STATS=1 "$ELFUSE" "$WAKE_GUEST" \
    2>&1 > /dev/null) && wake_rc=0 || wake_rc=$?
for guest_rc in "wait:$wait_rc" "wake:$wake_rc"; do
    case $guest_rc in
    *:0) ;;
    *)
        report_fail "${guest_rc%%:*} guest exited ${guest_rc##*:}"
        ;;
    esac
done

counter()
{
    printf '%s\n' "${2:-$stats}" \
        | awk -v k="$1" '$1 == k { print $2; found = 1 }
                       END { if (!found) print "missing" }'
}

check_positive()
{
    local name value
    name="$1"
    value=$(counter "$name" "${2:-$stats}")
    if [ "$value" = "missing" ]; then
        report_fail "$name absent from the shim-stats dump"
    elif [ "$value" -le 0 ]; then
        report_fail "$name is $value, expected a nonzero count"
    else
        report_pass "$name = $value"
    fi
}

# Two mismatched untimed waits are served at EL1. The tagged-address and
# matching-word cases decline on shape, and the matching-word case blocks.
check_positive FUTEX_EAGAIN_HIT
check_positive FUTEX_SHAPE_BAIL
check_positive FUTEX_MATCH_BAIL

# Fault fallback unwinds a nested exception frame before HVC. The guest's
# unresolvable addresses exercise it and must still return EFAULT.
check_positive FUTEX_FAULT_BAIL

# The wake path serves the shape a real contended workload actually produces, so
# a dispatch that stops reaching it costs more than the wait path does. Its bail
# counter moves too, because the guest parks a waiter.
check_positive FUTEX_WAKE_HIT "$wake_stats"
check_positive FUTEX_WAKE_WAITER_BAIL "$wake_stats"

report_summary
if [ "$fail" -ne 0 ]; then
    printf '%s\n' "$stats" >&2
    exit 1
fi
