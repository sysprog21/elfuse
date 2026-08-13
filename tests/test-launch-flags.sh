#!/usr/bin/env bash
# test-launch-flags.sh -- Pin the rejection rules of the guest launch flags
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Usage: tests/test-launch-flags.sh <elfuse-binary> <guest-elf>
#
# --user and --workdir are rejected before the first guest instruction
# (--user before the VM exists, --workdir during bring-up), so a launcher
# gets a diagnostic rather than a guest running as something other than what
# was asked for.

set -euo pipefail

ELFUSE="${1:?Usage: $0 <elfuse-binary> <guest-elf>}"
GUEST="${2:?Usage: $0 <elfuse-binary> <guest-elf>}"

# shellcheck source=tests/lib/report.sh
. "$(dirname "$0")/lib/report.sh"

# Counters are per-script; see tests/lib/report.sh.
pass=0
fail=0
skip=0

# check <reject|accept> <desc> <stderr-substring or ''> <flags...>
check()
{
    local want="$1" desc="$2" pattern="$3"
    shift 3
    local out status=0
    out="$("$ELFUSE" "$@" "$GUEST" 2>&1)" || status=$?
    if [ "$want" = reject ]; then
        if [ "$status" -eq 0 ]; then
            report_fail "$desc (accepted, want rejection)"
            return
        fi
        if ! printf '%s' "$out" | grep -qF "$pattern"; then
            report_fail "$desc (exit $status but message lacks '$pattern')"
            printf '%s\n' "$out" >&2
            return
        fi
    else
        if [ "$status" -ne 0 ]; then
            report_fail "$desc (exit $status, want success)"
            printf '%s\n' "$out" >&2
            return
        fi
    fi
    report_pass "$desc"
}

check reject "--fakeroot with a non-root --user" "cannot be combined" \
    --fakeroot --user 1000:1000
check reject "--fakeroot with a root uid but non-root gid" "cannot be combined" \
    --fakeroot --user 0:1000
check reject "--workdir relative path" "absolute" --workdir rel/path
check reject "--user non-numeric" "invalid --user" --user alice

# --fakeroot and --user agree here, so the pair must still launch: the check
# refuses a contradiction, not the combination itself.
check accept "--fakeroot with an explicit root --user" '' --fakeroot --user 0:0

# The containment refusal and its rationale live in elfuse_launch. mktemp
# lands in /var/folders, outside is_sysroot_backed_temp_path()'s /tmp prefix,
# so proc_resolve_sysroot_path's host fallback is reachable here.
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/sysroot/inroot" "$scratch/hostonly"

check reject "--workdir absent in the sysroot, present on the host" \
    "does not resolve inside the sysroot" \
    --sysroot "$scratch/sysroot" --workdir "$scratch/hostonly"

check accept "--workdir present in the sysroot" '' \
    --sysroot "$scratch/sysroot" --workdir /inroot

# Pins elfuse_launch's "--sysroot /" carve-out: a bare separator must not
# reject every workdir under it.
check accept "--workdir under a root sysroot" '' --sysroot / --workdir /var/tmp

report_summary
# shellcheck disable=SC2154  # fail is incremented in tests/lib/report.sh
[ "$fail" -eq 0 ] || exit 1
