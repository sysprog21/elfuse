#!/usr/bin/env bash
# test-launch-flags.sh -- Pin the behavior of the guest launch flags
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Usage: tests/test-launch-flags.sh <elfuse-binary> <guest-elf>
#            [<env-dump-guest> <cat-guest>]
#
# --user, --workdir, --env, and --clear-env are rejected before the first
# guest instruction (--user before the VM exists, --workdir during bring-up),
# so a launcher gets a diagnostic rather than a guest running as something
# other than what was asked for. Given <env-dump-guest> the environment lanes
# add only what tests/test-guest-env-host.c cannot reach: main() collecting
# the --env tokens, build_linux_stack, and the /proc/self/environ sink.

set -euo pipefail

ELFUSE="${1:?Usage: $0 <elfuse-binary> <guest-elf>}"
GUEST="${2:?Usage: $0 <elfuse-binary> <guest-elf>}"
# The environment observers are optional: a prebuilt guest-binary tree
# (GUEST_TEST_BINARIES) predates test-env-dump, so those lanes skip rather
# than fail when it is absent.
ENV_DUMP="${3:-}"
ENV_CAT="${4:-}"

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
check reject "--env with an empty variable name" "empty variable name" \
    --env =VAL

check reject "--env with an empty argument" "empty variable name" --env ""

# --fakeroot and --user agree here, so the pair must still launch: the check
# refuses a contradiction, not the combination itself.
check accept "--fakeroot with an explicit root --user" '' --fakeroot --user 0:0

# The containment refusal and its rationale live in elfuse_launch. mktemp
# lands in /var/folders, outside is_sysroot_backed_temp_path()'s /tmp prefix,
# so proc_resolve_sysroot_path's host fallback is reachable here.
scratch=$(mktemp -d)
# elfuse backs guest /dev/shm with a private host directory that outlives the
# run, so create the leaf: the check must measure the refusal, not a missing
# directory. chmod because create_private_dir() rejects a group or other bit.
shm_root="/tmp/elfuse-shm-$(id -u)"
shm_wd="$shm_root/launch-flags-wd"
trap 'rm -rf "$scratch" "$shm_wd"' EXIT
mkdir -p "$scratch/sysroot/inroot" "$scratch/hostonly" "$shm_wd"
chmod 700 "$shm_root"

check reject "--workdir absent in the sysroot, present on the host" \
    "does not resolve inside the sysroot" \
    --sysroot "$scratch/sysroot" --workdir "$scratch/hostonly"

check accept "--workdir present in the sysroot" '' \
    --sysroot "$scratch/sysroot" --workdir /inroot

# Pins elfuse_launch's "--sysroot /" carve-out: a bare separator must not
# reject every workdir under it.
check accept "--workdir under a root sysroot" '' --sysroot / --workdir /var/tmp

# Refusal rationale in elfuse_launch; see dev_shm_resolve_path().
check reject "--workdir under /dev/shm" "not supported" \
    --workdir /dev/shm/launch-flags-wd

# The environment the lanes below measure against. MARKER is set so an import
# and a replacement have something to find; ABSENT is cleared in this process
# so the "unset on the host" lane cannot be answered by an inherited value.
export ELFUSE_TEST_MARKER=marker-value
unset ELFUSE_TEST_ABSENT

# guest_env <flags...> -- the guest's environ, one entry per line, in order
guest_env()
{
    "$ELFUSE" "$@" "$ENV_DUMP" 2> /dev/null
}

# env_exact <desc> <want> <flags...>
#   asserts the guest's whole environ, in order. Every caller passes
#   --clear-env: only a cleared base makes the full vector predictable.
env_exact()
{
    local desc="$1" want="$2"
    shift 2
    local got status=0
    got="$(guest_env "$@")" || status=$?
    if [ "$status" -ne 0 ]; then
        report_fail "$desc (exit $status)"
        return
    fi
    if [ "$got" != "$want" ]; then
        report_fail "$desc"
        printf 'want:\n%s\ngot:\n%s\n' "$want" "$got" >&2
        return
    fi
    report_pass "$desc"
}

if [ -z "$ENV_DUMP" ] || [ ! -f "$ENV_DUMP" ]; then
    report_skip "environment lanes (no env-dump guest binary)"
else
    # The `elfuse-oci run` spelling, and the only one that makes the guest's
    # environment a function of the flags alone.
    env_exact "--clear-env alone yields an empty environment" "" --clear-env
    # One vector through every branch of the merge at once.
    # tests/test-guest-env-host.c settles which answer each branch owes; this
    # lane adds that the answer survives build_linux_stack into the guest.
    env_exact "the whole merge reaches the guest, in order" \
        "$(printf 'A=2\nB=\nC=b=c\nELFUSE_TEST_MARKER=marker-value')" \
        --clear-env --env A=1 --env B= --env C=b=c \
        --env ELFUSE_TEST_MARKER --env ELFUSE_TEST_ABSENT --env A=2
    # --clear-env selects the base wherever it appears, so a launcher that
    # appends it after the --env list gets the same environment.
    env_exact "--clear-env after --env selects the same base" "A=1" \
        --env A=1 --clear-env

    # The only lane with a long override list, so it is the one that would
    # catch main() sizing the override array short of the flags given.
    many_flags=()
    many_want=""
    for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
        many_flags+=(--env "K$i=v$i")
        many_want="$many_want${many_want:+$'\n'}K$i=v$i"
    done
    env_exact "twelve --env entries all reach the guest" "$many_want" \
        --clear-env "${many_flags[@]}"

    # Here-strings below, never pipes: under pipefail a `grep -q` exiting at
    # its first match SIGPIPEs the writer. Every capture carries
    # `|| status=$?` because set -e would abort on the very miss these lanes
    # exist to detect.
    status=0
    inherited="$(guest_env)" || status=$?
    if [ "$status" -ne 0 ]; then
        report_fail "no env flags inherits the host environment (exit $status)"
    elif grep -qx 'ELFUSE_TEST_MARKER=marker-value' <<< "$inherited"; then
        report_pass "no env flags inherits the host environment"
    else
        report_fail "no env flags inherits the host environment"
        printf '%s\n' "$inherited" >&2
    fi

    status=0
    appended="$(guest_env --env ELFUSE_TEST_NEW=x)" || status=$?
    if [ "$status" -ne 0 ]; then
        report_fail "--env appends a new name (exit $status)"
    elif [ "$(tail -1 <<< "$appended")" = "ELFUSE_TEST_NEW=x" ] \
        && grep -qx 'ELFUSE_TEST_MARKER=marker-value' <<< "$appended"; then
        report_pass "--env appends a new name and keeps the host entries"
    else
        report_fail "--env appends a new name and keeps the host entries"
        printf '%s\n' "$appended" >&2
    fi

    # One line for the name, at the index the host entry occupied.
    status=0
    unrelated="$(guest_env --env ELFUSE_TEST_UNRELATED=1)" || status=$?
    base_index="$(grep -n '^ELFUSE_TEST_MARKER=' <<< "$unrelated" \
        | cut -d: -f1)" || true
    replacement="$(guest_env --env ELFUSE_TEST_MARKER=replaced)" || status=$?
    replaced="$(grep -n '^ELFUSE_TEST_MARKER=' <<< "$replacement")" || true
    if [ "$status" -ne 0 ]; then
        report_fail "--env replaces a host name in place (exit $status)"
    elif [ -n "$base_index" ] \
        && [ "$replaced" = "$base_index:ELFUSE_TEST_MARKER=replaced" ]; then
        report_pass "--env replaces a host name in place"
    else
        report_fail "--env replaces a host name in place (got '$replaced', \
want index $base_index)"
    fi

    # "--" ends elfuse's own parsing, so an image entrypoint beginning with a
    # flag reaches the guest as argv instead of steering the launcher.
    status=0
    after_dashdash="$("$ELFUSE" --clear-env -- "$ENV_DUMP" --env A=1 \
        2> /dev/null)" || status=$?
    if [ "$status" -ne 0 ]; then
        report_fail "--env after -- is guest argv, not a flag (exit $status)"
    elif [ -z "$after_dashdash" ]; then
        report_pass "--env after -- is guest argv, not a flag"
    else
        report_fail "--env after -- is guest argv, not a flag"
        printf '%s\n' "$after_dashdash" >&2
    fi

    # The procfs sink is held to the same flags and expected entries as the
    # stack lanes above; it is not a direct comparison of one run's two
    # sinks.
    if [ -n "$ENV_CAT" ] && [ -f "$ENV_CAT" ]; then
        # /proc/self/environ is NUL-separated and command substitution drops
        # NUL bytes, so this one must translate inside the pipeline rather
        # than through a variable. Safe against the SIGPIPE race above
        # because tr reads to EOF and never exits early.
        status=0
        procfs="$("$ELFUSE" --clear-env --env A=1 --env B=2 "$ENV_CAT" \
            /proc/self/environ 2> /dev/null | tr '\0' '\n')" || status=$?
        if [ "$status" -ne 0 ]; then
            report_fail "/proc/self/environ cross-check (exit $status)"
        elif [ "$procfs" = "$(printf 'A=1\nB=2')" ]; then
            report_pass "/proc/self/environ agrees with the stack environ"
        else
            report_fail "/proc/self/environ agrees with the stack environ"
            printf '%s\n' "$procfs" >&2
        fi
    else
        report_skip "/proc/self/environ cross-check (no cat guest binary)"
    fi
fi

report_summary
# shellcheck disable=SC2154  # fail is incremented in tests/lib/report.sh
[ "$fail" -eq 0 ] || exit 1
