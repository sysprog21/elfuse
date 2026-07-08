#!/usr/bin/env bash
# Run aarch64 test suites under both elfuse and self-contained QEMU.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Modes:
#   elfuse-aarch64 : run binaries on macOS via build/elfuse
#   qemu-aarch64   : run binaries natively inside qemu-system-aarch64 (boots an
#                    Alpine minirootfs initramfs that the fixture script
#                    downloads on demand)
#   all            : run both modes back-to-back
#
# Environment overrides (defaults point at externals/test-fixtures/):
#   GUEST_TEST_BINARIES        dir of internal test binaries (build/ by default)
#   GUEST_COREUTILS            dir of coreutils-equivalent binaries
#   GUEST_BUSYBOX              path to a single busybox binary
#   GUEST_STATIC_BINS          dir of dash/bash/lua/jq/etc. (optional)
#   GUEST_SYSROOT              musl sysroot for elfuse --sysroot dynamic mode
#   GUEST_DYNAMIC_COREUTILS    dir of dynamic coreutils binaries (musl)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURES="${REPO_ROOT}/externals/test-fixtures"
# Allow tests to point the translator probe at a missing path to exercise the
# non-Rosetta-host skip path without uninstalling the translator.
: "${MATRIX_ROSETTA_TRANSLATOR:=/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta}"

MODE="${1:?Usage: $0 <elfuse-aarch64|qemu-aarch64|elfuse-x86_64|all>}"

# Tool paths.
ELFUSE="${ELFUSE:-${REPO_ROOT}/build/elfuse}"

# Default fixture paths. Each variable points at the actual directory (or file
# for busybox); no implicit /bin suffix is appended.
: "${GUEST_TEST_BINARIES:=${REPO_ROOT}/build}"
: "${GUEST_COREUTILS:=${FIXTURES}/aarch64-musl/staticbin/bin}"
: "${GUEST_BUSYBOX:=${FIXTURES}/aarch64-musl/staticbin/bin/busybox}"
: "${GUEST_STATIC_BINS:=${FIXTURES}/aarch64-musl/dyn-bin}"
: "${GUEST_SYSROOT:=${FIXTURES}/rootfs}"
: "${GUEST_DYNAMIC_COREUTILS:=${FIXTURES}/aarch64-musl/dyn-bin}"
: "${GUEST_GLIBC_SYSROOT:=}"
: "${GUEST_GLIBC_DYNAMIC_COREUTILS:=}"

# x86_64-via-Rosetta fixture roots. Populated by scripts/fetch-fixtures.sh once
# the x86_64 corpus lands. Empty defaults make the suite skip cleanly on hosts
# where the fixtures are not yet present.
: "${GUEST_X86_64_TEST_BINARIES:=${FIXTURES}/x86_64-musl/test-bin}"
: "${GUEST_X86_64_COREUTILS:=${FIXTURES}/x86_64-musl/staticbin/bin}"
: "${GUEST_X86_64_BUSYBOX:=${FIXTURES}/x86_64-musl/staticbin/bin/busybox}"
: "${GUEST_X86_64_STATIC_BINS:=${FIXTURES}/x86_64-musl/dyn-bin}"
: "${GUEST_X86_64_DYNAMIC_COREUTILS:=${FIXTURES}/x86_64-musl/dyn-bin}"
: "${GUEST_X86_64_SYSROOT:=${FIXTURES}/x86_64-musl/rootfs}"
: "${GUEST_X86_64_GLIBC_SYSROOT:=}"
: "${GUEST_X86_64_GLIBC_DYNAMIC_COREUTILS:=}"

# Reuse the shared per-test reporter so the output matches 'make check' (which
# drives tests through tests/driver.sh). TEST_LABEL_WIDTH controls the
# left-aligned name column and must be set before the source so the helper
# library picks it up.
# shellcheck disable=SC2034  # Consumed by tests/lib/test-runner.sh.
TEST_LABEL_WIDTH=45
# shellcheck source=tests/lib/test-runner.sh
source "${REPO_ROOT}/tests/lib/test-runner.sh"

# Globals (test-runner.sh seeds pass/fail/skip; test-matrix.sh resets them per
# mode and tracks no extra counters).
pass=0
fail=0
skip=0

# Test fixture directory; for qemu mode it points at a path inside the VM.
TEST_TMPDIR=""
_qemu_active=0

ensure_fixtures()
{
    if [ ! -s "${FIXTURES}/aarch64-musl/staticbin/bin/busybox" ] \
        || [ ! -s "${FIXTURES}/initramfs.cpio.gz" ]; then
        printf "Fetching test fixtures (one-time download)\n"
        bash "${REPO_ROOT}/tests/fetch-fixtures.sh"
    fi
}

ensure_x86_fixtures()
{
    if [ ! -x "$MATRIX_ROSETTA_TRANSLATOR" ]; then
        return 0
    fi
    if [ -x "${FIXTURES}/x86_64-musl/staticbin/bin/busybox" ] \
        && [ -d "${FIXTURES}/x86_64-musl/dyn-bin" ] \
        && [ -f "${FIXTURES}/x86_64-musl/rootfs/lib/ld-musl-x86_64.so.1" ] \
        && [ -x "${FIXTURES}/x86_64-musl/rootfs/usr/bin/luajit" ]; then
        return 0
    fi
    printf "Fetching x86_64 Rosetta fixtures (one-time download)\n"
    INCLUDE_X86_64=1 bash "${REPO_ROOT}/tests/fetch-fixtures.sh"
}

setup_fixtures()
{
    local mode="$1"
    case "$mode" in
        qemu-*)
            TEST_TMPDIR=$(qemu_exec mktemp -d /tmp/test-matrix.XXXXXX 2> /dev/null)
            qemu_exec sh -c "
            echo 'hello world' > '${TEST_TMPDIR}/hello.txt' &&
            printf 'cherry\napple\nbanana\n' > '${TEST_TMPDIR}/unsorted.txt' &&
            printf 'line1\nline2\nline3\nline4\nline5\n' > '${TEST_TMPDIR}/lines.txt'
        " 2> /dev/null
            ;;
        *)
            TEST_TMPDIR=$(mktemp -d)
            echo "hello world" > "$TEST_TMPDIR/hello.txt"
            printf 'cherry\napple\nbanana\n' > "$TEST_TMPDIR/unsorted.txt"
            printf 'line1\nline2\nline3\nline4\nline5\n' > "$TEST_TMPDIR/lines.txt"
            ;;
    esac
}

cleanup_fixtures()
{
    if [ "$_qemu_active" = "1" ] && [ -n "$TEST_TMPDIR" ]; then
        qemu_exec rm -rf "$TEST_TMPDIR" 2> /dev/null || true
    elif [ -n "$TEST_TMPDIR" ] && [ -d "$TEST_TMPDIR" ]; then
        rm -rf "$TEST_TMPDIR"
    fi
    TEST_TMPDIR=""
}

cleanup_qemu()
{
    if [ "$_qemu_active" = "1" ]; then
        qemu_stop 2> /dev/null || true
        _qemu_active=0
    fi
}

trap 'cleanup_fixtures; cleanup_qemu' EXIT

# Launch helpers. When the binary being launched lives under GUEST_SYSROOT
# (i.e., it's a dynamically-linked Alpine binary), pass --sysroot so the loader
# can find its libc. Static binaries from build/ run unchanged.
run_elfuse()
{
    local first="${1:-}" args=()
    if [ -n "${GUEST_SYSROOT:-}" ]; then
        case "$first" in
            "${GUEST_SYSROOT}"/*) args+=(--sysroot "$GUEST_SYSROOT") ;;
            "${FIXTURES}/aarch64-musl/dyn-bin"/*) args+=(--sysroot "$GUEST_SYSROOT") ;;
        esac
    fi
    timeout 30 "$ELFUSE" ${args[@]+"${args[@]}"} "$@" 2> /dev/null
}

# 'timeout' cannot wrap a shell function, so this runner inlines the path
# rewriting + ssh invocation that qemu_exec would otherwise do. Repo paths under
# REPO_ROOT are rewritten to /mnt/host/...; the remote command is launched with
# cwd=/mnt/host so unqualified paths in test arguments (e.g. "tests/hello.S")
# resolve against the 9p-shared repo just like in elfuse mode.
run_qemu()
{
    local args=() a
    for a in "$@"; do
        case "$a" in
            "${REPO_ROOT}"/*) args+=("/mnt/host/${a#"${REPO_ROOT}"/}") ;;
            *) args+=("$a") ;;
        esac
    done
    local quoted=""
    if [ "${#args[@]}" -gt 0 ]; then
        printf -v quoted '%q ' "${args[@]}"
    fi
    timeout 60 ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o BatchMode=yes \
        -o ConnectTimeout=10 \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=4 \
        -i "$QEMU_SSH_KEY" -p "$QEMU_PORT" \
        root@127.0.0.1 "cd /mnt/host && ${quoted}" 2> /dev/null
}

# elfuse with --sysroot for dynamically-linked guest binaries.
_SYSROOT=""
_ELFUSE_TIMEOUT=30
_GUEST_EXTRA=""

# Optional suffix for run_coreutils_tests section labels so dynamic and static
# runs are distinguishable in the merged output.
_COREUTILS_SUFFIX=""

# Guest path of the coreutils bindir for exec-child targets under --sysroot.
# Empty means "use the host launch path" (native/static runs).
_COREUTILS_GUEST_BINDIR=""

run_elfuse_sysroot()
{
    local bin="$1"
    shift
    local sysroot_args=""
    [ -n "$_SYSROOT" ] && sysroot_args="--sysroot $_SYSROOT"
    # shellcheck disable=SC2086
    timeout "$_ELFUSE_TIMEOUT" "$ELFUSE" $sysroot_args "$bin" $_GUEST_EXTRA "$@" 2> /dev/null
}

# Coreutils fixtures (hello.txt / lines.txt / unsorted.txt) live in the host
# TEST_TMPDIR, which the static runs read directly. Under --sysroot the guest
# view is chrooted to the sysroot, so a host-absolute path is redirected inside
# it and the fixture is not found. For a sysroot run, copy the fixtures into a
# scratch dir inside the sysroot and repoint TEST_TMPDIR at the guest-visible
# path so run_coreutils_tests addresses them by a path that resolves under the
# redirect. Reversed by unstage_sysroot_fixtures.
_HOST_TMPDIR=""
_STAGED_SYSROOT_DIR=""
stage_sysroot_fixtures()
{
    local sysroot="$1"
    local guest_rel="/tmp/matrix-coreutils.$$"
    local host_dir="${sysroot}${guest_rel}"
    mkdir -p "$host_dir"
    # Copy the fixtures setup_fixtures already authored rather than re-creating
    # their content here, so the two stay in sync from one definition.
    cp "$TEST_TMPDIR/hello.txt" "$TEST_TMPDIR/unsorted.txt" \
        "$TEST_TMPDIR/lines.txt" "$host_dir/"
    _HOST_TMPDIR="$TEST_TMPDIR"
    _STAGED_SYSROOT_DIR="$host_dir"
    TEST_TMPDIR="$guest_rel"
}

unstage_sysroot_fixtures()
{
    if [ -n "$_STAGED_SYSROOT_DIR" ]; then
        rm -rf "$_STAGED_SYSROOT_DIR"
    fi
    _STAGED_SYSROOT_DIR=""
    TEST_TMPDIR="$_HOST_TMPDIR"
    _HOST_TMPDIR=""
}

# Generic test helpers.

# Tests that either hang under qemu-system-aarch64 on Apple Silicon or currently
# diverge from the Alpine linux-virt reference kernel on the deprecated
# oom_adj procfs compatibility path exercised by test-io-opt. test-sysfs-cpu
# asserts the elfuse stub contract
# (cache/topology subtree empty, possible == online, cpuN count == online count)
# which a real kernel does not honor. All listed tests still run in
# elfuse-aarch64 mode and in 'make check'; the qemu reference run skips them.
QEMU_SKIP="
test-osync-requeue
test-io-opt
test-sysfs-cpu
"

is_qemu_skipped()
{
    local label="$1"
    local skipped
    for skipped in $QEMU_SKIP; do
        [ "$skipped" = "$label" ] && return 0
    done
    return 1
}

# Honor QEMU_SKIP across all test_* wrappers.
#
# Returns 0 (and prints SKIP) if the caller should not run the test; non-zero
# means proceed.
maybe_qemu_skip()
{
    local runner="$1" label="$2"
    if [ "$runner" = "run_qemu" ] && is_qemu_skipped "$label"; then
        test_report skip "$label" " (qemu)"
        skip=$((skip + 1))
        return 0
    fi
    return 1
}

# Report a timeout as a failure, matching tests/driver.sh.
report_timeout()
{
    local label="$1"
    test_report fail "$label" " (timeout)"
    fail=$((fail + 1))
}

# Account for an optional binary or fixture being absent. The previous pattern
# ('if [ -e "$bin/X" ]; then test_check ... fi') silently erased the assertion
# when X was missing, so the suite summary could report "all passed" while major
# coverage blocks never ran. require_binary always increments skip and emits a
# skip line, so absences are visible in the summary line at the bottom of each
# mode.
require_binary()
{
    local label="$1" path="$2"
    if [ -e "$path" ]; then
        return 0
    fi
    test_report skip "$label" " (missing $path)"
    skip=$((skip + 1))
    return 1
}

suite_summary_fields()
{
    local output="$1"
    printf '%s\n' "$output" \
        | sed -n \
            's/^Results: \([0-9][0-9]*\) passed, \([0-9][0-9]*\) failed, \([0-9][0-9]*\) skipped (of \([0-9][0-9]*\)).*/\1 \2 \3 \4/p' \
        | tail -n 1
}

run_summary_suite()
{
    local label="$1"
    shift

    local output rc
    if output=$("$@" 2>&1); then
        rc=0
    else
        rc=$?
    fi
    printf '%s\n' "$output"

    local fields
    fields="$(suite_summary_fields "$output")"
    if [ -n "$fields" ]; then
        local suite_pass=0 suite_fail=0 suite_skip=0 suite_total=0
        read -r suite_pass suite_fail suite_skip suite_total <<< "$fields"
        # Force decimal: a sub-suite that ever emits a zero-padded count ('08',
        # '09') would otherwise trip bash's "invalid octal" error inside
        # $((...)) and abort the matrix under 'set -e'.
        pass=$((pass + 10#${suite_pass:-0}))
        fail=$((fail + 10#${suite_fail:-0}))
        skip=$((skip + 10#${suite_skip:-0}))
        return "$rc"
    fi

    if [ "$rc" -eq 77 ]; then
        skip_suite "$label" "suite skipped"
        return 0
    fi
    if [ "$rc" -eq 0 ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi
    return "$rc"
}

# Suite-level analog of require_binary for whole fixture directories. The label
# names the suite that is being skipped. Use this in place of bare 'printf
# "SKIP\n"' lines so the skip counter reflects reality.
skip_suite()
{
    local label="$1" reason="$2"
    test_report skip "$label" " ($reason)"
    skip=$((skip + 1))
}

test_check()
{
    local runner="$1"
    shift
    local label="$1"
    shift
    local pattern="$1"
    shift

    maybe_qemu_skip "$runner" "$label" && return

    local output rc
    if output=$($runner "$@"); then rc=0; else rc=$?; fi

    if [ "$rc" = "124" ]; then
        report_timeout "$label"
        return
    fi
    # Require a clean exit before trusting the regex. A crashing tool can still
    # emit the expected substring on stdout before dying, and the earlier "regex
    # match alone passes" behavior would have reported that as OK -- the same
    # silent-skip shape that motivated the tightening of tests/driver.sh
    # evaluate_result.
    if [ "$rc" -ne 0 ]; then
        test_report fail "$label" " (exit $rc)"
        test_excerpt "$output"
        fail=$((fail + 1))
    elif echo "$output" | grep -qE "$pattern"; then
        test_report ok "$label"
        pass=$((pass + 1))
    else
        test_report fail "$label" " (pattern '$pattern' not found, rc=$rc)"
        test_excerpt "$output"
        fail=$((fail + 1))
    fi
}

test_rc()
{
    local runner="$1"
    shift
    local label="$1"
    shift
    local expect_rc="$1"
    shift

    maybe_qemu_skip "$runner" "$label" && return

    local output rc
    if output=$($runner "$@"); then rc=0; else rc=$?; fi

    if [ "$rc" = "124" ]; then
        report_timeout "$label"
        return
    fi
    if [ "$rc" = "$expect_rc" ]; then
        local detail=""
        [ "$expect_rc" -ne 0 ] && detail=" (exit $rc)"
        test_report ok "$label" "$detail"
        pass=$((pass + 1))
    else
        test_report fail "$label" " (got $rc, expected $expect_rc)"
        test_excerpt "$output"
        fail=$((fail + 1))
    fi
}

test_pipe()
{
    local runner="$1"
    shift
    local label="$1"
    shift
    local pattern="$1"
    shift
    local input="$1"
    shift

    maybe_qemu_skip "$runner" "$label" && return

    local output rc
    if output=$(printf '%s' "$input" | $runner "$@"); then rc=0; else rc=$?; fi

    if [ "$rc" = "124" ]; then
        report_timeout "$label"
        return
    fi
    # See test_check for the rc=0 precondition rationale: a non-zero exit must
    # surface as FAIL even when the regex matches, otherwise a crashing pipeline
    # that happens to print the expected substring would be reported OK.
    if [ "$rc" -ne 0 ]; then
        test_report fail "$label" " (exit $rc)"
        test_excerpt "$output"
        fail=$((fail + 1))
    elif echo "$output" | grep -qE "$pattern"; then
        test_report ok "$label"
        pass=$((pass + 1))
    else
        test_report fail "$label" " (pattern '$pattern' not found, rc=$rc)"
        test_excerpt "$output"
        fail=$((fail + 1))
    fi
}

# Test suites.
run_unit_tests()
{
    local runner="$1" bindir="$2"

    printf "Assembly tests\n"
    test_check "$runner" "test-hello" "hello" "$bindir/test-hello"

    printf "\nC unit tests\n"
    test_check "$runner" "hello-musl" "Hello" "$bindir/hello-musl"
    test_check "$runner" "hello-write" "Hello" "$bindir/hello-write"
    test_check "$runner" "echo-test" "hello world" "$bindir/echo-test" hello world
    test_check "$runner" "test-argc" "argc.*3" "$bindir/test-argc" arg1 arg2
    test_rc "$runner" "test-complex" 42 "$bindir/test-complex"
    test_check "$runner" "test-fileio" "lines" "$bindir/test-fileio" LICENSE
    test_check "$runner" "test-string" "memcpy" "$bindir/test-string"
    test_check "$runner" "test-malloc" "OK" "$bindir/test-malloc"
    test_check "$runner" "test-cat" "" "$bindir/test-cat" tests/hello.S
    test_check "$runner" "test-ls" "hello" "$bindir/test-ls" tests/
    test_check "$runner" "test-roundtrip" "OK" "$bindir/test-roundtrip"
    test_check "$runner" "test-comprehensive" "0 failures" "$bindir/test-comprehensive"

    printf "\nProcess tests\n"
    test_check "$runner" "test-fork" "PASS" "$bindir/test-fork"
    test_check "$runner" "test-clone-childtid" "PASS" "$bindir/test-clone-childtid"
    test_check "$runner" "test-exec" "exec-works" "$bindir/test-exec" "$bindir/echo-test" exec-works
    test_check "$runner" "test-fork-exec" "PASS" "$bindir/test-fork-exec" "$bindir/echo-test"
    test_check "$runner" "test-cloexec" "PASS" "$bindir/test-cloexec"

    printf "\nSignal tests\n"
    test_check "$runner" "test-signal" "PASS|0 failed" "$bindir/test-signal"
    test_check "$runner" "test-signal-thread" "PASS|0 failed" "$bindir/test-signal-thread"
    test_check "$runner" "test-tgkill-directed" "0 failed" "$bindir/test-tgkill-directed"
    test_check "$runner" "test-sigill" "0 failed" "$bindir/test-sigill"
    test_check "$runner" "test-kill-broadcast" "0 failed" \
        "$bindir/test-kill-broadcast"
    test_check "$runner" "test-kill-pgroup" "0 failed" \
        "$bindir/test-kill-pgroup"

    printf "\nSocket tests\n"
    test_check "$runner" "test-socket" "PASS|0 failed" "$bindir/test-socket"

    printf "\nSyscall coverage\n"
    test_check "$runner" "test-file-ops" "0 failed" "$bindir/test-file-ops"
    test_check "$runner" "test-sysinfo" "0 failed" "$bindir/test-sysinfo"
    test_check "$runner" "test-io-opt" "0 failed" "$bindir/test-io-opt"
    test_check "$runner" "test-poll" "0 failed" "$bindir/test-poll"

    printf "\nI/O subsystem\n"
    test_check "$runner" "test-eventfd" "0 failed" "$bindir/test-eventfd"
    test_check "$runner" "test-signalfd" "0 failed" "$bindir/test-signalfd"
    test_check "$runner" "test-signalfd-hardening" "0 failed" \
        "$bindir/test-signalfd-hardening"
    test_check "$runner" "test-epoll" "0 failed" "$bindir/test-epoll"
    test_check "$runner" "test-epoll-edge" "0 failed" "$bindir/test-epoll-edge"
    test_check "$runner" "test-epoll-close" "0 failed" "$bindir/test-epoll-close"
    test_check "$runner" "test-epoll-dup" "0 failed" "$bindir/test-epoll-dup"
    test_check "$runner" "test-epoll-refcount" "0 failed" \
        "$bindir/test-epoll-refcount"
    test_check "$runner" "test-timerfd" "0 failed" "$bindir/test-timerfd"

    printf "\n/proc and /dev\n"
    test_check "$runner" "test-proc" "0 failed" "$bindir/test-proc"
    test_check "$runner" "test-sysfs-cpu" "0 failed" "$bindir/test-sysfs-cpu"

    printf "\nNetwork\n"
    test_check "$runner" "test-net" "0 failed" "$bindir/test-net"

    printf "\nThreading\n"
    test_check "$runner" "test-thread" "0 failed" "$bindir/test-thread"
    test_check "$runner" "test-pthread" "0 failed" "$bindir/test-pthread"
    test_check "$runner" "test-osync-requeue" "0 failed" "$bindir/test-osync-requeue"
    test_check "$runner" "test-simd-clone" "0 failed" "$bindir/test-simd-clone"
    test_check "$runner" "test-stress" "0 failed" "$bindir/test-stress"

    printf "\nNegative tests\n"
    test_check "$runner" "test-negative" "0 failed" "$bindir/test-negative"

    printf "\nCoW fork isolation\n"
    test_check "$runner" "test-cow-fork" "PASS" "$bindir/test-cow-fork"

    printf "\nGuard page / mmap edge cases\n"
    test_check "$runner" "test-guard-page" "PASS" "$bindir/test-guard-page"

    printf "\nScatter-gather I/O\n"
    test_check "$runner" "test-readv-writev" "PASS" "$bindir/test-readv-writev"

    printf "\ninotify emulation\n"
    test_check "$runner" "test-inotify" "PASS" "$bindir/test-inotify"

    printf "\nPI futex + EINTR regression\n"
    test_check "$runner" "test-futex-pi" "0 failed" "$bindir/test-futex-pi"

    printf "\nX11 raw protocol\n"
    test_check "$runner" "test-x11" "0 failed" "$bindir/test-x11"
}

run_coreutils_tests()
{
    local runner="$1" bindir="$2"
    # Exec-child targets (env/nice/... run "<dir>/true") must resolve inside the
    # guest. Native/static runs address them by the same host path they launch
    # from; a --sysroot run overrides this with the binary's guest path via
    # _COREUTILS_GUEST_BINDIR so the redirected execve finds the child.
    local guest_bindir="${_COREUTILS_GUEST_BINDIR:-$bindir}"

    printf "Coreutils text%s\n" "$_COREUTILS_SUFFIX"
    test_check "$runner" "echo" "hello" "$bindir/echo" hello
    test_check "$runner" "cat" "hello world" "$bindir/cat" "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "head" "line1" "$bindir/head" "$TEST_TMPDIR/lines.txt"
    test_check "$runner" "tail" "line5" "$bindir/tail" "$TEST_TMPDIR/lines.txt"
    test_check "$runner" "wc" "5" "$bindir/wc" -l "$TEST_TMPDIR/lines.txt"
    test_check "$runner" "sort" "apple" "$bindir/sort" "$TEST_TMPDIR/unsorted.txt"
    test_pipe "$runner" "tr" "HELLO" "hello" "$bindir/tr" a-z A-Z
    test_check "$runner" "seq" "5" "$bindir/seq" 1 5
    test_check "$runner" "expr" "3" "$bindir/expr" 1 + 2
    test_check "$runner" "factor" "2 2 3" "$bindir/factor" 12
    test_check "$runner" "base64" "aGVsbG8" "$bindir/base64" "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "md5sum" "hello.txt" "$bindir/md5sum" "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "sha256sum" "hello.txt" "$bindir/sha256sum" "$TEST_TMPDIR/hello.txt"

    printf "\nCoreutils file ops%s\n" "$_COREUTILS_SUFFIX"
    test_rc "$runner" "cp" 0 "$bindir/cp" "$TEST_TMPDIR/hello.txt" "$TEST_TMPDIR/hello-cp-$$"
    test_rc "$runner" "touch" 0 "$bindir/touch" "$TEST_TMPDIR/touched-$$"
    test_check "$runner" "ls" "hello" "$bindir/ls" "$TEST_TMPDIR"
    test_check "$runner" "stat" "File:" "$bindir/stat" "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "basename" "hello.txt" "$bindir/basename" "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "dirname" "$TEST_TMPDIR" "$bindir/dirname" "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "realpath" "hello.txt" "$bindir/realpath" "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "df" "Filesystem" "$bindir/df" "$TEST_TMPDIR"
    test_check "$runner" "du" "[0-9]" "$bindir/du" -s "$TEST_TMPDIR"

    printf "\nCoreutils sysinfo%s\n" "$_COREUTILS_SUFFIX"
    test_check "$runner" "uname" "Linux" "$bindir/uname" -s
    test_check "$runner" "date" "202" "$bindir/date" "+%Y"
    test_check "$runner" "id" "uid=" "$bindir/id"
    test_check "$runner" "printenv" "/" "$bindir/printenv" PATH
    test_check "$runner" "nproc" "[0-9]" "$bindir/nproc"

    printf "\nCoreutils process%s\n" "$_COREUTILS_SUFFIX"
    test_rc "$runner" "true" 0 "$bindir/true"
    test_rc "$runner" "false" 1 "$bindir/false"
    test_rc "$runner" "sleep" 0 "$bindir/sleep" 0
    test_rc "$runner" "env" 0 "$bindir/env" "$guest_bindir/true"
    test_rc "$runner" "nice" 0 "$bindir/nice" "$guest_bindir/true"
    test_rc "$runner" "nohup" 0 "$bindir/nohup" "$guest_bindir/true"
    test_rc "$runner" "timeout" 0 "$bindir/timeout" 5 "$guest_bindir/true"

    printf "\nCoreutils encoding%s\n" "$_COREUTILS_SUFFIX"
    # The if/then form contains require_binary's exit status so missing binaries
    # do not propagate as a function-exit-1 under 'set -e'. The earlier '&&
    # test_check' chain failed the matrix script outright whenever the LAST
    # optional binary in a function was absent.
    if require_binary "base32" "$bindir/base32"; then
        test_check "$runner" "base32" "NBSWY" "$bindir/base32" "$TEST_TMPDIR/hello.txt"
    fi
    test_check "$runner" "sha1sum" "hello.txt" "$bindir/sha1sum" "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "sha512sum" "hello.txt" "$bindir/sha512sum" "$TEST_TMPDIR/hello.txt"
    if require_binary "b2sum" "$bindir/b2sum"; then
        test_check "$runner" "b2sum" "hello.txt" "$bindir/b2sum" "$TEST_TMPDIR/hello.txt"
    fi
    test_check "$runner" "cksum" "hello.txt" "$bindir/cksum" "$TEST_TMPDIR/hello.txt"
    if require_binary "numfmt" "$bindir/numfmt"; then
        test_check "$runner" "numfmt" "1\\.0[kK]" "$bindir/numfmt" --to=si 1000
    fi
}

run_rosetta_x86_64_suites()
{
    local rc=0

    printf "Rosetta CLI gating\n"
    run_summary_suite "rosetta-cli" \
        bash "${REPO_ROOT}/tests/test-rosetta-cli.sh" "$ELFUSE" || rc=1

    printf "\nRosetta failure modes\n"
    run_summary_suite "rosetta-failure-modes" \
        bash "${REPO_ROOT}/tests/test-rosetta-failure-modes.sh" "$ELFUSE" || rc=1

    if [ -x "$MATRIX_ROSETTA_TRANSLATOR" ]; then
        printf "\nRosetta statics\n"
        run_summary_suite "rosetta-statics" \
            bash "${REPO_ROOT}/tests/test-rosetta-statics.sh" "$ELFUSE" || rc=1

        printf "\nRosetta Alpine corpus\n"
        run_summary_suite "rosetta-alpine" \
            bash "${REPO_ROOT}/tests/test-rosetta-alpine.sh" "$ELFUSE" || rc=1

        printf "\nRosetta thread/signal audit\n"
        run_summary_suite "rosetta-audit" \
            bash "${REPO_ROOT}/tests/test-rosetta-audit.sh" "$ELFUSE" || rc=1

        printf "\nRosetta guest JIT\n"
        run_summary_suite "rosetta-jit" \
            bash "${REPO_ROOT}/tests/test-rosetta-jit.sh" "$ELFUSE" || rc=1

        printf "\nRosetta execve fd preservation\n"
        run_summary_suite "rosetta-execfd" \
            bash "${REPO_ROOT}/tests/test-rosetta-execfd.sh" "$ELFUSE" || rc=1

        printf "\nRosetta glibc dynamic\n"
        run_summary_suite "rosetta-glibc" \
            bash "${REPO_ROOT}/tests/test-rosetta-glibc.sh" "$ELFUSE" || rc=1

        printf "\nRosetta high-VA madvise\n"
        run_summary_suite "rosetta-madvise" \
            bash "${REPO_ROOT}/tests/test-rosetta-madvise.sh" "$ELFUSE" || rc=1

        printf "\nRosetta high-VA msync\n"
        run_summary_suite "rosetta-msync" \
            bash "${REPO_ROOT}/tests/test-rosetta-msync.sh" "$ELFUSE" || rc=1

        printf "\nRosetta high-VA mremap\n"
        run_summary_suite "rosetta-mremap" \
            bash "${REPO_ROOT}/tests/test-rosetta-mremap.sh" "$ELFUSE" || rc=1
    else
        local suite
        for suite in rosetta-statics rosetta-alpine rosetta-audit rosetta-jit \
            rosetta-execfd rosetta-glibc rosetta-madvise rosetta-msync \
            rosetta-mremap; do
            skip_suite "$suite" "Rosetta translator not installed"
        done
    fi

    return "$rc"
}

run_busybox_tests()
{
    local runner="$1" bb="$2"

    printf "Busybox core\n"
    test_check "$runner" "bb echo" "hello" "$bb" echo hello
    test_check "$runner" "bb cat" "hello world" "$bb" cat "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "bb head" "line1" "$bb" head -n1 "$TEST_TMPDIR/lines.txt"
    test_check "$runner" "bb tail" "line5" "$bb" tail -n1 "$TEST_TMPDIR/lines.txt"
    test_check "$runner" "bb wc" "5" "$bb" wc -l "$TEST_TMPDIR/lines.txt"
    test_check "$runner" "bb sort" "apple" "$bb" sort "$TEST_TMPDIR/unsorted.txt"
    test_check "$runner" "bb seq" "5" "$bb" seq 1 5
    test_check "$runner" "bb expr" "3" "$bb" expr 1 + 2
    test_check "$runner" "bb factor" "2 2 3" "$bb" factor 12
    test_check "$runner" "bb base64" "aGVsbG8" "$bb" base64 "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "bb md5sum" "hello.txt" "$bb" md5sum "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "bb sha256sum" "hello.txt" "$bb" sha256sum "$TEST_TMPDIR/hello.txt"
    test_pipe "$runner" "bb tr" "HELLO" "hello" "$bb" tr a-z A-Z
    test_pipe "$runner" "bb sed" "HELLO" "hello" "$bb" sed 's/hello/HELLO/'
    test_pipe "$runner" "bb awk" "b" "a b" "$bb" awk '{print $2}'
    test_pipe "$runner" "bb grep" "hello" "hello" "$bb" grep hello

    printf "\nBusybox file ops\n"
    test_rc "$runner" "bb cp" 0 "$bb" cp "$TEST_TMPDIR/hello.txt" "$TEST_TMPDIR/bb-cp-$$"
    test_rc "$runner" "bb touch" 0 "$bb" touch "$TEST_TMPDIR/bb-touch-$$"
    test_check "$runner" "bb ls" "hello" "$bb" ls "$TEST_TMPDIR"
    test_check "$runner" "bb stat" "File:" "$bb" stat "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "bb basename" "hello.txt" "$bb" basename "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "bb dirname" "$TEST_TMPDIR" "$bb" dirname "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "bb uname" "Linux" "$bb" uname -s
    test_check "$runner" "bb date" "202" "$bb" date "+%Y"
    test_check "$runner" "bb id" "uid=" "$bb" id

    printf "\nBusybox archive\n"
    test_rc "$runner" "bb gzip" 0 "$bb" gzip -kf "$TEST_TMPDIR/hello.txt"
    test_check "$runner" "bb zcat" "hello world" "$bb" zcat "$TEST_TMPDIR/hello.txt.gz"

    printf "\nBusybox shell\n"
    test_pipe "$runner" "bb ash" "hello" "" "$bb" ash -c "echo hello"
    test_pipe "$runner" "bb sh" "hello" "" "$bb" sh -c "echo hello"
}

run_static_tests()
{
    local runner="$1" bindir="$2"

    printf "Static bins\n"

    if require_binary "dash" "$bindir/dash"; then
        test_check "$runner" "dash echo" "hello" "$bindir/dash" -c "echo hello"
        test_check "$runner" "dash arithmetic" "2\\+3=5" "$bindir/dash" -c 'echo "2+3=$((2+3))"'
    fi
    if require_binary "bash" "$bindir/bash"; then
        test_check "$runner" "bash echo" "hello" "$bindir/bash" -c "echo hello"
        test_pipe "$runner" "bash subshell" "sub=25" "" "$bindir/bash" -c 'echo "sub=$(echo $((5*5)))"'
    fi
    # lua has two acceptable names; prefer 5.4, then fall back to plain lua, and
    # skip with accounting if neither is present.
    if [ -e "$bindir/lua5.4" ]; then
        test_check "$runner" "lua hello" "Hello" "$bindir/lua5.4" -e 'print("Hello from " .. _VERSION)'
        test_check "$runner" "lua fib(30)" "832040" "$bindir/lua5.4" -e 'local function f(n) if n<2 then return n end; return f(n-1)+f(n-2) end; print(f(30))'
    elif [ -e "$bindir/lua" ]; then
        test_check "$runner" "lua hello" "Hello" "$bindir/lua" -e 'print("Hello from " .. _VERSION)'
        test_check "$runner" "lua fib(30)" "832040" "$bindir/lua" -e 'local function f(n) if n<2 then return n end; return f(n-1)+f(n-2) end; print(f(30))'
    else
        skip_suite "lua" "neither lua5.4 nor lua under $bindir"
    fi
    if require_binary "gawk" "$bindir/gawk"; then
        test_pipe "$runner" "gawk field" "world" "hello world" "$bindir/gawk" '{print $2}'
    fi
    if require_binary "grep" "$bindir/grep"; then
        test_pipe "$runner" "grep basic" "hello" "hello world" "$bindir/grep" hello
    fi
    if require_binary "sed" "$bindir/sed"; then
        test_pipe "$runner" "sed subst" "HELLO" "hello" "$bindir/sed" 's/hello/HELLO/'
    fi
    if require_binary "jq" "$bindir/jq"; then
        test_pipe "$runner" "jq simple" "^1$" '{"a":1}' "$bindir/jq" '.a'
        test_pipe "$runner" "jq filter" "Alice" '{"users":[{"name":"Alice","age":30},{"name":"Bob","age":25}]}' "$bindir/jq" '.users[] | select(.age > 28) | .name'
    fi
    if require_binary "sqlite3" "$bindir/sqlite3"; then
        test_check "$runner" "sqlite version" "^3\\." "$bindir/sqlite3" ":memory:" "SELECT sqlite_version();"
        test_check "$runner" "sqlite arith" "^42$" "$bindir/sqlite3" ":memory:" "SELECT 6 * 7;"
    fi
    if require_binary "tree" "$bindir/tree"; then
        test_check "$runner" "tree" "director" "$bindir/tree" "$TEST_TMPDIR"
    fi
    if require_binary "find" "$bindir/find"; then
        test_check "$runner" "find" "hello.txt" "$bindir/find" "$TEST_TMPDIR" -name "hello.txt"
    fi
    if require_binary "diff" "$bindir/diff"; then
        test_rc "$runner" "diff identical" 0 "$bindir/diff" "$TEST_TMPDIR/hello.txt" "$TEST_TMPDIR/hello.txt"
    fi
}

# Mode runners.
run_suite()
{
    local mode="$1"
    local runner dyn_runner

    case "$mode" in
        elfuse-aarch64)
            runner="run_elfuse"
            dyn_runner="run_elfuse_sysroot"
            ;;
        qemu-aarch64)
            # shellcheck disable=SC1091
            . "${REPO_ROOT}/tests/qemu-runner.sh"
            printf "Booting qemu-system-aarch64 (Alpine minirootfs)\n"
            qemu_start || {
                echo "qemu boot failed"
                return 1
            }
            _qemu_active=1
            runner="run_qemu"
            dyn_runner="run_qemu"
            ;;
        elfuse-x86_64)
            ;;
        *)
            echo "Unknown mode: $mode"
            return 2
            ;;
    esac

    if [ "$mode" != "elfuse-x86_64" ]; then
        cleanup_fixtures
        setup_fixtures "$mode"
    fi

    printf "\nTesting: %s\n\n" "$mode"

    pass=0
    fail=0
    skip=0

    if [ "$mode" = "elfuse-x86_64" ]; then
        run_rosetta_x86_64_suites || true

        local total=$((pass + fail + skip))
        if [ "$fail" -eq 0 ] && [ "$skip" -eq 0 ]; then
            printf "  All %d tests passed\n\n" "$pass"
        else
            printf "  Results: %d passed, %d failed, %d skipped (of %d)\n\n" \
                "$pass" "$fail" "$skip" "$total"
        fi
        if [ ! -x "$MATRIX_ROSETTA_TRANSLATOR" ]; then
            printf "  Expected: elfuse-x86_64 ran host-independent guardrails; "
            printf "Rosetta-only suites skipped because the translator is absent.\n\n"
            return "$fail"
        fi
        verify_expected_counts "$mode"
        return $?
    fi

    run_unit_tests "$runner" "$GUEST_TEST_BINARIES"
    run_coreutils_tests "$runner" "$GUEST_COREUTILS"
    run_busybox_tests "$runner" "$GUEST_BUSYBOX"

    if [ -d "$GUEST_STATIC_BINS" ]; then
        # run_elfuse auto-adds --sysroot for binaries under GUEST_SYSROOT or the
        # dyn-bin dir (see its case), so tree/find/diff here run chrooted and
        # must read the fixtures from inside the sysroot, same as the dynamic
        # coreutils run. Stage them only for elfuse runs when that trigger
        # applies.
        local static_staged=0
        if [ "$mode" = "elfuse-aarch64" ] && [ -n "${GUEST_SYSROOT:-}" ]; then
            case "$GUEST_STATIC_BINS" in
                "${GUEST_SYSROOT}"/* | "${FIXTURES}/aarch64-musl/dyn-bin"*)
                    stage_sysroot_fixtures "$GUEST_SYSROOT"
                    static_staged=1
                    ;;
            esac
        fi
        run_static_tests "$runner" "$GUEST_STATIC_BINS"
        if [ "$static_staged" = 1 ]; then
            unstage_sysroot_fixtures
        fi
    else
        skip_suite "static-bins" "no $GUEST_STATIC_BINS"
    fi

    # Dynamic-musl coreutils: elfuse needs --sysroot, qemu runs natively. The
    # skip line always increments the counter so a partial fixture set surfaces
    # in the per-mode summary instead of looking like a full pass.
    if [ -d "$GUEST_DYNAMIC_COREUTILS" ]; then
        if {
            [ "$mode" = "elfuse-aarch64" ] || [ "$mode" = "elfuse-x86_64" ]
        } \
            && [ -z "$GUEST_SYSROOT" ]; then
            skip_suite "dyn-coreutils (musl)" "no GUEST_SYSROOT"
        else
            _COREUTILS_SUFFIX=" (musl dyn)"
            _SYSROOT="$GUEST_SYSROOT"
            if [ "$mode" = "elfuse-aarch64" ]; then
                # dyn-bin binaries symlink to the rootfs /bin multiplexer, so
                # their guest path under --sysroot is /bin.
                _COREUTILS_GUEST_BINDIR="/bin"
                stage_sysroot_fixtures "$GUEST_SYSROOT"
            fi
            run_coreutils_tests "$dyn_runner" "$GUEST_DYNAMIC_COREUTILS"
            if [ "$mode" = "elfuse-aarch64" ]; then
                unstage_sysroot_fixtures
                _COREUTILS_GUEST_BINDIR=""
            fi
            _COREUTILS_SUFFIX=""
        fi
    else
        skip_suite "dyn-coreutils (musl)" "no $GUEST_DYNAMIC_COREUTILS"
    fi

    if [ -n "$GUEST_GLIBC_DYNAMIC_COREUTILS" ] && [ -d "$GUEST_GLIBC_DYNAMIC_COREUTILS" ]; then
        if {
            [ "$mode" = "elfuse-aarch64" ] || [ "$mode" = "elfuse-x86_64" ]
        } \
            && [ -z "$GUEST_GLIBC_SYSROOT" ]; then
            skip_suite "dyn-coreutils (glibc)" "no GUEST_GLIBC_SYSROOT"
        else
            _COREUTILS_SUFFIX=" (glibc dyn)"
            _SYSROOT="$GUEST_GLIBC_SYSROOT"
            if [ "$mode" = "elfuse-aarch64" ]; then
                _COREUTILS_GUEST_BINDIR="/usr/bin"
                stage_sysroot_fixtures "$GUEST_GLIBC_SYSROOT"
            fi
            run_coreutils_tests "$dyn_runner" "$GUEST_GLIBC_DYNAMIC_COREUTILS"
            if [ "$mode" = "elfuse-aarch64" ]; then
                unstage_sysroot_fixtures
                _COREUTILS_GUEST_BINDIR=""
            fi
            _COREUTILS_SUFFIX=""
        fi
    else
        skip_suite "dyn-coreutils (glibc)" "no GUEST_GLIBC_DYNAMIC_COREUTILS"
    fi

    _SYSROOT=""

    local total=$((pass + fail + skip))
    if [ "$fail" -eq 0 ] && [ "$skip" -eq 0 ]; then
        printf "  All %d tests passed\n\n" "$pass"
    else
        printf "  Results: %d passed, %d failed, %d skipped (of %d)\n\n" \
            "$pass" "$fail" "$skip" "$total"
    fi

    cleanup_fixtures
    cleanup_qemu

    # Compare against the per-mode expected outcome.
    #
    # Return its verdict rather than the raw fail count so modes with recorded
    # known-failure baselines still exit 0 when their observed results match the
    # table.
    verify_expected_counts "$mode"
    return $?
}

# Per-mode expected outcome envelope. Each mode lists the minimum pass count and
# the exact failure count the matrix is allowed to report. Skip counts are
# advisory because some skips depend on the host environment (qemu running on
# Apple Silicon vs Linux, x86_64 fixtures present or not). When the runtime
# advances, bump these counts in the same commit that changes behaviour so
# reviewers see the new headline numbers explicitly.
#
# elfuse-x86_64 baseline (71) is the sum of the seven Rosetta sub-suites in
# run_rosetta_x86_64_suites:
#   test-rosetta-cli.sh            = 4
#   test-rosetta-failure-modes.sh  = 3
#   test-rosetta-statics.sh        = 20
#   test-rosetta-alpine.sh         = 33
#   test-rosetta-audit.sh          = 2
#   test-rosetta-jit.sh            = 2
#   test-rosetta-glibc.sh          = 7
# The full per-binary inventory and the per-host capture process live in
# docs/testing.md "x86_64 Acceptance Inventory and Per-Host Baselines". Bump
# these counts in the same commit that grows or trims any sub-suite's Results
# line so the matrix gate stays in sync.
#
# Per-mode baseline gate. Encoded as "key|min_pass|max_fail" tuples in a
# single indexed array so stock macOS bash 3.2 (which lacks 'declare -A') works
# the same as bash 4+.
#
# The bareword-subscript hazard the prior 'declare -A' form had to dodge (shfmt
# rewriting [a-b] into [a - b] inside subscripts) does not apply to this
# encoding: keys live inside a quoted string, never as a subscript expression.
#
# Order: aarch64 baselines first, then x86_64 baselines keyed by detected host
# SoC class. The two M-series classes diverge inside sys_mmap_fixed_high_va on
# IPA width (apple-m1-m2 is 36-bit, the overflow-segment path; apple-m3-plus is
# 40-bit, the bisected-slab path on M5). The seven Rosetta sub-suites currently
# emit fixed pass counts regardless of IPA width, so both rows start at 71; an
# operator with M3+ hardware updates the apple-m3-plus row in place when their
# observed counts diverge. apple-unknown is the fallback row for SoC strings the
# detector does not recognize yet.
EXPECTED_BASELINES=(
    "elfuse-aarch64|169|0"
    "qemu-aarch64|165|0"
    "elfuse-x86_64:apple-m1-m2|71|0"
    "elfuse-x86_64:apple-m3-plus|71|0"
    "elfuse-x86_64:apple-unknown|71|0"
)

# Look up the (min_pass, max_fail) baseline for a mode key. Writes the values
# into the named output variables and returns 0 on hit, 1 on miss. Callers use
# the rc=1 path as "no recorded baseline for this key, stay silent".
#
# Parses from the right so a key containing a literal '|' would still split
# correctly (today the schema has none, but the right-anchored form is no harder
# to read and removes the trap). printf -v sets the named output without eval;
# printf -v exists in bash 3.1+.
expected_baseline_get()
{
    local target="$1"
    local out_min="$2"
    local out_fail="$3"
    local entry head key min max
    for entry in "${EXPECTED_BASELINES[@]}"; do
        max="${entry##*|}"
        head="${entry%|*}"
        min="${head##*|}"
        key="${head%|*}"
        if [ "$key" = "$target" ]; then
            printf -v "$out_min" '%s' "$min"
            printf -v "$out_fail" '%s' "$max"
            return 0
        fi
    done
    return 1
}

# Host SoC class detector for x86_64 baseline selection. Reads
# machdep.cpu.brand_string (sysctl), which Apple Silicon Macs publish as "Apple
# M1", "Apple M2 Pro", "Apple M3 Max", etc. The MATRIX_HOST _CLASS_OVERRIDE env
# var exists so the M3+ row can be exercised from an M1/M2 host (and vice versa)
# without modifying the detector. The detector intentionally returns a stable
# apple-unknown rather than guessing on never-seen brand strings so new SoCs do
# not silently graft onto an existing row. Validate MATRIX_HOST_CLASS_OVERRIDE
# at script entry. The detector is invoked from $(...) inside
# verify_expected_counts, where an exit only terminates the subshell and the
# parent silently sees an empty class. Pre-validating here makes a typo (e.g.
# "apple-m3" missing -plus) fail loudly before any sub-suite runs.
if [ -n "${MATRIX_HOST_CLASS_OVERRIDE:-}" ]; then
    case "$MATRIX_HOST_CLASS_OVERRIDE" in
        apple-m1-m2 | apple-m3-plus | apple-unknown) ;;
        *)
            printf 'MATRIX_HOST_CLASS_OVERRIDE: unknown class "%s"; ' \
                "$MATRIX_HOST_CLASS_OVERRIDE" >&2
            printf 'expected one of apple-m1-m2 / apple-m3-plus / apple-unknown\n' >&2
            exit 2
            ;;
    esac
fi

detect_x86_64_host_class()
{
    if [ -n "${MATRIX_HOST_CLASS_OVERRIDE:-}" ]; then
        printf '%s\n' "$MATRIX_HOST_CLASS_OVERRIDE"
        return 0
    fi
    local brand
    brand="$(sysctl -n machdep.cpu.brand_string 2> /dev/null || true)"
    case "$brand" in
        *"Apple M1"* | *"Apple M2"*) printf 'apple-m1-m2\n' ;;
        *"Apple M3"* | *"Apple M4"* | *"Apple M5"*) printf 'apple-m3-plus\n' ;;
        *) printf 'apple-unknown\n' ;;
    esac
}

# Known-failure annotations. These are tests that fail by design under a given
# mode and are tracked here so the matrix runner can distinguish them from real
# regressions in surface output. The matrix does not yet rewrite their pass/fail
# accounting (the underlying drivers would need richer reporting), but this list
# is the canonical reference for "expected to fail" in code review and CI
# triage.
#
# qemu-aarch64: none. test-poll used to diverge inside the qemu reference VM but
# now passes there (observed on the self-hosted runner and in local captures);
# the qemu row in EXPECTED_BASELINES therefore pins exactly zero failures.
KNOWN_FAILURES_QEMU_AARCH64=""
# elfuse-x86_64: rosetta limitations documented in the upstream hyper-linux
# audit. test-signal-thread fails because rosetta shadows signal state
# internally (SA_RESETHAND not reset); test-thread / test-stress hang on
# rosetta's TLS=0 corner case.
KNOWN_FAILURES_ELFUSE_X86_64="test-signal-thread test-tgkill-directed test-thread test-stress"

verify_expected_counts()
{
    local mode="$1"
    local key="$mode"
    local host_class=""
    if [ "$mode" = "elfuse-x86_64" ]; then
        host_class="$(detect_x86_64_host_class)"
        key="${mode}:${host_class}"
    fi

    local exp_min="" exp_fail=""
    if ! expected_baseline_get "$key" exp_min exp_fail; then
        # No recorded baseline for this key (experimental local mode, or an
        # x86_64 host class the detector did not classify). Stay silent so the
        # matrix runner remains usable as a smoke probe.
        return 0
    fi

    # Uncaptured rows: apple-m3-plus inherits the M1/M2 numbers pending operator
    # capture on real M3+ hardware; apple-unknown means the SoC brand string did
    # not match a known class at all. In both cases surface that the baseline is
    # not authoritative for this host so a genuine M3+ divergence is not
    # silently absorbed.
    if [ "$mode" = "elfuse-x86_64" ]; then
        case "$host_class" in
            apple-m3-plus)
                printf "  Note: elfuse-x86_64 baseline for %s is held equal to\n" \
                    "$host_class"
                printf "  apple-m1-m2 pending capture on real M3+ hardware. If\n"
                printf "  your numbers diverge, update only the\n"
                printf "  EXPECTED_*[elfuse-x86_64:apple-m3-plus] rows.\n"
                ;;
            apple-unknown)
                printf "  Note: host SoC did not match a known M-series class;\n"
                printf "  falling back to the elfuse-x86_64:apple-unknown row.\n"
                printf "  Add the new SoC to detect_x86_64_host_class so future\n"
                printf "  runs gate against the right baseline.\n"
                ;;
        esac
    fi

    local err=0
    if [ "$pass" -lt "$exp_min" ]; then
        printf "  Expected-pass deviation: %s saw %d pass, baseline %d.\n" \
            "$key" "$pass" "$exp_min"
        err=1
    fi
    if [ "$fail" -ne "$exp_fail" ]; then
        printf "  Expected-fail deviation: %s saw %d fail, baseline %d.\n" \
            "$key" "$fail" "$exp_fail"
        err=1
    fi
    if [ "$err" -eq 0 ]; then
        printf "  Expected: %s within baseline (>= %d pass, exactly %d fail).\n\n" \
            "$key" "$exp_min" "$exp_fail"
    else
        printf "  Bump the EXPECTED_* table in tests/test-matrix.sh if this\n"
        printf "  shift is intentional.\n\n"
    fi
    return "$err"
}

# Main entry point. The aarch64 fixture fetch only matters for modes that
# actually consume those binaries; running elfuse-x86_64 in isolation lets the
# user iterate before the x86_64 corpus exists, without pulling the aarch64 musl
# rootfs and qemu kernel they will not use.
case "$MODE" in
    elfuse-x86_64)
        ensure_x86_fixtures
        ;;
    all)
        ensure_fixtures
        ensure_x86_fixtures
        ;;
    *) ensure_fixtures ;;
esac

total_fail=0
if [ "$MODE" = "all" ]; then
    for m in elfuse-aarch64 qemu-aarch64 elfuse-x86_64; do
        run_suite "$m" || total_fail=$((total_fail + $?))
    done
    exit "$total_fail"
else
    run_suite "$MODE"
fi
