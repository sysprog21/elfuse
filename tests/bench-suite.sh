#!/usr/bin/env bash
# bench-suite.sh -- two-tier performance benchmark suite (issue #195).
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Tier 1 (microbenchmarks): lmbench (issue #195), the three benchmarks
#   covering elfuse's critical execution paths:
#     lat_syscall   null/read/write/stat/open -- syscall entry and
#                   forwarding cost
#     lat_proc      fork and fork+execve -- process creation and the
#                   whole ELF load / process init path
#     lat_fs        file create/delete -- filesystem metadata cost
#   Binaries are cross-compiled from a sha256-pinned source snapshot
#   by tests/fetch-fixtures.sh (Alpine ships no lmbench package) into
#   externals/test-fixtures/aarch64-musl/lmbench/; static, so the same
#   artifacts run in every environment. lat_fs is invoked with lmbench's
#   native `-s 1024` option, selecting one 1 KiB case rather than its
#   four-size default sweep. Each metric is lmbench's own self-timed
#   result (microseconds). Each invocation uses one lmbench repetition;
#   the suite's outer samples provide the representative median.
#   lmbench's benchmp harness forks coordination children per run, so
#   a benchmark that fails or hangs (timeout) is retried once and then
#   recorded as a status ERR row rather than aborting the run.
#   lat_proc's exec target is the compiled-in path /tmp/hello-s,
#   staged into the environment's /tmp for the duration of Tier 1.
#
# Tier 2 (application benchmarks): representative developer workloads
#   over the fixed corpus in tests/bench-corpus/:
#     python3 -c pass   interpreter startup      (python_startup_ms)
#     git status        fs metadata walk         (git_status_ms)
#     rg                source search            (ripgrep_ms)
#     zstd              compression CPU + I/O    (zstd_ms)
#     make              process creation + fs    (make_ms)
#   Guest binaries come from the Alpine fixture rootfs
#   (tests/fetch-fixtures.sh). Under elfuse the rootfs is copied into a
#   throwaway case-sensitive APFS sparseimage: on the case-insensitive
#   default volume the sidecar's hashed-name overlay makes write-heavy
#   workloads unrepresentative, and guest execve() of absolute-target
#   symlinks (/bin/sh -> /bin/busybox) fails, so prep also rewrites the
#   copy's absolute symlinks to relative ones. The workload itself is
#   identical across environments. rg searches 512 replicated source-tree
#   shards (~87 MiB, tens of thousands of files) and zstd compresses an ~87 MiB
#   deterministic input. Those sizes keep short command/scheduler jitter
#   from dominating either measurement.
#
# Every timed invocation is wrapped in `timeout $TEST_TIMEOUT` via
# tests/lib/test-runner.sh (default here: 120s). Tier 1 self-times inside
# lmbench (BENCH_LMBENCH_TIMEOUT bounds each invocation) and Tier 2 uses
# bench-timeit. Every metric in both tiers runs
# BENCH_WARMUP + BENCH_ITERATIONS times; warmups are discarded and the
# median plus raw timed samples are reported.
#
# Usage: tests/bench-suite.sh [-o results.json]
#
# Environment:
#   BENCH_ENV         elfuse-aarch64 (default) | qemu-aarch64 | native |
#                     orbstack
#                     elfuse-aarch64: guests run through $ELFUSE on macOS.
#                     qemu-aarch64: commands run inside the fixture
#                              Alpine VM via tests/qemu-runner.sh (HVF +
#                              -cpu host where available) -- the
#                              same-silicon Linux-kernel reference column.
#                              Caveats: the guest root is the initramfs
#                              (tmpfs), so lat_fs and the write-heavy
#                              application metrics measure tmpfs rather
#                              than a disk filesystem, and Tier-2 samples
#                              are timed inside the guest by
#                              bench-timeit (ssh session setup would
#                              otherwise fold ~100 ms into ms-scale
#                              metrics). Recorded in meta.note.
#                     native:  binaries run directly; meant for an
#                              aarch64 Linux host (Tier-2 tools from the
#                              host distro must be installed).
#                     orbstack: commands run through `orb run` in the
#                              default OrbStack machine (Tier-2 tools
#                              must be installed inside the machine).
#                              Workloads run in a machine-local /tmp
#                              work area so they exercise the machine's
#                              Linux filesystem, not the virtiofs macOS
#                              share, and are timed in-machine by
#                              bench-timeit. Recorded in meta.note.
#
# Tier-2 metrics are workload-only in every environment: each column
# times every sample inside its guest/machine via bench-timeit.
# The per-command entry toll each environment charges a macOS caller is
# reported separately as applications.startup_ms: elfuse = VM + sysroot
# setup + static ELF load (busybox true); orbstack = `orb run true`
# session; qemu = one ssh round-trip (the per-command cost of using the
# fixture VM interactively); native = a bare no-op spawn.
#   BENCH_ITERATIONS  timed samples per metric (default 10)
#   BENCH_WARMUP      discarded leading samples per metric (default 2)
#   BENCH_STRICT      1 = missing prerequisites are fatal and fixtures
#                     are fetched on demand (CI); 0 = skip a tier with a
#                     warning when its fixtures are absent (default)
#   BENCH_LMBENCH_REPS     lmbench -N repetitions per outer sample
#                          (default 1; outer samples provide the median)
#   BENCH_LMBENCH_RETRIES  extra attempts for a failed/hung Tier-1
#                          benchmark before its ERR row (default 1)
#   BENCH_LMBENCH_TIMEOUT  per-lmbench-invocation timeout in seconds
#                          (default 60: generous for a healthy run --
#                          lat_syscall completes in ~10s -- while
#                          bounding the dead time of a wedged
#                          benchmark's attempts)
#   BENCH_LMBENCH_ENOUGH   lmbench ENOUGH: microseconds per timing
#                          interval (default 100000; empty = lmbench
#                          auto-calibration, ~30-40s extra per
#                          invocation under elfuse)
#   LMBENCH_DIR       dir with the lmbench fixtures (default
#                     externals/test-fixtures/aarch64-musl/lmbench)
#   ELFUSE            elfuse binary (default build/elfuse)
#   BENCH_BIN_DIR     dir with bench-timeit (default build/)
#   TEST_TIMEOUT      per-invocation timeout in seconds (default 120)
#
# Result schema (consumed by scripts/bench-compare.py; the lmbench
# section mirrors the issue #195 result format, with median and raw
# samples so results and baseline columns flatten the same way):
#   {
#     "schema": 1,
#     "meta": { "env", "host", "date", "iterations", "warmup", ... },
#     "lmbench": {
#       "lat_syscall": {
#         "null": {"median": <us>, "samples": [..], "unit": "us"},
#         "read": ..., "write": ..., "stat": ..., "open": ...,
#         "<metric>": {"status": "ERR"}     # failed/hung here
#       },
#       "lat_proc": { "fork": ..., "exec": ... },
#       "lat_fs": { "create": ..., "delete": ... }
#     },
#     "applications": {
#       "python_startup_ms": {"median": <ms>, "unit": "ms",
#                              "samples": [..]}, ...
#     }
#   }
#
# Baseline refresh procedure (tests/bench-baseline.json):
#   1. Build a release elfuse on the reference host (the self-hosted CI
#      runner for the elfuse-aarch64 column) and run
#          make bench                            (elfuse-aarch64 column)
#          BENCH_ENV=qemu-aarch64 make bench      (qemu-aarch64 reference
#                                                   column -- same silicon,
#                                                   real Linux kernel via
#                                                   HVF; there is no
#                                                   separate -qemu target,
#                                                   BENCH_ENV picks the
#                                                   column like any other)
#      until back-to-back runs agree within a few percent. Capture in
#      the FOREGROUND with the host otherwise idle: macOS demotes
#      background process groups to efficiency cores mid-run, which
#      shows up as a 2x step in the process-spawn-heavy metrics. A
#      non-default BENCH_ENV writes build/bench-results-$BENCH_ENV.json
#      instead of build/bench-results.json so the two captures don't
#      clobber each other.
#   2. Capture the orbstack column where hardware allows:
#          BENCH_ENV=orbstack make bench
#      (a Mac with OrbStack, Tier-2 tools installed inside the machine).
#   3. Promote each captured file into the baseline:
#          scripts/bench-promote.py --results build/bench-results.json
#          scripts/bench-promote.py \
#              --results build/bench-results-qemu-aarch64.json
#          scripts/bench-promote.py \
#              --results build/bench-results-orbstack.json
#      This merges medians into "environments.<env>" and records
#      host/date metadata into "captured.<env>" (pass --prune when a
#      case was removed or renamed so the stale key doesn't linger).
#   4. Commit the refreshed baseline together with whatever change
#      shifted performance (never alone, and never with corpus edits --
#      tests/bench-corpus is part of the benchmark definition).

set -u
set -o pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

: "${TEST_TIMEOUT:=120}"
# shellcheck source=tests/lib/test-runner.sh
source "${REPO_ROOT}/tests/lib/test-runner.sh"

BENCH_ENV="${BENCH_ENV:-elfuse-aarch64}"
BENCH_ITERATIONS="${BENCH_ITERATIONS:-10}"
BENCH_WARMUP="${BENCH_WARMUP:-2}"
BENCH_STRICT="${BENCH_STRICT:-0}"
BENCH_LMBENCH_REPS="${BENCH_LMBENCH_REPS:-1}"
BENCH_LMBENCH_RETRIES="${BENCH_LMBENCH_RETRIES:-1}"
BENCH_LMBENCH_ENOUGH="${BENCH_LMBENCH_ENOUGH:-100000}"
BENCH_LMBENCH_TIMEOUT="${BENCH_LMBENCH_TIMEOUT:-60}"
# Fixed parts of the Tier-2 benchmark definition, deliberately not knobs:
# making them configurable would make captured baseline columns incomparable.
RG_SHARDS=512
ZSTD_DOUBLINGS=9
ELFUSE="${ELFUSE:-${REPO_ROOT}/build/elfuse}"
BENCH_BIN_DIR="${BENCH_BIN_DIR:-${REPO_ROOT}/build}"
FIXTURES="${FIXTURES:-${REPO_ROOT}/externals/test-fixtures}"
ROOTFS="${ROOTFS:-${FIXTURES}/rootfs}"
LMBENCH_DIR="${LMBENCH_DIR:-${FIXTURES}/aarch64-musl/lmbench}"
STATICBIN_BIN="${STATICBIN_BIN:-${FIXTURES}/aarch64-musl/staticbin/bin}"
CORPUS="${REPO_ROOT}/tests/bench-corpus"

OUT_JSON="${REPO_ROOT}/build/bench-results.json"
while getopts "o:" opt; do
    case "$opt" in
        o) OUT_JSON="$OPTARG" ;;
        *)
            echo "usage: $0 [-o results.json]" >&2
            exit 2
            ;;
    esac
done

case "$BENCH_ENV" in
    elfuse-aarch64 | qemu-aarch64 | native | orbstack) ;;
    *)
        echo "bench-suite: unknown BENCH_ENV '$BENCH_ENV'" >&2
        exit 2
        ;;
esac

# Scratch state. SAMPLES accumulates "<section> <bench> <metric> <value>"
# rows for the wall-clock Tier-2 metrics; LMROWS accumulates
# "<benchmark> <metric> <value_us|ERR>" rows from the self-timed
# lmbench Tier-1 runs. The JSON emitter aggregates both at the end.
SCRATCH="$(mktemp -d)"
SAMPLES="${SCRATCH}/samples.txt"
LMROWS="${SCRATCH}/lmbench.txt"
: > "$SAMPLES"
: > "$LMROWS"

# Tier-2 guest state for the elfuse environment: a throwaway
# case-sensitive sparseimage holding a copy of the fixture rootfs.
IMG=""
MNT=""
SYS=""
# Host-side work dir for the native environment.
WORK=""
# Machine-local work dir for the orbstack environment (the workloads run
# on the machine's own filesystem, not the virtiofs macOS share).
ORB_WORK=""
APPS_SKIPPED=""

_QEMU_ACTIVE=0

cleanup()
{
    if [ "$_QEMU_ACTIVE" = 1 ]; then
        qemu_stop 2> /dev/null || true
    fi
    if [ -n "$ORB_WORK" ]; then
        timeout "$TEST_TIMEOUT" orb run rm -rf "$ORB_WORK" \
            > /dev/null 2>&1 || true
    fi
    if [ -n "$MNT" ]; then
        hdiutil detach "$MNT" -quiet > /dev/null 2>&1 \
            || hdiutil detach "$MNT" -force -quiet > /dev/null 2>&1 || true
    fi
    [ -n "$IMG" ] && rm -f "$IMG"
    [ -n "$WORK" ] && rm -rf "$WORK"
    rm -rf "$SCRATCH"
}
trap cleanup EXIT

# Boot the fixture Alpine VM for the qemu-aarch64 environment. Sourcing
# qemu-runner.sh replaces the EXIT trap with its own qemu_stop, so the
# combined cleanup is re-armed right after.
#
# Boot calibration: macOS occasionally schedules a fresh VM's vCPU
# threads on efficiency cores, which inflates every microsecond-scale
# metric by a uniform ~1.5x for the VM's whole lifetime. Probe the
# null-syscall latency after boot and reboot rather than publish a run
# that would gate against a performance-core baseline; after
# BENCH_QEMU_BOOT_RETRIES failed attempts, proceed with the warning
# recorded in meta.note. Tune BENCH_QEMU_NULL_CEILING (ns/op) when a
# reference host's performance-core latency differs from Apple
# M-series (~150 ns).
QEMU_BOOT_WARN=""
qemu_env_start()
{
    # shellcheck source=tests/qemu-runner.sh
    . "${REPO_ROOT}/tests/qemu-runner.sh"
    trap cleanup EXIT
    bench_note "booting qemu reference VM (accel auto-selected)"
    local tries=0 max="${BENCH_QEMU_BOOT_RETRIES:-2}"
    local ceiling="${BENCH_QEMU_NULL_CEILING:-180}" probe
    while :; do
        qemu_start || bench_die "qemu VM failed to boot"
        _QEMU_ACTIVE=1
        if [ ! -x "${LMBENCH_DIR}/lat_syscall" ]; then
            bench_note "qemu VM ready (accel=$QEMU_ACCEL cpu=$QEMU_CPU, uncalibrated)"
            return 0
        fi
        probe=$(qemu_exec timeout "$BENCH_LMBENCH_TIMEOUT" env \
            "ENOUGH=${BENCH_LMBENCH_ENOUGH:-100000}" \
            "${LMBENCH_DIR}/lat_syscall" -N 1 null 2>&1 \
            | awk -F': ' '$1 == "Simple syscall" \
                { split($2, a, " "); printf "%.0f", a[1] * 1000; exit }')
        if awk -v p="${probe:-999999}" -v c="$ceiling" \
            'BEGIN { exit !(p <= c) }'; then
            bench_note "qemu VM ready (accel=$QEMU_ACCEL cpu=$QEMU_CPU null=${probe}ns)"
            return 0
        fi
        tries=$((tries + 1))
        if [ "$tries" -gt "$max" ]; then
            QEMU_BOOT_WARN="vm slow after $max reboots: null-syscall=${probe}ns > ${ceiling}ns ceiling (efficiency-core placement?)"
            bench_note "WARNING: $QEMU_BOOT_WARN"
            return 0
        fi
        bench_note "boot calibration: null=${probe}ns > ${ceiling}ns; rebooting VM ($tries/$max)"
        qemu_stop
        _QEMU_ACTIVE=0
    done
}

bench_die()
{
    echo "bench-suite: $*" >&2
    exit 1
}

bench_note()
{
    printf "%s %s\n" "${BLUE}bench:${RESET}" "$*"
}

# ---------------------------------------------------------------------------
# Tier 1: microbenchmarks
# ---------------------------------------------------------------------------

# Full argv (including its timeout guard) for one Tier-1 run in the
# elfuse/native/orbstack environments. Tier-1 binaries are static
# aarch64-linux executables, so they run directly on native Linux and
# inside the OrbStack machine; the qemu environment is handled by
# lmbench_exec's remote shell line instead (see below).
#
# BENCH_LMBENCH_ENOUGH pins lmbench's per-timing-interval length
# (microseconds) via its standard ENOUGH knob, injected with env(1) in
# front of the benchmark so it reaches the guest in every transport.
# Without it lmbench auto-calibrates the interval, which costs ~30-40s
# of fixed calibration per invocation under elfuse; 100ms intervals
# keep a whole Tier-1 pass below ten minutes on the self-hosted M4 runner
# while still running syscall metrics hundreds of thousands of iterations
# per interval. Set
# BENCH_LMBENCH_ENOUGH= (empty) to restore lmbench's own calibration.
#
# elfuse-aarch64 runs the lmbench binary through a busybox sh wrapper
# rather than as elfuse's direct argv (which makes it guest PID 1).
# lmbench's benchmp() forks a child for every measurement and that
# child's benchmp_interval() treats getppid() == 1 as "my parent died,
# I've been reparented to init -- give up" (a standard, normally-safe
# idiom). When the benchmarked binary itself is PID 1, its own fork
# children have real, live ppid == 1, so the very first fork trips
# this false-positive: the child exits immediately without ever
# signaling readiness on lmbench's control pipe, and lmbench's parent
# side has no timeout on that read -- it spins forever re-polling the
# now-closed pipe. Never observed on native/orbstack (both already run
# under a normal init) or qemu (lmbench_exec's remote shell line
# already puts an sshd session between init and the benchmark). See
# issue #195 lmbench-fork-wedge notes.
tier1_cmd()
{
    local envp=()
    if [ -n "$BENCH_LMBENCH_ENOUGH" ]; then
        envp=(env "ENOUGH=${BENCH_LMBENCH_ENOUGH}")
    fi
    case "$BENCH_ENV" in
        elfuse-aarch64)
            printf '%s\n' timeout "$TEST_TIMEOUT" \
                ${envp[@]+"${envp[@]}"} "$ELFUSE" \
                "${STATICBIN_BIN}/busybox" sh -c '"$0" "$@"; exit $?' "$@"
            ;;
        native)
            printf '%s\n' timeout "$TEST_TIMEOUT" \
                ${envp[@]+"${envp[@]}"} "$@"
            ;;
        orbstack)
            printf '%s\n' timeout "$TEST_TIMEOUT" orb run \
                ${envp[@]+"${envp[@]}"} "$@"
            ;;
    esac
}

# Kill benchmark processes that outlive a failed or timed-out attempt.
# timeout(1) signals only its direct child; lmbench's benchmp children
# survive it, and a wedged one spins at full CPU (distorting every
# later measurement) or holds an inherited pipe open. elfuse guest
# processes carry a "<name> (aarch64-linux)" proctitle; native and
# orbstack stragglers keep the fixture path in their argv (the [/]
# regex trick stops pkill -f matching its own command line). The qemu
# environment reaps inside the remote shell line in lmbench_exec.
lmbench_reap_stragglers()
{
    local b
    case "$BENCH_ENV" in
        elfuse-aarch64)
            for b in lat_syscall lat_proc lat_fs hello-s; do
                pkill -9 -f "$b \\(aarch64-linux\\)" 2> /dev/null
            done
            ;;
        native)
            pkill -9 -f 'aarch64-musl/lmbench[/]' 2> /dev/null
            ;;
        orbstack)
            timeout "$TEST_TIMEOUT" orb run pkill -9 -f \
                'aarch64-musl/lmbench[/]' \
                > /dev/null 2>&1
            ;;
    esac
    return 0
}

# Run one lmbench binary through the environment transport and echo its
# combined output (lmbench prints results to stderr). Every attempt is
# bounded by BENCH_LMBENCH_TIMEOUT (dynamic-scope TEST_TIMEOUT override
# for tier1_cmd), and a failed attempt reaps straggler benchmark
# processes before the caller retries.
#
# qemu does not go through tier1_cmd: the benchmark runs inside one
# remote shell line that (a) sends its output to a guest file rather
# than the ssh channel -- benchmp children orphaned by the guest
# timeout inherit the channel and would otherwise hold the ssh session
# open indefinitely -- and (b) pkills stragglers on failure, guest-side.
# Repo paths are rewritten to /mnt/host by hand because they sit inside
# the sh -c string where qemu_exec's per-argument rewrite cannot reach.
lmbench_exec()
{
    if [ "$BENCH_ENV" = "qemu-aarch64" ]; then
        local script="" a q
        local remote_timeout=$((BENCH_LMBENCH_TIMEOUT + 10))
        for a in "$@"; do
            case "$a" in
                "${REPO_ROOT}"/*) a="/mnt/host${a#"${REPO_ROOT}"}" ;;
            esac
            printf -v q '%q' "$a"
            script="$script $q"
        done
        script="timeout ${BENCH_LMBENCH_TIMEOUT}${script}"
        if [ -n "$BENCH_LMBENCH_ENOUGH" ]; then
            script="ENOUGH=${BENCH_LMBENCH_ENOUGH} ${script}"
        fi
        # The outer guard includes cleanup margin so the inner timeout can
        # fire first and the shell can reap any benchmp stragglers.
        qemu_exec timeout "$remote_timeout" sh -c \
            "${script} > /tmp/.lmbench.out 2>&1; rc=\$?; [ \$rc -ne 0 ] && pkill -9 -f 'aarch64-musl/lmbench[/]' 2> /dev/null; cat /tmp/.lmbench.out; rm -f /tmp/.lmbench.out; exit \$rc"
        return $?
    fi

    local TEST_TIMEOUT="$BENCH_LMBENCH_TIMEOUT"
    local cmd=() line rc=0
    while IFS= read -r line; do
        cmd+=("$line")
    done < <(tier1_cmd "$@")
    "${cmd[@]}" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        lmbench_reap_stragglers
    fi
    return $rc
}

# lmbench_metric <benchmark> <metric> <label> <binary> [args...]
# Runs an independent lmbench invocation for every warmup and timed
# sample. -N controls lmbench's inner timing harness; these outer samples
# make the reported median robust to host noise. A failed/hung invocation
# is retried, then records ERR for the metric rather than allowing a
# partial sample set to look like a valid measurement.
lmbench_metric()
{
    local benchmark="$1" metric="$2" label="$3" binary="$4"
    shift 4
    local sample=0 total=$((BENCH_WARMUP + BENCH_ITERATIONS))
    local attempt out value rc=0
    for ((sample = 0; sample < total; sample++)); do
        value=""
        for ((attempt = 0; attempt <= BENCH_LMBENCH_RETRIES; attempt++)); do
            rc=0
            out="$(lmbench_exec "${LMBENCH_DIR}/${binary}" \
                -N "$BENCH_LMBENCH_REPS" "$@")" || rc=$?
            value="$(printf '%s\n' "$out" | awk -F': ' -v l="$label" \
                '$1 == l && $2 ~ /microseconds/ { split($2, a, " "); print a[1]; exit }')"
            if [ -n "$value" ]; then
                printf '%s %s %s\n' "$benchmark" "$metric" "$value" >> "$LMROWS"
                break
            fi
            bench_note "retrying $benchmark.$metric sample $((sample + 1))/$total (rc=$rc)"
        done
        if [ -z "$value" ]; then
            printf '%s %s ERR\n' "$benchmark" "$metric" >> "$LMROWS"
            {
                echo "bench-suite: WARNING: $benchmark.$metric sample $((sample + 1))/$total failed in this environment (rc=$rc); recorded as ERR"
                printf '%s\n' "$out" | tail -3 | sed 's/^/    /'
            } >&2
            return 0
        fi
    done
    return 0
}

# lat_fs prints one row per file size (0k/1k/4k/10k):
#   <size>k  <files>  <creations/sec>  <removals/sec>
# with -1 columns for a failed phase. `-s 1024` is an unmodified lmbench
# option that selects its 1k row only, avoiding the default four-size sweep.
# Convert ops/sec to microseconds per op to match the other Tier-1 metrics.
lmbench_lat_fs()
{
    local dir="$1"
    local sample=0 total=$((BENCH_WARMUP + BENCH_ITERATIONS))
    local attempt out row rc=0
    for ((sample = 0; sample < total; sample++)); do
        row=""
        for ((attempt = 0; attempt <= BENCH_LMBENCH_RETRIES; attempt++)); do
            rc=0
            out="$(lmbench_exec "${LMBENCH_DIR}/lat_fs" \
                -N "$BENCH_LMBENCH_REPS" -s 1024 "$dir")" || rc=$?
            row="$(printf '%s\n' "$out" | awk '$1 == "1k" && NF == 4 \
                && $3 > 0 && $4 > 0 \
                { printf "%.3f %.3f", 1e6 / $3, 1e6 / $4; exit }')"
            if [ -n "$row" ]; then
                printf 'lat_fs create %s\n' "${row%% *}" >> "$LMROWS"
                printf 'lat_fs delete %s\n' "${row##* }" >> "$LMROWS"
                break
            fi
            bench_note "retrying lat_fs sample $((sample + 1))/$total (rc=$rc)"
        done
        if [ -z "$row" ]; then
            printf 'lat_fs create ERR\nlat_fs delete ERR\n' >> "$LMROWS"
            echo "bench-suite: WARNING: lat_fs sample $((sample + 1))/$total failed in this environment (rc=$rc); recorded as ERR" >&2
            return 0
        fi
    done
    return 0
}

# Stage the Tier-1 guest paths, run the three issue #195 lmbench
# benchmarks, and collect their rows into LMROWS. Guest paths per
# environment: a probe file for stat/open, a scratch directory for
# lat_fs, and /tmp/hello-s for lat_proc exec (the target path is
# compiled into the binary, so concurrent suites on one host would
# alias it -- acceptable for a benchmark run).
run_tier1_suite()
{
    local missing="" b
    for b in lat_syscall lat_proc lat_fs hello-s; do
        [ -x "${LMBENCH_DIR}/${b}" ] || missing="$missing $b"
    done
    if [ -n "$missing" ]; then
        if [ "$BENCH_STRICT" = "1" ]; then
            bench_note "fetching fixtures (lmbench missing:$missing)"
            bash "${REPO_ROOT}/tests/fetch-fixtures.sh" \
                || bench_die "fixture fetch failed"
            for b in lat_syscall lat_proc lat_fs hello-s; do
                [ -x "${LMBENCH_DIR}/${b}" ] \
                    || bench_die "lmbench fixture $b still missing after fetch (no aarch64-linux cross compiler?)"
            done
        else
            bench_note "SKIP lmbench (missing:${missing}; run tests/fetch-fixtures.sh)"
            return 0
        fi
    fi

    local fs_host="" probe="" fsdir=""
    case "$BENCH_ENV" in
        elfuse-aarch64 | native)
            fs_host="$(mktemp -d "${TMPDIR:-/tmp}/elfuse-bench-fs.XXXXXX")"
            probe="${fs_host}/probe"
            fsdir="${fs_host}/fs"
            echo probe > "$probe"
            mkdir -p "$fsdir"
            cp "${LMBENCH_DIR}/hello-s" /tmp/hello-s
            ;;
        qemu-aarch64)
            # /tmp is the initramfs tmpfs (recorded in meta.note). The
            # hello-s copy rides the per-arg repo-path rewrite of
            # qemu_exec; the shell staging line uses guest paths only.
            probe="/tmp/bench-probe"
            fsdir="/tmp/bench-fs"
            {
                qemu_exec timeout "$TEST_TIMEOUT" sh -c \
                    'echo probe > /tmp/bench-probe && mkdir -p /tmp/bench-fs' \
                    && qemu_exec timeout "$TEST_TIMEOUT" cp \
                        "${LMBENCH_DIR}/hello-s" /tmp/hello-s
            } > /dev/null 2>&1 || bench_die "qemu Tier-1 staging failed"
            ;;
        orbstack)
            # Machine-local /tmp; the lmbench fixtures are reached over
            # the macOS share at their host-absolute paths.
            fs_host="/tmp/elfuse-bench-fs.$$"
            probe="${fs_host}/probe"
            fsdir="${fs_host}/fs"
            timeout "$TEST_TIMEOUT" orb run sh -c "mkdir -p ${fs_host}/fs \
                && echo probe > ${fs_host}/probe \
                && cp ${LMBENCH_DIR}/hello-s /tmp/hello-s" \
                > /dev/null 2>&1 || bench_die "orbstack Tier-1 staging failed"
            ;;
    esac

    bench_note "lmbench: ${BENCH_WARMUP} warmup + ${BENCH_ITERATIONS} timed samples/metric (-N ${BENCH_LMBENCH_REPS}/sample)"
    lmbench_metric lat_syscall null "Simple syscall" lat_syscall null
    lmbench_metric lat_syscall read "Simple read" lat_syscall read /dev/zero
    lmbench_metric lat_syscall write "Simple write" lat_syscall write /dev/null
    lmbench_metric lat_syscall stat "Simple stat" lat_syscall stat "$probe"
    lmbench_metric lat_syscall open "Simple open/close" lat_syscall open "$probe"
    lmbench_metric lat_proc fork "Static Process fork+exit" lat_proc fork
    lmbench_metric lat_proc exec "Static Process fork+execve" lat_proc exec
    lmbench_lat_fs "$fsdir"

    local ok_rows err_rows
    ok_rows=$(awk '$3 != "ERR"' "$LMROWS" | wc -l | tr -d ' ')
    err_rows=$(awk '$3 == "ERR" { print $1 "." $2 }' "$LMROWS")
    [ "$ok_rows" -gt 0 ] || bench_die "lmbench produced no results"
    if [ -n "$err_rows" ]; then
        {
            echo "bench-suite: WARNING: Tier-1 metrics errored in this environment:"
            printf '%s\n' "$err_rows" | sed 's/^/    /'
        } >&2
    fi
    bench_note "lmbench: $ok_rows samples OK"

    case "$BENCH_ENV" in
        elfuse-aarch64 | native)
            rm -rf "$fs_host" /tmp/hello-s
            ;;
        qemu-aarch64)
            qemu_exec timeout "$TEST_TIMEOUT" sh -c \
                'rm -rf /tmp/bench-probe /tmp/bench-fs /tmp/hello-s' \
                > /dev/null 2>&1 || true
            ;;
        orbstack)
            timeout "$TEST_TIMEOUT" orb run sh -c \
                "rm -rf ${fs_host} /tmp/hello-s" \
                > /dev/null 2>&1 || true
            ;;
    esac
    return 0
}

# ---------------------------------------------------------------------------
# Tier 2: application benchmarks
# ---------------------------------------------------------------------------

# Rewrite absolute-target symlinks in the rootfs copy to relative ones.
# Two reasons: guest execve() of an absolute-target symlink inside a
# sysroot ("/bin/sh -> /bin/busybox") does not resolve, and relative
# links keep resolving if the mount point ever moves.
relativize_symlinks()
{
    python3 - "$1" << 'PYEOF'
import os
import sys

root = sys.argv[1]
for dirpath, dirnames, filenames in os.walk(root):
    for name in dirnames + filenames:
        path = os.path.join(dirpath, name)
        if not os.path.islink(path):
            continue
        target = os.readlink(path)
        if not target.startswith("/"):
            continue
        rel = os.path.relpath(root + target, dirpath)
        os.remove(path)
        os.symlink(rel, path)
PYEOF
}

# Populate a corpus work area at host path $1: a source tree, 512 copied
# source-tree shards for ripgrep (~87 MiB / tens of thousands of files), and a zstd
# input grown deterministically to ~87 MiB. The larger fixed workloads keep
# short-run scheduling and command noise from dominating their medians.
prepare_corpus()
{
    local hostwork="$1"
    cp -R "$CORPUS" "${hostwork}/corpus" \
        || bench_die "failed to copy benchmark corpus"
    mkdir -p "${hostwork}/rg-corpus" \
        || bench_die "failed to create ripgrep corpus directory"
    local shard
    for ((shard = 0; shard < RG_SHARDS; shard++)); do
        cp -R "${hostwork}/corpus" "${hostwork}/rg-corpus/${shard}" \
            || bench_die "failed to copy ripgrep corpus shard $shard"
    done
    cat "${hostwork}/corpus"/*/*.c > "${hostwork}/zin" \
        || bench_die "failed to create zstd input"
    local i
    for ((i = 0; i < ZSTD_DOUBLINGS; i++)); do
        cat "${hostwork}/zin" "${hostwork}/zin" \
            > "${hostwork}/zin.2" \
            || bench_die "failed to grow zstd input at iteration $i"
        mv "${hostwork}/zin.2" "${hostwork}/zin" \
            || bench_die "failed to install zstd input at iteration $i"
    done
}

# tier2_cmd <tool> [args...]: full argv for one Tier-2 invocation in the
# selected environment. The guest environment is pinned (PATH, HOME,
# LC_ALL, GIT_CONFIG_NOSYSTEM) so host dotfiles and host PATH entries
# cannot leak into the measured workload -- under elfuse an unpinned
# PATH resolves /usr/bin/sed to the macOS binary via host fallback, and
# git/rg otherwise read ~/.config on the host.
GUEST_WORK=""
tier2_cmd()
{
    local tool="$1"
    shift
    case "$BENCH_ENV" in
        elfuse-aarch64)
            printf '%s\n' "/usr/bin/${tool}" "$@"
            ;;
        qemu-aarch64)
            printf '%s\n' env "PATH=/bin:/usr/bin" "HOME=${GUEST_WORK}" \
                LC_ALL=C GIT_CONFIG_NOSYSTEM=1 "/usr/bin/${tool}" "$@"
            ;;
        native)
            printf '%s\n' env "HOME=${GUEST_WORK}" LC_ALL=C \
                GIT_CONFIG_NOSYSTEM=1 "$tool" "$@"
            ;;
        orbstack)
            printf '%s\n' env "HOME=${GUEST_WORK}" LC_ALL=C \
                GIT_CONFIG_NOSYSTEM=1 "$tool" "$@"
            ;;
    esac
}

# Run one untimed Tier-2 command through the environment's transport.
tier2_run()
{
    case "$BENCH_ENV" in
        elfuse-aarch64)
            timeout "$TEST_TIMEOUT" env PATH=/bin:/usr/bin \
                "HOME=${GUEST_WORK}" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
                "$ELFUSE" --sysroot "$SYS" "$@"
            ;;
        qemu-aarch64) qemu_exec timeout "$TEST_TIMEOUT" "$@" ;;
        orbstack) timeout "$TEST_TIMEOUT" orb run "$@" ;;
        *) timeout "$TEST_TIMEOUT" "$@" ;;
    esac
}

# Timed sample: bench-timeit runs inside every guest/machine, so the
# printed integer covers spawn + run + exit of the workload only. The
# host-side entry toll remains separately visible as startup_ms.
timeit_sample_us()
{
    local label="$1"
    shift
    local out rc=0
    case "$BENCH_ENV" in
        elfuse-aarch64)
            out=$(timeout "$TEST_TIMEOUT" env PATH=/bin:/usr/bin \
                "HOME=${GUEST_WORK}" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
                "$ELFUSE" --sysroot "$SYS" /bench-timeit "$@" \
                2> /dev/null) || rc=$?
            ;;
        qemu-aarch64)
            out=$(qemu_exec timeout "$TEST_TIMEOUT" \
                "${BENCH_BIN_DIR}/bench-timeit" "$@" 2> /dev/null) || rc=$?
            ;;
        orbstack)
            out=$(timeout "$TEST_TIMEOUT" orb run \
                "${BENCH_BIN_DIR}/bench-timeit" "$@" 2> /dev/null) || rc=$?
            ;;
        native)
            out=$(timeout "$TEST_TIMEOUT" \
                "${BENCH_BIN_DIR}/bench-timeit" "$@" 2> /dev/null) || rc=$?
            ;;
    esac
    case "$out" in
        '' | *[!0-9]*) rc=1 ;;
    esac
    if [ "$rc" -ne 0 ]; then
        echo "bench-suite: sample '$label' failed (rc=$rc, out='$out'):" >&2
        echo "  $*" >&2
        exit 1
    fi
    echo "$out"
}

run_tier2_tool()
{
    local metric="$1"
    shift
    local pre_each="${1:-}"
    shift
    local cmd=()
    while IFS= read -r line; do
        cmd+=("$line")
    done < <(tier2_cmd "$@")

    local total=$((BENCH_WARMUP + BENCH_ITERATIONS))
    local i us
    for ((i = 0; i < total; i++)); do
        if [ -n "$pre_each" ]; then
            "$pre_each" \
                || bench_die "pre-sample setup for $metric failed"
        fi
        us=$(timeit_sample_us "$metric" "${cmd[@]}") || exit 1
        printf 'applications %s %s %s\n' "$metric" "$metric" "$us" \
            >> "$SAMPLES"
    done
    bench_note "$metric: $total runs"
}

# startup_ms: end-to-end wall-clock of a no-op command from the caller's
# side -- the per-command entry toll of each environment. For elfuse it
# includes VM + sysroot setup + static ELF load (via busybox true). It is
# reported separately from the guest-side bench-timeit workload metrics.
run_startup_metric()
{
    local total=$((BENCH_WARMUP + BENCH_ITERATIONS))
    local i start end rc
    for ((i = 0; i < total; i++)); do
        rc=0
        start=$(epoch_us)
        case "$BENCH_ENV" in
            elfuse-aarch64)
                timeout "$TEST_TIMEOUT" "$ELFUSE" --sysroot "$SYS" \
                    /bin/busybox true > /dev/null 2>&1 || rc=$?
                ;;
            qemu-aarch64)
                qemu_exec timeout "$TEST_TIMEOUT" true \
                    > /dev/null 2>&1 || rc=$?
                ;;
            native)
                timeout "$TEST_TIMEOUT" true > /dev/null 2>&1 || rc=$?
                ;;
            orbstack)
                timeout "$TEST_TIMEOUT" orb run true > /dev/null 2>&1 \
                    || rc=$?
                ;;
        esac
        end=$(epoch_us)
        if [ "$rc" -ne 0 ]; then
            echo "bench-suite: startup_ms sample failed (rc=$rc)" >&2
            exit 1
        fi
        printf 'applications startup_ms startup_ms %s\n' $((end - start)) \
            >> "$SAMPLES"
    done
    bench_note "startup_ms: $total runs"
}

# Guest-side helper for the elfuse env (busybox from the sysroot copy);
# native/orbstack use the host/machine shell directly.
tier2_sh()
{
    case "$BENCH_ENV" in
        elfuse-aarch64)
            timeout "$TEST_TIMEOUT" "$ELFUSE" --sysroot "$SYS" \
                /bin/busybox sh -c "$1" \
                > /dev/null 2>&1
            ;;
        qemu-aarch64)
            qemu_exec timeout "$TEST_TIMEOUT" sh -c "$1" \
                > /dev/null 2>&1
            ;;
        native)
            timeout "$TEST_TIMEOUT" sh -c "$1" > /dev/null 2>&1
            ;;
        orbstack)
            timeout "$TEST_TIMEOUT" orb run sh -c "$1" \
                > /dev/null 2>&1
            ;;
    esac
}

make_clean_out()
{
    tier2_sh "rm -rf ${GUEST_WORK}/out"
}

run_tier2_suite()
{
    # Prerequisites per environment.
    case "$BENCH_ENV" in
        elfuse-aarch64)
            if [ ! -d "$ROOTFS" ] || [ ! -x "${ROOTFS}/bin/busybox" ] \
                || [ ! -e "${ROOTFS}/usr/bin/python3" ]; then
                if [ "$BENCH_STRICT" = "1" ]; then
                    bench_note "fetching fixtures (one-time download)"
                    bash "${REPO_ROOT}/tests/fetch-fixtures.sh" \
                        || bench_die "fixture fetch failed"
                else
                    APPS_SKIPPED="fixture rootfs missing (run tests/fetch-fixtures.sh)"
                    bench_note "SKIP applications ($APPS_SKIPPED)"
                    return 0
                fi
            fi
            if ! command -v hdiutil > /dev/null 2>&1; then
                [ "$BENCH_STRICT" = "1" ] \
                    && bench_die "hdiutil unavailable; cannot stage bench sysroot"
                APPS_SKIPPED="hdiutil unavailable"
                bench_note "SKIP applications ($APPS_SKIPPED)"
                return 0
            fi
            [ -x "${BENCH_BIN_DIR}/bench-timeit" ] \
                || bench_die "missing ${BENCH_BIN_DIR}/bench-timeit (build it before benchmarking)"

            bench_note "staging case-sensitive bench sysroot"
            IMG="$(mktemp -u "${TMPDIR:-/tmp}/elfuse-bench.XXXXXX").sparseimage"
            # Volume name carries the PID so two concurrent suites (or a
            # leftover mount from a crashed run) cannot alias each other;
            # the sed keeps mount points containing spaces intact where a
            # naive awk-last-field parse would truncate them.
            hdiutil create -size 2g -type SPARSE -fs 'Case-sensitive APFS' \
                -volname "elfusebench-$$" -quiet "$IMG" \
                || bench_die "hdiutil create failed"
            MNT=$(hdiutil attach "$IMG" -nobrowse \
                | sed -n 's|.*[[:space:]]\(/Volumes/.*\)$|\1|p' | tail -1)
            [ -n "$MNT" ] || bench_die "hdiutil attach failed"
            cp -R "${ROOTFS}/" "${MNT}/rootfs" \
                || bench_die "rootfs copy failed"
            SYS="${MNT}/rootfs"
            relativize_symlinks "$SYS" \
                || bench_die "failed to rewrite rootfs symlinks"
            cp "${BENCH_BIN_DIR}/bench-timeit" "${SYS}/bench-timeit" \
                || bench_die "failed to stage guest bench-timeit"

            GUEST_WORK="/bench-work"
            mkdir -p "${SYS}${GUEST_WORK}" \
                || bench_die "failed to create guest benchmark work area"
            prepare_corpus "${SYS}${GUEST_WORK}"
            ;;
        qemu-aarch64)
            # The VM is already up (booted before Tier 1). Verify the
            # initramfs actually carries the Tier-2 tools: a fixture
            # tree fetched before the bench packages were added boots
            # fine but lacks them.
            if [ ! -x "${BENCH_BIN_DIR}/bench-timeit" ]; then
                bench_die "missing ${BENCH_BIN_DIR}/bench-timeit (build via 'BENCH_ENV=qemu-aarch64 make bench')"
            fi
            if ! qemu_exec timeout "$TEST_TIMEOUT" sh -c \
                'command -v python3 git rg zstd make' \
                > /dev/null 2>&1; then
                bench_die "fixture initramfs lacks the bench tools; rerun tests/fetch-fixtures.sh"
            fi
            GUEST_WORK="/bench-work"
            local prep
            prep='rm -rf /bench-work && mkdir -p /bench-work'
            prep="$prep && cp -R /mnt/host/tests/bench-corpus /bench-work/corpus"
            prep="$prep && mkdir -p /bench-work/rg-corpus"
            prep="$prep && i=0 && while [ \$i -lt $RG_SHARDS ]; do cp -R /bench-work/corpus /bench-work/rg-corpus/\$i || exit 1; i=\$((i + 1)); done"
            prep="$prep && cat /bench-work/corpus/*/*.c > /bench-work/zin"
            prep="$prep && i=0 && while [ \$i -lt $ZSTD_DOUBLINGS ]; do cat /bench-work/zin /bench-work/zin > /bench-work/zin.2 && mv /bench-work/zin.2 /bench-work/zin || exit 1; i=\$((i + 1)); done"
            qemu_exec timeout "$TEST_TIMEOUT" sh -c "$prep" \
                > /dev/null 2>&1 \
                || bench_die "guest corpus prep failed"
            ;;
        orbstack)
            local tool missing=""
            for tool in python3 git rg zstd make; do
                if ! tier2_sh "command -v $tool"; then
                    missing="$missing $tool"
                fi
            done
            if [ -n "$missing" ]; then
                [ "$BENCH_STRICT" = "1" ] \
                    && bench_die "missing Tier-2 tools in the OrbStack machine:$missing"
                APPS_SKIPPED="missing tools in OrbStack machine:$missing"
                bench_note "SKIP applications ($APPS_SKIPPED)"
                return 0
            fi
            # Machine-local work area (mirrors the qemu column): the
            # corpus is copied off the shared macOS path once, untimed,
            # so the timed workloads exercise the machine's own Linux
            # filesystem instead of the virtiofs share.
            ORB_WORK="/tmp/elfuse-bench-work.$$"
            GUEST_WORK="$ORB_WORK"
            local prep
            prep="rm -rf $ORB_WORK && mkdir -p $ORB_WORK"
            prep="$prep && cp -R $CORPUS $ORB_WORK/corpus"
            prep="$prep && mkdir -p $ORB_WORK/rg-corpus"
            prep="$prep && i=0 && while [ \$i -lt $RG_SHARDS ]; do cp -R $ORB_WORK/corpus $ORB_WORK/rg-corpus/\$i || exit 1; i=\$((i + 1)); done"
            prep="$prep && cat $ORB_WORK/corpus/*/*.c > $ORB_WORK/zin"
            prep="$prep && i=0 && while [ \$i -lt $ZSTD_DOUBLINGS ]; do cat $ORB_WORK/zin $ORB_WORK/zin > $ORB_WORK/zin.2 && mv $ORB_WORK/zin.2 $ORB_WORK/zin || exit 1; i=\$((i + 1)); done"
            tier2_sh "$prep" || bench_die "orbstack corpus prep failed"
            ;;
        native)
            local tool missing=""
            for tool in python3 git rg zstd make; do
                if ! tier2_sh "command -v $tool"; then
                    missing="$missing $tool"
                fi
            done
            if [ -n "$missing" ]; then
                [ "$BENCH_STRICT" = "1" ] \
                    && bench_die "missing Tier-2 tools:$missing"
                APPS_SKIPPED="missing tools:$missing"
                bench_note "SKIP applications ($APPS_SKIPPED)"
                return 0
            fi
            WORK="$(mktemp -d "${TMPDIR:-/tmp}/elfuse-bench.XXXXXX")" \
                || bench_die "failed to create native benchmark work area"
            GUEST_WORK="$WORK"
            prepare_corpus "$WORK"
            ;;
    esac

    # Untimed: turn the corpus copy into a committed repository with the
    # environment's own git so on-disk formats match the measured binary.
    local gitc=()
    while IFS= read -r line; do
        gitc+=("$line")
    done < <(tier2_cmd git -c user.name=bench -c user.email=bench@localhost \
        -c 'safe.directory=*' -C "${GUEST_WORK}/corpus")
    tier2_run "${gitc[@]}" init -q > /dev/null 2>&1 \
        || bench_die "git init failed"
    tier2_run "${gitc[@]}" add -A > /dev/null 2>&1 \
        || bench_die "git add failed"
    tier2_run "${gitc[@]}" commit -q -m corpus-snapshot \
        > /dev/null 2>&1 || bench_die "git commit failed"

    run_startup_metric
    run_tier2_tool python_startup_ms "" python3 -c pass
    run_tier2_tool git_status_ms "" git -c 'safe.directory=*' \
        --no-optional-locks -C "${GUEST_WORK}/corpus" status --porcelain
    run_tier2_tool ripgrep_ms "" rg --no-config -c '.' \
        "${GUEST_WORK}/rg-corpus"
    run_tier2_tool zstd_ms "" zstd -q -f -T1 "${GUEST_WORK}/zin" \
        -o "${GUEST_WORK}/zin.zst"
    # make builds from a clean output dir every sample so each run does
    # the full 49-target graph instead of a no-op stat pass.
    run_tier2_tool make_ms make_clean_out make -C "${GUEST_WORK}/corpus" \
        "OUT=${GUEST_WORK}/out" all
}

# ---------------------------------------------------------------------------
# Emit JSON
# ---------------------------------------------------------------------------

emit_json()
{
    local host_os host_ver host_machine host_cpu now
    host_os="$(uname -s)"
    host_ver="$(uname -r)"
    host_machine="$(uname -m)"
    if command -v sysctl > /dev/null 2>&1; then
        host_cpu="$(sysctl -n machdep.cpu.brand_string 2> /dev/null || true)"
    fi
    [ -n "${host_cpu:-}" ] \
        || host_cpu="$(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo \
            2> /dev/null | sed 's/^ //' || true)"
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    local note=""
    if [ "$BENCH_ENV" = "qemu-aarch64" ]; then
        note="qemu guest root is tmpfs (initramfs): lat_fs and write-heavy application metrics measure tmpfs, not a disk filesystem; Tier-2 samples timed in-guest by bench-timeit (workload only); startup_ms is the per-command ssh entry cost"
        if [ -n "$QEMU_BOOT_WARN" ]; then
            note="$note; WARNING: $QEMU_BOOT_WARN"
        fi
    elif [ "$BENCH_ENV" = "orbstack" ]; then
        note="workloads run on the OrbStack machine's own filesystem (machine-local /tmp), timed in-machine by bench-timeit (workload only); startup_ms is the orb run session cost"
    elif [ "$BENCH_ENV" = "elfuse-aarch64" ]; then
        note="Tier-2 samples are timed in-guest by bench-timeit (workload only); startup_ms is the per-command VM + sysroot setup + static ELF-load cost"
    fi

    # lmbench provenance for meta: the pinned commit recorded by
    # fetch-fixtures.sh. The VERSION stamp is the audit trail.
    local lmbench_src=""
    lmbench_src="$(awk -F': ' '$1 == "commit" { print "intel/lmbench@" substr($2, 1, 7) }' \
        "${LMBENCH_DIR}/VERSION" 2> /dev/null || true)"

    mkdir -p "$(dirname "$OUT_JSON")"
    BENCH_META_NOTE="$note" \
        BENCH_LMBENCH_FILE="$LMROWS" \
        BENCH_META_LMBENCH_SRC="$lmbench_src" \
        BENCH_META_LMBENCH_REPS="$BENCH_LMBENCH_REPS" \
        BENCH_META_LMBENCH_ENOUGH="$BENCH_LMBENCH_ENOUGH" \
        BENCH_META_ENV="$BENCH_ENV" \
        BENCH_META_OS="$host_os" \
        BENCH_META_OSVER="$host_ver" \
        BENCH_META_MACHINE="$host_machine" \
        BENCH_META_CPU="${host_cpu:-unknown}" \
        BENCH_META_DATE="$now" \
        BENCH_META_ITER="$BENCH_ITERATIONS" \
        BENCH_META_WARMUP="$BENCH_WARMUP" \
        BENCH_META_SKIPPED="$APPS_SKIPPED" \
        python3 - "$SAMPLES" "$OUT_JSON" << 'PYEOF'
import json
import os
import statistics
import sys

samples_path, out_path = sys.argv[1], sys.argv[2]
warmup = int(os.environ["BENCH_META_WARMUP"])

# section -> bench -> metric -> [values in file order]
data = {}
with open(samples_path, encoding="utf-8") as fh:
    for line in fh:
        section, bench, metric, value = line.split()
        rows = data.setdefault(section, {}).setdefault(bench, {})
        rows.setdefault(metric, []).append(float(value))

def summarize(values, to_unit):
    timed = values[warmup:] if len(values) > warmup else values
    scaled = [round(v * to_unit, 3) for v in timed]
    return {
        "median": round(statistics.median(scaled), 3),
        "samples": scaled,
    }

result = {
    "schema": 1,
    "meta": {
        "env": os.environ["BENCH_META_ENV"],
        "host": {
            "os": os.environ["BENCH_META_OS"],
            "os_version": os.environ["BENCH_META_OSVER"],
            "machine": os.environ["BENCH_META_MACHINE"],
            "cpu": os.environ["BENCH_META_CPU"],
        },
        "date": os.environ["BENCH_META_DATE"],
        "iterations": int(os.environ["BENCH_META_ITER"]),
        "warmup": warmup,
        "tier1": "lmbench lat_syscall/lat_proc/lat_fs (us, "
                 f"{os.environ['BENCH_META_LMBENCH_SRC'] or 'source unknown'}"
                 f", -N {os.environ['BENCH_META_LMBENCH_REPS']}"
                 f", ENOUGH={os.environ['BENCH_META_LMBENCH_ENOUGH'] or 'auto'}"
                 f", {warmup} warmup + {os.environ['BENCH_META_ITER']} timed samples)",
    },
    "lmbench": {},
    "applications": {},
}
if os.environ["BENCH_META_SKIPPED"]:
    result["meta"]["applications_skipped"] = os.environ[
        "BENCH_META_SKIPPED"
    ]
if os.environ.get("BENCH_META_NOTE"):
    result["meta"]["note"] = os.environ["BENCH_META_NOTE"]

# Tier-1 rows are lmbench's own self-timed results, one per outer
# warmup/timed sample: "<benchmark> <metric> <value_us|ERR>". An ERR
# invalidates that metric rather than publishing a partial sample set.
tier1 = {}
with open(os.environ["BENCH_LMBENCH_FILE"], encoding="utf-8") as fh:
    for line in fh:
        benchmark, metric, value = line.split()
        node = tier1.setdefault(benchmark, {}).setdefault(
            metric, {"values": [], "error": False})
        if value == "ERR":
            node["error"] = True
        else:
            node["values"].append(float(value))
for benchmark, metrics in tier1.items():
    out = result["lmbench"].setdefault(benchmark, {})
    for metric, values in metrics.items():
        if values["error"] or len(values["values"]) <= warmup:
            out[metric] = {"status": "ERR"}
        else:
            timed = values["values"][warmup:]
            out[metric] = {
                "median": round(statistics.median(timed), 6),
                "samples": timed,
                "unit": "us",
            }

# Tier-2 rows are bench-timeit's workload-only microseconds; report ms.
apps = data.get("applications", {})
for bench, rows in sorted(apps.items()):
    vals = rows[bench]
    result["applications"][bench] = dict(
        summarize(vals, 1.0 / 1000.0), unit="ms"
    )

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(result, fh, indent=2, sort_keys=False)
    fh.write("\n")
print(f"bench-suite: wrote {out_path}")
PYEOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if [ "$BENCH_ENV" = "elfuse-aarch64" ] && [ ! -x "$ELFUSE" ]; then
    bench_die "elfuse binary missing at $ELFUSE (run 'make elfuse')"
fi
if [ "$BENCH_ENV" = "orbstack" ] && ! command -v orb > /dev/null 2>&1; then
    bench_die "orb CLI not found (install OrbStack)"
fi
if [ "$BENCH_ENV" = "qemu-aarch64" ] \
    && ! command -v qemu-system-aarch64 > /dev/null 2>&1; then
    bench_die "qemu-system-aarch64 not found (brew install qemu)"
fi

bench_note "env=$BENCH_ENV iterations=$BENCH_ITERATIONS warmup=$BENCH_WARMUP"

# Both tiers of the qemu environment run inside the fixture VM, so it
# boots up front (qemu_ensure_fixtures fetches on demand) and is torn
# down by cleanup().
if [ "$BENCH_ENV" = "qemu-aarch64" ]; then
    qemu_env_start
fi

run_tier1_suite
run_tier2_suite
emit_json
