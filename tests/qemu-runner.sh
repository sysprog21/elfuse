#!/usr/bin/env bash

# qemu-runner.sh -- Boot qemu-system-aarch64 with the elfuse test fixtures
# initramfs and provide qemu_exec() for command execution over ssh.
#
# Sourced by tests/test-matrix.sh (for the qemu-aarch64 mode) but also usable
# interactively:
#   . tests/qemu-runner.sh
#   qemu_start
#   qemu_exec uname -a
#   qemu_stop
#
# The booted VM mounts the host repo root at /mnt/host via virtio-9p, so any
# path under the repo is reachable from the VM as /mnt/host/<relative-path>.
#
# SPDX-License-Identifier: Apache-2.0

# Resolve repo paths relative to this script's location.
_QR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
_QR_FIX="${_QR_DIR}/externals/test-fixtures"

# shellcheck source=tests/lib/qemu-ssh.sh
source "${_QR_DIR}/tests/lib/qemu-ssh.sh"

QEMU_BIN="${QEMU_BIN:-qemu-system-aarch64}"
QEMU_PORT="${QEMU_PORT:-2222}"
QEMU_MEM="${QEMU_MEM:-2048}"
QEMU_SMP="${QEMU_SMP:-4}"

# Accelerator + CPU model are auto-selected at qemu_start time: HVF + cpu=host
# on Apple Silicon when the qemu build supports it, otherwise TCG + cortex-a72
# (slower but portable to non-aarch64 hosts and qemu builds without HVF). Either
# can be forced via QEMU_ACCEL=tcg / QEMU_CPU=cortex-a72.
QEMU_ACCEL="${QEMU_ACCEL:-}"
QEMU_CPU="${QEMU_CPU:-}"
QEMU_BOOT_TIMEOUT="${QEMU_BOOT_TIMEOUT:-90}"
QEMU_SSH_KEY="${QEMU_SSH_KEY:-${_QR_FIX}/keys/ssh_key}"
QEMU_KERNEL="${QEMU_KERNEL:-${_QR_FIX}/kernel/vmlinuz-virt}"
QEMU_INITRD="${QEMU_INITRD:-${_QR_FIX}/initramfs.cpio.gz}"
QEMU_SHARE_PATH="${QEMU_SHARE_PATH:-${_QR_DIR}}"

_QR_PIDFILE=""
_QR_LOG=""
_QR_CTL=""

# Fixture path inside the VM (always /mnt/host/<relative>).
qemu_guestpath()
{
    local p="$1"
    case "$p" in
        "${_QR_DIR}"/*) echo "/mnt/host/${p#${_QR_DIR}/}" ;;
        /*) echo "$p" ;;
        *) echo "/mnt/host/$p" ;;
    esac
}

# Verify fixtures are present; fetch on demand if not.
qemu_ensure_fixtures()
{
    if [ ! -s "$QEMU_KERNEL" ] || [ ! -s "$QEMU_INITRD" ] || [ ! -s "$QEMU_SSH_KEY" ]; then
        echo "qemu-runner: fixtures missing, running tests/fetch-fixtures.sh"
        bash "${_QR_DIR}/tests/fetch-fixtures.sh" >&2
    fi
    for f in "$QEMU_KERNEL" "$QEMU_INITRD" "$QEMU_SSH_KEY"; do
        [ -s "$f" ] || {
            echo "qemu-runner: missing $f" >&2
            return 1
        }
    done
}

# Pick a free localhost TCP port for ssh forwarding (avoids collisions when
# several test-matrix runs overlap or QEMU_PORT is in use).
qemu_pick_port()
{
    if command -v python3 > /dev/null 2>&1; then
        python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
    else
        echo "$QEMU_PORT"
    fi
}

qemu_pick_accel()
{
    if [ -n "$QEMU_ACCEL" ]; then
        return
    fi
    if "$QEMU_BIN" -accel help 2> /dev/null | grep -qx hvf; then
        QEMU_ACCEL=hvf
    else
        QEMU_ACCEL=tcg
    fi
}

qemu_pick_cpu()
{
    [ -n "$QEMU_CPU" ] && return
    case "$QEMU_ACCEL" in
        hvf) QEMU_CPU=host ;;
        *) QEMU_CPU=cortex-a72 ;;
    esac
}

qemu_start()
{
    qemu_ensure_fixtures || return 1

    if [ -n "$_QR_PIDFILE" ] && [ -s "$_QR_PIDFILE" ]; then
        echo "qemu-runner: already started (pid=$(cat "$_QR_PIDFILE"))" >&2
        return 0
    fi

    command -v "$QEMU_BIN" > /dev/null 2>&1 || {
        echo "qemu-runner: $QEMU_BIN not found in PATH" >&2
        return 1
    }

    qemu_pick_accel
    qemu_pick_cpu

    local rundir
    rundir="$(mktemp -d -t elfuse-qemu.XXXXXX)"
    _QR_PIDFILE="${rundir}/qemu.pid"
    _QR_LOG="${rundir}/qemu-serial.log"
    _QR_CTL="${rundir}/ssh-ctl"

    QEMU_PORT="$(qemu_pick_port)"

    "$QEMU_BIN" \
        -machine virt -accel "$QEMU_ACCEL" -cpu "$QEMU_CPU" \
        -m "$QEMU_MEM" -smp "$QEMU_SMP" \
        -kernel "$QEMU_KERNEL" -initrd "$QEMU_INITRD" \
        -append "console=ttyAMA0 panic=5 quiet" \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${QEMU_PORT}-:22" \
        -device virtio-net-pci,netdev=net0 \
        -fsdev "local,id=share,path=${QEMU_SHARE_PATH},security_model=none,readonly=on" \
        -device virtio-9p-pci,fsdev=share,mount_tag=host \
        -nographic -display none -no-reboot -monitor none \
        -serial "file:${_QR_LOG}" \
        -pidfile "$_QR_PIDFILE" \
        > /dev/null 2>&1 &
    disown

    # Wait for ssh port to come up.

    for _ in $(seq 1 "$QEMU_BOOT_TIMEOUT"); do
        if (echo > /dev/tcp/127.0.0.1/"$QEMU_PORT") 2> /dev/null; then
            break
        fi
        sleep 1
    done
    if ! (echo > /dev/tcp/127.0.0.1/"$QEMU_PORT") 2> /dev/null; then
        echo "qemu-runner: VM did not boot within ${QEMU_BOOT_TIMEOUT}s" >&2
        qemu_stop
        return 1
    fi

    # Wait for dropbear to fully accept; first connection often races boot.
    for _ in $(seq 1 30); do
        if _qemu_ssh_raw -o ConnectTimeout=2 'echo ready' > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    # The Alpine initramfs keeps /tmp on "rootfs", which busybox df cannot
    # resolve to a /proc/mounts entry ("df: ...: can't find mount point"). Mount
    # a dedicated tmpfs, as any regular system has, so paths under /tmp map to a
    # resolvable st_dev. Guarded so a repeated qemu_start against a running VM
    # does not stack mounts.
    if ! _qemu_ssh_raw 'grep -q " /tmp tmpfs " /proc/mounts || mount -t tmpfs tmpfs /tmp'; then
        echo "qemu-runner: could not prepare /tmp in the guest" >&2
        qemu_stop
        return 1
    fi
}

# Each call opens a fresh ssh connection. Avoids ControlMaster pitfalls (master
# dying mid-suite cascades rc=255 to every later command) at the cost of ~100ms
# handshake overhead per call -- a flat ~15s across the full matrix, well within
# the suite's tolerance.
_qemu_ssh_raw()
{
    qemu_ssh_opts
    ssh "${QEMU_SSH_OPTS[@]}" root@127.0.0.1 "$@"
}

# Run a command in the VM. Any argument that is an absolute path under the host
# repo root is rewritten to its /mnt/host/... in-VM equivalent so the guest can
# dereference it through the virtio-9p share. Cwd is forced to /mnt/host so test
# arguments using paths like "tests/foo" work the same as they do when run on
# the macOS host.
qemu_exec()
{
    local args=() a
    for a in "$@"; do
        case "$a" in
            "${_QR_DIR}"/*) args+=("$(qemu_guestpath "$a")") ;;
            *) args+=("$a") ;;
        esac
    done
    local quoted
    printf -v quoted '%q ' "${args[@]}"
    _qemu_ssh_raw "cd /mnt/host && ${quoted}"
}

qemu_stop()
{
    if [ -n "$_QR_PIDFILE" ] && [ -s "$_QR_PIDFILE" ]; then
        local pid
        pid=$(cat "$_QR_PIDFILE" 2> /dev/null)

        # A state file outlives its VM, so the pid it names may since have been
        # recycled. qemu_start gives qemu this pidfile, and mktemp makes the
        # path unique, so the argv is what proves the process is ours.
        case " $(ps -o command= -p "${pid:-0}" 2> /dev/null) " in
            *" -pidfile $_QR_PIDFILE "*) ;;
            *) pid="" ;;
        esac
        if [ -n "$pid" ] && kill -0 "$pid" 2> /dev/null; then
            kill "$pid" 2> /dev/null
            # give qemu time to exit cleanly; force-kill if it lingers

            for _ in 1 2 3 4 5; do
                kill -0 "$pid" 2> /dev/null || break
                sleep 1
            done
            if kill -0 "$pid" 2> /dev/null; then
                kill -9 "$pid" 2> /dev/null
                sleep 1
                # Keep the pidfile and state so a later stop can retry.
                if kill -0 "$pid" 2> /dev/null; then
                    echo "qemu-runner: pid $pid survived SIGKILL" >&2
                    return 1
                fi
            fi
        fi
    fi
    if [ -n "$_QR_PIDFILE" ]; then
        rm -rf "$(dirname "$_QR_PIDFILE")"
    fi
    _QR_PIDFILE=""
    _QR_LOG=""
    _QR_CTL=""
}

qemu_write_state()
{
    printf 'port=%s\nkey=%s\npidfile=%s\n' \
        "$QEMU_PORT" "$QEMU_SSH_KEY" "$_QR_PIDFILE" > "$1.tmp" && mv -f "$1.tmp" "$1"
}

qemu_read_state()
{
    [ -s "$1" ] || {
        echo "qemu-runner: no state file $1" >&2
        return 1
    }
    QEMU_PORT="$(sed -n 's/^port=//p' "$1")"
    QEMU_SSH_KEY="$(sed -n 's/^key=//p' "$1")"
    _QR_PIDFILE="$(sed -n 's/^pidfile=//p' "$1")"

    # Restrict cleanup to the directory shape created by mktemp.
    case "$_QR_PIDFILE" in
        */elfuse-qemu.*/qemu.pid) ;;
        *)
            echo "qemu-runner: $1 names no qemu-runner pidfile: $_QR_PIDFILE; remove the file once the VM is gone" >&2
            return 1
            ;;
    esac
}

if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
    cmd="${1:-help}"
    shift || true
    state_file=""
    if [ "$cmd" != exec ] && [ "${1:-}" = "--state-file" ]; then
        state_file="${2:?--state-file needs a path}"
        shift 2
    fi
    case "$cmd" in
        start)
            if [ -n "$state_file" ] && [ -e "$state_file" ]; then
                echo "qemu-runner: $state_file names a live VM; run stop first" >&2
                exit 1
            fi
            trap 'qemu_stop' EXIT
            qemu_start || exit 1
            if [ -n "$state_file" ]; then
                qemu_write_state "$state_file" || exit 1
                trap - EXIT
            fi
            echo "PORT=$QEMU_PORT KEY=$QEMU_SSH_KEY"
            ;;
        exec)
            trap 'qemu_stop' EXIT
            qemu_start
            qemu_exec "$@"
            ;;
        stop)
            [ -z "$state_file" ] || qemu_read_state "$state_file" || exit 1
            qemu_stop || exit 1
            [ -z "$state_file" ] || rm -f "$state_file"
            ;;
        *)
            cat << EOF
Usage: $0 <start [--state-file PATH]|exec ARGS...|stop [--state-file PATH]>

Boots qemu-system-aarch64 with the test fixtures and exposes ssh.
The host repo is shared into the VM at /mnt/host (read-only).

Environment overrides:
  QEMU_BIN, QEMU_MEM, QEMU_SMP, QEMU_CPU,
  QEMU_PORT (initial; may be re-picked if busy),
  QEMU_BOOT_TIMEOUT, QEMU_SSH_KEY, QEMU_KERNEL, QEMU_INITRD.
EOF
            ;;
    esac
fi
