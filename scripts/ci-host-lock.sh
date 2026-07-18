#!/usr/bin/env bash
# ci-host-lock.sh -- machine-wide reader-writer lock for the self-hosted
# CI host.
#
# Normal runtime legs hold a shared lock while they may load the host. The
# benchmark leg acquires the exclusive lock immediately around make bench-ci,
# keeping only the measurement window isolated. A detached holder owns flock;
# release talks to that exact holder over a job-scoped Unix socket rather than
# signaling a possibly recycled PID.
#
# Environment:
#   CI_HOST_LOCK_FILE          machine-global lock file
#                              (default /tmp/elfuse-ci-host.lock)
#   CI_HOST_LOCK_PID_FILE      job-scoped holder state file
#                              (default $RUNNER_TEMP/elfuse-ci-host-lock.pid)
#   CI_HOST_LOCK_CONTROL_FILE  job-scoped holder control socket
#                              (default $CI_HOST_LOCK_PID_FILE.sock)
#   CI_HOST_LOCK_WAIT_MIN      acquisition timeout in minutes (default 60)
#   CI_HOST_LOCK_MAX_HOLD_MIN  holder self-expiry in minutes (default 120)
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

LOCK_FILE="${CI_HOST_LOCK_FILE:-/tmp/elfuse-ci-host.lock}"
PID_FILE="${CI_HOST_LOCK_PID_FILE:-${RUNNER_TEMP:-/tmp}/elfuse-ci-host-lock.pid}"
CONTROL_FILE="${CI_HOST_LOCK_CONTROL_FILE:-${PID_FILE}.sock}"
WAIT_MIN="${CI_HOST_LOCK_WAIT_MIN:-60}"
MAX_HOLD_MIN="${CI_HOST_LOCK_MAX_HOLD_MIN:-120}"

usage()
{
    echo "usage: $0 acquire shared|exclusive | release" >&2
    exit 2
}

case "${1:-}" in
    acquire)
        case "${2:-}" in shared | exclusive) ;; *) usage ;; esac
        exec python3 - "$LOCK_FILE" "${2}" "$PID_FILE" "$CONTROL_FILE" \
            "$WAIT_MIN" "$MAX_HOLD_MIN" << 'PY'
import fcntl
import os
import select
import signal
import socket
import sys
import time
import uuid

lock_path, mode, pid_path, control_path, wait_min, hold_min = sys.argv[1:7]
wait_seconds = float(wait_min) * 60
hold_seconds = float(hold_min) * 60
if wait_seconds <= 0 or hold_seconds <= 0:
    sys.exit("ci-host-lock: wait and maximum hold must be positive")

flags = fcntl.LOCK_EX if mode == "exclusive" else fcntl.LOCK_SH
writers_dir = f"{lock_path}.writers"


def writer_pending():
    """Return true while any live exclusive waiter has published intent."""
    os.makedirs(writers_dir, mode=0o777, exist_ok=True)
    pending = False
    for name in os.listdir(writers_dir):
        if name.startswith("."):
            continue
        path = os.path.join(writers_dir, name)
        try:
            fd = os.open(path, os.O_RDWR)
        except FileNotFoundError:
            continue
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pending = True
            else:
                # The publishing process died before removing its marker.
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
        finally:
            os.close(fd)
    return pending


def publish_writer():
    """Publish a pre-locked marker atomically so readers cannot miss it."""
    os.makedirs(writers_dir, mode=0o777, exist_ok=True)
    token = f"{os.getpid()}-{uuid.uuid4().hex}"
    tmp_path = os.path.join(writers_dir, f".{token}.tmp")
    marker_path = os.path.join(writers_dir, token)
    fd = os.open(tmp_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    os.rename(tmp_path, marker_path)
    return fd, marker_path


r, w = os.pipe()
child = os.fork()
if child == 0:
    os.close(r)
    os.setsid()

    # A detached descendant retaining the runner's stdout/stderr keeps the
    # Actions step pipe open even after the acquire parent exits.
    devnull = os.open(os.devnull, os.O_RDWR)
    for target in (0, 1, 2):
        os.dup2(devnull, target)
    if devnull > 2:
        os.close(devnull)

    lock_fd = -1
    marker_fd = -1
    marker_path = None
    listener = None
    try:
        control_parent = os.path.dirname(control_path)
        if control_parent:
            os.makedirs(control_parent, exist_ok=True)
        try:
            os.unlink(control_path)
        except FileNotFoundError:
            pass
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(control_path)
        os.chmod(control_path, 0o600)
        listener.listen(2)

        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o666)
        if mode == "exclusive":
            marker_fd, marker_path = publish_writer()
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            os.unlink(marker_path)
            marker_path = None
            os.close(marker_fd)
            marker_fd = -1
        else:
            # Check the writer-intent directory both before and after the
            # non-blocking shared flock. This closes the publication race and
            # prevents a stream of new readers from starving an exclusive job.
            while True:
                while writer_pending():
                    time.sleep(0.1)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except BlockingIOError:
                    time.sleep(0.1)
                    continue
                if not writer_pending():
                    break
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                time.sleep(0.1)

        os.write(w, b"1")
        os.close(w)
        w = -1

        deadline = time.monotonic() + hold_seconds
        released = False
        while not released:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            listener.settimeout(remaining)
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                break
            with conn:
                conn.settimeout(2)
                try:
                    request = conn.recv(16)
                except socket.timeout:
                    continue
                if request == b"probe":
                    conn.sendall(b"live")
                    continue
                if request != b"release":
                    continue
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
                lock_fd = -1
                conn.sendall(b"released")
                released = True
    finally:
        if w >= 0:
            os.close(w)
        if lock_fd >= 0:
            os.close(lock_fd)
        if marker_path is not None:
            try:
                os.unlink(marker_path)
            except FileNotFoundError:
                pass
        if marker_fd >= 0:
            os.close(marker_fd)
        if listener is not None:
            listener.close()
        try:
            os.unlink(control_path)
        except FileNotFoundError:
            pass
    os._exit(0)

os.close(w)
start = time.monotonic()
granted, _, _ = select.select([r], [], [], wait_seconds)
ready = os.read(r, 1) if granted else b""
os.close(r)
if ready == b"1":
    pid_parent = os.path.dirname(pid_path)
    if pid_parent:
        os.makedirs(pid_parent, exist_ok=True)
    tmp_path = f"{pid_path}.{os.getpid()}.tmp"
    with open(tmp_path, "w", encoding="ascii") as state:
        state.write(f"{child}\n")
    os.replace(tmp_path, pid_path)
    print(f"ci-host-lock: {mode} lock acquired (holder pid {child}, "
          f"waited {time.monotonic() - start:.0f}s)")
    sys.exit(0)

try:
    os.killpg(child, signal.SIGKILL)
except (ProcessLookupError, PermissionError):
    try:
        os.kill(child, signal.SIGKILL)
    except ProcessLookupError:
        pass
try:
    os.waitpid(child, 0)
except ChildProcessError:
    pass
try:
    os.unlink(control_path)
except FileNotFoundError:
    pass
sys.exit(f"ci-host-lock: {mode} lock on {lock_path} not acquired within "
         f"{wait_min} min (holder died or a sibling job is wedged; "
         f"inspect with: lsof {lock_path})")
PY
        ;;
    release)
        python3 - "$PID_FILE" "$CONTROL_FILE" << 'PY'
import os
import socket
import sys

pid_path, control_path = sys.argv[1:3]
released = False
try:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    client.connect(control_path)
    client.sendall(b"release")
    released = client.recv(16) == b"released"
    client.close()
except (FileNotFoundError, ConnectionError, socket.timeout):
    pass

for path in (pid_path, control_path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass

if released:
    print("ci-host-lock: released")
else:
    print("ci-host-lock: no live holder recorded (nothing to release)")
PY
        ;;
    *)
        usage
        ;;
esac
