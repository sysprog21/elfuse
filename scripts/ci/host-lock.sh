#!/usr/bin/env bash
# Machine-wide reader-writer lock for the self-hosted CI host.
#
# Normal runtime legs hold a shared lock while they may load the host. The
# benchmark leg acquires the exclusive lock immediately around make bench-ci,
# keeping only the measurement window isolated. A detached holder owns flock;
# release talks to that exact holder over a Unix socket rather than signaling a
# possibly recycled PID. Each acquire binds a socket of its own (the prefix plus
# a random suffix, recorded in the state file), so a holder that is still
# cleaning up after a release can never remove its successor's socket.
#
# Environment:
#   CI_HOST_LOCK_FILE          machine-global lock file
#                              (default /tmp/elfuse-ci-host.lock)
#   CI_HOST_LOCK_PID_FILE      job-scoped holder state file
#                              (default $RUNNER_TEMP/elfuse-ci-host-lock.pid)
#   CI_HOST_LOCK_CONTROL_FILE  job-scoped control socket path prefix
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
import traceback
import uuid

lock_path, mode, pid_path, control_prefix, wait_min, hold_min = sys.argv[1:7]
# The holder changes directory before it opens the lock file.
lock_path = os.path.abspath(lock_path)
control_path = os.path.abspath(f"{control_prefix}.{uuid.uuid4().hex}")
wait_seconds = float(wait_min) * 60
hold_seconds = float(hold_min) * 60
if wait_seconds <= 0 or hold_seconds <= 0:
    sys.exit("host-lock: wait and maximum hold must be positive")

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



def parent_gone():
    """A cancelled job kills the acquire parent but not this holder."""
    return os.getppid() != parent


parent = os.getpid()
r, w = os.pipe()
# The holder takes the lock only after this process has recorded it, so no
# granted holder is ever missing from the state file.
go_r, go_w = os.pipe()
child = os.fork()
if child == 0:
    os.close(r)
    os.close(go_w)
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
        os.makedirs(control_parent, exist_ok=True)
        # Bind by name relative to the socket's directory: sun_path holds 104
        # bytes on macOS, and a deep $RUNNER_TEMP alone can exceed that.
        os.chdir(control_parent)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.path.basename(control_path))
        os.chmod(control_path, 0o600)
        listener.listen(2)

        recorded = os.read(go_r, 1) == b"g"
        os.close(go_r)
        go_r = -1
        if not recorded:
            raise SystemExit("host-lock: acquire parent exited")

        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o666)
        if mode == "exclusive":
            marker_fd, marker_path = publish_writer()
            while True:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if parent_gone():
                        raise SystemExit("host-lock: acquire parent exited")
                    time.sleep(0.1)
            os.unlink(marker_path)
            marker_path = None
            os.close(marker_fd)
            marker_fd = -1
        else:
            # Check the writer-intent directory both before and after the
            # non-blocking shared flock. This closes the publication race and
            # prevents a stream of new readers from starving an exclusive job.
            while True:
                if parent_gone():
                    raise SystemExit("host-lock: acquire parent exited")
                if writer_pending():
                    time.sleep(0.1)
                    continue
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
            # A client that times out or disconnects must not end the holder,
            # which would drop the lock behind the job's back.
            with conn:
                conn.settimeout(2)
                try:
                    request = conn.recv(16)
                    if request == b"probe":
                        conn.sendall(b"live")
                except OSError:
                    continue
                if request != b"release":
                    continue
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
                lock_fd = -1
                released = True
                try:
                    conn.sendall(b"released")
                except OSError:
                    pass
    except BaseException:
        # stderr is /dev/null here, so hand the failure to the waiting parent
        # instead of letting it read as a lock that was never granted.
        if w >= 0:
            try:
                os.write(w, b"E" + traceback.format_exc().encode()[-3000:])
            except OSError:
                pass
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
os.close(go_r)

def forget_holder():
    try:
        os.unlink(pid_path)
    except FileNotFoundError:
        pass

# Record the holder, then let it lock, so that release finds it even when this
# process dies between the grant and its own exit. A holder still waiting when
# this process dies exits by itself (parent_gone above).
pid_parent = os.path.dirname(pid_path)
if pid_parent:
    os.makedirs(pid_parent, exist_ok=True)
tmp_path = f"{pid_path}.{os.getpid()}.tmp"
with open(tmp_path, "w", encoding="ascii") as state:
    state.write(f"{child}\n{control_path}\n")
os.replace(tmp_path, pid_path)
try:
    os.write(go_w, b"g")
except BrokenPipeError:
    pass  # The holder already failed; its report is waiting on r.
os.close(go_w)

start = time.monotonic()
granted, _, _ = select.select([r], [], [], wait_seconds)
ready = os.read(r, 4096) if granted else b""
os.close(r)
if ready.startswith(b"E"):
    os.waitpid(child, 0)
    forget_holder()
    sys.stderr.write(ready[1:].decode(errors="replace"))
    sys.exit(f"host-lock: {mode} lock holder failed before acquiring "
             f"{lock_path}")
if ready == b"1":
    print(f"host-lock: {mode} lock acquired (holder pid {child}, "
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
forget_holder()
sys.exit(f"host-lock: {mode} lock on {lock_path} not acquired within "
         f"{wait_min} min (holder died or a sibling job is wedged; "
         f"inspect with: lsof {lock_path})")
PY
        ;;
    release)
        python3 - "$PID_FILE" << 'PY'
import os
import socket
import sys

pid_path = sys.argv[1]
try:
    with open(pid_path, encoding="ascii") as state:
        lines = state.read().split("\n")
except FileNotFoundError:
    print("host-lock: no live holder recorded (nothing to release)")
    sys.exit(0)
control_path = lines[1] if len(lines) > 1 else ""

released = False
holder_gone = not control_path
if control_path:
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5)
        # Relative name, as the holder bound it (sun_path is 104 bytes).
        os.chdir(os.path.dirname(control_path))
        client.connect(os.path.basename(control_path))
        client.sendall(b"release")
        released = client.recv(16) == b"released"
        client.close()
    except (FileNotFoundError, ConnectionRefusedError):
        # No listener: the holder has exited, and flock went with it.
        holder_gone = True
    except (ConnectionError, socket.timeout):
        pass

if not (released or holder_gone):
    # The holder is alive but did not answer. Keep its socket and the state
    # file so a retry can still reach it, and fail so the job shows it.
    sys.exit(f"host-lock: holder at {control_path} did not confirm the "
             "release; state kept for a retry")

for path in (pid_path, control_path):
    if not path:
        continue
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass

if released:
    print("host-lock: released")
else:
    print("host-lock: recorded holder already exited (nothing to release)")
PY
        ;;
    *)
        usage
        ;;
esac
