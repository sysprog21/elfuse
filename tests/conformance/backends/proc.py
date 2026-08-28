# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

from conformance.model import Invocation

KILL_WAIT_S = 30


def classify(rc: int, timed_out: bool, wall_us: int, stdout: str, stderr: str) -> Invocation:
    """Interpret negative Popen return codes as signal deaths."""
    if timed_out:
        return Invocation(execution="timeout", wall_us=wall_us, stdout=stdout, stderr=stderr)
    if rc < 0:
        return Invocation(execution="signal", wall_us=wall_us, signal=-rc, stdout=stdout, stderr=stderr)
    return Invocation(execution="normal", wall_us=wall_us, exit_code=rc, stdout=stdout, stderr=stderr)


def _kill_and_reap(proc: subprocess.Popen) -> int:
    """Bound the wait for a guest stuck in an uninterruptible state."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        return proc.wait(timeout=KILL_WAIT_S)
    except subprocess.TimeoutExpired:
        return -signal.SIGKILL


def run_local(
    argv: List[str],
    timeout_s: int,
    scratch: Path,
    env: Optional[Dict[str, str]] = None,
    stdout_name: str = "stdout",
) -> Invocation:
    """Run argv in a new session so timeout cleanup reaches its group."""
    scratch.mkdir(parents=True, exist_ok=True)
    out_path, err_path = scratch / stdout_name, scratch / "stderr"
    started = time.monotonic()
    with open(out_path, "wb") as out, open(err_path, "wb") as err, \
            open(os.devnull, "rb") as feed:
        try:
            proc = subprocess.Popen(argv, cwd=str(scratch), env=env, stdin=feed,
                                    stdout=out, stderr=err, start_new_session=True)
        except OSError as e:
            err.write(("cannot spawn %s: %s\n" % (argv[0], e)).encode())
            return Invocation(execution="transport", wall_us=int((time.monotonic() - started) * 1_000_000),
                              stdout=str(out_path), stderr=str(err_path))
        timed_out = False
        try:
            rc = proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            rc = _kill_and_reap(proc)
    inv = classify(rc, timed_out, int((time.monotonic() - started) * 1_000_000), str(out_path), str(err_path))
    inv.pid = proc.pid  # start_new_session makes pid the process-group id
    return inv
