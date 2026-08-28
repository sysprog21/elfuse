# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import fcntl
import os
import signal
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from conformance.backends import base, proc
from conformance.model import Invocation


# Linux programs expect an 8 MiB initial stack.
WRAPPER = ["/bin/sh", "-c", 'ulimit -c 0; ulimit -s 8192; exec "$@"', "--"]


def orphan_pids(ps_output: str, binary: str, session: int) -> list:
    """Limit orphan cleanup to fork children from one case session."""
    out = []
    for line in ps_output.splitlines():
        fields = line.split(None, 3)
        if len(fields) < 4:
            continue
        pid, ppid, sess, command = fields
        if (ppid == "1" and sess == str(session) and command.startswith(binary + " ")
                and "--fork-child" in command):
            out.append(int(pid))
    return out


class ElfuseBackend(base.Backend):
    name = "elfuse"

    def __init__(self, repo_root: Path, sysroot: Optional[Path] = None,
                 binary: Optional[Path] = None):
        self.repo_root = repo_root
        self.binary = binary or repo_root / "build" / "elfuse"
        self.sysroot = sysroot
        # One session per user: guest /dev/shm is a per-uid host directory.
        self.lock_file = Path("/tmp/elfuse-conformance-%d.lock" % os.getuid())

    def prerequisites(self) -> Optional[str]:
        if not os.access(self.binary, os.X_OK):
            return "%s is absent; run: make" % self.binary
        if self.sysroot is not None and not self.sysroot.is_dir():
            return "sysroot %s is absent" % self.sysroot
        return None

    def argv(self, guest_argv: List[str]) -> List[str]:
        out = [str(self.binary), "--timeout", "0"]
        if self.sysroot is not None:
            out += ["--sysroot", str(self.sysroot)]
        return out + list(guest_argv)

    def run(
        self,
        argv: List[str],
        timeout_s: int,
        scratch: Path,
        env: Optional[Dict[str, str]] = None,
        fetch: Iterable[str] = (),
    ) -> Invocation:
        full = base.guest_environment(str(scratch), env)
        inv = proc.run_local(WRAPPER + self.argv(argv), timeout_s, scratch, env=full)
        if inv.pid is not None:
            self.reap_orphans(inv.pid)
        return inv

    def reap_orphans(self, session: int) -> None:
        """Release VMs held by fork children that outlived their case."""
        listing = subprocess.run(["ps", "-eo", "pid=,ppid=,sess=,command="], capture_output=True, text=True)
        for pid in orphan_pids(listing.stdout, str(self.binary), session):
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
