# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from conformance.backends import base, proc
from conformance.model import Invocation


# Linux programs expect an 8 MiB initial stack.
WRAPPER = ["/bin/sh", "-c", 'ulimit -c 0; ulimit -s 8192; exec "$@"', "--"]


def orphan_pids(ps_output: str, binary: str, group: int) -> list:
    """Limit orphan cleanup to fork children from one case process group."""
    out = []
    for line in ps_output.splitlines():
        fields = line.split(None, 3)
        if len(fields) < 4:
            continue
        pid, ppid, pgid, command = fields
        if (ppid == "1" and pgid == str(group) and command.startswith(binary + " ")
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
            return "%s is absent; run: make elfuse" % self.binary
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

    def reap_orphans(self, group: int) -> None:
        """Release VMs held by fork children that outlived their case."""
        try:
            # The case ran in its own session, so its pid is the pgid; an
            # empty group means no fork child survived and ps can be skipped.
            os.killpg(group, 0)
        except (ProcessLookupError, PermissionError):
            return
        try:
            listing = subprocess.run(
                ["ps", "-eo", "pid=,ppid=,pgid=,command="],
                capture_output=True,
                text=True,
            )
        except OSError:
            return
        for pid in orphan_pids(listing.stdout, str(self.binary), group):
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
