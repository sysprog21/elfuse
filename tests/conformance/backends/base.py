# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import contextlib
import fcntl
import os
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional

from conformance.model import Invocation


class BackendError(RuntimeError):
    pass


FIXED_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"}
SCRATCH_NAMES = ("HOME", "TMPDIR", "TEST_TMPDIR")


def guest_environment(scratch: str, env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    scratch = os.path.abspath(scratch)
    return {**FIXED_ENV, **{name: scratch for name in SCRATCH_NAMES}, **(env or {})}


class Backend:
    name = ""
    max_jobs = 0  # 0: no cap on --jobs
    lock_file: Optional[Path] = None  # held by serialize() when set

    def prerequisites(self) -> Optional[str]:
        """Return an exit-77 reason when the backend cannot run."""
        return None

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def run(
        self,
        argv: List[str],
        timeout_s: int,
        scratch: Path,
        env: Optional[Dict[str, str]] = None,
        fetch: Iterable[str] = (),
    ) -> Invocation:
        """Run argv in a fresh guest cwd and return artifacts in scratch."""
        raise NotImplementedError

    def guest_path(self, host_path: Path) -> str:
        return str(host_path)

    @contextlib.contextmanager
    def serialize(self) -> Iterator[None]:
        """Take a non-blocking flock when lock_file is set."""
        if self.lock_file is None:
            yield
            return
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.lock_file, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise BackendError("another %s conformance session holds %s"
                                   % (self.name, self.lock_file)) from None
            yield
        finally:
            os.close(fd)
