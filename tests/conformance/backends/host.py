# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Optional

from conformance.backends import base, proc
from conformance.model import Invocation


class HostBackend(base.Backend):
    name = "host"

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root

    def run(
        self,
        argv: List[str],
        timeout_s: int,
        scratch: Path,
        env: Optional[Dict[str, str]] = None,
        fetch: Iterable[str] = (),
    ) -> Invocation:
        return proc.run_local(argv, timeout_s, scratch, env=base.guest_environment(str(scratch), env))
