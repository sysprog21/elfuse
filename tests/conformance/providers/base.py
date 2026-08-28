# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from conformance.backends.base import Backend
from conformance.model import Attempt
from conformance.selection import Entry, Selection


class ProviderError(RuntimeError):
    pass


@dataclass
class Case:
    id: str
    group: str
    scope: str
    timeout_s: int
    meta: Dict[str, Any] = field(default_factory=dict)


class Provider:
    name = ""
    default_timeout_s = 120
    pins_schema: Dict[str, Dict[str, str]] = {}

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.suite_dir = repo_root / "tests" / "conformance" / self.name

    @property
    def pins_path(self) -> Path:
        return self.suite_dir / "pins.json"

    @property
    def selection(self) -> Selection:
        raise NotImplementedError

    @property
    def expectations_dir(self) -> Path:
        return self.suite_dir / "expectations"

    def backend_options(self, backend: str) -> Dict[str, Any]:
        return {}

    def prerequisites(self, backend: str) -> Optional[str]:
        """Return an exit-77 reason when the suite cannot run."""
        return None

    def enumerate(self, backend: Backend, entries: List[Entry]) -> List[Case]:
        raise NotImplementedError

    def batch_key(self, case: Case) -> str:
        return case.group

    def run_batch(self, backend: Backend, cases: List[Case], scratch: Path) -> Dict[str, Attempt]:
        """Run cases that share a batch key; ids left out are rerun alone."""
        raise NotImplementedError

    def run_single(self, backend: Backend, case: Case, scratch: Path) -> Attempt:
        raise NotImplementedError

    def payload_root(self) -> Path:
        return self.repo_root / "externals" / "payloads" / self.name

    def fingerprint(self) -> str:
        raise NotImplementedError

    def build_payload(self, force: bool = False) -> None:
        raise NotImplementedError

    def build_hint(self) -> str:
        return "make %s-payload" % self.name

    def latest_pin(self, doc: Dict[str, Any], ref: Optional[str]) -> Dict[str, Any]:
        raise NotImplementedError

    def update_next_steps(self) -> List[str]:
        return [self.build_hint()]

    def audit(self) -> List[str]:
        return []

    def regen_selection(self, check: bool = False) -> List[str]:
        return []
