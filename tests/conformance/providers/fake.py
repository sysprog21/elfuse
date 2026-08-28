# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from conformance import ids, jsonc, selection
from conformance.backends.base import Backend
from conformance.model import Attempt, Status
from conformance.providers.base import Case, Provider

_EXIT_STATUS = {0: Status.PASS, 1: Status.FAIL, 2: Status.BROK, 4: Status.WARN, 32: Status.CONF}


def status_of(inv) -> Status:
    if inv.execution == "timeout":
        return Status.TIMEOUT
    if inv.execution == "signal":
        return Status.CRASH
    if inv.execution == "transport":
        return Status.ERROR
    return _EXIT_STATUS.get(inv.exit_code, Status.FAIL)


def detail_of(inv) -> str:
    if inv.execution == "signal":
        return "signal %d" % inv.signal
    if inv.execution != "normal":
        return inv.execution
    return "exit %d" % inv.exit_code


class FakeProvider(Provider):
    name = "fake"
    default_timeout_s = 5

    def __init__(self, repo_root: Path):
        super().__init__(repo_root)
        self.suite_dir = repo_root / "tests" / "conformance"
        self.data = jsonc.load(self.suite_dir / "data" / "fake.jsonc")
        self._selection = selection.parse(self.data, "fake.jsonc")
        self.runs: Dict[str, int] = {}

    @property
    def selection(self) -> selection.Selection:
        return self._selection

    def enumerate(self, backend: Backend, entries: List[selection.Entry]) -> List[Case]:
        out = []
        for entry in entries:
            for name, script in self.data["cases"][entry.group].items():
                cid = "fake:%s/%s" % (entry.group, name)
                if entry.only and not any(ids.matches(o, name) for o in entry.only):
                    continue
                out.append(Case(cid, entry.group, entry.scope,
                                entry.timeout_s or self.default_timeout_s, {"script": script}))
        return out

    def _run(self, backend: Backend, case: Case, scratch: Path) -> Attempt:
        self.runs[case.id] = self.runs.get(case.id, 0) + 1
        script = case.meta["script"]
        if script == "flaky":
            script = "exit 1" if self.runs[case.id] == 1 else "exit 0"
        inv = backend.run(["sh", "-c", script], case.timeout_s, scratch)
        return Attempt(status_of(inv), inv, detail_of(inv))

    def run_batch(self, backend: Backend, cases: List[Case], scratch: Path) -> Dict[str, Attempt]:
        return {c.id: self._run(backend, c, scratch / ids.slug(c.id))
                for c in cases if c.meta["script"] != "unresolved"}

    def run_single(self, backend: Backend, case: Case, scratch: Path) -> Attempt:
        if case.meta["script"] == "unresolved":
            case = Case(case.id, case.group, case.scope, case.timeout_s, {"script": "exit 0"})
        return self._run(backend, case, scratch)
