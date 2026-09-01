# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Dict, List

from conformance import ids, payload, selection
from conformance.backends import proc
from conformance.backends.base import Backend
from conformance.model import Attempt, Status
from conformance.providers.base import Case, Provider


class TempDirTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = self.root = Path(tmp.name)

DATA = {
    "schema_version": 1,
    "enabled": [
        {"group": "basic", "scope": "pr"},
        {"group": "slow", "scope": "full", "timeout_s": 1},
    ],
}
CASES = {
    "basic": {
        "pass": "exit 0", "fail": "exit 1", "flaky": "flaky",
        "quarantined": "exit 1",
    },
    "slow": {"timeout": "sleep 30", "unresolved": "unresolved"},
}


def setup(root: Path) -> None:
    expectations = root / "fixture" / "expectations"
    expectations.mkdir(parents=True)
    (expectations / "fixture.jsonc").write_text(
        '{"actions":[{"type":"expect_pass","matchers":["*"]}]}\n'
    )
    (expectations / "fixture_elfuse.jsonc").write_text(
        '{"actions":[{"include":"fixture.jsonc"},'
        '{"type":"expect_failure","reason":"fixture exit",'
        '"matchers":["fixture:basic/fail"]}]}\n'
    )
    (expectations / "flaky.jsonc").write_text(
        '{"actions":[{"type":"quarantine","reason":"fixture retry",'
        '"matchers":["fixture:basic/flaky",'
        '"fixture:basic/quarantined"]}]}\n'
    )


class LocalBackend(Backend):
    name = "elfuse"

    def run(self, argv, timeout_s, scratch, env=None, fetch=()):
        return proc.run_local(argv, timeout_s, scratch, env=env)


class FixtureProvider(Provider):
    name = "fixture"

    def __init__(self, repo_root: Path):
        super().__init__(repo_root)
        self.suite_dir = repo_root / "fixture"
        self._selection = selection.parse(DATA, "fixture")
        self.runs: Dict[str, int] = {}

    @property
    def selection(self):
        return self._selection

    def fingerprint(self) -> str:
        return "0" * 64

    def build_payload(self, force: bool = False) -> None:
        root = self.payload_root()
        root.mkdir(parents=True, exist_ok=True)
        (root / "fixture").write_text("fixture\n")
        payload.write_manifest(root, self.fingerprint())

    def enumerate(self, backend: Backend,
                  entries: List[selection.Entry]) -> List[Case]:
        return [
            Case("fixture:%s/%s" % (entry.group, name), entry.group,
                 entry.scope, entry.timeout_s or 5, {"script": script})
            for entry in entries
            for name, script in CASES[entry.group].items()
        ]

    def invoke(self, backend: Backend, case: Case, scratch: Path) -> Attempt:
        self.runs[case.id] = self.runs.get(case.id, 0) + 1
        script = case.meta["script"]
        if script == "flaky":
            script = "exit %d" % (1 if self.runs[case.id] == 1 else 0)
        inv = backend.run(["sh", "-c", script], case.timeout_s, scratch)
        if inv.execution == "timeout":
            status = Status.TIMEOUT
        elif inv.execution != "normal":
            status = Status.ERROR
        else:
            status = Status.PASS if inv.exit_code == 0 else Status.FAIL
        return Attempt(status, inv, inv.execution)

    def run_batch(self, backend: Backend, cases: List[Case],
                  scratch: Path) -> Dict[str, Attempt]:
        return {
            case.id: self.invoke(backend, case, scratch / ids.slug(case.id))
            for case in cases
            if case.meta["script"] != "unresolved"
        }

    def run_single(self, backend: Backend, case: Case,
                   scratch: Path) -> Attempt:
        if case.meta["script"] == "unresolved":
            case = Case(case.id, case.group, case.scope, case.timeout_s,
                        {"script": "exit 0"})
        return self.invoke(backend, case, scratch)
