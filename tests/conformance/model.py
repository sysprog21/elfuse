# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    CONF = "CONF"
    WARN = "WARN"
    BROK = "BROK"
    TIMEOUT = "TIMEOUT"
    CRASH = "CRASH"
    INCONSISTENT = "INCONSISTENT"
    ERROR = "ERROR"


class Verdict(str, Enum):
    AS_EXPECTED = "as_expected"
    UNEXPECTED_FAILURE = "unexpected_failure"
    UNEXPECTED_PASS = "unexpected_pass"
    FLAKED = "flaked"
    FILTERED = "filtered"
    ERROR = "error"

    @property
    def is_red(self) -> bool:
        return self in (
            Verdict.UNEXPECTED_FAILURE,
            Verdict.UNEXPECTED_PASS,
            Verdict.ERROR,
        )


EXECUTIONS = ("normal", "timeout", "signal", "transport")


@dataclass
class Invocation:
    execution: str
    wall_us: int
    exit_code: Optional[int] = None
    signal: Optional[int] = None
    stdout: str = ""
    stderr: str = ""

    def __post_init__(self) -> None:
        if self.execution not in EXECUTIONS:
            raise ValueError("unknown execution %r" % (self.execution,))
        if self.wall_us < 0:
            raise ValueError("negative wall_us")
        carries = {"normal": "exit_code", "signal": "signal"}.get(self.execution)
        for name in ("exit_code", "signal"):
            if (getattr(self, name) is None) != (name != carries):
                raise ValueError("%s execution %s carry %s" % (
                    self.execution, "must" if name == carries else "cannot", name))

    pid: Optional[int] = dataclasses.field(default=None, compare=False)

    def to_dict(self) -> Dict[str, Any]:
        doc = dataclasses.asdict(self)
        del doc["pid"]
        return doc

    @classmethod
    def from_dict(cls, doc: Dict[str, Any]) -> "Invocation":
        return cls(**doc)


@dataclass
class Attempt:
    status: Status
    invocation: Invocation
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "invocation": self.invocation.to_dict(),
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, doc: Dict[str, Any]) -> "Attempt":
        return cls(
            status=Status(doc["status"]),
            invocation=Invocation.from_dict(doc["invocation"]),
            detail=doc.get("detail", ""),
        )


@dataclass
class CaseResult:
    id: str
    suite: str
    backend: str
    status: Status
    verdict: Verdict
    expectation: Dict[str, Any] = field(default_factory=dict)
    attempts: List[Attempt] = field(default_factory=list)
    detail: str = ""
    artifacts: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "suite": self.suite,
            "backend": self.backend,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "expectation": dict(self.expectation),
            "attempts": [a.to_dict() for a in self.attempts],
            "detail": self.detail,
            "artifacts": dict(self.artifacts),
        }

    @classmethod
    def from_dict(cls, doc: Dict[str, Any]) -> "CaseResult":
        return cls(
            id=doc["id"],
            suite=doc["suite"],
            backend=doc["backend"],
            status=Status(doc["status"]),
            verdict=Verdict(doc["verdict"]),
            expectation=dict(doc.get("expectation", {})),
            attempts=[Attempt.from_dict(a) for a in doc.get("attempts", [])],
            detail=doc.get("detail", ""),
            artifacts=dict(doc.get("artifacts", {})),
        )
