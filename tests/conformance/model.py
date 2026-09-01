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


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value):
        return {f.name: _plain(getattr(value, f.name))
                for f in dataclasses.fields(value) if f.compare}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return dict(value)
    return value


class Doc:
    """JSON mapping for the dataclasses below; compare=False stays out."""

    def to_dict(self) -> Dict[str, Any]:
        return _plain(self)

    @classmethod
    def from_dict(cls, doc: Dict[str, Any]) -> Any:
        kwargs = {f.name: _CONVERT.get(f.name, lambda v: v)(doc[f.name])
                  for f in dataclasses.fields(cls) if f.compare and f.name in doc}
        return cls(**kwargs)


@dataclass
class Invocation(Doc):
    execution: str
    wall_us: int
    exit_code: Optional[int] = None
    signal: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    pid: Optional[int] = dataclasses.field(default=None, compare=False)

    def __post_init__(self) -> None:
        if self.execution not in EXECUTIONS:
            raise ValueError("unknown execution %r" % (self.execution,))
        if self.wall_us < 0:
            raise ValueError("negative wall_us")
        carries = {"normal": "exit_code", "signal": "signal"}.get(self.execution)
        for name in ("exit_code", "signal"):
            if (getattr(self, name) is not None) != (name == carries):
                raise ValueError("%s execution %s carry %s" % (
                    self.execution, "must" if name == carries else "cannot", name))


@dataclass
class Attempt(Doc):
    status: Status
    invocation: Invocation
    detail: str = ""


@dataclass
class CaseResult(Doc):
    id: str
    suite: str
    backend: str
    status: Status
    verdict: Verdict
    expectation: Dict[str, Any] = field(default_factory=dict)
    attempts: List[Attempt] = field(default_factory=list)
    detail: str = ""


_CONVERT = {
    "status": Status,
    "verdict": Verdict,
    "invocation": Invocation.from_dict,
    "attempts": lambda docs: [Attempt.from_dict(a) for a in docs],
}
