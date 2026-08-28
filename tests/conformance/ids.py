# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import fnmatch
import hashlib
import re
from typing import Iterable, List, Optional, Tuple

_ID_RE = re.compile(
    r"^(?P<suite>[a-z][a-z0-9]*):(?P<group>[A-Za-z0-9_][A-Za-z0-9_.-]*)"
    r"(?P<case>(/[A-Za-z0-9_.-]+)*)$"
)


class IdError(ValueError):
    pass


def parse(test_id: str) -> Tuple[str, str, Optional[str]]:
    m = _ID_RE.match(test_id)
    if not m:
        raise IdError("not a canonical test id: %r" % (test_id,))
    case = m.group("case")
    return m.group("suite"), m.group("group"), case[1:] if case else None


def is_valid(test_id: str) -> bool:
    return _ID_RE.match(test_id) is not None


def suite_of(text: str) -> str:
    head, sep, _ = text.partition(":")
    return head if sep else ""


def group_of(test_id: str) -> str:
    return parse(test_id)[1]


def matches(pattern: str, test_id: str) -> bool:
    """Match wildcards across the full canonical id, including slashes."""
    return fnmatch.fnmatchcase(test_id, pattern)


def expand(patterns: Iterable[str], ids: Iterable[str]) -> List[str]:
    pats = list(patterns)
    return [i for i in ids if any(matches(p, i) for p in pats)]


def slug(test_id: str) -> str:
    """Keep sanitized ids distinct with a digest suffix."""
    digest = hashlib.sha256(test_id.encode()).hexdigest()[:8]
    return re.sub(r"[^A-Za-z0-9_.-]", "_", test_id) + "-" + digest
