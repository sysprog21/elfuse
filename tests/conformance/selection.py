# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from conformance import ids, jsonc

SCOPES = ("pr", "full")


class SelectionError(ValueError):
    pass


@dataclass(frozen=True)
class Entry:
    group: str
    scope: str
    timeout_s: Optional[int] = None
    only: Tuple[str, ...] = ()


@dataclass
class Selection:
    enabled: List[Entry]
    declined: List[Tuple[str, Tuple[str, ...]]]
    extra: Dict[str, Any] = field(default_factory=dict)
    source: str = ""

    def groups(self, scope: str) -> List[Entry]:
        if scope not in SCOPES:
            raise SelectionError("unknown scope %r" % (scope,))
        return [e for e in self.enabled if scope == "full" or e.scope == "pr"]

    def entry(self, group: str) -> Optional[Entry]:
        return next((e for e in self.enabled if e.group == group), None)

    def lint(self) -> List[str]:
        problems = []
        seen: Dict[str, str] = {}
        for e in self.enabled:
            if e.group in seen:
                problems.append("%s: %s is enabled twice" % (self.source, e.group))
            seen[e.group] = "enabled"
        for reason, groups in self.declined:
            for g in groups:
                if seen.get(g) == "enabled":
                    problems.append("%s: %s is both enabled and declined" % (self.source, g))
                elif g in seen:
                    problems.append("%s: %s is declined twice" % (self.source, g))
                seen[g] = "declined"
        return problems


def _entry(doc: Any, where: str) -> Entry:
    if not isinstance(doc, dict) or not isinstance(doc.get("group"), str):
        raise SelectionError("%s: enabled entry needs a group" % where)
    unknown = set(doc) - {"group", "scope", "timeout_s", "only"}
    if unknown:
        raise SelectionError("%s: unknown keys %s" % (where, sorted(unknown)))
    scope = doc.get("scope")
    if scope not in SCOPES:
        raise SelectionError("%s: %s has scope %r, want pr or full" % (where, doc["group"], scope))
    timeout = doc.get("timeout_s")
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, int)
                                or timeout <= 0):
        raise SelectionError("%s: timeout_s must be a positive integer" % where)
    only = doc.get("only", [])
    if not isinstance(only, list) or any(not isinstance(o, str) for o in only):
        raise SelectionError("%s: only must be a list of case globs" % where)
    return Entry(doc["group"], scope, timeout, tuple(only))


def parse(doc: Any, source: str) -> Selection:
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise SelectionError("%s: schema_version must be 1" % source)
    enabled = doc.get("enabled")
    if not isinstance(enabled, list):
        raise SelectionError("%s: enabled must be a list" % source)
    entries = [_entry(e, "%s:enabled[%d]" % (source, i)) for i, e in enumerate(enabled)]
    declined = []
    for i, d in enumerate(doc.get("declined", [])):
        where = "%s:declined[%d]" % (source, i)
        if (not isinstance(d, dict) or set(d) != {"reason", "groups"}
                or not isinstance(d["reason"], str) or not d["reason"].strip()
                or not isinstance(d["groups"], list) or not d["groups"]
                or any(not isinstance(g, str) for g in d["groups"])):
            raise SelectionError("%s: a declined entry is a reason and a group list" % where)
        declined.append((d["reason"], tuple(d["groups"])))
    extra = {k: v for k, v in doc.items() if k not in ("schema_version", "enabled", "declined")}
    sel = Selection(entries, declined, extra, source)
    problems = sel.lint()
    if problems:
        raise SelectionError("; ".join(problems))
    return sel


def load(path: Path) -> Selection:
    return parse(jsonc.load(path), path.name)


def resolve_ids(patterns: Iterable[str], universe: Iterable[str],
                suite: str) -> Tuple[List[str], List[str]]:
    """Report unmatched patterns with nearby canonical ids."""
    known = list(universe)
    chosen: List[str] = []
    seen = set()
    errors: List[str] = []
    for pattern in patterns:
        if ids.suite_of(pattern) != suite:
            errors.append("%s: not a %s id (want %s:<group>[/<case>])" % (pattern, suite, suite))
            continue
        # A bare group id also selects its cases.
        pats = [pattern] if "/" in pattern else [pattern, pattern + "/*"]
        hits = ids.expand(pats, known)
        if not hits:
            near = difflib.get_close_matches(pattern, known, n=3, cutoff=0.6)
            errors.append("%s: no such test%s" % (
                pattern, ("; near: " + ", ".join(near)) if near else ""))
        chosen.extend(h for h in hits if h not in seen)
        seen.update(hits)
    return chosen, errors
