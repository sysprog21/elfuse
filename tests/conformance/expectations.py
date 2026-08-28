# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from conformance import ids, jsonc

ACTION_TYPES = ("expect_pass", "expect_failure", "expect_conf", "skip", "quarantine")
_ACTION_KEYS = {"type", "matchers", "reason", "since", "tracking"}
_TRACKING_RE = re.compile(r"^(#\d+|https?://\S+)$")
_SINCE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SEEDED_PREFIX = "seeded from "
FLAKY = "flaky.jsonc"


class ExpectationError(ValueError):
    pass


@dataclass(frozen=True)
class Action:
    type: str
    matchers: tuple
    reason: str
    source: str
    since: str = ""
    tracking: str = ""


@dataclass(frozen=True)
class Resolution:
    type: str
    reason: str
    source: str
    matcher: str
    quarantined: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "reason": self.reason,
            "source": self.source,
            "matcher": self.matcher,
            "quarantined": self.quarantined,
        }


class Expectations:
    def __init__(self, suite: str, actions: List[Action]):
        self.suite = suite
        self.actions = list(actions)
        first = next((a for a in actions if a.type != "quarantine"), None)
        if first is None or first.type != "expect_pass" or first.matchers != ("*",):
            raise ExpectationError(
                'the first effective action must be expect_pass on "*"'
            )

    def resolve(self, test_id: str) -> Resolution:
        chosen: Optional[Action] = None
        chosen_matcher = ""
        quarantined = False
        for action in self.actions:
            for m in action.matchers:
                if ids.matches(m, test_id):
                    if action.type == "quarantine":
                        quarantined = True
                    else:
                        chosen, chosen_matcher = action, m
        assert chosen is not None
        return Resolution(
            type=chosen.type,
            reason=chosen.reason,
            source=chosen.source,
            matcher=chosen_matcher,
            quarantined=quarantined,
        )

    def stale(self, known: Iterable[str]) -> List[str]:
        universe = list(known)
        out = []
        for action in self.actions:
            for m in action.matchers:
                if m == "*" or ids.suite_of(m) != self.suite:
                    continue
                if not any(ids.matches(m, i) for i in universe):
                    out.append("%s: %r matches no test" % (action.source, m))
        return out


def _check_text(text: str, where: str) -> None:
    if "\u2014" in text:
        raise ExpectationError("%s: em dash in text" % where)


def _parse_action(doc: Any, where: str, suite: str) -> Action:
    if not isinstance(doc, dict):
        raise ExpectationError("%s: action is not an object" % where)
    unknown = set(doc) - _ACTION_KEYS
    if unknown:
        raise ExpectationError("%s: unknown keys %s" % (where, sorted(unknown)))
    kind = doc.get("type")
    if kind not in ACTION_TYPES:
        raise ExpectationError("%s: unknown action type %r" % (where, kind))
    matchers = doc.get("matchers")
    if not isinstance(matchers, list) or not matchers:
        raise ExpectationError("%s: matchers must be a non-empty list" % where)
    if any(not isinstance(m, str) for m in matchers):
        raise ExpectationError("%s: matchers must be strings" % where)
    if matchers != sorted(matchers):
        raise ExpectationError("%s: matchers are not sorted" % where)
    if len(set(matchers)) != len(matchers):
        raise ExpectationError("%s: duplicate matcher" % where)
    for m in matchers:
        if m == "*":
            if kind != "expect_pass":
                raise ExpectationError('%s: "*" is legal only on expect_pass' % where)
            continue
        if ids.suite_of(m) != suite:
            raise ExpectationError("%s: matcher %r is not in suite %s" % (where, m, suite))
        if not ids.is_valid(m.replace("*", "x").replace("?", "x")):
            raise ExpectationError("%s: matcher %r is not an id pattern" % (where, m))
    reason = doc.get("reason", "")
    if not isinstance(reason, str):
        raise ExpectationError("%s: reason must be a string" % where)
    if kind != "expect_pass" and not reason.strip():
        raise ExpectationError("%s: %s needs a reason" % (where, kind))
    _check_text(reason, where)
    since = doc.get("since", "")
    if since and not (isinstance(since, str) and _SINCE_RE.match(since)):
        raise ExpectationError("%s: since must be YYYY-MM-DD" % where)
    tracking = doc.get("tracking", "")
    if tracking and not (isinstance(tracking, str) and _TRACKING_RE.match(tracking)):
        raise ExpectationError("%s: tracking must be #N or a URL" % where)
    return Action(kind, tuple(matchers), reason, where, since, tracking)


def read_file(path: Path, suite: str, seen: Optional[List[Path]] = None) -> List[Action]:
    seen = list(seen or [])
    if path in seen:
        raise ExpectationError("%s: include cycle" % path)
    if len(seen) > 8:
        raise ExpectationError("%s: include chain too deep" % path)
    seen.append(path)
    out: List[Action] = []
    for where, entry in _entries(path):
        if isinstance(entry, dict) and "include" in entry:
            if set(entry) != {"include"} or not isinstance(entry["include"], str):
                raise ExpectationError("%s: include takes only a file name" % where)
            out.extend(read_file(path.parent / entry["include"], suite, seen))
            continue
        action = _parse_action(entry, where, suite)
        if action.type == "quarantine" and path.name != FLAKY:
            raise ExpectationError("%s: quarantine is legal only in %s" % (where, FLAKY))
        if path.name == FLAKY and action.type != "quarantine":
            raise ExpectationError("%s: %s holds only quarantine actions" % (where, FLAKY))
        out.append(action)
    return out


def _entries(path: Path) -> List[Tuple[str, Any]]:
    if not path.exists():
        raise ExpectationError("%s: no such file" % path)
    doc = jsonc.load(path)
    if not isinstance(doc, dict) or set(doc) != {"actions"}:
        raise ExpectationError('%s: expected an object with only "actions"' % path)
    if not isinstance(doc["actions"], list):
        raise ExpectationError("%s: actions must be a list" % path)
    return [("%s:%d" % (path.name, index), entry) for index, entry in enumerate(doc["actions"])]


def leaf_path(root: Path, suite: str, backend: str) -> Path:
    return root / ("%s_%s.jsonc" % (suite, backend))


def load(suite: str, backend: str, root: Path) -> Expectations:
    actions = read_file(leaf_path(root, suite, backend), suite)
    flaky = root / FLAKY
    if flaky.exists():
        actions.extend(a for a in read_flaky(flaky) if ids.suite_of(a.matchers[0]) == suite)
    return Expectations(suite, actions)


def read_flaky(path: Path) -> List[Action]:
    out = []
    for where, entry in _entries(path):
        matchers = entry.get("matchers") if isinstance(entry, dict) else None
        first = matchers[0] if isinstance(matchers, list) and matchers else ""
        suite = ids.suite_of(first) if isinstance(first, str) else ""
        action = _parse_action(entry, where, suite)
        if action.type != "quarantine":
            raise ExpectationError("%s: %s holds only quarantine actions" % (where, FLAKY))
        if any(ids.suite_of(m) != suite for m in action.matchers):
            raise ExpectationError("%s: matchers span suites" % where)
        out.append(action)
    return out


def lint(root: Path, seeded_ok: bool = False) -> List[str]:
    problems: List[str] = []
    seeded: List[str] = []
    for path in sorted(root.glob("*.jsonc")):
        try:
            if path.name == FLAKY:
                actions = read_flaky(path)
            else:
                suite = path.stem.split("_", 1)[0]
                actions = read_file(path, suite)
                if "_" in path.stem:
                    Expectations(suite, actions)
        except (ExpectationError, jsonc.JsoncError) as e:
            problems.append(str(e))
            continue
        seeded.extend(a.source for a in actions if a.reason.startswith(SEEDED_PREFIX))
    for source in () if seeded_ok else seeded:
        problems.append("%s: still carries a seeded reason; triage it" % source)
    return problems
