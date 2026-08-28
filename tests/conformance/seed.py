# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from conformance import ids, jsonc, payload
from conformance.expectations import SEEDED_PREFIX
from conformance.model import CaseResult, Status, Verdict

_ACTION_FOR = {
    Status.FAIL: "expect_failure",
    Status.BROK: "expect_failure",
    Status.CONF: "expect_conf",
    Status.TIMEOUT: "skip",
    Status.CRASH: "skip",
    Status.INCONSISTENT: "skip",
}
_ORDER = ("expect_pass", "expect_failure", "expect_conf", "skip")


def default_reason(results_dir: Path, date: str) -> str:
    return "%s%s on %s; untriaged" % (SEEDED_PREFIX, results_dir, date)


def propose(cases: List[CaseResult], reason: str, bootstrap: bool,
            whole_groups: bool = True) -> List[Dict[str, Any]]:
    """Collapse complete groups when whole_groups is set."""
    wanted: Dict[str, str] = {}
    for c in cases:
        if c.status is Status.ERROR:
            raise ValueError("%s is a harness ERROR; seeding refuses it" % c.id)
        if bootstrap:
            # What an earlier leaf recorded is not evidence.
            action = _ACTION_FOR.get(c.status)
            if action:
                wanted[c.id] = action
        elif c.verdict is Verdict.UNEXPECTED_PASS:
            wanted[c.id] = "expect_pass"
        elif c.verdict is Verdict.UNEXPECTED_FAILURE:
            wanted[c.id] = _ACTION_FOR.get(c.status, "expect_failure")
    by_group: Dict[tuple, List[str]] = {}
    for c in cases:
        by_group.setdefault((ids.suite_of(c.id), ids.group_of(c.id)), []).append(c.id)
    out: Dict[str, List[str]] = {}
    for (suite, group), members in sorted(by_group.items()):
        actions = {wanted.get(m) for m in members}
        if whole_groups and len(actions) == 1 and None not in actions and len(members) > 1:
            out.setdefault(actions.pop(), []).append("%s:%s/*" % (suite, group))
            continue
        for m in members:
            if m in wanted:
                out.setdefault(wanted[m], []).append(m)
    return [{"type": kind, "reason": reason, "matchers": sorted(out[kind])}
            for kind in _ORDER if kind in out]


def format_actions(actions: List[Dict[str, Any]], header: str = "") -> str:
    lines = [header.rstrip("\n")] if header else []
    lines += ["{", '  "actions": [']
    for a in actions:
        if "include" in a:
            lines.append('    { "include": %s },' % json.dumps(a["include"]))
            continue
        head = '    { "type": %s,' % json.dumps(a["type"])
        for key in ("reason", "since", "tracking"):
            if a.get(key):
                lines.append(head)
                head = '      "%s": %s,' % (key, json.dumps(a[key]))
        lines.append(head)
        matchers = a["matchers"]
        if len(matchers) == 1:
            lines.append('      "matchers": [%s] },' % json.dumps(matchers[0]))
        else:
            lines.append('      "matchers": [')
            lines.extend("        %s," % json.dumps(m) for m in matchers)
            lines.append("      ] },")
    lines += ["  ],", "}", ""]
    return "\n".join(lines)


def append(leaf: Path, actions: List[Dict[str, Any]]) -> None:
    """Append actions while preserving the leading comment block."""
    text = leaf.read_text() if leaf.exists() else ""
    header_lines = []
    for line in text.splitlines():
        if line.startswith("//") or not line.strip():
            header_lines.append(line)
        else:
            break
    if text.strip():
        existing = jsonc.loads(text)["actions"]
    else:
        # Prefer the shared suite default when present.
        base = leaf.parent / (leaf.stem.split("_", 1)[0] + ".jsonc")
        existing = ([{"include": base.name}] if base.exists()
                    else [{"type": "expect_pass", "matchers": ["*"]}])
    payload.atomic_write(leaf, format_actions(existing + actions, "\n".join(header_lines)))
