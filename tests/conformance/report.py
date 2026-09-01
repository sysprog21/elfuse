# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from conformance import payload
from conformance.model import CaseResult, Verdict

RESULTS = "results.json"


class ReportError(ValueError):
    pass


def red_line(case: CaseResult) -> str:
    return case.detail or "%s: %s" % (case.id, case.status.value)


def gate(cases: Iterable[CaseResult]) -> str:
    cases = list(cases)
    return "red" if not cases or any(c.verdict.is_red for c in cases) else "green"


def counts(cases: Iterable[CaseResult]) -> Dict[str, int]:
    out = {v.value: 0 for v in Verdict}
    for c in cases:
        out[c.verdict.value] += 1
    return out


def write(results_dir: Path, meta: Dict[str, Any], cases: List[CaseResult]) -> Dict[str, Any]:
    results_dir.mkdir(parents=True, exist_ok=True)
    doc = document(meta, cases)
    payload.atomic_write(results_dir / RESULTS, json.dumps(doc, indent=1, sort_keys=True) + "\n")
    (results_dir / "summary.txt").write_text("\n".join(summary_lines(meta, cases, results_dir)) + "\n")
    return doc


def document(meta: Dict[str, Any], cases: List[CaseResult]) -> Dict[str, Any]:
    return {"schema_version": 1, "kind": "run", "run": dict(meta),
            "gate": gate(cases), "counts": counts(cases),
            "cases": [c.to_dict() for c in cases]}


def load(results_dir: Path) -> Tuple[Dict[str, Any], List[CaseResult]]:
    path = results_dir / RESULTS
    if not path.is_file():
        raise ReportError("no %s under %s" % (RESULTS, results_dir))
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise ReportError("%s: %s" % (path, e)) from None
    if (not isinstance(doc, dict) or doc.get("kind") != "run"
            or not isinstance(doc.get("cases"), list)
            or not isinstance(doc.get("run"), dict)):
        raise ReportError("%s: unexpected shape" % path)
    if doc.get("schema_version") != 1:
        raise ReportError("%s: unknown schema" % path)
    try:
        cases = [CaseResult.from_dict(c) for c in doc["cases"]]
    except (TypeError, ValueError, KeyError) as e:
        raise ReportError("%s: malformed case record: %s" % (path, e)) from None
    if doc.get("gate") != gate(cases) or doc.get("counts") != counts(cases):
        raise ReportError("%s: stored gate or counts contradict the case records" % path)
    return doc["run"], cases


def _duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds >= 3600:
        return "%dh%02dm" % (seconds // 3600, seconds % 3600 // 60)
    return "%dm%02ds" % (seconds // 60, seconds % 60)


def summary_lines(meta: Dict[str, Any], cases: List[CaseResult], results_dir: Path) -> List[str]:
    n = counts(cases)
    head = "conformance %s/%s %s: %d cases in %s" % (
        meta.get("suite", "?"), meta.get("backend", "?"), meta.get("scope", "?"),
        len(cases), _duration(meta.get("elapsed_s", 0)))
    lines = [head]
    if meta.get("bootstrap"):
        lines.append("  bootstrap: expectations not applied")
    lines.append("  as_expected %d  flaked %d  filtered %d" % (
        n["as_expected"], n["flaked"], n["filtered"]))
    lines.append("  unexpected_failure %d  unexpected_pass %d  error %d" % (
        n["unexpected_failure"], n["unexpected_pass"], n["error"]))
    for c in cases:
        if c.verdict.is_red:
            lines.append("  RED " + red_line(c))
    if not cases:
        lines.append("  RED no cases ran")
    lines.append("RESULT: %s   (results: %s)" % (gate(cases).upper(), results_dir))
    return lines


def markdown(root: Path) -> str:
    rows = ["| lane | scope | gate | as_expected | flaked | filtered | red |", "|---|---|---|---|---|---|---|"]
    found = False
    for path in sorted(root.rglob(RESULTS)):
        found = True
        try:
            meta, cases = load(path.parent)
        except ValueError as e:
            rows.append("| %s | | error | | | | %s |" % (path.parent, e))
            continue
        n = counts(cases)
        rows.append("| %s/%s | %s | %s | %d | %d | %d | %d |" % (
            meta.get("suite"), meta.get("backend"), meta.get("scope"), gate(cases),
            n["as_expected"], n["flaked"], n["filtered"],
            n["unexpected_failure"] + n["unexpected_pass"] + n["error"]))
    return "\n".join(rows) + "\n" if found else "no conformance results under %s\n" % root
