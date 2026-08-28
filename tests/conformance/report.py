# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from conformance import payload
from conformance.model import CaseResult, Verdict

RESULTS = "results.json"
_NOT_XML = re.compile("[^\t\n\r\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


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
    doc = {"schema_version": 1, "run": dict(meta), "gate": gate(cases),
           "counts": counts(cases), "cases": [c.to_dict() for c in cases]}
    payload.atomic_write(results_dir / RESULTS, json.dumps(doc, indent=1, sort_keys=True) + "\n")
    (results_dir / "junit.xml").write_bytes(junit(meta, cases))
    (results_dir / "summary.txt").write_text("\n".join(summary_lines(meta, cases, results_dir)) + "\n")
    return doc


def load(results_dir: Path) -> Tuple[Dict[str, Any], List[CaseResult]]:
    path = results_dir / RESULTS
    if not path.is_file():
        raise ReportError("no %s under %s" % (RESULTS, results_dir))
    doc = json.loads(path.read_text())
    if (not isinstance(doc, dict) or not isinstance(doc.get("cases"), list)
            or not isinstance(doc.get("run"), dict)):
        raise ReportError("%s: unexpected shape" % path)
    if doc.get("schema_version") != 1:
        raise ReportError("%s: unknown schema" % path)
    cases = [CaseResult.from_dict(c) for c in doc["cases"]]
    if doc.get("gate") != gate(cases) or doc.get("counts") != counts(cases):
        raise ReportError("%s: stored gate or counts contradict the case records" % path)
    return doc["run"], cases


def _xml_text(text: str) -> str:
    return _NOT_XML.sub("?", text)


def junit(meta: Dict[str, Any], cases: List[CaseResult]) -> bytes:
    suite = ET.Element("testsuite", name="%s-%s" % (meta.get("suite", ""), meta.get("backend", "")),
                       tests=str(len(cases)),
                       failures=str(sum(1 for c in cases if c.verdict.is_red)),
                       skipped=str(sum(1 for c in cases if c.verdict is Verdict.FILTERED)))
    for c in cases:
        tc = ET.SubElement(suite, "testcase", name=c.id, classname=c.backend,
                           time="%.3f" % (sum(a.invocation.wall_us for a in c.attempts) / 1e6))
        if c.verdict.is_red:
            ET.SubElement(tc, "failure", message=c.status.value).text = _xml_text(c.detail)
        elif c.verdict is Verdict.FILTERED:
            ET.SubElement(tc, "skipped", message=_xml_text(c.detail))
    return ET.tostring(suite, encoding="utf-8", xml_declaration=True)


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
        except (ValueError, KeyError) as e:
            rows.append("| %s | | error | | | | %s |" % (path.parent, e))
            continue
        n = counts(cases)
        rows.append("| %s/%s | %s | %s | %d | %d | %d | %d |" % (
            meta.get("suite"), meta.get("backend"), meta.get("scope"), gate(cases),
            n["as_expected"], n["flaked"], n["filtered"],
            n["unexpected_failure"] + n["unexpected_pass"] + n["error"]))
    return "\n".join(rows) + "\n" if found else "no conformance results under %s\n" % root
