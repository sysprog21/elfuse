#!/usr/bin/env python3
"""Render an advisory PR comment from a bench-compare JSON report.

The input artifact comes from an unprivileged pull-request workflow. Treat it
strictly as untrusted data: validate its schema and values, escape metric
names, and never execute anything from the artifact.

The artifact supplies only the measured values. The baseline and the threshold
come from this checkout, which the workflow takes from the default branch, so a
pull request that edits tests/bench-baseline.json is still compared with the
baseline already merged. A baseline metric the artifact lacks is listed as a
failure. The comment text always goes to --output; stdout gets "changes" when
the comment lists anything, or "clean" when every metric was measured and is
inside the threshold, in which case the caller only updates an earlier comment.

A schema 3 report comes from bench-compare.py --paired and carries the
per-round values of a base build and a head build measured in the same job.
The reporter recomputes each verdict from those values with
bench-compare.py's paired_verdict, so the comment and the job log agree, and
renders one table of every metric. With no threshold set, the table carries
ratios and intervals and no slower or faster verdict. Its stdout is "changes"
when a metric is slower, faster or lost a head value in some round, and
"clean" otherwise. A metric missing on both sides stays clean, because the
head build did not cause it.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_compare():
    """Load bench-compare.py, whose hyphenated name cannot be imported."""
    path = ROOT / "scripts" / "bench-compare.py"
    spec = importlib.util.spec_from_file_location("bench_compare", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


compare = load_compare()
MAX_ROUNDS = compare.MAX_ROUNDS
MAX_METRICS = compare.MAX_METRICS
MAX_METRIC_NAME = compare.MAX_METRIC_NAME
MAX_REPORT_BYTES = compare.MAX_REPORT_BYTES


class ReportError(ValueError):
    """The report is not safe or usable as benchmark data."""


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReportError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> None:
    raise ReportError(f"non-finite JSON value: {value}")


def finite_number(value: object, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReportError(f"{field} must be a number")
    try:
        number = float(value)
    except OverflowError as exc:
        raise ReportError(f"{field} must be finite") from exc
    if not math.isfinite(number):
        raise ReportError(f"{field} must be finite")
    return number


def metric_name(value: object) -> str:
    error = compare.metric_name_error(value)
    if error is not None:
        raise ReportError(error)
    return value


def markdown_cell(value: str) -> str:
    """Escape a name for a code span in a table cell, which shows entities
    literally."""
    return value.replace("|", "\\|").replace("`", "'")


def display_number(value: float) -> str:
    return f"{value:.6g}"


def read_report(path: pathlib.Path) -> dict:
    """Parse the report file into a JSON object, before any schema check."""
    try:
        if path.stat().st_size > MAX_REPORT_BYTES:
            raise ReportError(
                f"report exceeds the {MAX_REPORT_BYTES}-byte limit"
            )
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_json_constant,
        )
    except FileNotFoundError as exc:
        raise ReportError(f"missing report: {path}") from exc
    except ReportError:
        raise
    # ValueError covers JSONDecodeError, UnicodeDecodeError and the int
    # conversion limit json.loads hits on an integer over 4300 digits.
    except (OSError, ValueError, RecursionError) as exc:
        raise ReportError(f"cannot read report {path}: {exc}") from exc

    if not isinstance(document, dict):
        raise ReportError("top-level report must be an object")
    return document


def schema_version(document: dict) -> object:
    version = document.get("schema_version")
    return None if isinstance(version, bool) else version


def check_header(document: dict, *, version: int,
                 expected_environment: str) -> None:
    if schema_version(document) != version:
        raise ReportError("unsupported schema_version")
    if document.get("environment") != expected_environment:
        raise ReportError(
            f"expected environment {expected_environment!r}, got "
            f"{document.get('environment')!r}"
        )
    if document.get("direction") != "lower-is-better":
        raise ReportError("unsupported metric direction")


def load_report(document: dict, *, expected_environment: str
                ) -> tuple[dict[str, float], list[str]]:
    """Return the measured value of each metric in a schema 2 report, and
    the metrics whose measurement failed."""
    check_header(document, version=2,
                 expected_environment=expected_environment)

    values = document.get("current")
    if not isinstance(values, dict):
        raise ReportError("current must be an object")
    if len(values) > MAX_METRICS:
        raise ReportError(f"current exceeds the {MAX_METRICS}-item limit")
    current: dict[str, float] = {}
    for key, value in values.items():
        name = metric_name(key)
        number = finite_number(value, field=f"{name}.current")
        if number < 0:
            raise ReportError(f"{name}.current must be non-negative")
        current[name] = number

    failed = document.get("failed")
    if not isinstance(failed, list):
        raise ReportError("failed must be a list")
    if len(failed) > MAX_METRICS:
        raise ReportError(f"failed exceeds the {MAX_METRICS}-item limit")
    names = [metric_name(value) for value in failed]
    if len(set(names)) != len(names):
        raise ReportError("failed lists a metric twice")
    if set(names) & set(current):
        raise ReportError("a metric is both measured and failed")
    return current, names


def load_paired_report(document: dict, *, expected_environment: str
                       ) -> dict[str, tuple[list[float | str | None],
                                            list[float | str | None]]]:
    """Return the base and head values of each metric in a schema 3
    report, one per round, None where the round produced no value and
    compare.SKIPPED where it skipped the metric's tier."""
    check_header(document, version=3,
                 expected_environment=expected_environment)
    rounds = document.get("rounds")
    if isinstance(rounds, bool) or not isinstance(rounds, int) \
            or not 1 <= rounds <= MAX_ROUNDS:
        raise ReportError(f"rounds must be an integer from 1 to {MAX_ROUNDS}")
    entries = document.get("metrics")
    if not isinstance(entries, dict) or not entries:
        raise ReportError("metrics must be a non-empty object")
    if len(entries) > MAX_METRICS:
        raise ReportError(f"metrics exceeds the {MAX_METRICS}-item limit")
    metrics = {}
    for key, entry in entries.items():
        name = metric_name(key)
        if not isinstance(entry, dict) or set(entry) != {"base", "head"}:
            raise ReportError(f"{name} must hold exactly base and head")
        sides = []
        for side in ("base", "head"):
            values = entry[side]
            if not isinstance(values, list) or len(values) != rounds:
                raise ReportError(
                    f"{name}.{side} must list one value per round")
            parsed = []
            for value in values:
                if value is None or value == compare.SKIPPED:
                    parsed.append(value)
                    continue
                number = finite_number(value, field=f"{name}.{side}")
                if number < 0:
                    raise ReportError(f"{name}.{side} must be non-negative")
                parsed.append(number)
            sides.append(parsed)
        metrics[name] = (sides[0], sides[1])
    return metrics


def percent(ratio: float) -> str:
    return f"{ratio - 1.0:+.1%}"


def render_paired(
    metrics: dict[str, tuple[list[float | str | None], list[float | str | None]]],
    *, threshold: float | None, environment: str
) -> tuple[str, bool]:
    """Return the paired comment text and whether it lists any change."""
    judged = []
    for name, (base, head) in metrics.items():
        verdict = compare.paired_verdict(name, base, head,
                                         threshold=threshold)
        judged.append((compare.VERDICTS.index(verdict["verdict"]), name,
                       verdict))
    judged.sort(key=lambda item: item[:2])
    listed = any(v["verdict"] in compare.LISTED for _, _, v in judged)
    rounds = max((len(base) for base, _ in metrics.values()), default=0)

    if threshold is None:
        rule = ("No threshold is set yet, so no metric gets a slower or "
                "faster verdict.")
    else:
        rule = ("A metric is slower or faster only when the 95% interval "
                "of its median head/base ratio excludes 1 and the median "
                f"is past ±{compare.threshold_text(threshold)}.")
    verdicts = {v["verdict"] for _, _, v in judged}
    if listed:
        title = "## Benchmark: head vs base commit"
    elif "no significant change" not in verdicts:
        title = "## Benchmark: head vs base commit, no verdicts"
    elif verdicts <= {"no significant change", "no verdict"}:
        title = "## Benchmark: no significant change"
    else:
        title = "## Benchmark: head vs base commit"
    lines = [
        title,
        "",
        f"Measured `{environment}` at the head commit and at the base "
        f"commit, in {rounds} alternating pair(s). Lower is better. "
        + rule + " Lost counts the rounds that lost only the base or only "
        "the head value; Change is the median of the per-pair ratios, not "
        "the ratio of the two medians.",
        "",
        "| Metric | Pairs | Lost base/head | Base median | Head median "
        "| Change | 95% interval | Verdict |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for _, name, v in judged:
        cells = [
            f"`{markdown_cell(name)}`",
            str(v["pairs"]),
            f"{v['base_lost']}/{v['head_lost']}",
            "-" if v["base"] is None else display_number(v["base"]),
            "-" if v["head"] is None else display_number(v["head"]),
            "-" if v["ratio"] is None else percent(v["ratio"]),
            "-" if v["low"] is None
            else f"{percent(v['low'])} to {percent(v['high'])}",
            v["verdict"],
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n", listed


def load_baseline(path: pathlib.Path, *, environment: str) -> dict[str, float]:
    """Return the trusted baseline column for environment."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"),
                              object_pairs_hook=unique_object)
        column = document["environments"][environment]
        return compare.flatten(column, source=f"baseline.{environment}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ReportError(f"cannot use baseline {path}: {exc}") from exc


def match(baseline: dict[str, float], current: dict[str, float],
          failed: list[str]
          ) -> tuple[list[tuple[str, float, float]],
                     list[tuple[str, float | None]]]:
    """Pair each baseline metric with its measured value, or list it as
    missing. A failed metric is missing even without a baseline; a measured
    metric with no baseline has nothing to compare."""
    compared: list[tuple[str, float, float]] = []
    missing: list[tuple[str, float | None]] = []
    for name in sorted(baseline):
        if name not in current:
            missing.append((name, baseline[name]))
        elif baseline[name] <= 0:
            raise ReportError(f"{name}.baseline must be greater than zero")
        else:
            compared.append((name, baseline[name], current[name]))
    missing.extend((name, None) for name in sorted(set(failed) - set(baseline)))
    return compared, missing


def section(
    title: str, rows: list[tuple[str, float, float, float]]
) -> list[str]:
    rendered = [
        f"### {title}",
        "",
        "| Metric | Baseline | Current | Change |",
        "| --- | ---: | ---: | ---: |",
    ]
    for name, baseline, current, change in rows:
        rendered.append(
            f"| `{markdown_cell(name)}` | {display_number(baseline)} | "
            f"{display_number(current)} | {change:+.1%} |"
        )
    return rendered


def render(
    metrics: list[tuple[str, float, float]],
    missing: list[tuple[str, float | None]],
    *, threshold: float, environment: str
) -> tuple[str, bool]:
    """Return the comment text and whether it lists anything."""
    regressions: list[tuple[str, float, float, float]] = []
    improvements: list[tuple[str, float, float, float]] = []
    for name, baseline, current in metrics:
        change = current / baseline - 1.0
        row = (name, baseline, current, change)
        if change > threshold:
            regressions.append(row)
        elif change < -threshold:
            improvements.append(row)

    threshold_text = f"{threshold:.0%}"
    if not regressions and not improvements and not missing:
        return (f"No benchmark metric is outside ±{threshold_text} of the "
                "default branch's baseline at this commit.\n", False)

    lines = [
        f"## Benchmark changes outside ±{threshold_text}",
        "",
        f"Compared `{environment}` with the default branch's baseline. "
        "Lower is better.",
    ]
    if regressions:
        lines.extend(["", *section("Regressions", regressions)])
    if missing:
        lines.extend([
            "",
            "### Missing measurements",
            "",
            "The run produced no value for these metrics.",
            "",
            "| Metric | Baseline |",
            "| --- | ---: |",
        ])
        for name, baseline in missing:
            shown = "-" if baseline is None else display_number(baseline)
            lines.append(f"| `{markdown_cell(name)}` | {shown} |")
    if improvements:
        lines.extend(["", *section("Improvements", improvements)])
    return "\n".join(lines) + "\n", True


def self_test() -> int:
    """Check the artifact parser and the comparison on fixed inputs."""
    import tempfile

    env = "elfuse-aarch64"
    head = ('{"schema_version": 2, "environment": "elfuse-aarch64", '
            '"direction": "lower-is-better", "failed": [], "current": ')
    rejected = {
        "schema 1": head.replace('": 2', '": 1') + '{"a.b": 1}}',
        "duplicate key": head + '{"a.b": 1, "a.b": 2}}',
        "NaN": head + '{"a.b": NaN}}',
        "overflow": head + '{"a.b": 1e999}}',
        "negative": head + '{"a.b": -1}}',
        "bidi name": head + '{"a\u202eb": 1}}',
        "surrogate name": head + '{"a\\ud800": 1}}',
        "huge integer": head + '{"a.b": 1' + "0" * 5000 + '}}',
        "wrong environment": head.replace(env, "native") + '{"a.b": 1}}',
        "measured and failed": head.replace('[]', '["a.b"]') + '{"a.b": 1}}',
    }
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "report.json"
        for label, text in rejected.items():
            path.write_text(text, encoding="utf-8")
            try:
                load_report(read_report(path), expected_environment=env)
                failures.append(f"accepted {label}")
            except ReportError:
                pass
        path.write_text(head + '{"x.slow": 13, "x.same": 10, "x.new": 1}}',
                        encoding="utf-8")
        current, failed = load_report(read_report(path),
                                      expected_environment=env)
    baseline = {"x.slow": 10.0, "x.same": 10.0, "x.gone": 5.0}
    compared, missing = match(baseline, current, failed)
    text, listed = render(compared, missing, threshold=0.2, environment=env)
    if not listed or "`x.slow`" not in text or "`x.gone`" not in text \
            or "`x.same`" in text or "x.new" in text:
        failures.append("regression and missing rows not rendered as expected")
    _, listed = render(*match({"x.same": 10.0}, current, failed),
                       threshold=0.2, environment=env)
    if listed:
        failures.append("an unchanged metric listed changes")
    text, listed = render(*match({"x.same": 10.0}, current, ["x.err"]),
                          threshold=0.2, environment=env)
    if not listed or "| `x.err` | - |" not in text:
        failures.append("a failed metric with no baseline was not listed")
    try:
        match({"x.same": 0.0}, current, failed)
        failures.append("accepted a zero baseline")
    except ReportError:
        pass
    failures.extend(paired_self_test())
    for failure in failures:
        print(f"bench-report: self-test: {failure}", file=sys.stderr)
    return 1 if failures else 0


def paired_self_test() -> list[str]:
    """Check the paired verdicts, the schema 3 parser, and one
    bench-compare.py --paired run read back by the reporter."""
    import subprocess
    import tempfile

    failures = []
    base = [10.0] * 8

    def verdict(head, name="x.y", base=base):
        return compare.paired_verdict(name, base, head,
                                      threshold=0.1)["verdict"]

    cases = {
        "a steady 30% slowdown":
            ([13.0, 13.1, 12.9, 13.0, 13.2, 12.8, 13.0, 13.1], "slower"),
        "a steady 30% speedup":
            ([7.0, 7.1, 6.9, 7.0, 7.2, 6.8, 7.0, 7.1], "faster"),
        "noise around 1":
            ([9.7, 10.3, 9.9, 10.1, 10.2, 9.8, 10.0, 10.0],
             "no significant change"),
        "a median past the threshold with an interval across 1":
            ([5.0, 6.0, 7.0, 12.5, 13.0, 16.0, 17.0, 18.0],
             "no significant change"),
        "a median below the threshold with an interval across 1":
            ([2.0, 3.0, 4.0, 7.5, 8.0, 11.0, 12.0, 13.0],
             "no significant change"),
        "a steady 2% slowdown, inside the threshold":
            ([10.2] * 8, "no significant change"),
        "a head value lost in one round":
            ([13.0, None, 13.0, 13.0, 13.0, 13.0, 13.0, 13.0],
             "lost on head"),
        "no head value": ([None] * 8, "lost on head"),
        "a zero head value": ([0.0] + [7.0] * 7, "lost on head"),
    }
    for label, (head, expected) in cases.items():
        got = verdict(head)
        if got != expected:
            failures.append(f"{label}: expected {expected}, got {got}")
    lost_base = [None] + [10.0] * 7
    if verdict([13.0] * 8, base=lost_base) != "slower":
        failures.append("a base value lost in one round blocked a verdict")
    if verdict([13.0] * 8, base=[10.0] * 5 + [None] * 3) != "too few pairs":
        failures.append("five usable pairs got a verdict")
    if verdict([13.0] * 8, base=[10.0] * 6 + [None] * 2) != "slower":
        failures.append("six steady pairs got no verdict")
    for ratios, expected in (([1, 2, 3, 4, 5], None), ([1, 2, 3, 4, 5, 6],
                             (1, 6)), (list(range(1, 21)), (6, 15))):
        got = compare.median_interval([float(r) for r in ratios])
        if got != expected:
            failures.append(f"interval of {len(ratios)} ratios was {got}, "
                            f"expected {expected}")
    if verdict([None] * 8, base=[None] * 8) != "no result":
        failures.append("a metric missing on both sides got a verdict")
    counts = compare.paired_verdict("x.y", lost_base, [13.0] * 7 + [None],
                                    threshold=0.1)
    if (counts["base_lost"], counts["head_lost"]) != (1, 1):
        failures.append(f"lost rounds counted as {counts['base_lost']}"
                        f"/{counts['head_lost']}")
    if compare.paired_verdict("x.y", base, [13.0] * 8,
                              threshold=None)["verdict"] != "no threshold":
        failures.append("a slowdown got a verdict with no threshold")
    if verdict([20.0] * 8, name="applications.make_ms") != "no verdict":
        failures.append("make_ms got a verdict")
    if verdict([20.0], base=[10.0]) != "too few pairs":
        failures.append("one pair got a verdict")
    zero = compare.paired_verdict("x.y", [0.0] * 8, [20.0] * 8,
                                  threshold=0.1)
    if (zero["verdict"], zero["base_lost"]) != ("no result", 8):
        failures.append(f"a zero base gave {zero['verdict']} with "
                        f"{zero['base_lost']} lost base value(s)")
    both = compare.paired_verdict("x.y", [0.0] + [10.0] * 7,
                                  [None] + [13.0] * 7, threshold=0.1)
    if (both["verdict"], both["base_lost"], both["head_lost"]) \
            != ("slower", 0, 0):
        failures.append("a zero base with no head value was not missing "
                        f"on both sides: {both['verdict']}, "
                        f"{both['base_lost']}/{both['head_lost']}")
    skips = {
        "a head-only skip next to a failed base": (
            [None] + [10.0] * 7, [compare.SKIPPED] + [10.0] * 7,
            ("lost on head", 0, 1)),
        "a skip on both sides": (
            [compare.SKIPPED] + [10.0] * 7, [compare.SKIPPED] + [10.0] * 7,
            ("no significant change", 0, 0)),
        "a skipped base next to a failed head": (
            [compare.SKIPPED] + [10.0] * 7, [None] + [10.0] * 7,
            ("lost on head", 0, 1)),
        "a base-only skip": (
            [compare.SKIPPED] + [10.0] * 7, [10.0] * 8,
            ("no significant change", 1, 0)),
    }
    for label, (skip_base, skip_head, expected) in skips.items():
        got = compare.paired_verdict("x.y", skip_base, skip_head,
                                     threshold=0.1)
        if (got["verdict"], got["base_lost"], got["head_lost"]) != expected:
            failures.append(f"{label} gave {got['verdict']}, "
                            f"{got['base_lost']}/{got['head_lost']}")
    lost = compare.paired_verdict("x.y", base, [13.0] * 7 + [None],
                                  threshold=0.1)
    if lost["verdict"] != "lost on head" or lost["low"] is None:
        failures.append("a lost head value blanked the remaining pairs")

    env = "elfuse-aarch64"
    head = ('{"schema_version": 3, "environment": "elfuse-aarch64", '
            '"direction": "lower-is-better", "rounds": 2, "metrics": ')
    rejected = {
        "short list": head + '{"a.b": {"base": [1], "head": [1, 1]}}}',
        "extra key": head + '{"a.b": {"base": [1, 1], "head": [1, 1], '
                            '"x": 1}}}',
        "string value": head + '{"a.b": {"base": ["1", 1], "head": [1, 1]}}}',
        "negative": head + '{"a.b": {"base": [-1, 1], "head": [1, 1]}}}',
        "zero rounds": head.replace('"rounds": 2', '"rounds": 0') + '{}}',
        "boolean rounds":
            head.replace('"rounds": 2', '"rounds": true') + '{}}',
        "too many rounds":
            head.replace('"rounds": 2', f'"rounds": {MAX_ROUNDS + 1}')
            + '{}}',
        "wrong environment": head.replace(env, "native") + '{}}',
        "no metrics": head + '{}}',
        "bidi name": head + '{"a\u202eb": {"base": [1, 1], "head": [1, 1]}}}',
        "surrogate name":
            head + '{"a\\ud800": {"base": [1, 1], "head": [1, 1]}}}',
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "report.json"
        for label, text in rejected.items():
            path.write_text(text, encoding="utf-8")
            try:
                load_paired_report(read_report(path),
                                   expected_environment=env)
                failures.append(f"accepted paired {label}")
            except ReportError:
                pass
        path.write_text(head + '{"a.b": {"base": [1, null], '
                        '"head": [null, 2.5]}}}', encoding="utf-8")
        try:
            parsed = load_paired_report(read_report(path),
                                        expected_environment=env)
            if parsed != {"a.b": ([1.0, None], [None, 2.5])}:
                failures.append(f"paired nulls parsed as {parsed}")
        except ReportError as exc:
            failures.append(f"rejected paired nulls: {exc}")

        # MAX_ROUNDS rounds per side through bench-compare.py:
        # lat_syscall.null 30% slower, lat_fs.create failed in every head
        # round, make_ms twice as slow, and head round 0 omitting
        # lat_fs.delete. The oci tier (meta.oci_skipped) is skipped by both
        # rounds of pair 0, by the head round of pair 1, by the base round
        # of pair 2, and by the head round of pair 3, whose base round
        # failed the pull; the skipped rounds of pairs 0 and 2 still carry
        # values.
        rounds = {"base": [], "head": []}
        for index in range(MAX_ROUNDS):
            for side, null, make in (("base", 0.20, 1000.0),
                                     ("head", 0.26, 2000.0)):
                create = ({"median": 5.0 + index / 100} if side == "base"
                          else {"status": "ERR"})
                document = {
                    "meta": {"env": env},
                    "lmbench": {
                        "lat_syscall": {
                            "null": {"median": null + index / 1000}},
                        "lat_fs": {"create": create},
                    },
                    "applications": {"make_ms": {"median": make + index}},
                }
                if side == "base" or index:
                    document["lmbench"]["lat_fs"]["delete"] = {
                        "median": 3.0 + index / 100}
                if (index, side) in ((0, "base"), (0, "head"), (1, "head"),
                                     (2, "base"), (3, "head")):
                    document["meta"]["oci_skipped"] = "pull failed"
                if (index, side) == (3, "base"):
                    document["oci"] = {"pull": {"status": "ERR"}}
                elif (index, side) not in ((0, "base"), (1, "head"),
                                           (3, "head")):
                    document["oci"] = {"pull": {"median": 100.0 + index}}
                file = pathlib.Path(tmp) / f"{side}-{index}.json"
                file.write_text(json.dumps(document), encoding="utf-8")
                rounds[side].append(str(file))
        artifact = pathlib.Path(tmp) / "paired.json"
        run = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bench-compare.py"),
             "--paired", "--threshold", "0.1", "--report-json",
             str(artifact), "--base", *rounds["base"],
             "--head", *rounds["head"]],
            capture_output=True, text=True, check=False)
        if run.returncode != 0:
            failures.append(f"bench-compare --paired exited "
                            f"{run.returncode}: {run.stderr.strip()}")
        else:
            if artifact.stat().st_size > MAX_REPORT_BYTES:
                failures.append("paired artifact is over the size limit")
            text, listed = render_paired(
                load_paired_report(read_report(artifact),
                                   expected_environment=env),
                threshold=0.1, environment=env)
            for row in (f"| `lmbench.lat_syscall.null` | {MAX_ROUNDS} | 0/0 |",
                        f"| `lmbench.lat_fs.create` | 0 | 0/{MAX_ROUNDS} |",
                        f"| `applications.make_ms` | {MAX_ROUNDS} | 0/0 |",
                        f"| `oci.pull` | {MAX_ROUNDS - 4} | 1/2 |",
                        f"| `lmbench.lat_fs.delete` | {MAX_ROUNDS - 1} "
                        "| 0/1 |"):
                if row not in text:
                    failures.append(f"paired table lacks {row!r}")
            if not listed or "| slower |" not in text \
                    or "| lost on head |" not in text \
                    or "| no verdict |" not in text:
                failures.append("paired verdicts not rendered as expected")
            if text.index("lat_syscall") > text.index("lat_fs"):
                failures.append("a slower row did not sort first")
            if "| Base median | Head median |" not in text:
                failures.append("paired columns not labelled as medians")
        text, listed = render_paired({"a.b": ([10.0] * 6, [10.0] * 6)},
                                     threshold=0.1, environment=env)
        if listed or "no significant change\n" not in text:
            failures.append("an unchanged paired metric not reported as "
                            "no significant change")
        unreadable = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bench-compare.py"),
             "--paired", "--base", tmp, "--head", tmp],
            capture_output=True, text=True, check=False)
        many = [rounds["base"][0]] * (MAX_ROUNDS + 1)
        too_many = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bench-compare.py"),
             "--paired", "--base", *many, "--head", *many],
            capture_output=True, text=True, check=False)
        if too_many.returncode != 2:
            failures.append("bench-compare --paired took more rounds than "
                            "the reporter accepts")
        if unreadable.returncode != 2 or "Traceback" in unreadable.stderr:
            failures.append("an unreadable round file did not exit 2")
        huge = "1" + "0" * 400
        for label, text in (
                ("median", f'{{"lmbench": {{"a": {{"median": {huge}}}}}}}'),
                ("bare value", f'{{"lmbench": {{"a": {huge}}}}}')):
            overflow = pathlib.Path(tmp) / "overflow.json"
            overflow.write_text(
                f'{{"meta": {{"env": "{env}"}}, ' + text[1:],
                encoding="utf-8")
            for argv in (["--paired", "--base", str(overflow),
                          "--head", str(overflow)],
                         ["--results", str(overflow)]):
                run = subprocess.run(
                    [sys.executable, str(ROOT / "scripts" /
                                         "bench-compare.py"), *argv],
                    capture_output=True, text=True, check=False)
                if run.returncode != 2 or "Traceback" in run.stderr:
                    failures.append(f"a {label} too large for a float "
                                    f"did not exit 2 with {argv[0]}")
        empty = pathlib.Path(tmp) / "empty.json"
        empty.write_text(json.dumps({"meta": {"env": env}}),
                         encoding="utf-8")
        no_metrics = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bench-compare.py"),
             "--paired", "--base", rounds["base"][0], "--head", str(empty)],
            capture_output=True, text=True, check=False)
        if no_metrics.returncode != 2:
            failures.append("bench-compare --paired took a head round with "
                            "no metric")
        native = pathlib.Path(tmp) / "native.json"
        native.write_text(json.dumps({
            "meta": {"env": "native"},
            "lmbench": {"lat_syscall": {"null": {"median": 0.2}}}}),
            encoding="utf-8")
        compare_py = str(ROOT / "scripts" / "bench-compare.py")
        for label, argv in (
                ("rounds from different environments",
                 ["--paired", "--base", rounds["base"][0],
                  "--head", str(native)]),
                ("unequal --base and --head counts",
                 ["--paired", "--base", *rounds["base"][:2],
                  "--head", rounds["head"][0]]),
                ("--base and --head without --paired",
                 ["--base", rounds["base"][0],
                  "--head", rounds["head"][0]])):
            bad = subprocess.run([sys.executable, compare_py, *argv],
                                 capture_output=True, text=True, check=False)
            if bad.returncode != 2 or "Traceback" in bad.stderr:
                failures.append(f"bench-compare took {label}")
        text, _ = render_paired(
            {"a.b": ([10.0] * 6, [10.0] * 6),
             "a.c": ([None] * 6, [None] * 6)},
            threshold=0.1, environment=env)
        if not text.startswith("## Benchmark: head vs base commit\n"):
            failures.append("a mix with no result claimed no significant "
                            "change")
        text, listed = render_paired(
            {"a.b": ([10.0] * 3 + [None] * 3, [13.0] * 6)},
            threshold=0.1, environment=env)
        if listed or not text.startswith("## Benchmark: head vs base "
                                         "commit, no verdicts\n"):
            failures.append("too few pairs listed changes or claimed no "
                            "significant change")
        _, listed = render_paired(
            {"a.b": ([10.0] * 6, [10.0] * 5 + [None])},
            threshold=0.1, environment=env)
        if not listed:
            failures.append("a lost head value did not list changes")
        _, listed = render_paired({"a.b": ([None] * 6, [None] * 6)},
                                  threshold=0.1, environment=env)
        if listed:
            failures.append("a metric missing on both sides listed changes")
        big = pathlib.Path(tmp) / "big.json"
        big.write_text(json.dumps({"meta": {"env": env}, "lmbench": {
            f"m{index}": {"median": 1 / 3 + index}
            for index in range(MAX_METRICS)
        }}), encoding="utf-8")
        oversized = pathlib.Path(tmp) / "oversized.json"
        many = [str(big)] * MAX_ROUNDS
        too_big = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bench-compare.py"),
             "--paired", "--report-json", str(oversized),
             "--base", *many, "--head", *many],
            capture_output=True, text=True, check=False)
        if too_big.returncode != 2 or oversized.exists():
            failures.append("bench-compare --paired wrote a report over the "
                            "size limit")
        unusable = {
            "more metrics than the reporter takes": {
                f"m{index}": {"median": 1}
                for index in range(MAX_METRICS + 1)},
            "a long metric name": {"x" * MAX_METRIC_NAME: {"median": 1}},
            "a bidi metric name": {"a\u202eb": {"median": 1}},
            "a negative median": {"x": {"median": -1}},
        }
        for label, section in unusable.items():
            empty.write_text(json.dumps({"meta": {"env": env},
                                         "lmbench": section}),
                             encoding="utf-8")
            refused = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "bench-compare.py"),
                 "--paired", "--report-json", str(oversized),
                 "--base", str(empty), "--head", str(empty)],
                capture_output=True, text=True, check=False)
            if refused.returncode != 2 or oversized.exists():
                failures.append(f"bench-compare --paired wrote {label}")
        for flag in (["--results", str(big)], ["--baseline", str(big)],
                     ["--fail-on-missing"]):
            ignored = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "bench-compare.py"),
                 "--paired", *flag, "--base", str(big), "--head", str(big)],
                capture_output=True, text=True, check=False)
            if ignored.returncode != 2:
                failures.append(f"bench-compare --paired took {flag[0]}")
        env_run = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bench-report.py"),
             "--report", str(artifact), "--output", str(path)],
            capture_output=True, text=True, check=False,
            env={**os.environ, "BENCH_REGRESSION_THRESHOLD": "0.37"})
        if env_run.returncode != 0 or "37%" not in path.read_text():
            failures.append("BENCH_REGRESSION_THRESHOLD did not reach the "
                            "comment")
        unset = {key: value for key, value in os.environ.items()
                 if key != "BENCH_REGRESSION_THRESHOLD"}
        for label, run_env in (
                ("unset", unset),
                ("blank", {**unset, "BENCH_REGRESSION_THRESHOLD": " "})):
            unset_run = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "bench-report.py"),
                 "--report", str(artifact), "--output", str(path)],
                capture_output=True, text=True, check=False, env=run_env)
            if unset_run.returncode != 0 \
                    or "| no threshold |" not in path.read_text() \
                    or "| slower |" in path.read_text():
                failures.append(f"a paired report with a threshold {label} "
                                "got verdicts")
            compare_run = subprocess.run(
                [sys.executable, compare_py, "--paired",
                 "--base", rounds["base"][0], "--head", rounds["head"][0]],
                capture_output=True, text=True, check=False, env=run_env)
            if compare_run.returncode != 0 \
                    or "threshold none" not in compare_run.stdout:
                failures.append(f"bench-compare --paired with a threshold "
                                f"{label} did not run without one")
        small = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bench-report.py"),
             "--report", str(artifact), "--output", str(path),
             "--threshold", "0.004"],
            capture_output=True, text=True, check=False)
        if small.returncode != 0 or "±0.4%" not in path.read_text():
            failures.append("a 0.004 threshold was not shown as 0.4%")
        static = pathlib.Path(tmp) / "static.json"
        static.write_text(json.dumps({
            "schema_version": 2, "environment": env,
            "direction": "lower-is-better", "current": {}, "failed": []}),
            encoding="utf-8")
        for value in ("0.37", "not-a-number"):
            static_run = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "bench-report.py"),
                 "--report", str(static), "--output", str(path)],
                capture_output=True, text=True, check=False,
                env={**os.environ, "BENCH_REGRESSION_THRESHOLD": value})
            if static_run.returncode != 0 \
                    or "20%" not in path.read_text():
                failures.append("BENCH_REGRESSION_THRESHOLD="
                                f"{value} reached a schema 2 comment")
        flag_run = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bench-report.py"),
             "--report", str(static), "--output", str(path),
             "--threshold", "0.05"],
            capture_output=True, text=True, check=False)
        if flag_run.returncode != 0 or "5%" not in path.read_text():
            failures.append("--threshold did not reach a schema 2 comment")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--report", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--environment", default="elfuse-aarch64")
    parser.add_argument("--baseline", type=pathlib.Path,
                        default=compare.DEFAULT_BASELINE)
    parser.add_argument("--threshold",
                        type=compare.non_negative_finite_fraction,
                        help="change threshold as a fraction (default 0.20 "
                             "for a schema 2 report; for schema 3, "
                             "BENCH_REGRESSION_THRESHOLD, else none)")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.report is None or args.output is None:
        parser.error("--report and --output are required")

    try:
        document = read_report(args.report)
        if schema_version(document) == 3:
            if args.threshold is None:
                try:
                    args.threshold = compare.env_threshold(
                        blank_is_unset=True)
                except argparse.ArgumentTypeError as exc:
                    raise ReportError(
                        f"BENCH_REGRESSION_THRESHOLD {exc}") from exc
            metrics = load_paired_report(
                document, expected_environment=args.environment)
            comment, listed = render_paired(metrics,
                                            threshold=args.threshold,
                                            environment=args.environment)
        else:
            if args.threshold is None:
                args.threshold = compare.DEFAULT_THRESHOLD
            current, failed = load_report(
                document, expected_environment=args.environment)
            baseline = load_baseline(args.baseline,
                                     environment=args.environment)
            compared, missing = match(baseline, current, failed)
            comment, listed = render(compared, missing,
                                     threshold=args.threshold,
                                     environment=args.environment)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(comment, encoding="utf-8")
    except (OSError, ReportError) as exc:
        print(f"bench-report: {exc}", file=sys.stderr)
        return 2
    print("changes" if listed else "clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
