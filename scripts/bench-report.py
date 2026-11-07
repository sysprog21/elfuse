#!/usr/bin/env python3
"""Render an advisory PR comment from a bench-compare JSON report.

The input artifact comes from an unprivileged pull-request workflow. Treat it
strictly as untrusted data: validate its schema and values, recompute every
ratio, escape metric names, and never execute anything from the artifact.

An empty output means every comparable metric was inside the threshold and the
caller must not create or update a comment.
"""

from __future__ import annotations

import argparse
import html
import json
import math
import pathlib
import sys

MAX_METRICS = 256
MAX_METRIC_NAME = 160
MAX_REPORT_BYTES = 64 * 1024


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
    number = float(value)
    if not math.isfinite(number):
        raise ReportError(f"{field} must be finite")
    return number


def metric_name(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_METRIC_NAME:
        raise ReportError("metric name must be a non-empty short string")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ReportError(f"metric name contains control characters: {value!r}")
    return value


def markdown_cell(value: str) -> str:
    return (html.escape(value, quote=False).replace("|", "\\|")
            .replace("`", "&#96;"))


def display_number(value: float) -> str:
    return f"{value:.6g}"


def load_report(
    path: pathlib.Path, *, expected_environment: str
) -> list[tuple[str, float, float]]:
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
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportError(f"cannot read report {path}: {exc}") from exc

    if not isinstance(document, dict):
        raise ReportError("top-level report must be an object")
    schema_version = document.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != 1:
        raise ReportError("unsupported schema_version")
    if document.get("environment") != expected_environment:
        raise ReportError(
            f"expected environment {expected_environment!r}, got "
            f"{document.get('environment')!r}"
        )
    if document.get("direction") != "lower-is-better":
        raise ReportError("unsupported metric direction")

    metrics = document.get("metrics")
    if not isinstance(metrics, list):
        raise ReportError("metrics must be an array")
    if len(metrics) > MAX_METRICS:
        raise ReportError(f"metrics exceeds the {MAX_METRICS}-item limit")

    parsed: list[tuple[str, float, float]] = []
    seen: set[str] = set()
    for index, item in enumerate(metrics):
        if not isinstance(item, dict):
            raise ReportError(f"metrics[{index}] must be an object")
        name = metric_name(item.get("metric"))
        if name in seen:
            raise ReportError(f"duplicate metric: {name}")
        seen.add(name)
        baseline = finite_number(item.get("baseline"),
                                 field=f"{name}.baseline")
        current = finite_number(item.get("current"),
                                field=f"{name}.current")
        if baseline <= 0:
            raise ReportError(f"{name}.baseline must be greater than zero")
        if current < 0:
            raise ReportError(f"{name}.current must be non-negative")
        parsed.append((name, baseline, current))
    return sorted(parsed)


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
    metrics: list[tuple[str, float, float]], *, threshold: float,
    environment: str
) -> str:
    regressions: list[tuple[str, float, float, float]] = []
    improvements: list[tuple[str, float, float, float]] = []
    for name, baseline, current in metrics:
        change = current / baseline - 1.0
        row = (name, baseline, current, change)
        if change > threshold:
            regressions.append(row)
        elif change < -threshold:
            improvements.append(row)

    if not regressions and not improvements:
        return ""

    threshold_text = f"{threshold:.0%}"
    lines = [
        f"## Benchmark changes outside ±{threshold_text}",
        "",
        f"Compared `{environment}` with the checked-in baseline. "
        "Lower is better.",
    ]
    if regressions:
        lines.extend(["", *section("Regressions", regressions)])
    if improvements:
        lines.extend(["", *section("Improvements", improvements)])
    return "\n".join(lines) + "\n"


def non_negative_finite_fraction(value: str) -> float:
    try:
        fraction = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be a finite, non-negative fraction"
        ) from exc
    if not math.isfinite(fraction) or fraction < 0:
        raise argparse.ArgumentTypeError(
            "must be a finite, non-negative fraction"
        )
    return fraction


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--environment", default="elfuse-aarch64")
    parser.add_argument("--threshold", type=non_negative_finite_fraction,
                        default=0.20)
    args = parser.parse_args()

    try:
        metrics = load_report(args.report,
                              expected_environment=args.environment)
        comment = render(metrics, threshold=args.threshold,
                         environment=args.environment)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(comment, encoding="utf-8")
    except (OSError, ReportError) as exc:
        print(f"bench-report: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
