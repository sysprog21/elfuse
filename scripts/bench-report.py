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
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import pathlib
import sys
import unicodedata

MAX_METRICS = 256
MAX_METRIC_NAME = 160
MAX_REPORT_BYTES = 64 * 1024
ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_compare():
    """Load bench-compare.py, whose hyphenated name cannot be imported."""
    path = ROOT / "scripts" / "bench-compare.py"
    spec = importlib.util.spec_from_file_location("bench_compare", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


compare = load_compare()


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
    if not isinstance(value, str) or not value or len(value) > MAX_METRIC_NAME:
        raise ReportError("metric name must be a non-empty short string")
    # Cf covers the bidi overrides and zero-width characters that could make
    # the rendered comment show a name other than the real one.
    if any(unicodedata.category(char) in ("Cc", "Cf") for char in value):
        raise ReportError(f"metric name contains control characters: {value!r}")
    return value


def markdown_cell(value: str) -> str:
    """Escape a name for a code span in a table cell, which shows entities
    literally."""
    return value.replace("|", "\\|").replace("`", "'")


def display_number(value: float) -> str:
    return f"{value:.6g}"


def load_report(path: pathlib.Path, *, expected_environment: str
                ) -> tuple[dict[str, float], list[str]]:
    """Return the measured value of each metric in the report, and the
    metrics whose measurement failed."""
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
    except (OSError, UnicodeDecodeError, RecursionError,
            json.JSONDecodeError) as exc:
        raise ReportError(f"cannot read report {path}: {exc}") from exc

    if not isinstance(document, dict):
        raise ReportError("top-level report must be an object")
    schema_version = document.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != 2:
        raise ReportError("unsupported schema_version")
    if document.get("environment") != expected_environment:
        raise ReportError(
            f"expected environment {expected_environment!r}, got "
            f"{document.get('environment')!r}"
        )
    if document.get("direction") != "lower-is-better":
        raise ReportError("unsupported metric direction")

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
        "wrong environment": head.replace(env, "native") + '{"a.b": 1}}',
        "measured and failed": head.replace('[]', '["a.b"]') + '{"a.b": 1}}',
    }
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "report.json"
        for label, text in rejected.items():
            path.write_text(text, encoding="utf-8")
            try:
                load_report(path, expected_environment=env)
                failures.append(f"accepted {label}")
            except ReportError:
                pass
        path.write_text(head + '{"x.slow": 13, "x.same": 10, "x.new": 1}}',
                        encoding="utf-8")
        current, failed = load_report(path, expected_environment=env)
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
    for failure in failures:
        print(f"bench-report: self-test: {failure}", file=sys.stderr)
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--report", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--environment", default="elfuse-aarch64")
    parser.add_argument("--baseline", type=pathlib.Path,
                        default=compare.DEFAULT_BASELINE)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.report is None or args.output is None:
        parser.error("--report and --output are required")

    try:
        current, failed = load_report(args.report,
                                      expected_environment=args.environment)
        baseline = load_baseline(args.baseline,
                                 environment=args.environment)
        metrics, missing = match(baseline, current, failed)
        comment, listed = render(metrics, missing,
                                 threshold=compare.DEFAULT_THRESHOLD,
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
