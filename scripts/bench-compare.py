#!/usr/bin/env python3
"""Compare bench-suite results against the checked-in baseline.

Reads build/bench-results.json (tests/bench-suite.sh output) and
tests/bench-baseline.json, prints a per-metric ratio table for the
matching environment column, and exits non-zero when any metric
regresses beyond the threshold (default +20%). The checked-in
qemu-aarch64 column is the same-silicon Linux reference for context.

Usage:
    scripts/bench-compare.py [--results PATH] [--baseline PATH]
                             [--threshold FRACTION] [--report-only]
                             [--fail-on-missing] [--report-json PATH]

Environment:
    BENCH_REGRESSION_THRESHOLD  overrides --threshold (e.g. 0.20)
    BENCH_REPORT_ONLY=1         report regressions but exit 0
"""

from __future__ import annotations

import argparse
import json
import math
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_RESULTS = ROOT / "build" / "bench-results.json"
DEFAULT_BASELINE = ROOT / "tests" / "bench-baseline.json"

SECTIONS = ("lmbench", "applications")


class BenchDataError(ValueError):
    """A benchmark document is valid JSON but has an invalid schema/value."""


def non_negative_finite_fraction(value: str) -> float:
    """Parse a regression threshold without allowing it to disable checks."""
    try:
        fraction = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be a finite, non-negative fraction") from exc
    if not math.isfinite(fraction) or fraction < 0:
        raise argparse.ArgumentTypeError(
            "must be a finite, non-negative fraction")
    return fraction


def flatten(tree: dict, *, source: str) -> dict[str, float]:
    """Flatten a results/baseline document into {dotted-path: median}.

    Result files store {"median": x, "samples": [...]} leaves; baseline
    columns store plain numbers. Both shapes are accepted so a captured
    results file can be pasted into the baseline as-is if desired.
    """
    if not isinstance(tree, dict):
        raise BenchDataError(f"{source} must be an object")
    flat: dict[str, float] = {}

    def walk(prefix: str, node) -> None:
        if isinstance(node, dict):
            if "median" in node:
                value = node["median"]
                if isinstance(value, bool):
                    raise BenchDataError(
                        f"{source}: metric '{prefix}' has a boolean median")
                try:
                    number = float(value)
                except (TypeError, ValueError) as exc:
                    raise BenchDataError(
                        f"{source}: metric '{prefix}' has a non-numeric "
                        "median") from exc
                if not math.isfinite(number):
                    raise BenchDataError(
                        f"{source}: metric '{prefix}' has a non-finite "
                        "median")
                if number < 0:
                    raise BenchDataError(
                        f"{source}: metric '{prefix}' has a negative median")
                flat[prefix] = number
                return
            if "status" in node:
                return
            for key, value in node.items():
                walk(f"{prefix}.{key}" if prefix else key, value)
        elif isinstance(node, (int, float)) and not isinstance(node, bool):
            number = float(node)
            if not math.isfinite(number):
                raise BenchDataError(
                    f"{source}: metric '{prefix}' is non-finite")
            if number < 0:
                raise BenchDataError(
                    f"{source}: metric '{prefix}' is negative")
            flat[prefix] = number
        else:
            raise BenchDataError(
                f"{source}: metric '{prefix}' must be numeric or an object")

    for section in SECTIONS:
        section_tree = tree.get(section, {})
        if not isinstance(section_tree, dict):
            raise BenchDataError(
                f"{source}: section '{section}' must be an object")
        walk(section, section_tree)
    return flat


def load_json(path: pathlib.Path) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"bench-compare: missing {path}", file=sys.stderr)
        raise SystemExit(2)
    except json.JSONDecodeError as exc:
        print(f"bench-compare: invalid JSON in {path}: {exc}",
              file=sys.stderr)
        raise SystemExit(2)
    if not isinstance(document, dict):
        print(f"bench-compare: invalid JSON in {path}: top-level value "
              "must be an object", file=sys.stderr)
        raise SystemExit(2)
    return document


def print_table(rows: list[tuple[str, str, str, str, str]]) -> None:
    widths = [max(len(row[col]) for row in rows) for col in range(5)]
    for row in rows:
        print("  {0:<{w0}}  {1:>{w1}}  {2:>{w2}}  {3:>{w3}}  {4}".format(
            *row, w0=widths[0], w1=widths[1], w2=widths[2], w3=widths[3]))


def write_report(path: pathlib.Path, *, environment: str, threshold: float,
                 metrics: list[dict[str, str | float]]) -> None:
    """Write the data-only artifact consumed by the trusted PR reporter."""
    report = {
        "schema_version": 1,
        "environment": environment,
        "direction": "lower-is-better",
        "threshold": threshold,
        "metrics": metrics,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(report, indent=2, sort_keys=True, allow_nan=False)
            + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError) as exc:
        raise BenchDataError(f"cannot write report {path}: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=pathlib.Path,
                        default=DEFAULT_RESULTS)
    parser.add_argument("--baseline", type=pathlib.Path,
                        default=DEFAULT_BASELINE)
    parser.add_argument(
        "--threshold", type=non_negative_finite_fraction,
        default=os.environ.get("BENCH_REGRESSION_THRESHOLD", "0.20"),
        help="regression threshold as a fraction (default 0.20 = +20%%)")
    parser.add_argument("--report-only", action="store_true",
                        default=os.environ.get("BENCH_REPORT_ONLY") == "1",
                        help="print the report but always exit 0")
    parser.add_argument("--fail-on-missing", action="store_true",
                        help="make missing baseline metrics fail even in "
                             "report-only mode")
    parser.add_argument(
        "--report-json", type=pathlib.Path,
        help="write a data-only comparison report for CI automation")
    args = parser.parse_args()

    results = load_json(args.results)
    baseline = load_json(args.baseline)

    meta = results.get("meta")
    if not isinstance(meta, dict):
        print("bench-compare: results meta must be an object",
              file=sys.stderr)
        return 2
    env = meta.get("env")
    if not isinstance(env, str) or not env.strip():
        print("bench-compare: results file has no non-empty meta.env",
              file=sys.stderr)
        return 2
    env = env.strip()

    environments = baseline.get("environments", {})
    if not isinstance(environments, dict):
        print("bench-compare: baseline environments must be an object",
              file=sys.stderr)
        return 2
    column = environments.get(env)
    if not isinstance(column, dict) or not column:
        print(f"bench-compare: baseline has no usable '{env}' column; "
              "nothing to compare (capture one per the procedure in "
              "tests/bench-suite.sh)", file=sys.stderr)
        return 1 if args.fail_on_missing else 0

    try:
        current = flatten(results, source="results")
        base = flatten(column, source=f"baseline.{env}")
    except BenchDataError as exc:
        print(f"bench-compare: invalid benchmark data: {exc}",
              file=sys.stderr)
        return 2

    regressions: list[str] = []
    missing: list[str] = []
    improvements: list[str] = []
    invalid_baselines: list[str] = []
    comparison_metrics: list[dict[str, str | float]] = []
    rows = [("metric", "baseline", "current", "ratio", "")]
    for metric in sorted(base):
        if metric not in current:
            rows.append((metric, f"{base[metric]:g}", "-", "-",
                         "MISSING (measurement failed)"))
            missing.append(metric)
            continue
        if base[metric] <= 0:
            rows.append((metric, f"{base[metric]:g}",
                         f"{current[metric]:g}", "-",
                         "n/a (baseline must be > 0)"))
            invalid_baselines.append(metric)
            continue
        ratio = current[metric] / base[metric]
        comparison_metrics.append({
            "metric": metric,
            "baseline": base[metric],
            "current": current[metric],
        })
        verdict = ""
        if ratio > 1.0 + args.threshold:
            verdict = f"REGRESSION (> +{args.threshold:.0%})"
            regressions.append(metric)
        elif ratio < 1.0 - args.threshold:
            verdict = "improved"
            improvements.append(metric)
        rows.append((metric, f"{base[metric]:g}", f"{current[metric]:g}",
                     f"{ratio:.2f}x", verdict))
    for metric in sorted(set(current) - set(base)):
        rows.append((metric, "-", f"{current[metric]:g}", "-",
                     "NEW (no baseline)"))

    captured_columns = baseline.get("captured") or {}
    captured = (captured_columns.get(env, {})
                if isinstance(captured_columns, dict) else {})
    if not isinstance(captured, dict):
        print(f"bench-compare: baseline captured.{env} must be an object",
              file=sys.stderr)
        return 2
    print(f"bench-compare: environment '{env}', threshold "
          f"+{args.threshold:.0%}")
    if captured:
        print(f"  baseline captured: {captured.get('date', '?')} on "
              f"{captured.get('host', '?')}")
    print_table(rows)

    if args.report_json is not None:
        try:
            write_report(args.report_json, environment=env,
                         threshold=args.threshold,
                         metrics=comparison_metrics)
        except BenchDataError as exc:
            print(f"bench-compare: {exc}", file=sys.stderr)
            return 2

    # qemu-aarch64 runs a real Linux kernel on the same Apple Silicon host,
    # so it is this project's reference target where native M-series Linux
    # is unavailable. This ratio is informational only.
    for ref in ("qemu-aarch64",):
        if ref == env:
            continue
        ref_column = environments.get(ref)
        if not ref_column:
            continue
        try:
            rbase = flatten(ref_column, source=f"baseline.{ref}")
        except BenchDataError as exc:
            print(f"bench-compare: invalid benchmark data: {exc}",
                  file=sys.stderr)
            return 2
        shared = sorted(set(rbase) & set(current))
        if not shared:
            continue
        print(f"\n  ratio vs {ref} baseline column (informational):")
        rrows = [("metric", ref, env, "ratio", "")]
        for metric in shared:
            if rbase[metric] <= 0:
                rrows.append((metric, f"{rbase[metric]:g}",
                              f"{current[metric]:g}", "-",
                              "n/a (non-positive reference)"))
                continue
            ratio = current[metric] / rbase[metric]
            rrows.append((metric, f"{rbase[metric]:g}",
                          f"{current[metric]:g}", f"{ratio:.2f}x", ""))
        print_table(rrows)

    if improvements:
        print(f"\nimproved beyond threshold: {', '.join(improvements)}")
        print("  (consider refreshing tests/bench-baseline.json so the "
              "gain is locked in)")

    if regressions or missing or invalid_baselines:
        sys.stdout.flush()
        failures = []
        if regressions:
            failures.append(
                f"{len(regressions)} regression(s): "
                f"{', '.join(regressions)}")
        if missing:
            failures.append(
                f"{len(missing)} missing measurement(s): "
                f"{', '.join(missing)}")
        if invalid_baselines:
            failures.append(
                f"{len(invalid_baselines)} invalid baseline metric(s): "
                f"{', '.join(invalid_baselines)}")
        print(f"\nbench-compare: FAIL -- {'; '.join(failures)}",
              file=sys.stderr)
        if invalid_baselines:
            return 2
        if args.report_only and not (args.fail_on_missing and missing):
            print("bench-compare: report-only mode, exiting 0",
                  file=sys.stderr)
            return 0
        return 1

    print("\nbench-compare: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
