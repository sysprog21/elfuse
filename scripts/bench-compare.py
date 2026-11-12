#!/usr/bin/env python3
"""Compare bench-suite results against the checked-in baseline.

Reads build/bench-results.json (tests/bench-suite.sh output) and
tests/bench-baseline.json, prints a per-metric ratio table for the
matching environment column, and exits non-zero when any metric
regresses beyond the threshold (default +20%). The checked-in
qemu-aarch64 column is the same-silicon Linux reference for context.

With --paired it instead compares two builds measured in alternating
rounds: --base and --head each take one results file per round, and the
Nth base file pairs with the Nth head file. For each metric it prints
the median of the head/base ratios of the pairs and a distribution-free
95% interval of that median, and calls the metric slower or faster only
when the interval excludes 1 and the median is past the threshold. Paired mode
has no default threshold: without --threshold or BENCH_REGRESSION_THRESHOLD
it shows ratios and intervals with no verdict. It is advisory and exits 0
on valid input; it exits 2 when an input is unusable or the --report-json
report would exceed 64 KiB, in which case it is not written.

Usage:
    scripts/bench-compare.py [--results PATH] [--baseline PATH]
                             [--threshold FRACTION] [--report-only]
                             [--fail-on-missing] [--report-json PATH]
    scripts/bench-compare.py --paired --base PATH... --head PATH...
                             [--threshold FRACTION] [--report-json PATH]

Environment:
    BENCH_REGRESSION_THRESHOLD  threshold when --threshold is not given
    BENCH_REPORT_ONLY=1         report regressions but exit 0
"""

from __future__ import annotations

import argparse
import json
import math
import os
import pathlib
import statistics
import sys
import unicodedata

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_RESULTS = ROOT / "build" / "bench-results.json"
DEFAULT_BASELINE = ROOT / "tests" / "bench-baseline.json"

SECTIONS = ("lmbench", "applications", "oci")
# scripts/bench-report.py reads this too, from the default branch.
DEFAULT_THRESHOLD = 0.20

# Paired mode. scripts/bench-report.py recomputes the verdicts with these
# from the default branch, so they are constants rather than options.
#
# make_ms samples jump between two levels inside one run (1.51 s to 2.36 s
# in one CI run), so its ratio is shown without a verdict.
NO_VERDICT = frozenset({"applications.make_ms"})
# No interval of a median reaches 95% coverage from fewer pairs: the widest,
# from the smallest to the largest of 5 ratios, covers 93.75%.
MIN_PAIRS = 6
# The most rounds per side, the largest report, the most metrics and the
# longest metric name that bench-report.py accepts.
MAX_ROUNDS = 32
MAX_REPORT_BYTES = 64 * 1024
MAX_METRICS = 256
MAX_METRIC_NAME = 160

VERDICTS = ("slower", "lost on head", "faster", "too few pairs",
            "no threshold", "no verdict", "no result",
            "no significant change")
# The verdicts that make bench-report.py post a new comment.
LISTED = frozenset({"slower", "lost on head", "faster"})
# A round value for a tier the round's meta records as skipped.
SKIPPED = "skipped"


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


def flatten(tree: dict, *, source: str,
            errors: list[str] | None = None) -> dict[str, float]:
    """Flatten a results/baseline document into {dotted-path: median}.

    Result files store {"median": x, "samples": [...]} leaves; baseline
    columns store plain numbers. Both shapes are accepted so a captured
    results file can be pasted into the baseline as-is if desired. The
    path of each {"status": "ERR"} leaf is appended to errors when given.
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
                except (TypeError, ValueError, OverflowError) as exc:
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
                if errors is not None and node["status"] == "ERR":
                    errors.append(prefix)
                return
            for key, value in node.items():
                walk(f"{prefix}.{key}" if prefix else key, value)
        elif isinstance(node, (int, float)) and not isinstance(node, bool):
            try:
                number = float(node)
            except OverflowError as exc:
                raise BenchDataError(
                    f"{source}: metric '{prefix}' is non-finite") from exc
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


def unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def load_json(path: pathlib.Path) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"),
                              object_pairs_hook=unique_object)
    except FileNotFoundError:
        print(f"bench-compare: missing {path}", file=sys.stderr)
        raise SystemExit(2)
    except OSError as exc:
        print(f"bench-compare: cannot read {path}: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except (ValueError, RecursionError) as exc:
        print(f"bench-compare: invalid JSON in {path}: {exc}",
              file=sys.stderr)
        raise SystemExit(2)
    if not isinstance(document, dict):
        print(f"bench-compare: invalid JSON in {path}: top-level value "
              "must be an object", file=sys.stderr)
        raise SystemExit(2)
    return document


def print_table(rows: list[tuple[str, ...]]) -> None:
    """Print rows with the first column left-aligned, the last unpadded and
    the others right-aligned."""
    count = len(rows[0])
    widths = [max(len(row[col]) for row in rows) for col in range(count)]
    for row in rows:
        cells = [row[0].ljust(widths[0])]
        cells.extend(row[col].rjust(widths[col])
                     for col in range(1, count - 1))
        cells.append(row[-1])
        print("  " + "  ".join(cells))


def metric_name_error(name: object) -> str | None:
    """Return why bench-report.py rejects a metric name, or None."""
    if not isinstance(name, str) or not name or len(name) > MAX_METRIC_NAME:
        return "metric name must be a non-empty short string"
    # Cf covers the bidi overrides and zero-width characters that could make
    # the rendered comment show a name other than the real one.
    # Cs is a lone surrogate, which JSON can carry but UTF-8 cannot encode,
    # so the comment could not be written.
    if any(unicodedata.category(char) in ("Cc", "Cf", "Cs") for char in name):
        return f"metric name contains control characters: {name!r}"
    return None


def env_threshold(*, blank_is_unset: bool) -> float | None:
    """Return BENCH_REGRESSION_THRESHOLD as a fraction, or None when unset.

    A workflow line such as BENCH_REGRESSION_THRESHOLD: ${{ vars.X }}
    expands to an empty string while vars.X is unset, so paired mode, which
    ships with no threshold, counts a blank value as unset. The static mode
    keeps rejecting it, as before. Raises argparse.ArgumentTypeError when
    the value is set but not a fraction.
    """
    value = os.environ.get("BENCH_REGRESSION_THRESHOLD")
    if value is None or (blank_is_unset and not value.strip()):
        return None
    return non_negative_finite_fraction(value)


def threshold_text(threshold: float) -> str:
    """Format a threshold as a percentage without rounding it away: an A/A
    threshold is likely sub-percent, and 0.004 would print as 0%."""
    return f"{threshold * 100:g}%"


def median_interval(ratios: list[float]) -> tuple[float, float] | None:
    """Return the k-th smallest and k-th largest ratio, with k the largest
    order that keeps the binomial coverage of the median at 95% or more,
    or None when no order does (below MIN_PAIRS)."""
    n, ordered = len(ratios), sorted(ratios)
    tail, k = 0.0, 0
    for i in range(n // 2):
        tail += math.comb(n, i) / 2 ** n
        if 2 * tail > 0.05:
            break
        k = i + 1
    return (ordered[k - 1], ordered[n - k]) if k else None


def paired_verdict(name: str, base: list[float | str | None],
                   head: list[float | str | None], *,
                   threshold: float | None) -> dict:
    """Judge one metric from its per-round values, None where the round
    produced none and SKIPPED where it skipped the metric's tier. A round
    the head skipped and the base did not is a lost head value whatever
    the base holds, and so is a round the head ran without a value while
    the base skipped; a pair both rounds skipped drops out.

    A pair counts only when both sides have a value above zero; a zero
    value counts as a missing one (flatten rejects a negative median, so
    such a round exits 2). The result holds the pair count, the rounds that
    lost only the base or only the head value, the medians of the usable
    base and head values, the median ratio with its 95% interval (None
    below MIN_PAIRS), and the verdict, one of VERDICTS. A head value lost
    in any round gives "lost on head", because the head build failed where
    the base did not, and the statistics of the remaining pairs stay in the
    result. With no threshold, a metric that would get a verdict gets "no
    threshold".
    """
    base_skipped = [b == SKIPPED for b in base]
    head_skipped = [h == SKIPPED for h in head]
    base = [b if isinstance(b, (float, int)) and b > 0 else None for b in base]
    head = [h if isinstance(h, (float, int)) and h > 0 else None for h in head]
    pairs = [(b, h) for b, h in zip(base, head)
             if b is not None and h is not None]
    result = {"pairs": len(pairs),
              "base_lost": sum(b is None and h is not None
                               for b, h in zip(base, head)),
              "head_lost": sum(
                  (hs and not bs)
                  or (not hs and h is None and (bs or b is not None))
                  for b, h, bs, hs in zip(base, head, base_skipped,
                                          head_skipped)),
              "base": None, "head": None,
              "ratio": None, "low": None, "high": None}
    if pairs:
        ratios = [h / b for b, h in pairs]
        result["base"] = statistics.median(b for b, _ in pairs)
        result["head"] = statistics.median(h for _, h in pairs)
        result["ratio"] = statistics.median(ratios)
        interval = median_interval(ratios)
        if interval is not None:
            result["low"], result["high"] = interval
    if result["head_lost"]:
        result["verdict"] = "lost on head"
    elif not pairs:
        result["verdict"] = "no result"
    elif len(pairs) < MIN_PAIRS:
        result["verdict"] = "too few pairs"
    elif name in NO_VERDICT:
        result["verdict"] = "no verdict"
    elif threshold is None:
        result["verdict"] = "no threshold"
    elif result["low"] > 1.0 and result["ratio"] > 1.0 + threshold:
        result["verdict"] = "slower"
    elif result["high"] < 1.0 and result["ratio"] < 1.0 - threshold:
        result["verdict"] = "faster"
    else:
        result["verdict"] = "no significant change"
    return result


def load_round(path: pathlib.Path
               ) -> tuple[str, dict[str, float], list[str], set[str]]:
    """Return the environment, the measured metrics, the failed metrics and
    the skipped tiers of one round's results file."""
    document = load_json(path)
    meta = document.get("meta")
    env = meta.get("env") if isinstance(meta, dict) else None
    if not isinstance(env, str) or not env.strip():
        raise BenchDataError(f"{path} has no non-empty meta.env")
    failed: list[str] = []
    values = flatten(document, source=str(path), errors=failed)
    if not values and not failed:
        raise BenchDataError(f"{path} holds no metric")
    # tests/bench-suite.sh records a skipped tier only here; lmbench never
    # skips, since a failure there stops the run.
    skipped = {tier for tier in ("oci", "applications")
               if meta.get(f"{tier}_skipped")}
    return env.strip(), values, failed, skipped


def run_paired(args: argparse.Namespace) -> int:
    try:
        bases = [load_round(path) for path in args.base]
        heads = [load_round(path) for path in args.head]
    except BenchDataError as exc:
        print(f"bench-compare: invalid benchmark data: {exc}",
              file=sys.stderr)
        return 2
    envs = {env for env, _, _, _ in bases + heads}
    if len(envs) != 1:
        print("bench-compare: rounds come from different environments: "
              f"{', '.join(sorted(envs))}", file=sys.stderr)
        return 2
    env = envs.pop()

    names = set()
    for _, values, failed, _ in bases + heads:
        names.update(values, failed)
    # bench-report.py rejects a schema 3 report that breaks these.
    if len(names) > MAX_METRICS:
        print(f"bench-compare: {len(names)} metrics, over the "
              f"{MAX_METRICS}-metric limit", file=sys.stderr)
        return 2
    for name in sorted(names):
        error = metric_name_error(name)
        if error is not None:
            print(f"bench-compare: {error}", file=sys.stderr)
            return 2
    # A round's values in a tier it records as skipped are replaced by
    # SKIPPED, so contradictory data cannot count as a loss on the other
    # side, and paired_verdict counts a head-only skip as a lost head value:
    # bench-suite.sh skips a tier when build/bench-timeit is missing or the
    # OCI pull fails, and the head checkout can cause either.
    metrics = {}
    for name in sorted(names):
        tier = name.split(".", 1)[0]
        sides = {"base": [], "head": []}
        for side, rounds in (("base", bases), ("head", heads)):
            for _, values, _, skipped in rounds:
                sides[side].append(SKIPPED if tier in skipped
                                   else values.get(name))
        metrics[name] = sides
    if args.report_json is not None:
        report = {
            "schema_version": 3,
            "environment": env,
            "direction": "lower-is-better",
            "rounds": len(bases),
            "metrics": metrics,
        }
        try:
            text = json.dumps(report, sort_keys=True, allow_nan=False) + "\n"
            if len(text.encode("utf-8")) > MAX_REPORT_BYTES:
                raise ValueError(f"over the {MAX_REPORT_BYTES}-byte limit")
            args.report_json.parent.mkdir(parents=True, exist_ok=True)
            args.report_json.write_text(text, encoding="utf-8")
        except (OSError, ValueError) as exc:
            print(f"bench-compare: cannot write report {args.report_json}: "
                  f"{exc}", file=sys.stderr)
            return 2

    shown = ("none" if args.threshold is None
             else f"+-{threshold_text(args.threshold)}")
    print(f"bench-compare: paired, environment '{env}', {len(bases)} "
          f"pair(s), threshold {shown}")
    rows = [("metric", "pairs", "lost base/head", "base median",
             "head median", "ratio", "95% interval", "")]
    for name, sides in metrics.items():
        v = paired_verdict(name, sides["base"], sides["head"],
                           threshold=args.threshold)
        rows.append((
            name, str(v["pairs"]), f"{v['base_lost']}/{v['head_lost']}",
            "-" if v["base"] is None else f"{v['base']:g}",
            "-" if v["head"] is None else f"{v['head']:g}",
            "-" if v["ratio"] is None else f"{v['ratio']:.3f}x",
            "-" if v["low"] is None
            else f"{v['low']:.3f}x to {v['high']:.3f}x",
            v["verdict"]))
    print_table(rows)
    return 0


def write_report(path: pathlib.Path, *, environment: str,
                 current: dict[str, float], failed: list[str]) -> None:
    """Write the data-only artifact consumed by the trusted PR reporter.

    It carries only what this run measured, and the metrics whose
    measurement failed. The reporter compares it with the default branch's
    baseline and threshold, never with this branch's.
    """
    report = {
        "schema_version": 2,
        "environment": environment,
        "direction": "lower-is-better",
        "current": current,
        "failed": failed,
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
                        help=f"default {DEFAULT_RESULTS}")
    parser.add_argument("--baseline", type=pathlib.Path,
                        help=f"default {DEFAULT_BASELINE}")
    parser.add_argument(
        "--threshold", type=non_negative_finite_fraction,
        help="regression threshold as a fraction (default "
             "BENCH_REGRESSION_THRESHOLD, else 0.20 = +20%%, or none with "
             "--paired)")
    parser.add_argument("--report-only", action="store_true",
                        default=os.environ.get("BENCH_REPORT_ONLY") == "1",
                        help="print the report but always exit 0")
    parser.add_argument("--fail-on-missing", action="store_true", default=None,
                        help="make missing baseline metrics fail even in "
                             "report-only mode")
    parser.add_argument(
        "--report-json", type=pathlib.Path,
        help="write a data-only comparison report for CI automation")
    parser.add_argument("--paired", action="store_true",
                        help="compare --base rounds with --head rounds")
    parser.add_argument("--base", type=pathlib.Path, nargs="+",
                        help="one results file per base round")
    parser.add_argument("--head", type=pathlib.Path, nargs="+",
                        help="one results file per head round")
    args = parser.parse_args()
    if args.threshold is None:
        try:
            args.threshold = env_threshold(blank_is_unset=args.paired)
        except argparse.ArgumentTypeError as exc:
            parser.error(f"BENCH_REGRESSION_THRESHOLD {exc}")

    if args.paired:
        for flag, value in (("--results", args.results),
                            ("--baseline", args.baseline),
                            ("--fail-on-missing", args.fail_on_missing)):
            if value is not None:
                parser.error(f"--paired does not take {flag}")
        if not args.base or not args.head:
            parser.error("--paired requires --base and --head")
        if len(args.base) != len(args.head):
            parser.error(f"--base has {len(args.base)} file(s), --head "
                         f"has {len(args.head)}")
        if len(args.base) > MAX_ROUNDS:
            parser.error(f"--paired takes at most {MAX_ROUNDS} rounds per "
                         "side")
        return run_paired(args)
    if args.base or args.head:
        parser.error("--base and --head require --paired")
    if args.threshold is None:
        args.threshold = DEFAULT_THRESHOLD

    results = load_json(args.results or DEFAULT_RESULTS)
    baseline = load_json(args.baseline or DEFAULT_BASELINE)

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

    failed: list[str] = []
    try:
        current = flatten(results, source="results", errors=failed)
    except BenchDataError as exc:
        print(f"bench-compare: invalid benchmark data: {exc}",
              file=sys.stderr)
        return 2
    if args.report_json is not None:
        try:
            write_report(args.report_json, environment=env,
                         current=current, failed=sorted(failed))
        except BenchDataError as exc:
            print(f"bench-compare: {exc}", file=sys.stderr)
            return 2

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
        if failed:
            print(f"bench-compare: FAIL -- {len(failed)} missing "
                  f"measurement(s): {', '.join(sorted(failed))}",
                  file=sys.stderr)
            if not (args.report_only and not args.fail_on_missing):
                return 1
        return 1 if args.fail_on_missing else 0

    try:
        base = flatten(column, source=f"baseline.{env}")
    except BenchDataError as exc:
        print(f"bench-compare: invalid benchmark data: {exc}",
              file=sys.stderr)
        return 2

    regressions: list[str] = []
    missing: list[str] = []
    improvements: list[str] = []
    invalid_baselines: list[str] = []
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
        verdict = ""
        if ratio > 1.0 + args.threshold:
            verdict = f"REGRESSION (> +{args.threshold:.0%})"
            regressions.append(metric)
        elif ratio < 1.0 - args.threshold:
            verdict = "improved"
            improvements.append(metric)
        rows.append((metric, f"{base[metric]:g}", f"{current[metric]:g}",
                     f"{ratio:.2f}x", verdict))
    # A failed metric with no baseline yet still fails the run.
    for metric in sorted(set(failed) - set(base)):
        rows.append((metric, "-", "-", "-", "MISSING (measurement failed)"))
        missing.append(metric)
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
