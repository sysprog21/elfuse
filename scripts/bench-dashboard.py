#!/usr/bin/env python3
"""Turn a paired benchmark run into points for the elfuse-bench dashboard.

Reads the rounds scripts/bench-paired.sh wrote to DIR and prints the JSON
array that github-action-benchmark's customSmallerIsBetter tool reads. Each
Tier 1 and Tier 2 metric gives two points: the median of its head rounds
(head-N.json) under the metric's name in the comparison report, and the
median of its base rounds (base-N.json) under that name with " (base)"
appended, so a shift of the host shows as both series moving at once. A
side's median takes every round of that side with a value, where the
comparison keeps only the rounds in which both sides have one. Each Tier 3
metric gives one point, its median in head-oci.json, because Tier 3 runs on
the head build only. As in the comparison, a zero value and a tier the file
records as skipped count as missing, and a metric missing from every round
of a side gets no point on that side.

With DATA_JS and COMMIT, the points that DATA_JS, a copy of the dashboard's
data.js, already holds for COMMIT are left out, so an empty array means the
dashboard has them all. A DATA_JS that cannot be read or parsed leaves no
point out.

Usage:
    scripts/bench-dashboard.py DIR [DATA_JS COMMIT]
    scripts/bench-dashboard.py --self-test

Exits 2 when DIR holds no base or no head round, when neither the rounds nor
head-oci.json measured any metric, or when a file it reads in DIR is not
valid bench-suite output.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import statistics
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Only the numbered rounds: not discard-*, head-oci or report.json.
ROUND = re.compile(r"(base|head)-([1-9][0-9]*)\.json\Z")
BASE_SUFFIX = " (base)"
# What github-action-benchmark writes before the JSON in data.js.
DATA_PREFIX = "window.BENCHMARK_DATA = "


def load_compare():
    """Load bench-compare.py, whose hyphenated name cannot be imported."""
    path = ROOT / "scripts" / "bench-compare.py"
    spec = importlib.util.spec_from_file_location("bench_compare", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


compare = load_compare()


def collect(paths: list[pathlib.Path]
            ) -> dict[str, tuple[str, list[float], int]]:
    """Map each metric that some file in paths measured to its unit, its
    median in each such file, and its sample count in the last."""
    metrics: dict[str, tuple[str, list[float], int]] = {}
    for path in paths:
        document = compare.load_json(path)
        # bench-compare's load_round checks the rounds the same way, but
        # head-oci.json never reaches it.
        meta = document.get("meta")
        env = meta.get("env") if isinstance(meta, dict) else None
        if not isinstance(env, str) or not env.strip():
            raise compare.BenchDataError(f"{path} has no non-empty meta.env")
        # The same rules as bench-compare's run_paired and paired_verdict.
        skipped = {tier for tier in ("oci", "applications")
                   if meta.get(f"{tier}_skipped")}
        flat = compare.flatten(document, source=str(path))
        for name, value in flat.items():
            if name.split(".", 1)[0] in skipped or value <= 0:
                continue
            leaf = document
            for key in name.split("."):
                leaf = leaf.get(key) if isinstance(leaf, dict) else None
            unit = leaf.get("unit") if isinstance(leaf, dict) else None
            if not isinstance(unit, str) or not unit.strip():
                raise compare.BenchDataError(
                    f"{path}: metric '{name}' has no unit")
            samples = leaf.get("samples")
            count = len(samples) if isinstance(samples, list) else 0
            known_unit, values, _ = metrics.get(name, (unit.strip(), [], 0))
            if known_unit != unit.strip():
                raise compare.BenchDataError(
                    f"{path}: metric '{name}' is in {unit.strip()}, an "
                    f"earlier round in {known_unit}")
            values.append(value)
            metrics[name] = (known_unit, values, count)
    return metrics


def shown(value: float) -> float:
    """Round to 12 significant digits, so the mean of the two middle rounds
    prints as 1.0262 instead of 1.0261999999999998. bench-suite rounds a
    median to at most 6 decimals, so the mean of two has at most 7, and 12
    digits keep all of them for a value below 100000."""
    return float(f"{value:.12g}")


def points(directory: pathlib.Path) -> list[dict]:
    rounds: dict[str, list[pathlib.Path]] = {"base": [], "head": []}
    for path in sorted(directory.iterdir()):
        match = ROUND.match(path.name)
        if match:
            rounds[match.group(1)].append(path)
    for side, found in rounds.items():
        if not found:
            raise compare.BenchDataError(
                f"{directory} holds no {side}-N.json round")
    head = collect(rounds["head"])
    base = collect(rounds["base"])
    result = []
    for name in list(head) + [n for n in base if n not in head]:
        for side, suffix in ((head, ""), (base, BASE_SUFFIX)):
            if name in side:
                unit, values, _ = side[name]
                result.append({"name": name + suffix, "unit": unit,
                               "value": shown(statistics.median(values)),
                               "extra": f"median of {len(values)} rounds"})
    oci = directory / "head-oci.json"
    if oci.exists():
        for name, (unit, values, count) in collect([oci]).items():
            result.append({"name": name, "unit": unit,
                           "value": shown(values[0]),
                           "extra": f"median of {count} samples"})
    # The action refuses an empty list with a message that names no metric.
    if not result:
        raise compare.BenchDataError(f"nothing in {directory} measured any "
                                     "metric")
    return result


def published(path: pathlib.Path, commit: str) -> set[str]:
    """Return the names of the points data.js at path holds for commit. A
    file that cannot be read or parsed gives none, with a warning, because
    a point published twice costs less than a point lost."""
    try:
        text = path.read_text(encoding="utf-8")
        if not text.startswith(DATA_PREFIX):
            raise ValueError(f"no leading {DATA_PREFIX.strip()!r}")
        entries = json.loads(text[len(DATA_PREFIX):])["entries"]
        return {bench["name"]
                for suite in entries.values() for entry in suite
                if entry["commit"]["id"] == commit
                for bench in entry["benches"]}
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"bench-dashboard: {path} left no point out: {exc!r}",
              file=sys.stderr)
        return set()


def self_test() -> int:
    """Check the points of a fixed run directory, with and without points
    its commit already has on the dashboard, and that a directory without
    base or head rounds, with a unitless metric, with a unit that changes
    between rounds, with a file lacking meta.env or with no measured metric
    is refused."""
    def leaf(value, unit="us"):
        return {"median": value, "samples": [value], "unit": unit}

    def round_doc(null, create, exec_=None, zstd=70.0, **meta):
        return {"meta": {"env": "e", **meta},
                "lmbench": {"lat_syscall": {"null": leaf(null)},
                            "lat_fs": {"create": create},
                            "lat_proc": {"exec": exec_ or {"status": "ERR"}}},
                "applications": {"zstd_ms": leaf(zstd, "ms")}}

    def data_js(*entries):
        return DATA_PREFIX + json.dumps(
            {"lastUpdate": 1, "repoUrl": "",
             "entries": {"Benchmarks": [
                 {"commit": {"id": commit}, "date": 1,
                  "tool": "customSmallerIsBetter",
                  "benches": [{"name": n, "value": 1.0, "unit": "us"}
                              for n in names]}
                 for commit, names in entries]}}, indent=2)

    err = {"status": "ERR"}
    files = {
        # The median of 0.1 and 0.2 is 0.15000000000000002.
        "base-1.json": round_doc(0.1, leaf(40.0), leaf(20.0)),
        "base-2.json": round_doc(0.2, leaf(42.0), leaf(22.0)),
        "head-1.json": round_doc(2.0, leaf(50.0)),
        "head-2.json": round_doc(4.0, leaf(0.0)),
        "head-10.json": round_doc(9.0, leaf(54.0), zstd=500.0,
                                  applications_skipped="1"),
        # Not rounds of this comparison: a value here would show.
        "discard-head-1.json": round_doc(500.0, leaf(500.0)),
        "head-1.json.orig": round_doc(500.0, leaf(500.0)),
        "report.json": {"schema": 3},
        "head-oci.json": {
            "meta": {"env": "e"}, "lmbench": {}, "applications": {},
            "oci": {"jvm_ms": {"median": 4000.0,
                               "samples": [3900.0, 4000.0, 4100.0],
                               "unit": "ms"},
                    "node_ms": err}},
    }
    want = [
        ("lmbench.lat_syscall.null", "us", 4.0, "median of 3 rounds"),
        ("lmbench.lat_syscall.null (base)", "us", 0.15, "median of 2 rounds"),
        ("lmbench.lat_fs.create", "us", 52.0, "median of 2 rounds"),
        ("lmbench.lat_fs.create (base)", "us", 41.0, "median of 2 rounds"),
        ("applications.zstd_ms", "ms", 70.0, "median of 2 rounds"),
        ("applications.zstd_ms (base)", "ms", 70.0, "median of 2 rounds"),
        ("lmbench.lat_proc.exec (base)", "us", 21.0, "median of 2 rounds"),
        ("oci.jvm_ms", "ms", 4000.0, "median of 3 samples"),
    ]
    commit = "c" * 40
    tier12 = [p[0] for p in want[:-1]]
    # Another commit holds every point; this one holds only Tier 1 and 2.
    partial = data_js(("d" * 40, [p[0] for p in want]), (commit, tier12))
    # A rerun added Tier 3 in a second entry.
    full = data_js((commit, tier12), (commit, ["oci.jvm_ms"]))
    no_base = {k: v for k, v in files.items() if not k.startswith("base-")}
    no_head = {k: v for k, v in files.items() if not k.startswith("head-")}
    unitless = dict(files, **{"head-1.json": {
        "meta": {"env": "e"}, "lmbench": {"x": {"median": 1.0}}}})
    unit_change = dict(files, **{"head-1.json": round_doc(2.0,
                                                          leaf(50.0, "ms"))})
    no_env = dict(files, **{"head-oci.json": {
        "oci": {"jvm_ms": leaf(4000.0, "ms")}}})
    failed = {"base-1.json": {"meta": {"env": "e"}, "lmbench": {"x": err}},
              "head-1.json": {"meta": {"env": "e"}, "lmbench": {"x": err}}}
    held = ["data.js", commit]
    cases = (
        ("run", files, [], 0, want),
        ("Tier 1 and 2 published", dict(files, **{"data.js": partial}), held,
         0, want[-1:]),
        ("all published", dict(files, **{"data.js": full}), held, 0, []),
        ("truncated data.js",
         dict(files, **{"data.js": partial[:len(partial) // 2]}), held, 0,
         want),
        ("no data.js", files, held, 0, want),
        ("no base", no_base, [], 2, None),
        ("no head", no_head, [], 2, None),
        ("unitless", unitless, [], 2, None),
        ("unit change", unit_change, [], 2, None),
        ("no meta.env", no_env, [], 2, None),
        ("all failed", failed, [], 2, None),
    )
    for case, contents, extra, rc, expected in cases:
        with tempfile.TemporaryDirectory() as tmp:
            for name, document in contents.items():
                text = (document if isinstance(document, str)
                        else json.dumps(document))
                pathlib.Path(tmp, name).write_text(text, encoding="utf-8")
            args = [str(pathlib.Path(tmp, a)) if a == "data.js" else a
                    for a in extra]
            run = subprocess.run([sys.executable, __file__, tmp, *args],
                                 capture_output=True, text=True)
        got = None
        if rc == 0 and run.returncode == 0:
            got = [(p["name"], p["unit"], p["value"], p["extra"])
                   for p in json.loads(run.stdout)]
        if run.returncode != rc or (rc == 0 and got != expected):
            print(f"bench-dashboard self-test: FAIL: {case}: rc "
                  f"{run.returncode}, points {got}\n{run.stderr}",
                  file=sys.stderr)
            return 1
    print("bench-dashboard self-test: ok")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if len(args) not in (1, 3) or any(a.startswith("-") for a in args):
        print("usage: scripts/bench-dashboard.py DIR [DATA_JS COMMIT] | "
              "--self-test", file=sys.stderr)
        return 2
    try:
        result = points(pathlib.Path(args[0]))
    except (compare.BenchDataError, OSError) as exc:
        print(f"bench-dashboard: {exc}", file=sys.stderr)
        return 2
    if len(args) == 3:
        held = published(pathlib.Path(args[1]), args[2])
        result = [p for p in result if p["name"] not in held]
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
