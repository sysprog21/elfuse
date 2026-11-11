#!/usr/bin/env python3
"""Promote a captured bench-suite results file into the baseline.

Reads build/bench-results.json (tests/bench-suite.sh output) and merges
its per-metric medians into tests/bench-baseline.json under the
"environments.<env>" and "captured.<env>" entries for the run's
BENCH_ENV column (taken from the results file's meta.env), then writes
the baseline back in place.

This is the mechanical half of the baseline refresh procedure in the
header of tests/bench-suite.sh: it does not decide whether an update is
warranted (capture back-to-back runs and confirm they agree within a
few percent first) or commit the result. Run it once per column after
each `make bench-ci` / `BENCH_ENV=... make bench-ci`:

    make bench-ci                         && scripts/bench-promote.py
    BENCH_ENV=qemu-aarch64 make bench-ci  && scripts/bench-promote.py \\
        --results build/bench-results-qemu-aarch64.json
    BENCH_ENV=orbstack make bench-ci      && scripts/bench-promote.py \\
        --results build/bench-results-orbstack.json

Cases/metrics present in the baseline but absent from the results file
(e.g. a filtered partial run) are left untouched by default; pass --prune
to drop them instead, which is what a full recapture after removing or
renaming cases should use. An ERR/SKIP row keeps its baseline even under
--prune: the case still exists, this capture only failed to measure it.

Usage:
    scripts/bench-promote.py [--results PATH] [--baseline PATH]
                             [--prune] [--dry-run]
    scripts/bench-promote.py --self-test
"""

from __future__ import annotations

import argparse
import json
import math
import os
import pathlib
import stat
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_RESULTS = ROOT / "build" / "bench-results.json"
DEFAULT_BASELINE = ROOT / "tests" / "bench-baseline.json"

SECTIONS = ("lmbench", "applications", "oci")


class BenchPromoteError(ValueError):
    """A benchmark document has an invalid shape or value."""


def to_baseline_tree(node: dict, prefix: str) -> dict:
    """Recursively collapse a results section tree to plain medians
    ({name: median} leaves, nested dicts preserved), dropping SKIP/ERR
    rows (they carry no number to promote)."""
    if not isinstance(node, dict):
        raise BenchPromoteError(f"results {prefix} must be an object")

    out: dict = {}
    for name, leaf in node.items():
        tag = f"{prefix}.{name}" if prefix else name
        if not isinstance(leaf, dict):
            raise BenchPromoteError(f"results {tag} must be an object")
        if "median" in leaf:
            value = leaf["median"]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise BenchPromoteError(
                    f"results {tag}.median must be numeric")
            if not math.isfinite(float(value)) or value <= 0:
                raise BenchPromoteError(
                    f"results {tag}.median must be finite and positive")
            out[name] = value
        elif "status" in leaf:
            continue  # {"status": "SKIP"|"ERR"} -- nothing to promote.
        else:
            sub = to_baseline_tree(leaf, tag)
            if sub:
                out[name] = sub
    return out


def merge_tree(dest: dict, src: dict, prefix: str,
               added: list, updated: list) -> None:
    for name, value in src.items():
        tag = f"{prefix}{name}"
        if isinstance(value, dict):
            if name in dest and not isinstance(dest[name], dict):
                raise BenchPromoteError(
                    f"shape mismatch at {tag}: baseline is scalar, "
                    "results is an object")
            child = dest.setdefault(name, {})
            merge_tree(child, value, f"{tag}.", added, updated)
        else:
            if name in dest and isinstance(dest[name], dict):
                raise BenchPromoteError(
                    f"shape mismatch at {tag}: baseline is an object, "
                    "results is scalar")
            if name in dest:
                if dest[name] != value:
                    updated.append(tag)
            else:
                added.append(tag)
            dest[name] = value


def prune_tree(dest: dict, src: dict, prefix: str, pruned: list) -> None:
    """Drop baseline entries that the raw results tree @src no longer names.
    A status row names its case without a number, so it is not descended."""
    for name in list(dest):
        tag = f"{prefix}{name}"
        if name not in src:
            pruned.append(tag)
            del dest[name]
        elif (isinstance(dest[name], dict) and isinstance(src[name], dict)
              and "median" not in src[name] and "status" not in src[name]):
            prune_tree(dest[name], src[name], f"{tag}.", pruned)
            if not dest[name]:
                del dest[name]


def missing_leaves(dest: dict, src: dict, prefix: str,
                   missing: list) -> None:
    """Record baseline metrics (scalar leaves) absent from this result
    capture, descending into every baseline group."""
    for name, value in dest.items():
        tag = f"{prefix}{name}"
        if isinstance(value, dict):
            sub = src.get(name, {})
            missing_leaves(value, sub if isinstance(sub, dict) else {},
                           f"{tag}.", missing)
        elif name not in src:
            missing.append(tag)


def format_host(host: dict) -> str:
    if not isinstance(host, dict):
        raise BenchPromoteError("results meta.host must be an object")
    return (f"{host.get('os', '?')} {host.get('os_version', '?')} "
            f"{host.get('machine', '?')} ({host.get('cpu', '?')})")


def load_json(path: pathlib.Path) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"bench-promote: missing {path}", file=sys.stderr)
        raise SystemExit(2)
    except json.JSONDecodeError as exc:
        print(f"bench-promote: invalid JSON in {path}: {exc}", file=sys.stderr)
        raise SystemExit(2)
    if not isinstance(document, dict):
        print(f"bench-promote: invalid JSON in {path}: top-level value "
              "must be an object", file=sys.stderr)
        raise SystemExit(2)
    return document


def mapping_entry(parent: dict, name: str, label: str) -> dict:
    value = parent.setdefault(name, {})
    if not isinstance(value, dict):
        raise BenchPromoteError(f"{label} must be an object")
    return value


def self_test() -> int:
    """Check that --prune keeps metrics whose capture failed, that those
    metrics and a skipped tier keep the earlier provenance, and that an
    emptied group does not."""
    dest = {"lat_fs": {"create": 5.0, "delete": 6.0}, "lat_proc": 7.0,
            "gone": 1.0}
    src = {"lat_fs": {"create": {"status": "ERR"},
                      "delete": {"status": "ERR"}},
           "lat_proc": {"status": "SKIP"}}
    pruned: list = []
    prune_tree(dest, src, "lmbench.", pruned)
    if pruned != ["lmbench.gone"] or set(dest) != {"lat_fs", "lat_proc"}:
        print(f"bench-promote self-test: FAIL: pruned {pruned}, "
              f"kept {sorted(dest)}", file=sys.stderr)
        return 1
    # Full --prune promotes through main(): an ERR row keeps the earlier
    # provenance; a group the capture emptied is dropped with its key, so
    # every value left is new and the provenance moves to this run;
    # a tier the capture skipped is not pruned, so its metrics keep the earlier
    # provenance.
    cases = [
        ({"lmbench": {"lat_fs": {"create": 5.0}, "lat_proc": 7.0}},
         {"lmbench": {"lat_fs": {"create": {"status": "ERR"}},
                      "lat_proc": {"median": 8.0}}},
         "old", {"lmbench": {"lat_fs": {"create": 5.0}, "lat_proc": 8.0}}),
        ({"lmbench": {"a": {"x": 1.0, "y": 2.0}, "p": 3.0}},
         {"lmbench": {"a": {}, "p": {"median": 4.0}}},
         "new", {"lmbench": {"p": 4.0}}),
        ({"lmbench": {"p": 3.0}, "applications": {"app": 2.0}},
         {"lmbench": {"p": {"median": 4.0}}},
         "old", {"lmbench": {"p": 4.0}, "applications": {"app": 2.0}}),
    ]
    for column, results, want_date, want_column in cases:
        with tempfile.TemporaryDirectory() as tmp:
            base_path = pathlib.Path(tmp, "baseline.json")
            res_path = pathlib.Path(tmp, "results.json")
            base_path.write_text(json.dumps({
                "captured": {"e": {"date": "old"}},
                "environments": {"e": column},
            }), encoding="utf-8")
            res_path.write_text(json.dumps({
                "meta": {"env": "e", "date": "new", "host": {},
                         "iterations": 1},
                **results,
            }), encoding="utf-8")
            run = subprocess.run(
                [sys.executable, __file__, "--prune", "--results",
                 str(res_path), "--baseline", str(base_path)],
                capture_output=True, text=True)
            promoted = json.loads(base_path.read_text(encoding="utf-8"))
        date = promoted["captured"]["e"]["date"]
        got = {name: promoted["environments"]["e"].get(name)
               for name in want_column}
        if run.returncode != 0 or date != want_date or got != want_column:
            print(f"bench-promote self-test: FAIL: rc {run.returncode}, "
                  f"captured date {date!r}, column {got}\n{run.stderr}",
                  file=sys.stderr)
            return 1
    print("bench-promote self-test: ok")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=pathlib.Path,
                        default=DEFAULT_RESULTS)
    parser.add_argument("--baseline", type=pathlib.Path,
                        default=DEFAULT_BASELINE)
    parser.add_argument("--prune", action="store_true",
                        help="drop baseline cases/metrics absent from "
                             "--results instead of leaving them untouched")
    parser.add_argument("--dry-run", action="store_true",
                        help="print what would change; don't write "
                             "--baseline")
    args = parser.parse_args()

    results = load_json(args.results)
    baseline = load_json(args.baseline)

    try:
        meta = results.get("meta")
        if not isinstance(meta, dict):
            raise BenchPromoteError("results meta must be an object")
        env = meta.get("env")
        if not isinstance(env, str) or not env.strip():
            raise BenchPromoteError("results file has no non-empty meta.env")
        env = env.strip()

        environments = mapping_entry(
            baseline, "environments", "baseline environments")
        column = mapping_entry(
            environments, env, f"baseline environments.{env}")

        added, updated, pruned, missing = [], [], [], []
        for section in SECTIONS:
            new_leaves = to_baseline_tree(
                results.get(section, {}), section)
            dest = mapping_entry(
                column, section,
                f"baseline environments.{env}.{section}")
            prefix = f"{section}."
            merge_tree(dest, new_leaves, prefix, added, updated)
            # An empty section is a tier the capture skipped, not one whose
            # metrics were all removed.
            if args.prune and new_leaves:
                prune_tree(dest, results[section], prefix, pruned)
            # What is left and not measured now still comes from an earlier
            # capture: ERR/SKIP rows --prune kept, a tier the capture skipped,
            # or everything without --prune.
            missing_leaves(dest, new_leaves, prefix, missing)

        captured_entry = {
            "date": meta.get("date"),
            "host": format_host(meta.get("host", {})),
            "iterations": meta.get("iterations"),
        }
        if meta.get("note"):
            captured_entry["note"] = meta["note"]
        captured = mapping_entry(baseline, "captured", "baseline captured")
        if missing:
            print("  capture is partial; preserving existing provenance "
                  f"({len(missing)} baseline metric(s) absent)")
            for tag in missing:
                print(f"    ? {tag}")
            print("  to record this run's provenance, capture those metrics "
                  f"again or delete them from {args.baseline}")
        else:
            captured[env] = captured_entry
    except BenchPromoteError as exc:
        print(f"bench-promote: invalid benchmark data: {exc}",
              file=sys.stderr)
        return 2

    print(f"bench-promote: environment '{env}' from {args.results}")
    print(f"  {len(added)} added, {len(updated)} updated, "
          f"{len(pruned)} pruned")
    for tag in added:
        print(f"    + {tag}")
    for tag in updated:
        print(f"    ~ {tag}")
    for tag in pruned:
        print(f"    - {tag}")

    if args.dry_run:
        print("bench-promote: --dry-run, not writing", file=sys.stderr)
        return 0

    try:
        serialized = json.dumps(
            baseline, indent=2, sort_keys=True, allow_nan=False) + "\n"
    except (TypeError, ValueError) as exc:
        print(f"bench-promote: baseline cannot be serialized: {exc}",
              file=sys.stderr)
        return 2

    fd, tmp_name = tempfile.mkstemp(prefix=f".{args.baseline.name}.",
                                    suffix=".tmp", dir=args.baseline.parent,
                                    text=True)
    try:
        os.fchmod(fd, stat.S_IMODE(args.baseline.stat().st_mode))
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            tmp.write(serialized)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmp_name, args.baseline)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise
    print(f"bench-promote: wrote {args.baseline}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
