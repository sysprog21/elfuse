#!/usr/bin/env python3
"""Convert ELFUSE_RUNTIME_STATS=jsonl output to simple viewer formats."""

import argparse
import csv
import json
import sys
import tempfile
from contextlib import redirect_stdout
from io import StringIO


def load_records(path):
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            rec = json.loads(line)
            if rec.get("schema") == "elfuse-runtime-stats/1":
                records.append(rec)
    return records


def ms(ns):
    return float(ns or 0) / 1_000_000.0


def syscall_rows(rec):
    return rec.get("syscalls", {}).get("rows", [])


def syscall_delta_rows(records):
    prev_by_pid = {}
    for rec in records:
        pid = rec.get("pid", 1)
        prev = prev_by_pid.setdefault(pid, {})
        rows = []
        for row in syscall_rows(rec):
            key = row.get("nr", row.get("name"))
            total = row.get("total_ns", 0)
            last = prev.get(key, 0)
            out = dict(row)
            out["total_ns"] = total - last if total >= last else total
            rows.append(out)
            prev[key] = total
        yield rec, rows
        if rec.get("final"):
            prev_by_pid.pop(pid, None)


def write_csv(records):
    fields = [
        "workload",
        "wall_ms",
        "guest_run_ms",
        "syscall_ms",
        "clone_ms",
        "wait_ms",
        "openat_ms",
        "null_exit_share",
    ]
    w = csv.DictWriter(sys.stdout, fieldnames=fields)
    w.writeheader()
    for rec in records:
        by_name = {r.get("name"): r for r in syscall_rows(rec)}
        argv = rec.get("argv") or []
        row = {
            "workload": " ".join(argv[1:]) if len(argv) > 1 else " ".join(argv),
            "wall_ms": ms(rec.get("wall_ns")),
            "guest_run_ms": ms(rec.get("guest_run_ns")),
            "syscall_ms": ms(rec.get("syscalls", {}).get("total_ns")),
            "clone_ms": ms((by_name.get("SYS_clone") or {}).get("total_ns")),
            "wait_ms": ms(
                sum(
                    (by_name.get(n) or {}).get("total_ns", 0)
                    for n in ("SYS_wait4", "SYS_waitid")
                )
            ),
            "openat_ms": ms((by_name.get("SYS_openat") or {}).get("total_ns")),
            "null_exit_share": rec.get("vmexit", {}).get("null_exit_share", 0),
        }
        w.writerow(row)


def write_folded(records):
    totals = {}
    for _, rows in syscall_delta_rows(records):
        for row in rows:
            name = row.get("name") or f"SYS_{row.get('nr')}"
            totals[f"elfuse;syscall;{name}"] = totals.get(
                f"elfuse;syscall;{name}", 0
            ) + row.get("total_ns", 0)
    for stack, total in sorted(totals.items()):
        print(stack, total)


def write_speedscope(records):
    frames = []
    frame_index = {}
    events = []
    at = 0
    for _, rows in syscall_delta_rows(records):
        for row in rows:
            name = row.get("name") or f"SYS_{row.get('nr')}"
            if name not in frame_index:
                frame_index[name] = len(frames)
                frames.append({"name": name})
            dur = row.get("total_ns", 0) / 1000.0
            events.append({"type": "O", "at": at, "frame": frame_index[name]})
            events.append({"type": "C", "at": at + dur, "frame": frame_index[name]})
            at += dur
    json.dump(
        {
            "$schema": "https://www.speedscope.app/file-format-schema.json",
            "shared": {"frames": frames},
            "profiles": [
                {
                    "type": "evented",
                    "name": "elfuse runtime stats",
                    "unit": "microseconds",
                    "startValue": 0,
                    "endValue": at,
                    "events": events,
                }
            ],
        },
        sys.stdout,
    )
    print()


def write_perfetto(records):
    trace = []
    pid = 1
    for rec, rows in syscall_delta_rows(records):
        tid = rec.get("pid", 1)
        ts = rec.get("time_ns", 0) / 1000.0
        for row in rows:
            trace.append(
                {
                    "name": row.get("name") or f"SYS_{row.get('nr')}",
                    "ph": "X",
                    "ts": ts,
                    "dur": row.get("total_ns", 0) / 1000.0,
                    "pid": pid,
                    "tid": tid,
                }
            )
            ts += row.get("total_ns", 0) / 1000.0
    json.dump({"traceEvents": trace}, sys.stdout)
    print()


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("format", choices=["csv", "folded", "speedscope", "perfetto"])
    ap.add_argument("input", nargs="?")
    args = ap.parse_args(argv)
    if args.selftest:
        selftest(args.format)
        return
    if not args.input:
        ap.error("input is required")
    records = load_records(args.input)
    if args.format == "csv":
        write_csv(records)
    elif args.format == "folded":
        write_folded(records)
    elif args.format == "speedscope":
        write_speedscope(records)
    else:
        write_perfetto(records)


def selftest(fmt):
    sample1 = {
        "schema": "elfuse-runtime-stats/1",
        "pid": 1,
        "time_ns": 1_000,
        "final": False,
        "argv": ["elfuse", "guest"],
        "wall_ns": 10_000_000,
        "guest_run_ns": 0,
        "vmexit": {"null_exit_share": 0.0},
        "syscalls": {
            "total_ns": 1_000_000,
            "rows": [
                {"nr": 220, "name": "SYS_clone", "total_ns": 1_000_000},
            ],
        },
    }
    sample2 = json.loads(json.dumps(sample1))
    sample2["time_ns"] = 2_000
    sample2["final"] = True
    sample2["wall_ns"] = 20_000_000
    sample2["syscalls"]["total_ns"] = 3_000_000
    sample2["syscalls"]["rows"].append(
        {"nr": 260, "name": "SYS_wait4", "total_ns": 2_000_000}
    )
    with tempfile.NamedTemporaryFile("w+", encoding="utf-8") as f:
        f.write(json.dumps(sample1) + "\n")
        f.write(json.dumps(sample2) + "\n")
        f.flush()
        records = load_records(f.name)
    out = StringIO()
    with redirect_stdout(out):
        if fmt == "csv":
            write_csv(records)
            assert "clone_ms" in out.getvalue()
        elif fmt == "folded":
            write_folded(records)
            assert "elfuse;syscall;SYS_clone 1000000" in out.getvalue()
        elif fmt == "speedscope":
            write_speedscope(records)
            profile = json.loads(out.getvalue())["profiles"][0]
            assert profile["endValue"] == 3000.0
        else:
            write_perfetto(records)
            trace = json.loads(out.getvalue())["traceEvents"]
            assert sum(e["dur"] for e in trace) == 3000.0


if __name__ == "__main__":
    main(sys.argv[1:])
