"""Exercise Python filesystem, SQLite, and process operations under elfuse."""

import json
import os
import re
import sqlite3
import subprocess
import sys
import threading

DB = "/tmp/elfuse-workload.db"
TREE = "/tmp/elfuse-workload-tree"
THREADS = 8
PER_THREAD = 2500
FANOUT = 20
SUBPROCS = 10


def setup_db():
    con = sqlite3.connect(DB)
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute(
            "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "tid INTEGER NOT NULL, n INTEGER NOT NULL)"
        )
        con.commit()
    finally:
        con.close()


def worker(tid):
    con = sqlite3.connect(DB, timeout=60)
    try:
        for n in range(PER_THREAD):
            con.execute("INSERT INTO t (tid, n) VALUES (?, ?)", (tid, n))
        con.commit()
    finally:
        con.close()


def db_count():
    con = sqlite3.connect(DB, timeout=60)
    try:
        (count,) = con.execute("SELECT COUNT(*) FROM t").fetchone()
        return count
    finally:
        con.close()


def db_query_ok():
    con = sqlite3.connect(DB, timeout=60)
    try:
        rows = con.execute(
            "SELECT tid, COUNT(*), MIN(n), MAX(n), SUM(n) FROM t"
            " GROUP BY tid ORDER BY tid"
        ).fetchall()
    finally:
        con.close()
    want_sum = PER_THREAD * (PER_THREAD - 1) // 2
    return rows == [
        (tid, PER_THREAD, 0, PER_THREAD - 1, want_sum) for tid in range(THREADS)
    ]


def json_regex_churn():
    word = re.compile(r"tok-(\d+)")
    for r in range(2000):
        doc = {"round": r, "items": [{"k": i, "v": "tok-%d" % i} for i in range(16)]}
        blob = json.dumps(doc)
        back = json.loads(blob)
        got = [int(m) for m in word.findall(blob)]
        if got != list(range(16)) or back != doc:
            return False
    return True


def content(i, j):
    return "elfuse-workload-%d-%d\n" % (i, j)


def fs_fanout_ok():
    for i in range(FANOUT):
        for j in range(FANOUT):
            d = os.path.join(TREE, str(i), str(j))
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "f"), "w") as fh:
                fh.write(content(i, j))
                fh.flush()
                os.fsync(fh.fileno())
    read_back = []
    for i in range(FANOUT):
        for j in range(FANOUT):
            with open(os.path.join(TREE, str(i), str(j), "f")) as fh:
                read_back.append(fh.read())
    expected = [content(i, j) for i in range(FANOUT) for j in range(FANOUT)]
    return read_back == expected


def walk_stdlib_ok():
    # The exact stdlib module count varies across image patch releases.
    root = os.path.dirname(os.__file__)
    n = 0
    for _, _, files in os.walk(root):
        n += sum(1 for f in files if f.endswith(".py"))
    return n > 200


def subprocesses_ok():
    for i in range(SUBPROCS):
        code = "print('child-%d')" % i
        out = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout.strip()
        if out != "child-%d" % i:
            return False
    return True


def main():
    setup_db()
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    count = db_count()
    if count != THREADS * PER_THREAD:
        print(
            "sqlite row count %d != %d (concurrent writers lost rows)"
            % (count, THREADS * PER_THREAD),
            file=sys.stderr,
        )
        sys.exit(1)

    if not db_query_ok():
        print("sqlite per-thread aggregate mismatch", file=sys.stderr)
        sys.exit(1)

    if not json_regex_churn():
        print("json/regex round-trip mismatch", file=sys.stderr)
        sys.exit(1)

    if not fs_fanout_ok():
        print("filesystem fan-out content mismatch", file=sys.stderr)
        sys.exit(1)

    if not walk_stdlib_ok():
        print("stdlib walk found too few modules", file=sys.stderr)
        sys.exit(1)

    if not subprocesses_ok():
        print("subprocess output mismatch", file=sys.stderr)
        sys.exit(1)

    print("elfuse-oci-python-workload-ok")


if __name__ == "__main__":
    main()
