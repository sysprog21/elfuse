# Python real-workload benchmark: the python row of the syscall-frequency
# ranking of elfuse (JSON and regex churn, sqlite3 inserts and queries,
# small-file I/O, a walk of the standard library, subprocesses, threads).
# Runs inside python:3.12-slim under elfuse; see tests/bench-suite.sh.
#
# SPDX-License-Identifier: Apache-2.0

import json
import os
import re
import sqlite3
import subprocess
import sys
import sysconfig
import tempfile
import threading

work = tempfile.mkdtemp(prefix="bench-python.")

# JSON and regex churn.
word = re.compile(r"[a-z]+_(\d+)")
total = 0
for i in range(2000):
    doc = {"id": i, "name": f"item_{i}", "tags": [f"t_{j}" for j in range(8)]}
    text = json.dumps(doc)
    back = json.loads(text)
    total += sum(int(m.group(1)) for m in word.finditer(text)) + back["id"]

# sqlite3: 20k inserts in one transaction, then indexed queries.
db = sqlite3.connect(os.path.join(work, "bench.db"))
db.execute("CREATE TABLE kv (k INTEGER PRIMARY KEY, v TEXT, g INTEGER)")
db.executemany("INSERT INTO kv VALUES (?, ?, ?)",
               ((i, f"value-{i}", i % 97) for i in range(20000)))
db.commit()
db.execute("CREATE INDEX kv_g ON kv (g)")
for g in range(97):
    total += db.execute("SELECT COUNT(*) FROM kv WHERE g = ?",
                        (g,)).fetchone()[0]
db.close()

# 400 small files: write, read back, delete.
for i in range(400):
    path = os.path.join(work, f"f{i:03d}.txt")
    with open(path, "w") as fh:
        fh.write(f"line {i}\n" * 16)
    with open(path) as fh:
        total += len(fh.read())
    os.unlink(path)

# Walk the standard library.
for _, dirs, files in os.walk(sysconfig.get_paths()["stdlib"]):
    total += len(dirs) + len(files)

# 10 subprocesses.
for i in range(10):
    out = subprocess.run([sys.executable, "-c", f"print({i} * 2)"],
                         capture_output=True, text=True, check=True).stdout
    total += int(out)


# 4 threads contending on one lock.
lock = threading.Lock()
counter = [0]


def worker():
    for _ in range(20000):
        with lock:
            counter[0] += 1


threads = [threading.Thread(target=worker) for _ in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()
if counter[0] != 80000:
    sys.exit(f"thread counter {counter[0]} != 80000")

os.unlink(os.path.join(work, "bench.db"))
os.rmdir(work)
print(total)
