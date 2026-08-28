#!/usr/bin/env python3
"""Read workflow jobs without adding a YAML dependency.

The named gate must reach every macOS job through needs.
"""

import re
import sys

_VALUE = r"[ \t]*(\[[^\]]*\]|[^\n]*(?:\n[ \t]+-[ \t]*[^\n]*)*)"


def _uncomment(value):
    # A YAML comment starts at a "#" that begins the line or follows a blank.
    return re.sub(r"(?m)(^|[ \t])#.*$", r"\1", value)


def _scalar(block, key):
    m = re.search(r"^    %s:[ \t]*(.*)$" % key, block, re.M)
    if not m:
        return ""
    value = m.group(1).strip()
    quoted = re.match(r"""(["'])(.*?)\1""", value)
    return quoted.group(2) if quoted else _uncomment(value).strip()


def _names(block, key):
    m = re.search(r"^    %s:%s" % (key, _VALUE), block, re.M)
    return re.findall(r"[A-Za-z][\w-]*", _uncomment(m.group(1))) if m else []


def jobs_of(text):
    section = re.split(r"^jobs:[ \t]*(?:#.*)?$", text, maxsplit=1, flags=re.M)
    if len(section) != 2:
        return None
    jobs = {}
    for block in re.split(r"^  (?=[A-Za-z_])", section[1], flags=re.M)[1:]:
        jobs[block.split(":", 1)[0]] = {
            "name": _scalar(block, "name"),
            "runs-on": " ".join(_names(block, "runs-on")),
            "needs": _names(block, "needs"),
        }
    return jobs


def reachable(jobs, start):
    seen, stack = set(), list(jobs[start]["needs"])
    while stack:
        job = stack.pop()
        if job in seen or job not in jobs:
            continue
        seen.add(job)
        stack.extend(jobs[job]["needs"])
    return seen


def check(text, suffix):
    """Report macOS jobs unreachable from the named gate."""
    jobs = jobs_of(text)
    if jobs is None:
        return ["no top-level 'jobs:' key"]
    gates = [j for j, v in jobs.items() if v["name"].endswith(suffix)]
    if len(gates) != 1:
        return ["expected exactly one job named '... %s', found %s" % (suffix, gates)]
    # Both macos-15 and [self-hosted, macOS, arm64] contain macos.
    macos = {j for j, v in jobs.items() if "macos" in v["runs-on"].lower()}
    missing = sorted(macos - reachable(jobs, gates[0]))
    if missing:
        return ["%s run on macOS but '%s' does not reach them through needs"
                % (missing, jobs[gates[0]]["name"])]
    return []


SAMPLE = """
on: [push]
jobs:  # inline comment
  a:
    runs-on: [self-hosted, macOS, arm64]
  b:
    needs: a
    runs-on: macos-15
  gate:
    name: "Gate (make x)"  # quoted, commented
    needs: [b]
    runs-on: ubuntu-latest
  stray:
    runs-on: macos-15
  listed:
    needs:
      - b
      - stray
    runs-on: ubuntu-latest
  block:
    runs-on:
      - self-hosted
      - macOS
      - arm64
"""


def self_test():
    problems = check(SAMPLE, "(make x)")
    assert problems and "['block', 'stray']" in problems[0], problems
    assert check(SAMPLE.replace("needs: [b]", "needs: [b, stray, block]"), "(make x)") == []
    assert check(SAMPLE.replace("needs: [b]", "needs: [b, listed, block]"), "(make x)") == []
    assert check(SAMPLE.replace("needs: [b]", "needs: [\n      b,\n      listed, block\n    ]"),
                 "(make x)") == []
    assert check(SAMPLE.replace("needs: [b]", "needs: [b]  # stray, block"), "(make x)") != []
    assert check(SAMPLE.replace('"Gate (make x)"', '"Gate #2 (make x)"')
                 .replace("needs: [b]", "needs: [b, stray, block]"), "(make x)") == []
    assert check("on: [push]\n", "(make x)") == ["no top-level 'jobs:' key"]
    return 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    if len(argv) != 2:
        print("usage: workflow-jobs.py WORKFLOW GATE_NAME_SUFFIX | --self-test", file=sys.stderr)
        return 2
    problems = check(open(argv[0]).read(), argv[1])
    for p in problems:
        print("  %s: %s" % (argv[0], p), file=sys.stderr)
    if not problems:
        print("%s: the '%s' gate reaches every macOS job" % (argv[0], argv[1]))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
