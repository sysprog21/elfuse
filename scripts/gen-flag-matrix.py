#!/usr/bin/env python3
"""Generate build/flag-matrix-vectors.h from tests/flag-matrix.tbl.

Each table row names one syscall, one flag, the arguments to call it with, and
what Linux answers with the flag set and with it clear. The generator joins the
syscall names against src/syscall/dispatch.tbl, so a row for a syscall the
dispatcher does not serve fails here instead of quietly testing nothing.

A row that starts with the word "pending" records an answer elfuse does not
give yet. The test reports its mismatch as known instead of failing, and fails
once the row passes, so the mark cannot outlive the divergence.

A row that starts with "unsupported:ANSWER" records a flag elfuse declines on
purpose. ANSWER is what elfuse gives with the flag set, and it has to be an
answer Linux itself documents for a kernel or filesystem without the feature.
The qemu lane still asserts the row's own answer.

Flag names and integer arguments are emitted as C expressions and resolved by
the guest toolchain's headers. No flag value is recorded in this script.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_TABLE = ROOT / "tests" / "flag-matrix.tbl"
DEFAULT_DISPATCH = ROOT / "src" / "syscall" / "dispatch.tbl"
DEFAULT_OUTPUT = ROOT / "build" / "flag-matrix-vectors.h"

ENTRY_RE = re.compile(r"^SYS_([A-Za-z0-9_]+)\s+sc_[A-Za-z0-9_]+\s+[01]$")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
TAG_RE = re.compile(r"^[a-z0-9-]+$")
MAX_ARGS = 6

PATHS = {
    "file": "FM_P_FILE",
    "dir": "FM_P_DIR",
    "link": "FM_P_LINK",
    "dangling": "FM_P_DANGLING",
    "new": "FM_P_NEW",
    "empty": "FM_P_EMPTY",
}
FDS = {"file": "FM_FD_FILE", "dir": "FM_FD_DIR", "listener": "FM_FD_LISTENER",
       "sealed": "FM_FD_SEALED"}

# Expectations that take no operand.
PLAIN_EXPECTS = {
    "ok": "FM_X_OK",
    "fd": "FM_X_FD",
    "fd:cloexec": "FM_X_FD_CLOEXEC",
    "fd:nocloexec": "FM_X_FD_NOCLOEXEC",
    "fd:appends": "FM_X_FD_APPENDS",
    "fd:overwrites": "FM_X_FD_OVERWRITES",
    "fd:readebadf": "FM_X_FD_READ_EBADF",
    "buf:reg": "FM_X_STAT_REG",
    "buf:lnk": "FM_X_STAT_LNK",
    "bufx:reg": "FM_X_STATX_REG",
    "bufx:lnk": "FM_X_STATX_LNK",
    "pair:packets": "FM_X_PAIR_PACKETS",
    "pair:stream": "FM_X_PAIR_STREAM",
    "stack:lowreadonly": "FM_X_STACK_LOW_READONLY",
    "stack:lowwritable": "FM_X_STACK_LOW_WRITABLE",
    "child": "FM_X_CHILD",
    "child:ptid": "FM_X_CHILD_PTID",
    "child:noptid": "FM_X_CHILD_NOPTID",
    "child:pidfd": "FM_X_CHILD_PIDFD",
    "arg0:cloexec": "FM_X_ARG0_CLOEXEC",
    "arg0:nocloexec": "FM_X_ARG0_NOCLOEXEC",
    "map": "FM_X_MAP",
    "map:atregion": "FM_X_MAP_AT_REGION",
    "map:elsewhere": "FM_X_MAP_ELSEWHERE",
    "map:writable": "FM_X_MAP_WRITABLE",
    "map:readonly": "FM_X_MAP_READONLY",
    "map:noread": "FM_X_MAP_NOREAD",
    "map:writesfile": "FM_X_MAP_WRITES_FILE",
    "map:keepsfile": "FM_X_MAP_KEEPS_FILE",
    "region:writable": "FM_X_REGION_WRITABLE",
    "region:readonly": "FM_X_REGION_READONLY",
    "region:noread": "FM_X_REGION_NOREAD",
}
# Expectations whose operand is a C expression.
EXPR_EXPECTS = {
    "err": "FM_X_ERR",
    "errkeeps": "FM_X_ERR_KEEPS",
    "fd:getfl": "FM_X_FD_GETFL",
    "fd:nogetfl": "FM_X_FD_NOGETFL",
    "fd:seals": "FM_X_FD_SEALS",
    "fd:perm": "FM_X_FD_PERM",
    "pair1:getfl": "FM_X_PAIR1_GETFL",
    "pair1:nogetfl": "FM_X_PAIR1_NOGETFL",
    "arg0:getfl": "FM_X_ARG0_GETFL",
    "arg0:nogetfl": "FM_X_ARG0_NOGETFL",
}
# Expectations whose operand is a fixture path.
PATH_EXPECTS = {
    "exists": "FM_X_EXISTS",
    "absent": "FM_X_ABSENT",
    "lreg": "FM_X_LSTAT_REG",
    "llnk": "FM_X_LSTAT_LNK",
}
# Expectations of the form kind:path=value.
PATH_VALUE_EXPECTS = {"size": "FM_X_SIZE", "mode": "FM_X_MODE"}


class TableError(ValueError):
    pass


def load_dispatch(path: pathlib.Path) -> set[str]:
    names = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = ENTRY_RE.match(line.strip())
        if match:
            names.add(match.group(1))
    if not names:
        raise TableError(f"{path}: no dispatch entries found")
    return names


def path_token(where: str, name: str) -> str:
    if name not in PATHS:
        raise TableError(f"{where}: unknown fixture path '{name}'")
    return PATHS[name]


def parse_arg(where: str, token: str) -> tuple[str, bool]:
    """Return the C initializer for one argument and whether it is the flags
    slot."""
    if token == "CWD":
        return "{FM_A_CWD, 0}", False
    if token == "buf":
        return "{FM_A_BUF, 0}", False
    if token == "pair":
        return "{FM_A_PAIR, 0}", False
    if token == "region":
        return "{FM_A_REGION, 0}", False
    if token == "stackpage":
        return "{FM_A_STACK, 0}", False
    if token.startswith("p:"):
        return f"{{FM_A_PATH, {path_token(where, token[2:])}}}", False
    if token.startswith("fd:"):
        if token[3:] not in FDS:
            raise TableError(f"{where}: unknown fixture fd '{token[3:]}'")
        return f"{{FM_A_FD, {FDS[token[3:]]}}}", False
    if token == "F":
        return "{FM_A_FLAGS, 0}", True
    if token.startswith("F|"):
        return f"{{FM_A_FLAGS, (long) ({token[2:]})}}", True
    return f"{{FM_A_INT, (long) ({token})}}", False


def parse_expect(where: str, text: str) -> str:
    if text in PLAIN_EXPECTS:
        return f"{{{PLAIN_EXPECTS[text]}, 0, 0}}"
    kind, _, operand = text.rpartition(":")
    if kind in EXPR_EXPECTS and operand:
        return f"{{{EXPR_EXPECTS[kind]}, (long) ({operand}), 0}}"
    if kind.endswith(":p"):
        base = kind[:-2]
        if base in PATH_EXPECTS:
            return f"{{{PATH_EXPECTS[base]}, {path_token(where, operand)}, 0}}"
        if base in PATH_VALUE_EXPECTS and "=" in operand:
            name, _, value = operand.partition("=")
            return (f"{{{PATH_VALUE_EXPECTS[base]}, {path_token(where, name)}, "
                    f"(long) ({value})}}")
    raise TableError(f"{where}: unknown expectation '{text}'")


def parse_table(path: pathlib.Path, dispatch: set[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        where = f"{path}:{lineno}"
        pending = line.startswith("pending ")
        if pending:
            line = line[len("pending "):]
        elfuse_text = ""
        if line.startswith("unsupported:"):
            elfuse_text, _, line = line[len("unsupported:"):].partition(" ")
            if pending:
                raise TableError(f"{where}: a row is pending or unsupported, "
                                 "not both")
        fields = [f.strip() for f in line.split(" | ")]
        if len(fields) != 5:
            raise TableError(f"{where}: expected 5 ' | '-separated fields, "
                             f"got {len(fields)}")
        sysname, flag, args_text, with_text, without_text = fields
        if not NAME_RE.match(sysname):
            raise TableError(f"{where}: malformed syscall name '{sysname}'")
        if sysname not in dispatch:
            raise TableError(f"{where}: {sysname} is not in dispatch.tbl")

        flag_expr, _, tag = flag.partition("@")
        if "@" in flag and not TAG_RE.match(tag):
            raise TableError(f"{where}: malformed tag '{tag}'")
        if not flag_expr:
            raise TableError(f"{where}: empty flag expression")
        if (sysname, flag) in seen:
            raise TableError(f"{where}: duplicate row {sysname} {flag}")
        seen.add((sysname, flag))

        tokens = args_text.split()
        if not 1 <= len(tokens) <= MAX_ARGS:
            raise TableError(f"{where}: need 1 to {MAX_ARGS} arguments")
        args = []
        flag_slots = 0
        for token in tokens:
            init, is_flags = parse_arg(where, token)
            args.append(init)
            flag_slots += is_flags
        if flag_slots != 1:
            raise TableError(f"{where}: need exactly one F argument, "
                             f"got {flag_slots}")

        with_x = parse_expect(where, with_text)
        without_x = with_x if without_text == "=" else parse_expect(
            where, without_text)
        elfuse_x = parse_expect(where, elfuse_text) if elfuse_text else with_x
        rows.append({"sys": sysname, "label": flag, "flag": flag_expr,
                     "elfuse": elfuse_x,
                     "unsupported": "1" if elfuse_text else "0",
                     "args": ", ".join(args), "nargs": str(len(args)),
                     "with": with_x, "without": without_x,
                     "pending": "1" if pending else "0"})
    if not rows:
        raise TableError(f"{path}: no rows")
    return rows


def render(rows: list[dict[str, str]]) -> str:
    out = [
        "/* Generated by scripts/gen-flag-matrix.py from tests/flag-matrix.tbl.",
        " * Do not edit.",
        " */",
        "",
        "static const struct fm_row fm_rows[] = {",
    ]
    for row in rows:
        out.append(f'    {{"{row["sys"]}", "{row["label"]}", __NR_{row["sys"]}, '
                   f'(long) ({row["flag"]}),')
        out.append(f'     {row["pending"]}, {row["nargs"]}, {{{row["args"]}}},')
        out.append(f'     {row["with"]}, {row["without"]},')
        out.append(f'     {row["unsupported"]}, {row["elfuse"]}}},')
    out.append("};")
    out.append("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--table", type=pathlib.Path, default=DEFAULT_TABLE)
    parser.add_argument("--dispatch", type=pathlib.Path,
                        default=DEFAULT_DISPATCH)
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true",
                        help="fail if the output file is missing or stale")
    parser.add_argument("--list", action="store_true",
                        help="print the syscalls the table covers and exit")
    args = parser.parse_args()

    try:
        rows = parse_table(args.table, load_dispatch(args.dispatch))
    except (OSError, TableError) as exc:
        print(f"gen-flag-matrix: {exc}", file=sys.stderr)
        return 1

    if args.list:
        for name in sorted({row["sys"] for row in rows}):
            print(name)
        return 0

    text = render(rows)
    if args.check:
        try:
            current = args.output.read_text(encoding="utf-8")
        except OSError:
            current = None
        if current != text:
            print(f"gen-flag-matrix: {args.output} is missing or stale",
                  file=sys.stderr)
            return 1
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
