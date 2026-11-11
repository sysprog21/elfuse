"""Fail on a store-buffering handshake that is not sequentially consistent.

Two threads that each store their own flag and then load the other's form the
store-buffering (SB) shape:

    thread A: store x = 1; r0 = load y
    thread B: store y = 1; r1 = load x

Mutual exclusion through this shape needs r0 == 0 && r1 == 0 to be impossible.
Release on the stores and acquire on the loads do not make it so: release orders
what comes before the store, acquire orders what comes after the load, and
nothing orders a store before a later load of another location. In the C11
model (RC11) the outcome is allowed unless both accesses on each side are
memory_order_seq_cst or a seq_cst fence sits between them, and on AArch64 the
release/acquire pair compiles to STLR then LDAPR, which the hardware may
reorder. A stress test rarely reproduces it on Apple silicon, so a review that
reads each side alone, as written, sees nothing wrong with either.

The check is lexical, per function: every store-like atomic (store, exchange,
fetch_*, compare_exchange) to location X followed in the same function by an
atomic load of a different location Y, with no seq_cst fence in between, is
recorded as the pair (X, Y), safe only when both carry memory_order_seq_cst.
A location is named by the last member or variable in the access expression,
with subscripts and casts dropped, so &ctx->ctl->retire.producer_active and
&c->retire.producer_active are both producer_active. The check fails when some
function records (X, Y) and some function records (Y, X) and either side is not
safe: that is the mirrored pair a handshake is made of.

What this deliberately does NOT do is prove a handshake correct, or tell two
unrelated locations that share a field name apart. A matching pair is a reason
to read both functions; the fix is seq_cst on all four accesses or a seq_cst
fence on each side, and tests/genmc is where a handshake is model-checked.

Usage:
    check-sb-handshake.py [--self-test] [ROOT...]
"""

import importlib.util
import pathlib
import re
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "check_atomics", REPO / "scripts" / "check-atomics.py"
)
_atomics = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_atomics)
splice = _atomics.splice
strip_comments = _atomics.strip_comments

CALL_RE = re.compile(
    r"\b(atomic_(?:store|load|exchange|fetch_\w+|compare_exchange_\w+)_explicit"
    r"|atomic_thread_fence)\s*\("
)

# The argument index that carries the order, per operation. compare_exchange
# takes the success order at index 3; its failure order only governs a load.
ORDER_ARG = {"store": 2, "exchange": 2, "fetch": 2, "compare": 3, "load": 1}


def call_args(text, open_paren):
    """Split the argument list starting at text[open_paren] on top-level commas."""
    depth, cur, args = 0, [], []
    for i in range(open_paren, len(text)):
        c = text[i]
        if c in "([{":
            depth += 1
            if depth == 1:
                continue
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(cur).strip())
                return args
        if c == "," and depth == 1:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
    return None


def location(expr):
    """The last identifier of an access expression, subscripts and casts gone."""
    expr = re.sub(r"\[[^\]]*\]", "", expr)
    expr = re.sub(r"\(\s*(?:const\s+)?(?:volatile\s+)?_Atomic[^)]*\)", "", expr)
    words = re.findall(r"[A-Za-z_]\w*", expr)
    return words[-1] if words else None


def function_name(head):
    """The function a top-level brace opens, from the text just before it.

    The declaration is what follows the previous statement, preprocessor line,
    or block; its first identifier followed by a parenthesis is the name.
    Anything ending in "=" opens an initializer, not a body.
    """
    head = re.split(r"[;}]|^\s*#.*$", head, flags=re.M)[-1]
    if head.rstrip().endswith("="):
        return None
    m = re.search(r"([A-Za-z_]\w*)\s*\(", head)
    if not m or m.group(1) in ("if", "for", "while", "switch"):
        return None
    return m.group(1)


def functions(masked):
    """Yield (name, start, end) for each top-level brace block that is a body."""
    depth, start = 0, None
    for i, c in enumerate(masked):
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start is not None:
                name = function_name(masked[max(0, start - 400) : start])
                if name:
                    yield name, start, i
                start = None


def events(body, base, lines):
    """The ordered atomic accesses in one function body."""
    out = []
    for m in CALL_RE.finditer(body):
        name = m.group(1)
        args = call_args(body, m.end() - 1)
        if args is None:
            continue
        line = lines[base + m.start()]
        if name == "atomic_thread_fence":
            out.append(("fence", None, args[0] if args else "", line))
            continue
        op = name[len("atomic_") :].split("_")[0]
        idx = ORDER_ARG.get(op)
        if idx is None or len(args) <= idx:
            continue
        kind = "load" if op == "load" else "store"
        out.append((kind, location(args[0]), args[idx], line))
    return out


def pairs_in(path, text):
    """Yield (x, y, safe, path, func, line) for each store-then-load pair."""
    logical, lines = splice(text)
    masked = strip_comments(logical)
    for func, start, end in functions(masked):
        evs = events(masked[start:end], start, lines)
        for i, (kind, x, xorder, xline) in enumerate(evs):
            if kind != "store" or not x:
                continue
            fenced = False
            for kind2, y, yorder, yline in evs[i + 1 :]:
                if kind2 == "fence":
                    fenced = fenced or "seq_cst" in yorder
                    continue
                if kind2 == "store" and y == x:
                    # The later store to x pairs with the loads after it, and
                    # it is what the other side can observe last.
                    break
                if kind2 != "load" or not y or y == x:
                    continue
                safe = fenced or ("seq_cst" in xorder and "seq_cst" in yorder)
                yield x, y, safe, path, func, xline


def check(roots):
    found = {}
    for root in roots:
        for pattern in ("*.c", "*.h"):
            for path in sorted(root.rglob(pattern)):
                text = path.read_text(errors="replace")
                for x, y, safe, p, func, line in pairs_in(path, text):
                    found.setdefault((x, y), []).append((safe, p, func, line))

    problems, seen = [], set()
    for (x, y), sites in sorted(found.items()):
        mirror = found.get((y, x))
        key = tuple(sorted((x, y)))
        if not mirror or key in seen:
            continue
        if all(s[0] for s in sites) and all(s[0] for s in mirror):
            continue
        seen.add(key)
        lines = [f"store {x} then load {y}, and store {y} then load {x}:"]
        for safe, p, func, line in sites + mirror:
            tag = "seq_cst" if safe else "NOT seq_cst"
            lines.append(f"      {p}:{line} in {func} ({tag})")
        problems.append("\n".join(lines))
    return problems


SELF_TEST_HOST = """
void host_close(_Atomic unsigned *gate, struct ctl *c)
{
    atomic_fetch_add_explicit(gate, 1, memory_order_acq_rel);
    while (atomic_load_explicit(&c->retire.producer_active, memory_order_acquire))
        ;
}
"""

SELF_TEST_EL1 = """
static int el1_enter(struct ctx *context)
{
    atomic_store_explicit(&context->control->retire.producer_active, 1,
                          memory_order_release);
    return atomic_load_explicit(context->gate, memory_order_acquire) != 0;
}
"""


def self_test():
    cases = []

    def case(name, sources, expect_fail):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for fname, text in sources.items():
                (root / fname).write_text(text)
            problems = check([root])
            cases.append((name, bool(problems) == expect_fail, problems))

    case(
        "a release/acquire handshake across two files fails",
        {"host.c": SELF_TEST_HOST, "el1.c": SELF_TEST_EL1},
        True,
    )
    case(
        "a fully seq_cst handshake passes",
        {
            "host.c": SELF_TEST_HOST.replace("acq_rel", "seq_cst").replace(
                "acquire", "seq_cst"
            ),
            "el1.c": SELF_TEST_EL1.replace("release", "seq_cst").replace(
                "acquire", "seq_cst"
            ),
        },
        False,
    )
    case(
        "one side fenced, the other not, still fails",
        {
            "host.c": SELF_TEST_HOST.replace(
                "    while",
                "    atomic_thread_fence(memory_order_seq_cst);\n    while",
            ),
            "el1.c": SELF_TEST_EL1,
        },
        True,
    )
    case(
        "seq_cst fences on both sides pass",
        {
            "host.c": SELF_TEST_HOST.replace(
                "    while",
                "    atomic_thread_fence(memory_order_seq_cst);\n    while",
            ),
            "el1.c": SELF_TEST_EL1.replace(
                "    return",
                "    atomic_thread_fence(memory_order_seq_cst);\n    return",
            ),
        },
        False,
    )
    case("one side alone is not a handshake", {"el1.c": SELF_TEST_EL1}, False)
    case(
        "a commented-out mirror does not count",
        {"host.c": "/*" + SELF_TEST_HOST + "*/", "el1.c": SELF_TEST_EL1},
        False,
    )

    failures = [(n, p) for n, ok, p in cases if not ok]
    if failures:
        print(f"  self-test: {len(failures)} of {len(cases)} cases fail:", file=sys.stderr)
        for name, problems in failures:
            print(f"    {name}: {problems}", file=sys.stderr)
        return 1
    print(f"  self-test: {len(cases)} cases, all pass")
    return 0


def main():
    args = sys.argv[1:]
    if "--self-test" in args:
        print("  SB      self-test", flush=True)
        return self_test()

    roots = [pathlib.Path(a) for a in args] or [REPO / "src"]
    print(f"  SB      {' '.join(str(r) for r in roots)}", flush=True)
    problems = check(roots)
    if problems:
        print(
            f"  {len(problems)} store-buffering handshake(s) without seq_cst:",
            file=sys.stderr,
        )
        for p in problems:
            print(f"    {p}", file=sys.stderr)
        print(
            "\n  Make all four accesses memory_order_seq_cst, or put\n"
            "  atomic_thread_fence(memory_order_seq_cst) between the store and\n"
            "  the load on both sides.",
            file=sys.stderr,
        )
        return 1
    print("  no unordered store-buffering handshake")
    return 0


if __name__ == "__main__":
    sys.exit(main())
