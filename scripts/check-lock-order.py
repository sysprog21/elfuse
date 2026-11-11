"""Fail when a lock exists that the lock-order document does not name.

src/syscall/internal.h opens with the acquisition order, and that block is the
only place the tree records which lock may be taken under which. It is prose, so
nothing stopped it from falling behind the code: at the time this check was
written it named 9 of the tree's 31 file-scope locks (one of those under a
shortened spelling that did not match the symbol), and seven of the twenty-two
it left out genuinely nested (autoreap_lock over pid_lock and pidfd_lock,
elf_path_lock over cwd_lock and sysroot_lock, oom_write_lock over fd_lock,
fuse_lock over the per-session lock, proc_tmpdir_lock over mmap_lock,
pty_keepalive_lock over fd_lock, cwd_lock over fuse_lock). Every one of those
was correct as written. The defect was that a reader adding the next lock had
no rule to consult, and an inversion is not the kind of bug the test suite
finds: it needs the two threads to interleave the one way that deadlocks, on a
machine loaded enough to make that likely, which describes CI and not a
developer's laptop.

So the document claims to be exhaustive, and this makes the claim true. Two
directions, both a set comparison rather than an analysis:

  1. Every file-scope pthread_mutex_t and pthread_rwlock_t under src/ appears
     in the block.
  2. Every lock the block names still exists in the source.

What this deliberately does NOT do is decide whether a lock belongs in the
ordered list or the leaf list. That question is "is this lock ever held across
another acquisition", which needs the call graph, and a branch-insensitive
answer to it is wrong in both directions: a linear scan of fuse.c drops
fuse_lock at an early-return unlock and calls it a leaf, while the same scan
reads two comments mentioning sys_close() as an sfd_lock/fd_lock cycle. Both
happened while auditing this. A gate that cries wolf gets an exemption list and
then gets ignored, so the placement stays a human judgement and only the
membership is mechanical. Placing a new lock wrongly is a mistake review can
catch; forgetting it entirely is the one nothing was looking for.
"""

import pathlib
import re
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
HEADER = pathlib.Path("src/syscall/internal.h")
SRC = pathlib.Path("src")

# A definition, not a declaration: column zero, so internal.h's own "extern
# pthread_mutex_t mmap_lock;" lines and any struct member (which clang-format
# indents) count as neither a definition nor a mention.
#
# The declarator list is captured whole rather than as one name, because every
# form of it has to be seen. A sharded "pthread_mutex_t shard_locks[16];" is the
# most likely next lock in a tree that already contends on mmap_lock, and a
# pattern anchored on "= PTHREAD_MUTEX_INITIALIZER" or on a single identifier
# misses it silently, which is the one way for a gate to be worse than no gate.
#
# pthread_rwlock_t counts as a lock too. The tree has two of them today
# (sysinfo_lock in syscall/sys.c, overlay_lock in syscall/chown-overlay.c), and
# a gate that only knew about pthread_mutex_t would have let the block claim to
# be exhaustive while both sat outside it.
#
# Everything between the type and the semicolon is captured, initializers
# included, and the structure is taken apart afterwards. Splitting it in the
# pattern cannot work: an initializer clause that stops at the first comma drops
# the declarators after it ("first = A, second;" loses second), one that runs to
# the semicolon swallows them, and one that refuses braces skips a brace
# initializer outright. All three are silent misses, which is the one shape
# worse than no gate. A function definition survives this because its declarator
# keeps the parenthesis or the leading star that declared_names rejects.
DEFINITION = re.compile(r"^(?:static\s+)?pthread_(?:mutex|rwlock)_t\s+([^;]+);", re.M)

# An ordered entry names its owning file and ends in a colon:
#     *   mmap_lock    (syscall/mem.c):     mmap/brk allocators
ORDERED = re.compile(r"^ \*   (\w+)\s+\([\w/.\-]+\):", re.M)

# A leaf entry is the same without the colon, two to a line:
#     *   absock_lock (net-absock.c)       nl_lock (netlink.c)
LEAF = re.compile(r"(\w+) \([\w/.\-]+\)(?!:)")


def split_declarators(declarators):
    """Split a declarator list on the commas that separate declarators.

    A comma inside parentheses, brackets or braces belongs to a parameter list,
    an array bound or an initializer, not to the list. Splitting on every comma
    tears "f(int a, int b)" into "f(int a" and "int b)", and only the first
    carries the parenthesis that marks it a function, so the second reads as a
    declarator named int and the gate demands the tree document a lock called
    int. Braces matter for the same reason in the other direction:
    "shard_locks[2] = {A, B}" is one declarator, not two.
    """
    parts, depth, cur = [], 0, []
    for ch in declarators:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def strip_initializer(declarator):
    """One declarator without its initializer.

    The "=" has to be the declarator's own, not one inside a brace initializer
    or a parameter default, so the scan stops at the first one outside every
    bracket. Cutting at the first "=" anywhere would truncate
    "shard_locks[2] = {A, B}" the same way but would also mangle a declarator
    whose array bound contains one.
    """
    depth = 0
    for i, ch in enumerate(declarator):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "=" and depth == 0:
            return declarator[:i]
    return declarator


def declared_names(declarators):
    """The mutex names in one declarator list.

    "a_lock = PTHREAD_MUTEX_INITIALIZER" -> a_lock
    "shard_locks[16]"                    -> shard_locks
    "a_lock, b_lock"                     -> a_lock, b_lock
    "first = A, second"                  -> first, second

    A pointer declarator is not a lock, it refers to one, so "*held" yields
    nothing: making the tree document a pointer would be a false positive, and
    the mutex it points at is defined somewhere this already sees. A declarator
    carrying a parameter list is a function returning the type rather than an
    object of it, which is what thread_get_lock in runtime/thread.h is.
    """
    names = []
    for part in split_declarators(declarators):
        part = strip_initializer(part).strip()
        if not part or part.startswith("*") or "(" in part:
            continue
        name = re.match(r"(\w+)", part)
        if name:
            names.append(name.group(1))
    return names


def lock_definitions(root):
    """Every file-scope mutex or rwlock under root, as {name: [paths]}.

    Headers are scanned too. None defines a mutex today, and the exhaustive
    claim the block above makes is about the tree rather than about one
    extension: a static definition in a header compiles into every translation
    unit that includes it, so it is the case least likely to be noticed and the
    one that most needs naming.
    """
    found = {}
    for pattern in ("*.c", "*.h"):
        for path in sorted(root.rglob(pattern)):
            for declarators in DEFINITION.findall(path.read_text(errors="replace")):
                for name in declared_names(declarators):
                    found.setdefault(name, []).append(path)
    return found


def documented_locks(header_text):
    """The ordered and leaf name sets from the lock-ordering block.

    Returns (ordered, leaves, ok). ok is False when the block itself is
    missing or malformed, which is its own failure: a header that lost the
    block would otherwise report every lock as undocumented and bury the
    real cause under twenty-nine lines of noise.

    The markers decide that, not the size of either list. Either list may
    legitimately empty out, one when no lock is held across another and the
    other when every lock is, and neither is a malformed header. Parsing
    nothing at all from a block whose markers are present is different: it
    means the entry spelling drifted out from under the patterns, so it keeps
    the one clear error rather than becoming a wall of false ones.
    """
    start = header_text.find(" * Lock ordering")
    if start < 0:
        return set(), set(), False
    end = header_text.find("\n */", start)
    if end < 0:
        return set(), set(), False
    block = header_text[start:end]

    split = block.find(" * Leaves.")
    if split < 0:
        return set(), set(), False

    ordered = set(ORDERED.findall(block[:split]))
    leaves = set(LEAF.findall(block[split:]))
    return ordered, leaves, bool(ordered or leaves)


def check(root, header_path):
    """Report every disagreement between the source and the document."""
    problems = []
    defined = lock_definitions(root)
    ordered, leaves, ok = documented_locks(header_path.read_text(errors="replace"))

    if not ok:
        problems.append(
            f"{header_path}: no readable lock-ordering block "
            "(expected ' * Lock ordering' and ' * Leaves.' before the close)"
        )
        return problems, defined, ordered, leaves

    for name in sorted(defined):
        where = ", ".join(str(p) for p in defined[name])

        # Two mutexes sharing a name are two locks, and one entry cannot
        # document both: the reader who looks the name up gets whichever the
        # author had in mind. Rejecting the collision keeps the check a
        # statement about every mutex rather than about every distinct name,
        # without teaching it to match the owning file, which would tie it to
        # how each entry happens to spell a path.
        if len(defined[name]) > 1:
            problems.append(
                f"{name} is defined in more than one place ({where}); "
                "one document entry cannot name both"
            )
            continue

        if name in ordered and name in leaves:
            problems.append(
                f"{name} ({where}) is in both the ordered list and the leaf "
                "list; a lock is one or the other"
            )
        elif name not in ordered and name not in leaves:
            problems.append(
                f"{name} ({where}) is in neither list. Put it in the ordered "
                "list if anything is acquired while it is held, in the leaf "
                "list if nothing is"
            )

    # Both patterns require the "name (file.c)" shape an entry has and the
    # surrounding prose does not, which is what keeps a sentence out of these
    # sets. The per-instance locks the block names by role ("epoll inst",
    # "futex bucket") are two words and match neither, so they never arrive
    # here needing to be filtered back out.
    for name in sorted((ordered | leaves) - set(defined)):
        problems.append(f"{name} is documented but no longer defined under {root}")

    return problems, defined, ordered, leaves


SELF_TEST_HEADER = """/*
 * Lock ordering (acquire in ascending order to prevent deadlocks).
 *
 *   outer_lock   (a.c):   holds inner_lock beneath it
 *   inner_lock   (b.c):   inner
 *
 * Leaves.
 *
 *   quiet_lock (c.c)
 */
#pragma once
"""


def self_test():
    """Synthetic trees, so the check is shown to fail before it is trusted."""
    cases = []

    def case(name, sources, header, expect):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "src"
            root.mkdir()
            for fname, text in sources.items():
                (root / fname).write_text(text)
            hpath = pathlib.Path(tmp) / "internal.h"
            hpath.write_text(header)
            problems, *_ = check(root, hpath)
            hit = any(expect in p for p in problems)
            cases.append((name, hit if expect else not problems, problems))

    ok_sources = {
        "a.c": "pthread_mutex_t outer_lock = PTHREAD_MUTEX_INITIALIZER;\n",
        "b.c": "static pthread_mutex_t inner_lock = PTHREAD_MUTEX_INITIALIZER;\n",
        "c.c": "static pthread_mutex_t quiet_lock = PTHREAD_MUTEX_INITIALIZER;\n",
    }
    case("a documented tree passes", ok_sources, SELF_TEST_HEADER, "")

    case(
        "an undocumented lock fails",
        dict(
            ok_sources,
            **{
                "d.c": "static pthread_mutex_t new_lock = "
                "PTHREAD_MUTEX_INITIALIZER;\n"
            },
        ),
        SELF_TEST_HEADER,
        "new_lock",
    )

    case(
        "a zero-initialized undocumented lock fails",
        dict(
            ok_sources,
            **{"d.c": "static pthread_mutex_t new_lock;\n"},
        ),
        SELF_TEST_HEADER,
        "new_lock",
    )

    case(
        "an undocumented lock array fails",
        dict(ok_sources, **{"d.c": "static pthread_mutex_t new_lock[16];\n"}),
        SELF_TEST_HEADER,
        "new_lock",
    )

    # The form the old pattern skipped: the brace initializer ended the match
    # before the declarator was ever read, so a whole array of locks went
    # undocumented with the gate green.
    case(
        "a brace-initialized undocumented lock array fails",
        dict(
            ok_sources,
            **{
                "d.c": "static pthread_mutex_t new_lock[2] = {\n"
                "    PTHREAD_MUTEX_INITIALIZER,\n"
                "    PTHREAD_MUTEX_INITIALIZER,\n"
                "};\n"
            },
        ),
        SELF_TEST_HEADER,
        "new_lock",
    )

    # An rwlock is a lock. The tree has two, and a mutex-only pattern let both
    # stay out of a block that claims to name every one.
    case(
        "an undocumented rwlock fails",
        dict(
            ok_sources,
            **{
                "d.c": "static pthread_rwlock_t new_lock = "
                "PTHREAD_RWLOCK_INITIALIZER;\n"
            },
        ),
        SELF_TEST_HEADER,
        "new_lock",
    )

    case(
        "the second name in a declarator list is not missed",
        dict(
            ok_sources,
            **{"d.c": "static pthread_mutex_t quiet_lock, new_lock;\n"},
        ),
        SELF_TEST_HEADER,
        "new_lock",
    )

    # A pointer refers to a lock rather than being one, so demanding it be
    # documented would be a false positive. The mutex it aims at is defined
    # wherever it is defined, and that definition is what this sees.
    case(
        "a pointer declarator is not a definition",
        dict(ok_sources, **{"e.c": "static pthread_mutex_t *held_lock;\n"}),
        SELF_TEST_HEADER,
        "",
    )

    case(
        "a lock in both lists fails",
        ok_sources,
        SELF_TEST_HEADER.replace(
            " *   quiet_lock (c.c)", " *   quiet_lock (c.c)   inner_lock (b.c)"
        ),
        "inner_lock",
    )

    case(
        "a deleted lock still documented fails",
        {k: v for k, v in ok_sources.items() if k != "c.c"},
        SELF_TEST_HEADER,
        "quiet_lock",
    )

    case(
        "a mutex defined in a header is seen",
        dict(ok_sources, **{"d.h": "static pthread_mutex_t new_lock;\n"}),
        SELF_TEST_HEADER,
        "new_lock",
    )

    # runtime/thread.h declares pthread_mutex_t *thread_get_lock(void) at
    # column zero, which is a function returning the type, not a lock.
    case(
        "a function returning the type is not a definition",
        dict(
            ok_sources,
            **{"d.h": "pthread_mutex_t get_lock(void);\n"},
        ),
        SELF_TEST_HEADER,
        "",
    )

    # The parameter list carries its own commas. Splitting on all of them
    # leaves "int b)" looking like a declarator, so the gate asks the tree to
    # document a lock named int.
    # An initializer clause that runs to the semicolon swallows the declarators
    # behind it, which is a silent miss rather than a false report.
    case(
        "a declarator after an initializer is not missed",
        dict(
            ok_sources,
            **{
                "d.c": "static pthread_mutex_t quiet_lock = "
                "PTHREAD_MUTEX_INITIALIZER, new_lock;\n"
            },
        ),
        SELF_TEST_HEADER,
        "new_lock",
    )

    case(
        "a declarator after a brace initializer is not missed",
        dict(
            ok_sources,
            **{"d.c": "static pthread_mutex_t ring[2] = {A, B}, new_lock;\n"},
        ),
        SELF_TEST_HEADER,
        "new_lock",
    )

    case(
        "a parameter list is not a declarator list",
        dict(
            ok_sources,
            **{"d.h": "pthread_mutex_t make_lock(int a, int b);\n"},
        ),
        SELF_TEST_HEADER,
        "",
    )

    case(
        "the same name defined twice is rejected",
        dict(ok_sources, **{"d.c": "static pthread_mutex_t quiet_lock;\n"}),
        SELF_TEST_HEADER,
        "more than one place",
    )

    # Either list may legitimately empty out. A block that still has both
    # markers and parses one list is a document, not a malformed header.
    case(
        "an empty leaf list is not a malformed block",
        {
            "a.c": "pthread_mutex_t outer_lock = PTHREAD_MUTEX_INITIALIZER;\n",
            "b.c": "static pthread_mutex_t inner_lock;\n",
        },
        "/*\n * Lock ordering.\n *\n *   outer_lock   (a.c):   holds inner_lock\n"
        " *   inner_lock   (b.c):   inner\n *\n * Leaves.\n *\n * None today.\n */\n",
        "",
    )

    case(
        "a header with no block fails as a header problem",
        ok_sources,
        "/*\n * Nothing here.\n */\n",
        "no readable lock-ordering block",
    )

    # An extern declaration is not a definition, so a header included by the
    # scan must not register a lock the .c files do not define.
    case(
        "an extern declaration is not a definition",
        dict(ok_sources, **{"e.c": "extern pthread_mutex_t elsewhere_lock;\n"}),
        SELF_TEST_HEADER,
        "",
    )

    failures = [(n, p) for n, hit, p in cases if not hit]
    if failures:
        print(
            f"  {len(failures)} of {len(cases)} self-test case(s) failed:",
            file=sys.stderr,
        )
        for name, problems in failures:
            print(f"    {name}: {problems}", file=sys.stderr)
        return 1
    print(f"  self-test: {len(cases)} cases, all pass")
    return 0


# The document's one lock below the whole order: any lock, a leaf included, may
# log while held (the paragraph under the leaf list in internal.h says so).
BOTTOM = "log_mutex"


def emit_lockdep(header_text, out):
    """Write the order document as the table src/debug/lockdep.c reads.

    The ordered list's position is the rank, since the block says to acquire in
    ascending order; the "Lock order: N" numbers at the definitions are not.
    """
    start = header_text.find(" * Lock ordering")
    end = header_text.find("\n */", start)
    block = header_text[start:end]
    split = block.find(" * Leaves.")
    ordered = ORDERED.findall(block[:split])
    leaves = sorted(set(LEAF.findall(block[split:])))
    if not ordered or BOTTOM not in leaves:
        print(f"  cannot emit lockdep table from {HEADER}", file=sys.stderr)
        return 1

    lines = [
        f"/* Generated by scripts/check-lock-order.py from {HEADER}. */",
        "#pragma once",
        "#define LOCKDEP_ORDERED 1",
        "#define LOCKDEP_LEAF 2",
        "#define LOCKDEP_BOTTOM 3",
        "#define LOCKDEP_DOC_ENTRIES \\",
    ]
    for rank, name in enumerate(ordered):
        lines.append(f'    {{"{name}", LOCKDEP_ORDERED, {rank}}}, \\')
    for name in leaves:
        kind = "LOCKDEP_BOTTOM" if name == BOTTOM else "LOCKDEP_LEAF"
        lines.append(f'    {{"{name}", {kind}, -1}}, \\')
    lines.append("")
    pathlib.Path(out).write_text("\n".join(lines) + "\n")
    return 0


def main():
    if "--emit-lockdep" in sys.argv[1:]:
        out = sys.argv[sys.argv.index("--emit-lockdep") + 1]
        return emit_lockdep((REPO / HEADER).read_text(errors="replace"), out)

    if "--self-test" in sys.argv[1:]:
        print("  LOCKS   self-test", flush=True)
        return self_test()

    print(f"  LOCKS   {HEADER}", flush=True)
    problems, defined, ordered, leaves = check(REPO / SRC, REPO / HEADER)
    if problems:
        print(
            f"  {len(problems)} lock(s) disagree with the order document:",
            file=sys.stderr,
        )
        for p in problems:
            print(f"    {p}", file=sys.stderr)
        print(f"\n  The block at the top of {HEADER} is the document.", file=sys.stderr)
        return 1

    named = len(ordered & set(defined))
    print(
        f"  {len(defined)} file-scope lock(s), all named: "
        f"{named} ordered, {len(leaves)} leaf"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
