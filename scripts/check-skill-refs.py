#!/usr/bin/env python3
"""Fail when a skill file has drifted from the tree or from another skill.

The files under .claude/skills/ are documentation, so nothing else in the
tree checks them, and a rotted pointer does not read as stale, it reads as
authoritative. The reference that prompted this script named
src/syscall/sidecar.c long after that file was split into casefold.c and
casefold-walk.c, and it survived review.

What is checked, per file:

  1. Frontmatter: name matches the directory, description is non-empty.
  2. Backticked paths resolve, to exactly one file in the tree or one
     beside the skill itself, which is how references/*.md is written. Two
     matches fails as well, since the reference is ambiguous and wants a
     longer path. A path inside a fenced block carries no backticks, so it
     needs a directory component to be recognized.
  3. "make <target>" names a target the makefiles define, including the
     verify-<name> targets mk/verify.mk instantiates from a template.
  4. A quoted section name attached to the word "section" exists as a
     heading in the docs file nearest it.
  5. A named sibling skill exists.
  6. No two skill files share a verbatim passage of DUP_RUN words or more.
     A second copy is the one that goes stale, and nothing else in the tree
     notices it diverge.

Only typeset references count: a path in backticks, a make command in
backticks or in a fenced block. Guessing which words in running prose are
meant to be paths costs more than it catches.

Some things stay unchecked on purpose: paraphrase, which no word match
sees; whether the prose is true, since only the mechanical half rots
silently; and a bare markdown name at the repo root, which may be a
per-developer working doc (see unverifiable()). The "fd.c/h" shorthand for
a file pair is rejected rather than ignored, since allowing it would leave a
reference that looks checked and is not.

A missing .claude/skills/ exits 0 with a note, so a build can call this
without depending on files a clone may not carry.

Usage:
    check-skill-refs.py [file ...]
    check-skill-refs.py --self-test

Every SKILL.md and references/*.md under .claude/skills/ is checked, plus
any file named on the command line, which is how a local routing document
gets covered without this script knowing it exists.

--self-test reads no skill file at all. It writes synthetic skills whose
references are known broken and requires check_file() to reject each one.
Nothing else separates "nothing is stale" from "nothing is checked": a
pattern that has stopped matching prints the same clean line as a tree where
everything resolves. make check-skill-refs runs both modes, self-test first.
"""

import functools
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILL_DIR = ROOT / ".claude" / "skills"

# externals/ is gitignored, so a reference resolving into it would pass on the
# machine that has it checked out and fail everywhere else.
PRUNE = {".git", "build", "externals", "node_modules", ".claude", ".agents"}

PATH_EXTS = ("c", "h", "S", "md", "tbl", "py", "sh", "mk", "yml")

# elfuse-prefixed names that are test-matrix lanes rather than skills.
LANES = {"elfuse-aarch64", "elfuse-x86_64"}

# Headers the SDK supplies, named by the skills as what Frama-C cannot model,
# so they must not resolve in tree. Narrow on purpose: exempting all of sys/
# would wave through a stale sys/anything.c too.
SYSTEM_HEADER_RE = re.compile(r"^(?:sys|Hypervisor)/[A-Za-z0-9_-]+\.h$")

# The leading dot matters: .github and .claude carry real references, and a
# pattern anchored on an alphanumeric would skip exactly those. The trailing
# group drops a shell-function suffix such as test-runner.sh::run.
PATH_RE = re.compile(
    r"`(\.?[A-Za-z0-9_][A-Za-z0-9_./+-]*\.(?:"
    + "|".join(PATH_EXTS)
    + r"))(?:::[A-Za-z_][A-Za-z0-9_]*)?`"
)

# A make target counts only where it is typeset: backticked, or a command line
# in a fenced block. Prose says things like "no make target may reference it",
# and reading that as a target name is how a checker gets switched off. Both
# fenced patterns tolerate any leading whitespace, since a fence inside a
# numbered step is indented to that step's content column, and further still
# one list deeper.
MAKE_RE = re.compile(r"`make ([a-z][a-z0-9-]*)")
MAKE_FENCED_RE = re.compile(r"^[ \t]*make ([a-z][a-z0-9-]*)", re.M)
FENCE_RE = re.compile(r"^[ \t]*(?:```.*?^[ \t]*```|~~~.*?^[ \t]*~~~)", re.M | re.S)

# Fenced paths carry no backticks, so PATH_RE cannot see them. Requiring both a
# directory component and a known extension keeps this off ordinary words and
# off build/elfuse.
FENCED_PATH_RE = re.compile(
    r"(?<![\w./-])((?:[A-Za-z0-9_.+-]+/)+[A-Za-z0-9_.+-]+\.(?:"
    + "|".join(PATH_EXTS)
    + r"))\b"
)

# An inline span holding a slash is a path, so the cross-reference pass does
# not read tools/elfuse-gen as a missing skill. A bare span stays visible.
INLINE_PATH_RE = re.compile(r"`[^`]*/[^`]*`")

DOCPATH_RE = re.compile(r"docs/[a-z0-9-]+\.md")
QUOTED_RE = re.compile(r'"([^"]+)"')
# A run of section names: quotes adjacent to the keyword, joined by commas or
# "and", stopping at the first item that is not another quoted name.
RUN_RE = re.compile(r'^\s*"[^"]+"(?:\s*(?:,|and)\s*"[^"]+")*')
PRE_RUN_RE = re.compile(r'"[^"]+"(?:\s*(?:,|and)\s*"[^"]+")*\s*$')
# The fd.c/h shorthand for a file pair. Nothing below can resolve it, and the
# working docs use it freely, so it is rejected by name.
SHORTHAND_RE = re.compile(r"`([A-Za-z0-9_-]+\.[chS](?:/[chS])+)`")
SKILLREF_RE = re.compile(r"\b(elfuse-[a-z0-9-]+)\b")
HEADING_RE = re.compile(r"^#+\s+(.*?)\s*$", re.M)


def system_header(token):
    """True for a system header the tree is not supposed to contain."""
    return bool(SYSTEM_HEADER_RE.match(token))


def unverifiable(token):
    """True for a reference this script cannot honestly resolve.

    A bare markdown name at the repo root may be a per-developer working doc,
    excluded locally rather than gitignored, so its absence proves nothing.
    Listing the current ones would put private filenames into a script
    everybody reads, and be wrong the day someone keeps a different set.
    """
    return "/" not in token and token.endswith(".md")


def section_refs(sentence):
    """(docs path, section names) pairs a sentence claims.

    Only quotes tied to the word "section" count, since a sentence can name a
    docs file and quote something else entirely. Both orders occur:
    'docs/x.md, section "A"' and 'the "A" section of docs/x.md', and one
    keyword can introduce a list.

    Each run goes to the docs file nearest the keyword. A sentence can cite
    internals.md for a mechanism and testing.md for its baselines, and
    checking against both would pass a heading belonging to the other.
    """
    docs = [(m.start(), m.group(0)) for m in DOCPATH_RE.finditer(sentence)]
    if not docs:
        return []

    refs = []
    for m in re.finditer(r"\bsections?\b", sentence):
        names = []
        before = sentence[: m.start()].rstrip()
        prerun = PRE_RUN_RE.search(before)
        if prerun:
            names.extend(QUOTED_RE.findall(prerun.group(0)))
        run = RUN_RE.match(sentence[m.end() :])
        if run:
            names.extend(QUOTED_RE.findall(run.group(0)))
        if names:
            nearest = min(docs, key=lambda d: abs(d[0] - m.start()))[1]
            refs.append((nearest, names))
    return refs


def tree_paths():
    """Every in-tree file, as a repo-relative path string."""
    paths = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if PRUNE & set(rel.parts):
            continue
        paths.append(rel.as_posix())
    return paths


def resolve(token, paths):
    """Files a reference could name, matched on a trailing path segment.

    The skills cite files three ways: a repo path, an include-style path the
    build resolves through -Isrc, and a bare name. A suffix match covers all
    three and still rejects src/wrong/guest.c, which ends no tracked path.
    """
    return [p for p in paths if p == token or p.endswith("/" + token)]


def make_targets():
    """Static rule names from the makefiles, plus the generated proof targets.

    mk/verify.mk instantiates verify-<name> from a template, so those exist
    only after make expands it; print-verify-targets is the list make reports.
    """
    names = set()
    for mk in [ROOT / "Makefile"] + sorted((ROOT / "mk").glob("*.mk")):
        for line in mk.read_text(errors="replace").splitlines():
            if line.startswith("\t"):
                continue
            if line.startswith(".PHONY:"):
                names.update(line.split(":", 1)[1].split())
                continue
            m = re.match(r"^([A-Za-z0-9._%-]+(?:\s+[A-Za-z0-9._%-]+)*)\s*:(?!=)", line)
            if m:
                names.update(m.group(1).split())
    try:
        out = subprocess.run(
            ["make", "print-verify-targets"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        names.update(out.stdout.split())
    except (OSError, subprocess.SubprocessError):
        pass
    return names


@functools.lru_cache(maxsize=None)
def headings_of(doc):
    """Heading text of a docs file, backticks stripped, or None if absent.

    Cached because one docs file is cited from many sentences and many skills.
    """
    path = ROOT / doc
    if not path.exists():
        return None
    body = path.read_text(errors="replace")
    return frozenset(h.replace("`", "") for h in HEADING_RE.findall(body))


def check_frontmatter(path, raw):
    """A skill's declared name has to match the directory that carries it.

    Claude Code loads a skill by directory, so a drifted name means the file
    is silently not the skill it says it is.
    """
    if path.name != "SKILL.md":
        return []

    head = raw.split("---")[1] if raw.startswith("---") else ""
    name = re.search(r"^name:\s*(\S+)", head, re.M)
    desc = re.search(r"^description:\s*(\S.*)", head, re.M)

    messages = []
    if not name or name.group(1) != path.parent.name:
        messages.append("frontmatter name does not match its directory")
    if not desc:
        messages.append("frontmatter has no description")
    return messages


def local_bases(path):
    """Directories a skill's own pointers resolve against.

    A skill writes references/x.md from SKILL.md and from a sibling under
    references/, so both the file's directory and the skill root are tried.
    The skills directory is third, which is what lets one skill cite
    elfuse-verify/SKILL.md.
    """
    parent = path.parent
    root = parent.parent if parent.name == "references" else parent
    return [parent, root, SKILL_DIR]


def check_paths(text, raw, paths, bases):
    """Every typeset path names exactly one file in the tree.

    @bases are the directories a skill's own references/*.md pointers resolve
    against. .claude stays pruned from the tree walk, so nothing unrelated can
    satisfy one by accident.
    """
    messages = []
    for token in sorted(set(SHORTHAND_RE.findall(text))):
        names = token.split("/")
        stem = names[0].rsplit(".", 1)[0]
        spelled = " and ".join(f"`{stem}.{ext}`" for ext in [names[0][-1]] + names[1:])
        messages.append(f"writes {token}, which nothing resolves; write {spelled}")

    tokens = set(PATH_RE.findall(text))
    for block in FENCE_RE.findall(raw):
        tokens.update(FENCED_PATH_RE.findall(block))

    # is_file(), not exists(): resolve() matches tree_paths(), which is files
    # only, so a directory named like a reference must not satisfy one here.
    for token in sorted(tokens):
        if unverifiable(token) or (ROOT / token).is_file():
            continue
        if any((b / token).is_file() for b in bases):
            continue
        # Exactly one match. A deleted src/a/foo.c would otherwise pass on an
        # unrelated src/b/foo.c, and two matches means the reference is
        # ambiguous and wants a longer path.
        matches = resolve(token, paths)
        if len(matches) == 1:
            continue
        # After resolution, so a stub the tree does carry, like the Hypervisor
        # header under frama-c-stubs/, is verified rather than exempted.
        if system_header(token):
            continue
        if len(matches) > 1:
            where = ", ".join(sorted(matches)[:3])
            messages.append(
                f"{token} is ambiguous, {len(matches)} files carry that "
                f"name ({where}); write the path"
            )
            continue
        messages.append(f"references {token}, which does not exist")
    return messages


def check_targets(text, raw, targets):
    """Every typeset make command names a rule the makefiles define."""
    named = set(MAKE_RE.findall(text))
    for block in FENCE_RE.findall(raw):
        named.update(MAKE_FENCED_RE.findall(block))

    messages = []
    for target in sorted(named):
        # "make verify-<name>" is a form: the capture stops at the angle
        # bracket, leaving a trailing hyphen no real rule has.
        if target.endswith("-"):
            continue
        if target not in targets:
            messages.append(f"names 'make {target}', which no makefile defines")
    return messages


def check_sections(text):
    """Every quoted section name is a heading in the docs file it cites.

    Exact match once backticks are stripped: a prefix would pass "Validation
    Strategy" for a heading titled "Validation Strategy By Change Type".
    """
    messages = []
    for sentence in text.split(". "):
        for doc, names in section_refs(sentence):
            known = headings_of(doc)
            if known is None:
                continue
            for name in names:
                if name not in known:
                    messages.append(f'no section "{name}" in {doc}')
    return messages


def check_skill_refs(text, skills):
    """Every sibling skill named in prose exists as a skill directory."""
    messages = []
    for ref in sorted(set(SKILLREF_RE.findall(INLINE_PATH_RE.sub(" ", text)))):
        if ref in LANES or ref in skills:
            continue
        messages.append(f"refers to skill {ref}, which does not exist")
    return messages


# Shorter shared runs are mostly ordinary phrasing; 20 words is a sentence
# copied, not two writers choosing the same words.
DUP_RUN = 20

# The closing section every skill carries by convention (elfuse-skills) is the
# one place meant to repeat, so it is dropped by heading, whatever its wording,
# up to the next heading of its own level or above, so a subsection stays in.
SOURCES_RE = re.compile(
    r"^##[ \t]+Authoritative sources[ \t]*\n.*?(?=^#{1,2}[ \t]|\Z)", re.M | re.S
)


def shingles(raw):
    """Every DUP_RUN-word window of prose, in order, fences and sources dropped.

    Each stretch between dropped blocks is windowed on its own, so the words
    either side of a fence never join into a passage neither file contains.
    """
    windows = {}
    for segment in SOURCES_RE.sub("\0", FENCE_RE.sub("\0", raw)).split("\0"):
        words = segment.split()
        for i in range(len(words) - DUP_RUN + 1):
            windows.setdefault(" ".join(words[i : i + DUP_RUN]))
    return windows


def check_duplicates(named_texts):
    """Report each pair of files sharing a DUP_RUN-word passage, once."""
    sets = [(name, shingles(raw)) for name, raw in named_texts]
    found = []
    for i, (a, sa) in enumerate(sets):
        for b, sb in sets[i + 1 :]:
            first = next((w for w in sa if w in sb), None)
            if first:
                found.append(
                    f"{a}: repeats a passage of {b}; keep one copy and point "
                    f"at it: \"{' '.join(first.split()[:10])} ...\""
                )
    return found


def check_file(path, paths, targets, skills, errors):
    """Run every pass over one file, prefixing each finding with its path."""
    raw = path.read_text(errors="replace")
    # An explicitly named file may sit outside the repo, where relative_to
    # raises rather than returning something printable.
    try:
        rel = path.relative_to(ROOT)
    except ValueError:
        rel = path

    # Prose wrapped at 79 columns splits references across lines, so every
    # pass below runs on whitespace-collapsed text; the raw text would skip
    # any reference landing on a line boundary. Frontmatter and the fenced
    # scan stay raw, since their patterns are line-anchored.
    text = re.sub(r"\s+", " ", raw)

    messages = (
        check_frontmatter(path, raw)
        + check_paths(text, raw, paths, local_bases(path))
        + check_targets(text, raw, targets)
        + check_sections(text)
        + check_skill_refs(text, skills)
    )
    errors.extend(f"{rel}: {message}" for message in messages)
    return str(rel), raw


# Each case is (what it exercises, body, substring of the expected error or
# None when the body must produce no error at all).
SELF_TEST_CASES = [
    ("wrong directory", "See `src/wrong/guest.c` for it.", "does not exist"),
    ("ambiguous bare name", "See `fuse.h` for it.", "is ambiguous"),
    ("dead make target", "Run `make\ncheck-fmt` first.", "check-fmt"),
    ("non-header under sys/", "Frama-C lacks `sys/bogus.c`.", "does not exist"),
    (
        "section near-miss",
        '`docs/testing.md`, section "Validation Strategy" is the table.',
        "no section",
    ),
    (
        "stale first pre-keyword section",
        'the "Not A Real Heading" and "Build Requirements" sections of '
        "`docs/testing.md` are useful.",
        "no section",
    ),
    (
        "section attributed to the wrong doc",
        "`docs/internals.md` has it and `docs/testing.md`, section "
        '"Memory Layout", does not.',
        "no section",
    ),
    ("unknown sibling skill", "See the `elfuse-nope` skill.", "refers to skill"),
    (
        "unresolvable shorthand",
        "Helpers in `fd.c/h` classify it.",
        "write `fd.c` and `fd.h`",
    ),
    (
        "sibling reference file that is missing",
        "Load `references/gone.md` at step 3.",
        "does not exist",
    ),
    ("path in a fenced block", "```sh\npython3 scripts/nope.py\n```", "does not exist"),
    ("path in a tilde fence", "~~~sh\npython3 scripts/nope.py\n~~~", "does not exist"),
    (
        "path in a fenced block inside a numbered step",
        "1. Run it:\n\n   ```sh\n   python3 scripts/nope.py\n   ```",
        "does not exist",
    ),
    (
        "make target in a fenced block inside a numbered step",
        "1. Run it:\n\n   ```sh\n   make check-fmt\n   ```",
        "check-fmt",
    ),
    (
        "sibling reference that resolves to a directory",
        "Load `references/dirlike.md` at step 3.",
        "does not exist",
    ),
    ("valid repo path", "See `src/core/guest.c`.", None),
    (
        "sibling reference file beside the skill",
        "Load `references/fixture.md` at step 3.",
        None,
    ),
    (
        "valid path in a fenced block",
        "```sh\npython3 scripts/check-mutants.py\n```",
        None,
    ),
    (
        "valid path in a fenced block inside a numbered step",
        "1. Run it:\n\n   ```sh\n   python3 scripts/check-mutants.py\n   ```",
        None,
    ),
    (
        "repo path that looks like a skill name",
        "The `tools/elfuse-gen` script.",
        None,
    ),
    ("valid include-style path", "Include it as `core/guest.h`.", None),
    ("valid system header", "Frama-C cannot model `sys/mount.h`.", None),
    ("valid line-wrapped target", "Run `make\ncheck-format` first.", None),
    ("make in prose is not a target", "No make target may reference it.", None),
    ("target placeholder", "Run `make verify-<name>` for one.", None),
    ("private root markdown", "`CLAUDE.md` is untracked.", None),
    (
        "unrelated quote after a real section",
        '`docs/testing.md`, section "Validation Strategy By Change Type", is '
        'a "wild guess" table.',
        None,
    ),
    (
        "two docs, section attributed correctly",
        '`docs/internals.md` section "Memory Layout" has the map, and '
        "`docs/testing.md` has the baselines.",
        None,
    ),
]

FRONTMATTER = "---\nname: {name}\ndescription: fixture\n---\n\n"


def self_test():
    """Assert this script still rejects each class of stale reference.

    Every case is a bug this script shipped with: a reference broken across
    a line boundary was invisible to every pass, a section name that was a
    prefix of a real heading passed as a match. The negative cases carry the
    same weight, since a checker that flags valid prose gets switched off and
    then protects nothing.
    """
    paths, targets, skills = tree_paths(), make_targets(), {"elfuse-syscall"}
    failures, adhoc = [], 0

    with tempfile.TemporaryDirectory() as tmp:
        skill_dir = pathlib.Path(tmp) / "elfuse-syscall"
        (skill_dir / "references").mkdir(parents=True)
        (skill_dir / "references" / "fixture.md").write_text("fixture\n")
        # A directory named like a reference, for the is_file() case.
        (skill_dir / "references" / "dirlike.md").mkdir()
        fixture = skill_dir / "SKILL.md"

        for label, body, expect in SELF_TEST_CASES:
            fixture.write_text(FRONTMATTER.format(name="elfuse-syscall") + body + "\n")
            errors = []
            check_file(fixture, paths, targets, skills, errors)
            found = " | ".join(e.split(": ", 1)[-1] for e in errors)
            if expect is None and errors:
                failures.append(f"{label}: expected no error, got: {found}")
            elif expect is not None and expect not in found:
                failures.append(f"{label}: expected {expect!r}, got: {found or 'none'}")

        adhoc += 1
        # A reference file cites siblings from one directory deeper, so it
        # needs a fixture that sits there.
        sibling = skill_dir / "references" / "sibling.md"
        sibling.write_text("See `references/fixture.md`.\n")
        errors = []
        check_file(sibling, paths, targets, skills, errors)
        if errors:
            failures.append(f"reference sibling: expected no error, got: {errors}")

        adhoc += 1
        # Frontmatter drift needs its own directory, since the name is checked
        # against the one the file sits in.
        other = pathlib.Path(tmp) / "elfuse-other"
        other.mkdir()
        drift = other / "SKILL.md"
        drift.write_text(FRONTMATTER.format(name="elfuse-syscall") + "Body.\n")
        errors = []
        check_file(drift, paths, targets, skills, errors)
        if not any("frontmatter name" in e for e in errors):
            failures.append("frontmatter drift: expected a name mismatch, got none")

        adhoc += 1
        # The duplicate pass compares files, so it runs on text pairs.
        copied = " ".join(f"w{i}" for i in range(DUP_RUN))
        if not check_duplicates([("a", f"x {copied} y"), ("b", f"z {copied}")]):
            failures.append("duplicate passage: expected a report, got none")
        adhoc += 1
        short = " ".join(copied.split()[1:])
        if check_duplicates([("a", f"x {short} y"), ("b", f"z {short}")]):
            failures.append("run one word short: expected no report, got one")
        adhoc += 1
        footer = f"## Authoritative sources  \n\n- {copied}\n"
        if check_duplicates([("a", "one\n" + footer), ("b", "two\n" + footer)]):
            failures.append("shared footer: expected no report, got one")
        adhoc += 1
        nested = f"## Authoritative sources\n\n### Runtime\n\n{copied}\n"
        if check_duplicates([("a", nested), ("b", nested)]):
            failures.append("footer subsection: expected no report, got one")
        adhoc += 1
        tilde = f"~~~\n{copied}\n~~~\n"
        if check_duplicates([("a", tilde), ("b", tilde)]):
            failures.append("tilde-fenced code: expected no report, got one")
        adhoc += 1
        half = copied.split()
        joined = " ".join(half[:10]) + "\n```\ncode\n```\n" + " ".join(half[10:])
        if check_duplicates([("a", joined), ("b", copied)]):
            failures.append("passage split by a fence: expected no report, got one")

    total = len(SELF_TEST_CASES) + adhoc
    if failures:
        print(
            f"  {len(failures)} of {total} self-test case(s) failed:", file=sys.stderr
        )
        for f in failures:
            print(f"    {f}", file=sys.stderr)
        return 1
    print(f"  self-test: {total} cases, all pass")
    return 0


def main():
    if "--self-test" in sys.argv[1:]:
        print("  SKILL   self-test", flush=True)
        return self_test()

    print("  SKILL   .claude/skills/", flush=True)

    skills, files = set(), []
    if SKILL_DIR.is_dir():
        skills = {d.name for d in SKILL_DIR.iterdir() if (d / "SKILL.md").is_file()}
        files = sorted(SKILL_DIR.glob("*/SKILL.md")) + sorted(
            SKILL_DIR.glob("*/references/*.md")
        )

    # A routing file is checked the same way, but only when its owner names
    # it: whether one exists is local to a working copy. It is checked even in
    # a clone with no skills directory, where its references rot fastest.
    for extra in sys.argv[1:]:
        path = pathlib.Path(extra)
        if not path.is_absolute():
            path = ROOT / extra
        if not path.is_file():
            print(f"  {extra}: not a file", file=sys.stderr)
            return 1
        files.insert(0, path)

    # One file named two ways is still one file.
    files = list(dict.fromkeys(path.resolve() for path in files))

    if not files:
        print("  no .claude/skills/ in this clone; nothing to check")
        return 0

    paths, targets, errors, skill_texts = tree_paths(), make_targets(), [], []
    for path in files:
        named = check_file(path, paths, targets, skills, errors)
        if SKILL_DIR in path.parents:
            skill_texts.append(named)
    errors += check_duplicates(skill_texts)

    # A file may name the same missing thing twice; report each once.
    errors = list(dict.fromkeys(errors))
    if errors:
        print(f"  {len(errors)} stale reference(s):", file=sys.stderr)
        for e in errors:
            print(f"    {e}", file=sys.stderr)
        return 1

    print(
        f"  {len(files)} file(s), every path, target, section, and "
        "cross-reference resolves, no passage repeats"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
