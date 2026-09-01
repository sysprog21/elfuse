#!/usr/bin/env python3
"""Decide which proof targets a set of changed files can affect.

verify.yml asks this file what to run, so it decides whether a proof runs at
all on a pull request. A target the diff cannot reach keeps the verdict the
base branch already established; a push to the base still proves everything, so
the guarantee on the branch a PR merges into is never the narrowed one.

Two questions, one code path. Without --mutation the answer is which targets to
prove; with it, which mutation sets to re-run, which a change to the machinery
that only schedules the run cannot alter. See SCHEDULING_FILES.

Every "cannot tell" answer widens back to the full set. Scoping is an
optimization, and an optimization that guesses turns into a correctness
problem: failing the run, or narrowing on an unverified assumption, are both
worse than proving something twice.

Two things decide the scope:

  - the include closure of each proved source, per the compiler's own -MM,
    unioned with that target's VERIFY_<T>_SCAN list and preprocessed with its
    VERIFY_<T>_CPP_DEFS, so the scan sees what the prover sees;
  - HARNESS_FILES and STUB_PREFIX, the inputs no closure can see.

--self-test pins what can rot in those two. It runs in lint.yml, the one
workflow with no path filter at all, so this file cannot skip the check on
itself.

Usage:
    proof-scope.py --print-targets-changed-since REF [--mutation]
    proof-scope.py --self-test
"""

import argparse
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


# scripts/ filenames are kebab-case per CLAUDE.md, which no plain "import"
# statement can name, so the shared reader is loaded by path.
def _load_verify_mk():
    import importlib.util

    path = pathlib.Path(__file__).resolve().parent / "verify-mk.py"
    spec = importlib.util.spec_from_file_location("verify_mk", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify_mk = _load_verify_mk()


# Changing any of these can change a verdict for every target, so a run that
# sees one move must not skip anything. mk/toolchain.mk sets CC, which
# check-char-signedness.py compiles with. The individual VERIFY_*_SRC/_SCAN/
# _FCTS lines in mk/verify.mk are covered separately by target_inputs() below,
# but the rest of that file (the shared recipe, MIN_GOALS, FRAMAC_TIMEOUT) is
# not, so the whole file still belongs here. mk/config.mk defines BUILD_DIR,
# which reaches the prover twice: as -I$(BUILD_DIR) in FRAMAC_CPP_ARGS and as
# the order-only prerequisite every verify rule carries; mk/common.mk is what
# builds that directory. The top-level Makefile owns the include of
# mk/verify.mk, so a Makefile-only diff can break the harness without touching
# any input a closure can see. None of these show up in an include closure.
#
# The scripts, the workflows and the composite actions are derived rather than
# listed: mk/verify.mk's recipes name the checkers they run, and the workflows
# name what they invoke. The rot nothing can catch from the other side is a new
# participant that nobody adds, so each derivation errs wide. The makefile half
# stays hand-listed because $(MAKEFILE_LIST) would pull in
# mk/{shim,tests,lint,...}.mk too, widening for changes that cannot reach a
# proof.
HARNESS_FILES = (
    verify_mk.recipe_scripts()
    | verify_mk.proof_actions()
    | verify_mk.proof_workflows()
    | {
        "scripts/verify-mk.py",
        "Makefile",
        "mk/verify.mk",
        "mk/toolchain.mk",
        "mk/config.mk",
        "mk/common.mk",
    }
)

# The mutation gate asks a narrower question than the proofs: does THIS target
# reject THIS broken source. Two harness files cannot change that answer, so a
# branch touching only those re-proves everything, as it must, without also
# re-running 93 mutations whose sources it never touched. Measured on a real
# run, that half was 51 of the workflow's 85 macOS-minutes.
#
# An exception list, carved out of the set above rather than built beside it,
# because the derivations that fill that set are deliberately wide and this is
# the one place anything narrows. lint.yml runs the self-test and no proof.
# proof-scope.py picks the two matrices; a bug there runs the wrong set of
# targets, which is a scoping failure the self-test guards and a push to main
# corrects, not a wrong verdict about a target that did run.
#
# verify.yml is deliberately NOT here: it carries FRAMAC_TIMEOUT and the make
# invocation for the mutation runs, and check-mutants.py's docstring explains
# why a shorter timeout silently converts a MISS into a "caught". verify-mk.py
# is not here either, since it hands check-mutants.py the per-target source a
# mutation copies and mutates. self_test refuses any scheduling workflow that
# carries a mark of either kind, which is what would have caught verify.yml.
#
# The entry below carries one obligation on this file: nothing a mutation run
# judges by may reach check-mutants.py through it. That is why check-mutants.py
# loads verify-mk.py itself rather than taking proof_scope.verify_mk, which
# would have routed the per-target source table through a file listed here.
SCHEDULING_FILES = {
    ".github/workflows/lint.yml",
    "scripts/proof-scope.py",
}

MUTATION_HARNESS_FILES = HARNESS_FILES - SCHEDULING_FILES

# A file cannot schedule a run and also judge it. These marks are what judging
# looks like in a workflow: a prover budget, a mutation knob, an invocation of
# the proof recipe, or a call into the action that installs the analyzer.
JUDGING_MARKS = ("FRAMAC_", "MUTANT_", "make verify", "uses: ./.github/actions/")


def _proof_relevant_names():
    """Variable names whose value can reach the prover.

    A fixpoint, not a union. Start from what mk/verify.mk expands, since that
    is the only file the proof recipe reads, then follow definitions: if a name
    in the set is assigned somewhere in PROOF_MAKEFILES, whatever that
    assignment expands joins the set. BUILD_DIR arrives because the recipe
    names it; anything BUILD_DIR is built out of arrives because BUILD_DIR
    does.

    Taking the plain union instead was measured and wrong in a way that
    defeated the whole point: mk/config.mk references its own test-list
    variables, so NATIVE_TESTS, ROSETTA_X86_64_SRCS and TEST_C_SRCS counted as
    proof-relevant and any edit to them re-proved all 17 targets. That was 11
    of the 25 remaining full-scope runs over 400 commits.

    The seed is wider than mk/verify.mk for one reason. In the other three
    makefiles a reference OUTSIDE an assignment's right-hand side -- in a
    conditional, a prerequisite, a recipe -- decides something the fixpoint
    cannot follow, because there is no assignment to walk back through.
    mk/common.mk's "ifeq ($(V),1)" is what picks Q, which every verify recipe
    expands; seeding only from mk/verify.mk would leave V inert and let a "V :=
    1" in a sliced file prune that file out of the diff. The test-list
    variables stay excluded because they are referenced only from assignment
    right-hand sides, which is the whole distinction.

    That seed is deliberately not narrowed to conditionals. CFLAGS and
    GENERATED_HEADERS come back with it, off mk/common.mk's compile rule, which
    no proof reads; excluding them again means recognizing which rules are on
    the proof path, and being wrong there narrows. Paying for a full run on the
    rare mk/config.mk CFLAGS edit is the cheaper mistake.

    Still the safe direction where it cannot tell: a name reached only through
    a computed reference, $($(VAR)_SRC) and the like, is invisible here, and
    the slicer keeps every line it cannot classify anyway.
    """
    texts = [re.sub(r"\\\n", " ", (ROOT / mk).read_text()) for mk in PROOF_MAKEFILES]
    expands = lambda s: set(re.findall(r"\$[({]([A-Za-z_.][A-Za-z0-9_.-]*)[)}]", s))
    assignment = re.compile(
        r"^\s*(?:(?:override|export)\s+)*([A-Za-z_.][A-Za-z0-9_.-]*)"
        r"\s*(?::::?=|:=|\+=|\?=|!=|=)(.*)$",
        re.M,
    )

    def outside_assignments(text):
        """Names expanded anywhere but an assignment's right-hand side.

        The left-hand side counts: a computed name, "$(T)_SRC := ...", is
        decided by whatever it expands.
        """
        out = set()
        for line in text.splitlines():
            m = assignment.match(line)
            out |= expands(line[: m.end(1)] if m else line)
        return out

    names = expands(texts[0])
    for text in texts[1:]:
        names |= outside_assignments(text)
    growing = True
    while growing:
        growing = False
        for text in texts:
            for m in assignment.finditer(text):
                if m.group(1) in names and not expands(m.group(2)) <= names:
                    names |= expands(m.group(2))
                    growing = True
    return names


def makefile_proof_slice(text):
    """The lines of the top-level Makefile a proof can be reached through.

    It is in HARNESS_FILES because it owns which mk/*.mk get read, and a
    proof runs inside whatever those set up. That is also ALL it owns here:
    the file uses BUILD_DIR and CC but defines neither, and its own nine
    assignments (SRCS, OBJS, the dispatch generator, the test cross-compile
    flags) are the elfuse build, which no proof reads.

    Treating every edit to it as proof-relevant was measured: over 400
    commits, 46 touched the Makefile and it was the sole reason 36 of them
    re-proved all 17 targets, each a rule for a new test binary or a source
    added to SRCS. That is 60 percent of the full-scope runs, bought by a
    file whose proof surface is nine include lines.

    So the entry stays and the question narrows: did the part a proof can
    reach change? The variable names come from mk/verify.mk rather than a
    list here, so a recipe that starts reading something new is covered
    without anyone remembering this function exists.

    Kept by exclusion rather than by recognition, which is the whole point.
    An earlier version listed the constructs that count (include lines,
    assignments) and dropped everything else, so every make directive it had
    not thought of read as inert: "SHELL := /bin/sh", ".ONESHELL:", a
    define/endef body, an "ifeq" flipped around an assignment the prover
    reads. Each changes how "make verify-<t>" runs while leaving the slice
    byte-identical, which prunes the file and narrows the scope to nothing.
    Listing what is PROVABLY inert instead puts the unrecognized line in the
    slice, so the failure direction matches the rest of this file.
    """
    read_by_verify = _proof_relevant_names()
    # The assignment forms make accepts, not just the plain ones: "override",
    # "export" and "unexport" can prefix any of them, and != assigns the output
    # of a shell command. An "override FRAMAC_TIMEOUT := 1" this failed to
    # parse would land in the slice rather than out of it, but the name is what
    # decides inertness, so it has to be read correctly either way.
    #
    # Non-greedy on the name, because make does not require the space: a greedy
    # class reads "CFLAGS+=-O2" as a variable literally called "CFLAGS+", which
    # is in no proof makefile, so the line reads as inert and drops out.
    assign = re.compile(
        r"^\s*(?:(?:override|export|unexport)\s+)*([^\s:=]+?)\s*"
        r"(?::::?=|:=|\+=|\?=|!=|=)"
    )
    rule = re.compile(r"^[^\t#][^:=]*:(?!=)")

    def inert_name(name):
        """Whether an assignment to @name can be ignored.

        A name no proof makefile ever expands cannot reach the prover. make's
        own specials are the exception: nothing writes "$(SHELL)", yet it
        decides which shell every verify recipe runs under. Dotted names go
        the same way, .DEFAULT_GOAL included.
        """
        return not (
            name in read_by_verify
            or name.startswith(".")
            or name in ("SHELL", "VPATH", "MAKEFILES", "GNUMAKEFLAGS")
        )

    kept = []
    # Continuations joined first, so a wrapped SRCS list is one logical line
    # rather than a head this classifies and a tail it cannot.
    for line in re.sub(r"\\\n", " ", text).splitlines():
        stripped = line.strip()
        # Blank, comment, or a recipe body. A recipe under a rule this already
        # calls inert cannot reach a proof either.
        if not stripped or stripped.startswith("#") or line.startswith("\t"):
            continue
        head = assign.match(line)
        if head:
            if inert_name(head.group(1)):
                continue
            kept.append(line.rstrip())
            continue
        if rule.match(line):
            target, _, tail = line.partition(":")
            # A target-specific override assigns for one rule, and
            # "verify-fuse: FRAMAC_TIMEOUT := 1" reaches that proof with no
            # line-initial assignment to see.
            specific = assign.match(tail)
            if specific and not inert_name(specific.group(1)):
                kept.append(line.rstrip())
                continue
            # .ONESHELL and .DELETE_ON_ERROR change how every recipe runs;
            # .PHONY is excluded because it names what is already a rule and
            # grows with every build target anyone adds.
            names = target.split()
            if any(n.startswith(".") and n != ".PHONY" for n in names):
                kept.append(line.rstrip())
            continue
        # Not blank, not a comment, not a recipe, not an assignment this can
        # read, not a rule: an include, a conditional, a define, a vpath, or
        # something make grew since. Unrecognized means kept.
        kept.append(line.rstrip())
    # In source order, deliberately. Sorting would hide a reordering, and the
    # order is load-bearing: mk/verify.mk expands "| $(BUILD_DIR)" as its rule
    # is read, so moving that include above mk/config.mk leaves the prerequisite
    # empty while every line of the file stays byte-identical.
    return kept


# Harness files whose relevance is a question about content rather than about
# the path. Every other entry widens on any change, which is the safe default;
# these earn the exception by having a surface small enough to state exactly.
#
# mk/config.mk qualifies for the same reason and through the same slicer: it
# defines no rules at all, so everything a proof can reach in it is an
# assignment of a name mk/verify.mk reads (BUILD_DIR, RED, RESET). mk/common.mk
# does NOT qualify, and the difference is worth stating: it owns the
# "$(BUILD_DIR):" rule that every verify target carries as an order-only
# prerequisite, and a slicer reading assignments would not see that recipe
# change.
#
# The completeness of both rests on one condition the self-test checks: neither
# file may define a target the verify rules depend on, or a change to that
# recipe would reach a proof without touching a line the slicer reads.
CONTENT_SENSITIVE = {
    "Makefile": makefile_proof_slice,
    "mk/config.mk": makefile_proof_slice,
}

# What "$(VERIFY_RULES): check-stub-constants check-stub-shadow | $(BUILD_DIR)"
# in mk/verify.mk names. A content-sensitive file that started defining one of
# these would put its recipe on the proof path.
VERIFY_PREREQUISITES = ("check-stub-constants", "check-stub-shadow", "$(BUILD_DIR)")

# The makefiles a proof runs inside. Their variable references are what the
# slicer treats as proof-relevant names, and taking all four rather than
# mk/verify.mk alone is what covers a value that reaches the prover through
# another file.
PROOF_MAKEFILES = ("mk/verify.mk", "mk/toolchain.mk", "mk/common.mk", "mk/config.mk")

# What the top-level Makefile includes, split by whether it can reach a proof.
# The inert half builds the shim, the tests, the linters and the help text; a
# proof reads none of them.
#
# The Makefile itself widens through HARNESS_FILES, so this split is not what
# decides a Makefile diff. It exists for the next makefile: a new mk/*.mk gets
# edited on its own later, without the Makefile in the same diff, and if it can
# reach a proof and is not in HARNESS_FILES the scope silently narrows. The
# self-test refuses to pass until a new include is classified one way or the
# other, which is the only moment anyone has the context to do it.
MAKEFILE_PROOF_INCLUDES = {
    "mk/toolchain.mk",
    "mk/config.mk",
    "mk/common.mk",
    "mk/verify.mk",
}
MAKEFILE_INERT_INCLUDES = {
    "mk/shim.mk",
    "mk/tests.mk",
    "mk/conformance.mk",
    "mk/lint.mk",
    "mk/format.mk",
    "mk/help.mk",
}

# The stub headers reach every proof and no include closure can see them: they
# arrive through -include and -I$(FRAMAC_STUB_DIR) in FRAMAC_CPP_ARGS, which
# the -MM scan below (plain -Isrc -Ibuild) does not reproduce. A wrong constant
# there changes what every target reasons about, so a change under the
# directory widens the scope the same way mk/verify.mk does. The name comes
# from mk/verify.mk so a rename cannot leave this pointing at nothing.
STUB_PREFIX = verify_mk.stub_dir().rstrip("/") + "/"


def make_words(text):
    """The words of a make dependency list, honoring backslash escapes.

    -MM writes a path holding a space as "with\\ space", so splitting on
    whitespace tears it into two words that match no file. That direction is
    the dangerous one: the real path drops out of the closure, and the target
    stops being selected by a diff that touches it. Same reasoning as the -z
    on the git diff below.

    The repository has no such path today. A checkout under one does, which is
    ordinary on macOS, and this function is reading absolute paths built from
    that checkout's location.
    """
    return [w.replace("\\ ", " ") for w in re.findall(r"(?:[^\s\\]|\\.)+", text)]


def include_closure(cc, src, workdir, defs=()):
    """Files @src pulls in transitively, per the compiler, not per SCAN.

    VERIFY_<T>_SCAN is a hand-maintained guess at this, kept in step by
    whoever adds a header, which is exactly the kind of thing that goes stale
    silently: a proved header gains an include, nobody updates SCAN, and a
    change touching only the new file selects no target without a diagnostic.
    -MM asks the same preprocessor that stands between the source and the
    proof, so the two cannot drift apart from each other.

    Returns None, not a partial answer, when the scan itself cannot be
    trusted. {src} alone would be a silent narrowing indistinguishable from a
    correct closure with no includes, which is exactly the failure mode this
    function exists to close for SCAN; failing quietly here would just move
    the bug rather than fix it. The caller treats None as grounds to run
    everything, same as an unresolvable ref.

    @defs carries the target's VERIFY_<T>_CPP_DEFS. The prover preprocesses
    with them, so an include sitting behind one is a real input; scanning
    without them would report a closure for a file the proof never sees.
    """
    # -Isrc and -Ibuild are spelled here rather than read out of
    # FRAMAC_CPP_ARGS, and the rest of that variable is deliberately not
    # reproduced: -nostdinc and Frama-C's modeled libc only change which SYSTEM
    # headers resolve, which -MM drops anyway, and the two -include stubs are
    # covered by STUB_PREFIX widening instead. That leaves the two project
    # include roots, whose names live in mk/config.mk (BUILD_DIR) and
    # mk/verify.mk. Both are in HARNESS_FILES, so a rename of either widens the
    # scope to everything on the commit that makes this copy stale.
    out = workdir / "closure.d"
    try:
        proc = subprocess.run(
            cc
            + list(defs)
            + [
                "-I",
                str(ROOT / "src"),
                "-I",
                str(ROOT / "build"),
                "-MM",
                "-MG",
                "-MF",
                str(out),
                str(ROOT / src),
            ],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        # cc itself does not exist or is not executable. A more certain
        # "cannot trust this scan" signal than a non-zero exit, and it must
        # fail the same way: return None rather than let the exception
        # propagate and crash the whole run instead of falling back.
        return None
    if proc.returncode != 0 or not out.exists():
        return None
    text = out.read_text().replace("\\\n", " ")
    if ":" not in text:
        # Malformed -MM output. Same reasoning as a non-zero exit: an empty
        # dependency list here would look identical to "genuinely no
        # includes", so it cannot be told apart from data and must not be
        # trusted as one.
        return None
    deps = make_words(text.split(":", 1)[1])
    rooted = set()
    for dep in deps:
        p = pathlib.Path(dep)
        if not p.is_absolute():
            rooted.add(dep)
            continue
        try:
            rooted.add(str(p.relative_to(ROOT)))
        except ValueError:
            # Absolute and outside the tree, which -MM is not supposed to
            # report but a toolchain wrapper or a symlinked include path can
            # still produce. Dropping it loses nothing, since the caller only
            # ever intersects this set with "git diff --name-only" output and
            # no path outside the repo can appear there. Raising, which is what
            # relative_to does unguarded, would crash the run instead of
            # falling back.
            continue
    rooted.add(src)
    return rooted


def target_closures(cc):
    """{target: {file}} straight from the compiler, or None if any target's
    closure could not be trusted.

    Returning None for the whole map rather than {src} for the one broken
    target is deliberate: a caller that gets a partial map back has no way to
    know which entries are real and which are silently degraded, so the only
    honest signal is "scope is unknown, verify everything."

    Kept separate from target_inputs so the self-test can compare SCAN against
    what the compiler actually reported. Asking that question of the unioned
    map is a tautology, which is how the first version of that assertion
    passed while a deliberately broken SCAN list was in place.
    """
    out = {}
    defs = verify_mk.target_cpp_defs()
    with tempfile.TemporaryDirectory() as tmp:
        workdir = pathlib.Path(tmp)
        for target, src in verify_mk.target_sources().items():
            closure = include_closure(cc, src, workdir, defs.get(target, ()))
            if closure is None:
                return None
            out[target] = closure
    return out


def target_inputs(cc, closures=None):
    """{target: {files whose change can alter that target's verdict}}, or None.

    The closure, unioned with VERIFY_<T>_SCAN rather than trusting the closure
    alone. SCAN is what check-acsl-coverage.py reads inside the verify-<T>
    recipe, and nothing requires it to be a subset of what the source includes.
    It is one today for all 17 targets, which the self-test asserts against the
    raw closures; the union is what keeps a future entry outside the closure
    widening the scope instead of vanishing from it.
    """
    if closures is None:
        closures = target_closures(cc)
        if closures is None:
            return None
    scans = verify_mk.target_scans()
    return {t: files | set(scans.get(t, [])) for t, files in closures.items()}


def targets_changed_since(cc, ref, harness=None):
    """The targets a diff against @ref can affect, or None when the scope
    cannot be determined and everything has to run.

    @harness selects the question: HARNESS_FILES asks which proofs to run,
    MUTATION_HARNESS_FILES which mutation sets to run. The difference is the
    scheduling files, which pick what runs without deciding what it concludes.

    Diagnostics go to stderr so the caller that prints the target names can be
    read by a machine.
    """
    # Two dots, not three. Three-dot asks git for the merge base, which a CI
    # shallow clone does not have, and this only ever wanted "which proved
    # sources differ between these two trees" anyway.
    #
    # -z, so a path is delimited by NUL and arrives raw. Without it git applies
    # core.quotePath and renders a non-ASCII name as an escaped C string, and
    # splitting on whitespace tears a name containing a space in half; either
    # one matches no closure entry, which drops the target from the scope
    # silently. That is the one direction this file must not fail in.
    diff = subprocess.run(
        ["git", "diff", "--name-only", "-z", ref, "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if diff.returncode != 0:
        detail = diff.stderr.strip().splitlines()
        print(
            f"  cannot diff against {ref}, running the full set "
            f"({detail[0] if detail else 'no detail'})",
            file=sys.stderr,
        )
        return None
    touched = set(diff.stdout.split("\0")) - {""}
    return scope_from_touched(cc, prune_inert_content(ref, touched), harness=harness)


def prune_inert_content(ref, touched):
    """@touched without the content-sensitive files whose proof slice is the
    same at @ref as it is now.

    Cannot tell keeps the file, as everywhere else here: an unreadable base
    version, or a slicer that raises, leaves the path in and the scope wide.
    """
    keep = set(touched)
    for path, slicer in CONTENT_SENSITIVE.items():
        if path not in keep:
            continue
        old = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if old.returncode != 0:
            continue
        try:
            unchanged = slicer(old.stdout) == slicer((ROOT / path).read_text())
        except Exception:
            # The docstring promises that cannot-tell keeps the file, and a
            # slicer that raises is cannot-tell however it raised: an
            # unreadable file is OSError, a version of the file this cannot
            # parse is whatever the slicer chose. Narrowing this to one
            # exception type would turn the rest into a crash, which is the
            # one thing worse than proving something twice.
            continue
        if unchanged:
            keep.discard(path)
            print(
                f"  {path} changed, but not the part a proof reads",
                file=sys.stderr,
            )
    return keep


def scope_from_touched(cc, touched, inputs=None, verbose=True, harness=None):
    """The proof targets @touched can affect, or None for "run everything".

    Split from targets_changed_since so the decision can be exercised with a
    synthetic file set; see self_test. @inputs is an already-built closure map,
    since building one costs a compiler run per target.
    """
    harness = HARNESS_FILES if harness is None else harness
    if touched & harness or any(f.startswith(STUB_PREFIX) for f in touched):
        if verbose:
            print(
                "  harness or proof config changed; running the full set",
                file=sys.stderr,
            )
        return None
    if inputs is None:
        inputs = target_inputs(cc)
        if inputs is None:
            # The compiler's include scan itself is what could not be trusted,
            # not the diff. Same rule: an unknown scope means verify
            # everything.
            if verbose:
                print(
                    "  cannot determine proof-input closures, running the full set",
                    file=sys.stderr,
                )
            return None
    return {target for target, files in inputs.items() if files & touched}


def makefile_includes():
    """Every makefile the build reads, per the makefiles themselves.

    Reads the top-level Makefile AND mk/*.mk, because an include one level
    down is the direction that rots: a new mk/verify-extra.mk pulled in by
    mk/verify.mk would reach a proof while being invisible to a scan of the
    top-level file alone.

    Not "make -pn" or $(MAKEFILE_LIST), which resolve computed includes this
    cannot. mk/common.mk ends with "-include $(wildcard $(BUILD_DIR)/*.d)", so
    make's answer is whatever .d files that tree happens to have built: dozens
    on a developer machine, none on a fresh CI checkout. A check whose result
    depends on whether someone has run make is not a check. Computed paths are
    skipped here for the same reason, and are the one thing this cannot see.

    Handles the forms make accepts and this tree does not use yet, since each
    one missed is an include the caller silently declines to classify: the
    optional -include and its sinclude synonym, several files on one line, a
    trailing comment, and a backslash continuation.
    """
    out = set()
    for path in [ROOT / "Makefile"] + sorted((ROOT / "mk").glob("*.mk")):
        text = re.sub(r"\\\n", " ", path.read_text())
        for line in re.findall(r"^\s*[-s]?include\s+([^#\n]*)", text, re.M):
            out.update(w for w in line.split() if "$" not in w)
    return out


def self_test(cc):
    """Assert the scoping decision still answers the cases CI relies on.

    This file decides whether the proofs run at all, and every neighbour
    (check-proof-targets, check-acsl-coverage, check-wp-result, the mutation
    gate itself) exists because a hand-kept list was judged likely to rot.
    HARNESS_FILES is exactly such a list.

    Only cases that can actually fail. Asking whether most harness paths widen,
    or whether a target's own source selects it, are tautologies over the code
    above: the first is the set membership the function tests, and the second
    holds because include_closure ends by adding src. Assertions that cannot
    fail read as coverage and are not.

    One named check per invariant below, each returning what it found, because
    this grew to a dozen groups spanning five different questions and a reader
    could no longer tell which line belonged to which claim.
    """
    closures = target_closures(cc)
    if closures is None:
        print(
            "  cannot determine proof-input closures; the self-test has "
            "nothing to check",
            file=sys.stderr,
        )
        return 1
    inputs = target_inputs(cc, closures)
    scans = verify_mk.target_scans()
    includes = makefile_includes()
    bad = (
        _harness_paths_resolve()
        + _scans_stay_inside_their_closure(scans, closures)
        + _makefile_includes_are_classified(includes)
        + _scheduling_files_do_not_judge()
        + _content_slicers_cut_where_they_claim()
        + _scope_answers_its_boundary_cases(cc, inputs)
    )
    if bad:
        print("  proof-scope self-test failed:", file=sys.stderr)
        for line in bad:
            print(f"    {line}", file=sys.stderr)
        return 1
    print(
        f"  scope self-test: {len(HARNESS_FILES)} harness path(s), "
        f"{len(scans)} SCAN list(s), {len(includes)} makefile include(s), "
        f"1 Makefile case, 1 inert case"
    )
    return 0


def _harness_paths_resolve():
    """Every harness path names something, and the derivation still finds the
    workflows the hand-kept floor names."""
    bad = []
    for harness in sorted(HARNESS_FILES):
        if not (ROOT / harness).exists():
            bad.append(f"{harness}: named in HARNESS_FILES but not in the tree")
    # Not "the floor is in HARNESS_FILES", which is true by construction since
    # the union that builds that set includes the floor. What can fail, and
    # what the floor is there to absorb, is the derivation losing a workflow it
    # used to find: the scope stays correct and nobody learns the marks rotted.
    undiscovered = sorted(
        verify_mk.KNOWN_PROOF_WORKFLOWS - verify_mk.discovered_proof_workflows()
    )
    if undiscovered:
        bad.append(
            f"{undiscovered}: only the hand-kept floor still finds these, so the "
            f"marks in verify-mk.py no longer match what they invoke"
        )
    if not (ROOT / STUB_PREFIX).is_dir():
        bad.append(f"{STUB_PREFIX}: FRAMAC_STUB_DIR is not a directory")
    return bad


def _scans_stay_inside_their_closure(scans, closures):
    """SCAN is unioned into the closure, so an entry outside it widens the
    scope rather than vanishing from it.

    That is the right failure direction and it hides the failure. If this ever
    fires, check-acsl-coverage.py is reading a file the prover does not
    preprocess, so it is checking contracts no proof consumes.
    """
    bad = []
    for target, scanned in sorted(scans.items()):
        stray = sorted(set(scanned) - closures.get(target, set()))
        if stray:
            bad.append(f"{target}: VERIFY_SCAN names {stray}, outside its closure")
    return bad


def _makefile_includes_are_classified(includes):
    """Every makefile the build reads is either proof-reaching or inert, and
    the proof-reaching ones are harness paths.

    Classifying one as proof-reaching and then leaving it out of the harness
    set is the way the split gets filled in wrong: the entry reads as handled
    while the scope still narrows on it.
    """
    bad = []
    unclassified = sorted(includes - MAKEFILE_PROOF_INCLUDES - MAKEFILE_INERT_INCLUDES)
    if unclassified:
        bad.append(
            f"the build includes {unclassified}, which HARNESS_FILES has not "
            f"classified as reaching a proof or not"
        )
    unlisted = sorted(MAKEFILE_PROOF_INCLUDES - HARNESS_FILES)
    if unlisted:
        bad.append(f"{unlisted}: classified as reaching a proof, but not harness paths")
    return bad


def _scheduling_files_do_not_judge():
    """The scheduling exceptions are the one narrowing decision a human makes
    here, so they are checked rather than trusted.

    An earlier version of the list held verify.yml, which carries
    FRAMAC_TIMEOUT and the mutation invocation, and a reviewer had to catch it.
    A mark scan catches the next one at the moment it is written.

    Workflows only: proof-scope.py names FRAMAC_TIMEOUT in its own prose, and a
    script that talks about the marks is not a script that carries them.
    """
    bad = []
    for sched in sorted(f for f in SCHEDULING_FILES if f.startswith(".github/")):
        path = ROOT / sched
        if not path.exists():
            continue
        carried = sorted(m for m in JUDGING_MARKS if m in path.read_text())
        if carried:
            bad.append(
                f"{sched}: carries {carried}, so it judges rather than schedules"
            )
    return bad


def _content_slicers_cut_where_they_claim():
    """The content-sensitive entries narrow rather than widen, the direction
    this file otherwise never goes, so their slicers are exercised.

    Two conditions their completeness rests on come first: the file must not
    define a verify rule, whose recipe a slicer reading values cannot see, nor
    a target the verify rules depend on.
    """
    bad = []
    for path, slicer in sorted(CONTENT_SENSITIVE.items()):
        text = (ROOT / path).read_text()
        # Every target on a rule line, not just one alone at column 0:
        # "foo check-stub-constants:" defines it too, and ${BUILD_DIR} is the
        # same variable as $(BUILD_DIR) to make.
        defined = set()
        for line in text.splitlines():
            head = re.match(r"^([^\t#][^:=]*):(?!=)", line)
            if head:
                defined.update(head.group(1).split())
        proof_rules = sorted(d for d in defined if d.startswith("verify"))
        if proof_rules:
            bad.append(
                f"{path}: defines {proof_rules}, and a slicer that reads values "
                f"cannot see what a recipe does"
            )
        for prereq in VERIFY_PREREQUISITES:
            braced = prereq.replace("$(", "${").replace(")", "}")
            if defined & {prereq, braced}:
                bad.append(
                    f"{path}: defines {prereq}, which a verify rule depends on, "
                    f"so reading only its assignments is no longer enough"
                )
        # A computed reference is outside what the name fixpoint can follow, so
        # an assignment reached only that way would be called inert. No
        # content-sensitive file constructs a name today; the day one does,
        # this says so rather than narrowing quietly.
        computed = [
            line.strip() for line in text.splitlines() if "$($" in line or "${$" in line
        ]
        if computed:
            bad.append(
                f"{path}: builds a variable name at {computed[:1]}, which the "
                f"relevant-name fixpoint cannot follow"
            )
        if not slicer(text):
            bad.append(f"{path}: its proof slice is empty, so no edit can widen")
        # What must stay out, which is the entire benefit: a rule for one more
        # test binary and one more source on the build's own list were between
        # them the sole reason 36 of 46 Makefile commits re-proved everything.
        for inert, why in (
            ("$(BUILD_DIR)/test-probe: ; @true", "a build rule"),
            ("SRCS += syscall/probe.c", "a source on the build's list"),
            (".PHONY: probe", "a phony declaration"),
        ):
            if slicer(text + "\n" + inert + "\n") != slicer(text):
                bad.append(f"{path}: {why} moved its proof slice")
        # What must move. Each of these changes how "make verify-<t>" runs while
        # every line a slice built by recognizing assignments would read stays
        # byte-identical; that slice missed the first four.
        for relevant, why in (
            ("SHELL := /bin/sh", "a shell override"),
            (".ONESHELL:", "a recipe-execution special target"),
            ("define FRAMAC_CPP_ARGS\n-nostdinc\nendef", "a define block"),
            ("ifdef PROBE\nendif", "a conditional"),
            # No space around the operator, which make accepts and a greedy
            # name class reads as a different variable entirely.
            ("CPP_DEFS+=-DPROBE", "a spaceless append to a name a proof reads"),
            ("include mk/probe.mk", "a new include"),
            ("override FRAMAC_TIMEOUT := 1", "an override assignment"),
            ("verify-probe: FRAMAC_TIMEOUT := 1", "a target-specific override"),
            ("vpath %.h src/proved", "a vpath directive"),
            ("unexport CC", "an unexport"),
        ):
            if slicer(text + "\n" + relevant + "\n") == slicer(text):
                bad.append(f"{path}: {why} did not move its proof slice")
        shuffled = list(reversed(slicer(text)))
        if shuffled != slicer(text) and sorted(shuffled) == sorted(slicer(text)):
            if slicer("\n".join(shuffled)) == slicer(text):
                bad.append(f"{path}: reordering its slice lines did not move it")
    return bad


def _scope_answers_its_boundary_cases(cc, inputs):
    """The three end-to-end answers the CI jobs are built on.

    A harness path widens, prose selects nothing, and prune_inert_content keeps
    what it cannot read. That last one is the only path in this file that takes
    a harness entry OUT of a diff, so its cannot-tell direction is exercised
    rather than inferred from the slicers.
    """
    bad = []
    makefile_scope = scope_from_touched(cc, {"Makefile"}, inputs, verbose=False)
    if makefile_scope is not None:
        bad.append(f"Makefile: selects {sorted(makefile_scope)}, expected full set")
    kept = prune_inert_content(
        "no-such-ref-proof-scope-self-test", set(CONTENT_SENSITIVE)
    )
    dropped = sorted(set(CONTENT_SENSITIVE) - kept)
    if dropped:
        bad.append(f"{dropped}: pruned against a ref whose version cannot be read")
    inert = scope_from_touched(cc, {"README.md"}, inputs)
    if inert != set():
        bad.append(f"README.md: selects {sorted(inert) if inert else 'everything'}")
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--print-targets-changed-since",
        metavar="REF",
        help="print the proof targets a diff against REF can affect, one per "
        "line (every target when the scope cannot be determined)",
    )
    ap.add_argument(
        "--mutation",
        action="store_true",
        help="answer for the mutation gate instead, which a change to the "
        "scheduling machinery cannot affect",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="assert the scoping still answers its boundary cases",
    )
    # Split rather than exec directly, since CC is routinely a wrapper or
    # carries flags ("ccache clang", "cc -DTEST"). The default is right for the
    # include scan: it only walks #include lines, which every C preprocessor
    # agrees on, unlike check-char-signedness.py where the exact CC matters.
    ap.add_argument("--cc", default="cc", help="compiler for the include scan")
    args = ap.parse_args()
    cc = shlex.split(args.cc) or ["cc"]

    if args.self_test:
        return self_test(cc)
    if args.print_targets_changed_since:
        harness = MUTATION_HARNESS_FILES if args.mutation else HARNESS_FILES
        scope = targets_changed_since(cc, args.print_targets_changed_since, harness)
        for target in sorted(verify_mk.target_sources() if scope is None else scope):
            print(target)
        return 0
    ap.error("nothing to do: pass --self-test or --print-targets-changed-since")


if __name__ == "__main__":
    sys.exit(main())
