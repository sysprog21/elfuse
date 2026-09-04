---
name: elfuse-conventions
description: elfuse conventions outside CONTRIBUTING.md. Use when adding, reviewing, or reducing prose in source comments, docstrings, README.md, or docs/*.md; drafting a commit message, PR description, or review reply; adding a file or type; touching an atomic or lock-free access; handling untracked working docs; or wiring the build to a tool absent from a fresh clone.
---

# elfuse conventions

Almost nothing here is enforced by a gate. `clang-format` settles formatting
and `make check-format` settles the generated files, so those are not in this
file; what is left is the set a reviewer would otherwise have to say out loud.

`CONTRIBUTING.md` is the other half and the tracked one. It settles C style,
which formatter and which version, what each gate actually covers, and the
seven commit-message rules. Read it before writing C rather than working from
a memory of typical C style, because several of its rules are not the common
default: `#pragma once` over include guards, `/* */` with no `//` anywhere,
the asterisk bound to the name, no VLA, and `(void)` for a function that takes
nothing, since `-Wstrict-prototypes` rejects the empty `()` form and the build
treats that warning as an error. This file does not restate it.
Where both speak, `CONTRIBUTING.md` wins, and a rule that drifts apart between
the two is a defect in this file.

The one exception is these files themselves. `scripts/check-skill-refs.py`
fails when a skill names a file, make target, docs section, or sibling skill
that no longer exists. It checks every skill, plus any routing document you
name on the command line. Run it after renaming or moving anything the skills
point at, because a pointer that no longer resolves does not read as stale, it
reads as authoritative.

## Working docs

A contributor may keep untracked working docs at the repo root or under
`.claude/`; which ones exist differs per clone. Never `git add`, commit,
stage, gitignore, or delete another person's: untracked but visible in
`git status` is deliberate. None of them survive a fresh clone, so nothing
here defers to one.

What a clean checkout does carry is `CONTRIBUTING.md`, `docs/`, and these
skills, which is where every load-bearing convention has to be written. Note
that `scripts/check-skill-refs.py` cannot tell those apart: a bare markdown
name at the repo root is left unverifiable on purpose, since it may be a
private working doc, so a pointer to `CONTRIBUTING.md` from a skill is not
gate-protected the way a `src/` path is. Renaming it is a manual sweep.

## Style

Source comments and commit messages are ASCII, with no markdown syntax: no
inline backticks, no non-ASCII arrows. Write code, path, and symbol references
as plain text (EPOLL_CTL_MOD, tests/foo.c). Markdown files are exempt and use
normal GitHub Markdown, so do not strip backticks out of a `.md` file in its
name.

One exception, in source only: a comment diagram may draw with the Box Drawing
block (U+2500 to U+257F) and the four small triangle arrowheads (U+25B4,
U+25B8, U+25BE, U+25C2). Eight files already do, and the diagrams are worth
more than the rule they break. `make check-ascii` fails on every other
non-ASCII character, so the rest of this is now a gate rather than a habit;
`scripts/check-ascii.py --self-test` states the classes it catches.

The em dash (U+2014) is banned on every surface, markdown included: comments,
commit messages, `docs/`, these skill files, PR bodies, and review replies.
In an otherwise-ASCII tree it is the clearest mark of machine-written prose,
rejected on sight (PR#209). Two gates catch it: `make check-ascii` over the C
sources, and `scripts/git-commit-msg.sh`, which requires a printable-ASCII
commit message and which `scripts/check-commit-log.sh` runs over every commit
in a PR. `docs/` and PR replies have no gate, so there it is still on the
writer; write the character as its codepoint rather than the glyph when you
have to name it, since a literal em dash in a grep pattern matches nothing and
reports a false all-clear.

A spaced double hyphen is not the way around it, on any of those surfaces.
It carries the register the em dash carries, so a comment, a commit body, a
docs paragraph, or a skill file reaches for a comma, a colon, parentheses, or
two sentences instead. A dashed aside is nearly always one of those already:
an appositive takes paired commas, a definition takes a colon, an afterthought
takes its own sentence. A pair opened with a dash and closed with a comma is
the tell that the sentence wanted commas from the start.

The tree already carries hundreds of them, in `src/` comments and in `docs/`,
and converting those is not a task: the diff would be unreviewable and the
prose is not wrong, only dated. Reword the sentence you were editing anyway,
and take the whole aside with you rather than half of it.

The rest of the machine register is banned on the same surfaces:
prompt echo, effort claims, inflation words, coined vocabulary, trailing
"-ing" glosses, and the invisible-character class among them. Read
`references/prose-register.md` before writing a comment block, a commit body,
a PR reply, or a paragraph of `docs/`, and treat it as the one place those
classes are defined.

When a prose task extends beyond a local sentence, read
`references/prose-reduction.md` to decide what survives and where it belongs.
The register reference above still settles how each survivor is written.

Comments and commit messages are third-person: name the subject (the caller,
this function) or use imperative phrasing.

Filenames use kebab-case, never underscore. Symbol names use snake_case.

## What the formatter settles, and what it cannot

Do not hand-format. `clang-format` owns indentation, brace placement (the
function brace on its own line, the control-structure brace on the same line),
the pointer asterisk binding to the name, spacing, wrapping, and trailing
commas in initializers. `commentflow` owns what clang-format
half-does: it breaks an over-long comment line but never refills a
short-wrapped one, so comment width is settled by reflowing to the same
`ColumnLimit`. Write it reasonably,
write the comment as a sentence, and let `make indent` place the breaks.

The formatter is silent on the rest, so apply these while writing rather than
after:

- Include order. `.clang-format` sets `SortIncludes: Never`, so the formatter
  neither sorts nor regroups what you wrote, and a wrong order stays wrong
  through every gate. System headers first, then project headers, each group
  separated by a blank line, the file's own header among the project group.
- ASCII in comments, `/* */` with no `//`, kebab-case filenames, snake_case
  symbols, `#pragma once`.
- Fixed-width types on the guest side of the boundary, host types on the host
  side, and `bool` versus `int` for what a function returns.
- The banned libc calls, no VLA, no invented `_`-prefixed identifier. Those
  fail in CI, not in the formatter.

Two scripts check, and both run in CI: `.ci/check-format.sh` for clang-format
over the C sources, `.ci/check-commentflow.sh` for comment width over the C,
shell, and assembly sources. The second owns its file list for `make
check-format` too, so the local target and the gate cannot drift apart on
coverage. Both fail rather than skip when their tool is missing.

`make indent` is a no-op on a clean tree, in both halves: every file clang-format
selects already formats to itself, and every file commentflow selects already
reflows to itself. That was not free. The tree's comments were wrapped by hand
before the tool existed, and the one-time reflow rewrote 142 of the 353 C and
header files, both assembly files, and 36 of the 41 shell scripts. It landed as
its own commit because a mechanical change with no behavior in it cannot be
reviewed alongside one that has some.

The gate is what keeps it a no-op. If `make indent` ever hands you a diff in a
file you did not touch, something reintroduced hand-wrapping, or your
commentflow is not the version the gate runs.

## Code

The conventions below are the ones that come from this project being a Linux
ABI reimplementation rather than an ordinary C program. They settle what a
declaration looks like, not whether the function should exist; for judging and
cleaning code that already works, `elfuse-refactor` is the calibration set.

### Shared mutable state

Shared mutable state uses `_Atomic` objects and the C11 `atomic_*_explicit`
operations from `<stdatomic.h>`. Compiler `__atomic_*` and obsolete `__sync_*`
primitives are not allowed. They take a plain `T *`, so nothing in the
declaration says the object is shared, and the next person to touch it adds a
plain access without seeing a reason not to.

Declare the object `_Atomic` wherever this tree owns the storage. The exception
is memory whose layout the guest ABI fixes and the EL1 shim also reads:
page-table descriptors, the `shim_data` slots, the vvar seqlock, a futex word.
Those cannot be declared, so the host casts to `_Atomic T *` at the point of
access. That cast holds only while `_Atomic T` is laid out like `T` and is
lock-free, because a lock-based atomic would take a host-side lock the shim's
LDAR and STLR cannot see, and the two sides would then order against different
things. `src/core/guest.h` asserts both properties at compile time; without
those asserts the cast is a guess about the toolchain.

Never reach an `_Atomic` object through a plain C operator. `p->pending |= bit`
is a sequentially-consistent read-modify-write, and a site already holding the
lock that serializes it pays for ordering it does not need while saying nothing
about the ordering it does. Where a file has many such sites, name the
discipline once in helpers rather than spelling the order out at each: the
`pending_load` / `pending_or` / `pending_clear` group at the top of
`src/syscall/signal.c` is the shape.

Never hand an `_Atomic` object to `memcpy` or to a guest read/write helper. That
copies the object representation, which is not an atomic read of it. Load into a
local first and pass the local.

A shared field that many files read gets an accessor rather than an
`atomic_load_explicit` at each site. `thread_blocked_load` and
`thread_blocked_store` in `src/runtime/thread.h`, `thread_tid` beside them, and
the `pending_load` / `pending_store` / `pending_or` / `pending_clear` group in
`src/syscall/signal.h` are the set, and the header comment above each says why:
one definition of how the field is reached means a new reader cannot plain-load
it by omission, which is how forty of them accumulated before. A field only one
file touches does not need one; `in_syscall` is reached directly in
`src/runtime/thread.c` and stays there.

The rule covers the bare `atomic_load(x)` spelling too, not just `x` on its own.
It is an atomic operation, but a sequentially-consistent one by default, so it
states no more about the ordering than the plain operator does.

`scripts/check-atomics.py` holds the two halves a regex can settle: no
`__atomic_*` or `__sync_*`, and no C11 atomic call without its `_explicit`
form. It does not check plain-operator access to an `_Atomic` object, because
finding those needs the declarations resolved and the tree still carries a large
pre-existing set of them; that half stays a review question.

State the order and name what it pairs with. Relaxed is right under a lock that
already serializes the access. Release and acquire are for a publish a lock-free
reader chases, and the comment says which reader. Sequential consistency is for
the cases that need the contrapositive rather than the forward direction, which
in this tree means the attention bits in `src/core/shim-globals.c`, where a
sibling vCPU observing a zero must not then observe the stores that preceded the
publish.

Fixed-width types for anything the guest defines: guest addresses, Linux ABI
structures, binary layouts, protocol fields, page-table entries. Host-side
types (`size_t`, `ssize_t`, `int`, POSIX types) for host API calls, where they
match what the host declares. The distinction is not cosmetic; it is how a
reader tells which side of the boundary a value came from.

```c
uint64_t gva;       /* guest virtual address */
uint64_t ipa;       /* intermediate physical address */
size_t len;         /* host buffer length */
int host_fd;        /* macOS file descriptor */
```

Packed Linux ABI structures are explicit and live next to the translation code
that uses them, not in a shared header where they can drift away from the
conversion that gives them meaning.

Never pass a guest pointer to a host syscall. Copy through the guest memory
helpers so bounds checking and fault behavior stay in one place.

`bool` is for functions whose only meaningful outcome is success or failure.
`int` is reserved for returns that carry a number: errno-style codes, counts,
indices, or forwarding the status of an `int`-returning primitive. A helper
that only ever returns 0 or -1 and is read with a `< 0` test should have been
a `bool`; a helper that forwards a page-table or syscall primitive's status
should stay `int`.

New code goes in the existing domain file, not a new one. New shared
declarations go in the domain's `internal.h` or an existing header, and a new
lock reaches the ordering record; `elfuse-syscall` locates that record, says
when a lock enters it, and names the three constraints in it that the
ordering alone does not give.

New C tests are `tests/test-<feature>.c` and use the shared harness macros
rather than rolling their own reporting.

## Comments

Brevity is part of correctness. Default to no comment; a survivor is cut to
its rationale, usually one to a few dense lines. A block growing toward a
paragraph stack is rejected even when every sentence is true ("Avoid long
comments!", PR#290, on a 28-line test header; "Shorten the comments
slightly.", PR#254, PR#261). An unrequested comment, log line, defensive
check, or restructuring is a defect to remove, not a favor.

A comment earns its place only for what the code cannot say: rationale, an
invariant, a boundary condition, a unit, a citation. Delete anything
restating the statement below it.

- Bad: `slot->refcount = 1; /* set refcount to 1 */`
- Good: `slot->refcount = 1; /* held by the /dev/fuse fd itself */`

Cite the authority at the point of use: the kernel path, the man page with
its section, the ELF or FUSE clause, the macOS or glibc behavior forcing a
host workaround. Code that looks wrong says why it is not, the highest-value
comment here. Never comment around bad code; rewrite it. Contracts,
invariants, and lock ordering live once in the owning `.h`; call sites cite
them. `sigwait()` returns on SIGUSR2 and no "doorbell" rings: a thread,
flag, or helper is named for its operation, not the manner.

Not in `src/`: attribution, dates, commented-out code, issue-tracker numbers
(barred from `docs/` and README prose too, PR#40, PR#223; they belong in a
commit trailer), or `TODO`/`FIXME`; incomplete work belongs in the commit
message or PR. Editing part of a comment re-opens all of it: re-read the
block and rewrite what no longer reads cleanly.

Mechanics: `/* */` only in `.c`, `.h`, and `.S`, no `//`, no Doxygen tags;
multi-line blocks align on ` * `, close with `*/` on its own line, indented
to the body; American English; `@name` references a parameter in prose. A
new file follows the surrounding legal-header form. Omit a title or synopsis
when the filename, module name, primary type, or entry point already states
it. Keep one short module paragraph only for a stable file-wide constraint
with no narrower owner. `#` comments in shell, Python, and Make obey the same
content rules. Update or delete a comment in the commit that changes its code:
a stale comment is worse than none, because it is believed. A comment
asserting a number or a guarantee is the case that rots silently, so recompute
it before carrying it into an edit; `elfuse-refactor` reads the same rule from
the reviewer's side.

## docs/

`docs/` describes how the system works now, for a reader who has never seen
it, as settled fact, and a past decision that still matters reads as
present-tense rationale ("paths are translated in one place so ..."). No
workflow reads markdown, so nothing checks any of this against the code; a
docs claim is only as true as the last person who read it against the
source.

## Vendored tools checked out for evaluation

A third-party tool checked out into an untracked directory to be tried out is
for evaluation and discovery only. Nothing in the build may come to depend on
it: no make target, no script, no CI job, and no documented workflow step. It
is absent from a fresh clone, so anything that reaches for it breaks for the
next person and cannot run in CI.

Run such a tool by hand from a scratch directory and leave any fixes to it
inside its own checkout. Record the outcome in the root working docs,
including when the answer was "evaluated, not integrated" - a rejected
evaluation is worth writing down so the next person does not repeat it. If the
output is worth keeping, land the finding in tree, not the tool.

Being untracked is not itself the test, and reading it that way gets the rule
backwards. The test fixtures are untracked too, and the build depends on them
on purpose: a make variable points at them, `make distclean` removes them, CI
restores them from a cache before the lanes that need them, and
`docs/testing.md` documents the paths the suites resolve. What makes that legitimate is that a tracked script fetches them, so
a fresh clone can reproduce the tree it needs. An evaluation checkout has no
such script, and that is the difference.

## Commit messages

The house style is Chris Beams' seven rules (https://cbea.ms/git-commit/), and
the log follows them closely enough that a deviation reads as an outsider
patch. `git log --no-merges --format=%s` is the calibration set if you want to
check the claim rather than take it.

1. Separate subject from body with a blank line.
2. Keep the subject within 50 characters. 72 is the hard ceiling, not the
   target; if you are past 50, the commit usually wants splitting.
3. Capitalize the subject.
4. No period at the end of the subject.
5. Imperative mood: "Fix the race", not "Fixed" or "Fixes" or "Fixing". The
   test is that the subject completes "If applied, this commit will ___".
6. Wrap the body at 72 columns. Do not let the editor reflow it into one line.
7. The body explains what and why, not how. The diff already shows how.

Real subjects from this tree, for calibration:

```
Stop nl_put_attr truncating its own extent
Prove the netlink walk loops
Count the shared pty declarations correctly
Give a pty's slave accounting one home
Say what the proof matrix cache actually costs
```

Note what is absent: no Conventional Commits prefix (`fix:`, `feat:`, `chore:`),
no area tag, no ticket number in the subject. The subject is a sentence about
behavior. A commit that removes something says what stops happening; a commit
that adds a proof says what is now proved.

The body is where the reasoning goes: what the old code claimed, why that
was wrong, what breaks if you do it the obvious other way. Substantial is
not the same as long: the target is the shortest faithful account, no
restating of the diff, no padding to look thorough. Two to four sentences
carry most commits; a body past roughly 50 lines is the signal to split the
commit, not to write more. Some commits label body paragraphs (`Verified:`,
`Coverage:`, `Concurrency:`) when a claim needs to be findable later. Issue
references go at the end as `Fixes #187`, `Closes #156`, or the URL form.

Subject and body name code objects and mechanisms, so every claim is
checkable against the diff: "Remove unread probe outputs and unreachable
arms", never "Drop dead weight from the probe". A diagram replaces prose
rather than joining it, so interleaved actors, a race window, or a
byte-layout off-by-one earn a small ASCII diagram inside 72 columns with
real names, the prose it replaces cut. Verify it as rendered.

The Style rules above bind here, `references/prose-register.md` included:
ASCII with no backticks around symbol names, no em dashes or non-ASCII
arrows, and third person throughout. A commit body is the surface those
classes were written for.

Merge commits keep git's generated subject and are exempt.

## Pull requests

A PR thread is human collaboration, and agent-shaped artifacts are rejected
on sight: no pasted walkthroughs or summaries ("We are humans. Don't copy
agent-specific reply here.", PR#116), no severity or status tables ("We're
here to discuss and improve the software together, not to act as task
trackers.", PR#90), no re-summarizing the diff git already shows. Close
addressed threads with "Resolve conversation"; a reply carries the
correction, the measurement, or nothing. A concise what and why belongs in
the commit body, not the thread.

The body is intent plus reproduction and commands: for a bug, a minimal
reproduction with host macOS and SDK version, hardware, and `make check`
status (PR#21, PR#41); for a performance claim, A/B benchmarks on a named
machine, same binary with and without the change, median over runs (PR#203).
Rebase on latest `main` (PR#58). One issue per bug (PR#135); validate
against a real application, not only a unit smoke test (PR#191).

## Layout

All source under `src/`, artifacts under `build/`. The build passes `-Isrc`,
so headers are included as `core/guest.h`, `syscall/internal.h`,
`proved/gva.h`.

Tests in `tests/`, scripts in `scripts/`. Reports and analyses stay out of
the tree: keep them in a scratch directory or in a repo-root directory the
clone excludes through `.git/info/exclude`, never through `.gitignore`, which
would push one person's habit onto everybody.

Build and toolchain requirements are in `docs/testing.md`, section "Build
Requirements". They belong to a machine, not to this convention set.
