---
name: elfuse-verify
description: How elfuse validates a change - choosing the lanes for the area you touched, the test matrix, make check, and the Frama-C proof targets declared in mk/verify.mk, including how to drive the frama-c MCP server on a stuck proof and how to read its proof_coverage report. Use when adding bounds math to src/proved/, writing or repairing ACSL contracts, running or debugging make verify / verify-mutants, asking how much of a target is actually proved, touching frama-c-stubs/, adding a test lane, or deciding what to run before calling work done.
---

# Validating an elfuse change

Two independent gates: the runtime tests and the proofs. A change to
attacker-facing bounds math needs both.

Independent in what they prove, not in what they consume. Run them one after
the other, never concurrently. `make verify` re-invokes itself parallel and
`verify-mutants` fans out too, while the runtime lanes are wall-clock
sensitive, so overlapping them makes the machine fail tests that a serial run
passes. Measured here: `make check` alongside the proof gate drove an 8-core
host to a load average of 43.8 against a busy threshold of 4.8, and
`test-thread-churn` timed out twice at 60 s and reported FAIL. The same binary
on the same tree at load 4.0 finishes in 0.34 s, three runs out of three.
Nothing was wrong with it. Neither mitigation saves you at that load, since
`test_host_is_busy` only skips the throughput guardrail and the runner only
re-runs once. A timing FAIL is worth nothing as evidence either way: it is not
a regression you can act on, and a serial re-run is the only thing that tells
you whether it was real.

The pure source scanners are the exception, and they are the cheap early
signal while something long is in flight: they read the tree, cost seconds,
and fail long before a full lane would. The `check:` prerequisite line in
`mk/tests.mk` is the live roster; `check-stub-shadow` is the one that hangs
off every `verify-*` target instead, so `make check` alone does not reach it.
Beside a build in flight, run the script directly with the flags its recipe
passes, not through its make target: any goal outside `print-%` evaluates the
build-flavor guard (`mk/common.mk`), which can wipe a build made with other
CFLAGS. Read the recipe first. `scripts/gen-usbdev-ioctl-departed.py`, behind
`check-usbdev-departed`, is a generator that writes its header unless given
`--check`, and `make check-usbdev-departed` rebuilds that header under
`build/` when it is stale before comparing.

None of them writes to the source tree. Three invoke make, each on a `print-%`
goal: `check-proof-targets` and `check-skill-refs` ask
`make print-verify-targets` for the proof list rather than reading
`mk/verify.mk`, and `check-usb-fixture-bin` asks for the binary path of both
build flavors. `print-%` goals skip the flavor guard, which is what keeps those
sub-makes safe beside a build. A scanner that invoked make on some other goal
would not be.

## Choosing what to run

`docs/testing.md`, section "Validation Strategy By Change Type", is a table
from the area you touched to the minimum command set, and it is more specific
than any habit. Consult it first. It is where you learn that Rosetta work
wants `make test-rosetta-all`, that ptrace and debugger work want
`make test-gdbstub`, and that filename-codec work wants the soak lane on top
of `make check`.

The defaults below are what that table falls back to, not a substitute for it.

```
make check                       # unit tests, busybox, coverage gate, guardrail
bash tests/test-matrix.sh all    # the three modes
```

## Runtime

Modes and what a failure in each means:

- `elfuse-aarch64` - primary. Must stay green. A failure here is a regression.
- `qemu-aarch64` - ground truth via Alpine `aarch64-linux-musl` under
  `qemu-system-aarch64`. It answers "what does real Linux do", which is why
  `elfuse-debug` reaches for it on any behavioral divergence. TIMEOUTs are
  emulation speed, not regressions.
- `elfuse-x86_64` - the Rosetta path, with per-host-class baselines from
  `detect_x86_64_host_class`. Skips cleanly without the translator.

`tests/fetch-fixtures.sh` pulls Alpine packages, the `linux-virt` kernel, and
Rosetta fixtures on first run. musl is Alpine's only libc, so glibc-dynamic
lanes skip unless `GUEST_GLIBC_*` points at an external sysroot.

A fixture download that fails is not always a download failure. Some networks
answer plain HTTP with a page of their own, which arrives as a valid 200 and
only breaks at whatever tries to parse it: `make check` here failed at
`ar: Inappropriate file type or format` on a busybox `.deb` that was 2997 bytes
of HTML. The suite already knows this happens, which is what the `wget` lane's
"no unintercepted http to example.com from this host" skip is about. So when a
fixture step fails on a malformed archive, check what actually arrived before
believing the archive is at fault, and prefer an HTTPS source: `build/busybox`
now rewrites the mirror the Debian page lists to `deb.debian.org`, since the
per-country mirrors it offers are plain HTTP and not all of them answer HTTPS
at all.

### Writing a test lane

The runner is already hardened, and every one of these exists because a test
once passed without running anything. Do not work around them, and do not
loosen one to get a build green.

- `tests/lib/test-runner.sh::run` and `run_check` wrap every invocation in
  `timeout $TEST_TIMEOUT` (gtimeout fallback on macOS).
- `run_check` and `run_pipe` fail on non-zero exit before pattern evaluation.
  A test that greps for a string in the output of a crashed binary is not a
  test.
- `driver.sh::evaluate_result` requires `rc == expected_rc`.
- `ALLOW_MISSING_BINARIES` defaults to 0. A missing fixture is a failure, not
  a skip.

## Proofs

`src/proved/` is header-only arithmetic carrying ACSL contracts: the bounds
math of an attacker-facing parser or packer, split out of a `.c` and proved
with `-wp-rte`.

Every `src/proved/` header must have a matching `make verify-<name>` target,
but the reverse does not hold. A few targets prove a `.c` file directly, each
for a reason stated in the comment above it in `mk/verify.mk`; the general
one is that the loops in question could only have been described as
test-covered had they been split into a header.

`make print-verify-targets` is the current list. CI reads it to build its
matrix, so do not hardcode the set anywhere else, including here.

```
make verify           # every proof target, parallel by default
make verify-<name>    # one target
make verify-mutants   # assert each proof rejects a known-broken source
make print-verify-targets
make check-contracts  # rebuild with -DELFUSE_CONTRACT_ASSERT, then make check
```

`make verify` re-invokes itself with `-j$(VERIFY_JOBS)` unless you brought your
own `-j`. `VERIFY_JOBS=1` is how you ask for serial on both GNU make 4.x and
Apple's 3.81.

`verify-mutants` accepts `MUTANT_TARGET=<name>`, `MUTANT_JOBS=<n>`,
`MUTANT_SINCE=<rev>` for a changed-only run, and `MUTANT_ESCALATE=<seconds>`
(see the exhaustion section below).

Read past the "N mutations, N caught" line. It also reports two coverage gaps:
proved functions with no mutation under any target, and functions mutated
under one target but not another target that proves them. The first asks
whether a proved function has any mutation. The second asks whether each target
that proves an already-mutated function has its own mutation. Both matter
because targets can use different models and header environments, so a
mutation under one does not exercise another target's proof. These reports are
advisory, but each entry is uncovered under the metric that reports it.

Recompute both gaps before quoting them and name the denominator used.

A function can also sit in a `_FCTS` list with no ACSL contract at all, proved
only for absence of runtime errors. Nothing there can reject a mutation, so
adding one is wasted effort until the function has a contract: that is the fix,
and it is usually two lines. Write the contract in the domain the code is in,
too. `futex_uaddr_is_aligned` would not discharge as `uaddr % 4 == 0` and does
as `(uaddr & 0x3) == 0`, because bridging modulo and bitmask on a 64-bit value
is what the prover times out on, not the property itself.

Adding a contract raises the obligation count, so raise
`VERIFY_<T>_MIN_GOALS` with it. That floor is a tripwire against an emptied
body or a dropped contract, which prove 0 of 0 and would otherwise pass; it is
meant to sit at the target's baseline. Two contracts added here left it 15 and
2 obligations low, and nothing failed to say so, because a floor is only ever
compared against from below.

Mutating a function that lives in an included header rather than in
`VERIFY_<T>_SRC` works: the runner stages the mutant in its own directory and
prepends it via `MUTANT_INCDIR`, where it shadows the real header. What a
target may mutate is its source plus the headers in its `VERIFY_<T>_SCAN`.

The staged path must mirror the original's path under `src/`, and
`MUTANT_INCDIR` must be the staging ROOT rather than the copy's parent, because
the spelling in the `#include` is what the preprocessor searches for. Deriving
it as the parent got `src/utils.h` right by luck and every nested header wrong:
`"proved/netlink.h"` resolved to `<parent>/proved/netlink.h`, missed, fell
through `-Isrc` to the real header, and the run proved unmutated code while
reporting a mutation nobody caught.

The unmutated baseline cannot catch that, and it is worth knowing why, because
the comment that claimed it could was wrong. The baseline stages a copy
identical to the file it shadows, so whether the preprocessor opens the shadow
or falls through, the program proved is the same and the run passes either way.
What does catch it is a probe: stage a copy carrying `#error`, require the run
to fail naming it, and read the LOG rather than make's stdout, since the recipe
redirects Frama-C there and a non-zero exit alone is also what a broken
override gives. It costs a parse, not a proof.

### A mutation is caught by exhaustion here, not by refutation

Worth knowing before tightening the gate on principle. An open goal means the
prover either reached a conclusion the mutant cannot satisfy (`[Unknown]`,
`[Failed]`) or ran out of budget (`[Timeout]`, `[Stepout]`), and only the first
is a refutation. In this tree the first never happens: across every mutation
log the tag is `[Timeout]`, and raising the budget eightfold to 240s on a host
at 0.3 to 0.6 runnable threads per CPU left all four `futexdeadline` mutations
exhausting exactly as they did at 30s. Alt-Ergo and Z3 do not refute these
goals, they grind. So refusing to count exhaustion does not make the gate
stricter, it makes "caught" unreachable and the gate permanently red.

What separates a broken contract from a merely hard one is the baseline, not
the tag: the unmutated source proves every goal, and the mutant, narrowed to
the mutated function, exhausts on that function's own goal. A goal that were
only hard would exhaust in the baseline too, and a failing baseline is fatal
rather than scored. The residual gap is a mutation that turns an easy true goal
into a hard true one: it exhausts at the short budget and would discharge at a
long one, and the tag alone cannot tell it from a rejection.

`--escalate SECONDS` closes that gap on demand. It re-runs every resource
verdict at the larger budget and reports MISSED for any mutation that then
proves, which is the honest verdict for one the proof does not reject. It is
off by default because it costs the escalated budget on precisely the goal that
already ran out of the short one, once per mutation, and every mutation in the
table is a resource verdict. Run it when a contract changes or when the claim
that these mutants are unprovable rather than slow is what is in question:

```
make verify-mutants MUTANT_TARGET=futexdeadline MUTANT_ESCALATE=240
```

Two things follow. Report the resource verdicts separately so the count never
reads as "these proofs refute their mutants", and say which budget produced
them. And do not diagnose them as load without measuring: a mutation run fans
out and becomes its own load source, so a split computed during a parallel run
will always disqualify itself. Serial (`MUTANT_JOBS=1`) on a quiet host is the
only measurement that means anything, and here it returned the same answer.

The mutation runs pass `-wp-cache none` for a related reason. WP's cache
defaults to `update` and stores a timeout as a stored verdict just like a
conclusion, so a replayed timeout would be a catch obtained with no prover run
at all. `make verify` keeps its cache, which is what makes a re-prove cheap;
only the mutation gate, where a fresh verdict is the whole point, turns it off.
That distinction is not academic: an `elf_place_segment` contract retried here
came back Timeout from the cache on a quiet host, and only defeating the cache
showed the real result.

`scripts/proof-scope.py` decides which targets a diff can reach, and
`.github/workflows/verify.yml` builds its jobs from it, so a target the branch
cannot affect gets no runner. It answers two questions: which targets to prove,
and, with `--mutation`, which mutation sets to re-run, the second being narrower
because a file that only schedules the run cannot change whether a target
rejects a broken source. Every "cannot tell" answer widens back to the whole
set, and a push to `main` always proves and mutates everything.

Three things follow when adding a target or a proof input. An input reached
through `-include` or an `-I` the scan does not use is invisible to the closure
and belongs in `HARNESS_FILES` (or under `STUB_PREFIX`). A file that only picks
what runs goes in `SCHEDULING_FILES`, and the self-test refuses it if it also
carries a prover budget or a make invocation. And `proof-scope.py --self-test`,
run by `.github/workflows/lint.yml`, is what tells you the lists are still
honest.

### Adding to src/proved/

Nothing lands there without a proof target -
`scripts/check-proof-targets.py`, run by `make check` and by
`.github/workflows/lint.yml`, fails otherwise. Callers include the header as
`proved/<name>.h`.

The routine:

1. Extract the arithmetic into `src/proved/<name>.h` with ACSL contracts.
2. Add the `VERIFY_<NAME>_SRC` / `VERIFY_<NAME>_MODEL` / `VERIFY_<NAME>_FCTS`
   variables in `mk/verify.mk` so the rule template instantiates
   `verify-<name>`. `typed` is the default choice for a model; see below.
3. `make verify-<name>` until it discharges with `-wp-rte`.
4. `make verify-mutants MUTANT_TARGET=<name>` - a proof that cannot reject a
   broken source proves nothing.

Supporting gates, all of which run per target:

- `scripts/check-acsl-coverage.py` - catches a contract assumed because its
  function was left out of `-wp-fct`.
- `scripts/check-char-signedness.py` (`make check-char-signedness`) - compiles
  each proved function under `-fsigned-char` and `-funsigned-char` at -O0 and
  requires identical code. The data model used for proving differs from arm64
  macOS on plain-char signedness; this is what keeps that sound.
- `scripts/check-stub-constants.py` (`make check-stub-constants`) - asserts
  every `frama-c-stubs/` constant matches the macOS SDK. The analyzer never
  links, so a wrong constant cannot fail a build, it silently changes what the
  proof reasons about.

### Choosing the next target

Parsability decides it before anything else does: a file Frama-C cannot parse
cannot be proved, however good a candidate it looks. Test that first, because
it costs one invocation and rules candidates out for free.

```
FC=$(command -v frama-c)
ARGS="-nostdinc -isystem $($FC -print-share-path)/libc -Iframa-c-stubs \
      -include prelude.h -include macos-libc.h -Isrc -Ibuild"
FILE=src/syscall/fs-stat.c
$FC -machdep gcc_x86_64 -cpp-extra-args="$ARGS" "$FILE"
```

`CPP_DEFS` is empty for every target but `verify-gva`, so leaving it out
matches what most targets are proved under. A failure names its own cause:
`'sys/attr.h' file not found` is the real modeling gap and ends the matter,
while `Cannot resolve variable X` is a missing declaration and is fixable
under `frama-c-stubs/`.

`parse_surface` does the same probe over a whole file list and groups the
failures by cause, which is the faster way to survey the tree. Give it the
flags above as `include_paths`, `isystem_paths`, `nostdinc` and
`force_includes`: a survey run without them measures a different program and
its blocked set fills with files that parse perfectly well. Measured with the
flags missing it reported 39 of 60 parsing against 46 of 60 true, and its
largest blocker group was a phantom.

Whatever the probe, read which header stopped a file and whose include it was.
A leaked include costs every file downstream of it and nothing to remove:
deleting one unused `sys/mount.h` from `runtime/procemu.h` took three files
straight into the parsing set.

Then rank what survives by whether it actually holds attacker-facing bounds
math. The shape that has worked every time is a self-contained codec or walk
over a guest-chosen blob: pure arithmetic, libc-only includes, an explicit
output-buffer bound, and no syscalls. A file whose header comment already says
it treats its input as untrusted and is free of project dependencies is
telling you it was written to be proved. Which inputs count as attacker-facing
is the boundary list in `elfuse-security`, not a judgment made per file.

Two things that look like candidates and are not. A file whose length
arithmetic is all delegated to an already-proved header adds nothing but a
second harness. And a translation table with no arithmetic, however
attacker-reachable, has no obligations worth generating: `-wp-rte` on it
proves that a switch is a switch.

### Memory models, and what no model checks

Each target picks its own model via `VERIFY_<NAME>_MODEL` in `mk/verify.mk`,
and the comment above it says why. Pick the model the code needs, not the
model a neighbour target uses.

The general limit is worth understanding before trusting any of them: a
non-`typed` model buys reasoning power by assuming something the proof does
not check. `caveat`, used where `typed` cannot follow a byte-addressed buffer
whose entry stride is attacker-chosen, assumes formal pointer parameters do
not alias. The contracts state that with `\separated`, but the callers are not
in `-wp-fct`, so nothing verifies they honor it, and a future caller passing
the same address twice would invalidate the proof with no diagnostic.

That call-site gap is general, and it bites hardest for `proved/gva.h`:
`guest.c` cannot be given to Frama-C at all, so nothing verifies its call
sites honor the `requires` clauses. `make check-contracts` narrows it from the
runtime side by turning the expressible ones into runtime asserts, and is
deliberately separate from `make check` because those functions sit on the
`guest_read` / `guest_write` hot path.

### The frama-c MCP server, when it is available

`make verify-<name>` is a batch run: it either discharges or it does not, and
a failure tells you little about which obligation is stuck. If the `frama-c`
MCP server is connected, it drives the same Frama-C interactively, which turns
contract writing into a loop instead of a guess. Start with `self_check`,
because the optional pieces degrade independently, then reload the target's
sources plus `FRAMAC_STUB_DIR`, run WP one function at a time, and use
`get_wp_goals` and `context` to find which obligation is unproved rather than
rewriting a contract on suspicion. `create_sandbox` is the honest way to try a
strengthening without touching the real source.

The MCP is an accelerator, never the gate. A change lands on `make verify`
plus `make verify-mutants`, run from the Makefile, because that is what CI
runs and what a contributor without the server can reproduce. Never report a
proof as done on MCP evidence alone, and never add a workflow step, script, or
CI job that depends on the server being connected.

The server reports more confidently than it measures, and the ways it can be
wrong are specific: a verdict that rests on a filtered goal set, a cached
replay read as a fresh run, a model or flag set that is not the target's, a
timeout on a loaded host. `references/frama-c-mcp.md` carries the whole of it,
including the shapes its `check` codes name, how to calibrate against a known
target before trusting a number, and how to make the server prove what the
Makefile proves. Read it before quoting anything the server prints.

### frama-c-stubs/

Declarations the analyzer needs that the compiler or macOS supplies.
`ls -R frama-c-stubs/` is the list, and three kinds live there: whole Darwin
headers Frama-C has no model of, constants the modeled libc omits, and Darwin
structure shapes it declares in the Linux spelling. `prelude.h` is the odd
one, declaring nothing of its own and instead force-including the two headers
Frama-C ships but never reaches on its own: its gcc-builtins model, and its
stdatomic.h for the `_Atomic` qualifier its front end cannot parse and for the
C11 atomics vocabulary the tree calls.

A stub of the third kind may take the modeled header whole through
`#include_next` and rename one name inside it. `scripts/check-stub-shadow.py`,
a prerequisite of every `verify-*` target, holds that to exactly one
declaration, because a second would follow the rename into a prototype and
change a signature the proofs reason about.

It sits outside `src/` on purpose so a real compile, which resolves through
`-Isrc`, cannot reach it. Only `FRAMAC_STUB_DIR` in `mk/verify.mk` does.
It is tracked in git because every proof target needs it to parse.

A missing declaration fails with "Cannot resolve variable" - that is how the
next one gets found. Most of `src/`'s `.c` files parse; the rest stop on macOS
headers Frama-C's libc does not model (`sys/mount.h`, `sys/event.h`,
`sys/xattr.h`, `sys/attr.h`, `sys/spawn.h`). That is a real modeling gap, and
a stub that invents a body for one is how a proof comes to reason about a
program nobody runs. A declarations-only stub is a different thing and is
legitimate: `frama-c-stubs/sys/sysctl.h` is the worked case, and its own
header comment argues why sysctl left the blocked list. Recompute the parse
count before quoting it; the probe above is how.

## Other checks

These are not part of `make check` and each answers a different question:

```
make lint                  # clang-tidy
make check-format          # formatting, and regenerates the dispatch header
make check-asan            # use-after-free, overflow, on the host side
make check-ubsan           # undefined behavior
make check-tsan            # data races, worth it for anything multi-vCPU
make infer-uninit          # uninitialized reads
```

A clean sanitizer lane is narrower than `make check`. The three sanitizer
targets run `check-sanitizer`, which runs only the `SANITIZER_SECTIONS`
subset in `mk/tests.mk` plus the shared lanes, `CHECK_HOST_UNIT_BINS` among
them. A parser reached by neither is not exercised under instrumentation at
all. The USB descriptor, ELF header and abstract socket name parsers are
reached through their host unit tests. Ancillary messages are only partly
inside: a few selected tests pass SCM_RIGHTS in passing, but the dedicated
cmsg suites and netlink parsing are outside. The sanitizer
targets instrument host C only: `src/core/shim.S` is assembled by its own rule
and stays outside, so a clean run says nothing about the shim fast paths.

## What done means

Green is a claim about named commands, so report it as one: which lanes ran,
what each said, and which ones did not run. The failure modes to avoid, all of
which have shipped before:

- A lane that could not run is named along with the risk that leaves. It is
  never rounded up into the passing set.
- The exit status a gate reports is the one to quote, and it is not always the
  one you are shown. A backgrounded `make check > log 2>&1; echo $?` reports
  the status of the whole command line, so a trailing `echo` makes a failing
  make look like a success: this happened three times in one session, twice
  hiding a real non-zero make. Read the status from inside the command, or read
  the log for `make: *** [target] Error N` and the suite's own `Results:` line.
  A single green summary line proves nothing on its own either, since `make`
  stops at the first failing step and the suites after it never print.
- A count, a latency, or a coverage figure is recomputed before it is quoted,
  including from this file and from `CLAUDE.md`, whose counts drift because
  nothing gates them. The gates print the live number: take the target count
  from `make print-verify-targets`, the lock split from `check-lock-order`,
  and the `src/proved/` count from `check-proof-targets`. A number carried
  forward from a document reads as measured and is not.
- The `PROVED n of n` line is not in `build/verify-<name>.log`, which carries
  Frama-C's own `[wp] Proved goals: N / N` instead. It is check-wp-result.py's
  console output, colorized unconditionally, with the escape sitting between
  `PROVED` and the count. So a total summed from a `make verify` transcript
  with a naive `grep -oE 'PROVED +[0-9]+ of [0-9]+'` silently matches nothing
  and reports an empty sum rather than failing. Strip the escapes first
  (`sed 's/\x1b\[[0-9;]*m//g'`), or total the logs on `Proved goals` instead.
- A proof is done when `make verify` and `make verify-mutants` say so from the
  Makefile. MCP goals discharging is progress, not a verdict.
- A failure blamed on the environment earns one reproduction attempt under the
  condition blamed for it before it is written off. "Transient" and "the host
  was busy" are the two that hide real defects here, because a test harness
  racing its own pipeline and a probe that measures the wrong thing both fail
  only under load or only on some networks. Reproduce it, or say it went
  unexplained; do not report it as understood. Raising the reproduction rate on
  a failure that will not repeat on demand is `elfuse-debug`, under "When it
  only fails sometimes".

The throughput guardrail is the exception to that bullet: it is the one lane
where load genuinely decides the result. It runs near the end of `make check`,
so it measures on a machine `make check` has just loaded, and an UNMEASURED
verdict there says nothing about the change. Re-run `make test-bench-guardrail`
alone on an idle host and report what it says. UNMEASURED exits non-zero
exactly as a threshold violation does.

Establish the baseline before a multi-command session rather than after: this
tree is not green everywhere, and without the before-picture there is no way
to separate breakage you caused from breakage you inherited.

## Authoritative sources

This skill is a working summary. These are tracked and survive a fresh clone,
so prefer them when the two disagree:

- `docs/testing.md`, section "Validation Strategy By Change Type" - the change
  area to command mapping.
- `mk/verify.mk` - the per-target `_SRC` / `_MODEL` / `_FCTS` variables and
  the comment above each explaining its model choice.
- `tests/test-bench-guardrail.sh` - the comment above the unmeasured check,
  for why UNMEASURED and FAIL both exit non-zero.
