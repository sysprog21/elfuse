---
name: elfuse-refactor
description: Behavior-preserving cleanup of elfuse code. Use when simplifying, deduplicating, or restructuring working code; reviewing maintainability; or reducing prose that narrates code or makes unchecked claims. Not for syscall changes (elfuse-syscall), naming or commit style (elfuse-conventions), or a live failure (elfuse-debug).
---

# Refactoring elfuse code

Refactoring preserves what the guest observes, not merely a host return value.
Do not call a behavior change a cleanup to make it easier to review.

## Route the change first

Use this skill only after the code is known to work. A fault, hang, wrong
errno, or intermittent result starts with `elfuse-debug` instead.

Read the sibling skill that owns a boundary before moving code across it:

- `elfuse-guest-abi` for guest registers, page permissions, HVC, TLBI, EL0
  return state, fork, or Rosetta state.
- `elfuse-syscall` for syscall dispatch, guest-memory translation, paths, file
  descriptors, or lock discipline in the syscall surface.
- `elfuse-verify` when changing arithmetic covered by `src/proved/` or adding
  bounds math over guest-controlled values.

Do not fold a correctness finding into a cleanup. Report it separately: a diff
that both moves code and changes behavior cannot be reviewed as either.

## Decide whether the finding is real

Measure it first. `references/measuring.md` carries the scans for function
size, duplication, and nesting, and the traps in reading each. Report a number
with the command that produced it and a judgment as a judgment; `elfuse-verify`
carries the rest of that rule, this file included among the documents a count
must not be quoted from.

Prefer deletion, an existing local helper, or a direct rewrite over a new
abstraction. A parameter every caller gives the same value, a hook with one
implementation, and future-facing scaffolding are dead flexibility. Remove
them unless a tracked contract needs them.

Extract only when it gives a named operation or makes one contract easier to
see. Splitting a single Linux flag matrix across helpers hides the syscall
contract; separating path resolution, a host call, and result translation can
clarify it.

Check all callers before changing a helper. A 0/-1 helper used only as a
success/failure test should normally return `bool`, but read the body before
converting: most such helpers here set `errno` on the failure path or forward a
primitive's, which is what `elfuse-conventions` reserves `int` for. A sweep by
call-site shape alone converts far more than it should. A repeated ABI literal
belongs in `src/syscall/abi.h` or `src/syscall/linux-wire.h`, whichever the
neighboring constants already use.

Treat these as intentional until the surrounding contract proves otherwise:

- Similar Linux and macOS ABI structures are a translation boundary, not
  duplicate types. Keep packed Linux structures beside their translation.
- Repeated conversion switches belong in `src/syscall/translate.c`. An inline
  conversion elsewhere is the smell.
- `sc_` wrappers in `src/syscall/syscall.c` are typed dispatch unpacking. Their
  unused-parameter runs are the widest hit any duplication scan reports here,
  every time. Collapsing them behind a macro hides which arguments a handler
  ignores.
- Fixed-width guest values and per-vCPU `_Thread_local` state carry ABI and
  concurrency meaning. Do not wrap or promote them for appearance alone.
- A test fixture that only prints may have its oracle in a shell lane. Find the
  lane before adding an assertion.

Before deleting a symbol, search `src/syscall/dispatch.tbl`, `src/core/shim.S`,
and `tests/` as well as C callers. Generated dispatch, assembly, and test
lanes are reachability paths.

## Preserve the boundaries

- A helper that acquires a lock changes lock order at every caller, against
  the record `elfuse-syscall` reads. A helper that releases one, or drops and
  retakes it, is the same hazard read backwards, and the name has to carry it:
  `_locked` already means "call me holding it", so a helper that hands the
  lock back needs a different suffix and a comment saying the caller must not
  touch that lock again.
- Moving an interruptible wait into a helper moves its restart classification.
  `scripts/check-eintr-contract.py` keys on the function that decides, not the
  syscall that returns, so the new helper takes the inventory entry and the
  caller, now a forwarder, drops out of it. The gate fails the build until both
  happen. Carry any reasoning the departing entry held into a comment at the
  code it described rather than deleting it with the entry.
- Vector entry stubs in `src/core/shim.S` cannot clobber a GPR before
  `svc_handler`; do not consolidate them through a scratch-register prologue.
- Do not unify X8 drop-frame-marker writes by appearance. Find current writes
  with `grep -rn 'HV_REG_X8' src/`, read `src/core/shim.S`, then follow
  `elfuse-guest-abi`.
- `src/syscall/dispatch.tbl` owns generated dispatch. Change that input, not
  generated output.

When two functions encode the same forward and reverse bit correspondence,
state the mapping once as a table and use it in both directions. Similar code
is not enough: the two bodies must represent the same fact.

## Work in small, evidenced steps

Run the baseline `elfuse-verify` selects for the area touched before a
multi-step cleanup. Keep inherited failures separate from the change. Stop
when the baseline is red in the area being changed.

A failure blamed on the environment earns one reproduction attempt under the
condition blamed for it before it is written off. "Transient" and "the host was
busy" are the two that hide real defects here, because a test harness racing
its own pipeline and a probe that measures the wrong thing both fail only under
load or only on some networks. Reproduce it, or say it went unexplained; do not
report it as understood.

The throughput guardrail is the one lane where load genuinely decides the
result, and it distinguishes UNMEASURED from FAIL for that reason. Reaching it
at the end of `make check` means measuring on a machine `make check` has just
loaded, so an UNMEASURED verdict there says nothing about the change. Re-run
that lane alone on an idle host and report what it says.

Make one behavior-preserving step at a time, then run its mapped lanes. A pure
cleanup uses the same validation as the feature area, not a weaker set. Changes
under `src/proved/` require `make verify` and `make verify-mutants`.

`make lint` is advisory except for `readability-function-size`, which
`.clang-tidy` names in `WarningsAsErrors`, so a function crossing the ceiling
fails the job. Consult `.clang-tidy` for its current checks; report only
warnings introduced by touched code, plus any `function-size` result. Do not
claim that lint is clean.

Keep formatting local. `make indent` should be a no-op on a clean tree; a
tree-wide formatter diff signals a version or tooling problem, not cleanup.
Check `git diff --numstat` before handoff and split unrelated churn out.

Extracting a helper almost always leaves a call site the formatter wants to
wrap differently, so expect `make check-format` to fail once per extraction.
Run the formatter on that file and confirm from `git diff --numstat` that it
touched only the lines you wrote: a file reporting far more is the version
problem above, not the wrap. `commentflow` reflows adjacent comment lines into
one paragraph, so a new comment block placed directly under an existing one
merges into it; separate them with a bare `*` or `#` line.

For a prose cleanup, follow
`.claude/skills/elfuse-conventions/references/prose-reduction.md`. A Python
docstring may be runtime data, so search its consumers before removing it.

## Authoritative sources

- `.clang-tidy` for the enabled lint checks and which of them gates.
- `references/measuring.md` for the scans behind any count reported here.
- `scripts/check-eintr-contract.py` for the restart classifications.
- `docs/testing.md`, section "Validation Strategy By Change Type", for
  validation lanes.
- `src/syscall/internal.h` for lock order.
- `src/core/shim.S` for shim entry and return conventions.
