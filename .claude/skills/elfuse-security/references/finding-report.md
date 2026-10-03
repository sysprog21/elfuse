# Writing a finding up

A finding is a claim that a specific guest action reaches a specific bad
outcome. It is worth writing only when the path can be stated end to end.
The schema below exists to stop a report degrading into a list of places the
reviewer felt uneasy about.

These rules decide what becomes a finding at all:

- One root cause is one finding, with every sink listed. Two callers of the
  same unchecked helper are one entry. Splitting by call site inflates the
  count and hides that a single fix closes them all.
- A finding carries its fix. When the fix cannot be stated, the issue is not
  understood well enough to report, and the honest output is a question.
- Claim only what was shown. A guest-triggered abort is not host code
  execution, and an out-of-bounds read is not a write; the stronger reading
  is a separate claim that needs its own trace.
- Order by what one bad value reaches, not by how interesting the bug is.

## Verdicts

Every candidate ends in exactly one of three states, and the states do not
blur:

- Confirmed: the path is traced end to end and a reproducer shows the effect.
  Only this state carries a severity, since a severity on an unproven path is
  a guess that reads as a measurement.
- Needs validation: the trace holds as far as the source shows, and one named
  fact decides it, such as an HVF behavior, a macOS kernel answer, or a
  reachability question no test has settled. A path traced end to end whose
  reproducer is not yet written belongs here too, with that as the fact. State
  the fact and the check that would settle it.
- Rejected: disproved by the source, an existing control, or a prerequisite
  the guest cannot reach. Keep it with the reason, so the next review does not
  raise the same claim; it suppresses that claim only while the cited source
  is unchanged. When the disproof is a control that already stops the path,
  the missing second layer is recorded as a hardening note under the
  rejection, not as a finding.

Name each root cause with a fingerprint built from the file, the function,
the sink the guest value reaches and the CWE id, never a line number; two
flaws in one function can share a CWE but not a sink. It stays the same across a state change
and across reviews, which is how a rejected claim and its later reappearance
are recognized as one.

## Severity

The anchors, applied under the claim-only-what-was-shown rule above:

- Critical: host code execution, or a host memory write outside the guest
  slab.
- High: sysroot escape, host privilege the launching user did not lend, or a
  read of host memory at an offset or length the guest chose.
- Medium: host bytes the host copies out on its own (uninitialized stack or
  heap), host-resource exhaustion from one call in a loop, or a guest read of
  EL1-only state such as shim_data.
- Low: host layout detail (a host path, a host address, a macOS errno) in
  guest-visible output, with no primitive attached.

A write into the infra reserve is graded by what the host then does with it,
not by where it landed. Page-table control alone reaches EL1-only state and
W^X, which is Medium. The walker keeps it inside the slab: `src/proved/gva.h`
proves the table offsets, and `gva_translate_perm` in `src/core/guest.c`
checks the leaf against `guest_size` by review rather than proof. A higher
grade needs the trace through a gap in one of them. When the
concrete damage cannot be named, the severity is lower than it feels.

## Per finding

- ID in the form WK-#, and a name giving the weakness in the entry point, in
  that order.
- Verdict, from the three above, and the fingerprint.
- Entry point: the syscall or format the guest drives, and which of its fields
  the guest chooses.
- Attack path: numbered steps from that entry point to the impact, tracing the
  chosen value from source to sink. One action per step, causally linked, no
  branching, with `path/to/file:line` and the exact value used at each step.
- Impact, named from the list the skill body opens with: host state read or
  written that the guest was never handed, sysroot escape, host memory
  corruption, host-resource exhaustion, or host privilege reached. When none
  of them fits, this is a robustness bug and saying so is the useful answer.
- Existing controls, and how far each one gets. This is where a report earns
  trust, because it is what the author of the code checks first.
- Severity after those controls, for a confirmed finding only.
- The fix, at the layer that closes every listed sink.
- CWE id, Variant or Base. The Class-level ids name a category, not a bug.
- Locations: every sink as `path/to/file:line` or a line range.

CVSS vectors are optional and usually not worth the keystrokes here. When one
is given the score has to match the vector, since a mismatch discredits the
report faster than omitting both.

## Evidence

Verbatim excerpts, the smallest that carry the path, original comments
stripped and excess indentation removed. Mark the file at the top of each
block and elide non-relevant code. Annotate the flow inline, one sentence
each: the source where the guest value enters, each propagator that carries
it, each sanitizer it passes with what that check does not cover, and the sink
where it does the damage.

The sanitizer line is the one that gets skipped and the one that matters.
Naming the guard and stating precisely what it fails to cover is what
separates a finding from a reviewer who did not read the guard.

## Reproducer

One guest program or unit test that fails on the current source and passes
after the fix, at the cheapest level that exercises the boundary. Least
damaging form that still demonstrates the path: prove the read leaves its
bounds, do not demonstrate what could be done with it. `elfuse-verify` says
which lane it belongs in.

The reproducer runs as the launching user, so a guest that escapes does real
damage. Point an escape reproducer at a canary file in a scratch directory,
never at a path that matters, and stop at the first observation that proves
the boundary was crossed.
