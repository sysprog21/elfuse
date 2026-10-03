# Sweeping the whole tree

Reviewing a diff and sweeping `src/` are different jobs. A diff has an author
and a reason; a sweep has neither, so it needs a fixed set of detectors and an
honest account of what each one cannot see. What follows is the set, and the
false positives each one produces here, which are worth knowing in advance
because every one of them costs a file read to dismiss.

State the scope in the result. A sweep that names the files it walked is
evidence; one that reports a verdict over `src/` without saying what it read
is a claim about every line in it that nobody made.

## The detectors

Run them over `src` with `--include='*.c'`, excluding `src/proved/`, whose
arithmetic is under contract already.

- Unsafe C string primitives: `strcpy`, `strcat`, `sprintf`, `gets`,
  `vsprintf`. Any hit is a finding; there is no accepted use in this tree.
- `alloca`, and array declarations whose size is a variable. A guest number
  must never size a stack object.
- `malloc`, `calloc` and `realloc` whose size argument is not a `sizeof`
  expression. Each hit is traced to the cap that bounds it, or it is a
  finding. This one is slow and is the highest-yield of the set.
- Additions inside a bounds test: `if (a + b > c)`. The wrap is the bug.
- Array subscripts named like syscall arguments: fd, signum, idx, slot, tid,
  clockid, nr.
- The same guest address read twice inside one function, which is the double
  fetch when the second read is the one used.
- A fallback that substitutes a constant for entropy.

## What each one gets wrong here

- The addition detector is mostly noise. Most hits combine values already
  bounded by `NAME_MAX` or by the destination size, and only the ones adding
  a length the other side chose can wrap. Read the provenance of both
  operands before writing anything down.
- The subscript detector answers a question about shape when the question is
  provenance. Most hits index a loop counter the code owns. It earns its
  place because the few that do take a guest number reach a host array.
- A grep for a discarded `guest_read` or `guest_write` return matches the
  continuation lines of multi-line conditions, and misses the case where the
  check is an accumulator on the previous line. Both directions are wrong, so
  confirm every hit against the file.

## Coverage units

Grep is the first pass, not the coverage. Split the work into units, one per
surface from the skill body crossed with the rule that applies to it (the
sockaddr formats against sizes, the at-family against paths, the FUSE frames
against caps and lifetime), and give each unit one of four dispositions:

- Covered: the files read are listed, and the rule holds on each.
- Candidate: a finding came out of it, under the verdicts in
  `references/finding-report.md`.
- Blocked: read in part, with the fact that stopped the rest named.
- Deferred: not reached, with the reason.

The result counts all four, which keeps a partial sweep from reading as a
full one.

A second sweep starts from the first one's units and rejected findings rather
than from nothing. A unit whose files changed since goes back to work; one
that did not change can be skipped, and says so. In practice a single pass
finds only part of what repeated passes find, so a re-run aimed at the
deferred and blocked units is worth more than a fresh pass over covered ones.

When a sweep is split across agents, each owns its units and returns them in
that shape; one more agent then reads the unit list against the surfaces and
asks what nobody was assigned, before any finding is written up.

## One table per format

For each format the host parses for the guest, fill in: each length or count
and who supplies it (the guest, a device, or the host itself), the
representation the check actually tests, who allocates the buffer, who consumes it, which thread, and who tears it down.
Most memory-safety findings here are one disagreement between two cells of
that row, and the table makes the disagreement visible where reading the
parser top to bottom does not.

A clean sanitizer run covers less than it looks: `elfuse-verify` says which
code and which test sections the sanitizer lanes reach.

## What no sweep sees

The same three things grep never sees: indirection, where the dangerous call
sits behind a helper; absence, where the missing check has no text to match;
and logic, where each step is safe and the sequence is not. Those need the
rules in the skill body applied by reading, and they are why a clean sweep is
reported as a clean sweep rather than as a clean tree.
