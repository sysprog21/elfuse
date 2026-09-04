---
name: elfuse-security
description: The guest as an attacker - where the trust boundary runs, the rules a handler on it obeys, what the gates already catch, and what is out of scope. Use when a change parses a guest-chosen length, translates a guest address, resolves a guest path, allocates on the guest's behalf, or blocks holding shared state, and when auditing a diff or writing a finding up.
---

# Security at the guest boundary

The guest binary is untrusted, and it is not a remote attacker. It picks every
register, every length, and the order the calls arrive in, at machine speed,
with a debugger attached and as many retries as it likes. A window that needs
a race to hit is a window it hits.

That is the whole threat model, and it decides what counts as a finding here:
the guest reading or writing host state it was never handed, escaping the
sysroot, corrupting host memory through a length the host trusted, exhausting
a host resource the guest does not own, or reaching a host privilege the
launching user did not intend to lend it. What the guest does to itself,
including wedging its own vCPU and exhausting its own address space, is a
correctness bug at most. Filing that as a security finding spends the
reviewer's attention in the wrong place.

This skill is the boundary. `elfuse-syscall` is how to add a handler on it,
`elfuse-guest-abi` is what the guest observes on return, and `elfuse-verify` is
which lanes prove it.

## Where the boundary runs

Five surfaces, ordered by what one bad value reaches:

- Syscall arguments. X0-X5 and X8 arrive from EL0 with no host filter in
  front, so every wrapper reached from `src/syscall/dispatch.tbl` is on the
  boundary.
- Guest addresses. Every guest pointer becomes a host pointer through one
  translator, and the permission half is the security half.
- Formats the host parses for the guest: the ELF the loader reads, netlink
  messages, FUSE frames, control messages, sigframes, sockaddrs, iovecs,
  dirents. Each carries lengths, offsets, or counts the guest supplies, but
  what the guest owns differs per format, so answer that per format rather
  than assuming it. The ELF is read by offset, a sockaddr length arrives as a
  separate syscall argument, and a sigframe is built by the host and then left
  where the guest can rewrite it before `rt_sigreturn` reads it back.
- Paths. Every name the guest supplies, absolute ones included.
- Shared pages. The guest and the host see the same memory, so a structure
  validated in guest memory and then passed on by address was not validated.

## The rules

`elfuse-syscall` carries the mechanism for most of these and names the symbols.
What this file adds is what breaking each one costs, because the cost lands
somewhere other than the line that caused it, and a rule with no consequence
attached gets traded away.

### Sizes

Never validate with arithmetic that can wrap: `off + len > size` wraps and
passes, `len > size || off > size - len` cannot. Read a wire length into an
unsigned type at the first assignment and reject the bad case in the same
statement, since a negative `int` passes an upper-bound test and then converts
to a vast `size_t` at the call. Give the clamp one spelling; the comment at the
top of `src/proved/slice.h` names the drifted copies that motivated it.

Cost: an out-of-bounds write that reproduces only at boundary values, which is
the region hand-written tests skip. New arithmetic on a guest-chosen length
belongs in `src/proved/` behind a contract, not inline.

A contract there proves the arithmetic and not its callers, so the call site
stays a review question rather than a proved one. `elfuse-verify` carries the
limit and what narrows it from the runtime side.

### Indexes

When a guest-chosen number selects a slot rather than a length: a descriptor,
a signal number, a bucket, a table entry.

`RANGE_CHECK` in `src/utils.h` is the one spelling, and its form is the point.
The unsigned subtraction makes a negative index wrap past the size and fail,
so the lower bound cannot be the one somebody forgets to write. Where the
bound cannot be tested at the site, state it instead: `elf_record_load` in
`src/core/elf.c` carries an ACSL `requires` for the lower bound on its slot
counter, because the function only raises that counter and can see the ceiling
but not the start.

Cost: the tables a guest number selects are host arrays, so this is the one
guest-supplied value that reaches host memory without passing through a length
or a translator. A slot past the end is a host write, and no bound on the
guest's own address space stands in the way.

### Guest addresses

`elfuse-syscall` owns guest-memory access. Two things it does not decide: a
host pointer already handed out is not rechecked when a mapping or a
permission changes, so translate again rather than hold one across; and one
physical page can carry two mappings, so the permission checked on one is not
the permission in force. `guest_kbuf_user_va_overlap` in `src/core/guest.h`
names the range that aliases under Rosetta.

Cost: a translation that checks presence but not entitlement turns any
read-into-buffer syscall into a disclosure primitive for whatever EL1
published in that space. Missing the alias costs the other direction: a TTBR0
mapping left executable over pages TTBR1 maps RW defeats HVF's per-mapping
W^X.

### The infra reserve

`elfuse-guest-abi` owns the mapping rules. What it leaves to review is that a
range which maps or repermissions memory is never presented as a pointer, so
no translator sees it: it is checked with `guest_range_hits_infra` or
`guest_addr_in_infra` or it is not checked at all.

Cost: the reserve holds the page-table pool, the shim code, and shim_data, so a
new mapping-shaped syscall that skips the check hands the guest its own page
tables. That is host memory corruption and host privilege at once, and no
translator refusal stands in the way, because nothing was translated.

### Paths

`elfuse-syscall` owns `path_translate_at`. The trap it leaves is that an
absolute at-family argument looks like it needs no directory context, and so
looks like it needs no resolver.

Cost: a full escape from the containment the rest of the program is built on,
not a degradation of it.

### Caps

Every allocation the guest sizes gets a ceiling, and so does every aggregate.
`src/syscall/fuse.c` caps sessions, mounts, open files, pending requests and
node refs; `src/syscall/netlink.c` caps request size, buffer size and open
netlink sockets; `src/runtime/futex.c` caps a waitv batch and bounds the
robust-list walk. Bound every traversal of a structure the guest wrote, since
a list it supplies can be circular and an unbounded walk hangs a thread
holding a lock.

Say in the comment which kind of cap it is. One that mirrors Linux is an ABI
cap, and moving it breaks compatibility; one invented here is a safety bound,
free to be raised, and sits far above any legitimate caller. The robust-list
bound in `src/runtime/futex.c` states its kind; `LINUX_SCM_MAX_FD` in
`src/syscall/net-msg.c` is the other kind and does not move.

Cost: uncapped is not a slow leak, it is one guest call in a loop.

### Lifetime across a wait

Pin the object with a count, then drop the lock. Holding the lock across a
wait deadlocks, and dropping it without a count lets a concurrent teardown free
the condition variable the waiter is parked on. The owning descriptor holds a
reference of its own so teardown and in-flight work share one accounting, and
destruction happens on the last put rather than at the close. In
`src/syscall/fuse.c`, the comments at `fuse_session_get_locked` and its
matching put carry the session half, down to why nothing is emitted to a dead
daemon, and `fuse_file_get_locked` with the comment on `fuse_file_t.refcount`
carries the pin-then-drop half.

Cost: a use-after-free on a synchronization primitive, reached by closing a
descriptor while another thread reads it, presenting as a rare hang rather
than a crash at the guilty line.

### Shared pages and locks

A guest value read twice is two values. Copy the structure in once, validate
the copy, then use only the copy; validating in place and passing the original
address on is the double fetch, and shared memory makes it reachable without
timing luck. A new file-scope lock enters the ordering record in the same
change, which the gate below fails for being missing. State the memory order
at every shared access.

Cost: a double fetch is not a race the guest has to win. It re-runs the syscall
until the two reads differ, so the window is as wide as it needs to be.

### The return path

`elfuse-guest-abi` owns the restart and HVC return-tail rules, and
`scripts/check-svc-tails.py` gates the tails. The half neither settles is which
waits owe `syscall_restart_forbid`: a wait that has sent a request or spent
part of a relative deadline cannot be re-run from its original arguments.

Cost: silent at the site. A wrongly restarted call repeats a side effect the
guest already observed, and the re-run looks identical to the first.

### Error paths

Fail closed. When an unwind runs, nothing may be left more permitted, more
mapped, or more executable than before it. Free once, on one path. Report only
what the Linux ABI specifies, since host paths, host addresses and macOS errno
detail leaking outward are how a guest learns the layout before using it.

Cost: an unwind that leaves a mapping writable, a descriptor open, or a
privilege raised converts a failed call into the primitive the guest wanted,
and the error return makes it look handled.

## What the gates already catch

Do not re-derive what these already prove, and check which target runs the one
being relied on, because they do not all run together. Read the module
docstring before relying on a one-line summary here or working around any of
them; several state a limit that decides whether a review still owes the
question.

Under `make check`:

- `scripts/check-lock-order.py` fails a file-scope mutex or rwlock missing from
  the ordering record, and a named lock that no longer exists. It checks
  membership, not placement.
- `scripts/check-eintr-contract.py` fails a new interruptible wait whose
  restart behavior is unstated.
- `scripts/check-atomics.py` fails a C11 atomic operation written without the
  `_explicit` form, and bans the compiler builtins, so the order is written at
  the site. What its docstring leaves out is a review question rather than a
  gap to skip, and it is the memory-order case worth the budget;
  `elfuse-conventions` states which access it cannot see and why a regex
  cannot close it.
- `scripts/check-svc-tails.py` holds every return tail to the X7 ptrace test,
  bar the one exception its docstring names and allowlists.
- `scripts/check-syscall-coverage.py` is a best-effort audit of `dispatch.tbl`
  against the tests corpus, satisfied by a textual mention and carrying an
  allowlist for the indirect cases. A green result is weaker than it looks.

Under `make verify`, once per proof target:

- `scripts/check-acsl-coverage.py` fails a contracted function left outside the
  proof set, which Frama-C would otherwise assume rather than prove.
- `scripts/check-char-signedness.py` catches plain `char` in proved code with
  the compiler rather than a regex, because its signedness differs between the
  target that compiles the proved sources and the one that compiles the guest
  tests.

Under `make verify-mutants`, which nothing else runs:

- `scripts/check-mutants.py` asserts each target rejects a known-broken source,
  which is the only evidence its clauses are load-bearing.

## Out of scope

Recorded once so it is not rediscovered as a finding on every review:

- Web and enterprise categories from the OWASP checklist. There is no server,
  no session, and no browser.
- Guest-versus-guest isolation. One process runs one guest program and its
  children; the guest is not a tenant to be separated from another tenant.
- Denial of service by the guest against itself. The guest owns its process,
  so wedging its own vCPU or filling its own address space is its business.
  Exhausting a host resource is not the same thing and stays in scope, which
  is what the caps rule above is for.
- Host hardening the operating system owns. An optional Seatbelt profile may
  backstop the path resolver, but it is not a second policy: containment stays
  defined and enforced by `path_translate_at`.

## Reviewing

Four habits that make a review worthless, each of which feels like diligence:

- Flagging without a fix. Naming what to validate, against what, and where is
  the finding; without it, the issue is not yet understood well enough to
  report.
- Claiming absence without tracing. Say which paths were walked and which were
  not. A stated gap is useful, an unstated one is a false clean.
- Reporting occurrences instead of the root cause. Findings sharing a cause
  are one finding with every sink listed.
- Flagging style as security. Naming and layout do not change the attack
  surface, and `elfuse-conventions` owns them anyway.

Writing one up: `references/finding-report.md`. Sweeping the whole tree
rather than a diff, and what each detector gets wrong here:
`references/sweeping-the-tree.md`.

## Commissioning a review

The habits above are the reviewer's. These are the requester's, and they
decide whether the reviewer's are reachable at all.

- Name a target and invite the null result. A request to make something
  secure presumes a defect, and a reviewer with a turn to justify will
  produce one. Asking for a verdict on a named diff, clean included, is what
  makes a clean answer worth anything.
- Require a file and a line for every claim, checked against the source
  rather than recalled, and read through something that returns the file
  verbatim. A shell here may be wrapped by a filter that elides content, and
  a claim built on elided output reads exactly like one that is true.
- State the threat model, or ask for it before the review rather than after.
  Without it a reviewer reports what the guest does to itself, and the
  out-of-scope list above gets rediscovered a category at a time.
- Ask what each gate deliberately does not check, not only whether it
  passed. That question is what turns the gate list above into review scope,
  and every docstring there states its own limit.
- Use two independent reviewers, both held to the citation rule, and keep
  what survives both. Without that rule a second opinion is a second guess,
  and a confident one costs more to disprove than it did to write.

The shape:

```
Review <target> for security.
Threat model: <state it, or ask for it first>.
Verify every claim against the source and cite file:line.
Say which paths were walked and which were not.
Each finding: root cause, every sink, the concrete fix.
Report clean if clean.
```

## Authoritative sources

- `src/syscall/internal.h` for lock order, `src/syscall/proc.h` for the
  restart contract, and the module docstring of each script above. All win
  over this file.
- CWE-699 for weakness names, preferring the Variant and Base abstractions.
  The process halves of NIST SP 800-218 and the OWASP checklist are written
  against web software; only their trust-boundary and input-validation
  sections carry over.
