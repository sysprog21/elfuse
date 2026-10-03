---
name: elfuse-security
description: The guest as an attacker - where the trust boundary runs, the rules a handler on it obeys, what the gates leave to review, and what is out of scope. Use when a change parses a guest-chosen length, translates a guest address, resolves a guest path, walks a raw USB descriptor blob, allocates on the guest's behalf, or blocks holding shared state, and when auditing a diff or writing a finding up.
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

The surfaces, ordered by what one bad value reaches:

- Syscall arguments. X0-X5 and X8 arrive from EL0 with no host filter in
  front, so every wrapper reached from `src/syscall/dispatch.tbl` is on the
  boundary.
- Guest addresses. Every guest pointer becomes a host pointer through one
  translator, and the permission half is the security half.
- Formats the host parses for the guest: the ELF the loader reads, netlink
  messages, FUSE frames, control messages, sigframes, sockaddrs, iovecs,
  dirents, and the usbdevfs URB structures (`usbdevfs_urb`,
  `usbdevfs_ctrltransfer`, `usbdevfs_bulktransfer`). Each carries lengths,
  offsets, or counts the guest supplies, but what the guest owns differs per
  format, so answer that per format rather than assuming it. The ELF is read
  by offset, a sockaddr length arrives as a separate syscall argument, and a
  sigframe is built by the host and then left where the guest can rewrite it
  before `rt_sigreturn` reads it back.
- Paths. Every name the guest supplies, absolute ones included.
- Raw USB descriptor blobs, walked by `src/runtime/usb-desc.c`. The one
  input here the guest does not author; the header comment in
  `src/runtime/usb-desc.h` says why it is untrusted anyway.
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

Check the unit as well as the arithmetic. A length may be in bytes, elements,
iovec entries, guest 4 KiB pages or host 16 KiB pages, and Linux and macOS
size the same-named field differently: the Linux `cmsg_len` that
`src/syscall/net-msg.c` writes is 8 bytes where the macOS one is 4. A bound
written in the same wrong unit as the allocation it guards passes every test
and is still wrong, so compare the unit at the parse, the check, the
allocation and the copy.

Cost: an out-of-bounds write that reproduces only at boundary values, which is
the region hand-written tests skip. New arithmetic on a guest-chosen length
belongs in `src/proved/` behind a contract, not inline, and its call sites
stay a review question; `elfuse-verify` says why.

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

`elfuse-guest-abi` owns the guard and what the reserve holds. What it leaves
to review is that a range which maps or repermissions memory is never
presented as a pointer, so no translator sees it: the guard is the only check
it gets.

Cost: a new mapping-shaped syscall that skips the guard hands the guest the
page tables `gva_translate_perm` walks for every later guest pointer, so the
guest writes its own permissions: shim_data stops being EL1-only and W^X is
whatever it says. No translator refusal stands in the way, because nothing
was translated. How far past the slab that reaches, and so how it grades, is
in `references/finding-report.md`.

### Paths

`elfuse-syscall` owns `path_translate_at` and the absolute at-family trap.
Every syscall that takes a path is a sibling of every other (below), so a
new path taker is checked against that rule, not against its nearest
neighbor.

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

### Shared pages

A guest value read twice is two values. Copy the structure in once, validate
the copy, then use only the copy; validating in place and passing the original
address on is the double fetch, and shared memory makes it reachable without
timing luck. Lock order belongs to `elfuse-syscall` and memory order to
`elfuse-conventions`.

Cost: a double fetch is not a race the guest has to win. It re-runs the syscall
until the two reads differ, so the window is as wide as it needs to be.

### Outbound copies

No byte reaches the guest that the path did not set. Padding, reserved
fields, union tails and members a given path leaves unset otherwise carry
whatever the host stack held there. Three shapes meet that here:

- Clear the whole object, then fill it, with `memset` rather than `= {0}`,
  which before C23 does not promise the padding. The sigframe build in
  `src/syscall/signal.c` is the pattern.
- For a packed record, set every field and zero the pad explicitly, as the
  getdents64 packer in `src/syscall/fs.c` does.
- For a variable-length encoding, copy out only the length that was written:
  `mac_to_linux_sockaddr` in `src/syscall/net-abi.c` returns exactly the bytes
  it filled, and its callers cap the guest copy at that.

Cost: a disclosure of host stack contents, which may include host pointers,
so the guest learns the layout every other primitive needs.

### Sibling paths

A check in one entry point does not protect the entries that reach the same
sink. The set is the callers of the shared helper, so grep them rather than
keep a list: in `src/syscall/io.c`, `io_xfer` for the descriptor transfers,
`host_iov_prepare` and `single_guest_iov` for guest iovecs, and
`copy_fd_range` for sendfile and copy_file_range; `path_translate_at` in
`src/syscall/path.c`; `linux_to_mac_sockaddr` and `mac_to_linux_sockaddr` in
`src/syscall/net-abi.c`; `elf_load_fd` in `src/core/elf.c`. A path that
does not share the helper is a sibling all the same, and no grep finds it:
splice keeps its own drain loop in `src/syscall/io.c`, and sendmsg its own
wait loop in `src/syscall/net-msg.c`. Read every sibling before calling a fix
done.

Cost: the guard reads as present in review, because it is, and the guest
takes the sibling that lacks it.

### The return path

`elfuse-guest-abi` owns the HVC return tails, and `src/syscall/proc.h` the
restart contract. What neither settles is whether a wait's stated answer is
right: a wait that has sent a request or spent part of a relative deadline
owes `syscall_restart_forbid`, because it cannot be re-run from its original
arguments.

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

## What the gates leave to review

Do not re-derive what a gate already proves; spend the review on what it
leaves. `elfuse-verify` owns which target runs which gate, and each script's
module docstring states its own limit and wins over the summary here.

- `scripts/check-lock-order.py` checks membership, not placement: whether a
  lock sits in the right place in the order is a review question.
- `scripts/check-eintr-contract.py` requires a stated restart behavior, not a
  correct one.
- `scripts/check-svc-tails.py` allowlists the tails its docstring names.
- `scripts/check-syscall-coverage.py` is satisfied by a call-shaped mention
  or a syscall-number macro in a test, not by a test of the behavior, so a
  green result is weaker than it looks.

`elfuse-conventions` carries the atomics gate's gap, and `elfuse-verify` the
proof gates' (call sites, and targets no mutant has been run against).

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

Habits that make the reading worthless, each of which feels like diligence:

- Claiming absence without tracing. Say which paths were walked and which were
  not. A stated gap is useful, an unstated one is a false clean.
- Flagging style as security. Naming and layout do not change the attack
  surface, and `elfuse-conventions` owns them anyway.
- Trusting the comment that says why a site is safe. A comment is the
  authority for intent; its safety claim is checked against the code like any
  other, since it is often older than the code under it.

Writing a finding up: `references/finding-report.md`. Sweeping the whole tree
rather than a diff, and what each detector gets wrong here:
`references/sweeping-the-tree.md`. Asking someone else, an agent or a second
model, for a review: `references/commissioning-review.md`.

## Authoritative sources

- `src/syscall/internal.h` for lock order, `src/syscall/proc.h` for the
  restart contract, and the module docstring of each script above. All win
  over this file.
- CWE-699 for weakness names, preferring the Variant and Base abstractions.
  The process halves of NIST SP 800-218 and the OWASP checklist are written
  against web software; only their trust-boundary and input-validation
  sections carry over.
