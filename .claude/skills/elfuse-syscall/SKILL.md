---
name: elfuse-syscall
description: Adding or changing a Linux syscall in elfuse. Covers dispatch.tbl, sc_ wrappers, the translation boundary, path and filename resolution, fd classes, lock order, and the coverage gate. Use when touching src/syscall/ or the syscall side of src/runtime/, adding a syscall number, or debugging a guest ENOSYS/EINVAL/EPERM. If the change also alters what the guest observes on return (registers, page permissions, the EL0 return path), read elfuse-guest-abi as well.
---

# Adding a syscall to elfuse

`src/syscall/dispatch.tbl` is the authoritative list. Everything else follows
from an entry there.

This skill covers the host side of the boundary: taking guest arguments,
translating them, and calling macOS. Anything that changes what the guest sees
when it comes back is `elfuse-guest-abi`, even when the file lives under
`src/syscall/`. The guest chooses every argument a wrapper receives, so the
rules for handling one it chose badly are `elfuse-security`.

## The steps

1. Add one line to `src/syscall/dispatch.tbl`:

   ```
   SYS_<name> sc_<wrapper> <extra>
   ```

   `<extra>` becomes `needs_extra_regs` in `syscall_table`
   (`src/syscall/syscall.c`). The dispatcher always fetches X0-X2 and fetches
   X3/X4/X5 only when it is set, so the criterion is whether the wrapper
   expression consumes x3, x4, or x5 - not the syscall's documented argument
   count. Several three-argument entries carry 1.

   The dispatcher zero-initializes x3-x5, so a wrapper that reads them with
   `<extra>` left at 0 sees a deterministic 0, not a stale register: a syscall
   whose 4th argument silently behaves as NULL or 0 on every call is the
   symptom to recognize.

   Section comments (`# I/O: ...`) and blank lines are preserved into the
   generated header, so put the entry in the right block.

2. `scripts/gen-syscall-dispatch.py` regenerates the header; `make
   check-format` runs it, via its `check-syscall-dispatch` prerequisite. Never
   hand-edit the generated file.

3. Implement it in two pieces. The `sc_` wrapper and the `sys_` function are
   not the same thing and do not live in the same file.

   3a. The wrapper goes in `src/syscall/syscall.c`, as one line built by the
   `SC_FORWARD` / `SC_LOCKED` / `SC_STUB` macros. It exists to unpack x0-x5
   into typed arguments. `SC_LOCKED` is the variant that holds `mmap_lock`
   across the call.

   ```c
   SC_FORWARD(sc_read,  sys_read(g, (int) x0, x1, x2))
   SC_FORWARD(sc_dup3,  sys_dup3((int) x0, (int) x1, (int) x2))
   ```

   Every `sc_` symbol in the tree is here. The domain files contain none, so
   defining one there gets you a dead symbol the dispatch table never reaches.

   3b. The `sys_` implementation goes in the domain file whose name says so:
   `ls src/syscall/` is the list, and read/write/ioctl in `io.c`,
   brk/mmap/mprotect in `mem.c`, sockets in the `net*.c` family are
   representative. `elfuse-conventions` settles where a new file or a new
   shared declaration may go, and the answer is almost never a new one.

   Two domains sit outside `src/syscall/` because they are runtime state
   rather than syscall surface: clone and fork in `src/runtime/forkipc.c`,
   futex in `src/runtime/futex.c`. Both carry guest-ABI rules on top of what
   is here.

4. Add a test that names the syscall, or the build fails. See the coverage
   gate below.

## The translation boundary

One rule generates this whole section: nothing crosses the boundary
unconverted. A guest number is a Linux number until a translator turns it into
a macOS one, and every translator lives in `translate.c`. Adding a conversion
inline in a domain file is how the next syscall gets it wrong.

The axes that actually diverge, which is the part you cannot derive by
reading either kernel's headers alone:

- errno. Return `-linux_errno(errno)`. The two agree below roughly 35 and
  diverge above it (macOS EAGAIN is 35, Linux EAGAIN is 11), so a copied
  constant is silently right in testing and wrong in production.
- `AT_*` flags. `translate_at_flags()` before any macOS call, with one
  exception that is not derivable: Linux puts `AT_EACCESS` on the same bit as
  `AT_REMOVEDIR`, so `faccessat` paths use `translate_faccessat_flags()`
  instead. A blanket "always call `translate_at_flags()`" produces a
  wrong-but-plausible `faccessat`.
- open flags. aarch64-linux differs from x86_64-linux, not just from macOS, so
  a value cribbed from x86_64 documentation is wrong.
- clock ids. `translate_clockid()`.
- `UTIME_NOW` / `UTIME_OMIT`.
- socket type flags. `SOCK_NONBLOCK` and `SOCK_CLOEXEC` are ORed into the type
  argument on Linux and must be stripped out before `socket()`.
- sockaddr. `linux_to_mac_sockaddr` / `mac_to_linux_sockaddr`. Linux has no
  `sa_len` byte, and the address families do not share numbering.

The numeric values are in `src/syscall/abi.h` and `translate.c`. Read them
there rather than from a copy: a stale constant in a document is worse than no
constant, because it looks like it was checked.

## Paths and filenames

Every guest path goes through `path_translate_at` (`path.c`), including the
at-family, so an absolute path handed to `fchmodat`, `utimensat`, or an xattr
call cannot bypass the sysroot redirect. Calling a host path syscall on a raw
guest string is the bug this prevents.

Calling the right function is necessary and not sufficient. The resolver
upholds invariants that a caller can still break by resolving twice, by
re-deriving a path from a resolved one, or by following a link the resolver
deliberately did not:

- `..` is clamped at the guest root, and the containment check is rechecked
  for relative paths rather than assumed from the first resolution.
- Some paths are resolved never-follow by design. Turning one into a
  follow-resolution to "fix" a symlink is how containment is lost.
- The no-symlinks precheck has no component budget, on purpose.

Read the "Path Resolution" sections of `docs/internals.md` before changing
anything in `path.c` or adding a caller that resolves a path itself.

Guest filenames that collide under case-insensitive APFS are kept distinct by
the case-fold codec (`casefold.c`, `casefold-walk.c`), which has a real
on-disk format with golden vectors: a red `test-casefold-host` means the
format moved, not that the test is flaky. `docs/filenames.md` is the
specification.

## Guest memory access

Reads and writes of guest pointers go through the `guest_read`/`guest_write`
path, which uses `proved/gva.h`. Do not open-code a GVA-to-host-pointer
conversion: `gva_translate_perm` is what refuses `MEM_PERM_EL1_ONLY`
descriptors on EL0's behalf, and that refusal is the only thing stopping
`read(fd, shim_data_gva, n)` from leaking the EL1 cache.

If your bounds math is non-trivial (a parser over guest-supplied lengths, a
packer emitting into a guest buffer), it belongs in `src/proved/` with a proof
target. See the `elfuse-verify` skill.

## FDs and locks

Guest fds are not host fds. Allocate through the bitmap allocator in
`fdtable.c`; classify with the helpers in `fd.c` and `fd.h` (socket, pidfd,
eventfd, timerfd, signalfd). A class check that reads the raw fd number is wrong after
a `dup`.

The lock order is the comment at the top of `internal.h`. Acquire in the order
it lists, and add a new lock to that comment as soon as it exists, whether or
not a second module uses it. Three constraints in it are not derivable from
the ordering:

- The per-epoll-instance lock is taken under `fd_lock` by the close hook, but
  taken alone by `epoll_ctl` and `epoll_pwait`. This is the one a summary
  usually drops, and it is the deadlock-prone one.
- `sfd_lock` is never held together with `thread_lock`.
- FUSE takes `fuse_lock` first, then the per-session lock.

## Subsystems with rules of their own

Three areas under `src/syscall/` are not ordinary domain files, and a change
that treats them as such tends to compile and then deadlock or leak:

- FUSE (`fuse.c`) runs a whole filesystem transport inside the guest. Sessions
  are refcounted so an in-flight read pins the session against daemon exit,
  and the wait paths have to honor SA_RESTART rather than returning EINTR
  blindly.
- procfs, sysfs, and device emulation (`src/runtime/procemu.c`) run as an
  interception layer: the resolver goes first and hands it a normalized guest
  path, and `proc_intercept_open` and friends are consulted before the host
  filesystem is touched, returning `PROC_NOT_INTERCEPTED` to fall through. A
  path that looks host-backed may be synthesized, so a new file-touching
  syscall has to offer it the intercept rather than assuming a real file.
- Abstract Unix sockets, SCM_RIGHTS, and netlink each carry their own
  serialization format over guest-supplied lengths, which is why several of
  them have proof targets.

`docs/internals.md` has a section for each.

## The coverage gate

`scripts/check-syscall-coverage.py` runs inside `make check` and fails when a
`dispatch.tbl` entry has no direct or aliased test reference. Two ways out,
one of them correct:

- Write the test (correct).
- Add to `INDIRECT_COVERAGE` in the script with a real reason (only when
  success-path coverage is genuinely filesystem- or host-dependent, e.g. the
  xattr family). The script also fails on a stale allowlist entry, so a name
  that later gains a real test must be removed from the dict.

## When the change is not only host-side

Read `elfuse-guest-abi` too if your change touches any of these, whatever
directory the file is in: page permissions or mappings (`mem.c`), signal
delivery or `rt_sigreturn` (`signal.c`), fork and clone state transfer
(`src/runtime/forkipc.c`, `thread.c`), or anything that writes guest registers
on the return path.

## Authoritative sources

This skill is a working summary. These are tracked and survive a fresh clone,
so prefer them when the two disagree:

- `src/syscall/internal.h` - the lock order comment at the top.
- `src/syscall/dispatch.tbl` - the syscall list itself.
- `docs/internals.md` - syscall dispatch, the lock map, path resolution, FUSE,
  and procfs emulation in full.
- `docs/filenames.md` - the sidecar codec and its golden vectors.

## Verifying

`elfuse-verify` maps the area you touched to the minimum command set, which is
more specific than a habit, and says what a failure in each lane means.
`elfuse-debug` localizes a failure inside one.
