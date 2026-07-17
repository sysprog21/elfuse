# elfuse Internals

This document is the canonical technical reference for the runtime. It maps the
source tree, then walks each subsystem from guest entry to syscall return:
memory layout, the EL1 shim and HVC protocol, page-table management, syscall
translation, threads, fork/clone, signals, ptrace, dynamic linking, and the
GDB stub.

It is aimed at contributors. For a high-level overview see
[../README.md](../README.md); for command-line use see [usage.md](usage.md);
for the validation flow see [testing.md](testing.md).

## Runtime Model

`elfuse` runs one Linux guest process inside one Hypervisor.framework VM owned
by one macOS host process. Guest code executes at EL0. A small EL1 shim
(`src/core/shim.S`) handles exceptions, provides the syscall trap path, and
cooperates with the host through a compact HVC protocol.

aarch64 guests execute their own instructions natively on the CPU.
x86_64 guests (both static and dynamic) execute through Apple's
Rosetta translator hosted inside the same VM at link address
`0x800000000000` (see [x86_64-via-Apple-Rosetta](#x86_64-via-apple-rosetta)).
Both architectures share the same EL1 shim, syscall surface, and
host-side handlers.

### Lifecycle In Five Steps

The whole runtime fits into a load -> boot -> run -> translate ->
return loop:

1. Load. `src/main.c` parses options; `src/core/elf.c` parses the
   guest ELF and any `PT_INTERP`; `src/core/guest.c` reserves a
   demand-paged guest address space (up to 1 TiB IPA on M3+); the
   initial Linux stack is built by `src/core/stack.c`.
2. Boot. `src/core/bootstrap.c` installs the EL1 shim
   (`src/core/shim.S`) in the runtime infrastructure reserve, seeds
   page tables, and enters EL0. For x86_64 guests, Rosetta is loaded
   alongside as a co-resident aarch64 binary at `0x800000000000`.
3. Run. The guest executes natively on an HVF vCPU. Pure computation
   never leaves the guest.
4. Translate. A guest `SVC #0` traps into the shim and is forwarded
   over `HVC #5` to the host. `src/syscall/syscall.c` dispatches into
   focused domain handlers (`mem.c`, `fs.c`, `net.c`, `signal.c`, ...)
   that translate errno values, flag layouts, struct shapes, and
   socket address formats between Linux and macOS.
5. Return. The host writes the result back into the vCPU, signals any
   required TLBI (see [Dynamic Page-Table Extension And
   TLBI](#dynamic-page-table-extension-and-tlbi)), and the shim
   `ERET`s back to EL0.

Threads enter the same loop on their own vCPU
(`src/runtime/thread.c`). `fork` clones the loop in a new
`posix_spawn`-ed `elfuse` process and transfers state through IPC
(`src/runtime/forkipc.c`). `execve` reloads the ELF inside the
existing VM and restarts the loop (`src/syscall/exec.c`).

Boot sequence:

1. `src/main.c` parses options and prepares guest bootstrap state.
2. `src/core/elf.c` parses the ELF image and any `PT_INTERP` interpreter.
3. `src/core/stack.c` builds a Linux-style initial stack (`argc`, `argv`,
   `envp`, `auxv`).
4. `src/core/guest.c` reserves guest memory, page tables, and semantic
   regions.
5. `src/core/shim.S` enters guest EL0 and forwards traps through HVC exits.
6. `src/syscall/syscall.c` dispatches Linux syscalls into domain handlers.
7. `src/syscall/proc.c` owns the main vCPU run loop and stop/exit
   integration.

## Source Map

Top-level areas:

- `src/core/`: guest memory, ELF loading, bootstrap, initial stack, vDSO,
  EL1 shim assembly, and the embedded Rosetta translator host
- `src/syscall/`: Linux syscall handlers and translation boundaries
- `src/runtime/`: thread table, futexes, procfs helpers, fork/clone IPC,
  argv/comm rewriting for `prctl PR_SET_NAME`
- `src/debug/`: crash reporting and built-in GDB RSP stub

Key files:

| File | Role |
|------|------|
| `src/main.c` | CLI, bootstrap, first vCPU creation, debugger startup |
| `src/core/guest.c` | guest memory reservation, region tracking, page tables |
| `src/core/elf.c` | ELF parsing, `PT_LOAD`, `PT_INTERP`, loader decisions |
| `src/core/stack.c` | Linux initial stack and `auxv` construction |
| `src/core/shim.S` | EL1 shim, exception vectors, HVC protocol |
| `src/core/shim-globals.c` | EL1-only `shim_data` cache (identity slots, urandom ring, attention bits) |
| `src/core/vdso.c` | synthetic vDSO (CNTVCT clock_gettime fast path, SVC trampolines) |
| `src/core/rosetta.c` | x86_64-via-Rosetta translator host, AOT cache, kbuf alias |
| `src/core/sysroot.c` | `--sysroot` / `--create-sysroot` provisioning |
| `src/syscall/syscall.c` | syscall dispatch and shared wrapper helpers |
| `src/syscall/mem.c` | `brk`, `mmap`, `mprotect`, `mremap`, `madvise`, `msync` |
| `src/syscall/fs.c`, `fs-stat.c`, `fs-xattr.c` | filesystem syscalls |
| `src/syscall/io.c`, `poll.c`, `fd.c`, `fdtable.c` | I/O, polling, FD lifecycle and table |
| `src/syscall/path.c` | centralized guest-to-host path resolution |
| `src/syscall/casefold.c` | guest/host filename encoding for case-folding volumes (see [filenames.md](filenames.md)) |
| `src/syscall/casefold-walk.c` | case-exact path resolution against the sysroot |
| `src/syscall/fuse.c` | guest-internal FUSE transport and minimal VFS |
| `src/syscall/inotify.c` | inotify via kqueue `EVFILT_VNODE` |
| `src/syscall/sysvipc.c` | System V shared memory and semaphores |
| `src/syscall/signal.c` | signal delivery, `rt_sigframe`, `rt_sigaction` |
| `src/syscall/time.c` | clocks, timers, `setitimer`, clock-ID translation |
| `src/syscall/sys.c` | `uname`, `sysinfo`, `getrandom`, `prlimit64` |
| `src/syscall/net.c`, `net-abi.c`, `net-absock.c`, `net-msg.c`, `net-sockopt.c`, `netlink.c` | sockets, SCM_RIGHTS, abstract Unix sockets, netlink |
| `src/syscall/translate.c` | errno and shared `AT_*` flag translation |
| `src/syscall/proc.c` | vCPU run loop, `wait4`, ptrace coordination, HVC #6 routing |
| `src/syscall/exec.c` | `execve`: ELF reload, interpreter resolve, vCPU restart |
| `src/runtime/forkipc.c`, `fork-state.c` | `fork`/`clone` state transfer over the fork IPC channel |
| `src/runtime/thread.c`, `futex.c` | guest thread table, futex wait queues |
| `src/runtime/procemu.c` | `/proc`, `/dev`, and selected pseudo-files |
| `src/runtime/proctitle.c` | argv / comm rewriting for `prctl PR_SET_NAME` |
| `src/debug/gdbstub.c`, `gdbstub-rsp.c`, `gdbstub-reg.c` | GDB RSP stub |

## Generic Dynamic Containers

`src/utils.h` provides the raw `dynamic_array_t` used by the procfs VMA
snapshot and the string builder. It is header-only: every operation is a
`static inline`, so there is no container object to link. Capacity
is measured in element slots, while `count` is the number of logical elements.
The allocation is one contiguous block of `capacity * element_size` bytes;
both the count addition and the multiplication are checked before a growth.
Arithmetic overflow reports `EOVERFLOW`, invalid arguments report `EINVAL`,
and an allocation failure reports `ENOMEM`. Growth is transactional: on any
failure the old pointer, count, and capacity remain valid.

The generated typed facades own only their array storage. Elements are copied
as trivially-copyable bytes, so the container does not call destructors and
does not manage pointers or other resources held by an element. `destroy`
frees the contiguous block and restores the zero state. A facade can therefore
be declared as `{0}` and initialized lazily on its first operation.

`string_builder_t` wraps a raw `dynamic_array_t` of `char`. The count is the
C-string length and excludes the terminator, so every path that grows the
builder reserves one byte beyond the payload and restores `data[count] ==
'\0'`. The surviving surface is `init`, `destroy`, `length`, `data_const`,
`append_n`, and `appendf`; the plain-text `append`, `reserve`, and the capacity accessor went
with the header-only conversion because nothing outside the tests used them.
`appendf` renders into a scratch buffer before touching storage, which is what
makes a format string or argument aliasing the builder's own data safe, and it
commits only the prefix through the first NUL, matching standard C string
semantics.

## Hypervisor.framework Constraints

Apple HVF imposes a handful of constraints that shape the rest of the design:

- W^X is enforced even with `SCTLR.WXN=0`. A page-table entry cannot be both
  writable and executable. Use RW for data and RX for code.
- HVF returns `SCTLR=0x0` by default; `RES1` bits must be set explicitly. The
  shim uses `SCTLR_RES1` (`0x30D00980`) plus the desired bits.
- The MMU must be enabled from inside the vCPU (via HVC #4 from the shim),
  not by the host before `hv_vcpu_run()`. Setting `SCTLR.M=1` from the host
  before vCPU entry causes permission faults on the first instruction fetch.
- `GUEST_IPA_BASE` must be `0`. ELF binaries use absolute addresses from
  their link address (e.g., `0x400000`); a non-zero IPA base produces
  translation faults.
- System registers cannot be set via `MSR` from the guest because
  `HCR_EL2.TSC=1` traps all `MSR` writes. Boot-time sysreg installation
  (RES1 bits, MMU enable, TTBR0, etc.) goes through HVC #4 from the EL1
  shim. Runtime EL0 sysreg traps -- `MSR TPIDR_EL0` and similar -- are
  handled by the HVC #12 system-instruction trap path.
- Only `HV_SYS_REG_*` constants from Hypervisor.framework may be used for
  register IDs.
- `hv_vcpu_t` value zero is a valid handle (normally the first vCPU in a VM),
  not an invalid sentinel. `guest_t` and `thread_entry_t` therefore track
  handle ownership with a separate `vcpu_valid` flag; signal preemption,
  quiesce, ptrace, and teardown must consult that flag before calling HVF.
- Cross-thread vCPU register access is unreliable; all register access must
  happen on the owning thread. This drives the snapshot protocol used by
  both ptrace and the GDB stub.
- HVF allows only one VM per host process. This is the reason `fork` is
  implemented through `posix_spawn` plus IPC state transfer.

## Memory Layout

Guest memory is identity-mapped (guest VA == guest IPA). Large areas use 2 MiB
block descriptors by default; mappings that need mixed permissions are split
to 4 KiB L3 pages (see [Page Table Splitting](#page-table-splitting)).

Low, fixed addresses:

```
0x00400000   - varies:       ELF LOAD segments (PIE_LOAD_BASE for ET_DYN)
0x01000000:                  brk base (16 MiB)
0x07800000   - 0x07800FFF:   Stack guard page (PROT_NONE, dynamic position)
0x07801000   - 0x07FFFFFF:   Stack (8 MiB, 4 x 2 MiB blocks, RW, grows down)
0x10000000   - 0x101FFFFF:   mmap RX region (initial 2 MiB, pre-mapped RX)
0x10200000   - mmap_limit:   mmap RX growth area
0x000200000000 - 0x0002001FFFFF: mmap RW region (initial 2 MiB at 8 GiB, RW)
0x000200200000 - mmap_limit:     mmap RW growth area
```

Within-32-bit values are rendered with 8-digit padding; values that
extend above 32 bits use 12-digit padding so a reader can tell the
range class at a glance.

High addresses, anchored to `interp_base` (computed from `guest_size`, see
below). The runtime infrastructure reserve is a 16 MiB region placed at
`[interp_base - INFRA_RESERVE, interp_base)` -- in the dead zone above
`mmap_limit` -- so guest binaries keep the low addresses their link scripts
expect. It is present regardless of `--sysroot`; offsets are relative to its
base `infra = interp_base - 16 MiB` (exact values in `src/core/guest.h`):

```
infra + 0x000000 - 0x00FFFF:  null guard (64 KiB, unmapped)
infra + 0x010000 - 0xDF5FFF:  page table pool (~13.9 MiB, RW)
infra + 0xDF6000 - 0xDFFFFF:  shim code slot (40 KiB, RX). Shares the PT
                              pool's tail 2 MiB L2 block, so that block
                              splits to 4 KiB L3 pages (mixed RX/RW).
infra + 0xE00000 - 0xFFFFFF:  shim data + EL1 stack (2 MiB L2 block, RW;
                              ends at interp_base)
interp_base      - varies:    Dynamic linker (g->interp_base, --sysroot only)
```

The reserve is demand-paged (`MAP_ANON`), so its unused page-table-pool pages
cost no host RAM despite the generous virtual reservation. The pool holds
~3558 L3 pages (~7 GiB of split address space), enough for the many V8
isolates a Node `worker_threads` pool or cluster spins up.

The guest size is determined by the VM's configured IPA width (capped at
40-bit / 1 TiB):

- 36-bit IPA (64 GiB) -- native AArch64 on Apple M2: `mmap_limit ≈ 56 GiB`,
  `interp_base ≈ 60 GiB`
- 40-bit IPA (1 TiB) -- native AArch64 on Apple M3 and later:
  `mmap_limit ≈ 1016 GiB`, `interp_base ≈ 1020 GiB`

Both `mmap_limit` and `interp_base` are computed at runtime from `guest_size`
and stored in `guest_t`. macOS demand-pages physical memory on first touch,
so the reservation costs no RAM until the guest writes to a page.

The mmap RW region starts at 8 GiB to match real Linux kernel address-space
layout, where `mmap` allocations sit well above text/data/brk.

For address spaces larger than 512 GiB, the L0 page table needs multiple
entries (each covers 512 GiB). The page-table builders compute the L0 index
from the actual IPA and allocate L1 tables on demand per L0 slot.

## Page Table Splitting

A 2 MiB L2 block descriptor cannot mix RW and RX permissions, but real shared
libraries combine `.text` (RX) and `.data` (RW) within a single 2 MiB range.
`guest_split_block()` in `src/core/guest.c` converts an L2 block descriptor
into a table descriptor pointing to an L3 table of 512 × 4 KiB page entries,
each with independent permissions.

Splitting is triggered by:

- `sys_mmap` with `MAP_FIXED`, when the fixed address lands in a block whose
  permissions differ from the request (typical case: the dynamic linker
  overlaying `.data` RW onto a library `.text` RX block).
- `sys_mprotect`, when changing permissions for a sub-block range, e.g.
  RELRO finalization.

`guest_update_perms()` orchestrates the full workflow: it checks whether a
block needs splitting, splits it if so, then updates the affected L3 page
entries. Whole-block permission changes are done in place without splitting.

`mmap` itself uses a gap-finding allocator that walks the sorted region array
to find free address space. `PROT_EXEC` requests go to the RX region
(`MMAP_RX_BASE = 0x10000000`); other requests go to the RW region
(`MMAP_BASE = 0x200000000`). Address hints are honored when possible. This
arrangement makes `.text` and `.data` land in different 2 MiB blocks where
practical, and L3 splitting handles the residual cases where they share a
block.

## Dynamic Page-Table Extension And TLBI

When `sys_mmap` or `sys_brk` needs memory beyond the currently mapped page
tables, the host calls `guest_extend_page_tables()` to add new L2 entries.
This is safe because the vCPU is paused while servicing HVC #5. The host
accumulates the smallest sufficient TLBI request into a per-vCPU
`_Thread_local cpu_tlbi_req` slot (see `src/core/guest.h`) and translates
it into `X8`, `X9`, `X10`, and `X11` on return from HVC #5:

```
X8 == 0  TLBI_NONE        no flush; restore GPRs (keep X0); ERET
X8 == 1  TLBI_BROADCAST   TLBI VMALLE1IS + DSB ISH + ISB
                          -> restore GPRs (keep X0); ERET
X8 == 2  drop-frame       discard the saved GPR frame
                          (`add sp, sp, #256`) and ERET on the rebuilt
                          EL0 register state. Set by `execve` and
                          `rt_sigreturn` (which write the whole frame
                          directly into the vCPU) and by
                          `signal_deliver()` on the syscall-return
                          path (so handler PC/SP/LR/args installed by
                          the host are not overwritten by the stale
                          shim frame on ERET). `execve` additionally
                          issues `IC IALLU` because the new program
                          text may live in pages that previously held
                          the old text.
X8 == 3  TLBI_RANGE       loop TLBI VAE1IS over `X9` (start VA),
                          `X10` (page count); 4 KiB granule. Used for
                          up to `TLBI_SELECTIVE_MAX_PAGES = 16` pages.
X8 == 4  TLBI_RANGE_LARGE single-shot TLBI RVAE1IS with the encoded
                          operand in `X9`. Used for 17..64 pages when
                          `FEAT_TLBIRANGE` is available
                          (`g_tlbi_range_supported`). Above 64 pages,
                          or when the feature is absent, the host
                          upgrades to broadcast (`X8 == 1`).
X11      icache hint      Set to `1` when the request transitions a
                          page to executable (W^X swap); the shim then
                          issues an `IC` invalidate alongside the
                          chosen TLBI flavor.
```

`TLBI VAE1IS` retires any 2 MiB block entry containing the VA
(ARM ARM B2.2.5.6), so `guest_split_block()` callers no longer issue a
separate broadcast after the split lands.

`X8 == 2` is the generic drop-saved-frame marker: the host has
rebuilt EL0 register state directly into the vCPU and the saved
syscall frame on the EL1 stack is stale, so the shim drops the frame
and `ERET`s without restoring GPRs. Three call sites use it:

- `sys_execve` (`src/syscall/exec.c:785, 1093`) after the ELF reload.
- `signal_rt_sigreturn` (`src/syscall/signal.c:1710`) after restoring
  the saved sigframe.
- `signal_deliver` (`src/syscall/signal.c:1594`) when a signal is
  delivered on the syscall-return path; without the marker the shim
  would overwrite the handler PC, SP, LR, and arg-register state with
  the stale syscall frame on `ERET`.

`X8` (the syscall-number register) and `X9`/`X10` are already considered
clobbered by the Linux syscall ABI, so callers never expect them to be
preserved across SVC.

Important: the first two paths (`sys_execve` and
`signal_rt_sigreturn`) return `SYSCALL_EXEC_HAPPENED` to bypass the
normal syscall dispatch epilogue. `signal_deliver` runs from inside
the epilogue. Any future code path that rebuilds EL0 register state
on the syscall-return path must write `X8 = 2` the same way.

## EL1 Shim And HVC Protocol

Vectors enter EL1 from EL0 traps and forward them to the host through HVC.
DC ZVA is emulated inside the shim (it zeroes 64 bytes at the cache-line-
aligned address from the `Rt` register); HVF traps DC ZVA via `HCR_EL2.TDZ=1`.

| HVC # | Purpose | Registers |
|-------|---------|-----------|
| #0 | Normal exit | `X0` = exit code |
| #2 | Bad exception | `X0`=ESR, `X1`=FAR, `X2`=ELR, `X3`=SPSR, `X5`=vector |
| #4 | Set boot system register | `X0` = reg ID (0–8), `X1` = value (used by the shim during boot to install RES1 bits and enable the MMU) |
| #5 | Syscall forward | `X0`–`X5` = args, `X8` = syscall number on entry; on return `X8` carries the TLBI kind (`0` = none, `1` = broadcast, `3` = selective range with `X9` = VA + `X10` = page count, `4` = single-shot `TLBI RVAE1IS` with encoded operand in `X9`). `X8 = 2` is the generic drop-saved-frame marker -- set when the host has rebuilt EL0 state directly (by `execve`, `rt_sigreturn`, and `signal_deliver()` on the syscall-return path) so the shim discards the saved syscall frame on ERET. `X11` is the icache-flush hint (set to `1` when the request transitions a page to executable, so the shim issues `IC` alongside the chosen TLBI) |
| #6 | Embedder extension | `X8` = call number, `X0`–`X7` = args; routed to `g->hvc6_handler` if set, no-op otherwise. Handler may request a vCPU yield via `proc_request_hvc6_yield()` |
| #7 | MRS trap (read sysreg) | host reads register from ESR ISS; returns value in `X0` |
| #9 | W^X toggle | `X0` = FAR, `X1` = type (0 = exec→RX, 1 = write→RW) |
| #10 | BRK from EL0 | SIGTRAP delivery / ptrace-stop; GPRs in frame |
| #11 | EL0 fault | SIGSEGV/SIGILL delivery; GPRs in frame |
| #12 | EL0 system-instruction trap | cache maintenance logging (DC CVAU, IC IVAU, …) and `MSR TPIDR_EL0` emulation |

### Critical Vector-Entry Rule

Vector entry stubs that lead to `svc_handler` MUST NOT clobber any GPR. The
Linux syscall ABI preserves all registers except `X0` across `SVC #0`, and
musl/glibc rely on this for scratch registers (`X9`–`X15`). If a vector entry
writes to any GPR (e.g., `mov x5, #offset`) before `svc_handler` saves
registers, the saved value is wrong and the EL0 caller's register state is
corrupted after `ERET`.

Only `bad_exception` vectors may clobber `X5` (they halt, so preservation is
unnecessary).

## Syscall Translation Boundary

Linux user-space compatibility comes from explicit translation at the syscall
boundary. `src/syscall/syscall.c` routes syscall numbers into focused domain
files. The translation layer is responsible for:

- errno translation
- flag translation
- Linux/macOS structure layout adaptation
- guest memory copying for pointer arguments
- Linux-compatible descriptor and signal semantics

### errno

macOS and Linux errno values diverge starting around 35. `linux_errno()` in
`src/syscall/translate.c` maps via switch. Notable mappings:

| Linux | macOS |
|-------|-------|
| `EAGAIN` (11) | `EAGAIN` (35) |
| `ENOSYS` (38) | `ENOSYS` (78) |
| `ENAMETOOLONG` (36) | `ENAMETOOLONG` (63) |
| `ELOOP` (40) | `ELOOP` (62) |

### `AT_*` Flags

`AT_*` flag bits differ between Linux and macOS:

| Flag | Linux | macOS |
|------|-------|-------|
| `AT_SYMLINK_NOFOLLOW` | `0x100` | `0x20` |
| `AT_SYMLINK_FOLLOW` | `0x400` | `0x40` |
| `AT_REMOVEDIR` | `0x200` | `0x80` |

Most `AT_*` flags go through `translate_at_flags()` in
`src/syscall/translate.c` before issuing macOS calls. `faccessat` is a
special case: Linux defines `AT_EACCESS` at the same bit (`0x200`) as
`AT_REMOVEDIR`, so `faccessat` paths instead use
`translate_faccessat_flags()` (also in `src/syscall/translate.c`), which
interprets that bit as `AT_EACCESS`.

### `open` Flag Values

Aarch64-Linux open flags differ from x86_64. From `asm-generic/fcntl.h`:

| Flag | Value (octal) | Value (hex) |
|------|---------------|-------------|
| `O_DIRECTORY` | `040000` | `0x4000` |
| `O_NOFOLLOW`  | `0100000` | `0x8000` |
| `O_DIRECT`    | `0200000` | `0x10000` |
| `O_LARGEFILE` | `0400000` | `0x20000` (no-op on LP64) |
| `O_CLOEXEC`   | `02000000` | `0x80000` |

### Clock IDs

Linux `CLOCK_MONOTONIC = 1`, macOS `CLOCK_MONOTONIC = 6`. See
`translate_clockid()` in `src/syscall/time.c`. Other clock IDs are
translated similarly.

### Sockets

Socket syscalls are translated in `src/syscall/net.c` and friends:

- `AF_INET6` differs: Linux `10`, macOS `30`.
- `sockaddr` has no `sa_len` byte on Linux but does on macOS. All conversions
  go through `linux_to_mac_sockaddr()` and `mac_to_linux_sockaddr()`.
- Linux ORs `SOCK_NONBLOCK` (`0x800`) and `SOCK_CLOEXEC` (`0x80000`) into the
  type argument; both bits must be extracted before calling `socket()`.
- `SOL_SOCKET` option numbers (`SO_TYPE`, `SO_SNDBUF`, `SO_RCVBUF`, …)
  differ between platforms and are remapped per option.

Netlink sockets are emulated in `src/syscall/netlink.c`: `NETLINK_ROUTE`
answers the `RTM_GETLINK` / `RTM_GETADDR` dumps `getifaddrs` issues, and
`NETLINK_KOBJECT_UEVENT` sockets are accepted as silent sockets -- no uevent
is ever synthesized, so the fd never becomes readable, which is exactly a
real Linux kernel with no hotplug activity -- because libusb-style hotplug
monitors must open, bind, and set `SO_PASSCRED` on one before they will
initialize at all.

`socket()` validates its type argument the way `__sock_create()` and
`netlink_create()` do, in that order: an unknown bit outside
`SOCK_NONBLOCK|SOCK_CLOEXEC` is `EINVAL`, and a base type other than
`SOCK_RAW` or `SOCK_DGRAM` is `ESOCKTNOSUPPORT` -- before the protocol
number is looked at, so `socket(AF_NETLINK, SOCK_STREAM, 99)` reports the
type error and not the family one.

`SOL_SOCKET` options on a netlink fd follow `sk_setsockopt` /
`sk_getsockopt` rather than being accepted and forgotten: whatever can be
set can be read back, `SO_RCVBUF` and `SO_SNDBUF` clamp-double-floor at the
two different `SOCK_MIN_*` floors, `SO_RCVTIMEO` really does bound a
blocking receive, and the options Linux refuses (`SO_SNDLOWAT`, a
privileged `SO_DEBUG`, a non-inet `SO_REUSEPORT`, a short `SO_LINGER` or
timeout `optlen`) are refused with the same errno.

`SO_RCVTIMEO` and `SO_SNDTIMEO` are stored as `sk_rcvtimeo` /
`sk_sndtimeo` are: a jiffy count with `HZ` pinned at 1000, which gives
`sock_set_timeout()`'s three states rather than two. `{0, 0}` and any
`tv_sec` past `MAX_SCHEDULE_TIMEOUT/HZ - 1` mean wait forever; a negative
`tv_sec` means do not wait at all, so a blocking receive under it reports
`EAGAIN` at once; anything else is that many milliseconds, rounded up from
a sub-jiffy `tv_usec`. Both of the first two read back as `{0, 0}`, exactly
as `sock_get_timeout()` reports them, so only a receive can tell them
apart. The deadline such a timeout produces is added to the clock with
saturation, since the largest one Linux accepts is within seconds of
overflowing a 64-bit millisecond count.

An interrupted receive with a finite timeout forbids the SVC restart only
when the interruption is one the guest can see. `io_wait_fd_timed_or_-
interrupted()` also reports `EINTR` for the dispatcher's own execve
handoff, which no signal accompanies; forbidding there turned a sibling's
`execve` into an `EINTR` on a `recvmsg`. The restarted call instead resumes
the deadline the interrupted attempt was using, which is what Linux's
`restart_block` carries.

`SOL_NETLINK` is emulated under the same contract `bind()` gives -- the
membership and the flags are recorded, and no multicast traffic is ever
synthesized to deliver on them. `NETLINK_ADD_MEMBERSHIP` /
`NETLINK_DROP_MEMBERSHIP` range-check the group and return 0;
`NETLINK_LIST_MEMBERSHIPS` reads the resulting bitmap back;
`NETLINK_PKTINFO`, `NETLINK_BROADCAST_ERROR`, `NETLINK_NO_ENOBUFS`,
`NETLINK_CAP_ACK`, `NETLINK_EXT_ACK` and `NETLINK_GET_STRICT_CHK` set and
read back as flags (a libnl or libmnl monitor sets several of these on the
way up and treats a refusal as a broken socket); `NETLINK_LISTEN_ALL_NSID`
wants `CAP_NET_ADMIN` and reports `EPERM`; the removed mmap ring options
and anything else report `ENOPROTOOPT`.

Netlink socket state is keyed by guest fd number, and a guest fd number
outlives its socket: `fd_cleanup_entry()` runs the netlink teardown after
the number is already back in the fd table's free pool, so a concurrent
`socket()` can be handed it while the previous slot is still live. Slots
therefore carry an allocation generation -- lookups answer with the newest
slot for a number and teardown retires the oldest -- which pairs each
teardown with the socket that asked for it whatever order the threads
arrive in.

### Stack Alignment

The Linux initial stack must have `SP` 16-byte aligned and pointing directly
at `argc`. Total 8-byte words on the structured area are
`35 + extra + argc + envc`, where:

- `35` covers the fixed scaffolding: 15 base auxv entries (`30` words) +
  the `AT_NULL` auxv terminator (`2` words) + the `envp` `NULL`
  terminator (`1`) + the `argv` `NULL` terminator (`1`) + `argc` itself
  (`1`) = `35`.
- `extra` starts at `4` because `AT_EXECFN` and `AT_BASE` are always
  emitted (`+2` words each). It adds another `2` for `AT_SYSINFO_EHDR`
  when a vDSO is present, and another `2` for `AT_EXECFD` when
  `binfmt_misc` passes one.
- `argc` and `envc` are the user-provided argument and environment counts.

If that total is odd, one padding word is pushed before `auxv`. Padding
goes above the structured area, never below. Post-push masking
(`sp &= ~15`) breaks because it inserts a gap between `SP` and `argc`. See
`build_linux_stack()` in `src/core/stack.c` for the full layout.

### `mmap` Notes

Private anonymous mappings are lazy at 2 MiB materialization granularity. A
host-side hierarchical bitmap records which low-VA 2 MiB blocks contain any
valid TTBR0 PTE, independently of the dirty-block bitmap. `munmap` and recycled
fast-path arenas use this index to visit only materialized blocks, so untouched
multi-GiB reservations have length-independent teardown. When every mapping in
a per-vCPU arena has been released and the index confirms that no PTE remains,
the arena cursor rewinds in place instead of taking a refill HVC.

Aligned file-backed `MAP_SHARED` (fixed or non-fixed) installs a real
host `mmap(MAP_FIXED|MAP_SHARED, fd)` overlay onto the guest slab so
the kernel page cache keeps the mapping coherent with the file (and
with peer overlays). The slab is tracked as a sorted list of
2 MiB-aligned `hvf_segment_t` entries; each overlay request splits,
unmaps, and re-`mmap`s the host file at the exact host VA, then
re-maps the segment. Apple Silicon enforces 16 KiB host pages, so the
gap-finder advances to the next host-page boundary after each
allocation.

The snapshot `pread` emulation (zero first for pages beyond EOF, then
overlay file content) is the fallback for the cases where the overlay
path cannot be used: misaligned `MAP_FIXED`, `MAP_PRIVATE` file-backed
mappings, and any time the host slab cannot accept a fresh overlay at
the requested VA.

`MAP_SHARED|MAP_ANONYMOUS` is promoted before fork to a memfd-style
overlay (`mmap_fork_prepare_anon_shared`) and reattached in the child
via `SCM_RIGHTS` (`mmap_fork_restore_overlays`), so cross-fork shared
anonymous memory stays coherent. Both promotion and overlay are
disabled for Rosetta because HVF caches host VA-to-PA at `hv_vm_map`
time. Validation: `tests/test-msync.c`,
`tests/test-cross-fork-mapshared.c`.

## Threads And Futexes

Guest threads map 1:1 to host pthreads. Each guest thread owns one vCPU and
shares the same guest address space. HVF supports multiple vCPUs per VM,
each bound to the host thread that created it; multiple vCPUs share guest
physical memory via `hv_vm_map()`. Up to `MAX_THREADS = 64` guest threads
are supported per VM.

### Thread Table

`src/runtime/thread.c` and `thread.h`:

- `thread_entry_t` per thread holds the vCPU handle plus its explicit validity,
  host pthread, per-thread signal mask, `clear_child_tid` (for
  `CLONE_CHILD_CLEARTID`), and the thread's `SP_EL1` exception stack.
- `_Thread_local current_thread` gives O(1) access from syscall handlers.
- Each thread receives a 4 KiB EL1 exception stack carved out of the shim
  data region.

### Futex

`src/runtime/futex.c` implements:

- The classic ops: `FUTEX_WAIT`, `FUTEX_WAKE`, `FUTEX_WAIT_BITSET`,
  `FUTEX_WAKE_BITSET`, `FUTEX_REQUEUE`, `FUTEX_CMP_REQUEUE`, `FUTEX_WAKE_OP`.
- A subset of priority-inheritance ops: `FUTEX_LOCK_PI`, `FUTEX_UNLOCK_PI`,
  `FUTEX_TRYLOCK_PI`. Priority semantics are not actually inherited -- the
  ops behave as ordinary mutex acquire/release, which is enough for glibc
  and musl to make forward progress.
- `futex_waitv` (syscall 449) for batch waits across up to 128 futex
  addresses.
- Robust-list cleanup: `set_robust_list` / `get_robust_list` are wired up
  in `src/syscall/syscall.c`, and `robust_list_walk()` releases owned
  futexes on thread exit, marking them `FUTEX_OWNER_DIED`.

Wait queues live in a hash table keyed by guest virtual address, with a
per-bucket mutex. Each waiter has its own condition variable for precise
wakeup. Thread exit calls `futex_wake_one()` on `clear_child_tid`, which is
how `pthread_join()` waits via the TID address.

Atomicity: the bucket mutex is held across the futex word read and the
waiter enqueue, so the compare-and-wait is a single critical section.

### Lock Map

| Resource | Lock | File |
|----------|------|------|
| `mmap`/`brk` allocators + page tables | `mmap_lock` (order 1) | `src/syscall/mem.c` |
| FD table | `fd_lock` (order 3) | `src/syscall/fdtable.c` |
| Special FDs (timerfd, eventfd, signalfd) | `sfd_lock` (order 5a) | `src/syscall/fd.c` |
| Thread table | `pthread_mutex` | `src/runtime/thread.c` |
| Futex wait queues | `pthread_mutex` (per bucket) | `src/runtime/futex.c` |
| FUSE (sessions, file/dir state) | global `fuse_lock` + per-session `session->lock` | `src/syscall/fuse.c` |
| Sysroot snapshot | `pthread_mutex` | `src/syscall/proc-state.c` |

Lock ordering is documented inline in those files
(`mmap_lock` is order 1, `fd_lock` is order 3, `sfd_lock` is order 5a)
so callers that need multiple locks acquire them in the right sequence.
See the lock-ordering comment block in `src/syscall/internal.h` for the
authoritative list.

Page-table consistency is preserved by the `mmap_lock` plus TLB broadcasts
via `TLBI VMALLE1IS` from any vCPU; hardware coherency is verified by
`tests/test-multi-vcpu`.

### Thread Group Exit

`exit_group` sets a global `exit_group_requested` flag, calls
`thread_for_each(thread_force_exit_cb)` which invokes `hv_vcpus_exit()` on
all worker vCPUs to break them out of `hv_vcpu_run()`, and joins worker
threads with a timeout so `CLEARTID` cleanup can complete.

### Not Implemented

- True priority inheritance for the PI futex ops. The ops are wired up but
  behave as ordinary mutexes; this matches what glibc and musl need for
  forward progress, not real RT scheduling.
- CPU affinity (`sched_setaffinity`) returns the all-CPUs mask.

## Fork, Clone, And `execve`

macOS HVF allows only one VM per process, so process-style `fork` cannot
clone the live VM. `elfuse` implements it through `posix_spawn` plus IPC
state transfer:

1. Parent creates a `socketpair(AF_UNIX, SOCK_STREAM)`.
2. Parent `posix_spawn`s a new `elfuse --fork-child <fd>` process.
3. Parent serializes VM state over IPC (see paths below).
4. Child receives state, creates its own VM, restores registers directly
   into EL0 (bypassing the shim `_start` so callee-saved GPRs survive), and
   enters the vCPU loop with `X0 = 0` (the child return from `clone`).
5. Before spawning, the parent allocates a namespace-wide guest PID and
   reserves both a local process-table slot and shared lifecycle entry. After
   IPC succeeds it commits the child's host PID, releases the child into guest
   code, and returns the child PID. Allocation or admission failure returns
   `EAGAIN` without allowing an untracked child to run.

### Process Lifecycle And Guest PID 1

The first guest process in an elfuse invocation has guest PID 1 and therefore
becomes the fallback parent for orphaned descendants when no living child
subreaper is closer. elfuse does not insert a hidden init process and does not
automatically discard an adopted child's exit status merely because its new
parent is PID 1. As on Linux, the new parent must consume that status with a
`wait*()` call, or explicitly select no-zombie semantics with
`SIGCHLD = SIG_IGN` or `SA_NOCLDWAIT`.

The invocation-scoped lifecycle registry keeps the Linux wait-format terminal
status (including signal and core-dump bits) and the exiting process's resource
usage until the new parent consumes it. A parent already blocked in `wait*()`
periodically imports newly adopted descendants; adoption of an already exited
child also sends `SIGCHLD` to wake the adopter. Both the per-process wait table
and the invocation-wide lifecycle registry grow geometrically with the actual
fork-family population; the on-disk registry serializes only its live records.
An empty newly created registry is initialized on first use; a nonempty record
set that cannot be read or validated fails closed instead of being overwritten
as empty. Fork admission is reserved before the host helper starts, so
allocation or registry failure fails the new fork instead of silently dropping
a waitable child. Pre-spawn registry reservations are not imported as adopted
children, and a matching local reserved slot remains authoritative through the
registry-publish/local-commit window.

An application runtime used directly as guest PID 1 may not perform that
reaper role. In that case, adopted terminal statuses remain in elfuse's
invocation-scoped lifecycle registry, and a direct macOS child of the PID 1
elfuse process may also remain a host zombie until the guest waits, changes its
SIGCHLD disposition, or exits. Guest waitability and host-process cleanup are
separate concerns: a future host-only reaper could collect the macOS process
while retaining its exit status for a later guest wait, but no such background
reaper is currently provided.

### CoW Fork Path

When `g->shm_fd >= 0` the guest memory is file-backed (`mkstemp` +
`unlink`, `MAP_SHARED`). Fork takes an APFS `fclonefileat` snapshot of
the backing file and sends the snapshot fd over `SCM_RIGHTS`:

- The snapshot decouples the parent and child: subsequent parent writes
  cannot be observed by the child even before the child remaps. APFS
  copy-on-write keeps the snapshot cheap.
- Parent stays on `MAP_SHARED` and does NOT remap -- HVF caches the host
  VA->PA mapping from `hv_vm_map`, and a `MAP_FIXED` remap does not
  update Stage-2, so a remapping parent would observe stale pages.
- Child maps the snapshot fd `MAP_PRIVATE`, producing an instant CoW
  clone with zero data copy.
- The IPC header sets `has_shm = 1` and `num_regions = 0`, skipping memory
  serialization entirely.
- Child calls `guest_init_from_shm()` instead of `guest_init()`, and must
  restore `g->ttbr0` from the IPC header -- `guest_init_from_shm` zeroes
  the struct, and without `ttbr0` page-table walks fail for all high VAs.
- `MAP_SHARED|MAP_ANONYMOUS` regions are promoted to a memfd-style
  overlay before fork (`mmap_fork_prepare_anon_shared`) and reattached in
  the child via SCM_RIGHTS (`mmap_fork_restore_overlays`) so cross-fork
  shared-memory coherence is preserved.

This path is roughly 50x faster than the legacy IPC copy path on large
guest memories.

The CoW path is disabled when hosting Rosetta because HVF caches the host
VA->PA mapping from `hv_vm_map`, and Rosetta's translated code touches
the parent's slab in ways the snapshot model cannot intercept. Rosetta
forks fall back to the legacy IPC copy path.

macOS rejects `MAP_PRIVATE` on `shm_open` fds (`EINVAL`), so the backing
file is created via `mkstemp` + `unlink`.

### Legacy IPC Copy Path

When `g->shm_fd < 0`, the parent serializes used memory regions in 1 MiB
chunks over the socket pair, the child calls `guest_init()` and receives the
data into fresh guest memory. CLOEXEC semantics follow POSIX: all FDs
(including those marked CLOEXEC) are inherited across `fork`. CLOEXEC takes
effect at `execve` (see `src/syscall/exec.c` step 4).

### `clone(CLONE_VM)`

`sys_clone_vm()` in `src/runtime/forkipc.c` handles `CLONE_VM` without
`CLONE_THREAD`. Unlike `sys_clone_thread()`, VM-clone children are waitable
via `wait4` and have exit semantics (`exit_signal`, `vm_exit_status`).
Unlike the `posix_spawn` fork path, they share the same `guest_t*`, the
same guest memory, and the same page tables.

### `clone(CLONE_THREAD)`

In `src/runtime/forkipc.c`:

1. `hv_vcpu_create()` and per-thread `SP_EL1` allocation.
2. Set the child SP, `TPIDR_EL0` (TLS), and copy the parent's signal mask.
3. `pthread_create()` running `vcpu_run_loop()` for the child vCPU.
4. Return the child TID to the parent; the child runs with `X0 = 0`.

### `execve`

`sys_execve` in `src/syscall/exec.c` reloads the ELF, resolves the dynamic
interpreter for dynamically-linked targets through `path_translate_at()`
like any other guest path, rebuilds page tables,
and restarts the vCPU. Signal handlers are reset to `SIG_DFL` per POSIX:
`SIG_IGN` stays `SIG_IGN`, and pending and blocked masks are preserved.
This happens in `signal_reset_for_exec()` after `guest_reset`.

## Signals

Signals are fully implemented in `src/syscall/signal.c`. The signal frame
matches Linux `arch/arm64/kernel/signal.c:setup_rt_frame()` so the C
library's `__restore_rt → rt_sigreturn` (syscall 139) restores state
correctly. Both musl and glibc use this mechanism.

Key points:

- `signal_deliver()` builds `linux_rt_sigframe_t` on the guest stack,
  redirects the vCPU PC to the handler, and sets `X0 = signum`,
  `X30 = sa_restorer`.
- `signal_rt_sigreturn()` restores all 31 GPRs, `SP`, `PC`, and `PSTATE`
  from the frame.
- SIGPIPE is queued automatically when `write`, `writev`, or `pwrite64`
  returns `EPIPE`.
- Guest `ITIMER_REAL` is emulated internally rather than being forwarded to
  host `setitimer`, because macOS shares `alarm()` and
  `setitimer(ITIMER_REAL)` as a single timer, and `elfuse` already needs
  `alarm()` for its per-iteration vCPU watchdog.
- `signal_check_timer()` is called from the vCPU loop after each syscall.
- After `SYSCALL_EXEC_HAPPENED`, the vCPU loop verifies that `ELR_EL1` is
  non-zero -- a defensive check against HVF register-sync bugs.
- Each `thread_entry_t` carries its own `blocked` mask. `rt_sigprocmask`
  operates on `current_thread->blocked`, and child threads inherit the
  parent's mask at clone time.

## Ptrace And `clone(CLONE_VM)` Tracing

`clone(CLONE_VM)` produces an inferior that shares guest memory; the tracer
attaches via `PTRACE_SEIZE`. `BRK` instructions trigger ptrace-stops, after
which the tracer reads and writes registers through the snapshot protocol.

### Operations

In `src/syscall/proc.c`:

- `PTRACE_SEIZE` -- attach without stopping; sets `ptraced = 1`.
- `PTRACE_CONT` -- resume the stopped tracee, optionally injecting a signal.
- `PTRACE_INTERRUPT` -- force the tracee into ptrace-stop via
  `hv_vcpus_exit()`.
- `PTRACE_GETREGSET` / `PTRACE_SETREGSET` (`NT_PRSTATUS`) -- read or write
  the tracee's register snapshot. Writes are applied on resume.

### Snapshot Protocol

Cross-thread HVF register access is unreliable, so every actor uses a
snapshot:

1. Tracee snapshots its own vCPU registers into `ptrace_regs` before
   entering ptrace-stop.
2. `ptrace_stopped = 1` and the tracer is signaled via `ptrace_cond`.
3. Tracer reads and writes the snapshot via `GETREGSET` / `SETREGSET`.
4. Tracer issues `PTRACE_CONT`; the tracee clears `ptrace_stopped` and is
   signaled via `resume_cond`.
5. Tracee applies any dirty register changes back to the vCPU and resumes.

### `BRK` Flow

1. Guest executes `BRK` → shim forwards via HVC #10.
2. If `current_thread->ptraced`, the tracee calls
   `thread_ptrace_stop(SIGTRAP)`.
3. Snapshot, broadcast, wait, resume as above.
4. `wait4` returns `WIFSTOPPED(status)` with `WSTOPSIG == SIGTRAP` to the
   tracer.

### `wait4` Integration

`sys_wait4()` first checks for ptraced or VM-clone children via
`thread_ptrace_wait()` before falling through to the process table for
regular `fork` children, so ptrace-stops and VM-exit states are reported
without racing the regular wait path.

## Guest-Internal FUSE

`src/syscall/fuse.c` implements `/dev/fuse`, `mount(..., "fuse", ...)`,
and the minimal VFS dispatch entirely inside the guest VM. Guest libfuse
programs (sshfs, ntfs-3g, AppImage runtimes) run without macFUSE,
FUSE-T, or FSKit on the host.

Key shape:

- A global `fuse_lock` plus per-session locks. Sessions are refcounted,
  so in-flight reads and writes pin the lock against daemon exit.
- Per-fd alias bindings for `dup`, `dup3`, and `fcntl(F_DUPFD)`.
- Per-file `io_in_progress` plus `io_cond` serializes `read` and
  `getdents64` against the offset field (matching Linux `f_pos_lock`).
  `lseek` waits on `io_in_progress`; `pread` skips it.
- Synchronous `FUSE_INIT` in `sys_mount`; negative `hdr.error`
  propagates back. Mount tombstones on daemon death and surfaces
  `-ENOTCONN`.
- `O_PATH` support, NAME_MAX-bounded `getdents64`, 8 MiB
  `FUSE_FRAME_CAP` on daemon writes, and procfs integration
  (`/proc/{mounts,filesystems,self/mountinfo}`).
- `fuse_materialize_path` so `execve` can load FUSE-backed binaries.
- The wait path honors `SA_RESTART` and ignored signals via the
  `signal_pending_interruption(restart_out)` helper.

Validation lives in `make test-fuse-alpine`, which exercises
`/dev/fuse` plus `mount("fuse")` against the staged Alpine musl
sysroot fixture.

## procfs And Device Emulation

`src/runtime/procemu.c` intercepts a focused set of guest-visible paths
under `/proc`, `/dev`, and a few Linux-expected compatibility files:

- Many procfs files are synthesized from host-side runtime state.
- `/proc/self/*` is backed by internal region, FD-table, and process data.
- Synthetic proc directories support common traversal patterns used by
  BusyBox `ps`, `uptime`, and `top`.
- Guest cwd handling preserves a virtual `/proc` working directory even
  though the host operates on synthetic backing directories.

### Reported Kernel Identity

Two surfaces tell the guest which kernel it is running on: `uname(2)`, served
from a static `linux_utsname_t` in `src/syscall/sys.c`, and `/proc/version`,
emitted as a literal by `src/runtime/procemu.c`. Both spell the release
through `GUEST_KERNEL_RELEASE` and `GUEST_KERNEL_VERSION` in
`src/syscall/sys.h`, so the two cannot disagree; `tests/test-proc.c` asserts
that the release `uname` reports appears in the `/proc/version` banner.

The reported release is `6.18.0`, the 6.18 LTS baseline; it tracks no test
image. `elfuse` emits no `/proc/sys/kernel/osrelease`, so glibc's
`dl_discover_osversion` falls back to `uname(2)` and reads this value at
every dynamic startup. It refuses a kernel only when the release is below its
build-time floor, so a high baseline is the safe side.

The release feeds version-gated feature detection. `src/syscall/dispatch.tbl`
is the implemented set with two exceptions: `pidfd_getfd` and `userfaultfd`
are registered there, but their handlers in `src/syscall/syscall.c` return
`-ENOSYS`, and `tests/test-pidfd.c` and `tests/test-userfaultfd.c` pin them
at that stub. Anything absent from the table gets `-ENOSYS` from the dispatch
default, whatever number `uname` prints. Calls a 6.18 kernel provides that
are absent: `io_uring_*`, `mseal`, `cachestat`, `process_madvise`,
`listmount`/`statmount`, `landlock_*`, and `file_getattr`/`file_setattr`.
Guests probe for a syscall and handle `ENOSYS`.

The `LINUX_2.6.39` tag in the synthetic vDSO (`src/core/vdso.c`) is the
frozen ELF symbol-version name the real arm64 vDSO exports; a genuine 6.18
kernel emits it too.

Three things read the release automatically. `tests/test-proc.c` runs on both
the elfuse and the qemu aarch64 lane and checks only that the banner and
`uname` agree, so on the qemu lane it pins the real Alpine kernel to itself.
`tests/test-comprehensive.c` asserts the release is at least 6.18 behind a
`uts.nodename == "elfuse"` gate, which holds on the elfuse lanes and not on
the qemu lane, whose initramfs hostname is `elfuse-qemu`. The third reader is
silent: `build/bench-hot-guard-glibc` is the one aarch64 glibc binary in
`make check`, built only when the cross-toolchain sysroot is present, and a
release below glibc's floor would abort its startup rather than fail an
assertion. The Alpine tree `tests/fetch-fixtures.sh` builds is musl
throughout and does no version gating.

`/proc/self/smaps` and `/proc/<pid>/smaps` are generated from the same tracked
VMA list as `/proc/self/maps`. The complete field set currently emitted for
each VMA is the maps header followed by these 24 fields, in this order:

```text
Size, KernelPageSize, MMUPageSize, Rss, Pss, Pss_Dirty,
Shared_Clean, Shared_Dirty, Private_Clean, Private_Dirty, Referenced,
Anonymous, KSM, LazyFree, AnonHugePages, ShmemPmdMapped, FilePmdMapped,
Shared_Hugetlb, Private_Hugetlb, Swap, SwapPss, Locked, THPeligible,
VmFlags
```

`Size` is the VMA length in KiB. `KernelPageSize` and `MMUPageSize` are
reported as 4 KiB. In a fork child, writable private anonymous VMAs that
existed in the parent's CoW snapshot report their full VMA size for
`Shared_Dirty`, `Rss`, `Pss`, and `Pss_Dirty`, keeping those coarse counters
internally consistent. Newly-created VMAs are excluded from that signal. Every
other numeric counter, including `THPeligible`, is emitted as a stable zero.
`ProtectionKey` (a Linux pkeys field added in Linux 4.9) is intentionally
omitted because the macOS host has no equivalent; consumers comparing against a
real Linux kernel should treat it as optional. `VmFlags` is evidence-based and
contains only the permission/sharing flags represented by the tracked VMA
(`rd`, `wr`, `ex`, `sh`, and `nr` when applicable); no untracked kernel flags
are invented. A VMA with no such evidence (for example `PROT_NONE`) still
prints the field's separating space as `VmFlags: `.
These are coarse VMA-level values, not host page-residency, dirty-bit, or
proportional-sharing accounting, so they are suitable for fork-safety checks
but not precise memory profiling. The fork-child marker is tracked per VMA, so
writable private anonymous mappings created after fork are excluded from the
compatibility signal. `smaps_rollup` is not implemented.

Synthetic proc directories have explicit snapshot boundaries. The backing
trees reached by opening `/proc` or `/proc/self` are materialized once, on the
first access, and their initial `stat`, `status`, `cmdline`, `maps`, and `smaps`
files remain fixed for the process lifetime. An absolute open of one of those
proc paths is intercepted directly and generates fresh content; opening the
same name through an already-open synthetic directory reads that directory's
snapshot. `/proc/self/fd` and `/proc/self/fdinfo` are rebuilt into an
independent scratch directory on every open, so each directory fd sees the
guest-fd table as it existed at that open and concurrent enumerations cannot
mutate one another. `/proc/self/task` is repopulated from the current thread
set whenever the directory is opened. These boundaries are intentional: a
directory stream is stable while it is being read, while dynamic task and fd
listings refresh only when a new directory is opened. The synthetic
`/sys/devices/system/cpu` tree follows the one-shot rule: its CPU count,
cpumask files, and `cpuN` directories are captured on first access and then
remain fixed.

Related implementation: `src/runtime/procemu.c`, `src/syscall/path.c`,
`src/syscall/fs.c`, `src/syscall/proc-state.c`.

## Path Resolution

A guest names files the way Linux does, from a namespace rooted at the guest's
`/`. The host has its own root, and with `--sysroot` the guest's tree is a
subdirectory of it. Every path-taking syscall therefore asks two questions
before it can act, and `path_translate_at()` in `src/syscall/path.c` answers
both in one place so no two syscalls can answer them differently for the same
name:

1. Does the sysroot claim this path? A path it holds resolves there; one it
   does not falls back to the host filesystem, except for the guest system
   directories and the temp roots, which resolve in the sysroot whether or not
   it holds them.
2. What host spelling does it get? That is the sysroot prefix plus the guest
   path, adjusted so the host kernel's own resolution lands where Linux's
   would.

Three resolvers in `src/syscall/proc-state.c` do the work:
`proc_resolve_sysroot_path()` for a following lookup, its
`_nofollow_` sibling, and `proc_resolve_sysroot_create_path()` for a path whose
final component may not exist yet. `path_translate_at()` picks one by flags;
`sys_path_has_symlink()` calls the nofollow form directly for absolute paths
in the `openat2(RESOLVE_NO_SYMLINKS)` precheck described below, and walks
relative paths from their descriptor with the same clamp applied in the walk.

### Clamping `..` At The Guest Root

A guest resolves `..` against its own root, and Linux clamps it there: `/..`
names `/`, and no number of `..` components reaches the directory above
(`path_resolution(7)`). The sysroot is an ordinary directory on the host, so
the host kernel has somewhere to go, and a guest path handed over unchanged
climbs straight out of the tree.

`clamp_dotdot_at_guest_root()` rewrites exactly the components that would do
that, and nothing else:

| guest path | host spelling below the sysroot | why |
|---|---|---|
| `/..`, `/../..` | `/` | the clamp, applied once per escaping component |
| `/../etc/hosts` | `/etc/hosts` | the escaping `..` is dropped, the rest is untouched |
| `/a/../b` | `/a/../b` | interior, so the host resolves it |
| `/a/../../etc/x` | `/a/../etc/x` | one `..` is interior, the second escapes |
| `/file/.`, `/file/` | unchanged | the trailing form still demands a directory |

Interior `..` survives on purpose. Collapsing it would spell a path whose
popped components the host never looks at, and their existence and type are
part of the answer Linux owes: `/absent/../b` is `ENOENT`, `/file/../b` is
`ENOTDIR`, `rmdir("/a/b/..")` fails rather than removing `/a`, and a `..` past
a symlink keeps that link in the path where the no-symlinks precheck can see
it. Only the host walk can report those, so only the host walk decides them.

Two spellings of a path therefore travel together: the clamped one, which is
probed and handed to the syscall, and the fully collapsed one from
`lexical_normalize_absolute_path()`, which is used solely to classify the path
as a guest system directory or a temp root, where `/usr/../home/x` must be
judged as `/home/x` rather than by its leading component.

### Relative Paths And The Containment Recheck

The resolvers key off a leading `/`, so a relative path reaches them
unchanged: they have no dirfd to rebuild a location from. That would leave
`openat(dirfd, name)` to the host kernel, whose resolution is not confined to
the sysroot, so `path_check_relative_sysroot_containment()` reconstructs the
absolute guest path from the descriptor's guest base path and runs it back
through the same resolver.

A reconstructed path that climbs above the guest root needs more than a
verdict. Clamping makes the guest's own answer well defined, but the host
still holds a descriptor from which `..` leads out of the sysroot, and the
recheck cannot express "contained, but not by that route": a path the sysroot
does not claim looks the same as one that never left. So when the
reconstruction clamps, the recheck hands back the absolute host path it
resolved and the caller uses that instead of the guest's relative spelling.
POSIX has the kernel ignore `dirfd` for an absolute path, so the descriptor
drops out of the resolution entirely, which is the point.

A climbed path is the one case where the recheck's answer is the resolution
itself rather than a discarded verdict, so it also honors the caller's create
intent: missing sysroot parents are materialized exactly as they would be for
the absolute spelling.

### Why The No-Symlinks Precheck Has No Component Budget

`openat2(RESOLVE_NO_SYMLINKS)` must fail with `ELOOP` if any component of the
path is a symlink. macOS has no equivalent flag, so `sys_path_has_symlink()`
walks the path itself, one component at a time, and reports `ELOOP` at the
first `S_ISLNK`.

An absolute path is walked in its host spelling, which the resolvers have
already clamped. A dirfd-relative path is walked from the descriptor, so the
clamp happens in the walk: the descriptor's guest depth seeds a counter, and a
`..` that would climb above the guest root stays in place instead of stepping
onto the sysroot's host parent, whose entries, macOS's own symlinks among
them, are not the guest's to trip over.

That walk deliberately carries no `MAXSYMLINKS` counter. It never follows a
link, so nothing can accumulate against a link budget; the only thing a
per-component counter could reject is a link-free path deeper than the limit,
which Linux resolves without complaint, since `path_resolution(7)` caps links
followed rather than components walked. The counter that does matter lives in
`path_openat2_crosses_mount()`, which follows links to answer
`RESOLVE_NO_XDEV` and charges `MAXSYMLINKS` once per link actually crossed.

Related implementation: `src/syscall/path.c` (`path_translate_at`,
`path_check_relative_sysroot_containment`, `sys_path_has_symlink`,
`path_openat2_crosses_mount`), `src/syscall/proc-state.c`
(`clamp_dotdot_at_guest_root`, `sysroot_seed_host_path`, the three resolvers).
Validation: `make test-sysroot-dotdot` and `make test-sysroot-openat2-walk`,
plus the `openat2` cases in `tests/test-syscall-fidelity.c`, which
`make test-matrix` runs against both `elfuse` and a reference kernel.

## POSIX Shared Memory (`/dev/shm`)

Linux exposes POSIX shared memory through `/dev/shm`, a tmpfs the C library
opens by name: `shm_open("/foo", ...)` opens `/dev/shm/foo`. macOS has no
`/dev/shm`, so `elfuse` backs it with a per-UID host directory,
`/tmp/elfuse-shm-<uid>/<name>`. `dev_shm_resolve_path()` in
`src/runtime/procemu.c` (exported as `proc_dev_shm_resolve`) is the single
source of truth for that mapping and gates the name. This is a different
mechanism from System V shared memory (`shmget`/`shmat`), which lives in
`src/syscall/sysvipc.c`.

### One Redirect, One Resolution

Every path syscall resolves guest paths through `path_translate_at()` in
`src/syscall/path.c`. For a `/dev/shm/<leaf>` path it rewrites `host_path` into
the backing directory and records the fact in `tx->is_dev_shm`. If each syscall
applied the redirect on its own, any that missed it would fall through to the
sysroot while its peers used the backing directory, so `/dev/shm/foo` would
resolve two ways for the same program:

```
/dev/shm/foo
  open  -> /tmp/elfuse-shm-<uid>/foo   (backing dir, created)
  chmod -> <sysroot>/dev/shm/foo       (absent -> ENOENT)
```

Resolving in `path_translate_at` instead means `chmod`, `chown`, `truncate`,
`utimensat`, `rename`, `link`, `symlink`, `mknod`, `readlink`, `mkdir`,
`statfs`, and the xattr calls all inherit the backing path from one place, so an
`open` followed by any of them on the same name stays consistent.

The early return also takes shm objects out of sysroot resolution entirely, so
the `/tmp/elfuse-shm-<uid>` backing directory is reached as a host path and is
unaffected by the sysroot's redirect of guest `/tmp`.

Only a non-empty flat leaf is redirected. Bare `/dev/shm` and `/dev/shm/` stay
on the sysroot path so the synthetic-directory intercepts keep answering for
them, and `statfs` on a shm leaf or on `/dev/shm` reports `TMPFS_MAGIC`
synthetically rather than the host filesystem's type. Because the backing path
is absolute, two inline helpers in `src/syscall/path.h` adapt the `*at()` calls:
`path_translation_dirfd()` returns `AT_FDCWD` (POSIX ignores `dirfd` for an
absolute path), and `path_translation_at_flags()` forces the nofollow flag
described next.

### The Never-Follow Invariant

On Linux `/dev/shm` is an in-namespace tmpfs, so a symlink planted at a shm leaf
resolves inside that namespace. `elfuse`'s backing store is a plain host
directory, so the same symlink would resolve onto the host filesystem, which is
a sandbox escape. A symlink leaf is never legitimate anyway: glibc's `shm_open`
(`sysdeps/posix/shm_open.c`) opens objects with `O_NOFOLLOW`. So every shm
operation acts on the leaf itself, never the target it points at. Because the
resolver hands back an absolute host path that bypasses the sysroot, that duty
is spread across the syscall families, one mechanism each:

| Operation family | Never-follow mechanism |
|------------------|------------------------|
| `*at()` metadata (chmod, chown, stat, utimensat, access) | `path_translation_at_flags()` adds `AT_SYMLINK_NOFOLLOW` |
| open for truncate/chdir | `shm_open_leaf()` opens `O_NOFOLLOW` |
| proc open | `O_NOFOLLOW` |
| xattr get/set/list/remove | `XATTR_NOFOLLOW` |
| stat | `lstat`, not `stat` |
| linkat | clears `AT_SYMLINK_FOLLOW` |
| statfs | nofollow `lstat` existence probe, then a synthetic reply |

The name gate lives with the resolver. A POSIX shm name is always a single flat
component: glibc's `__shm_get_name` (`posix/shm-directory.c`) strips the leading
slash and rejects an empty name or any embedded `/` with `EINVAL`.
`dev_shm_resolve_path()` enforces the same shape, additionally rejects the `..`
component (a flat name like `a..b` is fine), and returns `EACCES` for a
rejected name (`ENAMETOOLONG` if the backing path overflows).

Related implementation: `src/runtime/procemu.c` (`dev_shm_resolve_path`),
`src/syscall/path.c` and `path.h` (`path_translate_at`, `is_dev_shm`,
`path_translation_dirfd`, `path_translation_at_flags`), and the metadata
handlers in `src/syscall/fs.c`, `fs-stat.c`, and `fs-xattr.c`. Validation:
`tests/test-dev-shm-paths.c`.

## Dynamic Linking

`elfuse` supports dynamically linked aarch64-linux ELF binaries via
`--sysroot`:

```sh
elfuse --sysroot /path/to/sysroot ./my-dynamic-program
```

How it works:

1. `elf_load()` parses `PT_INTERP` to find the interpreter path
   (`/lib/ld-linux-aarch64.so.1` for glibc, `/lib/ld-musl-aarch64.so.1` for
   musl).
2. The interpreter is loaded as `ET_DYN` at `g->interp_base` (computed
   dynamically: 60 GiB for 36-bit IPA, 1020 GiB for 40-bit IPA).
3. `build_linux_stack()` passes `AT_BASE` (interpreter load address) and
   `AT_EXECFN` (the execve filename, supplied by the caller) in the auxiliary
   vector. Linux takes `AT_EXECFN` from `bprm->filename`, so it stays the
   program the guest asked for even when `argv[0]` is an alternate name or the
   rosetta binfmt_misc argv prepends the translator.
4. The entry point becomes `interp_entry + load_base`; the dynamic linker
   takes over from there.
5. Guest absolute paths reach the host through `path_translate_at()`
   (`src/syscall/path.c`), the single forward resolver every path-taking
   handler uses; with `--sysroot` set it dispatches each path between the
   sysroot and the host on existence. The temp roots (`/tmp`, `/var/tmp`, any
   `.ccache` directory) and the guest system directories are exempt from that
   dispatch and resolve in the sysroot either way, so lookup and removal cannot
   disagree about where a path lives. [filenames.md](filenames.md) covers how
   a name is spelled once it lands on the sysroot volume.

The sysroot is inherited by fork children via IPC state transfer.
`sys_execve` also loads the interpreter for dynamically linked targets, so
tools that `execve` dynamic children (`env`, `nice`, `nohup`) work
correctly. The two loaders resolve `PT_INTERP` in different orders.
Guest-issued execs route it through `path_translate_at()` like any other
guest path. The initial process is loaded by the core bootstrap
(`load_interpreter()` in `src/core/bootstrap.c`), which probes
`elf_resolve_interp()` (`src/core/elf.c`) first, a literal sysroot
concatenation plus a `/lib/<basename>` fallback, and only when both
probes miss does it fall through to `path_translate_at()`, materializing
a FUSE interpreter and refusing one in `/dev/shm`.

### Known Limitations

None specific to the aarch64-linux dynamic-linker path. Limitations in guest
path handling are covered by [filenames.md](filenames.md), which records what
the sysroot volume can and cannot represent.

## x86_64-via-Apple-Rosetta

`src/core/rosetta.c` hosts Apple's Rosetta Linux translator inside the
same VM that runs aarch64 guests, so statically linked x86_64-linux ELFs
execute through a translator the host process owns rather than an
external translation service. The guest architecture is auto-detected
from the ELF header; opt out via `--no-rosetta` or `ELFUSE_NO_ROSETTA=1`.

Address-space layout:

- The translator lives in the primary buffer at a low guest physical
  address but is mapped at its link address `0x800000000000` via a
  non-identity page-table entry. This works around the 36-bit Stage-2
  IPA cap on M1 / M2.
- A 256 MiB kernel buffer (kbuf) at `g->kbuf_gpa` is aliased at
  `KBUF_VA_BASE = 0xFFFFFFFFF0000000` under TTBR1 and at
  `KBUF_USER_VA = KBUF_VA_BASE & 0x0000FFFFFFFFFFFF` under TTBR0, so
  Rosetta's TaggedPointer extraction resolves both views to the same
  physical pages. The kbuf is always RW; nothing executable is
  installed there.
- M5 hosts bisect the primary slab from 1 TiB to 256 GiB or 64 GiB on
  `hv_vm_map` failure while keeping the IPA width at 48 so the high-VA
  Stage-2 entries remain reachable.

Runtime integration:

- The VZ ioctls (`CHECK 0x80456125`, `CAPS 0x80806123`,
  `ACTIVATE 0x6124`) are trapped when `g->is_rosetta` is set.
- `/proc/self/exe` is redirected to `ROSETTA_PATH` (the binfmt-misc
  convention Rosetta expects).
- The `rosettad` SCM_RIGHTS bridge implements an SHA-256-keyed AOT cache
  under `$HOME/.cache/elfuse-rosettad/`. First launch warms the cache;
  subsequent launches reuse translations.

Fork interaction: the CoW shm fast path is disabled for Rosetta because
HVF caches host VA-to-PA at `hv_vm_map` time. Rosetta forks use the
legacy IPC copy path.

Dynamic linking under Rosetta is supported. For x86_64 guests with a
`PT_INTERP` header, elfuse does not load the ELF segments or the
interpreter from the host side; `bootstrap_prepare` deliberately skips
the aarch64 loader path (`src/core/bootstrap.c:415-462`) and instead
hands control to Rosetta. The translator then opens the guest ELF
through Linux syscalls, reads `PT_INTERP`, and `mmap`s
`/lib64/ld-linux-x86-64.so.2` (or the musl equivalent) from the
sysroot. The translated dynamic linker loads shared libraries via the
same path. Coverage lives in `tests/test-rosetta-glibc.sh`, which
exercises direct loader bring-up, explicit `ld.so` invocation,
`ld.so --list`, runtime `dlopen`, initial-exec TLS, general-dynamic
TLS via `dlopen`, and per-pthread TLS.

Boundaries:

- `--gdb` is rejected because the stub serves the aarch64 view Rosetta
  produces, not the original x86_64 architectural state.
- Two Rosetta-internal divergences are tracked in the acceptance audit
  rather than papered over: `SA_RESETHAND` is shadowed by Rosetta's own
  signal-handler state, and `clone(..., CLONE_SETTLS, tls=0, ...)` can
  hang.

## GDB Stub

`src/debug/` is split by role:

- `gdbstub.c` -- session lifecycle, stop/resume flow, packet dispatch
- `gdbstub-rsp.c` -- RSP packet transport and hex helpers
- `gdbstub-reg.c` -- register snapshot layout, restore flow, `target.xml`

The stub runs in all-stop mode. Because Hypervisor.framework register access
must happen on the owning thread, the stopped vCPU snapshots its own state;
the GDB-handler thread reads and updates the snapshot, and the owning thread
restores the modified state on resume -- the same pattern used by ptrace.

The split mirrors the architectural boundary: transport and encoding are
independent of guest execution; register layout is independent of socket I/O;
stop/resume sequencing remains tightly coupled to process and thread state.

## Language Choice

`elfuse` is C11 plus a small amount of aarch64 assembly. This section records
why, against the specifics of this codebase rather than in the abstract.

### Where The Safety Boundary Falls

The central data structure is a slab of guest memory obtained from `mmap`,
which the guest rewrites at will from another vCPU thread. Host access goes
through bounds-checked accessors over that slab: `guest_ptr`, `guest_ptr_w`,
`guest_ptr_avail`, `guest_ptr_bound`, `guest_read`, and `guest_write` (see
[Memory Layout](#memory-layout)), each resolving a guest-controlled address
against the recorded mappings.

Rust would express the same shape as a safe wrapper over an `unsafe` core,
and would enforce that callers stay on the safe side, which C leaves to
convention. That enforcement is a real gain. What it does not do is validate
the checks inside the wrapper, and those checks are where the defects below
live: the interior of the guest slab, the page-table walk itself, and syscall
arguments arriving as guest-controlled integers.

### What Defects Surface In Practice

One worked example, from the loader. `elf_load_fd` saturates `load_max` to
`UINT64_MAX` when `p_vaddr + p_memsz` overflows (`src/core/elf.c`). For
`ET_EXEC` the saturation does its job: the fits-in-guest check in
`src/syscall/exec.c` sees `UINT64_MAX` and rejects the image. For `ET_DYN`
that check first adds `PIE_LOAD_BASE`, and the sum wraps to `0x3FFFFF`, which
passes. Nothing lands out of bounds, because `elf_map_segments_fd`
bounds-checks every segment against `guest_size`. What moves is the
rejection: it lands at a call site past the `execve` point of no return,
turning a recoverable `-ENOEXEC` into a fatal exec. Guarding it takes an
explicit checked add where `load_max` meets the load base.

The class of defect is the point. That is integer arithmetic, not memory
safety. Rust's `+` wraps silently in release builds too, so the same checked
add is required there.

`elf_map_segments_fd` also re-reads the header and program headers from the
fd, and can disagree with the first parse: a TOCTOU on the ELF image. Its own
bounds checks contain the damage, but no language rules the disagreement out.
It is a property of how the loader is structured.

### Verification Actually In Place

No formal-methods gate exists today. What gates CI is language-independent
tooling: `clang-format`, a banned-API and unsafe-preprocessor scan,
`cppcheck`, and the dispatch-table consistency check on Linux; `scan-build`
as an advisory job; `clang-tidy` advisory except for
`readability-function-size`, which is named in `WarningsAsErrors` and fails
the job when a function crosses its ceiling; an Infer run that fails on any
finding;
and a runtime matrix under ASAN, UBSAN, and TSAN (see [Testing And
Confidence](#testing-and-confidence)).

That catches memory-safety defects after the fact rather than excluding them
by construction, which is the honest cost of the choice. The improvement
worth pursuing on this surface is a proof obligation over the ELF parser
rather than another runtime check, because a guest-triggerable abort inside a
VMM is a denial of service, and a language that panics on bad input does not
address that.

### Host Interface Surface

`hv_vcpu_run`, `hv_vcpu_set_sys_reg`, Mach (`host_statistics64` behind
`/proc/meminfo`), pthreads, macOS syscalls, file descriptor passing over
`SCM_RIGHTS`, and hosting the Apple Rosetta translator are all C ABI. The EL1
shim is aarch64 assembly (`src/core/shim.S`) under any host language. A
safe-language port would spend a significant share of its effort on binding
layers for that surface.

## Testing And Confidence

`elfuse` uses several layers of validation:

- `make check` -- fast guest tests plus the BusyBox applet smoke suite,
  followed by `scripts/check-syscall-coverage.py` so any new
  `dispatch.tbl` entry without a direct or aliased test reference fails
  the build.
- `make test-busybox` -- applet coverage in isolation.
- `make test-fuse-alpine` -- guest-internal FUSE against the Alpine
  musl sysroot fixture.
- `make test-gdbstub` -- debugger integration.
- `make test-rosetta-all` -- the x86_64 acceptance sub-suites
  (CLI gating, failure modes, statics, Alpine pipelines, audit, JIT,
  glibc dynamic).
- `make test-matrix` -- cross-checks elfuse (aarch64), QEMU (aarch64),
  and elfuse (x86_64-via-Rosetta) on overlapping corpora, with per-host
  baselines for the Rosetta branch.

The rule for contributors is simple: match the validation depth to the
subsystem you changed. Procfs, process state, dynamic linking, and
debugging typically warrant more than `make check`. Touching the
Rosetta path additionally requires `make test-rosetta-all` so the
acceptance audit catches new divergences from the documented
Rosetta-internal failures. See [testing.md](testing.md) for the full
target list, per-host baseline scheme, and the validation-by-change-type
table.
