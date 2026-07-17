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
| `src/syscall/sidecar.c` | case-fold sidecar tokens for case-insensitive macOS volumes |
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

- `thread_entry_t` per thread holds the vCPU handle, host pthread, per-thread
  signal mask, `clear_child_tid` (for `CLONE_CHILD_CLEARTID`), and the
  thread's `SP_EL1` exception stack.
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
5. Parent records the child in the process table and returns the child PID.

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

`sys_execve` in `src/syscall/exec.c` reloads the ELF, loads the dynamic
interpreter for dynamically-linked targets via the shared
`elf_resolve_interp()` helper (also used at startup), rebuilds page tables,
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

Related implementation: `src/runtime/procemu.c`, `src/syscall/path.c`,
`src/syscall/fs.c`, `src/syscall/proc-state.c`.

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
   `AT_EXECFN` (`argv[0]`) in the auxiliary vector.
4. The entry point becomes `interp_entry + load_base`; the dynamic linker
   takes over from there.
5. `sys_openat()` redirects guest absolute paths through the sysroot: if
   `--sysroot` is set, it tries `<sysroot>/<path>` first.

The sysroot is inherited by fork children via IPC state transfer.
`sys_execve` also loads the interpreter for dynamically linked targets, so
tools that `execve` dynamic children (`env`, `nice`, `nohup`) work
correctly. `elf_resolve_interp()` in `src/core/elf.c` is shared between
`src/main.c` and `src/syscall/exec.c`.

### Known Limitations

None currently tracked for the aarch64-linux dynamic-linker path.

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
