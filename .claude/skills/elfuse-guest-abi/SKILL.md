---
name: elfuse-guest-abi
description: The elfuse guest/host boundary - HVC calls, the EL1 shim, exception vectors, page tables and W^X, TLBI, the paths that rebuild EL0 state, shim_data, memory layout, fork, and Rosetta hosting. Use when a change alters what the guest observes (registers on return, page permissions, the EL0 return path) whatever directory the file is in, when adding or changing an HVC, or when debugging a guest fault, a stale-TLB bug, or a handler that returns to the wrong PC.
---

# The elfuse guest/host boundary

Everything here is a rule you find out you broke by way of a guest that faults
on its first instruction, or worse, one that runs 99% of the time.

The skill is scoped by concern, not by directory. `src/syscall/mem.c`,
`src/syscall/signal.c`, `src/runtime/forkipc.c`, and `src/runtime/thread.c` all
carry rules from this file even though `elfuse-syscall` owns their host-side
half. If you cannot tell which half you are in, ask whether the guest can
observe the difference in a register, a permission, or a PC.

## Exception vectors: do not clobber GPRs

Vector entry stubs for `svc_handler` MUST NOT write any GPR.

This is the syscall boundary, not a function call: AAPCS64 caller-saved rules
do not apply. Linux SVC #0 restores every register except X0 on return, so
musl and GCC keep live values in X9-X15 across the call. Writing any GPR
before `svc_handler` has saved the frame corrupts the EL0 caller after ERET,
and the damage surfaces later as what looks like a miscompile somewhere else
entirely.

Only `bad_exception` vectors may clobber X5, because they halt.

## HVC protocol

| HVC # | Purpose | Registers |
|-------|---------|-----------|
| #0 | Normal exit | x0 = exit code |
| #2 | Bad exception | x0=ESR, x1=FAR, x2=ELR, x3=SPSR, x5=vector |
| #4 | Set sysreg | x0 = reg ID, x1 = value |
| #5 | Syscall forward | X0-X5=args, X8=nr; on return X8=TLBI kind, X7=ptrace-stop request |
| #6 | Embedder extension | X8=call nr, X0-X7=args |
| #7 | MRS trap | host reads reg from ESR ISS, returns in x0 |
| #9 | W^X toggle | x0=FAR, x1=type (0=exec->RX, 1=write->RW) |
| #10 | BRK from EL0 | SIGTRAP / ptrace-stop |
| #11 | EL0 fault | SIGSEGV / SIGILL |
| #12 | System instruction trap | cache maintenance logging |
| #13 | Ptrace stop | taken after the shim restores the HVC #5 saved frame |

The register contract per HVC, including which return values each one accepts,
is the header comment in `src/core/shim.S`. That comment is the specification;
this table is an index into it.

Changing the protocol is never a one-file change. The shim, the host
dispatcher, the crash and debug paths that decode HVCs, and the documentation
all encode it, and a half-landed change shows up as `CRASH_UNEXPECTED_HVC`
rather than as a compile error.

The guest cannot set sysregs via MSR (HCR_EL2.TSC=1); it must use HVC #4.
DC ZVA is emulated by the shim (HCR_EL2.TDZ=1 traps it): zero 64 bytes at the
cache-line-aligned address in Rt. Startup aborts if DCZID_EL0 does not report
the block size the shim assumes.

## TLBI wire encoding on HVC #5 return

| X8 | Kind | Shim action |
|----|------|-------------|
| 0 | TLBI_NONE | skip flush |
| 1 | TLBI_BROADCAST | TLBI VMALLE1IS + DSB ISH + ISB |
| 2 | drop-frame | host rebuilt EL0 state; discard saved frame on ERET |
| 3 | TLBI_RANGE | loop TLBI VAE1IS, X9=VA, X10=page count |
| 4 | TLBI_RANGE_LARGE | single RVAE1IS, encoded operand in X9 |

X11=1 is the icache-flush hint: set when a page transitions to executable, and
the shim then issues an IC invalidate alongside whichever TLBI it picked. The
shim restores X11 from the saved frame before ERET, so EL0 never observes it.

X7 is the ptrace-stop request on the same return, and it obeys a rule the TLBI
codes do not. The shim reads it only after restoring the saved frame, so the
tracer snapshots the guest's architectural registers rather than shim scratch;
non-zero means take HVC #13 before the ERET. That makes X7 unusable on the one
tail that never restores the frame, X8 = 2, where the live registers already
are the final EL0 state and a host write to X7 would land in EL0 as guest
state. The host takes that stop inline in the epilogue instead and leaves X7
alone, and an `execve` re-entry, which has no tail at all, leaves the stop owed
for the new image.

Two consequences for anyone editing the dispatch in `shim.S`. Every exit from
it has to reach the X7 test, so branch to `svc_hvc_restore_eret`, never to
`svc_restore_eret`: a tail that skips the test drops a stop the host has
already consumed, and the tracer waits forever in `wait4`. And do not put a
numeric label on `svc_restore_eret`, because a `1f` anywhere in the tail would
then reach it and skip the test. Both of these have been live bugs.

The host accumulates the smallest sufficient request in `cpu_tlbi_req`
(`src/core/guest.h`), which is `_Thread_local` per vCPU. Never promote it to a
guest-global: that reintroduces the race where one vCPU's epilogue drains
another's pending request before that vCPU ERETs.

The thresholds that pick between per-page VAE1IS, a single RVAE1IS, and a full
broadcast live next to the accumulator, and the range forms are conditional on
`g_tlbi_range_supported`. `TLBI VAE1IS` retires any 2 MiB block containing the
VA (ARM ARM B2.2.5.6), so `guest_split_block` callers do not need a separate
broadcast.

X8 is not a TLBI channel on every HVC, and the accepted values differ per HVC.
Read `shim.S` before assuming a code means the same thing on the path you are
adding.

A bug that survives most runs and fails under load is usually an accumulator
that asked for too little. `elfuse-debug` has the bisect: forcing the
broadcast fallback tells you whether the request or the caller is wrong.

## Paths that rebuild EL0 state

Three paths hand the guest a register set the guest did not produce: signal
delivery, `rt_sigreturn`, and `execve`. They share one rule and differ only in
how they satisfy it, and picking the wrong mechanism is how a handler ends up
running with the wrong PC, SP, or LR.

The rule: if you rebuild EL0 register state, the shim must not restore the
stale saved frame over it on ERET.

There are two ways to satisfy it, and which one you need depends on whether
your path goes through the dispatch epilogue at all:

- Inside the epilogue, set X8=2. The shim reads it as the drop-frame marker
  and discards the saved GPR frame. Signal delivery on the syscall-return path
  works this way. It does not need the marker when EL0 was preempted rather
  than returning from a syscall, because there is no shim frame to drop.
- Bypass the epilogue by returning `SYSCALL_EXEC_HAPPENED`. The epilogue
  returns early, before it writes X0 or X8. `sys_execve` works this way, and
  the normal X0 writeback is exactly what it needs to avoid. It must also skip
  the X7 write for the same reason it skips X0, which is what
  `syscall_return_epilogue` calls an exec re-entry.
- `signal_rt_sigreturn` does both, because it has restored the entire register
  set and neither the frame restore nor the X0 writeback may happen.

Do not copy an X8=2 into a new exec-like path on the strength of the name.
Work out which of the two situations you are in first. The comment above the
marker write in `src/syscall/signal.c` states which delivery paths consume it
and which do not, and it is the thing to read before adding a third.

The signal frame itself is a compatibility contract, not an internal layout.
It matches the Linux arm64 `setup_rt_frame` so that a libc `__restore_rt`
returning through `rt_sigreturn` restores state; musl and glibc both depend on
it, so a field that is convenient for elfuse but not where Linux puts it
breaks every guest. Its bounds math is proved (`src/proved/sigframe.h`).

## Page tables and W^X

HVF enforces W^X even with SCTLR.WXN=0. Data is RW, code is RX, and there is
no third option.

Tables use 2 MiB blocks. A mixed-permission range needs
`guest_split_block()` (`src/core/guest.c`) to convert the L2 block into a
table descriptor over 512 x 4 KiB L3 pages. `guest_update_perms()`
orchestrates; whole-block changes stay in place. Triggered by `sys_mmap`
MAP_FIXED landing in a differently-permissioned block, and by `sys_mprotect`
on a sub-block range (RELRO is the common one).

The rest of this area follows from one observation: HVF's defaults are not the
architecture's defaults, and guest state set from the host before the vCPU
runs is not the same as guest state set from inside it.

- HVF returns SCTLR as 0, which is not a legal SCTLR. RES1 bits must be set
  explicitly: OR the `SCTLR_RES1` macro (`src/hvutil.h`) with the bits you
  want rather than open-coding a literal.
- The MMU comes on via HVC #4 from the shim. Setting SCTLR.M=1 from the host
  before `hv_vcpu_run()` faults on the first instruction fetch.
- Only the owning vCPU thread touches that vCPU's HVF registers. Cross-thread
  register access is why both ptrace and the GDB stub use a snapshot protocol.
- Name system registers with the `HV_SYS_REG_*` constants. A raw encoding
  compiles and then addresses a different register than the one you meant.

## Memory layout

`GUEST_IPA_BASE` is 0 so that ELF link addresses equal guest IPA. Everything
else about the layout is derived, not fixed: `compute_infra_layout` computes
`mmap_limit`, `interp_base`, and the infra fields from `guest_size`, which
itself comes from the IPA width the host reports and may be bisected down when
`hv_vm_map` refuses the first size. Do not hardcode a number that
`compute_infra_layout` produces; ask the guest for it.

In ascending order the space holds: a null guard at the bottom of EL0, the ELF
load segments, brk, a guarded stack, the mmap RX region, the mmap RW region,
the infra reserve, the dynamic linker, and, under Rosetta, the translator and
its kbuf alias. `docs/internals.md` section "Memory Layout" has the map with
addresses.

Two rules survive any layout change:

- Guard every EL0-driven mmap, mprotect, and munmap with
  `guest_range_hits_infra` / `guest_addr_in_infra`. The infra reserve holds
  the page-table pool, the shim code, and shim_data, and EL0 must not reach
  any of them.
- An L0 entry covers 512 GiB, so a larger space needs more than one, and every
  walker (`guest_build_page_tables`, `guest_extend_page_tables`,
  `find_l2_entry`) computes its L0 index from the actual IPA rather than
  assuming entry zero.

## shim_data integrity

shim_data is `MEM_PERM_RW_EL1_ONLY` and holds a host-published cache the EL1
shim serves inline: identity slots (pid/ppid/uid/euid/gid/egid/tid), the
urandom-eligible fd bitmap, a urandom ring, and an attention bitmask
(`ATTN_BIT_SIGTIMER`, `ATTN_BIT_CRED`, `ATTN_BIT_TRACE`). HVC #5 is taken only
when attention is raised, the fd is not in the bitmap, or the ring needs a
refill.

Four things keep EL0 out of it, and a change that weakens any one of them is a
guest-readable host cache:

- `gva_translate_perm` refuses EL1-only descriptors on EL0 behalf, in both the
  L2 block and L3 page walk.
- `elf_map_segments` rejects PT_LOAD/PT_PHDR copies whose page-aligned write
  extent intersects the infra reserve.
- The shim's EL1 data-abort recover handler catches strb faults inside the
  urandom write ranges (a racing EL0 munmap/mprotect) and returns EFAULT.
- `/proc/self/maps` reports the span as PROT_NONE.

Publishing into the cache is bracketed rather than ordered by luck:
`shim_globals_attn_or` (`__ATOMIC_SEQ_CST`) raises the attention bit before
the mutator's stores, so a weakly-ordered ARM64 reader cannot observe the
publish without the bit; the clear is `__ATOMIC_RELEASE`.

## Stack construction

The Linux initial stack needs SP 16-byte aligned AND pointing directly at
argc. Padding goes above the structured area (before auxv), never after
pushing argc.

`build_linux_stack` (`src/core/stack.c`) maintains `total_entries` by hand as
a count of the pushes below it, computes where SP must land before pushing
anything, and fails the stack build when the final SP does not match. Adding
an auxv entry means updating both. That comparison is the gate, so there is no
need to memorize the current arithmetic; there is a need to keep the count
honest, because without it a miscount would silently shift argv rather than
fail.

Do not "fix" alignment with `sp &= ~15` after pushing: that opens a gap
between SP and argc and every libc fails to find its arguments.

## Fork

macOS HVF allows one VM per process, so fork is `posix_spawn` of
`elfuse --fork-child <fd>` plus IPC state transfer. Two rules that are easy to
violate:

- The parent must NOT remap `host_base`. HVF caches host VA to PA at
  `hv_vm_map` time, so a remap silently detaches the guest's view from the
  hypervisor's.
- The child must restore `g->ttbr0` from the IPC header.

The fast path takes an APFS `fclonefileat` snapshot and passes the fd via
SCM_RIGHTS; the child maps it MAP_PRIVATE. The snapshot decouples parent and
child even before the child remaps.

## Rosetta hosting

x86_64 guests run under Apple's Linux translator hosted inside the guest VM.
It is a guest-ABI subsystem, not a syscall one: what it needs from the host is
mappings and register state, and the ways it breaks are mapping-shaped.

- The translator is exposed at its link address through a non-identity
  page-table mapping rather than being loaded there, because that address is
  out of reach of the narrower Stage-2 IPA on some hosts.
- Its kbuf is aliased twice, once under TTBR1 and once under TTBR0, so that
  tagged-pointer extraction resolves to the same physical pages from either
  side. kbuf is always RW; nothing executable is installed there.
- Fork still attempts the APFS snapshot under Rosetta, but its fallback is
  different: a native guest can send the live `shm_fd` when the snapshot
  fails, and Rosetta cannot, so it drops to the region-copy path. The reason
  is the one from the fork section above, that HVF caches host VA to PA at
  map time.
- For dynamic x86_64 guests the host deliberately does not load segments or
  the interpreter. The translator reads PT_INTERP itself and mmaps the loader
  out of `--sysroot` through ordinary guest syscalls.
- The GDB stub is rejected for x86_64. `elfuse-debug` carries the reason,
  beside the invocation it refuses.

`docs/internals.md` section "x86_64-via-Apple-Rosetta" has the mechanism, and
`docs/testing.md` has the per-host baselines the x86_64 lane compares against.

## Authoritative sources

This skill is a working summary. These are tracked and survive a fresh clone,
so prefer them when the two disagree:

- `src/core/shim.S` - the header comment is the real HVC and marker contract,
  including the paths that do not consume X8.
- `docs/internals.md` - sections "Hypervisor.framework Constraints", "Memory
  Layout", "Page Table Splitting", "Dynamic Page-Table Extension And TLBI",
  "EL1 Shim And HVC Protocol", "Fork, Clone, And execve", "Signals",
  "x86_64-via-Apple-Rosetta".
