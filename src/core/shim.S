/* EL1 kernel shim
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Loaded at g->shim_base (a 16MiB infra reserve placed just below
 * g->interp_base; computed at guest_init time). Runs at EL1.
 * All system registers (VBAR, MAIR, TCR, TTBR0, SCTLR, etc.) are configured by
 * the host before vCPU start. The shim entry point transitions to EL0 via ERET.
 * Exception vectors handle SVC #0 (Linux syscall) forwarding to the host via
 * HVC #5.
 *
 * HVC protocol:
 *   #0  Normal exit       (x0 = exit code)
 *   #2  Bad exception     (x0=ESR, x1=FAR, x2=ELR, x3=SPSR, x5=vector)
 *   #4  Set sysreg        (x0 = reg ID (0-8), x1 = value)
 *   #5  Syscall forward   (X0-X5=args, X8=syscall nr;
 *                          on return X8 carries the post-syscall request:
 *                            0 = no TLB flush
 *                            1 = broadcast TLBI VMALLE1IS
 *                            2 = execve replaced register state (full flush
 *                                + drop frame + ERET without GPR restore)
 *                            3 = selective: TLBI VAE1IS over X10 pages
 *                                starting at page-aligned VA in X9
 *                            4 = single-shot TLBI RVAE1IS (FEAT_TLBIRANGE);
 *                                X9 carries the pre-encoded RVAE1IS operand
 *                                (baddr | NUM<<39 | SCALE<<44 | TTL<<37 |
 *                                ASID<<48; TTL=0 and ASID=0)
 *                          X11 carries the I-cache hint for X8 in {1, 3, 4}:
 *                          1 = IC IALLU after the TLBI sequence (new
 *                          executable content visible to EL0), 0 = skip the
 *                          I-cache invalidation (data-only PT change). The
 *                          X8 == 2 exec_drop_frame path always flushes
 *                          regardless because execve loads new code. The
 *                          shim restores X11 from the saved frame before
 *                          ERET so the EL0 caller never observes this hint.)
 *   #7  MRS trap          (host reads reg from ESR ISS; returns value in x0)
 *   #9  W^X toggle        (x0=FAR, x1=type: 0=exec->RX, 1=write->RW.
 *                          On return, X8==0 means retry after W^X TLBI;
 *                          X8==2 means host delivered a signal frame and the
 *                          shim must drop the saved fault frame.)
 *   #10 BRK from EL0      (SIGTRAP delivery / ptrace-stop; GPRs in frame)
 *   #11 EL0 fault         (SIGSEGV/SIGILL delivery; GPRs in frame.
 *                          On return the host sets X8 to the same TLBI
 *                          wire code as SVC #5 above (0/1/3/4 only;
 *                          X8 == 2 exec_drop_frame is rejected and falls
 *                          through to the conservative full flush). The
 *                          lazy MAP_NORESERVE materialize path uses this
 *                          to invalidate any negative TLB entry the EL0
 *                          retry would otherwise re-fault on. Eret tail
 *                          preserves X0/X1/X2/X30 so signal_deliver's
 *                          register writes survive.)
 *   #12 System instr trap (cache maintenance logging: DC CVAU, IC IVAU, etc.)
 *
 * macOS as uses ';' as a comment character on AArch64, NOT as a statement
 * separator. Each instruction must be on its own line.
 *
 * The Linux syscall ABI requires ALL general-purpose registers (X1-X30) to be
 * preserved across SVC #0, with only X0 modified (return value). Musl and other
 * libc implementations rely on this; the compiler does NOT save scratch
 * registers (X9-X15) across SVC calls. Therefore, the exception handler MUST
 * save and restore ALL 31 GPRs.
 */

.text

/* SAVE_GPRS: push all 31 GPRs onto a 256-byte EL1 stack frame.
 * Layout: [sp+0]  x0,x1   [sp+16] x2,x3   [sp+32] x4,x5
 *         [sp+48] x6,x7   [sp+64] x8,x9   ... [sp+240] x30,(pad)
 */
.macro SAVE_GPRS
    sub sp, sp, #256
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
.endm

/* LOAD_GPRS: load X0-X30 from the saved frame WITHOUT popping it.
 * Used at handle_svc_0 entry so the host can read the EL0 state via the vCPU
 * registers, while the frame remains live for the post-HVC restore.
 */
.macro LOAD_GPRS
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
.endm

/* RESTORE_GPRS: load all 31 GPRs and pop the frame. */
.macro RESTORE_GPRS
    LOAD_GPRS
    add sp, sp, #256
.endm

/* RESTORE_GPRS_KEEP_X0: load X1-X30 from the saved frame and pop it, leaving
 * X0 unchanged (so the syscall return value placed in X0 by the host survives).
 * Linux preserves X1-X30 across SVC #0.
 */
.macro RESTORE_GPRS_KEEP_X0
    ldr x1, [sp, #8]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    add sp, sp, #256
.endm

/* RESTORE_GPRS_KEEP_SIGFRAME: load X3-X29 from the saved frame and pop it,
 * leaving X0/X1/X2/X30 untouched. signal_deliver writes the signum, siginfo
 * pointer, ucontext pointer, and sa_restorer address into those live regs
 * via hv_vcpu_set_reg before returning from HVC #11; the standard
 * RESTORE_GPRS_KEEP_X0 tail would clobber X1/X2/X30 with their pre-fault
 * EL0 values. Used by the HVC #11 post-handler so the lazy-materialize
 * path can run TLBI ops (which clobber X11/X12/X13 as scratch) while
 * still preserving signal_deliver's register writes on the SIGSEGV /
 * SIGILL delivery path. The caller is responsible for setting X8 = 0
 * if no TLBI is needed; X8 is loaded from the frame here regardless.
 */
.macro RESTORE_GPRS_KEEP_SIGFRAME
    ldr x3, [sp, #24]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    add sp, sp, #256
.endm

/* ZERO_GPRS: clear X0-X30 (used before the EL1->EL0 transition). */
.macro ZERO_GPRS
    .irp r, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
    mov x\r, #0
    .endr
.endm

/* Counter byte offsets within shim_data. Mirror SHIM_COUNTER_* indices in
 * src/core/shim-globals.h; the static_asserts in shim-globals.c keep both
 * sides locked together. Byte offset = SHIM_COUNTERS_OFF + 8 * slot_index.
 *
 * SHIM_COUNTERS_OFF is 0x10C8, beyond AArch64's 12-bit add immediate range.
 * Split it explicitly so COUNTER_INC can fold the carry into one shifted add
 * and the low half plus the slot offset into the load/store immediate. The
 * shim-globals.c static_assert pins both halves.
 */
.equ SHIM_COUNTERS_OFF_HI,   0x1000
.equ SHIM_COUNTERS_OFF_LO12, 0xC8

/* Gate byte (uint8) inside the attention/identity padding. Loaded by
 * COUNTER_INC; zero (the default after shim_globals_init) skips the
 * counter body so disabled stats pay one cache-hot ldrb instead of a
 * full load-add-store on the shared counter line. The host publishes
 * via shim_globals_publish_stats_gate during bring-up.
 */
.equ SHIM_STATS_EN_OFF,      0x04

.equ CB_ATTN_BAIL,           0
.equ CB_URANDOM_FD_OOR,      8
.equ CB_URANDOM_FD_BMISS,    16
.equ CB_URANDOM_LEN_ZERO,    24
.equ CB_URANDOM_LEN_OVER,    32
.equ CB_URANDOM_RING_LOW,    40
.equ CB_URANDOM_PROBE_FAIL,  56
.equ CB_IDENTITY_HIT,        64
.equ CB_URANDOM_HIT,         72
.equ CB_GETRANDOM_HIT,       80
.equ CB_PGSID_HIT,           88
/* Slot 48 (SHIM_COUNTER_URANDOM_RING_WRAP) deliberately omitted: wrap
 * is handled inline by urandom_copy_loop, so no assembly path bumps it.
 * The C-side enum keeps the index for ABI stability.
 */

/* COUNTER_INC: bump diagnostic counter at byte offset
 * (SHIM_COUNTERS_OFF_LO12 + \byte_off) from TPIDR_EL1 by 1, only when
 * the host has published a nonzero stats gate at SHIM_STATS_EN_OFF.
 *
 * The gate keeps every fast-path tail from touching the counter cache
 * line in the common case (ELFUSE_SHIM_STATS unset). Without it, each
 * getpid / getuid / urandom hit drove a non-atomic load-add-store on
 * a single shared line, generating multi-vCPU coherence ping-pong on
 * top of the unconditional five-instruction tax.
 *
 * One shifted add carries the SHIM_COUNTERS_OFF_HI (#0x1000) high half;
 * the ldr/str fold the LO12 + slot-byte offset into the immediate (well
 * within the imm12*8 = 32760 byte range).
 *
 * Non-atomic ldr/add/str. Even with the gate enabled, multi-vCPU
 * concurrent bails may race and lose a small fraction of counts;
 * acceptable for diagnostic ratios. The gate-disabled tail expands to
 * three instructions (mrs + ldrb + cbz); the gate-enabled tail adds
 * the original five.
 *
 * x29/x30 are clobbered. svc_restore_eret's RESTORE_GPRS_KEEP_X0
 * reloads X1..X30 from the saved frame, so the clobber is safe on any
 * fast path. The end label uses GAS .L\@ macro-local naming so every
 * expansion gets a unique symbol -- nested or interleaved macros
 * cannot collide with a bare numeric label.
 */
.macro COUNTER_INC byte_off
    mrs x29, tpidr_el1
    ldrb w30, [x29, #SHIM_STATS_EN_OFF]
    cbz w30, .Lctr_skip_\@
    add x29, x29, #SHIM_COUNTERS_OFF_HI
    ldr x30, [x29, #(SHIM_COUNTERS_OFF_LO12 + \byte_off)]
    add x30, x30, #1
    str x30, [x29, #(SHIM_COUNTERS_OFF_LO12 + \byte_off)]
.Lctr_skip_\@:
.endm

/* Per-vCPU mmap counters live after the 32 x 24-byte publication ring in the
 * mmap control block. Each vCPU is the sole writer of its own slots. Keep the
 * shared stats gate so normal fast paths do not touch diagnostic cache lines.
 */
.equ SHIM_MMAP_COUNTERS_OFF, 0x340
.equ MC_SHAPE_MISS,          0
.equ MC_CAPACITY_MISS,       1
.equ MC_RING_FULL,           2
.equ MC_GENERATION_STALE,    3
.equ MC_ATTENTION,           4
.equ MC_HIT,                 5

.macro MMAP_COUNTER_INC slot
    mrs x29, tpidr_el1
    ldrb w30, [x29, #SHIM_STATS_EN_OFF]
    cbz w30, .Lmmap_ctr_skip_\@
    ldr x29, [x12, #(SHIM_MMAP_COUNTERS_OFF + 8 * \slot)]
    add x29, x29, #1
    str x29, [x12, #(SHIM_MMAP_COUNTERS_OFF + 8 * \slot)]
.Lmmap_ctr_skip_\@:
.endm

/* BAD_VEC: vector-table entry that reports an unexpected exception.
 * Each table slot is 128 bytes; the leading .align 7 places this entry at the
 * next 128-byte boundary.
 */
.macro BAD_VEC offset
    .align 7
    mov x5, #\offset
    b bad_exception
.endm

/* SVC_VEC: vector-table entry for synchronous exceptions (SVC #0).
 * Must NOT clobber any GPR before svc_handler saves them, since the Linux ABI
 * preserves X1-X30 across SVC.
 */
.macro SVC_VEC
    .align 7
    b svc_handler
.endm

.align 4
.globl _start
_start:
    /* Host has configured all system registers EXCEPT SCTLR.M (MMU enable).
     * Apple's Hypervisor.framework requires the MMU to be enabled DURING vCPU
     * execution (via HVC #4), not before hv_vcpu_run(). Setting SCTLR.M=1 via
     * hv_vcpu_set_sys_reg before start causes permission faults on the first
     * instruction fetch.
     *
     * Host passes the final SCTLR value (with M=1) in X0 before start.
     */

    /* Save SCTLR value from host (passed in X0) */
    mov x9, x0

    /* TLB + I-cache invalidation: ensure clean translation state before
     * enabling the MMU. Runs with SCTLR.M=0, so this fetch cannot be
     * misdirected by stale TLB state -- which is exactly why the execve
     * re-entry path lands here instead of resuming the interrupted
     * svc_handler frame: after guest_reset recycles the PT pool in place,
     * stale walk-cache entries can poison any translated fetch, and the
     * only architecturally safe point to drop them is before MMU-on.
     * IC IALLUIS covers stale I-cache lines from a pre-exec image that
     * loaded code at the same addresses (no-op cost at cold boot).
     */
    tlbi vmalle1is
    ic ialluis
    dsb ish
    isb

    /* Enable MMU: ask host to write SCTLR (reg ID 4 = SCTLR_EL1) */
    mov x0, #4
    mov x1, x9
    hvc #4
    isb

    /* Zero all general-purpose registers before entering EL0 */
    ZERO_GPRS

    eret

/* Exception Vector Table
 * Must be 2KiB (0x800) aligned. Each entry is 128 bytes (0x80).
 *
 * bad_exception vectors: mov x5, #offset + b bad_exception
 *   X5 carries the vector offset for host-side debugging.
 *   This is safe because bad_exception halts, so no register preservation
     needed.
 *
 * svc_handler vectors: b svc_handler (NO mov x5!)
 *   These MUST NOT clobber any GPR before svc_handler saves them. The Linux
 *   syscall ABI requires X0-X30 to be preserved across SVC #0 (only X0 is
 *   modified with the return value).
 *   If the shim wrote to X5 here, the saved value would be wrong and the
 *   restored X5 after ERET would corrupt the caller's state.
 */
.align 11
vectors:
    /* Current EL, SP0:                         0x000 Sync, 0x080 IRQ,
     *                                          0x100 FIQ,  0x180 SError
     */
    BAD_VEC 0x000
    BAD_VEC 0x080
    BAD_VEC 0x100
    BAD_VEC 0x180

    /* Current EL, SPx (0x200 dispatches to svc_handler from EL1):
     *                                          0x200 Sync, 0x280 IRQ,
     *                                          0x300 FIQ,  0x380 SError
     */
    SVC_VEC
    BAD_VEC 0x280
    BAD_VEC 0x300
    BAD_VEC 0x380

    /* Lower EL, AArch64 (0x400 dispatches to svc_handler from EL0):
     *                                          0x400 Sync, 0x480 IRQ,
     *                                          0x500 FIQ,  0x580 SError
     */
    SVC_VEC
    BAD_VEC 0x480
    BAD_VEC 0x500
    BAD_VEC 0x580

    /* Lower EL, AArch32:                       0x600 Sync, 0x680 IRQ,
     *                                          0x700 FIQ,  0x780 SError
     */
    BAD_VEC 0x600
    BAD_VEC 0x680
    BAD_VEC 0x700
    BAD_VEC 0x780

/* bad_exception: Report unexpected exception to host and halt
 */
bad_exception:
    mrs x0, esr_el1
    mrs x1, far_el1
    mrs x2, elr_el1
    mrs x3, spsr_el1
    /* x5 already holds vector offset from the entry stub */
    hvc #2

/* svc_handler: Synchronous exception dispatcher
 *
 * On entry from EL0 SVC #0 (or EL1 synchronous):
 *   X0-X5  = syscall arguments
 *   X8     = syscall number
 *   X6-X30 = caller state (MUST be preserved per Linux ABI)
 *
 * The Linux syscall ABI guarantees all registers except X0 survive the SVC.
 * Musl's inline syscall wrappers (and GCC/Clang codegen) rely on this: scratch
 * registers X9-X15 are NOT saved by the compiler across SVC calls. The shim
 * must save/restore ALL 31 GPRs.
 *
 * Stack frame: 256 bytes (16 pairs x 16 bytes)
 *   [sp+0]   x0,x1    [sp+16]  x2,x3    [sp+32]  x4,x5
 *   [sp+48]  x6,x7    [sp+64]  x8,x9    [sp+80]  x10,x11
 *   [sp+96]  x12,x13  [sp+112] x14,x15  [sp+128] x16,x17
 *   [sp+144] x18,x19  [sp+160] x20,x21  [sp+176] x22,x23
 *   [sp+192] x24,x25  [sp+208] x26,x27  [sp+224] x28,x29
 *   [sp+240] x30,(pad)
 */
svc_handler:
    /* Save all 31 general-purpose registers on the EL1 stack */
    SAVE_GPRS

    /* Decode exception class from ESR_EL1.
     * X9-X11 are now scratch (saved on stack above).
     */
    mrs x9, esr_el1
    lsr x10, x9, #26         /* EC = bits [31:26] */

    cmp x10, #0x15            /* SVC from AArch64? */
    b.ne not_svc

    /* Extract SVC immediate (bits [15:0]) */
    and x11, x9, #0xFFFF

    /* Inverted from "b.eq handle_svc_0" so the SVC #0 fast-path
     * dispatch can fall through without an extra branch.
     */
    cmp x11, #0
    b.ne restore_and_bad

    /* Identity-class fast path. X8 in [172, 179) is one of getpid (172),
     * getppid (173), getuid (174), geteuid (175), getgid (176), getegid (177),
     * or gettid (178). The first six read from the shim-globals cache
     * (TPIDR_EL1 base, host-published scalar slots starting at offset 8);
     * gettid reads its per-vCPU tid from CONTEXTIDR_EL1 directly. Layout-wise
     * the cache has the attention flag at offset 0 (LDAR'd here to enforce the
     * slow-path gate from Slice B and the --verbose trace gate) and six
     * identity slots after it.
     *
     * Saved X8 is at [sp+64] per SAVE_GPRS. Scratch X10..X13 are restored from
     * the frame by RESTORE_GPRS_KEEP_X0 at the named tail (svc_restore_eret),
     * so the Linux ABI guarantee (X1..X30 preserved across SVC) is intact even
     * on the fast path.
     */
    ldr x10, [sp, #64]               /* saved X8 (syscall nr) */
    sub x11, x10, #172
    cmp x11, #7                       /* in identity-class range? */
    b.lo identity_class_fast          /* 172..178 -> identity / gettid */
    cmp x10, #63                       /* SYS_read? */
    b.eq urandom_read_fast
    cmp x10, #155                      /* SYS_getpgid? */
    b.eq getpgid_fast
    cmp x10, #156                      /* SYS_getsid? */
    b.eq getsid_fast
    cmp x10, #278                      /* SYS_getrandom? */
    b.eq getrandom_fast
    cmp x10, #215                      /* SYS_munmap? */
    b.eq munmap_anon_fast
    cmp x10, #222                      /* SYS_mmap? */
    b.eq mmap_anon_fast
    b handle_svc_0

/* mmap_anon_fast: consume a host-prepared, per-vCPU VA arena for the exact
 * anonymous RW shape used by allocators:
 *
 *   mmap(NULL, len, PROT_READ|PROT_WRITE,
 *        MAP_PRIVATE|MAP_ANONYMOUS[|MAP_NORESERVE], fd, off)
 *
 * The control is selected without another system register.  SP_EL1 stack tops
 * are shim_data_end - slot*4KiB; controls are shim_data+0x20000 + slot*2KiB,
 * so (shim_data_end - ALIGN_UP(sp,4KiB))/2 is the control-array displacement.
 * Each vCPU is the sole producer of its ring and cursor.  The host acquire-
 * drains all rings whenever it takes mmap_lock.
 */
mmap_anon_fast:
    mrs x12, tpidr_el1                 /* shared shim-data base */
    ldar w13, [x12]                    /* tracing/signal attention gate */

    add x14, sp, #0xfff
    and x14, x14, #~0xfff              /* this vCPU's stack top */
    add x15, x12, #0x200, lsl #12      /* shim_data + 2MiB */
    sub x15, x15, x14                  /* slot * 4KiB */
    lsr x15, x15, #1                   /* slot * 2KiB */
    add x12, x12, x15
    add x12, x12, #0x20, lsl #12       /* control base + 0x20000 */

    cbnz w13, mmap_attention_bail

    ldr x14, [sp, #0]                  /* addr */
    cbnz x14, mmap_shape_bail
    ldr x16, [sp, #16]                 /* prot */
    cmp x16, #3                        /* PROT_READ|PROT_WRITE */
    b.ne mmap_shape_bail
    ldr x17, [sp, #24]                 /* flags */
    bic x18, x17, #0x4000              /* tolerate MAP_NORESERVE */
    cmp x18, #0x22                     /* MAP_PRIVATE|MAP_ANONYMOUS */
    b.ne mmap_shape_bail

    ldr x15, [sp, #8]                  /* len */
    cbz x15, mmap_shape_bail
    adds x15, x15, #0xfff
    b.cs mmap_shape_bail                /* PAGE_ALIGN_UP overflow */
    and x15, x15, #~0xfff

    ldar w13, [x12]                    /* descriptor generation */
    ldr w14, [x12, #4]                 /* consumer generation */
    cmp w13, w14
    b.ne mmap_generation_bail
    ldr w13, [x12, #8]                 /* SHIM_MMAP_CTRL_ENABLED */
    tbz w13, #0, mmap_capacity_bail

    ldr x19, [x12, #40]                /* private bump cursor */
    mov x20, #0x200000
    cmp x15, x20
    b.lo 1f
    sub x21, x20, #1
    adds x19, x19, x21
    b.cs mmap_capacity_bail
    bic x19, x19, x21                  /* >=2MiB: 2MiB-align */
1:  ldr x20, [x12, #32]                /* arena limit */
    adds x21, x19, x15                 /* new cursor */
    b.cs mmap_capacity_bail
    cmp x21, x20
    b.hi mmap_capacity_bail

    add x23, x12, #12                  /* &head */
    ldar w22, [x23]
    ldr w23, [x12, #16]                /* producer-owned tail */
    sub w24, w23, w22
    cmp w24, #32                       /* SHIM_MMAP_RING_SIZE */
    b.hs mmap_ring_full_bail

    and w24, w23, #31
    add x24, x24, x24, lsl #1          /* index * 3 */
    add x25, x12, #64                   /* ring base */
    add x25, x25, x24, lsl #3          /* index * 24 */
    str x19, [x25, #0]
    str x15, [x25, #8]
    str x16, [x25, #16]
    str x21, [x12, #40]                /* publish cursor before entry */
    add w23, w23, #1
    add x25, x12, #16
    stlr w23, [x25]                    /* release-publish ring entry */
    mov x0, x19
    MMAP_COUNTER_INC MC_HIT
    b svc_restore_eret

mmap_shape_bail:
    MMAP_COUNTER_INC MC_SHAPE_MISS
    b handle_svc_0

mmap_capacity_bail:
    MMAP_COUNTER_INC MC_CAPACITY_MISS
    b handle_svc_0

mmap_ring_full_bail:
    MMAP_COUNTER_INC MC_RING_FULL
    b handle_svc_0

mmap_attention_bail:
    MMAP_COUNTER_INC MC_ATTENTION
    b attn_bail

mmap_generation_bail:
    /* A revocation deliberately leaves the consumer generation stale.  Ack
     * only after the acquire load above, then make this syscall take HVC; the
     * host will either leave the control disabled or publish a fresh arena.
     */
    MMAP_COUNTER_INC MC_GENERATION_STALE
    str w13, [x12, #4]
    b handle_svc_0

/* munmap_anon_fast: invalidate an anonymous arena range synchronously at EL1,
 * then release-publish a metadata retirement to this vCPU's SPSC ring.  The
 * host consumes it at a later natural VM exit.  No shared allocator cursor is
 * modified here.
 *
 * The two-pass page-table walk is deliberate.  Pass one proves every partial
 * 2 MiB block already has an L3 table, so pass two cannot discover a need to
 * split after it has cleared an earlier descriptor.  Whole L2 blocks and L3
 * leaves are the only descriptors this path writes.
 */
munmap_anon_fast:
    mrs x12, tpidr_el1                 /* shim-data base */
    ldar w13, [x12]                    /* attention gate */

    add x20, sp, #0xfff
    and x20, x20, #~0xfff              /* this vCPU's stack top */
    add x21, x12, #0x200, lsl #12
    sub x21, x21, x20
    lsr x21, x21, #1
    add x21, x12, x21
    add x21, x21, #0x20, lsl #12       /* current mmap control */

    cbnz w13, munmap_pre_bail
    ldr x14, [sp, #0]                  /* addr */
    ldr x15, [sp, #8]                  /* length */
    cbz x15, munmap_pre_bail
    tst x14, #0xfff
    b.ne munmap_pre_bail
    tst x15, #0xfff
    b.ne munmap_pre_bail
    adds x16, x14, x15                 /* exclusive end */
    b.cs munmap_pre_bail

    add x17, x21, #0x400               /* private retire ring */
    add x20, x17, #0
    ldar w20, [x20]                    /* host head */
    ldr w19, [x17, #4]                 /* producer tail */
    sub w22, w19, w20
    cmp w22, #31                       /* near-full => batched HVC drain */
    b.hs munmap_pre_bail
    ldr x18, [x17, #8]                 /* producer byte sequence */

    /* Join the per-vCPU side of the host-writer handshake.  The second gate
     * read closes the check-vs-announce race: if host closed it in between,
     * withdraw without touching a PTE.
     */
    mrs x20, tpidr_el1
    add x20, x20, #0x1, lsl #12
    add x20, x20, #0x160               /* SHIM_MMAP_PT_GATE_OFF */
    ldar w22, [x20]
    cbnz w22, munmap_pre_bail
    mov w22, #1
    add x25, x17, #24
    stlr w22, [x25]                    /* producer_active = 1 */
    ldar w22, [x20]
    cbnz w22, munmap_active_bail

    /* Locate the one arena generation containing the whole range.  Scanning
     * 64 cache-cold descriptors is only the cross-vCPU case; the owner's
     * control normally matches early.  generation is re-read after bounds so
     * a descriptor publication can never be observed torn.
     */
    mrs x25, tpidr_el1
    add x25, x25, #0x20, lsl #12       /* control[0] */
    mov w24, #0                        /* arena slot */
1:  add x26, x25, #8
    ldar w23, [x26]                    /* arena flags */
    tbz w23, #0, 2f
    ldar w22, [x25]                    /* generation snapshot */
    ldr x26, [x25, #24]                /* arena base */
    cmp x14, x26
    b.lo 2f
    add x27, x25, #40
    ldar x27, [x27]                    /* consumed cursor */
    cmp x16, x27
    b.hi 2f
    ldar w28, [x25]
    cmp w22, w28
    b.eq munmap_arena_found
2:  add w24, w24, #1
    add x25, x25, #0x800
    cmp w24, #64
    b.lo 1b
    b munmap_active_bail

munmap_arena_found:
    /* Reserve and fill, but do not advance tail until PTE+TLBI completion. */
    and w20, w19, #31
    add x20, x20, x20, lsl #1          /* index * 3 */
    add x26, x17, #32                  /* retire.entries */
    add x26, x26, x20, lsl #3          /* index * 24 */
    str x14, [x26, #0]
    str x15, [x26, #8]
    str w22, [x26, #16]
    str w24, [x26, #20]

    /* Refill invalidates every stale descriptor before publishing a new
     * generation.  Until the host records a lazy materialization in that
     * generation, the entire arena is known PTE-empty and no walk/TLBI is
     * needed.  The host PT gate makes the generation marker stable here.
     */
    add x20, x25, #0x388
    ldar w20, [x20]
    cmp w20, w22
    b.ne munmap_publish
    ldr x11, [x25, #0x390]            /* materialized lower bound */
    ldr x12, [x25, #0x398]            /* materialized upper bound */
    cmp x11, x14
    csel x11, x11, x14, hi            /* max(addr, materialized_start) */
    cmp x12, x16
    csel x12, x12, x16, lo            /* min(end, materialized_end) */
    cmp x11, x12
    b.hs munmap_publish

    /* Common large-anonymous case: the materialized envelope is 2 MiB
     * aligned and consists only of L2 block descriptors (or holes retired by
     * a sibling). Walk L0 once, then L1 once per 1 GiB window and scan the L2
     * entries linearly. The generic path below remains the fallback for any
     * L3 table or unusual upper-level shape.
     */
    mov w10, #0                        /* generic mutation by default */
    orr x20, x11, x12
    tst x20, #0x1fffff
    b.ne munmap_validate_generic
    sub x20, x12, #1
    eor x20, x20, x11
    lsr x20, x20, #39                 /* must stay in one L0 slot */
    cbnz x20, munmap_validate_generic

    mov x13, #0
    mrs x25, ttbr0_el1
    ubfx x25, x25, #12, #36
    lsl x25, x25, #12                 /* L0 table */
    ubfx x26, x11, #39, #9
    add x26, x25, x26, lsl #3
    ldar x27, [x26]
    and x28, x27, #3
    cbz x28, munmap_validate_l2_fast_done
    cmp x28, #3
    b.ne munmap_validate_generic
    ubfx x25, x27, #12, #36
    lsl x25, x25, #12                 /* L1 table */

    mov x20, x11
munmap_validate_l2_fast_window:
    ubfx x26, x20, #30, #9
    add x26, x25, x26, lsl #3
    ldar x27, [x26]
    and x28, x27, #3
    lsr x29, x20, #30
    add x29, x29, #1
    lsl x30, x29, #30                 /* next 1 GiB boundary */
    cmp x30, x12
    csel x30, x30, x12, lo            /* this window's end */
    cbz x28, munmap_validate_l2_fast_next_window
    cmp x28, #3
    b.ne munmap_validate_generic
    ubfx x26, x27, #12, #36
    lsl x26, x26, #12                 /* L2 table */
    ubfx x29, x20, #21, #9
    add x26, x26, x29, lsl #3
munmap_validate_l2_fast_entry:
    ldr x27, [x26]
    and x28, x27, #3
    cbz x28, 1f
    cmp x28, #1                       /* L2 block, never L3 table */
    b.ne munmap_validate_generic
    add x13, x13, #512
1:  add x26, x26, #8
    add x20, x20, #0x200000
    cmp x20, x30
    b.lo munmap_validate_l2_fast_entry
    b 2f
munmap_validate_l2_fast_next_window:
    mov x20, x30
2:  cmp x20, x12
    b.lo munmap_validate_l2_fast_window
munmap_validate_l2_fast_done:
    mov w10, #1
    b munmap_clear_begin

    /* Validation pass. x20 is the current VA; x13 counts valid target pages.
     * Pending bytes are charged by materialized backing rather than virtual
     * length. Crossing the soft threshold records cleanup_requested but never
     * forces this producer to HVC; another natural exit will consume the ring.
     */
munmap_validate_generic:
    mov w10, #0
    mov x13, #0
    mov x20, x11
munmap_validate_block:
    cmp x20, x12
    b.hs munmap_clear_begin
    mrs x25, ttbr0_el1
    ubfx x25, x25, #12, #36
    lsl x25, x25, #12
    ubfx x26, x20, #39, #9
    add x26, x25, x26, lsl #3
    ldar x27, [x26]
    and x28, x27, #3
    cbz x28, munmap_validate_absent
    cmp x28, #3
    b.ne munmap_active_bail
    ubfx x25, x27, #12, #36
    lsl x25, x25, #12
    ubfx x26, x20, #30, #9
    add x26, x25, x26, lsl #3
    ldar x27, [x26]
    and x28, x27, #3
    cbz x28, munmap_validate_absent
    cmp x28, #3
    b.ne munmap_active_bail
    ubfx x25, x27, #12, #36
    lsl x25, x25, #12
    ubfx x26, x20, #21, #9
    add x26, x25, x26, lsl #3          /* &L2[index] */
    ldar x27, [x26]
    and x28, x27, #3
    cbz x28, munmap_validate_absent
    cmp x28, #3
    b.eq munmap_validate_l3
    cmp x28, #1
    b.ne munmap_active_bail
    /* An L2 block can only be cleared as a whole. */
    lsr x29, x20, #21
    lsl x29, x29, #21                  /* block start */
    cmp x14, x29
    b.hi munmap_active_bail
    add x30, x29, #0x200000
    cmp x16, x30
    b.lo munmap_active_bail
    add x13, x13, #512
    b munmap_validate_advance

munmap_validate_l3:
    ubfx x25, x27, #12, #36            /* L3 table VA */
    lsl x25, x25, #12
    lsr x29, x20, #21
    lsl x29, x29, #21
    add x30, x29, #0x200000
    cmp x30, x12
    csel x30, x30, x12, lo
1:  ubfx x26, x20, #12, #9
    add x26, x25, x26, lsl #3
    ldar x27, [x26]
    tbz x27, #0, 2f
    add x13, x13, #1
2:  add x20, x20, #0x1000
    cmp x20, x30
    b.lo 1b
    b munmap_validate_block

munmap_validate_absent:
    lsr x29, x20, #21
    add x29, x29, #1
    lsl x20, x29, #21
    b munmap_validate_block
munmap_validate_advance:
    mov x20, x30
    b munmap_validate_block

    /* Mutation pass.  Host writers are gated; sibling fast munmaps can only
     * change the same descriptors to zero, so repeated invalidation is safe.
     */
munmap_clear_begin:
    /* Encode the charged 4 KiB page count in the retire flags so the host's
     * single-writer consumed sequence advances by exactly the same amount.
     */
    and w20, w19, #31
    add x20, x20, x20, lsl #1
    add x26, x17, #32
    add x26, x26, x20, lsl #3
    lsl w29, w13, #6
    orr w29, w29, w24
    str w29, [x26, #20]
    cbz x13, munmap_publish

    add x20, x17, #16
    ldar x20, [x20]                    /* host-consumed byte sequence */
    sub x29, x18, x20                  /* pending materialized bytes */
    lsl x30, x13, #12                  /* this retirement's charge */
    adds x29, x29, x30
    b.cs munmap_active_bail
    adds x18, x18, x30                 /* next producer byte sequence */
    b.cs munmap_active_bail
    mov x20, #0x10000000               /* 256 MiB soft advisory */
    cmp x29, x20
    b.ls 1f
    mov w20, #1
    add x25, x17, #28
    stlr w20, [x25]                    /* never makes this vCPU exit */
1:

    cbnz w10, munmap_clear_l2_fast_begin
    mov x20, x11
munmap_clear_block:
    cmp x20, x12
    b.hs munmap_tlbi
    mrs x25, ttbr0_el1
    ubfx x25, x25, #12, #36
    lsl x25, x25, #12
    ubfx x26, x20, #39, #9
    add x26, x25, x26, lsl #3
    ldar x27, [x26]
    and x28, x27, #3
    cmp x28, #3
    b.ne munmap_clear_next_block
    ubfx x25, x27, #12, #36
    lsl x25, x25, #12
    ubfx x26, x20, #30, #9
    add x26, x25, x26, lsl #3
    ldar x27, [x26]
    and x28, x27, #3
    cmp x28, #3
    b.ne munmap_clear_next_block
    ubfx x25, x27, #12, #36
    lsl x25, x25, #12
    ubfx x26, x20, #21, #9
    add x26, x25, x26, lsl #3          /* &L2[index] */
    ldar x27, [x26]
    and x28, x27, #3
    cbz x28, munmap_clear_next_block
    cmp x28, #1
    b.eq munmap_clear_l2
    cmp x28, #3
    b.ne munmap_active_bail             /* validation invariant */

    ubfx x25, x27, #12, #36            /* L3 table VA */
    lsl x25, x25, #12
    lsr x29, x20, #21
    lsl x29, x29, #21                  /* block start */
    add x30, x29, #0x200000
    cmp x30, x12
    csel x30, x30, x12, lo             /* page-loop end */
munmap_clear_l3_page:
    ubfx x26, x20, #12, #9
    add x26, x25, x26, lsl #3
    stlr xzr, [x26]
    add x20, x20, #0x1000
    cmp x20, x30
    b.lo munmap_clear_l3_page
    b munmap_clear_block

munmap_clear_l2:
    stlr xzr, [x26]
munmap_clear_next_block:
    lsr x29, x20, #21
    add x29, x29, #1
    lsl x20, x29, #21
    b munmap_clear_block

munmap_clear_l2_fast_begin:
    /* Validation proved one L0 table and L2-block-only leaves. Re-walk L1 once
     * per 1 GiB window, then use ordinary aligned 64-bit stores. Those stores
     * are atomic; the DSB ISHST below supplies the required publication order,
     * so a release store on every descriptor is unnecessary.
     */
    mrs x25, ttbr0_el1
    ubfx x25, x25, #12, #36
    lsl x25, x25, #12
    ubfx x26, x11, #39, #9
    add x26, x25, x26, lsl #3
    ldr x27, [x26]
    ubfx x25, x27, #12, #36
    lsl x25, x25, #12                 /* L1 table */
    mov x20, x11
munmap_clear_l2_fast_window:
    ubfx x26, x20, #30, #9
    add x26, x25, x26, lsl #3
    ldr x27, [x26]
    and x28, x27, #3
    lsr x29, x20, #30
    add x29, x29, #1
    lsl x30, x29, #30
    cmp x30, x12
    csel x30, x30, x12, lo
    cbz x28, munmap_clear_l2_fast_next_window
    ubfx x26, x27, #12, #36
    lsl x26, x26, #12
    ubfx x29, x20, #21, #9
    add x26, x26, x29, lsl #3
munmap_clear_l2_fast_entry:
    /* Validation plus the closed host gate proves this slot is a block or
     * already zero. A sibling producer can only move it toward zero, so an
     * unconditional aligned store is safe and avoids a second load/branch.
     */
    str xzr, [x26]
    add x26, x26, #8
    add x20, x20, #0x200000
    cmp x20, x30
    b.lo munmap_clear_l2_fast_entry
    b 2f
munmap_clear_l2_fast_next_window:
    mov x20, x30
2:  cmp x20, x12
    b.lo munmap_clear_l2_fast_window
    b munmap_tlbi

munmap_tlbi:
    /* Descriptor stores -> broadcast invalidation -> completed visibility,
     * before the retire tail release makes metadata cleanup eligible.
     */
    dsb ishst
    sub x20, x12, x11
    lsr x20, x20, #12                  /* changed-page envelope */
    cmp x20, #8
    b.hi munmap_tlbi_large
    ubfx x25, x11, #12, #44
3:  tlbi vae1is, x25
    add x25, x25, #1
    subs x20, x20, #1
    b.ne 3b
    b munmap_tlbi_done

munmap_tlbi_large:
    /* Encode SCALE=0..3 RVAE1IS batches directly from the changed envelope.
     * Each instruction covers up to 32 scale units: 64 pages at SCALE=0,
     * 2048 at SCALE=1, 65536 at SCALE=2, and 2097152 (8 GiB) at SCALE=3.
     * Widening to the scale-unit boundary only invalidates neighboring TLB
     * entries; it cannot change mappings. Ranges larger than one instruction
     * are emitted as adjacent batches while retaining a single completion DSB.
     */
    tbz w23, #1, munmap_tlbi_full
    cmp x20, #64
    b.hi 1f
    mov x27, #13                       /* 2 pages = 8 KiB */
    mov x28, #0                        /* SCALE=0 */
    b munmap_tlbi_rvae_normalize
1:  cmp x20, #0x800
    b.hi 2f
    mov x27, #18                       /* 64 pages = 256 KiB */
    mov x28, #1                        /* SCALE=1 */
    b munmap_tlbi_rvae_normalize
2:  mov x29, #0x10000
    cmp x20, x29
    b.hi 3f
    mov x27, #23                       /* 2048 pages = 8 MiB */
    mov x28, #2                        /* SCALE=2 */
    b munmap_tlbi_rvae_normalize
3:  mov x27, #28                       /* 65536 pages = 256 MiB */
    mov x28, #3                        /* SCALE=3 */

munmap_tlbi_rvae_normalize:
    mov x29, #1
    lsl x29, x29, x27
    sub x29, x29, #1                   /* scale-unit byte mask */
    bic x25, x11, x29                  /* widened start */
    adds x26, x12, x29
    b.cs munmap_tlbi_full
    bic x26, x26, x29                  /* widened end */
munmap_tlbi_rvae_batch:
    sub x20, x26, x25
    lsrv x20, x20, x27                 /* remaining scale units */
    mov x30, #32
    cmp x20, x30
    csel x20, x20, x30, lo            /* this instruction's units */
    ubfx x29, x25, #12, #37            /* BaseADDR */
    sub x30, x20, #1                   /* NUM */
    lsl x30, x30, #39
    orr x29, x29, x30
    lsl x30, x28, #44                  /* SCALE */
    orr x29, x29, x30
    mov x30, #1
    lsl x30, x30, #46                  /* TG=01 (4 KiB) */
    orr x29, x29, x30
    tlbi rvae1is, x29
    lslv x20, x20, x27
    add x25, x25, x20
    cmp x25, x26
    b.lo munmap_tlbi_rvae_batch
    b munmap_tlbi_done
munmap_tlbi_full:
    tlbi vmalle1is
munmap_tlbi_done:
    dsb ish
    isb

munmap_publish:
    str x18, [x17, #8]                 /* publish producer byte sequence */
    add w19, w19, #1
    add x20, x17, #4
    stlr w19, [x20]                    /* publish retire record */
    add x20, x17, #24
    stlr wzr, [x20]                    /* leave writer handshake */
    mov x0, #0
    b svc_restore_eret

munmap_active_bail:
    add x20, x17, #24
    stlr wzr, [x20]
munmap_pre_bail:
    b handle_svc_0

identity_class_fast:
    mrs x12, tpidr_el1               /* shim-globals base */
    ldar w13, [x12]                  /* attention flag, acquire */
    cbnz w13, attn_bail              /* slow-path required */
    cmp x11, #6                       /* bias == 6 ==> gettid (178) */
    b.eq gettid_fast
    add x12, x12, #8                 /* skip attention -> identity[0] */
    ldr x0, [x12, x11, lsl #3]       /* identity[bias] for 172..177 */
    COUNTER_INC CB_IDENTITY_HIT
    b svc_restore_eret

gettid_fast:
    mrs x0, contextidr_el1            /* per-vCPU tid */
    COUNTER_INC CB_IDENTITY_HIT
    b svc_restore_eret

/* getpgid_fast / getsid_fast: serve getpgid(0) and getsid(0) from
 * shim-globals slots. Any non-zero pid argument or set attention bit
 * falls through to the host so per-pid lookups and post-setpgid/setsid
 * publish ordering remain authoritative.
 */
getpgid_fast:
    ldr x14, [sp, #0]                /* saved X0 = pid arg */
    cbnz x14, handle_svc_0           /* pid != 0: not a pure cache read */
    mrs x12, tpidr_el1
    ldar w13, [x12]
    cbnz w13, attn_bail
    ldr x0, [x12, #0x1148]            /* SHIM_IDENTITY_OFF_PGID */
    COUNTER_INC CB_PGSID_HIT
    b svc_restore_eret

getsid_fast:
    ldr x14, [sp, #0]
    cbnz x14, handle_svc_0
    mrs x12, tpidr_el1
    ldar w13, [x12]
    cbnz w13, attn_bail
    ldr x0, [x12, #0x1150]            /* SHIM_IDENTITY_OFF_SID */
    COUNTER_INC CB_PGSID_HIT
    b svc_restore_eret

    /* Urandom-read fast path. Serves read(urandom_fd, buf, len) with
     * len in [1, SHIM_URANDOM_INLINE_LIMIT (256)] by popping len bytes
     * from the shim-globals entropy ring (TPIDR_EL1 base + 0xC0) into
     * the guest-supplied buffer (X1), advancing the ring head
     * atomically. The 4 KiB ring boundary is handled inline via a
     * split-copy with a one-shot wrap flag. If the requested fd is not
     * FD_URANDOM or the ring is below the requested fill, falls through
     * to handle_svc_0 so the host serves the read and refills the ring.
     *
     * Layout offsets (match core/shim-globals.h SHIM_URANDOM_OFF_*):
     *   0x0038  URANDOM_FD_BITMAP   1024 bits = 128 bytes
     *   0x00B8  RING_HEAD            uint32, atomic consumer cursor
     *   0x00BC  RING_TAIL            uint32, host-released tail
     *   0x00C0  RING                  4096 bytes
     *   0x10C0  RING_LOCK             uint32
     */
urandom_read_fast:
    mrs x12, tpidr_el1
    ldar w13, [x12]                  /* attention flag */
    cbnz w13, attn_bail

    ldr x14, [sp, #0]                /* saved X0 = fd */
    cmp x14, #1024                    /* FD_TABLE_SIZE */
    b.hs urandom_fd_oor_bail
    ldr x15, [sp, #16]               /* saved X2 = len */
    cbz x15, urandom_len_zero_bail   /* host handles len == 0 */
    cmp x15, #256                     /* SHIM_URANDOM_INLINE_LIMIT */
    b.hi urandom_len_over_bail

    /* Bitmap test: word = fd >> 6, bit = fd & 63. */
    add x16, x12, #0x38              /* SHIM_URANDOM_OFF_BITMAP */
    lsr x17, x14, #6
    ldr x17, [x16, x17, lsl #3]
    and x18, x14, #63
    lsr x17, x17, x18
    tbz w17, #0, urandom_fd_bmiss_bail

    ldr x20, [sp, #8]                /* saved X1 = buf */
    /* Probe the guest buffer for stage-1 EL0-write translations before
     * doing any EL1 store. PROT_NONE or unmapped pages bail to the
     * slow path here; the host's sys_read returns -EFAULT.
     *
     * The probe handles the STATIC case (buffer already unmapped at
     * entry). The DYNAMIC case where a sibling vCPU munmaps the buffer
     * in the window between probe and strb is caught later by the
     * EL1 data abort vector routing into handle_el1_data_abort_recover
     * (which discards the reserved entropy, releases the lock, and
     * returns -EFAULT to EL0; the ring head is not rolled back -- the
     * already-published bytes are simply skipped on the next read).
     * Without that recovery the EL1 strb would fault into BAD_VEC and
     * halt the VM.
     *
     * len is in [1, SHIM_URANDOM_INLINE_LIMIT=256]. Probing the first
     * and last byte covers every page the inline copy can touch: even
     * at the smaller 4 KiB host page size a 256-byte buffer straddles
     * at most one page boundary, so probe(buf) + probe(buf+len-1) hits
     * both pages. The second probe is skipped when buf and buf+len-1
     * fall in the same 4 KiB page -- the dominant case for small
     * crypto/SSH-handshake reads. Detected via xor + mask.
     */
    sub x16, x15, #1                 /* len - 1 */
    adds x17, x20, x16               /* last_byte = buf + len - 1 */
    b.cs urandom_probe_fail_bail     /* overflow */
    at s1e0w, x20
    isb
    mrs x16, par_el1
    tbnz x16, #0, urandom_probe_fail_bail
    /* Same 4 KiB page? If (buf ^ last_byte) & ~0xFFF == 0, skip the
     * second probe. eor + tst against the page mask is two scalar ops
     * and one fused branch; cheaper than the full AT/ISB/MRS sequence
     * (~5-15 ns).
     */
    eor x18, x20, x17
    tst x18, #~0xFFF
    b.eq 7f
    at s1e0w, x17
    isb
    mrs x16, par_el1
    tbnz x16, #0, urandom_probe_fail_bail
7:

    /* Serialize host refill against the shim's reserve-then-copy window.
     * Lock word lives after the 4096-byte ring at offset 0x10C0.
     */
    add x19, x12, #0x1, lsl #12      /* base + 0x1000 */
    add x19, x19, #0xC0              /* &ring_lock */
    mov w18, #1
urandom_lock_spin:
    /* LSE swpal: atomic exchange. w17 receives the previous lock value;
     * w18 (1) is stored unconditionally. If the previous was 0, we
     * acquired. If it was 1, a sibling holds it; yield and retry.
     * Apple Silicon implements ARMv8.1 LSE atomics, so swpal is one
     * instruction (vs the prior ldaxr/stxr exclusive sequence). Release
     * on unlock stays as stlr wzr, [x19].
     */
    swpal w18, w17, [x19]
    cbnz w17, urandom_lock_busy
    b urandom_locked
urandom_lock_busy:
    yield
    b urandom_lock_spin

urandom_locked:
    add x21, x12, #0xB8              /* &ring_head */
    add x22, x12, #0xBC              /* &ring_tail */
0:  ldxr w23, [x21]                  /* head */
    ldar w24, [x22]                  /* tail (host release-store) */
    sub  w25, w24, w23                /* fill = tail - head */
    cmp  w25, w15
    b.lo urandom_ring_low_bail        /* ring too low */
    and  w26, w23, #(4096 - 1)        /* pos = head & (RING_SIZE - 1) */
    add  w27, w23, w15                /* new head = head + len (wraps via mask
                                       * at the next read; the copy below
                                       * splits at the 4 KiB boundary).
                                       */
    stxr w28, w27, [x21]
    cbnz w28, 0b

    /* Head reserved; lock held. Snapshot ELR_EL1 + SPSR_EL1 into a
     * recovery slot below the EL1 stack frame so the EL1 data abort
     * recovery handler (handle_el1_data_abort_recover, below) can
     * restore them if a subsequent strb faults. A sibling vCPU can
     * munmap the guest buffer in the window between the AT probe and
     * the byte copy; without this slot the resulting EL1 data abort
     * overwrites ELR_EL1 with the strb PC and there is no way to
     * resume EL0 at the post-SVC instruction. Both success exits
     * pop the slot before svc_restore_eret.
     */
    mrs x29, elr_el1
    mrs x30, spsr_el1
    stp x29, x30, [sp, #-16]!

    /* Copy bytes from ring[pos] to buf. len is in [1, 256].
     * w26 holds pos in [0, 4096); writing to w26 above zero-extends
     * into x26, so a plain reg add (no extension) is correct.
     */
    add  x16, x12, #0xC0             /* ring base */
    add  x16, x16, x26                /* ring + pos */
    cmp  x15, #1
    b.ne urandom_copy_loop

    /* Common case: 1-byte read. Single byte transfer. 1-byte reads
     * never wrap (a single byte at pos is always within the ring),
     * so the split-copy logic in urandom_copy_loop is skipped.
     */
.globl urandom_strb_1byte_start
.globl urandom_strb_1byte_end
urandom_strb_1byte_start:
    ldrb w0, [x16]
    strb w0, [x20]
urandom_strb_1byte_end:
    add  sp, sp, #16                 /* pop ELR/SPSR recovery slot */
    mov  x0, #1
    stlr wzr, [x19]                  /* release ring_lock */
    /* x10 still holds the syscall nr loaded by the svc_handler
     * dispatcher; none of the urandom/getrandom fast-path body writes
     * x10, so it remains 63 for read and 278 for getrandom. Use it to
     * pick the matching hit counter without burning a scratch register.
     * RESTORE_GPRS_KEEP_X0 reloads x10 from the saved frame.
     */
    cmp  x10, #63
    b.ne 1f
    COUNTER_INC CB_URANDOM_HIT
    b svc_restore_eret
1:  COUNTER_INC CB_GETRANDOM_HIT
    b svc_restore_eret

urandom_copy_loop:
    /* Bulk + tail copy for len in [2, 256] with split-at-4-KiB wrap
     * handling.
     *
     * Bulk pass moves 16 bytes per ldp/stp on Apple Silicon; tail
     * peels the remaining 0..15 bytes via tbz on the bits of the
     * residue. The wrap split runs the same code twice with rebased
     * dst/src/limit. Unaligned ldp/stp on normal memory is supported
     * by M-series with minimal penalty (one extra cycle when crossing
     * a 64-byte cache line); the small penalty is dwarfed by the win
     * from collapsing the byte loop's ~5 inst/byte into ldp/stp at
     * 16 bytes/cycle peak.
     *
     * handle_el1_data_abort_recover covers a single PC range
     * (urandom_strb_loop_start..urandom_strb_loop_end) that spans both
     * the bulk loop and the tail copies, so any sibling-vCPU munmap
     * mid-copy still routes to the EFAULT recovery path.
     */
    mov  w17, #4096
    sub  w17, w17, w26                /* w17 = 4096 - pos */
    cmp  w15, w17
    csel w17, w15, w17, ls            /* w17 = first segment length */
    /* Wrap-done flag: 0 on the first segment, set to 1 before re-
     * entering for the second segment. With len <= 256 and ring size
     * 4096, exactly one wrap is possible, so the flag guarantees the
     * loop runs at most twice (vs comparing x17 to x15, which would
     * infinitely re-wrap once the segment counter is rebased).
     */
    mov  w14, #0
urandom_copy_segment:
    /* Inputs: x16 = src cursor, x20 = dst cursor, x17 = segment bytes.
     * ldp/stp lack a register-offset form, so we use post-incremented
     * addressing. x16 and x20 advance through the segment; the wrap
     * rebase below recomputes x16 (ring base) and lets x20 keep its
     * post-increment position (exactly where segment 2 must start
     * writing).
     */
    cmp  x17, #16
    b.lo urandom_copy_tail_entry      /* < 16 bytes -> tail only */
    and  x28, x17, #~15               /* bulk byte count = w17 & ~15 */
    add  x28, x16, x28                /* bulk_end = src + bulk_count */
.globl urandom_strb_loop_start
.globl urandom_strb_loop_end
urandom_strb_loop_start:
1:  ldp  x9, x11, [x16], #16
    stp  x9, x11, [x20], #16
    cmp  x16, x28
    b.lo 1b
urandom_copy_tail_entry:
    and  x27, x17, #15                /* tail = segment_len % 16 */
    cbz  x27, urandom_copy_segment_done
    tbz  w27, #3, 2f                  /* 8-byte chunk */
    ldr  x9, [x16], #8
    str  x9, [x20], #8
2:  tbz  w27, #2, 3f                  /* 4-byte chunk */
    ldr  w9, [x16], #4
    str  w9, [x20], #4
3:  tbz  w27, #1, 4f                  /* 2-byte chunk */
    ldrh w9, [x16], #2
    strh w9, [x20], #2
4:  tbz  w27, #0, urandom_copy_segment_done
    ldrb w9, [x16], #1
    strb w9, [x20], #1
urandom_strb_loop_end:
urandom_copy_segment_done:
    cbnz w14, urandom_loop_done       /* second segment already ran */
    cmp  x17, x15                     /* first_copy_len == total? */
    b.eq urandom_loop_done            /* yes: no wrap needed */
    /* Wrap rebase: src goes back to ring base; dst is already at
     * (original buf + first_len) thanks to post-increment, so no
     * rebase needed there. Segment limit becomes the remaining count.
     */
    mov  w14, #1
    add  x16, x12, #0xC0              /* ring base = tpidr_el1 + 0xC0 */
    sub  x17, x15, x17                /* loop limit = remaining */
    b    urandom_copy_segment
urandom_loop_done:
    add  sp, sp, #16                 /* pop ELR/SPSR recovery slot */
    mov  x0, x15
    stlr wzr, [x19]                  /* release ring_lock */
    cmp  x10, #63
    b.ne 1f
    COUNTER_INC CB_URANDOM_HIT
    b svc_restore_eret
1:  COUNTER_INC CB_GETRANDOM_HIT
    b svc_restore_eret

/* Named bail labels: branch targets for every fast-path exit that gives
 * up. Each increments the matching diagnostic counter and routes into
 * the right slow-path predecessor: probe failures jump into the no-
 * clrex tail (no exclusive monitor was opened); ring_low jumps into
 * the clrex tail (the LDXR opened a monitor and the lock is held).
 * Ring wrap is no longer a bail reason now that urandom_copy_loop
 * splits the byte copy at the 4 KiB boundary inline.
 *
 * attn_bail is shared by identity/pgsid/urandom/getrandom because the
 * ATTN check predates any path-specific state setup; routing every
 * attention-set fast path through the same CB_ATTN_BAIL counter and
 * the same handle_svc_0 branch keeps the bail cluster compact.
 */
attn_bail:
    COUNTER_INC CB_ATTN_BAIL
    b handle_svc_0
urandom_fd_oor_bail:
    COUNTER_INC CB_URANDOM_FD_OOR
    b handle_svc_0
urandom_fd_bmiss_bail:
    COUNTER_INC CB_URANDOM_FD_BMISS
    b handle_svc_0
urandom_len_zero_bail:
    COUNTER_INC CB_URANDOM_LEN_ZERO
    b handle_svc_0
urandom_len_over_bail:
    COUNTER_INC CB_URANDOM_LEN_OVER
    b handle_svc_0
urandom_probe_fail_bail:
    COUNTER_INC CB_URANDOM_PROBE_FAIL
    b urandom_slow_no_clrex
urandom_ring_low_bail:
    /* Release the spinlock and clear the exclusive monitor BEFORE the
     * stats-mode counter bump. Otherwise a sibling vCPU waiting on the
     * lock pays for this vCPU's counter cache-line ping-pong while it
     * spins -- the counter write lands on a line the sibling does not
     * need but the lock holder does not release until after the bump.
     * Bailing through urandom_clrex_slow only clears the monitor and
     * drops the lock; it does no further work that depends on the
     * counter slot, so hoisting the unlock above COUNTER_INC is safe.
     */
    clrex
    stlr wzr, [x19]                  /* release ring_lock */
    COUNTER_INC CB_URANDOM_RING_LOW
    b handle_svc_0
    /* SHIM_COUNTER_URANDOM_RING_WRAP (C-side index 6) has no assembly
     * binding now that urandom_copy_loop splits the byte copy at the
     * 4 KiB ring boundary inline. The slot stays in the C enum for
     * ABI stability; a non-zero dump reading flags a regression that
     * re-introduced a wrap bail.
     */

urandom_slow_no_clrex:
    /* Probe-failure bails land here with no exclusive monitor open and
     * no lock held; route into handle_svc_0 so the host's HVC #5
     * sys_read either returns -EFAULT for the bad pointer or fulfills
     * the read normally. The post-lock ring_low bails handle their own
     * clrex + unlock inline so the stats counter bump stays outside the
     * spinlock critical section; they branch straight to handle_svc_0.
     */
    b handle_svc_0

/* getrandom_fast: serve getrandom(buf, len, flags) with len in
 * [1, SHIM_URANDOM_INLINE_LIMIT (256)] and flags in {0, GRND_NONBLOCK
 * (0x1)} by reusing the same urandom ring as the /dev/urandom fast
 * path. Shares the copy + ring epilogue at urandom_strb_1byte_start
 * and urandom_copy_loop (including the 4 KiB wrap split); the success
 * path discriminates GETRANDOM_HIT vs URANDOM_HIT off the syscall
 * number left in x10 by the dispatcher. Any other flag bit set
 * (GRND_RANDOM, GRND_INSECURE, conflicting combinations, or any
 * future kernel flag) falls through to sys_getrandom so the host
 * preserves the full Linux contract.
 */
getrandom_fast:
    mrs x12, tpidr_el1
    ldar w13, [x12]
    cbnz w13, attn_bail

    ldr x15, [sp, #8]                /* saved X1 = len */
    cbz x15, getrandom_len_zero_bail
    cmp x15, #256                     /* SHIM_URANDOM_INLINE_LIMIT */
    b.hi getrandom_len_over_bail

    ldr x16, [sp, #16]               /* saved X2 = flags */
    /* Accept flags == 0 and flags == GRND_NONBLOCK (0x1); both behave
     * identically against our arc4random-backed ring (always non-
     * blocking, always seeded). Any other bit set -- GRND_RANDOM (0x2),
     * GRND_INSECURE (0x4), the invalid combination of the two, or any
     * future kernel flag -- falls through to sys_getrandom so the host
     * preserves the full Linux contract (EINVAL on conflict, etc.).
     */
    cmp x16, #1
    b.hi handle_svc_0

    ldr x20, [sp, #0]                /* saved X0 = buf */
    /* See urandom_read_fast for the probe rationale; same shape, with
     * the single-page skip path so single-page reads pay only one AT.
     */
    sub x16, x15, #1
    adds x17, x20, x16
    b.cs getrandom_probe_fail_bail
    at s1e0w, x20
    isb
    mrs x16, par_el1
    tbnz x16, #0, getrandom_probe_fail_bail
    eor x18, x20, x17
    tst x18, #~0xFFF
    b.eq 7f
    at s1e0w, x17
    isb
    mrs x16, par_el1
    tbnz x16, #0, getrandom_probe_fail_bail
7:

    add x19, x12, #0x1, lsl #12
    add x19, x19, #0xC0              /* &ring_lock */
    mov w18, #1
getrandom_lock_spin:
    swpal w18, w17, [x19]            /* see urandom_lock_spin notes */
    cbnz w17, getrandom_lock_busy
    b getrandom_locked
getrandom_lock_busy:
    yield
    b getrandom_lock_spin

getrandom_locked:
    add x21, x12, #0xB8
    add x22, x12, #0xBC
0:  ldxr w23, [x21]
    ldar w24, [x22]
    sub  w25, w24, w23
    cmp  w25, w15
    b.lo getrandom_ring_low_bail
    and  w26, w23, #(4096 - 1)
    add  w27, w23, w15                /* new head = head + len; wrap handled
                                       * inline by the shared copy epilogue.
                                       */
    stxr w28, w27, [x21]
    cbnz w28, 0b

    mrs x29, elr_el1
    mrs x30, spsr_el1
    stp x29, x30, [sp, #-16]!

    add  x16, x12, #0xC0
    add  x16, x16, x26
    cmp  x15, #1
    b.eq urandom_strb_1byte_start
    b urandom_copy_loop

getrandom_len_zero_bail:
    COUNTER_INC CB_URANDOM_LEN_ZERO
    b handle_svc_0
getrandom_len_over_bail:
    COUNTER_INC CB_URANDOM_LEN_OVER
    b handle_svc_0
getrandom_probe_fail_bail:
    COUNTER_INC CB_URANDOM_PROBE_FAIL
    b urandom_slow_no_clrex
getrandom_ring_low_bail:
    /* Same hoist as urandom_ring_low_bail: drop the lock + clrex first
     * so the counter ping-pong in stats-enabled mode stays outside the
     * spinlock critical section.
     */
    clrex
    stlr wzr, [x19]                  /* release ring_lock */
    COUNTER_INC CB_URANDOM_RING_LOW
    b handle_svc_0

not_svc:
    /* EC=0x18: MSR/MRS / system instruction trap. */
    cmp x10, #0x18
    b.eq handle_sysreg_trap

    /* EC=0x20: Instruction abort from lower EL.
     * W^X demand toggle: when JIT code pages are mapped RW (for writing),
     * instruction fetch fails. Toggle to RX and retry.
     */
    cmp x10, #0x20
    b.eq handle_inst_abort

    /* EC=0x24: Data abort from lower EL.
     * W^X demand toggle: when JIT code pages are mapped RX (for execution),
     * writes fail. Toggle to RW and retry.
     */
    cmp x10, #0x24
    b.eq handle_data_abort

    /* EC=0x3C: BRK from AArch64 lower EL.
     * JIT translators use BRK instructions as trampolines.
     * The guest registers a SIGTRAP handler via rt_sigaction to catch these.
     * Forward to host for signal delivery.
     */
    cmp x10, #0x3C
    b.eq handle_brk

    /* EC=0x25: Data abort taken without a change in Exception level.
     * The only legitimate source today is the urandom fast path: a
     * sibling vCPU can munmap the guest buffer between the AT probe
     * and the EL1 strb, faulting the store. Recover by returning
     * -EFAULT to the guest instead of halting the VM (which is what
     * the EL1-from-EL1 default below would do).
     */
    cmp x10, #0x25
    b.eq handle_el1_data_abort_recover

    /* Unrecognized EC. Check if from EL0 (deliver signal) or EL1 (shim bug).
     * X11 is saved on stack, safe to use as scratch.
     */
    mrs x11, spsr_el1
    and x11, x11, #0xF
    cbnz x11, restore_and_bad   /* EL1 (M>=4): genuine shim bug */
    b handle_el0_fault           /* EL0 (M=0): forward for signal delivery */

/* handle_el1_data_abort_recover: tag a data abort whose faulting PC sits
 * inside the urandom-copy strb region as a recoverable EFAULT.
 *
 * Layout invariants exploited here:
 *   - SAVE_GPRS allocated 256 bytes for THIS (inner) entry on top of
 *     whatever the outer SVC entry already pushed. Dropping that 256
 *     puts SP at the recovery slot urandom_read_fast pushed before
 *     entering the strb region.
 *   - Recovery slot is 16 bytes: [sp+0]=ELR_EL1, [sp+8]=SPSR_EL1.
 *   - The lock at TPIDR_EL1 + 0x10C0 is held by this vCPU at the
 *     time the strb faulted, so release before transferring out.
 *
 * If the fault PC is outside the urandom strb ranges this is a genuine
 * shim bug; fall back to restore_and_bad.
 */
handle_el1_data_abort_recover:
    mrs x11, elr_el1
    adr x12, urandom_strb_1byte_start
    cmp x11, x12
    b.lo 2f
    adr x12, urandom_strb_1byte_end
    cmp x11, x12
    b.lo 1f                      /* in [1byte_start, 1byte_end) */
2:  adr x12, urandom_strb_loop_start
    cmp x11, x12
    b.lo restore_and_bad
    adr x12, urandom_strb_loop_end
    cmp x11, x12
    b.hs restore_and_bad
1:
    /* Drop the inner SAVE_GPRS frame; SP back at the urandom recovery slot. */
    add sp, sp, #256
    /* Pop the saved EL0 return state. ldp/post-index restores SP to the
     * outer SAVE_GPRS frame top so svc_restore_eret's RESTORE_GPRS_KEEP_X0
     * pulls the original EL0 GPR values.
     */
    ldp x9, x10, [sp], #16
    msr elr_el1, x9
    msr spsr_el1, x10
    /* Release the urandom ring_lock at TPIDR_EL1 + 0x10C0 (held by this
     * vCPU since urandom_locked acquired it before the byte copy).
     */
    mrs x11, tpidr_el1
    add x11, x11, #0x1, lsl #12
    add x11, x11, #0xC0
    stlr wzr, [x11]
    /* Drop any open exclusive monitor (the byte loop does not hold one
     * after the head STXR retired, but CLREX is cheap and removes a
     * latent footgun for future readers of this code).
     */
    clrex
    /* Linux EFAULT = 14; the kernel returns -14 to userspace. */
    mov x0, #-14
    b svc_restore_eret

/* handle_sysreg_trap: EC=0x18: MSR/MRS / system instruction
 *
 * MRS reads (Direction=1): forward to host via HVC #7 to read the system
 * register value (e.g., ID_AA64MMFR1_EL1, CNTFRQ_EL0).
 * MSR/SYS writes (Direction=0): execute IC IALLU as safety net for cache
 * maintenance instructions that trap despite SCTLR.UCI=1.
 */
handle_sysreg_trap:
    tst x9, #1
    b.eq 4f

    /* MRS read: host returns register value in X0 */
    hvc #7
    ubfx x10, x9, #5, #5     /* Rt = ISS[9:5] */
    cmp x10, #31
    b.eq 3f                   /* XZR -> discard */
    lsl x10, x10, #3
    str x0, [sp, x10]         /* frame[Rt] = value */
    b 3f

4:  /* System instruction: trapped cache/data operations.
     * DC ZVA (Data Cache Zero by VA) is trapped when HCR_EL2.TDZ=1 despite
     * SCTLR.DZE=1. DC ZVA zeroes a cache-line-sized block (64 bytes on Apple
     * Silicon). JIT translators and libc use it as fast memset(0).
     * Failure to emulate leaves stale data.
     *
     * DC CVAU, IC IVAU, and other cache maintenance instructions trap here
     * despite SCTLR.UCI=1 (HVF sets HCR_EL2.TPU=1). The shim executes IC IALLU
     * as safety net for I-cache coherency after any of these.
     *
     * ISS encoding for system instructions:
     *   Op0[21:20] Op2[19:17] Op1[16:14] CRn[13:10] Rt[9:5] CRm[4:1] Dir[0]
     * DC ZVA: Op0=01 Op2=001 Op1=011 CRn=0111 CRm=0100 Dir=0
     *   = (01 << 20) | (001 << 17) | (011 << 14) | (0111 << 10) | (0100 << 1) | 0
     *   = 0x12DC08 + (Rt << 5)
     */

    /* Check for DC ZVA: extract fields around Rt and compare.
     * DC ZVA ISS: Op0[21:20]=01 Op2[19:17]=001 Op1[16:14]=011
     *             CRn[13:10]=0111 Rt[9:5]=xxxxx CRm[4:1]=0100 Dir[0]=0
     * The code checks ISS[21:10] = 0x4B7 and ISS[4:0] = 0x08.
     */
    ubfx x10, x9, #10, #12        /* x10 = ISS[21:10] */
    mov x11, #0x4B7                /* Expected upper field value */
    cmp x10, x11
    b.ne 5f
    and x10, x9, #0x1F            /* x10 = ISS[4:0] */
    cmp x10, #0x08                 /* CRm=0100,Dir=0 -> 01000 = 0x08 */
    b.ne 5f                        /* Not DC ZVA -> skip to cache maint */

    /* DC ZVA emulation: zero 64 bytes at aligned address from Xt.
     * Extract Rt register number and load the VA from saved frame.
     */
    ubfx x10, x9, #5, #5          /* Rt = ISS[9:5] */
    cmp x10, #31
    b.eq 6f                        /* XZR -> address is 0, skip (nop) */
    lsl x10, x10, #3              /* Byte offset in frame */
    ldr x11, [sp, x10]            /* x11 = VA from Xt */
    and x11, x11, #~63            /* Align down to 64-byte cache line */
    /* Zero 64 bytes using four STP pairs */
    stp xzr, xzr, [x11, #0]
    stp xzr, xzr, [x11, #16]
    stp xzr, xzr, [x11, #32]
    stp xzr, xzr, [x11, #48]
6:  /* Forward to host for counting, then I-cache maintenance */

5:  /* Pass the source register value to host. Cache maintenance instructions
     * ignore it, but MSR writes (notably TPIDR_EL0 for userspace TLS setup)
     * need the original Xt value.
     */
    ubfx x10, x9, #5, #5          /* Rt = ISS[9:5] */
    cmp x10, #31
    b.eq 7f
    lsl x10, x10, #3
    ldr x0, [sp, x10]
    b 8f
7:  mov x0, #0
8:  hvc #12
    ic iallu
    dsb ish
    isb

3:  /* Advance ELR_EL1 past the trapped instruction */
    mrs x10, elr_el1
    add x10, x10, #4
    msr elr_el1, x10
    b restore_eret

/* handle_inst_abort: EC=0x20: Instruction abort from lower EL
 *
 * Two cases:
 * 1. Permission fault (IFSC[5:2]=0x03): W^X demand toggle for JIT.
 *    Code pages are initially RW; execution triggers permission fault.
 *    Ask host to flip to RX via HVC #9, flush TLB, retry.
 * 2. Translation fault (IFSC[5:2]=0x01) or other non-permission fault: Address
 *    not mapped in page tables. A real Linux kernel delivers SIGSEGV
 *    (si_code=SEGV_MAPERR) to the process. JIT translators may use SIGSEGV for
 *    fault-driven lazy translation: when code branches to an untranslated
 *    address, the translation fault triggers SIGSEGV, the handler translates
 *    the block, then resumes execution. Forward to host via HVC #11 for signal
 *    delivery.
 */
handle_inst_abort:
    and x11, x9, #0x3C       /* IFSC[5:2] */
    cmp x11, #0x0C            /* Permission fault? (0b0011xx) */
    b.eq 1f

    /* Non-permission fault (translation, access flag, etc.) from EL0.
     * Restore all GPRs and forward to host for SIGSEGV delivery.
     * x9 still holds ESR_EL1 for the host to decode fault type.
     */
    b handle_el0_fault

1:  mrs x0, far_el1           /* Faulting address */
    mov x1, #0                /* Type 0 = instruction fault -> flip to RX */
    hvc #9
    cmp x8, #2
    b.eq exec_drop_frame
    b tlbi_restore_eret

/* handle_data_abort: EC=0x24: Data abort from lower EL
 *
 * Three cases:
 * 1. Write permission fault (WnR=1, DFSC[5:2]=0x03): W^X toggle.
 *    Code page is RX; JIT write triggers permission fault. Flip to RW.
 * 2. Read/write translation fault (DFSC[5:2]=0x01): Address not mapped.
 *    Deliver SIGSEGV (SEGV_MAPERR) via host. Programs may use SIGSEGV
 *    handlers for lazy allocation or guard pages.
 * 3. Read permission fault (WnR=0, DFSC[5:2]=0x03): Permission denied.
 *    Deliver SIGSEGV (SEGV_ACCERR) via host.
 */
handle_data_abort:
    and x11, x9, #0x3C       /* DFSC[5:2] */
    cmp x11, #0x0C            /* Permission fault? (0b0011xx) */
    b.ne handle_el0_fault     /* Translation/other fault -> SIGSEGV */

    tst x9, #(1 << 6)        /* WnR bit: 1=write, 0=read */
    b.eq handle_el0_fault     /* Read permission fault -> SIGSEGV */

    mrs x0, far_el1           /* Faulting address */
    mov x1, #1                /* Type 1 = write fault -> flip to RW */
    hvc #9
    cmp x8, #2
    b.eq exec_drop_frame
    b tlbi_restore_eret

/* handle_el0_fault: Deliver SIGSEGV/SIGILL for EL0 faults
 *
 * Translation faults, access flag faults, read permission faults, and undefined
 * instructions from EL0 code should deliver the appropriate signal (SIGSEGV or
 * SIGILL) to the guest process. This matches real Linux kernel behavior: the
 * process gets a signal and can either handle it (e.g., lazy JIT translation
 * via SIGSEGV) or die from default disposition.
 *
 * Restore all GPRs from the stack frame (host needs the original EL0 state for
 * the signal frame), then forward to host via HVC #11. The host decodes the EC
 * from ESR_EL1: EC=0x20/0x24 -> SIGSEGV,
 * EC=0x00 (undefined) or other -> SIGILL.
 */
handle_el0_fault:
    /* Load EL0 GPRs from the saved frame WITHOUT popping it. The frame
     * must stay live across HVC #11 so the post-HVC dispatch below can
     * restore X3-X29 via the frameless RESTORE_GPRS_KEEP_SIGFRAME tail
     * after the host has overwritten X0/X1/X2/X30 via hv_vcpu_set_reg
     * (signal_deliver) and the inline TLBI handlers have clobbered
     * X11/X12/X13 as scratch.
     */
    LOAD_GPRS

    /* Forward to host. Host paths:
     *   (1) signal delivery -> writes X0=signum, X1=siginfo*, X2=ucontext*,
     *       X30=sa_restorer via hv_vcpu_set_reg; host leaves X8=0.
     *   (2) lazy MAP_NORESERVE materialize -> populates cpu_tlbi_req via
     *       guest_extend_page_tables / guest_update_perms / friends, then
     *       calls tlbi_request_emit_to_vcpu(vcpu) which writes
     *       X8/X9/X10/X11 per the same wire protocol the SVC #5 epilogue
     *       uses. Single-shot RVAE1IS via X8=4 is included.
     *
     * The dispatch below mirrors handle_svc_0's TLBI dispatch. exec_drop
     * (X8=2) is rejected on this path (the host never sets it here); fall
     * through to the conservative full flush rather than silently skip.
     */
    hvc #11

    cbz x8, .Lel0_fault_eret_only
    cmp x8, #1
    b.eq .Lel0_fault_tlbi_full
    cmp x8, #3
    b.eq .Lel0_fault_tlbi_sel
    cmp x8, #4
    b.eq .Lel0_fault_tlbi_rvae
    /* Unknown X8: conservative broadcast + I-cache flush. */
    mov x11, #1
    b .Lel0_fault_tlbi_full

.Lel0_fault_tlbi_full:
    /* Broadcast TLB + conditional I-cache flush. X11=0 skips IC IALLU. */
    dsb ishst
    tlbi vmalle1is
    dsb ish
    cbz x11, .Lel0_fault_full_no_ic
    ic iallu
    dsb ish
.Lel0_fault_full_no_ic:
    isb
    b .Lel0_fault_eret_restore

.Lel0_fault_tlbi_sel:
    /* Selective per-page TLBI VAE1IS loop. X9 = page-aligned VA,
     * X10 = page count (1..TLBI_SELECTIVE_MAX_PAGES). X11 carries the
     * I-cache hint on entry; save into X13 before the loop clobbers X11.
     * ubfx (not plain lsr) pins the VA to the 44-bit [43:0] field so a
     * future LPA2 / TTL / tagged-address change cannot leak high bits
     * into the operand's TTL [47:44] or ASID [63:48] fields. */
    cbz x10, .Lel0_fault_eret_only
    mov x13, x11
    ubfx x11, x9, #12, #44
    mov x12, x10
    dsb ishst
4:  tlbi vae1is, x11
    add x11, x11, #1
    subs x12, x12, #1
    b.ne 4b
    dsb ish
    cbz x13, .Lel0_fault_sel_no_ic
    ic iallu
    dsb ish
.Lel0_fault_sel_no_ic:
    isb
    b .Lel0_fault_eret_restore

.Lel0_fault_tlbi_rvae:
    /* Single-shot TLBI RVAE1IS (FEAT_TLBIRANGE). X9 carries the pre-encoded
     * operand (baddr | NUM<<39 | SCALE<<44 | TG=01<<46); X11 the I-cache
     * hint. */
    dsb ishst
    tlbi rvae1is, x9
    dsb ish
    cbz x11, .Lel0_fault_rvae_no_ic
    ic iallu
    dsb ish
.Lel0_fault_rvae_no_ic:
    isb
    /* fall through */

.Lel0_fault_eret_restore:
    /* TLBI clobbered X11/X12/X13 (and possibly X9/X10 in the selective
     * path). Reload X3-X29 from the saved frame so the EL0 retry sees the
     * same scratch state as pre-fault; skip X0/X1/X2/X30 in case
     * signal delivery set them. On lazy materialization and conservative
     * unknown-X8 fallback paths, the skipped registers still match the frame.
     */
    RESTORE_GPRS_KEEP_SIGFRAME
    eret

.Lel0_fault_eret_only:
    /* X8 == 0: no TLBI requested. signal-delivery and no-delivery paths
     * land here after the host wrote X8 as the post-HVC protocol value.
     * Reload X3-X29 so EL0 sees the pre-fault scratch state, while keeping
     * X0/X1/X2/X30 live for a materialized signal handler.
     */
    RESTORE_GPRS_KEEP_SIGFRAME
    eret

/* Shared exit paths for exception handlers
 */
tlbi_restore_eret:
    /* Single-page TLB flush after a W^X permission toggle. Only one page
     * (the one that triggered the HVC #9 fault, FAR_EL1 still in scope)
     * changed permissions, so per-VA TLBI VAE1IS is sufficient and avoids
     * blowing away unrelated TLB entries. The HVC #9 host handler does not
     * raise further exceptions, so FAR_EL1 is preserved.
     */
    mrs x0, far_el1
    /* TLBI VAE1IS operand: VA[55:12] held in bits [43:0]. ubfx pins the
     * 44-bit width so future LPA2 / TTL / tagged-address support cannot
     * leak VA bits into the TTL [47:44] or ASID [63:48] operand fields.
     */
    ubfx x0, x0, #12, #44
    dsb ishst
    tlbi vae1is, x0
    dsb ish
    ic iallu
    dsb ish
    isb
    /* Fall through to restore_eret */

restore_eret:
    /* Restore all GPRs from saved frame and return to EL0 */
    RESTORE_GPRS
    eret

restore_and_bad:
    RESTORE_GPRS

    /* Determine correct vector offset for bad_exception reporting.
     * After restore, X5 holds the EL0 caller's value, not the vector.
     * Check SPSR_EL1.M[3:0]: 0=EL0t (Lower EL -> 0x400), 4/5=EL1 (-> 0x200).
     */
    mrs x5, spsr_el1
    and x5, x5, #0xF
    cmp x5, #0
    mov x5, #0x400           /* Assume Lower EL (EL0 -> vec 0x400) */
    b.eq bad_exception
    mov x5, #0x200           /* Current EL (EL1 -> vec 0x200) */
    b bad_exception

/* handle_brk: BRK instruction from EL0 (EC=0x3C)
 *
 * JIT translators use BRK instructions as patching trampolines
 * and debug hooks. The guest registers a SIGTRAP
 * handler via rt_sigaction. The shim restores all GPRs and forwards to
 * the host via HVC #10 for signal delivery.
 *
 * Host reads ESR_EL1 (BRK immediate), ELR_EL1 (BRK PC), and
 * current GPRs from the vCPU. If a SIGTRAP handler is registered,
 * the host builds a signal frame and redirects PC to the handler.
 * Otherwise, the host performs the default SIGTRAP action (terminate).
 */
handle_brk:
    /* Restore all GPRs from stack frame (host needs current state) */
    RESTORE_GPRS

    /* Forward to host for SIGTRAP delivery */
    hvc #10

    /* Host has set up signal frame (if handler registered) or
     * flagged for termination. Either way, ERET to new PC.
     */
    eret

/* handle_svc_0: Linux syscall forwarding
 *
 * Restore ALL EL0 registers from the stack frame before HVC #5,
 * so the host can read X8 (syscall nr) and X0-X5 (args) directly
 * from vCPU registers. The host writes the result to X0 and
 * resumes the vCPU. The shim then ERET to EL0 with X0=result and all
 * other registers (X1-X30) in their original EL0 state.
 */
handle_svc_0:
    /* Restore all 31 GPRs to their EL0 values, but keep the saved frame
     * intact: after HVC #5 the post-syscall restore re-reads X1-X30 from
     * it (the host only writes back X0).
     */
    LOAD_GPRS

    /* Forward to host. Host will:
     *   1. Read X8 (syscall nr) and X0-X5 (args)
     *   2. Execute the syscall
     *   3. Write result to X0
     *   4. Set X8 to indicate the post-syscall request:
     *        0 = no TLB flush
     *        1 = broadcast TLBI VMALLE1IS
     *        2 = execve replaced register state (drop frame + flush)
     *        3 = selective TLBI VAE1IS over X10 pages starting at X9
     *        4 = single-shot TLBI RVAE1IS with encoded operand in X9
     *   5. Resume vCPU (execution continues below)
     */
    hvc #5

    /* Dispatch on X8. Encoded so the common case (X8 == 0, no flush) hits
     * the cbz fast path; the other branches sort by frequency thereafter.
     */
    cbz x8, 1f
    cmp x8, #1
    b.eq tlbi_full
    cmp x8, #3
    b.eq tlbi_selective
    cmp x8, #4
    b.eq tlbi_range_large
    cmp x8, #2
    b.eq exec_drop_frame
    /* Unknown X8: be conservative, broadcast, flush I-cache, and continue. */
    mov x11, #1

tlbi_full:
    /* Broadcast TLB + (conditional) I-cache flush. Used for page-table edits
     * whose affected range exceeds the selective cap, or any time the host
     * could not bound the change. X11 carries the I-cache hint: non-zero
     * means the host introduced executable content visible to EL0 (new X
     * mapping, NX->X mprotect, lazy materialize from a region that may
     * include exec), so the shim must IC IALLU; zero means a data-only
     * PT change and the I-cache invalidation is skipped.
     */
    dsb ishst
    tlbi vmalle1is
    dsb ish
    cbz x11, .Ltlbi_full_skip_ic
    ic iallu
    dsb ish
.Ltlbi_full_skip_ic:
    isb
    b svc_restore_eret

tlbi_selective:
    /* Selective TLBI VAE1IS loop.
     *   x9  = page-aligned VA of the first page to invalidate
     *   x10 = page count (1..TLBI_SELECTIVE_MAX_PAGES, see core/guest.h)
     *   x11 = I-cache hint (see tlbi_full above)
     * TLBI VAE1IS takes a Xt operand of (VA[55:12] | (ASID << 48)). The
     * guest runs single-ASID at EL0, so just shift the VA right by 12.
     * Issue all TLBI ops, then DSB ISH + (conditional) IC IALLU + DSB + ISB.
     *
     * Defensive: if x10 == 0, skip the loop. The per-vCPU host-side
     * accumulator (cpu_tlbi_req in core/guest.h) never sets pages == 0
     * alongside kind == TLBI_RANGE, but if a future helper bug or a stray
     * write ever produced the pair X8=3, X10=0, the subs x12, x12, #1
     * below would underflow to 0xFFFFFFFFFFFFFFFF and the b.ne would loop
     * ~2^64 iterations, hanging this vCPU. Cheap guard.
     *
     * x11 is the I-cache hint on entry but the per-page TLBI operand is
     * also computed from x9 -- save the hint into x13 before clobbering.
     */
    cbz x10, 1f
    mov x13, x11              /* x13 = saved I-cache hint */
    /* TLBI VAE1IS operand: VA[55:12] held in bits [43:0]. ubfx pins the
     * 44-bit width so future LPA2 / TTL / tagged-address support cannot
     * leak VA bits into the TTL [47:44] or ASID [63:48] operand fields. */
    ubfx x11, x9, #12, #44    /* x11 = VA[55:12] (current page operand) */
    mov x12, x10              /* x12 = remaining page counter */
    dsb ishst
3:  tlbi vae1is, x11
    add x11, x11, #1          /* next page (operand is in 4 KiB units) */
    subs x12, x12, #1
    b.ne 3b
    dsb ish
    cbz x13, .Ltlbi_sel_skip_ic
    ic iallu
    dsb ish
.Ltlbi_sel_skip_ic:
    isb
    b svc_restore_eret

tlbi_range_large:
    /* Single-shot TLBI RVAE1IS (FEAT_TLBIRANGE, ARMv8.4+). The host has
     * encoded the full operand in X9: baddr (VA >> 12), TTL=0, NUM in bits
     * [43:39], SCALE in bits [45:44], ASID=0. One instruction covers up to
     * TLBI_RVAE_MAX_PAGES. X11 carries the I-cache hint as in tlbi_full /
     * tlbi_selective.
     */
    dsb ishst
    tlbi rvae1is, x9
    dsb ish
    cbz x11, .Ltlbi_rvae_skip_ic
    ic iallu
    dsb ish
.Ltlbi_rvae_skip_ic:
    isb
    b svc_restore_eret

svc_restore_eret:
1:
    /* Restore all guest registers except X0, which now holds the syscall
     * return value.  Linux preserves X1-X30, including X8.
     *
     * Named alias for the cross-function jump from the identity fast
     * path in svc_handler. A bare 'b 1f' from up there would resolve
     * to the next forward '1:' -- which sits inside handle_inst_abort
     * -- and silently re-route the identity result into a W^X toggle.
     * Caught the hard way during the prior P2 attempt; keep the
     * named symbol to make the intent explicit.
     */
    RESTORE_GPRS_KEEP_X0

    /* Return to EL0. X0 now holds the syscall return value,
     * X1-X30 retain their original EL0 values.
     */
    eret

exec_drop_frame:
    tlbi vmalle1is
    dsb ish
    isb
    ic iallu
    dsb ish
    isb
    add sp, sp, #256
    eret
