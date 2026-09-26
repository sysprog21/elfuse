/*
 * Signal delivery
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux aarch64 signal structures and delivery API. Matches the kernel's
 * arch/arm64/kernel/signal.c:setup_rt_frame() layout so that musl's
 * __restore_rt -> rt_sigreturn (SYS 139) can correctly restore state.
 */

#pragma once

#include <stddef.h>

#include <Hypervisor/Hypervisor.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/time.h>
#include "core/guest.h"
#include "linux-limits.h"

/* Linux signal numbers (1-based, matching kernel). */
#define LINUX_SIGHUP 1
#define LINUX_SIGINT 2
#define LINUX_SIGQUIT 3
#define LINUX_SIGILL 4
#define LINUX_SIGTRAP 5
#define LINUX_SIGABRT 6
#define LINUX_SIGBUS 7
#define LINUX_SIGFPE 8
#define LINUX_SIGKILL 9
#define LINUX_SIGUSR1 10
#define LINUX_SIGSEGV 11
#define LINUX_SIGUSR2 12
#define LINUX_SIGPIPE 13
#define LINUX_SIGALRM 14
#define LINUX_SIGTERM 15
#define LINUX_SIGSTKFLT 16
#define LINUX_SIGCHLD 17
#define LINUX_SIGCONT 18
#define LINUX_SIGSTOP 19
#define LINUX_SIGTSTP 20
#define LINUX_SIGTTIN 21
#define LINUX_SIGTTOU 22
#define LINUX_SIGURG 23
#define LINUX_SIGXCPU 24
#define LINUX_SIGXFSZ 25
#define LINUX_SIGVTALRM 26
#define LINUX_SIGPROF 27
#define LINUX_SIGWINCH 28
#define LINUX_SIGIO 29
#define LINUX_SIGPWR 30
#define LINUX_SIGSYS 31

#define LINUX_SIGRTMIN 32
#define LINUX_NSIG 64

/* Linux sigaction flags. */
#define LINUX_SA_SIGINFO 0x00000004
#define LINUX_SA_NOCLDWAIT 0x00000002
#define LINUX_SA_ONSTACK 0x08000000
#define LINUX_SA_RESTART 0x10000000
#define LINUX_SA_NODEFER 0x40000000
#define LINUX_SA_RESETHAND 0x80000000U

/* SIG_DFL and SIG_IGN as handler addresses */
#define LINUX_SIG_DFL 0ULL
#define LINUX_SIG_IGN 1ULL

/* Signal mask operations. */
#define LINUX_SIG_BLOCK 0
#define LINUX_SIG_UNBLOCK 1
#define LINUX_SIG_SETMASK 2

/* Linux sigaction (kernel-style, aarch64). */
/* The kernel's struct sigaction for aarch64 (from
 * include/uapi/asm-generic/signal.h): sa_handler or sa_sigaction (8 bytes)
 *   sa_flags                    (8 bytes on LP64)
 *   sa_restorer                 (8 bytes)
 *   sa_mask                     (8 bytes, single uint64_t for 64 signals)
 */
#ifdef sa_handler
#undef sa_handler /* macOS <signal.h> defines this as a macro */
#endif
typedef struct {
    uint64_t sa_handler; /* Handler address (or SIG_DFL=0 / SIG_IGN=1) */
    uint64_t sa_flags;
    uint64_t sa_restorer; /* __restore_rt trampoline (calls rt_sigreturn) */
    uint64_t sa_mask;     /* Blocked signals during handler execution */
} linux_sigaction_t;

/* Default signal dispositions. */
typedef enum {
    SIG_DISP_TERM, /* Terminate the process */
    SIG_DISP_IGN,  /* Ignore the signal */
    SIG_DISP_CORE, /* Terminate; core files are not generated */
    SIG_DISP_STOP, /* Stop the process (not supported, treat as ignore) */
    SIG_DISP_CONT, /* Continue the process (not supported, treat as ignore) */
} sig_disposition_t;

/* Linux siginfo_t (aarch64, 128 bytes). */
typedef struct {
    int32_t si_signo, si_errno, si_code, _pad0;

    /* Common Linux siginfo fields on aarch64. The union payload starts at
     * offset 16; queued RT signals carry sigval at offset 24.
     */
    int32_t si_pid, si_uid;
    uint64_t si_value;
    uint8_t _pad[128 - 32]; /* Pad to 128 bytes total */
} linux_siginfo_t;

/* si_code values */
#define LINUX_SI_USER 0

/* si_code values for SIGTRAP */
#define LINUX_TRAP_BRKPT 1 /* Process breakpoint (BRK instruction) */

/* si_code values for SIGILL */
#define LINUX_ILL_ILLOPC 1 /* Illegal opcode */

/* si_code values for SIGSEGV */
#define LINUX_SEGV_MAPERR 1 /* Address not mapped to object */
#define LINUX_SEGV_ACCERR 2 /* Invalid permissions for mapped object */

/* Linux sigcontext (aarch64). From arch/arm64/include/uapi/asm/sigcontext.h
 * Size of the sigcontext extension area, matching Linux. Named rather than
 * spelled inline because build_sigcontext_reserved's contract is stated against
 * it: the running offset that walks the record chain is only provably in bounds
 * against a bound the prover can see.
 */
#define SIGCONTEXT_RESERVED_BYTES 4096

typedef struct {
    uint64_t fault_address;
    uint64_t regs[31]; /* X0-X30 */
    uint64_t sp;       /* SP_EL0 */
    uint64_t pc;       /* ELR_EL1 at time of signal */
    uint64_t pstate;   /* SPSR_EL1 at time of signal */
    /* Extension space for FPSIMD, ESR, SVE contexts */
    uint8_t __reserved[SIGCONTEXT_RESERVED_BYTES] __attribute__((aligned(16)));
} linux_sigcontext_t;

/* Linux stack_t and sigaltstack constants. */
#define LINUX_SS_ONSTACK 1 /* Currently executing on altstack */
#define LINUX_SS_DISABLE 2 /* Altstack is disabled */

typedef struct {
    uint64_t ss_sp;
    int32_t ss_flags, _pad;
    uint64_t ss_size;
} linux_stack_t;

/* Linux ucontext_t (aarch64). */
typedef struct {
    uint64_t uc_flags;
    uint64_t uc_link; /* Pointer to next ucontext (always 0) */
    linux_stack_t uc_stack;
    uint64_t uc_sigmask;   /* Signal mask to restore on sigreturn */
    uint8_t _pad[128 - 8]; /* Pad __reserved in kernel to 1024 bits */
    uint8_t _align_pad[8]; /* Align uc_mcontext to Linux's 16-byte boundary */
    linux_sigcontext_t uc_mcontext;
} linux_ucontext_t;

/* Linux rt_sigframe (pushed onto guest stack). From arch/arm64/kernel/signal.c:
 * this is what setup_rt_frame() builds.
 */
typedef struct {
    linux_siginfo_t info;
    linux_ucontext_t uc;
} linux_rt_sigframe_t;

/* Field offsets against arch/arm64 Linux, which is what makes rt_sigreturn
 * work: musl and glibc both return through __restore_rt, which reads this frame
 * back at these exact offsets. A silent drift here restores garbage into the
 * guest's registers, and no test would name the struct that caused it.
 *
 * The values are derived, not observed. sigcontext is fault_address at 0,
 * regs[31] at 8 through 256, sp 256, pc 264, pstate 272; __reserved carries
 * __attribute__((aligned(16))), so it starts at 288 rather than 280. ucontext
 * is uc_flags 0, uc_link 8, uc_stack 16 (stack_t is 24 bytes), uc_sigmask 40,
 * then 120 bytes of __unused reaching 168, and uc_mcontext is 16-byte aligned
 * so it starts at 176. rt_sigframe puts uc after a 128-byte siginfo.
 *
 * sigframe.h proves where the frame lands; this pins what is inside it, which
 * is the half that proof deliberately does not reach.
 */
_Static_assert(sizeof(linux_siginfo_t) == 128, "siginfo_t is 128 bytes");
_Static_assert(sizeof(linux_stack_t) == 24, "stack_t is 24 bytes");
_Static_assert(offsetof(linux_sigcontext_t, regs) == 8, "sigcontext.regs");
_Static_assert(offsetof(linux_sigcontext_t, sp) == 256, "sigcontext.sp");
_Static_assert(offsetof(linux_sigcontext_t, pc) == 264, "sigcontext.pc");
_Static_assert(offsetof(linux_sigcontext_t, pstate) == 272,
               "sigcontext.pstate");
_Static_assert(offsetof(linux_sigcontext_t, __reserved) == 288,
               "sigcontext.__reserved is 16-byte aligned, so 288 not 280");
_Static_assert(offsetof(linux_ucontext_t, uc_link) == 8, "ucontext.uc_link");
_Static_assert(offsetof(linux_ucontext_t, uc_stack) == 16, "ucontext.uc_stack");
_Static_assert(offsetof(linux_ucontext_t, uc_sigmask) == 40,
               "ucontext.uc_sigmask");
_Static_assert(offsetof(linux_ucontext_t, uc_mcontext) == 176,
               "ucontext.uc_mcontext is 16-byte aligned, so 176 not 168");
_Static_assert(offsetof(linux_rt_sigframe_t, uc) == 128,
               "rt_sigframe.uc follows a 128-byte siginfo");

/* RT signal queue. Maximum queued instances per RT signal. POSIX says at least
 * _POSIX_SIGQUEUE_MAX (32); Linux defaults to ~1024 per user.
 */
#define RT_SIGQUEUE_MAX 32
#define RT_SIGNAL_COUNT \
    (LINUX_NSIG - LINUX_SIGRTMIN + 1) /* 33 signals: 32-64 */

/* The gap before si_ptr is a named member rather than padding the compiler
 * inserts. Storing a value into a struct leaves its padding unspecified (C11
 * 6.2.6.1), and these are assigned whole, from signal_default_info's compound
 * literal among others, so the four bytes there would carry whatever the host
 * stack held. signal_get_state then memcpy's the array into the fork snapshot
 * and writes it to the IPC socket, which is 4 KiB of indeterminate host memory
 * handed to the child across 1056 entries. Named, the field is copied as a
 * value like any other and starts zero everywhere the struct does.
 */
typedef struct {
    int signum;
    int32_t si_code, si_pid;
    uint32_t si_uid;
    int32_t si_int;
    uint32_t _pad;
    uint64_t si_ptr;
} signal_rt_info_t;

_Static_assert(sizeof(signal_rt_info_t) ==
                   sizeof(int32_t) * 6 + sizeof(uint64_t),
               "signal_rt_info_t has padding the fork snapshot would leak");

/* One pending-signal set. Linux keeps two of these per task: the thread's
 * private set (task->pending, targeted by tgkill/tkill) and the thread-group
 * shared set (signal->shared_pending, targeted by kill). elfuse mirrors that:
 * signal_state_t holds one shared instance and each thread_entry_t holds its
 * own private instance. Delivery drains the current thread's private set first,
 * then the shared set.
 */
typedef struct {
    _Atomic uint64_t pending; /* Bitmask of pending signals in this set */
    /* Standard signal metadata: Linux coalesces signals 1-31, but preserves one
     * siginfo payload for the pending instance.
     */
    bool std_info_valid[LINUX_SIGRTMIN - 1];
    signal_rt_info_t std_info[LINUX_SIGRTMIN - 1];

    /* RT signal queue: count of pending instances per signal. Standard signals
     * (1-31) use the pending bitmask plus std_info[]. RT signals (32-64) are
     * queued: each instance is tracked separately.
     */
    int rt_queue[RT_SIGNAL_COUNT];
    uint8_t rt_head[RT_SIGNAL_COUNT];
    signal_rt_info_t rt_info[RT_SIGNAL_COUNT][RT_SIGQUEUE_MAX];
} signal_pending_t;

/* Signal state. */
typedef struct {
    linux_sigaction_t actions[LINUX_NSIG]; /* Per-signal handler state */
    signal_pending_t shared;               /* Process-directed pending set */
    _Atomic uint64_t blocked;              /* Bitmask of blocked signals */
    uint64_t saved_blocked;                /* Original mask before sigsuspend */
    bool saved_blocked_valid;              /* True if saved_blocked is set */
    linux_stack_t altstack; /* Alternate signal stack (sigaltstack) */
    bool on_altstack;       /* True if currently delivering on altstack */
} signal_state_t;

/* Plain fork-IPC representation of signal state. */
typedef struct {
    uint64_t pending;
    bool std_info_valid[LINUX_SIGRTMIN - 1];
    signal_rt_info_t std_info[LINUX_SIGRTMIN - 1];
    int rt_queue[RT_SIGNAL_COUNT];
    uint8_t rt_head[RT_SIGNAL_COUNT];
    signal_rt_info_t rt_info[RT_SIGNAL_COUNT][RT_SIGQUEUE_MAX];
} signal_pending_snapshot_t;

typedef struct {
    linux_sigaction_t actions[LINUX_NSIG];
    signal_pending_snapshot_t shared;
    uint64_t blocked;
    uint64_t saved_blocked;
    bool saved_blocked_valid;
    linux_stack_t altstack;
    bool on_altstack;
} signal_state_snapshot_t;

/* The snapshot mirrors signal_state_t with the two atomic members demoted to
 * plain types, and signal_get_state/signal_set_state copy it field by field.
 * Nothing in either direction makes the compiler notice a field added to one
 * and not the other, so tie the two together by size: guest.h already asserts
 * that _Atomic uint64_t is laid out like uint64_t, which is what makes these
 * two equal in the first place.
 */
_Static_assert(sizeof(signal_state_snapshot_t) == sizeof(signal_state_t),
               "signal_state_snapshot_t drifted from signal_state_t");
_Static_assert(sizeof(signal_pending_snapshot_t) == sizeof(signal_pending_t),
               "signal_pending_snapshot_t drifted from signal_pending_t");

/* The one definition of how a pending bitmask is reached.
 *
 * The field is _Atomic only so the lock-free scan in thread_pending_union can
 * read it without a data race; every mutator runs under sig_lock, which is the
 * whole ordering requirement, so relaxed is correct. Going through these rather
 * than the plain compound operators keeps the order stated: `p->pending |= bit`
 * on an _Atomic object compiles to a seq_cst read-modify-write, which buys
 * ordering nothing here needs. Declared here rather than in signal.c so
 * thread.c reaches the per-thread set the same way.
 */
static inline uint64_t pending_load(const _Atomic uint64_t *p)
{
    return atomic_load_explicit(p, memory_order_relaxed);
}

static inline void pending_store(_Atomic uint64_t *p, uint64_t v)
{
    atomic_store_explicit(p, v, memory_order_relaxed);
}

static inline void pending_or(_Atomic uint64_t *p, uint64_t bits)
{
    pending_store(p, pending_load(p) | bits);
}

static inline void pending_clear(_Atomic uint64_t *p, uint64_t bits)
{
    pending_store(p, pending_load(p) & ~bits);
}

/* API */

typedef struct {
    jmp_buf env;
    volatile sig_atomic_t armed;
} host_sigbus_recovery_t;

/* Initialize signal state: all SIG_DFL, nothing pending/blocked. */
void signal_init(void);

/* Arm per-thread host SIGBUS recovery for direct guest memory copies. */
host_sigbus_recovery_t *signal_host_sigbus_recovery(void);

/* Run the trailing statement with host SIGBUS recovery armed for this thread,
 * setting faulted to true when it took a fault instead of killing the host.
 *
 * A MAP_SHARED overlay stays live in the guest slab after anything truncates
 * the file, so a host access to the vanished page raises SIGBUS. Only host user
 * mode needs this; kernel copyin/copyout reports EFAULT instead. SA_NODEFER on
 * the handler is what lets the mask-free _setjmp serve here.
 *
 * Rules for the statement, worst breakage first:
 * - No return, break, goto, or longjmp out. That skips the disarm and leaves
 *   env naming a dead frame, so the next fault jumps into freed stack.
 * - No lock, including one inside a callee: arc4random_buf here stranded a libc
 *   lock and hung the next fork. Keep to memcpy, memchr, atomic builtins.
 * - No result in a non-volatile local read when faulted; _longjmp leaves those
 *   indeterminate.
 * - No nesting: an inner guard disarms the outer on exit.
 */
#define HOST_SIGBUS_GUARD(faulted, ...)                               \
    do {                                                              \
        host_sigbus_recovery_t *hsr_ = signal_host_sigbus_recovery(); \
        if (_setjmp(hsr_->env) != 0) {                                \
            signal_host_sigbus_recovery()->armed = 0;                 \
            (faulted) = true;                                         \
        } else {                                                      \
            hsr_->armed = 1;                                          \
            __VA_ARGS__;                                              \
            hsr_->armed = 0;                                          \
            (faulted) = false;                                        \
        }                                                             \
    } while (0)

/* Reset signal state for exec (POSIX requirement). Handlers set to SIG_DFL
 * (except SIG_IGN stays SIG_IGN). Pending signals and signal mask are
 * preserved.
 */
void signal_reset_for_exec(void);

/* Queue a process-directed signal (kill(2) semantics): lands in the shared
 * pending set, delivered to whichever eligible thread reaches a delivery point
 * first.
 */
void signal_queue(int signum);

/* Queue a thread-directed signal (tgkill/tkill semantics): lands in the target
 * thread's private pending set so only that thread consumes it, and standard
 * signals do not coalesce across threads. The target is resolved by guest tid
 * and enqueued atomically against thread-slot reuse.
 *
 * Returns true if the target thread was found (and the signal queued), false
 * otherwise (caller maps false to -ESRCH).
 */
bool signal_queue_thread(int64_t tid, int signum);
bool signal_queue_thread_info(int64_t tid,
                              int signum,
                              int32_t si_code,
                              int32_t si_pid,
                              uint32_t si_uid,
                              int32_t si_int,
                              uint64_t si_ptr);

/* Queue an RT signal with sender metadata and payload from sigqueue. */
void signal_queue_rt(int signum,
                     int32_t si_code,
                     int32_t si_pid,
                     uint32_t si_uid,
                     int32_t si_int,
                     uint64_t si_ptr);

/* Queue a signal with explicit siginfo metadata. Standard signals preserve one
 * payload while coalesced; RT signals enqueue every instance.
 */
void signal_queue_info(int signum,
                       int32_t si_code,
                       int32_t si_pid,
                       uint32_t si_uid,
                       int32_t si_int,
                       uint64_t si_ptr);

/* Set fault info for the next signal delivery. When set, signal_deliver()
 * populates si_code, si_addr, fault_address, and ESR context from these values
 * instead of using the default SI_USER/si_pid fields. Consumed (cleared) after
 * one delivery. Used for synchronous faults: BRK->SIGTRAP, SIGSEGV, etc. The
 * @esr parameter is the raw ESR_EL1 value; if non-zero, an esr_context block is
 * appended to __reserved after FPSIMD.
 */
void signal_set_fault_info(int si_code, uint64_t addr, uint64_t esr);

/* Recompute the global pending hint (shared set OR every active thread's
 * private set) under sig_lock. Call after a thread exits so its unconsumed
 * thread-directed pending bits stop keeping the identity-syscall fast path
 * disabled. Must NOT be called while holding thread_lock (sig_lock <
 * thread_lock in the lock order); the exiting thread's slot must already be
 * inactive so the union excludes it.
 */
void signal_refresh_pending_hint(void);

/* Check if any unblocked signal is pending. */
int signal_pending(void);
bool signal_pending_interruption(bool *restart_out);

/* True when a signal that reaches the guest is pending for the calling thread,
 * with a process-directed one moved into this thread's private set first. A
 * wait that several threads leave on one broadcast uses this instead of
 * signal_pending(): the shared set is visible to every thread, and Linux
 * complete_signal() interrupts only the one thread it picks.
 */
bool signal_claim_interruption(void);

/* True if anything that would normally be drained by signal_check_timer is
 * currently live: an unblocked pending signal, OR any of the three guest
 * itimers is armed. The shim's identity fast path consults this (indirectly via
 * shim_globals attention flag) to decide whether to skip the HVC #5 round-trip.
 * Whenever this returns true, the shim must take the slow path so the
 * epilogue's signal_check_timer + queue drain runs.
 */
bool signal_attention_needed(void);

/* Register the shim-globals guest pointer used by the attention setters in
 * signal_queue / setitimer / proc_set_exit_group. Called from bootstrap and
 * fork-child after guest_init. Asserts that the value is NULL or matches the
 * already-registered g; elfuse runs one VM per process and the singleton
 * catches lifecycle bugs (multiple concurrent VMs in one process would violate
 * this invariant).
 *
 * Passing NULL clears the registration (used by signal_init for a defensive
 * reset; the attention setters become no-ops in that state, matching the
 * pre-registration behavior).
 */
void signal_set_shim_globals_guest(guest_t *g);

/* Deliver the highest-priority pending unblocked signal to the guest. Builds an
 * rt_sigframe on the guest stack and redirects vCPU to handler.
 * Returns: 1 if signal was delivered, 0 if nothing pending,
 *         -1 if process should terminate (default TERM/CORE disposition).
 * On terminate, *exit_code is set to 128 + signum.
 */
int signal_deliver(hv_vcpu_t vcpu, guest_t *g, int *exit_code);

/* Return and clear the Linux wait-format status recorded when the current vCPU
 * thread terminated because of a signal.
 *
 * Returns zero after a normal syscall exit or when no fatal signal was
 * delivered.
 */
int signal_take_termination_wait_status(void);

/* Deliver a synchronous fault signal directly to the faulting (current) thread,
 * bypassing the process-wide pending set. The caller must have set the fault
 * info via signal_set_fault_info() immediately before. Same return convention
 * as signal_deliver(). Use this for SIGSEGV/SIGBUS/SIGILL/SIGFPE/SIGTRAP raised
 * from a guest exception, never signal_queue()+signal_deliver(): a queued fault
 * can be stolen by another vCPU thread (delivered as SI_USER, no si_addr) or
 * coalesced with another thread's fault into one bitmask bit.
 *
 * Follows Linux force_sig_info_to_task() semantics: a SIG_IGN or blocked
 * disposition is reset to SIG_DFL and unblocked before delivery, so an
 * unhandleable fault terminates the process rather than re-faulting forever or
 * invoking a handler the guest asked to block.
 */
int signal_deliver_fault(hv_vcpu_t vcpu,
                         guest_t *g,
                         int signum,
                         int *exit_code);

/* Handle rt_sigreturn (SYS 139): restore registers from rt_sigframe on the
 * guest stack.
 *
 * Returns SYSCALL_EXEC_HAPPENED to skip X0 writeback.
 */
int signal_rt_sigreturn(hv_vcpu_t vcpu, guest_t *g);

/* Drop the guest X8 that rt_sigreturn parked for a signal delivered later in
 * the same host epilogue.
 *
 * The drop-frame marker occupies X8, so a delivery that follows an rt_sigreturn
 * before the guest runs again cannot read the guest's X8 out of the register;
 * signal_rt_sigreturn parks it and that delivery takes the parked value. The
 * park is only ever correct for that stretch. Once the vCPU is resumed the
 * guest owns X8 again, and a record left behind would be handed to some later
 * delivery that merely resumes at the same PC -- a fault on an instruction the
 * guest returned to, say, whose ELR_EL1 is the faulting PC and whose X8 is
 * live.
 *
 * The vCPU run loop therefore calls this immediately before every resume, and
 * scripts/check-svc-tails.py holds every hv_vcpu_run() call site to it.
 */
void signal_forget_sigreturn_x8(void);

/* Re-key that record on the PC a ptrace stop left the guest at.
 *
 * Nothing moves the guest between the rt_sigreturn that parks an X8 and the
 * resume that ends the record's life, with one exception: a PTRACE_INTERRUPT
 * stop is taken inline on that same tail, and the tracer can write a new PC
 * before it resumes the tracee with an injected signal. The delivery that
 * follows then lands on an ELR_EL1 the record was not parked for, so the ELR
 * check that keeps a stale record from being read misses the one delivery the
 * record is genuinely for, and the frame it builds records the drop-frame
 * marker as the guest's X8.
 *
 * Called with the vCPU still inside that epilogue, where the guest is the same
 * guest with the same X8 owed to it and only the address it resumes from has
 * moved. Nothing to do when no value is parked, which is every stop taken
 * anywhere else.
 */
void signal_repark_sigreturn_x8(hv_vcpu_t vcpu);

/* Handle rt_sigaction (SYS 134). */
int64_t signal_rt_sigaction(guest_t *g,
                            int signum,
                            uint64_t act_gva,
                            uint64_t oldact_gva,
                            uint64_t sigsetsize);

/* Handle rt_sigprocmask (SYS 135). */
int64_t signal_rt_sigprocmask(guest_t *g,
                              int how,
                              uint64_t set_gva,
                              uint64_t oldset_gva,
                              uint64_t sigsetsize);

/* Handle rt_sigsuspend (SYS 133). */
int64_t signal_rt_sigsuspend(guest_t *g,
                             uint64_t mask_gva,
                             uint64_t sigsetsize);

/* Handle rt_sigpending (SYS 136). */
int64_t signal_rt_sigpending(guest_t *g, uint64_t set_gva, uint64_t sigsetsize);

/* Handle rt_sigtimedwait (SYS 137). Synchronously consume a pending signal
 * whose number is in *set*. info_gva (may be 0): if non-zero, populate the
 * guest siginfo_t there. timeout_gva (may be 0): if zero, block indefinitely;
 * otherwise block for at most the specified duration.
 *
 * Returns the signal number on success, -EAGAIN if the timeout expired with no
 * matching signal, or -EINTR if an unrelated signal arrived while waiting.
 */
int64_t signal_rt_sigtimedwait(guest_t *g,
                               uint64_t set_gva,
                               uint64_t info_gva,
                               uint64_t timeout_gva,
                               uint64_t sigsetsize);

/* Handle sigaltstack (SYS 132). ss_gva is pointer to new stack_t (or 0),
 * old_ss_gva is pointer to receive current stack_t (or 0).
 */
int64_t signal_sigaltstack(guest_t *g, uint64_t ss_gva, uint64_t old_ss_gva);

/* Snapshot/restore signal state for fork IPC serialization. */
void signal_get_state(signal_state_snapshot_t *state);

/* True only for the explicit Linux no-zombie dispositions. SIGCHLD's default
 * disposition is ignore but does not imply automatic reaping.
 */
bool signal_sigchld_autoreap(void);

/* Refresh the shim identity cache after an asynchronous reparent message.
 * Returns false while a fork child is still bootstrapping and has not
 * registered its guest cache yet.
 */
bool signal_refresh_identity_cache(void);
void signal_set_state(const signal_state_snapshot_t *state);
uint64_t signal_shared_pending_load(void);
uint64_t signal_blocked_load(void);

/* Snapshot or consume pending signals for signalfd. signal_peek_signalfd()
 * snapshots up to max matching entries without consuming them.
 * signal_take_signalfd_exact() then consumes those exact entries, preserving
 * any matching signals that arrived later. Peek fills out[] with matching
 * pending siginfo and, when src is non-NULL, tags each entry with the pending
 * set it came from (0 = the reading thread's private set, 1 = the shared set).
 * signal_take_signalfd_exact() must be handed that same src array so it
 * consumes each entry from the exact set it was peeked from, never a
 * same-valued entry in the other set.
 */
size_t signal_peek_signalfd(uint64_t mask,
                            signal_rt_info_t *out,
                            uint8_t *src,
                            size_t max);
size_t signal_take_signalfd_exact(const signal_rt_info_t *expected,
                                  const uint8_t *src,
                                  size_t max);

/* Bitmask of signals a signalfd read on the current thread could observe: the
 * shared set unioned with this thread's private (thread-directed) set. Used to
 * gate the signalfd fast path before peeking.
 */
uint64_t signal_signalfd_pending_mask(void);

/* Save and restore blocked mask for pselect6/ppoll signal mask atomicity.
 * signal_save_blocked returns the current blocked mask. signal_set_blocked
 * applies a new mask (respecting SIGKILL/SIGSTOP). signal_restore_blocked
 * restores a previously saved mask.
 */
uint64_t signal_save_blocked(void);
void signal_set_blocked(uint64_t mask);
void signal_restore_blocked(uint64_t saved);

/* Leave a wait's temporary mask installed for the signal that ended it, and
 * hand @saved to the next handler frame as uc_sigmask so rt_sigreturn restores
 * it. ppoll, pselect6 and epoll_pwait call this when they return EINTR for a
 * signal they claimed, which is where Linux keeps the mask for ERESTARTNOHAND.
 */
void signal_defer_restore_blocked(uint64_t saved);

/* Put back a mask left for delivery -- by signal_defer_restore_blocked() or
 * rt_sigsuspend -- that no handler frame took, because the signal was discarded
 * or a stop came first. The syscall epilogue calls this after it delivers, as
 * Linux restore_saved_sigmask() does.
 */
void signal_restore_saved_blocked(void);

/* Drop the claims @t holds on process-directed signals, so another thread can
 * take them. thread_deactivate() calls this before the slot can be reused.
 */
struct thread_entry;
void signal_release_claims(struct thread_entry *t);

/* Guest ITIMER_REAL emulation. These emulate the guest's setitimer(ITIMER_REAL)
 * internally rather than forwarding to the host, because macOS shares alarm()
 * and setitimer() as the same underlying timer, and elfuse needs alarm() for
 * its vCPU timeout.
 */

/* Set the guest's ITIMER_REAL timer. value/interval are relative durations.
 * old_value/old_interval receive the previous timer state (may be NULL).
 */
void signal_set_itimer(const struct timeval *value,
                       const struct timeval *interval,
                       struct timeval *old_value,
                       struct timeval *old_interval);

/* Get the guest's ITIMER_REAL remaining time and interval. */
void signal_get_itimer(struct timeval *value, struct timeval *interval);

/* Set/get ITIMER_VIRTUAL (which=1) or ITIMER_PROF (which=2). */
void signal_set_itimer_virt(int which,
                            const struct timeval *value,
                            const struct timeval *interval,
                            struct timeval *old_value,
                            struct timeval *old_interval);
void signal_get_itimer_virt(int which,
                            struct timeval *value,
                            struct timeval *interval);

/* Check if any guest itimer has expired; queue signals as needed. Called from
 * the vCPU loop after each syscall.
 */
void signal_check_timer(void);

/* ITIMER_REAL only. A blocking wait must not advance ITIMER_VIRTUAL or
 * ITIMER_PROF: those are charged to guest CPU time, and a thread parked in a
 * host call spends none.
 */
void signal_check_timer_real(void);
