/*
 * Signal delivery
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements Linux-compatible signal delivery for aarch64 guests. When a signal
 * is queued (e.g., SIGPIPE from write() to broken pipe), signal emulation
 * builds an rt_sigframe on the guest stack matching the kernel's setup_rt_frame
 * layout, then redirects the vCPU to the guest's signal handler. The guest
 * handler eventually calls rt_sigreturn (SYS 139), which restores the saved
 * register state from the frame.
 *
 * Reference: Linux arch/arm64/kernel/signal.c
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "utils.h"

#include "debug/log.h"
#include <time.h>
#include <sys/time.h>

#include "hvutil.h"

#include "core/shim-globals.h"
#include "core/mmap-fastpath.h"
#include "core/vdso.h"

#include "runtime/thread.h"

#include "syscall/abi.h"
#include "syscall/fd.h"   /* signalfd_notify */
#include "syscall/internal.h"
#include "syscall/poll.h" /* wakeup_pipe_signal */
#include "syscall/proc.h" /* proc_get_pid, proc_get_uid, SYSCALL_EXEC_HAPPENED */
#include "syscall/signal.h"

/* Signal state (module-level, process-wide). */
static signal_state_t sig_state;

/* Per-thread pending fault info. When a synchronous fault (BRK, segfault, etc.)
 * needs to deliver a signal, the caller sets this before
 * signal_queue()+signal_deliver(). signal_deliver() consumes it to populate
 * si_code/si_addr/fault_address in the signal frame instead of the default
 * SI_USER/si_pid fields. Thread-local because each vCPU thread delivers signals
 * independently.
 */
typedef struct {
    bool valid;    /* True if fault info is pending */
    int si_code;   /* e.g., LINUX_TRAP_BRKPT */
    uint64_t addr; /* Fault address (BRK PC, segfault addr, etc.) */
    uint64_t esr;  /* Raw ESR_EL1 value (0 if not applicable) */
} pending_fault_t;

static _Thread_local pending_fault_t pending_fault;

/* Per-delivery SROP cookie. Stored when signal_deliver builds the frame (in
 * uc_flags), validated when signal_rt_sigreturn reads it back. Thread-local
 * because each vCPU thread delivers independently. A stack of cookies handles
 * nested signals (up to 16 deep).
 */
#define MAX_NESTED_SIGNALS 16
static _Thread_local uint64_t sigreturn_cookies[MAX_NESTED_SIGNALS];
static _Thread_local int sigreturn_cookie_depth;

/* Protects signal actions array. Multiple threads may call rt_sigaction
 * concurrently (e.g., during musl init). Blocked masks are per-thread (each
 * thread_entry_t has its own blocked / saved_blocked).
 */
static pthread_mutex_t sig_lock = PTHREAD_MUTEX_INITIALIZER; /* Lock order: 4 */

/* Atomic "maybe pending" hint. signal_queue() sets it before releasing the
 * queue lock, and signal_deliver() clears it after draining visible state. The
 * vCPU hot path uses it to skip the locked signal_pending() check when no
 * thread can possibly observe a queued signal. False positives cost one extra
 * lock acquisition; false negatives would lose delivery, so ordering here stays
 * conservative.
 */
#include <stdatomic.h>
static _Atomic uint64_t sig_pending_hint = 0;

/* Guest ITIMER_REAL emulation. Signal emulation keeps the guest's ITIMER_REAL
 * internally rather than forwarding to the host setitimer(), because macOS
 * shares alarm() and setitimer(ITIMER_REAL) as the same underlying timer, and
 * elfuse needs alarm() for its own vCPU per-iteration timeout. The guest timer
 * is checked after each syscall in the vCPU loop via signal_check_timer().
 */
typedef struct {
    int active;              /* Non-zero if timer is armed */
    struct timeval expiry;   /* Absolute wall-clock time of next fire */
    struct timeval interval; /* Repeat interval (zero = one-shot) */
} guest_itimer_t;

static guest_itimer_t guest_itimer;      /* ITIMER_REAL -> SIGALRM */
static guest_itimer_t guest_itimer_virt; /* ITIMER_VIRTUAL -> SIGVTALRM */
static guest_itimer_t guest_itimer_prof; /* ITIMER_PROF -> SIGPROF */

/* Default disposition table. Index 0 unused (signals are 1-based). */
static const sig_disposition_t default_dispositions[LINUX_NSIG + 1] = {
    [0] = SIG_DISP_IGN, /* Invalid signal 0 */
    [LINUX_SIGHUP] = SIG_DISP_TERM,
    [LINUX_SIGINT] = SIG_DISP_TERM,
    [LINUX_SIGQUIT] = SIG_DISP_CORE,
    [LINUX_SIGILL] = SIG_DISP_CORE,
    [LINUX_SIGTRAP] = SIG_DISP_CORE,
    [LINUX_SIGABRT] = SIG_DISP_CORE,
    [LINUX_SIGBUS] = SIG_DISP_CORE,
    [LINUX_SIGFPE] = SIG_DISP_CORE,
    [LINUX_SIGKILL] = SIG_DISP_TERM, /* Cannot be caught */
    [LINUX_SIGUSR1] = SIG_DISP_TERM,
    [LINUX_SIGSEGV] = SIG_DISP_CORE,
    [LINUX_SIGUSR2] = SIG_DISP_TERM,
    [LINUX_SIGPIPE] = SIG_DISP_TERM,
    [LINUX_SIGALRM] = SIG_DISP_TERM,
    [LINUX_SIGTERM] = SIG_DISP_TERM,
    [LINUX_SIGSTKFLT] = SIG_DISP_TERM,
    [LINUX_SIGCHLD] = SIG_DISP_IGN,
    [LINUX_SIGCONT] = SIG_DISP_CONT,
    [LINUX_SIGSTOP] = SIG_DISP_STOP, /* Cannot be caught */
    [LINUX_SIGTSTP] = SIG_DISP_STOP,
    [LINUX_SIGTTIN] = SIG_DISP_STOP,
    [LINUX_SIGTTOU] = SIG_DISP_STOP,
    [LINUX_SIGURG] = SIG_DISP_IGN,
    [LINUX_SIGXCPU] = SIG_DISP_CORE,
    [LINUX_SIGXFSZ] = SIG_DISP_CORE,
    [LINUX_SIGVTALRM] = SIG_DISP_TERM,
    [LINUX_SIGPROF] = SIG_DISP_TERM,
    [LINUX_SIGWINCH] = SIG_DISP_IGN,
    [LINUX_SIGIO] = SIG_DISP_TERM,
    [LINUX_SIGPWR] = SIG_DISP_TERM,
    [LINUX_SIGSYS] = SIG_DISP_CORE,
    /* 32-64 (RT signals): default TERM */
};

static sig_disposition_t signal_default_disposition(int signum)
{
    if (signum < 1 || signum > LINUX_NSIG)
        return SIG_DISP_IGN;
    if (signum >= LINUX_SIGRTMIN)
        return SIG_DISP_TERM;
    return default_dispositions[signum];
}

/* Helpers. */

/* Convert signal number (1-based) to bitmask position. */
static inline uint64_t sig_bit(int signum)
{
    if (signum < 1 || signum > LINUX_NSIG)
        return 0;
    return BIT64(signum - 1);
}

/* Signals that cannot be caught, blocked, or ignored. */
static inline int sig_uncatchable(int signum)
{
    return signum == LINUX_SIGKILL || signum == LINUX_SIGSTOP;
}

static signal_rt_info_t signal_default_info(int signum)
{
    return (signal_rt_info_t) {
        .signum = signum,
        .si_code = LINUX_SI_USER,
        .si_pid = (int32_t) proc_get_pid(),
        .si_uid = proc_get_uid(),
        .si_int = 0,
        .si_ptr = 0,
    };
}

static void signal_standard_enqueue_locked(signal_pending_t *p,
                                           int signum,
                                           const signal_rt_info_t *info)
{
    int idx = signum - 1;
    uint64_t bit = sig_bit(signum);

    if (!(p->pending & bit)) {
        p->std_info[idx] = info ? *info : signal_default_info(signum);
        p->std_info_valid[idx] = info != NULL;
    }
    p->pending |= bit;
}

static signal_rt_info_t signal_standard_peek_locked(signal_pending_t *p,
                                                    int signum)
{
    int idx = signum - 1;
    if (p->std_info_valid[idx])
        return p->std_info[idx];
    return signal_default_info(signum);
}

static void signal_rt_enqueue_locked(signal_pending_t *p,
                                     int signum,
                                     const signal_rt_info_t *info)
{
    int idx = signum - LINUX_SIGRTMIN;
    signal_rt_info_t fallback = signal_default_info(signum);
    const signal_rt_info_t *entry = info ? info : &fallback;

    p->pending |= sig_bit(signum);
    if (p->rt_queue[idx] >= RT_SIGQUEUE_MAX)
        return;

    int tail = (p->rt_head[idx] + p->rt_queue[idx]) % RT_SIGQUEUE_MAX;
    p->rt_info[idx][tail] = *entry;
    p->rt_queue[idx]++;
}

static int signal_rt_dequeue_locked(signal_pending_t *p,
                                    int signum,
                                    signal_rt_info_t *out)
{
    int idx = signum - LINUX_SIGRTMIN;
    if (p->rt_queue[idx] <= 0) {
        p->pending &= ~sig_bit(signum);
        return 0;
    }

    if (out)
        *out = p->rt_info[idx][p->rt_head[idx]];
    p->rt_head[idx] = (uint8_t) ((p->rt_head[idx] + 1) % RT_SIGQUEUE_MAX);
    p->rt_queue[idx]--;
    if (p->rt_queue[idx] == 0) {
        p->pending &= ~sig_bit(signum);
        p->rt_head[idx] = 0;
    }
    return 1;
}

/* Route a signal into a specific pending set (shared or a thread's private). */
static void signal_enqueue_locked(signal_pending_t *p,
                                  int signum,
                                  const signal_rt_info_t *info)
{
    if (signum >= LINUX_SIGRTMIN)
        signal_rt_enqueue_locked(p, signum, info);
    else
        signal_standard_enqueue_locked(p, signum, info);
}

/* Recompute the global "maybe pending" hint from the shared set plus every
 * thread's private set. Caller holds sig_lock. The hint never produces a false
 * negative (a real pending bit is always represented), so signal_pending()'s
 * lock-free fast path can trust a zero result; false positives only cost one
 * extra locked recheck.
 */
static void refresh_pending_hint_locked(void)
{
    uint64_t hint = sig_state.shared.pending | thread_pending_union();
    atomic_store_explicit(&sig_pending_hint, hint, memory_order_release);
}

/* Signals pending for the current thread: its private (thread-directed) set
 * unioned with the shared (process-directed) set. Caller holds sig_lock.
 */
static inline uint64_t self_pending_locked(void)
{
    uint64_t pending = sig_state.shared.pending;
    if (current_thread)
        pending |= current_thread->tpending.pending;
    return pending;
}

/* Per-thread signal mask accessors. POSIX requires each thread to have its own
 * blocked mask. Falls back to sig_state.blocked when current_thread is NULL
 * (early startup, before threads are initialized).
 */
static inline uint64_t *thread_blocked_ptr(void)
{
    if (current_thread)
        return &current_thread->blocked;
    return &sig_state.blocked;
}
static inline uint64_t *thread_saved_blocked_ptr(void)
{
    if (current_thread)
        return &current_thread->saved_blocked;
    return &sig_state.saved_blocked;
}
static inline bool *thread_saved_valid_ptr(void)
{
    if (current_thread)
        return &current_thread->saved_blocked_valid;
    return &sig_state.saved_blocked_valid;
}

/* Public API. */

/* Singleton guest pointer used by attention-flag setters in this file. elfuse
 * runs one VM per process so a single global is correct. The setter
 * (signal_set_shim_globals_guest) asserts NULL-or-same to catch a lifecycle bug
 * in any future multi-VM design.
 *
 * Atomic because attention_raise runs on every signal queue from any thread
 * without holding sig_lock, while signal_init clears it across the execve reset
 * window. ARM64 aligned 64-bit pointer writes are single-copy atomic, but plain
 * reads/writes have no ordering, so a concurrent attention_raise could observe
 * a stale value or fail to see a fresh registration. The release-acquire pair
 * seals the window.
 */
static _Atomic(guest_t *) attention_guest;

void signal_init(void)
{
    memset(&sig_state, 0, sizeof(sig_state));
    /* Clear the attention singleton on every init pass. Bootstrap and the
     * fork-child receive path both call this before
     * signal_set_shim_globals_guest publishes the live g; the reset keeps the
     * setter's NULL-or-same assertion from latching onto a stale parent pointer
     * in the child process. Release-store so a sibling thread that
     * ACQUIRE-loads the slot after init observes NULL and falls back to
     * thread_interrupt_all instead of a stale parent pointer.
     */
    atomic_store_explicit(&attention_guest, NULL, memory_order_release);
    /* Altstack is now per-thread (in thread_entry_t), initialized to SS_DISABLE
     * by thread_register_main() and thread_alloc().
     */
}

void signal_set_shim_globals_guest(guest_t *g)
{
    guest_t *cur = atomic_load_explicit(&attention_guest, memory_order_acquire);
    if (g != NULL && cur != NULL && cur != g) {
        log_error(
            "signal: shim-globals guest already registered to %p, "
            "refusing to re-register with %p",
            (void *) cur, (void *) g);
        return;
    }
    atomic_store_explicit(&attention_guest, g, memory_order_release);
}

/* Raise the shim-globals attention flag if the singleton has been registered;
 * otherwise fall back to a bare vCPU interrupt. Both paths end up running
 * thread_interrupt_all (shim_globals_raise_attention issues it internally), so
 * callers only need this single helper.
 *
 * Also poke the wakeup pipe so a thread parked in a host poll/select/epoll/read
 * wait -- which hv_vcpus_exit cannot reach because it is not inside hv_vcpu_run
 * -- wakes and rechecks signal_pending(). Matches how exit_group and
 * futex_interrupt already signal the pipe.
 */
static inline void attention_raise(void)
{
    guest_t *g = atomic_load_explicit(&attention_guest, memory_order_acquire);
    if (g)
        shim_globals_raise_attention(g);
    else
        thread_interrupt_all();
    wakeup_pipe_signal();
}

/* Predicate matches the deliverability gate used by signal_queue and
 * signal_queue_info: SIGKILL/SIGSTOP are uncatchable and must always interrupt;
 * other signals only interrupt when at least one active thread does not block
 * them.
 */
static inline bool signal_should_interrupt(int signum)
{
    return sig_uncatchable(signum) ||
           thread_signal_deliverable(sig_bit(signum));
}

void signal_reset_for_exec(void)
{
    thread_entry_t *t = current_thread;

    pthread_mutex_lock(&sig_lock);
    for (int i = 0; i < LINUX_NSIG; i++) {
        /* POSIX: handlers reset to SIG_DFL, except SIG_IGN stays SIG_IGN.
         * Pending signals and signal mask are preserved across exec.
         */
        if (sig_state.actions[i].sa_handler != LINUX_SIG_IGN) {
            sig_state.actions[i].sa_handler = LINUX_SIG_DFL;
            sig_state.actions[i].sa_flags = 0;
            sig_state.actions[i].sa_restorer = 0;
            sig_state.actions[i].sa_mask = 0;
        }
    }
    /* Clear saved sigsuspend state (both global and per-thread) */
    sig_state.saved_blocked_valid = false;
    if (t)
        t->saved_blocked_valid = false;

    /* POSIX disables the alternate signal stack across exec. */
    if (t) {
        t->altstack_sp = 0;
        t->altstack_flags = LINUX_SS_DISABLE;
        t->altstack_size = 0;
        t->on_altstack = false;
    }
    pthread_mutex_unlock(&sig_lock);

    /* Clear any stale pending fault info so it does not leak into the new
     * program's first signal delivery (e.g., if a BRK handler called execve
     * with pending_fault still valid).
     */
    pending_fault.valid = false;
}

void signal_queue(int signum)
{
    if (signum < 1 || signum > LINUX_NSIG)
        return;
    pthread_mutex_lock(&sig_lock);
    signal_enqueue_locked(&sig_state.shared, signum, NULL);
    /* Publish hint before releasing lock so vCPU hot path sees it. */
    refresh_pending_hint_locked();
    pthread_mutex_unlock(&sig_lock);

    /* Notify any signalfd instances whose mask includes this signal. This makes
     * the signalfd pipe readable so poll/epoll sees it.
     */
    signalfd_notify(signum);

    /* Only force vCPUs out of hv_vcpu_run(), and only force the shim's identity
     * fast path off, if the signal is actually deliverable to at least one
     * thread. SIGKILL/SIGSTOP cannot be blocked and always need interruption.
     * For other signals, check per-thread blocked masks to avoid spurious
     * context switches -- Go, JVM, and Node.js mask signals in worker threads,
     * causing thousands of unnecessary ~1000ns VM exit+re-entry cycles per
     * second if signal emulation interrupts unconditionally.
     *
     * Race: if a thread concurrently unblocks this signal via rt_sigprocmask,
     * the pending signal could be missed here. signal_rt_sigprocmask handles
     * this by re-checking pending signals after unblocking and interrupting the
     * current thread if delivery became possible.
     */
    if (signal_should_interrupt(signum))
        attention_raise();
}

void signal_queue_rt(int signum,
                     int32_t si_code,
                     int32_t si_pid,
                     uint32_t si_uid,
                     int32_t si_int,
                     uint64_t si_ptr)
{
    signal_queue_info(signum, si_code, si_pid, si_uid, si_int, si_ptr);
}

void signal_queue_info(int signum,
                       int32_t si_code,
                       int32_t si_pid,
                       uint32_t si_uid,
                       int32_t si_int,
                       uint64_t si_ptr)
{
    if (signum < 1 || signum > LINUX_NSIG)
        return;
    pthread_mutex_lock(&sig_lock);
    signal_rt_info_t info = {
        .signum = signum,
        .si_code = si_code,
        .si_pid = si_pid,
        .si_uid = si_uid,
        .si_int = si_int,
        .si_ptr = si_ptr,
    };
    signal_enqueue_locked(&sig_state.shared, signum, &info);
    refresh_pending_hint_locked();
    pthread_mutex_unlock(&sig_lock);
    signalfd_notify(signum);
    /* Same shim-globals attention raise as signal_queue: force the fast path
     * off only when the queued signal can reach signal_deliver.
     */
    if (signal_should_interrupt(signum))
        attention_raise();
}

/* Thread-directed queueing (tgkill/tkill/pthread_kill). The signal lands in the
 * target thread's private pending set, so only that thread consumes it and
 * standard signals do not coalesce across threads. The target is resolved and
 * the enqueue performed while holding thread_lock so a concurrent thread exit
 * or slot reuse cannot misroute the signal.
 *
 * Returns true if the target was found. Lock order: sig_lock (4) then
 * thread_lock (5).
 */
static bool signal_queue_thread_common(int64_t tid,
                                       int signum,
                                       const signal_rt_info_t *info)
{
    if (signum < 1 || signum > LINUX_NSIG)
        return false;

    bool found = false;
    uint64_t blocked = 0;
    pthread_mutex_lock(&sig_lock);
    pthread_mutex_lock(thread_get_lock());
    thread_entry_t *t = thread_find_locked(tid);
    if (t) {
        signal_enqueue_locked(&t->tpending, signum, info);
        refresh_pending_hint_locked();
        blocked = __atomic_load_n(&t->blocked, __ATOMIC_ACQUIRE);
        found = true;
    }
    pthread_mutex_unlock(thread_get_lock());
    pthread_mutex_unlock(&sig_lock);

    if (!found)
        return false;

    /* Wake signalfd waiters. Linux backs every signalfd with the one shared
     * sighand wait queue, so a queued signal (directed or not) wakes it and
     * each reader re-evaluates against its own pending: the target thread finds
     * the signal (its private set), a sibling finds nothing and reads EAGAIN.
     * Skipping this for directed signals would leave the target thread's own
     * signalfd wait unwoken -- the standard "block the signal, drain it via
     * signalfd" pattern -- which matters far more than sparing a sibling a
     * spurious wake.
     */
    signalfd_notify(signum);

    /* Interrupt only if the signal can actually reach the target: uncatchable
     * signals always, otherwise the target must not block it. A concurrent
     * rt_sigprocmask unblock re-checks pending afterwards.
     */
    if (sig_uncatchable(signum) || !(blocked & sig_bit(signum)))
        attention_raise();
    return true;
}

bool signal_queue_thread(int64_t tid, int signum)
{
    return signal_queue_thread_common(tid, signum, NULL);
}

bool signal_queue_thread_info(int64_t tid,
                              int signum,
                              int32_t si_code,
                              int32_t si_pid,
                              uint32_t si_uid,
                              int32_t si_int,
                              uint64_t si_ptr)
{
    signal_rt_info_t info = {
        .signum = signum,
        .si_code = si_code,
        .si_pid = si_pid,
        .si_uid = si_uid,
        .si_int = si_int,
        .si_ptr = si_ptr,
    };
    return signal_queue_thread_common(tid, signum, &info);
}

void signal_set_fault_info(int si_code, uint64_t addr, uint64_t esr)
{
    pending_fault.valid = true;
    pending_fault.si_code = si_code;
    pending_fault.addr = addr;
    pending_fault.esr = esr;
}

int signal_pending(void)
{
    /* Fast path: check atomic hint to avoid locking on the hot path. If the
     * hint says nothing is pending, skip the lock entirely. The hint can have
     * false positives (stale pending bit after mask change) but never false
     * negatives (signal_queue always sets it before unlock).
     */
    uint64_t hint =
        atomic_load_explicit(&sig_pending_hint, memory_order_acquire);
    uint64_t blocked = __atomic_load_n(thread_blocked_ptr(), __ATOMIC_ACQUIRE);
    if ((hint & ~blocked) == 0)
        return 0;

    /* Slow path: confirm under lock. Deliverable = this thread's private set
     * (thread-directed) plus the shared set (process-directed), minus blocked.
     */
    pthread_mutex_lock(&sig_lock);
    blocked = __atomic_load_n(thread_blocked_ptr(), __ATOMIC_ACQUIRE);
    int result = (self_pending_locked() & ~blocked) != 0;
    pthread_mutex_unlock(&sig_lock);
    return result;
}

bool signal_attention_needed(void)
{
    /* Cheap atomic load on the sig-pending hint first; if a signal is queued
     * and deliverable to at least one active thread, the shim should drop to
     * the slow path even before we touch the itimer state. A pending signal
     * blocked by every active thread is not useful slow-path work and should
     * not keep identity syscalls out of the fast path indefinitely.
     */
    uint64_t hint =
        atomic_load_explicit(&sig_pending_hint, memory_order_acquire);
    if (hint != 0 && thread_signal_deliverable(hint))
        return true;
    /* Active guest itimers: even if no signal is queued YET, the timer can fire
     * at any moment, and signal_check_timer needs an HVC #5 epilogue to notice
     * it. Keep attention raised while any timer is armed.
     */
    if (__atomic_load_n(&guest_itimer.active, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&guest_itimer_virt.active, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&guest_itimer_prof.active, __ATOMIC_ACQUIRE))
        return true;
    return false;
}

bool signal_pending_interruption(bool *restart_out)
{
    pthread_mutex_lock(&sig_lock);
    uint64_t blocked = __atomic_load_n(thread_blocked_ptr(), __ATOMIC_ACQUIRE);
    uint64_t deliverable = self_pending_locked() & ~blocked;
    if (deliverable == 0) {
        pthread_mutex_unlock(&sig_lock);
        if (restart_out)
            *restart_out = false;
        return false;
    }

    /* Ignored/default-ignore signals are discarded by signal_deliver and must
     * not interrupt waits. Any guest-visible delivery must escape the wait so
     * the syscall epilogue can run the handler/default action; restart_out only
     * tells FUSE whether all visible handlers are SA_RESTART.
     */
    bool any_interrupt = false;
    bool all_restart = true;
    uint64_t bits = deliverable;
    while (bits) {
        int idx = bit_ctz64(bits);
        bits &= bits - 1;
        if (!RANGE_CHECK(idx, 0, LINUX_NSIG)) {
            any_interrupt = true;
            all_restart = false;
            break;
        }
        linux_sigaction_t *act = &sig_state.actions[idx];
        if (act->sa_handler == LINUX_SIG_IGN) {
            continue;
        } else if (act->sa_handler == LINUX_SIG_DFL) {
            /* Mirror signal_deliver's SIG_DFL switch: IGN, CONT, and STOP are
             * all discarded with no guest-visible effect on elfuse (STOP/CONT
             * are not meaningful here), so they cannot legitimately interrupt a
             * wait.
             */
            sig_disposition_t disp = signal_default_disposition(idx + 1);
            if (disp == SIG_DISP_IGN || disp == SIG_DISP_CONT ||
                disp == SIG_DISP_STOP)
                continue;
            any_interrupt = true;
            all_restart = false;
        } else {
            any_interrupt = true;
            if ((act->sa_flags & LINUX_SA_RESTART) == 0)
                all_restart = false;
        }
    }

    pthread_mutex_unlock(&sig_lock);
    if (restart_out)
        *restart_out = any_interrupt && all_restart;
    return any_interrupt;
}

const signal_state_t *signal_get_state(void)
{
    /* Populate IPC-serializable fields from per-thread state under the lock to
     * avoid data races with concurrent sigaction calls. This ensures fork
     * children inherit the parent thread's blocked mask and altstack (POSIX:
     * fork preserves signal mask).
     */
    pthread_mutex_lock(&sig_lock);
    if (current_thread) {
        sig_state.blocked = current_thread->blocked;
        sig_state.altstack.ss_sp = current_thread->altstack_sp;
        sig_state.altstack.ss_flags = current_thread->altstack_flags;
        sig_state.altstack._pad = 0;
        sig_state.altstack.ss_size = current_thread->altstack_size;
        sig_state.on_altstack = current_thread->on_altstack;
    }
    pthread_mutex_unlock(&sig_lock);
    return &sig_state;
}

void signal_set_state(const signal_state_t *state)
{
    if (!state)
        return;
    pthread_mutex_lock(&sig_lock);
    sig_state = *state;
    /* Restore per-thread state from deserialized signal state (fork child).
     * POSIX: fork preserves blocked mask, altstack, and on_altstack.
     */
    if (current_thread) {
        current_thread->blocked = state->blocked;
        current_thread->altstack_sp = state->altstack.ss_sp;
        current_thread->altstack_flags = state->altstack.ss_flags;
        current_thread->altstack_size = state->altstack.ss_size;
        current_thread->on_altstack = state->on_altstack;
    }
    pthread_mutex_unlock(&sig_lock);
}

size_t signal_peek_signalfd(uint64_t mask,
                            signal_rt_info_t *out,
                            uint8_t *src,
                            size_t max)
{
    size_t total = 0;
    /* Per-set RT read cursor so a peek does not re-report the same queued
     * instance.
     */
    int rt_offset[RT_SIGNAL_COUNT];

    /* signalfd observes the reading thread's private (thread-directed) set and
     * the shared (process-directed) set, in Linux dequeue order: task->pending
     * is drained before shared_pending. Iterate sets outer, signums inner so
     * every private signal precedes every shared one. Consumption is a separate
     * step (signal_take_signalfd_exact), so this only reads.
     */
    signal_pending_t *sets[2];
    size_t nsets = 0;
    if (current_thread)
        sets[nsets++] = &current_thread->tpending;
    sets[nsets++] = &sig_state.shared;

    pthread_mutex_lock(&sig_lock);
    for (size_t s = 0; s < nsets && total < max; s++) {
        signal_pending_t *sp = sets[s];
        memset(rt_offset, 0, sizeof(rt_offset));
        /* signum runs 1..LINUX_NSIG inclusive (64 is the highest valid RT
         * signal on aarch64 Linux). Bare-musl applications can target SIGRTMAX
         * directly, so the inclusive bound matters even though glibc reserves
         * the top of the RT range for itself.
         */
        for (int signum = 1; signum <= LINUX_NSIG && total < max; signum++) {
            uint64_t bit = BIT64(signum - 1);
            if (!(mask & bit) || !(sp->pending & bit))
                continue;

            if (signum >= LINUX_SIGRTMIN) {
                int idx = signum - LINUX_SIGRTMIN;
                while (rt_offset[idx] < sp->rt_queue[idx] && total < max) {
                    int head = sp->rt_head[idx];
                    int slot = (head + rt_offset[idx]) % RT_SIGQUEUE_MAX;
                    if (out)
                        out[total] = sp->rt_info[idx][slot];
                    if (src)
                        src[total] = (uint8_t) s;
                    rt_offset[idx]++;
                    total++;
                }
            } else {
                if (out)
                    out[total] = signal_standard_peek_locked(sp, signum);
                if (src)
                    src[total] = (uint8_t) s;
                total++;
            }
        }
    }
    pthread_mutex_unlock(&sig_lock);

    return total;
}

uint64_t signal_signalfd_pending_mask(void)
{
    pthread_mutex_lock(&sig_lock);
    uint64_t m = self_pending_locked();
    pthread_mutex_unlock(&sig_lock);
    return m;
}

void signal_refresh_pending_hint(void)
{
    pthread_mutex_lock(&sig_lock);
    refresh_pending_hint_locked();
    pthread_mutex_unlock(&sig_lock);
}

size_t signal_take_signalfd_exact(const signal_rt_info_t *expected,
                                  const uint8_t *src,
                                  size_t max)
{
    size_t total = 0;

    signal_pending_t *sets[2];
    size_t nsets = 0;
    if (current_thread)
        sets[nsets++] = &current_thread->tpending;
    sets[nsets++] = &sig_state.shared;

    pthread_mutex_lock(&sig_lock);
    for (; total < max; total++) {
        int signum = expected[total].signum;
        if (signum <= 0 || signum > LINUX_NSIG)
            break;

        /* Consume from the exact set this entry was peeked from. A same-valued
         * instance in the other set must not be substituted -- that would drop
         * a signal the reader never returned.
         */
        size_t s = src[total];
        if (s >= nsets)
            break;
        signal_pending_t *sp = sets[s];
        uint64_t bit = sig_bit(signum);
        if (!(sp->pending & bit))
            break;

        const signal_rt_info_t *want = &expected[total];
        if (signum >= LINUX_SIGRTMIN) {
            int idx = signum - LINUX_SIGRTMIN;
            if (sp->rt_queue[idx] <= 0)
                break;
            const signal_rt_info_t *head = &sp->rt_info[idx][sp->rt_head[idx]];
            /* Compare field by field; signal_rt_info_t has padding between
             * si_int and si_ptr that memcmp would treat as significant.
             */
            if (head->signum != want->signum ||
                head->si_code != want->si_code ||
                head->si_pid != want->si_pid || head->si_uid != want->si_uid ||
                head->si_int != want->si_int || head->si_ptr != want->si_ptr)
                break;
            signal_rt_dequeue_locked(sp, signum, NULL);
        } else {
            signal_rt_info_t current = signal_standard_peek_locked(sp, signum);
            if (current.signum != want->signum ||
                current.si_code != want->si_code ||
                current.si_pid != want->si_pid ||
                current.si_uid != want->si_uid ||
                current.si_int != want->si_int ||
                current.si_ptr != want->si_ptr)
                break;
            sp->std_info_valid[signum - 1] = false;
            sp->pending &= ~bit;
        }
    }
    refresh_pending_hint_locked();
    pthread_mutex_unlock(&sig_lock);

    return total;
}

uint64_t signal_save_blocked(void)
{
    pthread_mutex_lock(&sig_lock);
    uint64_t saved = *thread_blocked_ptr();
    pthread_mutex_unlock(&sig_lock);
    return saved;
}

void signal_set_blocked(uint64_t mask)
{
    uint64_t unmaskable = sig_bit(LINUX_SIGKILL) | sig_bit(LINUX_SIGSTOP);
    pthread_mutex_lock(&sig_lock);
    __atomic_store_n(thread_blocked_ptr(), mask & ~unmaskable,
                     __ATOMIC_RELEASE);
    pthread_mutex_unlock(&sig_lock);
}

void signal_restore_blocked(uint64_t saved)
{
    uint64_t unmaskable = sig_bit(LINUX_SIGKILL) | sig_bit(LINUX_SIGSTOP);
    pthread_mutex_lock(&sig_lock);
    __atomic_store_n(thread_blocked_ptr(), saved & ~unmaskable,
                     __ATOMIC_RELEASE);
    pthread_mutex_unlock(&sig_lock);
}

/* Guest ITIMER_REAL API. */

/* Get monotonic time as timeval. Uses CLOCK_MONOTONIC to avoid NTP drift;
 * wall-clock adjustments must not affect timer expiry calculations.
 */
static struct timeval monotonic_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (struct timeval) {.tv_sec = ts.tv_sec,
                             .tv_usec = (int) (ts.tv_nsec / 1000)};
}

/* Helper: compare timevals. Returns <0, 0, >0. */
static int timeval_cmp(const struct timeval *a, const struct timeval *b)
{
    if (a->tv_sec != b->tv_sec)
        return (a->tv_sec < b->tv_sec) ? -1 : 1;
    if (a->tv_usec != b->tv_usec)
        return (a->tv_usec < b->tv_usec) ? -1 : 1;
    return 0;
}

/* Helper: add two timevals with overflow saturation. Uses pre-check to avoid
 * signed overflow UB.
 */
static struct timeval timeval_add(const struct timeval *a,
                                  const struct timeval *b)
{
    /* Pre-check for overflow (avoid UB from signed addition) */
    if (a->tv_sec > 0 && b->tv_sec > 0 &&
        a->tv_sec > __LONG_MAX__ - b->tv_sec) {
        return (struct timeval) {.tv_sec = __LONG_MAX__, .tv_usec = 999999};
    }
    struct timeval r = {
        .tv_sec = a->tv_sec + b->tv_sec,
        .tv_usec = a->tv_usec + b->tv_usec,
    };
    if (r.tv_usec >= 1000000) {
        if (r.tv_sec == __LONG_MAX__) {
            r.tv_usec = 999999; /* Saturate */
        } else {
            r.tv_sec += 1;
            r.tv_usec -= 1000000;
        }
    }
    return r;
}

/* Helper: subtract b from a (a must be >= b). Clamps to zero if a < b to avoid
 * negative results.
 */
static struct timeval timeval_sub(const struct timeval *a,
                                  const struct timeval *b)
{
    struct timeval r = {
        .tv_sec = a->tv_sec - b->tv_sec,
        .tv_usec = a->tv_usec - b->tv_usec,
    };
    if (r.tv_usec < 0) {
        r.tv_sec -= 1;
        r.tv_usec += 1000000;
    }
    /* Clamp underflow to zero */
    if (r.tv_sec < 0) {
        r.tv_sec = 0;
        r.tv_usec = 0;
    }
    return r;
}

void signal_set_itimer(const struct timeval *value,
                       const struct timeval *interval,
                       struct timeval *old_value,
                       struct timeval *old_interval)
{
    struct timeval now = monotonic_now();
    pthread_mutex_lock(&sig_lock);

    /* Return old timer state */
    if (old_interval)
        *old_interval = guest_itimer.interval;
    if (old_value) {
        if (guest_itimer.active &&
            timeval_cmp(&guest_itimer.expiry, &now) > 0) {
            *old_value = timeval_sub(&guest_itimer.expiry, &now);
        } else {
            old_value->tv_sec = 0;
            old_value->tv_usec = 0;
        }
    }

    /* Set new timer (value may be NULL when caller only queries old state) */
    if (!value) {
        pthread_mutex_unlock(&sig_lock);
        return;
    }
    bool arm = (value->tv_sec != 0 || value->tv_usec != 0);
    if (!arm) {
        /* Disarm */
        __atomic_store_n(&guest_itimer.active, 0, __ATOMIC_RELEASE);
    } else {
        /* Publish expiry and interval BEFORE the release-store of active.
         * signal_check_timer and signal_attention_needed ACQUIRE-load active
         * without holding sig_lock; if active is published before its
         * associated fields, a consumer can observe active=1 with stale
         * expiry/interval and decide an early or late SIGALRM. Matches the
         * field order in signal_set_itimer_virt.
         */
        guest_itimer.expiry = timeval_add(&now, value);
        guest_itimer.interval = interval ? *interval : (struct timeval) {0, 0};
        __atomic_store_n(&guest_itimer.active, 1, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&sig_lock);

    /* Arming any timer requires the shim's identity fast path to drop to the
     * slow path so signal_check_timer can see the expiry. The disarm case is
     * handled by signal_attention_needed returning false at the next HVC
     * epilogue recompute -- no explicit clear here.
     */
    if (arm)
        attention_raise();
}

void signal_get_itimer(struct timeval *value, struct timeval *interval)
{
    pthread_mutex_lock(&sig_lock);
    if (interval)
        *interval = guest_itimer.interval;
    if (value) {
        if (guest_itimer.active) {
            struct timeval now = monotonic_now();
            if (timeval_cmp(&guest_itimer.expiry, &now) > 0) {
                *value = timeval_sub(&guest_itimer.expiry, &now);
            } else {
                value->tv_sec = 0;
                value->tv_usec = 0;
            }
        } else {
            value->tv_sec = 0;
            value->tv_usec = 0;
        }
    }
    pthread_mutex_unlock(&sig_lock);
}

/* Check a single timer; if expired, re-arm or deactivate, return signal to
 * queue. Must be called with sig_lock held.
 *
 * Returns 0 if not expired.
 */
static int check_one_timer(guest_itimer_t *timer, const struct timeval *now)
{
    if (!timer->active)
        return 0;
    if (timeval_cmp(now, &timer->expiry) < 0)
        return 0;

    if (timer->interval.tv_sec != 0 || timer->interval.tv_usec != 0) {
        timer->expiry = timeval_add(&timer->expiry, &timer->interval);
    } else {
        __atomic_store_n(&timer->active, 0, __ATOMIC_RELEASE);
    }
    return 1; /* expired */
}

void signal_check_timer(void)
{
    if (!__atomic_load_n(&guest_itimer.active, __ATOMIC_ACQUIRE) &&
        !__atomic_load_n(&guest_itimer_virt.active, __ATOMIC_ACQUIRE) &&
        !__atomic_load_n(&guest_itimer_prof.active, __ATOMIC_ACQUIRE))
        return;

    struct timeval now = monotonic_now();
    int sig_real = 0, sig_virt = 0, sig_prof = 0;

    pthread_mutex_lock(&sig_lock);
    if (check_one_timer(&guest_itimer, &now))
        sig_real = LINUX_SIGALRM;
    if (check_one_timer(&guest_itimer_virt, &now))
        sig_virt = 26; /* SIGVTALRM */
    if (check_one_timer(&guest_itimer_prof, &now))
        sig_prof = 27; /* SIGPROF */
    pthread_mutex_unlock(&sig_lock);

    if (sig_real)
        signal_queue(sig_real);
    if (sig_virt)
        signal_queue(sig_virt);
    if (sig_prof)
        signal_queue(sig_prof);
}

/* Set/get ITIMER_VIRTUAL (which=1) or ITIMER_PROF (which=2) */
void signal_set_itimer_virt(int which,
                            const struct timeval *value,
                            const struct timeval *interval,
                            struct timeval *old_value,
                            struct timeval *old_interval)
{
    guest_itimer_t *timer =
        (which == 1) ? &guest_itimer_virt : &guest_itimer_prof;
    struct timeval now = monotonic_now();

    pthread_mutex_lock(&sig_lock);
    if (old_interval)
        *old_interval = timer->interval;
    if (old_value) {
        if (timer->active && timeval_cmp(&timer->expiry, &now) > 0)
            *old_value = timeval_sub(&timer->expiry, &now);
        else
            *old_value = (struct timeval) {0, 0};
    }
    bool arm = value && (value->tv_sec != 0 || value->tv_usec != 0);
    if (value) {
        if (!arm) {
            __atomic_store_n(&timer->active, 0, __ATOMIC_RELEASE);
        } else {
            timer->expiry = timeval_add(&now, value);
            timer->interval = interval ? *interval : (struct timeval) {0, 0};
            __atomic_store_n(&timer->active, 1, __ATOMIC_RELEASE);
        }
    }
    pthread_mutex_unlock(&sig_lock);

    if (arm)
        attention_raise();
}

void signal_get_itimer_virt(int which,
                            struct timeval *value,
                            struct timeval *interval)
{
    guest_itimer_t *timer =
        (which == 1) ? &guest_itimer_virt : &guest_itimer_prof;

    pthread_mutex_lock(&sig_lock);
    if (interval)
        *interval = timer->interval;
    if (value) {
        if (timer->active) {
            struct timeval now = monotonic_now();
            if (timeval_cmp(&timer->expiry, &now) > 0)
                *value = timeval_sub(&timer->expiry, &now);
            else
                *value = (struct timeval) {0, 0};
        } else {
            *value = (struct timeval) {0, 0};
        }
    }
    pthread_mutex_unlock(&sig_lock);
}

/* rt_sigaction. */

int64_t signal_rt_sigaction(guest_t *g,
                            int signum,
                            uint64_t act_gva,
                            uint64_t oldact_gva,
                            uint64_t sigsetsize)
{
    if (sigsetsize != 8)
        return -LINUX_EINVAL;
    if (signum < 1 || signum > LINUX_NSIG)
        return -LINUX_EINVAL;
    /* Linux allows querying (oldact != NULL, act == NULL) for SIGKILL/SIGSTOP
     * but rejects installing a handler for them.
     */
    if (sig_uncatchable(signum) && act_gva)
        return -LINUX_EINVAL;

    int idx = signum - 1;

    pthread_mutex_lock(&sig_lock);

    /* Return old action if requested */
    if (oldact_gva) {
        if (guest_write_small(g, oldact_gva, &sig_state.actions[idx],
                              sizeof(linux_sigaction_t)) < 0) {
            pthread_mutex_unlock(&sig_lock);
            return -LINUX_EFAULT;
        }
    }

    /* Install new action if provided */
    if (act_gva) {
        linux_sigaction_t act;
        if (guest_read_small(g, act_gva, &act, sizeof(act)) < 0) {
            pthread_mutex_unlock(&sig_lock);
            return -LINUX_EFAULT;
        }

        log_debug(
            "rt_sigaction(%d): handler=0x%llx flags=0x%llx "
            "restorer=0x%llx mask=0x%llx%s%s%s%s",
            signum, (unsigned long long) act.sa_handler,
            (unsigned long long) act.sa_flags,
            (unsigned long long) act.sa_restorer,
            (unsigned long long) act.sa_mask,
            (act.sa_flags & LINUX_SA_SIGINFO) ? " SA_SIGINFO" : "",
            (act.sa_flags & LINUX_SA_ONSTACK) ? " SA_ONSTACK" : "",
            (act.sa_flags & LINUX_SA_RESETHAND) ? " SA_RESETHAND" : "",
            (act.sa_flags & LINUX_SA_NODEFER) ? " SA_NODEFER" : "");

        sig_state.actions[idx] = act;
    }

    pthread_mutex_unlock(&sig_lock);
    return 0;
}

/* rt_sigprocmask. */

int64_t signal_rt_sigprocmask(guest_t *g,
                              int how,
                              uint64_t set_gva,
                              uint64_t oldset_gva,
                              uint64_t sigsetsize)
{
    if (sigsetsize != 8)
        return -LINUX_EINVAL;

    pthread_mutex_lock(&sig_lock);
    uint64_t *blocked = thread_blocked_ptr();

    /* Return old mask if requested */
    if (oldset_gva) {
        if (guest_write_small(g, oldset_gva, blocked, sizeof(*blocked)) < 0) {
            pthread_mutex_unlock(&sig_lock);
            return -LINUX_EFAULT;
        }
    }

    /* Apply new mask if provided */
    if (set_gva) {
        uint64_t set;
        if (guest_read_small(g, set_gva, &set, sizeof(set)) < 0) {
            pthread_mutex_unlock(&sig_lock);
            return -LINUX_EFAULT;
        }

        /* Never allow blocking SIGKILL or SIGSTOP */
        uint64_t unmaskable = sig_bit(LINUX_SIGKILL) | sig_bit(LINUX_SIGSTOP);

        uint64_t old_blocked = __atomic_load_n(blocked, __ATOMIC_RELAXED);

        uint64_t new_mask;
        switch (how) {
        case LINUX_SIG_BLOCK:
            new_mask = old_blocked | set;
            break;
        case LINUX_SIG_UNBLOCK:
            new_mask = old_blocked & ~set;
            break;
        case LINUX_SIG_SETMASK:
            new_mask = set;
            break;
        default:
            pthread_mutex_unlock(&sig_lock);
            return -LINUX_EINVAL;
        }
        new_mask &= ~unmaskable;
        /* Atomic store: thread_signal_deliverable reads this field lock-free
         * via __atomic_load_n. Without atomic stores, the concurrent read is a
         * C data race (UB).
         */
        __atomic_store_n(blocked, new_mask, __ATOMIC_RELEASE);

        /* If this mask change makes a queued signal deliverable on the current
         * thread, refresh the global hint. The caller is already returning
         * through the vCPU loop, so the next signal_pending() check will
         * observe the updated mask without broadcasting a host thread
         * interrupt.
         *
         * This closes the race where signal_queue() saw the signal blocked on
         * every thread, skipped the interrupt path, and this thread then
         * unblocked it.
         */
        uint64_t newly_unblocked = old_blocked & ~*blocked;
        if (newly_unblocked & self_pending_locked())
            refresh_pending_hint_locked();
    }

    pthread_mutex_unlock(&sig_lock);
    return 0;
}

/* rt_sigsuspend. */

int64_t signal_rt_sigsuspend(guest_t *g, uint64_t mask_gva, uint64_t sigsetsize)
{
    if (sigsetsize != 8)
        return -LINUX_EINVAL;

    if (mask_gva) {
        uint64_t mask;
        if (guest_read_small(g, mask_gva, &mask, sizeof(mask)) < 0)
            return -LINUX_EFAULT;

        pthread_mutex_lock(&sig_lock);
        uint64_t *blocked = thread_blocked_ptr();
        uint64_t *saved_ptr = thread_saved_blocked_ptr();
        bool *valid_ptr = thread_saved_valid_ptr();

        /* Save original blocked mask for restoration after signal delivery */
        uint64_t saved_blocked = *blocked;

        /* Temporarily set blocked mask (never block SIGKILL/SIGSTOP) */
        uint64_t unmaskable = sig_bit(LINUX_SIGKILL) | sig_bit(LINUX_SIGSTOP);
        *blocked = mask & ~unmaskable;

        /* If no signal is pending with the new mask, restore immediately. In a
         * real kernel, sigsuspend blocks until a signal arrives. Signal
         * emulation check if any signal became deliverable with the new mask.
         * If yes, the vCPU loop will deliver it. If no, restore the mask; the
         * caller will loop (musl retries on -EINTR).
         */
        if (!(self_pending_locked() & ~*blocked)) {
            *blocked = saved_blocked;
        }
        /* If a signal IS pending, the mask stays temporarily modified.
         * signal_deliver() will execute the handler, and rt_sigreturn will
         * restore uc_sigmask. But signal delivery needs to set uc_sigmask to
         * the ORIGINAL mask (saved_blocked), not the sigsuspend mask. Store it
         * for signal_deliver to use.
         */
        else {
            *saved_ptr = saved_blocked;
            *valid_ptr = true;
        }

        pthread_mutex_unlock(&sig_lock);
    }

    /* Always return -EINTR. */
    return -LINUX_EINTR;
}

/* rt_sigpending. */

int64_t signal_rt_sigpending(guest_t *g, uint64_t set_gva, uint64_t sigsetsize)
{
    if (sigsetsize != 8)
        return -LINUX_EINVAL;
    if (!set_gva)
        return -LINUX_EFAULT;

    pthread_mutex_lock(&sig_lock);
    /* Return all pending signals (matching Linux kernel do_sigpending): the
     * calling thread's private set unioned with the shared set. In practice
     * unblocked signals are delivered before sigpending can observe them, but
     * returning the full set is strictly correct.
     */
    uint64_t result = self_pending_locked();
    pthread_mutex_unlock(&sig_lock);

    if (guest_write_small(g, set_gva, &result, sizeof(result)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* sigaltstack. */

int64_t signal_sigaltstack(guest_t *g, uint64_t ss_gva, uint64_t old_ss_gva)
{
    thread_entry_t *t = current_thread;
    if (!t)
        return -LINUX_EFAULT;

    /* Return current per-thread altstack if requested */
    if (old_ss_gva) {
        linux_stack_t old_ss;
        old_ss.ss_sp = t->altstack_sp;
        old_ss.ss_flags = t->altstack_flags;
        old_ss._pad = 0;
        old_ss.ss_size = t->altstack_size;
        if (t->on_altstack)
            old_ss.ss_flags |= LINUX_SS_ONSTACK;
        if (guest_write_small(g, old_ss_gva, &old_ss, sizeof(old_ss)) < 0)
            return -LINUX_EFAULT;
    }

    /* Install new altstack if provided */
    if (ss_gva) {
        if (t->on_altstack)
            return -LINUX_EPERM;

        linux_stack_t ss;
        if (guest_read_small(g, ss_gva, &ss, sizeof(ss)) < 0)
            return -LINUX_EFAULT;

        if (ss.ss_flags & LINUX_SS_DISABLE) {
            t->altstack_sp = 0;
            t->altstack_flags = LINUX_SS_DISABLE;
            t->altstack_size = 0;
        } else {
            if (ss.ss_size < LINUX_MINSIGSTKSZ)
                return -LINUX_ENOMEM;
            /* Alternate stacks have the same lifetime sensitivity as clone
             * stacks: once registered, their unmap must take the host path
             * instead of being classified only as an anonymous arena range.
             */
            mmap_lock_acquire(g);
            mmap_fastpath_revoke_all_locked(g, false);
            mmap_lock_release();
            t->altstack_sp = ss.ss_sp;
            t->altstack_flags = 0;
            t->altstack_size = ss.ss_size;
        }
    }

    return 0;
}

/* Signal delivery. */

/* FPSIMD context header (required by musl for setjmp/longjmp). Linux places
 * this immediately after sigcontext.__reserved starts.
 */
#define FPSIMD_MAGIC 0x46508001U
#define FPSIMD_CONTEXT_SIZE (8 + 4 + 4 + 32 * 16) /* 528 bytes */

/* ESR context header (Linux places this after FPSIMD for synchronous faults).
 * SIGTRAP handlers read this to determine the BRK immediate value.
 */
#define ESR_MAGIC 0x45535201U
#define ESR_CONTEXT_SIZE 16 /* { __u32 magic, size; __u64 esr; } */

/* Build the extended context chain in the __reserved area. Linux kernel
 * (arch/arm64/kernel/signal.c) builds:
 *   1. FPSIMD context (always present)
 *   2. ESR context (present for synchronous faults: BRK, segfault, etc.)
 *   3. Terminator (magic=0, size=0)
 * The @esr parameter is the raw ESR_EL1 value; if non-zero, the ESR context
 * block is included.
 */
static void build_sigcontext_reserved(uint8_t *reserved,
                                      uint64_t esr,
                                      hv_vcpu_t vcpu)
{
    uint32_t off = 0;

    /* 1. FPSIMD context: save actual FP/SIMD state so it is correctly restored
     * by rt_sigreturn. Without this, a signal handler that modifies FP
     * registers would corrupt the interrupted code's state.
     */
    uint32_t fpsimd_magic = FPSIMD_MAGIC, fpsimd_size = FPSIMD_CONTEXT_SIZE;
    memcpy(reserved + off, &fpsimd_magic, 4);
    memcpy(reserved + off + 4, &fpsimd_size, 4);

    /* Save FPSR and FPCR (32-bit each, at offsets 8 and 12) */
    uint64_t fpsr_val = 0, fpcr_val = 0;
    hv_vcpu_get_reg(vcpu, HV_REG_FPSR, &fpsr_val);
    hv_vcpu_get_reg(vcpu, HV_REG_FPCR, &fpcr_val);
    uint32_t fpsr32 = (uint32_t) fpsr_val, fpcr32 = (uint32_t) fpcr_val;
    memcpy(reserved + off + 8, &fpsr32, 4);
    memcpy(reserved + off + 12, &fpcr32, 4);

    /* Save V0-V31 (128-bit each, at offset 16) */
    for (int i = 0; i < 32; i++) {
        hv_simd_fp_uchar16_t vreg = vcpu_get_simd(vcpu, (unsigned) i);
        memcpy(reserved + off + 16 + (size_t) i * 16, &vreg, 16);
    }
    off += FPSIMD_CONTEXT_SIZE;

    /* 2. ESR context (only for synchronous faults with valid ESR) */
    if (esr != 0) {
        uint32_t esr_magic = ESR_MAGIC, esr_size = ESR_CONTEXT_SIZE;
        memcpy(reserved + off, &esr_magic, 4);
        memcpy(reserved + off + 4, &esr_size, 4);
        memcpy(reserved + off + 8, &esr, 8);
        off += ESR_CONTEXT_SIZE;
    }

    /* 3. Terminator: zero magic/size */
    memset(reserved + off, 0, 8);
}

/* Build and install the rt_sigframe for `signum` on the current thread, with
 * sig_lock held on entry and released on every return path. Shared by
 * signal_deliver() (signal selected from the process-wide pending set) and
 * signal_deliver_fault() (synchronous fault forced onto the faulting thread).
 * rt_info supplies si_code/si_pid/sigval when no thread-local pending_fault is
 * set; the pending_fault is consumed (one-shot) when valid.
 *
 * Returns 1 if a handler frame was installed, 0 if the signal was ignored, and
 * -1 (with *exit_code set) when the default disposition terminates the guest.
 */
static int deliver_signal_locked(hv_vcpu_t vcpu,
                                 guest_t *g,
                                 int signum,
                                 signal_rt_info_t rt_info,
                                 int *exit_code)
{
    uint64_t *blocked = thread_blocked_ptr();
    uint64_t *saved_ptr = thread_saved_blocked_ptr();
    bool *valid_ptr = thread_saved_valid_ptr();

    /* signum is 1..64 from the caller; the static analyzer cannot see the
     * bound, so gate the array access defensively.
     */
    int idx = signum - 1;
    if (!RANGE_CHECK(idx, 0, LINUX_NSIG)) {
        pthread_mutex_unlock(&sig_lock);
        return 0;
    }
    linux_sigaction_t *act = &sig_state.actions[idx];

    /* Check handler type */
    if (act->sa_handler == LINUX_SIG_IGN) {
        /* Ignored; discard signal. Clear any stale fault info so it does not
         * leak into a later signal delivery.
         */
        pending_fault.valid = false;
        pthread_mutex_unlock(&sig_lock);
        return 0;
    }

    if (act->sa_handler == LINUX_SIG_DFL) {
        /* Apply default disposition */
        sig_disposition_t disp = signal_default_disposition(signum);
        pending_fault.valid = false;
        switch (disp) {
        case SIG_DISP_TERM:
        case SIG_DISP_CORE:
            *exit_code = 128 + signum;
            pthread_mutex_unlock(&sig_lock);
            return -1; /* Terminate */
        case SIG_DISP_IGN:
        case SIG_DISP_CONT:
        case SIG_DISP_STOP:
            pthread_mutex_unlock(&sig_lock);
            return 0; /* Ignore (STOP/CONT not meaningful for elfuse) */
        }
    }

    /* Deliver to user handler: build rt_sigframe on guest stack */

    /* 1. Save current vCPU state.
     *
     * ELR_EL1/SPSR_EL1 hold the interrupted EL0 return state only while the
     * guest is unwinding a syscall (it is at EL1 in the shim, about to ERET).
     * When the vCPU was preempted while executing EL0 code -- a tight compute
     * loop interrupted by SIGALRM, or the cross-process guest-signal transport
     * (SIGUSR2) firing mid-execution -- the live interrupted state is in
     * HV_REG_PC / HV_REG_CPSR and ELR_EL1 is stale from the previous syscall.
     * Redirecting via ELR_EL1 alone is then a no-op because the resume uses
     * HV_REG_PC, so the handler never runs and the X0..X2 writes below clobber
     * the interrupted registers instead. Detect the EL0-preemption case from
     * the live PSTATE (M[3:0]==0 => EL0t) and use PC for both save and
     * redirect.
     */
    uint64_t saved_regs[31];
    uint64_t saved_sp, saved_pc, saved_pstate;
    uint64_t cur_cpsr = 0;
    hv_vcpu_get_reg(vcpu, HV_REG_CPSR, &cur_cpsr);
    bool el0_preempt = (cur_cpsr & 0xfULL) == 0;

    vcpu_snapshot_gprs(vcpu, saved_regs);
    saved_sp = vcpu_get_sysreg(vcpu, HV_SYS_REG_SP_EL0);
    if (el0_preempt) {
        hv_vcpu_get_reg(vcpu, HV_REG_PC, &saved_pc);
        saved_pstate = cur_cpsr;
    } else {
        saved_pc = vcpu_get_sysreg(vcpu, HV_SYS_REG_ELR_EL1);
        saved_pstate = vcpu_get_sysreg(vcpu, HV_SYS_REG_SPSR_EL1);
    }

    /* 1b. rseq abort: if the thread is in a restartable sequence critical
     * section, abort it. Linux does this on every signal delivery.
     */
    if (current_thread) {
        int rseq_rc = rseq_try_abort(g, current_thread->rseq_gva,
                                     current_thread->rseq_signature, &saved_pc);
        if (rseq_rc == 1)
            hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, saved_pc);
        if (rseq_rc == -1) {
            *exit_code = 128 + 11; /* SIGSEGV */
            pthread_mutex_unlock(&sig_lock);
            return -1;
        }
    }

    /* 2. Build the rt_sigframe */
    linux_rt_sigframe_t frame;
    memset(&frame, 0, sizeof(frame));

    /* siginfo: fault signals use si_code/si_addr from pending_fault; queued RT
     * signals preserve sender metadata and sigval.
     */
    frame.info.si_signo = signum;
    if (pending_fault.valid) {
        frame.info.si_code = pending_fault.si_code;
        /* si_addr overlaps si_pid/si_uid at offset 16 in the siginfo union. On
         * aarch64-linux, si_addr is a 64-bit pointer occupying both int32_t
         * fields. Write it via memcpy to avoid strict aliasing.
         */
        memcpy(&frame.info.si_pid, &pending_fault.addr, 8);
    } else {
        frame.info.si_code = rt_info.si_code;
        frame.info.si_pid = rt_info.si_pid;
        frame.info.si_uid = (int32_t) rt_info.si_uid;
        frame.info.si_value = rt_info.si_ptr;
    }

    /* ucontext: embed a per-delivery cookie in uc_flags for SROP validation.
     * rt_sigreturn checks this before restoring state. Low priority (guest is
     * same trust domain) but prevents accidental frame corruption from
     * redirecting execution.
     */
    uint64_t cookie;
    arc4random_buf(&cookie, sizeof(cookie));
    cookie |=
        1; /* Ensure nonzero because zero uc_flags means uncookied frame */
    frame.uc.uc_flags = cookie;
    frame.uc.uc_link = 0;

    /* If delivering from sigsuspend, store the ORIGINAL blocked mask so
     * rt_sigreturn restores it (not the temporary sigsuspend mask).
     */
    if (*valid_ptr) {
        frame.uc.uc_sigmask = *saved_ptr;
        *valid_ptr = false;
    } else {
        frame.uc.uc_sigmask = *blocked;
    }

    /* sigcontext: save all registers. fault_address: for synchronous faults
     * (BRK, segfault), set to the faulting address; for asynchronous signals,
     * zero. frame_esr: raw ESR_EL1 for the extended context chain. SIGTRAP
     * handlers read this to determine the BRK immediate value.
     */
    uint64_t frame_esr = 0;
    if (pending_fault.valid) {
        frame.uc.uc_mcontext.fault_address = pending_fault.addr;
        frame_esr = pending_fault.esr;
        pending_fault.valid = false; /* Consume (one-shot) */
    }

    memcpy(frame.uc.uc_mcontext.regs, saved_regs, sizeof(saved_regs));
    frame.uc.uc_mcontext.sp = saved_sp;
    frame.uc.uc_mcontext.pc = saved_pc;
    frame.uc.uc_mcontext.pstate = saved_pstate;

    /* Extended context chain in __reserved area (FPSIMD + optional ESR). The
     * ESR context lets signal handlers read the exception syndrome (e.g., BRK
     * immediate from ESR ISS[15:0]) to determine trap type.
     */
    build_sigcontext_reserved(frame.uc.uc_mcontext.__reserved, frame_esr, vcpu);

    /* Save the per-thread altstack info in uc_stack for gdb/tools */
    thread_entry_t *thr = current_thread;
    frame.uc.uc_stack.ss_sp = thr ? thr->altstack_sp : 0;
    frame.uc.uc_stack.ss_flags = thr ? thr->altstack_flags : LINUX_SS_DISABLE;
    frame.uc.uc_stack._pad = 0;
    frame.uc.uc_stack.ss_size = thr ? thr->altstack_size : 0;
    if (thr && thr->on_altstack)
        frame.uc.uc_stack.ss_flags |= LINUX_SS_ONSTACK;

    /* 3. Determine stack for signal frame: use altstack if SA_ONSTACK is set,
     * an altstack is configured, and the thread is not already on it. Across
     * fork, only the forking thread's altstack is preserved (via
     * signal_get_state). Worker thread altstacks start as SS_DISABLE in the
     * child, matching Linux kernel per-thread altstack semantics.
     */
    uint64_t signal_sp = saved_sp;
    bool use_altstack = false;
    if (thr && (act->sa_flags & LINUX_SA_ONSTACK) &&
        !(thr->altstack_flags & LINUX_SS_DISABLE) && !thr->on_altstack) {
        /* Place frame at top of altstack (stack grows down) */
        signal_sp = thr->altstack_sp + thr->altstack_size;
        use_altstack = true;
    }

    /* Guard against underflow: if signal_sp is too small to hold the frame, the
     * subtraction wraps to a huge address. guest_write_small would catch it,
     * but report the problem early with a diagnostic.
     */
    if (signal_sp < sizeof(frame)) {
        log_error(
            "signal_deliver: SP too low for frame "
            "(signal_sp=0x%llx signum=%d)",
            (unsigned long long) signal_sp, signum);
        *exit_code = 128 + signum;
        pthread_mutex_unlock(&sig_lock);
        return -1;
    }
    uint64_t frame_sp = (signal_sp - sizeof(frame)) & ~15ULL;

    /* Push the SROP cookie for validation on rt_sigreturn. If nesting exceeds
     * MAX_NESTED_SIGNALS, skip the cookie entirely (set uc_flags=0) so
     * rt_sigreturn does not mis-validate.
     */
    bool pushed_cookie = false;
    if (sigreturn_cookie_depth < MAX_NESTED_SIGNALS) {
        sigreturn_cookies[sigreturn_cookie_depth++] = cookie;
        pushed_cookie = true;
    } else {
        frame.uc.uc_flags = 0;
    }

    if (guest_write_small(g, frame_sp, &frame, sizeof(frame)) < 0) {
        /* Frame write failure terminates with default disposition */
        log_error(
            "signal_deliver: guest_write failed for "
            "frame_sp=0x%llx (signal_sp=0x%llx signum=%d frame_size=%zu)",
            (unsigned long long) frame_sp, (unsigned long long) signal_sp,
            signum, sizeof(frame));
        if (pushed_cookie)
            sigreturn_cookie_depth--;
        *exit_code = 128 + signum;
        pthread_mutex_unlock(&sig_lock);
        return -1;
    }

    /* 4. Redirect vCPU to signal handler */
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, frame_sp);
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, act->sa_handler);
    /* SPSR_EL1: EL0t (user mode) */
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SPSR_EL1, 0);

    /* EL0-preemption delivery: the resume runs from HV_REG_PC, not via an ERET
     * that consumes ELR_EL1, so redirect the live PC/PSTATE directly. The
     * ELR_EL1/SPSR_EL1 writes above still cover the rt_sigreturn path, which
     * unwinds back to EL0 through the shim ERET.
     */
    if (el0_preempt) {
        hv_vcpu_set_reg(vcpu, HV_REG_PC, act->sa_handler);
        hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0); /* EL0t */
    }

    /* X0 = signal number */
    hv_vcpu_set_reg(vcpu, HV_REG_X0, (uint64_t) signum);

    /* X30 (LR) = return address for signal handler. On aarch64-linux, the
     * kernel always sets LR to the vDSO's __kernel_rt_sigreturn (mov x8,#139;
     * svc #0; ret). The sa_restorer field is architecturally unused on aarch64;
     * the kernel ignores it. glibc leaves sa_restorer uninitialized (garbage);
     * musl sets it to __restore_rt. Match the kernel: always use the vDSO
     * trampoline.
     */
    hv_vcpu_set_reg(vcpu, HV_REG_X30, VDSO_BASE + VDSO_OFF_SIGRET);

    if (act->sa_flags & LINUX_SA_SIGINFO) {
        /* X1 = pointer to siginfo, X2 = pointer to ucontext */
        uint64_t siginfo_addr = frame_sp;
        uint64_t ucontext_addr = frame_sp + sizeof(linux_siginfo_t);
        hv_vcpu_set_reg(vcpu, HV_REG_X1, siginfo_addr);
        hv_vcpu_set_reg(vcpu, HV_REG_X2, ucontext_addr);
    }

    /* 5. Update blocked mask during handler execution */
    if (!(act->sa_flags & LINUX_SA_NODEFER))
        *blocked |= sig_bit(signum);
    *blocked |= act->sa_mask;
    /* Never block SIGKILL/SIGSTOP */
    *blocked &= ~(sig_bit(LINUX_SIGKILL) | sig_bit(LINUX_SIGSTOP));

    /* 6. Track per-thread altstack usage */
    if (use_altstack && thr)
        thr->on_altstack = true;

    /* 7. Reset to SIG_DFL if SA_RESETHAND is set */
    if (act->sa_flags & LINUX_SA_RESETHAND) {
        act->sa_handler = LINUX_SIG_DFL;
        act->sa_flags &= ~LINUX_SA_SIGINFO;
    }

    /* If delivery happens while returning from the syscall HVC path, the shim
     * still has the interrupted syscall frame on its EL1 stack. Tell it to drop
     * that frame so the handler PC/SP/LR/args installed above are not
     * overwritten before ERET. HVC #9 fault fallback uses the same marker when
     * it materializes a SIGSEGV frame; HVC #11 and BRK delivery paths do not
     * consume it. The EL0-preemption path resumes straight into the handler at
     * EL0 with no shim frame to drop, so the marker is neither needed nor
     * consulted.
     */
    if (!el0_preempt)
        hv_vcpu_set_reg(vcpu, HV_REG_X8, 2);

    pthread_mutex_unlock(&sig_lock);
    return 1;
}

/* Pre-fault the candidate signal-frame windows (current stack and altstack
 * top) before sig_lock is taken. The frame write in deliver_signal_locked
 * runs under sig_lock; letting it materialize lazy stack pages there would
 * acquire mmap_lock in descending lock order. The pre-fault is advisory --
 * the write path still faults in as a backstop -- but it makes the
 * under-lock engagement unreachable in practice. Reading the altstack
 * fields without sig_lock is benign for the same reason.
 */
static void signal_prefault_frame(hv_vcpu_t vcpu, guest_t *g)
{
    uint64_t need = sizeof(linux_rt_sigframe_t) + 512;
    uint64_t sp = 0;
    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL0, &sp);
    if (sp > need && sp <= g->guest_size)
        guest_lazy_faultin(g, sp - need, need);
    thread_entry_t *thr = current_thread;
    if (thr && thr->altstack_sp != 0 &&
        !(thr->altstack_flags & LINUX_SS_DISABLE) && thr->altstack_size > need)
        guest_lazy_faultin(g, thr->altstack_sp + thr->altstack_size - need,
                           need);
}

int signal_deliver(hv_vcpu_t vcpu, guest_t *g, int *exit_code)
{
    signal_prefault_frame(vcpu, g);
    pthread_mutex_lock(&sig_lock);
    uint64_t *blocked = thread_blocked_ptr();
    /* Consider this thread's private (thread-directed) set plus the shared
     * (process-directed) set. Linux dequeue_signal() drains task->pending
     * before signal->shared_pending, so for a given signum the private instance
     * wins.
     */
    signal_pending_t *tp = current_thread ? &current_thread->tpending : NULL;
    uint64_t thread_d = tp ? (tp->pending & ~*blocked) : 0;
    uint64_t shared_d = sig_state.shared.pending & ~*blocked;
    if ((thread_d | shared_d) == 0) {
        pthread_mutex_unlock(&sig_lock);
        return 0;
    }

    /* Linux dequeue_signal() drains task->pending before shared_pending, so the
     * private set wins even when the shared set holds a lower signal number.
     * Within the chosen set, pick the lowest pending unblocked signal.
     */
    int signum;
    signal_pending_t *src;
    if (thread_d) {
        signum = bit_ctz64(thread_d) + 1;
        src = tp;
    } else {
        signum = bit_ctz64(shared_d) + 1;
        src = &sig_state.shared;
    }
    signal_rt_info_t rt_info = signal_default_info(signum);

    /* Dequeue: for RT signals, decrement count and only clear the pending bit
     * when the queue is empty. Standard signals are always cleared (single
     * instance, bitmask semantics).
     */
    if (signum >= LINUX_SIGRTMIN) {
        signal_rt_dequeue_locked(src, signum, &rt_info);
    } else {
        rt_info = signal_standard_peek_locked(src, signum);
        src->std_info_valid[signum - 1] = false;
        src->pending &= ~sig_bit(signum);
    }
    /* A directed dequeue cleared a bit that only this thread's set held, so the
     * global hint must be recomputed from the surviving pending state.
     */
    refresh_pending_hint_locked();

    return deliver_signal_locked(vcpu, g, signum, rt_info, exit_code);
}

int signal_deliver_fault(hv_vcpu_t vcpu, guest_t *g, int signum, int *exit_code)
{
    /* Synchronous faults (SIGSEGV/SIGBUS/SIGILL/SIGFPE/SIGTRAP) are specific to
     * the thread that triggered them and must be delivered to that thread with
     * the thread-local fault info set by signal_set_fault_info(). Routing them
     * through the process-wide pending bitmask (signal_queue + signal_deliver)
     * is racy: another vCPU thread can dequeue the bit and deliver it with no
     * fault info (si_code becomes SI_USER, which makes a JVM treat a
     * recoverable implicit null-check as a fatal external signal), and two
     * threads faulting on the same signal collapse into one bit so one fault is
     * lost. Deliver directly here, never touching sig_state.pending.
     */
    signal_prefault_frame(vcpu, g);
    pthread_mutex_lock(&sig_lock);

    /* Linux force_sig_info_to_task(): a forced synchronous fault cannot be
     * postponed or ignored. If the disposition is SIG_IGN or the signum is
     * blocked, reset to SIG_DFL and unblock before delivery, so the default
     * disposition terminates the process instead of resuming at the faulting PC
     * (SIG_IGN would re-fault forever) or running a handler the guest asked to
     * block.
     */
    int idx = signum - 1;
    if (RANGE_CHECK(idx, 0, LINUX_NSIG)) {
        uint64_t *blocked = thread_blocked_ptr();
        linux_sigaction_t *act = &sig_state.actions[idx];
        if (act->sa_handler == LINUX_SIG_IGN || (*blocked & sig_bit(signum))) {
            act->sa_handler = LINUX_SIG_DFL;
            act->sa_flags &= ~LINUX_SA_SIGINFO;
            *blocked &= ~sig_bit(signum);
        }
    }

    signal_rt_info_t rt_info = signal_default_info(signum);
    return deliver_signal_locked(vcpu, g, signum, rt_info, exit_code);
}

/* rt_sigreturn. */

int signal_rt_sigreturn(hv_vcpu_t vcpu, guest_t *g)
{
    /* Read SP_EL0; frame was pushed at current SP */
    uint64_t sp;
    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL0, &sp);

    /* Read the rt_sigframe from guest stack */
    linux_rt_sigframe_t frame;
    if (guest_read_small(g, sp, &frame, sizeof(frame)) < 0)
        return -LINUX_EFAULT;

    /* Validate SROP cookie from uc_flags. Zero means the cookie was skipped
     * (nesting overflow or pre-existing frame); allow those.
     */
    uint64_t frame_cookie = frame.uc.uc_flags;
    if (frame_cookie != 0 && sigreturn_cookie_depth > 0) {
        uint64_t expected = sigreturn_cookies[sigreturn_cookie_depth - 1];
        if (frame_cookie != expected) {
            log_error(
                "rt_sigreturn: SROP cookie mismatch "
                "(expected=0x%llx got=0x%llx)",
                (unsigned long long) expected,
                (unsigned long long) frame_cookie);
            return -LINUX_EFAULT;
        }
        sigreturn_cookie_depth--;
    }

    /* Validate restored PC before touching any vCPU state. Reject addresses in
     * the EL1 shim or page table pool region; a crafted signal frame could
     * redirect execution into EL1 code. Must happen before GPR/SP/PSTATE
     * restore so that a failed check does not leave the vCPU with
     * partially-attacker-controlled state. The infra reserve sits at high IPA
     * (just below g->interp_base); use the runtime check rather than
     * compile-time constants.
     */
    uint64_t restored_pc = frame.uc.uc_mcontext.pc;
    if (guest_addr_in_infra(g, restored_pc))
        return -LINUX_EFAULT;

    /* Restore all 31 GPRs */
    vcpu_restore_gprs(vcpu, frame.uc.uc_mcontext.regs);

    /* Restore SP, PC, PSTATE */
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, frame.uc.uc_mcontext.sp);
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, restored_pc);
    /* Sanitize PSTATE: preserve EL0-safe bits, clear everything else. Bit
     * fields preserved (matching Linux kernel's valid_user_regs):
     *   [31:28] NZCV:   condition flags
     *   [27:26] RES0:   cleared
     *   [25]    TCO:    tag check override (MTE, EL0-accessible)
     *   [24]    DIT:    data independent timing (crypto, EL0-accessible)
     *   [23]    UAO:    cleared (EL1-only)
     *   [22]    PAN:    cleared (EL1-only)
     *   [21]    SS:     cleared (software step, debug)
     *   [20]    IL:     cleared (illegal state)
     *   [12]    SSBS:   speculative store bypass (EL0-accessible)
     *   [11:10] BTYPE:  BTI branch type (EL0-accessible, harmless)
     *   [9:0]   cleared (DAIF, mode bits)
     * Mask: 0xF3001C00
     */
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SPSR_EL1,
                        frame.uc.uc_mcontext.pstate & 0xF3001C00ULL);

    /* Restore FPSIMD state from the sigcontext __reserved area. The FPSIMD
     * context starts at offset 0 of __reserved (after magic/size).
     */
    const uint8_t *reserved = frame.uc.uc_mcontext.__reserved;
    uint32_t fpsimd_magic;
    memcpy(&fpsimd_magic, reserved, 4);
    if (fpsimd_magic == FPSIMD_MAGIC) {
        uint32_t fpsr32, fpcr32;
        memcpy(&fpsr32, reserved + 8, 4);
        memcpy(&fpcr32, reserved + 12, 4);
        hv_vcpu_set_reg(vcpu, HV_REG_FPSR, fpsr32);
        hv_vcpu_set_reg(vcpu, HV_REG_FPCR, fpcr32);
        for (int i = 0; i < 32; i++) {
            hv_simd_fp_uchar16_t vreg;
            memcpy(&vreg, reserved + 16 + (size_t) i * 16, 16);
            vcpu_set_simd(vcpu, (unsigned) i, vreg);
        }
    }

    /* Restore signal mask and update altstack-in-use flag. If the restored SP
     * is still within the altstack range (nested signal case), keep
     * on_altstack=1. Matches Linux kernel's restore_altstack.
     */
    pthread_mutex_lock(&sig_lock);
    uint64_t *blocked = thread_blocked_ptr();
    *blocked = frame.uc.uc_sigmask;
    *blocked &= ~(sig_bit(LINUX_SIGKILL) | sig_bit(LINUX_SIGSTOP));
    if (current_thread) {
        uint64_t restored_sp = frame.uc.uc_mcontext.sp;
        if (current_thread->altstack_sp &&
            restored_sp >= current_thread->altstack_sp &&
            restored_sp <
                current_thread->altstack_sp + current_thread->altstack_size)
            current_thread->on_altstack = true;
        else
            current_thread->on_altstack = false;
    }
    pthread_mutex_unlock(&sig_lock);

    /* Tell the EL1 shim to drop its saved syscall frame. rt_sigreturn has
     * restored the complete guest register state here; letting the shim restore
     * X1-X30 from the rt_sigreturn syscall entry would corrupt the interrupted
     * context.
     */
    hv_vcpu_set_reg(vcpu, HV_REG_X8, 2);

    /* Return SYSCALL_EXEC_HAPPENED to skip the normal X0 writeback, since
     * sigreturn has restored the entire register set.
     */
    return SYSCALL_EXEC_HAPPENED;
}
