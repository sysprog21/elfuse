/*
 * Per-thread state for Linux threading support
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Maintains a table of guest threads. Each thread has its own HVF vCPU running
 * on a dedicated host pthread. The main thread is registered at startup; worker
 * threads are added via clone(CLONE_THREAD). A _Thread_local pointer provides
 * O(1) access to the current thread's entry from any syscall handler.
 *
 * SP_EL1 allocation: each thread gets a 4KiB EL1 exception stack carved from
 * the shim data region (g->shim_data_base + 2MiB). Thread 0 (main) gets the
 * top, thread N gets offset -(N * 4096).
 */

#pragma once

#include <Hypervisor/Hypervisor.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

#include "core/guest.h"         /* guest_t (for thread_alloc_sp_el1) */
#include "syscall/linux-wire.h" /* linux_user_pt_regs_t */
#include "syscall/signal.h" /* signal_pending_t (per-thread directed signals) */

/* Maximum number of concurrent guest threads in one VM. */
#define MAX_THREADS 64

/* One EL1 exception stack per thread. Named because the region these slots
 * occupy is a bound as well as an allocation: the host writes into a live shim
 * frame on that stack, and anything below the lowest slot is the shim-globals
 * cache rather than stack.
 */
#define SP_EL1_SLOT_BYTES 4096
#define MAX_DEFERRED_STACK_UNMAPS 8

/* Per-thread state. One entry per guest thread (main + workers). Tagged (struct
 * thread_entry) so signal.h can forward-declare it for the thread-directed
 * signal API without an include cycle.
 */
typedef struct thread_entry {
    /* Read without thread_lock. Three scans walk the table lock-free
     * (thread_pending_union, thread_tid_alive, thread_signal_deliverable): each
     * loads active, then one of blocked, guest_tid, or tpending.pending, with
     * nothing in between. A scanner that saw active as 1 just before this slot
     * went inactive can still be loading one of those when thread_alloc
     * recycles the slot, so none of them may be plain-written there. They are
     * grouped here, cleared with atomic stores, and deliberately excluded from
     * the memset that clears the rest. Keep them ahead of the rest of the
     * struct; thread.c asserts that each one sits below where its memset
     * starts.
     */
    _Atomic int active; /* Non-zero while thread is running. Stays int (not
                         * bool) because lock-free paths in thread.c use
                         * atomic_load_explicit on it; the 32-bit width keeps
                         * the access pattern predictable across architectures.
                         */
    _Atomic uint64_t
        blocked; /* Per-thread signal mask (POSIX requires each thread to
                  * have its own). Initialized to the parent's mask on
                  * clone, modified via rt_sigprocmask.
                  */
    _Atomic int64_t guest_tid; /* Linux TID (unique per thread) */

    /* The Linux syscall this thread is inside, or -1 between calls. Written
     * around the handler call in syscall_dispatch and read only by the execve
     * teardown, which otherwise reports a sibling that would not leave by tid
     * alone and leaves the wait it is parked in to be guessed. Sits in this
     * group so the one memset below it stays one memset.
     */
    _Atomic int32_t in_syscall;

    /* Thread-directed pending signals (Linux task->pending). tgkill/tkill and
     * pthread_kill queue here so only this thread consumes them. Written and
     * read under the signal module's sig_lock; do not touch without it. Only
     * the leading pending bitmask is scanned lock-free, so the recycle clear
     * stores that one atomically and memsets the rest of this struct.
     */
    signal_pending_t tpending;

    /* First fully lock-private field. thread_alloc memsets from here on. */
    hv_vcpu_t vcpu;              /* HVF vCPU handle for this thread */
    bool vcpu_valid;             /* Handle has been published and not destroyed.
                                  * hv_vcpu_t value 0 is valid, so the handle
                                  * itself cannot be used as a sentinel.
                                  */
    hv_vcpu_exit_t *vexit;       /* vCPU exit info pointer */
    pthread_t host_thread;       /* macOS host thread running this vCPU */
    bool host_thread_needs_join; /* host_thread was created joinable and nobody
                                  * has joined it yet. Exactly one claimer
                                  * clears the flag under thread_lock before
                                  * joining: slot reuse in thread_alloc,
                                  * teardown in thread_join_workers, or the
                                  * clone startup-failure rollback. Never set
                                  * for the main thread or vm-clone children
                                  * (the latter are created detached).
                                  */
    uint64_t clear_child_tid;    /* GVA for CLONE_CHILD_CLEARTID (0=none) */
    uint64_t sp_el1;             /* Per-thread EL1 stack top (IPA) */
    int sp_el1_slot;             /* Slot index in sp_el1_allocated (-1 = none).
                                  * Stored at alloc time so the free path does
                                  * not need to recompute (top - sp) / 4096; the
                                  * shim data block is now at high IPA and only
                                  * known via guest_t.
                                  */
    uint64_t generation; /* Bumped by thread_alloc each time this slot is
                          * reused. Lets a caller holding a t pointer detect
                          * that its slot was recycled to a different logical
                          * thread while it was not looking (e.g. a clone
                          * parent that raced with a starting-up worker's own
                          * failure path). Read/written under thread_lock,
                          * except for the lock-free comparison in
                          * thread_join_workers' teardown poll, which uses
                          * acquire/release ordering against thread_alloc's
                          * release-store.
                          */
    bool join_abandoned; /* thread_join_workers timed out on this worker and
                          * pthread_detach()ed it. Later join passes
                          * (guest_destroy runs one after main()'s) must skip
                          * the entry: pthread_join/pthread_detach on an
                          * already-detached thread is undefined.
                          */
    /* Per-thread signal mask lives at the top of the struct; see the lock-free
     * group there. saved_blocked is touched only under sig_lock by the owning
     * thread, so it stays here with the rest of the signal state.
     */
    uint64_t saved_blocked; /* Original mask saved by sigsuspend */
    bool saved_blocked_valid;

    /* Per-thread alternate signal stack (Linux sigaltstack is per-thread).
     * Fields mirror linux_stack_t layout for easy copy.
     */
    uint64_t altstack_sp;   /* Alternate signal stack pointer */
    int32_t altstack_flags; /* SS_DISABLE / 0 */
    uint64_t altstack_size; /* Alternate signal stack size */
    bool on_altstack;       /* True if currently delivering on altstack */

    /* Robust futex list head (GVA). When non-zero, thread exit walks the list
     * and sets FUTEX_OWNER_DIED on each lock word.
     */
    uint64_t robust_list_head;

    /* rseq (restartable sequences) per-thread registration state. When rseq_gva
     * != 0, the thread has a registered struct rseq. Signal delivery and
     * preemption must abort active critical sections.
     */
    uint64_t rseq_gva;       /* Guest VA of struct rseq (0 = not registered) */
    uint32_t rseq_len;       /* Length from registration */
    uint32_t rseq_signature; /* Abort signature from registration */

    /* Fork-quiesce barrier accounting. Set by thread_quiesce_siblings for each
     * sibling it counted into fork_target_count; cleared when the thread either
     * reaches thread_fork_barrier_check (contributing to fork_quiesced_count)
     * or deactivates first (decrementing fork_target_count so the forker is not
     * stalled). Guards both sides so a thread created after the barrier armed
     * neither inflates nor deflates the tally. Written under thread_lock.
     */
    bool fork_counted;

    /* ptrace state. Used by two-process JIT architectures: the tracer attaches
     * via PTRACE_SEIZE, then uses BRK-triggered SIGTRAP + wait4 to discover
     * untranslated code on-demand. The tracee snapshots its own vCPU registers
     * before stopping and applies any tracer-written changes on resume,
     * avoiding cross-thread HVF register access (which may not be supported).
     */
    bool ptraced;                /* True if being traced */
    int64_t tracer_tid;          /* TID of tracing thread */
    bool ptrace_stopped;         /* True when in ptrace-stop */
    int ptrace_stop_sig;         /* Signal that caused the stop */
    pthread_cond_t ptrace_cond;  /* Tracee stopped -> tracer wakes */
    pthread_cond_t resume_cond;  /* Tracer CONT -> tracee wakes */
    bool ptrace_conds_inited;    /* Condvars initialized for this slot */
    int ptrace_waiters;          /* Tracers currently blocked on ptrace_cond */
    bool ptrace_cleanup_pending; /* Destroy condvars after last waiter leaves */
    int ptrace_cont_sig;         /* Signal to inject on resume (0=none) */
    bool ptrace_interrupt_pending;    /* A ptrace-stop is owed to this thread.
                                       * Set by every PTRACE_INTERRUPT, not only
                                       * the bring-up race it started as: the
                                       * kick alone is not enough, because it can
                                       * land while the vCPU is at EL1 in the
                                       * shim, where the live registers are shim
                                       * scratch and a stop would show the tracer
                                       * those instead of the guest's. Consumed
                                       * in the HVC #5 epilogue, which then
                                       * either stops in place or routes the
                                       * stop through HVC #13, or by the
                                       * canceled-exit handler once it has
                                       * established EL0. A vCPU
                                       * still in bring-up (!vcpu_valid) cannot
                                       * be kicked at all and self-kicks at
                                       * publish. Under thread_lock.
                                       */
    linux_user_pt_regs_t ptrace_regs; /* snapshot for cross-thread access */
    bool ptrace_regs_dirty;           /* Tracer modified registers */

    /* GDB stub state. Per-thread stop state for the GDB remote stub. When GDB
     * requests a stop (breakpoint, Ctrl+C, step), the thread records its stop
     * reason here so the stub can report it to GDB.
     *
     * Register access: HVF requires vCPU register reads/writes on the owning
     * thread. When stopped, the vCPU thread snapshots registers into
     * gdb_reg_snapshot; the GDB handler thread reads/writes that buffer. On
     * resume, dirty changes are applied back to the vCPU.
     */
    uint8_t gdb_reg_snapshot[788]; /* Register snapshot for GDB
                                    * Layout: 31xGPR(8) + SP(8) + PC(8)
                                    * + CPSR(4) + 32xV(16) + FPSR(4) + FPCR(4)
                                    */
    bool gdb_regs_dirty;           /* GDB handler modified snapshot */

    /* VM-clone child state. For clone(CLONE_VM) without CLONE_THREAD: shares
     * guest memory but has a separate TID, is waitable via wait4, and can be
     * ptraced. Used by clone(CLONE_VM) two-process architecture.
     */
    bool is_vm_clone;   /* Waitable via wait4 */
    int64_t parent_tid; /* Parent TID for wait4 matching */
    int exit_signal;    /* Signal on exit (usually SIGCHLD) */
    bool vm_exited;     /* Child has exited */
    int vm_exit_status; /* Wait-format exit status */

    /* Guest stack range supplied by clone3(stack, stack_size). elfuse uses this
     * to avoid tearing down a still-active child stack when another thread
     * munmaps the backing range before the child is done with its bootstrap
     * stack.
     */
    uint64_t stack_map_start;
    uint64_t stack_map_end;
    uint64_t deferred_stack_unmap_starts[MAX_DEFERRED_STACK_UNMAPS];
    uint64_t deferred_stack_unmap_ends[MAX_DEFERRED_STACK_UNMAPS];
    int deferred_stack_unmap_count;
    int deferred_stack_unmap_busy;
} thread_entry_t;

/* The one definition of how the lock-free-scanned signal mask is accessed.
 * Writers are the owning thread under sig_lock, plus the parent that clones a
 * child before its pthread exists; readers are the lock-free scans. Going
 * through these keeps the memory order in one place, so a new writer cannot
 * plain-store the field by omission.
 */
static inline void thread_blocked_store(thread_entry_t *t, uint64_t mask)
{
    atomic_store_explicit(&t->blocked, mask, memory_order_release);
}

static inline uint64_t thread_blocked_load(const thread_entry_t *t)
{
    return atomic_load_explicit(&t->blocked, memory_order_acquire);
}

/* The same treatment for the TID, which the lock-free scans in thread_tid_alive
 * and the /proc walkers read while thread_alloc is writing a recycled slot.
 * Relaxed is the whole requirement: the field is a value, not a gate on
 * anything else, and every caller that needs the slot's other fields reaches
 * them through the active flag's release-acquire pair.
 */
static inline int64_t thread_tid(const thread_entry_t *t)
{
    return atomic_load_explicit(&t->guest_tid, memory_order_relaxed);
}

typedef struct {
    thread_entry_t *thread;
    int64_t guest_tid;
    uint64_t start;
    uint64_t end;
    uint64_t deferred_starts[MAX_DEFERRED_STACK_UNMAPS];
    uint64_t deferred_ends[MAX_DEFERRED_STACK_UNMAPS];
    int deferred_count;
} thread_deferred_stack_unmap_txn_t;

/* Current thread pointer, set once per host pthread at thread start. All
 * syscall handlers can access per-thread state through this.
 */
extern _Thread_local thread_entry_t *current_thread;

/* Initialize the thread table. Call once before any thread operations. */
void thread_init(void);

/* Register the main thread (thread 0). Called from main.c after the initial
 * vCPU is created. Sets current_thread for the main thread.
 */
void thread_register_main(hv_vcpu_t vcpu,
                          hv_vcpu_exit_t *vexit,
                          int64_t tid,
                          uint64_t sp_el1);

/* Allocate a new thread table slot for the given TID.
 * Returns a pointer to the entry, or NULL if the table is full. The caller must
 * fill in vcpu, vexit, host_thread, sp_el1.
 */
thread_entry_t *thread_alloc(int64_t tid,
                             uint64_t stack_start,
                             uint64_t stack_end);

/* Mark a thread as inactive and release its table slot. */
void thread_deactivate(thread_entry_t *t);

/* Record the host pthread backing this entry, under thread_lock so concurrent
 * table readers (thread_join_workers snapshot, thread_alloc slot reuse) see a
 * consistent handle. joinable marks the handle as needing a pthread_join before
 * its slot can be reused; pass false for detached pthreads (vm-clone children).
 * generation must be the value of t->generation the caller observed when it
 * obtained t from thread_alloc: if the slot was recycled to a different logical
 * thread in the meantime (the calling worker failed startup and deactivated
 * before this call ran), the current generation no longer matches and the write
 * is rejected -- the caller then owns thr exclusively and must join or detach
 * it itself.
 *
 * Returns true if recorded.
 */
bool thread_set_host_thread(thread_entry_t *t,
                            pthread_t thr,
                            bool joinable,
                            uint64_t generation);

/* Atomically claim the right to pthread_join a worker's handle.
 *
 * Returns true when the caller must join thr; false when someone else (slot
 * reuse in thread_alloc) already claimed it, or the slot no longer holds thr.
 * Used by the clone startup-failure rollback so the parent's join cannot race
 * with a concurrent slot reuse joining the same terminated pthread.
 */
bool thread_claim_worker_join(thread_entry_t *t, pthread_t thr);

/* Find a thread by guest TID. Returns NULL if not found. */
thread_entry_t *thread_find(int64_t tid);

/* Find a thread by guest TID with thread_lock already held by the caller.
 * Returns a pointer that stays valid only while the caller keeps thread_lock.
 * Used by the signal module to resolve a tgkill target and enqueue into its
 * private pending set atomically against slot reuse. Acquire sig_lock (4)
 * before thread_lock (5) per the documented lock order.
 */
thread_entry_t *thread_find_locked(int64_t tid);

/* Lock-free check: is there an active thread with this TID?
 * Returns true if found. Safe to call without holding any lock (used from
 * futex_lock_pi to avoid lock order inversion with bucket locks). May return a
 * stale true if the thread is being deactivated concurrently; callers must
 * tolerate this.
 */
bool thread_tid_alive(int64_t tid);

/* Count currently active threads. */
int thread_active_count(void);

/* OR of every active thread's private pending bitmask (thread-directed
 * signals). The signal module folds this into its global "maybe pending" hint.
 * Caller must hold sig_lock so the tpending fields are stable; the active-slot
 * scan itself takes no lock and tolerates a racing (de)activation as a harmless
 * superset.
 */
uint64_t thread_pending_union(void);

/* Fast path: return non-zero when exactly one guest thread is active. */
int thread_is_single_active(void);

/* Allocate a per-thread SP_EL1 stack and record both the IPA and the slot index
 * into t. Thread N gets the Nth SP_EL1_SLOT_BYTES slot counting down from the
 * top of the shim data block (g->shim_data_base + 2MiB). The shim block lives
 * at high IPA computed by guest_init, so callers must pass g; the slot index is
 * stored in t->sp_el1_slot so the free path (which is reached from teardown
 * contexts that lack g) can clear the bitmask directly.
 * Returns the SP_EL1 IPA, or 0 on slot exhaustion.
 */
uint64_t thread_alloc_sp_el1(const guest_t *g, thread_entry_t *t);

/* The IPA range the slots above are carved from: *lo is the bottom of the
 * lowest slot, *hi one past the top of the highest, so a live SP_EL1 is in
 * [*lo, *hi).
 *
 * The shim data block holds two unrelated things. These slots sit at the top of
 * it, and the shim-globals cache -- identity slots, urandom ring, attention
 * bitmask -- starts at the bottom. A host that validates an SP_EL1 against the
 * whole block therefore accepts addresses that name cache and not stack, and
 * writing a shim frame at one of those corrupts the cache instead of reporting
 * the bad SP_EL1. Callers that write through an SP_EL1 bound it with this.
 */
void thread_sp_el1_region(const guest_t *g, uint64_t *lo, uint64_t *hi);

/* Iterate over all active threads, calling fn(entry, ctx) for each. Holds the
 * thread table lock during iteration.
 */
void thread_for_each(void (*fn)(thread_entry_t *t, void *ctx), void *ctx);

/* True when a tracee that can still consume one owes a PTRACE_INTERRUPT stop.
 * An exited vm-clone is not one of those. Caller holds thread_lock.
 */
bool thread_ptrace_interrupt_pending_locked(void);

/* Count active VM-clone threads (is_vm_clone && !vm_exited). Used to detect
 * when the last VM-clone child exits.
 */
int thread_count_active_vm_clones(void);

/* Join worker threads (all active threads except the caller, minus any already
 * join_abandoned by a prior pass). Collects thread handles under the lock, then
 * polls OUTSIDE the lock under one shared 500ms deadline so workers can call
 * thread_deactivate() to set active=0. Workers still alive past the deadline
 * are detached and marked join_abandoned so a later pass (e.g. guest_destroy's
 * internal join after main()'s) does not touch the same handle twice.
 */
void thread_join_workers(void);

/* Destroy the main vCPU (owned by the calling thread) during guest_destroy. HVF
 * vCPUs are thread-affine, so worker vCPUs are never destroyed here: an active
 * worker slot that has not published vm_exited is one whose owning thread is
 * still live -- running a vCPU or mid-bring-up about to enter one -- and a
 * cross-thread hv_vcpu_destroy on such a handle, or hv_vm_destroy while it
 * holds one, corrupts the kernel vCPU object and panics the host. Such a worker
 * is left for process-exit reclamation and reported via live_workers_left (may
 * be NULL) so the caller defers the rest of HVF teardown. A slot that has
 * already published vm_exited (a vm-clone child that self-destroyed its vCPU
 * and stays active only for wait4) holds no live vCPU and does not force the
 * deferral.
 *
 * Returns whether the main vCPU was destroyed.
 */
bool thread_destroy_all_vcpus(hv_vcpu_t main_vcpu,
                              bool main_vcpu_valid,
                              bool *live_workers_left);

/* Interrupt all active vCPUs by calling hv_vcpus_exit(). Used for signal
 * preemption: when a signal is queued while a vCPU is running in a tight loop
 * (no syscalls), this forces it to break out of hv_vcpu_run so the signal can
 * be delivered.
 */
void thread_interrupt_all(void);

/* Wake every thread parked anywhere it cannot see a teardown flag: futex
 * waiters, poll/epoll/read parks on the wakeup pipe, vCPUs inside hv_vcpu_run,
 * and the internal condvars. The four wakes are always needed together, so
 * exit_group teardown (guest_destroy, main's run-loop exit) and execve
 * de_thread share this rather than each keeping its own list. Callers that mean
 * process teardown must set the exit-group flag first, per
 * thread_wake_exit_waiters below.
 */
void thread_wake_all_blocked(void);

/* The same wakes minus the futex interrupt, for work only the leader has to
 * notice (an execve handed to it). The interrupt flag is process-wide and
 * one-shot, so a teardown-strength wake used for a handoff hands an unexplained
 * EINTR to whichever thread consumes it. Callers must publish the reason the
 * leader's thread_stop_requested turns true BEFORE calling this.
 */
void thread_wake_leader_for_work(void);

/* Wake workers parked on internal condvars (fork barrier, ptrace stop/wait) so
 * exit_group teardown reaches them within a bounded time. hv_vcpus_exit only
 * interrupts threads inside hv_vcpu_run, and the wakeup pipe / futex interrupt
 * only cover guest syscall waits; a thread parked on fork_cond, ptrace_cond, or
 * resume_cond would otherwise sleep past the join cap in thread_join_workers
 * and still be live when guest memory is unmapped. Callers must set the
 * exit-group flag (proc_request_exit_group) BEFORE calling this so woken
 * waiters observe it when they re-check.
 */
void thread_wake_exit_waiters(void);

/* Check if any active thread has sigbit unblocked in its signal mask. Uses
 * relaxed reads on per-thread blocked fields; false positives (stale blocked=0)
 * cause a harmless spurious interrupt; false negatives (stale blocked=1) are
 * corrected by rt_sigprocmask re-checking pending signals after unblock. Does
 * NOT acquire thread_lock.
 */
bool thread_signal_deliverable(uint64_t sigbit);

/* Fork quiesce helpers. */

/* Quiesce all sibling vCPUs for fork snapshot consistency. Calls hv_vcpus_exit
 * on all active threads except the caller, then waits until they are all
 * blocked on the fork barrier. Caller must NOT hold thread_lock. Hold every
 * sibling outside guest code until thread_resume_siblings.
 * Returns false without arming, and without any need to resume, when an execve
 * teardown is reaping: the caller is one of the threads being reaped, and the
 * barrier it would arm is one nobody would release. Callers must abandon the
 * operation the quiet was for.
 */
bool thread_quiesce_siblings(void);

/* Resume sibling vCPUs after fork snapshot is complete. Clears the quiesce flag
 * and broadcasts the fork condvar.
 */
void thread_resume_siblings(void);

/* Check if a fork quiesce is in progress. Called from the vCPU run loop's
 * HV_EXIT_REASON_CANCELED handler. If active, increments the quiesced counter,
 * blocks until the fork completes, then returns true.
 * Returns false if no quiesce is active.
 */
bool thread_fork_barrier_check(void);

/* Hand a counted sibling's slot back to an armed fork barrier when it exits or
 * fails bring-up before reaching thread_fork_barrier_check. Caller must hold
 * the thread lock (thread_get_lock()). No-op if no barrier is armed or the slot
 * was not counted. thread_deactivate calls this; paths that keep a failed slot
 * active for wait4 (vm-clone bring-up failure) must call it explicitly.
 */
void thread_fork_release_counted_locked(thread_entry_t *t);

/* execve de_thread helpers. */

/* True when an execve on another thread is tearing this one down. Callers that
 * already tested proc_exit_group_requested use this; everything else wants
 * thread_stop_requested below.
 */
int thread_exec_stop_requested(void);

/* The leader has an execve handed to it and must leave whatever it is parked in
 * to run it. Published by the exec layer, read by thread_stop_requested, so the
 * hot-path predicate stays inside runtime/.
 */
void thread_set_leader_work_pending(bool pending);
bool thread_leader_work_pending(void);

/* True when the calling thread must leave guest execution: a process-wide
 * exit_group was requested, or an execve is tearing this thread down. Every
 * blocking wait in a guest syscall re-checks this and returns EINTR so the run
 * loop can wind the thread down; a thread that only polled the exit-group flag
 * would keep the exec'ing thread parked in thread_exec_de_thread until the join
 * cap expired.
 */
int thread_stop_requested(void);

/* Record the syscall this thread is entering, or -1 on the way out. Relaxed:
 * the only reader is a diagnostic on a path that is already failing, and
 * ordering it against every syscall would cost the whole guest to sharpen one
 * log line.
 */
void thread_note_syscall(int nr);

/* True when the only thing thread_stop_requested is reporting is an execve
 * handed to this leader: nothing is tearing this thread down. The wait it broke
 * has nothing to report to the guest, since Linux returns no EINTR without a
 * signal, so the syscall epilogue restarts the SVC instead and the handoff runs
 * from the run loop in between.
 */
int thread_stop_is_leader_work_only(void);

/* True when the caller is the thread group leader (the main host thread, the
 * one whose run loop returning tears the process down). de_thread cannot
 * destroy the leader, so an execve from any other thread is handed to it and
 * runs on its vCPU; see exec_handoff_to_leader.
 */
bool thread_current_is_leader(void);

/* Drop the exec'ing thread's robust list and clear_child_tid, as Linux
 * begin_new_exec() does: both name addresses in the image that just went away.
 * Call from sys_execve after guest_reset.
 */
void thread_reset_for_exec(void);

/* Destroy every sibling guest thread on behalf of an execve, Linux de_thread().
 * Call from the exec'ing thread at the point of no return, BEFORE guest_reset:
 * siblings wind down against the old image, so their CLEARTID and robust-list
 * writes still land on the memory their guest expects.
 *
 * Returns the number of siblings still live, which is 0 unless one outlived the
 * bounded join. A non-zero return means guest memory MUST NOT be reset: that
 * thread still holds registers into the old image and would resume into the
 * zeroed one. The caller is past the point of no return, so its only safe
 * response is a diagnosed fatal exit.
 */
int thread_exec_de_thread(void);

/* Ptrace helpers. */

/* Tracee: snapshot vCPU regs, enter ptrace-stop, block until resumed.
 * Returns the signal to inject (from tracer's PTRACE_CONT), or 0.
 */
int thread_ptrace_stop(thread_entry_t *t, int sig);

/* Tracer: resume a stopped tracee with optional signal injection. */
void thread_ptrace_cont(thread_entry_t *t, int sig);

/* Tracer: wait for a ptraced or vm-clone child to stop or exit.
 * Returns child TID on success, 0 on WNOHANG with none ready, or negative Linux
 * errno. Writes wait-format status to *out_status.
 */
int64_t thread_ptrace_wait(int64_t tracer_tid,
                           int pid,
                           int *out_status,
                           int options);

/* Get the thread table mutex (needed for ptrace wait blocking). */
/*@
  ensures \valid(\result);
  assigns \nothing;
 */
pthread_mutex_t *thread_get_lock(void);

/* Snapshot every active guest stack range overlapping [start, end), then record
 * a deferred-unmap entry on each one. While the transaction is live, cleanup of
 * the affected thread's deferred stack entries will block so a later rollback
 * cannot race with thread exit. On success, txns[0..nranges) contains both the
 * overlapping ranges and the pre-update deferred-unmap state needed for
 * rollback.
 * Returns the number of overlapping stack ranges, or -1 if the caller's buffer
 * is too small or any thread's deferred-unmap budget is exhausted.
 */
int thread_collect_and_defer_stack_ranges(
    uint64_t start,
    uint64_t end,
    thread_deferred_stack_unmap_txn_t *txns,
    int max_ranges);

/* Release the in-flight marker set by thread_collect_and_defer_stack_ranges()
 * after the caller has successfully completed the non-deferred munmap work.
 */
void thread_finish_deferred_stack_ranges(
    const thread_deferred_stack_unmap_txn_t *txns,
    int nranges);

/* Restore the deferred-unmap state previously captured by
 * thread_collect_and_defer_stack_ranges(), then release the in-flight marker.
 */
void thread_rollback_deferred_stack_ranges(
    const thread_deferred_stack_unmap_txn_t *txns,
    int nranges);

/* For thread exit cleanup: wait for any in-flight deferred-stack munmap
 * transaction affecting this thread to finish, then clear the live stack map
 * and snapshot the current deferred unmaps.
 *
 * Returns the number of entries copied (capped at max_ranges).
 */
int thread_prepare_deferred_stack_unmaps_for_cleanup(thread_entry_t *t,
                                                     uint64_t *starts,
                                                     uint64_t *ends,
                                                     int max_ranges);

/* Snapshot the deferred unmap entries without modifying the thread record.
 * Returns the number of entries copied (capped at max_ranges).
 */
int thread_peek_deferred_stack_unmaps(thread_entry_t *t,
                                      uint64_t *starts,
                                      uint64_t *ends,
                                      int max_ranges);

/* Drop a single completed deferred unmap entry by exact [start, end) match.
 * Returns 1 if removed, 0 if no matching entry was found.
 */
int thread_drop_deferred_stack_unmap(thread_entry_t *t,
                                     uint64_t start,
                                     uint64_t end);

/* Forget the thread's stack range so future munmap calls do not enqueue new
 * deferred entries against this slot. Safe to call once the thread is dead.
 */
void thread_clear_stack_map(thread_entry_t *t);
