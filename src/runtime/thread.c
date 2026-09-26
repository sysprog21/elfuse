/*
 * Per-thread state for Linux threading support
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Thread table with _Thread_local fast path for current thread access.
 * Protected by a mutex since thread creation/destruction is infrequent relative
 * to per-syscall access (which uses the lock-free TLS pointer).
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"

#include "runtime/thread.h"
#include "debug/log.h"
#include "core/guest.h"    /* guest_t (shim_data_base/ipa_base), BLOCK_2MIB */
#include "hvutil.h"        /* vcpu_get_gpr, vcpu_get_sysreg */
#include "runtime/futex.h" /* futex_interrupt_request */

/* Only for the handoff wake below. The hot-path predicate no longer reaches
 * into the syscall layer: exec.c publishes it here through
 * thread_set_leader_work_pending.
 */
#include "syscall/exec.h"
#include "syscall/proc.h"        /* proc_exit_group_requested */
#include "syscall/wakeup-pipe.h" /* wakeup_pipe_signal */

/* From syscall/signal.h, included here directly to avoid pulling in the full
 * signal header (macOS defines sa_handler as a macro that conflicts with the
 * linux_sigaction_t field name).
 */
#define LINUX_SS_DISABLE 2

static void thread_ptrace_init(thread_entry_t *t);
static int thread_add_deferred_unmap_locked(thread_entry_t *t,
                                            uint64_t start,
                                            uint64_t end);
static int thread_can_add_deferred_unmap_locked(thread_entry_t *t,
                                                uint64_t start,
                                                uint64_t end);

/* Top of the EL1 exception stack region (one 4KiB slot per thread). The shim
 * data block sits at high IPA, computed at guest_init time and stored in
 * g->shim_data_base; the top of the EL1 stacks is the next 2MiB boundary above
 * that. Caller must hold a guest_t reference.
 */
static inline uint64_t sp_el1_top(const guest_t *g)
{
    return g->ipa_base + g->shim_data_base + BLOCK_2MIB;
}

/* Thread table. */

static thread_entry_t thread_table[MAX_THREADS];
static pthread_mutex_t thread_lock =
    PTHREAD_MUTEX_INITIALIZER; /* Lock order: 5 */
static _Atomic int active_thread_count = 0;

/* Fork barrier state. Protected by thread_lock. Declared here (rather than
 * beside thread_quiesce_siblings) because thread_deactivate, earlier in the
 * file, hands its count back when a counted sibling exits before the barrier.
 */
static bool fork_quiesce_active = false; /* True while a fork is in progress */
static int fork_quiesced_count = 0;      /* Siblings blocked on barrier */
static int fork_target_count = 0;        /* Number of siblings to quiesce */
static pthread_cond_t fork_cond = PTHREAD_COND_INITIALIZER;

/* Signalled when a deferred stack-unmap transaction clears. Declared here
 * rather than beside its users because thread_wake_exit_waiters, earlier in the
 * file, has to broadcast it too.
 */
static pthread_cond_t deferred_stack_unmap_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t fork_all_quiesced_cond = PTHREAD_COND_INITIALIZER;

/* Signalled when a quiesce window closes, so an execve teardown can wait for
 * one already open instead of tearing siblings out of it.
 */
static pthread_cond_t fork_window_closed_cond = PTHREAD_COND_INITIALIZER;

/* Defined with the rest of the execve teardown state further down; declared
 * here because thread_quiesce_siblings, above it, refuses to arm while a
 * teardown is running.
 */
static _Atomic bool exec_de_thread_active;

/* Iterate every slot. */
#define THREAD_FOR_EACH(t) \
    for (thread_entry_t *t = thread_table; t < thread_table + MAX_THREADS; t++)

/* Iterate active slots. Caller must hold thread_lock; the lock already orders
 * these reads against the release-stores of active, so a relaxed atomic load
 * suffices. It is used (rather than a plain read) only to keep every access to
 * active uniformly atomic -- no mixed atomic-write / plain-read on one object.
 */
#define THREAD_FOR_EACH_ACTIVE(t) \
    THREAD_FOR_EACH (t)           \
        if (atomic_load_explicit(&t->active, memory_order_relaxed))

/* Iterate active slots without holding thread_lock. Uses an acquire load on the
 * active flag so the lock-free observers in thread_tid_alive() and
 * thread_signal_deliverable() see a consistent transition.
 */
#define THREAD_FOR_EACH_ACTIVE_RELAXED(t) \
    THREAD_FOR_EACH (t)                   \
        if (atomic_load_explicit(&t->active, memory_order_acquire))

/* Bitmask tracking allocated SP_EL1 slots. Bit N set = slot N in use.
 * MAX_THREADS=64 fits exactly in a uint64_t. Slot 0 is the main thread (top of
 * shim data region); each subsequent slot is 4KiB below.
 */
static uint64_t sp_el1_allocated = 0;

/* Per-thread pointer to the current thread's entry. Set once when a host
 * pthread starts running a guest vCPU. Syscall handlers read this without
 * locking since it is thread-local and never changes after init.
 */
_Thread_local thread_entry_t *current_thread = NULL;

/* Public API */

void thread_init(void)
{
    pthread_mutex_lock(&thread_lock);
    memset(thread_table, 0, sizeof(thread_table));
    sp_el1_allocated = 0;
    atomic_store_explicit(&active_thread_count, 0, memory_order_relaxed);
    current_thread = NULL;
    pthread_mutex_unlock(&thread_lock);
}

void thread_register_main(hv_vcpu_t vcpu,
                          hv_vcpu_exit_t *vexit,
                          int64_t tid,
                          uint64_t sp_el1)
{
    pthread_mutex_lock(&thread_lock);

    thread_entry_t *t = &thread_table[0];
    atomic_store_explicit(&t->guest_tid, tid, memory_order_relaxed);
    t->vcpu = vcpu;
    t->vcpu_valid = true;
    t->vexit = vexit;
    t->host_thread = pthread_self();
    t->host_thread_needs_join = false; /* Never join the process main thread */
    t->clear_child_tid = 0;
    t->sp_el1 = sp_el1;
    t->sp_el1_slot = 0; /* Main thread always owns slot 0 */
    t->altstack_flags = LINUX_SS_DISABLE;
    t->on_altstack = false;
    thread_ptrace_init(t);

    /* Release-store so a lock-free scanner that acquire-loads active == 1 sees
     * this slot's initialized fields (see thread_pending_union,
     * thread_tid_alive).
     */
    atomic_store_explicit(&t->active, 1, memory_order_release);

    /* Slot 0 is consumed by main thread */
    sp_el1_allocated = BIT64(0);
    atomic_store_explicit(&active_thread_count, 1, memory_order_relaxed);

    pthread_mutex_unlock(&thread_lock);

    /* Set TLS pointer for the main thread */
    current_thread = t;
}

/* Where thread_slot_clear starts its first memset: just past the one word
 * inside tpending that a lock-free scan reads.
 */
#define THREAD_SLOT_CLEAR_START           \
    (offsetof(thread_entry_t, tpending) + \
     sizeof(((thread_entry_t *) 0)->tpending.pending))

/* Each lock-free-scanned field has to sit wholly below that point, or the
 * memset would plain-write something a scan can be loading. Assert the property
 * each field actually needs rather than a chain of orderings, so inserting a
 * field in the middle of the group cannot quietly weaken it.
 */
#define THREAD_SLOT_KEPT(field)                   \
    (offsetof(thread_entry_t, field) +            \
         sizeof(((thread_entry_t *) 0)->field) <= \
     THREAD_SLOT_CLEAR_START)

_Static_assert(THREAD_SLOT_KEPT(active), "active is cleared by the memset");
_Static_assert(THREAD_SLOT_KEPT(blocked), "blocked is cleared by the memset");
_Static_assert(THREAD_SLOT_KEPT(guest_tid),
               "guest_tid is cleared by the memset");
_Static_assert(THREAD_SLOT_KEPT(tpending.pending),
               "tpending.pending is cleared by the memset");
_Static_assert(THREAD_SLOT_KEPT(in_syscall),
               "in_syscall is cleared by the memset");

/* Clear a slot that thread_alloc is about to hand to a new thread.
 *
 * A whole-struct memset cannot be used. Three scans walk the table lock-free
 * and each loads active and then a payload field with no lock in between, so
 * one of them can still be reading this slot after it went inactive and while
 * the recycle runs. Plain-writing any field they read is a data race, so the
 * five they touch are stored atomically and the memset skips them.
 */
static void thread_slot_clear(thread_entry_t *t)
{
    atomic_store_explicit(&t->active, 0, memory_order_relaxed);
    atomic_store_explicit(&t->blocked, 0, memory_order_relaxed);
    atomic_store_explicit(&t->guest_tid, 0, memory_order_relaxed);
    pending_store(&t->tpending.pending, 0);
    atomic_store_explicit(&t->in_syscall, 0, memory_order_relaxed);

    /* Everything past the scanned fields is lock-private: one span covers the
     * rest of tpending and the whole tail, padding included.
     */
    memset((unsigned char *) t + THREAD_SLOT_CLEAR_START, 0,
           sizeof(*t) - THREAD_SLOT_CLEAR_START);
}

thread_entry_t *thread_alloc(int64_t tid,
                             uint64_t stack_start,
                             uint64_t stack_end)
{
    thread_entry_t *result = NULL;

    pthread_mutex_lock(&thread_lock);
rescan:
    THREAD_FOR_EACH (t) {
        if (atomic_load_explicit(&t->active, memory_order_relaxed))
            continue;

        /* Skip slots where a tracer is still inside pthread_cond_wait on
         * ptrace_cond. Memset+reinit while a waiter holds a reference is UB.
         */
        if (t->ptrace_conds_inited && t->ptrace_waiters > 0)
            continue;

        /* Reap the previous occupant's pthread before reusing the slot. Workers
         * that exit on their own are joinable but never joined
         * (thread_join_workers snapshots active entries only), so dropping the
         * handle in the memset below would leak its pthread bookkeeping for the
         * process lifetime. active == 0 means the pthread is already past
         * thread_deactivate, so the join blocks at most for its final wind-down
         * -- but that wind-down can take thread_lock (the last-worker wakeup
         * calls thread_interrupt_all), so the join must run with the lock
         * dropped. Claim the handle first so no one else joins it, then rescan:
         * the table may have changed while unlocked.
         */
        if (t->host_thread_needs_join) {
            pthread_t stale = t->host_thread;
            t->host_thread_needs_join = false;
            pthread_mutex_unlock(&thread_lock);
            pthread_join(stale, NULL);
            pthread_mutex_lock(&thread_lock);
            goto rescan;
        }
        if (t->ptrace_conds_inited) {
            pthread_cond_destroy(&t->ptrace_cond);
            pthread_cond_destroy(&t->resume_cond);
        }

        /* Bump generation across the memset so a caller still holding this
         * slot's pointer from before reuse (e.g. a clone parent racing its own
         * worker's startup-failure path) can detect the recycle via
         * thread_set_host_thread's generation check instead of writing into
         * what is now a different logical thread.
         */
        uint64_t next_generation = t->generation + 1;
        thread_slot_clear(t);
        t->generation = next_generation;
        t->sp_el1_slot = -1; /* No SP_EL1 yet; thread_alloc_sp_el1 fills this */
        /* Not in one; syscall_dispatch fills this */
        atomic_store_explicit(&t->in_syscall, -1, memory_order_relaxed);
        atomic_store_explicit(&t->guest_tid, tid, memory_order_relaxed);
        if (stack_start < stack_end) {
            t->stack_map_start = stack_start;
            t->stack_map_end = stack_end;
        }
        t->altstack_flags = LINUX_SS_DISABLE;
        thread_ptrace_init(t);

        /* Release-store last so a lock-free scanner that observes active == 1
         * also sees the zeroed tpending / guest_tid set above.
         */
        atomic_store_explicit(&t->active, 1, memory_order_release);
        atomic_fetch_add_explicit(&active_thread_count, 1,
                                  memory_order_relaxed);
        result = t;
        break;
    }
    pthread_mutex_unlock(&thread_lock);

    return result;
}

/* Free an SP_EL1 slot for reuse. Must be called with thread_lock held. Reads
 * the slot index recorded at allocation time and clears the bit.
 */
static void thread_free_sp_el1_locked(thread_entry_t *t)
{
    int slot = t->sp_el1_slot;
    if (RANGE_CHECK(slot, 0, MAX_THREADS))
        sp_el1_allocated &= ~BIT64(slot);
    t->sp_el1 = 0;
    t->sp_el1_slot = -1;
}

static void thread_ptrace_cleanup_locked(thread_entry_t *t)
{
    if (!t->ptrace_conds_inited ||
        atomic_load_explicit(&t->active, memory_order_relaxed) ||
        t->ptrace_waiters != 0)
        return;

    pthread_cond_destroy(&t->ptrace_cond);
    pthread_cond_destroy(&t->resume_cond);
    t->ptrace_conds_inited = false;
    t->ptrace_cleanup_pending = false;
}

bool thread_set_host_thread(thread_entry_t *t,
                            pthread_t thr,
                            bool joinable,
                            uint64_t generation)
{
    pthread_mutex_lock(&thread_lock);
    bool recorded = (t->generation == generation);
    if (recorded) {
        t->host_thread = thr;
        t->host_thread_needs_join = joinable;
    }
    pthread_mutex_unlock(&thread_lock);

    return recorded;
}

bool thread_claim_worker_join(thread_entry_t *t, pthread_t thr)
{
    pthread_mutex_lock(&thread_lock);
    bool claimed =
        t->host_thread_needs_join && pthread_equal(t->host_thread, thr);
    if (claimed)
        t->host_thread_needs_join = false;
    pthread_mutex_unlock(&thread_lock);

    return claimed;
}

void thread_fork_release_counted_locked(thread_entry_t *t)
{
    /* Caller holds thread_lock. If a fork snapshot counted this slot but it is
     * exiting or failing bring-up before it could reach
     * thread_fork_barrier_check, hand its count back so thread_quiesce_siblings
     * is not stalled the full timeout waiting for a thread that will never
     * arrive. Guarded by fork_counted so a slot created after the barrier armed
     * (never counted) does not over-decrement. No-op when no barrier is armed.
     */
    if (fork_quiesce_active && t->fork_counted) {
        t->fork_counted = false;
        fork_target_count--;
        if (fork_quiesced_count >= fork_target_count)
            pthread_cond_signal(&fork_all_quiesced_cond);
    }
}

void thread_deactivate(thread_entry_t *t)
{
    if (!t)
        return;

    /* Before thread_lock, which ranks after sig_lock, and before the slot can
     * be handed to a new thread that would inherit the claims by address.
     */
    signal_release_claims(t);

    pthread_mutex_lock(&thread_lock);

    /* If this is a VM-clone child, mark it as exited and wake the tracer/parent
     * so wait4 can collect the exit status. Must happen BEFORE destroying the
     * condvars, since broadcasting a destroyed condvar is undefined behavior.
     * Guard against double-deactivation: if already inactive, skip.
     */
    if (!atomic_load_explicit(&t->active, memory_order_relaxed)) {
        pthread_mutex_unlock(&thread_lock);
        return;
    }

    if (t->is_vm_clone) {
        t->vm_exited = true;
        pthread_cond_broadcast(&t->ptrace_cond);
    }

    /* Free SP_EL1 slot so it can be reused by future threads */
    thread_free_sp_el1_locked(t);

    /* Release store: everything this thread did -- including its last guest
     * memory access -- must happen-before thread_join_workers' acquire load
     * observing 0, or the joiner could green-light guest_destroy's unmap while
     * stores are still in flight. The joiner polls lock-free, so the mutex held
     * here provides no edge to it.
     */
    atomic_store_explicit(&t->active, 0, memory_order_release);
    atomic_fetch_sub_explicit(&active_thread_count, 1, memory_order_relaxed);

    thread_fork_release_counted_locked(t);

    /* Destroy condvars once no waiters still reference them. A tracer woken by
     * the broadcast above may still be re-acquiring thread_lock.
     */
    t->ptrace_cleanup_pending = true;
    thread_ptrace_cleanup_locked(t);

    pthread_mutex_unlock(&thread_lock);

    /* The slot is now inactive, so thread_pending_union() excludes it.
     * Recompute the global pending hint so any thread-directed signal left
     * unconsumed in this thread's private set stops pinning the
     * identity-syscall fast path off for the surviving threads. Done outside
     * thread_lock to honor sig_lock (4) before thread_lock (5).
     */
    signal_refresh_pending_hint();
}

thread_entry_t *thread_find(int64_t tid)
{
    thread_entry_t *result = NULL;

    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t) {
        if (thread_tid(t) == tid) {
            result = t;
            break;
        }
    }
    pthread_mutex_unlock(&thread_lock);

    return result;
}

thread_entry_t *thread_find_locked(int64_t tid)
{
    THREAD_FOR_EACH_ACTIVE (t) {
        if (thread_tid(t) == tid)
            return t;
    }
    return NULL;
}

uint64_t thread_pending_union(void)
{
    /* Lock-free active scan; sig_lock (held by the caller) already serializes
     * every tpending write, so reads here are stable. A slot mid-(de)activation
     * only ever contributes extra bits, which the caller treats as a harmless
     * false positive in the pending hint.
     */
    uint64_t u = 0;
    THREAD_FOR_EACH_ACTIVE_RELAXED (t)
        u |= pending_load(&t->tpending.pending);
    return u;
}

bool thread_tid_alive(int64_t tid)
{
    /* Lock-free scan: active transitions 1->0 exactly once (in
     * thread_deactivate under thread_lock), and guest_tid is set at allocation
     * and never changes until the slot is reused (after active=0). A stale read
     * of active=1 for a thread being deactivated is benign; the caller retries
     * on the next poll iteration (100ms later).
     */
    THREAD_FOR_EACH_ACTIVE_RELAXED (t)
        if (thread_tid(t) == tid)
            return true;
    return false;
}

int thread_active_count(void)
{
    return atomic_load_explicit(&active_thread_count, memory_order_relaxed);
}

int thread_is_single_active(void)
{
    return atomic_load_explicit(&active_thread_count, memory_order_relaxed) ==
           1;
}

int thread_count_active_vm_clones(void)
{
    int count = 0;

    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t)
        if (t->is_vm_clone && !t->vm_exited)
            count++;
    pthread_mutex_unlock(&thread_lock);

    return count;
}

uint64_t thread_alloc_sp_el1(const guest_t *g, thread_entry_t *t)
{
    uint64_t sp = 0;

    pthread_mutex_lock(&thread_lock);

    /* Find the first free slot (lowest clear bit in the bitmask). */
    uint64_t free_mask = ~sp_el1_allocated & bit_mask64_low(MAX_THREADS);
    if (free_mask == 0) {
        log_error("thread: SP_EL1 slots exhausted");
    } else {
        int slot = bit_ctz64(free_mask);

        /* Main thread's SP_EL1 sits at the top of the shim data block. Each
         * subsequent thread is one slot below.
         */
        uint64_t top = sp_el1_top(g);
        sp = top - (uint64_t) slot * SP_EL1_SLOT_BYTES;
        sp_el1_allocated |= BIT64(slot);
        t->sp_el1 = sp;
        t->sp_el1_slot = slot;
    }

    pthread_mutex_unlock(&thread_lock);

    return sp;
}

void thread_sp_el1_region(const guest_t *g, uint64_t *lo, uint64_t *hi)
{
    /* Derived from what thread_alloc_sp_el1 above hands out, not from the block
     * it hands it out of: slot 0 starts at the top and slot MAX_THREADS - 1 is
     * the last one, so the region is the top MAX_THREADS slots and everything
     * under it belongs to the shim-globals cache.
     */
    uint64_t top = sp_el1_top(g);

    *hi = top;
    *lo = top - (uint64_t) MAX_THREADS * SP_EL1_SLOT_BYTES;
}

void thread_for_each(void (*fn)(thread_entry_t *t, void *ctx), void *ctx)
{
    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t)
        fn(t, ctx);
    pthread_mutex_unlock(&thread_lock);
}

bool thread_ptrace_interrupt_pending_locked(void)
{
    THREAD_FOR_EACH_ACTIVE (t) {
        /* A vm-clone that has exited keeps its slot until a wait reaps it, and
         * carries whatever it was owed to the grave: nothing will consume it.
         * Counting one holds ATTN_BIT_PTRACE up for the life of the process and
         * sends every fast path down the slow lane for a stop that can never be
         * taken. execve reaches here past its own guard, which counts only
         * clones that have not exited.
         */
        if (t->is_vm_clone && t->vm_exited)
            continue;
        if (t->ptrace_interrupt_pending)
            return true;
    }
    return false;
}

/* exec_mode is de_thread's contract rather than teardown's: the process
 * continues afterwards, so a straggler must not be detached (the handle stays
 * claimable for the real teardown) and a vm-clone slot must not be waited on at
 * all. execve leaves a CLONE_VM child on the old mm and de_thread excludes it
 * from the survivor count, but an exited-but-unreaped one keeps active == 1 for
 * wait4, so the poll below would spend the whole cap on a thread that already
 * left. The other legitimate budget consumer, a sibling parked in the fork
 * barrier, is drained before the teardown is armed; see thread_exec_de_thread.
 */
static void thread_join_workers_mode(bool exec_mode)
{
    /* Snapshot worker threads under the lock. The code needs the host_thread
     * handle and a way to check the active flag without re-locking. Storing the
     * table entry pointer lets the loop use atomic_load_explicit on active.
     * Claim each joinable handle here (clear host_thread_needs_join) so a
     * concurrent slot reuse in thread_alloc cannot join the same pthread twice.
     * Unclaimed entries -- vm-clone children (created detached) and the main
     * thread's slot when a worker drives teardown -- are still polled below so
     * teardown waits for them to leave the guest, but their handle is never
     * joined or detached. Entries a previous pass already detached
     * (join_abandoned) are skipped outright: joining or detaching the same
     * pthread twice is undefined, and main()'s join is followed by
     * guest_destroy's internal one.
     */
    struct {
        pthread_t thr;
        thread_entry_t *t;
        uint64_t generation;
        bool claimed;
        bool recycled;
    } workers[MAX_THREADS];
    int nworkers = 0;

    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH (t) {
        if (t == current_thread || t->join_abandoned)
            continue;

        /* Never wait for the main thread (slot 0): its entry only deactivates
         * inside guest_destroy, which runs on the main thread AFTER its own
         * thread_join_workers. A worker waiting here (exit_group called from a
         * worker) would burn the full cap on it, and the resulting mutual wait
         * (worker polling main while main polls the worker) ends in
         * pthread_detach on both sides, leaving the loser to touch guest memory
         * after guest_destroy unmaps it.
         */
        if (t == &thread_table[0])
            continue;

        if (exec_mode && t->is_vm_clone)
            continue;

        /* Inactive slots are included when they still hold an unjoined handle:
         * a worker that exited on its own shortly before teardown and whose
         * slot was never reused. Its pthread has terminated (or is in final
         * wind-down), so the join below is immediate.
         */
        if (!atomic_load_explicit(&t->active, memory_order_relaxed) &&
            !t->host_thread_needs_join)
            continue;
        workers[nworkers].thr = t->host_thread;
        workers[nworkers].t = t;
        workers[nworkers].generation = t->generation;
        workers[nworkers].claimed = t->host_thread_needs_join;
        workers[nworkers].recycled = false;
        t->host_thread_needs_join = false;
        nworkers++;
    }
    pthread_mutex_unlock(&thread_lock);

    /* Poll under one shared 500ms deadline OUTSIDE the lock, then join or
     * detach each worker. Workers that responded to hv_vcpus_exit typically
     * finish within microseconds; the cap only matters for workers parked in
     * host blocking calls, and it must exceed the worst-case teardown-flag
     * re-check latency of every such state or a worker that WOULD wind down
     * cleanly gets abandoned on timing alone: the interruptible io wait
     * re-checks every 200ms (io.c wait helper) and the futex paths every 100ms
     * (FUTEX_OS_SYNC_POLL_CAP_NS quanta), so 500ms covers the slowest bound
     * with margin. One shared deadline keeps worst-case shutdown at the cap
     * even with many stuck workers, rather than multiplying a per-worker cap by
     * nworkers. A worker still alive past the cap is detached and, if this pass
     * claimed its handle, marked join_abandoned so a later pass does not touch
     * it again. The vCPU is NOT destroyed here because HVF vCPUs are
     * thread-affine, so cross-thread hv_vcpu_destroy while the owning thread
     * may still be inside hv_vcpu_run is unsafe.
     */
    for (int i = 0; i < 100; i++) {
        bool any_active = false;
        for (int w = 0; w < nworkers; w++) {
            if (workers[w].recycled)
                continue;
            if (!atomic_load_explicit(&workers[w].t->active,
                                      memory_order_acquire))
                continue;

            /* The slot may have been reused for a new logical thread while we
             * polled: thread_alloc only recycles a slot once its previous
             * occupant is inactive, so a generation bump here proves our
             * snapshotted worker already deactivated even though the slot now
             * reads active == 1 again for the replacement thread. Stop tracking
             * this worker's active bit for the rest of the loop rather than
             * following the wrong thread.
             */
            if (workers[w].t->generation != workers[w].generation) {
                workers[w].recycled = true;
                continue;
            }
            any_active = true;
        }
        if (!any_active)
            break;
        usleep(5000);
    }

    for (int w = 0; w < nworkers; w++) {
        if (!workers[w].claimed)
            continue;

        /* recycled short-circuits before the active re-check: once recycled,
         * that bit belongs to the replacement thread and must not influence the
         * join-vs-detach decision for our (already-terminated) handle.
         */
        if (workers[w].recycled ||
            !atomic_load_explicit(&workers[w].t->active,
                                  memory_order_acquire)) {
            pthread_join(workers[w].thr, NULL);
        } else if (exec_mode) {
            /* Hand the claim back instead of detaching. The caller answers a
             * straggler with a diagnosed exit, and until it does the handle
             * belongs to a process that is still running: detaching it here
             * would let a later teardown pass, or thread_alloc recycling the
             * slot, reason about a pthread nobody may touch any more.
             *
             * A generation bump seen only now (the poll loop broke before the
             * recycle) means the slot belongs to a different logical thread and
             * the claim would be handed to the wrong handle. thread_alloc only
             * recycles an inactive slot, so the previous occupant has already
             * exited and this join returns at once.
             */
            pthread_mutex_lock(&thread_lock);
            bool same_thread =
                workers[w].t->generation == workers[w].generation;
            if (same_thread)
                workers[w].t->host_thread_needs_join = true;
            pthread_mutex_unlock(&thread_lock);
            if (!same_thread)
                pthread_join(workers[w].thr, NULL);
        } else {
            pthread_detach(workers[w].thr);
            pthread_mutex_lock(&thread_lock);
            workers[w].t->join_abandoned = true;
            pthread_mutex_unlock(&thread_lock);
        }
    }
}

void thread_join_workers(void)
{
    thread_join_workers_mode(false);
}

bool thread_destroy_all_vcpus(hv_vcpu_t main_vcpu,
                              bool main_vcpu_valid,
                              bool *live_workers_left)
{
    bool main_destroyed = false;
    bool live_workers = false;
    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t) {
        /* The main vCPU is the only handle owned by the thread running
         * guest_destroy, so it is the only one this thread may destroy. The
         * vcpu_valid term guards a not-yet-published worker whose t->vcpu still
         * reads 0 from colliding with a main_vcpu handle of 0 (a valid value
         * for the first vCPU).
         */
        if (main_vcpu_valid && t->vcpu_valid && t->vcpu == main_vcpu) {
            hv_vcpu_destroy(t->vcpu);
            t->vcpu_valid = false;
            t->vcpu = 0;
            thread_free_sp_el1_locked(t);
            atomic_store_explicit(&t->active, 0, memory_order_release);

            /* Keep the count accurate rather than zeroing the whole table: any
             * leaked live worker stays active and counted until process exit
             * reclaims it.
             */
            atomic_fetch_sub_explicit(&active_thread_count, 1,
                                      memory_order_relaxed);
            main_destroyed = true;

            /* Do NOT destroy condvars. Same race as thread_deactivate: a waiter
             * woken by an earlier broadcast may still reference the condvar.
             * Process is exiting, so the leak is harmless.
             */
            continue;
        }

        /* A slot that has already published vm_exited destroyed its own vCPU on
         * its owning thread (under thread_lock, before setting vm_exited) and
         * that thread has terminated; a vm-clone child stays active past that
         * only so a later wait4 can reap it. It holds no live vCPU, so it does
         * not block teardown -- treating it as live would wrongly defer the
         * explicit HVF teardown/unmaps for an already-dead slot.
         *
         * Gate on !vcpu_valid too, not vm_exited alone: this is the guard that
         * keeps hv_vm_destroy/munmap from running under a live foreign vCPU and
         * panicking the host, so it checks the direct fact (no live handle
         * here) rather than trusting that vm_exited always implies the handle
         * is gone. The two are published together under thread_lock, so this
         * term is currently always true; keeping it fails closed (defer to
         * process exit) if that ordering ever regresses.
         */
        if (t->vm_exited && !t->vcpu_valid)
            continue;

        /* Every other active non-main slot is a live worker: running a vCPU, or
         * mid-bring-up (active, vcpu_valid not yet set) about to create and
         * enter one on its own thread. HVF vCPUs are thread-affine, so this
         * thread can neither destroy such a handle nor let hv_vm_destroy /
         * munmap run while the worker is live without corrupting kernel state
         * and panicking the host. vcpu_valid alone is not a sufficient proxy --
         * a bring-up worker is active with vcpu_valid still false. Report it so
         * guest_destroy defers teardown to process exit, the only safe way to
         * stop a foreign vCPU.
         */
        live_workers = true;
    }

    pthread_mutex_unlock(&thread_lock);
    if (live_workers_left)
        *live_workers_left = live_workers;
    return main_destroyed;
}

void thread_interrupt_all(void)
{
    /* Collect active vCPUs and kick them out of hv_vcpu_run() in one critical
     * section. hv_vcpus_exit must run under thread_lock, not after releasing
     * it: a worker destroys its own vCPU under the same lock on exit, so a
     * handle collected here and used after the lock is dropped could be handed
     * to HVF after it was freed, faulting the host on the released vCPU object.
     * Holding the lock across the kick serializes it against destruction --
     * every handle passed is still live, or the worker already cleared
     * vcpu_valid and was skipped. hv_vcpus_exit only signals the target vCPUs
     * to leave hv_vcpu_run and returns without waiting, so it does not block
     * under the lock (the signal-preemption path already kicks under
     * thread_lock the same way).
     */
    hv_vcpu_t vcpus[MAX_THREADS];
    int count = 0;

    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t)
        if (t->vcpu_valid) /* skip bring-up/torn-down slots */
            vcpus[count++] = t->vcpu;

    /* Each kicked vCPU sees HV_EXIT_REASON_CANCELED and checks pending signals
     * / teardown.
     */
    if (count > 0)
        hv_vcpus_exit(vcpus, (uint32_t) count);
    pthread_mutex_unlock(&thread_lock);
}

bool thread_signal_deliverable(uint64_t sigbit)
{
    /* Lock-free scan: a thread's blocked field is written under sig_lock (lock
     * order 4) by its owner, and once by the parent that clones it before the
     * child's pthread exists. This reads it without either lock, so every
     * writer publishes with an atomic store. A stale read is benign: worst case
     * is a harmless spurious interrupt after reading blocked=0 concurrently
     * with a transition to blocked=1, or a delayed delivery corrected by the
     * next signal_pending() check.
     */
    THREAD_FOR_EACH_ACTIVE_RELAXED (t) {
        uint64_t mask = thread_blocked_load(t);
        if (sigbit & ~mask)
            return true;
    }
    return false;
}

/* Fork quiesce. */

bool thread_quiesce_siblings(void)
{
    hv_vcpu_t vcpus[MAX_THREADS];
    int count = 0;
    int targets = 0;

    pthread_mutex_lock(&thread_lock);

    /* Refuse while an execve teardown is reaping. The caller is one of the
     * threads being reaped, and a window armed now would park its siblings in a
     * barrier that only the caller can release, which it will not do because it
     * is about to leave the guest itself. Refusing keeps the teardown and the
     * quiesce windows from overlapping at all, which is what lets the barrier
     * below block unconditionally: a sibling parked there is never one this
     * teardown is waiting for.
     *
     * Read under thread_lock, and thread_exec_de_thread publishes it under the
     * same lock after draining any window already open, so the two orderings
     * are the only ones possible: either this arms first and the teardown waits
     * for it, or the teardown publishes first and this refuses.
     */
    if (atomic_load_explicit(&exec_de_thread_active, memory_order_acquire)) {
        pthread_mutex_unlock(&thread_lock);
        return false;
    }

    /* Count every active sibling. Startup siblings may not have published a
     * vCPU yet, but once they do they check the barrier before guest entry.
     * fork_counted marks the slots that owe the barrier a response, so a
     * sibling that exits before arriving can hand its count back (see
     * thread_deactivate) instead of stalling the forker the full timeout.
     */
    THREAD_FOR_EACH_ACTIVE (t) {
        if (t == current_thread)
            continue;
        t->fork_counted = true;
        targets++;
        if (t->vcpu_valid)
            vcpus[count++] = t->vcpu;
    }

    if (targets == 0) {
        pthread_mutex_unlock(&thread_lock);
        return true; /* Nothing to quiet, so the window is trivially held */
    }

    /* Arm the barrier */
    fork_quiesce_active = true;
    fork_quiesced_count = 0;
    fork_target_count = targets;

    /* Force siblings out of hv_vcpu_run under the lock, before releasing it: a
     * sibling destroys its own vCPU under thread_lock on exit, so kicking a
     * collected handle after the lock is dropped could hand HVF a freed vCPU.
     * The kick does not block, so holding the lock across it is safe.
     */
    if (count > 0)
        hv_vcpus_exit(vcpus, (uint32_t) count);

    pthread_mutex_unlock(&thread_lock);

    /* Wait until all siblings have blocked on the barrier. Use a bounded wait:
     * siblings in long-running host syscalls (poll, read, accept) may not reach
     * the barrier check promptly since hv_vcpus_exit only affects threads
     * inside hv_vcpu_run. After the timeout, proceed with the snapshot; the
     * sibling is blocked in a host syscall and not mutating guest memory.
     */
    pthread_mutex_lock(&thread_lock);
    if (fork_quiesced_count < fork_target_count) {
        struct timespec deadline;
        timespec_deadline_in_ms(&deadline, 100);
        while (fork_quiesced_count < fork_target_count) {
            int rc = pthread_cond_timedwait(&fork_all_quiesced_cond,
                                            &thread_lock, &deadline);
            if (rc == ETIMEDOUT)
                break; /* Proceed with snapshot anyway */
        }
    }
    pthread_mutex_unlock(&thread_lock);

    return true;
}

void thread_resume_siblings(void)
{
    pthread_mutex_lock(&thread_lock);
    fork_quiesce_active = false;
    fork_quiesced_count = 0;
    fork_target_count = 0;

    /* Clear any fork_counted still set on siblings that never reached the
     * barrier (blocked in a host syscall and released by the timeout) so the
     * next barrier generation starts from a clean slate.
     */
    THREAD_FOR_EACH (t)
        t->fork_counted = false;
    pthread_cond_broadcast(&fork_cond);

    /* An execve teardown parked in thread_exec_de_thread is waiting for exactly
     * this.
     */
    pthread_cond_broadcast(&fork_window_closed_cond);
    pthread_mutex_unlock(&thread_lock);
}

bool thread_fork_barrier_check(void)
{
    pthread_mutex_lock(&thread_lock);
    if (!fork_quiesce_active) {
        pthread_mutex_unlock(&thread_lock);
        return false;
    }

    /* Only a thread that thread_quiesce_siblings counted contributes to the
     * quiesced tally, and only once. A thread created after the barrier armed
     * (fork_counted == false) still blocks below so it cannot run guest code
     * during the snapshot, but must not inflate fork_quiesced_count past
     * fork_target_count and let the forker proceed before a real sibling has
     * stopped.
     */
    if (current_thread && current_thread->fork_counted) {
        current_thread->fork_counted = false;
        if (++fork_quiesced_count >= fork_target_count)
            pthread_cond_signal(&fork_all_quiesced_cond);
    }

    /* Block until the window closes. An execve teardown deliberately does not
     * break this wait: the whole point of the barrier is that no other thread
     * mutates guest memory while the forker copies it, and a sibling released
     * here would run its exit path, which writes clear_child_tid, walks the
     * robust list and unmaps its stack. The child would receive a torn image.
     *
     * Unlike Linux, where fork() takes a copy-on-write snapshot that later
     * sibling writes cannot reach, the copy here is not atomic against a
     * running thread, so the quiet is load-bearing rather than advisory.
     *
     * Nothing deadlocks behind that, because a teardown and a window never
     * overlap. thread_exec_de_thread drains a window already open before it
     * publishes the teardown, and thread_quiesce_siblings refuses to arm a new
     * one once it has. Both sides of that handshake run under thread_lock, so
     * the thread that releases this barrier is never one the teardown is
     * waiting on. exit_group is still honored: that is process death, and no
     * snapshot outlives it.
     */
    while (fork_quiesce_active && !proc_exit_group_requested()) {
        if (!thread_exec_stop_requested()) {
            pthread_cond_wait(&fork_cond, &thread_lock);
            continue;
        }

        struct timespec deadline;
        timespec_deadline_in_ms(&deadline, 200);
        if (pthread_cond_timedwait(&fork_cond, &thread_lock, &deadline) ==
            ETIMEDOUT)
            break;
    }

    pthread_mutex_unlock(&thread_lock);
    return true;
}

void thread_wake_leader_for_work(void)
{
    /* hv_vcpus_exit only reaches threads inside hv_vcpu_run, so the wakeup pipe
     * covers poll/epoll/read parks and thread_wake_exit_waiters covers the
     * internal condvars (fork barrier, ptrace stop/wait). Each is answered by
     * the woken thread re-checking its own predicate, so aiming them at the
     * whole table to reach one thread costs nothing.
     *
     * Leaving futex_interrupt_request out (the header says why) loses nothing:
     * the futex waits re-check thread_stop_requested on a 100 ms quantum, and
     * that is what sends the leader to run the execve.
     */
    wakeup_pipe_signal();
    thread_interrupt_all();
    thread_wake_exit_waiters();
    exec_handoff_wake_waiters();
}

void thread_wake_all_blocked(void)
{
    /* Teardown: every thread really is leaving, so the futex interrupt on top
     * of the wakes above is an EINTR each of them has to see.
     */
    futex_interrupt_request();
    thread_wake_leader_for_work();
}

void thread_wake_exit_waiters(void)
{
    pthread_mutex_lock(&thread_lock);

    /* Fork barrier: siblings parked in thread_fork_barrier_check. Only
     * exit_group releases them, since an execve teardown waits for the window
     * to close rather than breaking it; the broadcast is what makes them
     * re-check on process death.
     */
    pthread_cond_broadcast(&fork_cond);

    /* Deferred stack-unmap transactions: a thread waiting for another one's
     * transaction to clear parks on this condvar, which nothing else wakes.
     * Without the broadcast it sleeps through an execve teardown and is then
     * counted as a thread that would not leave.
     */
    pthread_cond_broadcast(&deferred_stack_unmap_cond);

    /* Ptrace parks: tracers blocked in thread_ptrace_wait (ptrace_cond) and
     * tracees blocked in thread_ptrace_stop (resume_cond). Scan every slot with
     * live condvars, not just active ones: a tracer may still be parked on a
     * slot whose thread was deactivated. ptrace_conds_inited only transitions
     * under thread_lock with ptrace_waiters == 0, so broadcasting here never
     * touches a destroyed condvar.
     */
    THREAD_FOR_EACH (t) {
        if (!t->ptrace_conds_inited)
            continue;
        pthread_cond_broadcast(&t->ptrace_cond);
        pthread_cond_broadcast(&t->resume_cond);
    }

    pthread_mutex_unlock(&thread_lock);
}

/* execve de_thread. */

/* Set while an execve is tearing its siblings down. Linux destroys every
 * sibling in de_thread() before mapping the new image; elfuse has to do the
 * same before guest_reset zeroes the memory those siblings are still running
 * on.
 *
 * A flag rather than a survivor pointer because sys_execve hands a non-leader
 * caller to the leader before the point of no return, so the thread that runs
 * the teardown is always slot 0 and "am I the survivor" is "am I the leader".
 *
 * Two flags rather than one because the leader has to leave its blocking wait
 * for the handoff too, and that is the opposite of being torn down. Both are
 * read by every blocking wait, so they are plain atomics rather than
 * thread_lock state. _Atomic is spelled as a qualifier, never as _Atomic(T):
 * frama-c-stubs defines the keyword away so the analyzer can parse this file,
 * and the specifier form leaves a stray parenthesized type behind.
 */
static _Atomic bool exec_leader_work_pending;

void thread_set_leader_work_pending(bool pending)
{
    atomic_store_explicit(&exec_leader_work_pending, pending,
                          memory_order_release);
}

bool thread_leader_work_pending(void)
{
    return atomic_load_explicit(&exec_leader_work_pending,
                                memory_order_acquire);
}

int thread_exec_stop_requested(void)
{
    /* The flag first, so the common case (no execve in flight) never reaches
     * current_thread: on Darwin every _Thread_local read goes through the TLV
     * descriptor thunk, which is an indirect call, not a register read.
     */
    if (!atomic_load_explicit(&exec_de_thread_active, memory_order_acquire))
        return 0;

    /* No table entry (the preemption thread, the GDB stub, the rosettad
     * bridge): runs no guest code and is nobody's sibling. The leader is the
     * thread running the teardown. And a CLONE_VM child is a distinct task with
     * its own tgid, which Linux execve leaves alone: reaping it would publish a
     * bogus exit(0) to the parent's wait4 and let its exit path request a
     * process-wide exit_group in the middle of the exec.
     */
    return current_thread && !thread_current_is_leader() &&
           !current_thread->is_vm_clone;
}

static int thread_stop_requested_for_leader_work(void)
{
    /* A non-leader execve is handed to the leader, which can only pick it up
     * from its run loop. Break it out of whatever it is parked in so the
     * handoff does not wait on an unrelated blocking syscall. Every other
     * thread ignores this: the requester is blocked in the handoff itself, and
     * a third thread has no part in it.
     */
    return thread_leader_work_pending() && thread_current_is_leader();
}

void thread_note_syscall(int nr)
{
    if (current_thread)
        atomic_store_explicit(&current_thread->in_syscall, nr,
                              memory_order_relaxed);
}

int thread_stop_requested(void)
{
    return thread_exec_stop_requested() || proc_exit_group_requested() ||
           thread_stop_requested_for_leader_work();
}

int thread_stop_is_leader_work_only(void)
{
    return thread_stop_requested_for_leader_work() &&
           !proc_exit_group_requested() && !thread_exec_stop_requested();
}

/* Whether an execve teardown will reap this slot: not the caller, not the main
 * thread's (slot 0 is never torn down; it owns process teardown), and not a
 * CLONE_VM child (a separate task that execve leaves alone). Counting every
 * active thread instead would wait, and then report, on threads that were never
 * going to leave. Caller must hold thread_lock.
 */
static bool thread_is_joinable_sibling(const thread_entry_t *t)
{
    return t != current_thread && t != &thread_table[0] && !t->is_vm_clone;
}

static int thread_count_joinable_siblings(void)
{
    int n = 0;

    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t) {
        if (thread_is_joinable_sibling(t))
            n++;
    }
    pthread_mutex_unlock(&thread_lock);

    return n;
}

bool thread_current_is_leader(void)
{
    return current_thread == &thread_table[0];
}

/* Milliseconds on CLOCK_MONOTONIC since @since. Only the de_thread wait needs
 * it, which measures how long its siblings took rather than when they left.
 */
static int64_t thread_elapsed_ms(const struct timespec *since)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t) (now.tv_sec - since->tv_sec) * 1000 +
           (now.tv_nsec - since->tv_nsec) / 1000000;
}

int thread_exec_de_thread(void)
{
    if (!current_thread)
        return 0;

    /* execve tears down an in-process tracer with the old thread group. */
    pthread_mutex_lock(&thread_lock);
    current_thread->ptraced = false;
    current_thread->tracer_tid = 0;
    current_thread->ptrace_interrupt_pending = false;
    pthread_mutex_unlock(&thread_lock);

    if (thread_count_joinable_siblings() == 0)
        return 0;

    /* Let an open quiesce window close before reaping anything.
     *
     * The two cannot overlap. A sibling parked in the fork barrier owes the
     * forker its quiet until the snapshot is done, so the teardown must not
     * pull it out; but if the teardown were already running, the forker would
     * be a thread being reaped, and the barrier would never be released. Doing
     * the wait here, before the teardown is published, keeps the forker outside
     * it: it finishes and calls thread_resume_siblings, which is what wakes
     * this.
     *
     * Bounded, because the alternative to giving up is a teardown that cannot
     * finish. The cap covers a fork snapshot with margin. Past it the window is
     * treated as stuck and the teardown proceeds, which is the pre-existing
     * race rather than a new one.
     */
    pthread_mutex_lock(&thread_lock);
    if (fork_quiesce_active) {
        struct timespec deadline;
        timespec_deadline_in_ms(&deadline, 1000);
        while (fork_quiesce_active) {
            if (pthread_cond_timedwait(&fork_window_closed_cond, &thread_lock,
                                       &deadline) == ETIMEDOUT) {
                log_warn("execve: fork snapshot still open, reaping anyway");
                break;
            }
        }
    }
    atomic_store_explicit(&exec_de_thread_active, true, memory_order_release);
    pthread_mutex_unlock(&thread_lock);

    /* Siblings leave the guest through their normal exit path (robust list,
     * CLEARTID, own-vCPU destroy), which still runs against the pre-reset image
     * because this returns only once they are gone. futex_interrupt stays set;
     * execve clears it after guest_reset.
     */
    thread_wake_all_blocked();

    /* wakeup_pipe_drain takes every queued byte, so a sibling that reaches
     * poll() after another one drained sits out its own 200 ms recheck no
     * matter how many bytes the wake wrote. Re-poke while they wind down, which
     * costs a threaded execve milliseconds instead of a poll quantum per parked
     * sibling (measured: 38 s to 2.5 s over 200 threaded execs).
     *
     * One wall-clock ceiling bounds the wait, and nothing else does. Departures
     * look like a liveness signal and are not one: once a single sibling is
     * left there are none left to observe, so a stall interval only ever
     * measures that last sibling's own latency, which is the fixed bound it was
     * meant to replace. Sized honestly it would have to cover the slowest
     * re-check quantum a parked sibling owes (200 ms, in the io wait)
     * multiplied by how far behind schedule the host is running, and that
     * multiplier is not a property this code can know: CI runs the sanitizer
     * lanes of several workflows on one machine, where a 1000 ms stall interval
     * gave up on a sibling sitting in mmap and sent an otherwise healthy execve
     * to the post-PNR fatal exit.
     *
     * Spending the whole budget here rather than splitting it with the join
     * below is what the re-poke is for: this loop kicks the wake set every
     * iteration, and the join only polls. Time moved from here to there buys a
     * parked sibling nothing.
     *
     * Wall-clock, because the sleep is a floor: an oversubscribed host
     * stretches each iteration well past its 1 ms, so a bound counted in
     * iterations would run for minutes and blow the caller's timeout instead of
     * reaching the diagnosed exit.
     */
    enum { DE_THREAD_CEILING_MS = 10000 };
    struct timespec started;
    clock_gettime(CLOCK_MONOTONIC, &started);

    int remaining = thread_count_joinable_siblings();
    int64_t elapsed_ms = 0, progress_ms = 0;

    while (remaining > 0) {
        /* The whole wake set, not just the pipe: a sibling in a tight compute
         * loop is reachable only by hv_vcpus_exit, and one kick that lands
         * between two hv_vcpu_run calls is lost. Re-issuing costs nothing here
         * and removes the dependence on a single kick landing.
         */
        thread_wake_all_blocked();
        usleep(1000);

        int now = thread_count_joinable_siblings();
        elapsed_ms = thread_elapsed_ms(&started);
        if (now < remaining) {
            remaining = now;
            progress_ms = elapsed_ms;
        }
        if (elapsed_ms >= DE_THREAD_CEILING_MS)
            break;
    }

    /* Name who is still here before the bounded join runs, so a teardown that
     * ends fatally says which thread held it up rather than only how many did.
     * The timings go with it: a report that spent its whole budget with
     * siblings leaving throughout is a slow host, and one whose last departure
     * is the start of the wait is a sibling no wake reaches, which are
     * different bugs.
     */
    if (remaining > 0) {
        log_warn(
            "execve: %d sibling(s) still in the guest after %lld ms, last "
            "departure at %lld ms",
            remaining, (long long) elapsed_ms, (long long) progress_ms);
        pthread_mutex_lock(&thread_lock);
        THREAD_FOR_EACH_ACTIVE (t) {
            if (!thread_is_joinable_sibling(t))
                continue;
            int32_t nr =
                atomic_load_explicit(&t->in_syscall, memory_order_relaxed);
            if (nr < 0)
                log_warn(
                    "execve: tid=%lld has not left the guest yet, "
                    "running guest code",
                    (long long) thread_tid(t));
            else
                log_warn(
                    "execve: tid=%lld has not left the guest yet, "
                    "in syscall %d",
                    (long long) thread_tid(t), nr);
        }
        pthread_mutex_unlock(&thread_lock);
    }

    thread_join_workers_mode(true);

    /* The join is bounded, so a sibling parked in a host call that never
     * re-checked can outlive the cap and be detached. One such call is still
     * reachable from guest code: the read side of a blocking FIFO open, which
     * macOS gives nothing to poll on (see open_nonblocking_writer in
     * syscall/fs.c). semop, fcntl F_SETLKW and flock used to belong on this
     * list and no longer do; each polls a non-blocking form now.
     *
     * The caller must not reset guest memory under a straggler: it still holds
     * that thread's registers and would resume into the zeroed image. Report
     * the count and let sys_execve apply its post-PNR policy.
     */
    int left = thread_count_joinable_siblings();

    /* Cleared last. A straggler that wakes after this reads false and resumes,
     * which is only safe because the caller treats a non-zero return as fatal.
     */
    atomic_store_explicit(&exec_de_thread_active, false, memory_order_release);

    return left;
}

void thread_reset_for_exec(void)
{
    if (!current_thread)
        return;

    /* Linux begin_new_exec() drops both: the robust list and clear_child_tid
     * are addresses in the image that just went away. Carrying them across the
     * reset makes this thread's eventual exit walk a list, and write a zero
     * word plus a futex wake, at whatever the new image happens to have put
     * there. Nothing is marked FUTEX_OWNER_DIED on the way out because no
     * thread survives that could observe it.
     */
    current_thread->robust_list_head = 0;
    current_thread->clear_child_tid = 0;

    /* rseq goes the same way, as rseq_execve does. Left registered, the address
     * belongs to the old image while the new one cannot register its own:
     * sc_rseq answers EBUSY for a thread that already has one, and the
     * preemption and signal paths would abort against the stale critical
     * section.
     */
    current_thread->rseq_gva = 0;
    current_thread->rseq_len = 0;
    current_thread->rseq_signature = 0;
}

/* Ptrace helpers. */

pthread_mutex_t *thread_get_lock(void)
{
    return &thread_lock;
}

int thread_collect_and_defer_stack_ranges(
    uint64_t start,
    uint64_t end,
    thread_deferred_stack_unmap_txn_t *txns,
    int max_ranges)
{
    int nranges = 0;

    if (start >= end || !txns || max_ranges <= 0)
        return 0;

    pthread_mutex_lock(&thread_lock);
retry:
    nranges = 0;

    /* Pass 1: enumerate every thread whose live stack overlaps [start, end) and
     * verify each one can record a new deferred-unmap entry. If the
     * caller-provided buffer is too small or any thread is at its
     * deferred-unmap cap, refuse the whole operation so pass 2 never has to
     * handle a partial commit.
     */
    THREAD_FOR_EACH_ACTIVE (t) {
        uint64_t rs = t->stack_map_start;
        uint64_t re = t->stack_map_end;

        if (rs >= re || re <= start || rs >= end)
            continue;
        if (t->deferred_stack_unmap_busy > 0) {
            /* Give up rather than wait when this thread is leaving the guest.
             * The caller reports the failure to its guest, which never reads it
             * because the run loop winds the thread down first, and an execve
             * teardown that waited here instead would count this thread as one
             * that refused to leave.
             */
            if (thread_stop_requested()) {
                pthread_mutex_unlock(&thread_lock);
                return -1;
            }
            pthread_cond_wait(&deferred_stack_unmap_cond, &thread_lock);
            goto retry;
        }
        if (nranges >= max_ranges) {
            pthread_mutex_unlock(&thread_lock);
            return -1;
        }
        uint64_t ds = (rs > start) ? rs : start;
        uint64_t de = (re < end) ? re : end;
        if (thread_can_add_deferred_unmap_locked(t, ds, de) < 0) {
            pthread_mutex_unlock(&thread_lock);
            return -1;
        }

        txns[nranges].thread = t;
        txns[nranges].guest_tid = thread_tid(t);
        txns[nranges].start = ds;
        txns[nranges].end = de;
        txns[nranges].deferred_count = t->deferred_stack_unmap_count;
        for (int j = 0; j < t->deferred_stack_unmap_count; j++) {
            txns[nranges].deferred_starts[j] =
                t->deferred_stack_unmap_starts[j];
            txns[nranges].deferred_ends[j] = t->deferred_stack_unmap_ends[j];
        }
        nranges++;
    }

    /* Pass 2: commit. Both passes iterate the table in the same order under the
     * same lock, so the active set seen here matches pass 1.
     */
    for (int i = 0; i < nranges; i++) {
        (void) thread_add_deferred_unmap_locked(txns[i].thread, txns[i].start,
                                                txns[i].end);
        txns[i].thread->deferred_stack_unmap_busy++;
    }
    pthread_mutex_unlock(&thread_lock);

    return nranges;
}

void thread_finish_deferred_stack_ranges(
    const thread_deferred_stack_unmap_txn_t *txns,
    int nranges)
{
    bool wake = false;

    if (!txns || nranges <= 0)
        return;

    pthread_mutex_lock(&thread_lock);
    for (int i = 0; i < nranges; i++) {
        thread_entry_t *t = txns[i].thread;

        if (!t || !atomic_load_explicit(&t->active, memory_order_relaxed) ||
            thread_tid(t) != txns[i].guest_tid ||
            t->deferred_stack_unmap_busy <= 0)
            continue;
        t->deferred_stack_unmap_busy--;
        wake = true;
    }
    if (wake)
        pthread_cond_broadcast(&deferred_stack_unmap_cond);
    pthread_mutex_unlock(&thread_lock);
}

void thread_rollback_deferred_stack_ranges(
    const thread_deferred_stack_unmap_txn_t *txns,
    int nranges)
{
    bool wake = false;

    if (!txns || nranges <= 0)
        return;

    pthread_mutex_lock(&thread_lock);
    for (int i = 0; i < nranges; i++) {
        thread_entry_t *t = txns[i].thread;

        if (!t || !atomic_load_explicit(&t->active, memory_order_relaxed) ||
            thread_tid(t) != txns[i].guest_tid)
            continue;
        t->deferred_stack_unmap_count = txns[i].deferred_count;
        for (int j = 0; j < txns[i].deferred_count; j++) {
            t->deferred_stack_unmap_starts[j] = txns[i].deferred_starts[j];
            t->deferred_stack_unmap_ends[j] = txns[i].deferred_ends[j];
        }
        if (t->deferred_stack_unmap_busy > 0) {
            t->deferred_stack_unmap_busy--;
            wake = true;
        }
    }
    if (wake)
        pthread_cond_broadcast(&deferred_stack_unmap_cond);
    pthread_mutex_unlock(&thread_lock);
}

int thread_prepare_deferred_stack_unmaps_for_cleanup(thread_entry_t *t,
                                                     uint64_t *starts,
                                                     uint64_t *ends,
                                                     int max_ranges)
{
    int nranges = 0;

    if (!t || !starts || !ends || max_ranges <= 0)
        return 0;

    pthread_mutex_lock(&thread_lock);
    while (t->deferred_stack_unmap_busy > 0)
        pthread_cond_wait(&deferred_stack_unmap_cond, &thread_lock);
    t->stack_map_start = 0;
    t->stack_map_end = 0;
    nranges = t->deferred_stack_unmap_count;
    if (nranges > max_ranges)
        nranges = max_ranges;
    for (int i = 0; i < nranges; i++) {
        starts[i] = t->deferred_stack_unmap_starts[i];
        ends[i] = t->deferred_stack_unmap_ends[i];
    }
    pthread_mutex_unlock(&thread_lock);

    return nranges;
}

int thread_peek_deferred_stack_unmaps(thread_entry_t *t,
                                      uint64_t *starts,
                                      uint64_t *ends,
                                      int max_ranges)
{
    int nranges = 0;

    if (!t || !starts || !ends || max_ranges <= 0)
        return 0;

    pthread_mutex_lock(&thread_lock);
    nranges = t->deferred_stack_unmap_count;
    if (nranges > max_ranges)
        nranges = max_ranges;
    for (int i = 0; i < nranges; i++) {
        starts[i] = t->deferred_stack_unmap_starts[i];
        ends[i] = t->deferred_stack_unmap_ends[i];
    }
    pthread_mutex_unlock(&thread_lock);

    return nranges;
}

int thread_drop_deferred_stack_unmap(thread_entry_t *t,
                                     uint64_t start,
                                     uint64_t end)
{
    int removed = 0;

    if (!t || start >= end)
        return 0;

    pthread_mutex_lock(&thread_lock);
    int n = t->deferred_stack_unmap_count;
    for (int i = 0; i < n; i++) {
        if (t->deferred_stack_unmap_starts[i] != start ||
            t->deferred_stack_unmap_ends[i] != end)
            continue;
        n--;
        t->deferred_stack_unmap_starts[i] = t->deferred_stack_unmap_starts[n];
        t->deferred_stack_unmap_ends[i] = t->deferred_stack_unmap_ends[n];
        t->deferred_stack_unmap_count = n;
        removed = 1;
        break;
    }
    pthread_mutex_unlock(&thread_lock);

    return removed;
}

void thread_clear_stack_map(thread_entry_t *t)
{
    if (!t)
        return;

    pthread_mutex_lock(&thread_lock);
    t->stack_map_start = 0;
    t->stack_map_end = 0;
    pthread_mutex_unlock(&thread_lock);
}

static int thread_add_deferred_unmap_locked(thread_entry_t *t,
                                            uint64_t start,
                                            uint64_t end)
{
    if (!t || start >= end)
        return 0;

    /* Absorb every existing slot that overlaps or is adjacent to [start, end),
     * expanding the candidate as needed. Compact the array in place by pulling
     * the live tail into each absorbed slot.
     */
    int n = t->deferred_stack_unmap_count;
    int i = 0;
    while (i < n) {
        uint64_t rs = t->deferred_stack_unmap_starts[i];
        uint64_t re = t->deferred_stack_unmap_ends[i];

        if (end < rs || start > re) {
            i++;
            continue;
        }
        if (rs < start)
            start = rs;
        if (re > end)
            end = re;
        n--;
        t->deferred_stack_unmap_starts[i] = t->deferred_stack_unmap_starts[n];
        t->deferred_stack_unmap_ends[i] = t->deferred_stack_unmap_ends[n];
    }

    if (n >= MAX_DEFERRED_STACK_UNMAPS) {
        t->deferred_stack_unmap_count = n;
        return -1;
    }

    t->deferred_stack_unmap_starts[n] = start;
    t->deferred_stack_unmap_ends[n] = end;
    t->deferred_stack_unmap_count = n + 1;
    return 0;
}

static int thread_can_add_deferred_unmap_locked(thread_entry_t *t,
                                                uint64_t start,
                                                uint64_t end)
{
    if (!t || start >= end)
        return 0;

    for (int i = 0; i < t->deferred_stack_unmap_count; i++) {
        uint64_t rs = t->deferred_stack_unmap_starts[i];
        uint64_t re = t->deferred_stack_unmap_ends[i];

        if (end < rs || start > re)
            continue;
        return 0;
    }

    return (t->deferred_stack_unmap_count < MAX_DEFERRED_STACK_UNMAPS) ? 0 : -1;
}

static void thread_ptrace_init(thread_entry_t *t)
{
    t->ptraced = false;
    t->tracer_tid = 0;
    t->ptrace_stopped = false;
    t->ptrace_stop_sig = 0;
    t->ptrace_cont_sig = 0;
    t->ptrace_regs_dirty = false;
    t->is_vm_clone = false;
    t->parent_tid = 0;
    t->exit_signal = 0;
    t->vm_exited = false;
    t->vm_exit_status = 0;
    memset(&t->ptrace_regs, 0, sizeof(t->ptrace_regs));
    pthread_cond_init(&t->ptrace_cond, NULL);
    pthread_cond_init(&t->resume_cond, NULL);
    t->ptrace_conds_inited = true;
    t->ptrace_waiters = 0;
    t->ptrace_cleanup_pending = false;
}

int thread_ptrace_stop(thread_entry_t *t, int sig)
{
    pthread_mutex_lock(&thread_lock);

    /* Snapshot vCPU registers into ptrace_regs so the tracer can read them
     * without cross-thread HVF access.
     */
    vcpu_snapshot_gprs(t->vcpu, t->ptrace_regs.regs);
    t->ptrace_regs.sp = vcpu_get_sysreg(t->vcpu, HV_SYS_REG_SP_EL0);
    t->ptrace_regs.pc = vcpu_get_sysreg(t->vcpu, HV_SYS_REG_ELR_EL1);
    t->ptrace_regs.pstate = vcpu_get_sysreg(t->vcpu, HV_SYS_REG_SPSR_EL1);

    /* Enter ptrace-stop state */
    t->ptrace_stopped = true;
    t->ptrace_stop_sig = sig;
    t->ptrace_cont_sig = 0;
    t->ptrace_regs_dirty = false;

    /* Wake the tracer (blocked in thread_ptrace_wait) */
    pthread_cond_broadcast(&t->ptrace_cond);

    /* Block until tracer calls PTRACE_CONT. Bail out on exit_group: only the
     * tracer signals resume_cond, and a tracer that exits (or calls exit_group
     * itself) will never CONT this stop. thread_wake_exit_waiters broadcasts
     * resume_cond; returning 0 sends the caller back to its run loop, which
     * re-checks thread_stop_requested.
     */
    while (t->ptrace_stopped && !thread_stop_requested())
        pthread_cond_wait(&t->resume_cond, &thread_lock);

    /* Apply register changes if tracer wrote via SETREGSET */
    if (t->ptrace_regs_dirty) {
        vcpu_restore_gprs(t->vcpu, t->ptrace_regs.regs);
        vcpu_set_sysreg(t->vcpu, HV_SYS_REG_SP_EL0, t->ptrace_regs.sp);
        vcpu_set_sysreg(t->vcpu, HV_SYS_REG_ELR_EL1, t->ptrace_regs.pc);
        vcpu_set_sysreg(t->vcpu, HV_SYS_REG_SPSR_EL1, t->ptrace_regs.pstate);
        t->ptrace_regs_dirty = false;
    }

    int cont_sig = t->ptrace_cont_sig;
    pthread_mutex_unlock(&thread_lock);

    return cont_sig;
}

void thread_ptrace_cont(thread_entry_t *t, int sig)
{
    pthread_mutex_lock(&thread_lock);
    t->ptrace_cont_sig = sig;
    t->ptrace_stopped = false;
    pthread_cond_signal(&t->resume_cond);
    pthread_mutex_unlock(&thread_lock);
}

/* True when t is a waitable child of the given tracer, optionally narrowed by
 * pid (>0 = exact TID, <=0 = any). Caller holds thread_lock.
 */
static bool thread_matches_tracer_child(const thread_entry_t *t,
                                        int64_t tracer_tid,
                                        int pid)
{
    if (!atomic_load_explicit(&t->active, memory_order_relaxed))
        return false;
    bool is_child = (t->ptraced && t->tracer_tid == tracer_tid) ||
                    (t->is_vm_clone && t->parent_tid == tracer_tid);
    if (!is_child)
        return false;
    if (pid > 0 && thread_tid(t) != pid)
        return false;
    return true;
}

int64_t thread_ptrace_wait(int64_t tracer_tid,
                           int pid,
                           int *out_status,
                           int options)
{
    int wnohang = (options & 1); /* WNOHANG = 1 on Linux */

    pthread_mutex_lock(&thread_lock);

    for (;;) {
        /* exit_group or execve teardown: the stop/exit notifications that would
         * signal ptrace_cond stop arriving once workers are being torn down.
         *
         * Return 0 ("no matching children") so the caller falls through and its
         * blocking paths re-check proc_exit_group_requested.
         */
        if (thread_stop_requested()) {
            pthread_mutex_unlock(&thread_lock);
            return 0;
        }

        bool found_any = false; /* Any waitable children at all? */

        THREAD_FOR_EACH (t) {
            if (!thread_matches_tracer_child(t, tracer_tid, pid))
                continue;

            found_any = true;

            /* Ptrace-stopped: report stop signal in wait status. */
            if (t->ptrace_stopped) {
                int64_t tid = thread_tid(t);
                if (out_status)
                    *out_status = (t->ptrace_stop_sig << 8) | 0x7F;
                pthread_mutex_unlock(&thread_lock);
                return tid;
            }

            /* VM-clone child exited: reap and deactivate. */
            if (t->vm_exited) {
                int64_t tid = thread_tid(t);
                if (out_status)
                    *out_status = t->vm_exit_status;

                /* Destroy condvars after the last waiter returns from
                 * pthread_cond_wait().
                 */
                thread_free_sp_el1_locked(t);
                atomic_store_explicit(&t->active, 0, memory_order_release);
                atomic_fetch_sub_explicit(&active_thread_count, 1,
                                          memory_order_relaxed);
                t->ptrace_cleanup_pending = true;
                thread_ptrace_cleanup_locked(t);
                pthread_mutex_unlock(&thread_lock);

                /* Slot is now inactive; drop any unconsumed thread-directed
                 * pending bits from the global hint (same rationale as
                 * thread_deactivate). Outside thread_lock to honor sig_lock (4)
                 * before thread_lock (5).
                 */
                signal_refresh_pending_hint();
                return tid;
            }
        }

        if (!found_any) {
            pthread_mutex_unlock(&thread_lock);
            return 0; /* No matching children; let caller fall through */
        }

        if (wnohang) {
            pthread_mutex_unlock(&thread_lock);
            return 0;
        }

        /* Block on the first matching child's ptrace_cond. In practice VM-clone
         * has one tracee, so this scans little.
         */
        THREAD_FOR_EACH (t) {
            if (!thread_matches_tracer_child(t, tracer_tid, pid))
                continue;

            t->ptrace_waiters++;
            pthread_cond_wait(&t->ptrace_cond, &thread_lock);
            t->ptrace_waiters--;
            if (t->ptrace_cleanup_pending)
                thread_ptrace_cleanup_locked(t);
            break; /* Re-scan after wakeup */
        }
    }
}
