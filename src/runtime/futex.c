/*
 * Linux futex emulation
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hash table of wait queues keyed by guest virtual address. Each bucket has its
 * own mutex for fine-grained locking. Waiters are singly-linked lists with
 * per-waiter condition variables for precise wakeup.
 *
 * Atomicity: The critical FUTEX_WAIT race (guest writes futex word after the
 * current read but before the waiter sleeps) is prevented by holding the bucket
 * lock across the word-read + enqueue + cond_wait sequence. FUTEX_WAKE also
 * acquires the same bucket lock, so a wake cannot slip between the read and the
 * wait.
 *
 * Timeout: FUTEX_WAIT with a non-NULL timeout uses pthread_cond_timedwait with
 * an absolute deadline. FUTEX_WAIT_BITSET always uses absolute time.
 */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "utils.h"

#include "core/shim-globals.h"
#include "runtime/futex.h"
#include "runtime/thread.h"

#include "syscall/linux-wire.h"
#include "syscall/proc.h"
#include "syscall/signal.h"

#include "debug/log.h"
#include "proved/futexhash.h"
#include "proved/futexop.h"
#include "proved/futexpi.h"
#include "proved/futexreq.h"
#include "proved/futexwaitv.h"
#include "proved/futexwakeop.h"
#include "proved/timespec.h"

/* Interrupt flag: when set, futex_wait returns -EINTR. Raised only by teardown
 * through thread_wake_all_blocked, so every blocked wait can observe that the
 * process is tearing down without a full exit_group.
 */
static _Atomic int futex_interrupt_requested = 0;

/* Futex operations (from Linux uapi). */
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_REQUEUE 3
#define FUTEX_CMP_REQUEUE 4
#define FUTEX_WAKE_OP 5
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10

/* Strips the FUTEX_PRIVATE_FLAG (0x80) and FUTEX_CLOCK_REALTIME bits so the
 * dispatch switch sees only the base operation. Emulation doesn't differentiate
 * private vs shared futexes (single-process guest).
 */
#define FUTEX_CMD_MASK 0x7F

/* core/shim.S futex_wait_fast decodes the same three values as immediates,
 * because assembly cannot see these defines. That leaves the shim serving a
 * shape the host would decode differently if one ever changes, with nothing to
 * catch it: test-shim-futex-stats.sh only asserts the counters move. Pin them
 * the way shim-globals.c pins the urandom literals it shares with the shim.
 */
_Static_assert(FUTEX_CMD_MASK == 0x7F,
               "core/shim.S futex_wait_fast hardcodes and w15, w14, #0x7f");
_Static_assert(FUTEX_WAIT == 0,
               "core/shim.S futex_wait_fast hardcodes cmp w15, #0");
_Static_assert(FUTEX_WAIT_BITSET == 9,
               "core/shim.S futex_wait_fast hardcodes cmp w15, #9");
_Static_assert(FUTEX_WAKE == 1,
               "core/shim.S futex_wait_fast hardcodes cmp w15, #1");
_Static_assert(FUTEX_WAKE_BITSET == 10,
               "core/shim.S futex_wait_fast hardcodes cmp w15, #10");

#define FUTEX_BITSET_MATCH_ANY 0xFFFFFFFFU

/* The PI word's three fields and the edits made to them are proved/futexpi.h,
 * which carries the layout and Linux's own constants.
 */

/* The wait quantum is capped at 100 ms so proc_exit_group_requested() and
 * futex_interrupt_consume() get noticed promptly without a process-wide
 * broadcast channel. EINTR is only returned when an actual deliverable signal
 * is queued for this thread (confirmed under sig_lock via signal_pending(), not
 * the atomic hint, so that rt_sigprocmask masking the queued signal cannot
 * leave a stale-true edge behind), or when a guest itimer expires under the
 * poll loop's signal_check_timer poke. Earlier revisions returned -EINTR after
 * one unconditional second of waiting to unblock shutdown-stalled
 * multi-threaded runtimes, but that broke POSIX sem_wait callers that do not
 * retry on EINTR (e.g. foot's render worker).
 */
#define FUTEX_OS_SYNC_POLL_CAP_NS (100ULL * 1000 * 1000)

/* Hash table.
 *
 * Sized for wakers, not waiters. At most MAX_THREADS (64) threads can be queued
 * at once, so 64 buckets would already keep the chains short; what makes the
 * table too narrow is that futex_wake takes the bucket lock even when nothing
 * is queued in the chain. Two threads waking unrelated futexes therefore
 * serialize whenever their addresses collide, which at 64 buckets is often
 * enough to cost more than the wake itself: eight threads each waking their own
 * private futex measured 801 ns per wake, worse than the same test at four
 * threads.
 *
 * At 1024, paired with the multiply-shift hash below, the collapse is gone (316
 * ns per wake against 801, and eight threads now beat four). Width alone was
 * not enough: the old shift-xor hash kept page-strided futexes in two buckets
 * at any width, so both had to change. Not widened further: iSH runs 4096, but
 * with a 64-thread ceiling the residual collision rate is already negligible
 * and the table is a fixed allocation: 64 KiB of mutexes at this size, inside
 * 128 KiB of BSS once padded. The whole table went from 5 KiB to 128 KiB, which
 * also costs about 25 us of extra futex_init per launch and per fork child
 * (1024 mutex inits plus first touch), under 0.1 percent of a fork.
 */

#define FUTEX_BUCKETS 1024u

/* How many times a census violation has to reproduce before it is believed. See
 * the contract assert in futex_wake for why one reading cannot decide. Five,
 * because the observed transients cleared on the first re-read every time and
 * the cost is paid only on a reading that already looks wrong.
 */
#define FUTEX_CENSUS_RECHECKS 5

/* The shim's wake fast path recomputes this bucket index in assembly, so both
 * the table size and the multiplier are pinned here. A divergence would send
 * the shim to the wrong count, and a wrong count that reads zero is a lost
 * wakeup rather than a slow path.
 */
_Static_assert(FUTEX_BUCKETS == SHIM_FUTEX_BUCKETS,
               "core/shim.S futex_wake_fast hardcodes and x15, x15, #1023");
_Static_assert((FUTEX_BUCKETS & (FUTEX_BUCKETS - 1)) == 0,
               "the shim masks instead of dividing, so this must be a power "
               "of two");
_Static_assert(FUTEX_HASH_MULT == 0x9E3779B97F4A7C15ULL,
               "core/shim.S futex_wake_fast builds this constant with movz "
               "and three movk");

/* Per-waiter node. Allocated on the host stack of the waiting thread (no malloc
 * needed; the waiter is stack-local to sys_futex).
 *
 * group_lock / group_cond are optional: when non-NULL, a wake additionally
 * signals group_cond under group_lock. futex_waitv uses this so that any wake
 * across the wait set unblocks the polling thread without per-bucket polling.
 */
typedef struct futex_waiter {
    uint64_t uaddr;            /* Guest VA being waited on */
    uint32_t bitset;           /* For WAIT_BITSET matching */
    pthread_cond_t cond;       /* Signalled by WAKE to unblock this waiter */
    _Atomic int woken;         /* Set to 1 by WAKE before signalling */
    struct futex_waiter *next; /* Next waiter in same bucket */
    pthread_mutex_t *group_lock;
    pthread_cond_t *group_cond;

    /* Which bucket this waiter's published count was charged to. Normally the
     * bucket its uaddr hashes to, but FUTEX_REQUEUE moves a parked waiter to
     * another address, and the publication has to move with it: a count left on
     * the old bucket would let the shim answer a wake on the new address with
     * zero while this waiter is still parked. Requeue rewrites this field under
     * both bucket locks, and the wait path drops whatever it finds here rather
     * than what it charged on entry.
     */
    unsigned pub_bucket;

    /* Whether this waiter's owner drops the charge named by pub_bucket rather
     * than the bucket it charged on entry. futex_wait_inner and sys_futex_waitv
     * do; futex_lock_pi_inner does not, because its eight post-enqueue exits
     * leave no single point under the lock to report from. Requeue reads this
     * to decide whether moving the charge is safe: rewriting it for an owner
     * that will still debit its entry bucket underflows that count, and an
     * underflowed count wraps to a value a later waiter's increment brings back
     * to zero, which is a lost wakeup.
     */
    bool pub_follows;

    /* Index of the bucket whose chain holds this waiter. A wake takes only the
     * lock of the bucket it finds the waiter in, so the owner has to sleep, and
     * test woken, under that same lock or the two are not ordered. Requeue
     * stores this under both bucket locks when it moves the waiter and signals
     * cond, and the owner loads it to learn which lock to hold. Only a
     * futex_wait_inner waiter reads it: a PI waiter is never moved, and a
     * futex_waitv one sleeps on its group.
     */
    _Atomic unsigned home;
} futex_waiter_t;

/* If the waiter belongs to a futex_waitv group, signal the group's cond so the
 * polling thread wakes immediately. Caller holds the bucket lock; group_lock is
 * acquired below it (lock order: bucket -> group_lock).
 */
static void futex_waiter_notify_group(futex_waiter_t *w)
{
    if (!w->group_cond)
        return;
    pthread_mutex_lock(w->group_lock);
    pthread_cond_signal(w->group_cond);
    pthread_mutex_unlock(w->group_lock);
}

/* One bucket in the hash table. Protected by its own mutex. Lock order: 7 (leaf
 * locks, index-ordered when two acquired). Padded to a cache line. The struct
 * is 72 bytes and this host's line is 128, so unpadded neighbours share a line
 * and two futexes the hash correctly separated still contend on it. Measured
 * with eight threads each taking its own adjacent bucket: 16-18 ns per lock
 * unpadded against 5-8 ns padded, a 2-4x share of exactly the contention the
 * 64-to-1024 widening was made to remove. The padding itself costs BSS only,
 * 73728 bytes to 131072 at this bucket count; the table's total is above
 * FUTEX_BUCKETS.
 */
typedef struct {
    pthread_mutex_t lock;
    futex_waiter_t *head; /* Linked list of waiters hashing to this bucket */
} __attribute__((aligned(128))) futex_bucket_t;

static futex_bucket_t buckets[FUTEX_BUCKETS];

/* Hash a guest VA to a bucket index.
 *
 * The mixing and its bound are futex_bucket_index in proved/futexhash.h, which
 * carries the postcondition that makes buckets[idx] in-range for any address a
 * guest can name. That mattered enough to prove: the index selects an element
 * of a fixed array on a hot path.
 *
 * The form it replaced, ((uaddr >> 2) ^ (uaddr >> 14)), aliased badly on
 * exactly the strides real allocators produce. Futexes laid out one per
 * cache-line pair, per slab slot, or per page differ by a power of two, and a
 * shift-xor of a power-of-two stride leaves the low index bits constant. Eight
 * futexes 256 bytes apart landed in one bucket of 64; eight a page apart landed
 * in two buckets, and stayed in two however wide the table grew, so widening
 * relocated the collapse rather than fixing it and the hash had to change with
 * it.
 */
static inline unsigned futex_hash(uint64_t uaddr)
{
    return futex_bucket_index(uaddr, FUTEX_BUCKETS);
}

/* Linux requires a futex word to be naturally aligned, and every op checks this
 * before the address reaches a bucket. Stated as a contract because without one
 * a widened or narrowed mask breaks no obligation: the proof would pass on a
 * body it never constrained, and the mutation gate would have nothing to
 * reject.
 *
 * The ensures is in the bit domain rather than the more readable "uaddr % 4 ==
 * 0" because the prover times out bridging modulo and bitmask on a 64-bit
 * value. Measured at the 30s budget, and a fresh cache does not help.
 */
/*@
  assigns \nothing;
  ensures \result <==> (uaddr & 0x3) == 0;
 */
static inline bool futex_uaddr_is_aligned(uint64_t uaddr)
{
    return (uaddr & 0x3) == 0;
}

/* Poll the guest itimer and pending-signal state on behalf of a bucket waiter.
 * Lock order forbids doing that under the bucket lock (bucket is 7, sig_lock is
 * 4), so this drops b->lock and retakes it. The caller must re-check
 * waiter.woken afterward: a wake can land in the window.
 *
 * Returns whether a deliverable signal is queued for this thread, claimed so a
 * sibling woken by the same process-directed signal does not also report EINTR
 * for it.
 */
static bool futex_poll_signal_relock(futex_bucket_t *b)
{
    pthread_mutex_unlock(&b->lock);
    signal_check_timer_real();
    bool sig_ready = signal_claim_interruption();
    pthread_mutex_lock(&b->lock);
    return sig_ready;
}

/* Signal kick. A thread parked in FUTEX_WAIT or FUTEX_WAIT_BITSET watches
 * neither the wakeup pipe nor its condition variable, so futex_kick is what
 * tells it a signal was queued. The polling quantum stays, for teardown.
 *
 * The kicker sets futex_kick and then looks for a park; the thread publishes
 * its park and then tests futex_kick before it sleeps. All of it is seq_cst, so
 * at least one of the two sees the other. The park is signalled under the mutex
 * it published, which closes the window between its test and its sleep. A
 * waiter FUTEX_REQUEUE moved publishes again under its new bucket's lock.
 */
static bool futex_kick_consume(void)
{
    thread_entry_t *t = current_thread;
    return t && atomic_exchange_explicit(&t->futex_kick, 0,
                                         memory_order_seq_cst) != 0;
}

/* Caller holds @lock, and holds it again whenever it tests the kick. */
static void futex_park_publish(pthread_mutex_t *lock, pthread_cond_t *cond)
{
    thread_entry_t *t = current_thread;
    if (!t)
        return;
    atomic_store_explicit(&t->futex_park_cond, cond, memory_order_seq_cst);
    atomic_store_explicit(&t->futex_park_lock, lock, memory_order_seq_cst);
}

/* Under the mutex the park published and before its condvar is destroyed: the
 * kicker signals only while futex_park_lock, re-read under that mutex, still
 * names it.
 */
static void futex_park_withdraw(void)
{
    thread_entry_t *t = current_thread;
    if (t)
        atomic_store_explicit(&t->futex_park_lock, NULL, memory_order_seq_cst);
}

/* Sleep on a published park until @until, unless a kick is already waiting. The
 * caller runs its signal check after either.
 */
static void futex_park_wait(pthread_cond_t *cond,
                            pthread_mutex_t *lock,
                            const struct timespec *until)
{
    if (!futex_kick_consume())
        pthread_cond_timedwait(cond, lock, until);
}

void futex_kick(thread_entry_t *t)
{
    atomic_store_explicit(&t->futex_kick, 1, memory_order_seq_cst);

    pthread_mutex_t *lock =
        atomic_load_explicit(&t->futex_park_lock, memory_order_seq_cst);
    if (!lock)
        return;

    pthread_mutex_lock(lock);
    pthread_mutex_t *still =
        atomic_load_explicit(&t->futex_park_lock, memory_order_seq_cst);
    if (still == lock) {
        pthread_cond_t *cond =
            atomic_load_explicit(&t->futex_park_cond, memory_order_seq_cst);
        pthread_cond_signal(cond);
    }
    pthread_mutex_unlock(lock);
}

/* Unlink a waiter from its bucket's singly-linked list. Caller must hold
 * b->lock. Silently returns if the waiter is not in the list (already unlinked
 * by a wake/requeue).
 */
static void bucket_unlink_locked(futex_bucket_t *b, const futex_waiter_t *w)
{
    for (futex_waiter_t **pp = &b->head; *pp; pp = &(*pp)->next) {
        if (*pp == w) {
            *pp = w->next;
            return;
        }
    }
}

/* Trade @b->lock, which the caller holds, for the lock of the bucket @w is
 * queued in or was woken from, and return that bucket. home cannot change under
 * the lock it names, since moving the waiter out takes that lock, so once this
 * returns a wake has either finished with @w or not found it yet.
 */
static futex_bucket_t *futex_waiter_follow(futex_bucket_t *b,
                                           const futex_waiter_t *w)
{
    for (;;) {
        futex_bucket_t *home =
            &buckets[atomic_load_explicit(&w->home, memory_order_acquire)];
        if (home == b)
            return b;
        pthread_mutex_unlock(&b->lock);
        pthread_mutex_lock(&home->lock);
        b = home;
    }
}

/* Unlink the waiter at *pp from its bucket list and wake it. The bucket lock
 * must be held. Unlinking before the store/signal keeps a woken waiter from
 * observing itself still queued; the release store pairs with the waiter's
 * acquire load of woken. On return *pp points at the next entry, so a scanning
 * loop should re-test *pp without advancing pp.
 */
static void futex_wake_waiter_locked(futex_waiter_t **pp)
{
    futex_waiter_t *w = *pp;
    *pp = w->next; /* unlink before signaling */
    atomic_store_explicit(&w->woken, 1, memory_order_release);
    pthread_cond_signal(&w->cond);
    futex_waiter_notify_group(w);
}

/* Guarded access to a guest futex word.
 *
 * A futex word can sit in a MAP_SHARED file mapping, which elfuse backs with a
 * live host overlay. Once anything truncates that file the page is gone, and
 * these atomics run from host user mode, so an unguarded access kills elfuse
 * instead of reporting an error. Both helpers return false on that fault; every
 * caller turns it into EFAULT the same way it handles an unresolvable uaddr.
 *
 * The jump lands inside these helpers, so a caller holding a bucket lock still
 * reaches its own unlock path.
 */
static bool futex_word_load(const uint32_t *word, uint32_t *out)
{
    bool faulted;
    HOST_SIGBUS_GUARD(
        faulted, *out = atomic_load_explicit((const _Atomic uint32_t *) word,
                                             memory_order_seq_cst));
    return !faulted;
}

/* The compare every waiting futex operation makes before it commits to
 * blocking. The guest reads the word, decides it should sleep, and calls futex
 * with the value it saw; between those two the value may have moved and a wake
 * may already have been sent, so this re-reads it and refuses to sleep when it
 * no longer matches. Skipping that turns a wake that arrived a moment early
 * into a wait nothing will ever satisfy.
 *
 * Returns 0 when the caller should block, -LINUX_EAGAIN when the word moved,
 * -LINUX_EFAULT when uaddr does not resolve or the load faults.
 *
 * Three callers share this: futex_wait, futex_requeue's CMP_REQUEUE, and
 * futex_waitv. What differs between them is which bucket locks are held on an
 * error return, so each keeps its own unlock ladder rather than this taking
 * one.
 *
 * futex_wait_fast in core/shim.S is a fourth implementation, in EL1 assembly,
 * answering the -LINUX_EAGAIN case without the HVC round trip. It bails to the
 * host for every input this function would answer differently, so a change to
 * the outcomes or their order here needs the same change there.
 */
static int64_t futex_should_block(const guest_t *g,
                                  uint64_t uaddr,
                                  uint32_t expected)
{
    uint32_t *word = (uint32_t *) guest_ptr(g, uaddr);
    if (!word)
        return -LINUX_EFAULT;

    uint32_t current;
    if (!futex_word_load(word, &current))
        return -LINUX_EFAULT;
    return current != expected ? -LINUX_EAGAIN : 0;
}

/* Iterations to re-read the futex word before handing the thread to the host
 * scheduler. Re-derived after the SIGBUS guard was hoisted out of the loop: the
 * first sweep ran one _setjmp per read, so its counts measured that rather than
 * the spin, and the same wall-clock spin now takes many more iterations.
 *
 * Re-swept with the guard hoisted, contended handoff: 256 gives 29.3 us (about
 * what an unspun build gives), 1024 gives 26.6 us, 4096 gives 8.3 us, 16384
 * gives 9.3 us. The knee is 4096 and past it the extra spinning costs more than
 * the park it avoids. The old constant of 256 is in that table as a warning:
 * under the per-read guard it measured a 4x win, and it buys nothing now.
 */
#define FUTEX_SPIN_ITERS 4096

/* Spin briefly waiting for the word to move, returning true if it did.
 *
 * What this catches is not the wake, it is the waker's store, which every
 * correct futex user issues before FUTEX_WAKE. Parking costs a park and an
 * unpark through the host scheduler; a handoff that completes inside the spin
 * pays neither, which is worth 4x on a two-thread handoff.
 *
 * Measured not to cost what spinning usually costs. Against an unspun build it
 * is faster under oversubscription rather than slower (2x oversubscribed 1565
 * to 1131 ms, 4x 2390 to 1787 ms), and thread-churn is unchanged (0.87x, p=0.40
 * over nine paired runs). yield is a hint rather than a hold, and the
 * park/unpark pair it avoids costs more than the spin.
 *
 * A fault here is not this function's to report: it stops spinning and lets the
 * caller's own guarded load produce the EFAULT it would have produced anyway.
 */
static bool futex_spin_word_moved(const uint32_t *word, uint32_t expected)
{
    /* volatile because a SIGBUS longjmps out of the block below, which leaves
     * any non-volatile local modified inside it indeterminate.
     */
    volatile bool moved = false;
    bool faulted;

    /* The guard is armed once around the whole loop rather than per read.
     * futex_word_load arms it per call, and arming is a thread-local lookup
     * plus a _setjmp, so spinning through it would make the loop's duration a
     * function of that macro's cost rather than of FUTEX_SPIN_ITERS.
     */
    HOST_SIGBUS_GUARD(faulted, {
        for (int i = 0; i < FUTEX_SPIN_ITERS; i++) {
            /* Relaxed: this only detects that the word moved. Every consumer of
             * that fact re-reads it under the bucket mutex or through
             * futex_word_load, both of which carry their own ordering. Worth 9
             * percent of the spin.
             */
            uint32_t seen = atomic_load_explicit(
                (const _Atomic uint32_t *) word, memory_order_relaxed);
            if (seen != expected) {
                moved = true;
                break;
            }
            __asm__ __volatile__("yield" ::: "memory");
        }
    });

    /* A fault just ends the spin. Reporting it is the caller's own guarded
     * load's job, which runs next and produces the EFAULT it would have anyway.
     */
    return !faulted && moved;
}

/* swapped may be NULL where the caller retries regardless of who won the race.
 */
static bool futex_word_cas(uint32_t *word,
                           uint32_t *expected,
                           uint32_t desired,
                           bool *swapped)
{
    bool faulted, won;
    HOST_SIGBUS_GUARD(faulted, won = atomic_compare_exchange_strong_explicit(
                                   (_Atomic uint32_t *) word, expected, desired,
                                   memory_order_seq_cst, memory_order_seq_cst));
    if (faulted)
        return false;
    if (swapped)
        *swapped = won;
    return true;
}

/* Best-effort clear of FUTEX_WAITERS on a PI word whose last waiter gave up.
 * The caller is already returning a terminal status, so a fault here only means
 * the bit stays set on a page nobody can reach anyway.
 */
static void futex_clear_waiters_bit(uint32_t *word)
{
    for (;;) {
        uint32_t v;
        bool cleared;
        if (!futex_word_load(word, &v))
            return;
        if (!futex_pi_has_waiters(v))
            return;
        if (!futex_word_cas(word, &v, futex_pi_clear_waiters(v), &cleared))
            return;
        if (cleared)
            return;
    }
}

/* Public API */

void futex_init(void)
{
    for (unsigned i = 0; i < FUTEX_BUCKETS; i++) {
        pthread_mutex_init(&buckets[i].lock, NULL);
        buckets[i].head = NULL;
    }
}

void futex_interrupt_request(void)
{
    atomic_store_explicit(&futex_interrupt_requested, 1, memory_order_release);
}

void futex_interrupt_clear(void)
{
    atomic_store_explicit(&futex_interrupt_requested, 0, memory_order_relaxed);
}

/* Test-and-clear: returns 1 if the interrupt request was pending and atomically
 * clears it, 0 otherwise. The interrupt is a one-shot edge, set by the teardown
 * paths through thread_wake_all_blocked. Teardown state marks every thread as
 * leaving; the atomic interrupt itself is consumed by only one waiter. Without
 * the clear, the flag stays set and every subsequent epoll_pwait, ppoll, futex
 * wait, etc. spins on EINTR until execve clears it -- in foot's case it never
 * does, and the spinning main thread eventually faults in a code path the guest
 * never expects to reach.
 *
 * forkipc.c set it too, on the last clone-thread exit, for a SIGCHLD that
 * clone(2) does not send. That is gone; only a process actually tearing down
 * fabricates an EINTR now.
 */
int futex_interrupt_consume(void)
{
    int expected = 1;
    return atomic_compare_exchange_strong_explicit(
        &futex_interrupt_requested, &expected, 0, memory_order_acquire,
        memory_order_relaxed);
}

/* Cap on guest-supplied tv_sec. The cap exists purely so the int64_t / time_t
 * arithmetic in the deadline conversion (now.tv_sec + delta_sec, where
 * delta_sec = lts.tv_sec - mono.tv_sec) cannot overflow even for adversarial
 * inputs. INT64_MAX / 4 leaves four-way headroom for any pairwise sum or
 * difference and still allows absolute CLOCK_REALTIME deadlines billions of
 * years into the future, which comfortably covers the year-2038/2106 envelope.
 * Linux saturates at KTIME_MAX (INT64_MAX ns ~ 292 years) on conversion to
 * ktime_t; this code stays in struct timespec so it does not need that
 * conversion, only the cap.
 */
#define FUTEX_TIMESPEC_SEC_MAX (INT64_MAX / 4)

/*@ requires \valid_read(lts);
    assigns \nothing;
    ensures \result != 0 <==> (0 <= lts->tv_sec <= FUTEX_TIMESPEC_SEC_MAX &&
                               0 <= lts->tv_nsec < TIMESPEC_NSEC_PER_SEC);
 */
static int linux_timespec_is_valid(const linux_timespec_t *lts)
{
    /* timespec_valid_capped is the proved statement of what Linux accepts on
     * the sleep and wait paths, plus the seconds ceiling this file needs, both
     * inside one <==> the provers check (verify-timespec). Restating either
     * here would be a second copy free to drift from it.
     */
    return timespec_valid_capped(lts->tv_sec, lts->tv_nsec,
                                 FUTEX_TIMESPEC_SEC_MAX);
}

/* Convert a Linux guest timespec to an absolute struct timespec deadline. For
 * FUTEX_WAIT (relative timeout), adds the duration to the current time. For
 * FUTEX_WAIT_BITSET (absolute timeout), uses the value directly.
 * Returns 0 on success, -1 if the guest pointer is invalid, -2 if the guest
 * timespec is malformed.
 */
static int futex_make_deadline(guest_t *g,
                               uint64_t timeout_gva,
                               int is_absolute,
                               struct timespec *out)
{
    linux_timespec_t lts;
    if (guest_read_small(g, timeout_gva, &lts, sizeof(lts)) < 0)
        return -1;
    if (!linux_timespec_is_valid(&lts))
        return -2;

    if (is_absolute) {
        out->tv_sec = (time_t) lts.tv_sec;
        out->tv_nsec = (long) lts.tv_nsec;
    } else {
        /* Relative: add to current CLOCK_REALTIME (pthread_cond_timedwait uses
         * CLOCK_REALTIME by default on macOS)
         */
        struct timeval now;
        gettimeofday(&now, NULL);
        out->tv_sec = now.tv_sec + (time_t) lts.tv_sec;
        out->tv_nsec = (long) now.tv_usec * 1000 + (long) lts.tv_nsec;
        timespec_normalize(out);
    }
    return 0;
}

/* Relative wait quantum until an absolute CLOCK_REALTIME deadline, capped at
 * cap_ns.
 *
 * Returns 0 once the deadline has elapsed, so the caller surfaces ETIMEDOUT
 * without re-arming.
 *
 * This subtracted the two tv_sec fields directly, which was undefined for
 * inputs the guest can name: linux_timespec_is_valid accepts tv_sec up to
 * FUTEX_TIMESPEC_SEC_MAX (INT64_MAX / 4) and the absolute-deadline path
 * forwards it unchanged, so the subtraction was safe only because the other
 * operand came from the clock. Frama-C could not discharge those five
 * signed-overflow obligations at any timeout.
 *
 * now_out hands the caller the clock reading the remainder was measured
 * against. futex_quantum_deadline needs it: building an absolute target from a
 * second reading would place that target one clock read past the guest's
 * deadline rather than on it.
 *
 * timespec_to_ns_sat is total and its proved postcondition puts both operands
 * in [0, INT64_MAX], so the subtraction below is total by construction. Using
 * it rather than a futex-local saturating helper also keeps one answer in the
 * tree to "what is this guest timespec in nanoseconds": proved/timespec.h names
 * futex as a caller, and a second convention would differ on inputs neither
 * caller can produce, which is the same provenance argument this replaces.
 */
/*@ requires \valid_read(deadline);
    requires now_out == \null || \valid(now_out);
    requires 0 <= deadline->tv_sec;
    requires 0 <= deadline->tv_nsec < TIMESPEC_NSEC_PER_SEC;
    ensures 0 <= \result <= cap_ns;
    assigns *now_out, __fc_time;
    behavior reports_now:
      assumes now_out != \null;
      assigns *now_out, __fc_time;
      ensures 0 <= *now_out <= INT64_MAX;
    behavior discards_now:
      assumes now_out == \null;
      assigns __fc_time;
    complete behaviors;
    disjoint behaviors;
 */
static uint64_t futex_remaining_ns(const struct timespec *deadline,
                                   uint64_t cap_ns,
                                   int64_t *now_out)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    int64_t deadline_ns =
        timespec_to_ns_sat(deadline->tv_sec, deadline->tv_nsec);
    int64_t now_ns = timespec_to_ns_sat(now.tv_sec, now.tv_nsec);
    if (now_out)
        *now_out = now_ns;
    if (deadline_ns <= now_ns)
        return 0;

    uint64_t rem = (uint64_t) (deadline_ns - now_ns);
    return rem < cap_ns ? rem : cap_ns;
}

/* Absolute CLOCK_REALTIME wait target one bounded quantum from now: the guest
 * deadline capped at FUTEX_OS_SYNC_POLL_CAP_NS. Every condvar sleep in the
 * timed-wait paths goes through this so a waiter parked on a distant guest
 * deadline still re-checks the process-wide teardown flags
 * (proc_exit_group_requested / futex_interrupt) each quantum; an uncapped sleep
 * would outlive thread_join_workers' poll cap and race guest_destroy's unmap of
 * the memory the waiter touches on wake.
 * Returns false when the guest deadline has already passed.
 */
/*@ requires \valid_read(deadline);
    requires \valid(out);
    requires 0 <= deadline->tv_sec;
    requires 0 <= deadline->tv_nsec < TIMESPEC_NSEC_PER_SEC;
    requires \separated(deadline, out);
    assigns *out, __fc_time;
    ensures \result ==> 0 <= out->tv_nsec < TIMESPEC_NSEC_PER_SEC;
    ensures \result ==> 0 <= out->tv_sec;
 */
static bool futex_quantum_deadline(const struct timespec *deadline,
                                   struct timespec *out)
{
    int64_t now_ns = 0;
    uint64_t rem_ns =
        futex_remaining_ns(deadline, FUTEX_OS_SYNC_POLL_CAP_NS, &now_ns);
    if (rem_ns == 0)
        return false;

    /* now + rem, with every step defined for every value its operand can take.
     * The previous form added rem_ns into out->tv_nsec and normalized, which is
     * in range only because clock_gettime returns a normalized tv_nsec and the
     * caller passes a cap well under a second. Neither is stated anywhere, so
     * it was the same provenance argument futex_remaining_ns just stopped
     * making, one call up.
     *
     * now_ns is the reading rem_ns was measured against, so this lands on the
     * guest deadline exactly whenever the deadline is the nearer of the two.
     *
     * The futex_remaining_ns contract establishes that rem_ns is at most the
     * cap. The clamp still makes the cast and the add total if that
     * implementation ever drifts past its own bound: an unclamped rem_ns above
     * INT64_MAX casts to a negative add, and INT64_MAX - add then overflows.
     * Clamping in the unsigned domain keeps the comparison well defined.
     */
    uint64_t bounded = rem_ns > (uint64_t) FUTEX_OS_SYNC_POLL_CAP_NS
                           ? (uint64_t) FUTEX_OS_SYNC_POLL_CAP_NS
                           : rem_ns;
    int64_t add = (int64_t) bounded;
    int64_t at_ns = now_ns > INT64_MAX - add ? INT64_MAX : now_ns + add;

    out->tv_sec = (time_t) (at_ns / TIMESPEC_NSEC_PER_SEC);
    out->tv_nsec = (long) (at_ns % TIMESPEC_NSEC_PER_SEC);
    return true;
}

/* FUTEX_WAIT / FUTEX_WAIT_BITSET: atomically check word == val, then sleep. */
static int64_t futex_wait_inner(unsigned *pub_bucket_out,
                                guest_t *g,
                                uint64_t uaddr,
                                uint32_t expected,
                                uint64_t timeout_gva,
                                uint32_t bitset,
                                int is_absolute)
{
    if (bitset == 0)
        return -LINUX_EINVAL;
    if (!futex_uaddr_is_aligned(uaddr))
        return -LINUX_EINVAL;

    unsigned idx = futex_hash(uaddr);
    futex_bucket_t *b = &buckets[idx];

    /* Build deadline before locking (avoid holding lock during syscall) */
    bool has_timeout = (timeout_gva != 0);
    struct timespec deadline;
    if (has_timeout) {
        int rc = futex_make_deadline(g, timeout_gva, is_absolute, &deadline);
        if (rc == -1)
            return -LINUX_EFAULT;
        if (rc == -2)
            return -LINUX_EINVAL;
    }

    /* Spin before the lock, not under it: holding the bucket lock while
     * spinning would block the very waker being waited for. FUTEX_WAIT_BITSET
     * arrives here, which is what glibc's pthread_cond_timedwait issues, so
     * without this the path a threaded glibc guest actually takes gets no
     * benefit. Returning EAGAIN without enqueueing is what Linux does whenever
     * the word does not match at the check.
     *
     * Skipped when the guest's deadline has already passed. A caller using
     * sem_timedwait or pthread_mutex_timedlock with a past deadline as a
     * non-blocking probe would otherwise pay the whole spin to be told
     * ETIMEDOUT, which the wait below reaches anyway (measured 4788 ns per call
     * against 1756 with this guard). The clock read this costs on the timed
     * path is one that path makes regardless; an untimed wait short-circuits
     * before it.
     */
    if (!has_timeout ||
        futex_remaining_ns(&deadline, FUTEX_OS_SYNC_POLL_CAP_NS, NULL) > 0) {
        const uint32_t *spin_word = (const uint32_t *) guest_ptr(g, uaddr);
        if (spin_word && futex_spin_word_moved(spin_word, expected))
            return -LINUX_EAGAIN;
    }

    pthread_mutex_lock(&b->lock);

    /* Read the futex word while holding the bucket lock, so the enqueue below
     * is ordered against a concurrent wake. A mismatch returns EAGAIN and never
     * enqueues.
     */
    int64_t block = futex_should_block(g, uaddr, expected);
    if (block != 0) {
        pthread_mutex_unlock(&b->lock);
        return block;
    }

    /* Enqueue waiter (stack-allocated, lives on this thread's stack) */
    futex_waiter_t waiter = {
        .uaddr = uaddr,
        .bitset = bitset,
        .woken = 0,
        .next = b->head,
        .pub_bucket = idx,
        .pub_follows = true,
        .home = idx,
    };
    pthread_cond_init(&waiter.cond, NULL);
    b->head = &waiter;
    futex_park_publish(&b->lock, &waiter.cond);

    /* Wait until woken or timeout */
    int ret = 0;

    for (;;) {
        /* FUTEX_REQUEUE may have moved the waiter since the last pass. Re-park
         * under the lock of the bucket that holds it now.
         */
        if (&buckets[atomic_load_explicit(&waiter.home,
                                          memory_order_acquire)] != b) {
            futex_park_withdraw();
            b = futex_waiter_follow(b, &waiter);
            futex_park_publish(&b->lock, &waiter.cond);
        }
        if (atomic_load_explicit(&waiter.woken, memory_order_acquire))
            break;

        if (has_timeout) {
            /* Sleep in bounded quanta rather than to the guest deadline: a
             * worker parked here for a long guest timeout (JVM parkNanos,
             * sem_timedwait) would otherwise be unreachable by exit_group /
             * futex_interrupt, outlive thread_join_workers' poll cap, and race
             * guest_destroy's unmap. The interrupt checks mirror the no-timeout
             * branch below.
             */
            struct timespec quantum = {0};
            if (!futex_quantum_deadline(&deadline, &quantum)) {
                ret = -LINUX_ETIMEDOUT;
                break;
            }
            futex_park_wait(&waiter.cond, &b->lock, &quantum);
            if (thread_stop_requested() || futex_interrupt_consume()) {
                ret = -LINUX_EINTR;
                break;
            }

            if (atomic_load_explicit(&waiter.woken, memory_order_acquire))
                break;

            /* Mirror the no-timeout branch's re-check below: without it, a
             * thread parked in a timed FUTEX_WAIT_BITSET (glibc sem_timedwait,
             * pthread_cond_timedwait, JVM parkNanos) only observes an expired
             * guest itimer or a deliverable queued signal once the futex wakes
             * or the full guest deadline elapses.
             */
            bool sig_ready = futex_poll_signal_relock(b);

            if (atomic_load_explicit(&waiter.woken, memory_order_acquire))
                break;

            if (sig_ready) {
                ret = -LINUX_EINTR;
                break;
            }
            continue;
        }

        /* No timeout specified: poll every 100 ms to check for exit_group,
         * futex_interrupt and expired guest itimers. A queued signal does not
         * wait for the poll: its kick ends the sleep.
         */
        struct timespec poll_ts;
        timespec_deadline_in_ms(&poll_ts, 100);
        futex_park_wait(&waiter.cond, &b->lock, &poll_ts);

        if (thread_stop_requested() || futex_interrupt_consume()) {
            ret = -LINUX_EINTR;
            break;
        }

        /* The confirm under sig_lock inside the claim avoids the stale-true
         * edge the atomic hint can carry after rt_sigprocmask masks the queued
         * signal. Re-check waiter.woken below: a wake can land in the window
         * the poll opens.
         */
        bool sig_ready = futex_poll_signal_relock(b);

        if (atomic_load_explicit(&waiter.woken, memory_order_acquire))
            break;

        /* Return EINTR only when a real deliverable signal is queued for this
         * thread. POSIX callers (e.g. glibc sem_wait, foot's render worker)
         * often do not retry on EINTR, so synthetic spurious wakeups cannot be
         * issued here.
         */
        if (sig_ready) {
            ret = -LINUX_EINTR;
            break;
        }
    }

    /* Still under the bucket lock the park was published with; the dequeue
     * below may trade it for another.
     */
    futex_park_withdraw();

    /* Dequeue under the lock a wake would hold. A wake unlinks the waiter,
     * stores woken and signals cond all under that lock, so here it has either
     * finished, and cond is safe to destroy, or it has not found the waiter,
     * which is then still in the chain to unlink.
     */
    b = futex_waiter_follow(b, &waiter);
    if (!atomic_load_explicit(&waiter.woken, memory_order_acquire))
        bucket_unlink_locked(b, &waiter);

    /* Report where the charge ended up, read while the bucket lock is still
     * held. A requeue rewrites pub_bucket under both bucket locks, so the entry
     * bucket this call charged is not necessarily the one to drop; the wrapper
     * drops whatever is reported here. Dropping the entry bucket after a move
     * debits a bucket that no longer carries this waiter and leaves the
     * destination charged forever, and the first of those wraps a uint32 count
     * that a later waiter's increment brings back to zero.
     */
    if (pub_bucket_out)
        *pub_bucket_out = waiter.pub_bucket;

    pthread_mutex_unlock(&b->lock);
    pthread_cond_destroy(&waiter.cond);

    if (atomic_load_explicit(&waiter.woken, memory_order_acquire))
        return 0;

    /* Plain FUTEX_WAIT counts its timeout from the call, so part of it is spent
     * by the time any of the exits above reports EINTR, and an SVC restart
     * would re-derive the deadline from the guest's original relative value.
     * FUTEX_WAIT_BITSET is absolute and re-derives the same instant, so it
     * stays restartable. See syscall_restart_forbid.
     */
    if (ret == -LINUX_EINTR && has_timeout && !is_absolute)
        syscall_restart_forbid();
    return ret;
}

/* FUTEX_WAKE / FUTEX_WAKE_BITSET: wake up to val waiters at uaddr. Woken
 * waiters are unlinked from the bucket list so subsequent operations do not
 * count them as still-sleeping entries.
 *
 * Plain FUTEX_WAIT enqueues with implicit FUTEX_BITSET_MATCH_ANY, which matches
 * every legal FUTEX_WAKE_BITSET mask (mask must be non-zero by Linux contract),
 * so those waiters remain valid wake targets. Publish this bucket's waiter
 * count around the whole wait.
 *
 * The increment has to land before the wait reads the futex word, which it does
 * here because every read futex_wait_inner makes is inside the call. A wrapper
 * rather than an increment threaded through the body: the body has eight
 * returns, and one that missed the drop would leave the bucket looking occupied
 * forever, quietly costing the shim's wake fast path rather than failing
 * anything.
 */
static int64_t futex_wait(guest_t *g,
                          uint64_t uaddr,
                          uint32_t expected,
                          uint64_t timeout_gva,
                          uint32_t bitset,
                          int is_absolute)
{
    unsigned idx = futex_hash(uaddr);
    unsigned pub = idx;

    shim_globals_futex_waiters_add(g, idx, +1);
    int64_t rc = futex_wait_inner(&pub, g, uaddr, expected, timeout_gva, bitset,
                                  is_absolute);
    shim_globals_futex_waiters_add(g, pub, -1);
    return rc;
}

/* Whether a plain wake would meet a PI waiter among the first budget entries it
 * would touch at uaddr. A PI waiter stays tied to its entry bucket while it
 * retries and is not woken by a plain wake, so Linux answers EINVAL from inside
 * futex_wake() and futex_wake_op(); this decides before anything is woken, the
 * way futex_requeue decides, so a refused call leaves the chain as it found it.
 *
 * The budget is what bounds the walk, because a waiter Linux never reaches
 * cannot refuse the call: its loops stop once nr_wake entries are woken.
 */
static bool futex_pi_waiter_within(const futex_bucket_t *b,
                                   uint64_t uaddr,
                                   uint32_t bitset,
                                   uint32_t budget)
{
    for (const futex_waiter_t *w = b->head; w && budget != 0; w = w->next) {
        if (w->uaddr != uaddr || (w->bitset & bitset) == 0)
            continue;

        /* pub_follows is false only for a PI waiter today; see where it is set
         * in futex_lock_pi_inner.
         */
        if (!w->pub_follows)
            return true;
        budget--;
    }
    return false;
}

static int64_t futex_wake(const guest_t *g,
                          uint64_t uaddr,
                          uint32_t val,
                          uint32_t bitset)
{
    if (bitset == 0)
        return -LINUX_EINVAL;
    if (!futex_uaddr_is_aligned(uaddr))
        return -LINUX_EINVAL;

    unsigned idx = futex_hash(uaddr);
    futex_bucket_t *b = &buckets[idx];
    int woken = 0;

    pthread_mutex_lock(&b->lock);

#ifdef ELFUSE_CONTRACT_ASSERT
    /* The published count may never understate what is parked on this bucket.
     * An understatement is what the shim's wake fast path reads as "nobody
     * here", so it is the one error that loses a wakeup rather than costing a
     * round trip. Checked here because this is the one place that holds the
     * bucket lock and can see both numbers at once; the fast path itself is
     * assembly and out of reach.
     */
    {
        /* Re-read before believing a violation, because a single reading of
         * this cannot tell one from a transient.
         *
         * The chain is stable here, under the bucket lock, but the published
         * count is not: a waiter charges it before it takes this lock and drops
         * the charge after releasing it.
         *
         * A real one is a charge that is missing rather than in flight, so it
         * does not go away when looked at again. Requiring the violation to
         * hold across re-reads is what separates the two. Measured before this
         * was added: test-signal-in-shim reported pub=0 against parked=1 on
         * every run and it survived 0 of 5 re-reads every time, on four
         * workloads including the contended benchmark. That was a false alarm
         * being read as a lost wakeup.
         */
        unsigned parked = 0;
        for (const futex_waiter_t *q = b->head; q; q = q->next)
            parked++;
        if (shim_globals_futex_waiters_get(g, idx) < parked) {
            int persisted = 0;
            for (int retry = 0; retry < FUTEX_CENSUS_RECHECKS; retry++) {
                unsigned again = 0;
                for (const futex_waiter_t *q = b->head; q; q = q->next)
                    again++;
                if (shim_globals_futex_waiters_get(g, idx) < again)
                    persisted++;
            }
            if (persisted == FUTEX_CENSUS_RECHECKS)
                abort();
        }
    }
#endif

    if (futex_pi_waiter_within(b, uaddr, bitset, val)) {
        pthread_mutex_unlock(&b->lock);
        return -LINUX_EINVAL;
    }

    futex_waiter_t **pp = &b->head;
    while (*pp && (uint32_t) woken < val) {
        futex_waiter_t *w = *pp;
        if (w->uaddr == uaddr && (w->bitset & bitset) != 0) {
            futex_wake_waiter_locked(pp);
            woken++;
        } else {
            pp = &w->next;
        }
    }

    pthread_mutex_unlock(&b->lock);

    return woken;
}

/* FUTEX_REQUEUE / FUTEX_CMP_REQUEUE: wake val waiters at uaddr, then move up to
 * val2 remaining waiters from uaddr to uaddr2.
 *
 * CMP_REQUEUE additionally checks *uaddr == val3 before proceeding; returns
 * -EAGAIN if the comparison fails (stale wakeup avoidance).
 *
 * Musl uses FUTEX_REQUEUE (not CMP) in pthread_cond_timedwait.c for efficient
 * condition variable broadcast, avoiding thundering herd by moving waiters
 * directly to the mutex futex instead of waking them all.
 *
 * Lock ordering: always acquire lower-indexed bucket first to avoid deadlock
 * when source and destination hash to different buckets.
 */
static int64_t futex_requeue(guest_t *g,
                             uint64_t uaddr,
                             uint32_t wake_count,
                             uint32_t requeue_count,
                             uint64_t uaddr2,
                             int do_cmp,
                             uint32_t expected)
{
    /* Linux refuses these before taking either key; proved/futexreq.h carries
     * why the sign is only visible as the top bit here.
     */
    if (!futex_requeue_counts_valid(wake_count, requeue_count))
        return -LINUX_EINVAL;

    if (!futex_uaddr_is_aligned(uaddr) || !futex_uaddr_is_aligned(uaddr2))
        return -LINUX_EINVAL;

    unsigned idx_src = futex_hash(uaddr);
    unsigned idx_dst = futex_hash(uaddr2);
    futex_bucket_t *b_src = &buckets[idx_src];
    futex_bucket_t *b_dst = &buckets[idx_dst];

    /* Lock both buckets in consistent order (lower index first) */
    if (idx_src == idx_dst) {
        pthread_mutex_lock(&b_src->lock);
    } else if (idx_src < idx_dst) {
        pthread_mutex_lock(&b_src->lock);
        pthread_mutex_lock(&b_dst->lock);
    } else {
        pthread_mutex_lock(&b_dst->lock);
        pthread_mutex_lock(&b_src->lock);
    }

    /* CMP_REQUEUE: atomically verify *uaddr == expected */
    if (do_cmp) {
        int64_t block = futex_should_block(g, uaddr, expected);
        if (block != 0) {
            if (idx_src != idx_dst)
                pthread_mutex_unlock(&b_dst->lock);
            pthread_mutex_unlock(&b_src->lock);
            return block;
        }
    }

    /* A PI waiter stays tied to its entry bucket while it retries, and
     * FUTEX_REQUEUE has no PI-aware form here, so reject one before anything
     * moves. Every waiter the call could touch is checked, wake candidates
     * included, matching where requeue.c makes the same decision. The budget is
     * summed in 64 bits: both halves are guest-supplied and wake-all passes
     * INT_MAX.
     */
    uint64_t checked = futex_requeue_budget(wake_count, requeue_count);
    for (futex_waiter_t *w = b_src->head; w && checked != 0; w = w->next) {
        if (w->uaddr != uaddr)
            continue;

        /* pub_follows is false only for a PI waiter today; see where it is set
         * in futex_lock_pi_inner.
         */
        if (!w->pub_follows) {
            if (idx_src != idx_dst)
                pthread_mutex_unlock(&b_dst->lock);
            pthread_mutex_unlock(&b_src->lock);
            return -LINUX_EINVAL;
        }
        checked--;
    }

    int woken = 0, requeued = 0;

    /* Walk source bucket: wake up to wake_count, requeue up to requeue_count */
    futex_waiter_t **pp = &b_src->head;
    while (*pp) {
        futex_waiter_t *w = *pp;
        if (w->uaddr != uaddr) {
            pp = &w->next;
            continue;
        }

        if ((uint32_t) woken < wake_count) {
            /* Wake this waiter: unlink from source, then signal */
            futex_wake_waiter_locked(pp);
            woken++;
            /* Leave pp unchanged because *pp is already the next node */
        } else if ((uint32_t) requeued < requeue_count) {
            if (idx_src == idx_dst) {
                /* Same bucket: only the key changes. Linux's requeue_futex()
                 * takes this path too (hb1 == hb2), rewriting q->key without
                 * moving the entry. Unlinking and relinking here would put w
                 * right back at *pp, so pp would never advance past it.
                 */
                w->uaddr = uaddr2;
                pp = &w->next;
            } else {
                /* Requeue: remove from source, add to destination */
                *pp = w->next;

                /* Credit the destination before debiting the source, so the
                 * shim never sees this waiter charged to no bucket. Both halves
                 * sit under pub_follows: a waiter carrying no charge of its own
                 * must not gain one here, which is how a charge outlived its
                 * waiter.
                 */
                if (w->pub_follows) {
                    shim_globals_futex_waiters_add(g, idx_dst, +1);
                    shim_globals_futex_waiters_add(g, w->pub_bucket, -1);
                    w->pub_bucket = idx_dst;
                }
                w->uaddr = uaddr2;
                w->next = b_dst->head;
                b_dst->head = w;

                /* The owner sleeps under the source lock, and a wake at uaddr2
                 * takes the destination's. Send it to re-park there.
                 */
                atomic_store_explicit(&w->home, idx_dst, memory_order_release);
                pthread_cond_signal(&w->cond);
            }
            requeued++;
        } else {
            break; /* Both limits reached */
        }
    }

    /* Unlock in reverse order */
    if (idx_src == idx_dst) {
        pthread_mutex_unlock(&b_src->lock);
    } else if (idx_src < idx_dst) {
        pthread_mutex_unlock(&b_dst->lock);
        pthread_mutex_unlock(&b_src->lock);
    } else {
        pthread_mutex_unlock(&b_src->lock);
        pthread_mutex_unlock(&b_dst->lock);
    }

    return (int64_t) woken + requeued;
}

/* FUTEX_WAKE_OP: atomically modify *uaddr2, wake val waiters at uaddr, then
 * conditionally wake val2 waiters at uaddr2 based on the old value.
 *
 * The op argument encodes: operation on *uaddr2 and comparison predicate. Used
 * by glibc's pthread_cond_signal; musl does NOT use this, but futex emulation
 * implements it for compatibility with glibc-linked binaries.
 *
 * val3 encodes both the operation and comparison:
 *   bits 28-31: op code (SET=0, ADD=1, OR=2, ANDN=3, XOR=4)
 *   bits 24-27: cmp code (EQ=0, NE=1, LT=2, LE=3, GT=4, GE=5)
 *   bits 12-23: op arg
 *   bits  0-11: cmp arg
 */
static int64_t futex_wake_op(guest_t *g,
                             uint64_t uaddr,
                             uint32_t val,
                             uint64_t uaddr2,
                             uint32_t val2,
                             uint32_t val3)
{
    if (!futex_uaddr_is_aligned(uaddr) || !futex_uaddr_is_aligned(uaddr2))
        return -LINUX_EINVAL;

    /* Decode operation and comparison from val3. Bits 31-28: operation (bit 31
     * = OPARG_SHIFT flag, bits 30-28 = op) Bits 27-24: comparison operator Bits
     * 23-12: op_arg (operand for modify, 12-bit signed) Bits 11-0: cmp_arg
     * (operand for compare, 12-bit signed) Both op_arg and cmp_arg are
     * sign-extended from 12 bits to match the Linux kernel's sign_extend32() in
     * futex_atomic_op_inuser().
     *
     * Decoded before the buckets are locked, so an operand this rejects returns
     * without an unlock path of its own.
     */
    unsigned wake_op = (val3 >> 28) & 0xF;
    unsigned wake_cmp = (val3 >> 24) & 0xF;
    int32_t op_arg = futex_op_sign_extend12(val3 >> 12);
    int32_t cmp_arg = futex_op_sign_extend12(val3);

    /* The modify operand is applied to a uint32_t word, and every op below is
     * modular, so the sign-extended value is carried as its two's complement
     * bits. Only cmp_arg stays signed, because the comparisons are signed.
     */
    uint32_t op_val = (uint32_t) op_arg;

    /* FUTEX_OP_OPARG_SHIFT (bit 3 of wake_op): interpret op_arg as 1<<op_arg.
     * Linux masks an operand outside 0..31 to its low five bits and warns,
     * rather than rejecting it, so an out-of-range operand still names a shift
     * and the call proceeds. The bound is what removes the undefined behavior:
     * a negative operand reaching the shift is the fault, and the mask fixes
     * it. Linux commit 30d6e0a4190d is the same change.
     */
    if (wake_op & 8)
        op_val = 1U << futex_op_shift_arg_mask(op_arg);
    wake_op &= 7; /* Actual operation is bits 0-2 */

    /* An op Linux does not implement stops here, before the modify and before
     * any wake. proved/futexwakeop.h carries both gates.
     */
    if (!futex_wake_op_supported(wake_op))
        return -LINUX_ENOSYS;

    unsigned idx1 = futex_hash(uaddr);
    unsigned idx2 = futex_hash(uaddr2);
    futex_bucket_t *b1 = &buckets[idx1];
    futex_bucket_t *b2 = &buckets[idx2];

    /* Lock ordering */
    if (idx1 == idx2) {
        pthread_mutex_lock(&b1->lock);
    } else if (idx1 < idx2) {
        pthread_mutex_lock(&b1->lock);
        pthread_mutex_lock(&b2->lock);
    } else {
        pthread_mutex_lock(&b2->lock);
        pthread_mutex_lock(&b1->lock);
    }

    /* Atomically modify *uaddr2 */
    uint32_t *word2 = (uint32_t *) guest_ptr_w(g, uaddr2);
    if (!word2) {
        if (idx1 != idx2)
            pthread_mutex_unlock(&b2->lock);
        pthread_mutex_unlock(&b1->lock);
        return -LINUX_EFAULT;
    }

    /* Atomic read-modify-write on *uaddr2 using CAS loop. Matches Linux
     * kernel's futex_atomic_op_inuser() semantics: the modification must be
     * atomic w.r.t. concurrent guest stores.
     */
    uint32_t old_val, new_val;
    bool swapped = false, ok;
    do {
        ok = futex_word_load(word2, &old_val);
        if (!ok)
            break;
        new_val = futex_wake_op_apply(old_val, wake_op, op_val);
        ok = futex_word_cas(word2, &old_val, new_val, &swapped);
    } while (ok && !swapped);

    if (!ok) {
        if (idx1 != idx2)
            pthread_mutex_unlock(&b2->lock);
        pthread_mutex_unlock(&b1->lock);
        return -LINUX_EFAULT;
    }

    /* A comparison Linux does not implement stops here: the modify above has
     * already landed, and neither wake runs.
     */
    if (!futex_wake_cmp_supported(wake_cmp)) {
        if (idx1 != idx2)
            pthread_mutex_unlock(&b2->lock);
        pthread_mutex_unlock(&b1->lock);
        return -LINUX_ENOSYS;
    }

    /* Signed comparison on the word as it was before the modify. Evaluated here
     * because the test below has to know whether the second wake runs at all: a
     * walk the comparison never reaches cannot refuse the call.
     */
    int cond_met = futex_wake_op_cmp((int32_t) old_val, wake_cmp, cmp_arg);

    /* Neither wake reaches a PI waiter. Both walks are tested before either one
     * wakes anybody, so a refused call leaves both chains as it found them. The
     * modify above stays: Linux applies it before its own walks reach the
     * waiter that answers EINVAL.
     */
    if (futex_pi_waiter_within(b1, uaddr, FUTEX_BITSET_MATCH_ANY, val) ||
        (cond_met &&
         futex_pi_waiter_within(b2, uaddr2, FUTEX_BITSET_MATCH_ANY, val2))) {
        if (idx1 != idx2)
            pthread_mutex_unlock(&b2->lock);
        pthread_mutex_unlock(&b1->lock);
        return -LINUX_EINVAL;
    }

    /* Wake up to val waiters at uaddr (unlink woken entries) */
    int woken1 = 0;
    futex_waiter_t **pp1 = &b1->head;
    while (*pp1 && (uint32_t) woken1 < val) {
        futex_waiter_t *w = *pp1;
        if (w->uaddr == uaddr) {
            futex_wake_waiter_locked(pp1);
            woken1++;
        } else {
            pp1 = &w->next;
        }
    }

    /* Conditionally wake up to val2 waiters at uaddr2 (unlink woken) */
    int woken2 = 0;
    if (cond_met) {
        futex_waiter_t **pp2 = &b2->head;
        while (*pp2 && (uint32_t) woken2 < val2) {
            futex_waiter_t *w2 = *pp2;
            if (w2->uaddr == uaddr2) {
                futex_wake_waiter_locked(pp2);
                woken2++;
            } else {
                pp2 = &w2->next;
            }
        }
    }

    /* Unlock reverse order */
    if (idx1 == idx2) {
        pthread_mutex_unlock(&b1->lock);
    } else if (idx1 < idx2) {
        pthread_mutex_unlock(&b2->lock);
        pthread_mutex_unlock(&b1->lock);
    } else {
        pthread_mutex_unlock(&b1->lock);
        pthread_mutex_unlock(&b2->lock);
    }

    return (int64_t) woken1 + woken2;
}

/* PI (Priority-Inheritance) futex.
 *
 * PI futexes use the futex word itself as an atomic lock:
 *   bits 0-29 = owner TID (FUTEX_TID_MASK), bit 30 = FUTEX_OWNER_DIED,
 *   bit 31 = FUTEX_WAITERS
 *
 * Futex emulation does not implement real priority inheritance (boosting the
 * holder's priority to the highest waiter's), but it implements the locking
 * semantics correctly. Some runtimes use PI futexes for internal locks and only
 * need the mutex behavior, not the RT priority boosting. Waiters block on a
 * per-address condition variable (reusing the same bucket hash table as normal
 * futexes).
 */

/* FUTEX_LOCK_PI: Block until the lock at uaddr can be acquired.
 *
 * The PI futex word stores the owner TID in bits 0-29 and a WAITERS flag in bit
 * 31. The kernel emulation sets FUTEX_WAITERS when a thread blocks, so the
 * current owner knows to call FUTEX_UNLOCK_PI instead of releasing the word
 * with the uncontended userspace CAS(TID->0) path.
 *
 * Flow: try CAS(0->TID). If held by another thread, set WAITERS bit via CAS,
 * then block. On wakeup, retry acquisition.
 */
static int64_t futex_lock_pi_inner(guest_t *g,
                                   uint64_t uaddr,
                                   uint64_t timeout_gva)
{
    if (!futex_uaddr_is_aligned(uaddr))
        return -LINUX_EINVAL;

    uint32_t *word = (uint32_t *) guest_ptr_w(g, uaddr);
    if (!word)
        return -LINUX_EFAULT;

    uint32_t tid = current_thread ? (uint32_t) thread_tid(current_thread)
                                  : (uint32_t) proc_get_pid();

    /* Build deadline (if timeout specified, it's absolute CLOCK_REALTIME) */
    bool has_timeout = (timeout_gva != 0);
    struct timespec deadline;
    if (has_timeout) {
        int rc =
            futex_make_deadline(g, timeout_gva, /*is_absolute=*/1, &deadline);
        if (rc == -1)
            return -LINUX_EFAULT;
        if (rc == -2)
            return -LINUX_EINVAL;
    }

    unsigned idx = futex_hash(uaddr);
    futex_bucket_t *b = &buckets[idx];

    for (;;) {
        /* Fast path: try to CAS 0 -> the current TID (uncontended acquisition)
         */
        uint32_t expected = 0;
        bool acquired;
        if (!futex_word_cas(word, &expected, tid, &acquired))
            return -LINUX_EFAULT;
        if (acquired)
            return 0;

        /* Already own it? Deadlock (Linux returns EDEADLK) */
        if (futex_pi_owner_tid(expected) == tid)
            return -LINUX_EDEADLK;

        /* Robust owner death: the robust-list walk sets FUTEX_OWNER_DIED and
         * clears the TID field on thread exit (see robust_list_walk), so the
         * word is nonzero (OWNER_DIED set) with an empty TID -- the CAS(0->TID)
         * fast path above cannot acquire it. Recover by clearing the word and
         * retrying. This must run before the nonzero-TID dead-owner test below,
         * which never sees a robust-cleaned word (TID == 0) and would otherwise
         * spin forever.
         */
        if (futex_pi_owner_died(expected)) {
            if (!futex_word_cas(word, &expected, 0, NULL))
                return -LINUX_EFAULT;
            continue; /* Retry acquisition */
        }

        /* Owner thread has exited without releasing the lock and without robust
         * cleanup (no OWNER_DIED). Linux does not recover such a lock:
         * FUTEX_LOCK_PI returns -ESRCH (attach_to_pi_owner ->
         * handle_exit_race).
         */
        uint32_t owner_tid = futex_pi_owner_tid(expected);
        if (owner_tid != 0 && !thread_find((int64_t) owner_tid))
            return -LINUX_ESRCH;

        /* Set the WAITERS bit so the owner takes the kernel-mediated unlock
         * path. Retry the CAS in a loop since the owner may release
         * concurrently.
         */
        for (;;) {
            uint32_t cur;
            if (!futex_word_load(word, &cur))
                return -LINUX_EFAULT;
            if (futex_pi_unowned(cur))
                break; /* Owner released; retry outer loop */
            if (futex_pi_has_waiters(cur))
                break; /* Already set by another waiter */
            uint32_t desired = futex_pi_set_waiters(cur);
            bool marked;
            if (!futex_word_cas(word, &cur, desired, &marked))
                return -LINUX_EFAULT;
            if (marked)
                break; /* WAITERS bit set */
        }

        /* Re-check after WAITERS bit: if lock is now free, retry */
        uint32_t cur;
        if (!futex_word_load(word, &cur))
            return -LINUX_EFAULT;
        if (futex_pi_unowned(cur))
            continue;

        /* Enqueue and block */
        pthread_mutex_lock(&b->lock);

        /* Double-check under bucket lock: owner may have released and called
         * UNLOCK_PI between the current WAITERS set and lock.
         */
        if (!futex_word_load(word, &cur)) {
            pthread_mutex_unlock(&b->lock);
            return -LINUX_EFAULT;
        }
        if (futex_pi_unowned(cur)) {
            pthread_mutex_unlock(&b->lock);
            continue;
        }

        /* pub_bucket names the bucket futex_lock_pi charged on entry. Leaving
         * it at the implicit zero would make futex_requeue debit bucket 0,
         * which carries no charge for this waiter, so that count underflows and
         * a later waiter's increment can bring it back to zero while it is
         * parked. Every exit below unlinks from b, so idx is also the bucket
         * the wrapper drops.
         */
        futex_waiter_t waiter = {
            .uaddr = uaddr,
            .bitset = FUTEX_BITSET_MATCH_ANY,
            .woken = 0,
            .next = b->head,
            .pub_bucket = idx,

            /* Deliberately false: this function's wrapper drops idx.
             *
             * futex_requeue reads this same bit as "is a PI waiter" when it
             * decides whether to reject a migration, which is sound only
             * because this is the one place that sets it false. A future waiter
             * that cannot follow pub_bucket for some unrelated reason would be
             * rejected there as if it were PI, so give that one its own bit
             * rather than widening this one.
             */
            .pub_follows = false,
        };
        pthread_cond_init(&waiter.cond, NULL);
        b->head = &waiter;

        bool owner_died = false;
        while (!atomic_load_explicit(&waiter.woken, memory_order_acquire)) {
            if (has_timeout) {
                /* Bounded quanta for the same teardown-reachability reason as
                 * futex_wait: never sleep to a distant guest deadline.
                 */
                struct timespec quantum = {0};
                bool expired = !futex_quantum_deadline(&deadline, &quantum);
                if (!expired) {
                    pthread_cond_timedwait(&waiter.cond, &b->lock, &quantum);
                    if (!atomic_load_explicit(&waiter.woken,
                                              memory_order_acquire) &&
                        thread_stop_requested()) {
                        /* Mirror the no-timeout exit_group path below. */
                        bucket_unlink_locked(b, &waiter);
                        pthread_mutex_unlock(&b->lock);
                        pthread_cond_destroy(&waiter.cond);
                        return -LINUX_EINTR;
                    }

                    /* Mirror futex_wait's untimed branch: without this, a
                     * thread parked here with a timeout only observes an
                     * expired guest itimer or a deliverable queued signal once
                     * the lock is acquired or the full guest deadline elapses.
                     */
                    bool sig_ready = futex_poll_signal_relock(b);

                    if (!atomic_load_explicit(&waiter.woken,
                                              memory_order_acquire) &&
                        sig_ready) {
                        bucket_unlink_locked(b, &waiter);
                        pthread_mutex_unlock(&b->lock);
                        pthread_cond_destroy(&waiter.cond);
                        return -LINUX_EINTR;
                    }
                } else if (!atomic_load_explicit(&waiter.woken,
                                                 memory_order_acquire)) {
                    /* Timeout: dequeue and return */
                    bucket_unlink_locked(b, &waiter);
                    /* Only clear WAITERS bit if no waiters for this address */
                    bool has_waiters = false;
                    for (futex_waiter_t *w = b->head; w; w = w->next) {
                        if (w->uaddr == uaddr) {
                            has_waiters = true;
                            break;
                        }
                    }
                    pthread_mutex_unlock(&b->lock);
                    pthread_cond_destroy(&waiter.cond);
                    if (!has_waiters)
                        futex_clear_waiters_bit(word);
                    return -LINUX_ETIMEDOUT;
                }
            } else {
                /* No timeout: poll every 100ms to check exit_group and dead
                 * lock owners.
                 */
                struct timespec poll_ts;
                timespec_deadline_in_ms(&poll_ts, 100);
                pthread_cond_timedwait(&waiter.cond, &b->lock, &poll_ts);

                if (thread_stop_requested()) {
                    /* Dequeue and return */
                    bucket_unlink_locked(b, &waiter);
                    pthread_mutex_unlock(&b->lock);
                    pthread_cond_destroy(&waiter.cond);
                    return -LINUX_EINTR;
                }

                /* Mirror futex_wait's untimed branch: without this, a thread
                 * parked in FUTEX_LOCK_PI with no timeout never observes an
                 * expired guest itimer or a deliverable queued signal until the
                 * lock is acquired or the owner dies.
                 */
                bool sig_ready = futex_poll_signal_relock(b);

                if (!atomic_load_explicit(&waiter.woken,
                                          memory_order_acquire) &&
                    sig_ready) {
                    bucket_unlink_locked(b, &waiter);
                    pthread_mutex_unlock(&b->lock);
                    pthread_cond_destroy(&waiter.cond);
                    return -LINUX_EINTR;
                }

                /* Check if the owner thread has died while the waiter was
                 * waiting. Use thread_tid_alive (lock-free) instead of
                 * thread_find to avoid lock order inversion: bucket lock(7) is
                 * held here, and thread_find acquires thread_lock(5).
                 *
                 * As in the fast path, Linux only recovers a PI lock whose
                 * owner died if the robust-list walk marked it
                 * FUTEX_OWNER_DIED. A robust death clears the TID field, so
                 * test OWNER_DIED first (recover via the clear-and-retry path
                 * below); a non-robust dead owner keeps its TID but has no
                 * OWNER_DIED, and Linux yields -ESRCH.
                 */
                uint32_t check;
                if (!futex_word_load(word, &check)) {
                    bucket_unlink_locked(b, &waiter);
                    pthread_mutex_unlock(&b->lock);
                    pthread_cond_destroy(&waiter.cond);
                    return -LINUX_EFAULT;
                }
                if (futex_pi_owner_died(check)) {
                    owner_died = true;
                    break;
                }
                uint32_t check_tid = futex_pi_owner_tid(check);
                if (check_tid != 0 && !thread_tid_alive((int64_t) check_tid)) {
                    bucket_unlink_locked(b, &waiter);
                    pthread_mutex_unlock(&b->lock);
                    pthread_cond_destroy(&waiter.cond);
                    return -LINUX_ESRCH;
                }
            }
        }

        /* Dequeue waiter from bucket list */
        bucket_unlink_locked(b, &waiter);
        pthread_mutex_unlock(&b->lock);
        pthread_cond_destroy(&waiter.cond);

        if (owner_died) {
            /* Clear the dead owner's lock word and retry acquisition */
            uint32_t v;
            if (!futex_word_load(word, &v) ||
                !futex_word_cas(word, &v, 0, NULL))
                return -LINUX_EFAULT;
            continue;
        }

        /* Woken: retry acquisition. The outer loop re-reads the lock word and
         * retries CAS(0->TID). If FUTEX_WAITERS (bit 31) is still set by other
         * waiters, CAS(0->TID) will fail since the word is non-zero; the loop
         * will then see the WAITERS bit and handle it appropriately.
         */
    }
}

/* FUTEX_TRYLOCK_PI: Non-blocking version of LOCK_PI. CAS 0 -> TID; if the lock
 * is held, return -EAGAIN immediately. Same publish-around-the-wait shape as
 * futex_wait. A PI waiter parks on the ordinary bucket queue, and futex_wake
 * walks that queue without distinguishing it, so a PI waiter is reachable by a
 * plain FUTEX_WAKE and has to be visible to the shim's wake fast path like any
 * other. The wrapper also spares the fourteen returns inside from carrying the
 * drop.
 */
static int64_t futex_lock_pi(guest_t *g, uint64_t uaddr, uint64_t timeout_gva)
{
    unsigned idx = futex_hash(uaddr);

    shim_globals_futex_waiters_add(g, idx, +1);
    int64_t rc = futex_lock_pi_inner(g, uaddr, timeout_gva);
    shim_globals_futex_waiters_add(g, idx, -1);
    return rc;
}

static int64_t futex_trylock_pi(guest_t *g, uint64_t uaddr)
{
    if (!futex_uaddr_is_aligned(uaddr))
        return -LINUX_EINVAL;

    uint32_t *word = (uint32_t *) guest_ptr_w(g, uaddr);
    if (!word)
        return -LINUX_EFAULT;

    uint32_t tid = current_thread ? (uint32_t) thread_tid(current_thread)
                                  : (uint32_t) proc_get_pid();

    uint32_t expected = 0;
    bool acquired;
    if (!futex_word_cas(word, &expected, tid, &acquired))
        return -LINUX_EFAULT;
    if (acquired)
        return 0;

    return -LINUX_EAGAIN; /* Lock held, cannot acquire */
}

/* FUTEX_UNLOCK_PI: Release the PI lock at uaddr and wake one waiter.
 *
 * Called by the lock owner when FUTEX_WAITERS is set (slow unlock path).
 * Atomically clear the word to 0 (releasing the lock + clearing WAITERS), then
 * wake one blocked waiter so it can retry CAS(0->TID) acquisition.
 */
static int64_t futex_unlock_pi(guest_t *g, uint64_t uaddr)
{
    uint32_t tid = current_thread ? (uint32_t) thread_tid(current_thread)
                                  : (uint32_t) proc_get_pid();

    /* Linux futex_unlock_pi() reads the word and rejects a non-owner with
     * -EPERM *before* it validates alignment (get_user + owner check run ahead
     * of get_futex_key, whose -EINVAL is never reached), so releasing a lock
     * you do not own returns -EPERM even for an unaligned uaddr. Match that
     * ordering. The word may be unaligned here, so read it with
     * guest_read_small (boundary-safe, and avoids the aligned-atomic-load fault
     * an unaligned atomic load would take on the arm64 host).
     */
    uint32_t cur;
    if (guest_read_small(g, uaddr, &cur, sizeof(cur)) != 0)
        return -LINUX_EFAULT;
    if (futex_pi_owner_tid(cur) != tid)
        return -LINUX_EPERM;

    /* Only the owner reaches here, and an owned PI lock is always aligned
     * (LOCK_PI/TRYLOCK_PI reject an unaligned uaddr up front). Validate before
     * the atomic release path below, which requires a 4-byte-aligned word.
     */
    if (!futex_uaddr_is_aligned(uaddr))
        return -LINUX_EINVAL;

    uint32_t *word = (uint32_t *) guest_ptr_w(g, uaddr);
    if (!word)
        return -LINUX_EFAULT;

    /* Atomically release: set word to 0 (clear TID + WAITERS flag). Use CAS
     * loop in case another thread is concurrently setting WAITERS.
     */
    for (;;) {
        uint32_t v;
        bool released;
        if (!futex_word_load(word, &v) ||
            !futex_word_cas(word, &v, 0, &released))
            return -LINUX_EFAULT;
        if (released)
            break;
    }

    /* Wake one waiter so it can retry acquisition */
    unsigned idx = futex_hash(uaddr);
    futex_bucket_t *b = &buckets[idx];

    pthread_mutex_lock(&b->lock);
    futex_waiter_t **pp = &b->head;
    while (*pp) {
        futex_waiter_t *w = *pp;
        if (w->uaddr == uaddr) {
            futex_wake_waiter_locked(pp);
            break; /* Wake exactly one */
        }
        pp = &w->next;
    }
    pthread_mutex_unlock(&b->lock);

    return 0;
}

/* Syscall entry point. */

int64_t sys_futex(guest_t *g,
                  uint64_t uaddr,
                  int op,
                  uint32_t val,
                  uint64_t timeout_gva,
                  uint64_t uaddr2,
                  uint32_t val3)
{
    int cmd = op & FUTEX_CMD_MASK;

    switch (cmd) {
    case FUTEX_WAIT:
        /* On the bucket, like FUTEX_WAIT_BITSET. Darwin's
         * os_sync_wait_on_address would park it with no bucket lock, but the
         * only way to reach a thread parked there is to wake its address, which
         * it cannot tell from a FUTEX_WAKE. Ending the wait for a queued signal
         * that way reports EINTR for a wake that counted the waiter, or 0 for a
         * signal it could not claim. waiter.woken is what tells them apart.
         */
        return futex_wait(g, uaddr, val, timeout_gva, FUTEX_BITSET_MATCH_ANY,
                          /*is_absolute=*/0);

    case FUTEX_WAKE:
        return futex_wake(g, uaddr, val, FUTEX_BITSET_MATCH_ANY);

    case FUTEX_REQUEUE:
        /* For REQUEUE, the timeout arg is repurposed as val2 (requeue count) */
        return futex_requeue(g, uaddr, val, (uint32_t) timeout_gva, uaddr2,
                             /*do_cmp=*/0, 0);

    case FUTEX_CMP_REQUEUE:
        /* Same repurposing of timeout -> val2, plus compare against val3 */
        return futex_requeue(g, uaddr, val, (uint32_t) timeout_gva, uaddr2,
                             /*do_cmp=*/1, val3);

    case FUTEX_WAKE_OP:
        /* timeout arg repurposed as val2 (wake count for uaddr2) */
        return futex_wake_op(g, uaddr, val, uaddr2, (uint32_t) timeout_gva,
                             val3);

    case FUTEX_WAIT_BITSET:
        return futex_wait(g, uaddr, val, timeout_gva, val3, /*is_absolute=*/1);

    case FUTEX_WAKE_BITSET:
        return futex_wake(g, uaddr, val, val3);

    case FUTEX_LOCK_PI:
        return futex_lock_pi(g, uaddr, timeout_gva);

    case FUTEX_UNLOCK_PI:
        return futex_unlock_pi(g, uaddr);

    case FUTEX_TRYLOCK_PI:
        return futex_trylock_pi(g, uaddr);

    default:
        /* Unimplemented futex operation (robust futexes, PI requeue).
         * Return ENOSYS so musl knows to fall back.
         */
        return -LINUX_ENOSYS;
    }
}

int futex_wake_one(guest_t *g, uint64_t uaddr)
{
    return (int) futex_wake(g, uaddr, 1, FUTEX_BITSET_MATCH_ANY);
}

/* Unlink a waiter from whichever bucket it currently sits in, with retry on
 * concurrent requeue. The waiter's struct lives on the calling thread's stack;
 * leaving a dangling reference behind is a real host-safety bug because a later
 * wake at the new uaddr would dereference it. The regular futex_wait
 * self-dequeue path handles the same race the same way.
 *
 * Termination: on each iteration we either find w in the bucket (unlink and
 * return), or observe w->woken==1 under the bucket lock (the wake path unlinks
 * before storing woken with RELEASE under the bucket lock; once we acquire that
 * bucket lock we synchronize with it), or determine w was requeued elsewhere
 * (re-hash and retry). Forward progress is guaranteed because every requeue and
 * every wake also holds bucket locks, so once we take the lock for the bucket
 * that hashes w's current uaddr, no concurrent mover can step around us.
 */
static void waitv_unlink(futex_waiter_t *w)
{
    if (atomic_load_explicit(&w->woken, memory_order_acquire))
        return;
    for (;;) {
        unsigned idx = futex_hash(w->uaddr);
        futex_bucket_t *b = &buckets[idx];
        pthread_mutex_lock(&b->lock);
        bool found = false;
        for (futex_waiter_t **pp = &b->head; *pp; pp = &(*pp)->next) {
            if (*pp == w) {
                *pp = w->next;
                found = true;
                break;
            }
        }
        bool was_woken = atomic_load_explicit(&w->woken, memory_order_acquire);
        pthread_mutex_unlock(&b->lock);
        if (found || was_woken)
            return;

        /* w must have been requeued to another bucket while we hashed. Re-read
         * uaddr and try again.
         */
    }
}

/* futex_waitv (SYS 449): batch futex wait on multiple addresses.
 *
 * Blocks until any one of the specified futexes is woken, or a timeout expires.
 * Returns the 0-based index of the woken futex, or negative errno.
 *
 * Linux struct futex_waitv layout (24 bytes per element):
 *   uint64_t val, uaddr, uint32_t flags, __reserved
 */
#define FUTEX_WAITV_MAX 128 /* Linux limit */

#define FUTEX2_SIZE_U32 0x02
#define FUTEX2_SIZE_MASK 0x03
#define FUTEX2_PRIVATE 0x80
#define FUTEX2_VALID_FLAGS (FUTEX2_SIZE_MASK | FUTEX2_PRIVATE)

typedef struct {
    uint64_t val, uaddr;
    uint32_t flags, __reserved;
} linux_futex_waitv_t;

_Static_assert(sizeof(linux_futex_waitv_t) == 24,
               "futex_waitv element must be 24 bytes");

/* Shared wakeup state for futex_waitv. Each enqueued waiter holds pointers to
 * this struct so any wake site (futex_wake, futex_requeue, futex_wake_op,
 * futex_unlock_pi) signals shared.cond after marking the waiter woken. The
 * polling loop sleeps on shared.cond with a bounded timeout so it still picks
 * up exit_group requests and real timeouts even when no signal arrives.
 */
typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;
} waitv_shared_t;

/* Linux clockid values accepted by futex_waitv. */
#define LINUX_CLOCK_REALTIME 0
#define LINUX_CLOCK_MONOTONIC 1

/* The distinct buckets the wait set covers, ascending. The locks below are
 * taken in this order and released in reverse, so both properties of the answer
 * are load-bearing: proved/futexwaitv.h carries them.
 *
 * nr_futexes is bounded by FUTEX_WAITV_MAX before the call, which is what keeps
 * nbuckets below the array length at every insert.
 */
static int waitv_collect_buckets(const linux_futex_waitv_t *elts,
                                 uint32_t nr_futexes,
                                 unsigned bucket_ids[FUTEX_WAITV_MAX])
{
    unsigned nbuckets = 0;

    for (uint32_t i = 0; i < nr_futexes; i++)
        nbuckets = futex_bucket_insert(bucket_ids, nbuckets, FUTEX_WAITV_MAX,
                                       futex_hash(elts[i].uaddr));

    return (int) nbuckets;
}

int64_t sys_futex_waitv(guest_t *g,
                        uint64_t waiters_gva,
                        uint32_t nr_futexes,
                        uint32_t flags,
                        uint64_t timeout_gva,
                        int clockid)
{
    /* Validation order matches Linux do_futex_waitv():
     *   1. flags
     *   2. nr_futexes / !waiters
     *   3. clockid (when timeout != NULL)
     *   4. copy_from_user(timeout) -> EFAULT
     *   5. timespec64_valid(timeout) -> EINVAL
     *   6. copy_from_user(waiters) -> EFAULT
     *   7. per-element validate -> EINVAL
     * Reordering steps 4-7 to match Linux means a guest that passes a bad
     * timeout AND bad waiters sees the same errno Linux would, instead of
     * having ours fault on waiters first.
     */
    if (flags != 0)
        return -LINUX_EINVAL;
    if (nr_futexes == 0 || nr_futexes > FUTEX_WAITV_MAX || waiters_gva == 0)
        return -LINUX_EINVAL;

    bool has_timeout = (timeout_gva != 0);
    if (has_timeout && clockid != LINUX_CLOCK_REALTIME &&
        clockid != LINUX_CLOCK_MONOTONIC)
        return -LINUX_EINVAL;

    /* Copy and validate the timeout before reading the waiters array. */
    struct timespec deadline;
    if (has_timeout) {
        linux_timespec_t lts;
        if (guest_read_small(g, timeout_gva, &lts, sizeof(lts)) < 0)
            return -LINUX_EFAULT;
        if (!linux_timespec_is_valid(&lts))
            return -LINUX_EINVAL;

        if (clockid == LINUX_CLOCK_MONOTONIC) {
            /* Translate the monotonic absolute deadline to a CLOCK_REALTIME
             * absolute deadline so pthread_cond_timedwait (which uses
             * CLOCK_REALTIME) waits the right amount. macOS has no
             * CLOCK_MONOTONIC condattr, so this conversion is unavoidable;
             * minor wall-clock skew is accepted. lts.tv_sec is bounded by
             * FUTEX_TIMESPEC_SEC_MAX (linux_timespec_is_valid), so the
             * subtraction and addition stay inside int64_t / time_t range.
             */
            struct timeval now;
            gettimeofday(&now, NULL);
            struct timespec mono;
            clock_gettime(CLOCK_MONOTONIC, &mono);
            int64_t delta_sec = lts.tv_sec - mono.tv_sec;
            long delta_nsec = (long) lts.tv_nsec - mono.tv_nsec;
            deadline.tv_sec = now.tv_sec + delta_sec;
            deadline.tv_nsec = (long) now.tv_usec * 1000 + delta_nsec;
        } else {
            deadline.tv_sec = (time_t) lts.tv_sec;
            deadline.tv_nsec = (long) lts.tv_nsec;
        }
        timespec_normalize(&deadline);
    }

    linux_futex_waitv_t elts[FUTEX_WAITV_MAX];
    size_t sz = nr_futexes * sizeof(linux_futex_waitv_t);
    if (guest_read_small(g, waiters_gva, elts, sz) < 0)
        return -LINUX_EFAULT;

    for (uint32_t i = 0; i < nr_futexes; i++) {
        if (elts[i].__reserved != 0)
            return -LINUX_EINVAL;
        if (elts[i].flags & ~FUTEX2_VALID_FLAGS)
            return -LINUX_EINVAL;
        if ((elts[i].flags & FUTEX2_SIZE_MASK) != FUTEX2_SIZE_U32)
            return -LINUX_EINVAL;

        /* uaddr must be naturally aligned for the declared size. For
         * FUTEX2_SIZE_U32 that is 4-byte alignment; an unaligned futex word
         * loses atomicity on aarch64 and matches no kernel-side behavior.
         */
        if (!futex_uaddr_is_aligned(elts[i].uaddr))
            return -LINUX_EINVAL;
    }

    waitv_shared_t shared;
    pthread_mutex_init(&shared.lock, NULL);
    pthread_cond_init(&shared.cond, NULL);

    /* Validate and enqueue while holding every distinct bucket lock in index
     * order so the whole wait set is checked atomically.
     */
    futex_waiter_t waiters[FUTEX_WAITV_MAX];
    unsigned bucket_ids[FUTEX_WAITV_MAX];
    int nbuckets = waitv_collect_buckets(elts, nr_futexes, bucket_ids);
    int enqueued = 0;
    int64_t result_err = 0;

    /* Publish before the word checks below, not at the enqueue that follows
     * them. The shim's wake fast path reads these counts without taking any
     * bucket lock, so holding the locks across check and enqueue does not order
     * it: a wake landing between the check and the enqueue would read zero and
     * answer 0 while this call was still on its way to parking. Publishing
     * first is what shim_globals_futex_waiters_add requires.
     *
     * One charge per element rather than per distinct bucket, so a requeue that
     * moves one of these waiters can transfer its charge the same way it does
     * for an ordinary waiter. entry_bucket keeps the original for the elements
     * that never reached the enqueue.
     */
    unsigned entry_bucket[FUTEX_WAITV_MAX];
    for (uint32_t i = 0; i < nr_futexes; i++) {
        entry_bucket[i] = futex_hash(elts[i].uaddr);
        shim_globals_futex_waiters_add(g, entry_bucket[i], +1);
    }

    for (int i = 0; i < nbuckets; i++)
        pthread_mutex_lock(&buckets[bucket_ids[i]].lock);

    for (uint32_t i = 0; i < nr_futexes; i++) {
        uint64_t uaddr = elts[i].uaddr;
        uint32_t expected = (uint32_t) elts[i].val;
        unsigned idx = entry_bucket[i];
        futex_bucket_t *b = &buckets[idx];

        int64_t block = futex_should_block(g, uaddr, expected);
        if (block != 0) {
            result_err = block;
            goto unlock_early;
        }

        futex_waiter_t *w = &waiters[i];
        w->uaddr = uaddr;
        w->bitset = FUTEX_BITSET_MATCH_ANY;
        atomic_store_explicit(&w->woken, 0, memory_order_relaxed);
        w->next = b->head;
        w->group_lock = &shared.lock;
        w->group_cond = &shared.cond;
        w->pub_bucket = idx;
        w->pub_follows = true;
        pthread_cond_init(&w->cond, NULL);
        b->head = w;
        enqueued++;
    }

    for (int i = nbuckets - 1; i >= 0; i--)
        pthread_mutex_unlock(&buckets[bucket_ids[i]].lock);

    /* All enqueued. Block on shared.cond until any wake site signals it. The
     * bounded sleep (capped at 100 ms or the user deadline, whichever is
     * sooner) gives proc_exit_group_requested() and timeout checks a chance to
     * run if the cond_signal never arrives. The cap matches the other futex
     * wait paths so every futex-parked worker re-checks teardown flags well
     * inside thread_join_workers' poll cap.
     */
    int result_idx = -1;
    pthread_mutex_lock(&shared.lock);
    for (;;) {
        for (uint32_t i = 0; i < nr_futexes; i++) {
            if (atomic_load_explicit(&waiters[i].woken, memory_order_acquire)) {
                result_idx = (int) i;
                break;
            }
        }
        if (result_idx >= 0)
            break;

        if (thread_stop_requested()) {
            result_idx = -LINUX_EINTR;
            break;
        }

        struct timespec wait_ts;
        timespec_deadline_in_ms(&wait_ts, 100);
        if (has_timeout) {
            if (deadline.tv_sec < wait_ts.tv_sec ||
                (deadline.tv_sec == wait_ts.tv_sec &&
                 deadline.tv_nsec < wait_ts.tv_nsec)) {
                wait_ts = deadline;
            }
        }

        pthread_cond_timedwait(&shared.cond, &shared.lock, &wait_ts);

        if (has_timeout) {
            struct timeval now;
            gettimeofday(&now, NULL);
            long now_ns = (long) now.tv_usec * 1000;
            bool past_deadline =
                now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec && now_ns >= deadline.tv_nsec);
            if (past_deadline) {
                /* Re-check woken under shared.lock before declaring a timeout:
                 * a wake that arrived during the cond_timedwait may not have
                 * been signalled yet on this thread but the woken flag is set.
                 */
                for (uint32_t i = 0; i < nr_futexes; i++) {
                    if (atomic_load_explicit(&waiters[i].woken,
                                             memory_order_acquire)) {
                        result_idx = (int) i;
                        break;
                    }
                }
                if (result_idx < 0)
                    result_idx = -LINUX_ETIMEDOUT;
                break;
            }
        }
    }
    pthread_mutex_unlock(&shared.lock);

    /* Unlink all waiters (woken entries are already removed by the wake path,
     * but a second pass is harmless and avoids stale pointers).
     */
    for (uint32_t i = 0; i < nr_futexes; i++)
        waitv_unlink(&waiters[i]);

    for (uint32_t i = 0; i < nr_futexes; i++)
        pthread_cond_destroy(&waiters[i].cond);
    pthread_mutex_destroy(&shared.lock);
    pthread_cond_destroy(&shared.cond);

    for (uint32_t i = 0; i < nr_futexes; i++)
        shim_globals_futex_waiters_add(g, waiters[i].pub_bucket, -1);

    return result_idx;

unlock_early:
    for (int i = nbuckets - 1; i >= 0; i--)
        pthread_mutex_unlock(&buckets[bucket_ids[i]].lock);

    for (int i = enqueued - 1; i >= 0; i--) {
        waitv_unlink(&waiters[i]);
        pthread_cond_destroy(&waiters[i].cond);
    }
    pthread_mutex_destroy(&shared.lock);
    pthread_cond_destroy(&shared.cond);

    for (uint32_t i = 0; i < nr_futexes; i++)
        shim_globals_futex_waiters_add(
            g, (int) i < enqueued ? waiters[i].pub_bucket : entry_bucket[i],
            -1);

    return result_err;
}

/* Robust futex list walk. */

/* Linux robust_list_head layout:
 *   struct robust_list_head {
 *       struct robust_list *list;       offset 0: pointer to first entry
 *       long futex_offset;              offset 8: offset from entry to futex
 *       word struct robust_list *list_op_pending; offset 16: in-progress lock
 *   };
 *
 * Each entry in the list:
 *   struct robust_list {
 *       struct robust_list *next;       pointer to next (or back to head)
 *   };
 *
 * The futex word is at (entry_addr + futex_offset). The list is circular:
 * list->next... eventually points back to &head->list.
 */

#define ROBUST_LIST_LIMIT 2048 /* safety bound against corrupted lists */

void robust_list_walk(guest_t *g, thread_entry_t *t)
{
    uint64_t head_gva = t->robust_list_head;
    if (head_gva == 0)
        return;

    /* Read robust_list_head: { list, futex_offset, list_op_pending } */
    uint64_t head[3];
    if (guest_read_small(g, head_gva, head, sizeof(head)) < 0)
        return;

    uint64_t list_ptr = head[0]; /* pointer to first robust_list entry */
    int64_t futex_offset = (int64_t) head[1];
    uint64_t pending = head[2]; /* list_op_pending */

    /* The head of the list is at &head->list (which is head_gva itself). Walk
     * entries until the walk loops back to the head pointer.
     */
    uint64_t head_entry = head_gva; /* address of head->list field */
    int count = 0;

    while (list_ptr != head_entry && count < ROBUST_LIST_LIMIT) {
        /* The futex word is at list_ptr + futex_offset. Use unsigned add to
         * avoid signed overflow UB; skip entries where the result wraps past
         * the guest address space.
         */
        uint64_t futex_gva;
        if (futex_offset >= 0)
            futex_gva = list_ptr + (uint64_t) futex_offset;
        else
            futex_gva = list_ptr - (uint64_t) (-futex_offset);

        /* Canonical user-VA range check (bits 47:0). Anything with bit 63 set
         * is kernel-VA territory and is never a valid futex address. The
         * previous primary-buffer-only check (futex_gva < ipa_base +
         * guest_size) silently dropped rosetta's high-VA futexes; the
         * subsequent guest_read_small / guest_write_small calls do the actual
         * mapping check via the page-table walker.
         */
        if (futex_gva > 0x0000FFFFFFFFFFFFULL ||
            !futex_uaddr_is_aligned(futex_gva)) {
            /* Out of range or unaligned: skip. Linux's unaligned_p() rejects
             * these; emulating the same avoids partial cross-page writes
             * leaving the futex word corrupted while the wake is suppressed.
             */
            uint64_t next;
            if (guest_read_small(g, list_ptr, &next, sizeof(next)) < 0)
                break;
            list_ptr = next;
            count++;
            continue;
        }

        /* Read the futex word */
        uint32_t futex_val;
        if (guest_read_small(g, futex_gva, &futex_val, sizeof(futex_val)) ==
            0) {
            /* Only act if this thread owns the lock */
            uint32_t owner = futex_pi_owner_tid(futex_val);
            if (owner == (uint32_t) thread_tid(t)) {
                /* Set FUTEX_OWNER_DIED and clear TID */
                uint32_t new_val = futex_pi_mark_owner_died(futex_val);
                if (guest_write_small(g, futex_gva, &new_val, sizeof(new_val)) <
                    0)
                    log_debug(
                        "futex: robust list OWNER_DIED write to 0x%llx "
                        "failed; waiters on this lock may hang",
                        (unsigned long long) futex_gva);
                else
                    futex_wake(g, futex_gva, 1, FUTEX_BITSET_MATCH_ANY);
            }
        }

        /* Read next pointer */
        uint64_t next;
        if (guest_read_small(g, list_ptr, &next, sizeof(next)) < 0)
            break;
        list_ptr = next;
        count++;
    }

    /* Handle pending operation (lock that was being acquired when the thread
     * died)
     */
    if (pending && pending != head_entry) {
        uint64_t futex_gva;
        if (futex_offset >= 0)
            futex_gva = pending + (uint64_t) futex_offset;
        else
            futex_gva = pending - (uint64_t) (-futex_offset);

        /* Canonical user-VA + alignment only; guest_read_small below is the
         * actual reachability test, so rosetta high-VA robust futexes are not
         * silently skipped (was: futex_gva >= ipa_base + guest_size).
         */
        if (futex_gva > 0x0000FFFFFFFFFFFFULL ||
            !futex_uaddr_is_aligned(futex_gva))
            return;
        uint32_t futex_val;
        if (guest_read_small(g, futex_gva, &futex_val, sizeof(futex_val)) ==
            0) {
            uint32_t owner = futex_pi_owner_tid(futex_val);
            if (owner == (uint32_t) thread_tid(t)) {
                uint32_t new_val = futex_pi_mark_owner_died(futex_val);
                if (guest_write_small(g, futex_gva, &new_val, sizeof(new_val)) <
                    0)
                    log_debug(
                        "futex: robust list pending OWNER_DIED write to "
                        "0x%llx failed; waiters on this lock may hang",
                        (unsigned long long) futex_gva);
                else
                    futex_wake(g, futex_gva, 1, FUTEX_BITSET_MATCH_ANY);
            }
        }
    }
}
