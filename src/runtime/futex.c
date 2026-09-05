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

/* macOS 14.4+ ships os_sync_{wait_on_address_with_timeout,wake_by_address_any}
 * with futex-style compare-and-wait semantics on process-private addresses.
 * elfuse routes plain FUTEX_WAIT / FUTEX_WAKE through this path. Darwin folds
 * the Linux -EAGAIN pre-block race into a successful wait; futex_os_sync_wait
 * closes that common gap with a compare-after-block re-check (word moved off
 * the expected value on a rc>=0 return maps to -EAGAIN). FUTEX_WAIT_BITSET, PI
 * variants, and futex_waitv stay on the bucket path: they need state the kernel
 * API does not expose.
 *
 * SDK gate: probe the header via __has_include so older SDKs build clean.
 * Runtime gate: __builtin_available cached in futex_init().
 */
#if __has_include(<os/os_sync_wait_on_address.h>)
#include <os/os_sync_wait_on_address.h>
#define ELFUSE_HAVE_OS_SYNC_WAIT_ON_ADDRESS 1
#else
#define ELFUSE_HAVE_OS_SYNC_WAIT_ON_ADDRESS 0
#endif

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

/* Address-wait helper state.
 *
 * os_sync_available is set in futex_init() when the runtime supports the
 * os_sync_wait_on_address family (macOS 14.4+). os_sync_wait_enabled gates
 * whether plain FUTEX_WAIT / FUTEX_WAKE use the address-wait path; it is set
 * alongside os_sync_available now that futex_os_sync_wait's compare-after-block
 * re-check preserves Linux's -EAGAIN race semantics.
 *
 * The wait quantum is capped at 100 ms so proc_exit_group_requested() and
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
#if ELFUSE_HAVE_OS_SYNC_WAIT_ON_ADDRESS
static bool os_sync_available;
static bool os_sync_wait_enabled;
#endif

#define FUTEX_OS_SYNC_POLL_CAP_NS (100ULL * 1000 * 1000)

/* Hash table.
 *
 * Sized for wakers, not waiters. At most MAX_THREADS (64) threads can be queued
 * at once, so 64 buckets would already keep the chains short; what makes the
 * table too narrow is that futex_wake takes the bucket lock even when the
 * waiter it is looking for lives on the Darwin address-wait queue rather than
 * in the chain. Two threads waking unrelated futexes therefore serialize
 * whenever their addresses collide, which at 64 buckets is often enough to cost
 * more than the wake itself: eight threads each waking their own private futex
 * measured 801 ns per wake, worse than the same test at four threads.
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
 * is 80 bytes and this host's line is 128, so unpadded neighbours share a line
 * and two futexes the hash correctly separated still contend on it. Measured
 * with eight threads each taking its own adjacent bucket: 16-18 ns per lock
 * unpadded against 5-8 ns padded, a 2-4x share of exactly the contention the
 * 64-to-1024 widening was made to remove. The padding itself costs BSS only,
 * 81920 bytes to 131072 at this bucket count; the table's total is above
 * FUTEX_BUCKETS.
 */
typedef struct {
    pthread_mutex_t lock;
    futex_waiter_t *head; /* Linked list of waiters hashing to this bucket */

    /* Threads inside futex_os_sync_wait for an address hashing here, so a wake
     * can tell an empty Darwin address-wait queue from a populated one without
     * asking the kernel.
     *
     * Every bucket-walking wake tops up from that queue when it woke fewer than
     * asked, and the top-up costs a guest_ptr walk plus an
     * os_sync_wake_by_address_any syscall whether or not anyone is queued
     * (measured: 242 ns per wake). Only plain FUTEX_WAIT enqueues there, so a
     * guest whose waiters are all FUTEX_WAIT_BITSET, PI, or futex_waitv paid
     * for a queue that could not hold a waiter.
     *
     * Per bucket rather than process-wide: one idle worker parked in
     * pthread_cond_wait puts musl on that queue, and a single global count then
     * re-enables the walk and the syscall for every wake on every unrelated
     * address, which is the steady state of any threaded guest.
     *
     * Ordering, and why a wake cannot be lost. The waiter increments before
     * loading the futex word, and both that increment and the waker's read are
     * seq_cst, so a waker reading zero is ordered before the increment and
     * hence before the waiter's load of the word, which therefore sees the
     * waker's store and returns EAGAIN rather than blocking. Waiter and waker
     * reach the same counter because both index it with futex_hash(uaddr). Two
     * addresses colliding in one bucket read as occupied, which costs one
     * pointless syscall, the behavior this replaces.
     *
     * What orders the guest's store to the word against the waker's read is
     * that every call site reaches futex_wake_topup_osync just after a
     * pthread_mutex_unlock, whose release store supplies the edge, and that the
     * guest's own unlock is an STLR on the same hardware thread as the vCPU.
     * Moving the read above that unlock would break it.
     *
     * Not a licence to drop the bucket mutex on an empty wake. This counts the
     * Darwin queue only; FUTEX_WAIT_BITSET, PI and futex_waitv still live in
     * head, and an unlocked pre-check of head is unsound anyway: the waiter is
     * load-then-store (read the word under the lock, then publish) against the
     * waker's store-then-load, which is not the store-buffer shape and so is
     * permitted to miss.
     *
     * Keyed on the guest VA, like the chain beside it, which costs nothing
     * observable here. The reflex worry is a futex reached through two
     * mappings: keyed per VA the wake consults one bucket and misses a waiter
     * parked under the other. It does not arise. GUEST_IPA_BASE is 0, so a GVA
     * is its own GPA and two mappings of one file get two GPAs, hence two host
     * addresses; the Darwin queue keys on the host address, so such a wake
     * could not have reached across the aliases before this change either. The
     * one genuine GVA alias onto a single GPA is the Rosetta kbuf TTBR0/TTBR1
     * pair, which holds no futexes. Every other futex path here is already
     * GVA-keyed (the chain walk compares w->uaddr exactly), so this keeps the
     * file uniform. Linux does match across aliases, keying a shared futex on
     * (inode, offset); that gap is older and wider than this counter.
     */
    _Atomic uint32_t os_sync_waiters;
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

static inline bool futex_uaddr_is_aligned(uint64_t uaddr)
{
    return (uaddr & 0x3) == 0;
}

/* Poll the guest itimer and pending-signal state on behalf of a bucket waiter.
 * Lock order forbids doing that under the bucket lock (bucket is 7, sig_lock is
 * 4), so this drops b->lock and retakes it. The caller must re-check
 * waiter.woken afterward: a wake can land in the window.
 *
 * Returns whether a deliverable signal is queued for this thread.
 */
static bool futex_poll_signal_relock(futex_bucket_t *b)
{
    pthread_mutex_unlock(&b->lock);
    signal_check_timer_real();
    bool sig_ready = signal_pending() != 0;
    pthread_mutex_lock(&b->lock);
    return sig_ready;
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
 * -LINUX_EFAULT when uaddr does not resolve or the load faults. word_out, when
 * non-NULL, receives the resolved host pointer; only futex_os_sync_wait needs
 * it, to hand to the kernel address-wait.
 *
 * Four callers share this: futex_os_sync_wait, futex_wait, futex_requeue's
 * CMP_REQUEUE, and futex_waitv. What differs between them is which bucket locks
 * are held on an error return, so each keeps its own unlock ladder rather than
 * this taking one.
 *
 * futex_wait_fast in core/shim.S is a fifth implementation, in EL1 assembly,
 * answering the -LINUX_EAGAIN case without the HVC round trip. It bails to the
 * host for every input this function would answer differently, so a change to
 * the outcomes or their order here needs the same change there.
 */
static int64_t futex_should_block(const guest_t *g,
                                  uint64_t uaddr,
                                  uint32_t expected,
                                  uint32_t **word_out)
{
    uint32_t *word = (uint32_t *) guest_ptr(g, uaddr);
    if (!word)
        return -LINUX_EFAULT;
    if (word_out)
        *word_out = word;

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

        /* Reset with head, not left to BSS. The shim reads a bucket's published
         * count without a lock and answers a wake with zero when it is zero, so
         * a count that survived a reinit would leave that bucket permanently
         * occupied and its wake fast path silently dead.
         */
        atomic_store_explicit(&buckets[i].os_sync_waiters, 0,
                              memory_order_relaxed);
    }
#if ELFUSE_HAVE_OS_SYNC_WAIT_ON_ADDRESS
    if (__builtin_available(macOS 14.4, *)) {
        os_sync_available = true;

        /* Plain FUTEX_WAIT / FUTEX_WAKE take the Darwin address-wait path.
         * Enable the gate only where the API is actually available so the two
         * flags cannot disagree. The late-EAGAIN gap is bridged by the
         * compare-after-block re-check in futex_os_sync_wait (a rc>=0 return
         * with the word moved off expected maps to -EAGAIN, matching Linux for
         * the pre-block race; the post-wake case is equally safe since a
         * correct caller re-reads the word either way). FUTEX_REQUEUE of such a
         * waiter cannot migrate a kernel os_sync waiter between addresses, so
         * futex_requeue degrades the requeue portion into a wake at the source
         * address; woken callers re-acquire what they need in userspace. glibc
         * condvars are safe because broadcast/signal wake with FUTEX_WAKE, not
         * requeue (2.25+ dropped the requeue optimization); musl's
         * private-condvar barrier->mutex handoff tolerates wake-in-place,
         * matching its own emscripten fallback. Only plain FUTEX_WAIT enqueues
         * on the os_sync queue; FUTEX_WAIT_BITSET, PI waits, and futex_waitv
         * stay on the bucket path. Every wake site drains both queues via
         * futex_wake_topup_osync, so os_sync waiters are reached regardless of
         * which wake op (FUTEX_WAKE, requeue, wake_op) fires.
         */
        os_sync_wait_enabled = true;
    }
#endif
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

#if ELFUSE_HAVE_OS_SYNC_WAIT_ON_ADDRESS

/* Wake up to budget kernel-side waiters at uaddr via
 * os_sync_wake_by_address_any. Loops until the cap is hit or the API stops
 * finding waiters; ENOENT (no more waiters) and any other error break out. _all
 * overshoots the syscall return -- the count must be exact -- so this function
 * intentionally calls _any in a loop instead.
 *
 * budget is uint64_t to accommodate FUTEX_REQUEUE's wake + requeue sum after
 * the bucket walk; the loop counter is clamped to UINT32_MAX, which still
 * preserves the INT_MAX "wake all" sentinel without overflow.
 */
static uint32_t futex_os_sync_wake_n(const guest_t *g,
                                     uint64_t uaddr,
                                     uint64_t budget)
{
    if (!os_sync_available || !os_sync_wait_enabled || budget == 0)
        return 0;

    /* Nobody is on the Darwin queue for this address, so skip the walk and the
     * syscall.
     */
    if (atomic_load_explicit(&buckets[futex_hash(uaddr)].os_sync_waiters,
                             memory_order_seq_cst) == 0)
        return 0;
    void *host_addr = guest_ptr(g, uaddr);
    if (!host_addr)
        return 0;
    if (budget > UINT32_MAX)
        budget = UINT32_MAX;

    uint32_t woken = 0;
    while (woken < (uint32_t) budget) {
        int rc = os_sync_wake_by_address_any(host_addr, 4,
                                             OS_SYNC_WAKE_BY_ADDRESS_NONE);
        if (rc < 0)
            break;
        woken++;
    }
    return woken;
}

/* Plain FUTEX_WAIT routed through os_sync_wait_on_address_with_timeout.
 *
 * The pre-check is required: the kernel API silently returns rc>=0 when the
 * value already differs at entry, indistinguishable from a real wakeup. Linux
 * returns -EAGAIN in that case, so an explicit atomic load bridges the contract
 * gap.
 *
 * Quantum is bounded by FUTEX_OS_SYNC_POLL_CAP_NS so proc_exit_group_requested
 * and futex_interrupt_consume get observed without a global wake-everyone
 * broadcast channel. ETIMEDOUT, EINTR, EFAULT, and ENOMEM are all transient per
 * Apple's docs; each must run the flag check before re-arming. EINVAL would
 * indicate a programmer error here (size != 4/8 or bad flags), so it surfaces
 * directly rather than spinning.
 */
static int64_t futex_os_sync_wait(guest_t *g,
                                  uint64_t uaddr,
                                  uint32_t expected,
                                  uint64_t timeout_gva)
{
    if (!futex_uaddr_is_aligned(uaddr))
        return -LINUX_EINVAL;

    bool has_timeout = (timeout_gva != 0);
    struct timespec deadline;
    if (has_timeout) {
        int rc =
            futex_make_deadline(g, timeout_gva, /*is_absolute=*/0, &deadline);
        if (rc == -1)
            return -LINUX_EFAULT;
        if (rc == -2)
            return -LINUX_EINVAL;
    }

    uint32_t *host_addr;
    int64_t block = futex_should_block(g, uaddr, expected, &host_addr);
    if (block != 0)
        return block;

    /* Bound consecutive EFAULT retries. Apple documents EFAULT as transient
     * (kernel copyin failure under memory pressure), so a few retries are fine;
     * but a genuinely bad page would otherwise cause the loop to spin with no
     * real sleep (timeout_ns is supplied to a syscall that returns immediately)
     * until the user deadline finally bails out. Surface EFAULT to the guest
     * after this many back-to-back failures so the host CPU does not burn for
     * ~1 s.
     */
    int efault_retries = 0;

    /* Once, before the wait, not inside it. The spin exists to catch a waker's
     * store racing the entry to this wait, which is the handoff case. On a
     * re-arm after a 100 ms quantum there is no imminent handoff, and the "word
     * moved between the checks and the syscall" case is already covered
     * atomically by os_sync_wait_on_address_with_timeout, which returns rc >= 0
     * when the value already differs at entry. Inside the loop this burned 4.3
     * us per parked thread per quantum for nothing: 0.28 percent of a core with
     * MAX_THREADS parked.
     */
    if (!has_timeout ||
        futex_remaining_ns(&deadline, FUTEX_OS_SYNC_POLL_CAP_NS, NULL) > 0) {
        if (futex_spin_word_moved(host_addr, expected))
            return -LINUX_EAGAIN;
    }

    for (;;) {
        uint64_t timeout_ns;
        if (has_timeout) {
            timeout_ns =
                futex_remaining_ns(&deadline, FUTEX_OS_SYNC_POLL_CAP_NS, NULL);
            if (timeout_ns == 0)
                return -LINUX_ETIMEDOUT;
        } else {
            timeout_ns = FUTEX_OS_SYNC_POLL_CAP_NS;
        }

        int rc = os_sync_wait_on_address_with_timeout(
            host_addr, (uint64_t) expected, 4, OS_SYNC_WAIT_ON_ADDRESS_NONE,
            OS_CLOCK_MACH_ABSOLUTE_TIME, timeout_ns);
        if (rc >= 0) {
            /* Compare-after-block re-check. Darwin folds two distinct Linux
             * outcomes into a single rc>=0: a genuine wake, and the racy "value
             * moved off expected between the pre-check and the in-kernel
             * compare" case that Linux reports as -EAGAIN. Reload the word:
             * value still == expected means a real (or spurious) wake -> return
             * 0; value != expected means it moved, which is -EAGAIN under Linux
             * for the pre-block race and is equally safe for the post-wake
             * case, since a correct futex caller must re-read the word and
             * re-test its condition on either return. This is not a perfect
             * oracle: a value that moves off expected and back before the
             * reload returns 0 where Linux returns -EAGAIN, a benign spurious
             * wake the futex contract permits. No wake is lost: the kernel's
             * atomic compare-and-block already guarantees a waiter enqueued at
             * expected cannot miss an os_sync_wake_by_address, and any value
             * change carries the state the caller re-reads.
             */
            uint32_t observed;
            if (!futex_word_load(host_addr, &observed))
                return -LINUX_EFAULT;
            return observed == expected ? 0 : -LINUX_EAGAIN;
        }

        int err = errno;
        if (err != ETIMEDOUT && err != EINTR && err != EFAULT && err != ENOMEM)
            return -LINUX_EINVAL;

        if (err == EFAULT) {
            if (++efault_retries >= 8)
                return -LINUX_EFAULT;
        } else {
            efault_retries = 0;
        }

        if (thread_stop_requested() || futex_interrupt_consume()) {
            /* This path's deadline is relative (futex_make_deadline above is
             * called with is_absolute = 0), so part of it is already spent and
             * a restart would re-derive it from the guest's original value.
             */
            if (has_timeout)
                syscall_restart_forbid();
            return -LINUX_EINTR;
        }

        /* Drain any expired guest itimer so its SIGALRM / SIGVTALRM / SIGPROF
         * queues into sig_state.pending; without this poke, a guest with all
         * threads parked in futex_wait would never advance the timers.
         */
        signal_check_timer_real();

        /* Return EINTR only when a real deliverable signal is queued for this
         * thread. POSIX callers (e.g. glibc sem_wait, foot's render worker)
         * often do not retry on EINTR, so synthetic spurious wakeups cannot be
         * issued here. signal_pending() confirms under sig_lock so the atomic
         * hint cannot produce a stale-true edge after rt_sigprocmask masked the
         * queued signal.
         */
        if (signal_pending()) {
            if (has_timeout)
                syscall_restart_forbid();
            return -LINUX_EINTR;
        }

        /* For has_timeout: futex_remaining_ns returns 0 next iteration once the
         * user deadline elapses, so the loop exits with -ETIMEDOUT.
         */
    }
}

/* Hold this address's bucket census up for the whole wait, from before
 * futex_os_sync_wait's first load of the futex word to after its last. That
 * function returns from a dozen places; counting out here rather than in it is
 * what makes "every exit decrements" a property of the code rather than a rule
 * each new return has to remember. futex_os_sync_wait keeps its own name so
 * scripts/check-eintr-contract.py still records its EINTR returns against it.
 */
static int64_t futex_os_sync_wait_counted(guest_t *g,
                                          uint64_t uaddr,
                                          uint32_t expected,
                                          uint64_t timeout_gva)
{
    unsigned idx = futex_hash(uaddr);
    futex_bucket_t *b = &buckets[idx];

    /* Both counts go up before the wait reads the futex word, and the shim's
     * wake path depends on that order: see shim_globals_futex_waiters_add.
     * os_sync_waiters stays separate because it answers a narrower question,
     * whether the Darwin queue specifically needs draining.
     *
     * The published count strictly encloses os_sync_waiters, rather than the
     * two nesting the other way round. futex_wake reads this bucket's census as
     * the chain plus os_sync_waiters and holds the published count to be no
     * lower, which is the invariant its contract assert checks and the one the
     * shim reads a zero against. Charging os_sync_waiters first, or dropping
     * the published count first, opens an instant on either side where the
     * census counts a waiter the published count does not: a contended plain
     * FUTEX_WAIT workload trips that assert within a second.
     */
    shim_globals_futex_waiters_add(g, idx, +1);
    atomic_fetch_add_explicit(&b->os_sync_waiters, 1, memory_order_seq_cst);
    int64_t rc = futex_os_sync_wait(g, uaddr, expected, timeout_gva);
    atomic_fetch_sub_explicit(&b->os_sync_waiters, 1, memory_order_seq_cst);
    shim_globals_futex_waiters_add(g, idx, -1);
    return rc;
}

#else /* !ELFUSE_HAVE_OS_SYNC_WAIT_ON_ADDRESS */

/* Stub fallback: dead branch on builds whose SDK lacks the header. The dispatch
 * sites guard on os_sync_available, so this stub is unreachable at runtime, but
 * it keeps the link clean.
 */
static uint32_t futex_os_sync_wake_n(const guest_t *g,
                                     uint64_t uaddr,
                                     uint64_t budget)
{
    (void) g;
    (void) uaddr;
    (void) budget;
    return 0;
}

#endif /* ELFUSE_HAVE_OS_SYNC_WAIT_ON_ADDRESS */

/* Top up a wake after the bucket walk. A plain FUTEX_WAIT enqueues on the
 * kernel os_sync queue, not the hash bucket, so any site that wakes by walking
 * the bucket must also drain the os_sync queue at the same address or it
 * strands those waiters. woken is how many of target the bucket walk already
 * satisfied at uaddr; this drains the shortfall and returns the new total.
 * futex_os_sync_wake_n is a no-op when the address-wait path is disabled or
 * when no kernel waiter sits at uaddr, so this is safe to call unconditionally.
 * Call it AFTER dropping the bucket lock: os_sync_wake is a syscall and must
 * not run under the leaf lock.
 *
 * Every bucket-walking wake site (futex_wake, futex_requeue, futex_wake_op)
 * routes through here so the "drain both queues" invariant is one named step,
 * not a rule each new caller has to remember. The int64_t return absorbs
 * futex_os_sync_wake_n's uint32_t count without sign-extension.
 */
static int64_t futex_wake_topup_osync(const guest_t *g,
                                      uint64_t uaddr,
                                      int64_t woken,
                                      uint64_t target)
{
    if ((uint64_t) woken >= target)
        return woken;
    uint64_t budget = target - (uint64_t) woken;
    return woken + (int64_t) futex_os_sync_wake_n(g, uaddr, budget);
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
    int64_t block = futex_should_block(g, uaddr, expected, NULL);
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
    };
    pthread_cond_init(&waiter.cond, NULL);
    b->head = &waiter;

    /* Wait until woken or timeout */
    int ret = 0;

    while (!atomic_load_explicit(&waiter.woken, memory_order_acquire)) {
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
            pthread_cond_timedwait(&waiter.cond, &b->lock, &quantum);
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
         * futex_interrupt, expired guest itimers, and queued signals.
         */
        struct timespec poll_ts;
        timespec_deadline_in_ms(&poll_ts, 100);
        pthread_cond_timedwait(&waiter.cond, &b->lock, &poll_ts);

        if (thread_stop_requested() || futex_interrupt_consume()) {
            ret = -LINUX_EINTR;
            break;
        }

        /* The slow-path confirm inside signal_pending() avoids the stale-true
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

    /* Dequeue waiter. If woken=1, the wake/requeue operation already unlinked
     * the waiter from the bucket list, so skip dequeue. If woken=0 (timeout /
     * interrupt), the waiter is still in the list and must self-dequeue.
     *
     * For the self-dequeue path: requeue may have moved the waiter to a
     * different bucket (changed waiter.uaddr), so re-hash. Race: between
     * releasing the old bucket lock and acquiring the new one, another requeue
     * can move the waiter again. Loop until the waiter is found and dequeued.
     */
    if (!atomic_load_explicit(&waiter.woken, memory_order_acquire)) {
        for (;;) {
            unsigned dequeue_idx = futex_hash(waiter.uaddr);
            futex_bucket_t *b_dequeue = &buckets[dequeue_idx];
            if (b_dequeue != b) {
                pthread_mutex_unlock(&b->lock);
                pthread_mutex_lock(&b_dequeue->lock);
                b = b_dequeue;
            }
            /* Search for the current waiter in the bucket */
            bool found = false;
            futex_waiter_t **pp = &b->head;
            while (*pp) {
                if (*pp == &waiter) {
                    *pp = waiter.next;
                    found = true;
                    break;
                }
                pp = &(*pp)->next;
            }
            if (found)
                break;

            /* Not found: waiter was requeued again between the current hash
             * computation and lock acquisition. Re-read uaddr and retry.
             */
        }
    }

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
 * After walking the bucket, futex_wake_topup_osync drains any kernel-side
 * waiters at the same address up to the remaining budget so a wake that walked
 * only the bucket does not strand them; it is a no-op when the Darwin
 * address-wait path is inactive. Plain FUTEX_WAIT enqueues with implicit
 * FUTEX_BITSET_MATCH_ANY, which matches every legal FUTEX_WAKE_BITSET mask
 * (mask must be non-zero by Linux contract), so those waiters remain valid wake
 * targets. Publish this bucket's waiter count around the whole wait.
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
         * The chain is stable here: this holds the bucket lock. os_sync_waiters
         * is not, by design, since the Darwin address-wait path takes no lock.
         * So the three loads are not one instant, and either order is wrong in
         * one direction. Read the census last and a waiter that finishes in
         * between drops it under a population already counted; read it first
         * and a waiter that arrives in between raises the population above a
         * census already read. Neither is an understatement.
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
        parked +=
            atomic_load_explicit(&b->os_sync_waiters, memory_order_seq_cst);
        if (shim_globals_futex_waiters_get(g, idx) < parked) {
            int persisted = 0;
            for (int retry = 0; retry < FUTEX_CENSUS_RECHECKS; retry++) {
                unsigned again = 0;
                for (const futex_waiter_t *q = b->head; q; q = q->next)
                    again++;
                again += atomic_load_explicit(&b->os_sync_waiters,
                                              memory_order_seq_cst);
                if (shim_globals_futex_waiters_get(g, idx) < again)
                    persisted++;
            }
            if (persisted == FUTEX_CENSUS_RECHECKS)
                abort();
        }
    }
#endif

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

    return futex_wake_topup_osync(g, uaddr, woken, val);
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
        int64_t block = futex_should_block(g, uaddr, expected, NULL);
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
            /* Requeue: remove from source, add to destination */
            *pp = w->next;

            /* Credit the destination before debiting the source, so the shim
             * never sees this waiter charged to no bucket. Both halves sit
             * under pub_follows: a waiter carrying no charge of its own must
             * not gain one here, which is how a charge outlived its waiter.
             */
            if (w->pub_follows) {
                shim_globals_futex_waiters_add(g, idx_dst, +1);
                shim_globals_futex_waiters_add(g, w->pub_bucket, -1);
                w->pub_bucket = idx_dst;
            }
            w->uaddr = uaddr2;
            w->next = b_dst->head;
            b_dst->head = w;
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

    /* The kernel os_sync API cannot migrate waiters between addresses, so the
     * requeue portion degrades into a wake at the source uaddr: os_sync waiters
     * return to userland and re-acquire what they actually need (typically the
     * mutex pthread_cond_broadcast wanted to requeue onto). Both the wake and
     * requeue shortfalls therefore drain as wakes at uaddr; target is the full
     * wake_count + requeue_count so the returned count stays within the Linux
     * contract (woken + requeued must not exceed that sum).
     */
    return futex_wake_topup_osync(g, uaddr, (int64_t) woken + requeued,
                                  (uint64_t) wake_count + requeue_count);
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

    /* Signed comparison on the word as it was before the modify. */
    int cond_met = futex_wake_op_cmp((int32_t) old_val, wake_cmp, cmp_arg);

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

    /* Drain the os_sync queue at each address for the bucket shortfall. The
     * uaddr2 wake only fires when the predicate matched the old *uaddr2.
     */
    int64_t total1 = futex_wake_topup_osync(g, uaddr, woken1, val);
    int64_t total2 =
        cond_met ? futex_wake_topup_osync(g, uaddr2, woken2, val2) : woken2;

    return total1 + total2;
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
#if ELFUSE_HAVE_OS_SYNC_WAIT_ON_ADDRESS
        if (os_sync_available && os_sync_wait_enabled)
            return futex_os_sync_wait_counted(g, uaddr, val, timeout_gva);
#endif
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
        /* Stays on the bucket even when val3 is MATCH_ANY, which is
         * semantically a plain wait and could take the address-wait backend
         * instead. Measured on the bench-futex handoff with that spelling, n=45
         * paired runs: 1.03x, p=0.16. There is no win to bank, and routing it
         * would cost one: a kernel address-wait waiter cannot be migrated
         * between addresses, so futex_requeue degrades to a wake in place, and
         * that divergence is today confined to plain FUTEX_WAIT. Widening it
         * for an effect that does not survive its own error bars is the wrong
         * trade. tests/bench-futex.c keeps the row (BENCH_FUTEX_HANDOFF_BITSET)
         * so the next attempt starts from a measurement rather than the idea.
         */
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

        int64_t block = futex_should_block(g, uaddr, expected, NULL);
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
