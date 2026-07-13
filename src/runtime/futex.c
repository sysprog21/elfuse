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
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "utils.h"

#include "runtime/futex.h"
#include "runtime/thread.h"

#include "syscall/linux-wire.h"
#include "syscall/proc.h"
#include "syscall/signal.h"

#include "debug/log.h"

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

/* Interrupt flag: when set, futex_wait returns -EINTR. Used to simulate SIGCHLD
 * delivery when all CLONE_THREAD workers exit: wakes the main thread from
 * blocking futex_wait without triggering a full exit_group.
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

#define FUTEX_BITSET_MATCH_ANY 0xFFFFFFFFU

/* PI futex word layout (bits):
 *   0-29: TID of lock holder (0 = unlocked)
 *   30:   FUTEX_OWNER_DIED (set by robust_list_walk on thread exit)
 *   31:   FUTEX_WAITERS (at least one thread is blocked)
 *
 * Linux kernel: FUTEX_WAITERS=0x80000000 (bit 31), FUTEX_OWNER_DIED=0x40000000
 * (bit 30), FUTEX_TID_MASK=0x3FFFFFFF. FUTEX_OWNER_DIED=0x40000000 (bit 30) is
 * set by robust_list_walk on thread exit. FUTEX_TID_MASK is 30 bits.
 */
#define FUTEX_TID_MASK 0x3FFFFFFFU
#define FUTEX_OWNER_DIED 0x40000000U
#define FUTEX_WAITERS 0x80000000U

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

/* Hash table */

#define FUTEX_BUCKETS 64

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
 * locks, index-ordered when two acquired).
 */
typedef struct {
    pthread_mutex_t lock;
    futex_waiter_t *head; /* Linked list of waiters hashing to this bucket */
} futex_bucket_t;

static futex_bucket_t buckets[FUTEX_BUCKETS];

/* Hash a guest VA to a bucket index. Futex addresses are typically 4-byte
 * aligned, so the low bits carry no entropy; shift them off and XOR a higher
 * slice in to spread aligned addresses across buckets.
 */
static inline unsigned futex_hash(uint64_t uaddr)
{
    return (unsigned) ((uaddr >> 2) ^ (uaddr >> 14)) % FUTEX_BUCKETS;
}

static inline bool futex_uaddr_is_aligned(uint64_t uaddr)
{
    return (uaddr & 0x3) == 0;
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
        if (!(v & FUTEX_WAITERS))
            return;
        if (!futex_word_cas(word, &v, v & ~FUTEX_WAITERS, &cleared))
            return;
        if (cleared)
            return;
    }
}

/* Public API */

void futex_init(void)
{
    for (int i = 0; i < FUTEX_BUCKETS; i++) {
        pthread_mutex_init(&buckets[i].lock, NULL);
        buckets[i].head = NULL;
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
 * clears it, 0 otherwise. The interrupt is a one-shot edge: forkipc.c sets it
 * when the last clone-thread exits so the main thread observes EINTR in its
 * next blocking wait, mirroring how real Linux delivers SIGCHLD. Without the
 * clear, the flag stays set and every subsequent epoll_pwait, ppoll, futex
 * wait, etc. spins on EINTR until execve clears it -- in foot's case it never
 * does, and the spinning main thread eventually faults in a code path the guest
 * never expects to reach.
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

static int linux_timespec_is_valid(const linux_timespec_t *lts)
{
    return lts->tv_sec >= 0 && lts->tv_sec <= FUTEX_TIMESPEC_SEC_MAX &&
           lts->tv_nsec >= 0 && lts->tv_nsec < 1000000000L;
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

/* Compute the relative wait quantum until an absolute CLOCK_REALTIME deadline,
 * capped at cap_ns. Operates on (sec, nsec) pairs to avoid overflowing int64_t
 * when delta_sec * NSEC_PER_SEC could exceed INT64_MAX: linux_timespec_is_valid
 * accepts tv_sec up to FUTEX_TIMESPEC_SEC_MAX (== INT64_MAX/4), and the
 * absolute-deadline path forwards that value unchanged into the host timespec.
 * Multiplying tv_sec * 1e9 first would overflow signed arithmetic for
 * adversarial guest inputs.
 *
 * Borrow-normalize the (delta_sec, delta_nsec) pair before comparing so caller
 * who hits delta_sec == 1 with delta_nsec < 0 (e.g., deadline tv_nsec just past
 * now tv_nsec when now is near a second boundary) does not get billed the full
 * cap when only a few nanoseconds remain. After the borrow delta_nsec lives in
 * [0, NSEC_PER_SEC); a single borrow always suffices because both inputs are
 * normalized.
 *
 * Once delta_sec >= 1 (post-borrow) the cap (~100 ms) dominates regardless of
 * delta_nsec, so the function returns cap_ns. delta_sec == 0 falls through to
 * min(delta_nsec, cap_ns). delta_sec < 0 (or delta_sec == 0 and delta_nsec ==
 * 0) means the deadline has elapsed; return 0 so the caller surfaces ETIMEDOUT
 * without re-arming.
 */
static uint64_t futex_remaining_ns(const struct timespec *deadline,
                                   uint64_t cap_ns)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    int64_t delta_sec = (int64_t) deadline->tv_sec - (int64_t) now.tv_sec;
    long delta_nsec = deadline->tv_nsec - now.tv_nsec;
    if (delta_nsec < 0) {
        delta_sec -= 1;
        delta_nsec += (long) NSEC_PER_SEC;
    }
    if (delta_sec < 0 || (delta_sec == 0 && delta_nsec == 0))
        return 0;
    if (delta_sec >= 1)
        return cap_ns;

    /* delta_sec == 0 and delta_nsec > 0; the borrow above guarantees delta_nsec
     * < NSEC_PER_SEC.
     */
    uint64_t rem = (uint64_t) delta_nsec;
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
static bool futex_quantum_deadline(const struct timespec *deadline,
                                   struct timespec *out)
{
    uint64_t rem_ns = futex_remaining_ns(deadline, FUTEX_OS_SYNC_POLL_CAP_NS);
    if (rem_ns == 0)
        return false;
    clock_gettime(CLOCK_REALTIME, out);
    out->tv_nsec += (long) rem_ns;
    timespec_normalize(out);
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

    uint32_t *host_addr = (uint32_t *) guest_ptr(g, uaddr);
    if (!host_addr)
        return -LINUX_EFAULT;

    uint32_t current;
    if (!futex_word_load(host_addr, &current))
        return -LINUX_EFAULT;
    if (current != expected)
        return -LINUX_EAGAIN;

    /* Bound consecutive EFAULT retries. Apple documents EFAULT as transient
     * (kernel copyin failure under memory pressure), so a few retries are fine;
     * but a genuinely bad page would otherwise cause the loop to spin with no
     * real sleep (timeout_ns is supplied to a syscall that returns immediately)
     * until the user deadline finally bails out. Surface EFAULT to the guest
     * after this many back-to-back failures so the host CPU does not burn for
     * ~1 s.
     */
    int efault_retries = 0;

    for (;;) {
        uint64_t timeout_ns;
        if (has_timeout) {
            timeout_ns =
                futex_remaining_ns(&deadline, FUTEX_OS_SYNC_POLL_CAP_NS);
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
static int64_t futex_wait(guest_t *g,
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

    pthread_mutex_lock(&b->lock);

    /* Atomically read the futex word while holding the bucket lock. If it does
     * not match, return EAGAIN immediately.
     */
    uint32_t *word = (uint32_t *) guest_ptr(g, uaddr);
    if (!word) {
        pthread_mutex_unlock(&b->lock);
        return -LINUX_EFAULT;
    }

    uint32_t current;
    if (!futex_word_load(word, &current)) {
        pthread_mutex_unlock(&b->lock);
        return -LINUX_EFAULT;
    }
    if (current != expected) {
        pthread_mutex_unlock(&b->lock);
        return -LINUX_EAGAIN;
    }

    /* Enqueue waiter (stack-allocated, lives on this thread's stack) */
    futex_waiter_t waiter = {
        .uaddr = uaddr,
        .bitset = bitset,
        .woken = 0,
        .next = b->head,
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

            /* Mirror the no-timeout branch's itimer/queued-signal re-check
             * below: without it, a thread parked in a timed FUTEX_WAIT_BITSET
             * (glibc sem_timedwait, pthread_cond_timedwait, JVM parkNanos) only
             * observes an expired guest itimer or a deliverable queued signal
             * once the futex wakes or the full guest deadline elapses. Lock
             * order requires dropping the bucket lock before touching sig_lock
             * (4).
             */
            pthread_mutex_unlock(&b->lock);
            signal_check_timer_real();
            bool sig_ready = signal_pending() != 0;
            pthread_mutex_lock(&b->lock);

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

        /* Lock-order: bucket lock(7) outranks sig_lock(4), so signal_pending()
         * and signal_check_timer() may only be called once the bucket lock has
         * been released. Drop it, poke the itimers, observe queued signals
         * under sig_lock (the slow-path confirm avoids the stale-true edge that
         * the atomic hint can carry after rt_sigprocmask masks the queued
         * signal), then re-acquire and re-check waiter.woken in case a wake
         * landed in the window.
         */
        pthread_mutex_unlock(&b->lock);
        signal_check_timer_real();
        bool sig_ready = signal_pending() != 0;
        pthread_mutex_lock(&b->lock);

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
 * targets.
 */
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
        uint32_t *word = (uint32_t *) guest_ptr(g, uaddr);
        if (!word) {
            if (idx_src != idx_dst)
                pthread_mutex_unlock(&b_dst->lock);
            pthread_mutex_unlock(&b_src->lock);
            return -LINUX_EFAULT;
        }
        uint32_t current;
        bool ok = futex_word_load(word, &current);
        if (!ok || current != expected) {
            if (idx_src != idx_dst)
                pthread_mutex_unlock(&b_dst->lock);
            pthread_mutex_unlock(&b_src->lock);
            return ok ? -LINUX_EAGAIN : -LINUX_EFAULT;
        }
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

    /* Decode operation and comparison from val3. Bits 31-28: operation (bit 31
     * = OPARG_SHIFT flag, bits 30-28 = op) Bits 27-24: comparison operator Bits
     * 23-12: op_arg (operand for modify, 12-bit signed) Bits 11-0: cmp_arg
     * (operand for compare, 12-bit signed) Both op_arg and cmp_arg are
     * sign-extended from 12 bits to match the Linux kernel's sign_extend32() in
     * futex_atomic_op_inuser().
     */
    unsigned wake_op = (val3 >> 28) & 0xF;
    unsigned wake_cmp = (val3 >> 24) & 0xF;
    int op_arg_raw = (int) ((val3 >> 12) & 0xFFF);
    int op_arg = (op_arg_raw << 20) >> 20; /* Sign-extend 12->32 */
    int cmp_arg_raw = (int) (val3 & 0xFFF);
    int cmp_arg = (cmp_arg_raw << 20) >> 20; /* Sign-extend 12->32 */

    /* FUTEX_OP_OPARG_SHIFT (bit 3 of wake_op): interpret op_arg as 1<<op_arg */
    int op_shift = (int) (wake_op & 8);
    wake_op &= 7; /* Actual operation is bits 0-2 */
    if (op_shift)
        op_arg = (int) (1U << (op_arg & 0x1F));

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
        switch (wake_op) {
        case 0:
            new_val = op_arg;
            break; /* SET */
        case 1:
            new_val = old_val + op_arg;
            break; /* ADD */
        case 2:
            new_val = old_val | op_arg;
            break; /* OR */
        case 3:
            new_val = old_val & ~op_arg;
            break; /* ANDN */
        case 4:
            new_val = old_val ^ op_arg;
            break; /* XOR */
        default:
            new_val = old_val;
            break;
        }
        ok = futex_word_cas(word2, &old_val, new_val, &swapped);
    } while (ok && !swapped);

    if (!ok) {
        if (idx1 != idx2)
            pthread_mutex_unlock(&b2->lock);
        pthread_mutex_unlock(&b1->lock);
        return -LINUX_EFAULT;
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

    /* Evaluate comparison predicate on old_val */
    int cond_met = 0;
    /* Linux FUTEX_WAKE_OP uses signed comparison semantics */
    int32_t sv = (int32_t) old_val, sa = (int32_t) cmp_arg;
    switch (wake_cmp) {
    case 0:
        cond_met = (sv == sa);
        break; /* EQ */
    case 1:
        cond_met = (sv != sa);
        break; /* NE */
    case 2:
        cond_met = (sv < sa);
        break; /* LT (signed) */
    case 3:
        cond_met = (sv <= sa);
        break; /* LE (signed) */
    case 4:
        cond_met = (sv > sa);
        break; /* GT (signed) */
    case 5:
        cond_met = (sv >= sa);
        break; /* GE (signed) */
    default:
        break;
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
static int64_t futex_lock_pi(guest_t *g, uint64_t uaddr, uint64_t timeout_gva)
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
        if ((expected & FUTEX_TID_MASK) == tid)
            return -LINUX_EDEADLK;

        /* Robust owner death: the robust-list walk sets FUTEX_OWNER_DIED and
         * clears the TID field on thread exit (see robust_list_walk), so the
         * word is nonzero (OWNER_DIED set) with an empty TID -- the CAS(0->TID)
         * fast path above cannot acquire it. Recover by clearing the word and
         * retrying. This must run before the nonzero-TID dead-owner test below,
         * which never sees a robust-cleaned word (TID == 0) and would otherwise
         * spin forever.
         */
        if (expected & FUTEX_OWNER_DIED) {
            if (!futex_word_cas(word, &expected, 0, NULL))
                return -LINUX_EFAULT;
            continue; /* Retry acquisition */
        }

        /* Owner thread has exited without releasing the lock and without robust
         * cleanup (no OWNER_DIED). Linux does not recover such a lock:
         * FUTEX_LOCK_PI returns -ESRCH (attach_to_pi_owner ->
         * handle_exit_race).
         */
        uint32_t owner_tid = expected & FUTEX_TID_MASK;
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
            if ((cur & FUTEX_TID_MASK) == 0)
                break; /* Owner released; retry outer loop */
            if (cur & FUTEX_WAITERS)
                break; /* Already set by another waiter */
            uint32_t desired = cur | FUTEX_WAITERS;
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
        if ((cur & FUTEX_TID_MASK) == 0)
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
        if ((cur & FUTEX_TID_MASK) == 0) {
            pthread_mutex_unlock(&b->lock);
            continue;
        }

        futex_waiter_t waiter = {
            .uaddr = uaddr,
            .bitset = FUTEX_BITSET_MATCH_ANY,
            .woken = 0,
            .next = b->head,
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
                     * Lock order requires dropping the bucket lock before
                     * signal_check_timer/signal_pending touch sig_lock (4).
                     */
                    pthread_mutex_unlock(&b->lock);
                    signal_check_timer_real();
                    bool sig_ready = signal_pending() != 0;
                    pthread_mutex_lock(&b->lock);

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
                 * lock is acquired or the owner dies. Lock order requires
                 * dropping the bucket lock before signal_check_timer/
                 * signal_pending touch sig_lock (4).
                 */
                pthread_mutex_unlock(&b->lock);
                signal_check_timer_real();
                bool sig_ready = signal_pending() != 0;
                pthread_mutex_lock(&b->lock);

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
                if (check & FUTEX_OWNER_DIED) {
                    owner_died = true;
                    break;
                }
                uint32_t check_tid = check & FUTEX_TID_MASK;
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
 * is held, return -EAGAIN immediately.
 */
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
    if ((cur & FUTEX_TID_MASK) != tid)
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

    /* Pre-fault lazy mappings before any bucket lock is taken. The word
     * resolves below run under per-bucket locks, which rank after mmap_lock;
     * materializing there would invert the lock order. A futex word in a
     * mapping the guest never touched reads as zero, matching Linux.
     */
    guest_lazy_faultin(g, uaddr, sizeof(uint32_t));
    if (cmd == FUTEX_REQUEUE || cmd == FUTEX_CMP_REQUEUE ||
        cmd == FUTEX_WAKE_OP)
        guest_lazy_faultin(g, uaddr2, sizeof(uint32_t));

    switch (cmd) {
    case FUTEX_WAIT:
#if ELFUSE_HAVE_OS_SYNC_WAIT_ON_ADDRESS
        if (os_sync_available && os_sync_wait_enabled)
            return futex_os_sync_wait(g, uaddr, val, timeout_gva);
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

static int waitv_collect_buckets(const linux_futex_waitv_t *elts,
                                 uint32_t nr_futexes,
                                 unsigned bucket_ids[FUTEX_WAITV_MAX],
                                 futex_bucket_t *bucket_ptrs[FUTEX_WAITV_MAX])
{
    unsigned nbuckets = 0;

    for (uint32_t i = 0; i < nr_futexes; i++) {
        unsigned idx = futex_hash(elts[i].uaddr);
        unsigned pos = 0;

        while (pos < nbuckets && bucket_ids[pos] < idx)
            pos++;
        if (pos < nbuckets && bucket_ids[pos] == idx)
            continue;

        for (unsigned j = nbuckets; j > pos; j--) {
            bucket_ids[j] = bucket_ids[j - 1];
            bucket_ptrs[j] = bucket_ptrs[j - 1];
        }
        bucket_ids[pos] = idx;
        bucket_ptrs[pos] = &buckets[idx];
        nbuckets++;
    }

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
        /* Pre-fault lazy mappings: the word resolves below run with every
         * bucket lock held, where materializing would invert the lock order
         * against mmap_lock.
         */
        guest_lazy_faultin(g, elts[i].uaddr, sizeof(uint32_t));
    }

    waitv_shared_t shared;
    pthread_mutex_init(&shared.lock, NULL);
    pthread_cond_init(&shared.cond, NULL);

    /* Validate and enqueue while holding every distinct bucket lock in index
     * order so the whole wait set is checked atomically.
     */
    futex_waiter_t waiters[FUTEX_WAITV_MAX];
    unsigned bucket_ids[FUTEX_WAITV_MAX];
    futex_bucket_t *bucket_ptrs[FUTEX_WAITV_MAX];
    int nbuckets =
        waitv_collect_buckets(elts, nr_futexes, bucket_ids, bucket_ptrs);
    int enqueued = 0;
    int64_t result_err = 0;

    for (int i = 0; i < nbuckets; i++)
        pthread_mutex_lock(&bucket_ptrs[i]->lock);

    for (uint32_t i = 0; i < nr_futexes; i++) {
        uint64_t uaddr = elts[i].uaddr;
        uint32_t expected = (uint32_t) elts[i].val;
        unsigned idx = futex_hash(uaddr);
        futex_bucket_t *b = &buckets[idx];

        uint32_t *word = (uint32_t *) guest_ptr(g, uaddr);
        if (!word) {
            result_err = -LINUX_EFAULT;
            goto unlock_early;
        }

        uint32_t current;
        if (!futex_word_load(word, &current)) {
            result_err = -LINUX_EFAULT;
            goto unlock_early;
        }
        if (current != expected) {
            result_err = -LINUX_EAGAIN;
            goto unlock_early;
        }

        futex_waiter_t *w = &waiters[i];
        w->uaddr = uaddr;
        w->bitset = FUTEX_BITSET_MATCH_ANY;
        atomic_store_explicit(&w->woken, 0, memory_order_relaxed);
        w->next = b->head;
        w->group_lock = &shared.lock;
        w->group_cond = &shared.cond;
        pthread_cond_init(&w->cond, NULL);
        b->head = w;
        enqueued++;
    }

    for (int i = nbuckets - 1; i >= 0; i--)
        pthread_mutex_unlock(&bucket_ptrs[i]->lock);

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

    return result_idx;

unlock_early:
    for (int i = nbuckets - 1; i >= 0; i--)
        pthread_mutex_unlock(&bucket_ptrs[i]->lock);

    for (int i = enqueued - 1; i >= 0; i--) {
        waitv_unlink(&waiters[i]);
        pthread_cond_destroy(&waiters[i].cond);
    }
    pthread_mutex_destroy(&shared.lock);
    pthread_cond_destroy(&shared.cond);
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
            uint32_t owner = futex_val & FUTEX_TID_MASK;
            if (owner == (uint32_t) thread_tid(t)) {
                /* Set FUTEX_OWNER_DIED and clear TID */
                uint32_t new_val =
                    (futex_val & ~FUTEX_TID_MASK) | FUTEX_OWNER_DIED;
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
            uint32_t owner = futex_val & FUTEX_TID_MASK;
            if (owner == (uint32_t) thread_tid(t)) {
                uint32_t new_val =
                    (futex_val & ~FUTEX_TID_MASK) | FUTEX_OWNER_DIED;
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
