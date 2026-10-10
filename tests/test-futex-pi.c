/*
 * PI futex and EINTR regression tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests:
 *   1. PI futex non-robust dead owner: a child thread acquires a PI lock
 *      and exits without releasing it or registering a robust list, so no
 *      FUTEX_OWNER_DIED is set. Linux does not recover such a lock -- the
 *      parent's FUTEX_LOCK_PI returns -ESRCH -- so elfuse must too.
 *
 *   1b. Robust OWNER_DIED recovery: FUTEX_LOCK_PI on a word left in the
 *      post-robust-walk state (FUTEX_OWNER_DIED set, TID cleared) must take
 *      the lock over and return 0, not spin on the CAS(0->TID) fast path.
 *
 *   2. FUTEX_LOCK_PI + FUTEX_UNLOCK_PI round-trip: acquire and
 *      release a PI lock from the same thread.
 *
 *   3. futex_wait blocks indefinitely without a signal: an earlier
 *      revision returned synthetic -EINTR after ~1 s of unconditional
 *      blocking, which violated POSIX sem_wait callers that do not
 *      retry on EINTR (e.g. foot's render_worker_thread). The wait
 *      must only return when a real wake arrives or a signal is
 *      genuinely queued for the thread.
 *
 *   4. PI waiter against an owner that retakes the lock in guest code: two
 *      threads take and release one PI lock in a tight loop, entering the
 *      kernel only on contention, until 2000 acquisitions have gone through
 *      FUTEX_LOCK_PI. A waiter that parks while the word has no FUTEX_WAITERS
 *      is never woken, because the owner's next release is a guest-side CAS
 *      that makes no syscall.
 *
 * Syscalls exercised: futex(98), clone(220), gettid(178), exit(93)
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <linux/futex.h>

#include "test-harness.h"
#include "raw-syscall.h"

int passes = 0, fails = 0;

/* Linux PI futex word layout */
#ifndef FUTEX_TID_MASK
#define FUTEX_TID_MASK 0x3FFFFFFF
#endif
#ifndef FUTEX_WAITERS
#define FUTEX_WAITERS 0x80000000
#endif
#ifndef FUTEX_OWNER_DIED
#define FUTEX_OWNER_DIED 0x40000000
#endif

/* Linux futex ops */
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8
#define FUTEX_PRIVATE 128

/* PI lock word: shared between parent and child thread. Must be aligned to 4
 * bytes (futex requirement).
 */
static volatile uint32_t pi_lock __attribute__((aligned(4))) = 0;

/* Sync flag: child signals it has acquired the lock */
static volatile int child_ready = 0;

/* PI futex syscall wrappers */

static long raw_futex_lock_pi(uint32_t *addr)
{
    return raw_syscall6(__NR_futex, (long) addr, FUTEX_LOCK_PI | FUTEX_PRIVATE,
                        0, 0, 0, 0);
}

static long raw_futex_unlock_pi(uint32_t *addr)
{
    return raw_syscall6(__NR_futex, (long) addr,
                        FUTEX_UNLOCK_PI | FUTEX_PRIVATE, 0, 0, 0, 0);
}

/* Child thread for dead-owner test */

/* Stack for child thread (8KiB, 16-byte aligned) */
static char child_stack_buf[8192] __attribute__((aligned(16)));

/* Child: acquire PI lock, signal parent, exit WITHOUT releasing and WITHOUT a
 * robust list. Exercises the non-robust dead-owner path in futex_lock_pi().
 */
static void child_acquire_and_die(void)
{
    /* Acquire the PI lock (sets pi_lock = the current TID) */
    long r = raw_futex_lock_pi((uint32_t *) &pi_lock);
    if (r != 0) {
        /* Lock acquisition failed; signal parent anyway */
        child_ready = 99;
        raw_futex_wake((int *) &child_ready, 1);
        raw_exit(1);
    }

    /* Signal parent that the child holds the lock */
    child_ready = 1;
    raw_futex_wake((int *) &child_ready, 1);

    /* Exit WITHOUT calling FUTEX_UNLOCK_PI and WITHOUT a robust list, so no
     * FUTEX_OWNER_DIED is set on pi_lock. The parent's FUTEX_LOCK_PI must then
     * fail with -ESRCH, matching Linux's non-robust dead-owner behavior.
     */
    raw_exit(0);
}

/* Test 1: PI lock/unlock round-trip */

static void test_pi_lock_unlock(void)
{
    TEST("PI lock/unlock round-trip");

    pi_lock = 0;

    long r = raw_futex_lock_pi((uint32_t *) &pi_lock);
    if (r != 0) {
        FAIL("LOCK_PI failed");
        return;
    }

    /* Verify the current thread owns the lock (low bits = the current TID) */
    uint32_t tid = (uint32_t) raw_gettid();
    uint32_t val = __atomic_load_n(&pi_lock, __ATOMIC_SEQ_CST);
    if ((val & FUTEX_TID_MASK) != tid) {
        FAIL("lock word doesn't contain our TID");
        return;
    }

    r = raw_futex_unlock_pi((uint32_t *) &pi_lock);
    if (r != 0) {
        FAIL("UNLOCK_PI failed");
        return;
    }

    /* Lock should be free (0) */
    val = __atomic_load_n(&pi_lock, __ATOMIC_SEQ_CST);
    EXPECT_TRUE(val == 0, "lock word not zero after unlock");
}

/* Test 2: Dead-owner recovery */

static void test_pi_dead_owner(void)
{
    TEST("PI non-robust dead owner returns ESRCH");

    /* Reset shared state */
    pi_lock = 0;
    child_ready = 0;

    /* Clone a child thread that acquires the PI lock and exits.
     * CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
     * CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |
     * CLONE_CHILD_CLEARTID | CLONE_DETACHED (0x7d0f00; DETACHED is a legacy
     * no-op on modern Linux)
     */
    void *stack_top = child_stack_buf + sizeof(child_stack_buf);
    int child_tid_val = 0;

    long ret = raw_clone(0x7d0f00, stack_top, &child_tid_val, 0,
                         (int *) &child_tid_val);

    if (ret < 0) {
        FAIL("clone failed");
        return;
    }

    if (ret == 0) {
        /* Child path */
        child_acquire_and_die();
        /* Should not reach here */
        raw_exit(1);
    }

    /* Parent: wait for child to signal it holds the lock */
    for (int i = 0; i < 100; i++) {
        if (__atomic_load_n(&child_ready, __ATOMIC_SEQ_CST) != 0)
            break;
        raw_futex_wait((int *) &child_ready, 0);
    }

    if (child_ready != 1) {
        FAIL("child didn't acquire lock");
        return;
    }

    /* Wait for child thread to actually exit (CLONE_CHILD_CLEARTID clears
     * child_tid_val and does futex_wake). Give it 500ms.
     */
    for (int i = 0; i < 50; i++) {
        if (__atomic_load_n(&child_tid_val, __ATOMIC_SEQ_CST) == 0)
            break;
        usleep(10000); /* 10ms */
    }

    /* Now try to acquire the PI lock. The child exited without releasing it and
     * without registering a robust list, so no FUTEX_OWNER_DIED was set. Linux
     * does NOT silently recover such a lock: FUTEX_LOCK_PI returns -ESRCH
     * (attach_to_pi_owner sees the owner TID is dead with no OWNER_DIED mark).
     * A guest that wants dead-owner recovery must use a robust futex list.
     */
    long r = raw_futex_lock_pi((uint32_t *) &pi_lock);
    if (r != -3 /* -ESRCH */) {
        printf(
            "FAIL: LOCK_PI expected -ESRCH(-3) for non-robust dead owner, "
            "got %ld\n",
            r);
        fails++;
        return;
    }
    PASS();
}

/* Test: LOCK_PI recovers a robust OWNER_DIED word */

static void test_pi_owner_died_recover(void)
{
    TEST("PI LOCK_PI recovers an OWNER_DIED word");

    /* Reproduce the post-robust-walk state directly: the robust-list walk sets
     * FUTEX_OWNER_DIED and clears the TID field on owner exit, leaving a
     * nonzero word (OWNER_DIED set) with an empty TID. FUTEX_LOCK_PI must take
     * over such a word -- Linux reacquires it and returns 0 -- rather than spin
     * forever on the CAS(0->TID) fast path (which never matches OWNER_DIED) or
     * fall through to the non-robust dead-owner -ESRCH path (TID is 0 here).
     */
    pi_lock = FUTEX_OWNER_DIED;

    long r = raw_futex_lock_pi((uint32_t *) &pi_lock);
    if (r != 0) {
        printf(
            "FAIL: LOCK_PI on OWNER_DIED word expected 0 (recovered), "
            "got %ld\n",
            r);
        fails++;
        return;
    }

    /* We now own it; the low bits carry our TID. */
    uint32_t tid = (uint32_t) raw_gettid();
    uint32_t val = __atomic_load_n(&pi_lock, __ATOMIC_SEQ_CST);
    if ((val & FUTEX_TID_MASK) != tid) {
        FAIL("lock word doesn't contain our TID after recovery");
        return;
    }

    raw_futex_unlock_pi((uint32_t *) &pi_lock);
    PASS();
}

/* Test: a PI waiter is woken when the owner retakes the lock in guest code */

#define RELOCK_CONTENDED 2000 /* FUTEX_LOCK_PI acquisitions to collect */
#define RELOCK_BUDGET_SEC 10  /* Give up collecting after this long */
#define RELOCK_DEADLINE_SEC 2 /* On one FUTEX_LOCK_PI call */

static volatile uint32_t relock_word __attribute__((aligned(4))) = 0;
static volatile long relock_count = 0;     /* Guarded by relock_word */
static volatile long relock_iters = 0;     /* Loop passes of both threads */
static volatile long relock_contended = 0; /* FUTEX_LOCK_PI calls that won */
static volatile long relock_failure = 0;   /* First failed acquisition */
static char relock_stack_buf[8192] __attribute__((aligned(16)));

static long relock_clock(int clock, struct timespec *ts)
{
    return raw_syscall6(__NR_clock_gettime, clock, (long) ts, 0, 0, 0, 0);
}

/* The protocol glibc and Rosetta both use: take the lock with a guest-side CAS
 * and enter the kernel only when that fails. The kernel call carries a deadline
 * so that a waiter nobody wakes reports ETIMEDOUT rather than hanging the
 * suite; with the lock changing hands every few microseconds, two seconds is
 * never reached by a waiter that is woken.
 */
static long relock_acquire(uint32_t tid)
{
    uint32_t expected = 0;
    if (__atomic_compare_exchange_n((uint32_t *) &relock_word, &expected, tid,
                                    0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        return 0;

    /* FUTEX_LOCK_PI takes an absolute CLOCK_REALTIME deadline. */
    struct timespec deadline;
    long r = relock_clock(CLOCK_REALTIME, &deadline);
    if (r != 0)
        return r;
    deadline.tv_sec += RELOCK_DEADLINE_SEC;
    r = raw_syscall6(__NR_futex, (long) &relock_word,
                     FUTEX_LOCK_PI | FUTEX_PRIVATE, 0, (long) &deadline, 0, 0);
    if (r == 0)
        __atomic_fetch_add((long *) &relock_contended, 1, __ATOMIC_SEQ_CST);
    return r;
}

static void relock_release(uint32_t tid)
{
    /* Fails exactly when FUTEX_WAITERS is set, which is the kernel's way of
     * asking for the syscall.
     */
    uint32_t expected = tid;
    if (__atomic_compare_exchange_n((uint32_t *) &relock_word, &expected, 0, 0,
                                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        return;
    raw_futex_unlock_pi((uint32_t *) &relock_word);
}

/* Runs on both threads until they have collected RELOCK_CONTENDED kernel
 * acquisitions between them. A thread running alone collects none, so the two
 * need no start signal: whichever starts first keeps going until the other
 * arrives. Raw syscalls only: the clone child has no TLS.
 */
static void relock_loop(void)
{
    uint32_t tid = (uint32_t) raw_gettid();
    struct timespec now;
    long stop_sec = 0;
    long iters = 0;

    if (relock_clock(CLOCK_MONOTONIC, &now) == 0)
        stop_sec = now.tv_sec + RELOCK_BUDGET_SEC;

    for (;;) {
        if (__atomic_load_n((long *) &relock_failure, __ATOMIC_SEQ_CST) != 0 ||
            __atomic_load_n((long *) &relock_contended, __ATOMIC_SEQ_CST) >=
                RELOCK_CONTENDED)
            break;

        /* The budget ends a run that cannot contend, such as one CPU; the
         * caller then fails on the count.
         */
        if ((iters & 1023) == 0 &&
            (relock_clock(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec > stop_sec))
            break;

        long r = relock_acquire(tid);
        if (r != 0) {
            long none = 0;
            __atomic_compare_exchange_n((long *) &relock_failure, &none, r, 0,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            break;
        }
        relock_count = relock_count + 1;
        relock_release(tid);
        iters++;
    }
    __atomic_fetch_add((long *) &relock_iters, iters, __ATOMIC_SEQ_CST);
}

static void test_pi_owner_relock(void)
{
    TEST("PI waiter woken across relock");

    relock_word = 0;
    relock_count = 0;
    relock_iters = 0;
    relock_contended = 0;
    relock_failure = 0;

    void *stack_top = relock_stack_buf + sizeof(relock_stack_buf);
    int child_tid_val = 0;
    long ret = raw_clone(0x7d0f00, stack_top, &child_tid_val, 0,
                         (int *) &child_tid_val);
    if (ret < 0) {
        FAIL("clone failed");
        return;
    }
    if (ret == 0) {
        relock_loop();
        raw_exit(0);
    }

    relock_loop();

    /* The child is at most one deadline plus one budget behind. */
    for (int i = 0; i < (RELOCK_DEADLINE_SEC + RELOCK_BUDGET_SEC + 1) * 100;
         i++) {
        if (__atomic_load_n(&child_tid_val, __ATOMIC_SEQ_CST) == 0)
            break;
        usleep(10000);
    }
    if (__atomic_load_n(&child_tid_val, __ATOMIC_SEQ_CST) != 0) {
        FAIL("relock child did not exit");
        return;
    }

    long failure = __atomic_load_n((long *) &relock_failure, __ATOMIC_SEQ_CST);
    if (failure != 0) {
        printf(
            "FAIL: lock acquisition returned %ld (-110: a parked waiter "
            "was never woken)\n",
            failure);
        fails++;
        return;
    }

    /* Fewer means the run could not contend enough to show a lost wake, and a
     * pass would then say nothing about the kernel path.
     */
    long contended =
        __atomic_load_n((long *) &relock_contended, __ATOMIC_SEQ_CST);
    if (contended < RELOCK_CONTENDED) {
        printf("FAIL: %ld of %d FUTEX_LOCK_PI acquisitions in %d s\n",
               contended, RELOCK_CONTENDED, RELOCK_BUDGET_SEC);
        fails++;
        return;
    }
    if (relock_count != relock_iters) {
        printf("FAIL: %ld increments under the lock, expected %ld\n",
               relock_count, relock_iters);
        fails++;
        return;
    }
    PASS();
}

/* Test 3: futex_wait without a signal blocks until woken */

/* Sibling that waits ~1.2 s, flips the futex word, and issues FUTEX_WAKE on the
 * parent's address. Used to drive the parent out of an indefinite futex_wait
 * via a real wake (not synthetic EINTR).
 */
static volatile int waker_word __attribute__((aligned(4))) = 0;
static char waker_stack_buf[8192] __attribute__((aligned(16)));

static void waker_thread(void)
{
    struct timespec ts = {1, 200 * 1000 * 1000};
    raw_syscall6(__NR_nanosleep, (long) &ts, 0, 0, 0, 0, 0);

    __atomic_store_n(&waker_word, 1, __ATOMIC_SEQ_CST);
    raw_futex_wake((int *) &waker_word, 1);
    raw_exit(0);
}

static void test_futex_eintr(void)
{
    TEST("futex_wait blocks until real wake, no synthetic EINTR");

    waker_word = 0;
    void *waker_top = waker_stack_buf + sizeof(waker_stack_buf);
    int waker_tid_val = 0;
    long sret = raw_clone(0x7d0f00, waker_top, &waker_tid_val, 0,
                          (int *) &waker_tid_val);
    if (sret < 0) {
        FAIL("waker clone failed");
        return;
    }
    if (sret == 0) {
        waker_thread();
        raw_exit(1); /* unreachable */
    }

    struct timeval t0, t1;
    gettimeofday(&t0, NULL);

    /* No timeout. With no signal queued, the wait must NOT return until the
     * waker thread issues FUTEX_WAKE; earlier revisions returned synthetic
     * -EINTR after ~1 s, which broke glibc sem_wait callers.
     */
    long r = raw_futex_wait((int *) &waker_word, 0);

    gettimeofday(&t1, NULL);
    long elapsed_ms =
        (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_usec - t0.tv_usec) / 1000;

    /* Reap the waker. */
    for (int i = 0; i < 100; i++) {
        if (__atomic_load_n(&waker_tid_val, __ATOMIC_SEQ_CST) == 0)
            break;
        usleep(10000);
    }

    /* The waker sleeps ~1200 ms before waking the parent. Accept either rc==0
     * (woken by FUTEX_WAKE after the wait observed waker_word change) or
     * -EAGAIN (woken between the waker_word store and the FUTEX_WAKE; the
     * value-mismatch path is the documented race for FUTEX_WAIT). Either
     * outcome proves the parent did not bail out on synthetic EINTR.
     */
    if ((r == 0 || r == -11 /* -EAGAIN */) && elapsed_ms >= 1000 &&
        elapsed_ms <= 4000) {
        PASS();
    } else {
        printf(
            "FAIL: expected rc=0 or -EAGAIN after ~1200ms, got %ld at "
            "%ldms\n",
            r, elapsed_ms);
        fails++;
    }
}

static void test_futex_unaligned(void)
{
    TEST("futex rejects unaligned uaddr");

    uint32_t words[2] = {0};
    int *unaligned = (int *) (void *) (((unsigned char *) words) + 1);

    long r = raw_futex_wait(unaligned, 0);
    if (r != -22) {
        printf("FAIL: WAIT expected -EINVAL(-22) got %ld\n", r);
        fails++;
        return;
    }

    r = raw_futex_wake(unaligned, 1);
    if (r != -22) {
        printf("FAIL: WAKE expected -EINVAL(-22) got %ld\n", r);
        fails++;
        return;
    }

    r = raw_syscall6(__NR_futex, (long) unaligned,
                     FUTEX_LOCK_PI | FUTEX_PRIVATE, 0, 0, 0, 0);
    if (r != -22) {
        printf("FAIL: LOCK_PI expected -EINVAL(-22) got %ld\n", r);
        fails++;
        return;
    }

    r = raw_syscall6(__NR_futex, (long) unaligned,
                     FUTEX_TRYLOCK_PI | FUTEX_PRIVATE, 0, 0, 0, 0);
    if (r != -22) {
        printf("FAIL: TRYLOCK_PI expected -EINVAL(-22) got %ld\n", r);
        fails++;
        return;
    }

    /* UNLOCK_PI checks ownership before alignment (Linux futex_unlock_pi runs
     * get_user + owner check ahead of get_futex_key), so an unaligned word you
     * do not own returns -EPERM, not -EINVAL.
     */
    r = raw_syscall6(__NR_futex, (long) unaligned,
                     FUTEX_UNLOCK_PI | FUTEX_PRIVATE, 0, 0, 0, 0);
    if (r != -1 /* -EPERM */) {
        printf("FAIL: UNLOCK_PI expected -EPERM(-1) got %ld\n", r);
        fails++;
        return;
    }

    PASS();
}

/* Main */

int main(void)
{
    printf("test-futex-pi: PI futex and EINTR regression tests\n");

    test_pi_lock_unlock();
    test_futex_eintr();
    test_futex_unaligned();
    test_pi_owner_died_recover();
    test_pi_owner_relock();
    test_pi_dead_owner(); /* Last: uses CLONE_THREAD which may hang on x64 */

    SUMMARY("test-futex-pi");
    return fails > 0 ? 1 : 0;
}
