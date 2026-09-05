/*
 * A plain FUTEX_REQUEUE must refuse a PI waiter, whatever the addresses are
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux answers EINVAL when a requeue without FUTEX_CMP_REQUEUE_PI meets a
 * waiter holding an rt_waiter or a pi_state. The test is on the waiter alone,
 * so neither the addresses nor the wake budget excuses one, and this file puts
 * a case to each of those. It also holds the negative counts requeue.c refuses
 * before it takes either key.
 *
 * The requeue is retried while it reports zero, which is the answer when nobody
 * is parked yet: without that loop a slow thread start would pass by never
 * reaching the case.
 *
 * Syscalls exercised: futex(98), clone(220), gettid(178), exit(93), sched_yield
 */

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/futex.h>

#include "test-harness.h"
#include "raw-syscall.h"

int passes = 0, fails = 0;

/* The lock under test and the four handshake words that sequence the two
 * threads around it.
 */
static int pi_lock;       /* the PI futex the waiter parks on */
static int holder_ready;  /* set once the holder has settled, either way */
static int holder_failed; /* set instead of owning it, when LOCK_PI refused */
static int release;       /* set to tell the holder to unlock */
static int waiter_done;   /* set once the waiter has taken and released it */

static int holder_stack[16384] __attribute__((aligned(16)));
static int waiter_stack[16384] __attribute__((aligned(16)));

/* Every op carries FUTEX_PRIVATE_FLAG, as the neighbouring futex tests do.
 * elfuse masks it off, but on a reference kernel private and shared hash to
 * different keys, and raw_futex_wake sets it.
 */
static long futex_lock_pi(int *addr)
{
    return raw_syscall6(__NR_futex, (long) addr,
                        FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
}

static long futex_unlock_pi(int *addr)
{
    return raw_syscall6(__NR_futex, (long) addr,
                        FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
}

/* FUTEX_REQUEUE reads its requeue count out of the timeout slot. */
static long futex_requeue_same(int *addr, long wake, long requeue)
{
    return raw_syscall6(__NR_futex, (long) addr,
                        FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG, wake, requeue,
                        (long) addr, 0);
}

static void set_and_wake(int *addr)
{
    __atomic_store_n(addr, 1, __ATOMIC_RELEASE);
    raw_futex_wake(addr, 1);
}

/* holder_ready is the one flag two threads wait on, main and the waiter, and it
 * is set once. Waking a single one of them strands the other for good, because
 * the flag never returns to zero and no second wake is coming.
 *
 * Both readers usually observe the store before they park, which is why the
 * single wake survived every run on a host with hardware virtualization. Under
 * qemu's tcg the window between the load in wait_until_set and the FUTEX_WAIT
 * behind it is wide enough to lose, and the matrix's qemu-aarch64 lane hung
 * there about one run in three.
 *
 * The other three flags keep set_and_wake. Each has exactly one reader, and
 * leaving them alone is what keeps that readable.
 */
static void set_and_wake_all(int *addr)
{
    __atomic_store_n(addr, 1, __ATOMIC_RELEASE);
    raw_futex_wake(addr, INT_MAX);
}

static void wait_until_set(int *addr)
{
    while (__atomic_load_n(addr, __ATOMIC_ACQUIRE) == 0)
        raw_futex_wait(addr, 0);
}

/* Takes pi_lock, reports it, and holds it until told to let go. The waiter
 * cannot park until someone else owns the word.
 */
static void holder_fn(void)
{
    if (futex_lock_pi(&pi_lock) == 0) {
        set_and_wake_all(&holder_ready);
        wait_until_set(&release);
        futex_unlock_pi(&pi_lock);
    } else {
        /* Say so rather than leave main parked on holder_ready forever: a tree
         * whose LOCK_PI is broken is the one this lane exists to catch.
         */
        set_and_wake(&holder_failed);
        set_and_wake_all(&holder_ready);
    }
    raw_exit(0);
}

/* Parks in FUTEX_LOCK_PI on the held word. This is the waiter whose charge the
 * requeue must not move, and the one whose bucket is left over-counted.
 */
static void waiter_fn(void)
{
    wait_until_set(&holder_ready);
    if (futex_lock_pi(&pi_lock) == 0)
        futex_unlock_pi(&pi_lock);
    set_and_wake(&waiter_done);
    raw_exit(0);
}

int main(void)
{
    /* CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
     * CLONE_SYSVSEM, spelled as the value the way test-futex-pi.c does. No TLS
     * or tid flags: a CHILD_CLEARTID wake would only add futex traffic.
     */
    unsigned long flags = 0x50f00;

    printf("=== futex requeue PI rejection tests ===\n\n");

    /* No waiter needed: on an empty address both counts are no-ops, so the zero
     * an unguarded build reports is what EINVAL separates from.
     */
    TEST("a negative wake count is EINVAL");
    EXPECT_RAW_ERRNO(futex_requeue_same(&pi_lock, -1, 0), -EINVAL,
                     "a negative wake count must be refused");

    TEST("a negative requeue count is EINVAL");
    EXPECT_RAW_ERRNO(futex_requeue_same(&pi_lock, 0, -1), -EINVAL,
                     "a negative requeue count must be refused");

    /* One clone at a time, each with its child branch immediately after it:
     * issuing both first lets the first child run the second raw_clone too.
     * test-thread.c and test-futex-pi.c clone this way for the same reason.
     */
    TEST("clone holder and waiter");
    long holder = raw_clone(flags, holder_stack + 16384, 0, 0, 0);
    if (holder == 0) {
        holder_fn();
        __builtin_unreachable();
    }
    if (holder < 0) {
        FAIL("holder clone failed");
        goto done;
    }

    long waiter = raw_clone(flags, waiter_stack + 16384, 0, 0, 0);
    if (waiter == 0) {
        waiter_fn();
        __builtin_unreachable();
    }
    if (waiter < 0) {
        FAIL("waiter clone failed");
        goto done;
    }
    PASS();

    wait_until_set(&holder_ready);

    TEST("holder takes pi_lock");
    if (__atomic_load_n(&holder_failed, __ATOMIC_ACQUIRE) != 0) {
        FAIL("FUTEX_LOCK_PI refused the holder, nothing to requeue against");
        goto done;
    }
    PASS();

    /* Zero is the answer before the waiter parks; anything else means the call
     * saw it, and EINVAL is the only correct one.
     */
    TEST("requeue a parked PI waiter onto its own address");
    long rc = 0;
    for (int i = 0; i < 100000 && rc == 0; i++) {
        rc = futex_requeue_same(&pi_lock, 0, 1);
        if (rc == 0)
            raw_syscall0(__NR_sched_yield);
    }
    EXPECT_RAW_ERRNO(rc, -EINVAL, "requeuing a PI waiter must be EINVAL");

    /* Still parked, so the other two shapes reuse it. The check outranks the
     * wake/requeue decision, so neither budget excuses a PI waiter.
     */
    TEST("PI waiter inside the wake budget");
    EXPECT_RAW_ERRNO(futex_requeue_same(&pi_lock, 1, 1), -EINVAL,
                     "a PI waiter within wake_count must be EINVAL, not woken");

    TEST("wake-only requeue with a PI waiter");
    EXPECT_RAW_ERRNO(futex_requeue_same(&pi_lock, 1, 0), -EINVAL,
                     "requeue_count 0 does not excuse a PI waiter");

    set_and_wake(&release);
    wait_until_set(&waiter_done);

    /* Nobody is parked now, so a rejected requeue must not have left the waiter
     * somewhere a later wake still finds.
     */
    TEST("wake the drained address");
    for (int i = 0; i < 8; i++) {
        if (raw_futex_wake(&pi_lock, 1) != 0) {
            FAIL("a drained address reported a woken waiter");
            goto done;
        }
    }
    PASS();

done:
    SUMMARY("test-futex-requeue-pi");
    return fails > 0 ? 1 : 0;
}
