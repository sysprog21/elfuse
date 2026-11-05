/*
 * test-futex-wake-nowaiter.c -- FUTEX_WAKE with nobody parked, and the race
 * that makes answering it early dangerous.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse answers a wake with no waiter from EL1, off a per-bucket count the
 * wait paths publish. Two things have to hold and only one of them is obvious.
 *
 * The obvious one is the ABI: a wake on an address nobody waits on returns 0,
 * including for an unmapped address, and a malformed one still returns EINVAL.
 *
 * The other is that the count may never read zero while a waiter is on its way
 * to parking, because the answer would then be 0 for a waiter that is still
 * there and the wakeup is lost. The stress below is built to sit in that
 * window: each round starts a waiter and wakes it from another thread with no
 * synchronization between the two beyond the futex itself, so the wake lands
 * before, during and after the wait across enough rounds. A regression here
 * does not fail an assertion, it hangs, which is why the harness timeout is the
 * real assertion.
 *
 * Every assertion is plain Linux futex ABI, so the reference kernel adjudicates
 * this file unchanged.
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <linux/futex.h>

#include "raw-syscall.h"
#include "test-harness.h"

int passes = 0, fails = 0;

/* Enough rounds to cover the window repeatedly, few enough to stay quick: each
 * round costs the settle below.
 */
#define ROUNDS 200

/* How long the waker waits for the waiter to be parked before storing and
 * waking. It has to be a sleep and not a spin: a guest thread here is a host
 * thread, and a spin loop on a loaded machine starves rather than converges,
 * which reads as the hang this test exists to detect.
 */
#define SETTLE_NS 200000L

static uint32_t word;
static uint32_t round_gate;

static long wake(uint32_t *w, int n)
{
    return raw_syscall6(__NR_futex, (long) w, FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
                        n, 0, 0, 0);
}

static long wait_on(uint32_t *w, uint32_t expect)
{
    return raw_syscall6(__NR_futex, (long) w, FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
                        expect, 0, 0, 0);
}

/* Let the waiter reach its park, then store and wake. Storing only after the
 * settle is what makes a lost wakeup show up: the waiter is already blocked, so
 * its own re-check cannot rescue it and the round never ends.
 */
static void *waker(void *arg)
{
    (void) arg;
    for (int i = 0; i < ROUNDS; i++) {
        while (__atomic_load_n(&round_gate, __ATOMIC_ACQUIRE) != (uint32_t) i)
            wait_on(&round_gate, (uint32_t) i - 1);

        struct timespec ts = {0, SETTLE_NS};
        nanosleep(&ts, NULL);

        __atomic_store_n(&word, 1, __ATOMIC_SEQ_CST);
        wake(&word, 1);
    }
    return NULL;
}

static uint32_t count_word;

static void *count_waiter(void *arg)
{
    (void) arg;
    wait_on(&count_word, 0);
    return NULL;
}

/* How many of the three parked waiters one wake of count n releases. */
static long wake_three_count(int n)
{
    return wake(&count_word, n);
}

int main(void)
{
    printf("FUTEX_WAKE no-waiter tests\n");

    /* Nothing is parked, so nothing wakes. */
    TEST("wake with no waiter returns 0");
    EXPECT_RAW_ERRNO(wake(&word, 1), 0, "expected 0 woken");

    TEST("wake of INT_MAX with no waiter returns 0");
    EXPECT_RAW_ERRNO(wake(&word, 0x7fffffff), 0, "expected 0 woken");

    /* An address the guest never mapped still answers 0 rather than EFAULT: a
     * wake resolves nothing, it only matches parked waiters.
     */
    TEST("wake on an unmapped address returns 0");
    EXPECT_RAW_ERRNO(wake((uint32_t *) 0x4000ULL, 1), 0, "expected 0 woken");

    /* Malformed shapes are still the host's answer, not 0. */
    TEST("unaligned wake is EINVAL");
    EXPECT_RAW_ERRNO(wake((uint32_t *) ((char *) &word + 1), 1), -EINVAL,
                     "expected EINVAL for an unaligned uaddr");

    TEST("wake_bitset with a zero bitset is EINVAL");
    EXPECT_RAW_ERRNO(
        raw_syscall6(__NR_futex, (long) &word,
                     FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1, 0, 0, 0),
        -EINVAL, "expected EINVAL for a zero bitset");

    /* The race. Each round parks on the word and has the sibling wake it; a
     * lost wakeup stops this dead rather than failing it.
     */
    TEST("no wakeup is lost against a concurrent waiter");
    pthread_t th;
    int rc1 = pthread_create(&th, NULL, waker, NULL);
    if (rc1 != 0) {
        fprintf(stderr, "pthread_create: %s\n", strerror(rc1));
        FAIL("pthread_create");
    } else {
        for (int i = 0; i < ROUNDS; i++) {
            __atomic_store_n(&word, 0, __ATOMIC_SEQ_CST);
            __atomic_store_n(&round_gate, (uint32_t) i, __ATOMIC_RELEASE);
            wake(&round_gate, 1);
            while (__atomic_load_n(&word, __ATOMIC_SEQ_CST) == 0)
                wait_on(&word, 0);
        }
        pthread_join(th, NULL);
        PASS();
    }

    /* The count is a signed int that Linux checks after waking a waiter, so a
     * zero or negative count still wakes exactly one. Three waiters park on one
     * word; each call below releases one, and the last count is the ordinary
     * large one for the remaining waiter.
     */
    pthread_t cw[3];
    int started = 0;
    for (; started < 3; started++)
        if (pthread_create(&cw[started], NULL, count_waiter, NULL) != 0)
            break;
    struct timespec park = {0, 300000000L};
    nanosleep(&park, NULL);

    TEST("wake with count 0 wakes one waiter");
    EXPECT_RAW_ERRNO(wake_three_count(0), 1, "expected 1 woken");

    TEST("wake with a negative count wakes one waiter");
    EXPECT_RAW_ERRNO(wake_three_count(-1), 1, "expected 1 woken");

    TEST("wake with INT_MAX wakes the rest");
    EXPECT_RAW_ERRNO(wake_three_count(0x7fffffff), 1, "expected 1 woken");

    /* A waiter the wakes above missed would hang the join. */
    wake(&count_word, 0x7fffffff);
    for (int i = 0; i < started; i++)
        pthread_join(cw[i], NULL);

    SUMMARY("test-futex-wake-nowaiter");
    return fails > 0 ? 1 : 0;
}
