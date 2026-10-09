/*
 * A requeued futex waiter leaving its wait while a wake reaches it
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * FUTEX_REQUEUE moves a parked waiter to another futex word, which is how
 * musl's pthread_cond_broadcast hands its waiters to the mutex. A wake at the
 * new word then races the waiter re-parking there, or leaving on its own with
 * EINTR for a signal or ETIMEDOUT for its deadline. Whichever wins, the waiter
 * has to return, a wake that counted it must find it returning 0 and promptly,
 * and a wake that found nobody must find it reporting why it left.
 *
 * The two words sit on different pages so they hash to different buckets, and
 * the wake is aimed across the waiter's exit so it lands on every side of it.
 */

#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* What, besides the wake, ends the wait. */
enum { LEAVE_NEVER, LEAVE_SIGNAL, LEAVE_TIMEOUT };

#define ROUNDS 20000
#define TIMEOUT_ROUNDS 4000
#define MAX_DELAY_SPINS 30000
#define TIMEOUT_NS 500000LL

/* How far past the deadline the wake is aimed. A host timeout fires late by
 * about half its length, so the window brackets that.
 */
#define AIM_SPAN_NS 600000LL

/* A wake that reaches a waiter sleeping under the wrong lock is answered a
 * polling quantum late, 100 ms. A fifth of that, far above a real handoff.
 */
#define MAX_GAP_NS 20000000LL
#define GIVE_UP_NS 3000000000LL

static uint32_t word_a __attribute__((aligned(4096)));
static uint32_t word_b __attribute__((aligned(4096)));

static int wait_op, wait_leave;
static _Atomic int round_go, round_done, waiter_errno;
static _Atomic int waiter_tid;
static _Atomic long long round_deadline_ns, waiter_back_ns;

static long long clock_ns(clockid_t clock)
{
    struct timespec t;
    clock_gettime(clock, &t);
    return (long long) t.tv_sec * 1000000000LL + t.tv_nsec;
}

static void on_signal(int sig)
{
    (void) sig;
}

static void *waiter(void *arg)
{
    (void) arg;
    atomic_store(&waiter_tid, (int) syscall(SYS_gettid));
    for (int seen = 0;;) {
        while (atomic_load(&round_go) == seen)
            ;
        seen = atomic_load(&round_go);
        if (seen < 0)
            return NULL;

        /* FUTEX_WAIT counts its timeout from the call and FUTEX_WAIT_BITSET
         * takes an instant, here on CLOCK_REALTIME.
         */
        long long deadline_ns = clock_ns(CLOCK_REALTIME) + TIMEOUT_NS;
        struct timespec ts = {0, TIMEOUT_NS};
        if (wait_op != FUTEX_WAIT) {
            ts.tv_sec = deadline_ns / 1000000000LL;
            ts.tv_nsec = deadline_ns % 1000000000LL;
        }
        atomic_store(&round_deadline_ns, deadline_ns);
        long rc = syscall(SYS_futex, &word_a, wait_op, 0,
                          wait_leave == LEAVE_TIMEOUT ? &ts : NULL, NULL,
                          FUTEX_BITSET_MATCH_ANY);
        atomic_store(&waiter_errno, rc == 0 ? 0 : errno);
        atomic_store(&waiter_back_ns, clock_ns(CLOCK_MONOTONIC));
        atomic_store(&round_done, seen);
    }
}

/* NULL when every round came back consistent, else what went wrong. */
static const char *race(int op, int leave)
{
    wait_op = op;
    wait_leave = leave;
    atomic_store(&round_go, 0);
    atomic_store(&round_done, 0);
    atomic_store(&waiter_tid, 0);

    pthread_t th;
    if (pthread_create(&th, NULL, waiter, NULL) != 0)
        return "could not start the waiter";
    while (!atomic_load(&waiter_tid))
        ;

    unsigned seed = 12345;
    int rounds = leave == LEAVE_TIMEOUT ? TIMEOUT_ROUNDS : ROUNDS;
    int left_alone = leave == LEAVE_TIMEOUT ? ETIMEDOUT : EINTR;
    for (int r = 1; r <= rounds; r++) {
        atomic_store(&round_deadline_ns, 0);
        atomic_store(&round_go, r);
        while (!atomic_load(&round_deadline_ns))
            ;

        /* Requeue returns 0 until the waiter is parked. A timed waiter may
         * leave first, and then the round has nothing to race.
         */
        long long give_up_ns = clock_ns(CLOCK_MONOTONIC) + GIVE_UP_NS;
        while (syscall(SYS_futex, &word_a, FUTEX_REQUEUE, 0, 1, &word_b, 0) !=
               1) {
            if (atomic_load(&round_done) == r)
                break;
            if (clock_ns(CLOCK_MONOTONIC) > give_up_ns)
                return "the waiter never parked";
        }

        if (leave == LEAVE_TIMEOUT) {
            long long aim_ns =
                atomic_load(&round_deadline_ns) + rand_r(&seed) % AIM_SPAN_NS;
            while (clock_ns(CLOCK_REALTIME) < aim_ns)
                ;
        } else {
            if (leave == LEAVE_SIGNAL &&
                syscall(SYS_tgkill, getpid(), atomic_load(&waiter_tid),
                        SIGUSR1) != 0)
                return "could not signal the waiter";
            for (volatile long i = rand_r(&seed) % (MAX_DELAY_SPINS + 1); i > 0;
                 i--)
                ;
        }
        long long woke_ns = clock_ns(CLOCK_MONOTONIC);
        long woke = syscall(SYS_futex, &word_b, FUTEX_WAKE, 1, NULL, NULL, 0);
        if (woke != 0 && woke != 1)
            return "the wake failed";

        give_up_ns = woke_ns + GIVE_UP_NS;
        while (atomic_load(&round_done) != r) {
            if (clock_ns(CLOCK_MONOTONIC) > give_up_ns)
                return "the waiter never returned";
        }

        int err = atomic_load(&waiter_errno);
        if (woke == 1 && err != 0)
            return "a wake counted a waiter that reported an error";
        if (woke == 1 && atomic_load(&waiter_back_ns) - woke_ns > MAX_GAP_NS)
            return "a wake reached the waiter a polling quantum late";
        if (woke == 0 && (leave == LEAVE_NEVER || err != left_alone))
            return "the waiter returned without a wake or a reason";
    }

    atomic_store(&round_go, -1);
    pthread_join(th, NULL);
    return NULL;
}

static void check(const char *name, int op, int leave)
{
    const char *why = race(op, leave);
    TEST(name);
    if (!why) {
        PASS();
        return;
    }

    /* Stop here. A waiter that never returned may be holding a bucket lock, and
     * the next futex call on that bucket would park this thread behind it.
     */
    FAIL(why);
    SUMMARY("test-futex-requeue-race");
    fflush(stdout);
    _exit(1);
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        printf("  sigaction failed, errno=%d\n", errno);
        return 1;
    }

    int bitset = FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME;
    check("FUTEX_WAIT requeued, then woken", FUTEX_WAIT, LEAVE_NEVER);
    check("FUTEX_WAIT requeued, signal against wake", FUTEX_WAIT, LEAVE_SIGNAL);
    check("FUTEX_WAIT requeued, timeout against wake", FUTEX_WAIT,
          LEAVE_TIMEOUT);
    check("FUTEX_WAIT_BITSET requeued, then woken", bitset, LEAVE_NEVER);
    check("FUTEX_WAIT_BITSET requeued, signal against wake", bitset,
          LEAVE_SIGNAL);
    check("FUTEX_WAIT_BITSET requeued, timeout against wake", bitset,
          LEAVE_TIMEOUT);

    SUMMARY("test-futex-requeue-race");
    return 0;
}
