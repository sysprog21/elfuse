/*
 * Test that closing a pidfd leaves a newer pidfd on the same fd number alone
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Several threads open, dup and close pidfds on one live child, so an fd number
 * one thread has just closed is handed straight to another thread's pidfd_open.
 * A close must tear down only the pidfd it closed, and closing a dup must tear
 * down none. Each round checks the pidfd it holds: the child is alive, so the
 * fd must not poll readable, and a signal 0 probe through it must succeed.
 */

#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#include "raw-syscall.h"
#include "test-harness.h"

#define __NR_pidfd_open_nr 434
#define __NR_pidfd_send_signal_nr 424

int passes = 0, fails = 0;

/* Enough opens to hit the reuse window on every run. A closed pidfd's monitor
 * holds a host thread and a host kqueue descriptor until the child exits, so
 * the total stays under both the host thread limit and the descriptor limit
 * elfuse runs with (HOST_NOFILE_MIN). Past either, pidfd_open or the readable
 * check fails for want of host resources.
 */
#define THREADS 4
#define ROUNDS 250

static pid_t child;

typedef struct {
    int open_failed;
    int dup_failed;
    int readable;
    int probe_failed;
} tally_t;

static void *churn(void *arg)
{
    tally_t *t = arg;
    for (int i = 0; i < ROUNDS; i++) {
        long pfd = raw_syscall2(__NR_pidfd_open_nr, (long) child, 0);
        if (pfd < 0) {
            t->open_failed++;
            continue;
        }

        /* Closing an alias must leave alone both the pidfd it aliased and
         * whichever pidfd holds its number next.
         */
        int alias = dup((int) pfd);
        if (alias < 0)
            t->dup_failed++;
        else
            close(alias);
        if (raw_syscall4(__NR_pidfd_send_signal_nr, pfd, 0, 0, 0) != 0)
            t->probe_failed++;
        struct pollfd pv = {.fd = (int) pfd, .events = POLLIN};
        if (poll(&pv, 1, 0) != 0)
            t->readable++;
        close((int) pfd);
    }
    return NULL;
}

int main(void)
{
    int gop[2];
    if (pipe(gop) < 0)
        return 1;

    child = fork();
    if (child < 0)
        return 1;
    if (child == 0) {
        /* Stay alive until the parent closes the other end. */
        close(gop[1]);
        uint8_t byte = 0;
        (void) read(gop[0], &byte, 1);
        _exit(0);
    }
    close(gop[0]);

    pthread_t thr[THREADS];
    tally_t tally[THREADS] = {0};
    int started = 0;
    for (; started < THREADS; started++) {
        if (pthread_create(&thr[started], NULL, churn, &tally[started]) != 0)
            break;
    }

    tally_t sum = {0};
    for (int i = 0; i < started; i++) {
        pthread_join(thr[i], NULL);
        sum.open_failed += tally[i].open_failed;
        sum.dup_failed += tally[i].dup_failed;
        sum.readable += tally[i].readable;
        sum.probe_failed += tally[i].probe_failed;
    }

    close(gop[1]);
    int status = 0;
    (void) waitpid(child, &status, 0);

    printf("test-pidfd-reuse: pidfd close under fd number reuse\n");

    TEST("all threads started");
    EXPECT_EQ(started, THREADS, "pthread_create failed");

    TEST("pidfd_open on a live child");
    EXPECT_EQ(sum.open_failed, 0, "pidfd_open failed");

    TEST("dup of a pidfd");
    EXPECT_EQ(sum.dup_failed, 0, "dup failed");

    TEST("pidfd on a live child is not readable");
    EXPECT_EQ(sum.readable, 0, "a sibling's close completed this pidfd");

    TEST("pidfd_send_signal(pfd, 0)");
    EXPECT_EQ(sum.probe_failed, 0, "a sibling's close removed this pidfd");

    SUMMARY("test-pidfd-reuse");
    return fails > 0 ? 1 : 0;
}
