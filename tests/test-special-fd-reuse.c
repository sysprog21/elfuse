/*
 * Test that closing a timerfd or signalfd leaves a newer fd of the same kind on
 * the same fd number alone
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Several threads open, dup and close fds of one kind, so an fd number one
 * thread has just closed is handed straight to another thread's open. A close
 * must tear down only the fd it closed, and closing a dup must tear down none.
 * Each round checks the fd it holds with a call that fails once the state
 * behind the fd is gone.
 */

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/signalfd.h>
#include <sys/timerfd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define THREADS 4
#define ROUNDS 1000

static int timerfd_open(void)
{
    return timerfd_create(CLOCK_MONOTONIC, 0);
}

/* A sibling's close that reached this timer leaves it gone or disarmed. */
static int timerfd_probe(int fd)
{
    struct itimerspec its = {.it_value = {.tv_sec = 100}}, cur = {0};
    if (timerfd_settime(fd, 0, &its, NULL) != 0 ||
        timerfd_gettime(fd, &cur) != 0)
        return -1;
    return cur.it_value.tv_sec > 0 ? 0 : -1;
}

static void usr1_mask(sigset_t *mask)
{
    sigemptyset(mask);
    sigaddset(mask, SIGUSR1);
}

static int signalfd_open(void)
{
    sigset_t mask;
    usr1_mask(&mask);
    return signalfd(-1, &mask, 0);
}

static int signalfd_probe(int fd)
{
    sigset_t mask;
    usr1_mask(&mask);
    return signalfd(fd, &mask, 0) == fd ? 0 : -1;
}

typedef struct {
    const char *name;
    int (*open)(void);
    int (*probe)(int fd);
} kind_t;

static const kind_t kinds[] = {
    {"timerfd", timerfd_open, timerfd_probe},
    {"signalfd", signalfd_open, signalfd_probe},
};

typedef struct {
    const kind_t *kind;
    int open_failed;
    int dup_failed;
    int probe_failed;
} tally_t;

static void *churn(void *arg)
{
    tally_t *t = arg;
    for (int i = 0; i < ROUNDS; i++) {
        int fd = t->kind->open();
        if (fd < 0) {
            t->open_failed++;
            continue;
        }

        /* Closing an alias must leave alone both the fd it aliased and
         * whichever fd holds its number next.
         */
        int alias = dup(fd);
        if (alias < 0)
            t->dup_failed++;
        else
            close(alias);
        if (t->kind->probe(fd) != 0)
            t->probe_failed++;
        close(fd);
    }
    return NULL;
}

static void run_kind(const kind_t *kind)
{
    pthread_t thr[THREADS];
    tally_t tally[THREADS] = {0};
    int started = 0;
    for (; started < THREADS; started++) {
        tally[started].kind = kind;
        if (pthread_create(&thr[started], NULL, churn, &tally[started]) != 0)
            break;
    }

    tally_t sum = {0};
    for (int i = 0; i < started; i++) {
        pthread_join(thr[i], NULL);
        sum.open_failed += tally[i].open_failed;
        sum.dup_failed += tally[i].dup_failed;
        sum.probe_failed += tally[i].probe_failed;
    }

    char name[32];
    snprintf(name, sizeof(name), "%s: threads started", kind->name);
    TEST(name);
    EXPECT_EQ(started, THREADS, "pthread_create failed");

    snprintf(name, sizeof(name), "%s: open", kind->name);
    TEST(name);
    EXPECT_EQ(sum.open_failed, 0, "open failed");

    snprintf(name, sizeof(name), "%s: dup", kind->name);
    TEST(name);
    EXPECT_EQ(sum.dup_failed, 0, "dup failed");

    snprintf(name, sizeof(name), "%s: fd keeps its state", kind->name);
    TEST(name);
    EXPECT_EQ(sum.probe_failed, 0, "a sibling's close reached this fd");
}

int main(void)
{
    printf("test-special-fd-reuse: close under fd number reuse\n");
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++)
        run_kind(&kinds[i]);

    SUMMARY("test-special-fd-reuse");
    return fails > 0 ? 1 : 0;
}
