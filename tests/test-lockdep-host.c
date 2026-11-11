/*
 * Runtime lock-order validator self-test
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Each case runs in a child, single-threaded: the validator has to fail an
 * inversion without the two orders ever racing. The locks borrow names from the
 * order document so the documented-rank and leaf rules apply to them.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>

#if defined(ELFUSE_LOCKDEP)

static pthread_mutex_t mmap_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fd_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t absock_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t inst_a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t inst_b = PTHREAD_MUTEX_INITIALIZER;

static void nest(pthread_mutex_t *outer, pthread_mutex_t *inner)
{
    pthread_mutex_lock(outer);
    pthread_mutex_lock(inner);
    pthread_mutex_unlock(inner);
    pthread_mutex_unlock(outer);
}

static void documented_order(void)
{
    nest(&mmap_lock, &fd_lock);
    pthread_mutex_lock(&fd_lock);
    pthread_mutex_lock(&log_mutex);
    pthread_mutex_unlock(&log_mutex);
    pthread_mutex_unlock(&fd_lock);
    pthread_mutex_lock(&absock_lock);
    pthread_mutex_lock(&log_mutex);
    pthread_mutex_unlock(&log_mutex);
    pthread_mutex_unlock(&absock_lock);
}

static void against_rank(void)
{
    pthread_mutex_lock(&fd_lock);
    pthread_mutex_lock(&mmap_lock);
}

static void under_leaf(void)
{
    pthread_mutex_lock(&absock_lock);
    pthread_mutex_lock(&inst_a);
}

static void instance_cycle(void)
{
    nest(&inst_a, &inst_b);
    nest(&inst_b, &inst_a);
}

static void destroyed_lock_forgotten(void)
{
    pthread_mutex_t *a = malloc(sizeof(*a));
    pthread_mutex_init(a, NULL);
    nest(a, &inst_b);
    pthread_mutex_destroy(a);
    pthread_mutex_init(a, NULL);
    nest(&inst_b, a);
    pthread_mutex_destroy(a);
    free(a);
}

static int run(const char *name, void (*fn)(void), int want_abort)
{
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0)
            dup2(devnull, 2);
        fn();
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    int aborted = WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT;
    int ok = want_abort ? aborted : (WIFEXITED(status) && !WEXITSTATUS(status));
    printf("%s %s\n", ok ? "PASS:" : "FAIL:", name);
    return ok ? 0 : 1;
}

int main(void)
{
    int fails = 0;
    fails += run("documented order passes", documented_order, 0);
    fails += run("acquisition against the rank aborts", against_rank, 1);
    fails += run("acquisition under a leaf aborts", under_leaf, 1);
    fails += run("instance AB-BA aborts", instance_cycle, 1);
    fails += run("destroyed lock leaves no edge", destroyed_lock_forgotten, 0);
    return fails ? 1 : 0;
}

#else

int main(void)
{
    printf("SKIP: built without LOCKDEP=1\n");
    return 77;
}

#endif
