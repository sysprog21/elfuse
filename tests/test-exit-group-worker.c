/*
 * exit_group issued by a non-main thread must terminate the process cleanly
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Regression test for the exit_group teardown race: when a worker thread calls
 * exit_group while its siblings are mid-iteration, the main thread must join
 * the workers before unmapping guest memory. A regression shows up as the
 * process dying of a host-level SIGSEGV (status 139) instead of reporting the
 * exit_group code.
 *
 * Phase 1 forks N children; in each child a worker thread calls exit_group(42)
 * while sibling workers occupy every blocking state a thread can be torn down
 * from -- spinners hammering guest memory (in hv_vcpu_run), a worker parked in
 * a timed FUTEX_WAIT_BITSET with a distant absolute deadline (the condvar wait
 * path glibc's sem_timedwait and pthread_cond_timedwait sit in), and a worker
 * parked in a blocking pipe read (the interruptible io wait). The parent
 * verifies the child exited 42 (fork children tear down through guest_destroy).
 * Phase 2 repeats the pattern in the top-level process itself, so this test's
 * own exit code 0 is produced by a worker-initiated exit_group through main()'s
 * teardown path. The parked variants regress the bounded-quantum futex waits:
 * an uncapped sleep would outlive the join cap, get detached, and race the
 * unmap.
 *
 * Syscalls: clone(220), exit_group(94), wait4(260), sched_yield(124),
 * futex(98), read(63), pipe2(59)
 */

#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "raw-syscall.h"
#include "test-harness.h"

int passes = 0, fails = 0;

#define FORK_ITERS 10
#define N_SPINNERS 3
#define N_WORKERS (N_SPINNERS + 2) /* spinners + futex parker + read parker */

static volatile unsigned long sink[512];
static volatile int workers_ready;
static int futex_word;
static int park_pipe[2];

static void *spinner_fn(void *arg)
{
    (void) arg;
    __sync_fetch_and_add(&workers_ready, 1);
    /* Keep touching guest memory until exit_group tears the process down. */
    for (unsigned long i = 0;; i++)
        sink[i % 512] = i;
    return NULL;
}

/* Park in a timed futex wait far in the future. FUTEX_WAIT_BITSET takes an
 * absolute deadline and is what glibc timed waits issue, so this exercises the
 * bounded-quantum teardown re-check. Re-arm on any spurious wake; exit_group is
 * the only way out.
 */
static void *futex_parker_fn(void *arg)
{
    (void) arg;
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 600;
    __sync_fetch_and_add(&workers_ready, 1);
    for (;;)
        raw_syscall6(
            __NR_futex, (long) &futex_word,
            FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME, 0,
            (long) &deadline, 0, (long) FUTEX_BITSET_MATCH_ANY);
    return NULL;
}

/* Park in a blocking read on a pipe that never gets written (the write end
 * stays open so the read cannot see EOF). Exercises the interruptible io wait's
 * teardown re-check.
 */
static void *read_parker_fn(void *arg)
{
    (void) arg;
    char c;
    __sync_fetch_and_add(&workers_ready, 1);
    for (;;)
        (void) read(park_pipe[0], &c, 1);
    return NULL;
}

static void *killer_fn(void *arg)
{
    int code = (int) (long) arg;
    while (__sync_fetch_and_add(&workers_ready, 0) < N_WORKERS)
        sched_yield();

    /* Give the parkers a moment to actually enter their blocking waits (the
     * ready increment happens just before the call). Not required for
     * correctness -- a parker that enters its wait after the exit-group flag is
     * set still notices it within one bounded quantum -- but it makes the test
     * exercise the parked states rather than the entry races.
     */
    usleep(20000);
    syscall(SYS_exit_group, code);
    return NULL;
}

/* Spawn the worker set plus a thread that calls exit_group(code), then spin on
 * the main thread. Never returns: exit_group ends the process.
 */
static void run_victim(int code)
{
    pthread_t t;
    workers_ready = 0;
    if (pipe(park_pipe) != 0)
        syscall(SYS_exit_group, 99);
    for (int i = 0; i < N_SPINNERS; i++) {
        if (pthread_create(&t, NULL, spinner_fn, NULL) != 0)
            syscall(SYS_exit_group, 99);
    }
    if (pthread_create(&t, NULL, futex_parker_fn, NULL) != 0)
        syscall(SYS_exit_group, 99);
    if (pthread_create(&t, NULL, read_parker_fn, NULL) != 0)
        syscall(SYS_exit_group, 99);
    if (pthread_create(&t, NULL, killer_fn, (void *) (long) code) != 0)
        syscall(SYS_exit_group, 99);
    for (;;)
        sched_yield();
}

int main(void)
{
    TEST("exit_group from worker thread (forked children)");

    int bad_status = -1;
    for (int iter = 0; iter < FORK_ITERS && bad_status < 0; iter++) {
        pid_t pid = fork();
        if (pid < 0) {
            FAIL("fork failed");
            goto summary;
        }
        if (pid == 0)
            run_victim(42); /* does not return */

        int status;
        if (waitpid(pid, &status, 0) != pid) {
            FAIL("waitpid failed");
            goto summary;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 42)
            bad_status = status;
    }
    if (bad_status >= 0) {
        if (WIFSIGNALED(bad_status))
            FAIL("child killed by signal (teardown race)");
        else
            FAIL("child reported wrong exit code");
    } else {
        PASS();
    }

summary:
    SUMMARY("test-exit-group-worker");
    if (fails)
        return 1;

    /* Phase 2: our own exit code 0 must come from a worker-initiated exit_group
     * in the top-level process. Flush first: exit_group does not flush stdio
     * buffers.
     */
    fflush(NULL);
    run_victim(0);
    return 1; /* unreachable */
}
