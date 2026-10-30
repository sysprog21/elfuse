/*
 * Test RLIMIT_CPU: SIGXCPU at the soft limit, SIGKILL at the hard limit
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Each case runs in its own fork child, since the limits count the CPU time of
 * the whole process. The children run at once, so the test takes about as long
 * as the slowest one, 3.5 CPU seconds. The spinning children make no syscalls,
 * so only a sampler outside the guest can see the limit pass.
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "test-harness.h"
#include "test-util.h"

int passes = 0, fails = 0;

static volatile int report_fd = -1;

static void spin(void)
{
    volatile unsigned long n = 0;
    for (;;)
        n++;
}

static void set_cpu_limit(rlim_t cur, rlim_t max)
{
    struct rlimit rl = {cur, max};
    if (setrlimit(RLIMIT_CPU, &rl) != 0)
        _exit(100);
}

static void set_cpu_soft(rlim_t cur)
{
    struct rlimit rl;
    getrlimit(RLIMIT_CPU, &rl);
    set_cpu_limit(cur, rl.rlim_max);
}

/* Write the soft limit this handler sees, so the parent can check that each
 * SIGXCPU moved it up by one second, and whether the kernel sent it: Linux
 * check_rlimit sends SEND_SIG_PRIV, which reads as SI_KERNEL with no sender.
 */
static void on_xcpu(int sig, siginfo_t *si, void *ctx)
{
    (void) sig;
    (void) ctx;
    struct rlimit rl;
    unsigned char rep[2] = {0, si->si_code == SI_KERNEL && si->si_pid == 0};
    if (getrlimit(RLIMIT_CPU, &rl) == 0)
        rep[0] = (unsigned char) rl.rlim_cur;
    (void) write(report_fd, rep, sizeof(rep));
}

/* Spin past a 1 s soft limit with SIGXCPU at its default action. */
static void child_default(void)
{
    set_cpu_soft(1);
    spin();
}

/* Soft limit 1 s, hard limit 3 s, SIGXCPU caught. */
static void child_caught(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_xcpu;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGXCPU, &sa, NULL);
    set_cpu_limit(1, 3);
    spin();
}

static volatile unsigned char late_seen[8];
static volatile int late_n;

static void on_xcpu_late(int sig)
{
    (void) sig;
    struct rlimit rl;
    if (late_n < (int) sizeof(late_seen) && getrlimit(RLIMIT_CPU, &rl) == 0)
        late_seen[late_n++] = (unsigned char) rl.rlim_cur;
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000u + (uint64_t) ts.tv_nsec;
}

/* Lift an inherited soft limit, use 3 s of CPU, lower the soft limit to 1 s,
 * and spin on to 3.5 s. The limit catches up as 2, 3 and 4, and a delayed
 * handler can see merged or repeated steps, so exits 1 unless it saw
 * non-decreasing limits ending at 4. Raised once per check, as
 * check_process_timers raises it once per tick, 4 is two checks away from the
 * lowering; raised in one burst, it is there at once. A busy host only delays
 * the checks, so exits 2 when 4 was visible within 1 ms, below the 2 ms two
 * ticks take at HZ 1000.
 */
static void child_late(void)
{
    struct rlimit rl;
    getrlimit(RLIMIT_CPU, &rl);
    set_cpu_soft(rl.rlim_max);
    signal(SIGXCPU, on_xcpu_late);
    while (clock() < 3 * CLOCKS_PER_SEC)
        ;
    uint64_t t0 = now_ns(), t4 = 0;
    set_cpu_soft(1);
    while (clock() < 7 * CLOCKS_PER_SEC / 2) {
        if (!t4 && getrlimit(RLIMIT_CPU, &rl) == 0 && rl.rlim_cur >= 4)
            t4 = now_ns();
    }
    int rising = late_n >= 1 && late_seen[late_n - 1] == 4;
    for (int i = 1; i < late_n; i++)
        rising = rising && late_seen[i] >= late_seen[i - 1];
    _exit(!rising || !t4 ? 1 : t4 - t0 < 1000000u ? 2 : 0);
}

static void *spin_thread(void *arg)
{
    (void) arg;
    spin();
    return NULL;
}

/* Sleep in the leader while a worker spins past a 1 s hard limit, so the
 * SIGKILL is most likely dequeued by the worker.
 */
static void child_worker(void)
{
    set_cpu_limit(1, 1);
    pthread_t t;
    if (pthread_create(&t, NULL, spin_thread, NULL) != 0)
        _exit(100);
    for (;;)
        pause();
}

/* Sleep through 1.5 s of wall time under a 1 s soft limit. */
static void child_sleeper(void)
{
    set_cpu_soft(1);
    struct timespec ts = {1, 500000000};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
        ;
    _exit(0);
}

static pid_t start(void (*fn)(void))
{
    pid_t pid = fork();
    if (pid == 0) {
        fn();
        _exit(101);
    }
    return pid;
}

/* Give up after 10 s and kill the child, so a limit that is never enforced
 * fails its case rather than the run. Not alarm() in the child: elfuse checks a
 * guest ITIMER_REAL only when the vCPU exits, which a spinning child never
 * does. SIGKILL is sent until the child is reaped, since under elfuse a worker
 * thread that takes it ends alone.
 */
static int wait_status(pid_t pid)
{
    int status = 0;
    if (pid < 0)
        return -1;
    for (int i = 0;; i++) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid)
            return i < 100 ? status : -1;
        if (r < 0)
            return -1;
        if (i >= 100)
            kill(pid, SIGKILL);
        usleep(100000);
    }
}

/* Fork under a 0 s soft limit with SIGXCPU blocked, so the SIGXCPU this process
 * earns at once stays pending and the fork always runs. The child unblocks it
 * and spins under the limit it inherited. Exits 0 when the child died of
 * SIGXCPU.
 */
static void child_inherit_parent(void)
{
    sigset_t xcpu;
    sigemptyset(&xcpu);
    sigaddset(&xcpu, SIGXCPU);
    sigprocmask(SIG_BLOCK, &xcpu, NULL);
    set_cpu_soft(0);
    pid_t pid = fork();
    if (pid == 0) {
        sigprocmask(SIG_UNBLOCK, &xcpu, NULL);
        spin();
    }
    int st = wait_status(pid);
    _exit(st != -1 && WIFSIGNALED(st) && WTERMSIG(st) == SIGXCPU ? 0 : 1);
}

/* Set {0, 0}, a hard limit this process is already past. */
static void child_zero(void)
{
    set_cpu_limit(0, 0);
    spin();
}

int main(void)
{
    printf("test-rlimit-cpu: RLIMIT_CPU enforcement\n");

    struct rlimit rl;
    if (getrlimit(RLIMIT_CPU, &rl) != 0 ||
        (rl.rlim_max != RLIM_INFINITY && rl.rlim_max < 4)) {
        printf("  SKIP: RLIMIT_CPU hard limit below 4 s\n");
        SUMMARY("test-rlimit-cpu");
        return 0;
    }

    int pfd[2];
    if (pipe(pfd) != 0) {
        TEST("pipe");
        FAIL("pipe");
        SUMMARY("test-rlimit-cpu");
        return 1;
    }

    report_fd = pfd[1];
    pid_t def = start(child_default);
    pid_t caught = start(child_caught);
    close(pfd[1]);
    pid_t sleeper = start(child_sleeper);
    pid_t inherit = start(child_inherit_parent);
    pid_t zero = start(child_zero);
    pid_t late = start(child_late);
    pid_t worker = start(child_worker);

    int st = wait_status(def);
    TEST("soft limit raises SIGXCPU");
    if (st != -1 && WIFSIGNALED(st) && WTERMSIG(st) == SIGXCPU)
        PASS();
    else
        FAIL("child did not die of SIGXCPU");

    st = wait_status(sleeper);
    TEST("sleep is not CPU time");
    if (st != -1 && WIFEXITED(st) && WEXITSTATUS(st) == 0)
        PASS();
    else
        FAIL("sleeping child did not exit 0");

    /* Reaped first, so a child that outlives its limit is killed and closes the
     * pipe rather than leaving the read blocked.
     */
    st = wait_status(caught);
    char seen[8];
    ssize_t n = read_fd_all_nul(pfd[0], seen, sizeof(seen));

    TEST("SIGXCPU repeats each second");
    if (n == 4 && seen[0] == 2 && seen[2] == 3)
        PASS();
    else
        FAIL("expected handler to see soft limits 2 then 3");

    TEST("SIGXCPU is SI_KERNEL");
    if (n == 4 && seen[1] && seen[3])
        PASS();
    else
        FAIL("expected si_code SI_KERNEL and si_pid 0");

    TEST("hard limit raises SIGKILL");
    if (st != -1 && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL)
        PASS();
    else
        FAIL("child did not die of SIGKILL");

    st = wait_status(zero);
    TEST("{0, 0} raises SIGKILL at once");
    if (st != -1 && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL)
        PASS();
    else
        FAIL("child did not die of SIGKILL");

    st = wait_status(inherit);
    TEST("inherited soft limit raises SIGXCPU");
    if (st != -1 && WIFEXITED(st) && WEXITSTATUS(st) == 0)
        PASS();
    else
        FAIL("fork child did not die of SIGXCPU");

    st = wait_status(late);
    TEST("soft limit far behind catches up");
    if (st != -1 && WIFEXITED(st) &&
        (WEXITSTATUS(st) == 0 || WEXITSTATUS(st) == 2))
        PASS();
    else
        FAIL("expected handler to see rising soft limits ending at 4");

    TEST("soft limit far behind rises one step");
    if (st != -1 && WIFEXITED(st) && WEXITSTATUS(st) == 0)
        PASS();
    else
        FAIL("soft limit reached 4 within 1 ms of the lowering");

    st = wait_status(worker);
    TEST("hard limit kills a sleeping leader");
    if (st != -1 && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL)
        PASS();
    else
        FAIL("process did not die of SIGKILL");

    SUMMARY("test-rlimit-cpu");
    return fails ? 1 : 0;
}
