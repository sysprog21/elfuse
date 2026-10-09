/*
 * execve handed from a worker thread to the group leader
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse cannot destroy the main host thread, so an execve issued from a
 * sibling is published to the leader and run on its vCPU. Getting the leader
 * out of whatever it is parked in is part of that handoff, and this holds the
 * two things the guest must not be able to see happen to it.
 *
 * 1. The leader's own blocking syscall is not collateral. Linux returns EINTR
 *    only when a signal was delivered, and none is here, so a read() parked
 *    across a failing handoff has to come back with its data, not -EINTR.
 * 2. A fork in flight on a third thread does not turn the exec fatal. The
 *    forker's siblings sit in a barrier that only the forker releases, and a
 *    teardown armed underneath it would wait on threads that cannot answer.
 *    The forker's SIGCHLDs double as cover for the other half of case 1: a
 *    signal that is merely queued and then discarded must not suppress the
 *    restart, or the bare EINTR comes straight back.
 * 3. A signal delivered on top of a handoff leaves the guest with a result it
 *    can read. The restart is armed before the signal is known, so delivery
 *    has to take it back off; a half-undone restart would return the syscall's
 *    own first argument in place of a result.
 * 4. Two threads calling execve at once both finish. There is one handoff
 *    slot, and a requester that waits for it while holding mmap_lock deadlocks
 *    against the leader, which needs that lock to run the request that frees
 *    the slot.
 * 5. A wait the guest gave a timeout still expires. The restart re-runs the
 *    original arguments, so a relative timeout would start again from zero and
 *    a guest whose siblings hand off execve faster than the timeout would never
 *    see it fire.
 * 6. A connect issued once stays a connect issued once. It is the one syscall
 *    here that leaves host state behind before it waits, so a restart re-issues
 *    it against a socket that has moved on, and the errno that comes back
 *    (EALREADY, or EISCONN once the handshake lands) is one Linux does not give
 *    a caller that connected once. Measured before the fix: about 60% of a
 *    connect loop under exec pressure reported EISCONN, against 4000/4000
 *    clean on a real kernel.
 *
 * Every case execs a path that does not exist, so the handoff fails before its
 * point of no return and the leader stays in the original image to be checked.
 *
 * Syscalls exercised: execve(221), clone(220), read(63), write(64), pipe2(59),
 *                     wait4(260), rt_sigaction(134), tgkill(131),
 *                     nanosleep(101), futex(98), rt_sigtimedwait(137),
 *                     socket(198), connect(203), accept4(242)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <linux/futex.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

extern char **environ;

static int pipe_rd = -1, pipe_wr = -1;
static atomic_int leader_parked;

/* Read one byte, retrying the interruption that is not this file's subject. A
 * sibling thread exiting arms a process-wide one-shot that makes the next
 * blocking wait anywhere in the guest report EINTR, which elfuse does on
 * purpose to mirror SIGCHLD on thread exit. Only case 1 treats an EINTR as the
 * failure, and it reads directly rather than through this.
 *
 * Returns the read result with EINTR filtered out.
 */
static ssize_t read_byte_retrying(int fd, char *out)
{
    ssize_t n;

    do {
        n = read(fd, out, 1);
    } while (n < 0 && errno == EINTR);

    return n;
}

/* Workers report here rather than into the harness counter: fails is a plain
 * int the main thread owns, and two threads incrementing it is a data race that
 * can drop the very failure this test exists to report. Folded in after the
 * join.
 */
static atomic_int worker_fails;
static atomic_int handler_ran;
static pthread_t leader_tid;

static void usr1_handler(int sig)
{
    (void) sig;
    atomic_fetch_add(&handler_ran, 1);
}

/* Same handoff as doomed_exec_worker, with a signal aimed at the leader so the
 * two land together: the epilogue arms a restart for the handoff, then the
 * delivery cancels it. Signal first, so it is queued before the leader leaves
 * its wait.
 */
static void *signal_and_exec_worker(void *arg)
{
    (void) arg;

    while (!atomic_load(&leader_parked))
        sched_yield();
    usleep(50000);

    pthread_kill(leader_tid, SIGUSR1);

    char *argv[] = {(char *) "/nonexistent/elfuse-exec-handoff", NULL};
    execve(argv[0], argv, environ);
    if (errno != ENOENT) {
        atomic_fetch_add(&worker_fails, 1);
        printf("\nworker execve errno %d, want ENOENT\n", errno);
    }

    char c = 'x';
    if (write(pipe_wr, &c, 1) != 1) {
        atomic_fetch_add(&worker_fails, 1);
        printf("\nwrite to wake the leader failed\n");
    }

    return NULL;
}

/* The leader's read must end in one of the two states Linux can produce: the
 * byte, or EINTR with the handler having run. A cancel that restored ELR_EL1
 * without X0 would resume past the SVC carrying the read's own first argument,
 * so any other non-negative return is the failure this looks for.
 */
static void expect_signal_cancels_cleanly(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = usr1_handler;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        FAIL("sigaction(SIGUSR1) failed");
        return;
    }

    leader_tid = pthread_self();
    atomic_store(&worker_fails, 0);
    atomic_store(&handler_ran, 0);

    int bad = 0, saw_eintr = 0, eintr_without_handler = 0;
    for (int i = 0; i < 30; i++) {
        /* Cleared per round: a handler that ran in an earlier one would
         * otherwise answer for a round whose EINTR had no delivery.
         */
        atomic_store(&handler_ran, 0);
        pthread_t t;
        atomic_store(&leader_parked, 0);
        if (pthread_create(&t, NULL, signal_and_exec_worker, NULL) != 0) {
            FAIL("pthread_create(signal_and_exec) failed");
            return;
        }

        char c = 0;
        bool round_eintr = false;
        atomic_store(&leader_parked, 1);
        ssize_t n = read(pipe_rd, &c, 1);
        if (n < 0 && errno == EINTR) {
            saw_eintr++;
            round_eintr = true;

            /* The worker still wrote its byte; take it so the pipe stays
             * balanced for the next iteration.
             */
            ssize_t n2 = read_byte_retrying(pipe_rd, &c);
            if (n2 != 1 || c != 'x') {
                bad++;
                printf("\ndrain read returned %zd (c=%d), want the byte\n", n2,
                       (int) c);
            }
        } else if (n != 1 || c != 'x') {
            bad++;
            printf("\nleader read returned %zd (c=%d), want 1 or EINTR\n", n,
                   (int) c);
        }
        pthread_join(t, NULL);

        /* Read after the round rather than at the EINTR: the guest runs the
         * handler on the way out of the syscall, so the count is still zero at
         * the moment the interrupted read returns.
         */
        if (round_eintr && atomic_load(&handler_ran) == 0)
            eintr_without_handler++;
    }

    signal(SIGUSR1, SIG_DFL);

    if (saw_eintr > 0 && eintr_without_handler > 0) {
        bad++;
        printf("\nread reported EINTR but no SIGUSR1 handler ran\n");
    }

    EXPECT_EQ(bad + atomic_load(&worker_fails), 0,
              "signal on top of a handoff left an unreadable result");
}

static void *doomed_exec_worker(void *arg)
{
    (void) arg;

    /* The leader publishes the flag just before it blocks, so give the read
     * itself time to reach the host call. Landing early only weakens the test:
     * the leader would not be parked and there would be nothing to interrupt.
     */
    while (!atomic_load(&leader_parked))
        sched_yield();
    usleep(50000);

    /* Fails before the point of no return (the path cannot be resolved), so the
     * leader that runs it survives and returns to this image.
     */
    char *argv[] = {(char *) "/nonexistent/elfuse-exec-handoff", NULL};
    execve(argv[0], argv, environ);
    if (errno != ENOENT) {
        atomic_fetch_add(&worker_fails, 1);
        printf("\nworker execve errno %d, want ENOENT\n", errno);
    }

    /* Release the leader whether or not the handoff behaved, so a failure
     * reports rather than hanging the suite.
     */
    char c = 'x';
    if (write(pipe_wr, &c, 1) != 1) {
        atomic_fetch_add(&worker_fails, 1);
        printf("\nwrite to wake the leader failed\n");
    }

    return NULL;
}

/* The leader parks here with no EINTR retry: a retry is what would hide the
 * bug. The read must return the byte the worker writes after its execve fails.
 */
static void expect_uninterrupted_read(void)
{
    char c = 0;
    atomic_store(&leader_parked, 1);
    ssize_t n = read(pipe_rd, &c, 1);

    if (n == 1 && c == 'x')
        PASS();
    else if (n < 0 && errno == EINTR)
        FAIL("leader read returned EINTR across a sibling execve");
    else
        FAIL("leader read returned neither the byte nor EINTR");
}

static void *forking_worker(void *arg)
{
    atomic_int *stop = arg;

    while (!atomic_load(stop)) {
        pid_t pid = fork();
        if (pid == 0)
            _exit(0);
        if (pid < 0 && errno == EINTR)
            continue;
        if (pid < 0) {
            atomic_fetch_add(&worker_fails, 1);
            printf("\nfork failed: %s\n", strerror(errno));
            return NULL;
        }
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
            ;
    }

    return NULL;
}

/* A fork snapshot parks every other thread in the fork barrier, which only the
 * forker releases. An exec teardown armed under an open window would wait on
 * threads that cannot answer it and take the post-PNR fatal. Run the two
 * against each other and require the process to still be here afterwards.
 */
static void expect_fork_and_exec_coexist(void)
{
    atomic_int stop = 0;
    pthread_t forker, execer;

    atomic_store(&worker_fails, 0);
    if (pthread_create(&forker, NULL, forking_worker, &stop) != 0) {
        FAIL("pthread_create(forker) failed");
        return;
    }

    int leader_fails = 0;
    for (int i = 0; i < 20; i++) {
        atomic_store(&leader_parked, 0);
        if (pthread_create(&execer, NULL, doomed_exec_worker, NULL) != 0) {
            FAIL("pthread_create(execer) failed");
            atomic_store(&stop, 1);
            pthread_join(forker, NULL);
            return;
        }

        char c = 0;
        atomic_store(&leader_parked, 1);
        ssize_t got = read_byte_retrying(pipe_rd, &c);
        if (got != 1) {
            leader_fails++;
            printf("\nleader read failed during the fork race\n");
        }
        pthread_join(execer, NULL);
    }

    atomic_store(&stop, 1);
    pthread_join(forker, NULL);

    EXPECT_EQ(leader_fails + atomic_load(&worker_fails), 0,
              "fork and execve on different threads diverged");
}

/* Keeps handing the leader an execve that fails, until told to stop. Unlike
 * doomed_exec_worker this does not synchronize with the leader: the point is
 * sustained handoff pressure across many connects, not one placed interruption.
 */
static void *exec_pressure_worker(void *arg)
{
    atomic_int *stop = arg;
    char *argv[] = {(char *) "/nonexistent/elfuse-exec-handoff", NULL};

    while (!atomic_load(stop))
        execve(argv[0], argv, environ);

    return NULL;
}

static int accept_listener = -1;
static atomic_int accept_stop;

static void *accept_worker(void *arg)
{
    (void) arg;

    while (!atomic_load(&accept_stop)) {
        int c = accept(accept_listener, NULL, NULL);
        if (c >= 0) {
            close(c);
            continue;
        }

        /* Retried like any real server would. A sibling thread exiting arms a
         * one-shot interrupt that the next blocking wait anywhere in the guest
         * reports as EINTR, so treating it as fatal would leave the listener
         * unattended, fill its backlog, and stall the connects this case is
         * measuring rather than the handoff it is about.
         */
        if (errno == EINTR)
            continue;
        return NULL;
    }

    return NULL;
}

/* Closing a listener does not reliably return a thread already blocked inside
 * accept(), on Linux or on macOS, so hand it one last connection instead and
 * let it observe the stop flag. Called with the pressure worker already joined,
 * so this connect runs without a handoff racing it.
 */
static void stop_accepter(int listener,
                          const struct sockaddr_in *addr,
                          pthread_t accepter)
{
    atomic_store(&accept_stop, 1);

    int waker = socket(AF_INET, SOCK_STREAM, 0);
    if (waker >= 0) {
        connect(waker, (const struct sockaddr *) addr, sizeof(*addr));
        close(waker);
    }
    pthread_join(accepter, NULL);
    close(listener);
}

/* Two requesters against the one handoff slot. The second has to wait for the
 * first to be serviced, and the leader has to be able to service it: with both
 * of them queued the lock the leader needs must not be one a waiting requester
 * is holding. Both threads must return from every execve they issue.
 */
static void *concurrent_exec_worker(void *arg)
{
    int *rounds = arg;
    char *argv[] = {(char *) "/nonexistent/elfuse-exec-handoff", NULL};

    for (int i = 0; i < 25; i++) {
        execve(argv[0], argv, environ);
        if (errno != ENOENT) {
            atomic_fetch_add(&worker_fails, 1);
            printf("\nconcurrent execve errno %d, want ENOENT\n", errno);
            return NULL;
        }
        (*rounds)++;
    }

    return NULL;
}

static void expect_concurrent_execves_finish(void)
{
    pthread_t a, b;
    int rounds_a = 0, rounds_b = 0;

    atomic_store(&worker_fails, 0);
    if (pthread_create(&a, NULL, concurrent_exec_worker, &rounds_a) != 0 ||
        pthread_create(&b, NULL, concurrent_exec_worker, &rounds_b) != 0) {
        FAIL("pthread_create(concurrent execve) failed");
        return;
    }
    pthread_join(a, NULL);
    pthread_join(b, NULL);

    /* Asserted separately rather than summed: a worker that failed on its last
     * round would contribute its failure back into a total of 50 and pass.
     */
    bool ok =
        rounds_a == 25 && rounds_b == 25 && atomic_load(&worker_fails) == 0;
    if (!ok)
        printf("\nrounds a=%d b=%d, failures=%d, want 25/25/0\n", rounds_a,
               rounds_b, atomic_load(&worker_fails));
    EXPECT_TRUE(ok, "concurrent execves did not both complete");
}

static double elapsed_ms(struct timespec *t0, struct timespec *t1)
{
    clock_gettime(CLOCK_MONOTONIC, t1);
    return (t1->tv_sec - t0->tv_sec) * 1000.0 +
           (t1->tv_nsec - t0->tv_nsec) / 1e6;
}

/* A timeout the guest supplied has to expire even while handoffs keep arriving.
 * Restarting the SVC re-runs the original relative timeout, so without an
 * opt-out the wait below never returns and the elapsed time runs away.
 */
static void expect_timeout_still_expires(void)
{
    atomic_int stop = 0;
    pthread_t pressure;

    atomic_store(&worker_fails, 0);
    if (pthread_create(&pressure, NULL, exec_pressure_worker, &stop) != 0) {
        FAIL("pthread_create(exec pressure) failed");
        return;
    }

    /* Retried on EINTR the way every libc sleep wrapper does, so what this
     * measures is whether the guest can finish the interval at all, not whether
     * any single call returns it.
     */
    struct timespec t0, t1, req = {0, 400 * 1000 * 1000}, rem;
    int interruptions = 0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    while (nanosleep(&req, &rem) != 0 && errno == EINTR) {
        req = rem;
        interruptions++;
    }
    double sleep_ms = elapsed_ms(&t0, &t1);

    /* The other two relative-timeout waits reach the same hazard through
     * different code: a plain FUTEX_WAIT, whose timeout is relative where
     * FUTEX_WAIT_BITSET's is absolute, and sigtimedwait, which spends its
     * timeout in a chunk loop of its own. Neither is retried here, because one
     * bounded return is the whole question.
     */
    int word = 0;
    struct timespec rel = {1, 0};
    clock_gettime(CLOCK_MONOTONIC, &t0);
    syscall(SYS_futex, &word, FUTEX_WAIT, 0, &rel, NULL, 0);
    double futex_ms = elapsed_ms(&t0, &t1);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    rel.tv_sec = 1;
    rel.tv_nsec = 0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    sigtimedwait(&set, NULL, &rel);
    double sigwait_ms = elapsed_ms(&t0, &t1);

    atomic_store(&stop, 1);
    pthread_join(pressure, NULL);

    /* The interruption count is reported, not asserted. On elfuse a handoff
     * breaks the sleep and it is non-zero; on a real kernel there is no handoff
     * to break it and zero is the right answer, which is why the timings rather
     * than the count are what both have to satisfy. Linux measures 403 ms, 1002
     * ms and 1000 ms here, all of them expiring on schedule.
     */
    bool ok = sleep_ms >= 400 && sleep_ms <= 3000 && futex_ms <= 3000 &&
              sigwait_ms <= 3000;
    if (!ok)
        printf(
            "\nsleep %.0fms (%d interruptions), futex %.0fms, "
            "sigtimedwait %.0fms\n",
            sleep_ms, interruptions, futex_ms, sigwait_ms);
    EXPECT_TRUE(ok, "a guest timeout did not expire on schedule");
}

/* A blocking connect that the guest issued once must report what Linux reports:
 * success. EINTR is the bug this file exists for; EALREADY and EISCONN are the
 * host's answer to elfuse re-issuing the call, which the guest never asked for
 * and must never see.
 */
static void expect_connect_survives_handoff(void)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t addrlen = sizeof(addr);

    if (listener < 0 ||
        bind(listener, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
        listen(listener, 64) < 0 ||
        getsockname(listener, (struct sockaddr *) &addr, &addrlen) < 0) {
        FAIL("listener setup failed");
        if (listener >= 0)
            close(listener);
        return;
    }

    atomic_int stop = 0;
    pthread_t pressure, accepter;
    accept_listener = listener;
    atomic_store(&accept_stop, 0);
    if (pthread_create(&accepter, NULL, accept_worker, NULL) != 0) {
        FAIL("pthread_create(accepter) failed");
        close(listener);
        return;
    }
    if (pthread_create(&pressure, NULL, exec_pressure_worker, &stop) != 0) {
        FAIL("pthread_create(exec pressure) failed");
        stop_accepter(listener, &addr, accepter);
        return;
    }

    int bad = 0, bad_errno = 0;
    for (int i = 0; i < 400; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0)
            continue;
        if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
            if (!bad)
                bad_errno = errno;
            bad++;
        }
        close(s);
    }

    atomic_store(&stop, 1);
    pthread_join(pressure, NULL);
    stop_accepter(listener, &addr, accepter);

    if (bad)
        printf("\n%d of 400 connects failed, first errno=%d\n", bad, bad_errno);
    EXPECT_EQ(bad, 0, "connect reported the host's retry state to the guest");
}

int main(void)
{
    int fds[2];
    if (pipe2(fds, 0) != 0) {
        FAIL("pipe2 failed");
        return 1;
    }
    pipe_rd = fds[0];
    pipe_wr = fds[1];

    printf("test-exec-handoff: execve handed from a worker to the leader\n");

    pthread_t t;
    TEST("leader read across a failed handoff");
    if (pthread_create(&t, NULL, doomed_exec_worker, NULL) != 0) {
        FAIL("pthread_create failed");
        return 1;
    }
    expect_uninterrupted_read();
    pthread_join(t, NULL);
    fails += atomic_exchange(&worker_fails, 0);

    TEST("fork and handoff on separate threads");
    expect_fork_and_exec_coexist();

    TEST("signal delivered on top of a handoff");
    expect_signal_cancels_cleanly();

    TEST("two threads execing at once");
    expect_concurrent_execves_finish();

    TEST("guest timeout expires under handoff pressure");
    expect_timeout_still_expires();

    TEST("connect under sustained handoff pressure");
    expect_connect_survives_handoff();

    SUMMARY("test-exec-handoff");
    return fails > 0 ? 1 : 0;
}
