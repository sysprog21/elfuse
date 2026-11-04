/*
 * Test rt_sigtimedwait (SYS 137)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Verifies:
 * 1. sigwait() consumes a pending signal synchronously.
 * 2. sigwaitinfo() returns the correct signal number and
 *    populates siginfo_t.
 * 3. sigtimedwait() with a zero timeout returns EAGAIN when
 *    no signal is pending (poll-once semantic).
 * 4. sigtimedwait() with a short timeout returns EAGAIN after
 *    expiry when no signal arrives.
 * 5. A signal sent from another thread is consumed by
 *    sigwaitinfo() in the waiting thread.
 * 6. A timed wait parks instead of polling.
 * 7. A POSIX timer wakes timed and untimed waits.
 * 8. A fast periodic timer whose signal is already pending does
 *    not make a wait for another signal wake once per period.
 * 9. alarm() delivers SIGALRM to a single-threaded wait for it.
 * 10. A far-off ITIMER_REAL does not disturb a short timed wait.
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, fmt, ...)                         \
    do {                                              \
        if (!(cond)) {                                \
            printf("FAIL: " fmt "\n", ##__VA_ARGS__); \
            failures++;                               \
        }                                             \
    } while (0)

/* Test 1: sigwait() consumes a pending SIGUSR1 */
static void test_sigwait_basic(void)
{
    printf("test-sigtimedwait: 1. sigwait basic... ");

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);

    /* Queue SIGUSR1 to ourselves so it is pending. */
    kill(getpid(), SIGUSR1);

    int sig = 0;
    int rc = sigwait(&set, &sig);
    CHECK(rc == 0, "sigwait returned %d (errno %d)", rc, errno);
    CHECK(sig == SIGUSR1, "sigwait returned sig %d, expected %d", sig, SIGUSR1);

    sigprocmask(SIG_UNBLOCK, &set, NULL);
    printf("PASS\n");
}

/* Test 2: sigwaitinfo() populates siginfo_t */
static void test_sigwaitinfo_info(void)
{
    printf("test-sigtimedwait: 2. sigwaitinfo populates siginfo... ");

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    sigprocmask(SIG_BLOCK, &set, NULL);

    kill(getpid(), SIGUSR2);

    siginfo_t info;
    memset(&info, 0, sizeof(info));
    int rc = sigwaitinfo(&set, &info);
    CHECK(rc == SIGUSR2, "sigwaitinfo returned %d, expected %d", rc, SIGUSR2);
    CHECK(info.si_signo == SIGUSR2, "si_signo=%d, expected %d", info.si_signo,
          SIGUSR2);

    sigprocmask(SIG_UNBLOCK, &set, NULL);
    printf("PASS\n");
}

/* Test 3: sigtimedwait() poll-once (zero timeout) -> EAGAIN */
static void test_sigtimedwait_poll_eagain(void)
{
    printf("test-sigtimedwait: 3. zero timeout EAGAIN... ");

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);

    /* No signal queued. */
    struct timespec zero = {0, 0};
    siginfo_t info;
    int rc = sigtimedwait(&set, &info, &zero);
    CHECK(rc == -1 && errno == EAGAIN, "expected EAGAIN, got rc=%d errno=%d",
          rc, errno);

    sigprocmask(SIG_UNBLOCK, &set, NULL);
    printf("PASS\n");
}

/* Test 4: sigtimedwait() with short timeout -> EAGAIN after expiry */
static void test_sigtimedwait_timeout(void)
{
    printf("test-sigtimedwait: 4. short timeout EAGAIN... ");

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);

    /* 20ms timeout; no signal will arrive. */
    struct timespec ts = {0, 20000000};
    siginfo_t info;
    int rc = sigtimedwait(&set, &info, &ts);
    CHECK(rc == -1 && errno == EAGAIN, "expected EAGAIN, got rc=%d errno=%d",
          rc, errno);

    sigprocmask(SIG_UNBLOCK, &set, NULL);
    printf("PASS\n");
}

/* Test 5: signal sent from another thread is consumed by sigwaitinfo */
static pthread_t waiter_tid;

static void *sender_fn(void *arg)
{
    (void) arg;
    /* Give the main thread time to enter sigwaitinfo. */
    struct timespec ts = {0, 50000000}; /* 50ms */
    nanosleep(&ts, NULL);
    pthread_kill(waiter_tid, SIGUSR1);
    return NULL;
}

static void test_sigwaitinfo_thread(void)
{
    printf("test-sigtimedwait: 5. cross-thread sigwaitinfo... ");

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    /* Block SIGUSR1 so it does not fire the default handler. */
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    waiter_tid = pthread_self();

    pthread_t sender;
    pthread_create(&sender, NULL, sender_fn, NULL);

    /* Wait up to 2 seconds for SIGUSR1. */
    struct timespec ts = {2, 0};
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    int rc = sigtimedwait(&set, &info, &ts);

    pthread_join(sender, NULL);

    CHECK(rc == SIGUSR1, "sigtimedwait returned %d (errno %d)", rc, errno);
    if (rc == SIGUSR1)
        CHECK(info.si_signo == SIGUSR1, "si_signo=%d", info.si_signo);

    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
    printf("PASS\n");
}

/* */

/* Test 6: a timed wait parks instead of polling. The old 1 ms poll cost about 9
 * ms of process CPU per second of waiting; a parked wait costs well under 1.
 */
static void test_sigtimedwait_parks(void)
{
    printf("test-sigtimedwait: 6. wait does not burn CPU... ");

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    sigprocmask(SIG_BLOCK, &set, NULL);

    struct timespec ts = {1, 0}, c0, c1;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &c0);
    int rc = sigtimedwait(&set, NULL, &ts);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &c1);
    CHECK(rc == -1 && errno == EAGAIN, "expected EAGAIN, got rc=%d errno=%d",
          rc, errno);
    long cpu_us =
        (c1.tv_sec - c0.tv_sec) * 1000000L + (c1.tv_nsec - c0.tv_nsec) / 1000;
    CHECK(cpu_us < 4000, "1 s wait used %ld us of CPU", cpu_us);

    sigprocmask(SIG_UNBLOCK, &set, NULL);
    printf("PASS\n");
}

/* Test 7: a POSIX timer armed before the wait wakes sigwaitinfo and
 * sigtimedwait promptly.
 */
static void test_timer_wait(void)
{
    printf("test-sigtimedwait: 7. timer wakes wait... ");
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    struct sigevent event = {.sigev_notify = SIGEV_SIGNAL,
                             .sigev_signo = SIGUSR1};
    int timer;
    if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &event, &timer) != 0) {
        CHECK(0, "timer_create failed: %d", errno);
        sigprocmask(SIG_UNBLOCK, &set, NULL);
        return;
    }
    for (int timed = 0; timed < 2; timed++) {
        struct itimerspec arm = {.it_value = {0, 50000000}};
        struct timespec start, end, timeout = {2, 0};
        if (syscall(SYS_timer_settime, timer, 0, &arm, NULL) != 0) {
            CHECK(0, "timer_settime failed: %d", errno);
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &start);
        int rc = timed ? sigtimedwait(&set, NULL, &timeout)
                       : sigwaitinfo(&set, NULL);
        clock_gettime(CLOCK_MONOTONIC, &end);
        long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000L +
                          (end.tv_nsec - start.tv_nsec) / 1000000;
        CHECK(rc == SIGUSR1 && elapsed_ms < 700,
              "timer wait rc=%d elapsed=%ld ms", rc, elapsed_ms);
    }
    syscall(SYS_timer_delete, timer);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    printf("PASS\n");
}

/* Test 8: a fast periodic timer whose signal is already pending must not make a
 * wait for a different signal wake once per period.
 */
static void test_timer_pending_no_spin(void)
{
    printf("test-sigtimedwait: 8. pending timer does not spin... ");
    sigset_t set, other;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigemptyset(&other);
    sigaddset(&other, SIGUSR2);
    sigprocmask(SIG_BLOCK, &set, NULL);
    sigprocmask(SIG_BLOCK, &other, NULL);
    struct sigevent event = {.sigev_notify = SIGEV_SIGNAL,
                             .sigev_signo = SIGUSR1};
    int timer;
    if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &event, &timer) != 0) {
        CHECK(0, "timer_create failed: %d", errno);
        goto out;
    }
    struct itimerspec arm = {.it_value = {0, 200000},
                             .it_interval = {0, 200000}};
    if (syscall(SYS_timer_settime, timer, 0, &arm, NULL) != 0) {
        CHECK(0, "timer_settime failed: %d", errno);
    } else {
        usleep(10000); /* let SIGUSR1 become pending */
        struct timespec ts = {0, 500000000}, c0, c1;
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &c0);
        int rc = sigtimedwait(&other, NULL, &ts);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &c1);
        CHECK(rc == -1 && errno == EAGAIN, "expected EAGAIN, got rc=%d", rc);
        long cpu_us = (c1.tv_sec - c0.tv_sec) * 1000000L +
                      (c1.tv_nsec - c0.tv_nsec) / 1000;
        CHECK(cpu_us < 3000, "0.5 s wait used %ld us of CPU", cpu_us);
    }
    syscall(SYS_timer_delete, timer);
out:
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    sigprocmask(SIG_UNBLOCK, &other, NULL);
    printf("PASS\n");
}

/* Test 9: ITIMER_REAL is advanced by the wait itself, so a lone thread parked
 * on SIGALRM sees it at the alarm instant rather than timing out.
 */
static void test_alarm_wait(void)
{
    printf("test-sigtimedwait: 9. alarm wakes wait... ");

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigprocmask(SIG_BLOCK, &set, NULL);

    struct timespec ts = {3, 0}, t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    alarm(1);
    int rc = sigtimedwait(&set, NULL, &ts);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    CHECK(rc == SIGALRM, "expected SIGALRM, got rc=%d errno=%d", rc, errno);
    long ms =
        (t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;
    CHECK(ms < 2000, "alarm(1) wait took %ld ms", ms);

    alarm(0);
    signal(SIGALRM, SIG_IGN);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    signal(SIGALRM, SIG_DFL);
    printf("PASS\n");
}

/* Test 10: an expiry too far out to fit in nanoseconds must not overflow the
 * park bound; the short timeout still governs.
 */
static void test_far_itimer(void)
{
    printf("test-sigtimedwait: 10. far itimer, short timeout... ");

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    sigprocmask(SIG_BLOCK, &set, NULL);

    struct itimerval it = {{0, 0}, {20000000000L, 0}};
    setitimer(ITIMER_REAL, &it, NULL);
    struct timespec ts = {0, 100000000}, t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = sigtimedwait(&set, NULL, &ts);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    CHECK(rc == -1 && errno == EAGAIN, "expected EAGAIN, got rc=%d errno=%d",
          rc, errno);
    long ms =
        (t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;
    CHECK(ms >= 90 && ms < 1000, "100 ms wait took %ld ms", ms);

    memset(&it, 0, sizeof(it));
    setitimer(ITIMER_REAL, &it, NULL);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    printf("PASS\n");
}

int main(void)
{
    printf("test-sigtimedwait: starting\n");

    test_sigwait_basic();
    test_sigwaitinfo_info();
    test_sigtimedwait_poll_eagain();
    test_sigtimedwait_timeout();
    test_sigwaitinfo_thread();
    test_sigtimedwait_parks();
    test_timer_wait();
    test_timer_pending_no_spin();
    test_alarm_wait();
    test_far_itimer();

    int total = 10;
    int passed = total - failures;
    printf("test-sigtimedwait: %d passed, %d failed - %s\n", passed, failures,
           failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
