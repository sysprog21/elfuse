/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

static int passes, fails;

static void require(int ok, const char *message)
{
    if (!ok) {
        perror(message);
        exit(2);
    }
}

static sigset_t signal_set(int signum)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signum);
    return set;
}

static timer_t create_timer(int signum, int payload)
{
    struct sigevent event = {
        .sigev_notify = SIGEV_SIGNAL,
        .sigev_signo = signum,
        .sigev_value.sival_int = payload,
    };
    timer_t timer;
    require(timer_create(CLOCK_MONOTONIC, &event, &timer) == 0, "timer_create");
    return timer;
}

static void arm_timer(timer_t timer, int periodic)
{
    struct itimerspec value = {
        .it_value.tv_nsec = 10000000,
        .it_interval.tv_nsec = periodic ? 100000000 : 0,
    };
    require(timer_settime(timer, 0, &value, NULL) == 0, "timer_settime");
}

static void expire_timers(void)
{
    struct timespec delay = {.tv_nsec = 350000000};
    require(nanosleep(&delay, NULL) == 0, "nanosleep");
}

static int take_signal(int signum, siginfo_t *info)
{
    sigset_t set = signal_set(signum);
    struct timespec timeout = {.tv_nsec = 100000000};
    return sigtimedwait(&set, info, &timeout);
}

static void test_create(void)
{
    /* Use the kernel ABI: libc can reject a bad signal before timer_create. */
    int signals[] = {0, -1, 65, INT_MAX, 1, 64};
    for (unsigned i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
        struct sigevent event = {
            .sigev_notify = SIGEV_SIGNAL,
            .sigev_signo = signals[i],
        };
        int id = -1;
        long rc = syscall(SYS_timer_create, CLOCK_MONOTONIC, &event, &id);
        int error = errno;
        if (rc == 0)
            syscall(SYS_timer_delete, id);
        TEST("timer signal range is 1..64");
        EXPECT_TRUE(signals[i] > 0 && signals[i] <= 64
                        ? rc == 0
                        : rc == -1 && error == EINVAL,
                    "wrong timer_create result");
    }

    struct sigevent event = {.sigev_notify = SIGEV_NONE};
    timer_t timer;
    TEST("CLOCK_BOOTTIME is accepted");
    int rc = timer_create(CLOCK_BOOTTIME, &event, &timer);
    EXPECT_EQ(rc, 0, "CLOCK_BOOTTIME rejected");
    if (rc == 0)
        timer_delete(timer);

    require(timer_create(CLOCK_MONOTONIC, &event, &timer) == 0,
            "create silent timer");
    arm_timer(timer, 1);
    expire_timers();
    struct itimerspec value;
    TEST("silent periodic timer advances");
    EXPECT_TRUE(timer_gettime(timer, &value) == 0 &&
                    value.it_value.tv_sec == 0 && value.it_value.tv_nsec > 0 &&
                    value.it_value.tv_nsec <= 100000000,
                "silent timer did not advance");
    struct itimerspec stop = {.it_interval.tv_sec = 1};
    require(timer_settime(timer, 0, &stop, &value) == 0, "disarm timer");
    TEST("settime returns the old interval");
    EXPECT_EQ(value.it_interval.tv_nsec, 100000000, "old interval lost");
    TEST("disarm clears value and interval");
    EXPECT_TRUE(timer_gettime(timer, &value) == 0 &&
                    value.it_value.tv_sec == 0 && value.it_value.tv_nsec == 0 &&
                    value.it_interval.tv_sec == 0 &&
                    value.it_interval.tv_nsec == 0,
                "disarmed timer retains an interval");
    timer_delete(timer);

    timer = create_timer(SIGUSR1, 71);
    struct itimerspec absolute = {0};
    require(clock_gettime(CLOCK_MONOTONIC, &absolute.it_value) == 0,
            "clock_gettime");
    absolute.it_value.tv_nsec += 10000000;
    if (absolute.it_value.tv_nsec >= 1000000000) {
        absolute.it_value.tv_sec++;
        absolute.it_value.tv_nsec -= 1000000000;
    }
    require(timer_settime(timer, TIMER_ABSTIME, &absolute, NULL) == 0,
            "arm absolute timer");
    expire_timers();
    siginfo_t info;
    TEST("absolute timer carries its payload");
    EXPECT_TRUE(take_signal(SIGUSR1, &info) == SIGUSR1 &&
                    info.si_code == SI_TIMER && info.si_value.sival_int == 71,
                "absolute timer notification missing");
    TEST("one-shot overrun is zero");
    EXPECT_EQ(timer_getoverrun(timer), 0, "unexpected overrun");
    timer_delete(timer);
}

static void test_notifications(int signum, int use_fd, int periodic)
{
    int count = signum == SIGUSR1 ? 2 : 33;
    sigset_t set = signal_set(signum);
    int fd = use_fd ? signalfd(-1, &set, SFD_NONBLOCK) : -1;
    require(!use_fd || fd >= 0, "signalfd");
    timer_t timers[33];
    for (int i = 0; i < count; i++) {
        timers[i] = create_timer(signum, i + 1);
        arm_timer(timers[i], periodic);
    }
    expire_timers();
    uint64_t seen = 0;
    int received = 0, metadata_ok = 1;
    while (received < count) {
        int payload, overrun;
        if (use_fd) {
            struct signalfd_siginfo info;
            ssize_t n = read(fd, &info, sizeof(info));
            if (n == -1 && errno == EAGAIN)
                break;
            require(n == sizeof(info), "read signalfd");
            metadata_ok &=
                info.ssi_signo == signum && info.ssi_code == SI_TIMER;
            payload = info.ssi_int;
            overrun = info.ssi_overrun;
        } else {
            siginfo_t info;
            if (take_signal(signum, &info) != signum)
                break;
            metadata_ok &= info.si_code == SI_TIMER;
            payload = info.si_value.sival_int;
            overrun = info.si_overrun;
        }
        require(payload > 0 && payload <= count, "timer payload");
        uint64_t bit = UINT64_C(1) << (payload - 1);
        metadata_ok &= !(seen & bit);
        seen |= bit;
        metadata_ok &= periodic ? overrun > 0 : overrun == 0;
        metadata_ok &= timer_getoverrun(timers[payload - 1]) == overrun;
        received++;
    }
    printf("  signal=%d signalfd=%d periodic=%d\n", signum, use_fd, periodic);
    TEST("each timer delivers once");
    EXPECT_EQ(received, count, "timer notification lost");
    TEST("payloads and overruns agree");
    EXPECT_TRUE(metadata_ok, "wrong payload or overrun");
    for (int i = 0; i < count; i++)
        timer_delete(timers[i]);
    if (fd >= 0)
        close(fd);
}

static void test_fairness(int signum)
{
    int count = signum == SIGUSR1 ? 3 : 33;
    sigset_t set = signal_set(signum);
    int fd = signalfd(-1, &set, SFD_NONBLOCK);
    require(fd >= 0, "signalfd");
    timer_t timers[33];
    for (int i = 0; i < count; i++) {
        timers[i] = create_timer(signum, i + 1);
        struct itimerspec value = {
            .it_value.tv_nsec = 1000000,
            .it_interval.tv_nsec = i + 1 < count ? 1 : 0,
        };
        require(timer_settime(timers[i], 0, &value, NULL) == 0,
                "timer_settime");
    }
    struct timespec delay = {.tv_nsec = 10000000};
    require(nanosleep(&delay, NULL) == 0, "nanosleep");
    int seen = 0;
    for (int i = 0; i < 2 * count && !seen; i++) {
        struct signalfd_siginfo info;
        ssize_t n = read(fd, &info, sizeof(info));
        if (n == -1 && errno == EAGAIN)
            break;
        require(n == sizeof(info), "read signalfd");
        seen = info.ssi_code == SI_TIMER && info.ssi_int == count;
    }
    printf("  signal=%d competing_timers=%d\n", signum, count - 1);
    TEST("fast periodic timers do not starve a one-shot");
    EXPECT_TRUE(seen, "one-shot notification starved");
    for (int i = 0; i < count; i++)
        timer_delete(timers[i]);
    siginfo_t info;
    while (take_signal(signum, &info) == signum)
        ;
    close(fd);
}

static void test_cleanup(int signum, int rearm)
{
    timer_t timer = create_timer(signum, 99);
    union sigval first = {.sival_int = 10}, last = {.sival_int = 20};
    siginfo_t info;
    if (signum >= SIGRTMIN) {
        /* Exercise cleanup with the retained entries across the ring's end. */
        for (int i = 0; i < 32; i++)
            require(sigqueue(getpid(), signum, first) == 0,
                    "queue first signal");
        for (int i = 0; i < 31; i++)
            require(take_signal(signum, &info) == signum,
                    "advance signal queue");
    }
    arm_timer(timer, 1);
    expire_timers();
    if (signum >= SIGRTMIN)
        require(sigqueue(getpid(), signum, last) == 0, "queue last signal");
    if (rearm) {
        struct itimerspec value = {.it_value.tv_sec = 60};
        require(timer_settime(timer, 0, &value, NULL) == 0, "rearm timer");
    } else {
        require(timer_delete(timer) == 0, "delete timer");
    }
    if (signum < SIGRTMIN)
        require(sigqueue(getpid(), signum, last) == 0, "queue last signal");
    if (signum >= SIGRTMIN) {
        TEST("cleanup preserves earlier signal");
        EXPECT_TRUE(take_signal(signum, &info) == signum &&
                        info.si_code == SI_QUEUE &&
                        info.si_value.sival_int == 10,
                    "earlier signal lost or reordered");
    }
    TEST(rearm ? "rearm discards stale notification"
               : "delete discards stale notification");
    EXPECT_TRUE(take_signal(signum, &info) == signum &&
                    info.si_code == SI_QUEUE && info.si_value.sival_int == 20,
                "stale timer signal or lost user signal");
    if (rearm) {
        arm_timer(timer, 0);
        expire_timers();
        TEST("new arm starts with zero overruns");
        EXPECT_TRUE(take_signal(signum, &info) == signum &&
                        info.si_code == SI_TIMER && info.si_overrun == 0 &&
                        timer_getoverrun(timer) == 0,
                    "old arm changed new arm accounting");
        timer_delete(timer);
    }
    while (take_signal(signum, &info) == signum)
        ;
}

static void test_exec(const char *path)
{
    pid_t child = fork();
    require(child >= 0, "fork");
    if (child == 0) {
        timer_t standard = create_timer(SIGUSR1, 1);
        timer_t realtime = create_timer(SIGRTMIN, 2);
        arm_timer(standard, 0);
        arm_timer(realtime, 0);
        expire_timers();
        union sigval value = {.sival_int = 42};
        require(sigqueue(getpid(), SIGRTMIN, value) == 0, "queue user signal");
        execl(path, path, "exec-child", NULL);
        _exit(2);
    }
    int status;
    require(waitpid(child, &status, 0) == child, "waitpid");
    TEST("exec drops timers, keeps user signal");
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "exec retained a timer signal or lost the user signal");
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    sigset_t blocked = signal_set(SIGUSR1);
    sigaddset(&blocked, SIGRTMIN);
    require(sigprocmask(SIG_BLOCK, &blocked, NULL) == 0, "block signals");
    if (argc > 1 && strcmp(argv[1], "exec-child") == 0) {
        siginfo_t info;
        int ok = take_signal(SIGRTMIN, &info) == SIGRTMIN &&
                 info.si_code == SI_QUEUE && info.si_value.sival_int == 42;
        sigprocmask(SIG_UNBLOCK, &blocked, NULL);
        return !ok;
    }
    if (argc > 1 && strcmp(argv[1], "elfuse") == 0) {
        /* Older Linux kernels keep a queued signal after delete or rearm. */
        for (int rearm = 0; rearm < 2; rearm++) {
            test_cleanup(SIGUSR1, rearm);
            test_cleanup(SIGRTMIN, rearm);
        }
        struct sigevent event = {
            .sigev_notify = SIGEV_THREAD_ID,
            .sigev_signo = SIGUSR1,
        };
#ifdef __GLIBC__
        event._sigev_un._tid = getpid();
#else
        event.sigev_notify_thread_id = getpid();
#endif
        int id;
        TEST("thread notification reports ENOSYS");
        EXPECT_ERRNO(syscall(SYS_timer_create, CLOCK_MONOTONIC, &event, &id),
                     ENOSYS, "unsupported notification misreported");
    } else {
        test_create();
        for (int periodic = 0; periodic < 2; periodic++) {
            for (int use_fd = 0; use_fd < 2; use_fd++) {
                test_notifications(SIGUSR1, use_fd, periodic);
                test_notifications(SIGRTMIN, use_fd, periodic);
            }
        }
        test_fairness(SIGUSR1);
        test_fairness(SIGRTMIN);
        test_exec(argv[0]);
    }
    SUMMARY("test-posix-timers");
    return fails != 0;
}
