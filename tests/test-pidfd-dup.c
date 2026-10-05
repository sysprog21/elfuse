/*
 * Test that a dup of a pidfd names the same process as the original
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * dup, dup3 and F_DUPFD each hand back a second name for one pidfd. Every alias
 * must signal and wait on the same child, stay unreadable while the child runs
 * whichever alias is closed first, and turn readable when the child exits. The
 * fd table is the only limit on how many aliases there are, and a dup2 onto an
 * open fd succeeds however many pidfds are open. Closing a pidfd lets another
 * be opened in its place, and a dup that fails on EMFILE changes nothing.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "raw-syscall.h"
#include "test-harness.h"

#define __NR_pidfd_open_nr 434
#define __NR_pidfd_send_signal_nr 424
#define P_PIDFD_NR 3

/* More aliases, and more opens, than a table with one entry per pidfd holds. */
#define MANY 64

int passes = 0, fails = 0;

static bool readable(int fd, int timeout_ms)
{
    struct pollfd pv = {.fd = fd, .events = POLLIN};
    return poll(&pv, 1, timeout_ms) == 1 && (pv.revents & POLLIN);
}

static long probe(int fd)
{
    return raw_syscall4(__NR_pidfd_send_signal_nr, fd, 0, 0, 0);
}

/* Open pidfds on @pid into @fds until one fails or all MANY are open. The
 * failed call's negated errno is left in the slot after the last open one.
 */
static int open_many(pid_t pid, int *fds)
{
    int n = 0;
    for (; n < MANY; n++) {
        fds[n] = (int) raw_syscall2(__NR_pidfd_open_nr, (long) pid, 0);
        if (fds[n] < 0)
            break;
    }
    return n;
}

/* dup(@fd) with no fd number free: @fd holds the lowest free number, and the
 * limit is lowered to end just above it.
 *
 * Returns the errno of the failed dup, or 0 when the dup went through.
 */
static int dup_without_room(int fd)
{
    struct rlimit all, none;
    if (getrlimit(RLIMIT_NOFILE, &all) != 0)
        return 0;
    none = all;
    none.rlim_cur = (rlim_t) fd + 1;
    if (setrlimit(RLIMIT_NOFILE, &none) != 0)
        return 0;
    int alias = dup(fd);
    int err = alias < 0 ? errno : 0;
    setrlimit(RLIMIT_NOFILE, &all);
    if (alias >= 0)
        close(alias);
    return err;
}

int main(void)
{
    int gop[2];
    if (pipe(gop) < 0)
        return 1;

    pid_t child = fork();
    if (child < 0)
        return 1;
    if (child == 0) {
        /* Stay alive until the parent closes the other end. */
        close(gop[1]);
        uint8_t byte = 0;
        (void) read(gop[0], &byte, 1);
        _exit(7);
    }
    close(gop[0]);

    printf("test-pidfd-dup: aliases of one pidfd\n");

    int pfd = (int) raw_syscall2(__NR_pidfd_open_nr, (long) child, 0);
    int by_dup = dup(pfd);
    int by_dup3 = dup3(pfd, 100, O_CLOEXEC);
    int by_fcntl = fcntl(pfd, F_DUPFD, 50);

    TEST("pidfd_open, dup, dup3, F_DUPFD");
    EXPECT_TRUE(pfd >= 0 && by_dup >= 0 && by_dup3 == 100 && by_fcntl >= 50,
                "an alias was not created");

    TEST("signal 0 through each alias");
    EXPECT_TRUE(
        probe(by_dup) == 0 && probe(by_dup3) == 0 && probe(by_fcntl) == 0,
        "an alias does not name the child");

    int many[MANY];
    int made = 0;
    for (; made < MANY; made++) {
        many[made] = dup(pfd);
        if (many[made] < 0)
            break;
    }

    TEST("64 dups of one pidfd");
    EXPECT_TRUE(made == MANY && probe(many[MANY - 1]) == 0,
                "dup failed with room left in the fd table");
    for (int i = 0; i < made; i++)
        close(many[i]);

    /* As many as the host hands out: Linux all of them, elfuse a table's worth.
     * A stop for any other reason leaves the dup2 below with nothing to show.
     */
    int opened = open_many(child, many);

    TEST("pidfd_open stops only on EMFILE");
    EXPECT_TRUE(opened == MANY || many[opened] == -24 /* EMFILE */,
                "pidfd_open failed for another reason");

    int target = dup(gop[1]);
    int onto = dup2(pfd, target);

    TEST("dup2 onto an open fd");
    EXPECT_TRUE(target >= 0 && onto == target && probe(target) == 0,
                "dup2 failed, or closed its target");
    close(target);
    for (int i = 0; i < opened; i++)
        close(many[i]);

    /* Every pidfd above is closed, so as many can be opened again. */
    int reopened = open_many(child, many);

    TEST("closed pidfds can be opened again");
    EXPECT_EQ(reopened, opened, "a closed pidfd still counts as open");
    for (int i = 0; i < reopened; i++)
        close(many[i]);

    /* A dup that fails on EMFILE leaves its source as it was. If the failed dup
     * kept the pidfd open, the closes here would free nothing and pidfd_open
     * would fail before MANY rounds.
     */
    int kept = 0;
    for (int i = 0; i < MANY; i++) {
        int one = (int) raw_syscall2(__NR_pidfd_open_nr, (long) child, 0);
        if (one < 0 || dup_without_room(one) != EMFILE)
            kept++;
        if (one >= 0)
            close(one);
    }

    TEST("dup with no fd number free");
    EXPECT_EQ(kept, 0, "dup did not fail on EMFILE, or kept its pidfd open");

    close(pfd);
    close(by_dup3);

    TEST("closing the original leaves an alias unreadable");
    EXPECT_TRUE(!readable(by_dup, 100) && !readable(by_fcntl, 0),
                "an alias reports the live child exited");

    TEST("signal 0 after the original is closed");
    EXPECT_TRUE(probe(by_dup) == 0 && probe(by_fcntl) == 0,
                "an alias lost the child with the original");

    TEST("a closed alias number is not a pidfd");
    EXPECT_RAW_ERRNO(probe(by_dup3), -9 /* EBADF */, "closed alias answered");

    close(gop[1]);

    TEST("child exit makes every alias readable");
    EXPECT_TRUE(readable(by_dup, 10000) && readable(by_fcntl, 10000),
                "an alias missed the exit");

    siginfo_t info = {0};
    TEST("waitid(P_PIDFD) through an alias");
    EXPECT_TRUE(
        waitid((idtype_t) P_PIDFD_NR, (id_t) by_fcntl, &info, WEXITED) == 0 &&
            info.si_pid == child && info.si_status == 7,
        "waitid did not reap the child");

    close(by_dup);
    close(by_fcntl);

    SUMMARY("test-pidfd-dup");
    return fails > 0 ? 1 : 0;
}
