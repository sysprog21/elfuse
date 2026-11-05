/*
 * epoll_ctl decides EPERM from the target, not from the requested events
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * epoll_ctl(2) reports EPERM from the target alone: a target with no poll
 * support is refused whatever the event mask asks for, and a target that never
 * becomes writable still accepts EPOLLOUT. macOS kqueue disagrees in both
 * directions. It refuses a knote on a directory or a character device, refuses
 * EVFILT_WRITE on a kqueue (which is what a timerfd and a nested epoll fd are
 * here), and accepts one on a plain file that Linux refuses. This pins all
 * three against src/syscall/poll.c sys_epoll_ctl.
 *
 * Syscalls exercised: epoll_create1(20), epoll_ctl(21), epoll_pwait(22),
 *                     openat(56), close(57), pipe2(59),
 *                     timerfd_create(85), timerfd_settime(86)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/wait.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* ADD fd to a fresh epoll instance and report the raw result. */
static int add_to_fresh_epoll(int fd, uint32_t events)
{
    int epfd = epoll_create1(0);
    if (epfd < 0)
        return -1;
    struct epoll_event ev = {.events = events, .data.fd = fd};
    int rc = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    int saved = errno;
    close(epfd);
    errno = saved;
    return rc;
}

/* Closes @fd: every caller passes a freshly opened descriptor. */
static void expect_eperm(const char *label, int fd, uint32_t events)
{
    TEST(label);
    if (fd < 0) {
        FAIL("open failed");
        return;
    }
    EXPECT_ERRNO(add_to_fresh_epoll(fd, events), EPERM, "expected EPERM");
    close(fd);
}

/* Open @path and require the EPERM that Linux answers for it. */
static void expect_eperm_path(const char *path)
{
    TEST(path);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        FAIL("open failed");
        return;
    }
    EXPECT_ERRNO(add_to_fresh_epoll(fd, EPOLLIN), EPERM, "expected EPERM");
    close(fd);
}

/* Open @path and require that epoll_ctl accepts it. */
static void expect_accepted_path(const char *path)
{
    TEST(path);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        FAIL("open failed");
        return;
    }
    EXPECT_EQ(add_to_fresh_epoll(fd, EPOLLIN), 0, "target was refused");
    close(fd);
}

/* Run one operation on a never-registered target and check the errno. */
static void expect_op_errno(const char *label,
                            const char *path,
                            int op,
                            int expected)
{
    TEST(label);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        FAIL("open failed");
        return;
    }
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        FAIL("epoll_create1 failed");
        close(fd);
        return;
    }
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = fd};
    EXPECT_ERRNO(epoll_ctl(epfd, op, fd, &ev), expected, "wrong errno");
    close(epfd);
    close(fd);
}

/* Register @path for @events and require the readiness Linux reports for it.
 * @want is the event mask a zero-timeout wait must produce, or 0 for none.
 */
static void expect_ready(const char *label,
                         const char *path,
                         uint32_t events,
                         uint32_t want)
{
    TEST(label);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        FAIL("open failed");
        return;
    }
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        FAIL("epoll_create1 failed");
        close(fd);
        return;
    }
    struct epoll_event ev = {.events = events, .data.fd = fd};
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        FAIL("ADD was refused");
    } else {
        struct epoll_event out[2];
        int n = epoll_wait(epfd, out, 2, 0);
        if (want)
            EXPECT_TRUE(n == 1 && out[0].events == want, "wrong readiness");
        else
            EXPECT_EQ(n, 0, "expected no ready event");
    }
    close(epfd);
    close(fd);
}

/* Require the errno of one epoll_ctl against a target with no poll method, and
 * the errno of the same call against a pollable one. Linux decides EPERM from
 * the target before it validates either the op or the epoll descriptor, so the
 * pair is what shows the ordering rather than a lucky single answer.
 */
static void expect_outranks_einval(const char *label, int epfd, int op)
{
    TEST(label);
    int plain = open("/etc/hosts", O_RDONLY);
    int pipefd[2];
    if (plain < 0 || pipe(pipefd) != 0) {
        FAIL("setup failed");
        close(plain);
        return;
    }
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = plain};
    bool eperm = epoll_ctl(epfd, op, plain, &ev) == -1 && errno == EPERM;
    bool einval = epoll_ctl(epfd, op, pipefd[0], &ev) == -1 && errno == EINVAL;
    EXPECT_TRUE(eperm && einval, "EPERM does not outrank this EINVAL");
    close(pipefd[0]);
    close(pipefd[1]);
    close(plain);
}

static void expect_accepted(const char *label, int fd, uint32_t events)
{
    TEST(label);
    if (fd < 0) {
        FAIL("target fd unavailable");
        return;
    }
    EXPECT_EQ(add_to_fresh_epoll(fd, events), 0, "ADD was refused");
}

static void test_unsupported_targets(void)
{
    /* No poll support: EPERM whichever events are asked for. The EPOLLOUT-only
     * case is the one that cannot read the answer off the write filter alone.
     */
    expect_eperm("/dev/null EPOLLIN", open("/dev/null", O_RDWR), EPOLLIN);
    expect_eperm("/dev/null EPOLLOUT", open("/dev/null", O_RDWR), EPOLLOUT);
    expect_eperm("/dev/zero EPOLLIN", open("/dev/zero", O_RDONLY), EPOLLIN);
    expect_eperm("directory EPOLLIN|EPOLLOUT",
                 open("/", O_RDONLY | O_DIRECTORY), EPOLLIN | EPOLLOUT);

    /* The two random devices split, and not the way their names suggest.
     * random_fops carries .poll and urandom_fops does not, since a read from
     * urandom never waits, so Linux 6.12 accepts the first and answers EPERM
     * for the second. macOS refuses a knote on both, so nothing but the path
     * separates them here.
     */
    expect_eperm("/dev/urandom EPOLLIN", open("/dev/urandom", O_RDONLY),
                 EPOLLIN);
    expect_accepted("/dev/random EPOLLIN", open("/dev/random", O_RDONLY),
                    EPOLLIN);
    expect_accepted("/dev/random EPOLLOUT", open("/dev/random", O_RDONLY),
                    EPOLLOUT);
    expect_accepted("/dev/random EPOLLIN|EPOLLOUT",
                    open("/dev/random", O_RDONLY), EPOLLIN | EPOLLOUT);

    /* Accepting the registration is only half of it: no knote can carry the
     * readiness, so the wait has to answer from the registration itself. Linux
     * reports the pool readable and never writable.
     */
    expect_ready("/dev/random reports EPOLLIN", "/dev/random", EPOLLIN,
                 EPOLLIN);
    expect_ready("/dev/random reports no EPOLLOUT", "/dev/random", EPOLLOUT, 0);

    /* A plain file has no poll method on Linux. A fifo opened by path does, and
     * so does /proc/self/mountinfo, which is a plain file to fstat: both are
     * here because the obvious fd-type test would refuse them.
     */
    expect_eperm("regular file EPOLLIN", open("/etc/hosts", O_RDONLY), EPOLLIN);
    expect_eperm("regular file EPOLLOUT", open("/etc/hosts", O_RDONLY),
                 EPOLLOUT);

    /* A mask naming no readiness filter still has to consult the target: Linux
     * decides EPERM before it reads the event, so an empty mask is refused on
     * exactly the targets a full one is.
     */
    expect_eperm("/dev/null no filter", open("/dev/null", O_RDWR), 0);
    expect_eperm("directory no filter", open("/", O_RDONLY | O_DIRECTORY), 0);
    expect_eperm("regular file EPOLLET only", open("/etc/hosts", O_RDONLY),
                 EPOLLET);

    /* Linux tests the target's poll support before it looks at the operation,
     * so an unsupported target answers EPERM to MOD and DEL as well, while a
     * supported but unregistered one still answers ENOENT.
     */
    expect_op_errno("regular file MOD", "/etc/hosts", EPOLL_CTL_MOD, EPERM);
    expect_op_errno("regular file DEL", "/etc/hosts", EPOLL_CTL_DEL, EPERM);
    expect_op_errno("/dev/null MOD", "/dev/null", EPOLL_CTL_MOD, EPERM);
    expect_op_errno("/dev/null DEL", "/dev/null", EPOLL_CTL_DEL, EPERM);
    expect_op_errno("unregistered MOD", "/proc/self/mountinfo", EPOLL_CTL_MOD,
                    ENOENT);
    expect_op_errno("unregistered DEL", "/proc/self/mountinfo", EPOLL_CTL_DEL,
                    ENOENT);
}

static void test_path_classes(void)
{
    /* A private directory: guest pids restart at 1, so a pid-derived name was
     * the same name in every concurrent run.
     */
    char fifo_dir[] = "/tmp/elfuse-epoll-fifo-XXXXXX";
    TEST("fifo opened by path");
    if (!mkdtemp(fifo_dir)) {
        FAIL("mkdtemp failed");
    } else {
        char fifo_path[128];
        snprintf(fifo_path, sizeof(fifo_path), "%s/f", fifo_dir);
        if (mkfifo(fifo_path, 0600) != 0) {
            FAIL("mkfifo failed");
        } else {
            int ff = open(fifo_path, O_RDONLY | O_NONBLOCK);
            EXPECT_EQ(add_to_fresh_epoll(ff, EPOLLIN), 0, "fifo was refused");
            close(ff);
        }
        unlink(fifo_path);
        rmdir(fifo_dir);
    }

    /* Trees elfuse serves from ordinary host files. fstat calls every one of
     * them a plain file; Linux polls them, so the plain-file rule has to go by
     * the path classification rather than by fstat alone.
     */
    expect_accepted_path("/proc/self/mountinfo");
    expect_accepted_path("/proc/self/mounts");
    expect_accepted_path("/sys/devices/system/cpu/online");
    expect_accepted_path("/etc/mtab");
    expect_accepted_path("/proc/meminfo");
    expect_accepted_path("/proc/cpuinfo");
    expect_accepted_path("/proc/uptime");
    expect_accepted_path("/proc/net/dev");
    expect_accepted_path("/proc/sys/vm/mmap_min_addr");

    /* The same host storage, refused. A per-process procfs file is opened
     * through proc_single_file_operations, which carries no poll method, so
     * Linux answers EPERM for all of these while accepting the mount tables two
     * lines up. "elfuse staged this file" cannot tell the two groups apart,
     * which is why the classification goes by path.
     */
    expect_eperm_path("/proc/self/stat");
    expect_eperm_path("/proc/self/status");
    expect_eperm_path("/proc/self/maps");
    expect_eperm_path("/proc/self/smaps");
    expect_eperm_path("/proc/self/cmdline");
    expect_eperm_path("/proc/self/environ");
    expect_eperm_path("/proc/self/auxv");
    expect_eperm_path("/proc/self/io");
    expect_eperm_path("/proc/self/limits");
    expect_eperm_path("/proc/self/oom_score");
    expect_eperm_path("/proc/self/oom_score_adj");
    expect_eperm_path("/proc/self/fdinfo/0");
    expect_eperm_path("/etc/passwd");
    expect_eperm_path("/etc/group");

    /* The numeric spelling of the process directory reaches the same rule, and
     * carries the mount-table exception with it.
     */
    char pidpath[64];
    snprintf(pidpath, sizeof(pidpath), "/proc/%d/stat", (int) getpid());
    expect_eperm_path(pidpath);
    snprintf(pidpath, sizeof(pidpath), "/proc/%d/mountinfo", (int) getpid());
    expect_accepted_path(pidpath);
}

static int test_dup_and_magic_links(void)
{
    /* The marker belongs to the open file description, so a dup answers the
     * same way its source does. fd_init_entry clears it for every fresh slot,
     * which without the alias carry would make the copy read as a plain file.
     */
    TEST("dup of an intercepted open");
    int mntfd = open("/proc/self/mountinfo", O_RDONLY);
    if (mntfd < 0) {
        FAIL("open failed");
    } else {
        int dupfd = dup(mntfd);
        if (dupfd < 0) {
            FAIL("dup failed");
        } else {
            EXPECT_EQ(add_to_fresh_epoll(dupfd, EPOLLIN), 0, "dup was refused");
            close(dupfd);
        }
        close(mntfd);
    }
    int hostsfd = open("/etc/hosts", O_RDONLY);
    expect_eperm("dup of a regular file", hostsfd < 0 ? -1 : dup(hostsfd),
                 EPOLLIN);
    close(hostsfd);

    /* The other direction: an intercepted open Linux refuses stays refused
     * through the dup, so the carry cannot be a blanket "intercepted means
     * pollable" either.
     */
    int statfd = open("/proc/self/stat", O_RDONLY);
    expect_eperm("dup of a refused intercept", statfd < 0 ? -1 : dup(statfd),
                 EPOLLIN);
    close(statfd);

    /* Opening a magic link is a dup here and a reopen on Linux, so the answer
     * has to come from the description behind the link rather than from the
     * link's own path -- /proc/self/fd/N is a per-process procfs name whatever
     * it points at, and classifying it as one would refuse all four of these.
     */
    static const struct {
        const char *label, *path;
        bool accepted;
    } magic[] = {
        {"magic link to mountinfo", "/proc/self/mountinfo", true},
        {"magic link to /proc/self/stat", "/proc/self/stat", false},
        {"magic link to a regular file", "/etc/hosts", false},
        {"magic link to a pipe", NULL, true},
    };
    int pipefds[2];
    if (pipe(pipefds) < 0) {
        perror("pipe");
        return 1;
    }
    for (size_t i = 0; i < sizeof(magic) / sizeof(magic[0]); i++) {
        TEST(magic[i].label);
        int target = magic[i].path ? open(magic[i].path, O_RDONLY) : pipefds[0];
        if (target < 0) {
            FAIL("open failed");
            continue;
        }
        char link[64];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", target);
        int viafd = open(link, O_RDONLY);
        if (viafd < 0) {
            FAIL("magic link open failed");
        } else if (magic[i].accepted) {
            EXPECT_EQ(add_to_fresh_epoll(viafd, EPOLLIN), 0, "link refused");
        } else {
            EXPECT_ERRNO(add_to_fresh_epoll(viafd, EPOLLIN), EPERM,
                         "expected EPERM");
        }
        close(viafd);
        if (magic[i].path)
            close(target);
    }
    close(pipefds[0]);
    close(pipefds[1]);

    return 0;
}

static int test_timerfd_and_pipe(void)
{
    /* Never writable, still accepted. */
    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    expect_accepted("timerfd EPOLLOUT", tfd, EPOLLOUT);
    expect_accepted("timerfd EPOLLIN|EPOLLOUT", tfd, EPOLLIN | EPOLLOUT);
    int nested = epoll_create1(0);
    expect_accepted("nested epoll EPOLLOUT", nested, EPOLLOUT);
    close(nested);

    int p[2];
    if (pipe(p) < 0) {
        perror("pipe");
        return 1;
    }
    expect_accepted("pipe read end EPOLLIN", p[0], EPOLLIN);

    /* Reuse one instance across a probe. Registering only EPOLLOUT on a timerfd
     * runs the pollability probe, which adds and removes a disabled read knote
     * on this same kqueue. A later MOD to EPOLLIN still has to arm, which is
     * the shape a skipped probe delete would silently break.
     */
    TEST("MOD to EPOLLIN after a probe");
    int reuse = epoll_create1(0);
    int tfd2 = timerfd_create(CLOCK_MONOTONIC, 0);
    struct epoll_event out_only = {.events = EPOLLOUT, .data.fd = tfd2};
    struct epoll_event in_only = {.events = EPOLLIN, .data.fd = tfd2};
    if (reuse < 0 || tfd2 < 0 ||
        epoll_ctl(reuse, EPOLL_CTL_ADD, tfd2, &out_only) != 0 ||
        epoll_ctl(reuse, EPOLL_CTL_MOD, tfd2, &in_only) != 0) {
        FAIL("ADD or MOD refused");
    } else {
        struct itimerspec arm = {{0, 0}, {0, 50 * 1000 * 1000}};
        timerfd_settime(tfd2, 0, &arm, NULL);
        struct epoll_event got[2];
        EXPECT_TRUE(epoll_wait(reuse, got, 2, 2000) == 1, "timer never fired");
    }
    close(tfd2);
    close(reuse);

    /* A refused target must not poison the instance for later registrations. */
    TEST("instance usable after EPERM");
    int after = epoll_create1(0);
    int devnull = open("/dev/null", O_RDWR);
    struct epoll_event nul = {.events = EPOLLOUT, .data.fd = devnull};
    int refused = epoll_ctl(after, EPOLL_CTL_ADD, devnull, &nul) < 0;
    struct epoll_event again = {.events = EPOLLIN, .data.fd = p[0]};
    EXPECT_TRUE(refused && epoll_ctl(after, EPOLL_CTL_ADD, p[0], &again) == 0,
                "instance unusable after a refused target");
    close(devnull);
    close(after);

    /* A dropped write filter must not take the read filter with it: the timer
     * still has to report EPOLLIN and nothing else.
     */
    TEST("timerfd fires EPOLLIN only");
    int epfd = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT, .data.fd = tfd};
    if (epfd < 0 || epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev) != 0) {
        FAIL("ADD failed");
    } else {
        struct itimerspec its = {{0, 0}, {0, 50 * 1000 * 1000}};
        timerfd_settime(tfd, 0, &its, NULL);
        struct epoll_event out[2];
        int n = epoll_wait(epfd, out, 2, 2000);
        EXPECT_TRUE(n == 1 && out[0].events == EPOLLIN, "timer edge wrong");
    }
    close(epfd);
    close(tfd);
    close(p[0]);
    close(p[1]);

    return 0;
}

static void test_marker_survives_fork(void)
{
    /* The intercept marker travels in the fd table, which fork rebuilds over
     * IPC. A child that loses it would refuse a synthesized target its parent
     * accepts, so this pins both answers on the far side of a fork.
     */
    TEST("marker survives fork");
    int sysfd = open("/sys/devices/system/cpu/online", O_RDONLY);
    int regfd = open("/etc/hosts", O_RDONLY);
    if (sysfd < 0 || regfd < 0) {
        FAIL("open failed");
    } else {
        fflush(stdout);
        pid_t child = fork();
        if (child == 0) {
            int ok = add_to_fresh_epoll(sysfd, EPOLLIN) == 0 &&
                     add_to_fresh_epoll(regfd, EPOLLIN) == -1 && errno == EPERM;
            _exit(ok ? 0 : 1);
        }
        int status = 1;
        if (child > 0)
            waitpid(child, &status, 0);
        EXPECT_TRUE(child > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                    "child disagreed with the parent");
    }
    close(sysfd);
    close(regfd);
}

static void test_eperm_outranks_einval(void)
{
    /* do_epoll_ctl tests file_can_poll before is_file_epoll and before the op
     * switch, so a target with no poll method outranks both EINVALs this
     * syscall would otherwise answer first.
     */
    {
        int ep = epoll_create1(0);
        int notep = open("/etc/hosts", O_RDONLY);
        if (ep < 0 || notep < 0) {
            TEST("EPERM outranks EINVAL");
            FAIL("setup failed");
        } else {
            expect_outranks_einval("unknown op", ep, 99);
            expect_outranks_einval("epfd is not an epoll fd", notep,
                                   EPOLL_CTL_ADD);
        }
        close(ep);
        close(notep);
    }
}

int main(void)
{
    printf("epoll_ctl target-support tests\n");

    test_unsupported_targets();
    test_path_classes();
    if (test_dup_and_magic_links())
        return 1;
    if (test_timerfd_and_pipe())
        return 1;
    test_marker_survives_fork();
    test_eperm_outranks_einval();

    SUMMARY("test-epoll-unsupported");
    return fails > 0 ? 1 : 0;
}
