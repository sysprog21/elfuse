/*
 * Test guest rlimit state and the /proc/self/limits synthetic file
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Verifies that /proc/self/limits is readable and contains expected rows
 * matching prlimit64 values, and that a limit set through setrlimit or
 * prlimit64 reads back, crosses fork and execve, and can be reached by pid.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>

#include "test-harness.h"
#include "raw-syscall.h"

#define __NR_openat 56
#define __NR_read 63
#define __NR_close 57

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif
#define LINUX_O_RDONLY 0

int passes = 0, fails = 0;

/* One soft value per limit that no other limit uses, so a slot that aliases
 * another reads back wrong. Each is far above what this test consumes. NICE and
 * RTPRIO start with a hard limit of 0, which only root can raise, so they get
 * their own values in the runs that are root and stay 0 in the one that is not.
 */
static const struct {
    int resource;
    const char *name;
    rlim_t cur;
} tracked[] = {
    {RLIMIT_CPU, "RLIMIT_CPU round trip", 100000},
    {RLIMIT_FSIZE, "RLIMIT_FSIZE round trip", (rlim_t) 1 << 40},
    {RLIMIT_DATA, "RLIMIT_DATA round trip", (rlim_t) 1 << 41},
    {RLIMIT_STACK, "RLIMIT_STACK round trip", (rlim_t) 16 << 20},
    {RLIMIT_RSS, "RLIMIT_RSS round trip", (rlim_t) 1 << 42},
    {RLIMIT_MEMLOCK, "RLIMIT_MEMLOCK round trip", (rlim_t) 1 << 36},
    {RLIMIT_AS, "RLIMIT_AS round trip", (rlim_t) 1 << 43},
    {RLIMIT_LOCKS, "RLIMIT_LOCKS round trip", 1234567},
    {RLIMIT_SIGPENDING, "RLIMIT_SIGPENDING round trip", 97},
    {RLIMIT_MSGQUEUE, "RLIMIT_MSGQUEUE round trip", 4096},
    {RLIMIT_NICE, "RLIMIT_NICE round trip", 13},
    {RLIMIT_RTPRIO, "RLIMIT_RTPRIO round trip", 14},
    {RLIMIT_RTTIME, "RLIMIT_RTTIME round trip", 7654321},
};
#define N_TRACKED ((int) (sizeof(tracked) / sizeof(tracked[0])))

/* The soft value tracked[i] is set to: its own, or the hard limit if lower. The
 * hard limits are settled before the first child is made, so every process in
 * this test agrees.
 */
static rlim_t tracked_cur(int i)
{
    struct rlimit rl;
    if (getrlimit(tracked[i].resource, &rl) < 0)
        return 0;
    return tracked[i].cur > rl.rlim_max ? rl.rlim_max : tracked[i].cur;
}

/* Number of tracked limits whose soft value is not the one this test set. */
static int tracked_mismatches(void)
{
    int bad = 0;
    for (int i = 0; i < N_TRACKED; i++) {
        struct rlimit rl;
        if (getrlimit(tracked[i].resource, &rl) < 0 ||
            rl.rlim_cur != tracked_cur(i))
            bad++;
    }
    return bad;
}

/* Run @child_main in a fork child and return its exit status, or -1. */
static int run_child(int (*child_main)(void *), void *arg)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0)
        _exit(child_main(arg));
    int status = 0;
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static int child_reads_limits(void *arg)
{
    (void) arg;
    return tracked_mismatches();
}

static int child_execs_self(void *arg)
{
    char *argv[] = {arg, "after-exec", NULL};
    execv(argv[0], argv);
    return 127;
}

static void test_rlimit_state(char *self)
{
    /* Give NICE and RTPRIO room for a value of their own where that is allowed.
     */
    if (getuid() == 0) {
        struct rlimit room = {.rlim_cur = 0, .rlim_max = 40};
        setrlimit(RLIMIT_NICE, &room);
        setrlimit(RLIMIT_RTPRIO, &room);
    }

    for (int i = 0; i < N_TRACKED; i++) {
        struct rlimit rl, got = {0};
        TEST(tracked[i].name);
        rlim_t want = tracked_cur(i);
        if (getrlimit(tracked[i].resource, &rl) < 0) {
            FAIL("getrlimit failed");
            continue;
        }
        rl.rlim_cur = want;
        if (setrlimit(tracked[i].resource, &rl) < 0 ||
            getrlimit(tracked[i].resource, &got) < 0)
            FAIL("setrlimit then getrlimit failed");
        else
            EXPECT_TRUE(got.rlim_cur == want && got.rlim_max == rl.rlim_max,
                        "read-back differs from the value set");
    }

    /* macOS defines RLIMIT_RSS as RLIMIT_AS; the guest's two must not merge. */
    TEST("RSS and AS stay independent");
    {
        struct rlimit rss, as;
        if (getrlimit(RLIMIT_RSS, &rss) < 0 || getrlimit(RLIMIT_AS, &as) < 0)
            FAIL("getrlimit failed");
        else
            EXPECT_TRUE(rss.rlim_cur == (rlim_t) 1 << 42 &&
                            as.rlim_cur == (rlim_t) 1 << 43,
                        "RSS and AS read back the same slot");
    }

    TEST("fork child reads parent limits");
    EXPECT_EQ(run_child(child_reads_limits, NULL), 0,
              "child saw different limits");

    TEST("execve keeps limits");
    EXPECT_EQ(run_child(child_execs_self, self), 0,
              "image after execve saw different limits");

    TEST("prlimit64 on own pid");
    {
        struct rlimit rl = {0};
        if (prlimit(getpid(), RLIMIT_AS, NULL, &rl) < 0)
            FAIL("prlimit64 failed");
        else
            EXPECT_TRUE(rl.rlim_cur == (rlim_t) 1 << 43, "wrong soft limit");
    }

    TEST("prlimit64 on a dead pid is ESRCH");
    {
        struct rlimit rl;
        EXPECT_ERRNO(prlimit(999999, RLIMIT_AS, NULL, &rl), ESRCH,
                     "expected ESRCH");
    }

    TEST("soft above hard is EINVAL");
    {
        struct rlimit rl = {.rlim_cur = 2, .rlim_max = 1};
        EXPECT_ERRNO(setrlimit(RLIMIT_CPU, &rl), EINVAL, "expected EINVAL");
    }

    /* The child blocks on the pipe until the parent has changed its limit. */
    TEST("prlimit64 sets a child's limit");
    {
        int gate[2];
        struct rlimit own = {0}, old = {0}, after = {0};
        if (pipe(gate) < 0 || getrlimit(RLIMIT_CPU, &own) < 0) {
            FAIL("setup failed");
        } else {
            struct rlimit new = {.rlim_cur = own.rlim_cur - 1,
                                 .rlim_max = own.rlim_max};
            pid_t pid = fork();
            if (pid == 0) {
                char c;
                struct rlimit rl = {0};
                close(gate[1]);
                if (read(gate[0], &c, 1) != 1 || getrlimit(RLIMIT_CPU, &rl) < 0)
                    _exit(2);
                _exit(rl.rlim_cur == new.rlim_cur ? 0 : 1);
            }
            close(gate[0]);
            int rc = pid < 0 ? -1 : prlimit(pid, RLIMIT_CPU, &new, &old);
            int status = -1;
            (void) !write(gate[1], "x", 1);
            close(gate[1]);
            if (pid > 0)
                waitpid(pid, &status, 0);
            getrlimit(RLIMIT_CPU, &after);
            EXPECT_TRUE(rc == 0 && old.rlim_cur == own.rlim_cur &&
                            WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                            after.rlim_cur == own.rlim_cur,
                        "child limit not set, or parent limit moved");
        }
    }

    /* A child that has exited cannot be waited on to publish anything, so the
     * call returns at once. What it returns is not compared: Linux still has
     * the limits of a zombie and elfuse does not.
     */
    TEST("prlimit64 on an exited child is prompt");
    {
        struct rlimit rl;
        struct timespec t0, t1;
        siginfo_t info;
        pid_t pid = fork();
        if (pid == 0)
            _exit(0);

        /* Until it has exited, and without reaping it. */
        if (pid > 0)
            waitid(P_PID, (id_t) pid, &info, WEXITED | WNOWAIT);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        (void) prlimit(pid, RLIMIT_CPU, NULL, &rl);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long ms = (t1.tv_sec - t0.tv_sec) * 1000 +
                  (t1.tv_nsec - t0.tv_nsec) / 1000000;
        if (pid > 0)
            waitpid(pid, NULL, 0);
        EXPECT_TRUE(pid > 0 && ms < 500, "waited on a child that had exited");
    }
}

/* Read the soft and hard columns of the /proc/self/limits row named @name.
 * "unlimited" reads as RLIM_INFINITY.
 *
 * Returns 0, or -1 if the row is missing.
 */
static int limits_row(const char *name, struct rlimit *out)
{
    char buf[4096], soft[32], hard[32];
    int fd = open("/proc/self/limits", O_RDONLY);
    ssize_t n = fd < 0 ? -1 : read(fd, buf, sizeof(buf) - 1);
    if (fd >= 0)
        close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';

    const char *row = strstr(buf, name);
    if (!row || sscanf(row + strlen(name), "%31s %31s", soft, hard) != 2)
        return -1;
    out->rlim_cur =
        strcmp(soft, "unlimited") ? strtoull(soft, NULL, 10) : RLIM_INFINITY;
    out->rlim_max =
        strcmp(hard, "unlimited") ? strtoull(hard, NULL, 10) : RLIM_INFINITY;
    return 0;
}

/* test_rlimit_state left these limits at different soft values; each row must
 * show its own, the one getrlimit returns in this same run.
 */
static void test_limits_rows(void)
{
    static const struct {
        int resource;
        const char *row, *name;
    } checked[] = {
        {RLIMIT_AS, "Max address space", "address space row is RLIMIT_AS"},
        {RLIMIT_RSS, "Max resident set", "resident set row is RLIMIT_RSS"},
        {RLIMIT_FSIZE, "Max file size", "file size row is RLIMIT_FSIZE"},
        {RLIMIT_CPU, "Max cpu time", "cpu time row is RLIMIT_CPU"},
        {RLIMIT_LOCKS, "Max file locks", "file locks row is RLIMIT_LOCKS"},
        {RLIMIT_RTTIME, "Max realtime timeout",
         "realtime timeout row is RLIMIT_RTTIME"},
    };
    enum { N_CHECKED = sizeof(checked) / sizeof(checked[0]) };
    rlim_t soft[N_CHECKED] = {0};

    for (int i = 0; i < N_CHECKED; i++) {
        struct rlimit want = {0}, row = {0};
        TEST(checked[i].name);
        if (getrlimit(checked[i].resource, &want) < 0 ||
            limits_row(checked[i].row, &row) < 0) {
            FAIL("getrlimit or the row is missing");
            continue;
        }
        soft[i] = row.rlim_cur;
        EXPECT_TRUE(
            row.rlim_cur == want.rlim_cur && row.rlim_max == want.rlim_max,
            "row differs from getrlimit");
    }

    TEST("the rows are distinct");
    {
        int distinct = 1;
        for (int i = 0; i < N_CHECKED; i++)
            for (int j = i + 1; j < N_CHECKED; j++)
                if (soft[i] == soft[j])
                    distinct = 0;
        EXPECT_TRUE(distinct, "two rows print the same soft limit");
    }
}

int main(int argc, char **argv)
{
    char buf[4096];

    /* The image test_rlimit_state execs into: report what survived. */
    if (argc > 1 && !strcmp(argv[1], "after-exec"))
        return tracked_mismatches();

    printf("test-proc-limits: guest rlimits and /proc/self/limits\n");

    /* Open /proc/self/limits */
    TEST("open /proc/self/limits");
    long fd = raw_syscall4(__NR_openat, AT_FDCWD, (long) "/proc/self/limits",
                           LINUX_O_RDONLY, 0);
    if (fd < 0)
        FAIL("openat failed");
    else
        PASS();

    if (fd < 0)
        goto done;

    /* Read the content */
    TEST("read content");
    long n = raw_syscall3(__NR_read, fd, (long) buf, sizeof(buf) - 1);
    if (n <= 0)
        FAIL("read returned <= 0");
    else
        PASS();

    raw_syscall1(__NR_close, fd);

    if (n <= 0)
        goto done;
    buf[n] = '\0';

    /* Check header line */
    TEST("header line present");
    if (strstr(buf, "Limit") && strstr(buf, "Soft Limit") &&
        strstr(buf, "Hard Limit") && strstr(buf, "Units"))
        PASS();
    else
        FAIL("header missing expected columns");

    /* Check for known resource rows */
    TEST("Max open files row");
    EXPECT_TRUE(strstr(buf, "Max open files"), "missing 'Max open files'");

    TEST("Max stack size row");
    EXPECT_TRUE(strstr(buf, "Max stack size"), "missing 'Max stack size'");

    TEST("Max cpu time row");
    EXPECT_TRUE(strstr(buf, "Max cpu time"), "missing 'Max cpu time'");

    TEST("Max processes row");
    EXPECT_TRUE(strstr(buf, "Max processes"), "missing 'Max processes'");

    TEST("Max locked memory row");
    EXPECT_TRUE(strstr(buf, "Max locked memory"),
                "missing 'Max locked memory'");

    TEST("Max file locks row");
    EXPECT_TRUE(strstr(buf, "Max file locks"), "missing 'Max file locks'");

    /* Verify Max open files has a numeric soft limit (not unlimited). Scan from
     * the name to the end of the line for a digit sequence.
     */
    TEST("Max open files has numeric value");
    {
        const char *p = strstr(buf, "Max open files");
        int found_digit = 0;
        if (p) {
            /* Find the end of the line */
            const char *eol = strchr(p, '\n');
            if (!eol)
                eol = p + strlen(p);
            /* Skip past the name to the value columns */
            for (const char *s = p + 14; s < eol; s++) {
                if (*s >= '1' && *s <= '9') {
                    found_digit = 1;
                    break;
                }
            }
        }
        EXPECT_TRUE(found_digit, "expected numeric NOFILE soft limit");
    }

    /* Verify at least 16 rows (header + 16 resources) */
    TEST("at least 17 lines");
    {
        int lines = 0;
        for (long i = 0; i < n; i++)
            if (buf[i] == '\n')
                lines++;
        EXPECT_TRUE(lines >= 17, "too few lines");
    }

done:
    test_rlimit_state(argv[0]);
    test_limits_rows();

    SUMMARY("test-proc-limits");
    return fails ? 1 : 0;
}
