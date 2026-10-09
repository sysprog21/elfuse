/*
 * Test emulated UID/GID, capabilities, priority, and affinity
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: setuid, setgid, setgroups, setresuid, setresgid, setreuid, setregid,
 *        getresuid, getresgid, capset, setpriority, getpriority,
 *        sched_setaffinity
 */

#include <sys/types.h> /* gid_t */
#include <sys/wait.h>  /* waitpid */
#include <unistd.h>    /* getgroups */

#include "test-harness.h"
#include "raw-syscall.h"

/* aarch64 Linux syscall numbers */
#define __NR_setuid 146
#define __NR_setgid 144
#define __NR_setresuid 147
#define __NR_getresuid 148
#define __NR_getresgid 150
#define __NR_setreuid 145
#define __NR_setfsuid 151
#define __NR_setfsgid 152
#define __NR_capset 91
#define __NR_setpriority 140
#define __NR_getpriority 141
#define __NR_sched_setaffinity 122
#define __NR_sched_getaffinity 123
#define __NR_getuid 174
#define __NR_geteuid 175
#define __NR_getgid 176
#define __NR_setgroups 159
#define __NR_sched_yield 124
#define __NR_clock_gettime 113

#define CLOCK_MONOTONIC 1

#define CLONE_VM 0x00000100UL
#define CLONE_FS 0x00000200UL
#define CLONE_FILES 0x00000400UL
#define CLONE_SIGHAND 0x00000800UL
#define CLONE_THREAD 0x00010000UL
#define CLONE_SYSVSEM 0x00040000UL
#define CLONE_PARENT_SETTID 0x00100000UL
#define CLONE_CHILD_CLEARTID 0x00200000UL
#define CLONE_DETACHED 0x00400000UL

typedef struct {
    long tv_sec;
    long tv_nsec;
} test_timespec_t;

static volatile int prio_child_tid = 0;
static volatile int prio_child_ready = 0;
static volatile int prio_child_release = 0;
static int prio_dead_tid = 0;
static char prio_child_stack[8192] __attribute__((aligned(16)));

static long monotonic_ms(void)
{
    test_timespec_t ts = {0};
    long rc = raw_syscall2(__NR_clock_gettime, CLOCK_MONOTONIC, (long) &ts);
    if (rc != 0)
        return -1;
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void priority_child_work(void)
{
    prio_child_ready = 1;
    raw_futex_wake((int *) &prio_child_ready, 1);

    while (prio_child_release == 0)
        raw_futex_wait((int *) &prio_child_release, 0);

    raw_exit(0);
}

static long spawn_priority_child(void)
{
    prio_child_tid = 0;
    prio_child_ready = 0;
    prio_child_release = 0;

    unsigned long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                          CLONE_THREAD | CLONE_SYSVSEM | CLONE_PARENT_SETTID |
                          CLONE_CHILD_CLEARTID | CLONE_DETACHED;
    void *stack_top = prio_child_stack + sizeof(prio_child_stack);
    long ret =
        raw_clone(flags, stack_top, (int *) &prio_child_tid, /* parent_tid */
                  0,                                         /* tls */
                  (int *) &prio_child_tid);                  /* child_tid */
    if (ret == 0) {
        priority_child_work();
        __builtin_unreachable();
    }
    return ret;
}

static void release_priority_child(void)
{
    prio_child_release = 1;
    raw_futex_wake((int *) &prio_child_release, 1);
    raw_wait_cleartid(&prio_child_tid);
}

static long wait_for_dead_priority_tid(int tid)
{
    long start_ms = monotonic_ms();
    long prio = 0;

    for (;;) {
        prio = raw_syscall2(__NR_getpriority, 0, tid);
        if (prio == -3)
            return prio;
        raw_syscall0(__NR_sched_yield);

        long now_ms = monotonic_ms();
        if (start_ms >= 0 && now_ms >= 0 && now_ms - start_ms > 2000)
            return prio;
    }
}

int main(void)
{
    int passes = 0, fails = 0;

    printf("test-credentials: UID/GID, capabilities, priority, affinity\n");

    long uid = raw_syscall0(__NR_getuid);
    long expected_id = (uid == 0) ? 0 : 1000;

    /* Baseline: UID/GID should match expected_id */
    TEST("getuid matches expected");
    EXPECT_TRUE(raw_syscall0(__NR_getuid) == expected_id, "unexpected uid");

    TEST("geteuid matches expected");
    EXPECT_TRUE(raw_syscall0(__NR_geteuid) == expected_id, "unexpected euid");

    TEST("getgid matches expected");
    EXPECT_TRUE(raw_syscall0(__NR_getgid) == expected_id, "unexpected gid");

    /* getresuid returns coherent triple */
    TEST("getresuid coherent");
    {
        unsigned int ruid = 0, euid = 0, suid = 0;
        long rc = raw_syscall3(__NR_getresuid, (long) &ruid, (long) &euid,
                               (long) &suid);
        EXPECT_TRUE(rc == 0 && ruid == expected_id && euid == expected_id &&
                        suid == expected_id,
                    "getresuid mismatch");
    }

    /* setuid: can set euid to current ruid, no-op but must succeed */
    TEST("setuid(expected) succeeds");
    EXPECT_TRUE(raw_syscall1(__NR_setuid, expected_id) == 0, "setuid failed");

    /* setuid: setting to arbitrary value must fail with -EPERM for non-root */
    TEST("setuid(other) returns expected status");
    {
        pid_t pid = fork();
        if (pid == 0) {
            long rc = raw_syscall1(__NR_setuid, expected_id == 0 ? 1000 : 0);
            _exit(rc == 0 ? 0 : 1);
        }
        int status;
        waitpid(pid, &status, 0);
        if (expected_id == 0)
            EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                        "setuid(1000) failed for root");
        else
            EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 1,
                        "expected -EPERM");
    }

    /* setresuid: swap euid (no-op but must succeed) */
    TEST("setresuid(-1,-1,-1) no-op");
    {
        long rc = raw_syscall3(__NR_setresuid, (long) (unsigned) -1,
                               (long) (unsigned) -1, (long) (unsigned) -1);
        EXPECT_TRUE(rc == 0, "setresuid no-op failed");
    }

    /* setresuid: set euid to a value not in {ruid, euid, suid} */
    TEST("setresuid(-1,other,-1) returns expected status");
    {
        pid_t pid = fork();
        if (pid == 0) {
            long rc = raw_syscall3(__NR_setresuid, (long) (unsigned) -1,
                                   expected_id == 0 ? 1000 : 42,
                                   (long) (unsigned) -1);
            _exit(rc == 0 ? 0 : 1);
        }
        int status;
        waitpid(pid, &status, 0);
        if (expected_id == 0)
            EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                        "setresuid failed for root");
        else
            EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 1,
                        "expected -EPERM");
    }

    /* setreuid: ruid can only be set to current ruid or euid */
    TEST("setreuid(expected,-1) succeeds");
    {
        long rc =
            raw_syscall2(__NR_setreuid, expected_id, (long) (unsigned) -1);
        EXPECT_TRUE(rc == 0, "setreuid(ruid,-1) failed");
    }

    TEST("setreuid(other,-1) returns expected status");
    {
        pid_t pid = fork();
        if (pid == 0) {
            long rc = raw_syscall2(__NR_setreuid, expected_id == 0 ? 1000 : 42,
                                   (long) (unsigned) -1);
            _exit(rc == 0 ? 0 : 1);
        }
        int status;
        waitpid(pid, &status, 0);
        if (expected_id == 0)
            EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                        "setreuid failed for root");
        else
            EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 1,
                        "expected -EPERM");
    }

    /* getresgid */
    TEST("getresgid coherent");
    {
        unsigned int rgid = 0, egid = 0, sgid = 0;
        long rc = raw_syscall3(__NR_getresgid, (long) &rgid, (long) &egid,
                               (long) &sgid);
        EXPECT_TRUE(rc == 0 && rgid == expected_id && egid == expected_id &&
                        sgid == expected_id,
                    "getresgid mismatch");
    }

    /* setgid: same constraints as setuid */
    TEST("setgid(expected) succeeds");
    EXPECT_TRUE(raw_syscall1(__NR_setgid, expected_id) == 0, "setgid failed");

    TEST("setgid(other) returns expected status");
    {
        pid_t pid = fork();
        if (pid == 0) {
            long rc = raw_syscall1(__NR_setgid, expected_id == 0 ? 1000 : 0);
            _exit(rc == 0 ? 0 : 1);
        }
        int status;
        waitpid(pid, &status, 0);
        if (expected_id == 0)
            EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                        "setgid(1000) failed for root");
        else
            EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 1,
                        "expected -EPERM");
    }

    TEST("setgroups model");
    {
        unsigned int group = (unsigned int) expected_id;
        long rc = raw_syscall2(__NR_setgroups, 1, (long) &group);
        if (expected_id == 0)
            EXPECT_TRUE(rc == 0, "setgroups root no-op failed");
        else
            EXPECT_TRUE(rc == -1, "setgroups non-root expected EPERM");
    }

    TEST("setgroups zero count");
    {
        long rc = raw_syscall2(__NR_setgroups, 0, 0);
        if (expected_id == 0)
            EXPECT_TRUE(rc == 0, "setgroups(0,NULL) root failed");
        else
            EXPECT_TRUE(rc == -1, "setgroups(0,NULL) non-root expected EPERM");
    }

    if (expected_id == 0) {
        TEST("setgroups bad pointer");
        EXPECT_TRUE(raw_syscall2(__NR_setgroups, 1, 1) == -14,
                    "expected -EFAULT");
    }

    TEST("setgroups invalid size");
    {
        long rc = raw_syscall2(__NR_setgroups, (long) (unsigned) -1, 0);
        if (expected_id == 0)
            EXPECT_TRUE(rc == -22, "expected -EINVAL");
        else
            EXPECT_TRUE(rc == -1, "expected -EPERM");
    }

    /* setfsuid / setfsgid: Linux contract is to return the previous fsuid /
     * fsgid.
     */
    TEST("setfsuid(other) returns expected_id");
    EXPECT_TRUE(
        raw_syscall1(__NR_setfsuid, expected_id == 0 ? 1000 : 0) == expected_id,
        "setfsuid did not return current euid");

    TEST("setfsuid(expected_id) returns expected_id");
    EXPECT_TRUE(raw_syscall1(__NR_setfsuid, expected_id) == expected_id,
                "setfsuid did not return current euid");

    TEST("setfsgid(other) returns expected_id");
    EXPECT_TRUE(
        raw_syscall1(__NR_setfsgid, expected_id == 0 ? 1000 : 0) == expected_id,
        "setfsgid did not return current egid");

    TEST("setfsgid(expected_id) returns expected_id");
    EXPECT_TRUE(raw_syscall1(__NR_setfsgid, expected_id) == expected_id,
                "setfsgid did not return current egid");

    /* setfsuid(-1) / setfsgid(-1) is the canonical glibc "read fsuid without
     * changing it" idiom: -1 is never a valid uid, so the kernel only reports
     * the current fsuid.
     */
    TEST("setfsuid(-1) reports current fsuid");
    EXPECT_TRUE(
        raw_syscall1(__NR_setfsuid, (long) (unsigned) -1) == expected_id,
        "setfsuid(-1) did not report current euid");

    TEST("setfsgid(-1) reports current fsgid");
    EXPECT_TRUE(
        raw_syscall1(__NR_setfsgid, (long) (unsigned) -1) == expected_id,
        "setfsgid(-1) did not report current egid");

    /* capset: unprivileged process cannot set capabilities */
    TEST("capset returns -EPERM");
    {
        /* Linux capset header: version=0x20080522, pid=0 */
        unsigned int hdr[2] = {0x20080522, 0};
        unsigned int data[6] = {0};
        long rc = raw_syscall2(__NR_capset, (long) hdr, (long) data);
        if (rc == -1) /* -EPERM */
            PASS();
        else
            FAIL("expected -EPERM");
    }

    /* getgroups supplementary groups check */
    TEST("getgroups returns expected groups");
    {
        gid_t list[64];
        int ngroups = getgroups(64, list);
        if (expected_id == 0) {
            EXPECT_TRUE(ngroups == 1 && list[0] == 0,
                        "fakeroot getgroups mismatch");
        } else {
            EXPECT_TRUE(ngroups >= 0, "getgroups failed");
        }
    }

    /* setpriority/getpriority coherence */
    TEST("setpriority(0) then getpriority");
    {
        /* PRIO_PROCESS=0, who=0 (self), prio=5 */
        long rc = raw_syscall3(__NR_setpriority, 0, 0, 5);
        if (rc != 0) {
            FAIL("setpriority failed");
        } else {
            /* Linux getpriority returns 20-nice, so nice=5 -> return 15 */
            long prio = raw_syscall2(__NR_getpriority, 0, 0);
            EXPECT_TRUE(prio == 15, "getpriority mismatch");
        }
        /* Reset nice to 0 */
        raw_syscall3(__NR_setpriority, 0, 0, 0);
    }

    TEST("getpriority live thread TID");
    {
        long ret = spawn_priority_child();
        if (ret < 0) {
            FAIL("clone failed");
        } else {
            while (prio_child_ready == 0)
                raw_futex_wait((int *) &prio_child_ready, 0);

            long prio = raw_syscall2(__NR_getpriority, 0, prio_child_tid);
            EXPECT_TRUE(prio == 20, "getpriority(live tid) mismatch");
            release_priority_child();
        }
    }

    TEST("setpriority live thread TID rejected");
    {
        long ret = spawn_priority_child();
        if (ret < 0) {
            FAIL("clone failed");
        } else {
            while (prio_child_ready == 0)
                raw_futex_wait((int *) &prio_child_ready, 0);

            raw_syscall3(__NR_setpriority, 0, 0, 0);
            long baseline_prio = raw_syscall2(__NR_getpriority, 0, 0);
            int tid = prio_child_tid;
            long rc = raw_syscall3(__NR_setpriority, 0, tid, 5);
            long self_prio = raw_syscall2(__NR_getpriority, 0, 0);
            long tid_prio = raw_syscall2(__NR_getpriority, 0, tid);
            EXPECT_TRUE(rc == -3 && self_prio == baseline_prio &&
                            tid_prio == baseline_prio,
                        "setpriority(live tid) changed global nice");
            release_priority_child();
            prio_dead_tid = tid;
        }
        raw_syscall3(__NR_setpriority, 0, 0, 0);
    }

    TEST("getpriority dead thread TID");
    {
        if (prio_dead_tid == 0) {
            FAIL("no dead tid from setpriority test");
        } else {
            long dead_prio = wait_for_dead_priority_tid(prio_dead_tid);
            EXPECT_TRUE(dead_prio == -3, "getpriority(dead tid) succeeded");
        }
    }

    /* sched_setaffinity: mask with CPU 0 should succeed */
    TEST("sched_setaffinity(CPU0)");
    {
        unsigned long mask = 1; /* CPU 0 */
        long rc =
            raw_syscall3(__NR_sched_setaffinity, 0, sizeof(mask), (long) &mask);
        EXPECT_TRUE(rc == 0, "setaffinity with CPU0 failed");
    }

    /* sched_setaffinity: empty mask should fail */
    TEST("sched_setaffinity(empty) fails");
    {
        unsigned long mask = 0;
        long rc =
            raw_syscall3(__NR_sched_setaffinity, 0, sizeof(mask), (long) &mask);
        EXPECT_TRUE(rc != 0, "expected failure for empty mask");
    }

    /* sched_getaffinity: should report CPU 0 */
    TEST("sched_getaffinity has CPU0");
    {
        unsigned long mask = 0;
        long rc =
            raw_syscall3(__NR_sched_getaffinity, 0, sizeof(mask), (long) &mask);
        EXPECT_TRUE(rc > 0 && (mask & 1), "CPU0 not in mask");
    }

    if (expected_id == 0) {
        TEST("privileged setreuid(1000, -1) sets real ID");
        {
            pid_t pid = fork();
            if (pid == 0) {
                long rc =
                    raw_syscall2(__NR_setreuid, 1000, (long) (unsigned) -1);
                _exit(rc == 0 ? 0 : 1);
            }
            int status;
            waitpid(pid, &status, 0);
            EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                        "setreuid(1000, -1) failed");
        }

        TEST("privileged setuid(1000) resets ruid/euid/suid");
        {
            pid_t pid = fork();
            if (pid == 0) {
                long rc = raw_syscall1(__NR_setuid, 1000);
                if (rc != 0)
                    _exit(1);
                unsigned int ruid = 0, euid = 0, suid = 0;
                long grc = raw_syscall3(__NR_getresuid, (long) &ruid,
                                        (long) &euid, (long) &suid);
                if (grc == 0 && ruid == 1000 && euid == 1000 && suid == 1000)
                    _exit(0);
                _exit(2);
            }
            int status;
            waitpid(pid, &status, 0);
            EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                        "uid triple not fully updated");
        }
    }

    SUMMARY("test-credentials");
    return fails ? 1 : 0;
}
