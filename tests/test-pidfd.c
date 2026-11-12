/*
 * Test pidfd subsystem
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: pidfd_open, pidfd_send_signal, clone3 with CLONE_PIDFD, and poll on
 * pidfd for exit notification.
 */

#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "test-harness.h"
#include "raw-syscall.h"

#define __NR_getpid 172
#define __NR_pidfd_open 434
#define __NR_pidfd_send_signal 424
#define __NR_pidfd_getfd 438
#define __NR_close 57
#define __NR_clone3 435
#define __NR_ppoll 73
#define __NR_exit 93
#define __NR_wait4 260

#define CLONE_PIDFD 0x00001000
#define CLONE_VM 0x00000100
#define CLONE_PARENT_SETTID 0x00100000
#define SIGCHLD 17

int passes = 0, fails = 0;
static _Atomic int vm_exit_gate;

/* Linux clone3 args */
struct clone_args {
    uint64_t flags;
    uint64_t pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
};

/* Linux pollfd (aarch64) */
struct linux_pollfd {
    int fd;
    short events, revents;
};

/* The child changes SP, so it cannot access the caller's C frame. */
static long clone_vm_wait_for_gate(struct clone_args *ca)
{
    register long x0 __asm__("x0") = (long) ca;
    register long x1 __asm__("x1") = sizeof(*ca);
    register long x2 __asm__("x2") = (long) &vm_exit_gate;
    register long x8 __asm__("x8") = __NR_clone3;
    __asm__ volatile(
        "svc #0\n"
        "cbnz x0, 2f\n"
        "1: ldar w9, [x2]\n"
        "cbz w9, 1b\n"
        "mov x0, #42\n"
        "mov x8, %c[exit_nr]\n"
        "svc #0\n"
        "brk #0\n"
        "2:\n"
        : "+r"(x0), "+r"(x8)
        : "r"(x1), "r"(x2), [exit_nr] "i"(__NR_exit)
        : "x9", "memory", "cc");
    return x0;
}

static void test_clone_failure(uint64_t output, long error)
{
    struct clone_args ca = {
        .flags = CLONE_PIDFD,
        .pidfd = output,
        .exit_signal = SIGCHLD,
    };
    long child = raw_syscall2(__NR_clone3, (long) &ca, sizeof(ca));
    if (child == 0) {
        raw_syscall1(__NR_exit, 42);
        __builtin_unreachable();
    }
    if (child > 0)
        raw_syscall4(__NR_wait4, child, 0, 0, 0);
    EXPECT_EQ(child, error, "wrong clone3 error");
    TEST("failed clone leaves no child");
    EXPECT_RAW_ERRNO(raw_syscall4(__NR_wait4, -1, 0, 1, 0), -ECHILD,
                     "failed clone left a child");
}

int main(void)
{
    printf("test-pidfd: pidfd subsystem\n");

    long pid = raw_syscall0(__NR_getpid);

    /* pidfd_open for self */
    TEST("pidfd_open(self, 0)");
    long pfd = raw_syscall2(__NR_pidfd_open, pid, 0);
    EXPECT_TRUE(pfd >= 0, "pidfd_open failed");

    /* pidfd_send_signal: signal 0 (validity check) */
    TEST("pidfd_send_signal(pfd, 0)");
    if (pfd >= 0) {
        long r = raw_syscall4(__NR_pidfd_send_signal, pfd, 0, 0, 0);
        EXPECT_TRUE(r == 0, "pidfd_send_signal sig=0 failed");
    } else {
        FAIL("no pidfd");
    }

    /* Close the self-pidfd */
    if (pfd >= 0)
        raw_syscall1(__NR_close, pfd);

    /* pidfd_open for unknown PID returns ESRCH */
    TEST("pidfd_open(99999) returns ESRCH");
    {
        long r = raw_syscall2(__NR_pidfd_open, 99999, 0);
        EXPECT_TRUE(r == -3 /* LINUX_ESRCH */, "expected -ESRCH");
        if (r >= 0)
            raw_syscall1(__NR_close, r);
    }

    /* pidfd_open with invalid flags */
    TEST("pidfd_open(self, 1) returns EINVAL");
    {
        long r = raw_syscall2(__NR_pidfd_open, pid, 1);
        EXPECT_TRUE(r == -22 /* LINUX_EINVAL */, "expected -EINVAL");
        if (r >= 0)
            raw_syscall1(__NR_close, r);
    }

    /* pidfd_getfd returns ENOSYS (not implemented) */
    TEST("pidfd_getfd returns ENOSYS");
    {
        long r = raw_syscall3(__NR_pidfd_getfd, 0, 0, 0);
        EXPECT_TRUE(r == -38 /* LINUX_ENOSYS */, "expected -ENOSYS");
    }

    TEST("clone3 rejects null pidfd output");
    test_clone_failure(0, -EFAULT);
    TEST("clone3 rejects unmapped pidfd output");
    test_clone_failure(UINT64_MAX - 4095, -EFAULT);

    /* Fill elfuse's bounded pidfd table before clone creates its child. */
    {
        long fds[32];
        int count = 0;
        while (count < 32) {
            long fd = raw_syscall2(__NR_pidfd_open, pid, 0);
            if (fd < 0)
                break;
            fds[count++] = fd;
        }
        TEST("failed clones release pidfds");
        EXPECT_EQ(count, 32, "failed clone leaked a pidfd");
        int32_t output = -1;
        TEST("clone3 cancels on pidfd allocation failure");
        test_clone_failure((uint64_t) &output, -EMFILE);
        for (int i = 0; i < count; i++)
            raw_syscall1(__NR_close, fds[i]);
    }

    /* clone3 with separate CLONE_PIDFD and CLONE_PARENT_SETTID outputs. */
    TEST("clone3 CLONE_PIDFD");
    {
        /* Allocate stack for child */
        void *stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (stack == MAP_FAILED) {
            FAIL("mmap for stack failed");
            goto done;
        }

        int32_t child_pidfd = -1;
        int32_t parent_tid = -1;
        struct clone_args ca = {0};
        ca.flags = CLONE_PIDFD | CLONE_PARENT_SETTID;
        ca.pidfd = (uint64_t) &child_pidfd;
        ca.parent_tid = (uint64_t) &parent_tid;
        ca.exit_signal = SIGCHLD;
        ca.stack = (uint64_t) stack;
        ca.stack_size = 65536;

        long child = raw_syscall2(__NR_clone3, (long) &ca, sizeof(ca));
        if (child == 0) {
            /* Child: exit immediately */
            raw_syscall1(__NR_exit, 42);
            __builtin_unreachable();
        }
        if (child < 0) {
            FAIL("clone3 failed");
            goto done;
        }

        EXPECT_TRUE(child_pidfd >= 0, "pidfd not written");
        TEST("clone3 writes a separate parent TID");
        EXPECT_EQ(parent_tid, child, "parent TID not written");

        /* Poll the pidfd for child exit (with 1s timeout) */
        TEST("poll pidfd for exit");
        if (child_pidfd >= 0) {
            struct linux_pollfd pf = {
                .fd = child_pidfd,
                .events = 1, /* POLLIN */
                .revents = 0,
            };
            /* 100ms timeout */
            uint64_t ts[2] = {0, 100000000};
            long pr = raw_syscall5(__NR_ppoll, (long) &pf, 1, (long) ts, 0, 0);
            EXPECT_TRUE(pr > 0 && (pf.revents & 1),
                        "pidfd not readable after child exit");

            raw_syscall1(__NR_close, child_pidfd);
        } else {
            FAIL("no pidfd to poll");
        }

        /* Reap the child */
        raw_syscall4(__NR_wait4, child, 0, 0, 0);
    }

    /* A CLONE_VM child's pidfd becomes readable only after the child exits. */
    TEST("clone3 CLONE_PIDFD|CLONE_VM pidfd not readable while child runs");
    {
        void *stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (stack == MAP_FAILED) {
            FAIL("mmap for stack failed");
            goto done;
        }
        int32_t vm_pidfd = -1;
        struct clone_args ca = {0};
        ca.flags = CLONE_PIDFD | CLONE_VM;
        ca.pidfd = (uint64_t) &vm_pidfd;
        ca.exit_signal = SIGCHLD;
        ca.stack = (uint64_t) stack;
        ca.stack_size = 65536;

        long child = clone_vm_wait_for_gate(&ca);
        if (child < 0) {
            FAIL("clone3 CLONE_VM failed");
            munmap(stack, 65536);
            goto done;
        }

        /* Without this, the check below passes vacuously: ppoll skips a
         * negative fd and reports nothing, so an unwritten pidfd would look
         * like one that correctly stays unreadable.
         */
        EXPECT_TRUE(vm_pidfd >= 0,
                    "clone3 wrote no pidfd for the CLONE_VM "
                    "child");

        struct linux_pollfd pf = {.fd = vm_pidfd, .events = 1, .revents = 0};
        uint64_t ts[2] = {0, 100000000}; /* 100 ms */
        long pr = raw_syscall5(__NR_ppoll, (long) &pf, 1, (long) ts, 0, 0);
        EXPECT_TRUE(pr == 0 && pf.revents == 0,
                    "pidfd reports an exit while the CLONE_VM child runs");

        atomic_store_explicit(&vm_exit_gate, 1, memory_order_release);
        ts[0] = 2;
        ts[1] = 0;
        TEST("CLONE_VM pidfd becomes readable after child exit");
        pr = raw_syscall5(__NR_ppoll, (long) &pf, 1, (long) ts, 0, 0);
        EXPECT_TRUE(pr > 0 && (pf.revents & 1),
                    "pidfd not readable after CLONE_VM child exit");
        TEST("CLONE_VM child can be reaped after pidfd notification");
        int status = 0;
        EXPECT_EQ(raw_syscall4(__NR_wait4, child, (long) &status, 0, 0), child,
                  "wait4 did not reap the CLONE_VM child");
        TEST("CLONE_VM child exit status leaves the parent running");
        EXPECT_EQ(status, 42 << 8, "wrong CLONE_VM child exit status");
        raw_syscall1(__NR_close, vm_pidfd);
        munmap(stack, 65536);
    }

done:
    SUMMARY("test-pidfd");
    return fails ? 1 : 0;
}
