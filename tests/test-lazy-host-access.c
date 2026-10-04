/*
 * test-lazy-host-access.c -- syscalls handed guest memory the guest has not
 * touched yet
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * An anonymous MAP_NORESERVE mapping has no page-table entries until something
 * touches it. Linux faults such a page in whenever a syscall reads or writes
 * it, so every case below hands a syscall a buffer in a fresh mapping and
 * expects the answer the same call gives on a touched one.
 *
 * Each case is one whose guest access happens under a lock below elfuse's
 * mmap_lock (a futex bucket, the timerfd table, the cwd view, the process
 * table, a directory stream), where the page cannot be faulted in on the spot.
 * A wrong fix shows up as EFAULT, or as a hang where the fault-in and the lock
 * deadlock against each other.
 *
 * The PROT_NONE and PROT_READ cases check the other side: a fault-in must not
 * hand the access what the mapping's protection refuses.
 *
 * FUTEX_WAIT is left out: elfuse answers a wait at EL1 before the host sees it,
 * and that path reports a fault on the word itself.
 *
 * Syscalls exercised: futex(98), futex_waitv(449), timerfd_create(85),
 * timerfd_settime(86), getcwd(17), waitid(95), getdents64(61), mincore(232).
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/futex.h>

#include "raw-syscall.h"
#include "test-harness.h"

#ifndef __NR_futex_waitv
#define __NR_futex_waitv 449
#endif
#define FUTEX2_SIZE_U32 0x02

struct waitv_elem {
    uint64_t val;
    uint64_t uaddr;
    uint32_t flags;
    uint32_t __reserved;
};

int passes = 0, fails = 0;

#define LAZY_LEN (64 * 1024)

/* A fresh mapping nothing has touched. Each case takes its own, so one case
 * faulting a page in cannot make the next one pass.
 */
static void *lazy_map(int prot)
{
    void *p = mmap(NULL, LAZY_LEN, prot,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

static long futex(uint32_t *uaddr,
                  int op,
                  uint32_t val,
                  long arg4,
                  uint32_t *uaddr2,
                  uint32_t val3)
{
    return raw_syscall6(__NR_futex, (long) uaddr, op | FUTEX_PRIVATE_FLAG,
                        (long) val, arg4, (long) uaddr2, (long) val3);
}

static void test_futex(void)
{
    TEST("cmp_requeue compares an untouched word");
    uint32_t *w = lazy_map(PROT_READ | PROT_WRITE);
    uint32_t other = 0;
    EXPECT_RAW_ERRNO(futex(w, FUTEX_CMP_REQUEUE, 1, 1, &other, 0), 0,
                     "expected 0 woken, the compare matches 0");

    TEST("wake_op modifies an untouched word");
    w = lazy_map(PROT_READ | PROT_WRITE);
    uint32_t first = 0;
    long r = futex(&first, FUTEX_WAKE_OP, 1, 1, w,
                   FUTEX_OP(FUTEX_OP_SET, 7, FUTEX_OP_CMP_EQ, 0));
    EXPECT_TRUE(r == 0 && *w == 7, "expected 0 woken and the word set to 7");

    TEST("lock_pi takes an untouched word");
    w = lazy_map(PROT_READ | PROT_WRITE);
    r = futex(w, FUTEX_LOCK_PI, 0, 0, NULL, 0);
    uint32_t owner = *w & FUTEX_TID_MASK;
    EXPECT_TRUE(r == 0 && owner == (uint32_t) raw_syscall0(__NR_gettid),
                "expected the lock taken by this thread");
    futex(w, FUTEX_UNLOCK_PI, 0, 0, NULL, 0);

    TEST("futex_waitv reads untouched words");
    w = lazy_map(PROT_READ | PROT_WRITE);
    struct waitv_elem elts[2] = {
        {.val = 0, .uaddr = (uint64_t) (uintptr_t) w, .flags = FUTEX2_SIZE_U32},
        {.val = 1,
         .uaddr = (uint64_t) (uintptr_t) (w + 4096),
         .flags = FUTEX2_SIZE_U32},
    };
    EXPECT_RAW_ERRNO(
        raw_syscall5(__NR_futex_waitv, (long) elts, 2, 0, 0, CLOCK_MONOTONIC),
        -EAGAIN, "expected EAGAIN from the second word");

    /* The fault-in follows the mapping's protection, as Linux's does. */
    TEST("cmp_requeue on PROT_NONE is EFAULT");
    w = lazy_map(PROT_NONE);
    EXPECT_RAW_ERRNO(futex(w, FUTEX_CMP_REQUEUE, 1, 1, &other, 0), -EFAULT,
                     "expected EFAULT");

    TEST("wake_op on PROT_READ is EFAULT");
    w = lazy_map(PROT_READ);
    EXPECT_RAW_ERRNO(futex(&first, FUTEX_WAKE_OP, 1, 1, w,
                           FUTEX_OP(FUTEX_OP_SET, 7, FUTEX_OP_CMP_EQ, 0)),
                     -EFAULT, "expected EFAULT");

    TEST("cmp_requeue on PROT_READ reads 0");
    w = lazy_map(PROT_READ);
    EXPECT_RAW_ERRNO(futex(w, FUTEX_CMP_REQUEUE, 1, 1, &other, 1), -EAGAIN,
                     "expected EAGAIN: the word reads 0, not 1");
}

static void test_timerfd(void)
{
    TEST("timerfd_settime with untouched buffers");
    int fd = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec *its = lazy_map(PROT_READ | PROT_WRITE);
    struct itimerspec *old = lazy_map(PROT_READ | PROT_WRITE);
    if (fd < 0 || !its || !old) {
        FAIL("setup");
        return;
    }
    /* An all-zero new value disarms, so the call needs nothing written. */
    int rc = timerfd_settime(fd, 0, its, old);
    EXPECT_TRUE(
        rc == 0 && old->it_value.tv_sec == 0 && old->it_value.tv_nsec == 0,
        "expected 0 and a disarmed old value");
    close(fd);
}

static void test_getcwd(void)
{
    TEST("getcwd into an untouched buffer");
    char *buf = lazy_map(PROT_READ | PROT_WRITE);
    char ref[4096];
    EXPECT_TRUE(buf && getcwd(buf, 4096) && getcwd(ref, sizeof(ref)) &&
                    strcmp(buf, ref) == 0,
                "expected the same path as a touched buffer");
}

static void test_waitid(void)
{
    TEST("waitid into an untouched siginfo");
    siginfo_t *si = lazy_map(PROT_READ | PROT_WRITE);
    pid_t pid = fork();
    if (pid == 0)
        _exit(42);
    int rc = si ? waitid(P_PID, (id_t) pid, si, WEXITED) : -1;
    EXPECT_TRUE(rc == 0 && si->si_pid == pid && si->si_status == 42,
                "expected the child's exit in siginfo");
    if (rc != 0)
        waitpid(pid, NULL, 0);
}

static void test_getdents(void)
{
    TEST("getdents64 into an untouched buffer");
    int fd = open("/", O_RDONLY | O_DIRECTORY);
    void *buf = lazy_map(PROT_READ | PROT_WRITE);
    long n = (fd >= 0 && buf)
                 ? raw_syscall3(__NR_getdents64, fd, (long) buf, LAZY_LEN)
                 : -1;
    EXPECT_TRUE(n > 0, "expected directory entries");
    if (fd >= 0)
        close(fd);
}

static void test_mincore(void)
{
    TEST("mincore into an untouched vector");
    long page = sysconf(_SC_PAGESIZE);
    unsigned char *vec = lazy_map(PROT_READ | PROT_WRITE);
    void *probe = mmap(NULL, (size_t) page * 4, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    EXPECT_TRUE(vec && probe != MAP_FAILED &&
                    mincore(probe, (size_t) page * 4, vec) == 0,
                "expected 0");
}

int main(void)
{
    printf("test-lazy-host-access: syscalls on untouched MAP_NORESERVE\n");
    test_futex();
    test_timerfd();
    test_getcwd();
    test_waitid();
    test_getdents();
    test_mincore();
    SUMMARY("test-lazy-host-access");
    return fails ? 1 : 0;
}
