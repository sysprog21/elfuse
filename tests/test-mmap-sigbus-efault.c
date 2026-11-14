/*
 * MAP_SHARED truncated-page regression test
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse backs a MAP_SHARED file mapping with a live host mmap overlay onto the
 * guest slab. Truncating the file leaves the overlay in place with no backing
 * page. Each case below drives one access path to it, host or guest, and
 * expects what Linux answers: EFAULT from a syscall, SIGBUS from a load or
 * store.
 *
 * Host syscall buffers are deliberately absent: the kernel reports EFAULT from
 * copyin/copyout rather than signaling, so read/write/sendmsg never needed a
 * pad.
 *
 * SIGCHLD stays blocked: a pending one raises the shim's attention flag, which
 * would send the inline fast paths to the host and leave them untested.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* Map one page MAP_SHARED, then truncate the file out from under it.
 *
 * This only exercises the recovery pad while elfuse serves the mapping through
 * a live host file overlay, which it installs for MAP_SHARED at a
 * host-page-aligned slab offset and file offset. Offset 0 keeps the file side
 * aligned and the mmap gap finder keeps the slab side aligned. Should either
 * stop holding, the mapping falls back to snapshot pread, no host page can
 * vanish, and every case here passes without proving anything.
 *
 * Returns the mapping, or NULL after reporting the failure. On success *fd_out
 * holds the still-open file descriptor.
 */
static char *map_then_truncate(size_t page, int *fd_out)
{
    char path[] = "/tmp/elfuse-mmap-sigbus-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        FAIL("mkstemp");
        return NULL;
    }
    unlink(path);

    if (ftruncate(fd, (off_t) page) < 0) {
        close(fd);
        FAIL("initial ftruncate");
        return NULL;
    }

    char *p = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        close(fd);
        FAIL("mmap");
        return NULL;
    }
    memset(p, 0, page);
    strcpy(p, "/tmp/elfuse-never-opened");

    /* Truncate from a child so the mapping in this process stays live. */
    pid_t pid = fork();
    if (pid == 0)
        _exit(ftruncate(fd, 0) == 0 ? 0 : 1);
    if (pid < 0) {
        munmap(p, page);
        close(fd);
        FAIL("fork");
        return NULL;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        munmap(p, page);
        close(fd);
        FAIL("child truncate");
        return NULL;
    }

    *fd_out = fd;
    return p;
}

/* guest_read_str, through the path argument of open(2). */
static void test_path_copy(void)
{
    TEST("path copy from truncated MAP_SHARED returns EFAULT");

    const size_t page = (size_t) sysconf(_SC_PAGESIZE);
    int fd = -1;
    char *p = map_then_truncate(page, &fd);
    if (!p)
        return;

    errno = 0;
    int got = open(p, O_RDONLY);
    if (got >= 0)
        close(got);

    EXPECT_TRUE(got < 0 && errno == EFAULT,
                "open path copy should fail with EFAULT after truncate");

    munmap(p, page);
    close(fd);
}

/* The futex word atomics, which run from host user mode. The shim serves a
 * timeout only below 2^31 seconds and hands a longer one to the host, so this
 * reaches the host whatever the attention flag says.
 */
static void test_futex_word(void)
{
    TEST("futex on truncated MAP_SHARED returns EFAULT");

    const size_t page = (size_t) sysconf(_SC_PAGESIZE);
    int fd = -1;
    char *p = map_then_truncate(page, &fd);
    if (!p)
        return;

    /* FUTEX_WAIT compares before it decides anything, so the read that faults
     * happens whatever value is passed.
     *
     * 0 is deliberately a value the word cannot hold: map_then_truncate leaves
     * the poison path string at offset 0, so the word reads as "/tmp". A page
     * that has not actually lost its backing therefore answers EAGAIN and fails
     * the assertion below, where an expected value that matched would enqueue a
     * waiter and hang the suite instead.
     */
    struct timespec far = {.tv_sec = (time_t) 1 << 40, .tv_nsec = 0};
    errno = 0;
    long rc =
        syscall(SYS_futex, (int *) p, FUTEX_WAIT_PRIVATE, 0, &far, NULL, 0);

    EXPECT_TRUE(rc < 0 && errno == EFAULT,
                "FUTEX_WAIT should fail with EFAULT after truncate");

    munmap(p, page);
    close(fd);
}

/* The same word read by the shim's LDTR at EL1, untimed and with the attention
 * flag clear, then the timespec read the same way for the timed shape.
 */
static void test_futex_word_shim(void)
{
    TEST("shim futex on truncated MAP_SHARED returns EFAULT");

    const size_t page = (size_t) sysconf(_SC_PAGESIZE);
    int fd = -1;
    char *p = map_then_truncate(page, &fd);
    if (!p)
        return;

    /* 0 for the same reason as in test_futex_word. */
    errno = 0;
    long rc =
        syscall(SYS_futex, (int *) p, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    EXPECT_TRUE(rc < 0 && errno == EFAULT,
                "untimed FUTEX_WAIT should fail with EFAULT after truncate");

    /* The word matches, so only the unreadable timespec can fail the call. */
    static int word = 7;
    errno = 0;
    rc = syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 7, (void *) p, NULL, 0);
    EXPECT_TRUE(rc < 0 && errno == EFAULT,
                "FUTEX_WAIT with a truncated timespec should fail with EFAULT");

    munmap(p, page);
    close(fd);
}

static sigjmp_buf bus_jmp;
static volatile sig_atomic_t bus_code;
static void *volatile bus_addr;

static void on_sigbus(int sig, siginfo_t *si, void *uc)
{
    (void) sig;
    (void) uc;
    bus_code = si->si_code;
    bus_addr = si->si_addr;
    siglongjmp(bus_jmp, 1);
}

/* A load and a store from EL0. Linux raises SIGBUS with BUS_ADRERR at the
 * faulting address, and the handler stays installed for a second fault.
 */
static void test_el0_access(void)
{
    TEST("EL0 access to truncated MAP_SHARED raises SIGBUS");

    const size_t page = (size_t) sysconf(_SC_PAGESIZE);
    int fd = -1;
    char *p = map_then_truncate(page, &fd);
    if (!p)
        return;

    struct sigaction sa = {0}, old;
    sa.sa_sigaction = on_sigbus;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGBUS, &sa, &old);

    for (int store = 0; store < 2; store++) {
        volatile int *word = (volatile int *) (p + 8 * store);
        bus_code = 0;
        bus_addr = NULL;
        bool faulted = false;
        if (sigsetjmp(bus_jmp, 1) == 0) {
            if (store)
                *word = 1;
            else
                (void) *word;
        } else {
            faulted = true;
        }
        EXPECT_TRUE(faulted && bus_code == 2 /* BUS_ADRERR */ &&
                        bus_addr == (void *) word,
                    store ? "store should raise SIGBUS/BUS_ADRERR"
                          : "load should raise SIGBUS/BUS_ADRERR");
    }

    sigaction(SIGBUS, &old, NULL);
    munmap(p, page);
    close(fd);
}

static void test_el0_exec(void)
{
    TEST("EL0 fetch from truncated MAP_SHARED raises SIGBUS");

    const size_t page = (size_t) sysconf(_SC_PAGESIZE);
    int fd = -1;
    char *p = map_then_truncate(page, &fd);
    if (!p)
        return;
    munmap(p, page);

    /* Restore one page holding a RET, map it executable, then truncate again so
     * the fetch, not a load, reaches the vanished page.
     */
    const uint32_t ret = 0xd65f03c0;
    void (*fn)(void) = MAP_FAILED;
    if (ftruncate(fd, (off_t) page) == 0 && pwrite(fd, &ret, 4, 0) == 4)
        fn = (void (*)(void)) mmap(NULL, page, PROT_READ | PROT_EXEC,
                                   MAP_SHARED, fd, 0);
    if (fn == MAP_FAILED) {
        FAIL("exec mapping");
        close(fd);
        return;
    }
    fn();
    pid_t pid = fork();
    if (pid == 0)
        _exit(ftruncate(fd, 0) == 0 ? 0 : 1);
    if (pid > 0)
        waitpid(pid, NULL, 0);

    struct sigaction sa = {0}, old;
    sa.sa_sigaction = on_sigbus;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGBUS, &sa, &old);

    bus_code = 0;
    bus_addr = NULL;
    bool faulted = false;
    if (sigsetjmp(bus_jmp, 1) == 0)
        fn();
    else
        faulted = true;
    EXPECT_TRUE(
        faulted && bus_code == 2 /* BUS_ADRERR */ && bus_addr == (void *) fn,
        "fetch should raise SIGBUS/BUS_ADRERR");

    sigaction(SIGBUS, &old, NULL);
    munmap((void *) fn, page);
    close(fd);
}

/* arc4random_buf writing into the guest slab behind getrandom(2). The length is
 * above the shim's inline urandom limit of 256 bytes so the host serves it; the
 * inline store is test_urandom_inline.
 */
static void test_getrandom_fill(void)
{
    TEST("getrandom into truncated MAP_SHARED returns EFAULT");

    const size_t page = (size_t) sysconf(_SC_PAGESIZE);
    int fd = -1;
    char *p = map_then_truncate(page, &fd);
    if (!p)
        return;

    errno = 0;
    long rc = syscall(SYS_getrandom, p, (size_t) 2048, 0);

    EXPECT_TRUE(rc < 0 && errno == EFAULT,
                "getrandom should fail with EFAULT after truncate");

    munmap(p, page);
    close(fd);
}

/* read/readv on /dev/urandom, the sibling of the getrandom fill. Both are
 * served by a host-side memcpy under the per-fd entropy cache lock, so both
 * have to stage through a host buffer rather than take the recovery pad.
 *
 * The request is deliberately larger than the shim's inline urandom limit so
 * the read reaches the host handler instead of being served from EL1.
 */
static void test_urandom_read(void)
{
    TEST("read(/dev/urandom) into truncated MAP_SHARED returns EFAULT");

    const size_t page = (size_t) sysconf(_SC_PAGESIZE);
    int fd = -1;
    char *p = map_then_truncate(page, &fd);
    if (!p)
        return;

    int u = open("/dev/urandom", O_RDONLY);
    if (u < 0) {
        munmap(p, page);
        close(fd);
        FAIL("open /dev/urandom");
        return;
    }

    errno = 0;
    long rc = read(u, p, 2048);
    EXPECT_TRUE(rc < 0 && errno == EFAULT,
                "read(/dev/urandom) should fail with EFAULT after truncate");

    struct iovec iov = {.iov_base = p, .iov_len = 2048};
    errno = 0;
    rc = readv(u, &iov, 1);
    EXPECT_TRUE(rc < 0 && errno == EFAULT,
                "readv(/dev/urandom) should fail with EFAULT after truncate");

    /* Two entries, because one short-circuits to the scalar read path and never
     * reaches the multi-entry loop that resolves each iov separately. That loop
     * is its own host kill: it dies with SIGBUS before the staging fix.
     *
     * The good page comes first so some bytes move before the vanished one is
     * reached, which is what makes this a partial transfer rather than an
     * outright failure. Both outcomes are accepted because the split depends on
     * how far the kernel got, not on anything elfuse decides; what must not
     * happen is a full count, which would mean the vanished page was reported
     * as written.
     */
    char scratch[64];
    struct iovec two[2] = {{.iov_base = scratch, .iov_len = sizeof(scratch)},
                           {.iov_base = p, .iov_len = 2048}};
    errno = 0;
    rc = readv(u, two, 2);
    EXPECT_TRUE(rc < 0 ? errno == EFAULT
                       : rc >= 0 && rc < (long) (sizeof(scratch) + 2048),
                "multi-entry readv must stop at the vanished page");

    close(u);
    munmap(p, page);
    close(fd);
}

/* getrandom(2) and read(2) on /dev/urandom at or under 256 bytes, which the
 * shim serves by storing into the buffer at EL1.
 */
static void test_urandom_inline(void)
{
    TEST("inline urandom into truncated MAP_SHARED returns EFAULT");

    const size_t page = (size_t) sysconf(_SC_PAGESIZE);
    int fd = -1;
    char *p = map_then_truncate(page, &fd);
    if (!p)
        return;

    errno = 0;
    long rc = syscall(SYS_getrandom, p, (size_t) 64, 0);
    EXPECT_TRUE(rc < 0 && errno == EFAULT,
                "inline getrandom should fail with EFAULT after truncate");

    int u = open("/dev/urandom", O_RDONLY);
    if (u < 0) {
        munmap(p, page);
        close(fd);
        FAIL("open /dev/urandom");
        return;
    }
    errno = 0;
    rc = read(u, p, 64);
    EXPECT_TRUE(rc < 0 && errno == EFAULT,
                "inline read(/dev/urandom) should fail with EFAULT");

    close(u);
    munmap(p, page);
    close(fd);
}

/* The host-side memmove in process_vm_readv, guest memory on both ends. */
static void test_process_vm_readv(void)
{
    TEST("process_vm_readv from truncated MAP_SHARED returns EFAULT");

    const size_t page = (size_t) sysconf(_SC_PAGESIZE);
    int fd = -1;
    char *p = map_then_truncate(page, &fd);
    if (!p)
        return;

    char dst[64];
    struct iovec local = {.iov_base = dst, .iov_len = sizeof(dst)};
    struct iovec remote = {.iov_base = p, .iov_len = sizeof(dst)};

    errno = 0;
    long rc = syscall(SYS_process_vm_readv, (long) getpid(), &local, 1UL,
                      &remote, 1UL, 0UL);

    /* ENOSYS is an acceptable outcome: the point is that elfuse survives. */
    EXPECT_TRUE(rc < 0 && (errno == EFAULT || errno == ENOSYS),
                "process_vm_readv should fail rather than kill the host");

    munmap(p, page);
    close(fd);
}

int main(void)
{
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, NULL);

    test_path_copy();
    test_futex_word();
    test_futex_word_shim();
    test_el0_access();
    test_el0_exec();
    test_getrandom_fill();
    test_urandom_inline();
    test_urandom_read();
    test_process_vm_readv();
    SUMMARY("test-mmap-sigbus-efault");
    return fails ? 1 : 0;
}
