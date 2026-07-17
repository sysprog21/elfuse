/*
 * Negative / error-path tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises error paths: invalid FDs, bad syscall numbers, bad mmap arguments,
 * EFAULT (bad pointers), errno translation, EINVAL (bad flags), and boundary
 * conditions. All should return proper Linux error codes without crashing.
 */

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#include <time.h>

#include "test-harness.h"
#include "raw-syscall.h"

#ifndef O_PATH
#define O_PATH 010000000
#endif

#ifndef LINUX_AT_EMPTY_PATH
#define LINUX_AT_EMPTY_PATH 0x1000
#endif

int passes = 0, fails = 0;

static sigjmp_buf segv_jmp;
static volatile sig_atomic_t saw_segv;

static void on_sigsegv(int sig)
{
    (void) sig;
    saw_segv = 1;
    siglongjmp(segv_jmp, 1);
}

/* Test 1: Invalid FD operations */

static void test_invalid_fd(void)
{
    TEST("read(999) -> EBADF");
    {
        char buf[16];
        EXPECT_ERRNO(read(999, buf, sizeof(buf)), EBADF, "expected EBADF");
    }

    TEST("write(999) -> EBADF");
    EXPECT_ERRNO(write(999, "x", 1), EBADF, "expected EBADF");

    TEST("close(999) -> EBADF");
    EXPECT_ERRNO(close(999), EBADF, "expected EBADF");

    TEST("dup(-1) -> EBADF");
    EXPECT_ERRNO(dup(-1), EBADF, "expected EBADF");
}

/* Test 2: Invalid syscall number -> ENOSYS */

static void test_invalid_syscall(void)
{
    /* Linux ENOSYS = 38 */
    TEST("syscall(9999) -> ENOSYS");
    EXPECT_RAW_ERRNO(raw_syscall1(9999, 0), -38, "expected -ENOSYS (-38)");
}

/* Test 3: mmap with bad arguments */

static void test_bad_mmap(void)
{
    TEST("mmap bad fd (not ANON) -> error");
    {
        /* Non-anonymous mmap with invalid fd should fail */
        void *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 999, 0);
        if (p == MAP_FAILED)
            PASS();
        else {
            munmap(p, 4096);
            FAIL("expected MAP_FAILED");
        }
    }

    TEST("mmap(MAP_FIXED, bad addr) -> error");
    {
        /* MAP_FIXED at an absurdly high address should fail */
        void *p =
            mmap((void *) 0xFFFF000000000000ULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        EXPECT_TRUE(p == MAP_FAILED, "expected MAP_FAILED");
    }

    TEST("mmap + munmap round-trip");
    {
        /* Verify basic mmap+munmap lifecycle works */
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            FAIL("mmap failed");
        } else {
            *(volatile int *) p = 42;
            int r = munmap(p, 4096);
            EXPECT_TRUE(r == 0, "munmap failed");
        }
    }
}

/* Test 4: Read/write on closed FD */

static void test_closed_fd(void)
{
    TEST("read closed pipe -> EBADF");
    {
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            FAIL("pipe() failed");
            return;
        }
        int rd = pipefd[0];
        close(rd);

        char buf[16];
        EXPECT_ERRNO(read(rd, buf, sizeof(buf)), EBADF,
                     "expected EBADF on closed FD");

        close(pipefd[1]);
    }
}

/* Test 5: Double close */

static void test_double_close(void)
{
    TEST("double close -> EBADF");
    {
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            FAIL("pipe() failed");
            return;
        }
        close(pipefd[0]);
        EXPECT_ERRNO(close(pipefd[0]), EBADF, "expected EBADF on double close");
        close(pipefd[1]);
    }
}

/* Test 6: Write to read-only mmap region */

static void test_mmap_prot(void)
{
    TEST("mmap read-only is readable");
    {
        /* Allocate RW, write data, change to RO, verify readable */
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            FAIL("mmap failed");
            return;
        }
        *(volatile int *) p = 42;
        mprotect(p, 4096, PROT_READ);
        int val = *(volatile int *) p;
        EXPECT_TRUE(val == 42, "data not readable after RO mprotect");
        munmap(p, 4096);
    }

    TEST("same-prot mprotect keeps RO mmap unwritable");
    {
        void *p =
            mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            FAIL("mmap failed");
            return;
        }
        if (mprotect(p, 4096, PROT_READ) != 0) {
            munmap(p, 4096);
            FAIL("mprotect failed");
            return;
        }

        struct sigaction old_sa;
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_sigsegv;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGSEGV, &sa, &old_sa) != 0) {
            munmap(p, 4096);
            FAIL("sigaction failed");
            return;
        }

        saw_segv = 0;
        if (sigsetjmp(segv_jmp, 1) == 0)
            *(volatile int *) p = 7;

        sigaction(SIGSEGV, &old_sa, NULL);
        munmap(p, 4096);
        EXPECT_TRUE(saw_segv, "write to read-only mapping succeeded");
    }

    TEST("fast single-page mprotect drains publication ring");
    {
        volatile int *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            FAIL("mmap failed");
            return;
        }
        *p = 1; /* Materialize a partial block, which installs an L3 table. */
        for (int i = 0; i < 96; i++) {
            int prot = (i & 1) ? PROT_READ : PROT_READ | PROT_WRITE;
            if (mprotect((void *) p, 4096, prot) != 0) {
                munmap((void *) p, 4096);
                FAIL("mprotect toggle failed");
                return;
            }
        }

        struct sigaction old_sa;
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_sigsegv;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGSEGV, &sa, &old_sa) != 0) {
            munmap((void *) p, 4096);
            FAIL("sigaction failed");
            return;
        }
        saw_segv = 0;
        if (sigsetjmp(segv_jmp, 1) == 0)
            *p = 2;
        sigaction(SIGSEGV, &old_sa, NULL);

        int restored = mprotect((void *) p, 4096, PROT_READ | PROT_WRITE) == 0;
        if (restored)
            *p = 3;
        int final = *p;
        munmap((void *) p, 4096);
        EXPECT_TRUE(saw_segv && restored && final == 3,
                    "fast mprotect permissions or ring drain were stale");
    }

    TEST("first lazy 2MiB block mprotect materializes safely");
    {
        const size_t block_size = 2 * 1024 * 1024;
        volatile unsigned char *seed =
            mmap(NULL, block_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (seed == MAP_FAILED) {
            FAIL("seed mmap failed");
            return;
        }
        seed[1024 * 1024] = 0x7f;
        munmap((void *) seed, block_size);
        /* Force retirement so the next mmap can reuse backing whose dirty bit
         * remains conservative. mprotect must update lazy metadata without
         * exposing the stale byte; the later read performs the zeroing fault.
         */
        (void) fcntl(-1, F_GETFD);

        volatile unsigned char *p =
            mmap(NULL, block_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            FAIL("mmap failed");
            return;
        }
        volatile unsigned char *mid = p + 1024 * 1024;
        if (mprotect((void *) mid, 4096, PROT_READ) != 0) {
            munmap((void *) p, block_size);
            FAIL("first-block mprotect failed");
            return;
        }

        int zeroed = p[0] == 0 && mid[0] == 0 && p[block_size - 1] == 0;
        p[0] = 0x31;
        p[block_size - 1] = 0x32;

        struct sigaction old_sa;
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_sigsegv;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGSEGV, &sa, &old_sa) != 0) {
            munmap((void *) p, block_size);
            FAIL("sigaction failed");
            return;
        }
        saw_segv = 0;
        if (sigsetjmp(segv_jmp, 1) == 0)
            mid[0] = 0x33;
        sigaction(SIGSEGV, &old_sa, NULL);

        int restored =
            mprotect((void *) mid, 4096, PROT_READ | PROT_WRITE) == 0;
        if (restored)
            mid[0] = 0x34;
        int neighbors = p[0] == 0x31 && p[block_size - 1] == 0x32;
        int target = mid[0] == 0x34;
        munmap((void *) p, block_size);
        EXPECT_TRUE(zeroed && saw_segv && restored && neighbors && target,
                    "first-block split exposed stale bytes or wrong perms");
    }
}

/* Test 7: fcntl on invalid FD */

static void test_fcntl_invalid(void)
{
    TEST("fcntl(999, F_GETFL) -> EBADF");
    EXPECT_ERRNO(fcntl(999, F_GETFL), EBADF, "expected EBADF");
}

/* Test 8: lseek on pipe -> ESPIPE */

static void test_lseek_pipe(void)
{
    TEST("lseek(pipe) -> ESPIPE");
    {
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            FAIL("pipe() failed");
            return;
        }
        EXPECT_ERRNO(lseek(pipefd[0], 0, SEEK_SET), ESPIPE, "expected ESPIPE");
        close(pipefd[0]);
        close(pipefd[1]);
    }
}

/* Test 9: Read from write-only FD */

static void test_write_only_read(void)
{
    TEST("read(write-end of pipe) -> EBADF");
    {
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            FAIL("pipe() failed");
            return;
        }
        char buf[16];
        EXPECT_ERRNO(read(pipefd[1], buf, sizeof(buf)), EBADF,
                     "expected EBADF");
        close(pipefd[0]);
        close(pipefd[1]);
    }
}

/* Test 10: EFAULT (bad pointer to read/write/getcwd) */

static void test_efault(void)
{
    /* Use an unmapped high address as a bad pointer. Raw syscalls return -errno
     * directly. Linux EFAULT = 14.
     */
    void *bad_ptr = (void *) 0xDEAD000000000000ULL;
    const char *expected_efault = "expected -EFAULT (-14)";

    TEST("read(0, bad_ptr) -> EFAULT");
    EXPECT_RAW_ERRNO(raw_syscall3(__NR_read, 0, (long) bad_ptr, 16), -14,
                     expected_efault);

    TEST("write(1, bad_ptr) -> EFAULT");
    EXPECT_RAW_ERRNO(raw_syscall3(__NR_write, 1, (long) bad_ptr, 16), -14,
                     expected_efault);

    TEST("getcwd(bad_ptr) -> EFAULT");
    EXPECT_RAW_ERRNO(raw_syscall2(__NR_getcwd, (long) bad_ptr, 256), -14,
                     expected_efault);

    TEST("uname(bad_ptr) -> EFAULT");
    EXPECT_RAW_ERRNO(raw_syscall1(__NR_uname, (long) bad_ptr), -14,
                     expected_efault);

    TEST("clock_gettime(bad_ptr) -> EFAULT");
    EXPECT_RAW_ERRNO(raw_syscall2(__NR_clock_gettime, 0 /* CLOCK_REALTIME */,
                                  (long) bad_ptr),
                     -14, expected_efault);
}

/* Test 11: Linux errno numeric values */

static void test_errno_values(void)
{
    /* Verify that elfuse translates macOS errno -> Linux errno correctly. These
     * are the most commonly divergent values.
     */

    TEST("EAGAIN is 11");
    {
        /* Non-blocking read on empty pipe gives EAGAIN */
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            FAIL("pipe() failed");
            return;
        }
        fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
        char buf[1];
        EXPECT_ERRNO(read(pipefd[0], buf, 1), 11, "expected errno 11 (EAGAIN)");
        close(pipefd[0]);
        close(pipefd[1]);
    }

    TEST("ENOSYS is 38");
    EXPECT_RAW_ERRNO(raw_syscall1(9999, 0), -38, "expected -38 (ENOSYS)");

    TEST("EBADF is 9");
    EXPECT_RAW_ERRNO(raw_syscall3(__NR_read, 999, 0, 0), -9,
                     "expected -9 (EBADF)");

    TEST("EINVAL is 22");
    {
        /* clock_gettime with invalid clock ID */
        struct timespec ts;
        EXPECT_RAW_ERRNO(
            raw_syscall2(__NR_clock_gettime, 99 /* invalid */, (long) &ts), -22,
            "expected -22 (EINVAL)");
    }

    TEST("ESPIPE is 29");
    {
        /* lseek on pipe */
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            FAIL("pipe() failed");
            return;
        }
        EXPECT_RAW_ERRNO(
            raw_syscall3(__NR_lseek, pipefd[0], 0, 0 /* SEEK_SET */), -29,
            "expected -29 (ESPIPE)");
        close(pipefd[0]);
        close(pipefd[1]);
    }
}

/* Test 12: EINVAL (bad arguments) */

static void test_einval(void)
{
    TEST("socket(bad domain) -> error");
    {
        /* AF 255 is not a valid address family */
        int s = socket(255, SOCK_STREAM, 0);
        if (s == -1 && (errno == EINVAL || errno == EAFNOSUPPORT ||
                        errno == EPROTONOSUPPORT))
            PASS();
        else {
            if (s >= 0)
                close(s);
            FAIL("expected EINVAL/EAFNOSUPPORT");
        }
    }

    TEST("munmap(0, 0) -> EINVAL");
    EXPECT_ERRNO(munmap(NULL, 0), EINVAL, "expected EINVAL");

    TEST("mmap(size=0) -> EINVAL");
    {
        void *p = mmap(NULL, 0, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED && errno == EINVAL)
            PASS();
        else {
            if (p != MAP_FAILED)
                munmap(p, 4096);
            FAIL("expected EINVAL for zero size");
        }
    }

    TEST("pipe2(bad flags) -> EINVAL");
    {
        int pipefd[2];
        EXPECT_ERRNO(pipe2(pipefd, O_APPEND), EINVAL,
                     "expected EINVAL for invalid pipe2 flags");
    }

    TEST("pipe2(O_DIRECT) accepted");
    {
        int pipefd[2];
        int r = pipe2(pipefd, O_DIRECT);
        if (r == 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            PASS();
        } else {
            FAIL("expected O_DIRECT pipe2 flag to be accepted");
        }
    }

    TEST("dup3(bad flags) -> EINVAL");
    {
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            FAIL("pipe() failed");
        } else {
            EXPECT_ERRNO(dup3(pipefd[0], pipefd[1], O_NONBLOCK), EINVAL,
                         "expected EINVAL for invalid dup3 flags");
            close(pipefd[0]);
            close(pipefd[1]);
        }
    }

    TEST("fcntl(F_DUPFD, -1) -> EINVAL");
    {
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            FAIL("pipe() failed");
        } else {
            EXPECT_ERRNO(fcntl(pipefd[0], F_DUPFD, -1), EINVAL,
                         "expected EINVAL for negative F_DUPFD");
            close(pipefd[0]);
            close(pipefd[1]);
        }
    }

    TEST("nanosleep(bad nsec) -> EINVAL");
    {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000000000L};
        EXPECT_ERRNO(nanosleep(&ts, NULL), EINVAL,
                     "expected EINVAL for invalid tv_nsec");
    }

    TEST("clock_nanosleep(bad clockid) -> EINVAL");
    {
        /* Replaces an earlier "bad flags" probe that was unreliable: Linux's
         * clock_nanosleep only validates the (flags & TIMER_ABSTIME) bit and
         * silently ignores other bits, so a raw-syscall flag check round-trips
         * to glibc territory rather than the kernel. An invalid clockid is a
         * real kernel-side error path.
         */
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 1};
        EXPECT_RAW_ERRNO(raw_syscall4(__NR_clock_nanosleep, 99 /* invalid */, 0,
                                      (long) &ts, 0),
                         -22, "expected -EINVAL for invalid clockid");
    }

    TEST("clock_nanosleep(absolute past)");
    {
        /* TIMER_ABSTIME with a deadline already in the past must return 0
         * immediately (no sleep). Use tv_sec=0 to stay in the kernel's "valid
         * timespec" space -- Linux rejects negative tv_sec with -EINVAL even
         * before the deadline-in-past check.
         */
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 0};
        long r = raw_syscall4(__NR_clock_nanosleep, CLOCK_MONOTONIC,
                              TIMER_ABSTIME, (long) &ts, 0);
        EXPECT_TRUE(r == 0, "expected past absolute sleep to return 0");
    }

    TEST("*at bad flags -> EINVAL");
    {
        /* Path must exist: kernel validates flags before path resolution for
         * the *at syscalls below, but a non-existent path can mask the flag
         * error if the implementation reorders these (or if the flag arg is
         * silently ignored, like sys_faccessat which only takes
         * dirfd/path/mode). Using "/tmp" sidesteps both pitfalls.
         */
        const char *path = "/tmp";
        const long bad = 0x40000000L;
        long r1 = raw_syscall3(__NR_unlinkat, AT_FDCWD, (long) path, bad);
        long r2 = raw_syscall6(__NR_linkat, AT_FDCWD, (long) path, AT_FDCWD,
                               (long) path, bad, 0);
        long r3 = raw_syscall6(__NR_fchownat, AT_FDCWD, (long) path, (long) -1,
                               (long) -1, bad, 0);
        long r4 =
            raw_syscall6(__NR_utimensat, AT_FDCWD, (long) path, 0, bad, 0, 0);
        EXPECT_TRUE(r1 == -22 && r2 == -22 && r3 == -22 && r4 == -22,
                    "expected EINVAL for invalid *at flags");
    }

    TEST("utimensat both UTIME_OMIT ignores NULL-path validation");
    {
        struct timespec omit[2] = {{.tv_sec = 0, .tv_nsec = UTIME_OMIT},
                                   {.tv_sec = 0, .tv_nsec = UTIME_OMIT}};
        long r = raw_syscall6(__NR_utimensat, AT_FDCWD, 0, (long) omit,
                              LINUX_AT_EMPTY_PATH, 0, 0);
        EXPECT_TRUE(r == 0,
                    "expected UTIME_OMIT no-op to bypass NULL-path checks");
    }

    TEST("open(O_PATH) metadata-only fd");
    {
        const char *path = "/tmp/elfuse-negative-opath";
        int wfd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (wfd < 0) {
            FAIL("create test file failed");
        } else {
            write(wfd, "x", 1);
            close(wfd);

            int fd = open(path, O_PATH | O_CLOEXEC);
            if (fd < 0) {
                unlink(path);
                FAIL("open(O_PATH) failed");
            } else {
                struct stat st;
                int fl = fcntl(fd, F_GETFL);
                char c;
                int ok = (fstat(fd, &st) == 0) && ((fl & O_PATH) == O_PATH) &&
                         (read(fd, &c, 1) == -1 && errno == EBADF);
                close(fd);
                unlink(path);
                EXPECT_TRUE(
                    ok, "expected O_PATH fd to allow fstat but reject read");
            }
        }
    }
}

/* Test 13: Socket error paths */

static void test_socket_errors(void)
{
    TEST("connect(bad fd) -> EBADF");
    {
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        EXPECT_ERRNO(connect(999, (struct sockaddr *) &addr, sizeof(addr)),
                     EBADF, "expected EBADF");
    }

    TEST("getsockopt(bad fd) -> EBADF");
    {
        int val;
        socklen_t len = sizeof(val);
        EXPECT_ERRNO(getsockopt(999, SOL_SOCKET, SO_TYPE, &val, &len), EBADF,
                     "expected EBADF");
    }

    TEST("accept(non-socket) -> ENOTSOCK");
    {
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            FAIL("pipe failed");
            return;
        }
        EXPECT_ERRNO(accept(pipefd[0], NULL, NULL), ENOTSOCK,
                     "expected ENOTSOCK");
        close(pipefd[0]);
        close(pipefd[1]);
    }
}

/* Main */

int main(void)
{
    printf("test-negative: error path tests\n");

    test_invalid_fd();
    test_invalid_syscall();
    test_bad_mmap();
    test_closed_fd();
    test_double_close();
    test_mmap_prot();
    test_fcntl_invalid();
    test_lseek_pipe();
    test_write_only_read();
    test_efault();
    test_errno_values();
    test_einval();
    test_socket_errors();

    SUMMARY("test-negative");
    return fails > 0 ? 1 : 0;
}
