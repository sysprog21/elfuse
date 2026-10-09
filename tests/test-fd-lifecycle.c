/*
 * fd metadata lifecycle regression tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Syscalls: memfd_create, fcntl, dup, close, openat, write, setrlimit
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef SYS_memfd_create
#define SYS_memfd_create 279
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef MFD_HUGETLB
#define MFD_HUGETLB 0x0004U
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif

#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif

#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif

int passes = 0, fails = 0;

static int create_memfd(void)
{
    return (int) syscall(SYS_memfd_create, "elfuse-seal-test",
                         MFD_ALLOW_SEALING);
}

static void test_memfd_accepts_valid_linux_flags(void)
{
    TEST("memfd accepts valid flags");

    int fd = (int) syscall(SYS_memfd_create, "elfuse-valid-flags",
                           MFD_ALLOW_SEALING | MFD_HUGETLB);
    if (fd < 0) {
        FAIL("memfd_create rejected valid flags");
        return;
    }
    close(fd);
    PASS();
}

/* An MFD_HUGETLB memfd is a hugetlbfs file, the one kind of file Linux lets
 * MAP_HUGETLB name. Without a huge page pool the mapping can still fail with
 * ENOMEM, so only EINVAL is wrong.
 */
static void test_memfd_hugetlb_maps_hugetlb(void)
{
    TEST("MAP_HUGETLB on an MFD_HUGETLB memfd");

    int fd = (int) syscall(SYS_memfd_create, "elfuse-hugetlb",
                           MFD_ALLOW_SEALING | MFD_HUGETLB);
    if (fd < 0) {
        FAIL("memfd_create failed");
        return;
    }

    int seals = fcntl(fd, F_GET_SEALS);
    size_t len = 2u << 20;
    void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_HUGETLB,
                   fd, 0);
    int map_errno = p == MAP_FAILED ? errno : 0;
    if (p != MAP_FAILED)
        munmap(p, len);
    close(fd);

    if (seals != 0)
        FAIL("F_GET_SEALS reported bits that are not seals");
    else if (map_errno == EINVAL)
        FAIL("mmap refused MAP_HUGETLB with EINVAL");
    else
        PASS();
}

static void test_memfd_seals_survive_dup(void)
{
    TEST("memfd seals copied to dup");

    int fd = create_memfd();
    if (fd < 0) {
        FAIL("memfd_create failed");
        return;
    }

    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) < 0) {
        FAIL("F_ADD_SEALS failed");
        close(fd);
        return;
    }

    int dupfd = dup(fd);
    if (dupfd < 0) {
        FAIL("dup failed");
        close(fd);
        return;
    }

    char c = 'x';
    errno = 0;
    EXPECT_ERRNO(write(dupfd, &c, 1), EPERM, "sealed dup accepted write");

    close(dupfd);
    close(fd);
}

static void test_memfd_seals_propagate_to_dup(void)
{
    TEST("memfd seals propagate to dup");

    int fd = create_memfd();
    if (fd < 0) {
        FAIL("memfd_create failed");
        return;
    }

    int dupfd = dup(fd);
    if (dupfd < 0) {
        FAIL("dup failed");
        close(fd);
        return;
    }

    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) < 0) {
        FAIL("F_ADD_SEALS failed");
        close(dupfd);
        close(fd);
        return;
    }

    char c = 'x';
    errno = 0;
    EXPECT_ERRNO(write(dupfd, &c, 1), EPERM,
                 "post-dup seal did not affect dup");

    close(dupfd);
    close(fd);
}

static void test_memfd_seals_cleared_on_reuse(void)
{
    TEST("fd seals cleared on reuse");

    int fd = create_memfd();
    if (fd < 0) {
        FAIL("memfd_create failed");
        return;
    }
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) < 0) {
        FAIL("F_ADD_SEALS failed");
        close(fd);
        return;
    }

    close(fd);

    char path[] = "/tmp/elfuse-seal-reuse-XXXXXX";
    int regular = mkstemp(path);
    if (regular < 0) {
        FAIL("mkstemp failed");
        return;
    }
    unlink(path);

    char c = 'y';
    errno = 0;
    ssize_t ret = write(regular, &c, 1);
    EXPECT_TRUE(ret == 1, "reused fd kept stale seal");

    close(regular);
}

static void test_rlimit_nofile_reports_emfile(void)
{
    TEST("RLIMIT_NOFILE reports EMFILE");

    struct rlimit old_limit;
    if (getrlimit(RLIMIT_NOFILE, &old_limit) != 0) {
        FAIL("getrlimit failed");
        return;
    }

    int held = open("/dev/null", O_RDONLY);
    if (held < 0) {
        FAIL("open setup failed");
        return;
    }

    struct rlimit new_limit = old_limit;
    new_limit.rlim_cur = (rlim_t) (held + 1);
    if (setrlimit(RLIMIT_NOFILE, &new_limit) != 0) {
        FAIL("setrlimit failed");
        close(held);
        return;
    }

    errno = 0;
    int fd = open("/dev/null", O_RDONLY);
    if (fd < 0 && errno == EMFILE)
        PASS();
    else {
        if (fd >= 0)
            close(fd);
        FAIL("open did not return EMFILE");
    }

    setrlimit(RLIMIT_NOFILE, &old_limit);
    close(held);
}

static void test_dup3_above_rlimit_fails(void)
{
    TEST("dup3 above RLIMIT_NOFILE fails");

    struct rlimit old_limit;
    if (getrlimit(RLIMIT_NOFILE, &old_limit) != 0) {
        FAIL("getrlimit failed");
        return;
    }

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        FAIL("pipe setup failed");
        return;
    }

    struct rlimit new_limit = old_limit;
    new_limit.rlim_cur = (rlim_t) (pipefd[1] + 1);
    if (setrlimit(RLIMIT_NOFILE, &new_limit) != 0) {
        FAIL("setrlimit failed");
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    errno = 0;
    int dupfd = dup3(pipefd[0], pipefd[1] + 1, 0);
    EXPECT_TRUE(dupfd < 0 && (errno == EBADF || errno == EMFILE),
                "dup3 beyond RLIMIT_NOFILE should fail with EBADF or EMFILE");

    setrlimit(RLIMIT_NOFILE, &old_limit);
    close(pipefd[0]);
    close(pipefd[1]);
}

static void test_nofile_hides_host_reserve(void)
{
    TEST("RLIMIT_NOFILE hides host reserve");

    struct rlimit limit;
    struct utsname uts;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || uname(&uts) != 0) {
        FAIL("getrlimit or uname failed");
        return;
    }

    if (strcmp(uts.nodename, "elfuse") == 0) {
        EXPECT_TRUE(limit.rlim_cur == 1024 && limit.rlim_max == 1024,
                    "elfuse exposed its host FD reserve");
    } else {
        EXPECT_TRUE(limit.rlim_cur > 0 && limit.rlim_cur <= limit.rlim_max,
                    "native RLIMIT_NOFILE is invalid");
    }
}

static void test_nofile_lowered_before_fork(void)
{
    TEST("fork preserves FDs above lowered RLIMIT_NOFILE");

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        FAIL("pipe setup failed");
        return;
    }

    struct rlimit low_limit = {.rlim_cur = 3, .rlim_max = 3};
    if (setrlimit(RLIMIT_NOFILE, &low_limit) != 0) {
        FAIL("setrlimit failed");
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        char byte = 'x';
        ssize_t n = write(pipefd[1], &byte, 1);
        _exit(n == 1 ? 0 : 1);
    }
    if (pid < 0) {
        FAIL("fork failed after lowering RLIMIT_NOFILE");
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    close(pipefd[1]);
    char byte = 0;
    ssize_t n = read(pipefd[0], &byte, 1);
    close(pipefd[0]);

    int status = 0;
    pid_t waited = waitpid(pid, &status, 0);
    EXPECT_TRUE(n == 1 && byte == 'x' && waited == pid && WIFEXITED(status) &&
                    WEXITSTATUS(status) == 0,
                "fork child did not preserve the inherited pipe");
}

int main(void)
{
    printf("test-fd-lifecycle: fd metadata lifecycle tests\n\n");

    test_memfd_seals_survive_dup();
    test_memfd_seals_propagate_to_dup();
    test_memfd_seals_cleared_on_reuse();
    test_memfd_accepts_valid_linux_flags();
    test_memfd_hugetlb_maps_hugetlb();
    test_rlimit_nofile_reports_emfile();
    test_dup3_above_rlimit_fails();
    test_nofile_hides_host_reserve();
    /* This permanently lowers the hard limit, so it must remain last. */
    test_nofile_lowered_before_fork();

    SUMMARY("test-fd-lifecycle");
    return fails > 0 ? 1 : 0;
}
