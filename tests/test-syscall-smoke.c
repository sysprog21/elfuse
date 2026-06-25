/* Direct syscall smoke coverage for less frequently hit dispatch entries
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef SYS_close_range
#define SYS_close_range 436
#endif

#ifndef SYS_execveat
#define SYS_execveat 281
#endif

#ifndef SYS_pwrite64
#define SYS_pwrite64 68
#endif

#ifndef SYS_preadv2
#define SYS_preadv2 286
#endif

#ifndef SYS_renameat
#define SYS_renameat 38
#endif

#ifndef SYS_sigaltstack
#define SYS_sigaltstack 132
#endif

#ifndef O_PATH
#define O_PATH 010000000
#endif

#ifndef SYS_set_tid_address
#define SYS_set_tid_address 96
#endif

#ifndef SYS_sync_file_range
#define SYS_sync_file_range 84
#endif

#ifndef SYS_syncfs
#define SYS_syncfs 267
#endif

int passes = 0, fails = 0;
extern char **environ;

struct linux_cap_user_header {
    uint32_t version;
    int32_t pid;
};

struct linux_cap_user_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

static void test_pwrite64_basic(void)
{
    TEST("pwrite64");
    char path[] = "/tmp/elfuse-pwrite64-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }
    unlink(path);

    const char *msg = "xyz";
    ssize_t rc = (ssize_t) syscall(SYS_pwrite64, fd, msg, 3, 1);
    if (rc != 3) {
        FAIL("pwrite64");
        close(fd);
        return;
    }

    char buf[8] = {0};
    lseek(fd, 0, SEEK_SET);
    if (read(fd, buf, sizeof(buf)) >= 4 && memcmp(buf, "\0xyz", 4) == 0)
        PASS();
    else
        FAIL("pwrite64 contents");
    close(fd);
}

static void test_splice_family(void)
{
    TEST("vmsplice + splice");
    int src[2] = {-1, -1};
    int mid[2] = {-1, -1};
    struct iovec iov = {.iov_base = (void *) "pipe-data", .iov_len = 9};
    char out[16] = {0};
    bool ok = false;

    if (pipe(src) != 0 || pipe(mid) != 0) {
        FAIL("pipe");
        goto out;
    }
    if (syscall(SYS_vmsplice, src[1], &iov, 1, 0) != 9) {
        FAIL("vmsplice");
        goto out;
    }
    if (syscall(SYS_splice, src[0], NULL, mid[1], NULL, 9, 0) != 9) {
        FAIL("splice");
        goto out;
    }
    if (read(mid[0], out, sizeof(out)) != 9 ||
        memcmp(out, "pipe-data", 9) != 0) {
        FAIL("splice payload");
        goto out;
    }
    ok = true;

out:
    if (src[0] >= 0)
        close(src[0]);
    if (src[1] >= 0)
        close(src[1]);
    if (mid[0] >= 0)
        close(mid[0]);
    if (mid[1] >= 0)
        close(mid[1]);
    if (ok)
        PASS();
}

static void test_tee_stub_errno(void)
{
    TEST("tee returns EINVAL");
    int src[2] = {-1, -1};
    int dst[2] = {-1, -1};

    if (pipe(src) != 0 || pipe(dst) != 0) {
        FAIL("pipe");
        goto out;
    }

    errno = 0;
    EXPECT_ERRNO(syscall(SYS_tee, src[0], dst[1], 1, 0), EINVAL,
                 "tee should report EINVAL");

out:
    if (src[0] >= 0)
        close(src[0]);
    if (src[1] >= 0)
        close(src[1]);
    if (dst[0] >= 0)
        close(dst[0]);
    if (dst[1] >= 0)
        close(dst[1]);
}

static void test_close_range_basic(void)
{
    TEST("close_range");
    int pipes[3][2];
    memset(pipes, -1, sizeof(pipes));
    for (size_t i = 0; i < 3; i++) {
        if (pipe(pipes[i]) != 0) {
            FAIL("pipe");
            goto out;
        }
    }

    unsigned first = (unsigned) pipes[0][0];
    unsigned last = (unsigned) pipes[2][1];
    if (syscall(SYS_close_range, first, last, 0) != 0) {
        FAIL("close_range");
        goto out;
    }

    /* Probe before clearing pipes[] so the EXPECT_ERRNO actually tests
     * close_range's effect, not close(-1). On success every fd in the range is
     * closed, so leave pipes[] zeroed afterward to keep the cleanup loop from
     * double-closing.
     */
    int probe_fd = pipes[1][0];
    memset(pipes, -1, sizeof(pipes));
    errno = 0;
    EXPECT_ERRNO(close(probe_fd), EBADF, "close_range left fd open");

out:
    for (size_t i = 0; i < 3; i++) {
        if (pipes[i][0] >= 0)
            close(pipes[i][0]);
        if (pipes[i][1] >= 0)
            close(pipes[i][1]);
    }
}

static void test_at_path_ops(void)
{
    TEST("mknodat + mkdirat + symlinkat + renameat");
    char dir_template[] = "/tmp/elfuse-atops-XXXXXX";
    char fifo_path[256] = "";
    char link_path[256] = "";
    char moved_path[256] = "";
    char subdir_path[256] = "";
    int dirfd = -1;
    bool ok = false;

    if (!mkdtemp(dir_template)) {
        FAIL("mkdtemp");
        return;
    }
    /* Materialize cleanup paths up-front so that any early goto-out still
     * unlinks/rmdirs whatever the syscalls under test managed to create.
     */
    snprintf(fifo_path, sizeof(fifo_path), "%s/fifo", dir_template);
    snprintf(link_path, sizeof(link_path), "%s/fifo.link", dir_template);
    snprintf(moved_path, sizeof(moved_path), "%s/fifo.moved", dir_template);
    snprintf(subdir_path, sizeof(subdir_path), "%s/sub", dir_template);

    dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        goto out;
    }
    if (syscall(SYS_mkdirat, dirfd, "sub", 0700) != 0) {
        FAIL("mkdirat");
        goto out;
    }
    if (syscall(SYS_mknodat, dirfd, "fifo", S_IFIFO | 0600, 0) != 0) {
        FAIL("mknodat");
        goto out;
    }
    if (syscall(SYS_symlinkat, "fifo", dirfd, "fifo.link") != 0) {
        FAIL("symlinkat");
        goto out;
    }
    if (syscall(SYS_renameat, dirfd, "fifo.link", dirfd, "fifo.moved") != 0) {
        FAIL("renameat");
        goto out;
    }
    if (access(link_path, F_OK) == 0 || errno != ENOENT ||
        access(moved_path, F_OK) != 0 || access(fifo_path, F_OK) != 0) {
        FAIL("path ops verification");
        goto out;
    }
    ok = true;

out:
    if (dirfd >= 0)
        close(dirfd);
    if (moved_path[0])
        unlink(moved_path);
    if (link_path[0])
        unlink(link_path);
    if (fifo_path[0])
        unlink(fifo_path);
    if (subdir_path[0])
        rmdir(subdir_path);
    rmdir(dir_template);
    /* Body-side FAIL() already reported the specific step on failure; only
     * report PASS here. Adding a trailing else-FAIL would double-count.
     */
    if (ok)
        PASS();
}

static void test_statfs_and_umask(void)
{
    TEST("statfs + umask");
    struct statfs st;
    mode_t old = umask(022);
    mode_t restored = umask(old);
    if (statfs("/tmp", &st) == 0 && st.f_bsize > 0 && restored == 022)
        PASS();
    else
        FAIL("statfs/umask");
}

static void test_direct_gap_syscalls(void)
{
    TEST(
        "preadv2 + fstatfs + fchmodat + sync + setregid + setresgid + "
        "sched_yield");
    char path[] = "/tmp/elfuse-syscall-gap-XXXXXX";
    int fd = -1;
    struct iovec iov;
    char buf[8] = {0};
    struct statfs st;
    struct stat sb;
    bool ok = false;

    fd = mkstemp(path);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }

    if (write(fd, "abcd", 4) != 4) {
        FAIL("write");
        goto out;
    }

    iov.iov_base = buf;
    iov.iov_len = 3;
    if (preadv2(fd, &iov, 1, 1, 0) != 3 || memcmp(buf, "bcd", 3) != 0) {
        FAIL("preadv2");
        goto out;
    }
    if (fstatfs(fd, &st) != 0 || st.f_bsize <= 0) {
        FAIL("fstatfs");
        goto out;
    }
    if (fchmodat(AT_FDCWD, path, 0600, 0) != 0) {
        FAIL("fchmodat");
        goto out;
    }
    if (stat(path, &sb) != 0 || (sb.st_mode & 0777) != 0600) {
        FAIL("fchmodat verify");
        goto out;
    }
    sync();
    if (setregid((gid_t) -1, (gid_t) -1) != 0) {
        FAIL("setregid");
        goto out;
    }
    if (setresgid((gid_t) -1, (gid_t) -1, (gid_t) -1) != 0) {
        FAIL("setresgid");
        goto out;
    }
    if (sched_yield() != 0) {
        FAIL("sched_yield");
        goto out;
    }
    ok = true;

out:
    if (fd >= 0)
        close(fd);
    unlink(path);
    if (ok)
        PASS();
}

static void test_sigaltstack_and_timers(void)
{
    TEST("sigaltstack + getitimer + setitimer + clock_getres");
    stack_t old_ss;
    stack_t ss = {0};
    sigset_t oldmask, blockmask;
    bool mask_saved = false;
    struct itimerval old_timer;
    struct itimerval timer = {0};
    struct timespec ts;
    bool ok = false;

    ss.ss_size = SIGSTKSZ;
    ss.ss_sp = malloc(ss.ss_size);
    if (!ss.ss_sp) {
        FAIL("malloc");
        return;
    }
    if (syscall(SYS_sigaltstack, &ss, &old_ss) != 0) {
        FAIL("sigaltstack");
        goto out;
    }
    sigemptyset(&blockmask);
    sigaddset(&blockmask, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &blockmask, &oldmask) != 0) {
        FAIL("sigprocmask");
        goto out;
    }
    mask_saved = true;
    timer.it_value.tv_usec = 1000;
    if (setitimer(ITIMER_REAL, &timer, &old_timer) != 0) {
        FAIL("setitimer");
        goto out;
    }
    if (getitimer(ITIMER_REAL, &timer) != 0) {
        FAIL("getitimer");
        goto out;
    }
    if (clock_getres(CLOCK_MONOTONIC, &ts) != 0) {
        FAIL("clock_getres");
        goto out;
    }
    if (timer.it_value.tv_sec < 0 || ts.tv_nsec < 0) {
        FAIL("timer query");
        goto out;
    }
    ok = true;

out:
    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &timer, NULL);
    if (mask_saved)
        sigprocmask(SIG_SETMASK, &oldmask, NULL);
    ss.ss_flags = SS_DISABLE;
    syscall(SYS_sigaltstack, &ss, NULL);
    free(ss.ss_sp);
    /* Body-side FAIL() already reported the specific step on failure. */
    if (ok)
        PASS();
}

static void test_waitid(void)
{
    TEST("waitid");
    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork");
        return;
    }
    if (pid == 0)
        _exit(17);

    siginfo_t info;
    memset(&info, 0, sizeof(info));
    long rc = syscall(SYS_waitid, P_PID, pid, &info, WEXITED, NULL);
    if (rc == 0 && info.si_pid == pid && info.si_status == 17) {
        PASS();
        return;
    }
    /* waitid failed or returned the wrong siginfo; reap with waitpid so the
     * child does not linger as a zombie and skew later tests.
     */
    int status;
    waitpid(pid, &status, 0);
    FAIL("waitid");
}

static void test_execveat(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--execveat-child") == 0)
        _exit(23);

    TEST("execveat");
    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork");
        return;
    }
    if (pid == 0) {
        char *child_argv[] = {argv[0], "--execveat-child", NULL};
        syscall(SYS_execveat, AT_FDCWD, argv[0], child_argv, environ, 0);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
        WEXITSTATUS(status) == 23)
        PASS();
    else
        FAIL("execveat");
}

static void test_process_query_stubs(void)
{
    TEST("set_tid_address + capget + personality");
    int clear_tid = 0;
    struct linux_cap_user_header hdr = {
        .version = 0x20080522,
        .pid = 0,
    };
    struct linux_cap_user_data data[2];
    memset(data, 0, sizeof(data));

    long tid = syscall(SYS_set_tid_address, &clear_tid);
    long caps = syscall(SYS_capget, &hdr, data);
    long pers = syscall(SYS_personality, 0xffffffffu);
    if (tid > 0 && caps == 0 && pers >= 0)
        PASS();
    else
        FAIL("process query stubs");
}

static void test_stub_errnos(void)
{
    TEST("sethostname returns EPERM");
    errno = 0;
    EXPECT_ERRNO(syscall(SYS_sethostname, "elfuse", 6), EPERM,
                 "sethostname should fail with EPERM");

    TEST("io_destroy returns EINVAL");
    errno = 0;
    EXPECT_ERRNO(syscall(SYS_io_destroy, 1), EINVAL,
                 "io_destroy should fail with EINVAL");

    TEST("mincore returns ENOSYS");
    char page[4096];
    unsigned char vec = 0xff;
    errno = 0;
    EXPECT_ERRNO(syscall(SYS_mincore, page, sizeof(page), &vec), ENOSYS,
                 "mincore should fail with ENOSYS");
}

static void test_memory_stubs(void)
{
    TEST("mlock + munlock");
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    if (mlock(p, 4096) == 0 && munlock(p, 4096) == 0)
        PASS();
    else
        FAIL("mlock/munlock");
    munmap(p, 4096);
}

static void test_accept4(void)
{
    TEST("accept4");
    int listen_fd = -1, client_fd = -1, server_fd = -1;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    pid_t pid;
    int status = 0;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        FAIL("socket");
        return;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listen_fd, (struct sockaddr *) &addr, sizeof(addr)) != 0 ||
        listen(listen_fd, 1) != 0 ||
        getsockname(listen_fd, (struct sockaddr *) &addr, &addrlen) != 0) {
        FAIL("listen setup");
        goto out;
    }

    pid = fork();
    if (pid < 0) {
        FAIL("fork");
        goto out;
    }
    if (pid == 0) {
        client_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (client_fd < 0)
            _exit(1);
        int rc = connect(client_fd, (struct sockaddr *) &addr, sizeof(addr));
        _exit(rc == 0 ? 0 : 2);
    }

    /* Gate the blocking accept4() on a poll(): if the child fails before
     * connect(), no incoming connection will ever arrive and the parent would
     * wedge the test until the driver timeout. The poll bounds the wait so we
     * can detect that case and fail fast.
     */
    struct pollfd pfd = {.fd = listen_fd, .events = POLLIN};
    int pr = poll(&pfd, 1, 2000);
    if (pr <= 0) {
        waitpid(pid, &status, 0);
        FAIL("no client connection within 2s");
        goto out;
    }
    server_fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
    waitpid(pid, &status, 0);
    if (server_fd < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        FAIL("accept4 handshake");
        goto out;
    }
    int flags = fcntl(server_fd, F_GETFD);
    if (flags < 0 || !(flags & FD_CLOEXEC)) {
        FAIL("SOCK_CLOEXEC not applied");
        goto out;
    }
    PASS();

out:
    if (server_fd >= 0)
        close(server_fd);
    if (client_fd >= 0)
        close(client_fd);
    if (listen_fd >= 0)
        close(listen_fd);
}

static void test_sysv_semaphore_ops(void)
{
    TEST("semget + semctl + semop");
    int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    if (semid < 0) {
        FAIL("semget");
        return;
    }

    union semun arg = {.val = 1};
    struct sembuf sop = {.sem_num = 0, .sem_op = -1, .sem_flg = 0};
    if (semctl(semid, 0, SETVAL, arg) == 0 && semop(semid, &sop, 1) == 0 &&
        semctl(semid, 0, IPC_RMID, arg) == 0)
        PASS();
    else {
        semctl(semid, 0, IPC_RMID, arg);
        FAIL("semop");
    }
}

static void test_urandom_byte_reads(void)
{
    TEST("/dev/urandom byte reads");
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        FAIL("open");
        return;
    }

    unsigned char bytes[32];
    for (size_t i = 0; i < sizeof(bytes); i++) {
        ssize_t n = read(fd, &bytes[i], 1);
        if (n != 1) {
            close(fd);
            FAIL("read");
            return;
        }
    }
    close(fd);

    bool all_same = true;
    for (size_t i = 1; i < sizeof(bytes); i++) {
        if (bytes[i] != bytes[0]) {
            all_same = false;
            break;
        }
    }
    if (all_same) {
        FAIL("entropy stream did not vary");
        return;
    }
    PASS();
}

static void test_urandom_open_flags(void)
{
    TEST("/dev/urandom open flags");

    errno = 0;
    int dirfd = open("/dev/urandom", O_RDONLY | O_DIRECTORY);
    if (dirfd >= 0) {
        close(dirfd);
        FAIL("O_DIRECTORY open succeeded");
        return;
    }
    if (errno != ENOTDIR) {
        FAIL("O_DIRECTORY errno");
        return;
    }

    int pathfd = open("/dev/urandom", O_PATH | O_CLOEXEC);
    if (pathfd < 0) {
        FAIL("O_PATH open");
        return;
    }
    unsigned char b = 0;
    errno = 0;
    ssize_t n = read(pathfd, &b, 1);
    int saved_errno = errno;
    close(pathfd);
    if (n != -1 || saved_errno != EBADF) {
        FAIL("O_PATH read");
        return;
    }

    int wfd = open("/dev/urandom", O_WRONLY | O_CLOEXEC);
    if (wfd < 0) {
        FAIL("O_WRONLY open");
        return;
    }
    int fl = fcntl(wfd, F_GETFL);
    errno = 0;
    n = read(wfd, &b, 1);
    saved_errno = errno;
    close(wfd);
    if (fl < 0 || (fl & O_ACCMODE) != O_WRONLY) {
        FAIL("O_WRONLY F_GETFL");
        return;
    }
    if (n != -1 || saved_errno != EBADF) {
        FAIL("O_WRONLY read");
        return;
    }

    wfd = open("/dev/urandom", O_WRONLY | O_CLOEXEC);
    if (wfd < 0) {
        FAIL("O_WRONLY open dup");
        return;
    }
    int dupfd = dup(wfd);
    close(wfd);
    if (dupfd < 0) {
        FAIL("O_WRONLY dup");
        return;
    }
    errno = 0;
    n = read(dupfd, &b, 1);
    saved_errno = errno;
    close(dupfd);
    if (n != -1 || saved_errno != EBADF) {
        FAIL("O_WRONLY dup read");
        return;
    }

    wfd = open("/dev/urandom", O_WRONLY | O_CLOEXEC);
    if (wfd < 0) {
        FAIL("O_WRONLY open readv");
        return;
    }
    struct iovec wv[2] = {{&b, 1}, {&b, 1}};
    errno = 0;
    n = readv(wfd, wv, 2);
    saved_errno = errno;
    close(wfd);
    if (n != -1 || saved_errno != EBADF) {
        FAIL("O_WRONLY readv");
        return;
    }

    wfd = open("/dev/urandom", O_WRONLY | O_CLOEXEC);
    if (wfd < 0) {
        FAIL("O_WRONLY open oversized readv");
        return;
    }
    struct iovec huge_wv[2] = {{&b, SSIZE_MAX}, {&b, 1}};
    errno = 0;
    n = readv(wfd, huge_wv, 2);
    saved_errno = errno;
    close(wfd);
    if (n != -1 || saved_errno != EBADF) {
        FAIL("O_WRONLY oversized readv");
        return;
    }

    wfd = open("/dev/urandom", O_WRONLY | O_CLOEXEC);
    if (wfd < 0) {
        FAIL("O_WRONLY open oversized single readv");
        return;
    }
    struct iovec huge_one_wv = {&b, (size_t) SSIZE_MAX + 1};
    errno = 0;
    n = readv(wfd, &huge_one_wv, 1);
    saved_errno = errno;
    close(wfd);
    if (n != -1 || saved_errno != EBADF) {
        FAIL("O_WRONLY oversized single readv");
        return;
    }

    int rfd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (rfd < 0) {
        FAIL("O_RDONLY open readv");
        return;
    }
    unsigned char rb[2] = {0};
    struct iovec rv[2] = {{&rb[0], 1}, {&rb[1], 1}};
    n = readv(rfd, rv, 2);
    if (n != 2) {
        close(rfd);
        FAIL("O_RDONLY readv");
        return;
    }

    struct iovec huge[2] = {{&b, SSIZE_MAX}, {&b, 1}};
    errno = 0;
    n = readv(rfd, huge, 2);
    saved_errno = errno;
    if (n != -1 || saved_errno != EINVAL) {
        close(rfd);
        FAIL("oversized readv");
        return;
    }

    struct iovec huge_one = {&b, (size_t) SSIZE_MAX + 1};
    errno = 0;
    n = readv(rfd, &huge_one, 1);
    saved_errno = errno;
    if (n != -1 || saved_errno != EINVAL) {
        close(rfd);
        FAIL("oversized single readv");
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(rfd);
        FAIL("fork inherited urandom");
        return;
    }
    if (pid == 0) {
        unsigned char child_b = 0;
        _exit(read(rfd, &child_b, 1) == 1 ? 0 : 1);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        close(rfd);
        FAIL("inherited urandom read");
        return;
    }

    int p[2];
    if (pipe(p) != 0) {
        close(rfd);
        FAIL("urandom fork pipe");
        return;
    }
    unsigned char seed = 0;
    if (read(rfd, &seed, 1) != 1) {
        close(rfd);
        close(p[0]);
        close(p[1]);
        FAIL("prime urandom cache before fork");
        return;
    }
    pid = fork();
    if (pid < 0) {
        close(rfd);
        close(p[0]);
        close(p[1]);
        FAIL("fork urandom cache isolation");
        return;
    }
    if (pid == 0) {
        close(p[0]);
        unsigned char child_buf[64];
        ssize_t got = read(rfd, child_buf, sizeof(child_buf));
        ssize_t put = got == (ssize_t) sizeof(child_buf)
                          ? write(p[1], child_buf, sizeof(child_buf))
                          : -1;
        close(p[1]);
        _exit(put == (ssize_t) sizeof(child_buf) ? 0 : 1);
    }
    close(p[1]);
    unsigned char parent_buf[64];
    unsigned char child_buf[64];
    ssize_t parent_n = read(rfd, parent_buf, sizeof(parent_buf));
    ssize_t child_n = read(p[0], child_buf, sizeof(child_buf));
    close(p[0]);
    status = 0;
    waitpid(pid, &status, 0);
    close(rfd);
    if (parent_n != (ssize_t) sizeof(parent_buf) ||
        child_n != (ssize_t) sizeof(child_buf) || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        FAIL("urandom fork cache isolation read");
        return;
    }
    if (memcmp(parent_buf, child_buf, sizeof(parent_buf)) == 0) {
        FAIL("urandom fork duplicated cached bytes");
        return;
    }

    PASS();
}

static void test_sync_file_range(void)
{
    TEST("sync_file_range");
    char path[] = "/tmp/elfuse-sync-file-range-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }
    unlink(path);

    /* Write some data first */
    const char *msg = "hello sync_file_range";
    if (write(fd, msg, strlen(msg)) != (ssize_t) strlen(msg)) {
        FAIL("write");
        close(fd);
        return;
    }

    /* 1. Test basic success case with valid flags (SYNC_FILE_RANGE_WRITE, etc.)
     */
    /* Note: SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE |
     * SYNC_FILE_RANGE_WAIT_AFTER is 7 */
    if (syscall(SYS_sync_file_range, fd, (off64_t) 0, (off64_t) 0, 7) != 0) {
        FAIL("sync_file_range basic");
        close(fd);
        return;
    }

    /* 2. Test invalid flags (only bits 1, 2, 4 are valid) */
    errno = 0;
    if (syscall(SYS_sync_file_range, fd, (off64_t) 0, (off64_t) 0, 8) != -1 ||
        errno != EINVAL) {
        FAIL("sync_file_range invalid flags");
        close(fd);
        return;
    }

    /* 3. Test invalid offset (offset < 0) */
    errno = 0;
    if (syscall(SYS_sync_file_range, fd, (off64_t) -1, (off64_t) 0, 7) != -1 ||
        errno != EINVAL) {
        FAIL("sync_file_range negative offset");
        close(fd);
        return;
    }

    /* 4. Test invalid nbytes (nbytes < 0) */
    errno = 0;
    if (syscall(SYS_sync_file_range, fd, (off64_t) 0, (off64_t) -1, 7) != -1 ||
        errno != EINVAL) {
        FAIL("sync_file_range negative nbytes");
        close(fd);
        return;
    }

    /* 5. Test offset + nbytes overflow */
    errno = 0;
    off64_t huge_offset = 0x7fffffffffffffffLL;
    off64_t huge_nbytes = 1;
    if (syscall(SYS_sync_file_range, fd, huge_offset, huge_nbytes, 7) != -1 ||
        errno != EINVAL) {
        FAIL("sync_file_range offset+nbytes overflow");
        close(fd);
        return;
    }

    /* 6. SYNC_FILE_RANGE_WRITE only (async hint) returns 0 without blocking.
     * Covers the deliberate-divergence branch. */
    if (syscall(SYS_sync_file_range, fd, (off64_t) 0, (off64_t) 0, 2) != 0) {
        FAIL("sync_file_range write-only");
        close(fd);
        return;
    }

    /* 7. Bad fd → EBADF. */
    errno = 0;
    if (syscall(SYS_sync_file_range, -1, (off64_t) 0, (off64_t) 0, 7) != -1 ||
        errno != EBADF) {
        FAIL("sync_file_range bad fd");
        close(fd);
        return;
    }

    /* 8. Unsupported file type (pipe) → ESPIPE. */
    int pipefds[2];
    if (pipe(pipefds) == 0) {
        errno = 0;
        if (syscall(SYS_sync_file_range, pipefds[0], (off64_t) 0, (off64_t) 0,
                    7) != -1 ||
            errno != ESPIPE) {
            FAIL("sync_file_range pipe ESPIPE");
            close(pipefds[0]);
            close(pipefds[1]);
            close(fd);
            return;
        }
        close(pipefds[0]);
        close(pipefds[1]);
    } else {
        FAIL("pipe creation failed");
    }

    close(fd);
    PASS();
}

static void test_syncfs(void)
{
    TEST("syncfs");
    char path[] = "/tmp/elfuse-syncfs-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }
    unlink(path);

    /* 1. Test basic success case */
    if (syscall(SYS_syncfs, fd) != 0) {
        FAIL("syncfs basic");
        close(fd);
        return;
    }

    /* 2. Test invalid fd case (should return EBADF) */
    errno = 0;
    if (syscall(SYS_syncfs, -1) != -1 || errno != EBADF) {
        FAIL("syncfs invalid fd");
        close(fd);
        return;
    }

    close(fd);
    PASS();
}

int main(int argc, char **argv)
{
    printf("test-syscall-smoke: direct syscall smoke coverage\n\n");

    test_pwrite64_basic();
    test_splice_family();
    test_tee_stub_errno();
    test_close_range_basic();
    test_at_path_ops();
    test_statfs_and_umask();
    test_direct_gap_syscalls();
    test_sigaltstack_and_timers();
    test_waitid();
    test_execveat(argc, argv);
    test_process_query_stubs();
    test_stub_errnos();
    test_memory_stubs();
    test_accept4();
    test_sysv_semaphore_ops();
    test_urandom_byte_reads();
    test_urandom_open_flags();
    test_sync_file_range();
    test_syncfs();

    SUMMARY("test-syscall-smoke");
    return fails > 0 ? 1 : 0;
}
