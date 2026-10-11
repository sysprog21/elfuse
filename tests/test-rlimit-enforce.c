/*
 * Test that guest rlimits are enforced
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * RLIMIT_FSIZE at the write, truncate and file-copy boundaries, RLIMIT_CPU
 * against a loop that makes no syscall, and RLIMIT_AS and RLIMIT_DATA where a
 * mapping or the break would grow past them. Each limit is lowered in a fork
 * child, so the process that reports the results keeps its own limits.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define FSIZE_LIMIT 4096

static volatile sig_atomic_t xfsz_count;

static void on_xfsz(int sig)
{
    (void) sig;
    xfsz_count++;
}

/* True if @rc is -1 with EFBIG and exactly one more SIGXFSZ has arrived. */
static int refused_with_xfsz(long rc, int *seen)
{
    int ok = rc == -1 && errno == EFBIG && xfsz_count == *seen + 1;
    *seen = xfsz_count;
    return ok;
}

/* Runs in a child under RLIMIT_FSIZE = FSIZE_LIMIT. Nothing is printed while
 * the limit is in force, because stdout may be a regular file too. The exit
 * status is the number of the first step that went wrong, 0 if none did.
 */
static int fsize_child(void)
{
    char path[] = "/tmp/elfuse-rlimit-enforce.XXXXXX";
    char block[FSIZE_LIMIT];
    int fd = mkstemp(path);
    struct rlimit rl;
    struct sigaction sa = {.sa_handler = on_xfsz};
    int seen = 0, step = 0;

    memset(block, 'x', sizeof(block));
    if (fd < 0 || sigaction(SIGXFSZ, &sa, NULL) < 0 ||
        getrlimit(RLIMIT_FSIZE, &rl) < 0)
        return 100;
    rl.rlim_cur = FSIZE_LIMIT;
    if (setrlimit(RLIMIT_FSIZE, &rl) < 0)
        return 101;

    /* 1: a write that ends at the limit is whole. */
    step++;
    if (write(fd, block, 4000) != 4000)
        goto out;

    /* 2: a write that crosses the limit is cut at it, with no signal. */
    step++;
    if (write(fd, block, 200) != 96 || xfsz_count != 0)
        goto out;

    /* 3: a write that starts at the limit. */
    step++;
    if (!refused_with_xfsz(write(fd, block, 1), &seen))
        goto out;

    /* 4: pwrite past the limit. */
    step++;
    if (!refused_with_xfsz(pwrite(fd, block, 1, 2 * FSIZE_LIMIT), &seen))
        goto out;

    /* 5: a two-entry writev that crosses the limit is cut at it. */
    step++;
    {
        struct iovec iov[2] = {{block, 50}, {block, 100}};
        if (lseek(fd, FSIZE_LIMIT - 60, SEEK_SET) < 0 ||
            writev(fd, iov, 2) != 60 || xfsz_count != seen)
            goto out;
    }

    /* 6: an O_APPEND descriptor starts at end of file, which is the limit. */
    step++;
    {
        int afd = open(path, O_WRONLY | O_APPEND);
        long rc = afd < 0 ? 0 : write(afd, block, 1);
        int ok = refused_with_xfsz(rc, &seen);

        /* pwrite on it appends too, so an offset under the limit is no help. */
        rc = afd < 0 ? 0 : pwrite(afd, block, 1, 0);
        ok = ok && refused_with_xfsz(rc, &seen);
        if (afd >= 0)
            close(afd);
        if (!ok)
            goto out;
    }

    /* 7 and 8: growing past the limit, by descriptor and by path. */
    step++;
    if (!refused_with_xfsz(ftruncate(fd, 2 * FSIZE_LIMIT), &seen))
        goto out;
    step++;
    if (!refused_with_xfsz(truncate(path, 2 * FSIZE_LIMIT), &seen))
        goto out;

    /* 9: a descriptor not open for writing is refused for that, with no signal,
     * before the limit is looked at.
     */
    step++;
    {
        int rfd = open(path, O_RDONLY);
        int rc = rfd < 0 ? 0 : ftruncate(rfd, 2 * FSIZE_LIMIT);
        int ok = rc == -1 && errno == EINVAL && xfsz_count == seen;
        rc = rfd < 0 ? 0 : fallocate(rfd, 0, 0, 2 * FSIZE_LIMIT);
        ok = ok && rc == -1 && errno == EBADF && xfsz_count == seen;

        /* So is a write, at the limit by position and past it by offset. */
        struct iovec iov = {block, 1};
        ok = ok && lseek(rfd, 0, SEEK_END) == FSIZE_LIMIT;
        ok = ok && write(rfd, block, 1) == -1 && errno == EBADF;
        ok = ok && writev(rfd, &iov, 1) == -1 && errno == EBADF;
        ok = ok && pwrite(rfd, block, 1, 2 * FSIZE_LIMIT) == -1 &&
             errno == EBADF;
        ok = ok && pwritev(rfd, &iov, 1, 2 * FSIZE_LIMIT) == -1 &&
             errno == EBADF && xfsz_count == seen;
        if (rfd >= 0)
            close(rfd);
        if (!ok)
            goto out;
    }

    /* 10: shrinking, and growing back up to the limit, are not refused. */
    step++;
    if (ftruncate(fd, 100) < 0 || ftruncate(fd, FSIZE_LIMIT) < 0 ||
        xfsz_count != seen)
        goto out;

    /* 11: RWF_APPEND writes at end of file, now the limit, whatever offset it
     * is given. The raw call, because the glibc wrapper reports any failure of
     * a flagged request as ENOTSUP.
     */
    step++;
    {
        struct iovec iov = {block, 1};
        if (!refused_with_xfsz(
                syscall(SYS_pwritev2, fd, &iov, 1, 0L, 0L, RWF_APPEND), &seen))
            goto out;
    }

    /* 12: a vector with no bytes in it writes nothing and is not refused, at
     * the limit or past it.
     */
    step++;
    {
        struct iovec iov[2] = {{block, 0}, {block, 0}};
        if (lseek(fd, 0, SEEK_END) != FSIZE_LIMIT || writev(fd, iov, 2) != 0 ||
            pwritev(fd, iov, 2, 2 * FSIZE_LIMIT) != 0 ||
            syscall(SYS_pwritev2, fd, iov, 2, 0L, 0L, RWF_APPEND) != 0 ||
            xfsz_count != seen)
            goto out;
    }

    step = 0;
out:
    close(fd);
    unlink(path);
    return step;
}

#define COPY_SRC_SIZE 20000

/* Empty @dst_fd, grow it to @dst_size and leave its position there; put
 * @src_fd's position at @src_pos.
 */
static int copy_reset(int dst_fd, off_t dst_size, int src_fd, off_t src_pos)
{
    return ftruncate(dst_fd, 0) < 0 || ftruncate(dst_fd, dst_size) < 0 ||
           lseek(dst_fd, dst_size, SEEK_SET) < 0 ||
           lseek(src_fd, src_pos, SEEK_SET) < 0;
}

/* Runs in a child under RLIMIT_FSIZE = FSIZE_LIMIT, for the calls that grow a
 * file without write or truncate. A stream copy cut at the limit still raises
 * SIGXFSZ, because the kernel goes on to offer the rest of its input to the
 * file; copy_file_range checks its whole request up front and does not.
 */
static int fsize_copy_child(void)
{
    char src[] = "/tmp/elfuse-rlimit-src.XXXXXX";
    char dst[] = "/tmp/elfuse-rlimit-dst.XXXXXX";
    static char block[COPY_SRC_SIZE];
    int sfd = mkstemp(src), dfd = mkstemp(dst), pfd[2];
    struct rlimit rl;
    struct sigaction sa = {.sa_handler = on_xfsz};
    int seen = 0, step = 0;

    memset(block, 'y', sizeof(block));
    if (sfd < 0 || dfd < 0 || pipe(pfd) < 0 ||
        write(sfd, block, sizeof(block)) != sizeof(block) ||
        sigaction(SIGXFSZ, &sa, NULL) < 0 || getrlimit(RLIMIT_FSIZE, &rl) < 0)
        return 100;
    rl.rlim_cur = FSIZE_LIMIT;
    if (setrlimit(RLIMIT_FSIZE, &rl) < 0)
        return 101;

    /* 1: sendfile across the limit is cut at it and raises the signal. */
    step++;
    if (copy_reset(dfd, 0, sfd, 0) ||
        sendfile(dfd, sfd, NULL, 10000) != FSIZE_LIMIT || xfsz_count != 1 ||
        lseek(sfd, 0, SEEK_CUR) != FSIZE_LIMIT)
        goto out;
    seen = xfsz_count;

    /* 2: sendfile that starts at the limit. */
    step++;
    if (!refused_with_xfsz(sendfile(dfd, sfd, NULL, 100), &seen))
        goto out;

    /* 3: no signal when the input ends where the limit is. */
    step++;
    if (copy_reset(dfd, FSIZE_LIMIT - 96, sfd, COPY_SRC_SIZE - 96) ||
        sendfile(dfd, sfd, NULL, 5000) != 96 || xfsz_count != seen)
        goto out;

    /* 4: copy_file_range across the limit is cut at it with no signal. */
    step++;
    if (copy_reset(dfd, 0, sfd, 0) ||
        copy_file_range(sfd, NULL, dfd, NULL, 10000, 0) != FSIZE_LIMIT ||
        xfsz_count != seen)
        goto out;

    /* 5: at the limit it is refused whatever the length. */
    step++;
    if (!refused_with_xfsz(copy_file_range(sfd, NULL, dfd, NULL, 0, 0), &seen))
        goto out;

    /* 6: splice across the limit leaves the rest in the pipe. */
    step++;
    if (copy_reset(dfd, 0, sfd, 0) || write(pfd[1], block, 10000) != 10000 ||
        splice(pfd[0], NULL, dfd, NULL, 10000, 0) != FSIZE_LIMIT ||
        xfsz_count != seen + 1 ||
        read(pfd[0], block, sizeof(block)) != 10000 - FSIZE_LIMIT)
        goto out;
    seen = xfsz_count;

    /* 7: fallocate may reach the limit and not pass it. */
    step++;
    if (copy_reset(dfd, 0, sfd, 0) || fallocate(dfd, 0, 0, FSIZE_LIMIT) < 0 ||
        xfsz_count != seen ||
        !refused_with_xfsz(fallocate(dfd, 0, 0, FSIZE_LIMIT + 1), &seen))
        goto out;

    /* 8: with the file at the limit, a pipe that has nothing to give raises no
     * signal: no byte reached the file. It is EAGAIN while a writer is left and
     * end of input once the writer is gone.
     */
    step++;
    {
        int empty[2];
        if (pipe2(empty, O_NONBLOCK) < 0 ||
            copy_reset(dfd, FSIZE_LIMIT, sfd, 0))
            goto out;
        long rc = splice(empty[0], NULL, dfd, NULL, 100, SPLICE_F_NONBLOCK);
        int ok = rc == -1 && errno == EAGAIN && xfsz_count == seen;
        close(empty[1]);
        rc = splice(empty[0], NULL, dfd, NULL, 100, SPLICE_F_NONBLOCK);
        ok = ok && rc == 0 && xfsz_count == seen;
        close(empty[0]);
        if (!ok)
            goto out;
    }

    step = 0;
out:
    close(sfd);
    close(dfd);
    unlink(src);
    unlink(dst);
    return step;
}

static void *unblock_xfsz_and_wait(void *arg)
{
    sigset_t set;
    char c;
    sigemptyset(&set);
    sigaddset(&set, SIGXFSZ);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
    (void) !write(((int *) arg)[1], "r", 1);
    (void) !read(((int *) arg)[2], &c, 1);
    return NULL;
}

/* Runs in a child. The writer has SIGXFSZ blocked and a second thread does not:
 * a signal sent to the process would run the handler on that thread, and one
 * sent to the writer stays pending on it.
 */
static int fsize_thread_child(void)
{
    char path[] = "/tmp/elfuse-rlimit-thread.XXXXXX";
    int fd = mkstemp(path), ready[2], hold[2], step = 1;
    struct sigaction sa = {.sa_handler = on_xfsz};
    struct rlimit rl;
    sigset_t set, pending;
    pthread_t thread;
    char c;

    sigemptyset(&set);
    sigaddset(&set, SIGXFSZ);
    if (fd < 0 || pipe(ready) < 0 || pipe(hold) < 0 ||
        sigaction(SIGXFSZ, &sa, NULL) < 0 ||
        pthread_sigmask(SIG_BLOCK, &set, NULL) != 0 ||
        getrlimit(RLIMIT_FSIZE, &rl) < 0)
        return 100;
    int fds[3] = {ready[0], ready[1], hold[0]};
    if (pthread_create(&thread, NULL, unblock_xfsz_and_wait, fds) != 0 ||
        read(ready[0], &c, 1) != 1)
        return 101;
    rl.rlim_cur = 0;
    if (setrlimit(RLIMIT_FSIZE, &rl) < 0)
        return 102;

    if (write(fd, "x", 1) != -1 || errno != EFBIG)
        goto out;
    step++;
    usleep(100000);
    if (xfsz_count != 0 || sigpending(&pending) < 0 ||
        !sigismember(&pending, SIGXFSZ))
        goto out;
    step = 0;
out:
    (void) !write(hold[1], "x", 1);
    pthread_join(thread, NULL);
    close(fd);
    unlink(path);
    return step;
}

static int cpu_report_fd;

static void on_xcpu(int sig)
{
    (void) sig;
    (void) !write(cpu_report_fd, "x", 1);
}

/* Runs in a child under RLIMIT_CPU = 1 s soft, 2 s hard, and never returns. It
 * reports 'p' once it has run for a while with the limit set, which a guest
 * stalled by the limit never does, then loops with no syscall, so only the
 * limit can end it.
 */
static void cpu_child(int report_fd)
{
    struct rlimit rl = {.rlim_cur = 1, .rlim_max = 2};
    struct sigaction sa = {.sa_handler = on_xcpu};
    struct timespec t0, t;

    cpu_report_fd = report_fd;
    if (sigaction(SIGXCPU, &sa, NULL) < 0 || setrlimit(RLIMIT_CPU, &rl) < 0)
        _exit(100);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        clock_gettime(CLOCK_MONOTONIC, &t);
    } while ((t.tv_sec - t0.tv_sec) * 1000000000L + t.tv_nsec - t0.tv_nsec <
             100000000L);
    (void) !write(report_fd, "p", 1);
    for (volatile unsigned long spin = 0;; spin++)
        ;
}

#define MIB ((size_t) 1 << 20)

/* VmSize from /proc/self/status in bytes, which is what RLIMIT_AS bounds. */
static size_t vm_size(void)
{
    char buf[4096];
    int fd = open("/proc/self/status", O_RDONLY);
    ssize_t n = fd < 0 ? -1 : read(fd, buf, sizeof(buf) - 1);
    if (fd >= 0)
        close(fd);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    char *p = strstr(buf, "VmSize:");
    return p ? (size_t) strtoul(p + 7, NULL, 10) * 1024 : 0;
}

static int set_soft(int resource, rlim_t cur)
{
    struct rlimit rl;
    if (getrlimit(resource, &rl) < 0)
        return -1;
    rl.rlim_cur = cur;
    return setrlimit(resource, &rl);
}

static void *map_anon(void *addr, size_t len, int prot, int flags)
{
    return mmap(addr, len, prot, flags | MAP_ANONYMOUS, -1, 0);
}

/* Runs in a child with RLIMIT_AS 24 MiB above what is mapped. The exit status
 * is the number of the first step that went wrong, 0 if none did.
 */
static int as_child(void)
{
    size_t base = vm_size();
    int rw = PROT_READ | PROT_WRITE;
    if (base == 0 || set_soft(RLIMIT_AS, base + 24 * MIB) < 0)
        return 100;

    /* 1: a mapping that stays below the limit. */
    void *a = map_anon(NULL, 16 * MIB, rw, MAP_PRIVATE);
    if (a == MAP_FAILED)
        return 1;

    /* 2: one that crosses it, with 8 MiB left. */
    errno = 0;
    if (map_anon(NULL, 16 * MIB, rw, MAP_PRIVATE) != MAP_FAILED ||
        errno != ENOMEM)
        return 2;

    /* 3: a shared or read-only mapping is address space too. */
    errno = 0;
    if (map_anon(NULL, 16 * MIB, PROT_READ, MAP_SHARED) != MAP_FAILED ||
        errno != ENOMEM)
        return 3;

    /* 4: MAP_FIXED over the first mapping replaces it and adds nothing. */
    if (map_anon(a, 16 * MIB, rw, MAP_PRIVATE | MAP_FIXED) != a)
        return 4;

    /* 5: growing it by mremap crosses the limit. */
    errno = 0;
    if (mremap(a, 16 * MIB, 32 * MIB, MREMAP_MAYMOVE) != MAP_FAILED ||
        errno != ENOMEM)
        return 5;

    /* 6: what munmap gives back can be mapped again. */
    if (munmap(a, 16 * MIB) < 0 ||
        map_anon(NULL, 16 * MIB, rw, MAP_PRIVATE) == MAP_FAILED)
        return 6;

    /* 7: a bad descriptor is reported before the limit is, for a hinted, a
     * placed and a fixed request alike.
     */
    void *at = (char *) a + 16 * MIB;
    int fixed = MAP_PRIVATE | MAP_FIXED;
    errno = 0;
    if (mmap(NULL, 32 * MIB, PROT_READ, MAP_PRIVATE, -1, 0) != MAP_FAILED ||
        errno != EBADF)
        return 7;
    errno = 0;
    if (mmap(at, 32 * MIB, PROT_READ, fixed, -1, 0) != MAP_FAILED ||
        errno != EBADF)
        return 7;
    return 0;
}

/* Bytes /proc/self/maps lists, less the elfuse runtime records ([shim],
 * [shim-data]) that a Linux process has no mapping for.
 */
static size_t maps_size(void)
{
    static char buf[64 * 1024];
    size_t len = 0;
    ssize_t n = 0;
    int fd = open("/proc/self/maps", O_RDONLY);
    while (fd >= 0 && len < sizeof(buf) - 1 &&
           (n = read(fd, buf + len, sizeof(buf) - 1 - len)) > 0)
        len += (size_t) n;
    if (fd >= 0)
        close(fd);
    if (fd < 0 || n < 0)
        return 0;
    buf[len] = '\0';

    size_t total = 0;
    for (char *line = buf; *line; line = strchr(line, '\n') + 1) {
        char *end;
        unsigned long lo = strtoul(line, &end, 16);
        unsigned long hi = strtoul(end + 1, NULL, 16);
        char *nl = strchr(line, '\n');
        if (!nl)
            break;
        *nl = '\0';
        if (!strstr(line, "[shim"))
            total += hi - lo;
        *nl = '\n';
    }
    return total;
}

/* Runs in a child with RLIMIT_AS 1 MiB above what maps lists. The exit status
 * is the number of the first step that went wrong, 0 if none did.
 */
static int as_exact_child(void)
{
    size_t base = maps_size();
    int rw = PROT_READ | PROT_WRITE;
    if (base == 0 || set_soft(RLIMIT_AS, base + MIB) < 0)
        return 100;

    /* 1: the last MiB under the limit. */
    if (map_anon(NULL, MIB, rw, MAP_PRIVATE) == MAP_FAILED)
        return 1;

    /* 2: another MiB past it. */
    errno = 0;
    if (map_anon(NULL, MIB, rw, MAP_PRIVATE) != MAP_FAILED || errno != ENOMEM)
        return 2;
    return 0;
}

/* Runs in a child with RLIMIT_DATA at 24 MiB, far above the data this static
 * binary starts with. The sizes stay small enough that the break has room to
 * grow where no limit is set.
 */
static int data_child(void)
{
    int rw = PROT_READ | PROT_WRITE;
    if (set_soft(RLIMIT_DATA, 24 * MIB) < 0)
        return 100;

    /* 1: a break that stays below the limit. */
    if (sbrk(8 * MIB) == (void *) -1)
        return 1;

    /* 2: one that crosses it leaves the break where it was. */
    void *before = sbrk(0);
    errno = 0;
    if (sbrk(32 * MIB) != (void *) -1 || errno != ENOMEM || sbrk(0) != before)
        return 2;

    /* 3: a private writable mapping is data. */
    errno = 0;
    if (map_anon(NULL, 32 * MIB, rw, MAP_PRIVATE) != MAP_FAILED ||
        errno != ENOMEM)
        return 3;

    /* 4: a read-only or shared mapping of the same size is not. */
    char *ro = map_anon(NULL, 32 * MIB, PROT_READ, MAP_PRIVATE);
    char *shared = map_anon(NULL, 32 * MIB, PROT_READ, MAP_SHARED);
    if (ro == MAP_FAILED || shared == MAP_FAILED)
        return 4;

    /* 5: making the private one writable turns it into data. */
    errno = 0;
    if (mprotect(ro, 32 * MIB, rw) != -1 || errno != ENOMEM)
        return 5;

    /* 6: a part that fits, and the whole of the shared one, may be. */
    if (mprotect(ro, 4 * MIB, rw) < 0 || mprotect(shared, 32 * MIB, rw) < 0)
        return 6;
    ro[0] = shared[0] = 1;

    /* 7: a range over two mappings stops at the one that does not fit, with the
     * one below it already writable. The second mprotect below splits one
     * mapping into the two.
     */
    char *two = map_anon(NULL, 36 * MIB, PROT_NONE, MAP_PRIVATE);
    int zero = open("/dev/zero", O_RDONLY);
    if (two == MAP_FAILED || zero < 0 ||
        mprotect(two + 4 * MIB, 32 * MIB, PROT_READ) < 0)
        return 100;
    errno = 0;
    if (mprotect(two, 36 * MIB, rw) != -1 || errno != ENOMEM ||
        read(zero, two, 1) != 1 || read(zero, two + 4 * MIB, 1) != -1)
        return 7;
    close(zero);
    return 0;
}

/* Run @child_main in a fork child and report its first failed step. */
static void expect_child_steps(int (*child_main)(void))
{
    int status = -1;
    pid_t pid = fork();
    if (pid == 0)
        _exit(child_main());
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) {
        FAIL("child did not exit");
    } else if (WEXITSTATUS(status) != 0) {
        printf("FAIL: step %d\n", WEXITSTATUS(status));
        fails++;
    } else {
        PASS();
    }
}

int main(void)
{
    printf("test-rlimit-enforce: guest rlimits are enforced\n");

    TEST("RLIMIT_FSIZE on write and truncate");
    expect_child_steps(fsize_child);

    TEST("RLIMIT_FSIZE on sendfile, copy, splice, fallocate");
    expect_child_steps(fsize_copy_child);

    TEST("SIGXFSZ goes to the writing thread");
    expect_child_steps(fsize_thread_child);

    {
        int report[2], status = -1;
        char got[8];
        ssize_t n = -1;
        pid_t pid = pipe(report) < 0 ? -1 : fork();
        if (pid == 0) {
            close(report[0]);
            cpu_child(report[1]);
        }
        if (pid > 0) {
            close(report[1]);
            waitpid(pid, &status, 0);
            n = read(report[0], got, sizeof(got));
            close(report[0]);
        }

        TEST("guest runs under a CPU limit");
        EXPECT_TRUE(n >= 1 && got[0] == 'p', "no progress after setrlimit");

        TEST("SIGXCPU at the soft CPU limit");
        EXPECT_TRUE(n >= 2 && got[1] == 'x', "the spin loop got no SIGXCPU");

        TEST("SIGKILL at the hard CPU limit");
        EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
                    "the spin loop was not killed");
    }

    TEST("RLIMIT_AS on mmap and mremap");
    expect_child_steps(as_child);

    TEST("RLIMIT_AS counts only guest mappings");
    expect_child_steps(as_exact_child);

    TEST("RLIMIT_DATA on brk, mmap and mprotect");
    expect_child_steps(data_child);

    SUMMARY("test-rlimit-enforce");
    return fails ? 1 : 0;
}
