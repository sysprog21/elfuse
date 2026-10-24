/*
 * Test that RLIMIT_FSIZE is enforced on regular-file writes
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers write, pwrite, writev, pwritev2, truncate, fallocate, sendfile,
 * copy_file_range and splice: a request is cut at the soft limit, and one that
 * starts at or past it fails with EFBIG and raises SIGXFSZ on the thread that
 * made it. The limit is lowered in a fork child, so the process that reports
 * the results keeps its own limits.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
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
    char path[] = "/tmp/elfuse-rlimit-fsize.XXXXXX";
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

        /* A negative offset is EINVAL before the append moves it. */
        rc = afd < 0 ? 0 : pwrite(afd, block, 1, -1);
        ok = ok && rc == -1 && errno == EINVAL && xfsz_count == seen;
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
        ok = ok && rc == -1 && xfsz_count == seen;

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

    /* 13: truncate on a FIFO is EINVAL, not a refusal by the limit. */
    step++;
    {
        char fifo[sizeof(path) + 5];
        snprintf(fifo, sizeof(fifo), "%s.fifo", path);
        int ok = mkfifo(fifo, 0600) == 0 &&
                 truncate(fifo, 2 * FSIZE_LIMIT) == -1 && errno == EINVAL &&
                 xfsz_count == seen;
        unlink(fifo);
        if (!ok)
            goto out;
    }

    /* 14: a refused truncate by path leaves the caller's record locks alone, as
     * another process sees them.
     */
    step++;
    {
        struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
        if (fcntl(fd, F_SETLK, &fl) < 0 ||
            !refused_with_xfsz(truncate(path, 2 * FSIZE_LIMIT), &seen))
            goto out;
        pid_t pid = fork();
        if (pid == 0) {
            int cfd = open(path, O_RDONLY);
            struct flock q = {.l_type = F_RDLCK, .l_whence = SEEK_SET};
            _exit(cfd >= 0 && fcntl(cfd, F_GETLK, &q) == 0 &&
                          q.l_type == F_WRLCK
                      ? 0
                      : 1);
        }
        int status;
        if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)
            goto out;
    }

    /* 15: an O_APPEND pwrite at an offset far past the limit lands at end of
     * file, so on an empty file it fits and is not refused.
     */
    step++;
    {
        int afd = open(path, O_WRONLY | O_APPEND | O_TRUNC);
        struct stat st;
        int ok = afd >= 0 && pwrite(afd, block, 100, 1L << 30) == 100 &&
                 fstat(afd, &st) == 0 && st.st_size == 100 &&
                 xfsz_count == seen;
        if (afd >= 0)
            close(afd);
        if (!ok)
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

    /* 9: SPLICE_F_NONBLOCK on a blocking empty pipe is EAGAIN, with no signal,
     * when the file is at the limit.
     */
    step++;
    {
        int empty[2];
        if (pipe(empty) < 0 || copy_reset(dfd, FSIZE_LIMIT, sfd, 0))
            goto out;
        alarm(5);
        long rc = splice(empty[0], NULL, dfd, NULL, 100, SPLICE_F_NONBLOCK);
        alarm(0);
        int ok = rc == -1 && errno == EAGAIN && xfsz_count == seen;
        close(empty[0]);
        close(empty[1]);
        if (!ok)
            goto out;
    }

    /* 10: a pipe's write end as input is EBADF, with the file at the limit and
     * the read end still open, where a probe for input would wait forever.
     */
    step++;
    {
        if (copy_reset(dfd, FSIZE_LIMIT, sfd, 0))
            goto out;
        long rc = splice(pfd[1], NULL, dfd, NULL, 1, 0);
        int ok = rc == -1 && errno == EBADF && xfsz_count == seen;
        rc = sendfile(dfd, pfd[1], NULL, 1);
        ok = ok && rc == -1 && errno == EBADF && xfsz_count == seen;
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
    printf("test-rlimit-fsize: RLIMIT_FSIZE is enforced\n");

    TEST("RLIMIT_FSIZE on write and truncate");
    expect_child_steps(fsize_child);

    TEST("RLIMIT_FSIZE on sendfile, copy, splice, fallocate");
    expect_child_steps(fsize_copy_child);

    TEST("SIGXFSZ goes to the writing thread");
    expect_child_steps(fsize_thread_child);

    SUMMARY("test-rlimit-fsize");
    return fails ? 1 : 0;
}
