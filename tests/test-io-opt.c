/*
 * Test I/O optimization syscalls (Batch 3)
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: sendfile, copy_file_range, splice, fsync, fallocate
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

#include "test-harness.h"

/* splice(@in, NULL, a pipe, NULL, 5, SPLICE_F_NONBLOCK) on a blocking socket
 * whose peer @peer sends those 5 bytes from a child after 300 ms.
 *
 * Returns the splice result, with errno set when it is -1.
 */
static ssize_t splice_late_socket(int in, int peer)
{
    int pfd[2];
    if (pipe(pfd) != 0)
        return -2;
    pid_t pid = fork();
    if (pid == 0) {
        usleep(300000);
        _exit(send(peer, "hello", 5, 0) == 5 ? 0 : 1);
    }
    alarm(5);
    ssize_t rc = splice(in, NULL, pfd[1], NULL, 5, SPLICE_F_NONBLOCK);
    int saved = errno;
    alarm(0);
    if (pid > 0)
        waitpid(pid, NULL, 0);
    close(pfd[0]);
    close(pfd[1]);
    errno = saved;
    return rc;
}

/* SPLICE_F_NONBLOCK on fd 0, which tests/test-matrix.sh holds open as an empty
 * pipe the guest did not create.
 */
static int splice_stdin_nonblock(void)
{
    char path[] = "/tmp/elfuse-io-opt-stdin-XXXXXX";
    int out = mkstemp(path);
    if (out < 0)
        return 1;
    unlink(path);
    alarm(5);
    ssize_t rc = splice(0, NULL, out, NULL, 16, SPLICE_F_NONBLOCK);
    alarm(0);
    if (rc != -1 || errno != EAGAIN)
        return 1;
    printf("stdin splice: EAGAIN\n");
    return 0;
}

int main(int argc, char **argv)
{
    int passes = 0, fails = 0;

    if (argc > 1 && strcmp(argv[1], "stdin") == 0)
        return splice_stdin_nonblock();

    char tmpdir[] = "/tmp/elfuse-io-opt-XXXXXX";
    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return 1;
    }
    char src_path[256], dst_path[256];
    char alloc_path[256], punch_path[256], cfr_dst[256];
    snprintf(src_path, sizeof(src_path), "%s/src.txt", tmpdir);
    snprintf(dst_path, sizeof(dst_path), "%s/dst.txt", tmpdir);
    snprintf(alloc_path, sizeof(alloc_path), "%s/alloc.bin", tmpdir);
    snprintf(punch_path, sizeof(punch_path), "%s/punch.bin", tmpdir);
    snprintf(cfr_dst, sizeof(cfr_dst), "%s/cfr-dst.txt", tmpdir);
    const char *test_data = "Hello from sendfile test! This is test data.\n";

    printf("test-io-opt: Batch 3 I/O optimization tests\n");

    /* Create source file */
    int src_fd = open(src_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (src_fd < 0) {
        printf("FATAL: cannot create %s\n", src_path);
        rmdir(tmpdir);
        return 1;
    }
    write(src_fd, test_data, strlen(test_data));
    close(src_fd);

    /* Test sendfile */
    TEST("sendfile");
    {
        int in_fd = open(src_path, O_RDONLY);
        int out_fd = open(dst_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (in_fd >= 0 && out_fd >= 0) {
            off_t offset = 0;
            ssize_t copied =
                sendfile(out_fd, in_fd, &offset, strlen(test_data));
            if (copied == (ssize_t) strlen(test_data)) {
                close(out_fd);
                close(in_fd);

                /* Verify content */
                char buf[256];
                int verify_fd = open(dst_path, O_RDONLY);
                if (verify_fd < 0) {
                    FAIL("open verify failed");
                } else {
                    ssize_t n = read(verify_fd, buf, sizeof(buf));
                    close(verify_fd);
                    if (n == (ssize_t) strlen(test_data) &&
                        !memcmp(buf, test_data, n))
                        PASS();
                    else
                        FAIL("content mismatch");
                }
            } else {
                close(out_fd);
                close(in_fd);
                FAIL("sendfile returned wrong count");
            }
        } else {
            if (in_fd >= 0)
                close(in_fd);
            if (out_fd >= 0)
                close(out_fd);
            FAIL("open failed");
        }
    }

    /* Test fsync */
    TEST("fsync");
    {
        int fd = open(dst_path, O_RDWR);
        if (fd >= 0) {
            EXPECT_TRUE(fsync(fd) == 0, "fsync failed");
            close(fd);
        } else
            FAIL("open failed");
    }

    /* Test fallocate (via ftruncate fallback) */
    TEST("fallocate (extend)");
    {
        int fd = open(alloc_path, O_CREAT | O_RDWR, 0644);
        if (fd >= 0) {
            /* fallocate mode=0 should extend the file */
            if (fallocate(fd, 0, 0, 4096) == 0) {
                struct stat st;
                fstat(fd, &st);
                EXPECT_TRUE(st.st_size == 4096, "size mismatch");
            } else
                FAIL("fallocate failed");
            close(fd);
            unlink(alloc_path);
        } else
            FAIL("open failed");
    }

    TEST("fallocate punch hole keeps size past EOF");
    {
        int fd = open(punch_path, O_CREAT | O_RDWR, 0644);
        if (fd >= 0) {
            const char data[] = "abc";
            const off_t data_size = (off_t) sizeof(data) - 1;
            if (write(fd, data, sizeof(data) - 1) == (ssize_t) data_size &&
                fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 1,
                          4096) == 0) {
                struct stat st;
                char buf[sizeof(data) - 1];
                int stat_ok = fstat(fd, &st) == 0;
                ssize_t nr = -1;
                if (stat_ok)
                    nr = pread(fd, buf, sizeof(buf), 0);
                if (stat_ok && st.st_size == data_size &&
                    nr == (ssize_t) sizeof(buf) && buf[0] == 'a' &&
                    buf[1] == '\0' && buf[2] == '\0')
                    PASS();
                else
                    FAIL("punch hole did not preserve size and zero bytes");
            } else
                FAIL("punch hole setup failed");
            close(fd);
            unlink(punch_path);
        } else
            FAIL("open failed");
    }

    /* Test copy_file_range (via off_t-based API) */
    TEST("copy_file_range");
    {
        int in_fd = open(src_path, O_RDONLY);
        int out_fd = open(cfr_dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (in_fd >= 0 && out_fd >= 0) {
            off_t off_in = 0, off_out = 0;
            ssize_t copied = copy_file_range(in_fd, &off_in, out_fd, &off_out,
                                             strlen(test_data), 0);
            close(in_fd);
            close(out_fd);

            if (copied == (ssize_t) strlen(test_data)) {
                /* Verify content */
                char buf[256];
                int v = open(cfr_dst, O_RDONLY);
                if (v < 0) {
                    FAIL("open verify failed");
                } else {
                    ssize_t n = read(v, buf, sizeof(buf));
                    close(v);
                    if (n == (ssize_t) strlen(test_data) &&
                        !memcmp(buf, test_data, n))
                        PASS();
                    else
                        FAIL("content mismatch");
                }
            } else
                FAIL("copy_file_range wrong count");
        } else {
            if (in_fd >= 0)
                close(in_fd);
            if (out_fd >= 0)
                close(out_fd);
            FAIL("open failed");
        }
        unlink(cfr_dst);
    }

    /* copy_file_range refuses a directory, anything else not a regular file, an
     * input not open for reading, and an output not open for writing or open
     * O_APPEND, before it copies anything.
     */
    TEST("copy_file_range refuses bad ends");
    {
        int rd = open(src_path, O_RDONLY);
        int wr = open(src_path, O_WRONLY);
        int ap = open(src_path, O_WRONLY | O_APPEND);
        int out = open(cfr_dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        int dir = open(tmpdir, O_RDONLY);
        int pfd[2] = {-1, -1};
        int ok = rd >= 0 && wr >= 0 && ap >= 0 && out >= 0 && dir >= 0 &&
                 pipe(pfd) == 0 && write(pfd[1], "x", 1) == 1;
        const char *why = "setup failed";

        if (ok) {
            why = "write-only input not EBADF";
            ok = copy_file_range(wr, NULL, out, NULL, 4, 0) == -1 &&
                 errno == EBADF;
        }
        if (ok) {
            why = "read-only output not EBADF";
            ok = copy_file_range(rd, NULL, rd, NULL, 4, 0) == -1 &&
                 errno == EBADF;
        }
        if (ok) {
            why = "O_APPEND output not EBADF";
            ok = copy_file_range(rd, NULL, ap, NULL, 4, 0) == -1 &&
                 errno == EBADF;
        }
        if (ok) {
            why = "pipe input not EINVAL";
            ok = copy_file_range(pfd[0], NULL, out, NULL, 4, 0) == -1 &&
                 errno == EINVAL;
        }
        if (ok) {
            why = "directory input not EISDIR";
            ok = copy_file_range(dir, NULL, out, NULL, 4, 0) == -1 &&
                 errno == EISDIR;
        }
        if (ok)
            PASS();
        else
            FAIL(why);

        int fds[] = {rd, wr, ap, out, dir, pfd[0], pfd[1]};
        for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
            if (fds[i] >= 0)
                close(fds[i]);
        unlink(cfr_dst);
    }

    /* copy_file_range refuses a range whose end wraps as an unsigned sum, at
     * either end, before it copies anything. A negative offset passed by
     * pointer wraps too unless the length is short, and is then EINVAL.
     */
    TEST("copy_file_range refuses a wrapping range");
    {
        int rd = open(src_path, O_RDONLY);
        int out = open(cfr_dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        int ok = rd >= 0 && out >= 0;
        const char *why = "setup failed";
        loff_t one = 1, neg = -1, zero = 0;
        struct stat st;

        if (ok) {
            why = "off_in 1, len UINT64_MAX not EOVERFLOW";
            ok = copy_file_range(rd, &one, out, NULL, SIZE_MAX, 0) == -1 &&
                 errno == EOVERFLOW;
        }
        if (ok) {
            why = "off_out -1 not EOVERFLOW";
            ok = copy_file_range(rd, &zero, out, &neg, 4, 0) == -1 &&
                 errno == EOVERFLOW;
        }
        if (ok) {
            why = "off_in -1 not EOVERFLOW";
            ok = copy_file_range(rd, &neg, out, NULL, 4, 0) == -1 &&
                 errno == EOVERFLOW;
        }
        if (ok) {
            loff_t far = -4096;
            why = "off_out -4096, len 10 not EINVAL";
            ok = copy_file_range(rd, &zero, out, &far, 10, 0) == -1 &&
                 errno == EINVAL;
        }
        if (ok) {
            loff_t far = -4096;
            why = "off_in -4096, len 10 not EINVAL";
            ok = copy_file_range(rd, &far, out, NULL, 10, 0) == -1 &&
                 errno == EINVAL;
        }
        if (ok) {
            why = "output grew";
            ok = fstat(out, &st) == 0 && st.st_size == 0;
        }
        if (ok)
            PASS();
        else
            FAIL(why);

        if (rd >= 0)
            close(rd);
        if (out >= 0)
            close(out);
        unlink(cfr_dst);
    }

    /* sendfile and a pipe-to-file splice refuse an O_APPEND output with EINVAL
     * and move nothing, after the EBADF for an end opened the wrong way. A
     * zero-length splice returns 0 before either check. sendfile checks a
     * negative input offset before it looks at the output.
     */
    TEST("sendfile and splice refuse an O_APPEND output");
    {
        int rd = open(src_path, O_RDONLY);
        int ap = open(cfr_dst, O_CREAT | O_WRONLY | O_APPEND | O_TRUNC, 0644);
        int pfd[2] = {-1, -1};
        int ok =
            rd >= 0 && ap >= 0 && pipe(pfd) == 0 && write(pfd[1], "xy", 2) == 2;
        const char *why = "setup failed";
        struct stat st;

        if (ok) {
            why = "sendfile not EINVAL";
            ok = sendfile(ap, rd, NULL, 2) == -1 && errno == EINVAL;
        }
        if (ok) {
            why = "splice not EINVAL";
            ok = splice(pfd[0], NULL, ap, NULL, 2, 0) == -1 && errno == EINVAL;
        }
        if (ok) {
            why = "zero-length splice not 0";
            ok = splice(pfd[0], NULL, ap, NULL, 0, 0) == 0;
        }
        if (ok) {
            int wr = open(src_path, O_WRONLY);
            why = "write-only input not EBADF ahead of O_APPEND";
            ok = wr >= 0 && sendfile(ap, wr, NULL, 2) == -1 && errno == EBADF &&
                 splice(pfd[1], NULL, ap, NULL, 2, 0) == -1 && errno == EBADF;
            if (wr >= 0)
                close(wr);
        }
        if (ok) {
            off_t neg = -1;
            why = "negative offset not EINVAL ahead of a read-only output";
            ok = sendfile(rd, rd, &neg, 2) == -1 && errno == EINVAL;
        }
        if (ok) {
            why = "output grew";
            ok = fstat(ap, &st) == 0 && st.st_size == 0;
        }
        if (ok)
            PASS();
        else
            FAIL(why);

        int fds[] = {rd, ap, pfd[0], pfd[1]};
        for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
            if (fds[i] >= 0)
                close(fds[i]);
        unlink(cfr_dst);
    }

    /* SPLICE_F_NONBLOCK answers EAGAIN on an empty pipe whose writer is still
     * open, even when the pipe itself is blocking.
     */
    TEST("splice SPLICE_F_NONBLOCK on empty pipe");
    {
        int pfd[2] = {-1, -1};
        int out = open(cfr_dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (out < 0 || pipe(pfd) != 0) {
            FAIL("setup failed");
        } else {
            alarm(5);
            ssize_t rc = splice(pfd[0], NULL, out, NULL, 16, SPLICE_F_NONBLOCK);
            alarm(0);
            EXPECT_TRUE(rc == -1 && errno == EAGAIN, "not EAGAIN");
        }
        if (pfd[0] >= 0) {
            close(pfd[0]);
            close(pfd[1]);
        }
        if (out >= 0)
            close(out);
        unlink(cfr_dst);
    }

    /* With the output pipe full, SPLICE_F_NONBLOCK answers EAGAIN before it
     * reads anything; once a reader frees some room, it moves only what fits.
     * Either way every byte is in one pipe or the other.
     */
    TEST("splice SPLICE_F_NONBLOCK into a full pipe loses nothing");
    {
        enum { IN_BYTES = 8192 };
        static char fill[4096];
        int a[2] = {-1, -1}, b[2] = {-1, -1};
        int ok = pipe(a) == 0 && pipe(b) == 0 &&
                 write(a[1], fill, sizeof(fill)) == sizeof(fill) &&
                 write(a[1], fill, sizeof(fill)) == sizeof(fill) &&
                 fcntl(b[1], F_SETFL, O_NONBLOCK) == 0;
        while (ok && write(b[1], fill, sizeof(fill)) > 0)
            ;
        while (ok && write(b[1], fill, 1) > 0)
            ;
        ok = ok && fcntl(b[1], F_SETFL, 0) == 0;
        const char *why = "setup failed";
        ssize_t moved = 0;
        int left = -1;

        if (ok) {
            why = "full output not EAGAIN";
            ok = splice(a[0], NULL, b[1], NULL, IN_BYTES, SPLICE_F_NONBLOCK) ==
                     -1 &&
                 errno == EAGAIN;
        }
        if (ok) {
            why = "input consumed on EAGAIN";
            ok = ioctl(a[0], FIONREAD, &left) == 0 && left == IN_BYTES;
        }
        if (ok) {
            why = "nothing moved after the reader freed room";
            ok = read(b[0], fill, sizeof(fill)) == sizeof(fill);
            moved = splice(a[0], NULL, b[1], NULL, IN_BYTES, SPLICE_F_NONBLOCK);
            ok = ok && moved > 0;
        }
        if (ok) {
            why = "bytes lost";
            ok = ioctl(a[0], FIONREAD, &left) == 0 && moved + left == IN_BYTES;
        }
        if (ok)
            PASS();
        else
            FAIL(why);

        int fds[] = {a[0], a[1], b[0], b[1]};
        for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
            if (fds[i] >= 0)
                close(fds[i]);
    }

    /* SPLICE_F_NONBLOCK reaches an AF_UNIX stream input
     * (unix_stream_splice_read), but a TCP input follows its own O_NONBLOCK
     * (tcp_splice_read) and waits for data.
     */
    TEST("splice SPLICE_F_NONBLOCK on socket inputs");
    {
        int sv[2] = {-1, -1};
        int ls = socket(AF_INET, SOCK_STREAM, 0);
        int cli = socket(AF_INET, SOCK_STREAM, 0);
        int srv = -1;
        struct sockaddr_in sa = {.sin_family = AF_INET,
                                 .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        socklen_t sl = sizeof(sa);
        int ok = socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 && ls >= 0 &&
                 cli >= 0 && bind(ls, (struct sockaddr *) &sa, sl) == 0 &&
                 listen(ls, 1) == 0 &&
                 getsockname(ls, (struct sockaddr *) &sa, &sl) == 0 &&
                 connect(cli, (struct sockaddr *) &sa, sl) == 0 &&
                 (srv = accept(ls, NULL, NULL)) >= 0;
        const char *why = "setup failed";

        if (ok) {
            why = "AF_UNIX input not EAGAIN";
            ok = splice_late_socket(sv[0], sv[1]) == -1 && errno == EAGAIN;
        }
        if (ok) {
            why = "TCP input did not wait for data";
            ok = splice_late_socket(srv, cli) == 5;
        }
        if (ok)
            PASS();
        else
            FAIL(why);

        int fds[] = {sv[0], sv[1], ls, cli, srv};
        for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
            if (fds[i] >= 0)
                close(fds[i]);
    }

    /* do_splice raises SPLICE_F_NONBLOCK itself when a pipe end is O_NONBLOCK,
     * so a full O_NONBLOCK output answers EAGAIN before anything is read, and
     * an empty AF_UNIX input does not wait.
     */
    TEST("splice follows a pipe end's O_NONBLOCK");
    {
        int sv[2] = {-1, -1}, a[2] = {-1, -1}, b[2] = {-1, -1};
        int ok = socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 && pipe(a) == 0 &&
                 pipe(b) == 0 && write(sv[1], "0123456789", 10) == 10 &&
                 write(a[1], "xyz", 3) == 3 &&
                 fcntl(b[1], F_SETFL, O_NONBLOCK) == 0;
        static char fill[4096];
        while (ok && write(b[1], fill, sizeof(fill)) > 0)
            ;
        while (ok && write(b[1], fill, 1) > 0)
            ;
        const char *why = "setup failed";
        int left = -1;

        if (ok) {
            why = "AF_UNIX input to a full pipe not EAGAIN, or bytes lost";
            ok = splice(sv[0], NULL, b[1], NULL, 10, 0) == -1 &&
                 errno == EAGAIN && ioctl(sv[0], FIONREAD, &left) == 0 &&
                 left == 10;
        }
        if (ok) {
            why = "pipe input to a full pipe not EAGAIN, or bytes lost";
            ok = splice(a[0], NULL, b[1], NULL, 3, 0) == -1 &&
                 errno == EAGAIN && ioctl(a[0], FIONREAD, &left) == 0 &&
                 left == 3;
        }
        if (ok) {
            char drain[4096];
            while (read(sv[0], drain, sizeof(drain)) == sizeof(drain))
                ;
            ok = read(b[0], drain, sizeof(drain)) == sizeof(drain);
            why = "empty AF_UNIX input waited";
            alarm(5);
            ok = ok && splice(sv[0], NULL, b[1], NULL, 10, 0) == -1 &&
                 errno == EAGAIN;
            alarm(0);
        }
        if (ok)
            PASS();
        else
            FAIL(why);

        int fds[] = {sv[0], sv[1], a[0], a[1], b[0], b[1]};
        for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
            if (fds[i] >= 0)
                close(fds[i]);
    }

    /* An output pipe whose reader is gone fails with EPIPE and SIGPIPE before
     * the input is read (wait_for_space).
     */
    TEST("splice SPLICE_F_NONBLOCK into a pipe with no reader");
    {
        int sv[2] = {-1, -1}, p[2] = {-1, -1};
        int ok = socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 && pipe(p) == 0 &&
                 write(sv[1], "0123456789", 10) == 10;
        if (ok) {
            close(p[0]);
            p[0] = -1;
        }
        sigset_t pipe_set, old;
        sigemptyset(&pipe_set);
        sigaddset(&pipe_set, SIGPIPE);
        sigprocmask(SIG_BLOCK, &pipe_set, &old);
        int left = -1, sig = 0;
        struct timespec now = {0};
        const char *why = "setup failed";

        if (ok) {
            why = "not EPIPE";
            ok = splice(sv[0], NULL, p[1], NULL, 10, SPLICE_F_NONBLOCK) == -1 &&
                 errno == EPIPE;
        }
        if (ok) {
            why = "input consumed";
            ok = ioctl(sv[0], FIONREAD, &left) == 0 && left == 10;
        }
        if (ok) {
            why = "no SIGPIPE";
            sig = sigtimedwait(&pipe_set, NULL, &now);
            ok = sig == SIGPIPE;
        }
        sigprocmask(SIG_SETMASK, &old, NULL);
        if (ok)
            PASS();
        else
            FAIL(why);

        int fds[] = {sv[0], sv[1], p[0], p[1]};
        for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
            if (fds[i] >= 0)
                close(fds[i]);
    }

    /* Cleanup. The other three fixtures are unlinked by the blocks that make
     * them, so only these two are left for rmdir to trip over.
     */
    unlink(src_path);
    unlink(dst_path);
    rmdir(tmpdir);

    SUMMARY("test-io-opt");
    return fails > 0 ? 1 : 0;
}
