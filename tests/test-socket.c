/*
 * Test socket syscalls (AF_UNIX socketpair)
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Verifies socket syscalls work by creating an AF_UNIX socketpair and
 * exchanging data. This avoids needing a network stack.
 */

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <netinet/in.h>

static void alarm_noop(int sig)
{
    (void) sig;
}

/* Test 2: send/recv data */
static int test_stream_io(const int sv[2])
{
    int failures = 0;

    printf("test-socket: 2. write/read through socketpair... ");
    const char *msg = "hello socket";
    ssize_t n = write(sv[0], msg, strlen(msg));
    if (n != (ssize_t) strlen(msg)) {
        printf("FAIL (write returned %zd)\n", n);
        failures++;
    } else {
        char buf[64] = {0};
        n = read(sv[1], buf, sizeof(buf) - 1);
        if (n == (ssize_t) strlen(msg) && !memcmp(buf, msg, strlen(msg))) {
            printf("PASS\n");
        } else {
            printf("FAIL (read returned %zd, got '%s')\n", n, buf);
            failures++;
        }
    }

    /* Test 3: getsockopt SO_TYPE */
    printf("test-socket: 3. getsockopt(SO_TYPE)... ");
    int sock_type = 0;
    socklen_t optlen = sizeof(sock_type);
    if (getsockopt(sv[0], SOL_SOCKET, SO_TYPE, &sock_type, &optlen) < 0) {
        printf("FAIL (getsockopt: %m)\n");
        failures++;
    } else if (sock_type == SOCK_STREAM) {
        printf("PASS\n");
    } else {
        printf("FAIL (type=%d, expected %d)\n", sock_type, SOCK_STREAM);
        failures++;
    }

    /* Test 4: getsockname/getpeername */
    printf("test-socket: 4. getsockname/getpeername... ");
    {
        struct sockaddr_un sa = {0};
        socklen_t salen = sizeof(sa);
        if (getsockname(sv[0], (struct sockaddr *) &sa, &salen) < 0) {
            printf("FAIL (getsockname: %m)\n");
            failures++;
        } else if (sa.sun_family != AF_UNIX || salen < sizeof(sa.sun_family)) {
            printf("FAIL (getsockname family=%d len=%u)\n", sa.sun_family,
                   (unsigned) salen);
            failures++;
        } else {
            memset(&sa, 0, sizeof(sa));
            salen = sizeof(sa);
            if (getpeername(sv[0], (struct sockaddr *) &sa, &salen) < 0) {
                printf("FAIL (getpeername: %m)\n");
                failures++;
            } else if (sa.sun_family != AF_UNIX ||
                       salen < sizeof(sa.sun_family)) {
                printf("FAIL (getpeername family=%d len=%u)\n", sa.sun_family,
                       (unsigned) salen);
                failures++;
            } else {
                printf("PASS\n");
            }
        }
    }

    /* Test 5: sendmsg/recvmsg single iovec */
    printf("test-socket: 5. sendmsg/recvmsg single iovec... ");
    {
        char send_buf[] = "msg-payload";
        char recv_buf[32] = {0};
        struct iovec send_iov = {.iov_base = send_buf,
                                 .iov_len = sizeof(send_buf) - 1};
        struct iovec recv_iov = {.iov_base = recv_buf,
                                 .iov_len = sizeof(recv_buf)};
        struct msghdr send_msg = {.msg_iov = &send_iov, .msg_iovlen = 1};
        struct msghdr recv_msg = {.msg_iov = &recv_iov, .msg_iovlen = 1};

        n = sendmsg(sv[0], &send_msg, 0);
        if (n != (ssize_t) send_iov.iov_len) {
            printf("FAIL (sendmsg returned %zd)\n", n);
            failures++;
        } else {
            n = recvmsg(sv[1], &recv_msg, 0);
            if (n == (ssize_t) send_iov.iov_len &&
                !memcmp(recv_buf, send_buf, send_iov.iov_len) &&
                recv_msg.msg_flags == 0) {
                printf("PASS\n");
            } else {
                printf("FAIL (recvmsg returned %zd, flags=%d)\n", n,
                       recv_msg.msg_flags);
                failures++;
            }
        }
    }

    /* Test 6: sendmsg/recvmsg two iovecs */
    printf("test-socket: 6. sendmsg/recvmsg two iovecs... ");
    {
        char send0[] = "msg-", send1[] = "payload2";
        char recv_buf[32] = {0};
        struct iovec send_iov[2] = {
            {.iov_base = send0, .iov_len = sizeof(send0) - 1},
            {.iov_base = send1, .iov_len = sizeof(send1) - 1},
        };
        struct iovec recv_iov[2] = {
            {.iov_base = recv_buf, .iov_len = 4},
            {.iov_base = recv_buf + 4, .iov_len = sizeof(recv_buf) - 4},
        };
        struct msghdr send_msg = {.msg_iov = send_iov, .msg_iovlen = 2};
        struct msghdr recv_msg = {.msg_iov = recv_iov, .msg_iovlen = 2};

        n = sendmsg(sv[0], &send_msg, 0);
        if (n != (ssize_t) (send_iov[0].iov_len + send_iov[1].iov_len)) {
            printf("FAIL (sendmsg returned %zd)\n", n);
            failures++;
        } else {
            static const char expected[] = "msg-payload2";
            n = recvmsg(sv[1], &recv_msg, 0);
            if (n == (ssize_t) (sizeof(expected) - 1) &&
                !memcmp(recv_buf, expected, sizeof(expected) - 1) &&
                recv_msg.msg_flags == 0) {
                printf("PASS\n");
            } else {
                printf("FAIL (recvmsg returned %zd, flags=%d)\n", n,
                       recv_msg.msg_flags);
                failures++;
            }
        }
    }

    /* Test 7: sendmmsg/recvmmsg single message */
    printf("test-socket: 7. sendmmsg/recvmmsg single message... ");
    {
        char send_buf[] = "mmsg-payload";
        char recv_buf[32] = {0};
        struct iovec send_iov = {.iov_base = send_buf,
                                 .iov_len = sizeof(send_buf) - 1};
        struct iovec recv_iov = {.iov_base = recv_buf,
                                 .iov_len = sizeof(recv_buf)};
        struct mmsghdr send_msg = {
            .msg_hdr = {.msg_iov = &send_iov, .msg_iovlen = 1},
            .msg_len = 0,
        };
        struct mmsghdr recv_msg = {
            .msg_hdr = {.msg_iov = &recv_iov, .msg_iovlen = 1},
            .msg_len = 0,
        };

        n = sendmmsg(sv[0], &send_msg, 1, 0);
        if (n != 1 || send_msg.msg_len != send_iov.iov_len) {
            printf("FAIL (sendmmsg returned %zd, len=%u)\n", n,
                   send_msg.msg_len);
            failures++;
        } else {
            n = recvmmsg(sv[1], &recv_msg, 1, 0, NULL);
            if (n == 1 && recv_msg.msg_len == send_iov.iov_len &&
                !memcmp(recv_buf, send_buf, send_iov.iov_len) &&
                recv_msg.msg_hdr.msg_flags == 0) {
                printf("PASS\n");
            } else {
                printf("FAIL (recvmmsg returned %zd, len=%u, flags=%d)\n", n,
                       recv_msg.msg_len, recv_msg.msg_hdr.msg_flags);
                failures++;
            }
        }
    }

    return failures;
}

/* Test 8: sendto/recvfrom on AF_UNIX datagram socketpair */
static int test_dgram_msgs(void)
{
    int failures = 0;
    ssize_t n;

    printf("test-socket: 8. sendto/recvfrom AF_UNIX dgram... ");
    {
        int dsv[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, dsv) < 0) {
            printf("FAIL (socketpair dgram: %m)\n");
            failures++;
        } else {
            char send_buf[] = "dgram";
            char recv_buf[16] = {0};
            struct sockaddr_un sa = {0};
            socklen_t salen = sizeof(sa);
            n = sendto(dsv[0], send_buf, sizeof(send_buf) - 1, 0, NULL, 0);
            if (n != (ssize_t) (sizeof(send_buf) - 1)) {
                printf("FAIL (sendto returned %zd)\n", n);
                failures++;
            } else {
                n = recvfrom(dsv[1], recv_buf, sizeof(recv_buf), 0,
                             (struct sockaddr *) &sa, &salen);

                /* Linux returns salen=0 for unnamed AF_UNIX socketpair
                 * endpoints (no source address). Accept both salen==0 and salen
                 * with AF_UNIX family filled in.
                 */
                int addr_ok = (salen == 0) || (salen >= sizeof(sa.sun_family) &&
                                               sa.sun_family == AF_UNIX);
                if (n == (ssize_t) (sizeof(send_buf) - 1) &&
                    !memcmp(recv_buf, send_buf, sizeof(send_buf) - 1) &&
                    addr_ok) {
                    printf("PASS\n");
                } else {
                    printf("FAIL (recvfrom returned %zd, family=%d, len=%u)\n",
                           n, sa.sun_family, (unsigned) salen);
                    failures++;
                }
            }
            close(dsv[0]);
            close(dsv[1]);
        }
    }

    /* Test 9: recvmsg single-iovec preserves MSG_TRUNC on datagrams */
    printf("test-socket: 9. recvmsg single iovec preserves MSG_TRUNC... ");
    {
        int dsv[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, dsv) < 0) {
            printf("FAIL (socketpair dgram: %m)\n");
            failures++;
        } else {
            char send_buf[] = "oversized-dgram";
            char recv_buf[4] = {0};
            struct iovec recv_iov = {
                .iov_base = recv_buf,
                .iov_len = sizeof(recv_buf),
            };
            struct msghdr recv_msg = {
                .msg_iov = &recv_iov,
                .msg_iovlen = 1,
            };

            n = send(dsv[0], send_buf, sizeof(send_buf) - 1, 0);
            if (n != (ssize_t) (sizeof(send_buf) - 1)) {
                printf("FAIL (send returned %zd)\n", n);
                failures++;
            } else {
                n = recvmsg(dsv[1], &recv_msg, 0);
                if (n == (ssize_t) sizeof(recv_buf) &&
                    (recv_msg.msg_flags & MSG_TRUNC)) {
                    printf("PASS\n");
                } else {
                    printf("FAIL (recvmsg returned %zd, flags=%d)\n", n,
                           recv_msg.msg_flags);
                    failures++;
                }
            }
            close(dsv[0]);
            close(dsv[1]);
        }
    }

    return failures;
}

/* Test 10: getsockopt(SO_ERROR) remains read-and-clear */
static int test_so_error(void)
{
    int failures = 0;

    printf("test-socket: 10. getsockopt(SO_ERROR) read-and-clear... ");
    int listener = -1, client = -1;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        printf("FAIL (listener socket: %m)\n");
        failures++;
        goto test10_done;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    socklen_t addrlen = sizeof(addr);
    if (bind(listener, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
        getsockname(listener, (struct sockaddr *) &addr, &addrlen) < 0) {
        printf("FAIL (listener setup: %m)\n");
        failures++;
        goto test10_done;
    }

    /* Close listener so connect() gets ECONNREFUSED */
    close(listener);
    listener = -1;

    client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0) {
        printf("FAIL (client socket: %m)\n");
        failures++;
        goto test10_done;
    }

    int old_flags = fcntl(client, F_GETFL, 0);
    if (old_flags < 0 || fcntl(client, F_SETFL, old_flags | O_NONBLOCK) < 0) {
        printf("FAIL (fcntl: %m)\n");
        failures++;
        goto test10_done;
    }

    int rc = connect(client, (struct sockaddr *) &addr, sizeof(addr));
    if (rc == 0 || (rc < 0 && errno != EINPROGRESS)) {
        printf("FAIL (connect rc=%d errno=%d)\n", rc, errno);
        failures++;
        goto test10_done;
    }

    int so_error1 = 0, so_error2 = -1;
    socklen_t so_error_len = sizeof(so_error1);

    for (int spins = 0; spins < 200; spins++) {
        if (getsockopt(client, SOL_SOCKET, SO_ERROR, &so_error1,
                       &so_error_len) == 0 &&
            so_error1 != 0)
            break;
        usleep(1000);
    }

    so_error_len = sizeof(so_error2);
    if (getsockopt(client, SOL_SOCKET, SO_ERROR, &so_error2, &so_error_len) <
        0) {
        printf("FAIL (second getsockopt: %m)\n");
        failures++;
    } else if (so_error1 == ECONNREFUSED && so_error2 == 0) {
        printf("PASS\n");
    } else {
        printf("FAIL (first=%d second=%d)\n", so_error1, so_error2);
        failures++;
    }

test10_done:
    if (client >= 0)
        close(client);
    if (listener >= 0)
        close(listener);

    return failures;
}

/* Test 19: a fresh connect on an established stream returns EISCONN */
static int test_second_connect(void)
{
    int failures = 0;

    printf("test-socket: 19. second connect returns EISCONN... ");
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int client = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    socklen_t addrlen = sizeof(addr);

    const char *step = NULL;
    if (listener < 0 || client < 0)
        step = "socket";
    else if (bind(listener, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        step = "bind";
    else if (listen(listener, 1) < 0)
        step = "listen";
    else if (getsockname(listener, (struct sockaddr *) &addr, &addrlen) < 0)
        step = "getsockname";
    else if (connect(client, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        step = "first connect";
    else if (connect(client, (struct sockaddr *) &addr, sizeof(addr)) != -1)
        step = "second connect returned 0";
    else if (errno != EISCONN)
        step = "second connect errno";

    if (step) {
        printf("FAIL at %s (errno=%d)\n", step, errno);
        failures++;
    } else {
        printf("PASS\n");
    }
    if (listener >= 0)
        close(listener);
    if (client >= 0)
        close(client);

    return failures;
}

/* Test 11: shutdown + EOF */
static int test_shutdown_eof(const int sv[2])
{
    int failures = 0;
    ssize_t n;

    printf("test-socket: 11. shutdown(SHUT_WR) -> EOF... ");
    shutdown(sv[0], SHUT_WR);
    char buf2[16];
    n = read(sv[1], buf2, sizeof(buf2));
    if (n == 0) {
        printf("PASS\n");
    } else {
        printf("FAIL (read after shutdown returned %zd)\n", n);
        failures++;
    }

    return failures;
}

/* Test 14: zero-length recvmsg follows receive-readiness semantics. Linux
 * clamps the receive low-water target to one byte (sock_rcvlowat returns v ?:
 * 1), so a zero-length recvmsg behaves like a one-byte receive for readiness:
 * EAGAIN on an empty nonblocking socket, blocks on an empty blocking socket
 * (observed here as EINTR via alarm), and returns 0 without consuming anything
 * once data is pending.
 */
static int test_zero_length_recvmsg(void)
{
    int failures = 0;
    ssize_t n;

    printf("test-socket: 14. zero-length recvmsg readiness semantics... ");
    int zsv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, zsv) < 0) {
        printf("FAIL (socketpair: %m)\n");
        failures++;
    } else {
        char dummy = 0;
        struct iovec ziov[2] = {
            {.iov_base = &dummy, .iov_len = 0},
            {.iov_base = &dummy, .iov_len = 0},
        };
        struct msghdr zmsg = {.msg_iov = ziov, .msg_iovlen = 2};
        int zfail = 0;

        /* Empty socket, nonblocking: EAGAIN, not 0. */
        errno = 0;
        n = recvmsg(zsv[1], &zmsg, MSG_DONTWAIT);
        if (n != -1 || errno != EAGAIN) {
            printf("FAIL (empty dontwait: n=%zd errno=%d)\n", n, errno);
            zfail++;
        }

        /* Empty socket, blocking: parks until the timer interrupts. A repeating
         * interval (not a one-shot alarm) closes the race where the first
         * SIGALRM lands before recvmsg enters the kernel and the call then
         * blocks with no interrupt left.
         */
        struct sigaction zsa, old_zsa;
        memset(&zsa, 0, sizeof(zsa));
        zsa.sa_handler = alarm_noop; /* no SA_RESTART */
        sigaction(SIGALRM, &zsa, &old_zsa);
        struct itimerval zit = {
            .it_value = {.tv_sec = 1, .tv_usec = 0},
            .it_interval = {.tv_sec = 1, .tv_usec = 0},
        };
        struct itimerval zit_off = {{0, 0}, {0, 0}};
        setitimer(ITIMER_REAL, &zit, NULL);
        errno = 0;
        n = recvmsg(zsv[1], &zmsg, 0);
        int zerrno = errno;
        setitimer(ITIMER_REAL, &zit_off, NULL);
        sigaction(SIGALRM, &old_zsa, NULL);
        if (n != -1 || zerrno != EINTR) {
            printf("FAIL (empty blocking: n=%zd errno=%d)\n", n, zerrno);
            zfail++;
        }

        /* Data pending: returns 0 and leaves the byte queued. */
        char kept = 0;
        ssize_t klen = -1;
        if (write(zsv[0], "X", 1) != 1) {
            printf("FAIL (write: %m)\n");
            zfail++;
        } else {
            errno = 0;
            n = recvmsg(zsv[1], &zmsg, 0);
            klen = read(zsv[1], &kept, 1);
            if (n != 0 || klen != 1 || kept != 'X') {
                printf(
                    "FAIL (pending: recvmsg=%zd read=%zd byte=0x%02x "
                    "errno=%d)\n",
                    n, klen, (unsigned char) kept, errno);
                zfail++;
            }
        }

        if (zfail == 0)
            printf("PASS\n");
        failures += zfail;
        close(zsv[0]);
        close(zsv[1]);
    }

    return failures;
}

/* Test 15: invalid recvmsg iov returns EFAULT immediately */
static int test_invalid_recvmsg_iov(void)
{
    int failures = 0;
    ssize_t n;

    printf("test-socket: 15. invalid recvmsg iov returns EFAULT... ");
    int isv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, isv) < 0) {
        printf("FAIL (socketpair: %m)\n");
        failures++;
    } else {
        struct msghdr imsg = {
            .msg_iov = (struct iovec *) 1,
            .msg_iovlen = 1,
        };
        errno = 0;
        alarm(2);
        n = recvmsg(isv[1], &imsg, 0);
        int saved_errno = errno;
        alarm(0);
        if (n == -1 && saved_errno == EFAULT)
            printf("PASS\n");
        else {
            printf("FAIL (recvmsg returned %zd errno=%d)\n", n, saved_errno);
            failures++;
        }
        close(isv[0]);
        close(isv[1]);
    }

    return failures;
}

/* Test 12: SOCK_SEQPACKET UNIX socketpair */
static int test_seqpacket(void)
{
    int failures = 0;

    printf("test-socket: 12. socketpair(AF_UNIX, SOCK_SEQPACKET)... ");
    int seq_sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, seq_sv) < 0) {
        printf("FAIL (socketpair: %m)\n");
        failures++;
    } else {
        const char *seq_msg1 = "msg1";
        const char *seq_msg2 = "longer_msg2";
        if (write(seq_sv[0], seq_msg1, strlen(seq_msg1)) !=
                (ssize_t) strlen(seq_msg1) ||
            write(seq_sv[0], seq_msg2, strlen(seq_msg2)) !=
                (ssize_t) strlen(seq_msg2)) {
            printf("FAIL (write)\n");
            failures++;
        } else {
            char seq_buf1[64] = {0};
            char seq_buf2[64] = {0};
            ssize_t seq_n1 = read(seq_sv[1], seq_buf1, sizeof(seq_buf1) - 1);
            ssize_t seq_n2 = read(seq_sv[1], seq_buf2, sizeof(seq_buf2) - 1);
            if (seq_n1 == (ssize_t) strlen(seq_msg1) &&
                !memcmp(seq_buf1, seq_msg1, strlen(seq_msg1)) &&
                seq_n2 == (ssize_t) strlen(seq_msg2) &&
                !memcmp(seq_buf2, seq_msg2, strlen(seq_msg2))) {
                int seq_type = 0;
                socklen_t seq_optlen = sizeof(seq_type);
                if (getsockopt(seq_sv[0], SOL_SOCKET, SO_TYPE, &seq_type,
                               &seq_optlen) < 0) {
                    printf("FAIL (getsockopt SO_TYPE: %m)\n");
                    failures++;
                } else if (seq_type == SOCK_SEQPACKET) {
                    printf("PASS\n");
                } else {
                    printf("FAIL (type=%d, expected %d)\n", seq_type,
                           SOCK_SEQPACKET);
                    failures++;
                }
            } else {
                printf("FAIL (read: n1=%zd got '%s', n2=%zd got '%s')\n",
                       seq_n1, seq_buf1, seq_n2, seq_buf2);
                failures++;
            }
        }
        close(seq_sv[0]);
        close(seq_sv[1]);
    }

    /* Test 13: socket(AF_UNIX, SOCK_SEQPACKET, 0) */
    printf("test-socket: 13. socket(AF_UNIX, SOCK_SEQPACKET)... ");
    int seq_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (seq_fd < 0) {
        printf("FAIL (socket: %m)\n");
        failures++;
    } else {
        int seq_type = 0;
        socklen_t seq_optlen = sizeof(seq_type);
        if (getsockopt(seq_fd, SOL_SOCKET, SO_TYPE, &seq_type, &seq_optlen) <
            0) {
            printf("FAIL (getsockopt: %m)\n");
            failures++;
        } else if (seq_type == SOCK_SEQPACKET) {
            printf("PASS\n");
        } else {
            printf("FAIL (type=%d, expected %d)\n", seq_type, SOCK_SEQPACKET);
            failures++;
        }
        close(seq_fd);
    }

    return failures;
}

/* Test 16: SEQPACKET peer close reads as EOF, not ECONNRESET. Rust's process
 * spawn uses an AF_UNIX SOCK_SEQPACKET socketpair as its CLOEXEC status channel
 * and treats a recv error there as unreachable (it aborts). macOS has no
 * AF_UNIX SEQPACKET, so elfuse substitutes SOCK_DGRAM, whose recv reports
 * ECONNRESET on peer close where Linux SEQPACKET returns EOF. Verify the
 * clean-EOF contract holds.
 */
static int test_seqpacket_peer_eof(void)
{
    int failures = 0;

    printf("test-socket: 16. SEQPACKET peer close -> EOF... ");

    /* Every receive syscall must report the peer close as EOF (0), not
     * ECONNRESET, on the SEQPACKET-over-DGRAM substitute. recv covers Rust's
     * spawn channel; read, readv, recvmsg, and recvmmsg are the sibling paths
     * that forward the same host error.
     */
    int ok = 1;
    for (int which = 0; which < 6 && ok; which++) {
        int eof_sv[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, eof_sv) < 0) {
            printf("FAIL (socketpair: %m)\n");
            ok = 0;
            break;
        }
        close(eof_sv[0]); /* drop the peer, as an exec'd child would */
        char eof_buf[8];
        char eof_buf2[8];
        ssize_t eof_n;
        const char *op;
        int meta_ok = 1;
        if (which == 0) {
            op = "recv";
            eof_n = recv(eof_sv[1], eof_buf, sizeof(eof_buf), 0);
        } else if (which == 1) {
            op = "read";
            eof_n = read(eof_sv[1], eof_buf, sizeof(eof_buf));
        } else if (which == 2) {
            /* Two iovecs forces sys_readv's multi-iovec host readv(). */
            op = "readv";
            struct iovec iov[2] = {
                {.iov_base = eof_buf, .iov_len = sizeof(eof_buf)},
                {.iov_base = eof_buf2, .iov_len = sizeof(eof_buf2)}};
            eof_n = readv(eof_sv[1], iov, 2);
        } else if (which == 3) {
            op = "recvfrom";
            struct sockaddr_storage ss;
            socklen_t slen = sizeof(ss);
            eof_n = recvfrom(eof_sv[1], eof_buf, sizeof(eof_buf), 0,
                             (struct sockaddr *) &ss, &slen);
            meta_ok = slen == 0;
        } else if (which == 4) {
            op = "recvmsg";
            struct iovec iov = {.iov_base = eof_buf,
                                .iov_len = sizeof(eof_buf)};
            struct sockaddr_storage ss;
            struct msghdr mh = {.msg_name = &ss,
                                .msg_namelen = sizeof(ss),
                                .msg_iov = &iov,
                                .msg_iovlen = 1};
            eof_n = recvmsg(eof_sv[1], &mh, 0);
            meta_ok = mh.msg_namelen == 0;
        } else {
            /* recvmmsg with vlen==1 records one empty message on EOF. */
            op = "recvmmsg";
            struct iovec iov = {.iov_base = eof_buf,
                                .iov_len = sizeof(eof_buf)};
            struct mmsghdr mm = {0};
            mm.msg_hdr.msg_iov = &iov;
            mm.msg_hdr.msg_iovlen = 1;
            int r = recvmmsg(eof_sv[1], &mm, 1, 0, NULL);
            /* Expect 1 message received, of length 0. */
            eof_n = (r == 1 && mm.msg_len == 0) ? 0 : (r < 0 ? -1 : 1);
        }
        if (eof_n != 0 || !meta_ok) {
            printf("FAIL (%s=%zd errno=%d %s)\n", op, eof_n,
                   eof_n < 0 ? errno : 0,
                   eof_n < 0 ? strerror(errno)
                             : (meta_ok ? "data" : "stale address"));
            ok = 0;
        }
        close(eof_sv[1]);
    }
    if (ok)
        printf("PASS\n");
    else
        failures++;

    return failures;
}

/* Test 17: a genuine AF_UNIX datagram socket must NOT fold a peer-close
 * ECONNRESET into EOF -- only the SEQPACKET-over-DGRAM substitute does. Linux
 * never reports EOF on a datagram receive (it blocks, or returns EAGAIN when
 * nonblocking), so a clean 0 here would misreport a live peer as end-of-stream.
 * Use a nonblocking receiver so the check cannot hang on a real Linux host
 * where the datagram recv would otherwise block.
 */
static int test_dgram_peer_close(void)
{
    int failures = 0;

    printf("test-socket: 17. datagram peer close is not EOF... ");
    int dsv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, dsv) < 0) {
        printf("FAIL (socketpair: %m)\n");
        failures++;
    } else {
        fcntl(dsv[1], F_SETFL, O_NONBLOCK);
        close(dsv[0]);
        char b[8];
        ssize_t dn = recv(dsv[1], b, sizeof(b), 0);

        /* Any error is acceptable (ECONNRESET on macOS/elfuse, EAGAIN on
         * Linux); a clean EOF(0) is the regression this guards.
         */
        if (dn != 0) {
            printf("PASS (recv=%zd errno=%d)\n", dn, dn < 0 ? errno : 0);
        } else {
            printf("FAIL (datagram peer close reported EOF)\n");
            failures++;
        }
        close(dsv[1]);
    }

    return failures;
}

/* Test 18: a blocking recvmmsg(vlen>1) on a peer-closed SEQPACKET substitute
 * must terminate the batch at the folded EOF, not hang. The macOS datagram
 * substitute reports the peer close only once (then EAGAIN), so a naive loop
 * would block forever on the second iteration's readiness gate. Expect at least
 * one zero-length message and a prompt return; the test-runner timeout catches
 * a regression to the hang.
 */
static int test_recvmmsg_eof(void)
{
    int failures = 0;

    printf("test-socket: 18. recvmmsg(vlen>1) EOF does not hang... ");
    int msv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, msv) < 0) {
        printf("FAIL (socketpair: %m)\n");
        failures++;
    } else {
        close(msv[0]);
        char mb[4][8];
        struct mmsghdr mm[4];
        struct iovec miov[4];
        memset(mm, 0, sizeof(mm));
        for (int i = 0; i < 4; i++) {
            miov[i].iov_base = mb[i];
            miov[i].iov_len = sizeof(mb[i]);
            mm[i].msg_hdr.msg_iov = &miov[i];
            mm[i].msg_hdr.msg_iovlen = 1;
        }
        /* Blocking (no MSG_DONTWAIT): this is the path that would hang. */
        int mr = recvmmsg(msv[1], mm, 4, 0, NULL);

        /* elfuse stops at the first EOF (mr==1); Linux keeps reading the
         * persistent EOF and returns 4. Accept any mr>=1 with the first message
         * empty; the point is that it returned at all.
         */
        if (mr >= 1 && mm[0].msg_len == 0) {
            printf("PASS (mr=%d)\n", mr);
        } else {
            printf("FAIL (mr=%d len0=%u)\n", mr, mm[0].msg_len);
            failures++;
        }
        close(msv[1]);
    }

    return failures;
}

int main(void)
{
    int failures = 0;
    int sv[2];

    /* Test 1: socketpair */
    printf("test-socket: 1. socketpair(AF_UNIX)... ");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        printf("FAIL (socketpair: %m)\n");
        return 1;
    }
    if (sv[0] >= 0 && sv[1] >= 0) {
        printf("PASS (fds=%d,%d)\n", sv[0], sv[1]);
    } else {
        printf("FAIL (bad fds)\n");
        failures++;
    }

    failures += test_stream_io(sv);
    failures += test_dgram_msgs();
    failures += test_so_error();
    failures += test_second_connect();
    failures += test_shutdown_eof(sv);
    failures += test_zero_length_recvmsg();
    failures += test_invalid_recvmsg_iov();

    close(sv[0]);
    close(sv[1]);

    failures += test_seqpacket();
    failures += test_seqpacket_peer_eof();
    failures += test_dgram_peer_close();
    failures += test_recvmmsg_eof();

    if (failures == 0) {
        printf("test-socket: all tests passed -- PASS\n");
        return 0;
    }
    printf("test-socket: %d test(s) failed -- FAIL\n", failures);
    return 1;
}
