/*
 * Test AF_INET/AF_INET6 networking syscalls
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: TCP self-connect (socket/bind/listen/connect/accept/send/recv),
 *        UDP loopback (sendto/recvfrom), AF_INET6 socket creation,
 *        setsockopt/getsockopt (SO_REUSEADDR, SO_SNDBUF, SO_RCVBUF)
 *
 * Syscalls exercised: socket(198), bind(200), listen(201), connect(203),
 *                     accept(202), sendto(206), recvfrom(207),
 *                     getsockname(204), setsockopt(208), getsockopt(209),
 *                     shutdown(210), close(57)
 */

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "test-harness.h"

int passes = 0, fails = 0;

static int ip_bool_roundtrip(int sock, int optname)
{
    int val = 42;
    if (setsockopt(sock, IPPROTO_IP, optname, &val, sizeof(val)) < 0)
        return -1;

    val = 0;
    socklen_t len = sizeof(val);
    if (getsockopt(sock, IPPROTO_IP, optname, &val, &len) < 0)
        return -1;

    return val;
}

static void test_tcp_udp(void)
{
    /* Test TCP self-connect: server binds, client connects, exchange data */
    TEST("TCP self-connect");
    {
        int server = socket(AF_INET, SOCK_STREAM, 0);
        if (server < 0) {
            FAIL("server socket");
            goto tcp_done;
        }

        /* Bind to 127.0.0.1:0 (kernel picks port) */
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;

        if (bind(server, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
            FAIL("bind");
            close(server);
            goto tcp_done;
        }
        if (listen(server, 1) < 0) {
            FAIL("listen");
            close(server);
            goto tcp_done;
        }

        /* Get assigned port */
        socklen_t alen = sizeof(addr);
        getsockname(server, (struct sockaddr *) &addr, &alen);

        /* Connect client */
        int client = socket(AF_INET, SOCK_STREAM, 0);
        if (client < 0) {
            FAIL("client socket");
            close(server);
            goto tcp_done;
        }
        if (connect(client, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
            FAIL("connect");
            close(client);
            close(server);
            goto tcp_done;
        }

        /* Accept connection */
        int conn = accept(server, NULL, NULL);
        if (conn < 0) {
            FAIL("accept");
            close(client);
            close(server);
            goto tcp_done;
        }

        /* Exchange data */
        const char *msg = "hello-tcp";
        send(client, msg, strlen(msg), 0);

        char buf[64];
        ssize_t n = recv(conn, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            EXPECT_TRUE(!strcmp(buf, msg), "data mismatch");
        } else
            FAIL("recv failed");

        close(conn);
        close(client);
        close(server);
    }
tcp_done:;

    /* Test UDP loopback: send + receive on same socket */
    TEST("UDP loopback");
    {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            FAIL("socket");
            goto udp_done;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;

        if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
            FAIL("bind");
            close(sock);
            goto udp_done;
        }

        /* Get assigned port */
        socklen_t alen = sizeof(addr);
        getsockname(sock, (struct sockaddr *) &addr, &alen);

        /* Send to self */
        const char *msg = "hello-udp";
        ssize_t sent = sendto(sock, msg, strlen(msg), 0,
                              (struct sockaddr *) &addr, sizeof(addr));
        if (sent < 0) {
            FAIL("sendto");
            close(sock);
            goto udp_done;
        }

        /* Receive */
        char buf[64];
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(sock, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *) &from, &flen);
        if (n > 0) {
            buf[n] = '\0';
            EXPECT_TRUE(!strcmp(buf, msg), "data mismatch");
        } else
            FAIL("recvfrom failed");

        close(sock);
    }
udp_done:;
}

static void test_efault_consumes(void)
{
    TEST("accept consumes pending connection on EFAULT");
    {
        int server = -1, client = -1;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;

        server = socket(AF_INET, SOCK_STREAM, 0);
        if (server < 0) {
            FAIL("server socket");
        } else if (bind(server, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
            FAIL("bind");
        } else if (listen(server, 1) < 0) {
            FAIL("listen");
        } else {
            socklen_t alen = sizeof(addr);
            getsockname(server, (struct sockaddr *) &addr, &alen);

            client = socket(AF_INET, SOCK_STREAM, 0);
            if (client < 0) {
                FAIL("client socket");
            } else if (connect(client, (struct sockaddr *) &addr,
                               sizeof(addr)) < 0) {
                FAIL("connect");
            } else {
                struct sockaddr_in peer;
                errno = 0;
                int conn = accept(server, (struct sockaddr *) &peer, NULL);
                int saved_errno = errno;
                int fl = fcntl(server, F_GETFL, 0);
                int drained = 0;

                if (conn >= 0) {
                    close(conn);
                    FAIL("accept unexpectedly succeeded");
                } else if (saved_errno != EFAULT) {
                    FAIL("accept did not report EFAULT");
                } else if (fl < 0 ||
                           fcntl(server, F_SETFL, fl | O_NONBLOCK) < 0) {
                    FAIL("fcntl");
                } else {
                    errno = 0;
                    drained = accept(server, NULL, NULL);
                    EXPECT_TRUE(drained < 0 && errno == EAGAIN,
                                "pending connection was not consumed");
                }
            }
        }

        if (client >= 0)
            close(client);
        if (server >= 0)
            close(server);
    }

    TEST("recvfrom consumes datagram on EFAULT");
    {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            FAIL("socket");
        } else {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;

            if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
                FAIL("bind");
            } else {
                socklen_t alen = sizeof(addr);
                char buf[64];
                struct sockaddr_in from;
                const char *msg = "drop-me";
                getsockname(sock, (struct sockaddr *) &addr, &alen);

                if (sendto(sock, msg, strlen(msg), 0, (struct sockaddr *) &addr,
                           sizeof(addr)) < 0) {
                    FAIL("sendto");
                } else {
                    errno = 0;
                    ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                                         (struct sockaddr *) &from, NULL);
                    int saved_errno = errno;
                    int fl = fcntl(sock, F_GETFL, 0);

                    if (n >= 0) {
                        FAIL("recvfrom unexpectedly succeeded");
                    } else if (saved_errno != EFAULT) {
                        FAIL("recvfrom did not report EFAULT");
                    } else if (fl < 0 ||
                               fcntl(sock, F_SETFL, fl | O_NONBLOCK) < 0) {
                        FAIL("fcntl");
                    } else {
                        errno = 0;
                        n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
                        EXPECT_TRUE(n < 0 && errno == EAGAIN,
                                    "pending datagram was not consumed");
                    }
                }
            }
            close(sock);
        }
    }
}

static void test_ipv6(void)
{
    /* Test AF_INET6 socket creation + bind to ::1 */
    TEST("AF_INET6 socket + bind");
    {
        int sock = socket(AF_INET6, SOCK_STREAM, 0);
        if (sock < 0) {
            FAIL("socket");
            goto ipv6_done;
        }

        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_addr = in6addr_loopback;
        addr6.sin6_port = 0;

        if (bind(sock, (struct sockaddr *) &addr6, sizeof(addr6)) == 0) {
            /* Verify getsockname returns AF_INET6 */
            struct sockaddr_in6 out;
            socklen_t olen = sizeof(out);
            getsockname(sock, (struct sockaddr *) &out, &olen);
            EXPECT_TRUE(out.sin6_family == AF_INET6, "wrong family");
        } else
            FAIL("bind ::1");

        close(sock);
    }
ipv6_done:;

    TEST("IPV6_V6ONLY after bind still fails");
    {
        int sock = socket(AF_INET6, SOCK_STREAM, 0);
        if (sock >= 0) {
            struct sockaddr_in6 addr6;
            memset(&addr6, 0, sizeof(addr6));
            addr6.sin6_family = AF_INET6;
            addr6.sin6_addr = in6addr_loopback;
            addr6.sin6_port = 0;

            if (bind(sock, (struct sockaddr *) &addr6, sizeof(addr6)) < 0) {
                FAIL("bind ::1");
            } else {
                int val = 0;
                errno = 0;
                int rc = setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &val,
                                    sizeof(val));
                EXPECT_TRUE(rc < 0 && errno == EINVAL,
                            "setsockopt(IPV6_V6ONLY) did not fail with EINVAL");
            }
            close(sock);
        } else
            FAIL("socket failed");
    }
}

static void test_sockopts(void)
{
    /* Test setsockopt + getsockopt: SO_REUSEADDR */
    TEST("SO_REUSEADDR set+get");
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            int val = 1;
            if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) ==
                0) {
                int got = 0;
                socklen_t glen = sizeof(got);
                getsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &got, &glen);
                EXPECT_TRUE(got != 0, "SO_REUSEADDR not set");
            } else
                FAIL("setsockopt failed");
            close(sock);
        } else
            FAIL("socket failed");
    }

    /* Test SO_SNDBUF get */
    TEST("SO_SNDBUF getsockopt");
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            int val = 0;
            socklen_t vlen = sizeof(val);
            if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &val, &vlen) == 0) {
                EXPECT_TRUE(val > 0, "SO_SNDBUF is 0");
            } else
                FAIL("getsockopt failed");
            close(sock);
        } else
            FAIL("socket failed");
    }

    TEST("cached SO_TYPE setsockopt still fails");
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            int val = 0;
            socklen_t len = sizeof(val);
            if (getsockopt(sock, SOL_SOCKET, SO_TYPE, &val, &len) < 0) {
                FAIL("getsockopt failed");
            } else {
                errno = 0;
                EXPECT_TRUE(setsockopt(sock, SOL_SOCKET, SO_TYPE, &val,
                                       sizeof(val)) < 0,
                            "setsockopt(SO_TYPE) unexpectedly succeeded");
            }
            close(sock);
        } else
            FAIL("socket failed");
    }

    TEST("cached SO_SNDLOWAT setsockopt still fails");
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            int val = 0;
            socklen_t len = sizeof(val);
            if (getsockopt(sock, SOL_SOCKET, SO_SNDLOWAT, &val, &len) < 0) {
                FAIL("getsockopt failed");
            } else {
                errno = 0;
                EXPECT_TRUE(setsockopt(sock, SOL_SOCKET, SO_SNDLOWAT, &val,
                                       sizeof(val)) < 0,
                            "setsockopt(SO_SNDLOWAT) unexpectedly succeeded");
            }
            close(sock);
        } else
            FAIL("socket failed");
    }

    TEST("SO_ACCEPTCONN setsockopt still fails");
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            int val = 0;
            errno = 0;
            EXPECT_TRUE(setsockopt(sock, SOL_SOCKET, SO_ACCEPTCONN, &val,
                                   sizeof(val)) < 0,
                        "setsockopt(SO_ACCEPTCONN) unexpectedly succeeded");
            close(sock);
        } else
            FAIL("socket failed");
    }

    /* Test SO_RCVBUF get */
    TEST("SO_RCVBUF getsockopt");
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            int val = 0;
            socklen_t vlen = sizeof(val);
            if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &val, &vlen) == 0) {
                EXPECT_TRUE(val > 0, "SO_RCVBUF is 0");
            } else
                FAIL("getsockopt failed");
            close(sock);
        } else
            FAIL("socket failed");
    }

    TEST("IP boolean sockopts normalize to 1");
    {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0) {
            int pktinfo = ip_bool_roundtrip(sock, IP_PKTINFO);
            int recvttl = ip_bool_roundtrip(sock, IP_RECVTTL);
            int recvtos = ip_bool_roundtrip(sock, IP_RECVTOS);

            EXPECT_TRUE(pktinfo == 1 && recvttl == 1 && recvtos == 1,
                        "IP boolean sockopt returned non-normalized value");
            close(sock);
        } else
            FAIL("socket failed");
    }
}

int main(void)
{
    printf("test-net: AF_INET/AF_INET6 networking tests\n");

    test_tcp_udp();
    test_efault_consumes();
    test_ipv6();
    test_sockopts();

    SUMMARY("test-net");
    return fails > 0 ? 1 : 0;
}
