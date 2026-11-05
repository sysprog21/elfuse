/*
 * Test EPOLLET edge-trigger fidelity (kqueue EV_CLEAR backend)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises the documented EPOLLET contract: the application drains the fd to
 * EAGAIN (or EOF) to consume an edge, and the next event fires only when new
 * readable/writable state arrives. This is what well-behaved EPOLLET event
 * loops (nginx, redis, etc.) actually do.
 *
 * Known divergence (kqueue EV_CLEAR limitation, intentionally not tested):
 *   Partial read without draining to EAGAIN. Linux suppresses readiness until
 *   new data arrives; kqueue re-fires on the data-count state change.
 *   Well-behaved apps are unaffected. See src/syscall/poll.c.
 *
 * Syscalls exercised: epoll_create1(20), epoll_ctl(21), epoll_pwait(22),
 *                     pipe2(59), eventfd2(19), socketpair(199),
 *                     read(63), write(64), close(57), fcntl(25)
 */

#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>

#include "test-harness.h"

/* Drain a non-blocking fd until read() returns -1/EAGAIN.
 * Returns total bytes drained, or -1 on unexpected error.
 */
static ssize_t drain_to_eagain(int fd)
{
    char buf[1024];
    ssize_t total = 0;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            total += n;
            continue;
        }
        if (n == 0)
            return total; /* EOF */
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return total;
        return -1;
    }
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int passes = 0, fails = 0;

static void test_edge_basic(void)
{
    /* Edge fires once on data arrival */
    TEST("EPOLLET: fire on data arrival");
    {
        int epfd = epoll_create1(0);
        int p[2];
        pipe(p);
        set_nonblock(p[0]);

        struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.fd = p[0]};
        epoll_ctl(epfd, EPOLL_CTL_ADD, p[0], &ev);

        write(p[1], "x", 1);

        struct epoll_event out;
        int n = epoll_wait(epfd, &out, 1, 100);
        EXPECT_TRUE(n == 1 && (out.events & EPOLLIN), "edge did not fire");

        drain_to_eagain(p[0]);
        close(p[0]);
        close(p[1]);
        close(epfd);
    }

    /* Drain-to-EAGAIN consumes the edge: next epoll_wait returns 0 with no new
     * data. This is the canonical EPOLLET use pattern.
     */
    TEST("EPOLLET: drain-to-EAGAIN consumes edge");
    {
        int epfd = epoll_create1(0);
        int p[2];
        pipe(p);
        set_nonblock(p[0]);

        struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.fd = p[0]};
        epoll_ctl(epfd, EPOLL_CTL_ADD, p[0], &ev);
        write(p[1], "hello", 5);

        struct epoll_event out;
        int n = epoll_wait(epfd, &out, 1, 100);
        if (n != 1) {
            FAIL("first edge missed");
        } else {
            ssize_t drained = drain_to_eagain(p[0]);
            if (drained != 5) {
                FAIL("drain count mismatch");
            } else {
                /* No new data: must not refire */
                n = epoll_wait(epfd, &out, 1, 50);
                EXPECT_TRUE(n == 0, "spurious refire after drain-to-EAGAIN");
            }
        }

        close(p[0]);
        close(p[1]);
        close(epfd);
    }

    /* New data after drain re-arms the edge. This proves edge transitions from
     * not-readable to readable are observed.
     */
    TEST("EPOLLET: new edge after drain + new data");
    {
        int epfd = epoll_create1(0);
        int p[2];
        pipe(p);
        set_nonblock(p[0]);

        struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.fd = p[0]};
        epoll_ctl(epfd, EPOLL_CTL_ADD, p[0], &ev);
        write(p[1], "first", 5);

        struct epoll_event out;
        int n = epoll_wait(epfd, &out, 1, 100);
        if (n != 1) {
            FAIL("first edge missed");
        } else {
            drain_to_eagain(p[0]);
            n = epoll_wait(epfd, &out, 1, 50);
            if (n != 0) {
                FAIL("spurious fire between edges");
            } else {
                write(p[1], "second", 6);
                n = epoll_wait(epfd, &out, 1, 100);
                EXPECT_TRUE(n == 1 && (out.events & EPOLLIN),
                            "second edge missed after new data");
            }
        }

        drain_to_eagain(p[0]);
        close(p[0]);
        close(p[1]);
        close(epfd);
    }
}

static void test_edge_stream_eventfd(void)
{
    /* EPOLLET on a SOCK_STREAM pair, the typical server path. Repeated
     * drain-fill cycles, each producing exactly one edge.
     */
    TEST("EPOLLET: stream socket drain-fill cycles");
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
            FAIL("socketpair");
        } else {
            set_nonblock(sv[0]);
            int epfd = epoll_create1(0);
            struct epoll_event ev = {.events = EPOLLIN | EPOLLET,
                                     .data.fd = sv[0]};
            epoll_ctl(epfd, EPOLL_CTL_ADD, sv[0], &ev);

            int cycles_ok = 0;
            for (int i = 0; i < 4; i++) {
                char msg[8];
                snprintf(msg, sizeof(msg), "msg%d", i);
                write(sv[1], msg, 4);

                struct epoll_event out;
                int n = epoll_wait(epfd, &out, 1, 100);
                if (n != 1)
                    break;
                if (drain_to_eagain(sv[0]) != 4)
                    break;
                /* Idle wait: must report nothing */
                n = epoll_wait(epfd, &out, 1, 20);
                if (n != 0)
                    break;
                cycles_ok++;
            }
            EXPECT_TRUE(cycles_ok == 4, "drain-fill cycle mismatch");

            close(epfd);
            close(sv[0]);
            close(sv[1]);
        }
    }

    /* EPOLLET on eventfd. Counter semantics: read() returns the accumulated
     * count and resets to 0; that drain consumes the edge.
     */
    TEST("EPOLLET: eventfd counter drain");
    {
        int efd = eventfd(0, EFD_NONBLOCK);
        int epfd = epoll_create1(0);
        struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.fd = efd};
        epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &ev);

        uint64_t one = 1;
        write(efd, &one, sizeof(one));
        write(efd, &one, sizeof(one));
        write(efd, &one, sizeof(one));

        struct epoll_event out;
        int n = epoll_wait(epfd, &out, 1, 100);
        if (n != 1) {
            FAIL("first edge missed");
        } else {
            uint64_t v = 0;
            ssize_t r = read(efd, &v, sizeof(v));
            if (r != (ssize_t) sizeof(v) || v != 3) {
                FAIL("eventfd counter mismatch");
            } else {
                /* Counter is now 0; no further edge until next write */
                n = epoll_wait(epfd, &out, 1, 30);
                EXPECT_TRUE(n == 0, "spurious edge after eventfd drain");
            }
        }

        close(efd);
        close(epfd);
    }
}

static void test_edge_oneshot_multi(void)
{
    /* EPOLLET + EPOLLONESHOT: edge fires exactly once and stays armed until
     * EPOLL_CTL_MOD re-arms.
     */
    TEST("EPOLLET + EPOLLONESHOT");
    {
        int epfd = epoll_create1(0);
        int p[2];
        pipe(p);
        set_nonblock(p[0]);

        struct epoll_event ev = {
            .events = EPOLLIN | EPOLLET | EPOLLONESHOT,
            .data.fd = p[0],
        };
        epoll_ctl(epfd, EPOLL_CTL_ADD, p[0], &ev);
        write(p[1], "a", 1);

        struct epoll_event out;
        int n = epoll_wait(epfd, &out, 1, 100);
        if (n != 1) {
            FAIL("first edge missed");
        } else {
            drain_to_eagain(p[0]);
            /* New write must NOT fire until re-arm */
            write(p[1], "b", 1);
            n = epoll_wait(epfd, &out, 1, 30);
            if (n != 0) {
                FAIL("ONESHOT did not disarm");
            } else {
                /* Re-arm; pending data should produce a fresh edge */
                ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
                ev.data.fd = p[0];
                epoll_ctl(epfd, EPOLL_CTL_MOD, p[0], &ev);
                n = epoll_wait(epfd, &out, 1, 100);
                EXPECT_TRUE(n == 1 && (out.events & EPOLLIN),
                            "re-armed edge missed");
            }
        }

        drain_to_eagain(p[0]);
        close(p[0]);
        close(p[1]);
        close(epfd);
    }

    /* Independent edge tracking across two fds in one epoll instance */
    TEST("EPOLLET: independent edges across fds");
    {
        int epfd = epoll_create1(0);
        int p1[2], p2[2];
        pipe(p1);
        pipe(p2);
        set_nonblock(p1[0]);
        set_nonblock(p2[0]);

        struct epoll_event ev1 = {.events = EPOLLIN | EPOLLET,
                                  .data.fd = p1[0]};
        struct epoll_event ev2 = {.events = EPOLLIN | EPOLLET,
                                  .data.fd = p2[0]};
        epoll_ctl(epfd, EPOLL_CTL_ADD, p1[0], &ev1);
        epoll_ctl(epfd, EPOLL_CTL_ADD, p2[0], &ev2);

        /* Write to fd 1 only; only fd 1 should report */
        write(p1[1], "x", 1);
        struct epoll_event out[2];
        int n = epoll_wait(epfd, out, 2, 100);
        if (n != 1 || out[0].data.fd != p1[0]) {
            FAIL("first edge wrong fd");
        } else {
            drain_to_eagain(p1[0]);

            /* Now write to fd 2; only fd 2 should report */
            write(p2[1], "y", 1);
            n = epoll_wait(epfd, out, 2, 100);
            EXPECT_TRUE(n == 1 && out[0].data.fd == p2[0],
                        "second edge wrong fd");
            drain_to_eagain(p2[0]);
        }

        close(p1[0]);
        close(p1[1]);
        close(p2[0]);
        close(p2[1]);
        close(epfd);
    }
}

static void test_edge_hangup(void)
{
    /* EOF reports an edge: pipe write end closed -> EPOLLHUP set on the read
     * end, observable through one EPOLLET wait. Require EPOLLHUP explicitly so
     * a regression that drops it is caught.
     */
    TEST("EPOLLET: EOF / EPOLLHUP edge");
    {
        int epfd = epoll_create1(0);
        int p[2];
        pipe(p);
        set_nonblock(p[0]);

        struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.fd = p[0]};
        epoll_ctl(epfd, EPOLL_CTL_ADD, p[0], &ev);

        close(p[1]); /* triggers EOF on p[0] */

        struct epoll_event out;
        int n = epoll_wait(epfd, &out, 1, 100);
        EXPECT_TRUE(n == 1 && (out.events & EPOLLHUP), "EOF edge missed");

        close(p[0]);
        close(epfd);
    }

    /* EPOLLRDHUP edge on socketpair half-close: peer shuts down its write side,
     * the read side sees EPOLLRDHUP. Distinct from EPOLLHUP because the local
     * write side is still functional.
     */
    TEST("EPOLLET: EPOLLRDHUP on half-close");
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
            FAIL("socketpair");
        } else {
            set_nonblock(sv[0]);
            int epfd = epoll_create1(0);
            struct epoll_event ev = {
                .events = EPOLLIN | EPOLLRDHUP | EPOLLET,
                .data.fd = sv[0],
            };
            epoll_ctl(epfd, EPOLL_CTL_ADD, sv[0], &ev);

            shutdown(sv[1], SHUT_WR);

            struct epoll_event out;
            int n = epoll_wait(epfd, &out, 1, 100);
            EXPECT_TRUE(n == 1 && (out.events & EPOLLRDHUP),
                        "RDHUP edge missed");

            close(epfd);
            close(sv[0]);
            close(sv[1]);
        }
    }
}

static void test_edge_oneshot_filters(void)
{
    /* Multi-filter EPOLLONESHOT: register both EPOLLIN and EPOLLOUT. After
     * EPOLLOUT fires (send buffer initially empty), the unfired EPOLLIN filter
     * must NOT fire on a subsequent epoll_wait until EPOLL_CTL_MOD re-arms.
     * Without the oneshot_armed guard in the wait result loop, kqueue's
     * still-registered EVFILT_READ would leak through. Re-arm via MOD must then
     * surface the pending IN.
     */
    TEST("EPOLLET + EPOLLONESHOT: surviving filter stays disarmed");
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
            FAIL("socketpair");
        } else {
            set_nonblock(sv[0]);
            set_nonblock(sv[1]);
            int epfd = epoll_create1(0);
            struct epoll_event ev = {
                .events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLONESHOT,
                .data.fd = sv[0],
            };
            epoll_ctl(epfd, EPOLL_CTL_ADD, sv[0], &ev);

            /* First wait: only EPOLLOUT is ready (send buffer empty, receive
             * buffer empty).
             */
            struct epoll_event out;
            int n = epoll_wait(epfd, &out, 1, 100);
            if (n != 1 || !(out.events & EPOLLOUT)) {
                FAIL("EPOLLOUT did not fire first");
            } else {
                /* Now make the read side ready. The disarmed fd must stay
                 * silent until MOD re-arms.
                 */
                write(sv[1], "x", 1);
                n = epoll_wait(epfd, &out, 1, 50);
                if (n != 0) {
                    FAIL("EPOLLIN leaked through ONESHOT disarm");
                } else {
                    /* Re-arm dropping OUT entirely. Pending EPOLLIN must
                     * surface; EPOLLOUT must NOT, because MOD has to clean up
                     * the surviving EVFILT_WRITE that ONESHOT did not remove
                     * (only the firing filter was removed).
                     */
                    ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
                    ev.data.fd = sv[0];
                    epoll_ctl(epfd, EPOLL_CTL_MOD, sv[0], &ev);
                    n = epoll_wait(epfd, &out, 1, 100);
                    EXPECT_TRUE(
                        n == 1 && (out.events & EPOLLIN) &&
                            !(out.events & EPOLLOUT),
                        "re-arm misdelivery (IN missing or stale OUT leak)");
                }
            }

            drain_to_eagain(sv[0]);
            close(epfd);
            close(sv[0]);
            close(sv[1]);
        }
    }

    /* Symmetric ONESHOT MOD case: register with IN ready and send-buffer full
     * (so only IN fires). The unfired EVFILT_WRITE survives. MOD dropping OUT
     * must clean the surviving write-side filter; otherwise a later writability
     * transition surfaces a stale EPOLLOUT.
     *
     * This locks in the kqueue-batched-EV_DELETE fix: when the first EV_DELETE
     * in a batch fails ENOENT (the fired filter was already removed by
     * EV_ONESHOT), kevent with NULL eventlist stops and the second EV_DELETE
     * never runs, leaking the survivor. The fix issues each delete in its own
     * kevent call.
     */
    TEST("EPOLLET + EPOLLONESHOT: stale write filter cleaned by MOD");
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
            FAIL("socketpair");
        } else {
            set_nonblock(sv[0]);
            set_nonblock(sv[1]);

            /* Make sv[0] readable: peer writes a few bytes. */
            write(sv[1], "abc", 3);

            /* Fill sv[0] send buffer until EAGAIN so OUT is NOT ready. */
            char fill[8 * 1024];
            for (size_t i = 0; i < sizeof(fill); i++)
                fill[i] = 'B';
            ssize_t total = 0;
            for (;;) {
                ssize_t w = write(sv[0], fill, sizeof(fill));
                if (w < 0)
                    break;
                total += w;
                if (total > 16 * 1024 * 1024) {
                    FAIL("send buffer never filled");
                    close(sv[0]);
                    close(sv[1]);
                    goto stale_write_done;
                }
            }

            int epfd = epoll_create1(0);
            struct epoll_event ev = {
                .events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLONESHOT,
                .data.fd = sv[0],
            };
            epoll_ctl(epfd, EPOLL_CTL_ADD, sv[0], &ev);

            /* First wait: only IN fires (OUT was not ready). EV_ONESHOT removes
             * EVFILT_READ; EVFILT_WRITE survives in kqueue.
             */
            struct epoll_event out;
            int n = epoll_wait(epfd, &out, 1, 100);
            if (n != 1 || (out.events & EPOLLOUT)) {
                FAIL("expected only IN to fire (OUT must not be ready)");
            } else {
                /* MOD to IN-only -- drops OUT entirely. The implementation must
                 * remove the surviving EVFILT_WRITE; with the kevent
                 * batched-delete bug it would leak.
                 */
                ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
                ev.data.fd = sv[0];
                epoll_ctl(epfd, EPOLL_CTL_MOD, sv[0], &ev);

                /* Drain pending IN data so a re-armed IN cannot fire. */
                drain_to_eagain(sv[0]);

                /* Drain peer to free sv[0] send buffer. If the stale
                 * EVFILT_WRITE leaked, the writability transition fires and we
                 * observe a spurious EPOLLOUT.
                 */
                char rbuf[8 * 1024];
                ssize_t got = 0;
                while (got < total) {
                    ssize_t r = read(sv[1], rbuf, sizeof(rbuf));
                    if (r <= 0)
                        break;
                    got += r;
                }

                n = epoll_wait(epfd, &out, 1, 100);
                EXPECT_TRUE(
                    n == 0 || !(out.events & EPOLLOUT),
                    "stale EPOLLOUT leaked through MOD (batched delete bug)");
            }

            close(epfd);
            close(sv[0]);
            close(sv[1]);
        }
    stale_write_done:;
    }
}

int main(void)
{
    printf("test-epoll-edge: EPOLLET semantics tests\n");

    test_edge_basic();
    test_edge_stream_eventfd();
    test_edge_oneshot_multi();
    test_edge_hangup();
    test_edge_oneshot_filters();

    SUMMARY("test-epoll-edge");
    return fails > 0 ? 1 : 0;
}
