/*
 * Test epoll emulation (kqueue backend)
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: epoll_create1, epoll_ctl (ADD/MOD/DEL), epoll_wait with
 *        pipes and eventfds, data.u64 preservation, timeout behavior
 *
 * Syscalls exercised: epoll_create1(20), epoll_ctl(21), epoll_pwait(22),
 *                     pipe2(59), eventfd2(19), write(64), close(57)
 */

#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <time.h>

#include "test-harness.h"

#ifndef __NR_epoll_pwait2
#define __NR_epoll_pwait2 441
#endif

int passes = 0, fails = 0;

static void test_basic_wait(void)
{
    /* Test epoll_create1 with CLOEXEC */
    TEST("epoll_create1(CLOEXEC)");
    {
        int epfd = epoll_create1(EPOLL_CLOEXEC);
        EXPECT_TRUE(epfd >= 0, "epoll_create1 failed");
        close(epfd);
    }

    /* Test EPOLL_CTL_ADD + epoll_wait: pipe read end becomes ready */
    TEST("ADD pipe + wait EPOLLIN");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }

        struct epoll_event ev = {.events = EPOLLIN, .data.fd = pipefd[0]};
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) == 0) {
            write(pipefd[1], "x", 1);

            struct epoll_event out;
            int n = epoll_wait(epfd, &out, 1, 100);
            EXPECT_TRUE(
                n == 1 && (out.events & EPOLLIN) && out.data.fd == pipefd[0],
                "epoll_wait wrong result");
        } else
            FAIL("epoll_ctl ADD failed");

        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }
}

static void test_read_masks(void)
{
    /* The read half of "epoll reads the same bits poll does". eventpoll has no
     * mask of its own: ep_item_poll masks the file's answer by
     * epi->event.events, so a registration naming only EPOLLRDNORM asks for one
     * of the two bits a readable pipe raises, has to be woken by it, and has to
     * be told EPOLLRDNORM rather than EPOLLIN. Gating the arming on EPOLLIN
     * alone registered no filter at all and the wait ran to its timeout.
     */
    TEST("ADD pipe + wait EPOLLRDNORM alone");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }

        struct epoll_event ev = {.events = EPOLLRDNORM, .data.fd = pipefd[0]};
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) == 0) {
            write(pipefd[1], "x", 1);

            struct epoll_event out = {0};
            int n = epoll_wait(epfd, &out, 1, 500);
            EXPECT_TRUE(n == 1 && (out.events & EPOLLRDNORM) &&
                            !(out.events & EPOLLIN) && out.data.fd == pipefd[0],
                        "EPOLLRDNORM alone did not fire as EPOLLRDNORM");
        } else
            FAIL("epoll_ctl ADD failed");

        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }

    /* The mask is reported back as asked for, both bits or one. */
    TEST("EPOLLIN|EPOLLRDNORM reports both");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }

        struct epoll_event ev = {.events = EPOLLIN | EPOLLRDNORM,
                                 .data.fd = pipefd[0]};
        struct epoll_event out = {0};
        int n = -1;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) == 0) {
            write(pipefd[1], "x", 1);
            n = epoll_wait(epfd, &out, 1, 500);
        }
        EXPECT_TRUE(n == 1 && (out.events & (EPOLLIN | EPOLLRDNORM)) ==
                                  (EPOLLIN | EPOLLRDNORM),
                    "both bits asked for, both not reported");

        TEST("and EPOLLIN alone reports only EPOLLIN");
        ev.events = EPOLLIN;
        out.events = 0;
        n = -1;
        if (epoll_ctl(epfd, EPOLL_CTL_MOD, pipefd[0], &ev) == 0)
            n = epoll_wait(epfd, &out, 1, 500);
        EXPECT_TRUE(
            n == 1 && (out.events & EPOLLIN) && !(out.events & EPOLLRDNORM),
            "EPOLLIN alone reported a bit it did not ask for");

        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }

    /* A registration naming no read bit at all still has its read filter armed,
     * to catch the EOF EPOLLRDHUP is about -- but armed with a low-water mark
     * no readable byte can reach, so mere readability is not an event it hears.
     * That is what Linux does: do_epoll_ctl widens the requested mask by
     * EPOLLERR|EPOLLHUP only, ep_item_poll masks the pipe's EPOLLIN|EPOLLRDNORM
     * by it, and nothing survives, so ep_poll waits the caller out and returns
     * 0 at the deadline. Measured at rc=0 after 503-510 ms on Linux 6.18.50
     * (aarch64), the qemu reference lane this file also runs in.
     *
     * The answer neither side may give is 0 *before* the deadline, which would
     * make a guest treat a timeout it never waited for as one it did. So the
     * elapsed time is the assertion, not just the count.
     */
    TEST("EPOLLRDHUP alone waits its timeout out on a merely readable fd");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }

        struct epoll_event ev = {.events = EPOLLRDHUP, .data.fd = pipefd[0]};
        struct epoll_event out = {0};
        int n = -1;
        struct timespec t0 = {0}, t1 = {0};
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) == 0) {
            write(pipefd[1], "x", 1);
            clock_gettime(CLOCK_MONOTONIC, &t0);
            n = epoll_wait(epfd, &out, 1, 500);
            clock_gettime(CLOCK_MONOTONIC, &t1);
        }
        long waited_ms = (long) (t1.tv_sec - t0.tv_sec) * 1000 +
                         (t1.tv_nsec - t0.tv_nsec) / 1000000;
        EXPECT_TRUE(n == 0 && waited_ms >= 450,
                    "a merely readable fd was reported to an EPOLLRDHUP-only "
                    "registration, or the wait ended before its timeout");

        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }

    /* And the hangup it did ask for still arrives at once. This is the other
     * half of the low-water mark above: silencing readability must not silence
     * the EOF, which activates the read filter whatever the mark is.
     */
    TEST("EPOLLRDHUP alone still reports the hangup when the writer closes");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }

        struct epoll_event ev = {.events = EPOLLRDHUP, .data.fd = pipefd[0]};
        struct epoll_event out = {0};
        int n = -1;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) == 0) {
            write(pipefd[1], "x", 1);
            close(pipefd[1]);
            pipefd[1] = -1;
            n = epoll_wait(epfd, &out, 1, 500);
        }

        /* A pipe hangup is EPOLLHUP on Linux; this layer also sets EPOLLRDHUP
         * on it, since kqueue reports one EV_EOF for both the full hangup a
         * pipe means by it and the half-shutdown a socket does. Only the bit
         * both agree on is asserted here.
         */
        EXPECT_TRUE(n == 1 && (out.events & EPOLLHUP),
                    "a closed writer raised no hangup");

        close(pipefd[0]);
        if (pipefd[1] >= 0)
            close(pipefd[1]);
        close(epfd);
    }

    /* MOD onto the read pair has to arm, and DEL of it has to disarm: both
     * decide from the same mask the ADD above does.
     */
    TEST("MOD to EPOLLRDNORM arms, DEL of it disarms");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }

        struct epoll_event ev = {.events = EPOLLOUT, .data.fd = pipefd[0]};
        struct epoll_event out = {0};
        int n = -1;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) == 0) {
            ev.events = EPOLLRDNORM;
            if (epoll_ctl(epfd, EPOLL_CTL_MOD, pipefd[0], &ev) == 0) {
                write(pipefd[1], "x", 1);
                n = epoll_wait(epfd, &out, 1, 500);
            }
        }
        EXPECT_TRUE(n == 1 && (out.events & EPOLLRDNORM),
                    "MOD onto EPOLLRDNORM armed nothing");

        TEST("and DEL of an EPOLLRDNORM-only registration is silent after");
        int d = epoll_ctl(epfd, EPOLL_CTL_DEL, pipefd[0], NULL);
        out.events = 0;
        n = epoll_wait(epfd, &out, 1, 100);
        EXPECT_TRUE(d == 0 && n == 0, "DEL left the read filter registered");

        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }
}

static void test_write_masks(void)
{
    /* Test EPOLLOUT on pipe write end (always writable) */
    TEST("ADD pipe write + EPOLLOUT");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }

        struct epoll_event ev = {.events = EPOLLOUT, .data.fd = pipefd[1]};
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[1], &ev) == 0) {
            struct epoll_event out;
            int n = epoll_wait(epfd, &out, 1, 100);
            EXPECT_TRUE(n == 1 && (out.events & EPOLLOUT),
                        "pipe not write-ready");
        } else
            FAIL("epoll_ctl ADD failed");

        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }

    /* The write half of the same rule, off the usbfs path. ep_item_poll masks
     * the file's answer by epi->event.events, and a pipe with room raises
     * EPOLLOUT|EPOLLWRNORM (fs/pipe.c:697 at v6.18), as a writable socket does
     * (net/ipv4/tcp.c:606 at the same tag), so a registration naming only
     * EPOLLWRNORM is a legal write registration Linux both wakes and reports as
     * EPOLLWRNORM. Gating the arming on EPOLLOUT alone registered no
     * EVFILT_WRITE and the wait ran to its timeout.
     */
    TEST("ADD pipe write + wait EPOLLWRNORM alone");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }

        struct epoll_event ev = {.events = EPOLLWRNORM, .data.fd = pipefd[1]};
        struct epoll_event out = {0};
        int n = -1;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[1], &ev) == 0)
            n = epoll_wait(epfd, &out, 1, 500);
        EXPECT_TRUE(n == 1 && (out.events & EPOLLWRNORM) &&
                        !(out.events & EPOLLOUT) && out.data.fd == pipefd[1],
                    "EPOLLWRNORM alone did not fire as EPOLLWRNORM");

        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }

    /* The write mask is reported back as asked for, both bits or one. */
    TEST("EPOLLOUT|EPOLLWRNORM reports both");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }

        struct epoll_event ev = {.events = EPOLLOUT | EPOLLWRNORM,
                                 .data.fd = pipefd[1]};
        struct epoll_event out = {0};
        int n = -1;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[1], &ev) == 0)
            n = epoll_wait(epfd, &out, 1, 500);
        EXPECT_TRUE(n == 1 && (out.events & (EPOLLOUT | EPOLLWRNORM)) ==
                                  (EPOLLOUT | EPOLLWRNORM),
                    "both write bits asked for, both not reported");

        TEST("and EPOLLOUT alone reports only EPOLLOUT");
        ev.events = EPOLLOUT;
        out.events = 0;
        n = -1;
        if (epoll_ctl(epfd, EPOLL_CTL_MOD, pipefd[1], &ev) == 0)
            n = epoll_wait(epfd, &out, 1, 500);
        EXPECT_TRUE(
            n == 1 && (out.events & EPOLLOUT) && !(out.events & EPOLLWRNORM),
            "EPOLLOUT alone reported a bit it did not ask for");

        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }

    /* MOD onto the write pair has to arm, and DEL of it has to disarm: both
     * decide from the same mask the ADD above does, the way the read twins do.
     */
    TEST("MOD to EPOLLWRNORM arms, DEL of it disarms");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }

        struct epoll_event ev = {.events = EPOLLIN, .data.fd = pipefd[1]};
        struct epoll_event out = {0};
        int n = -1;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[1], &ev) == 0) {
            ev.events = EPOLLWRNORM;
            if (epoll_ctl(epfd, EPOLL_CTL_MOD, pipefd[1], &ev) == 0)
                n = epoll_wait(epfd, &out, 1, 500);
        }
        EXPECT_TRUE(n == 1 && (out.events & EPOLLWRNORM),
                    "MOD onto EPOLLWRNORM armed nothing");

        TEST("and DEL of an EPOLLWRNORM-only registration is silent after");
        int d = epoll_ctl(epfd, EPOLL_CTL_DEL, pipefd[1], NULL);
        out.events = 0;
        n = epoll_wait(epfd, &out, 1, 100);
        EXPECT_TRUE(d == 0 && n == 0, "DEL left the write filter registered");

        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }
}

static void test_ctl_mod_del(void)
{
    /* Test EPOLL_CTL_MOD: change monitored events */
    TEST("CTL_MOD events");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }

        /* Add read end for EPOLLIN */
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = pipefd[0]};
        epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev);

        /* Modify to EPOLLOUT; pipe read end cannot write, so no event */
        ev.events = EPOLLOUT;
        if (epoll_ctl(epfd, EPOLL_CTL_MOD, pipefd[0], &ev) == 0) {
            struct epoll_event out;
            int n = epoll_wait(epfd, &out, 1, 10);
            EXPECT_TRUE(n == 0, "unexpected event after MOD");
        } else
            FAIL("epoll_ctl MOD failed");

        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }

    /* Test EPOLL_CTL_DEL: events stop after removal */
    TEST("CTL_DEL removes fd");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }

        struct epoll_event ev = {.events = EPOLLIN, .data.fd = pipefd[0]};
        epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev);

        if (epoll_ctl(epfd, EPOLL_CTL_DEL, pipefd[0], NULL) == 0) {
            write(pipefd[1], "x", 1);
            struct epoll_event out;
            int n = epoll_wait(epfd, &out, 1, 10);
            EXPECT_TRUE(n == 0, "event after DEL");
        } else
            FAIL("epoll_ctl DEL failed");

        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }

    /* Test EPOLL_CTL_DEL on an unregistered fd. Repeat the failure path enough
     * times to catch leaked host dup refs.
     */
    TEST("CTL_DEL ENOENT does not leak refs");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }
        int ok = 1;

        for (int i = 0; i < 4096; i++) {
            errno = 0;
            if (epoll_ctl(epfd, EPOLL_CTL_DEL, pipefd[0], NULL) != -1 ||
                errno != ENOENT) {
                ok = 0;
                break;
            }
        }

        EXPECT_TRUE(ok, "unexpected result from repeated DEL ENOENT");

        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }
}

static void test_wait_basics(void)
{
    /* Test timeout=0: non-blocking poll returns immediately */
    TEST("timeout=0 no events");
    {
        int epfd = epoll_create1(0);
        struct epoll_event out;
        int n = epoll_wait(epfd, &out, 1, 0);
        EXPECT_TRUE(n == 0, "expected 0 events");
        close(epfd);
    }

    /* Test epoll_pwait2 timeout=0 path */
    TEST("epoll_pwait2 timeout=0 no events");
    {
        int epfd = epoll_create1(0);
        struct epoll_event out;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 0};
        int n = syscall(__NR_epoll_pwait2, epfd, &out, 1, &ts, NULL, 8);
        EXPECT_TRUE(n == 0, "expected 0 events");
        close(epfd);
    }

    /* Test multiple FDs in same epoll instance */
    TEST("multiple fds (pipe+eventfd)");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }
        int efd = eventfd(0, EFD_NONBLOCK);

        struct epoll_event ev1 = {.events = EPOLLIN, .data.fd = pipefd[0]};
        struct epoll_event ev2 = {.events = EPOLLIN, .data.fd = efd};
        epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev1);
        epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &ev2);

        /* Make both readable */
        write(pipefd[1], "x", 1);
        uint64_t val = 1;
        write(efd, &val, sizeof(val));

        struct epoll_event out[4];
        int n = epoll_wait(epfd, out, 4, 100);
        EXPECT_TRUE(n >= 1, "no events from multiple fds");

        close(efd);
        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }

    /* Test epoll_data.u64 is preserved through epoll_wait */
    TEST("epoll_data.u64 preserved");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }

        struct epoll_event ev = {.events = EPOLLIN,
                                 .data.u64 = 0xDEADBEEFCAFEULL};
        epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev);
        write(pipefd[1], "x", 1);

        struct epoll_event out;
        int n = epoll_wait(epfd, &out, 1, 100);
        EXPECT_TRUE(n == 1 && out.data.u64 == 0xDEADBEEFCAFEULL,
                    "data not preserved");

        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }
}

static void test_oneshot_rearm(void)
{
    /* Test EPOLLONESHOT + EPOLL_CTL_MOD re-arm This is the critical test: after
     * EPOLLONESHOT fires and is reported, EPOLL_CTL_MOD should succeed to
     * re-arm the registration.
     */
    TEST("EPOLLONESHOT re-arm with MOD");
    {
        int epfd = epoll_create1(0);
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            FAIL("pipe");
            pipefd[0] = pipefd[1] = -1;
        }

        /* Register with EPOLLONESHOT */
        struct epoll_event ev = {.events = EPOLLIN | EPOLLONESHOT,
                                 .data.fd = pipefd[0]};
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) == 0) {
            write(pipefd[1], "x", 1);

            /* First event should fire */
            struct epoll_event out;
            int n = epoll_wait(epfd, &out, 1, 100);
            if (n == 1 && (out.events & EPOLLIN)) {
                /* KEY: MOD should succeed to re-arm after ONESHOT fired */
                ev.events = EPOLLIN | EPOLLONESHOT;
                ev.data.fd = pipefd[0];
                if (epoll_ctl(epfd, EPOLL_CTL_MOD, pipefd[0], &ev) == 0) {
                    /* Write again to verify re-arm */
                    write(pipefd[1], "y", 1);
                    n = epoll_wait(epfd, &out, 1, 100);
                    EXPECT_TRUE(n == 1 && (out.events & EPOLLIN),
                                "re-armed EPOLLONESHOT did not fire");
                } else {
                    FAIL(
                        "EPOLL_CTL_MOD failed after ONESHOT (this was the "
                        "bug)");
                }
            } else {
                FAIL("initial EPOLLONESHOT did not fire");
            }
        } else {
            FAIL("epoll_ctl ADD with EPOLLONESHOT failed");
        }

        close(pipefd[0]);
        close(pipefd[1]);
        close(epfd);
    }
}

static void test_ctl_validation(void)
{
    /* An op outside the three constants must be refused before anything is
     * armed. The arms test DEL, then ADD, then MOD, so an unknown value used to
     * fall past all three into the registration path and arm a knote.
     *
     * The null-event cases go with it: Linux reads no event for DEL, so a null
     * pointer there is not an error, and faults for ADD and MOD.
     */
    int vep = epoll_create1(0);
    int vfd[2];
    if (vep >= 0 && pipe(vfd) == 0) {
        struct epoll_event vev = {.events = EPOLLIN, .data.fd = vfd[0]};

        TEST("an unknown epoll_ctl op is EINVAL");
        EXPECT_ERRNO(epoll_ctl(vep, 99, vfd[0], &vev), EINVAL,
                     "op 99 accepted");

        TEST("and a negative op is EINVAL");
        EXPECT_ERRNO(epoll_ctl(vep, -1, vfd[0], &vev), EINVAL,
                     "op -1 accepted");

        TEST("the rejected op armed nothing");
        struct epoll_event got;
        EXPECT_EQ(epoll_wait(vep, &got, 1, 0), 0, "a knote was registered");

        TEST("a null event on ADD is EFAULT");
        EXPECT_ERRNO(epoll_ctl(vep, EPOLL_CTL_ADD, vfd[0], NULL), EFAULT,
                     "null event accepted");

        /* The order these are decided in, measured against Linux 6.18 rather
         * than read off the source. Each of these was a divergence: the first
         * three because the fd == epfd test used to open the function, ahead of
         * both descriptor lookups, and the last because the event was tested
         * for NULL instead of being copied. And above all of them, the copy.
         * The kernel runs it in the syscall wrapper, before do_epoll_ctl
         * reaches either fdget, so an unreadable event outranks a bad
         * descriptor for every op that reads one. DEL reads none, which is the
         * one call in this family that still answers EBADF.
         */
        TEST("an unreadable event outranks a bad epfd");
        EXPECT_ERRNO(
            epoll_ctl(-1, EPOLL_CTL_ADD, vfd[0], (struct epoll_event *) 1),
            EFAULT, "not EFAULT");

        TEST("an unreadable event outranks a bad target fd");
        EXPECT_ERRNO(
            epoll_ctl(vep, EPOLL_CTL_ADD, -1, (struct epoll_event *) 1), EFAULT,
            "not EFAULT");

        TEST("an unreadable event outranks a bad epfd and a bad op");
        EXPECT_ERRNO(epoll_ctl(-1, 99, -1, (struct epoll_event *) 1), EFAULT,
                     "not EFAULT");

        TEST("but DEL reads none, so a bad epfd wins there");
        EXPECT_ERRNO(epoll_ctl(-1, EPOLL_CTL_DEL, -1, (struct epoll_event *) 1),
                     EBADF, "not EBADF");

        TEST("a bad epfd outranks a bad op");
        EXPECT_ERRNO(epoll_ctl(-1, 99, vfd[0], &vev), EBADF, "not EBADF");

        TEST("a bad target fd outranks a bad op");
        EXPECT_ERRNO(epoll_ctl(vep, 99, -1, &vev), EBADF, "not EBADF");

        TEST("a bad epfd outranks the self-add check");
        EXPECT_ERRNO(epoll_ctl(-1, EPOLL_CTL_ADD, -1, &vev), EBADF,
                     "not EBADF");

        TEST("an unreadable event outranks a bad op");
        EXPECT_ERRNO(epoll_ctl(vep, 99, vfd[0], (struct epoll_event *) 1),
                     EFAULT, "not EFAULT");

        TEST("an unreadable event outranks the self-add check");
        EXPECT_ERRNO(epoll_ctl(vep, EPOLL_CTL_ADD, vep, NULL), EFAULT,
                     "not EFAULT");

        TEST("a null event on DEL is not an error for a registered fd");
        EXPECT_EQ(epoll_ctl(vep, EPOLL_CTL_ADD, vfd[0], &vev), 0, "add failed");
        EXPECT_EQ(epoll_ctl(vep, EPOLL_CTL_DEL, vfd[0], NULL), 0,
                  "DEL rejected a null event");

        close(vfd[0]);
        close(vfd[1]);
        close(vep);
    }
}

int main(void)
{
    printf("test-epoll: epoll emulation tests\n");

    test_basic_wait();
    test_read_masks();
    test_write_masks();
    test_ctl_mod_del();
    test_wait_basics();
    test_oneshot_rearm();
    test_ctl_validation();

    SUMMARY("test-epoll");
    return fails > 0 ? 1 : 0;
}
