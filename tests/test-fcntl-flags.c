/*
 * F_GETFL / F_SETFL across every fd type elfuse answers for
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse answers the file status flags from three different places depending on
 * the fd: the host description, a per-fd shadow, or a fixed reply. FUSE fds are
 * pure shadow, a timerfd is a kqueue the host will not take F_SETFL on, O_ASYNC
 * is never armed on the host fd, the access mode of a regular file is kept in
 * the shadow because O_PATH and O_DIRECTORY have no macOS equivalent, and
 * O_NONBLOCK is elfuse's own on the fds whose transfers it owns.
 *
 * Each of those is defensible alone, and together they are a matrix nothing
 * pinned. This walks it: what F_GETFL reports for a freshly opened fd of each
 * kind, which bits survive a round trip through F_SETFL, and which the kernel
 * is supposed to ignore. It is written to hold across a refactor of how the
 * flags are stored, so it asserts what Linux answers, not how elfuse gets
 * there.
 *
 * Syscalls exercised: fcntl(25), openat(56), pipe2(59), socket(198),
 *                     timerfd_create(85), eventfd2(19), ioctl(29)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <stddef.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#ifndef O_PATH
#define O_PATH 010000000
#endif


static void check_accmode(const char *what, int fd, int want)
{
    TEST(what);
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0)
        FAIL("F_GETFL failed");
    else
        EXPECT_EQ(fl & O_ACCMODE, want, "wrong access mode");
}

/* A bit the guest sets through F_SETFL must read back through F_GETFL, and
 * clearing it must stick. Both directions, because a shadow that is written but
 * not read (or read but not written) passes a one-way check.
 */
static void check_roundtrip(const char *what, int fd, int bit)
{
    TEST(what);
    int base = fcntl(fd, F_GETFL);
    if (base < 0) {
        FAIL("F_GETFL failed");
        return;
    }
    if (fcntl(fd, F_SETFL, base | bit) < 0) {
        FAIL("F_SETFL failed");
        return;
    }
    int set = fcntl(fd, F_GETFL);
    if (fcntl(fd, F_SETFL, base & ~bit) < 0) {
        FAIL("F_SETFL clear failed");
        return;
    }
    int cleared = fcntl(fd, F_GETFL);
    EXPECT_TRUE((set & bit) && !(cleared & bit), "bit did not round trip");
}

/* F_SETFL cannot change the access mode: Linux masks the argument down to the
 * settable set and leaves O_ACCMODE alone.
 */
static void check_accmode_immutable(const char *what, int fd, int want)
{
    TEST(what);
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0) {
        FAIL("F_GETFL failed");
        return;
    }
    /* Ask for the opposite access mode plus a settable bit. */
    int other = (want == O_RDONLY) ? O_WRONLY : O_RDONLY;
    fcntl(fd, F_SETFL, (fl & ~O_ACCMODE) | other);
    int after = fcntl(fd, F_GETFL);
    EXPECT_EQ(after & O_ACCMODE, want, "F_SETFL changed the access mode");
}

static void test_regular_access(const char *regular_file)
{
    /* Regular files, one per access mode. */
    int rd = open("/etc/hostname", O_RDONLY);
    if (rd < 0)
        rd = open("/proc/self/cmdline", O_RDONLY);
    int wr = open(regular_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int rw = open(regular_file, O_RDWR);

    check_accmode("regular O_RDONLY", rd, O_RDONLY);
    check_accmode("regular O_WRONLY", wr, O_WRONLY);
    check_accmode("regular O_RDWR", rw, O_RDWR);
    check_accmode_immutable("regular access mode is immutable", wr, O_WRONLY);
    check_roundtrip("regular O_APPEND round trip", rw, O_APPEND);
    check_roundtrip("regular O_NONBLOCK round trip", rw, O_NONBLOCK);

    if (rd >= 0)
        close(rd);
    if (wr >= 0)
        close(wr);
    if (rw >= 0)
        close(rw);
    unlink(regular_file);
}

static void test_pipe_nonblock(void)
{
    /* A pipe: elfuse owns O_NONBLOCK on both ends. */
    int p[2];
    if (pipe(p) == 0) {
        check_accmode("pipe read end is O_RDONLY", p[0], O_RDONLY);
        check_accmode("pipe write end is O_WRONLY", p[1], O_WRONLY);
        check_roundtrip("pipe O_NONBLOCK round trip", p[0], O_NONBLOCK);
        check_roundtrip("pipe O_ASYNC round trip", p[0], O_ASYNC);
        check_accmode_immutable("pipe access mode is immutable", p[0],
                                O_RDONLY);

        TEST("pipe2(O_NONBLOCK) reports it at once");
        int q[2];
        if (pipe2(q, O_NONBLOCK) == 0) {
            EXPECT_TRUE(fcntl(q[0], F_GETFL) & O_NONBLOCK, "not reported");
            close(q[0]);
            close(q[1]);
        } else {
            FAIL("pipe2 failed");
        }
        close(p[0]);
        close(p[1]);
    }

    /* A nonblocking write bigger than the pipe buffer reports what it moved.
     * Waiting for the remainder is exactly what O_NONBLOCK said not to do, and
     * a transfer path that loops until the whole request is out hangs here
     * instead of returning.
     */
    int nbw[2];
    if (pipe(nbw) == 0) {
        fcntl(nbw[1], F_SETFL, fcntl(nbw[1], F_GETFL) | O_NONBLOCK);
        static char big[1 << 20];
        ssize_t n = write(nbw[1], big, sizeof(big));
        TEST("nonblocking write past the pipe buffer reports a partial count");
        EXPECT_TRUE(n > 0 && (size_t) n < sizeof(big), "not a partial count");

        TEST("and the next one reports EAGAIN");
        EXPECT_ERRNO(write(nbw[1], big, sizeof(big)), EAGAIN,
                     "write did not report EAGAIN");
        close(nbw[0]);
        close(nbw[1]);
    }
}

static void test_socket_timerfd_eventfd(void)
{
    /* A socket: never owned, so the host flag is the guest's. */
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock >= 0) {
        check_accmode("socket is O_RDWR", sock, O_RDWR);
        check_roundtrip("socket O_NONBLOCK round trip", sock, O_NONBLOCK);
        close(sock);
    }

    /* A timerfd is a kqueue on the host, which refuses F_SETFL, so its flags
     * live entirely in the shadow.
     */
    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (tfd >= 0) {
        check_accmode("timerfd is O_RDWR", tfd, O_RDWR);
        check_roundtrip("timerfd O_NONBLOCK round trip", tfd, O_NONBLOCK);
        close(tfd);
    }

    int efd = eventfd(0, 0);
    if (efd >= 0) {
        check_accmode("eventfd is O_RDWR", efd, O_RDWR);
        check_roundtrip("eventfd O_NONBLOCK round trip", efd, O_NONBLOCK);

        /* Reporting the flag is not the same as honouring it. A synthetic fd is
         * backed by elfuse's own pipe, so the emulation has to read the guest's
         * O_NONBLOCK from the same place F_GETFL answers from; when it did not,
         * this read blocked forever instead of reporting EAGAIN.
         */
        uint64_t v;
        fcntl(efd, F_SETFL, fcntl(efd, F_GETFL) | O_NONBLOCK);
        TEST("eventfd honours O_NONBLOCK set by fcntl");
        EXPECT_ERRNO(read(efd, &v, sizeof(v)), EAGAIN, "read did not EAGAIN");

        int on = 1;
        fcntl(efd, F_SETFL, fcntl(efd, F_GETFL) & ~O_NONBLOCK);
        ioctl(efd, FIONBIO, &on);
        TEST("eventfd honours O_NONBLOCK set by FIONBIO");
        EXPECT_ERRNO(read(efd, &v, sizeof(v)), EAGAIN, "read did not EAGAIN");
        close(efd);
    }

    int efd_nb = eventfd(0, EFD_NONBLOCK);
    if (efd_nb >= 0) {
        uint64_t v;
        TEST("eventfd honours EFD_NONBLOCK from creation");
        EXPECT_ERRNO(read(efd_nb, &v, sizeof(v)), EAGAIN,
                     "read did not EAGAIN");
        close(efd_nb);
    }
}

static void test_signalfd_nonblock(void)
{
    /* Same shape for signalfd, whose flag lived in the same private field. */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    int sfd = signalfd(-1, &mask, 0);
    if (sfd >= 0) {
        check_accmode("signalfd is O_RDWR", sfd, O_RDWR);
        char sbuf[128];
        fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK);
        TEST("signalfd honours O_NONBLOCK set by fcntl");
        EXPECT_ERRNO(read(sfd, sbuf, sizeof(sbuf)), EAGAIN,
                     "read did not EAGAIN");
        close(sfd);
    }
}

static void test_dup_synthetic(void)
{
    /* inotify keeps the same shape: O_RDONLY on Linux, and a private copy of
     * the nonblock flag would strand a guest that set it after creation. An
     * alias of a synthetic fd shares its open file description, so it inherits
     * the mode and the flag. The dup paths for these types rebuild linux_flags
     * by hand, which is how they came to drop both.
     */
    int edup_src = eventfd(0, EFD_NONBLOCK);
    if (edup_src >= 0) {
        int alias = dup(edup_src);
        if (alias >= 0) {
            uint64_t v;
            check_accmode("dup(eventfd) keeps O_RDWR", alias, O_RDWR);
            TEST("dup(eventfd) keeps O_NONBLOCK");
            EXPECT_TRUE(fcntl(alias, F_GETFL) & O_NONBLOCK, "flag lost");
            TEST("dup(eventfd) honours it");
            EXPECT_ERRNO(read(alias, &v, sizeof(v)), EAGAIN,
                         "read did not EAGAIN");
            close(alias);
        }
        close(edup_src);
    }

    int tdup_src = timerfd_create(CLOCK_MONOTONIC, 0);
    if (tdup_src >= 0) {
        int alias = dup(tdup_src);
        if (alias >= 0) {
            /* F_SETFL on one alias is a change to the description, so the other
             * one sees it too.
             */
            fcntl(tdup_src, F_SETFL, fcntl(tdup_src, F_GETFL) | O_NONBLOCK);
            TEST("F_SETFL on a timerfd reaches its alias");
            EXPECT_TRUE(fcntl(alias, F_GETFL) & O_NONBLOCK, "alias missed it");

            /* Every bit the shadow answers belongs to the description, not just
             * O_NONBLOCK: O_APPEND is one Linux keeps for a timerfd.
             */
            fcntl(tdup_src, F_SETFL, fcntl(tdup_src, F_GETFL) | O_APPEND);
            TEST("every shadowed timerfd bit reaches the alias");
            EXPECT_TRUE(fcntl(alias, F_GETFL) & O_APPEND, "alias missed it");
            close(alias);
        }
        close(tdup_src);
    }
}

static void test_inotify_nonblock(void)
{
    int ifd = inotify_init();
    if (ifd >= 0) {
        check_accmode("inotify is O_RDONLY", ifd, O_RDONLY);
        char ibuf[512];
        fcntl(ifd, F_SETFL, fcntl(ifd, F_GETFL) | O_NONBLOCK);
        TEST("inotify honours O_NONBLOCK set by fcntl");
        EXPECT_ERRNO(read(ifd, ibuf, sizeof(ibuf)), EAGAIN,
                     "read did not EAGAIN");
        close(ifd);
    }

    int ifd_nb = inotify_init1(IN_NONBLOCK);
    if (ifd_nb >= 0) {
        char ibuf[512];
        TEST("inotify honours IN_NONBLOCK from creation");
        EXPECT_ERRNO(read(ifd_nb, ibuf, sizeof(ibuf)), EAGAIN,
                     "read did not EAGAIN");
        close(ifd_nb);
    }
}

static void test_o_direct(void)
{
    /* O_DIRECT is settable on a pipe (that is packet mode) and refused on a
     * socket, where Linux has no FMODE_CAN_ODIRECT to offer. Both spellings
     * measured against qemu-aarch64; recording O_DIRECT for a socket would
     * report a mode the guest cannot have.
     */
    int odp[2];
    if (pipe(odp) == 0) {
        TEST("a pipe accepts O_DIRECT");
        fcntl(odp[1], F_SETFL, fcntl(odp[1], F_GETFL) | O_DIRECT);
        EXPECT_TRUE(fcntl(odp[1], F_GETFL) & O_DIRECT, "bit did not stick");
        close(odp[0]);
        close(odp[1]);
    }
    int odsock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (odsock >= 0) {
        TEST("a socket refuses O_DIRECT");
        EXPECT_ERRNO(fcntl(odsock, F_SETFL, fcntl(odsock, F_GETFL) | O_DIRECT),
                     EINVAL, "F_SETFL did not report EINVAL");
        TEST("and does not report it afterwards");
        EXPECT_EQ(fcntl(odsock, F_GETFL) & O_DIRECT, 0, "bit leaked in");
        close(odsock);
    }
}

static void test_noatime_and_dir_flags(const char *noatime_file)
{
    /* O_NOATIME is settable, and macOS has no equivalent, so the shadow owns
     * it: F_SETFL has to write it there or F_GETFL keeps answering with what
     * open() recorded. Checked in both directions, since a shadow that is only
     * ever set looks correct until something clears it.
     */
    int nafd = open(noatime_file, O_RDWR | O_CREAT, 0600);
    if (nafd >= 0) {
        TEST("O_NOATIME is not reported before it is set");
        EXPECT_EQ(fcntl(nafd, F_GETFL) & O_NOATIME, 0, "reported unset flag");

        fcntl(nafd, F_SETFL, fcntl(nafd, F_GETFL) | O_NOATIME);
        TEST("F_SETFL records O_NOATIME");
        EXPECT_TRUE(fcntl(nafd, F_GETFL) & O_NOATIME, "bit did not stick");

        fcntl(nafd, F_SETFL, fcntl(nafd, F_GETFL) & ~O_NOATIME);
        TEST("F_SETFL clears O_NOATIME");
        EXPECT_EQ(fcntl(nafd, F_GETFL) & O_NOATIME, 0, "bit did not clear");
        close(nafd);
        unlink(noatime_file);
    }

    /* O_PATH and O_DIRECTORY have no macOS equivalent and are carried in the
     * shadow; both must survive F_GETFL.
     */
    int dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (dirfd >= 0) {
        TEST("O_DIRECTORY survives F_GETFL");
        EXPECT_TRUE(fcntl(dirfd, F_GETFL) & O_DIRECTORY, "bit lost");
        close(dirfd);
    }

    int pathfd = open("/tmp", O_PATH);
    if (pathfd >= 0) {
        TEST("O_PATH survives F_GETFL");
        EXPECT_TRUE(fcntl(pathfd, F_GETFL) & O_PATH, "bit lost");
        close(pathfd);
    }
}

static void test_o_async(void)
{
    /* O_ASYNC sticks only where the object supports it. Linux does not carry
     * FASYNC in SETFL_MASK: setfl() lands the bit by calling
     * file_operations->fasync, so an object whose fops lack one keeps O_ASYNC
     * clear however often the guest sets it. The expectations here were
     * measured under qemu-aarch64, and this table is why they cannot drift:
     * elfuse used to answer 1 for all eleven.
     */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    struct {
        const char *name;
        int fd, want;
    } fasync[] = {
        {"timerfd drops O_ASYNC", timerfd_create(CLOCK_MONOTONIC, 0), 0},
        {"eventfd drops O_ASYNC", eventfd(0, 0), 0},
        {"signalfd drops O_ASYNC", signalfd(-1, &mask, 0), 0},
        {"epoll drops O_ASYNC", epoll_create1(0), 0},
        {"pidfd drops O_ASYNC", (int) syscall(434, getpid(), 0), 0},
        {"inotify keeps O_ASYNC", inotify_init(), 1},
        {"netlink keeps O_ASYNC", socket(AF_NETLINK, SOCK_RAW, 0), 1},
        {"socket keeps O_ASYNC", socket(AF_UNIX, SOCK_STREAM, 0), 1},
    };
    for (size_t i = 0; i < sizeof(fasync) / sizeof(fasync[0]); i++) {
        if (fasync[i].fd < 0)
            continue;
        TEST(fasync[i].name);
        fcntl(fasync[i].fd, F_SETFL, fcntl(fasync[i].fd, F_GETFL) | O_ASYNC);
        int got = (fcntl(fasync[i].fd, F_GETFL) & O_ASYNC) ? 1 : 0;
        EXPECT_EQ(got, fasync[i].want, "O_ASYNC does not match Linux");
        close(fasync[i].fd);
    }

    /* Character devices are the case a type test cannot answer: elfuse types
     * them all FD_REGULAR, and Linux lets the flag stick on /dev/urandom
     * (random_fasync) but not on /dev/null or /dev/zero. Deciding from "can
     * this block" got all three wrong.
     */
    struct {
        const char *name, *path;
        int want;
    } chardev[] = {
        {"/dev/null drops O_ASYNC", "/dev/null", 0},
        {"/dev/zero drops O_ASYNC", "/dev/zero", 0},
        {"/dev/urandom keeps O_ASYNC", "/dev/urandom", 1},
        {"/dev/random keeps O_ASYNC", "/dev/random", 1},
    };
    for (size_t i = 0; i < sizeof(chardev) / sizeof(chardev[0]); i++) {
        int cfd = open(chardev[i].path, O_RDONLY);
        if (cfd < 0)
            continue;
        TEST(chardev[i].name);
        fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) | O_ASYNC);
        int got = (fcntl(cfd, F_GETFL) & O_ASYNC) ? 1 : 0;
        EXPECT_EQ(got, chardev[i].want, "O_ASYNC does not match Linux");
        close(cfd);
    }

    /* A pipe keeps it too, and both ends of one are worth checking: the write
     * end is the alias path that lost flags before.
     */
    int afds[2];
    if (pipe(afds) == 0) {
        for (int i = 0; i < 2; i++) {
            TEST(i == 0 ? "pipe read end keeps O_ASYNC"
                        : "pipe write end keeps O_ASYNC");
            fcntl(afds[i], F_SETFL, fcntl(afds[i], F_GETFL) | O_ASYNC);
            EXPECT_TRUE(fcntl(afds[i], F_GETFL) & O_ASYNC, "bit did not stick");
            close(afds[i]);
        }
    }
}

static void test_synthetic_access_modes(void)
{
    /* Every synthetic fd answers its access mode from elfuse's shadow, because
     * the host fd behind it is a pipe or a kqueue elfuse opened for its own
     * purposes. Each one has to carry the mode Linux gives its anon inode.
     */
    struct {
        const char *name;
        int fd, want;
    } synth[] = {
        {"epoll is O_RDWR", epoll_create1(0), O_RDWR},
        {"netlink is O_RDWR", socket(AF_NETLINK, SOCK_RAW, 0), O_RDWR},
        {"pidfd is O_RDWR", (int) syscall(434, getpid(), 0), O_RDWR},
    };
    for (size_t i = 0; i < sizeof(synth) / sizeof(synth[0]); i++) {
        if (synth[i].fd < 0)
            continue;
        check_accmode(synth[i].name, synth[i].fd, synth[i].want);
        close(synth[i].fd);
    }

    int urand = open("/dev/urandom", O_RDONLY);
    if (urand >= 0) {
        check_accmode("urandom is O_RDONLY", urand, O_RDONLY);
        close(urand);
    }
}

static void test_sync_flags(const char *sync_file)
{
    /* A raw openat may carry __O_SYNC without O_DSYNC. Linux normalizes it to
     * O_SYNC, while an O_DSYNC-only open remains weaker. Every F_GETFL result
     * is stored before it is masked. A failed call returns -1, whose bits
     * satisfy every mask below, so testing the call inline would turn a failure
     * into a row of green checks. check_accmode above guards the same way.
     */
    int sfd_sync = open(sync_file, O_RDWR | O_CREAT | O_SYNC, 0600);
    if (sfd_sync >= 0) {
        int fl = fcntl(sfd_sync, F_GETFL);
        TEST("O_SYNC round trips through F_GETFL");
        if (fl < 0)
            FAIL("F_GETFL failed");
        else
            EXPECT_EQ(fl & O_SYNC, O_SYNC, "flag was lost");
        close(sfd_sync);
    }
    int sfd_raw_sync = syscall(SYS_openat, AT_FDCWD, sync_file,
                               O_RDWR | O_CREAT | (O_SYNC & ~O_DSYNC), 0600);
    if (sfd_raw_sync >= 0) {
        int fl = fcntl(sfd_raw_sync, F_GETFL);
        TEST("standalone __O_SYNC normalizes through F_GETFL");
        if (fl < 0)
            FAIL("F_GETFL failed");
        else
            EXPECT_EQ(fl & O_SYNC, O_SYNC, "flag was lost");
        close(sfd_raw_sync);
    }
    int sfd_dsync = open(sync_file, O_RDWR | O_CREAT | O_DSYNC, 0600);
    if (sfd_dsync >= 0) {
        int fl = fcntl(sfd_dsync, F_GETFL);
        TEST("O_DSYNC round trips through F_GETFL");
        if (fl < 0) {
            FAIL("F_GETFL failed");
        } else {
            EXPECT_TRUE(fl & O_DSYNC, "flag was lost");
            TEST("and an O_DSYNC open is not reported as O_SYNC");
            EXPECT_EQ(fl & O_SYNC, O_DSYNC & O_SYNC,
                      "the weaker flag was widened");
        }
        close(sfd_dsync);
    }
    unlink(sync_file);
}

int main(void)
{
    printf("test-fcntl-flags: status flags across fd types\n");

    /* A directory private to this run, under /tmp so the guest can create it
     * under either sysroot. The fixed names it replaces were unlinked mid-test
     * by concurrent runs.
     */
    char tmpdir[] = "/tmp/elfuse-fcntl-flags-XXXXXX";
    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return 1;
    }
    char noatime_file[128], sync_file[128], regular_file[128];
    snprintf(noatime_file, sizeof(noatime_file), "%s/noatime.tmp", tmpdir);
    snprintf(sync_file, sizeof(sync_file), "%s/sync.tmp", tmpdir);
    snprintf(regular_file, sizeof(regular_file), "%s/regular", tmpdir);

    test_regular_access(regular_file);
    test_pipe_nonblock();
    test_socket_timerfd_eventfd();
    test_signalfd_nonblock();
    test_dup_synthetic();
    test_inotify_nonblock();
    test_o_direct();
    test_noatime_and_dir_flags(noatime_file);
    test_o_async();
    test_synthetic_access_modes();
    test_sync_flags(sync_file);
    rmdir(tmpdir);

    SUMMARY("test-fcntl-flags");
    return fails > 0 ? 1 : 0;
}
