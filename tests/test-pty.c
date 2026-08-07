/*
 * PTY ioctl regression test
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Foot, sshd, tmux, and any libvte-derived terminal need the multiplexer
 * primitives glibc's posix_openpt(3) / ptsname(3) / openpty(3) stack rests on.
 * Exercise the pieces glibc and posix-compliant pty children depend on:
 *
 *   1. TIOCSWINSZ on the /dev/ptmx master fd (the direct failure foot saw)
 *   2. TIOCGPTN -> /dev/pts/N path round trip
 *   3. TIOCSPTLCK(0) for unlockpt(), plus non-zero lock request fd typing
 *   4. /dev/pts/N open + stat intercept and the slave fd's window size
 *   5. /dev/pts/N open in a forked child after the child has already closed
 *      its master (foot/sshd/openssh sftp-server pattern)
 *   6. TIOCPKT packet mode on the master, which libvte turns on right after
 *      posix_openpt and treats as fatal on failure
 *
 * The test stays self-contained on the syscall surface (no libutil/openpty), so
 * it runs the same way under elfuse-aarch64, qemu-aarch64, and any future
 * elfuse-x86_64 reuse.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

/* Linux spells the ordinary-data packet type this way; the
 * value is 0 and matches macOS.
 */
#ifndef TIOCPKT_DATA
#define TIOCPKT_DATA 0
#endif

#ifndef TIOCSWINSZ
#define TIOCSWINSZ 0x5414
#endif
#ifndef TIOCGPTN
#define TIOCGPTN 0x80045430
#endif
#ifndef TIOCSPTLCK
#define TIOCSPTLCK 0x40045431
#endif
#ifndef TIOCGPTPEER
#define TIOCGPTPEER 0x5441
#endif
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef SYS_statx
#define SYS_statx 291
#endif

int passes = 0, fails = 0;

/* A master with no hangup support blocks these reads forever; the alarm turns
 * that into a visible failure instead of a wedged run.
 */
static void hup_on_alarm(int sig)
{
    (void) sig;
    _exit(2);
}

static int count_pts_entries(void)
{
    DIR *dir = opendir("/dev/pts");
    if (!dir)
        return -1;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
            continue;
        int numeric = 1;
        for (const char *p = ent->d_name; *p; p++) {
            if (!isdigit((unsigned char) *p)) {
                numeric = 0;
                break;
            }
        }
        if (numeric)
            count++;
    }
    closedir(dir);
    return count;
}

int main(void)
{
    printf("test-pty: PTY ioctl + /dev/pts/N path support\n");

    /* Regression guard for the pty_keepalive_table BSS-zero collision: any
     * close that runs before the very first /dev/ptmx open would walk the
     * still-zero-initialized table and match a master_host_fd of zero, silently
     * closing the wrong slave_host_fd (also zero). Closing stdin here forces
     * fd_cleanup_entry to invoke proc_pty_close_keepalive in that vulnerable
     * window. If the fix regresses, every subsequent test still passes locally
     * but a future stdio fd in another vCPU may go missing. The cheap sentinel
     * makes sure stdin's close itself does not corrupt elfuse's own file table.
     */
    close(STDIN_FILENO);

    TEST("open(/dev/ptmx, O_PATH) does not allocate a pty");
    int before_path_pts = count_pts_entries();
    int path_fd = open("/dev/ptmx", O_PATH | O_CLOEXEC);
    int after_path_pts = count_pts_entries();
    if (path_fd >= 0) {
        struct stat ptmx_path_st;
        int fstat_rc = fstat(path_fd, &ptmx_path_st);
        struct stat ptmx_at_st;
        int fstatat_rc = fstatat(path_fd, "", &ptmx_at_st, AT_EMPTY_PATH);
        struct statx ptmx_sx;
        memset(&ptmx_sx, 0, sizeof(ptmx_sx));
        long statx_rc =
            syscall(SYS_statx, path_fd, "", AT_EMPTY_PATH, 0x7ff, &ptmx_sx);
        errno = 0;
        int fchdir_rc = fchdir(path_fd);
        int fchdir_errno = errno;
        int ok = before_path_pts >= 0 && after_path_pts == before_path_pts &&
                 fstat_rc == 0 && S_ISCHR(ptmx_path_st.st_mode) &&
                 major(ptmx_path_st.st_rdev) == 5 &&
                 minor(ptmx_path_st.st_rdev) == 2 && fstatat_rc == 0 &&
                 S_ISCHR(ptmx_at_st.st_mode) &&
                 major(ptmx_at_st.st_rdev) == 5 &&
                 minor(ptmx_at_st.st_rdev) == 2 && statx_rc == 0 &&
                 S_ISCHR(ptmx_sx.stx_mode) && ptmx_sx.stx_rdev_major == 5 &&
                 ptmx_sx.stx_rdev_minor == 2 && fchdir_rc < 0 &&
                 fchdir_errno == ENOTDIR;
        close(path_fd);
        EXPECT_TRUE(ok,
                    "O_PATH open allocated a pty or exposed wrong path fd "
                    "semantics");
    } else {
        FAIL("O_PATH /dev/ptmx open failed");
    }

    int ptmx = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    TEST("open(/dev/ptmx, O_RDWR | O_NOCTTY)");
    EXPECT_TRUE(ptmx >= 0, "open /dev/ptmx failed");
    if (ptmx < 0) {
        SUMMARY("test-pty");
        return 1;
    }

    /* TIOCSWINSZ on the master was the direct regression that broke foot's
     * terminal startup: sys_ioctl had no case for it and fell through to the
     * default -ENOTTY arm.
     */
    TEST("TIOCSWINSZ on /dev/ptmx master");
    struct winsize ws_set = {
        .ws_row = 40,
        .ws_col = 132,
        .ws_xpixel = 1056,
        .ws_ypixel = 640,
    };
    EXPECT_TRUE(ioctl(ptmx, TIOCSWINSZ, &ws_set) == 0, "TIOCSWINSZ failed");

    TEST("TIOCGWINSZ round-trips the values set above");
    struct winsize ws_get = {0};
    int ok = ioctl(ptmx, TIOCGWINSZ, &ws_get) == 0 && ws_get.ws_row == 40 &&
             ws_get.ws_col == 132 && ws_get.ws_xpixel == 1056 &&
             ws_get.ws_ypixel == 640;
    EXPECT_TRUE(ok, "TIOCGWINSZ round trip mismatch");

    TEST("TIOCSPTLCK(0) unlocks the slave");
    int unlock = 0;
    EXPECT_TRUE(ioctl(ptmx, TIOCSPTLCK, &unlock) == 0, "TIOCSPTLCK(0) failed");

    /* Linux TIOCSPTLCK(non-zero) locks the slave and returns success. elfuse
     * cannot actually enforce the lock on macOS (no re-lock primitive) but must
     * still report success so callers do not misread the result as "this kernel
     * has no devpts".
     */
    TEST("TIOCSPTLCK(1) accepted as best-effort no-op");
    int lock = 1;
    EXPECT_TRUE(ioctl(ptmx, TIOCSPTLCK, &lock) == 0, "TIOCSPTLCK(1)");

    TEST("TIOCSPTLCK(1) rejects a regular file");
    char lock_template[] = "/tmp/elfuse-pty-lock-XXXXXX";
    int regular = mkstemp(lock_template);
    if (regular < 0) {
        FAIL("mkstemp failed");
    } else {
        EXPECT_ERRNO(ioctl(regular, TIOCSPTLCK, &lock), ENOTTY,
                     "regular fd accepted TIOCSPTLCK(1)");
        close(regular);
        unlink(lock_template);
    }

    TEST("TIOCSPTLCK(1) rejects a pipe");
    int lock_pipe[2];
    if (pipe(lock_pipe) != 0) {
        FAIL("pipe(lock_pipe) failed");
    } else {
        EXPECT_ERRNO(ioctl(lock_pipe[0], TIOCSPTLCK, &lock), ENOTTY,
                     "pipe fd accepted TIOCSPTLCK(1)");
        close(lock_pipe[0]);
        close(lock_pipe[1]);
    }

    TEST("TIOCGPTN returns a numeric slave id");
    unsigned int ptyno = (unsigned int) -1;
    EXPECT_TRUE(ioctl(ptmx, TIOCGPTN, &ptyno) == 0 && ptyno < 100000u,
                "TIOCGPTN failed");

    TEST("stat(/dev/pts) succeeds and reports a directory");
    struct stat pts_dir_st;
    int pts_dir_statrc = stat("/dev/pts", &pts_dir_st);
    EXPECT_TRUE(pts_dir_statrc == 0 && S_ISDIR(pts_dir_st.st_mode),
                "stat /dev/pts failed");

    TEST("open(/dev/pts, O_DIRECTORY) succeeds");
    int pts_dir_fd = open("/dev/pts", O_RDONLY | O_DIRECTORY);
    EXPECT_TRUE(pts_dir_fd >= 0, "open /dev/pts directory failed");
    if (pts_dir_fd >= 0)
        close(pts_dir_fd);

    TEST("readdir(/dev/pts) lists the active slave id");
    DIR *pts_dir = opendir("/dev/pts");
    if (!pts_dir) {
        FAIL("opendir /dev/pts failed");
    } else {
        char want[32];
        snprintf(want, sizeof(want), "%u", ptyno);
        int saw_ptyno = 0;
        struct dirent *ent;
        while ((ent = readdir(pts_dir))) {
            if (!strcmp(ent->d_name, want)) {
                saw_ptyno = 1;
                break;
            }
        }
        closedir(pts_dir);
        EXPECT_TRUE(saw_ptyno, "active pts id missing from /dev/pts");
    }

    char pts_path[32];
    snprintf(pts_path, sizeof(pts_path), "/dev/pts/%u", ptyno);

    /* glibc ptsname(3) stats the formatted path before returning it. Until the
     * path.c stat allowlist included /dev/pts/N, the stat went to the host
     * (which has no /dev/pts at all) and ptsname returned ENOENT, leaving every
     * caller without a usable slave path.
     */
    TEST("stat(/dev/pts/N) succeeds and reports a char device");
    struct stat st;
    int statrc = stat(pts_path, &st);
    EXPECT_TRUE(statrc == 0 && S_ISCHR(st.st_mode), "stat /dev/pts/N failed");

    TEST("stat(/dev/pts/N) major is Linux pts (136)");
    EXPECT_EQ(major(st.st_rdev), 136, "wrong pts major");

    TEST("open(/dev/pts/N) returns a usable slave fd");
    int slave = open(pts_path, O_RDWR | O_NOCTTY);
    EXPECT_TRUE(slave >= 0, "open /dev/pts/N failed");

    if (slave >= 0) {
        TEST("TIOCGWINSZ on the slave reflects the master-side update");
        struct winsize ws_slave = {0};
        int slave_ok = ioctl(slave, TIOCGWINSZ, &ws_slave) == 0 &&
                       ws_slave.ws_row == 40 && ws_slave.ws_col == 132;
        EXPECT_TRUE(slave_ok, "slave winsize mismatch");

        TEST("TIOCSPTLCK(1) rejects the pty slave");
        EXPECT_ERRNO(ioctl(slave, TIOCSPTLCK, &lock), ENOTTY,
                     "slave fd accepted TIOCSPTLCK(1)");

        TEST("TIOCSWINSZ on the slave propagates back to the master");
        struct winsize ws_resize = {
            .ws_row = 24,
            .ws_col = 80,
            .ws_xpixel = 0,
            .ws_ypixel = 0,
        };
        if (ioctl(slave, TIOCSWINSZ, &ws_resize) != 0) {
            FAIL("slave TIOCSWINSZ failed");
        } else {
            struct winsize ws_after = {0};
            int after_ok = ioctl(ptmx, TIOCGWINSZ, &ws_after) == 0 &&
                           ws_after.ws_row == 24 && ws_after.ws_col == 80;
            EXPECT_TRUE(after_ok, "master did not see slave resize");
        }

        close(slave);
    }

    /* TIOCGPTPEER short-circuits the ptsname/stat/open dance. Recent foot and
     * util-linux prefer it; older kernels return ENOTTY and the caller falls
     * back to /dev/pts. Accept either an fd or ENOTTY (some hosts legitimately
     * do not implement it), but never silent corruption.
     */
    TEST("TIOCGPTPEER returns a slave fd or ENOTTY");
    int peer = ioctl(ptmx, TIOCGPTPEER, O_RDWR | O_NOCTTY);
    int peer_ok = peer >= 0 || (peer == -1 && errno == ENOTTY);
    EXPECT_TRUE(peer_ok, "TIOCGPTPEER returned unexpected status");
    if (peer >= 0)
        close(peer);

    /* dup of the master must keep both aliases functional even after the
     * original is closed. The keepalive slave needs to be mirrored across the
     * dup so the surviving alias still observes master-side tty ioctls.
     */
    TEST("dup(ptmx) followed by close(orig) leaves alias usable");
    int alias = dup(ptmx);
    if (alias < 0) {
        FAIL("dup(ptmx) failed");
    } else {
        close(ptmx);
        struct winsize ws_alias = {.ws_row = 50, .ws_col = 100};
        if (ioctl(alias, TIOCSWINSZ, &ws_alias) != 0) {
            FAIL("TIOCSWINSZ on alias after closing original");
        } else {
            struct winsize ws_check = {0};
            int alias_ok = ioctl(alias, TIOCGWINSZ, &ws_check) == 0 &&
                           ws_check.ws_row == 50 && ws_check.ws_col == 100;
            EXPECT_TRUE(alias_ok, "alias winsize did not stick");
        }
        ptmx = alias; /* the alias is the live master from here on */
    }

    /* Fork must propagate the master's keepalive across the IPC handoff so the
     * child can do master-side tty ioctls without the macOS ENOTTY fallback.
     * The parent's keepalive slave fd is independent (each side holds its own
     * slot) so closing one side does not affect the other.
     */
    TEST("child fork inherits master keepalive (TIOCSWINSZ works)");
    int sync_pipe[2];
    if (pipe(sync_pipe) != 0) {
        FAIL("pipe(sync_pipe) failed");
    } else {
        pid_t pid = fork();
        if (pid < 0) {
            FAIL("fork failed");
            close(sync_pipe[0]);
            close(sync_pipe[1]);
        } else if (pid == 0) {
            /* Child: do master-side TIOCSWINSZ and report rc via pipe. */
            close(sync_pipe[0]);
            struct winsize ws_child = {
                .ws_row = 30,
                .ws_col = 90,
            };
            int rc = ioctl(ptmx, TIOCSWINSZ, &ws_child);
            char status = (rc == 0) ? 'Y' : 'N';
            (void) !write(sync_pipe[1], &status, 1);
            close(sync_pipe[1]);
            _exit(rc == 0 ? 0 : 1);
        } else {
            close(sync_pipe[1]);
            char status = '?';
            ssize_t n = read(sync_pipe[0], &status, 1);
            close(sync_pipe[0]);
            int wstatus = 0;
            waitpid(pid, &wstatus, 0);
            int child_ok = (n == 1) && (status == 'Y') && WIFEXITED(wstatus) &&
                           WEXITSTATUS(wstatus) == 0;
            EXPECT_TRUE(child_ok, "child TIOCSWINSZ on master failed");
            /* Parent should still see the child's update because the slave
             * keepalive in the parent is still alive.
             */
            struct winsize ws_parent = {0};
            int parent_ok = ioctl(ptmx, TIOCGWINSZ, &ws_parent) == 0 &&
                            ws_parent.ws_row == 30 && ws_parent.ws_col == 90;
            TEST("parent observes the child's master-side resize");
            EXPECT_TRUE(parent_ok, "parent winsize mismatch after child");
        }
    }

    close(ptmx);

    /* Re-open and immediately close should not leak the keepalive slave.
     * Without the proc_pty_close_keepalive call in sys_close's fast path,
     * single-thread close goes through fd_close_regular_relaxed and bypasses
     * fd_cleanup_entry, leaving the hidden slave fd open until elfuse exits.
     * Loop enough times to expose any per-close leak.
     */
    TEST("repeated open/close does not exhaust the keepalive table");
    int leak_loop_ok = 1;
    for (int i = 0; i < 300; i++) {
        int f = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (f < 0) {
            leak_loop_ok = 0;
            break;
        }
        close(f);
    }
    EXPECT_TRUE(leak_loop_ok,
                "repeated /dev/ptmx open/close exhausted the keepalive table");

    /* foot/sshd/openssh sftp-server pattern: the child closes its inherited
     * master fd before opening the slave (the child has no use for the master).
     * Earlier, this dropped the keepalive table entry that held the macOS
     * slave_path mapping, and the subsequent open("/dev/pts/N") in the child
     * failed with ENOENT even though the parent still held the master and the
     * macOS slave node was openable. The retained-path semantics in
     * proc_pty_close_keepalive must let the child still translate the path.
     */
    TEST("child can open /dev/pts/N after closing its master");
    int spawn_master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (spawn_master < 0) {
        FAIL("open(/dev/ptmx) for spawn scenario");
    } else {
        unsigned int spawn_ptyno = (unsigned int) -1;
        int unlock_zero = 0;
        if (ioctl(spawn_master, TIOCGPTN, &spawn_ptyno) != 0 ||
            ioctl(spawn_master, TIOCSPTLCK, &unlock_zero) != 0) {
            FAIL("TIOCGPTN/TIOCSPTLCK on spawn master");
            close(spawn_master);
        } else {
            char spawn_pts[32];
            snprintf(spawn_pts, sizeof(spawn_pts), "/dev/pts/%u", spawn_ptyno);
            int spawn_pipe[2];
            if (pipe(spawn_pipe) != 0) {
                FAIL("pipe for spawn scenario");
                close(spawn_master);
            } else {
                pid_t spawn_pid = fork();
                if (spawn_pid < 0) {
                    FAIL("fork for spawn scenario");
                    close(spawn_pipe[0]);
                    close(spawn_pipe[1]);
                    close(spawn_master);
                } else if (spawn_pid == 0) {
                    /* Child: foot's slave_exec sequence -- close the master,
                     * then open(pts_name) for the controlling terminal.
                     */
                    close(spawn_pipe[0]);
                    if (setsid() < 0)
                        _exit(11);
                    close(spawn_master);
                    int slave_fd = open(spawn_pts, O_RDWR);
                    char status = (slave_fd >= 0) ? 'Y' : 'N';
                    (void) !write(spawn_pipe[1], &status, 1);
                    if (slave_fd >= 0) {
                        (void) !write(slave_fd, "ok\n", 3);
                        close(slave_fd);
                    }
                    close(spawn_pipe[1]);
                    _exit(slave_fd >= 0 ? 0 : 12);
                } else {
                    close(spawn_pipe[1]);
                    char status = '?';
                    ssize_t n = read(spawn_pipe[0], &status, 1);
                    close(spawn_pipe[0]);
                    int wstatus = 0;
                    waitpid(spawn_pid, &wstatus, 0);
                    int spawn_ok = (n == 1) && (status == 'Y') &&
                                   WIFEXITED(wstatus) &&
                                   WEXITSTATUS(wstatus) == 0;
                    EXPECT_TRUE(spawn_ok,
                                "child open(/dev/pts/N) after close(master)");
                    if (spawn_ok) {
                        char drain[16] = {0};
                        int flags = fcntl(spawn_master, F_GETFL);
                        if (flags >= 0 && fcntl(spawn_master, F_SETFL,
                                                flags | O_NONBLOCK) == 0) {
                            (void) !read(spawn_master, drain,
                                         sizeof(drain) - 1);
                            (void) fcntl(spawn_master, F_SETFL, flags);
                        }
                    }
                    close(spawn_master);

                    TEST("stale /dev/pts/N expires after master teardown");
                    int stale_fd = open(spawn_pts, O_RDWR);
                    /* Both ENOENT (devfs node gone) and ENXIO (devfs node
                     * lingers but the pty pair has been torn down) are valid
                     * macOS responses depending on kernel version. The
                     * invariant the test guards is "the stale cached path does
                     * not silently hand back an unrelated tty"; any open
                     * failure satisfies that.
                     */
                    int stale_ok =
                        stale_fd < 0 && (errno == ENOENT || errno == ENXIO);
                    if (stale_fd >= 0)
                        close(stale_fd);
                    EXPECT_TRUE(stale_ok, "stale /dev/pts/N stayed openable");
                }
            }
        }
    }

    /* /dev/pts/N for a never-allocated minor must surface ENOENT (the cached
     * paths in the keepalive table cannot satisfy an arbitrary number).
     */
    TEST("/dev/pts/<unknown> returns ENOENT");
    int unknown = open("/dev/pts/999999", O_RDWR);
    int unknown_ok = unknown < 0 && errno == ENOENT;
    if (unknown >= 0)
        close(unknown);
    EXPECT_TRUE(unknown_ok, "open(/dev/pts/999999) did not return ENOENT");

    /* A pty master received via SCM_RIGHTS bypasses the /dev/ptmx open
     * intercept, so the receiver process has no keepalive entry for it.
     * proc_pty_master_adopt must lazily register one before master-side tty
     * ioctls, even when TIOCSWINSZ runs before the first TIOCGPTN. Two checks
     * live inside this block: TIOCSWINSZ-first and the post-adopt
     * stat(/dev/pts/N). Each has its own TEST() label below.
     */
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
        TEST("socketpair for SCM_RIGHTS adoption setup");
        FAIL("socketpair failed");
    } else {
        int donor = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (donor < 0) {
            FAIL("donor open(/dev/ptmx) failed");
            close(sp[0]);
            close(sp[1]);
        } else {
            char iobuf = 'x';
            struct iovec iov = {.iov_base = &iobuf, .iov_len = 1};
            char ctrl[CMSG_SPACE(sizeof(int))] = {0};
            struct msghdr msg = {.msg_iov = &iov,
                                 .msg_iovlen = 1,
                                 .msg_control = ctrl,
                                 .msg_controllen = sizeof(ctrl)};
            struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
            cm->cmsg_level = SOL_SOCKET;
            cm->cmsg_type = SCM_RIGHTS;
            cm->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(cm), &donor, sizeof(int));
            ssize_t sent = sendmsg(sp[0], &msg, 0);
            close(donor);
            if (sent < 0) {
                FAIL("sendmsg(SCM_RIGHTS) failed");
            } else {
                char rbuf;
                struct iovec riov = {.iov_base = &rbuf, .iov_len = 1};
                char rctrl[CMSG_SPACE(sizeof(int))] = {0};
                struct msghdr rmsg = {.msg_iov = &riov,
                                      .msg_iovlen = 1,
                                      .msg_control = rctrl,
                                      .msg_controllen = sizeof(rctrl)};
                ssize_t got = recvmsg(sp[1], &rmsg, 0);
                if (got < 0) {
                    FAIL("recvmsg(SCM_RIGHTS) failed");
                } else {
                    struct cmsghdr *rcm = CMSG_FIRSTHDR(&rmsg);
                    int recv_master = -1;
                    if (rcm && rcm->cmsg_level == SOL_SOCKET &&
                        rcm->cmsg_type == SCM_RIGHTS)
                        memcpy(&recv_master, CMSG_DATA(rcm), sizeof(int));
                    if (recv_master < 0) {
                        TEST("SCM_RIGHTS recv yields a master fd");
                        FAIL("recv_master fd not received");
                    } else {
                        TEST("TIOCSWINSZ first on SCM_RIGHTS-received master");
                        struct winsize ws_recv = {
                            .ws_row = 33,
                            .ws_col = 101,
                            .ws_xpixel = 808,
                            .ws_ypixel = 528,
                        };
                        EXPECT_TRUE(
                            ioctl(recv_master, TIOCSWINSZ, &ws_recv) == 0,
                            "TIOCSWINSZ before TIOCGPTN on "
                            "SCM_RIGHTS-received master");
                        TEST("TIOCGPTN on SCM_RIGHTS-received master");
                        unsigned int recv_ptyno = (unsigned int) -1;
                        int gpn_rc = ioctl(recv_master, TIOCGPTN, &recv_ptyno);
                        EXPECT_TRUE(gpn_rc == 0 && recv_ptyno < 100000u,
                                    "TIOCGPTN on SCM_RIGHTS-received master");
                        char recv_pts_path[32];
                        snprintf(recv_pts_path, sizeof(recv_pts_path),
                                 "/dev/pts/%u", recv_ptyno);
                        /* TIOCPKT has to work on a master the receiver never
                         * opened itself, the shape libvte sees when a terminal
                         * is handed a pty from elsewhere.
                         *
                         * This does not isolate the proc_pty_master_adopt call
                         * in the TIOCPKT path: TIOCSWINSZ above has already
                         * adopted this fd, and every master a guest can obtain
                         * came from the /dev/ptmx intercept, which eagerly
                         * opens the keepalive slave (see the side-table header
                         * in procemu.c). The cold-master ENOTTY that adoption
                         * exists to prevent is therefore not reachable from
                         * inside the guest, so the call stays as the same
                         * defence TIOCSWINSZ carries rather than something a
                         * test here can pin.
                         */
                        TEST("TIOCPKT on SCM_RIGHTS-received master");
                        int recv_pkt = 1;
                        EXPECT_TRUE(ioctl(recv_master, TIOCPKT, &recv_pkt) == 0,
                                    "TIOCPKT rejected on an adopted master");

                        TEST("stat(/dev/pts/N) after SCM_RIGHTS adoption");
                        struct stat recv_st;
                        EXPECT_TRUE(stat(recv_pts_path, &recv_st) == 0 &&
                                        S_ISCHR(recv_st.st_mode),
                                    "stat after SCM_RIGHTS adoption failed");
                        close(recv_master);
                    }
                }
            }
            close(sp[0]);
            close(sp[1]);
        }
    }

    /* 6. Packet mode. libvte enables it on the master immediately after
     * posix_openpt and aborts the whole PTY setup if the ioctl fails, so
     * gnome-terminal and its relatives never start without it. Assert the
     * observable effect rather than just the return code: in packet mode a
     * master read is prefixed with a status byte, and ordinary data carries
     * TIOCPKT_DATA (0).
     */
    {
        int pkt_master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (pkt_master < 0) {
            TEST("TIOCPKT packet mode on master");
            FAIL("open /dev/ptmx");
        } else {
            unsigned int pkt_ptyno = (unsigned int) -1;
            int unlock = 0;
            TEST("TIOCPKT enable on master");
            int one = 1;
            EXPECT_TRUE(ioctl(pkt_master, TIOCPKT, &one) == 0,
                        "TIOCPKT(1) rejected");

            if (ioctl(pkt_master, TIOCGPTN, &pkt_ptyno) == 0 &&
                ioctl(pkt_master, TIOCSPTLCK, &unlock) == 0) {
                char pkt_path[32];
                snprintf(pkt_path, sizeof(pkt_path), "/dev/pts/%u", pkt_ptyno);
                int pkt_slave = open(pkt_path, O_RDWR | O_NOCTTY);
                if (pkt_slave < 0) {
                    TEST("packet-mode read carries a status byte");
                    FAIL("open slave");
                } else {
                    /* Raw mode so the slave does not echo the payload back
                     * at the master and confuse the packet stream. A failure
                     * here is a setup failure rather than a verdict on packet
                     * mode, so it gets its own message below: reporting it as
                     * a bad read would blame the feature under test.
                     */
                    struct termios tio;
                    bool raw_ok = tcgetattr(pkt_slave, &tio) == 0;
                    if (raw_ok) {
                        cfmakeraw(&tio);
                        raw_ok = tcsetattr(pkt_slave, TCSANOW, &tio) == 0;
                    }

                    /* A pty may take a short write, so loop rather than
                     * assuming one call moves the payload.
                     */
                    static const char payload[] = "pkt";
                    const size_t want = sizeof(payload) - 1;
                    size_t sent = 0;
                    while (raw_ok && sent < want) {
                        ssize_t n =
                            write(pkt_slave, payload + sent, want - sent);
                        if (n <= 0)
                            break;
                        sent += (size_t) n;
                    }

                    TEST("packet-mode read carries a status byte");
                    if (!raw_ok) {
                        FAIL("could not put the slave in raw mode");
                    } else if (sent != want) {
                        FAIL("short write to the slave");
                    } else {
                        /* Reassemble instead of expecting one packet to hold
                         * the payload: the stream may split it, and control
                         * packets are interleaved -- the termios change above
                         * emits TIOCPKT_NOSTOP, and TIOCPKT_IOCTL carries a
                         * termios of its own after the status byte. Skip any
                         * packet that is not TIOCPKT_DATA and accumulate the
                         * rest until the payload is whole or the budget runs
                         * out, so a missing packet fails rather than blocks.
                         */
                        char acc[sizeof(payload)];
                        size_t have = 0;
                        bool overflow = false;
                        for (int attempt = 0; have < want && attempt < 8;
                             attempt++) {
                            struct pollfd pfd = {
                                .fd = pkt_master,
                                .events = POLLIN,
                            };
                            if (poll(&pfd, 1, 2000) <= 0)
                                break;
                            char buf[32];
                            ssize_t got = read(pkt_master, buf, sizeof(buf));
                            if (got < 1)
                                break;
                            if (buf[0] != TIOCPKT_DATA)
                                continue; /* control packet */
                            size_t chunk = (size_t) got - 1;
                            if (chunk > sizeof(acc) - have) {
                                overflow = true;
                                break;
                            }
                            memcpy(acc + have, buf + 1, chunk);
                            have += chunk;
                        }
                        EXPECT_TRUE(!overflow && have == want &&
                                        memcmp(acc, payload, want) == 0,
                                    "master reads did not reassemble a "
                                    "TIOCPKT_DATA payload");
                    }
                    close(pkt_slave);
                }
            } else {
                /* Never skip quietly: without the pts number and the unlock
                 * there is no slave to write through, so the packet-read check
                 * cannot run and the file would otherwise report a pass having
                 * asserted only the ioctl return code.
                 */
                TEST("packet-mode read carries a status byte");
                FAIL("TIOCGPTN/TIOCSPTLCK failed, no slave to test with");
            }
            close(pkt_master);
        }
    }

    /* Hangup. macOS only hangs a master up once every slave fd is gone, and
     * elfuse keeps one open for the master's whole life, so the pty layer has
     * to report this itself. A terminal waiting for it to learn its shell
     * exited -- foot polls for exactly this -- otherwise never closes.
     */
    {
        int hup_master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        unsigned int hup_ptyno = (unsigned int) -1;
        int hup_unlock = 0;
        if (hup_master < 0 || ioctl(hup_master, TIOCGPTN, &hup_ptyno) != 0 ||
            ioctl(hup_master, TIOCSPTLCK, &hup_unlock) != 0) {
            TEST("master reports POLLHUP once the slave closes");
            FAIL("could not stage a master");
            if (hup_master >= 0)
                close(hup_master);
        } else {
            char hup_path[32];
            snprintf(hup_path, sizeof(hup_path), "/dev/pts/%u", hup_ptyno);
            int hup_slave = open(hup_path, O_RDWR | O_NOCTTY);
            if (hup_slave < 0) {
                TEST("master reports POLLHUP once the slave closes");
                FAIL("open slave");
            } else {
                /* Queued output must survive: Linux hands over what the slave
                 * wrote before reporting the hangup, so a shell's parting
                 * words are not swallowed.
                 */
                static const char bye[] = "bye";
                ssize_t put = write(hup_slave, bye, sizeof(bye) - 1);
                close(hup_slave);

                struct pollfd hp = {.fd = hup_master, .events = POLLIN};
                int hr = poll(&hp, 1, 2000);
                TEST("master reports POLLHUP once the slave closes");
                EXPECT_TRUE(hr > 0 && (hp.revents & POLLHUP),
                            "no POLLHUP after the last slave closed");

                char hbuf[16];
                ssize_t drained = put == (ssize_t) (sizeof(bye) - 1)
                                      ? read(hup_master, hbuf, sizeof(hbuf))
                                      : -1;
                TEST("queued output survives the hangup");
                EXPECT_TRUE(drained == (ssize_t) (sizeof(bye) - 1) &&
                                memcmp(hbuf, bye, sizeof(bye) - 1) == 0,
                            "pending slave output was lost");

                errno = 0;
                TEST("read reports EIO once drained");
                EXPECT_TRUE(
                    read(hup_master, hbuf, sizeof(hbuf)) < 0 && errno == EIO,
                    "read did not report the hangup as EIO");
            }
            close(hup_master);
        }
    }

    /* The same hangup through epoll. poll and epoll answer from the same pty
     * bookkeeping, but they are separate readiness paths: epoll_wait needs its
     * own wiring, and a terminal that waits with epoll (foot does) hangs on
     * exit without it.
     */
    {
        int ep_master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        unsigned int ep_ptyno = (unsigned int) -1;
        int ep_unlock = 0;
        if (ep_master < 0 || ioctl(ep_master, TIOCGPTN, &ep_ptyno) != 0 ||
            ioctl(ep_master, TIOCSPTLCK, &ep_unlock) != 0) {
            TEST("epoll reports EPOLLHUP once the slave closes");
            FAIL("could not stage a master");
            if (ep_master >= 0)
                close(ep_master);
        } else {
            char ep_path[32];
            snprintf(ep_path, sizeof(ep_path), "/dev/pts/%u", ep_ptyno);
            int ep_slave = open(ep_path, O_RDWR | O_NOCTTY);
            int ep = epoll_create1(0);
            if (ep_slave < 0 || ep < 0) {
                TEST("epoll reports EPOLLHUP once the slave closes");
                FAIL("could not stage slave/epoll fd");
                if (ep_slave >= 0)
                    close(ep_slave);
            } else {
                close(ep_slave);

                struct epoll_event reg = {.events = EPOLLIN};
                reg.data.u64 = 0x5eed;
                int added = epoll_ctl(ep, EPOLL_CTL_ADD, ep_master, &reg);

                /* A finite timeout: before the fix this returned 0 here and
                 * blocked forever on the -1 an actual terminal passes.
                 */
                struct epoll_event ev;
                memset(&ev, 0, sizeof(ev));
                int er = added == 0 ? epoll_wait(ep, &ev, 1, 2000) : -1;

                TEST("epoll reports EPOLLHUP once the slave closes");
                EXPECT_TRUE(er > 0 && (ev.events & EPOLLHUP),
                            "no EPOLLHUP after the last slave closed");

                TEST("EPOLLHUP carries the registered epoll_data");
                EXPECT_TRUE(er > 0 && ev.data.u64 == 0x5eed,
                            "hangup event lost its user data");

                /* An already-pending hangup must not be held until the
                 * caller's deadline: the host never makes the fd ready, so a
                 * finite wait that only checks after kevent returns would
                 * block for the full timeout before reporting.
                 */
                struct timespec t0, t1;
                clock_gettime(CLOCK_MONOTONIC, &t0);
                memset(&ev, 0, sizeof(ev));
                int er2 = epoll_wait(ep, &ev, 1, 10000);
                clock_gettime(CLOCK_MONOTONIC, &t1);
                long elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000 +
                                  (t1.tv_nsec - t0.tv_nsec) / 1000000;

                TEST("a pending EPOLLHUP does not wait out a finite timeout");
                EXPECT_TRUE(
                    er2 > 0 && (ev.events & EPOLLHUP) && elapsed_ms < 2000,
                    "hangup was delayed until the epoll_wait deadline");
            }
            if (ep >= 0)
                close(ep);
            close(ep_master);
        }
    }

    /* A slave obtained through TIOCGPTPEER has to count toward the same
     * accounting as a /dev/pts/N open. It has been the recommended way to reach
     * the peer since Linux 4.13, and a master whose only slave arrived that way
     * would otherwise never report a hangup at all.
     */
    {
        int gp_master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        int gp_unlock = 0;
        unsigned int gp_ptyno = (unsigned int) -1;
        if (gp_master < 0 || ioctl(gp_master, TIOCGPTN, &gp_ptyno) != 0 ||
            ioctl(gp_master, TIOCSPTLCK, &gp_unlock) != 0) {
            TEST("TIOCGPTPEER slave counts toward the hangup");
            FAIL("could not stage a master");
            if (gp_master >= 0)
                close(gp_master);
        } else {
            int gp_slave = ioctl(gp_master, TIOCGPTPEER, O_RDWR | O_NOCTTY);
            if (gp_slave < 0) {
                /* Matches the existing TIOCGPTPEER case above, which accepts
                 * ENOTTY on hosts without peer support.
                 */
                TEST("TIOCGPTPEER slave counts toward the hangup");
                EXPECT_TRUE(
                    errno == ENOTTY,
                    "TIOCGPTPEER failed for a reason other than ENOTTY");
            } else {
                close(gp_slave);

                struct pollfd gp = {.fd = gp_master, .events = POLLIN};
                int gr = poll(&gp, 1, 2000);
                TEST("TIOCGPTPEER slave counts toward the hangup");
                EXPECT_TRUE(gr > 0 && (gp.revents & POLLHUP),
                            "no POLLHUP after the TIOCGPTPEER slave closed");
            }
            close(gp_master);
        }
    }

    /* The shape a real terminal has: the master stays in this process and the
     * slave lives in a forked child, which is the shell. "exit" in the terminal
     * is that child going away.
     *
     * A guest fork is a posix_spawn of a fresh elfuse process, so the child
     * keeps its own keepalive table and nothing about its slave reaches the
     * parent's accounting by itself. Without the shared per-pty counters this
     * reports no hangup on either readiness path, and foot's window stays open
     * after the shell exits even though the same-process cases above pass.
     */
    {
        int fk_master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        unsigned int fk_ptyno = (unsigned int) -1;
        int fk_unlock = 0;
        if (fk_master < 0 || ioctl(fk_master, TIOCGPTN, &fk_ptyno) != 0 ||
            ioctl(fk_master, TIOCSPTLCK, &fk_unlock) != 0) {
            TEST("master reports POLLHUP when a forked child's slave closes");
            FAIL("could not stage a master");
            if (fk_master >= 0)
                close(fk_master);
        } else {
            char fk_path[32];
            snprintf(fk_path, sizeof(fk_path), "/dev/pts/%u", fk_ptyno);

            pid_t fk_pid = fork();
            if (fk_pid == 0) {
                /* The shell: take the slave, say something, leave. */
                int slave = open(fk_path, O_RDWR | O_NOCTTY);
                if (slave < 0)
                    _exit(3);
                write(slave, "bye", 3);
                close(slave);
                _exit(0);
            }

            int fk_status = 0;
            bool reaped =
                fk_pid > 0 && waitpid(fk_pid, &fk_status, 0) == fk_pid;
            bool child_ok =
                reaped && WIFEXITED(fk_status) && WEXITSTATUS(fk_status) == 0;

            if (!child_ok) {
                TEST(
                    "master reports POLLHUP when a forked child's slave "
                    "closes");
                FAIL("child could not open the slave");
            } else {
                /* Queued output still comes first, exactly as in the
                 * same-process case: drain before judging the hangup.
                 */
                char fk_buf[32];
                struct pollfd fk_drain = {.fd = fk_master, .events = POLLIN};
                if (poll(&fk_drain, 1, 1000) > 0 && (fk_drain.revents & POLLIN))
                    read(fk_master, fk_buf, sizeof(fk_buf));

                struct pollfd fp = {.fd = fk_master, .events = POLLIN};
                int fr = poll(&fp, 1, 2000);
                TEST(
                    "master reports POLLHUP when a forked child's slave "
                    "closes");
                EXPECT_TRUE(fr > 0 && (fp.revents & POLLHUP),
                            "no POLLHUP after the forked child's slave closed");

                int fep = epoll_create1(0);
                struct epoll_event freg = {.events = EPOLLIN};
                freg.data.u64 = 0xf00d;
                struct epoll_event fev;
                memset(&fev, 0, sizeof(fev));
                int fer = -1;
                if (fep >= 0 &&
                    epoll_ctl(fep, EPOLL_CTL_ADD, fk_master, &freg) == 0)
                    fer = epoll_wait(fep, &fev, 1, 2000);
                TEST(
                    "epoll reports EPOLLHUP when a forked child's slave "
                    "closes");
                EXPECT_TRUE(fer > 0 && (fev.events & EPOLLHUP),
                            "no EPOLLHUP after the forked child's slave "
                            "closed");
                if (fep >= 0)
                    close(fep);
            }
            close(fk_master);
        }
    }

    SUMMARY("test-pty");
    return fails > 0 ? 1 : 0;
}
