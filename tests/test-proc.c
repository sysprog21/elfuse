/*
 * Test /proc and /dev emulation
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: /proc/self/cmdline, /proc/meminfo, /proc/stat, /proc/version,
 *        /proc/filesystems, /proc/mounts, readlink(/proc/self/exe),
 *        /dev/null, /dev/zero, /dev/urandom, /dev/full, /dev/console
 *
 * Syscalls exercised: openat(56), read(63), write(64), writev(66),
 *                     lseek(62), readlinkat(78), close(57)
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include "test-harness.h"
#include "test-util.h"

static char orig_cwd[512];

#define RESTORE_CWD()                   \
    do {                                \
        if (chdir(orig_cwd) < 0)        \
            FAIL("restore cwd failed"); \
    } while (0)

static int cwd_matches_proc_fd_dir(const char *cwd)
{
    if (!strcmp(cwd, "/proc/self/fd"))
        return 1;

    char expected[64];
    int n = snprintf(expected, sizeof(expected), "/proc/%d/fd", getpid());
    if (n < 0 || (size_t) n >= sizeof(expected))
        return 0;

    return !strcmp(cwd, expected);
}

int main(void)
{
    if (!getcwd(orig_cwd, sizeof(orig_cwd))) {
        orig_cwd[0] = '/';
        orig_cwd[1] = '\0';
    }

    int passes = 0, fails = 0;

    printf("test-proc: /proc and /dev emulation tests\n");

    /* /proc/self/cmdline: should contain argv[0], NUL-separated */
    TEST("/proc/self/cmdline");
    {
        char buf[4096];
        ssize_t n = read_file_nul("/proc/self/cmdline", buf, sizeof(buf));
        if (n > 0) {
            /* argv[0] should be non-empty (the binary name) */
            EXPECT_TRUE(strlen(buf) > 0, "empty argv[0]");
        } else
            FAIL("read failed");
    }

    /* /proc/meminfo: should contain "MemTotal:" with a positive value */
    TEST("/proc/meminfo");
    {
        char buf[4096];
        ssize_t n = read_file_nul("/proc/meminfo", buf, sizeof(buf));
        if (n > 0) {
            char *mt = strstr(buf, "MemTotal:");
            if (mt) {
                unsigned long kb = 0;
                sscanf(mt, "MemTotal: %lu", &kb);
                EXPECT_TRUE(kb > 0, "MemTotal is 0");
            } else
                FAIL("MemTotal not found");
        } else
            FAIL("read failed");
    }

    /* /proc/stat: should contain "cpu " aggregate line */
    TEST("/proc/stat");
    {
        char buf[8192];
        ssize_t n = read_file_nul("/proc/stat", buf, sizeof(buf));
        if (n > 0) {
            EXPECT_TRUE(strstr(buf, "cpu "), "cpu line not found");
        } else
            FAIL("read failed");
    }

    /* /proc/version: should start with "Linux version" */
    TEST("/proc/version");
    {
        char buf[512];
        ssize_t n = read_file_nul("/proc/version", buf, sizeof(buf));
        if (n > 0) {
            EXPECT_TRUE(!strncmp(buf, "Linux version", 13), "wrong prefix");
        } else
            FAIL("read failed");
    }

    /* /proc/filesystems: should contain at least one fs type */
    TEST("/proc/filesystems");
    {
        char buf[1024];
        ssize_t n = read_file_nul("/proc/filesystems", buf, sizeof(buf));
        if (n > 0) {
            /* Check for ext4 or tmpfs (both in the current synthetic file) */
            EXPECT_TRUE(strstr(buf, "ext4") || strstr(buf, "tmpfs"),
                        "no known fs type");
        } else
            FAIL("read failed");
    }

    /* /proc/mounts: should have at least one mount entry */
    TEST("/proc/mounts");
    {
        char buf[2048];
        ssize_t n = read_file_nul("/proc/mounts", buf, sizeof(buf));
        if (n > 0) {
            /* Check for any mount point */
            EXPECT_TRUE(strstr(buf, " / "), "no root mount");
        } else
            FAIL("read failed");
    }

    /* readlink("/proc/self/exe"): should return a non-empty path */
    TEST("readlink /proc/self/exe");
    {
        char buf[4096];
        ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            EXPECT_TRUE(strlen(buf) > 0, "empty path");
        } else
            FAIL("readlink failed");
    }

    TEST("readlink /proc/<pid>/exe aliases /proc/self/exe");
    {
        char path[64];
        char self_buf[4096], pid_buf[4096];
        snprintf(path, sizeof(path), "/proc/%d/exe", getpid());
        ssize_t self_n =
            readlink("/proc/self/exe", self_buf, sizeof(self_buf) - 1);
        ssize_t pid_n = readlink(path, pid_buf, sizeof(pid_buf) - 1);
        if (self_n > 0 && pid_n > 0) {
            self_buf[self_n] = '\0';
            pid_buf[pid_n] = '\0';
            EXPECT_TRUE(!strcmp(self_buf, pid_buf), "exe targets differ");
        } else
            FAIL("readlink failed");
    }

    /* openat(procfd, "<pid>/stat"): proc walkers keep /proc as a dirfd. */
    TEST("openat /proc/<pid>/stat");
    {
        int procfd = open("/proc", O_RDONLY | O_DIRECTORY);
        if (procfd >= 0) {
            char rel[64];
            snprintf(rel, sizeof(rel), "%d/stat", getpid());
            int fd = openat(procfd, rel, O_RDONLY);
            if (fd >= 0) {
                char buf[256];
                ssize_t n = read(fd, buf, sizeof(buf) - 1);
                EXPECT_TRUE(n > 0, "empty stat");
                close(fd);
            } else
                FAIL("openat failed");
            close(procfd);
        } else
            FAIL("open /proc failed");
    }

    TEST("readdir /proc");
    {
        DIR *dir = opendir("/proc");
        if (dir) {
            int found_self = 0;
            struct dirent *de;
            while ((de = readdir(dir))) {
                if (!strcmp(de->d_name, "self")) {
                    found_self = 1;
                    break;
                }
            }
            closedir(dir);
            EXPECT_TRUE(found_self, "self not found");
        } else
            FAIL("opendir failed");
    }

    TEST("chdir /proc preserves guest cwd");
    {
        char cwd[256];
        struct stat st;
        if (chdir("/proc") < 0) {
            FAIL("chdir /proc failed");
        } else if (!getcwd(cwd, sizeof(cwd))) {
            FAIL("getcwd after chdir /proc failed");
        } else if (strcmp(cwd, "/proc") != 0) {
            FAIL("getcwd did not return /proc");
        } else if (stat("self/stat", &st) < 0) {
            FAIL("relative stat under /proc failed");
        } else {
            int fd = open("self/stat", O_RDONLY);
            if (fd < 0) {
                FAIL("relative open under /proc failed");
            } else {
                close(fd);
                PASS();
            }
        }
        RESTORE_CWD();
    }

    TEST("proc cwd allows dotdot escape");
    {
        char cwd[256];
        if (chdir("/proc") < 0) {
            FAIL("chdir /proc failed");
        } else if (chdir("..") < 0) {
            FAIL("chdir .. from /proc failed");
        } else if (!getcwd(cwd, sizeof(cwd))) {
            FAIL("getcwd after chdir .. failed");
        } else if (strcmp(cwd, "/") != 0) {
            FAIL("chdir .. from /proc did not reach /");
        } else {
            PASS();
        }
        RESTORE_CWD();
    }

    TEST("proc cwd dotdot reaches ordinary files");
    {
        char path[] = "/tmp/elfuse-proc-dotdot-XXXXXX";
        const char *name = strrchr(path, '/');
        int fd = mkstemp(path);
        int relfd = -1;

        if (fd < 0) {
            FAIL("mkstemp failed");
        } else if (!name || name[1] == '\0') {
            FAIL("mkstemp path parse failed");
        } else {
            close(fd);
            fd = -1;
            if (chdir("/proc") < 0) {
                FAIL("chdir /proc failed");
            } else {
                char relpath[512];
                int n =
                    snprintf(relpath, sizeof(relpath), "../tmp/%s", name + 1);
                if (n < 0 || (size_t) n >= sizeof(relpath)) {
                    FAIL("relative path build failed");
                } else {
                    relfd = open(relpath, O_RDONLY);
                }
                if (relfd < 0) {
                    FAIL("relative open escaped to wrong directory");
                } else {
                    close(relfd);
                    relfd = -1;
                    PASS();
                }
            }
        }

        RESTORE_CWD();
        if (relfd >= 0)
            close(relfd);
        if (fd >= 0)
            close(fd);
        unlink(path);
    }

    TEST("chdir /proc/self/fd preserves guest cwd");
    {
        char cwd[256];
        if (chdir("/proc/self/fd") < 0) {
            FAIL("chdir /proc/self/fd failed");
        } else if (!getcwd(cwd, sizeof(cwd))) {
            FAIL("getcwd after chdir /proc/self/fd failed");
        } else if (!cwd_matches_proc_fd_dir(cwd)) {
            FAIL("getcwd did not return /proc/self/fd");
        } else {
            int fd = open("0", O_RDONLY);
            if (fd < 0) {
                FAIL("relative open under /proc/self/fd failed");
            } else {
                close(fd);
                PASS();
            }
        }
        RESTORE_CWD();
    }

    TEST("fchdir follows /proc/self/fd target");
    {
        char tmpl[] = "/tmp/elfuse-proc-fchdir-XXXXXX";
        char *tmpdir = mkdtemp(tmpl);
        int dirfd = -1, procfd = -1, filefd = -1;
        char cwd[512];
        char procfd_path[64];
        char marker[512] = "";
        struct stat cwd_st, tmp_st;

        if (!tmpdir) {
            FAIL("mkdtemp failed");
        } else {
            dirfd = open(tmpdir, O_RDONLY | O_DIRECTORY);
            if (dirfd < 0) {
                FAIL("open temp dir failed");
            } else {
                snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d",
                         dirfd);
                procfd = open(procfd_path, O_RDONLY | O_DIRECTORY);
                if (procfd < 0) {
                    FAIL("open proc fd magiclink failed");
                } else if (fchdir(procfd) < 0) {
                    FAIL("fchdir via proc fd failed");
                } else if (!getcwd(cwd, sizeof(cwd))) {
                    FAIL("getcwd after proc fchdir failed");
                } else if (!strcmp(cwd, procfd_path)) {
                    FAIL("proc fchdir reported the magiclink path");
                } else if (stat(".", &cwd_st) < 0 ||
                           stat(tmpdir, &tmp_st) < 0) {
                    FAIL("stat after proc fchdir failed");
                } else if (cwd_st.st_dev != tmp_st.st_dev ||
                           cwd_st.st_ino != tmp_st.st_ino) {
                    FAIL("proc fchdir did not reach the target directory");
                } else {
                    snprintf(marker, sizeof(marker), "%s/marker", tmpdir);
                    filefd = open("marker", O_CREAT | O_RDWR | O_TRUNC, 0600);
                    if (filefd < 0) {
                        FAIL("relative open after proc fchdir failed");
                    } else {
                        close(filefd);
                        filefd = -1;
                        PASS();
                    }
                }
            }
        }

        RESTORE_CWD();
        if (filefd >= 0)
            close(filefd);
        if (procfd >= 0)
            close(procfd);
        if (dirfd >= 0)
            close(dirfd);
        if (marker[0] != '\0')
            unlink(marker);
        if (tmpdir)
            rmdir(tmpdir);
    }

    TEST("openat on /proc/self/fd dirfd uses target directory");
    {
        char tmpl[] = "/tmp/elfuse-proc-openat-XXXXXX";
        char *tmpdir = mkdtemp(tmpl);
        int dirfd = -1, procfd = -1, filefd = -1;
        char procfd_path[64];
        char marker[512] = "";
        struct stat st;

        if (!tmpdir) {
            FAIL("mkdtemp failed");
        } else {
            dirfd = open(tmpdir, O_RDONLY | O_DIRECTORY);
            if (dirfd < 0) {
                FAIL("open temp dir failed");
            } else {
                snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d",
                         dirfd);
                procfd = open(procfd_path, O_RDONLY | O_DIRECTORY);
                if (procfd < 0) {
                    FAIL("open proc fd magiclink failed");
                } else {
                    filefd = openat(procfd, "marker",
                                    O_CREAT | O_RDWR | O_TRUNC, 0600);
                    if (filefd < 0) {
                        FAIL("openat via proc fd failed");
                    } else {
                        close(filefd);
                        filefd = -1;
                        snprintf(marker, sizeof(marker), "%s/marker", tmpdir);
                        if (stat(marker, &st) < 0) {
                            FAIL("openat via proc fd missed target directory");
                        } else {
                            PASS();
                        }
                    }
                }
            }
        }

        if (filefd >= 0)
            close(filefd);
        if (procfd >= 0)
            close(procfd);
        if (dirfd >= 0)
            close(dirfd);
        if (marker[0] != '\0')
            unlink(marker);
        if (tmpdir)
            rmdir(tmpdir);
    }

    TEST("O_DIRECTORY rejects proc file");
    {
        errno = 0;
        int fd = open("/proc/self/cmdline", O_RDONLY | O_DIRECTORY);
        if (fd < 0 && errno == ENOTDIR) {
            PASS();
        } else {
            if (fd >= 0)
                close(fd);
            FAIL("open unexpectedly succeeded");
        }
    }

    /* /dev/null: write succeeds, read returns 0 (EOF) */
    TEST("/dev/null write+read");
    {
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
            char data[] = "test";
            ssize_t w = write(fd, data, 4);
            if (w == 4) {
                char buf[16];
                ssize_t r = read(fd, buf, sizeof(buf));
                EXPECT_TRUE(r == 0, "read not EOF");
            } else
                FAIL("write failed");
            close(fd);
        } else
            FAIL("open failed");
    }

    /* /dev/zero: read returns all zeros */
    TEST("/dev/zero");
    {
        int fd = open("/dev/zero", O_RDONLY);
        if (fd >= 0) {
            unsigned char buf[64];
            memset(buf, 0xFF, sizeof(buf));
            ssize_t r = read(fd, buf, sizeof(buf));
            if (r == 64) {
                int all_zero = 1;
                for (int i = 0; i < 64; i++) {
                    if (buf[i] != 0) {
                        all_zero = 0;
                        break;
                    }
                }
                EXPECT_TRUE(all_zero, "not all zeros");
            } else
                FAIL("read wrong size");
            close(fd);
        } else
            FAIL("open failed");
    }

    /* /dev/urandom: read returns data (extremely unlikely to be all zeros) */
    TEST("/dev/urandom");
    {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            unsigned char buf[32];
            memset(buf, 0, sizeof(buf));
            ssize_t r = read(fd, buf, sizeof(buf));
            if (r == 32) {
                int any_nonzero = 0;
                for (int i = 0; i < 32; i++) {
                    if (buf[i] != 0) {
                        any_nonzero = 1;
                        break;
                    }
                }
                EXPECT_TRUE(any_nonzero, "all zeros (astronomically unlikely)");
            } else
                FAIL("read wrong size");
            close(fd);
        } else
            FAIL("open failed");
    }

    /* /dev/full: write fails with ENOSPC, read returns NUL stream. */
    TEST("/dev/full write returns ENOSPC");
    {
        int fd = open("/dev/full", O_RDWR);
        if (fd < 0) {
            FAIL("open failed");
        } else {
            char data[] = "test";
            ssize_t w = write(fd, data, 4);
            int saved_errno = errno;
            if (w == 0)
                FAIL("zero-byte short write instead of error");
            else if (w > 0)
                FAIL("write unexpectedly succeeded");
            else
                EXPECT_TRUE(saved_errno == ENOSPC, "wrong errno on write");

            /* POSIX zero-length write must short-circuit cleanly. */
            ssize_t zw = write(fd, data, 0);
            EXPECT_TRUE(zw == 0, "zero-length write did not return 0");
            close(fd);
        }
    }

    TEST("/dev/full read returns zeros");
    {
        int fd = open("/dev/full", O_RDONLY);
        if (fd < 0) {
            FAIL("open failed");
        } else {
            unsigned char buf[64];
            memset(buf, 0xFF, sizeof(buf));
            ssize_t r = read(fd, buf, sizeof(buf));
            if (r != 64) {
                FAIL("read wrong size");
            } else {
                int all_zero = 1;
                for (size_t i = 0; i < sizeof(buf); i++) {
                    if (buf[i] != 0) {
                        all_zero = 0;
                        break;
                    }
                }
                EXPECT_TRUE(all_zero, "not all zeros");
            }
            close(fd);
        }
    }

    TEST("/dev/full lseek");
    {
        int fd = open("/dev/full", O_RDWR);
        if (fd < 0) {
            FAIL("open failed");
        } else {
            off_t pos = lseek(fd, 4096, SEEK_SET);
            EXPECT_TRUE(pos == 4096, "lseek returned wrong offset");
            close(fd);
        }
    }

    TEST("/dev/full writev returns ENOSPC");
    {
        int fd = open("/dev/full", O_WRONLY);
        if (fd < 0) {
            FAIL("open failed");
        } else {
            char a[] = "abcd";
            char b[] = "wxyz";
            struct iovec iov[2] = {
                {a, 4},
                {b, 4},
            };
            ssize_t w = writev(fd, iov, 2);
            int saved_errno = errno;
            if (w > 0)
                FAIL("writev unexpectedly succeeded");
            else
                EXPECT_TRUE(saved_errno == ENOSPC, "wrong errno on writev");
            close(fd);
        }
    }

    /* /dev/console: container-style alias for the controlling tty. With no
     * controlling terminal (CI invocation via pipe), the host /dev/tty
     * open returns ENXIO on Linux but ENOTTY on macOS; ENOENT / EACCES /
     * EPERM are also tolerated so a real regression still surfaces.
     */
    TEST("/dev/console open");
    {
        int fd = open("/dev/console", O_RDWR);
        if (isatty(STDIN_FILENO)) {
            if (fd < 0) {
                FAIL("/dev/console open under tty failed");
            } else {
                ssize_t w = write(fd, "", 0);
                EXPECT_TRUE(w == 0, "zero-byte write on /dev/console");
                close(fd);
            }
        } else {
            int saved_errno = errno;
            int ok =
                (fd >= 0) || (saved_errno == ENXIO || saved_errno == ENOTTY ||
                              saved_errno == EACCES || saved_errno == ENOENT ||
                              saved_errno == EPERM);
            EXPECT_TRUE(ok, "unexpected errno from non-tty open");
            if (fd >= 0)
                close(fd);
        }
    }

    TEST("writable /dev/zero and /dev/random");
    {
        int zero_fd = open("/dev/zero", O_WRONLY);
        int rand_fd = open("/dev/random", O_WRONLY);
        int ok = 1;

        if (zero_fd < 0 || rand_fd < 0) {
            ok = 0;
        } else {
            int zero_fl = fcntl(zero_fd, F_GETFL);
            int rand_fl = fcntl(rand_fd, F_GETFL);
            char byte = 'x';
            ssize_t zero_w = write(zero_fd, &byte, 1);
            if (zero_fl < 0 || rand_fl < 0 || zero_w != 1 ||
                (zero_fl & O_ACCMODE) != O_WRONLY ||
                (rand_fl & O_ACCMODE) != O_WRONLY) {
                ok = 0;
            }
        }

        if (zero_fd >= 0)
            close(zero_fd);
        if (rand_fd >= 0)
            close(rand_fd);
        EXPECT_TRUE(ok, "writable device open regression");
    }

    SUMMARY("test-proc");
    return fails > 0 ? 1 : 0;
}
