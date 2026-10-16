/*
 * Test file manipulation syscalls (Batch 1)
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: chmod, symlink, readlinkat, hardlink, utimensat, statx, faccessat2,
 * renameat2
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"
#include "test-util.h"

#ifndef SYS_statx
#define SYS_statx 291
#endif

#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif

#ifndef SYS_readlinkat
#define SYS_readlinkat 78
#endif

#ifndef SYS_renameat2
#define SYS_renameat2 276
#endif

#ifndef O_PATH
#define O_PATH 010000000
#endif

static int create_test_file(const char *path, const char *contents)
{
    int rc = -1;
    size_t len = strlen(contents);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0)
        return -1;

    if (write_fd_all(fd, contents, len) == 0 && close(fd) == 0) {
        fd = -1;
        rc = 0;
    }

    if (fd >= 0)
        close(fd);
    if (rc < 0)
        unlink(path);
    return rc;
}

int main(void)
{
    int passes = 0, fails = 0;

    char tmpdir[] = "/tmp/elfuse-file-ops-XXXXXX";
    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return 1;
    }
    char testfile[256], symlink_path[256], hardlink_path[256];
    char renamed_path[256], no_such_path[256], noreplace_dest[256];
    snprintf(testfile, sizeof(testfile), "%s/file.txt", tmpdir);
    snprintf(symlink_path, sizeof(symlink_path), "%s/symlink", tmpdir);
    snprintf(hardlink_path, sizeof(hardlink_path), "%s/hardlink", tmpdir);
    snprintf(renamed_path, sizeof(renamed_path), "%s/renamed.txt", tmpdir);
    snprintf(no_such_path, sizeof(no_such_path), "%s/no-such.txt", tmpdir);
    snprintf(noreplace_dest, sizeof(noreplace_dest), "%s/noreplace.txt",
             tmpdir);

    printf("test-file-ops: Batch 1 file manipulation tests\n");

    /* Create a test file */
    int fd;
    if (create_test_file(testfile, "hello\n") < 0) {
        printf("FATAL: cannot create %s\n", testfile);
        rmdir(tmpdir);
        return 1;
    }

    /* Test fchmod */
    TEST("fchmod");
    fd = open(testfile, O_RDONLY);
    if (fd >= 0) {
        if (fchmod(fd, 0755) == 0) {
            struct stat st;
            fstat(fd, &st);
            EXPECT_TRUE((st.st_mode & 0777) == 0755, "mode mismatch");
        } else
            FAIL("fchmod failed");
        close(fd);
    } else
        FAIL("open failed");

    /* Test chmod (via fchmodat) */
    TEST("chmod (fchmodat)");
    if (chmod(testfile, 0644) == 0) {
        struct stat st;
        stat(testfile, &st);
        EXPECT_TRUE((st.st_mode & 0777) == 0644, "mode mismatch");
    } else
        FAIL("chmod failed");

    /* Test symlink */
    TEST("symlink");
    if (symlink(testfile, symlink_path) == 0) {
        struct stat st;
        if (lstat(symlink_path, &st) == 0 && S_ISLNK(st.st_mode)) {
            char buf[256];
            ssize_t len = readlink(symlink_path, buf, sizeof(buf) - 1);
            if (len > 0) {
                buf[len] = '\0';
                EXPECT_TRUE(!strcmp(buf, testfile), "readlink mismatch");
            } else
                FAIL("readlink failed");
        } else
            FAIL("not a symlink");
    } else
        FAIL("symlink failed");

    TEST("readlinkat absolute path");
    {
        char buf[256];
        ssize_t len =
            syscall(SYS_readlinkat, AT_FDCWD, symlink_path, buf, sizeof(buf));
        EXPECT_TRUE(len == (ssize_t) strlen(testfile) &&
                        !memcmp(buf, testfile, (size_t) len),
                    "readlinkat absolute path mismatch");
    }

    TEST("readlinkat relative to dirfd");
    {
        char buf[256];
        int dirfd = open(tmpdir, O_RDONLY | O_DIRECTORY);
        if (dirfd < 0) {
            FAIL("open tmpdir failed");
        } else {
            ssize_t len =
                syscall(SYS_readlinkat, dirfd, "symlink", buf, sizeof(buf));
            close(dirfd);
            EXPECT_TRUE(len == (ssize_t) strlen(testfile) &&
                            !memcmp(buf, testfile, (size_t) len),
                        "readlinkat dirfd path mismatch");
        }
    }

    TEST("readlinkat truncates without terminator");
    {
        char buf[5] = {'X', 'X', 'X', 'X', 'X'};
        ssize_t len = syscall(SYS_readlinkat, AT_FDCWD, symlink_path, buf, 4);
        EXPECT_TRUE(len == 4 && !memcmp(buf, testfile, 4) && buf[4] == 'X',
                    "readlinkat truncation mismatch");
    }

    TEST("readlinkat invalid dirfd");
    {
        char buf[1];
        EXPECT_ERRNO(syscall(SYS_readlinkat, -1, "symlink", buf, sizeof(buf)),
                     EBADF, "expected EBADF for invalid dirfd");
    }

    /* An empty name reads the link an O_PATH|O_NOFOLLOW descriptor is open on,
     * and is ENOENT on anything that is not a link.
     */
    TEST("readlinkat empty path on O_PATH symlink fd");
    {
        char buf[256];
        int fd = open(symlink_path, O_PATH | O_NOFOLLOW);
        ssize_t len =
            fd < 0 ? -1 : syscall(SYS_readlinkat, fd, "", buf, sizeof(buf));
        if (fd >= 0)
            close(fd);
        EXPECT_TRUE(len == (ssize_t) strlen(testfile) &&
                        !memcmp(buf, testfile, (size_t) len),
                    "readlinkat empty path mismatch");
    }

    TEST("readlinkat empty path on a regular file");
    {
        char buf[16];
        int fd = open(testfile, O_RDONLY);
        EXPECT_ERRNO(syscall(SYS_readlinkat, fd, "", buf, sizeof(buf)), ENOENT,
                     "expected ENOENT for a descriptor that is not a link");
        if (fd >= 0)
            close(fd);
    }

    /* Acting on a descriptor needs search permission on its parent, not read
     * permission.
     */
    TEST("linkat and readlinkat on a descriptor in a 0311 directory");
    {
        char dir[256], file[256], link[256], linked[256], buf[256];
        snprintf(dir, sizeof(dir), "%s/noread", tmpdir);
        snprintf(file, sizeof(file), "%s/f", dir);
        snprintf(link, sizeof(link), "%s/l", dir);
        snprintf(linked, sizeof(linked), "%s/linked", tmpdir);
        int ffd = -1, lfd = -1;
        if (mkdir(dir, 0755) == 0 && create_test_file(file, "x") == 0 &&
            symlink("f", link) == 0) {
            ffd = open(file, O_RDONLY);
            lfd = open(link, O_PATH | O_NOFOLLOW);
        }
        bool ready = ffd >= 0 && lfd >= 0 && chmod(dir, 0311) == 0;
        long lrc = ready ? syscall(SYS_linkat, ffd, "", AT_FDCWD, linked,
                                   AT_EMPTY_PATH)
                         : -2;
        long n =
            ready ? syscall(SYS_readlinkat, lfd, "", buf, sizeof(buf)) : -2;
        chmod(dir, 0755);
        EXPECT_TRUE(lrc == 0 && n == 1 && buf[0] == 'f',
                    "descriptor call failed without read permission");
        if (ffd >= 0)
            close(ffd);
        if (lfd >= 0)
            close(lfd);
        unlink(linked);
        unlink(link);
        unlink(file);
        rmdir(dir);
    }

    /* A descriptor on a synthetic file answers by the file's own mode, as its
     * path does. Which answer that is depends on who runs the test (root may
     * write a 0444 file), so the two are compared rather than fixed.
     */
    TEST("faccessat2 AT_EMPTY_PATH on O_PATH /proc file matches its path");
    {
        const char *proc_file = "/proc/self/status";
        int fd = open(proc_file, O_PATH);
        errno = 0;
        long by_fd =
            fd < 0 ? -2 : syscall(SYS_faccessat2, fd, "", W_OK, AT_EMPTY_PATH);
        int fd_errno = errno;
        errno = 0;
        long by_path = syscall(SYS_faccessat2, AT_FDCWD, proc_file, W_OK, 0);
        int path_errno = errno;
        if (fd >= 0)
            close(fd);
        EXPECT_TRUE(by_fd == by_path && fd_errno == path_errno,
                    "descriptor and path answers differ");
    }

    /* The open file still answers once its name has left /proc. */
    TEST("faccessat2 AT_EMPTY_PATH on O_PATH fdinfo after its fd closes");
    {
        char fdinfo[64];
        int n = dup(1);
        snprintf(fdinfo, sizeof(fdinfo), "/proc/self/fdinfo/%d", n);
        int fd = n < 0 ? -1 : open(fdinfo, O_PATH);
        if (n >= 0)
            close(n);
        long rc =
            fd < 0 ? -2 : syscall(SYS_faccessat2, fd, "", R_OK, AT_EMPTY_PATH);
        if (fd >= 0)
            close(fd);
        EXPECT_TRUE(rc == 0, "faccessat2 on the open fdinfo failed");
    }

    /* Test hardlink */
    TEST("hardlink (link)");
    if (link(testfile, hardlink_path) == 0) {
        struct stat st1, st2;
        stat(testfile, &st1);
        stat(hardlink_path, &st2);
        EXPECT_TRUE(st1.st_ino == st2.st_ino && st1.st_nlink >= 2,
                    "inode/nlink mismatch");
    } else
        FAIL("link failed");

    /* Test utimensat (set modification time) */
    TEST("utimensat");
    {
        struct timespec times[2] = {{.tv_sec = 1000000000, .tv_nsec = 0},
                                    {.tv_sec = 1000000000, .tv_nsec = 0}};
        if (utimensat(AT_FDCWD, testfile, times, 0) == 0) {
            struct stat st;
            stat(testfile, &st);
            EXPECT_TRUE(st.st_mtime == 1000000000, "mtime not updated");
        } else {
            FAIL("utimensat failed");
        }
    }

    TEST("utimensat UTIME_NOW/UTIME_OMIT");
    {
        struct timespec times[2] = {{.tv_sec = 0, .tv_nsec = UTIME_OMIT},
                                    {.tv_sec = 0, .tv_nsec = UTIME_NOW}};
        struct stat st;
        time_t before = time(NULL);
        if (utimensat(AT_FDCWD, testfile, times, 0) == 0 &&
            stat(testfile, &st) == 0) {
            time_t after = time(NULL);
            bool atime_unchanged = (st.st_atime == 1000000000);
            bool mtime_updated =
                (st.st_mtime >= before && st.st_mtime <= after + 1);
            EXPECT_TRUE(atime_unchanged && mtime_updated,
                        "UTIME_NOW/UTIME_OMIT semantics mismatch");
        } else {
            FAIL("utimensat UTIME_NOW/UTIME_OMIT failed");
        }
    }

    /* Test stat after operations */
    TEST("stat consistency");
    {
        struct stat st;
        if (stat(testfile, &st) == 0) {
            EXPECT_TRUE(st.st_size == 6 && (st.st_mode & 0777) == 0644,
                        "stat mismatch");
        } else
            FAIL("stat failed");
    }

    TEST("statx");
    {
        struct stat st;
        struct statx sx;

        memset(&sx, 0, sizeof(sx));
        if (stat(testfile, &st) != 0) {
            FAIL("stat failed");
        } else {
            long r = syscall(SYS_statx, AT_FDCWD, testfile, 0, 0x7ff, &sx);
            if (r == 0 && sx.stx_dev_major == (unsigned int) major(st.st_dev) &&
                sx.stx_dev_minor == (unsigned int) minor(st.st_dev)) {
                PASS();
            } else {
                FAIL("statx dev mismatch");
            }
        }
    }

    TEST("statx /proc/self/status");
    {
        struct statx sx;

        memset(&sx, 0, sizeof(sx));
        if (syscall(SYS_statx, AT_FDCWD, "/proc/self/status", 0, 0x7ff, &sx) ==
                0 &&
            S_ISREG(sx.stx_mode)) {
            PASS();
        } else {
            FAIL("statx /proc/self/status failed");
        }
    }

    TEST("statx /dev/shm");
    {
        struct statx sx;

        memset(&sx, 0, sizeof(sx));
        if (syscall(SYS_statx, AT_FDCWD, "/dev/shm", 0, 0x7ff, &sx) == 0 &&
            S_ISDIR(sx.stx_mode)) {
            PASS();
        } else {
            FAIL("statx /dev/shm failed");
        }
    }

    TEST("faccessat2");
    {
        long r = syscall(SYS_faccessat2, AT_FDCWD, testfile, F_OK, 0);
        EXPECT_TRUE(r == 0, "faccessat2 failed");
    }

    TEST("renameat2");
    {
        struct stat renamed_st, old_st;
        long r = syscall(SYS_renameat2, AT_FDCWD, testfile, AT_FDCWD,
                         renamed_path, 0);
        if (r == 0 && stat(renamed_path, &renamed_st) == 0 &&
            stat(testfile, &old_st) == -1 && errno == ENOENT) {
            EXPECT_TRUE(syscall(SYS_renameat2, AT_FDCWD, renamed_path, AT_FDCWD,
                                testfile, 0) == 0,
                        "renameat2 restore failed");
        } else {
            FAIL("renameat2 failed");
        }
        unlink(renamed_path);
    }

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

    TEST("renameat2 conflicting flags EINVAL");
    EXPECT_ERRNO(syscall(SYS_renameat2, AT_FDCWD, testfile, AT_FDCWD,
                         no_such_path, RENAME_NOREPLACE | RENAME_EXCHANGE),
                 EINVAL, "expected EINVAL for conflicting flags");

    TEST("renameat2 NOREPLACE with existing dest");
    {
        int dfd = open(noreplace_dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (dfd >= 0)
            close(dfd);
        long r = syscall(SYS_renameat2, AT_FDCWD, testfile, AT_FDCWD,
                         noreplace_dest, RENAME_NOREPLACE);
        bool ok = (r == -1 && errno == EEXIST);
        /* Verify source still exists */
        struct stat st;
        ok = ok && (stat(testfile, &st) == 0);
        unlink(noreplace_dest);
        EXPECT_TRUE(ok, "NOREPLACE should fail with EEXIST");
    }

    TEST("renameat2 NOREPLACE with dirfds");
    {
        char dir_template[] = "/tmp/elfuse-test-renameat2-dir.XXXXXX";
        char src_path[256] = {0};
        char dst_path[256] = {0};
        int dirfd = -1;
        bool dir_created = false;
        bool ok = false;

        if (!mkdtemp(dir_template)) {
            FAIL("mkdtemp failed");
            goto renameat2_dirfds_done;
        }
        dir_created = true;

        dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
        if (dirfd < 0) {
            FAIL("open dir failed");
            goto renameat2_dirfds_done;
        }

        snprintf(src_path, sizeof(src_path), "%s/src.txt", dir_template);
        snprintf(dst_path, sizeof(dst_path), "%s/dst.txt", dir_template);
        if (create_test_file(src_path, "") < 0) {
            FAIL("create src failed");
            goto renameat2_dirfds_done;
        }

        if (syscall(SYS_renameat2, dirfd, "src.txt", dirfd, "dst.txt",
                    RENAME_NOREPLACE) == 0) {
            struct stat src_st;
            struct stat dst_st;
            ok = (stat(src_path, &src_st) == -1 && errno == ENOENT &&
                  stat(dst_path, &dst_st) == 0);
        }

        EXPECT_TRUE(ok, "dirfd NOREPLACE rename failed");

    renameat2_dirfds_done:
        if (dirfd >= 0)
            close(dirfd);
        unlink(src_path);
        unlink(dst_path);
        if (dir_created)
            rmdir(dir_template);
    }

    /* Cleanup */
    unlink(hardlink_path);
    unlink(symlink_path);
    unlink(testfile);
    rmdir(tmpdir);

    SUMMARY("test-file-ops");
    return fails > 0 ? 1 : 0;
}
