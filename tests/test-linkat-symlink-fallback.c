/*
 * linkat() hard-link-to-symlink fallback on non-APFS filesystems
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Per linkat(2) on Darwin: without AT_SYMLINK_FOLLOW, hard-linking a symlink
 * itself (rather than its target) "may result in some file systems returning an
 * error" -- reproduced on Case-sensitive HFS+ as ENOTSUP, where the same call
 * against a regular file succeeds. Linux allows hard-linking a symlink
 * unconditionally. sys_linkat() falls back to symlinkat() with the same target
 * when the host linkat() fails with EPERM/ENOTSUP and the source is a symlink,
 * so the guest sees the Linux-compatible outcome regardless of the host
 * filesystem.
 *
 * The Makefile target only runs this under a --sysroot backed by a
 * Case-sensitive HFS+ disk image (created via hdiutil); it skips with exit 77
 * when hdiutil/HFS+ is unavailable in the current environment.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

int main(void)
{
    printf("test-linkat-symlink-fallback: linkat() on a symlink source\n");

    TEST("linkat(flags=0) on a symlink source succeeds");
    EXPECT_TRUE(linkat(AT_FDCWD, "/d1/sym", AT_FDCWD, "/d1/hardlink", 0) == 0,
                "linkat failed");

    TEST("result names a symlink (not the followed target)");
    {
        struct stat st;
        EXPECT_TRUE(lstat("/d1/hardlink", &st) == 0 && S_ISLNK(st.st_mode),
                    "hardlink is not a symlink");
    }

    TEST("symlink target matches the original");
    {
        char buf[64] = {0};
        ssize_t n = readlink("/d1/hardlink", buf, sizeof(buf) - 1);
        EXPECT_TRUE(n > 0 && !strncmp(buf, "target.txt", (size_t) n),
                    "target mismatch");
    }

    TEST("reading through it reaches the same file content");
    {
        int fd = open("/d1/hardlink", O_RDONLY);
        char buf[64] = {0};
        ssize_t n = fd >= 0 ? read(fd, buf, sizeof(buf) - 1) : -1;
        if (fd >= 0)
            close(fd);
        EXPECT_TRUE(n > 0 && !strncmp(buf, "hello\n", (size_t) n),
                    "content mismatch");
    }

    /* The same source reached through a descriptor: an O_PATH fd on the symlink
     * itself, linked with AT_EMPTY_PATH.
     */
    TEST("linkat(AT_EMPTY_PATH) on an O_PATH fd of the symlink succeeds");
    {
        int lfd = open("/d1/sym", O_PATH | O_NOFOLLOW);
        EXPECT_TRUE(lfd >= 0 && linkat(lfd, "", AT_FDCWD, "/d1/hardlink-fd",
                                       AT_EMPTY_PATH) == 0,
                    "linkat failed");
        if (lfd >= 0)
            close(lfd);
    }

    TEST("that result is a symlink to the same target");
    {
        struct stat st;
        char buf[64] = {0};
        ssize_t n = readlink("/d1/hardlink-fd", buf, sizeof(buf) - 1);
        EXPECT_TRUE(lstat("/d1/hardlink-fd", &st) == 0 && S_ISLNK(st.st_mode) &&
                        n == (ssize_t) strlen("target.txt") &&
                        !strcmp(buf, "target.txt"),
                    "not a symlink to target.txt");
    }

    SUMMARY("test-linkat-symlink-fallback");
    return fails > 0 ? 1 : 0;
}
