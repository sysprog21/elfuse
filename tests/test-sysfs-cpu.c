/*
 * Test /sys/devices/system/cpu behavior
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: /sys/devices/system/cpu/{online,possible,present} read,
 *        opendir + readdir on /sys/devices/system/cpu, stat on cpuN
 *        directories, and access()/faccessat() mode checks that are shared by
 *        elfuse's synthetic tree and a real Linux sysfs tree under qemu.
 *
 * Syscalls exercised: openat(56), read(63), close(57), getdents64(61),
 *                     newfstatat(79).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

#include "test-harness.h"
#include "test-util.h"

/* Parse a "0\n" or "0-N\n" cpumask range file into the highest set CPU index.
 *
 * Returns -1 on malformed input.
 */
static int parse_cpurange(const char *s, ssize_t len)
{
    if (len <= 0)
        return -1;
    /* Skip leading whitespace just in case */
    int i = 0;
    while (i < len && (s[i] == ' ' || s[i] == '\t'))
        i++;
    if (i >= len || s[i] < '0' || s[i] > '9')
        return -1;
    int low = 0;
    while (i < len && s[i] >= '0' && s[i] <= '9')
        low = low * 10 + (s[i++] - '0');

    if (i < len && s[i] == '-') {
        i++;
        if (i >= len || s[i] < '0' || s[i] > '9')
            return -1;
        int high = 0;
        while (i < len && s[i] >= '0' && s[i] <= '9')
            high = high * 10 + (s[i++] - '0');
        return high;
    }
    return low;
}

/* Read a cpumask range file (online/possible/present) and return the highest
 * CPU index it advertises. -1 on read or parse failure.
 */
static int read_cpurange(const char *path)
{
    char buf[64];
    ssize_t n = read_file_nul(path, buf, sizeof(buf));
    if (n <= 0)
        return -1;
    return parse_cpurange(buf, n);
}

static int errno_is(int actual, int a, int b)
{
    return actual == a || actual == b;
}

int main(void)
{
    int passes = 0, fails = 0;

    printf("test-sysfs-cpu: /sys/devices/system/cpu behavior\n");

    TEST("read /sys/devices/system/cpu/online");
    int max_cpu = read_cpurange("/sys/devices/system/cpu/online");
    EXPECT_TRUE(max_cpu >= 0, "online read or parse failed");

    TEST("possible matches online");
    EXPECT_EQ(read_cpurange("/sys/devices/system/cpu/possible"), max_cpu,
              "possible disagrees with online");

    TEST("present matches online");
    EXPECT_EQ(read_cpurange("/sys/devices/system/cpu/present"), max_cpu,
              "present disagrees with online");

    TEST("readdir lists cpu0");
    {
        DIR *dir = opendir("/sys/devices/system/cpu");
        if (dir) {
            int found_cpu0 = 0;
            struct dirent *de;
            while ((de = readdir(dir))) {
                if (!strcmp(de->d_name, "cpu0")) {
                    found_cpu0 = 1;
                    break;
                }
            }
            closedir(dir);
            EXPECT_TRUE(found_cpu0, "cpu0 entry not found");
        } else
            FAIL("opendir failed");
    }

    TEST("cpu0 is a directory");
    {
        struct stat st;
        if (stat("/sys/devices/system/cpu/cpu0", &st) == 0)
            EXPECT_TRUE(S_ISDIR(st.st_mode), "cpu0 is not a directory");
        else
            FAIL("stat failed");
    }

    TEST("topology core_id readable or absent");
    {
        errno = 0;
        int fd =
            open("/sys/devices/system/cpu/cpu0/topology/core_id", O_RDONLY);
        if (fd < 0 && errno == ENOENT) {
            PASS();
        } else if (fd >= 0) {
            char buf[64];
            ssize_t n = read(fd, buf, sizeof(buf));
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            EXPECT_TRUE(n >= 0, "topology core_id unreadable");
        } else {
            FAIL("unexpected topology core_id open error");
        }
    }

    TEST("opendir on /sys/devices/system/cpu enumerates ncpu cpuN dirs");
    {
        DIR *dir = opendir("/sys/devices/system/cpu");
        if (dir) {
            int ncpu_dirs = 0;
            struct dirent *de;
            while ((de = readdir(dir))) {
                if (!strncmp(de->d_name, "cpu", 3) && de->d_name[3] >= '0' &&
                    de->d_name[3] <= '9') {
                    ncpu_dirs++;
                }
            }
            closedir(dir);
            EXPECT_EQ(ncpu_dirs, max_cpu + 1, "cpuN dir count != online+1");
        } else
            FAIL("opendir failed");
    }

    /* elfuse's synthetic tree is read-only, while a real qemu sysfs tree runs
     * these tests as root. Keep the shared checks focused on non-mutation and
     * accept the errno/root-access differences Linux permits.
     */
    TEST("EACCES on O_WRONLY of online");
    {
        errno = 0;
        int fd = open("/sys/devices/system/cpu/online", O_WRONLY);
        if (fd >= 0)
            close(fd);
        EXPECT_TRUE(fd < 0 && errno == EACCES, "writable open accepted");
    }

    TEST("O_WRONLY of sysfs cpu root fails");
    {
        errno = 0;
        int fd = open("/sys/devices/system/cpu", O_WRONLY);
        if (fd >= 0)
            close(fd);
        EXPECT_TRUE(fd < 0 && errno_is(errno, EACCES, EISDIR),
                    "writable root open accepted");
    }

    TEST("EACCES on O_CREAT of new entry");
    {
        errno = 0;
        int fd =
            open("/sys/devices/system/cpu/intruder", O_WRONLY | O_CREAT, 0644);
        if (fd >= 0) {
            close(fd);
            unlink("/sys/devices/system/cpu/intruder");
        }
        EXPECT_TRUE(fd < 0 && errno == EACCES, "O_CREAT accepted");
    }

    TEST("access reports online readable and not executable");
    {
        EXPECT_TRUE(access("/sys/devices/system/cpu/online", F_OK) == 0,
                    "F_OK failed");
        EXPECT_TRUE(access("/sys/devices/system/cpu/online", R_OK) == 0,
                    "R_OK failed");
        errno = 0;
        int writable = access("/sys/devices/system/cpu/online", W_OK);
        EXPECT_TRUE(writable == 0 || (writable < 0 && errno == EACCES),
                    "W_OK returned unexpected error");
        errno = 0;
        EXPECT_TRUE(access("/sys/devices/system/cpu/online", X_OK) < 0 &&
                        errno == EACCES,
                    "X_OK unexpectedly succeeded");
    }

    TEST("access reports cpu root searchable");
    {
        EXPECT_TRUE(access("/sys/devices/system/cpu", R_OK) == 0,
                    "cpu root R_OK failed");
        EXPECT_TRUE(access("/sys/devices/system/cpu", X_OK) == 0,
                    "cpu root X_OK failed");
        errno = 0;
        int writable = access("/sys/devices/system/cpu", W_OK);
        EXPECT_TRUE(writable == 0 || (writable < 0 && errno == EACCES),
                    "cpu root W_OK returned unexpected error");
    }

    /* '..' in the suffix must not let the open/stat reach a real target.
     * elfuse rejects traversal inside the synthetic tree with EACCES; Linux
     * resolves the normalized sysfs path and reports ENOENT for this probe.
     */
    TEST("dotdot traversal in open does not resolve");
    {
        errno = 0;
        int fd = open("/sys/devices/system/cpu/../../etc/hostname", O_RDONLY);
        if (fd >= 0)
            close(fd);
        EXPECT_TRUE(fd < 0 && errno_is(errno, EACCES, ENOENT),
                    "dotdot traversal accepted");
    }

    TEST("dotdot traversal in stat does not resolve");
    {
        struct stat st;
        errno = 0;
        int rc = stat("/sys/devices/system/cpu/../../etc/hostname", &st);
        EXPECT_TRUE(rc < 0 && errno_is(errno, EACCES, ENOENT),
                    "dotdot traversal accepted in stat");
    }

    SUMMARY("test-sysfs-cpu");
    return fails > 0 ? 1 : 0;
}
