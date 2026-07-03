/*
 * /proc/self/* completeness tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests:
 *   1. /proc/self/auxv returns valid auxv with AT_PAGESZ=4096
 *   2. /proc/self/environ contains at least one entry
 *   3. /proc/self/cmdline is non-empty
 *   4. /proc/self/maps contains [heap] and [stack]
 *   5. /proc/self/status contains correct PID
 *   6. /proc/self/cgroup is cgroup v2 "0::/" (not containerized)
 *   7. /proc/self/comm is non-empty, single LF-terminated line
 *   8. /proc/self/statm has seven page-count fields with size >= resident
 *   9. /proc/sys/kernel/ostype is "Linux"
 *  10. /proc/sys/kernel/osrelease agrees with uname(2)
 *  11. /proc/sys/kernel/hostname agrees with uname(2)
 *
 * Syscalls: openat(56), read(63), close(57), getpid(172), uname(160)
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/utsname.h>

#include "test-harness.h"
#include "test-util.h"

int passes = 0, fails = 0;

#define AT_NULL 0
#define AT_PAGESZ 6

int main(void)
{
    char buf[4096] __attribute__((aligned(8)));
    ssize_t n;

    TEST("procfs: /proc/self/auxv readable");
    {
        n = raw_read_file_nul("/proc/self/auxv", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else if (n > 0) {
            PASS();
        } else {
            FAIL("empty auxv");
        }
    }

    TEST("procfs: auxv contains AT_PAGESZ=4096");
    {
        n = raw_read_file_nul("/proc/self/auxv", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else {
            bool found = false;
            uint64_t *p = (uint64_t *) buf;
            for (ssize_t i = 0; i + 1 < n / 8; i += 2) {
                if (p[i] == AT_PAGESZ && p[i + 1] == 4096) {
                    found = true;
                    break;
                }
                if (p[i] == AT_NULL)
                    break;
            }
            EXPECT_TRUE(found, "AT_PAGESZ not found");
        }
    }

    TEST("procfs: /proc/self/environ readable");
    {
        n = raw_read_file_nul("/proc/self/environ", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else if (n > 0) {
            PASS();
        } else {
            FAIL("empty environ");
        }
    }

    TEST("procfs: /proc/self/cmdline non-empty");
    {
        n = raw_read_file_nul("/proc/self/cmdline", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else if (n > 0) {
            PASS();
        } else {
            FAIL("empty cmdline");
        }
    }

    TEST("procfs: /proc/self/maps contains [stack] and [heap]");
    {
        n = raw_read_file_nul("/proc/self/maps", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else {
            if (n > 0) {
                if (strstr(buf, "[stack]") && strstr(buf, "[heap]"))
                    PASS();
                else
                    FAIL("stack or heap not found in maps");
            } else {
                FAIL("empty maps");
            }
        }
    }

    TEST("procfs: /proc/self/status has correct PID");
    {
        long pid = raw_getpid();
        n = raw_read_file_nul("/proc/self/status", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else {
            if (n > 0) {
                /* Check Pid: field */
                bool found = false;
                for (ssize_t i = 0; i < n - 5; i++) {
                    if (buf[i] == 'P' && buf[i + 1] == 'i' &&
                        buf[i + 2] == 'd' && buf[i + 3] == ':') {
                        /* Parse the PID value */
                        ssize_t j = i + 4;
                        while (j < n && (buf[j] == ' ' || buf[j] == '\t'))
                            j++;
                        long parsed_pid = 0;
                        while (j < n && buf[j] >= '0' && buf[j] <= '9')
                            parsed_pid = parsed_pid * 10 + (buf[j++] - '0');
                        if (parsed_pid == pid)
                            found = true;
                        break;
                    }
                }
                EXPECT_TRUE(found, "PID mismatch in status");
            } else {
                FAIL("empty status");
            }
        }
    }

    TEST("procfs: /proc/self/cgroup is cgroup v2 \"0::/\"");
    {
        n = raw_read_file_nul("/proc/self/cgroup", buf, sizeof(buf));
        if (n < 0)
            FAIL("open failed");
        else
            EXPECT_TRUE(strstr(buf, "0::/") != NULL,
                        "cgroup v2 root marker missing");
    }

    TEST("procfs: /proc/self/cgroup ends with newline");
    {
        n = raw_read_file_nul("/proc/self/cgroup", buf, sizeof(buf));
        if (n <= 0)
            FAIL("open failed");
        else
            EXPECT_TRUE(buf[n - 1] == '\n', "cgroup last byte not LF");
    }

    TEST("procfs: /proc/self/comm is single LF-terminated line");
    {
        n = raw_read_file_nul("/proc/self/comm", buf, sizeof(buf));
        if (n <= 0) {
            FAIL("open failed");
        } else {
            bool ok = (n >= 2) && (buf[n - 1] == '\n');
            /* Only one newline allowed (Linux semantic). */
            int lfs = 0;
            for (ssize_t i = 0; i < n; i++)
                if (buf[i] == '\n')
                    lfs++;
            EXPECT_TRUE(ok && lfs == 1, "comm shape wrong");
        }
    }

    TEST("procfs: /proc/self/statm has seven fields");
    {
        n = raw_read_file_nul("/proc/self/statm", buf, sizeof(buf));
        if (n <= 0) {
            FAIL("open failed");
        } else {
            int fields = 0;
            bool in_token = false;
            for (ssize_t i = 0; i < n; i++) {
                char c = buf[i];
                if (c == '\n')
                    break;
                if (c == ' ') {
                    in_token = false;
                } else if (!in_token) {
                    in_token = true;
                    fields++;
                }
            }
            EXPECT_TRUE(fields == 7, "statm field count wrong");
        }
    }

    TEST("procfs: /proc/self/statm size >= resident");
    {
        n = raw_read_file_nul("/proc/self/statm", buf, sizeof(buf));
        if (n <= 0) {
            FAIL("open failed");
        } else {
            unsigned long long total = 0, resident = 0;
            /* Skip whitespace, parse digits for the first two fields. */
            ssize_t i = 0;
            while (i < n && (buf[i] == ' ' || buf[i] == '\t'))
                i++;
            while (i < n && buf[i] >= '0' && buf[i] <= '9')
                total = total * 10 + (unsigned long long) (buf[i++] - '0');
            while (i < n && (buf[i] == ' ' || buf[i] == '\t'))
                i++;
            while (i < n && buf[i] >= '0' && buf[i] <= '9')
                resident =
                    resident * 10 + (unsigned long long) (buf[i++] - '0');
            EXPECT_TRUE(total >= resident, "statm total smaller than resident");
        }
    }

    TEST("procfs: /proc/sys/kernel/ostype is \"Linux\"");
    {
        n = raw_read_file_nul("/proc/sys/kernel/ostype", buf, sizeof(buf));
        if (n <= 0)
            FAIL("open failed");
        else
            EXPECT_TRUE(n == 6 && !memcmp(buf, "Linux\n", 6),
                        "ostype content mismatch");
    }

    TEST("procfs: /proc/sys/kernel/osrelease agrees with uname");
    {
        struct utsname u;
        if (uname(&u) < 0) {
            FAIL("uname syscall failed");
        } else {
            n = raw_read_file_nul("/proc/sys/kernel/osrelease", buf,
                                  sizeof(buf));
            if (n <= 0) {
                FAIL("open failed");
            } else {
                /* Trim trailing LF before strcmp. */
                if (buf[n - 1] == '\n')
                    buf[n - 1] = '\0';
                EXPECT_TRUE(!strcmp(buf, u.release),
                            "osrelease disagrees with uname.release");
            }
        }
    }

    TEST("procfs: /proc/sys/kernel/hostname agrees with uname");
    {
        struct utsname u;
        if (uname(&u) < 0) {
            FAIL("uname syscall failed");
        } else {
            n = raw_read_file_nul("/proc/sys/kernel/hostname", buf,
                                  sizeof(buf));
            if (n <= 0) {
                FAIL("open failed");
            } else {
                if (buf[n - 1] == '\n')
                    buf[n - 1] = '\0';
                EXPECT_TRUE(!strcmp(buf, u.nodename),
                            "hostname disagrees with uname.nodename");
            }
        }
    }

    SUMMARY("test-procfs");
    return fails > 0 ? 1 : 0;
}
