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
 *   4. /proc/self/maps contains [heap] and [stack], every offset is
 *      page-aligned, and the lines add up to VmSize
 *   5. /proc/self/status contains correct PID
 *
 * Syscalls: openat(56), read(63), close(57), getpid(172)
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "test-harness.h"
#include "test-util.h"

int passes = 0, fails = 0;

#define AT_NULL 0
#define AT_PAGESZ 6

static bool parse_proc_stat_field_u64(const char *buf,
                                      int target,
                                      uint64_t *out)
{
    if (target < 4)
        return false;

    const char *p = strrchr(buf, ')');
    if (!p)
        return false;
    p++;

    int field = 3;
    while (*p == ' ')
        p++;
    while (*p != '\0' && field <= target) {
        char *endp;
        if (field == 3) {
            if (*p == '\0' || p[1] != ' ')
                return false;
            endp = (char *) p + 1;
        } else {
            unsigned long long val = strtoull(p, &endp, 10);
            if (endp == p)
                return false;
            if (field == target) {
                *out = (uint64_t) val;
                return true;
            }
        }
        p = endp;
        while (*p == ' ')
            p++;
        field++;
    }
    return false;
}

/* Walk the maps text in @buf: add each line's size to @total, leaving out the
 * elfuse runtime records ([shim], [shim-data]) a Linux process does not have,
 * and report whether every file offset is page-aligned.
 */
static bool maps_walk(char *buf, uint64_t *total)
{
    bool aligned = true;
    *total = 0;
    for (char *line = buf; *line;) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        char *p;
        uint64_t lo = strtoull(line, &p, 16);
        uint64_t hi = strtoull(p + 1, &p, 16);
        uint64_t off = strtoull(p + 6, NULL, 16); /* past " rwxp " */
        if (!strstr(line, "[shim"))
            *total += hi - lo;
        aligned &= (off & 0xfff) == 0;
        if (!nl)
            break;
        *nl = '\n';
        line = nl + 1;
    }
    return aligned;
}

static bool parse_stack_range(const char *buf, uint64_t *start, uint64_t *end)
{
    const char *line = buf;
    while ((line = strstr(line, "[stack]")) != NULL) {
        const char *begin = line;
        while (begin > buf && begin[-1] != '\n')
            begin--;

        unsigned long long lo, hi;
        if (sscanf(begin, "%llx-%llx", &lo, &hi) == 2) {
            *start = (uint64_t) lo;
            *end = (uint64_t) hi;
            return true;
        }
        line += 7;
    }
    return false;
}

static bool read_stack_range(uint64_t *start, uint64_t *end)
{
    char mapsbuf[65536];
    ssize_t maps_n =
        raw_read_file_nul("/proc/self/maps", mapsbuf, sizeof(mapsbuf));
    return maps_n > 0 && parse_stack_range(mapsbuf, start, end);
}

static bool read_start_stack(const char *path, uint64_t *start_stack)
{
    char statbuf[1024];
    ssize_t stat_n = raw_read_file_nul(path, statbuf, sizeof(statbuf));
    return stat_n > 0 && parse_proc_stat_field_u64(statbuf, 28, start_stack);
}

static bool start_stack_is_recorded(uint64_t start_stack, uint64_t stack_end)
{
    return start_stack != stack_end - 16;
}

static int child_write_start_stack(int fd)
{
    uint64_t start_stack = 0;
    if (!read_start_stack("/proc/self/stat", &start_stack))
        return 1;
    if (write_fd_all(fd, &start_stack, sizeof(start_stack)) < 0)
        return 2;
    return 0;
}

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

    TEST("procfs: maps offsets page-aligned, lines add up to VmSize");
    {
        uint64_t maps_total = 0;
        n = raw_read_file_nul("/proc/self/maps", buf, sizeof(buf));
        bool aligned = n > 0 && maps_walk(buf, &maps_total);
        n = raw_read_file_nul("/proc/self/status", buf, sizeof(buf));
        char *vm = n > 0 ? strstr(buf, "VmSize:") : NULL;
        uint64_t vm_kb = vm ? strtoull(vm + 7, NULL, 10) : 0;
        if (aligned && vm_kb * 1024 == maps_total) {
            PASS();
        } else {
            printf("FAIL: aligned %d, VmSize %llu kB, maps %llu kB\n", aligned,
                   (unsigned long long) vm_kb,
                   (unsigned long long) (maps_total / 1024));
            fails++;
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

    TEST("procfs: stat startstack is in [stack]");
    {
        uint64_t start_stack = 0, stack_start = 0, stack_end = 0;
        bool ok = read_start_stack("/proc/self/stat", &start_stack) &&
                  read_stack_range(&stack_start, &stack_end) &&
                  start_stack >= stack_start && start_stack < stack_end;
        EXPECT_TRUE(ok, "startstack not inside [stack]");
    }

    TEST("procfs: task stat startstack is in [stack]");
    {
        char path[128];
        snprintf(path, sizeof(path), "/proc/self/task/%ld/stat",
                 (long) raw_getpid());
        uint64_t start_stack = 0, stack_start = 0, stack_end = 0;
        bool ok = read_start_stack(path, &start_stack) &&
                  read_stack_range(&stack_start, &stack_end) &&
                  start_stack >= stack_start && start_stack < stack_end;
        EXPECT_TRUE(ok, "task startstack not inside [stack]");
    }

    TEST("procfs: stat startstack is recorded SP");
    {
        uint64_t start_stack = 0, stack_start = 0, stack_end = 0;
        bool ok = read_start_stack("/proc/self/stat", &start_stack) &&
                  read_stack_range(&stack_start, &stack_end) &&
                  start_stack >= stack_start && start_stack < stack_end &&
                  start_stack_is_recorded(start_stack, stack_end);
        EXPECT_TRUE(ok, "startstack used fallback value");
    }

    TEST("procfs: fork preserves stat startstack");
    {
        int pipefd[2];
        uint64_t parent_start = 0, child_start = 0;
        uint64_t stack_start = 0, stack_end = 0;
        bool ok = read_start_stack("/proc/self/stat", &parent_start) &&
                  read_stack_range(&stack_start, &stack_end) &&
                  start_stack_is_recorded(parent_start, stack_end) &&
                  pipe(pipefd) == 0;
        if (!ok) {
            EXPECT_TRUE(false, "fork startstack setup failed");
        } else {
            pid_t pid = fork();
            if (pid == 0) {
                close(pipefd[0]);
                int rc = child_write_start_stack(pipefd[1]);
                close(pipefd[1]);
                _exit(rc);
            }
            close(pipefd[1]);
            ssize_t nread = read(pipefd[0], &child_start, sizeof(child_start));
            close(pipefd[0]);
            int status = 0;
            if (pid < 0 || waitpid(pid, &status, 0) < 0)
                ok = false;
            else
                ok = nread == (ssize_t) sizeof(child_start) &&
                     WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                     child_start == parent_start &&
                     start_stack_is_recorded(child_start, stack_end);
            EXPECT_TRUE(ok, "fork child startstack mismatch");
        }
    }

    SUMMARY("test-procfs");
    return fails > 0 ? 1 : 0;
}
