/*
 * A guest that sets its rlimits leaves elfuse's own limits where they were
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guest limits are guest state, so setrlimit in the guest must not reach host
 * setrlimit. Only elfuse can read the limits of its own process, which is what
 * ELFUSE_HOST_RLIMIT_CHECK is for: each elfuse process records its host limits
 * at start and fails its exit, with a line on stderr, when one has moved. This
 * runs test-proc-limits, which sets every limit elfuse tracks in a parent and
 * in fork children, with the check armed.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define ELFUSE_BIN "build/elfuse"
#define GUEST_BIN "build/test-proc-limits"

/* Run the guest with the check armed, its stdout dropped and its stderr in
 * @err_fd.
 *
 * Returns the exit status of the top-level elfuse, or -1.
 */
static int run_guest_checked(int err_fd)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd < 0 || dup2(null_fd, STDOUT_FILENO) < 0 ||
            dup2(err_fd, STDERR_FILENO) < 0 ||
            setenv("ELFUSE_HOST_RLIMIT_CHECK", "1", 1) < 0)
            _exit(127);
        execl(ELFUSE_BIN, ELFUSE_BIN, GUEST_BIN, (char *) NULL);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main(void)
{
    printf("test-rlimit-unchanged-host: host limits across a guest run\n");

    if (access(ELFUSE_BIN, X_OK) != 0 || access(GUEST_BIN, R_OK) != 0) {
        printf("  SKIP: %s or %s not built\n", ELFUSE_BIN, GUEST_BIN);
        return 0;
    }

    char err_path[] = "/tmp/elfuse-rlimit-unchanged-XXXXXX";
    int err_fd = mkstemp(err_path);
    if (err_fd < 0) {
        TEST("stderr capture");
        FAIL("mkstemp");
        SUMMARY("test-rlimit-unchanged-host");
        return 1;
    }
    unlink(err_path);

    int rc = run_guest_checked(err_fd);

    /* A fork child reports its exit status through the lifecycle registry
     * before its atexit handlers run, so a child whose check fired shows only
     * as the line it wrote.
     */
    char err[4096] = {0};
    ssize_t n = pread(err_fd, err, sizeof(err) - 1, 0);
    close(err_fd);

    TEST("guest exits 0 with the check armed");
    EXPECT_EQ(rc, 0, "guest or the top-level check failed");

    TEST("no elfuse process moved a host limit");
    EXPECT_TRUE(n >= 0 && !strstr(err, "host rlimit"), err);

    SUMMARY("test-rlimit-unchanged-host");
    return fails ? 1 : 0;
}
