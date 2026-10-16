/*
 * Record the bytes a command wrote to disk, as the kernel charged them
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Usage: probe-disk-writes OUT CMD [ARG...]
 *
 * Runs CMD, waits for it to exit without reaping it, and writes the
 * ri_diskio_byteswritten count of the zombie to OUT. That count includes the
 * write-back a process forces by closing the last descriptor of a file with
 * dirty mapped pages, which is what test-slab-exit-writes measures; once
 * reaped, the count is gone. OUT keeps the number clear of whatever CMD prints.
 * Exits with CMD's status.
 */

#include <libproc.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>

extern char **environ;

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s OUT CMD [ARG...]\n", argv[0]);
        return 2;
    }

    pid_t pid;
    int rc = posix_spawnp(&pid, argv[2], NULL, NULL, argv + 2, environ);
    if (rc != 0) {
        fprintf(stderr, "probe-disk-writes: %s: %s\n", argv[2], strerror(rc));
        return 2;
    }

    siginfo_t info;
    if (waitid(P_PID, (id_t) pid, &info, WEXITED | WNOWAIT) < 0) {
        perror("probe-disk-writes: waitid");
        return 2;
    }
    struct rusage_info_v4 usage;
    if (proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *) &usage) != 0) {
        perror("probe-disk-writes: proc_pid_rusage");
        return 2;
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("probe-disk-writes: waitpid");
        return 2;
    }
    FILE *out = fopen(argv[1], "w");
    if (!out ||
        fprintf(out, "%llu\n",
                (unsigned long long) usage.ri_diskio_byteswritten) < 0 ||
        fclose(out) != 0) {
        perror(argv[1]);
        return 2;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
