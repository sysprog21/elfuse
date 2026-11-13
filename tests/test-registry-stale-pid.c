/*
 * Stale fork-family registry record on a reused host pid
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The test-registry-stale-pid recipe plants a record for guest pid 99 that
 * carries the host pid of an unrelated live elfuse process and a start time
 * that process does not have. kill(99, 0) must then fail with ESRCH, as it does
 * on Linux for a pid that no longer exists.
 *
 * Modes:
 *   hold     sleep until killed (the unrelated process), at most 300 s in
 *            case the recipe shell dies without running its trap
 *   default  fork a child so the family registry exists, print READY, wait
 *            for a line on stdin, then print STALE=esrch or STALE=<errno>
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char buf[16];
    if (argc > 1 && strcmp(argv[1], "hold") == 0) {
        sleep(300);
        return 0;
    }

    /* The child reports on @ready once it runs guest code, which is after its
     * registry record is published, and exits when @release closes.
     */
    int ready[2], release[2];
    if (pipe(ready) != 0 || pipe(release) != 0)
        return 1;
    pid_t pid = fork();
    if (pid < 0)
        return 1;
    if (pid == 0) {
        close(release[1]);
        if (write(ready[1], "R", 1) != 1)
            _exit(1);
        while (read(release[0], buf, 1) > 0)
            ;
        _exit(0);
    }
    close(ready[1]);
    close(release[0]);
    if (read(ready[0], buf, 1) != 1)
        return 1;

    printf("READY\n");
    fflush(stdout);
    if (read(0, buf, sizeof(buf)) <= 0)
        return 1;

    errno = 0;
    int r = kill(99, 0);
    if (r == -1 && errno == ESRCH)
        printf("STALE=esrch\n");
    else
        printf("STALE=%s\n", r == 0 ? "found" : strerror(errno));

    close(release[1]);
    waitpid(pid, NULL, 0);
    return 0;
}
