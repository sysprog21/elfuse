/*
 * Every queued real-time signal from other processes arrives
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * SENDERS children each send SHARE copies of every real-time signal to their
 * parent, which keeps them blocked until all children are reaped. Real-time
 * signals do not merge, so the parent then has COPIES of each pending. COPIES
 * stays below the per-signal queue limit, where a doubled record would be
 * dropped unseen. The children start together from a pipe, so under elfuse
 * their appends to the parent's signal transport file race each other and the
 * parent's drains. One drain still sees well under one 8 KiB read chunk;
 * test-record-split-host covers a record cut by a chunk end.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define SENDERS 8
#define SHARE 3
#define COPIES (SENDERS * SHARE)

int main(void)
{
    int first = SIGRTMIN, last = SIGRTMAX;
    sigset_t rt;
    sigemptyset(&rt);
    for (int s = first; s <= last; s++)
        sigaddset(&rt, s);
    sigprocmask(SIG_BLOCK, &rt, NULL);

    TEST("every queued real-time signal arrives");
    pid_t parent = getpid();
    int go[2];
    int forked = 0, ok = pipe(go) == 0;
    for (int c = 0; ok && c < SENDERS; c++) {
        pid_t child = fork();
        if (child == 0) {
            char b;
            close(go[1]);
            if (read(go[0], &b, 1) != 0)
                _exit(1);
            for (int s = first; s <= last; s++)
                for (int i = 0; i < SHARE; i++)
                    if (kill(parent, s) != 0)
                        _exit(1);
            _exit(0);
        }
        if (child < 0)
            ok = 0;
        else
            forked++;
    }
    if (forked > 0) {
        close(go[0]);
        close(go[1]);
    }
    for (int c = 0; c < forked; c++) {
        int status = 0;
        if (wait(&status) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            ok = 0;
    }
    if (!ok) {
        FAIL("pipe, fork, kill or wait failed");
    } else {
        int bad = 0;
        struct timespec zero = {0, 0};
        for (int s = first; s <= last; s++) {
            sigset_t one;
            sigemptyset(&one);
            sigaddset(&one, s);
            int got = 0, rc;
            while ((rc = sigtimedwait(&one, NULL, &zero)) == s)
                got++;
            if (got != COPIES || rc != -1 || errno != EAGAIN)
                bad++;
        }
        if (bad == 0) {
            PASS();
        } else {
            char msg[80];
            snprintf(msg, sizeof(msg), "%d of %d signals not queued %d times",
                     bad, last - first + 1, COPIES);
            FAIL(msg);
        }
    }

    SUMMARY("test-signal-backlog");
    return fails ? 1 : 0;
}
