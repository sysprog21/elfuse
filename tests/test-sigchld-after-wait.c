/*
 * A reaped child's SIGCHLD does not reach a handler installed after the wait
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux generates SIGCHLD with the zombie, so under SIG_DFL it is discarded
 * before wait4 returns and a handler installed afterwards never runs for that
 * child. lmbench's benchmp relies on this between its two lat_fs phases.
 */

#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define ROUNDS 20
#define WATCH_NS (100 * 1000 * 1000L)

static volatile sig_atomic_t handler_runs;

static void on_sigchld(int sig)
{
    (void) sig;
    handler_runs++;
}

/* Sleep for the whole window, resuming after each interruption. */
static void watch_window(void)
{
    struct timespec left = {.tv_sec = 0, .tv_nsec = WATCH_NS};
    while (nanosleep(&left, &left) != 0 && errno == EINTR)
        ;
}

enum mode {
    HANDLER_FIRST, /* handler installed before the fork: runs once per child */
    REAP_DFL,      /* reaped under SIG_DFL, handler installed after: never */
    REAP_IGN, /* auto-reaped under SIG_IGN, handler installed after: never */
};

/* Fork a child that exits and wait for it with waitid or waitpid, 20 times, in
 * @mode.
 *
 * Returns the number of rounds whose handler count was wrong, or -1 on a setup
 * failure.
 */
static int bad_rounds(bool use_waitid, enum mode mode)
{
    struct sigaction before, catch;
    memset(&before, 0, sizeof(before));
    before.sa_handler = mode == REAP_IGN ? SIG_IGN : SIG_DFL;
    memset(&catch, 0, sizeof(catch));
    catch.sa_handler = on_sigchld;
    catch.sa_flags = SA_RESTART;
    if (mode == HANDLER_FIRST)
        before = catch;

    int bad = 0;
    for (int round = 0; round < ROUNDS; round++) {
        handler_runs = 0;
        if (sigaction(SIGCHLD, &before, NULL) != 0)
            return -1;
        pid_t pid = fork();
        if (pid < 0)
            return -1;
        if (pid == 0)
            _exit(0);

        /* Under SIG_IGN the kernel reaps the child, and the wait returns ECHILD
         * once it is gone.
         */
        if (use_waitid) {
            siginfo_t info;
            memset(&info, 0, sizeof(info));
            int rc = waitid(P_PID, (id_t) pid, &info, WEXITED);
            if (mode == REAP_IGN ? rc != -1 || errno != ECHILD
                                 : rc != 0 || info.si_pid != pid ||
                                       info.si_code != CLD_EXITED)
                return -1;
        } else {
            int status = 0;
            pid_t rc = waitpid(pid, &status, 0);
            if (mode == REAP_IGN ? rc != -1 || errno != ECHILD
                                 : rc != pid || !WIFEXITED(status))
                return -1;
        }

        if (mode != HANDLER_FIRST && sigaction(SIGCHLD, &catch, NULL) != 0)
            return -1;
        watch_window();
        if (handler_runs != (mode == HANDLER_FIRST ? 1 : 0))
            bad++;
    }
    return bad;
}

static void report(const char *name, int bad)
{
    TEST(name);
    if (bad == 0) {
        PASS();
    } else if (bad < 0) {
        FAIL("fork, wait or sigaction failed");
    } else {
        char msg[80];
        snprintf(msg, sizeof(msg), "wrong handler count in %d of %d rounds",
                 bad, ROUNDS);
        FAIL(msg);
    }
}

int main(void)
{
    report("one SIGCHLD per waitpid child", bad_rounds(false, HANDLER_FIRST));
    report("one SIGCHLD per waitid child", bad_rounds(true, HANDLER_FIRST));
    report("no SIGCHLD after a waitpid reap", bad_rounds(false, REAP_DFL));
    report("no SIGCHLD after a waitid reap", bad_rounds(true, REAP_DFL));
    report("no SIGCHLD after a SIG_IGN waitpid", bad_rounds(false, REAP_IGN));
    report("no SIGCHLD after a SIG_IGN waitid", bad_rounds(true, REAP_IGN));
    signal(SIGCHLD, SIG_DFL);

    SUMMARY("test-sigchld-after-wait");
    return fails ? 1 : 0;
}
