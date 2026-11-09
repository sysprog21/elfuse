/*
 * Guest-side wall-clock timer for Tier-2 benchmark samples.
 *
 * Runs the given command via fork+execvp+waitpid and prints the elapsed time
 * from just before fork() to child exit as a single integer number of
 * microseconds. tests/bench-suite.sh uses it for the qemu-aarch64 environment,
 * where timing from the host would fold the ~100 ms ssh session setup into
 * millisecond-scale measurements; running the clock inside the guest keeps the
 * measured window identical to the other environments (spawn + run + exit of
 * the workload).
 *
 * A non-zero child exit (or a signal) prints nothing and exits 1 so a failing
 * sample can never be mistaken for a fast one. The workload runs in its own
 * process group; a termination signal received by this wrapper kills that group
 * so descendants cannot survive and distort later samples.
 *
 * Usage: bench-timeit <command> [args...]
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t workload_pgid = -1;
static volatile sig_atomic_t termination_signal;

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

/* SIGKILL rather than the signal received: a workload that ignores SIGTERM
 * would otherwise keep waitpid waiting.
 */
static void kill_workload(int signo)
{
    termination_signal = signo;
    if (workload_pgid > 0)
        (void) kill(-(pid_t) workload_pgid, SIGKILL);
}

static int install_termination_handler(int signo)
{
    struct sigaction action = {
        .sa_handler = kill_workload,
    };
    sigemptyset(&action.sa_mask);
    return sigaction(signo, &action, NULL);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: bench-timeit <command> [args...]\n");
        return 2;
    }

    /* Hold the termination signals until their handlers are installed, so one
     * that arrives right after fork cannot kill this process by default action
     * and leave the workload running in its own process group.
     */
    sigset_t block, saved;
    sigemptyset(&block);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGHUP);
    sigaddset(&block, SIGQUIT);
    if (sigprocmask(SIG_BLOCK, &block, &saved) != 0) {
        perror("sigprocmask");
        return 1;
    }

    uint64_t start = monotonic_ns();
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        if (sigprocmask(SIG_SETMASK, &saved, NULL) != 0) {
            perror("sigprocmask");
            _exit(127);
        }
        if (setpgid(0, 0) != 0) {
            perror("setpgid");
            _exit(127);
        }

        /* Drop the child's stdout so workload output cannot mix into the single
         * microseconds line the parent prints.
         */
        FILE *devnull = freopen("/dev/null", "w", stdout);
        (void) devnull;
        execvp(argv[1], &argv[1]);
        perror(argv[1]);
        _exit(127);
    }

    workload_pgid = pid;
    if (setpgid(pid, pid) != 0 && errno != EACCES && errno != ESRCH) {
        perror("setpgid");
        (void) kill(pid, SIGKILL);
        (void) waitpid(pid, NULL, 0);
        return 1;
    }
    if (install_termination_handler(SIGTERM) != 0 ||
        install_termination_handler(SIGINT) != 0 ||
        install_termination_handler(SIGHUP) != 0 ||
        install_termination_handler(SIGQUIT) != 0) {
        perror("sigaction");
        (void) kill(-pid, SIGKILL);
        (void) waitpid(pid, NULL, 0);
        return 1;
    }
    if (sigprocmask(SIG_SETMASK, &saved, NULL) != 0) {
        perror("sigprocmask");
        (void) kill(-pid, SIGKILL);
        (void) waitpid(pid, NULL, 0);
        return 1;
    }

    /* kill_workload kills the workload group, so the wait always ends. */
    int status = 0;
    while (waitpid(pid, &status, 0) != pid) {
        if (errno != EINTR) {
            perror("waitpid");
            (void) kill(-pid, SIGKILL);
            return 1;
        }
    }
    if (termination_signal != 0)
        return 128 + termination_signal;
    uint64_t elapsed = monotonic_ns() - start;

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "bench-timeit: command failed (status 0x%x)\n", status);
        return 1;
    }

    /* A fork, exec and exit cannot finish in under a microsecond, so a reading
     * that rounds to 0 means the clock or the workload is broken. Printing 0
     * would score as a large improvement.
     */
    if (elapsed < 1000) {
        fprintf(stderr, "bench-timeit: implausible elapsed time %llu ns\n",
                (unsigned long long) elapsed);
        return 1;
    }

    printf("%llu\n", (unsigned long long) (elapsed / 1000));
    return 0;
}
