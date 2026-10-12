/*
 * Test what RLIMIT_STACK decides at execve
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux lets argv and envp take a quarter of the soft limit, between 128 KiB
 * and 6 MiB. Each check sets the limit in a fork child and execs this binary
 * again, because the limit that counts is the one in force at execve.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define KIB 1024UL
#define MIB (1024UL * 1024)

/* Exec @self with argv[1] = @mode and @arg_bytes of further arguments, under a
 * soft RLIMIT_STACK of @limit.
 *
 * Returns the image's exit status, -1 if a signal ended it, or -2 if execve
 * failed with E2BIG.
 */
static int run_under(char *self, rlim_t limit, char *mode, size_t arg_bytes)
{
    enum { EACH = 100 * 1024 };
    size_t n = arg_bytes / EACH;
    char **argv = calloc(n + 3, sizeof(*argv));
    int status = -1;

    if (!argv)
        return -3;
    argv[0] = self;
    argv[1] = mode;
    for (size_t i = 0; i < n; i++) {
        argv[2 + i] = malloc(EACH);
        if (!argv[2 + i])
            return -3;
        memset(argv[2 + i], 'a', EACH - 1);
        argv[2 + i][EACH - 1] = '\0';
    }

    pid_t pid = fork();
    if (pid == 0) {
        struct rlimit rl;
        if (getrlimit(RLIMIT_STACK, &rl) < 0)
            _exit(120);
        rl.rlim_cur = limit;
        if (setrlimit(RLIMIT_STACK, &rl) < 0)
            _exit(121);

        /* An empty environment, so what fits depends on the arguments alone and
         * not on what the caller of this test had exported.
         */
        char *envp[] = {NULL};
        execve(self, argv, envp);
        _exit(errno == E2BIG ? 122 : 123);
    }
    if (pid > 0)
        waitpid(pid, &status, 0);
    for (size_t i = 0; i < n; i++)
        free(argv[2 + i]);
    free(argv);

    if (!WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status) == 122 ? -2 : WEXITSTATUS(status);
}

/* execve takes @fits bytes of arguments under @limit and refuses @too_big. */
static void expect_args(const char *name,
                        char *self,
                        rlim_t limit,
                        size_t fits,
                        size_t too_big)
{
    TEST(name);
    int ok = run_under(self, limit, "nop", fits);
    int big = run_under(self, limit, "nop", too_big);
    if (ok == 0 && big == -2) {
        PASS();
    } else {
        printf("FAIL: %zu KiB gave %d, %zu KiB gave %d\n", fits / KIB, ok,
               too_big / KIB, big);
        fails++;
    }
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "nop"))
        return 0;

    printf("test-rlimit-stack: RLIMIT_STACK at execve\n");

    /* A quarter of the limit, between 128 KiB and 6 MiB. */
    expect_args("execve arguments under 1 MiB", argv[0], MIB, 200 * KIB,
                300 * KIB);
    expect_args("execve arguments under 8 MiB", argv[0], 8 * MIB, 1900 * KIB,
                2200 * KIB);
    expect_args("execve arguments under 64 MiB", argv[0], 64 * MIB, 5800 * KIB,
                6200 * KIB);

    SUMMARY("test-rlimit-stack");
    return fails ? 1 : 0;
}
