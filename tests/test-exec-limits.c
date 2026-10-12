/*
 * Test execve() limits (MAX_ARG_STRLEN and ARG_MAX)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "success-case") == 0) {
        printf("exec-limits-passed\n");
        return 0;
    }

    extern char **environ;

    /* The 2 MB budget below is a quarter of the stack limit (Linux
     * bprm_stack_limits), so pin the limit instead of inheriting one: under a
     * raised limit the "too large" exec succeeds and this binary runs again.
     * The make that ships with macOS hands its children such a limit.
     */
    struct rlimit stack_limit;
    if (getrlimit(RLIMIT_STACK, &stack_limit) < 0) {
        perror("getrlimit");
        return 1;
    }
    stack_limit.rlim_cur = 8 * 1024 * 1024;
    if (setrlimit(RLIMIT_STACK, &stack_limit) < 0) {
        perror("setrlimit");
        return 1;
    }

    // 1. Test single string too long (> 128 KB) -> expect E2BIG
    {
        size_t size = 130 * 1024;
        char *huge_arg = malloc(size);
        if (!huge_arg) {
            perror("malloc");
            return 1;
        }
        memset(huge_arg, 'a', size - 1);
        huge_arg[size - 1] = '\0';

        char *new_argv[] = {argv[0], huge_arg, NULL};
        execve(argv[0], new_argv, environ);

        if (errno != E2BIG) {
            fprintf(stderr,
                    "Expected E2BIG for >128KB single argument, got errno %d "
                    "(%s)\n",
                    errno, strerror(errno));
            free(huge_arg);
            return 1;
        }
        free(huge_arg);
    }

    // 2. Test total byte budget exceeded (> 2 MB) -> expect E2BIG
    {
        // 22 strings of 100 KB each is ~2.2 MB (exceeds 2 MB ARG_MAX limit)
        int num_args = 22;
        size_t arg_size = 100 * 1024;
        char **new_argv = calloc(num_args + 2, sizeof(char *));
        if (!new_argv) {
            perror("calloc");
            return 1;
        }
        new_argv[0] = argv[0];
        for (int i = 0; i < num_args; i++) {
            new_argv[i + 1] = malloc(arg_size);
            if (!new_argv[i + 1]) {
                perror("malloc");
                return 1;
            }
            memset(new_argv[i + 1], 'b', arg_size - 1);
            new_argv[i + 1][arg_size - 1] = '\0';
        }
        new_argv[num_args + 1] = NULL;

        execve(argv[0], new_argv, environ);

        if (errno != E2BIG) {
            fprintf(stderr,
                    "Expected E2BIG for >2MB total argument list, got errno %d "
                    "(%s)\n",
                    errno, strerror(errno));
            return 1;
        }

        for (int i = 0; i < num_args; i++) {
            free(new_argv[i + 1]);
        }
        free(new_argv);
    }

    // 3. Test success case (large arguments under 2 MB limit) -> expect success
    {
        // 12 strings of 100 KB each is ~1.2 MB
        int num_args = 12;
        size_t arg_size = 100 * 1024;
        char **new_argv = calloc(num_args + 3, sizeof(char *));
        if (!new_argv) {
            perror("calloc");
            return 1;
        }
        new_argv[0] = argv[0];
        new_argv[1] = "success-case";
        for (int i = 0; i < num_args; i++) {
            new_argv[i + 2] = malloc(arg_size);
            if (!new_argv[i + 2]) {
                perror("malloc");
                return 1;
            }
            memset(new_argv[i + 2], 'c', arg_size - 1);
            new_argv[i + 2][arg_size - 1] = '\0';
        }
        new_argv[num_args + 2] = NULL;

        execve(argv[0], new_argv, environ);

        // If execve returns, it failed
        perror("execve success-case failed");
        return 1;
    }

    return 0;
}
