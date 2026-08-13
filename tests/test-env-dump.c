/*
 * Dump the guest environment, one entry per line
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Prints environ verbatim and in order so tests/test-launch-flags.sh can
 * hold the vector build_linux_stack copied to what --env asked for, entry
 * for entry.
 */

#include <stdio.h>

extern char **environ;

int main(void)
{
    for (char **e = environ; *e; e++)
        puts(*e);
    return 0;
}
