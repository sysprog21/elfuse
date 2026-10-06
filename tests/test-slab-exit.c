/*
 * Guest memory at process exit
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Driven by the test-slab-exit-writes and test-slab-exit-fork lanes in
 * mk/tests.mk, which judge the outcome on the host:
 *
 *   dirty MIB           write every page of MIB of anonymous memory, then exit
 *   write MIB FILE      write MIB to FILE and fsync it, the lane's control for
 *                       its disk-write counter
 *   orphan DIR          fill memory with a pattern and fork; the parent exits
 *                       at once, the child waits up to a minute for DIR/go
 *                       (created after the parent's process is gone), checks
 *                       the pattern, and writes "ok" or the first bad offset
 *                       to DIR/result. Removing DIR cancels the wait.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test-util.h"

#define MIB (1UL << 20)
#define PATTERN_LEN (8 * MIB)

static unsigned char *map_anon(size_t len)
{
    unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    return p;
}

static int dirty(size_t len)
{
    unsigned char *p = map_anon(len);
    for (size_t off = 0; off < len; off += 4096)
        p[off] = 1;
    return 0;
}

static int write_file(size_t len, const char *path)
{
    static unsigned char chunk[MIB];
    memset(chunk, 0x5a, sizeof(chunk));
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror(path);
        return 1;
    }
    for (size_t done = 0; done < len; done += sizeof(chunk)) {
        if (write_fd_all(fd, chunk, sizeof(chunk)) < 0) {
            perror("write");
            return 1;
        }
    }
    if (fsync(fd) != 0) {
        perror("fsync");
        return 1;
    }
    return close(fd);
}

static unsigned char pattern(size_t off)
{
    return (unsigned char) (off * 131 + 7);
}

/* Return the first offset whose byte is wrong, or PATTERN_LEN if none is. */
static size_t check(const unsigned char *p)
{
    size_t off = 0;
    while (off < PATTERN_LEN && p[off] == pattern(off))
        off++;
    return off;
}

/* Fill memory with the pattern and fork; returns fork's result in both. */
static pid_t fill_and_fork(unsigned char **p)
{
    *p = map_anon(PATTERN_LEN);
    for (size_t off = 0; off < PATTERN_LEN; off++)
        (*p)[off] = pattern(off);
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    return pid;
}

static int orphan(const char *dir)
{
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        perror(dir);
        return 1;
    }
    unsigned char *p;
    if (fill_and_fork(&p) > 0) {
        close(dirfd);
        return 0;
    }

    /* Removing the scratch directory cancels the child's wait on lane failure.
     */
    int waited = 0;
    while (faccessat(dirfd, "go", F_OK, 0) != 0) {
        if (access(dir, F_OK) != 0 || ++waited > 600)
            _exit(1);
        usleep(100000);
    }

    char msg[64] = "ok\n";
    size_t bad = check(p);
    if (bad != PATTERN_LEN)
        snprintf(msg, sizeof(msg), "bad byte at %zu\n", bad);
    _exit(file_write_at(dirfd, "result", msg) < 0 ? 1 : 0);
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "dirty") == 0)
        return dirty(strtoul(argv[2], NULL, 10) * MIB);
    if (argc == 4 && strcmp(argv[1], "write") == 0)
        return write_file(strtoul(argv[2], NULL, 10) * MIB, argv[3]);
    if (argc == 3 && strcmp(argv[1], "orphan") == 0)
        return orphan(argv[2]);
    fprintf(stderr, "usage: %s dirty MIB | write MIB FILE | orphan DIR\n",
            argv[0]);
    return 2;
}
