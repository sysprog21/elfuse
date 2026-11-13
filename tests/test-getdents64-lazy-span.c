/*
 * A getdents64 buffer that crosses into an untouched lazy block fills past it
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Code under test: sys_getdents64 in src/syscall/fs.c.
 *
 * The walk writes entries with guest_write_nofault, so only what was faulted in
 * before it can be filled. When the prefault covered just the first record, a
 * buffer starting 4 KiB below a 2 MiB boundary of a never-touched MAP_NORESERVE
 * mapping returned at most 4 KiB on every call, because each call faulted in
 * the same first block again. The listing stayed complete but every call
 * stopped at the boundary.
 *
 * Syscalls exercised: mkdirat(34), openat(56), getdents64(61), mmap(222)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test-harness.h"

#define BLOCK (2UL * 1024 * 1024)
#define BELOW 4096UL
#define BUF_LEN (32UL * 1024)
#define NAMES 400

int passes = 0, fails = 0;

static char dir[64];

static void cleanup(void)
{
    char path[160];
    for (int i = 0; i < NAMES; i++) {
        snprintf(path, sizeof(path), "%s/entry-with-a-long-enough-name-%04d",
                 dir, i);
        unlink(path);
    }
    rmdir(dir);
}

int main(void)
{
    snprintf(dir, sizeof(dir), "/tmp/getdents-span-XXXXXX");
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        return 1;
    }
    for (int i = 0; i < NAMES; i++) {
        char path[160];
        snprintf(path, sizeof(path), "%s/entry-with-a-long-enough-name-%04d",
                 dir, i);
        int fd = open(path, O_CREAT | O_WRONLY, 0600);
        if (fd < 0) {
            perror("open");
            cleanup();
            return 1;
        }
        close(fd);
    }

    /* Three blocks of address space, never touched, so a 2 MiB boundary with an
     * untouched block on each side lies inside it.
     */
    uint8_t *map = mmap(NULL, 3 * BLOCK, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        cleanup();
        return 1;
    }
    uintptr_t boundary = ((uintptr_t) map + BLOCK) & ~(BLOCK - 1);
    uint8_t *buf = (uint8_t *) (boundary - BELOW);

    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
        perror("open dir");
        cleanup();
        return 1;
    }

    TEST("first call fills past the block boundary");
    long n = syscall(SYS_getdents64, dfd, buf, BUF_LEN);
    if (n > (long) BELOW) {
        PASS();
    } else {
        fprintf(stderr, "  getdents64 returned %ld, boundary at %lu\n", n,
                BELOW);
        FAIL("the call stopped at the untouched block");
    }

    close(dfd);
    munmap(map, 3 * BLOCK);
    cleanup();
    SUMMARY("test-getdents64-lazy-span");
    return fails == 0 ? 0 : 1;
}
