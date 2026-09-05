/*
 * mremap syscall tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: mremap grow, shrink, MREMAP_MAYMOVE, MREMAP_FIXED,
 *        overflow checks, overlapping fixed ranges.
 *
 * Syscalls exercised: mmap(222), mremap(216), munmap(215)
 */

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif
#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif

/* Test 1: shrink in place */

static void test_shrink(void)
{
    TEST("mremap shrink in place");
    void *p = mmap(NULL, 4096 * 4, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    /* Write pattern */
    memset(p, 0xAA, 4096 * 4);

    /* Shrink to 1 page */
    void *q = mremap(p, 4096 * 4, 4096, 0);
    if (q == MAP_FAILED) {
        FAIL("mremap shrink failed");
        munmap(p, 4096 * 4);
        return;
    }

    /* Verify address did not change */
    if (q != p) {
        FAIL("shrink moved the mapping");
        munmap(q, 4096);
        return;
    }

    /* Verify data preserved */
    unsigned char *cp = (unsigned char *) q;
    bool ok = true;
    for (int i = 0; i < 4096; i++) {
        if (cp[i] != 0xAA) {
            ok = false;
            break;
        }
    }
    EXPECT_TRUE(ok, "data corrupted after shrink");

    munmap(q, 4096);
}

/* Test 2: grow with MREMAP_MAYMOVE */

static void test_grow_maymove(void)
{
    TEST("mremap grow MREMAP_MAYMOVE");
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    /* Write a pattern */
    memset(p, 0xBB, 4096);

    /* Grow to 4 pages */
    void *q = mremap(p, 4096, 4096 * 4, MREMAP_MAYMOVE);
    if (q == MAP_FAILED) {
        FAIL("mremap grow failed");
        munmap(p, 4096);
        return;
    }

    /* Verify original data preserved */
    unsigned char *cp = (unsigned char *) q;
    bool ok = true;
    for (int i = 0; i < 4096; i++) {
        if (cp[i] != 0xBB) {
            ok = false;
            break;
        }
    }

    /* Verify extension is zeroed */
    for (int i = 4096; i < 4096 * 4; i++) {
        if (cp[i] != 0) {
            ok = false;
            break;
        }
    }

    EXPECT_TRUE(ok, "data corrupted or extension not zeroed");

    munmap(q, 4096 * 4);
}

static void test_grow_move_adjacent_fault(void)
{
    TEST("mremap fixed move keeps adjacent page unmapped");
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap source");
        return;
    }
    char *dest =
        mmap(NULL, 4096 * 3, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (dest == MAP_FAILED) {
        FAIL("mmap dest");
        munmap(p, 4096);
        return;
    }
    if (munmap(dest + 8192, 4096) < 0) {
        FAIL("munmap guard");
        munmap(dest, 4096 * 3);
        munmap(p, 4096);
        return;
    }
    ((char *) p)[0] = 0x5a;

    void *q = mremap(p, 4096, 8192, MREMAP_MAYMOVE | MREMAP_FIXED, dest);
    if (q == MAP_FAILED) {
        FAIL("mremap move");
        munmap(dest, 8192);
        munmap(p, 4096);
        return;
    }
    if (q != dest || ((char *) q)[0] != 0x5a || ((char *) q)[4096] != 0) {
        FAIL("mremap data");
        munmap(q, 8192);
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        volatile unsigned char value = *((volatile unsigned char *) q + 8192);
        (void) value;
        _exit(1);
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid) {
        FAIL("fork/wait");
        munmap(q, 8192);
        return;
    }
    if ((WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) ||
        (WIFEXITED(status) && WEXITSTATUS(status) == 139))
        PASS();
    else
        FAIL("adjacent page became readable");
    munmap(q, 8192);
}

static void test_fixed_preserves_neighbor_l3(void)
{
    TEST("mremap fixed preserves neighboring lazy PTEs");
    char *source = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (source == MAP_FAILED) {
        FAIL("mmap source");
        return;
    }
    char *anchor = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (anchor == MAP_FAILED) {
        FAIL("mmap anchor");
        munmap(source, 4096);
        return;
    }
    char *dest = anchor + 4096;
    if (munmap(dest, 4096) < 0) {
        FAIL("munmap dest");
        munmap(anchor, 8192);
        munmap(source, 4096);
        return;
    }
    source[0] = 0x11;
    anchor[0] = 0x7e;

    void *moved =
        mremap(source, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, dest);
    if (moved == MAP_FAILED) {
        FAIL("mremap fixed");
        munmap(anchor, 4096);
        munmap(source, 4096);
        return;
    }
    if (moved != dest || dest[0] != 0x11 || anchor[0] != 0x7e)
        FAIL("neighboring lazy page changed");
    else
        PASS();

    munmap(dest, 4096);
    munmap(anchor, 4096);
}

/* Test 3: grow without MAYMOVE fails if blocked */

static void test_grow_no_maymove(void)
{
    TEST("mremap grow w/o MAYMOVE blocked");

    /* Allocate two adjacent pages via MAP_FIXED to block in-place growth */
    void *base = mmap(NULL, 4096 * 4, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    /* Place a blocker right after the first page (different prot to prevent
     * region coalescing; PROT_READ only, not RW)
     */
    void *blocker = mmap((char *) base + 4096, 4096, PROT_READ,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (blocker == MAP_FAILED) {
        FAIL("mmap blocker failed");
        munmap(base, 4096 * 4);
        return;
    }

    /* Try to grow the first page without MAYMOVE; should fail */
    void *q = mremap(base, 4096, 4096 * 2, 0);
    if (q == MAP_FAILED)
        PASS();
    else {
        FAIL("should have failed without MAYMOVE");
        munmap(q, 4096 * 2);
    }

    munmap(base, 4096 * 4);
}

/* Test 4: MREMAP_FIXED moves to new address */

static void test_fixed(void)
{
    TEST("mremap MREMAP_FIXED");
    void *src = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *dst = mmap(NULL, 4096 * 2, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (src == MAP_FAILED || dst == MAP_FAILED) {
        FAIL("mmap failed");
        if (src != MAP_FAILED)
            munmap(src, 4096);
        if (dst != MAP_FAILED)
            munmap(dst, 4096 * 2);
        return;
    }

    /* Write pattern to source */
    memset(src, 0xCC, 4096);

    /* Move src to dst location with MREMAP_FIXED */
    void *q = mremap(src, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, dst);
    if (q == MAP_FAILED) {
        FAIL("mremap FIXED failed");
        munmap(src, 4096);
        munmap(dst, 4096 * 2);
        return;
    }

    if (q != dst) {
        FAIL("FIXED didn't move to requested address");
        munmap(q, 4096);
        return;
    }

    /* Verify data at new location */
    unsigned char *cp = (unsigned char *) q;
    bool ok = true;
    for (int i = 0; i < 4096; i++) {
        if (cp[i] != 0xCC) {
            ok = false;
            break;
        }
    }

    EXPECT_TRUE(ok, "data corrupted after FIXED move");

    munmap(q, 4096);
}

/* Test 5: same size is a no-op */

static void test_same_size(void)
{
    TEST("mremap same size no-op");
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    void *q = mremap(p, 4096, 4096, 0);
    if (q == p)
        PASS();
    else if (q == MAP_FAILED)
        FAIL("mremap same size returned error");
    else
        FAIL("mremap same size moved mapping");

    munmap(p, 4096);
}

/* Test 6: large mremap (glibc realloc pattern) */

static void test_large_realloc(void)
{
    TEST("mremap large (256KiB->512KiB)");
    size_t old_sz = 256 * 1024, new_sz = 512 * 1024;
    void *p = mmap(NULL, old_sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    /* Fill with pattern */
    memset(p, 0xDD, old_sz);

    void *q = mremap(p, old_sz, new_sz, MREMAP_MAYMOVE);
    if (q == MAP_FAILED) {
        FAIL("mremap failed");
        munmap(p, old_sz);
        return;
    }

    /* Check old data preserved */
    unsigned char *cp = (unsigned char *) q;
    bool ok = true;
    for (size_t i = 0; i < old_sz; i++) {
        if (cp[i] != 0xDD) {
            ok = false;
            break;
        }
    }
    /* Check extension is zeroed */
    for (size_t i = old_sz; i < new_sz; i++) {
        if (cp[i] != 0) {
            ok = false;
            break;
        }
    }

    EXPECT_TRUE(ok, "data integrity failure");

    munmap(q, new_sz);
}

/* Test 7: invalid arguments */

static void test_invalid_args(void)
{
    TEST("mremap invalid: unaligned addr");
    void *q = mremap((void *) 0x1001, 4096, 4096, 0);
    EXPECT_TRUE(q == MAP_FAILED, "should reject unaligned address");

    TEST("mremap invalid: zero new_size");
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }
    q = mremap(p, 4096, 0, 0);
    EXPECT_TRUE(q == MAP_FAILED, "should reject zero new_size");
    munmap(p, 4096);

    TEST("mremap invalid: zero old_size");
    p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }
    q = mremap(p, 0, 4096, MREMAP_MAYMOVE);
    EXPECT_TRUE(q == MAP_FAILED, "should reject zero old_size");
    munmap(p, 4096);

    TEST("mremap invalid: FIXED w/o MAYMOVE");
    p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }
    q = mremap(p, 4096, 4096, MREMAP_FIXED);
    EXPECT_TRUE(q == MAP_FAILED, "should reject FIXED without MAYMOVE");
    munmap(p, 4096);
}

/* Test 8: PROT_NONE stays inaccessible after mremap */

static void test_prot_none_mremap(void)
{
    TEST("mremap PROT_NONE stays inaccessible");

    void *p = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    void *q = mremap(p, 4096, 8192, MREMAP_MAYMOVE);
    if (q == MAP_FAILED) {
        FAIL("mremap failed");
        munmap(p, 4096);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork failed");
        munmap(q, 8192);
        return;
    }

    if (pid == 0) {
        volatile unsigned char value = *((volatile unsigned char *) q);
        (void) value;
        _exit(1);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        FAIL("waitpid failed");
        munmap(q, 8192);
        return;
    }

    if ((WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) ||
        (WIFEXITED(status) && WEXITSTATUS(status) == 139))
        PASS();
    else
        FAIL("PROT_NONE mapping became readable");

    munmap(q, 8192);
}

/* Test 9: source range must stay within one VMA */

static void test_source_range_hole(void)
{
    TEST("mremap rejects source range hole");

    void *p = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    if (munmap((char *) p + 4096, 4096) != 0) {
        FAIL("munmap tail failed");
        munmap(p, 4096);
        return;
    }

    void *q = mremap(p, 8192, 12288, MREMAP_MAYMOVE);
    if (q == MAP_FAILED)
        PASS();
    else {
        FAIL("mremap accepted a range with an unmapped hole");
        munmap(q, 12288);
        return;
    }

    munmap(p, 4096);
}

int main(void)
{
    printf("test-mremap: mremap syscall tests\n");

    test_shrink();
    test_grow_maymove();
    test_grow_move_adjacent_fault();
    test_fixed_preserves_neighbor_l3();
    test_grow_no_maymove();
    test_fixed();
    test_same_size();
    test_large_realloc();
    test_invalid_args();
    test_prot_none_mremap();
    test_source_range_hole();

    SUMMARY("test-mremap");
    return fails > 0 ? 1 : 0;
}
