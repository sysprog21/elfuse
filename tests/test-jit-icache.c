/*
 * Self-modifying JIT instruction cache invalidation test
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: mprotect(PROT_READ | PROT_EXEC) invalidates instruction cache
 *        when guest JIT code is updated in place.
 *
 * Syscalls exercised: mmap(222), mprotect(226)
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

typedef int (*jit_fn_t)(void);

static void test_jit_icache_flush(void)
{
    TEST("JIT mprotect instruction cache flush");

    uint32_t *buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    /* Write 1st version: return 1 0x52800020 : mov w0, #1 0xd65f03c0 : ret */
    buf[0] = 0x52800020u;
    buf[1] = 0xd65f03c0u;

    if (mprotect(buf, 4096, PROT_READ | PROT_EXEC) != 0) {
        FAIL("mprotect RX failed");
        munmap(buf, 4096);
        return;
    }

    jit_fn_t fn = (jit_fn_t) buf;
    int res1 = fn();
    if (res1 != 1) {
        FAIL("initial JIT execution returned wrong value");
        munmap(buf, 4096);
        return;
    }

    /* Change permissions back to RW to rewrite code */
    if (mprotect(buf, 4096, PROT_READ | PROT_WRITE) != 0) {
        FAIL("mprotect RW failed");
        munmap(buf, 4096);
        return;
    }

    /* Write 2nd version: return 42 0x52800540 : mov w0, #42 0xd65f03c0 : ret */
    buf[0] = 0x52800540u;
    buf[1] = 0xd65f03c0u;

    /* Change permissions to RX (must invalidate instruction cache) */
    if (mprotect(buf, 4096, PROT_READ | PROT_EXEC) != 0) {
        FAIL("mprotect RX 2nd failed");
        munmap(buf, 4096);
        return;
    }

    int res2 = fn();
    if (res2 != 42) {
        FAIL("stale instruction cache detected (JIT rewrite failed)");
        munmap(buf, 4096);
        return;
    }

    /* Re-issue mprotect RX while region is ALREADY tracked as RX to exercise
     * same-protection fast path icache invalidation.
     */
    if (mprotect(buf, 4096, PROT_READ | PROT_EXEC) != 0) {
        FAIL("same-protection mprotect RX failed");
        munmap(buf, 4096);
        return;
    }

    int res3 = fn();
    if (res3 != 42) {
        FAIL("same-protection mprotect icache flush failed");
        munmap(buf, 4096);
        return;
    }

    PASS();
    munmap(buf, 4096);
}

int main(void)
{
    test_jit_icache_flush();
    SUMMARY("test-jit-icache");
    return fails == 0 ? 0 : 1;
}
