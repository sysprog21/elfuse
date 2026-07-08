/*
 * Stress tests resource limits
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises resource limits: max threads, mmap churn, FD exhaustion, and rapid
 * mprotect cycling. Verifies correct behavior at and beyond capacity
 * boundaries.
 *
 * Syscalls exercised: clone(220), futex(98), mmap(222), munmap(215),
 *                     mprotect(226), pipe2(59), close(57), exit(93)
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "test-harness.h"
#include "raw-syscall.h"

int passes = 0, fails = 0;

/* Test 1: 32 concurrent threads */

#define STRESS_THREADS 32

static volatile int thread_results[STRESS_THREADS];
static volatile int thread_tids[STRESS_THREADS];
static char thread_stacks[STRESS_THREADS][8192] __attribute__((aligned(16)));

static void test_max_threads(void)
{
    TEST("32 concurrent threads");

    memset((void *) thread_results, 0, sizeof(thread_results));
    memset((void *) thread_tids, 0, sizeof(thread_tids));

    /* CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
     * CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |
     * CLONE_CHILD_CLEARTID
     */
    unsigned long flags = 0x7d0f00;

    int spawned = 0;
    for (int i = 0; i < STRESS_THREADS; i++) {
        /* Store the index in a 16-byte aligned slot at the top of the child's
         * stack. AArch64 requires SP to be 16-byte aligned.
         */
        char *stack_top = thread_stacks[i] + sizeof(thread_stacks[i]);
        int *slot = (int *) (stack_top - 16);
        slot[0] = i;
        void *sp = slot;

        long ret = raw_clone(flags, sp, (int *) &thread_tids[i], 0,
                             (int *) &thread_tids[i]);
        if (ret == 0) {
            /* Child: read the index from our own stack (16-byte aligned) */
            int my_idx;
            __asm__ volatile("ldr %w0, [sp]" : "=r"(my_idx));
            thread_results[my_idx] = my_idx + 1000;
            raw_exit(0);
            __builtin_unreachable();
        }
        if (ret > 0)
            spawned++;
    }

    /* Wait for all children to exit via CLONE_CHILD_CLEARTID */
    for (int i = 0; i < STRESS_THREADS; i++) {
        while (thread_tids[i] != 0) {
            raw_futex_wait_cleartid((int *) &thread_tids[i], thread_tids[i]);
        }
    }

    /* Verify all threads ran */
    bool all_ok = true;
    for (int i = 0; i < STRESS_THREADS; i++) {
        if (thread_results[i] != i + 1000) {
            all_ok = false;
            break;
        }
    }

    EXPECT_TRUE(spawned == STRESS_THREADS && all_ok,
                "not all 32 threads completed");
}

/* Test 2: mmap/munmap churn */

static void test_mmap_churn(void)
{
    TEST("mmap/munmap churn (256 cycles)");

#define CHURN_CYCLES 256
#define CHURN_SIZE (64 * 1024) /* 64KiB each */
    bool ok = true;

    for (int i = 0; i < CHURN_CYCLES; i++) {
        void *p = mmap(NULL, CHURN_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            ok = false;
            break;
        }
        /* Write to first and last page to verify mapping is valid */
        ((volatile char *) p)[0] = (char) i;
        ((volatile char *) p)[CHURN_SIZE - 1] = (char) i;
        if (munmap(p, CHURN_SIZE) != 0) {
            ok = false;
            break;
        }
    }

    EXPECT_TRUE(ok, "mmap/munmap churn failed");
}

/* Test 3: Many concurrent mmap regions */

static void test_many_regions(void)
{
    TEST("128 concurrent mmap regions");

#define N_REGIONS 128
    void *addrs[N_REGIONS];
    bool ok = true;

    /* Allocate all */
    for (int i = 0; i < N_REGIONS; i++) {
        addrs[i] = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addrs[i] == MAP_FAILED) {
            ok = false;
            /* Clean up allocated resources */
            for (int j = 0; j < i; j++)
                munmap(addrs[j], 4096);
            break;
        }
        /* Write a sentinel */
        *(int *) addrs[i] = i;
    }

    if (ok) {
        /* Verify all sentinels */
        for (int i = 0; i < N_REGIONS; i++) {
            if (*(int *) addrs[i] != i) {
                ok = false;
                break;
            }
        }
        /* Free all */
        for (int i = 0; i < N_REGIONS; i++) {
            munmap(addrs[i], 4096);
        }
    }

    EXPECT_TRUE(ok, "concurrent region allocation failed");
}

/* Test 4: FD exhaustion */

static void test_fd_exhaustion(void)
{
    TEST("FD exhaustion (EMFILE)");

    int *fds = NULL;
    size_t cap = 0;
    int opened = 0, fail_errno = 0;
    bool got_emfile = false;

    for (;;) {
        int pipefd[2];
        size_t new_cap;
        int *new_fds;

        if (pipe(pipefd) != 0) {
            fail_errno = errno;
            got_emfile = (errno == EMFILE);
            break;
        }

        if ((size_t) opened + 2 > cap) {
            new_cap = cap ? cap * 2 : 256;
            while ((size_t) opened + 2 > new_cap)
                new_cap *= 2;
            new_fds = realloc(fds, new_cap * sizeof(*fds));
            if (!new_fds) {
                close(pipefd[0]);
                close(pipefd[1]);
                break;
            }
            fds = new_fds;
            cap = new_cap;
        }

        fds[opened++] = pipefd[0];
        fds[opened++] = pipefd[1];
    }

    /* Clean up all FDs */
    for (int i = 0; i < opened; i++)
        close(fds[i]);
    free(fds);

    if (fail_errno && !got_emfile) {
        FAIL("pipe failed before EMFILE");
        return;
    }

    if (!got_emfile && opened >= 500) {
        FAIL("did not observe EMFILE before bookkeeping failed");
        return;
    }

    /* The test expects to have opened at least 500 FDs and eventually hit the
     * limit (EMFILE).
     */
    EXPECT_TRUE(opened >= 500 && got_emfile,
                "too few FDs opened before exhaustion");
}

/* Test 5: Rapid mprotect cycling */

static void test_mprotect_cycling(void)
{
    TEST("mprotect RW->RX->RW cycling (64x)");

    /* Allocate a page, fill with known data, cycle permissions */
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    /* Write known data while RW */
    memset(p, 0xAB, 4096);

    bool ok = true;
    for (int i = 0; i < 64; i++) {
        /* RW -> RX */
        if (mprotect(p, 4096, PROT_READ | PROT_EXEC) != 0) {
            ok = false;
            break;
        }
        /* Verify the mapping remains readable (via volatile) */
        if (((volatile unsigned char *) p)[0] != 0xAB) {
            ok = false;
            break;
        }

        /* RX -> RW */
        if (mprotect(p, 4096, PROT_READ | PROT_WRITE) != 0) {
            ok = false;
            break;
        }
        /* Verify the mapping remains readable and writable */
        if (((volatile unsigned char *) p)[0] != 0xAB) {
            ok = false;
            break;
        }
        ((volatile unsigned char *) p)[0] = 0xAB; /* re-write */
    }

    munmap(p, 4096);

    EXPECT_TRUE(ok, "mprotect cycling failed");
}

/* Test 6: Large mmap + memset */

static void test_large_mmap(void)
{
    TEST("large mmap (16MiB)");

    size_t sz = 16 * 1024 * 1024;
    void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    /* Touch every page (4KiB stride) */
    volatile char *vp = (volatile char *) p;
    for (size_t off = 0; off < sz; off += 4096) {
        vp[off] = (char) (off >> 12);
    }

    /* Verify */
    bool ok = true;
    for (size_t off = 0; off < sz; off += 4096) {
        if (vp[off] != (char) (off >> 12)) {
            ok = false;
            break;
        }
    }

    munmap(p, sz);

    EXPECT_TRUE(ok, "large mmap data corruption");
}

/* Main */

int main(void)
{
    printf("test-stress: resource limit stress tests\n");

    test_max_threads();
    test_mmap_churn();
    test_many_regions();
    test_fd_exhaustion();
    test_mprotect_cycling();
    test_large_mmap();

    SUMMARY("test-stress");
    return fails > 0 ? 1 : 0;
}
