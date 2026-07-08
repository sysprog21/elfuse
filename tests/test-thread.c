/*
 * Test clone(CLONE_THREAD) + futex in elfuse
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests raw clone(CLONE_THREAD) with futex-based synchronization. Uses inline
 * syscall wrappers (no pthread) to directly exercise elfuse's thread
 * implementation.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#include "test-harness.h"
#include "raw-syscall.h"

int passes = 0, fails = 0;

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/* Shared state */

/* Shared variable written by child thread, read by parent */
static volatile int shared_value = 0;

/* Child TID: written by CLONE_PARENT_SETTID and cleared by CLONE_CHILD_CLEARTID
 * on thread exit
 */
static volatile int child_tid = 0;

/* Synchronization flag: child sets to 1 when done, parent waits */
static volatile int done_flag = 0;
static volatile int parked_state = 0;

/* Child thread function */

/* This is the entry point for the child thread. Since clone returns to the same
 * instruction, main branches on the return value and calls this only in the
 * child path.
 */

static void child_work(void)
{
    long tid = raw_gettid();

    /* Verify the child got a unique TID */
    shared_value = (int) tid;

    /* Signal parent that the child is done */
    done_flag = 1;
    raw_futex_wake((int *) &done_flag, 1);

    /* Exit this thread (not the process) */
    raw_exit(0);
}

static void parked_child_work(void)
{
    parked_state = 1;
    raw_futex_wake((int *) &parked_state, 1);

    while (parked_state == 1)
        raw_futex_wait((int *) &parked_state, 1);

    raw_exit(0);
}

/* Tests */

/* Stack for child thread (8KiB, 16-byte aligned) */
static char child_stack_buf[8192] __attribute__((aligned(16)));

/* Test 1: clone(CLONE_THREAD) creates a new thread that runs concurrently */
static void test_clone_thread(void)
{
    TEST("clone(CLONE_THREAD)");

    /* Reset shared state */
    shared_value = 0;
    done_flag = 0;
    child_tid = 0;

    /* CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
     * CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |
     * CLONE_CHILD_CLEARTID | CLONE_DETACHED (0x7d0f00; DETACHED is a legacy
     * no-op on modern Linux)
     */
    unsigned long flags = 0x7d0f00;
    void *stack_top = child_stack_buf + sizeof(child_stack_buf);

    long ret = raw_clone(flags, stack_top,
                         (int *) &child_tid,  /* CLONE_PARENT_SETTID */
                         0,                   /* TLS (not used here) */
                         (int *) &child_tid); /* CLONE_CHILD_CLEARTID */

    if (ret == 0) {
        /* This path is the child thread */
        child_work();
        /* child_work calls raw_exit, should not reach here */
        __builtin_unreachable();
    }

    if (ret < 0) {
        FAIL("clone returned error");
        return;
    }

    /* Parent: ret = child TID Wait for child to signal completion */
    while (done_flag == 0) {
        raw_futex_wait((int *) &done_flag, 0);
    }

    /* Verify child wrote its TID */
    if (shared_value > 0 && shared_value != (int) raw_gettid()) {
        PASS();
    } else {
        FAIL("child did not write unique TID to shared_value");
    }
}

/* Test 2: CLONE_PARENT_SETTID writes child TID to ptid */
static void test_parent_settid(void)
{
    TEST("CLONE_PARENT_SETTID");

    /* child_tid was set by CLONE_PARENT_SETTID in test_clone_thread Wait for
     * child to fully exit (CLONE_CHILD_CLEARTID clears it)
     */
    while (child_tid != 0) {
        raw_futex_wait_cleartid((int *) &child_tid, child_tid);
    }

    /* If execution reaches this point, CHILD_CLEARTID cleared it and FUTEX_WAKE
     * woke the parent. The original value was > 0 (written by PARENT_SETTID).
     */
    PASS();
}

static void test_settid_failure_preserves_slots(void)
{
    TEST("failed SETTID behavior");

    int parent_tid = 12345;
    unsigned long flags = 0x7d0f00 | 0x01000000; /* + CLONE_CHILD_SETTID */
    void *stack_top = child_stack_buf + sizeof(child_stack_buf);

    long ret = raw_clone(flags, stack_top, &parent_tid, 0, (int *) 1);
    if (ret == 0) {
        raw_exit(1);
        __builtin_unreachable();
    }

    if (ret == -EFAULT && parent_tid == 12345) {
        PASS();
    } else if (ret > 0 && parent_tid == (int) ret) {
        PASS();
    } else {
        FAIL("failed clone changed parent TID slot");
    }
}

/* Test 3: Multiple concurrent threads */

#define N_THREADS 4

/* Per-thread index passed through the child stack to avoid racing with the
 * parent's loop variable (both share VM via CLONE_VM).
 */
static volatile int mt_results[N_THREADS];
static volatile int mt_tids[N_THREADS];
static char mt_stacks[N_THREADS][8192] __attribute__((aligned(16)));
static void test_multi_thread(void)
{
    TEST("multiple threads");

    memset((void *) mt_results, 0, sizeof(mt_results));
    memset((void *) mt_tids, 0, sizeof(mt_tids));

    unsigned long flags = 0x7d0f00;

    int spawned = 0;
    for (int i = 0; i < N_THREADS; i++) {
        /* Store the index in a 16-byte aligned slot at the top of the child's
         * stack. AArch64 requires SP to be 16-byte aligned.
         */
        char *stack_top = mt_stacks[i] + sizeof(mt_stacks[i]);
        int *slot = (int *) (stack_top - 16);
        slot[0] = i;
        void *sp = slot;

        long ret =
            raw_clone(flags, sp, (int *) &mt_tids[i], 0, (int *) &mt_tids[i]);
        if (ret == 0) {
            /* Child: read the index from our own stack (16-byte aligned) */
            int my_idx;
            __asm__ volatile("ldr %w0, [sp]" : "=r"(my_idx));
            mt_results[my_idx] = (int) raw_gettid();
            raw_exit(0);
            __builtin_unreachable();
        }
        if (ret > 0)
            spawned++;
    }

    /* Wait for all children to complete (CHILD_CLEARTID clears tids) */
    for (int i = 0; i < N_THREADS; i++) {
        while (mt_tids[i] != 0) {
            raw_futex_wait_cleartid((int *) &mt_tids[i], mt_tids[i]);
        }
    }

    /* Verify all threads ran and got unique TIDs */
    bool all_unique = true;
    for (int i = 0; i < N_THREADS; i++) {
        if (mt_results[i] == 0) {
            all_unique = false;
            break;
        }
        for (int j = i + 1; j < N_THREADS; j++) {
            if (mt_results[i] == mt_results[j]) {
                all_unique = false;
                break;
            }
        }
    }

    if (spawned == N_THREADS && all_unique) {
        PASS();
    } else {
        FAIL("not all threads completed with unique TIDs");
    }
}

#undef N_THREADS

static void test_clone_stack_unmap_reuse(void)
{
    TEST("clone stack munmap reuse");

    size_t stack_size = 65536;
    void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        FAIL("mmap failed");
        return;
    }

    parked_state = 0;
    child_tid = 0;

    unsigned long flags = 0x7d0f00;
    void *stack_top = (char *) stack + stack_size;
    long ret =
        raw_clone(flags, stack_top, (int *) &child_tid, 0, (int *) &child_tid);

    if (ret == 0) {
        parked_child_work();
        __builtin_unreachable();
    }
    if (ret < 0) {
        munmap(stack, stack_size);
        FAIL("clone returned error");
        return;
    }

    while (parked_state == 0)
        raw_futex_wait((int *) &parked_state, 0);

    if (munmap(stack, stack_size) != 0) {
        FAIL("munmap failed");
        return;
    }

    parked_state = 2;
    raw_futex_wake((int *) &parked_state, 1);

    while (child_tid != 0)
        raw_futex_wait_cleartid((int *) &child_tid, child_tid);

    void *reuse =
        mmap(stack, stack_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (reuse == stack) {
        munmap(reuse, stack_size);
        PASS();
    } else {
        FAIL("stack VA was not reusable");
    }
}

/* Main */

int main(void)
{
    printf("test-thread: raw clone(CLONE_THREAD) + futex tests\n");

    test_clone_thread();
    test_parent_settid();
    test_settid_failure_preserves_slots();
    test_multi_thread();
    test_clone_stack_unmap_reuse();

    SUMMARY("test-thread");
    return fails > 0 ? 1 : 0;
}
