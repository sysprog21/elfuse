/*
 * Robust futex owner-died cleanup tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests:
 *   1. Thread acquires lock, exits, verify FUTEX_OWNER_DIED is set
 *   2. Robust list with multiple entries
 *   3. Pending lock (list_op_pending) cleanup
 *
 * Syscalls: set_robust_list(99), clone(220), futex(98), gettid(178)
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>

#include "test-harness.h"
#include "raw-syscall.h"
#include "test-util.h"

int passes = 0, fails = 0;

#ifndef FUTEX_OWNER_DIED
#define FUTEX_OWNER_DIED 0x40000000
#endif
#ifndef FUTEX_TID_MASK
#define FUTEX_TID_MASK 0x3FFFFFFF
#endif
#ifndef FUTEX_WAITERS
#define FUTEX_WAITERS 0x80000000
#endif

/* Linux robust_list structures */
struct robust_list {
    struct robust_list *next;
};

struct robust_list_head {
    struct robust_list list;
    long futex_offset;
    struct robust_list *list_op_pending;
};

/* Shared memory for cross-thread communication */
static volatile uint32_t lock_word __attribute__((aligned(4)));
static struct robust_list_head rhead __attribute__((aligned(8)));
static struct robust_list entry1 __attribute__((aligned(8)));

static char child_stack[8192] __attribute__((aligned(16)));
static volatile int preset_waiters;

static int child_fn(void *arg)
{
    (void) arg;
    long tid = raw_syscall0(178); /* gettid */

    /* Set up robust list */
    rhead.list.next = &entry1;
    rhead.futex_offset = (long) &lock_word - (long) &entry1;
    rhead.list_op_pending = NULL;
    entry1.next = &rhead.list; /* circular: points back to head */

    /* "Acquire" the lock by writing the current TID, with WAITERS already set
     * when the case under test wants it there.
     */
    lock_word =
        (uint32_t) tid | (preset_waiters ? (uint32_t) FUTEX_WAITERS : 0u);

    /* Register robust list with kernel */
    raw_syscall2(99, (long) &rhead, sizeof(rhead)); /* set_robust_list */

    /* Exit without releasing the lock; robust walk should set FUTEX_OWNER_DIED
     * on lock_word
     */
    raw_syscall1(93, 0); /* exit */
    test_unreachable();
}

/* Wait for a cloned thread to finish tearing down. CLEARTID zeroes the address
 * only after the robust walk has run, so a cleared word proves the walk
 * finished and the reused child stack is free. -1 if it never clears.
 */
static int join_child(volatile int *ctid)
{
    /* Plain FUTEX_WAIT: the CLEARTID wake is not private. The timeout only
     * turns a stuck teardown into a reported failure.
     */
    struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};

    for (int i = 0; i < 10; i++) {
        int seen = __atomic_load_n(ctid, __ATOMIC_SEQ_CST);
        if (seen == 0)
            return 0;
        raw_syscall6(98, (long) ctid, FUTEX_WAIT, seen, (long) &ts, 0, 0);
    }
    return __atomic_load_n(ctid, __ATOMIC_SEQ_CST) == 0 ? 0 : -1;
}

/* One owner-dies run.
 *
 * Returns the word the robust walk left behind; on failure *err names what went
 * wrong and the word means nothing.
 */
static uint32_t run_owner_death(int waiters, const char **err)
{
    *err = NULL;
    lock_word = 0;
    memset(&rhead, 0, sizeof(rhead));
    memset(&entry1, 0, sizeof(entry1));
    preset_waiters = waiters;

    /* CLONE_THREAD | CLONE_VM | CLONE_FS | CLONE_SIGHAND | CLONE_PARENT_SETTID
     * | CLONE_CHILD_CLEARTID. CLONE_THREAD implies CLONE_VM and CLONE_SIGHAND.
     * PARENT_SETTID seeds the word CLEARTID later zeroes, so join_child has
     * something to wait on.
     */
    long flags = 0x00010000 | 0x00000100 | 0x00000200 | 0x00000800 |
                 0x00100000 | 0x00200000;

    volatile int child_tid_addr = 0;
    long ret =
        raw_syscall5(220, flags, (long) (child_stack + sizeof(child_stack)),
                     (long) &child_tid_addr, 0, (long) &child_tid_addr);
    if (ret == 0) {
        child_fn(NULL);
        test_unreachable();
    }
    if (ret < 0) {
        *err = "clone failed";
        return 0;
    }
    if (join_child(&child_tid_addr) != 0) {
        *err = "child never cleared its CLEARTID word";
        return 0;
    }
    return lock_word;
}

int main(void)
{
    const char *err;

    TEST("robust-futex: owner-died on exit");
    uint32_t plain = run_owner_death(0, &err);
    if (err) {
        FAIL(err);
    } else {
        EXPECT_TRUE(plain & FUTEX_OWNER_DIED, "FUTEX_OWNER_DIED not set");
    }

    /* The walk owes the word two more things than the flag. A TID left behind
     * is an owner no LOCK_PI can displace, and it is what separates the robust
     * path from an ordinary abandoned lock. A run that never started says
     * nothing about either, so it reports once above.
     */
    if (!err) {
        TEST("robust-futex: owner-died clears the TID");
        EXPECT_TRUE((plain & FUTEX_TID_MASK) == 0,
                    "the dead owner's TID survived the walk");

        TEST("robust-futex: owner-died keeps WAITERS clear");
        EXPECT_TRUE((plain & FUTEX_WAITERS) == 0,
                    "WAITERS appeared on a word that never had it");
    }

    /* Same transition over a word that already had waiters: the bit has to
     * survive, or the parked waiter is never woken.
     */
    TEST("robust-futex: owner-died keeps WAITERS set");
    uint32_t contended = run_owner_death(1, &err);
    if (err) {
        FAIL(err);
    } else {
        EXPECT_TRUE(contended == ((uint32_t) FUTEX_WAITERS |
                                  (uint32_t) FUTEX_OWNER_DIED),
                    "a contended lock's word is not WAITERS|OWNER_DIED");
    }

    TEST("robust-futex: set_robust_list returns 0");
    {
        struct robust_list_head h;
        memset(&h, 0, sizeof(h));
        long r = raw_syscall2(99, (long) &h, sizeof(h));
        EXPECT_TRUE(r == 0, "set_robust_list returned non-zero");
    }

    TEST("robust-futex: get_robust_list returns head");
    {
        struct robust_list_head h;
        memset(&h, 0, sizeof(h));
        raw_syscall2(99, (long) &h, sizeof(h));

        void *head_out = NULL;
        long len_out = 0;
        long r = raw_syscall3(100, 0, (long) &head_out, (long) &len_out);
        EXPECT_TRUE(r == 0 && head_out == &h && len_out == 24,
                    "get_robust_list mismatch");
    }

    SUMMARY("test-robust-futex");
    return fails > 0 ? 1 : 0;
}
