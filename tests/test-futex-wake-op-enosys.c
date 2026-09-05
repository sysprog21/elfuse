/*
 * FUTEX_WAKE_OP must answer ENOSYS for a selector Linux does not implement
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Both selectors in val3 are guest-supplied and both have unassigned encodings.
 * Linux refuses each at a different point, which the modify makes visible: an
 * unimplemented op stops before it, an unimplemented comparison after it.
 * Neither wakes anybody.
 *
 * Every assertion is an errno or a word the guest can read, so the same source
 * runs against a reference kernel.
 *
 * Syscalls exercised: futex(98), clone(220), exit(93), sched_yield(124)
 */

#include <stdint.h>
#include <linux/futex.h>

#include "test-harness.h"
#include "raw-syscall.h"

int passes = 0, fails = 0;

static int park_word;      /* the address the waiter parks on */
static int target_word;    /* the address the modify lands on */
static int waiter_parking; /* set just before the waiter enters FUTEX_WAIT */
static int waiter_done;    /* set once FUTEX_WAIT has returned for real */

static int waiter_stack[16384] __attribute__((aligned(16)));

/* val3 layout: bit 31 OPARG_SHIFT, 30-28 op, 27-24 cmp, 23-12 oparg, 11-0
 * cmparg.
 */
static uint32_t encode(unsigned op,
                       unsigned cmp,
                       uint32_t oparg,
                       uint32_t cmparg)
{
    return ((op & 7u) << 28) | ((cmp & 0xfu) << 24) | ((oparg & 0xfffu) << 12) |
           (cmparg & 0xfffu);
}

/* FUTEX_WAKE_OP reads its second wake count out of the timeout slot. */
static long futex_wake_op(long nr_wake, long nr_wake2, uint32_t val3)
{
    return raw_syscall6(__NR_futex, (long) &park_word,
                        FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG, nr_wake, nr_wake2,
                        (long) &target_word, (long) val3);
}

/* SET 0x111, compared EQ against 0x111. The modify always lands; the compare is
 * against the word as it was before, so the second wake does not fire.
 */
static uint32_t valid_val3(void)
{
    return encode(0, 0, 0x111, 0x111);
}

static void set_and_wake(int *addr)
{
    __atomic_store_n(addr, 1, __ATOMIC_RELEASE);
    raw_futex_wake(addr, 1);
}

/* Parks once. EINTR is a retry rather than a wake, so a build that interrupts
 * the wait does not read as one that answered it.
 */
static void waiter_fn(void)
{
    long r;
    set_and_wake(&waiter_parking);
    do {
        r = raw_futex_wait(&park_word, 0);
    } while (r == -EINTR);
    set_and_wake(&waiter_done);
    raw_exit(0);
}

static int parked(void)
{
    return __atomic_load_n(&waiter_done, __ATOMIC_ACQUIRE) == 0;
}

/* Give a wake that should not have happened room to arrive. A real one lands
 * within a few yields; this is generous rather than tuned.
 */
static void settle(void)
{
    for (int i = 0; i < 10000; i++)
        raw_syscall0(__NR_sched_yield);
}

/* No waiter is needed for the errno and the modify: on an empty address both
 * wake counts are no-ops.
 */
static void unsupported_op_case(const char *name, unsigned op)
{
    TEST(name);
    __atomic_store_n(&target_word, 0, __ATOMIC_RELEASE);
    long rc = futex_wake_op(1, 1, encode(op, 0, 0x111, 0x111));
    if (rc != -ENOSYS) {
        FAIL("an unimplemented op must be ENOSYS");
        return;
    }
    if (__atomic_load_n(&target_word, __ATOMIC_ACQUIRE) != 0) {
        FAIL("a refused op must not have modified the word");
        return;
    }
    PASS();
}

static void unsupported_cmp_case(const char *name, unsigned cmp)
{
    TEST(name);
    __atomic_store_n(&target_word, 0, __ATOMIC_RELEASE);
    long rc = futex_wake_op(1, 1, encode(0, cmp, 0x111, 0x111));
    if (rc != -ENOSYS) {
        FAIL("an unimplemented comparison must be ENOSYS");
        return;
    }

    /* The comparison is refused after the modify, so unlike the op case the
     * word carries the operand.
     */
    if (__atomic_load_n(&target_word, __ATOMIC_ACQUIRE) != 0x111) {
        FAIL("a refused comparison must still have modified the word");
        return;
    }
    PASS();
}

int main(void)
{
    /* CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
     * CLONE_SYSVSEM, spelled as the value the way the sibling futex tests do.
     */
    unsigned long flags = 0x50f00;

    printf("=== futex wake_op selector tests ===\n\n");

    TEST("a supported pair modifies the word");
    __atomic_store_n(&target_word, 0, __ATOMIC_RELEASE);
    long rc = futex_wake_op(1, 1, valid_val3());
    if (rc < 0) {
        FAIL("a supported op and comparison must not be refused");
    } else if (__atomic_load_n(&target_word, __ATOMIC_ACQUIRE) != 0x111) {
        FAIL("a supported op must have modified the word");
    } else {
        PASS();
    }

    unsupported_op_case("op 5 is ENOSYS", 5);
    unsupported_op_case("op 6 is ENOSYS", 6);
    unsupported_op_case("op 7 is ENOSYS", 7);

    unsupported_cmp_case("comparison 6 is ENOSYS", 6);
    unsupported_cmp_case("comparison 15 is ENOSYS", 15);

    /* Both unassigned: the op is read first, so the word stays untouched. */
    unsupported_op_case("an unsupported pair stops at the op", 5);

    TEST("clone the waiter");
    long waiter = raw_clone(flags, waiter_stack + 16384, 0, 0, 0);
    if (waiter == 0) {
        waiter_fn();
        __builtin_unreachable();
    }
    if (waiter < 0) {
        FAIL("waiter clone failed");
        goto done;
    }
    PASS();

    while (__atomic_load_n(&waiter_parking, __ATOMIC_ACQUIRE) == 0)
        raw_futex_wait(&waiter_parking, 0);
    settle();

    TEST("a refused op leaves the waiter parked");
    if (futex_wake_op(1, 1, encode(5, 0, 0x111, 0x111)) != -ENOSYS) {
        FAIL("an unimplemented op must be ENOSYS");
        goto release;
    }
    settle();
    if (!parked()) {
        FAIL("a refused op woke a parked waiter");
        goto release;
    }
    PASS();

    TEST("a refused comparison leaves the waiter parked");
    if (futex_wake_op(1, 1, encode(0, 6, 0x111, 0x111)) != -ENOSYS) {
        FAIL("an unimplemented comparison must be ENOSYS");
        goto release;
    }
    settle();
    if (!parked()) {
        FAIL("a refused comparison woke a parked waiter");
        goto release;
    }
    PASS();

    /* The waiter is still there, so a supported pair reaches it. This is also
     * what keeps the two cases above from passing on a waiter that never
     * parked: one that had gone leaves nothing to wake here.
     */
    TEST("a supported op wakes the waiter left behind");
    __atomic_store_n(&park_word, 1, __ATOMIC_RELEASE);
    if (futex_wake_op(1, 1, valid_val3()) != 1) {
        FAIL("the waiter the refused calls left parked was not woken");
        goto release;
    }
    PASS();

release:
    __atomic_store_n(&park_word, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&waiter_done, __ATOMIC_ACQUIRE) == 0) {
        raw_futex_wake(&park_word, 1);
        raw_syscall0(__NR_sched_yield);
    }

done:
    SUMMARY("test-futex-wake-op-enosys");
    return fails > 0 ? 1 : 0;
}
