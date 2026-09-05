/*
 * Requeue count validation, split out of futex_requeue in src/runtime/futex.c
 * and proved here.
 *
 * Linux refuses a plain FUTEX_REQUEUE whose wake or requeue count is negative,
 * before it takes either futex key. The counts reach elfuse as uint32_t --
 * sc_futex forwards val as (uint32_t) x2 and the requeue half out of the
 * timeout slot -- so the sign the guest passed survives only as the top bit.
 *
 * The test compares against 2^31 rather than casting back to int32_t.
 * Converting a value above INT32_MAX to a signed type is implementation-defined
 * before C23, and the provers reason about the unsigned value directly, the way
 * futexop.h and futexhash.h stay in the value theory for the same reason.
 *
 * Validation has to come first because of the budget below: the walk stops once
 * it has touched nr_wake + nr_requeue waiters, and a negative pair read as
 * unsigned makes that bound 2^33 - 2. Refusing the pair is what holds the sum
 * inside 32 bits. The overflow CVE-2018-6927 reached went through this same
 * argument pair, on the same syscall.
 */
#pragma once

#include <stdint.h>

/* One past the largest count a guest can pass as a non-negative int32_t. */
#define FUTEX_COUNT_LIMIT 0x80000000u

/*@
  assigns \nothing;
  ensures binary: \result == 0 || \result == 1;
  ensures exact:
    \result != 0 <==> (nr_wake < 0x80000000 && nr_requeue < 0x80000000);
 */
static inline int futex_requeue_counts_valid(uint32_t nr_wake,
                                             uint32_t nr_requeue)
{
    return nr_wake < FUTEX_COUNT_LIMIT && nr_requeue < FUTEX_COUNT_LIMIT;
}

/* How many waiters the call may touch. Linux bounds its walk the same way, by
 * breaking once task_count reaches nr_wake + nr_requeue.
 *
 * The sum is taken in 64 bits so the addition itself cannot wrap whatever the
 * caller passes; no_overflow is the stronger statement, that a validated pair
 * leaves the result inside 32 bits.
 */
/*@
  requires valid: nr_wake < 0x80000000 && nr_requeue < 0x80000000;
  assigns \nothing;
  ensures sum: \result == (uint64_t) nr_wake + nr_requeue;
  ensures covers_wake: \result >= nr_wake;
  ensures covers_requeue: \result >= nr_requeue;
  ensures no_overflow: \result < 0x100000000;
 */
static inline uint64_t futex_requeue_budget(uint32_t nr_wake,
                                            uint32_t nr_requeue)
{
    return (uint64_t) nr_wake + nr_requeue;
}
