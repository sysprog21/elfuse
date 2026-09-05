/*
 * Operation and comparison selectors for FUTEX_WAKE_OP, split out of
 * futex_wake_op in src/runtime/futex.c and proved here.
 *
 * Both selectors are guest-supplied and both have unassigned encodings. Linux
 * answers ENOSYS for those, and refuses each at a different point: an op it
 * does not implement stops before the read-modify-write, an unimplemented
 * comparison stops after it. Neither wakes anybody. The measurements behind
 * that split are in the commit message.
 *
 * The selectors are compared against their bounds rather than enumerated, so
 * the supported set stays one number per side.
 */
#pragma once

#include <stdint.h>

/* Largest selector Linux implements: FUTEX_OP_XOR and FUTEX_OP_CMP_GE. */
#define FUTEX_WAKE_OP_MAX 4u
#define FUTEX_WAKE_CMP_MAX 5u

/*@
  assigns \nothing;
  ensures binary: \result == 0 || \result == 1;
  ensures exact: \result != 0 <==> op <= 4;
 */
static inline int futex_wake_op_supported(uint32_t op)
{
    return op <= FUTEX_WAKE_OP_MAX;
}

/*@
  assigns \nothing;
  ensures binary: \result == 0 || \result == 1;
  ensures exact: \result != 0 <==> cmp <= 5;
 */
static inline int futex_wake_cmp_supported(uint32_t cmp)
{
    return cmp <= FUTEX_WAKE_CMP_MAX;
}

/* The word uaddr2 takes. Every op is modular, so a sign-extended operand is
 * carried as its two's complement bits.
 *
 * The postconditions pin a value per op rather than a range: a body that
 * returned old_val throughout, which is what an unhandled op used to do, meets
 * a range and fails these.
 *
 * ANDN casts its complement back to uint32_t. Without the cast ACSL reads ~x as
 * -x-1, and relating a negative operand of & to the code times out.
 */
/*@
  requires supported: op <= 4;
  assigns \nothing;
  ensures set:  op == 0 ==> \result == op_val;
  ensures add:  op == 1 ==> \result == (uint32_t) (old_val + op_val);
  ensures or:   op == 2 ==> \result == (old_val | op_val);
  ensures andn: op == 3 ==> \result == (old_val & (uint32_t) ~op_val);
  ensures xor:  op == 4 ==> \result == (old_val ^ op_val);
 */
static inline uint32_t futex_wake_op_apply(uint32_t old_val,
                                           uint32_t op,
                                           uint32_t op_val)
{
    switch (op) {
    case 0:
        return op_val;
    case 1:
        return old_val + op_val;
    case 2:
        return old_val | op_val;
    case 3:
        return old_val & ~op_val;
    default:
        return old_val ^ op_val;
    }
}

/* Whether the second wake fires. The comparisons are signed, on the word as it
 * was before the modify above.
 */
/*@
  requires supported: cmp <= 5;
  assigns \nothing;
  ensures binary: \result == 0 || \result == 1;
  ensures eq: cmp == 0 ==> (\result != 0 <==> old_val == cmp_arg);
  ensures ne: cmp == 1 ==> (\result != 0 <==> old_val != cmp_arg);
  ensures lt: cmp == 2 ==> (\result != 0 <==> old_val <  cmp_arg);
  ensures le: cmp == 3 ==> (\result != 0 <==> old_val <= cmp_arg);
  ensures gt: cmp == 4 ==> (\result != 0 <==> old_val >  cmp_arg);
  ensures ge: cmp == 5 ==> (\result != 0 <==> old_val >= cmp_arg);
 */
static inline int futex_wake_op_cmp(int32_t old_val,
                                    uint32_t cmp,
                                    int32_t cmp_arg)
{
    switch (cmp) {
    case 0:
        return old_val == cmp_arg;
    case 1:
        return old_val != cmp_arg;
    case 2:
        return old_val < cmp_arg;
    case 3:
        return old_val <= cmp_arg;
    case 4:
        return old_val > cmp_arg;
    default:
        return old_val >= cmp_arg;
    }
}
