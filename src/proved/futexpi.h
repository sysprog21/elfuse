/*
 * The PI lock word, split out of the FUTEX_LOCK_PI paths and robust_list_walk
 * in src/runtime/futex.c and proved here.
 *
 * Layout, which Linux fixes and a guest can write any bit pattern into:
 *
 *   bits 0-29  owner TID (FUTEX_TID_MASK)
 *   bit 30     FUTEX_OWNER_DIED
 *   bit 31     FUTEX_WAITERS
 *
 * The death transition is the one worth a contract rather than a mask: it has
 * to clear the TID, set OWNER_DIED and leave WAITERS alone, and an owner whose
 * waiters bit it dropped is a lock nobody is ever woken from.
 */
#pragma once

#include <stdint.h>

#define FUTEX_PI_TID_MASK 0x3FFFFFFFu
#define FUTEX_PI_OWNER_DIED 0x40000000u
#define FUTEX_PI_WAITERS 0x80000000u

/*@
  assigns \nothing;
  ensures bounded: \result <= 0x3FFFFFFF;
  ensures exact: \result == (word & 0x3FFFFFFF);
 */
static inline uint32_t futex_pi_owner_tid(uint32_t word)
{
    return word & FUTEX_PI_TID_MASK;
}

/*@
  assigns \nothing;
  ensures binary: \result == 0 || \result == 1;
  ensures exact: \result != 0 <==> (word & 0x3FFFFFFF) == 0;
 */
static inline int futex_pi_unowned(uint32_t word)
{
    return (word & FUTEX_PI_TID_MASK) == 0;
}

/*@
  assigns \nothing;
  ensures binary: \result == 0 || \result == 1;
  ensures exact: \result != 0 <==> (word & 0x40000000) != 0;
 */
static inline int futex_pi_owner_died(uint32_t word)
{
    return (word & FUTEX_PI_OWNER_DIED) != 0;
}

/* WAITERS is the top bit, so the three below read it as magnitude and edit it
 * as a remainder. Under the bitwise spelling the "leaves the rest alone"
 * clauses time out at 30s on both provers, the wall futexop.h documents; these
 * forms discharge. Nothing about the shipped code needs the bit operators.
 */
/*@
  assigns \nothing;
  ensures binary: \result == 0 || \result == 1;
  ensures exact: \result != 0 <==> word >= 0x80000000;
 */
static inline int futex_pi_has_waiters(uint32_t word)
{
    return word >= FUTEX_PI_WAITERS;
}

/* The two edits a waiter makes to the flag, neither of which may disturb the
 * owner field between them.
 */
/*@
  assigns \nothing;
  ensures set: \result >= 0x80000000;
  ensures others_kept: \result % 0x80000000 == word % 0x80000000;
 */
static inline uint32_t futex_pi_set_waiters(uint32_t word)
{
    return word % FUTEX_PI_WAITERS + FUTEX_PI_WAITERS;
}

/*@
  assigns \nothing;
  ensures clear: \result < 0x80000000;
  ensures others_kept: \result % 0x80000000 == word % 0x80000000;
 */
static inline uint32_t futex_pi_clear_waiters(uint32_t word)
{
    return word % FUTEX_PI_WAITERS;
}

/* What robust_list_walk writes over a lock whose owner exited holding it.
 *
 * Spelled the way handle_futex_death() in kernel/futex/core.c spells it. The
 * three postconditions pin every bit of the answer: the low 30 are zero, bit 30
 * is set, bit 31 is whatever it was.
 */
/*@
  assigns \nothing;
  ensures tid_cleared: (\result & 0x3FFFFFFF) == 0;
  ensures died_set: (\result & 0x40000000) != 0;
  ensures waiters_kept: \result >= 0x80000000 <==> word >= 0x80000000;
 */
static inline uint32_t futex_pi_mark_owner_died(uint32_t word)
{
    return (word >= FUTEX_PI_WAITERS ? FUTEX_PI_WAITERS : 0u) |
           FUTEX_PI_OWNER_DIED;
}
