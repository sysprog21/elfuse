/*
 * Alignment and window arithmetic: the parts a proof can reach
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The mmap gap finder walks the sorted region array rounding a candidate
 * address past each region it collides with, and asks twice whether a length
 * still fits before the end of the search window. Both operations are one
 * expression, and both are wrong in the same way at the top of the address
 * space: ALIGN_UP in src/utils.h is "(x + a - 1) & ~(a - 1)", which wraps to a
 * small value rather than saturating, and a fits test written as "start +
 * length <= limit" has already overflowed by the time it is read.
 *
 * A wrapped round-up in the gap finder is not a crash. It is an allocation
 * whose start address sits below regions the walk already passed, so the guest
 * gets a mapping overlapping one it already holds. Guest addresses are bounded
 * by guest_size, at most 1 TiB, so neither wrap is reachable today: unreachable
 * by provenance rather than by construction, which is the state this header
 * exists to change.
 *
 * The align-up is written with division rather than the mask, so the proof does
 * not first have to establish that the alignment is one less than a power of
 * two, and so a caller passing a non-power-of-two alignment still gets a
 * defined answer. That is not free here, and the comparison to
 * src/proved/netlink.h does not carry: netlink's alignment is the literal 4, so
 * the compiler folds the division away, while this one arrives as a parameter
 * (a host page size or BLOCK_2MIB) and compiles to a real UDIV. The gap walk
 * pays one per region it steps past, under mmap_lock, where ALIGN_UP cost two
 * ALU ops. The trade is deliberate: the mask form makes "the result is at least
 * x" a bitvector goal that neither prover here discharges, and an unproved wrap
 * in this function is a guest mapping that overlaps one it already holds. If
 * the walk ever shows up in an mmap profile, the fix is to prove the mask form
 * under a power-of-two precondition, not to drop back to ALIGN_UP.
 *
 * Split into a header because mem.c cannot be given to Frama-C: it includes the
 * macOS mman and HVF headers, which the analyzer's libc does not model. This
 * header needs nothing but stdint.h, so make verify-align proves it directly.
 */

#pragma once

#include <stdint.h>

/* Round an address up to the next multiple of align, or 0 when that would carry
 * past the end of the address space.
 *
 * Rejects exactly the inputs with no answer, which the pad-then-mask shape used
 * elsewhere (netlink_align_up) does not: padding by align - 1 before testing
 * refuses an address that is already a multiple and sits within align - 1 of
 * UINT64_MAX, even though rounding it up is a no-op that cannot overflow. That
 * takes a non-power-of-two align to reach, so the mmap gap finder never saw it,
 * but a rejection wider than the arithmetic requires is the kind of thing a
 * caller ends up encoding around.
 */
/*@
  requires align > 0;
  requires \valid(out);
  assigns *out;
  ensures binary: \result == 0 || \result == 1;
  ensures rejects_only_on_wrap:
            \result != 0 <==> (x % align == 0
                              || x / align < UINT64_MAX / align);
  ensures aligned:
            \result != 0 ==> (\exists integer k; *out == k * align);
  ensures never_below: \result != 0 ==> *out >= x;
  ensures rounds_up_once: \result != 0 ==> *out < x + align;
  ensures untouched_on_reject: \result == 0 ==> *out == \old(*out);
 */
static inline int align_up_ok(uint64_t x, uint64_t align, uint64_t *out)
{
    uint64_t k = x / align;

    /* Counting in multiples rather than padding the address is what keeps the
     * rejection exact. Padding by align - 1 first, then masking down, refuses
     * an x that is already a multiple and sits within align - 1 of the top,
     * because the pad overflows even though no rounding was needed.
     *
     * One assignment of the k * align form, so the alignment postcondition has
     * its own witness. Stating it as "*out % align == 0" instead leaves a
     * divisibility goal over a symbolic modulus, which neither alt-ergo nor z3
     * discharges in 30s; so does reaching the same value by adding align to a
     * floor computed earlier, which needs distributivity the provers do not
     * apply here.
     */
    if (k * align != x) {
        if (k >= UINT64_MAX / align)
            return 0;
        k++;
    }

    *out = k * align;
    return 1;
}

/* Whether [start, start + length) fits below limit.
 *
 * The subtraction form is the point. "start + length <= limit" is the form that
 * reads naturally and admits a length large enough to wrap the sum, which turns
 * a rejected allocation into an accepted one that runs off the end of the
 * window.
 */
/*@
  assigns \nothing;
  ensures binary: \result == 0 || \result == 1;
  ensures exact: \result != 0 <==> (start <= limit && length <= limit - start);
  ensures fits: \result != 0 ==> start + length <= limit;
  ensures no_wrap: \result != 0 ==> start + length >= start;
 */
static inline int window_fits(uint64_t start, uint64_t length, uint64_t limit)
{
    return start <= limit && length <= limit - start;
}
