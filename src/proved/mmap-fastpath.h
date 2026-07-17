/*
 * EL1 mmap fast-path arena sizing and capacity arithmetic: the parts a proof
 * can reach
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Each per-vCPU arena is a bump allocator: EL1 hands out [cursor, cursor+len)
 * and advances cursor until a request no longer fits, at which point the host
 * refills or grows the arena from the guest's own mmap history. Every value
 * here is guest-influenced (request_len is the guest's mmap length, window_max
 * is derived from a history of guest-chosen lengths), so a slip either wedges
 * the allocator (undersizes an arena forever) or, in
 * mmap_fastpath_request_fits, accepts a request that runs past arena_limit.
 *
 * Split out of mem.c because mem.c cannot be given to Frama-C: it includes
 * sys/mman.h and the HVF headers, which the analyzer's libc does not model.
 * These functions need nothing but stdint.h plus proved/align.h, so make
 * verify-mmapfastpath proves this header directly.
 *
 * MMAP_FAST_ARENA_MIN/MAX/TARGET_ENTRIES and MMAP_FAST_PUBLICATION_WINDOW live
 * here rather than in core/mmap-fastpath.h so the sizing policy has one
 * definition; core/mmap-fastpath.h includes this header for them rather than
 * repeating the numbers where a proof cannot see whether they still match.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "proved/align.h"

#define MMAP_FAST_ARENA_MIN (64ULL * 1024 * 1024)
#define MMAP_FAST_ARENA_MAX (32ULL * 1024 * 1024 * 1024)
#define MMAP_FAST_ARENA_TARGET_ENTRIES 32u

/* Registrations the arena sizer looks back over. Sixteen is long enough to
 * outlive a burst of one allocation size (so a phase change does not resize the
 * arena on its first mapping) and short enough that an outlier washes out
 * within a few dozen mappings.
 */
#define MMAP_FAST_PUBLICATION_WINDOW 16u

/* Whether a request of len bytes still fits the bump cursor before limit.
 *
 * Requests at least block_align wide are served block-aligned, matching the
 * fast path's block-granular VA carve (guest_invalidate_ptes clears a whole
 * block, so a sub-block bump allocation inside a block already carrying a live
 * mapping would straddle stale and fresh PTEs). Requests below that threshold
 * draw straight from cursor.
 *
 * len == 0 is its own case rather than falling out of the general fits test:
 * mmap_fastpath_topup_locked calls this with len == 0 to ask "is there any room
 * left", and an arena with cursor == limit has none, so that case needs cursor
 * < limit rather than window_fits's cursor <= limit (which would call a
 * completely full arena still fitting a zero-length request).
 *
 * Only the len >= block_align case is stated one-directionally (\result ==>
 * room existed at the unaligned cursor, not the converse): its true value comes
 * from align_up_ok, which bounds the aligned start (never_below,
 * rounds_up_once) rather than pinning it to a closed-form expression restated
 * here. That is enough to rule out the dangerous direction -- this function
 * reporting a fit that ends up past limit -- and chasing the converse would
 * mean re-deriving align_up_ok's own arithmetic in this contract instead of
 * resting on its proof.
 */
/*@
  requires block_align > 0;
  assigns \nothing;
  ensures zero_len:
    len == 0 ==> (\result <==> cursor < limit);
  ensures small_request:
    (len != 0 && len < block_align) ==>
      (\result <==> (cursor <= limit && len <= limit - cursor));
  ensures large_request_sound:
    (len != 0 && len >= block_align && \result) ==>
      (cursor <= limit && len <= limit - cursor);
 */
static inline bool mmap_fastpath_request_fits(uint64_t cursor,
                                              uint64_t limit,
                                              uint64_t len,
                                              uint64_t block_align)
{
    if (!len)
        return cursor < limit;
    uint64_t start = cursor;
    if (len >= block_align && !align_up_ok(cursor, block_align, &start))
        return false;
    return window_fits(start, len, limit);
}

/* Ratio the doubling loop below relies on: MMAP_FAST_ARENA_MAX is exactly
 * MMAP_FAST_ARENA_MIN doubled 9 times. Guards the loop's trip-count bound
 * against either constant changing without updating the other.
 */
_Static_assert(
    MMAP_FAST_ARENA_MAX == MMAP_FAST_ARENA_MIN * 512,
    "mmap_fastpath_pow2_clamped's loop bound assumes MAX == MIN << 9");

/*@
  axiomatic ArenaPow2 {
    logic integer arena_pow2(integer k);
    axiom arena_pow2_zero: arena_pow2(0) == 1;
    axiom arena_pow2_succ:
      \forall integer k; k >= 0 ==> arena_pow2(k + 1) == 2 * arena_pow2(k);
  }
*/

/* Smallest power of two in [MMAP_FAST_ARENA_MIN, MMAP_FAST_ARENA_MAX] that is
 * at least value, or the nearer bound when value falls outside that range.
 *
 * This used to be the classic bit-smear round-up-to-power-of-two (value--;
 * value |= value >> 1; ...; return value + 1;). Every claim reaching through
 * that form -- including a bound as simple as \result >= MMAP_FAST_ARENA_MIN --
 * turned out to be a bitvector-shaped goal (OR only sets bits, so value | value
 * >> k >= value for any k, but that is a property of the bit pattern, not of
 * linear arithmetic), and neither alt-ergo nor z3 discharges even a single OR
 * step of it here; proved/align.h's own history is the same shape one level
 * down. Same semantics, different algorithm: this doubles from
 * MMAP_FAST_ARENA_MIN instead, which is linear arithmetic all the way through
 * and discharges completely, including the power-of-two and covering properties
 * the smear form could not get past its two boundary branches. It costs at most
 * 9 iterations (see the _Static_assert above) where the smear was 6 fixed
 * shifts; both run once per arena refill, not per mmap, so the difference does
 * not reach the hot path this feeds.
 */
/*@
  assigns \nothing;
  ensures bounded_low: \result >= MMAP_FAST_ARENA_MIN;
  ensures bounded_high: \result <= MMAP_FAST_ARENA_MAX;
  ensures covers:
    value <= MMAP_FAST_ARENA_MAX ==> \result >= value;
  ensures clamp_low:
    value <= MMAP_FAST_ARENA_MIN ==> \result == MMAP_FAST_ARENA_MIN;
  ensures clamp_high:
    value >= MMAP_FAST_ARENA_MAX ==> \result == MMAP_FAST_ARENA_MAX;
 */
static inline uint64_t mmap_fastpath_pow2_clamped(uint64_t value)
{
    if (value <= MMAP_FAST_ARENA_MIN)
        return MMAP_FAST_ARENA_MIN;
    if (value >= MMAP_FAST_ARENA_MAX)
        return MMAP_FAST_ARENA_MAX;
    uint64_t p = MMAP_FAST_ARENA_MIN;
    /*@ ghost int k = 0; */
    /*@
      loop invariant p_eq: p == MMAP_FAST_ARENA_MIN * arena_pow2(k);
      loop invariant k_range: 0 <= k <= 9;
      loop assigns p, k;
      loop variant 9 - k;
    */
    while (p < value) {
        p += p;
        /*@ ghost k = k + 1; */
    }
    return p;
}

/* Largest registration still inside a fixed-size history window. window must
 * point at MMAP_FAST_PUBLICATION_WINDOW live entries; the caller passes
 * shim_mmap_control_t's publication_window array, which this header does not
 * name so it never has to see that struct's _Atomic fields.
 *
 * Only the upper bound is stated, not that \result is itself one of the
 * entries: a ghost witness index tracking argmax alongside max proves its own
 * base case and the two ensures it would support (both go through by taking the
 * invariant as given), but the loop-invariant preservation step itself times
 * out under both alt-ergo and z3 -- at 90s, ten times FRAMAC_TIMEOUT, not just
 * 30s -- while the plain upper-bound invariant below proves in milliseconds.
 * The upper bound is also the only property arena_size's sizing math actually
 * needs.
 */
/*@
  requires \valid_read(window + (0 .. MMAP_FAST_PUBLICATION_WINDOW - 1));
  assigns \nothing;
  ensures upper_bound:
    \forall integer i; 0 <= i < MMAP_FAST_PUBLICATION_WINDOW ==>
      window[i] <= \result;
 */
static inline uint64_t mmap_fastpath_window_max(
    const uint64_t window[MMAP_FAST_PUBLICATION_WINDOW])
{
    uint64_t max = 0;
    /*@
      loop invariant bound: 0 <= i <= MMAP_FAST_PUBLICATION_WINDOW;
      loop invariant prefix_le_max:
        \forall integer j; 0 <= j < i ==> window[j] <= max;
      loop assigns i, max;
      loop variant MMAP_FAST_PUBLICATION_WINDOW - i;
    */
    for (unsigned i = 0; i < MMAP_FAST_PUBLICATION_WINDOW; i++)
        if (window[i] > max)
            max = window[i];
    return max;
}

/* Target arena size covering both the recent registration history (window_max)
 * and the request that is about to be served (request_len), clamped to
 * [MMAP_FAST_ARENA_MIN, MMAP_FAST_ARENA_MAX].
 *
 * The bound ensures below rest on mmap_fastpath_pow2_clamped's own
 * bounded_low/bounded_high: adaptive and covering are each either
 * MMAP_FAST_ARENA_MIN (the guard's false branch) or a pow2_clamped result, both
 * now fully covered by that function's contract. -wp-rte separately proves this
 * function's own arithmetic sound regardless: the two multiplication guards
 * (window_max > MAX / target_entries, request_len > MAX / 2) mean neither
 * window_max * target_entries nor request_len * 2 can overflow, and there is no
 * division-by-zero.
 */
/*@
  assigns \nothing;
  ensures result_ge_min: \result >= MMAP_FAST_ARENA_MIN;
  ensures result_le_max: \result <= MMAP_FAST_ARENA_MAX;
 */
static inline uint64_t mmap_fastpath_arena_size(uint64_t window_max,
                                                uint64_t request_len)
{
    uint64_t adaptive = MMAP_FAST_ARENA_MIN;
    if (window_max) {
        const uint64_t target_entries = MMAP_FAST_ARENA_TARGET_ENTRIES;
        uint64_t target = window_max > MMAP_FAST_ARENA_MAX / target_entries
                              ? MMAP_FAST_ARENA_MAX
                              : window_max * target_entries;
        adaptive = mmap_fastpath_pow2_clamped(target);
    }

    uint64_t covering = MMAP_FAST_ARENA_MIN;
    if (request_len) {
        uint64_t target = request_len > MMAP_FAST_ARENA_MAX / 2
                              ? MMAP_FAST_ARENA_MAX
                              : request_len * 2;
        covering = mmap_fastpath_pow2_clamped(target);
    }
    return adaptive > covering ? adaptive : covering;
}
