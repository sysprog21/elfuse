/*
 * The bucket set a futex_waitv call locks, split out of waitv_collect_buckets
 * in src/runtime/futex.c and proved here.
 *
 * sys_futex_waitv takes up to 128 guest-chosen addresses, hashes each to a
 * bucket, and locks the distinct buckets in ascending index order. Two entries
 * hashing alike is ordinary: there are 1024 buckets and the guest picks the
 * addresses. What holds the call together is that this set comes out sorted and
 * without repeats. A repeat locks one non-recursive mutex twice, and an
 * unsorted set takes the bucket locks out of order against every other futex
 * path.
 *
 * The insertion is proved rather than the walk around it: the walk's own bound
 * is nr_futexes, which sys_futex_waitv checks before it gets here.
 */
#pragma once

#include <stdint.h>

/*@
  predicate sorted_strict(unsigned *a, integer n) =
    \forall integer i, j; 0 <= i < j < n ==> a[i] < a[j];

  predicate holds(unsigned *a, integer n, unsigned v) =
    \exists integer k; 0 <= k < n && a[k] == v;
 */

/* Insert idx into a sorted, repeat-free prefix, and answer the new length.
 *
 * cap is the array's length rather than the caller's bound, so the shift below
 * is inside the object for any n the precondition allows.
 */
/*@
  requires room: n < cap;
  requires valid: \valid(ids + (0 .. cap - 1));
  requires sorted: sorted_strict(ids, n);
  assigns ids[0 .. cap - 1];
  ensures grows_by_at_most_one: \result == n || \result == n + 1;
  ensures still_sorted: sorted_strict(ids, \result);
  ensures present: holds(ids, \result, idx);
  ensures fresh_is_longer:
    \result == n + 1 <==> !\at(holds(ids, n, idx), Pre);
 */
static inline unsigned futex_bucket_insert(unsigned *ids,
                                           unsigned n,
                                           unsigned cap,
                                           unsigned idx)
{
    unsigned pos = 0;

    /*@
      loop invariant bound: 0 <= pos <= n;
      loop invariant below: \forall integer i; 0 <= i < pos ==> ids[i] < idx;
      loop assigns pos;
      loop variant n - pos;
     */
    while (pos < n && ids[pos] < idx)
        pos++;

    if (pos < n && ids[pos] == idx)
        return n;

    /* Nothing at or after pos equals idx either: the scan stopped at the first
     * entry not below idx, and the prefix is strictly increasing.
     */
    /*@ assert past: pos < n ==> ids[pos] > idx; */
    /*@ assert absent: !holds(ids, n, idx); */

    /*@
      loop invariant bound: pos <= j <= n;
      loop invariant shifted:
        \forall integer k; j < k <= n ==> ids[k] == \at(ids[k - 1], LoopEntry);
      loop invariant kept:
        \forall integer k; 0 <= k < j ==> ids[k] == \at(ids[k], LoopEntry);
      loop assigns j, ids[pos + 1 .. n];
      loop variant j - pos;
     */
    for (unsigned j = n; j > pos; j--)
        ids[j] = ids[j - 1];

    ids[pos] = idx;
    return n + 1;
}
