/* OCI digest set implementation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Sorted-array set: add() performs a lower-bound scan with strcmp and
 * keeps the array ordered so contains() can use bsearch. The capacity
 * grows geometrically (x2) because the garbage collector collects up
 * to one entry per manifest + config + layer across every pinned
 * image plus every unpacked sysroot, and an O(n) realloc per add
 * would dominate that.
 */

#include "digest-set.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

void oci_digest_set_init(oci_digest_set_t *s)
{
    if (!s)
        return;
    s->items = NULL;
    s->count = 0;
    s->cap = 0;
}

void oci_digest_set_free(oci_digest_set_t *s)
{
    if (!s)
        return;
    if (s->items) {
        for (size_t i = 0; i < s->count; i++)
            free(s->items[i]);
        free((void *) s->items);
    }
    s->items = NULL;
    s->count = 0;
    s->cap = 0;
}

/* Locate the lower bound of digest in the sorted items[] range. Returns
 * an index in [0, count]; *found is true when items[idx] equals digest.
 */
static size_t lower_bound(const oci_digest_set_t *s,
                          const char *digest,
                          bool *found)
{
    size_t lo = 0, hi = s->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = strcmp(s->items[mid], digest);
        if (cmp < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    *found = lo < s->count && strcmp(s->items[lo], digest) == 0;
    return lo;
}

int oci_digest_set_add(oci_digest_set_t *s, const char *digest)
{
    if (!s || !digest) {
        errno = EINVAL;
        return -1;
    }
    bool found = false;
    size_t pos = lower_bound(s, digest, &found);
    if (found)
        return 0;

    if (s->count == s->cap) {
        size_t newcap = s->cap ? s->cap * 2 : 16;
        void *raw = realloc((void *) s->items, newcap * sizeof(*s->items));
        if (!raw) {
            errno = ENOMEM;
            return -1;
        }
        s->items = (char **) raw;
        s->cap = newcap;
    }

    char *copy = strdup(digest);
    if (!copy) {
        errno = ENOMEM;
        return -1;
    }
    /* Shift the tail right one slot so the new entry slides into its
     * sorted position. memmove handles the overlap; with pos == count
     * the move length is zero.
     */
    if (pos < s->count)
        memmove((void *) &s->items[pos + 1], (const void *) &s->items[pos],
                (s->count - pos) * sizeof(*s->items));
    s->items[pos] = copy;
    s->count++;
    return 0;
}

bool oci_digest_set_contains(const oci_digest_set_t *s, const char *digest)
{
    if (!s || !digest || s->count == 0)
        return false;
    bool found = false;
    (void) lower_bound(s, digest, &found);
    return found;
}

size_t oci_digest_set_size(const oci_digest_set_t *s)
{
    return s ? s->count : 0;
}

const char *oci_digest_set_at(const oci_digest_set_t *s, size_t i)
{
    if (!s || i >= s->count)
        return NULL;
    return s->items[i];
}
