/* OCI digest set
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Append-only ordered set of "<algo>:<hex>" digest strings, used by the
 * garbage collector to accumulate the reachable blob set across pin
 * walks, image-config blobs, and unpacked-sysroot origin sidecars.
 *
 * Storage is a sorted, strdup-owned C array. Membership is checked via
 * bsearch and insertion uses lower-bound + memmove. The expected
 * working size is in the low hundreds (one entry per manifest, config,
 * and layer blob across all pinned images), so O(n) per insertion is
 * cheap. The sweep walks blobs/<algo>/<hex> and calls contains() once
 * per blob, which bsearch makes O(log n). If profiling later
 * proves the set hot enough to matter, swap to a hash table without
 * touching the public API.
 *
 * The set treats digest strings as opaque bytes: the caller is
 * expected to feed only validated "<algo>:<hex>" forms produced by
 * oci_digest_parse so a hand-edited index.json cannot smuggle in an
 * uppercase variant that defeats the dedup.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char **items;
    size_t count;
    size_t cap;
} oci_digest_set_t;

/* Zero-initialise a set in place. Safe to call on a struct that was
 * declared with {0}; provided for readability at allocation sites.
 */
void oci_digest_set_init(oci_digest_set_t *s);

/* Release every owned digest string and zero the struct. Safe on a
 * zero-initialised set and on NULL.
 */
void oci_digest_set_free(oci_digest_set_t *s);

/* Insert digest into the set. Returns 0 on success or when the digest
 * is already present (idempotent), -1 with errno set on failure. A
 * NULL digest is rejected with EINVAL so a caller bug does not leak
 * into the sweep phase later.
 */
int oci_digest_set_add(oci_digest_set_t *s, const char *digest);

/* True when digest is in the set. NULL inputs return false. */
bool oci_digest_set_contains(const oci_digest_set_t *s, const char *digest);

/* Current cardinality of the set. */
size_t oci_digest_set_size(const oci_digest_set_t *s);

/* Borrow the digest string at index i (lexicographically ordered). The
 * returned pointer is valid until the next mutating call or free.
 * Returns NULL when i is out of range.
 */
const char *oci_digest_set_at(const oci_digest_set_t *s, size_t i);
