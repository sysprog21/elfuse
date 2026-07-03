/* OCI stack cache back-fill for legacy unpacked sysroots
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The ChainID-keyed stack cache lives at
 * <store>/layers/stacks/sha256/<chain_hex>/ so a re-unpack of any image whose
 * layer prefix matches an already-extracted tree short-circuits the per-
 * layer apply loop into a single APFS clonefile restore. The cache only
 * grows as a side effect of oci_unpack, which means any image that was
 * unpacked before the stack cache existed (or that was unpacked into a
 * store whose schema marker had just wiped older entries) leaves no
 * stack snapshot on disk: the next unpack still pays the full extract
 * cost even though a usable assembled stage_dir already sits under
 * <volume>/images/sha256-<hex>/.
 *
 * oci_rebuild_cache walks every unpacked sysroot under <volume>/images/,
 * reads its .elfuse-origin.json sidecar to recover the original layer
 * diff_id ordering, recomputes ChainID for the terminating layer, and (when
 * commit is true) clonefiles the tree into a fresh stack cache entry keyed
 * by that ChainID. Subsequent unpacks of any image sharing the same ordered
 * layer list short-circuit immediately. Intermediate-prefix entries are NOT
 * back-filled because an unpacked tree only captures the final overlay
 * state; the per-layer raw cache <store>/layers/sha256/<diff_id>/ similarly
 * remains empty until a re-pull + re-unpack of the source image repopulates
 * it.
 *
 * The walk is purely additive: existing stack cache entries are never
 * modified or deleted, and the rename(2) used by oci_store_stack_commit
 * treats EEXIST as a benign loss to a racing writer so repeated invocations
 * are idempotent. No interaction with raw cache entries, blob storage, or
 * pin metadata; rebuild-cache only manipulates layers/stacks/.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "store.h"

/* Inputs and outputs for oci_rebuild_cache. Output counters are zeroed on
 * entry so a caller can render a uniform report regardless of dry-run vs
 * commit, and they reflect the same "what would happen" view: a dry-run
 * reports trees_rebuilt as the number of trees that WOULD have landed a
 * stack snapshot, while a commit run reports the number that actually did.
 * trees_failed counts trees whose snapshot pipeline (chainid compute,
 * clonefile, stack_commit) raised an error and which were therefore left
 * out of trees_rebuilt; the offending tree is reported on stderr and the
 * walk continues so a single bad tree does not abort the whole back-fill.
 */
typedef struct {
    /* Inputs */
    bool commit; /* false = dry-run, true = back-fill */

    /* Outputs */
    size_t trees_scanned; /* candidates encountered under images/ */
    size_t trees_rebuilt; /* would-rebuild (dry-run) or rebuilt (commit) */
    size_t trees_skipped_cached;    /* terminating ChainID already on disk */
    size_t trees_skipped_no_origin; /* .elfuse-origin.json missing (ENOENT) */
    size_t
        trees_skipped_bad_origin; /* origin sidecar parse or schema failure */
    size_t trees_skipped_empty_diffids; /* origin diff_ids array is empty */
    size_t trees_failed;        /* chainid_compute / clonefile / commit IO */
    size_t stack_entries_added; /* sum across rebuilt trees */
} oci_rebuild_cache_options_t;

/* Walk <volume_root>/images/sha256-<hex>/ and back-fill the stack cache
 * entry at <store>/layers/stacks/sha256/<terminating_chainid>/ for every
 * tree whose .elfuse-origin.json carries a non-empty layer_diffids array
 * and whose terminating ChainID is not already on disk.
 *
 * volume_root may be NULL; in that case oci_volume_list_unpacked treats the
 * request as the empty case and trees_scanned stays 0. A missing
 * <volume_root>/images/ directory is also treated as empty.
 *
 * The walk uses oci_volume_list_unpacked to enumerate candidates; only
 * directories shaped sha256-<lowercase-hex> are returned, so dotfiles and
 * the .staging/ subtree are skipped automatically.
 *
 * The unpacked tree contains .elfuse-origin.json (written by oci_unpack
 * AFTER the stack snapshot is taken on the fresh-unpack path). The
 * back-fill strips that file from the staged snapshot before commit so a
 * rebuilt stack cache entry is byte-identical to a fresh-unpack one.
 *
 * Failure policy:
 *   - per-tree origin read failure (ENOENT vs other) is counted in
 *     trees_skipped_no_origin / trees_skipped_bad_origin and the walk
 *     continues.
 *   - per-tree chainid_compute, clonefile, or stack_commit failure is
 *     counted in trees_failed and the walk continues. A diagnostic line is
 *     written to stderr identifying the tree path.
 *   - listing failure (failure to traverse images/) returns -1 with errno
 *     preserved and *err populated; opts->trees_scanned reflects the trees
 *     processed before the failure surfaced.
 *
 * Returns 0 on success and -1 on listing-level failure. err may be NULL.
 */
int oci_rebuild_cache(oci_store_t *store,
                      const char *volume_root,
                      oci_rebuild_cache_options_t *opts,
                      const char **err);
