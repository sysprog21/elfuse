/* OCI cross-image layer dedup metrics
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Computes how much of one image's layer set is shared with every other image
 * recorded in the local store. Two dedup angles are reported because the two
 * layer caches dedup along different axes:
 *
 *   - raw cache (layers/sha256/<diff_id>/) keys per-layer payloads by their
 *     uncompressed-tar digest. Two images that share a layer with the same
 *     diff_id share that cache entry regardless of where the layer sits in
 *     either image's ordered layer list. shared_layers counts individual
 *     layers; shared_bytes accumulates the on-disk size of the raw entries
 *     covering those shared diff_ids (entries the raw cache has actually
 *     populated; absent entries still count as shared layers, just with zero
 *     bytes).
 *
 *   - ChainID stack cache (layers/stacks/sha256/<chain_id>/) keys cumulative
 *     stage_dir snapshots by the OCI ChainID of the terminating layer in an
 *     ordered prefix. Two images can share a stack prefix only when their
 *     first K layers (in order) have identical diff_ids; ChainID composition
 *     captures that. deepest_shared_prefix reports the longest such prefix
 *     length the target shares with at least one other image. This is the
 *     same shape the unpack orchestrator short-circuits on.
 *
 * Output is informational, not a GC keep-set: missing or malformed image-
 * config blobs on the OTHER images are skipped silently rather than failing
 * the whole compute. Failure semantics are stricter for the TARGET image
 * (missing config or missing manifest blob is surfaced as -1) so the caller
 * can render a graceful-degrade notice instead of bogus numbers.
 *
 * `oci status` reuses this helper by calling it once per pin and
 * aggregating the results client-side.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "digest.h"
#include "store.h"

typedef struct {
    /* Number of layers in target's image-config rootfs.diff_ids. */
    size_t total_layers;
    /* |target.diff_ids ∩ union(other_image.diff_ids)|. A diff_id counted
     * here may or may not have a raw cache entry on disk: dedup is about
     * cross-image overlap, not cache populate state.
     */
    size_t shared_layers;
    /* Sum of <root>/layers/sha256/<diff_id>/ tree sizes for diff_ids in the
     * intersection that have an extant raw cache entry. Reports logical
     * bytes (sum of file st_size) rather than physical disk usage; APFS
     * clonefile means the on-disk footprint is typically much smaller.
     */
    uint64_t shared_bytes;
    /* Number of OTHER images that contributed at least one diff_id, deduped
     * by manifest digest so a pin and its unpacked sysroot for the same
     * manifest do not double-count. Excludes the target itself.
     */
    size_t compared_images;
    /* Longest K such that ChainID(target.diff_ids[0..K-1]) is also a
     * ChainID reached by some other image's diff_id chain. 0 means no
     * shared prefix.
     */
    size_t deepest_shared_prefix;
    /* The ChainID at depth deepest_shared_prefix, in "<algo>:<hex>" form.
     * Empty string when deepest_shared_prefix == 0. Sized for sha512-prefixed
     * output so the same buffer fits both digest algos plus the "<algo>:"
     * separator.
     */
    char deepest_shared_chainid[OCI_DIGEST_HEX_MAX + 16];
} oci_dedup_metrics_t;

/* Compute cross-image dedup metrics for one target image.
 *
 * target_manifest_digest: the manifest the caller is inspecting, in canonical
 *   "<algo>:<hex>" form. Must already be present under <store>/blobs/. For
 *   an image-index pin, the caller is responsible for resolving the per-
 *   platform sub-manifest first; this helper does not pick arm64 itself.
 *
 * volume_root: optional path to the unpacked-sysroot volume (the directory
 *   holding images/sha256-<hex>/). NULL skips the unpacked-tree walk and
 *   the compute uses only pins recorded in index.json. Missing volume_root
 *   or empty images/ subtree is treated as the empty case, not an error.
 *
 * out: receives the computed metrics on success; left zeroed on failure.
 *
 * Failure model (-1 with errno preserved and *err populated):
 *   - target manifest blob missing or unparseable
 *   - target image-config blob missing or unparseable
 *   - target image-config has no rootfs.diff_ids (spec violation)
 *   - allocation failure during walk
 *
 * Other-image failures (malformed config, missing blob, malformed origin
 * sidecar) are NOT surfaced: the offending image is skipped and the walk
 * continues. compared_images reflects only images that contributed at
 * least one usable diff_id list.
 */
int oci_dedup_metrics_compute(oci_store_t *store,
                              const char *target_manifest_digest,
                              const char *volume_root,
                              oci_dedup_metrics_t *out,
                              const char **err);
