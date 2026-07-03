/* OCI layer unpack orchestrator
 *
 * Drives the full pipeline: resolve a ref to a manifest digest through
 * oci_store, read the manifest from the blob store, walk its layers,
 * re-verify each layer blob's digest, and apply via oci_layer_apply
 * (which reads gzip/zstd/uncompressed tar through libarchive) into a
 * staging directory under the sysroot volume's images/.staging/
 * subtree. Successful unpack commits via atomic rename into
 * images/sha256-<hex>/.
 *
 * `elfuse oci run IMAGE` consumes the resulting directory
 * automatically; the directory can also be wired manually through
 * `elfuse --sysroot <path>`.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>

#include "oci/blob-store.h"
#include "oci/layer-apply.h"
#include "oci/layer-meta.h"
#include "oci/manifest.h"
#include "oci/ref.h"
#include "oci/store.h"

typedef struct {
    const char *volume_root; /* NULL -> default sparse APFS volume */
    bool quiet;
    bool force_relayer;
} oci_unpack_options_t;

/* Apply one OCI layer's tar payload into stage_dir as a pure overlay
 * extract.
 *
 * Re-verifies the compressed blob digest against desc, opens the blob
 * via the running blob store, decompresses per desc->media_type, then
 * drives oci_layer_apply (overlay mode) against stage_dir. stage_dir
 * must already exist and be writable; the helper does not mkdir it.
 *
 * Whiteout and opaque tar entries are processed by oci_layer_apply
 * with overlay semantics: ".wh.<name>" deletes upper-layer state in
 * stage_dir; ".wh..wh..opq" clears the containing directory. This
 * helper has no concern with caches; moved all cache
 * orchestration up into oci_unpack itself, which drives raw-tar
 * populate via oci_unpack_layer_raw and assembles via
 * oci_unpack_assemble_layer.
 *
 * Parameters:
 *   bs         - blob store backing the layer payload.
 *   desc       - layer descriptor; algo / hex / media_type / size used.
 *   stage_dir  - destination directory, absolute path, no trailing '/'.
 *   stats      - optional; per-layer counters are summed when non-NULL.
 *   meta       - optional; tar uid/gid/mode entries recorded when non-NULL.
 *   log_label  - optional; when non-NULL the helper prints
 *                "<label>: <digest>" plus a stats line to stderr so
 *                multi-layer driver loops do not re-implement the format.
 *   err        - on failure receives a static diagnostic string.
 *
 * Returns 0 on success, -1 with errno set on failure. Notable errno values:
 *   ENOTSUP    foreign / nondistributable layer media type
 *   EINVAL     compressed blob digest mismatch or malformed media type
 *   ENOENT     blob missing from store
 *   ELOOP      tar entry escapes stage_dir via symlink
 *   ENOLINK    tar hardlink target not seen
 *   ENAMETOOLONG  assembled path overflow
 */
int oci_unpack_layer(oci_blob_store_t *bs,
                     const oci_descriptor_t *desc,
                     const char *stage_dir,
                     oci_layer_apply_stats_t *stats,
                     oci_meta_table_t *meta,
                     const char *log_label,
                     const char **err);

/* raw-tar populate primitive for the per-layer cache.
 *
 * Identical to oci_unpack_layer except the underlying applier is
 * oci_layer_apply_raw_tar, so ".wh.<name>" and ".wh..wh..opq" tar
 * entries land on disk as zero-byte regular files at their tar path
 * instead of executing overlay-style delete / clear directives. The
 * resulting raw_dir captures the layer's bytes-on-the-wire shape and
 * is what the per-layer cache <root>/layers/<algo>/<hex>/ stores after
 * the orchestrator commits it via oci_store_layer_commit.
 *
 * The caller MUST mkdir raw_dir before the call (this helper does not
 * create it). On error raw_dir is left in whatever partial state the
 * applier reached; the caller is responsible for rm-rf'ing it.
 *
 * Parameters and errno surface match oci_unpack_layer except for one
 * removal: there is no whiteout interpretation, so whiteout-marker
 * preservation cannot fail with ELOOP from a fake symlink target.
 */
int oci_unpack_layer_raw(oci_blob_store_t *bs,
                         const oci_descriptor_t *desc,
                         const char *raw_dir,
                         oci_layer_apply_stats_t *stats,
                         oci_meta_table_t *meta,
                         const char *log_label,
                         const char **err);

/* two-pass overlay assembly from a raw per-layer cache
 * entry onto a running stage_dir.
 *
 * Walks raw_dir twice. Pass 1 interprets whiteout markers ".wh.<name>"
 * (rm -rf the named upper-layer entry under stage_dir) and
 * ".wh..wh..opq" (clear the marker's parent directory of lower-layer
 * contents while preserving the directory itself). Pass 2 copies every
 * non-whiteout entry onto stage_dir via clonefile(CLONE_NOFOLLOW). The
 * two-pass discipline makes the result independent of readdir order so
 * an opaque marker can apply before sibling content within the same
 * layer payload.
 *
 * Both passes skip the layer's per-cache meta sidecar file
 * (".elfuse-meta.layer.json") because it is bookkeeping rather than
 * tar content.
 *
 * Known limitation: tar-level hardlink relationships are not
 * reconstructed by the assembler. Each per-file
 * clonefile produces an independent inode under stage_dir; APFS COW
 * keeps the on-disk byte cost flat regardless.
 *
 * raw_dir and stage_dir must both exist as directories. Returns 0 on
 * success, -1 with errno set and *err populated on failure. Notable
 * errno values:
 *   EINVAL        a NULL argument
 *   EXDEV         clonefile crossed an APFS volume boundary
 *   ENAMETOOLONG  assembled path exceeded the internal PATH_MAX
 *   EIO / etc.    bubbled up from the underlying VFS calls
 */
int oci_unpack_assemble_layer(const char *raw_dir,
                              const char *stage_dir,
                              const char **err);

/* Unpack the manifest pinned by ref into the sysroot volume's images/
 * subtree. The pin must already exist (set by a prior `oci pull`).
 *
 * Returns 0 on success and writes a heap-allocated absolute path to
 * the unpacked image sysroot into *out_image_dir (caller frees). The
 * path always ends with '/' so a downstream
 *
 *   strcat(out_image_dir, "lib/...")
 *
 * composes cleanly.
 *
 * Returns -1 with errno set and *err pointing to a static description
 * on failure. Notable errno values surfaced to the CLI:
 *   ENOENT      pin missing (caller should suggest `oci pull` first)
 *   EINVAL      manifest malformed, override volume not case-sensitive,
 *               or layer digest re-verify mismatch
 *   ENOTSUP    unsupported tar entry type in a layer
 *   ELOOP       symlink escape detected during apply
 *   ENOLINK    hardlink target missing
 *   EPROTONOSUPPORT  tar PAX records encountered
 */
int oci_unpack(oci_store_t *store,
               const oci_ref_t *ref,
               const oci_unpack_options_t *opts,
               char **out_image_dir,
               const char **err);
