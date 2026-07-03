/* OCI layer applier: drive a tar stream into an unpack root
 *
 * Consumes oci_tar_entry_t records from oci_tar_reader_t (fed by the
 * decompression dispatch) and applies them under root_dir. Walks
 * entries in strict order so whiteouts and opaque markers interact
 * with prior upper-layer state correctly.
 *
 * Path containment rules mirror src/syscall/path.h::path_translate_at
 * from PR #33: reject `..` traversal in any path component, reject
 * absolute components past the layer root, and reject symlinks whose
 * resolved target would escape the unpack root. Lexical checks
 * (oci_path_join_safe + oci_symlink_target_check) reject `..` and
 * absolute paths up front, and every write resolves its parent chain
 * from a root dirfd one component at a time with openat(O_NOFOLLOW),
 * so a symlink planted by an earlier tar entry cannot redirect a later
 * entry's parent outside the unpack root.
 *
 * Whiteouts:
 *   .wh.<name>         remove the upper-layer entry <name> from this dir
 *   .wh..wh..opq       clear the containing dir's lower-layer contents
 *
 * Mode bits and uid/gid go into the running oci_meta_table_t; the host
 * inode is created with the running user's identity, and the sidecar
 * lookup at runtime restores the Linux view. Block, char, fifo, and
 * socket entries are rejected with ENOTSUP: an intentionally
 * asymmetric subset of the full tar entry-type space.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "oci/layer-meta.h"
#include "oci/tar.h"

typedef struct {
    size_t files;
    size_t dirs;
    size_t symlinks;
    size_t hardlinks;
    size_t whiteouts;
    size_t opaques;
} oci_layer_apply_stats_t;

/* Apply every entry from r into root_dir. root_dir must already exist
 * and be writable; the applier creates parent directories on demand.
 * stats and meta may be NULL; passing both lets the caller drive a
 * dry-run for fixture validation.
 *
 * Whiteout entries (.wh.<name>) and opaque markers (.wh..wh..opq) are
 * processed against root_dir: .wh.<name> rm-rfs the named upper-layer
 * entry, and .wh..wh..opq clears the marker's directory of lower-layer
 * contents. This is the canonical overlay-merge behaviour used by the
 * top-level oci_unpack assembly path. For populating a raw
 * per-layer cache where whiteout markers must remain on disk as files,
 * use oci_layer_apply_raw_tar instead.
 *
 * Returns 0 on success, -1 on error with *err set and errno carrying
 * one of:
 *   ENOTSUP        - tar entry type rejected (block/char/fifo/socket)
 *   ELOOP          - symlink target escapes the unpack root
 *   ENOLINK        - hardlink target was not seen earlier in the same
 *                    layer or as a previously-unpacked file under root
 *   ENAMETOOLONG   - assembled host path overflows PATH_MAX
 *   EINVAL         - tar entry path contains `..` or is absolute
 *   ENAMETOOLONG / EIO - tar reader / payload write surface
 */
int oci_layer_apply(oci_tar_reader_t *r,
                    const char *root_dir,
                    oci_layer_apply_stats_t *stats,
                    oci_meta_table_t *meta,
                    const char **err);

/* raw per-layer extract for the cross-image dedup cache.
 *
 * Identical to oci_layer_apply except .wh.<name> and .wh..wh..opq tar
 * entries are NOT interpreted as delete / clear directives: they fall
 * through to the regular-file dispatch and land on disk as 0-byte
 * regular files at their tar path. The on-disk shape of root_dir then
 * preserves the layer's whiteout intent for the later assembly pass
 * (the assembler walks the raw directory, applies whiteouts against
 * the running work_dir, then copies non-whiteout entries on top).
 *
 * Consequences vs overlay mode:
 *   - stats->whiteouts and stats->opaques stay at zero; the markers
 *     are counted in stats->files because they exist on disk as
 *     regular zero-length files
 *   - the per-layer oci_meta_table_t records the markers like any
 *     other regular file (uid/gid/mode tuples from the tar header)
 *   - root_dir is treated as a fresh extraction target: there is no
 *     pre-existing upper-layer state to delete or clear, so the
 *     whiteout branches would have been no-ops even if executed
 *
 * Returns 0 on success, -1 on error with the same errno surface as
 * oci_layer_apply (the dispatch and path validation logic is shared).
 */
int oci_layer_apply_raw_tar(oci_tar_reader_t *r,
                            const char *root_dir,
                            oci_layer_apply_stats_t *stats,
                            oci_meta_table_t *meta,
                            const char **err);

/* Compose root_dir + '/' + guest_path into out. Rejects:
 *   - leading '/' in guest_path (absolute is not allowed for tar entries)
 *   - any path component equal to `..` (escape)
 *   - empty path or `.` (no-op write target)
 *   - assembled length >= cap
 * Exposed for unit tests; the applier consumes it internally.
 */
int oci_path_join_safe(const char *root_dir,
                       const char *guest_path,
                       char *out,
                       size_t cap,
                       const char **err);

/* Validate that a symlink at link_dir pointing to target stays under
 * the unpack root if a follower started at link_dir. Pure string-level
 * analysis: parses absolute vs relative target, normalizes
 * `.`/`..`/empty segments, and asserts the running depth never drops
 * below zero relative to the unpack root.
 *
 * link_dir is the symlink's containing directory expressed as a
 * sysroot-relative path (without leading `/`), e.g. "etc/links" for a
 * symlink at "etc/links/foo". An empty link_dir means the symlink
 * lives directly under the unpack root.
 *
 * Returns 0 when the target is safe, -1 with errno=ELOOP otherwise.
 */
int oci_symlink_target_check(const char *link_dir, const char *target);
