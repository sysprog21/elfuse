/* OCI unpacked-tree provenance sidecar
 *
 * Records which manifest produced an unpacked image directory so the
 * garbage collector can walk unpacked sysroots and recover the
 * full set of blobs (manifest, image-config, layer tars + diff-id
 * pre-images) still referenced by on-disk state. Without this file the
 * mark phase has no way to attribute an unpacked tree back to a stored
 * manifest, and a prune sweep would happily delete layer blobs that are
 * still backing a live sysroot.
 *
 * Serialization format: <root_dir>/.elfuse-origin.json with the shape
 *   { "manifest_digest": "sha256:...",
 *     "config_digest":   "sha256:...",
 *     "layer_diffids":   ["sha256:...", "sha256:..."] }
 *
 * The diff_ids come from the image-config blob's rootfs.diff_ids field,
 * not from the manifest's layer descriptors: per the OCI image spec a
 * diff_id is the digest of the uncompressed layer tar, while the
 * manifest's layer.digest references the (possibly compressed) blob on
 * disk. Recording both lets the root-set walker map each unpacked
 * tree back to every blob it depends on regardless of layer media
 * type.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

/* Parsed contents of an unpacked image tree's .elfuse-origin.json. All
 * three fields are heap-allocated and owned by the struct: free via
 * oci_origin_free. layer_diffids is a NULL-terminated array of
 * "<algo>:<hex>" strings; the array itself is malloc'd and so is every
 * entry. An image with zero layers parses to a one-element array
 * containing only the NULL terminator.
 */
typedef struct {
    char *manifest_digest;
    char *config_digest;
    char **layer_diffids;
} oci_origin_t;

/* Write <root_dir>/.elfuse-origin.json via atomic rename. manifest_digest
 * and config_digest are NUL-terminated "<algo>:<hex>" strings; diff_ids
 * is a NULL-terminated array of the same form (an empty array is
 * permitted and serializes to []). Returns 0 on success, -1 on failure
 * with errno set and *err pointing to a static diagnostic. err may be
 * NULL.
 */
int oci_origin_write(const char *root_dir,
                     const char *manifest_digest,
                     const char *config_digest,
                     char *const *diff_ids,
                     const char **err);

/* Read <root_dir>/.elfuse-origin.json into *out. The struct is
 * populated only on success; on failure out is left zeroed. Validates
 * that manifest_digest and config_digest are present and string-typed
 * and that layer_diffids is an array of strings; missing or
 * mistyped fields surface as -1 with errno=EINVAL so the garbage
 * collector treats a malformed sidecar as a fatal root-set hole rather
 * than silently dropping the tree's blobs from the keep set. Returns 0
 * on success, -1 on failure with errno set and *err pointing to a
 * static diagnostic. err may be NULL.
 */
int oci_origin_read(const char *root_dir, oci_origin_t *out, const char **err);

/* Release every heap field in o and zero the struct. Safe on a
 * zero-initialised struct and on NULL.
 */
void oci_origin_free(oci_origin_t *o);
