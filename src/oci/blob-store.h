/* Content-addressable blob store for OCI image data
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Layout matches the OCI image-layout convention:
 *
 *   <root>/blobs/<algo>/<hex>     finalized blob, immutable
 *   <root>/tmp/blob-put-XXXXXX    in-flight staging file
 *
 * Every blob is committed by writing a staging file, fsync'ing it, hashing
 * the bytes, comparing the actual hex to the expected hex from the manifest
 * descriptor, and then publishing via link(2) into the final
 * blobs/<algo>/<hex> slot. link(2) rather than rename(2): a second writer
 * racing on the same digest cannot silently overwrite a blob another
 * process already finalized; link returning EEXIST is a dedup hit and both
 * clients report success. A digest mismatch unlinks the staging file before
 * returning -1, so a hostile or corrupt source leaves no visible-complete
 * blob behind.
 *
 * Registry transfer writes blobs through skopeo (see pull.h), not through
 * this API; the store writes only its own small documents (manifests,
 * configs, fixture layers), so the single whole-buffer entry point below
 * replaces the streaming/resumable writer the in-tree registry client once
 * needed.
 *
 * The store path is opaque to this module; the caller picks it.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "digest.h"

typedef struct oci_blob_store oci_blob_store_t;

/* Open or create the store rooted at `root`. The directory tree (root,
 * blobs/<algo>, tmp) is created with mode 0755 if missing. Returns NULL on
 * failure with errno preserved.
 */
oci_blob_store_t *oci_blob_store_open(const char *root);

/* Release the store handle. Does not delete on-disk state. Safe on NULL. */
void oci_blob_store_close(oci_blob_store_t *s);

/* Resolve the final on-disk path for algo:hex. Returns the number of bytes
 * the full path occupies excluding the trailing NUL, or -1 if algo or hex
 * is malformed. Always writes a NUL terminator when out_size > 0; if the
 * full path does not fit, out is truncated but still NUL-terminated and the
 * caller can detect overflow by comparing the return value to out_size.
 */
int oci_blob_store_path(const oci_blob_store_t *s,
                        oci_digest_algo_t algo,
                        const char *hex,
                        char *out,
                        size_t out_size);

/* True when blobs/<algo>/<hex> exists as a regular file. */
bool oci_blob_store_has(const oci_blob_store_t *s,
                        oci_digest_algo_t algo,
                        const char *hex);

/* Write a memory buffer into the store: hash, verify against expected_hex,
 * stage under tmp/, fsync, publish via link(2). Returns 0 on success
 * (including the dedup hit where the blob already exists) or -1 with errno
 * preserved; a digest mismatch reports EINVAL and leaves no staging file.
 */
int oci_blob_store_put_bytes(oci_blob_store_t *s,
                             oci_digest_algo_t algo,
                             const char *expected_hex,
                             const void *buf,
                             size_t len);
