/* OCI / Docker media-type canonicalization
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * OCI image references carry media-type strings on every descriptor. The
 * registry client, manifest parser, and unpack stage all branch on the media
 * type, so a single canonical enum lookup keeps the comparisons one place
 * away from string typos. Docker registries continue to serve the legacy
 * docker-namespaced media types (vnd.docker.distribution.manifest.v2+json)
 * even when the image-spec wire format is OCI v1; the table accepts both.
 *
 * Foreign (nondistributable) layers are recognized but classified as
 * unsupported: elfuse cannot fetch the out-of-band payload those
 * layers reference, so rejecting them at parse time is the honest
 * answer rather than carrying a half-supported code path.
 */

#pragma once

#include <stdbool.h>

typedef enum {
    OCI_MT_UNKNOWN = 0,

    /* Manifest documents (single platform). */
    OCI_MT_MANIFEST_OCI,
    OCI_MT_MANIFEST_DOCKER,

    /* Image index / manifest list (multi-platform). */
    OCI_MT_INDEX_OCI,
    OCI_MT_INDEX_DOCKER,

    /* Image config blob. */
    OCI_MT_CONFIG_OCI,
    OCI_MT_CONFIG_DOCKER,

    /* Layer blobs that elfuse can actually consume. */
    OCI_MT_LAYER_OCI_TAR,
    OCI_MT_LAYER_OCI_TAR_GZIP,
    OCI_MT_LAYER_OCI_TAR_ZSTD,
    OCI_MT_LAYER_DOCKER_TAR_GZIP,
    OCI_MT_LAYER_DOCKER_TAR_ZSTD,

    /* Foreign layers: distinguishable but explicitly unsupported. */
    OCI_MT_LAYER_FOREIGN_OCI,
    OCI_MT_LAYER_FOREIGN_OCI_GZIP,
    OCI_MT_LAYER_FOREIGN_DOCKER,
    OCI_MT_LAYER_FOREIGN_DOCKER_GZIP,
} oci_media_type_t;

typedef enum {
    OCI_COMPRESSION_NONE,
    OCI_COMPRESSION_GZIP,
    OCI_COMPRESSION_ZSTD,
} oci_compression_t;

/* Classify a media-type string. Trailing parameters after ';' (e.g. charset)
 * are stripped before matching; surrounding whitespace is ignored. Returns
 * OCI_MT_UNKNOWN for any string not in the recognized table. NULL is treated
 * as OCI_MT_UNKNOWN.
 */
oci_media_type_t oci_media_type_parse(const char *s);

/* Lookup the canonical name string for a media-type enum. Returns NULL for
 * OCI_MT_UNKNOWN or an out-of-range enum value. The returned pointer is to
 * static storage.
 */
const char *oci_media_type_name(oci_media_type_t mt);

/* Predicates by document category. Each returns false for OCI_MT_UNKNOWN. */
bool oci_media_type_is_manifest(oci_media_type_t mt);
bool oci_media_type_is_index(oci_media_type_t mt);
bool oci_media_type_is_config(oci_media_type_t mt);
bool oci_media_type_is_layer(oci_media_type_t mt);

/* True when the layer media type is one elfuse can actually decode. Foreign
 * layers and OCI_MT_UNKNOWN return false; the manifest parser rejects layer
 * descriptors that fail this check.
 */
bool oci_media_type_is_layer_supported(oci_media_type_t mt);

/* True for the four foreign-layer media types. The manifest parser keeps
 * these distinguishable so the error message can name the actual layer type
 * instead of a generic 'unsupported'.
 */
bool oci_media_type_is_foreign(oci_media_type_t mt);

/* Compression algorithm carried by a layer media type. Non-layer or unknown
 * inputs return OCI_COMPRESSION_NONE; callers should gate on
 * oci_media_type_is_layer first.
 */
oci_compression_t oci_media_type_compression(oci_media_type_t mt);
