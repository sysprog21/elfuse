/* OCI / Docker media-type canonicalization
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "media-type.h"

#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

struct mt_entry {
    const char *name;
    oci_media_type_t kind;
};

/* All recognized OCI and Docker media types in a single table. Order has no
 * semantic meaning; the lookup is linear because the table is small (~16
 * entries) and runs at most once per descriptor parse.
 */
static const struct mt_entry MEDIA_TYPES[] = {
    /* Manifest documents. */
    {"application/vnd.oci.image.manifest.v1+json", OCI_MT_MANIFEST_OCI},
    {"application/vnd.docker.distribution.manifest.v2+json",
     OCI_MT_MANIFEST_DOCKER},

    /* Image indexes / manifest lists. */
    {"application/vnd.oci.image.index.v1+json", OCI_MT_INDEX_OCI},
    {"application/vnd.docker.distribution.manifest.list.v2+json",
     OCI_MT_INDEX_DOCKER},

    /* Image config. */
    {"application/vnd.oci.image.config.v1+json", OCI_MT_CONFIG_OCI},
    {"application/vnd.docker.container.image.v1+json", OCI_MT_CONFIG_DOCKER},

    /* Supported layer payloads. */
    {"application/vnd.oci.image.layer.v1.tar", OCI_MT_LAYER_OCI_TAR},
    {"application/vnd.oci.image.layer.v1.tar+gzip", OCI_MT_LAYER_OCI_TAR_GZIP},
    {"application/vnd.oci.image.layer.v1.tar+zstd", OCI_MT_LAYER_OCI_TAR_ZSTD},
    {"application/vnd.docker.image.rootfs.diff.tar.gzip",
     OCI_MT_LAYER_DOCKER_TAR_GZIP},
    {"application/vnd.docker.image.rootfs.diff.tar.zstd",
     OCI_MT_LAYER_DOCKER_TAR_ZSTD},

    /* Foreign (nondistributable) layers. Recognized so the parser can produce
     * a precise rejection message instead of falling through to UNKNOWN.
     */
    {"application/vnd.oci.image.layer.nondistributable.v1.tar",
     OCI_MT_LAYER_FOREIGN_OCI},
    {"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
     OCI_MT_LAYER_FOREIGN_OCI_GZIP},
    {"application/vnd.docker.image.rootfs.foreign.diff.tar",
     OCI_MT_LAYER_FOREIGN_DOCKER},
    {"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
     OCI_MT_LAYER_FOREIGN_DOCKER_GZIP},
};

#define MEDIA_TYPE_COUNT (sizeof(MEDIA_TYPES) / sizeof(MEDIA_TYPES[0]))

/* Strip surrounding whitespace and any parameters after ';'. Writes the
 * canonical span into out. Returns the canonical length or 0 if the input
 * collapses to empty.
 */
static size_t canonicalize(const char *s, char *out, size_t out_size)
{
    if (!s || out_size == 0)
        return 0;

    while (*s == ' ' || *s == '\t')
        s++;

    const char *end = s;
    while (*end && *end != ';')
        end++;
    while (end > s && (end[-1] == ' ' || end[-1] == '\t'))
        end--;

    size_t len = (size_t) (end - s);
    if (len == 0 || len >= out_size)
        return 0;
    memcpy(out, s, len);
    out[len] = '\0';
    return len;
}

oci_media_type_t oci_media_type_parse(const char *s)
{
    if (!s)
        return OCI_MT_UNKNOWN;

    /* Media-type values in OCI manifests are short; 192 bytes covers every
     * canonical name in the table with room for adversarial whitespace.
     */
    char buf[192];
    if (canonicalize(s, buf, sizeof(buf)) == 0)
        return OCI_MT_UNKNOWN;

    /* RFC 6838: media type and subtype tokens are case-insensitive. The
     * parameter span (after ';') is already stripped by canonicalize, so the
     * whole of buf is type/subtype and can be matched case-insensitively.
     */
    for (size_t i = 0; i < MEDIA_TYPE_COUNT; i++) {
        if (!strcasecmp(MEDIA_TYPES[i].name, buf))
            return MEDIA_TYPES[i].kind;
    }
    return OCI_MT_UNKNOWN;
}

const char *oci_media_type_name(oci_media_type_t mt)
{
    for (size_t i = 0; i < MEDIA_TYPE_COUNT; i++) {
        if (MEDIA_TYPES[i].kind == mt)
            return MEDIA_TYPES[i].name;
    }
    return NULL;
}

bool oci_media_type_is_manifest(oci_media_type_t mt)
{
    return mt == OCI_MT_MANIFEST_OCI || mt == OCI_MT_MANIFEST_DOCKER;
}

bool oci_media_type_is_index(oci_media_type_t mt)
{
    return mt == OCI_MT_INDEX_OCI || mt == OCI_MT_INDEX_DOCKER;
}

bool oci_media_type_is_config(oci_media_type_t mt)
{
    return mt == OCI_MT_CONFIG_OCI || mt == OCI_MT_CONFIG_DOCKER;
}

bool oci_media_type_is_layer(oci_media_type_t mt)
{
    switch (mt) {
    case OCI_MT_LAYER_OCI_TAR:
    case OCI_MT_LAYER_OCI_TAR_GZIP:
    case OCI_MT_LAYER_OCI_TAR_ZSTD:
    case OCI_MT_LAYER_DOCKER_TAR_GZIP:
    case OCI_MT_LAYER_DOCKER_TAR_ZSTD:
    case OCI_MT_LAYER_FOREIGN_OCI:
    case OCI_MT_LAYER_FOREIGN_OCI_GZIP:
    case OCI_MT_LAYER_FOREIGN_DOCKER:
    case OCI_MT_LAYER_FOREIGN_DOCKER_GZIP:
        return true;
    default:
        return false;
    }
}

bool oci_media_type_is_layer_supported(oci_media_type_t mt)
{
    switch (mt) {
    case OCI_MT_LAYER_OCI_TAR:
    case OCI_MT_LAYER_OCI_TAR_GZIP:
    case OCI_MT_LAYER_OCI_TAR_ZSTD:
    case OCI_MT_LAYER_DOCKER_TAR_GZIP:
    case OCI_MT_LAYER_DOCKER_TAR_ZSTD:
        return true;
    default:
        return false;
    }
}

bool oci_media_type_is_foreign(oci_media_type_t mt)
{
    switch (mt) {
    case OCI_MT_LAYER_FOREIGN_OCI:
    case OCI_MT_LAYER_FOREIGN_OCI_GZIP:
    case OCI_MT_LAYER_FOREIGN_DOCKER:
    case OCI_MT_LAYER_FOREIGN_DOCKER_GZIP:
        return true;
    default:
        return false;
    }
}

oci_compression_t oci_media_type_compression(oci_media_type_t mt)
{
    switch (mt) {
    case OCI_MT_LAYER_OCI_TAR_GZIP:
    case OCI_MT_LAYER_DOCKER_TAR_GZIP:
    case OCI_MT_LAYER_FOREIGN_OCI_GZIP:
    case OCI_MT_LAYER_FOREIGN_DOCKER_GZIP:
        return OCI_COMPRESSION_GZIP;
    case OCI_MT_LAYER_OCI_TAR_ZSTD:
    case OCI_MT_LAYER_DOCKER_TAR_ZSTD:
        return OCI_COMPRESSION_ZSTD;
    default:
        return OCI_COMPRESSION_NONE;
    }
}
