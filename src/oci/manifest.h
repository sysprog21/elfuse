/* OCI image manifest, image index, and image config parsers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Parses the three JSON document types served by an OCI / Docker registry:
 *
 *   - image manifest:  config descriptor + ordered layer descriptors
 *   - image index:     platform-tagged manifest descriptors (multi-arch)
 *   - image config:    architecture/os + runtime fields + rootfs diff_ids
 *
 * The model stays offline: parsers operate on in-memory JSON bytes the
 * caller already read from the local blob store or a disk fixture.
 * Registry transfer is delegated to skopeo(1) (see oci/pull.c); the
 * manifest model lets the blob store persist the parsed graph without
 * round-tripping through opaque JSON.
 *
 * Every descriptor digest is validated up-front with oci/digest.c, so a
 * parsed oci_descriptor_t is guaranteed to have a lowercase
 * <algo>:<hex> form and a populated (algo, hex[]) pair the blob store can
 * consume directly.
 *
 * Unknown / extension media types do not fail the parse; they are recorded
 * with raw_media_type set and media_type == OCI_MT_UNKNOWN so callers can
 * decide whether to ignore or reject. The selection helper for
 * linux/arm64 manifests intentionally skips any entry that already failed
 * media-type recognition because the registry fetch path cannot resolve
 * it anyway.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "digest.h"
#include "media-type.h"

typedef struct {
    /* Original "<algo>:<hex>" string, lowercase, never NULL after parse. */
    char *digest_str;
    /* Parsed digest algorithm. */
    oci_digest_algo_t algo;
    /* Parsed lowercase hex (NUL-terminated). */
    char hex[OCI_DIGEST_HEX_MAX + 1];
    /* Declared size in bytes. Negative values are rejected at parse. */
    int64_t size;
    /* Canonical media-type enum, OCI_MT_UNKNOWN if not in the recognized
     * table.
     */
    oci_media_type_t media_type;
    /* Original media-type string for diagnostics. NULL if absent. */
    char *raw_media_type;
} oci_descriptor_t;

typedef struct {
    /* "arm64", "amd64", "ppc64le", ... Never NULL after parse. */
    char *architecture;
    /* "linux", "windows", ... Never NULL after parse. */
    char *os;
    /* "v8", "v7", "" (empty string when absent in JSON). */
    char *variant;
    /* "10.0.14393.1066" for Windows builds, "" otherwise. */
    char *os_version;
} oci_platform_t;

typedef struct {
    oci_descriptor_t desc;
    /* Empty platform fields ("" strings, not NULL) when JSON omits them so
     * predicates can compare unconditionally.
     */
    oci_platform_t platform;
} oci_index_entry_t;

typedef struct {
    int schema_version;
    /* Top-level mediaType field. OCI manifests carry an explicit mediaType;
     * Docker manifests historically rely on the descriptor or HTTP
     * Content-Type. The parser falls back to OCI_MT_UNKNOWN if the JSON
     * field is missing and lets the caller cross-check against the
     * registry's Content-Type.
     */
    oci_media_type_t media_type;
    /* Original mediaType string, NULL if absent. */
    char *raw_media_type;
    oci_index_entry_t *entries;
    size_t nentries;
} oci_index_t;

typedef struct {
    int schema_version;
    oci_media_type_t media_type;
    char *raw_media_type;
    oci_descriptor_t config;
    oci_descriptor_t *layers;
    size_t nlayers;
} oci_manifest_t;

/* Image config runtime block (the inner "config" object). `elfuse oci
 * run` folds these fields into the launched guest's Entrypoint / Cmd /
 * Env / WorkingDir / User; `elfuse oci inspect` renders them for
 * display. NULL-terminated string arrays are NULL when
 * the JSON omits the field; empty arrays are represented as an allocated
 * one-element array containing only the NULL terminator.
 */
typedef struct {
    char *user;
    char *working_dir;
    char **env;
    char **entrypoint;
    char **cmd;
} oci_image_runtime_t;

typedef struct {
    char *architecture;
    char *os;
    char *variant;
    oci_image_runtime_t config;
    /* rootfs.diff_ids, NULL-terminated. Always populated (the OCI image-spec
     * requires "rootfs"); a parse without this field returns -1.
     */
    char **rootfs_diff_ids;
} oci_image_config_t;

/* Parsers. Each takes raw JSON bytes (need not be NUL-terminated; pass the
 * exact length). On success returns 0 and populates out. On failure returns
 * -1 with errno preserved when set (ENOMEM, EINVAL) and writes a static
 * diagnostic message into *err_msg (when err_msg != NULL).
 */
int oci_manifest_parse(const char *json,
                       size_t len,
                       oci_manifest_t *out,
                       const char **err_msg);

int oci_index_parse(const char *json,
                    size_t len,
                    oci_index_t *out,
                    const char **err_msg);

int oci_image_config_parse(const char *json,
                           size_t len,
                           oci_image_config_t *out,
                           const char **err_msg);

/* Release any heap fields. Safe on zero-initialised structs and on NULL. */
void oci_manifest_free(oci_manifest_t *m);
void oci_index_free(oci_index_t *idx);
void oci_image_config_free(oci_image_config_t *c);
void oci_descriptor_free(oci_descriptor_t *d);
void oci_platform_free(oci_platform_t *p);

/* Select the linux/arm64 manifest from an index. Returns a pointer into
 * idx->entries on success (caller does not free) or NULL when no acceptable
 * platform is present. Preference order, highest first:
 *   1. os=="linux" && arch=="arm64" && variant=="v8"
 *   2. os=="linux" && arch=="arm64" && variant==""
 *   3. os=="linux" && arch=="arm64" (any other variant; first wins)
 * Foreign / unsupported media types are skipped: even if a foreign-layer
 * manifest claims linux/arm64, the registry fetch path cannot consume it.
 */
const oci_index_entry_t *oci_index_pick_linux_arm64(const oci_index_t *idx);
