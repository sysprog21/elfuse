/* Store-wide OCI status report
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Aggregates a single point-in-time snapshot of every pin in index.json plus
 * every unpacked sysroot under volume_root, into a flat struct the CLI can
 * render or serialise to JSON. The walker is informational rather than a GC
 * keep-set: a malformed manifest or unreadable origin sidecar surfaces as a
 * per-entry status code without aborting the rest of the walk, so an operator
 * with one corrupt pin still sees the healthy rows.
 *
 * Layer-cache populate ratios (raw + stack) drill into reachable diff_ids and
 * ChainID prefixes the same way oci_dedup_metrics_compute does, except the
 * aggregation is store-wide rather than per-target. The two values are
 * separate metrics (raw vs stack) because the two caches dedup along
 * different axes; collapsing them into one number would hide which family
 * needs operator attention.
 *
 * first consumer. Reusable bits to revisit if or any
 * later store-wide reporter lands a fourth caller: the diff_id / ChainID
 * walker duplication this file inherits from dedup-metrics.c and store.c
 * crosses the lift threshold once a fourth caller appears; see
 * project_oci_plan3 memory for the pattern.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "store.h"

/* Per-pin entry status. ok == 0 means every field below is populated;
 * non-zero codes name which step failed so the renderer can print a sentinel
 * row instead of suppressing the pin entirely.
 */
typedef enum {
    OCI_STATUS_PIN_OK = 0,
    OCI_STATUS_PIN_MISSING_MANIFEST = 1, /* manifest blob not on disk */
    OCI_STATUS_PIN_CORRUPT_MANIFEST =
        2, /* blob unparseable as manifest or index */
    OCI_STATUS_PIN_CORRUPT_CONFIG =
        3, /* image-config blob missing or unparseable */
    OCI_STATUS_PIN_INDEX_NO_ARM64 =
        4, /* image-index has no linux/arm64 entry */
} oci_status_pin_code_t;

typedef struct {
    char *name;              /* canonical "<registry>/<repository>:<tag>" */
    char *digest;            /* pinned manifest digest, "<algo>:<hex>" */
    uint64_t manifest_size;  /* st_size of manifest blob; 0 on missing */
    uint64_t config_size;    /* st_size of image-config blob; 0 on missing */
    size_t layer_count;      /* rootfs.diff_ids length; 0 on resolve failure */
    int64_t last_seen_mtime; /* st_mtime of manifest blob (epoch sec); -1 if
                                missing */
    oci_status_pin_code_t status;
} oci_status_pin_entry_t;

/* Per-unpacked-sysroot entry status. */
typedef enum {
    OCI_STATUS_UNPACKED_OK = 0,
    OCI_STATUS_UNPACKED_MISSING_ORIGIN = 1,
    OCI_STATUS_UNPACKED_CORRUPT_ORIGIN = 2,
} oci_status_unpacked_code_t;

typedef struct {
    char *path;            /* absolute path to <volume>/images/sha256-<hex>/ */
    char *manifest_digest; /* origin.manifest_digest; NULL on read failure */
    size_t layer_count;    /* origin.layer_diffids length; 0 on read failure */
    uint64_t tree_bytes;   /* recursive st_size sum; 0 under skip_disk_usage */
    oci_status_unpacked_code_t status;
} oci_status_unpacked_entry_t;

/* Inputs to oci_status_compute. */
typedef struct {
    /* When non-NULL, the unpacked-tree walker scans <volume_root>/images/.
     * NULL skips that source entirely; pins-only mode still populates every
     * blob and cache total. Missing or unreadable volume_root is the empty
     * case (unpacked_count = 0), not an error.
     */
    const char *volume_root;

    /* When true, every byte counter is left at zero and the rendered output
     * notes that disk usage was skipped. This is the operator escape hatch
     * for stores large enough that walking layers/sha256/ and
     * layers/stacks/sha256/ trees would be too slow.
     */
    bool skip_disk_usage;
} oci_status_options_t;

/* The aggregated report. Owned by the caller; release via oci_status_free.
 * Array fields are NULL with count == 0 when empty so the renderer can
 * branch on count alone.
 */
typedef struct {
    /* Pins: always populated from index.json (best-effort; an unreadable
     * index.json is the same as an empty store, not a fatal error so the
     * renderer can still print store totals).
     */
    oci_status_pin_entry_t *pins;
    size_t pin_count;

    /* Unpacked sysroots: empty when volume_root was NULL or the
     * <volume_root>/images/ directory was missing.
     */
    oci_status_unpacked_entry_t *unpacked;
    size_t unpacked_count;

    /* Store-wide disk totals. Counts are always populated. Byte totals are
     * zero when skip_disk_usage is true.
     */
    size_t blob_count;
    uint64_t blob_bytes_total;
    size_t layer_cache_count;
    uint64_t layer_cache_bytes_total;
    size_t stack_cache_count;
    uint64_t stack_cache_bytes_total;

    /* Reachable-set populate ratios. Numerator counts entries the union of
     * reachable diff_ids / ChainIDs that are actually present on disk under
     * <root>/layers/<algo>/<hex>/ or <root>/layers/stacks/<algo>/<hex>/.
     * A diff_id or ChainID is reachable if some healthy pin or unpacked
     * sysroot named it; corrupt pins contribute nothing here so the ratios
     * are not skewed by unreadable manifests.
     */
    size_t diff_ids_reachable;
    size_t diff_ids_populated;
    size_t chain_ids_reachable;
    size_t chain_ids_populated;

    /* Mirrors options.skip_disk_usage so the renderer does not need the
     * options struct in scope.
     */
    bool disk_usage_skipped;
} oci_status_t;

/* Compute a store-wide status snapshot.
 *
 * Failure model: fatal only on bad arguments or a store-open / index.json
 * lock failure where no useful snapshot can be produced. Per-pin and
 * per-tree failures surface as the entry's status code; the walker keeps
 * going.
 *
 * On entry *out is reset; on success it is fully populated and the caller
 * must release it via oci_status_free. On failure *out is left in the
 * freed-empty state and *err (when non-NULL) points at a static description.
 *
 * opts may be NULL for "pin-only, include disk usage" defaults.
 */
int oci_status_compute(oci_store_t *store,
                       const oci_status_options_t *opts,
                       oci_status_t *out,
                       const char **err);

/* Release every owned heap field in *out and zero the struct. Safe on a
 * zero-initialised struct and on NULL.
 */
void oci_status_free(oci_status_t *out);
