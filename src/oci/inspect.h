/* Offline manifest tree renderer for elfuse oci inspect
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reads the local store the slice 5a pull pipeline populated and prints the
 * resolved manifest graph without touching the network. The function does not
 * print the canonical reference header (registry / repository / tag / digest);
 * that piece is owned by src/oci/cli.c so the slice-1 inspect smoke output
 * stays exactly the same when the store has no record for a ref.
 *
 * Manifest digest resolution order:
 *   1. ref->digest, when set (digest-pinned reference)
 *   2. Pin descriptor in <root>/index.json whose ref.name annotation matches
 *      the canonical "<registry>/<repository>:<tag>" form
 *   3. Neither: print "(no local manifest...)" and return 0 (informational)
 *
 * Render policy:
 *   - The blob is parsed as an index or a manifest based on the canonical
 *     mediaType embedded in the JSON. Unknown media types abort with EPROTO.
 *   - For an image index: prints a platform table. Default mode shows only
 *     the linux/arm64 entry and then drills into its sub-manifest to print
 *     the config descriptor and layer table. --all-platforms (opts->
 *     show_all_platforms) lists every entry and skips the drill -- it is
 *     "what platforms does this image cover", not "what is inside the arm64
 *     variant".
 *   - For an image manifest: prints config + layers directly.
 *
 * Failure mode for partial stores: when the index loads but the linux/arm64
 * sub-manifest blob is missing from the store, the platform table is still
 * printed (stdout), a warning lands on stderr, and the call returns -1 with
 * errno=ENOENT. That preserves the informational view while letting scripts
 * detect the inconsistency through the exit code.
 */

#pragma once

#include <stdbool.h>
#include <stdio.h>

#include "ref.h"
#include "store.h"

typedef struct {
    /* Destination for the rendered tree. NULL defaults to stdout. */
    FILE *out;
    /* List every platform entry of an image index instead of only the picked
     * linux/arm64 entry. In this mode oci_inspect does not drill into any
     * sub-manifest and skips the layer reuse section.
     */
    bool show_all_platforms;
    /* Optional volume root for the unpacked-sysroot walk in the layer reuse
     * section. NULL means pin-only dedup, matching the garbage collector's
     * walk convention. Pure information: dedup metrics never write to disk.
     */
    const char *volume_root;
    /* When true, suppress the "layer reuse:" section that is otherwise
     * rendered after the manifest layer table. The default (false, which is
     * also the NULL-opts case) renders the section; tests that only want to
     * verify the renderer baseline without the dedup compute side-effects set
     * this true to skip it. The CLI never sets this true.
     */
    bool suppress_layer_reuse;
} oci_inspect_options_t;

/* Render the manifest tree the store holds for ref. opts may be NULL for the
 * defaults (out=stdout, show_all_platforms=false). Returns 0 on success or
 * pin miss; -1 with errno preserved and *err_msg (when non-NULL) pointing at
 * a static description on failure (malformed blob, blob missing, IO error).
 */
int oci_inspect(oci_store_t *store,
                const oci_ref_t *ref,
                const oci_inspect_options_t *opts,
                const char **err_msg);
