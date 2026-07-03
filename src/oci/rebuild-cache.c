/* OCI stack cache back-fill driver.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * See rebuild-cache.h for the externally visible contract. Implementation
 * sketch: oci_volume_list_unpacked yields every <volume_root>/images/
 * sha256-<hex>/ directory; for each one this module reads the origin
 * sidecar, recomputes the terminating ChainID from the recorded diff_id
 * list, probes the stack cache for an existing entry, and (when
 * opts->commit is set) clonefiles the tree into a staged stack snapshot,
 * strips the .elfuse-origin.json that the unpacker wrote AFTER the fresh-
 * unpack snapshot was taken, and atomically promotes the staged tree via
 * oci_store_stack_commit. Failures inside the per-tree loop are aggregated
 * into stats counters and reported on stderr; the loop never aborts so a
 * single corrupt tree cannot block the rest of the back-fill.
 */

#include "rebuild-cache.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/stat.h>
#include <unistd.h>

#include "digest.h"
#include "origin-meta.h"
#include "volume.h"
#include "util.h"

#define RC_PATH_MAX 4096

static size_t count_diff_ids(char *const *diff_ids)
{
    size_t n = 0;
    if (!diff_ids)
        return 0;
    while (diff_ids[n])
        n++;
    return n;
}

/* Compute the terminating ChainID over a non-empty diff_id list. Iterates
 * oci_chainid_compute with a two-buffer ping-pong so the running chain
 * value can be threaded through each step without per-iteration alloc.
 * Writes the result into out (must hold at least OCI_DIGEST_HEX_MAX + 16
 * bytes). Returns 0 on success, -1 with errno set on failure.
 */
static int compute_terminal_chain(char *const *diff_ids,
                                  size_t n,
                                  char *out,
                                  size_t cap)
{
    char buf_a[OCI_DIGEST_HEX_MAX + 16];
    char buf_b[OCI_DIGEST_HEX_MAX + 16];
    char *cur = buf_a;
    char *nxt = buf_b;
    if (oci_chainid_compute(NULL, diff_ids[0], cur, sizeof(buf_a)) < 0)
        return -1;
    for (size_t i = 1; i < n; i++) {
        if (oci_chainid_compute(cur, diff_ids[i], nxt, sizeof(buf_b)) < 0)
            return -1;
        char *tmp = cur;
        cur = nxt;
        nxt = tmp;
    }
    size_t need = strlen(cur) + 1;
    if (need > cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, cur, need);
    return 0;
}

/* Stage + clonefile + sanitize + stack_commit one tree. The caller verified
 * that oci_store_stack_has returned 0 for chain_id; this function does not
 * re-probe. Returns 0 on success, -1 with errno preserved on failure. On
 * failure the staging path (if any) is removed.
 */
static int snapshot_tree_to_stack(oci_store_t *store,
                                  const char *tree_path,
                                  const char *chain_id,
                                  const char **err)
{
    char stage_path[RC_PATH_MAX];
    if (oci_store_stack_stage_path(store, chain_id, stage_path,
                                   sizeof(stage_path)) < 0) {
        if (err)
            *err = "rebuild-cache: stack stage_path resolve failed";
        return -1;
    }
    if (clonefile(tree_path, stage_path, CLONE_NOFOLLOW) < 0) {
        int saved = errno;
        if (err)
            *err = saved == EXDEV
                       ? "rebuild-cache: stack snapshot EXDEV (store and "
                         "volume must share an APFS volume)"
                       : "rebuild-cache: stack snapshot clonefile failed";
        errno = saved;
        return -1;
    }
    /* Strip the origin sidecar so the rebuilt snapshot matches the shape
     * a fresh-unpack snapshot would have produced (oci_unpack writes the
     * origin sidecar AFTER it takes the stack snapshot).
     */
    char origin_path[RC_PATH_MAX];
    int n = snprintf(origin_path, sizeof(origin_path), "%s/.elfuse-origin.json",
                     stage_path);
    if (n < 0 || (size_t) n >= sizeof(origin_path)) {
        (void) oci_rm_recursive(stage_path);
        if (err)
            *err = "rebuild-cache: origin sidecar path overflow";
        errno = ENAMETOOLONG;
        return -1;
    }
    if (unlink(origin_path) < 0 && errno != ENOENT) {
        int saved = errno;
        (void) oci_rm_recursive(stage_path);
        if (err)
            *err = "rebuild-cache: origin sidecar unlink failed";
        errno = saved;
        return -1;
    }
    const char *scerr = NULL;
    if (oci_store_stack_commit(store, stage_path, chain_id, &scerr) < 0) {
        int saved = errno;
        (void) oci_rm_recursive(stage_path);
        if (err)
            *err = scerr ? scerr : "rebuild-cache: stack_commit failed";
        errno = saved;
        return -1;
    }
    return 0;
}

int oci_rebuild_cache(oci_store_t *store,
                      const char *volume_root,
                      oci_rebuild_cache_options_t *opts,
                      const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!store || !opts)
        return set_err(err, "rebuild-cache: NULL argument", EINVAL);

    /* Zero only output fields; the caller's commit flag must survive. */
    opts->trees_scanned = 0;
    opts->trees_rebuilt = 0;
    opts->trees_skipped_cached = 0;
    opts->trees_skipped_no_origin = 0;
    opts->trees_skipped_bad_origin = 0;
    opts->trees_skipped_empty_diffids = 0;
    opts->trees_failed = 0;
    opts->stack_entries_added = 0;

    oci_volume_list_t trees = {0};
    const char *list_err = NULL;
    if (oci_volume_list_unpacked(volume_root, &trees, &list_err) < 0) {
        int saved = errno;
        set_err(err,
                list_err ? list_err : "rebuild-cache: list unpacked failed",
                saved);
        return -1;
    }

    for (size_t i = 0; i < trees.count; i++) {
        const char *tree = trees.items[i];
        opts->trees_scanned++;

        oci_origin_t origin = {0};
        if (oci_origin_read(tree, &origin, NULL) < 0) {
            if (errno == ENOENT)
                opts->trees_skipped_no_origin++;
            else
                opts->trees_skipped_bad_origin++;
            continue;
        }

        size_t n_diffs = count_diff_ids(origin.layer_diffids);
        if (n_diffs == 0) {
            opts->trees_skipped_empty_diffids++;
            oci_origin_free(&origin);
            continue;
        }

        char chain[OCI_DIGEST_HEX_MAX + 16];
        if (compute_terminal_chain(origin.layer_diffids, n_diffs, chain,
                                   sizeof(chain)) < 0) {
            fprintf(stderr, "rebuild-cache: %s: chainid compute failed: %s\n",
                    tree, strerror(errno));
            opts->trees_failed++;
            oci_origin_free(&origin);
            continue;
        }
        oci_origin_free(&origin);

        int has = oci_store_stack_has(store, chain);
        if (has < 0) {
            fprintf(stderr, "rebuild-cache: %s: stack_has probe failed: %s\n",
                    tree, strerror(errno));
            opts->trees_failed++;
            continue;
        }
        if (has > 0) {
            opts->trees_skipped_cached++;
            continue;
        }

        if (!opts->commit) {
            opts->trees_rebuilt++;
            opts->stack_entries_added++;
            continue;
        }

        const char *snap_err = NULL;
        if (snapshot_tree_to_stack(store, tree, chain, &snap_err) < 0) {
            fprintf(stderr, "rebuild-cache: %s: %s: %s\n", tree,
                    snap_err ? snap_err : "snapshot failed", strerror(errno));
            opts->trees_failed++;
            continue;
        }
        opts->trees_rebuilt++;
        opts->stack_entries_added++;
    }

    oci_volume_list_free(&trees);
    return 0;
}
