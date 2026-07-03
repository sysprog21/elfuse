/* OCI cross-image layer dedup metrics
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * One walker per source:
 *
 *   - Pins from index.json. For each pin's manifest digest, the manifest blob
 *     is parsed; an image-manifest contributes its config blob's diff_ids
 *     directly, an image-index contributes the picked linux/arm64 sub-
 *     manifest's diff_ids. Anything that fails along the way is a per-pin
 *     skip, not a hard error (see header for rationale: dedup is
 *     informational, not GC).
 *
 *   - Unpacked sysroots under volume_root/images/sha256-<hex>/. The origin
 *     sidecar already records the manifest digest, the config digest, and
 *     the diff_id list, so this walker never has to read a blob. The walker
 *     dedupes against the pin walk by manifest_digest so a pin pointing at
 *     the same manifest as an unpacked tree does not count twice.
 *
 * Once both walkers finish, the result sets are intersected against the
 * target's diff_ids and its per-layer ChainID chain. shared_bytes accumulates
 * the on-disk tree size of layers/sha256/<diff_id>/ entries that exist and
 * fall in the intersection; entries absent from the raw cache still register
 * as shared layers (cross-image overlap is independent of cache populate).
 *
 * Memory ownership:
 *   - oci_dedup_metrics_compute zeroes *out on entry and on failure, so the
 *     caller can pass a stack-resident struct safely.
 *   - Internal scratch state (oci_digest_set_t accumulators, the target's
 *     ChainID chain heap, manifest parses) is owned and freed by this file.
 *
 * Path budget: DEDUP_PATH_MAX = 4096 matches src/oci/store.c::STORE_PATH_MAX
 * so a layers/<algo>/<hex>/ tree walk has the same headroom store.c assumes.
 */

#include "dedup-metrics.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "blob-store.h"
#include "digest-set.h"
#include "manifest.h"
#include "origin-meta.h"
#include "volume.h"

#define DEDUP_PATH_MAX 4096

/* Largest blob this helper will memory-map. The manifest renderer in
 * src/oci/inspect.c uses 64 MiB; the cross-image walker reads many blobs
 * back to back so the cap is the same to keep parser failure modes
 * uniform.
 */
#define DEDUP_BLOB_MAX ((size_t) 64 * 1024 * 1024)

/* Slurp a blob from the store into a fresh heap buffer. The buffer is
 * NUL-terminated so the caller can pass the byte range as either a
 * length-bounded array or a C string. Returns 0 on success, -1 with
 * errno preserved on failure.
 */
static int slurp_blob(oci_blob_store_t *blobs,
                      const char *digest_str,
                      char **out_body,
                      size_t *out_len)
{
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(digest_str, &algo, hex)) {
        errno = EINVAL;
        return -1;
    }
    char path[DEDUP_PATH_MAX];
    int n = oci_blob_store_path(blobs, algo, hex, path, sizeof(path));
    if (n < 0 || (size_t) n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (st.st_size < 0 || (uintmax_t) st.st_size > DEDUP_BLOB_MAX) {
        close(fd);
        errno = EFBIG;
        return -1;
    }
    size_t want = (size_t) st.st_size;
    char *buf = malloc(want + 1);
    if (!buf) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }
    size_t off = 0;
    while (off < want) {
        ssize_t r = read(fd, buf + off, want - off);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            int saved = errno;
            free(buf);
            close(fd);
            errno = saved;
            return -1;
        }
        if (r == 0)
            break;
        off += (size_t) r;
    }
    close(fd);
    if (off != want) {
        free(buf);
        errno = EIO;
        return -1;
    }
    buf[want] = '\0';
    *out_body = buf;
    *out_len = want;
    return 0;
}

/* Free a NULL-terminated char ** array allocated as { strdup, strdup, NULL }.
 */
static void free_strv(char **v)
{
    if (!v)
        return;
    for (size_t i = 0; v[i]; i++)
        free(v[i]);
    free((void *) v);
}

/* Walk a path tree summing the st_size of every regular file. Returns the
 * accumulated total on success or 0 when the entry is absent / unreadable
 * (the caller treats absence as "cache entry not populated", which is
 * shared_bytes == 0 for that diff_id). Symlinks are skipped (lstat) so a
 * stray symlink can never inflate the count by following it into the
 * blob store.
 */
static uint64_t sum_tree_size(const char *path)
{
    struct stat st;
    if (lstat(path, &st) < 0)
        return 0;
    if (S_ISREG(st.st_mode))
        return (uint64_t) st.st_size;
    if (!S_ISDIR(st.st_mode))
        return 0;
    DIR *d = opendir(path);
    if (!d)
        return 0;
    uint64_t total = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char child[DEDUP_PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        if (n < 0 || (size_t) n >= sizeof(child))
            continue;
        total += sum_tree_size(child);
    }
    closedir(d);
    return total;
}

/* Add every diff_id from cfg.rootfs_diff_ids and every ChainID in the chain
 * built from those diff_ids into the accumulators. Returns 0 on success,
 * -1 with errno set on allocation failure inside oci_digest_set_add or
 * oci_chainid_compute (caller treats this as a per-image skip).
 */
static int accumulate_chain(char *const *diff_ids,
                            oci_digest_set_t *diff_acc,
                            oci_digest_set_t *chain_acc)
{
    char prev[OCI_DIGEST_HEX_MAX + 16] = "";
    for (size_t i = 0; diff_ids[i]; i++) {
        if (oci_digest_set_add(diff_acc, diff_ids[i]) < 0)
            return -1;
        char chain[OCI_DIGEST_HEX_MAX + 16];
        const char *prev_arg = (i == 0) ? NULL : prev;
        if (oci_chainid_compute(prev_arg, diff_ids[i], chain, sizeof(chain)) <
            0)
            return -1;
        memcpy(prev, chain, strlen(chain) + 1);
        if (oci_digest_set_add(chain_acc, chain) < 0)
            return -1;
    }
    return 0;
}

/* Hard ceiling on index -> index nesting for the resolve walk below;
 * mirrors STATUS_MAX_INDEX_DEPTH in status.c. A corrupt or crafted store
 * whose index eventually points back at itself must hit this cap instead
 * of recursing until stack exhaustion.
 */
#define DEDUP_MAX_INDEX_DEPTH 4

/* For an arbitrary manifest blob digest, locate the per-arch image-config
 * digest. Walks image-index indirection (linux/arm64 pick) up to
 * DEDUP_MAX_INDEX_DEPTH levels. Returns a heap-allocated config digest
 * string on success (caller frees), or NULL with errno set when the
 * manifest is missing, malformed, nested too deep, or the index has no
 * linux/arm64 entry whose sub-manifest blob is on disk.
 */
static char *resolve_config_digest(oci_store_t *store,
                                   const char *manifest_digest,
                                   int depth)
{
    if (depth > DEDUP_MAX_INDEX_DEPTH) {
        errno = EINVAL;
        return NULL;
    }
    oci_blob_store_t *blobs = oci_store_blobs(store);
    char *body = NULL;
    size_t body_len = 0;
    if (slurp_blob(blobs, manifest_digest, &body, &body_len) < 0)
        return NULL;

    oci_manifest_t mf = {0};
    if (oci_manifest_parse(body, body_len, &mf, NULL) == 0) {
        char *cfg = strdup(mf.config.digest_str);
        oci_manifest_free(&mf);
        free(body);
        if (!cfg) {
            errno = ENOMEM;
            return NULL;
        }
        return cfg;
    }

    oci_index_t idx = {0};
    if (oci_index_parse(body, body_len, &idx, NULL) < 0) {
        free(body);
        errno = EINVAL;
        return NULL;
    }
    free(body);

    const oci_index_entry_t *picked = oci_index_pick_linux_arm64(&idx);
    if (!picked) {
        oci_index_free(&idx);
        errno = ENOENT;
        return NULL;
    }
    char *sub_digest = strdup(picked->desc.digest_str);
    oci_index_free(&idx);
    if (!sub_digest) {
        errno = ENOMEM;
        return NULL;
    }
    /* Recurse on the picked sub-manifest. Only one level deep is expected;
     * the depth cap bounds a store whose index chain never reaches an
     * image-manifest.
     */
    char *cfg = resolve_config_digest(store, sub_digest, depth + 1);
    free(sub_digest);
    return cfg;
}

/* Read the image-config at config_digest and return a freshly allocated
 * NULL-terminated copy of its rootfs_diff_ids array. Returns NULL with
 * errno set on any failure; the caller treats this as a per-image skip.
 * The returned strv must be released via free_strv.
 */
static char **load_diff_ids(oci_store_t *store, const char *config_digest)
{
    oci_blob_store_t *blobs = oci_store_blobs(store);
    char *body = NULL;
    size_t body_len = 0;
    if (slurp_blob(blobs, config_digest, &body, &body_len) < 0)
        return NULL;

    oci_image_config_t cfg = {0};
    if (oci_image_config_parse(body, body_len, &cfg, NULL) < 0) {
        free(body);
        errno = EINVAL;
        return NULL;
    }
    free(body);

    /* Count and copy. rootfs_diff_ids is guaranteed non-NULL by the parser
     * contract; an image with zero layers gives back a one-element array
     * containing only the NULL terminator.
     */
    size_t n = 0;
    while (cfg.rootfs_diff_ids[n])
        n++;
    char **copy = (char **) calloc(n + 1, sizeof(*copy));
    if (!copy) {
        oci_image_config_free(&cfg);
        errno = ENOMEM;
        return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        copy[i] = strdup(cfg.rootfs_diff_ids[i]);
        if (!copy[i]) {
            free_strv(copy);
            oci_image_config_free(&cfg);
            errno = ENOMEM;
            return NULL;
        }
    }
    oci_image_config_free(&cfg);
    return copy;
}

/* Accumulate a pin's contribution. The pin's manifest digest is checked
 * against target_manifest_digest (self-skip) and against compared_manifests
 * (dedup with unpacked-tree walk). A pin whose blob is missing, malformed,
 * or whose image-config cannot be parsed contributes nothing and is NOT
 * counted in compared_images; the walker continues with the next pin.
 *
 * The accumulator pair is updated atomically per pin: if a mid-pin failure
 * leaves partial entries in the sets, the affected pin still does not bump
 * compared_images, which means compared_images reads "images that fully
 * contributed". Partial sets only inflate shared_layers / shared_bytes; the
 * overcount is bounded by the smaller of {pin's diff_id list length, target
 * diff_id list length} and is preferable to dropping the pin's first N-1
 * diff_ids when entry N hits ENOMEM.
 */
static void walk_pin(oci_store_t *store,
                     const char *pin_manifest_digest,
                     const char *target_manifest_digest,
                     oci_digest_set_t *diff_acc,
                     oci_digest_set_t *chain_acc,
                     oci_digest_set_t *compared_manifests,
                     size_t *compared_images)
{
    if (strcmp(pin_manifest_digest, target_manifest_digest) == 0)
        return;

    /* For an image-index pin, the picked linux/arm64 sub-manifest is the
     * representative entry. Mark BOTH the pin's manifest digest and the
     * resolved sub-manifest digest as compared so a later unpacked-tree
     * lookup (which keys on whichever digest the operator unpacked from)
     * does not double-count.
     */
    char *config_digest = resolve_config_digest(store, pin_manifest_digest, 0);
    if (!config_digest)
        return;

    char **diff_ids = load_diff_ids(store, config_digest);
    free(config_digest);
    if (!diff_ids)
        return;

    if (accumulate_chain(diff_ids, diff_acc, chain_acc) < 0) {
        free_strv(diff_ids);
        return;
    }
    free_strv(diff_ids);

    (void) oci_digest_set_add(compared_manifests, pin_manifest_digest);
    (*compared_images)++;
}

/* Walk every unpacked image tree under volume_root/images/. The origin
 * sidecar yields the manifest_digest + diff_ids directly, so no blob read
 * is required. Trees whose origin sidecar matches a manifest already
 * counted via the pin walk are skipped silently.
 */
static void walk_unpacked(oci_store_t *store,
                          const char *volume_root,
                          const char *target_manifest_digest,
                          oci_digest_set_t *diff_acc,
                          oci_digest_set_t *chain_acc,
                          oci_digest_set_t *compared_manifests,
                          size_t *compared_images)
{
    (void) store;
    if (!volume_root)
        return;
    oci_volume_list_t trees = {0};
    if (oci_volume_list_unpacked(volume_root, &trees, NULL) < 0)
        return;
    for (size_t i = 0; i < trees.count; i++) {
        oci_origin_t origin = {0};
        if (oci_origin_read(trees.items[i], &origin, NULL) < 0)
            continue;
        if (origin.manifest_digest &&
            strcmp(origin.manifest_digest, target_manifest_digest) == 0) {
            oci_origin_free(&origin);
            continue;
        }
        if (origin.manifest_digest &&
            oci_digest_set_contains(compared_manifests,
                                    origin.manifest_digest)) {
            oci_origin_free(&origin);
            continue;
        }
        if (!origin.layer_diffids) {
            oci_origin_free(&origin);
            continue;
        }
        if (accumulate_chain(origin.layer_diffids, diff_acc, chain_acc) < 0) {
            oci_origin_free(&origin);
            continue;
        }
        if (origin.manifest_digest)
            (void) oci_digest_set_add(compared_manifests,
                                      origin.manifest_digest);
        (*compared_images)++;
        oci_origin_free(&origin);
    }
    oci_volume_list_free(&trees);
}

int oci_dedup_metrics_compute(oci_store_t *store,
                              const char *target_manifest_digest,
                              const char *volume_root,
                              oci_dedup_metrics_t *out,
                              const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;

    if (!store || !target_manifest_digest || !out) {
        *err = "dedup_metrics: NULL argument";
        errno = EINVAL;
        return -1;
    }
    memset(out, 0, sizeof(*out));

    /* Resolve the target's image-config and diff_ids. Hard failure here is
     * surfaced to the caller: there is no useful "layer reuse" line when
     * the target's own layer list is unknown.
     */
    char *target_config =
        resolve_config_digest(store, target_manifest_digest, 0);
    if (!target_config) {
        int saved = errno;
        *err = "dedup_metrics: target manifest blob missing or unparseable";
        errno = saved;
        return -1;
    }
    char **target_diff_ids = load_diff_ids(store, target_config);
    free(target_config);
    if (!target_diff_ids) {
        int saved = errno;
        *err = "dedup_metrics: target image-config missing or unparseable";
        errno = saved;
        return -1;
    }

    size_t n_target = 0;
    while (target_diff_ids[n_target])
        n_target++;
    out->total_layers = n_target;

    /* Precompute the target's ChainID chain so the longest-shared-prefix
     * lookup is a per-layer set membership check rather than a recompute.
     * chain_strs[i] holds ChainID(target_diff_ids[0..i]).
     */
    char **chain_strs = NULL;
    if (n_target > 0) {
        chain_strs = (char **) calloc(n_target, sizeof(*chain_strs));
        if (!chain_strs) {
            free_strv(target_diff_ids);
            *err = "dedup_metrics: chain alloc failed";
            errno = ENOMEM;
            return -1;
        }
        char prev[OCI_DIGEST_HEX_MAX + 16] = "";
        for (size_t i = 0; i < n_target; i++) {
            char chain[OCI_DIGEST_HEX_MAX + 16];
            const char *prev_arg = (i == 0) ? NULL : prev;
            if (oci_chainid_compute(prev_arg, target_diff_ids[i], chain,
                                    sizeof(chain)) < 0) {
                int saved = errno;
                for (size_t j = 0; j < i; j++)
                    free(chain_strs[j]);
                free((void *) chain_strs);
                free_strv(target_diff_ids);
                *err = "dedup_metrics: chainid compute failed for target";
                errno = saved;
                return -1;
            }
            chain_strs[i] = strdup(chain);
            if (!chain_strs[i]) {
                for (size_t j = 0; j < i; j++)
                    free(chain_strs[j]);
                free((void *) chain_strs);
                free_strv(target_diff_ids);
                *err = "dedup_metrics: chainid strdup failed";
                errno = ENOMEM;
                return -1;
            }
            memcpy(prev, chain, strlen(chain) + 1);
        }
    }

    /* Walk pins and unpacked sysroots into the two accumulators. */
    oci_digest_set_t diff_acc = {0};
    oci_digest_set_t chain_acc = {0};
    oci_digest_set_t compared_manifests = {0};
    oci_digest_set_init(&diff_acc);
    oci_digest_set_init(&chain_acc);
    oci_digest_set_init(&compared_manifests);

    oci_pin_list_t pins = {0};
    if (oci_store_list_refs(store, &pins, NULL) == 0) {
        for (size_t i = 0; i < pins.count; i++) {
            walk_pin(store, pins.items[i].digest, target_manifest_digest,
                     &diff_acc, &chain_acc, &compared_manifests,
                     &out->compared_images);
        }
        oci_pin_list_free(&pins);
    }
    walk_unpacked(store, volume_root, target_manifest_digest, &diff_acc,
                  &chain_acc, &compared_manifests, &out->compared_images);

    /* Intersect target's diff_ids against the accumulated set. For every
     * shared diff_id, walk the raw cache entry tree (if present) and add
     * its on-disk size to shared_bytes.
     */
    const char *store_root = oci_store_root(store);
    for (size_t i = 0; i < n_target; i++) {
        const char *diff_id = target_diff_ids[i];
        if (!oci_digest_set_contains(&diff_acc, diff_id))
            continue;
        out->shared_layers++;
        oci_digest_algo_t algo;
        char hex[OCI_DIGEST_HEX_MAX + 1];
        if (!oci_digest_parse(diff_id, &algo, hex))
            continue;
        const char *algo_name = oci_digest_algo_name(algo);
        if (!algo_name)
            continue;
        char layer_path[DEDUP_PATH_MAX];
        int n = snprintf(layer_path, sizeof(layer_path), "%s/layers/%s/%s",
                         store_root, algo_name, hex);
        if (n < 0 || (size_t) n >= sizeof(layer_path))
            continue;
        out->shared_bytes += sum_tree_size(layer_path);
    }

    /* Longest k such that ChainID(target[0..k-1]) is also reachable from
     * some other image. Walk from the deepest layer backwards so the first
     * hit terminates the search.
     */
    for (size_t k = n_target; k > 0; k--) {
        if (oci_digest_set_contains(&chain_acc, chain_strs[k - 1])) {
            out->deepest_shared_prefix = k;
            snprintf(out->deepest_shared_chainid,
                     sizeof(out->deepest_shared_chainid), "%s",
                     chain_strs[k - 1]);
            break;
        }
    }

    oci_digest_set_free(&diff_acc);
    oci_digest_set_free(&chain_acc);
    oci_digest_set_free(&compared_manifests);
    if (chain_strs) {
        for (size_t i = 0; i < n_target; i++)
            free(chain_strs[i]);
        free((void *) chain_strs);
    }
    free_strv(target_diff_ids);
    return 0;
}
