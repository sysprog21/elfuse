/* Store-wide OCI status report
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Single walker over both store sources (pins via index.json + optional
 * unpacked sysroots) plus three disk sweeps (blobs/, layers/, layers/stacks/).
 * The pin walker resolves each manifest down to its image-config diff_ids,
 * accumulates reachable diff_id and ChainID prefix sets into shared
 * oci_digest_set_t accumulators, and records per-pin status / sizes / mtime
 * for the CLI render. Unpacked sysroots feed the same accumulators from
 * .elfuse-origin.json so no blob read is needed.
 *
 * After the walk, every diff_id in the reachable set is probed against
 * <root>/layers/<algo>/<hex>/ to compute the raw cache populate ratio; the
 * same probe runs against <root>/layers/stacks/<algo>/<hex>/ for the ChainID
 * accumulator. The store sweeps under blobs/<algo>/, layers/<algo>/, and
 * layers/stacks/<algo>/ count every entry (regardless of reachability) so the
 * STORE TOTALS section can report the disk footprint.
 *
 * Failure policy: any per-entry error (missing manifest blob, malformed
 * origin sidecar, bad image-config JSON) is recorded as the entry's status
 * code rather than aborting. Fatal cases are reserved for the few states
 * where no snapshot is possible: a NULL store, a failure walking
 * <root>/blobs/, or any other IO error during the directory sweeps.
 *
 * Duplication note: slurp_blob / sum_tree_size / resolve_config_digest /
 * load_diff_ids / accumulate_chain are pattern-duplicates of helpers in
 * src/oci/dedup-metrics.c and src/oci/store.c. Hoisting them into a shared
 * helper is deferred until a fourth caller of the diff_id walker pattern
 * appears; status.c is the third caller, still below that threshold.
 */

#include "status.h"

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
#include "digest.h"
#include "manifest.h"
#include "origin-meta.h"
#include "volume.h"

#define STATUS_PATH_MAX 4096

/* Largest blob this helper will read into a heap buffer. Mirrors the
 * 64 MiB cap used by dedup-metrics.c so manifest / image-config parse
 * failure modes stay uniform across the OCI module set.
 */
#define STATUS_BLOB_MAX ((size_t) 64 * 1024 * 1024)

/* ── Helpers duplicated from dedup-metrics.c / store.c ───────────────── */

/* Slurp a blob into a fresh heap buffer, NUL-terminated for parser ergonomics.
 * Returns 0 on success and writes the body + length; -1 with errno preserved
 * on failure. Caller frees *out_body.
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
    char path[STATUS_PATH_MAX];
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
    if (st.st_size < 0 || (uintmax_t) st.st_size > STATUS_BLOB_MAX) {
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

/* Stat manifest blob to capture size + mtime for the pin row. Returns 0 on
 * hit; -1 with errno=ENOENT on miss (caller treats as MISSING_MANIFEST) or
 * with errno preserved on other failures.
 */
static int stat_blob(oci_blob_store_t *blobs,
                     const char *digest_str,
                     uint64_t *out_size,
                     int64_t *out_mtime)
{
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(digest_str, &algo, hex)) {
        errno = EINVAL;
        return -1;
    }
    char path[STATUS_PATH_MAX];
    int n = oci_blob_store_path(blobs, algo, hex, path, sizeof(path));
    if (n < 0 || (size_t) n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    struct stat st;
    if (stat(path, &st) < 0)
        return -1;
    if (out_size)
        *out_size = (uint64_t) (st.st_size < 0 ? 0 : st.st_size);
    if (out_mtime)
        *out_mtime = (int64_t) st.st_mtime;
    return 0;
}

/* Recursive st_size sum over a path tree. Returns the accumulated total on
 * success or 0 when the entry is absent / unreadable (a missing layer cache
 * entry simply contributes zero bytes). Symlinks are skipped via lstat so a
 * stray symlink can never inflate the count.
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
        char child[STATUS_PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        if (n < 0 || (size_t) n >= sizeof(child))
            continue;
        total += sum_tree_size(child);
    }
    closedir(d);
    return total;
}

/* Free a NULL-terminated char ** array (strdup'd entries plus the array). */
static void free_strv(char **v)
{
    if (!v)
        return;
    for (size_t i = 0; v[i]; i++)
        free(v[i]);
    free((void *) v);
}

/* Hard ceiling on index -> index nesting for the resolve walk below. Real
 * images use at most one level; anything deeper than a few is a corrupt or
 * crafted store (e.g. an index whose entry cycles back to itself), which
 * unbounded recursion would turn into stack exhaustion.
 */
#define STATUS_MAX_INDEX_DEPTH 4

/* Resolve a manifest blob to its image-config digest. Walks image-index
 * indirection (linux/arm64 pick) up to STATUS_MAX_INDEX_DEPTH levels.
 * Returns a heap-allocated "<algo>:<hex>" config digest on success (caller
 * frees) or NULL with errno set on failure:
 *   ENOENT - manifest blob missing OR index has no linux/arm64 entry
 *   EINVAL - manifest blob neither parseable as manifest nor index,
 *            or the index nesting exceeds STATUS_MAX_INDEX_DEPTH
 *   other  - propagated from slurp_blob
 *
 * out_status_code, when non-NULL, receives a hint matching the pin status
 * enum so the caller can map ENOENT-from-missing-sub-manifest to
 * MISSING_MANIFEST (rather than INDEX_NO_ARM64) and so on.
 */
static char *resolve_config_digest(oci_store_t *store,
                                   const char *manifest_digest,
                                   oci_status_pin_code_t *out_status_code,
                                   int depth)
{
    if (depth > STATUS_MAX_INDEX_DEPTH) {
        errno = EINVAL;
        if (out_status_code)
            *out_status_code = OCI_STATUS_PIN_CORRUPT_MANIFEST;
        return NULL;
    }
    oci_blob_store_t *blobs = oci_store_blobs(store);
    char *body = NULL;
    size_t body_len = 0;
    if (slurp_blob(blobs, manifest_digest, &body, &body_len) < 0) {
        if (out_status_code)
            *out_status_code = (errno == ENOENT)
                                   ? OCI_STATUS_PIN_MISSING_MANIFEST
                                   : OCI_STATUS_PIN_CORRUPT_MANIFEST;
        return NULL;
    }

    oci_manifest_t mf = {0};
    if (oci_manifest_parse(body, body_len, &mf, NULL) == 0) {
        char *cfg = strdup(mf.config.digest_str);
        oci_manifest_free(&mf);
        free(body);
        if (!cfg) {
            errno = ENOMEM;
            if (out_status_code)
                *out_status_code = OCI_STATUS_PIN_CORRUPT_CONFIG;
            return NULL;
        }
        return cfg;
    }

    oci_index_t idx = {0};
    if (oci_index_parse(body, body_len, &idx, NULL) < 0) {
        free(body);
        errno = EINVAL;
        if (out_status_code)
            *out_status_code = OCI_STATUS_PIN_CORRUPT_MANIFEST;
        return NULL;
    }
    free(body);

    const oci_index_entry_t *picked = oci_index_pick_linux_arm64(&idx);
    if (!picked) {
        oci_index_free(&idx);
        errno = ENOENT;
        if (out_status_code)
            *out_status_code = OCI_STATUS_PIN_INDEX_NO_ARM64;
        return NULL;
    }
    char *sub_digest = strdup(picked->desc.digest_str);
    oci_index_free(&idx);
    if (!sub_digest) {
        errno = ENOMEM;
        if (out_status_code)
            *out_status_code = OCI_STATUS_PIN_CORRUPT_CONFIG;
        return NULL;
    }
    /* Recurse on the picked sub-manifest. Status code on a sub-manifest miss
     * is MISSING_MANIFEST rather than INDEX_NO_ARM64: the index itself was
     * fine, the sub-manifest blob just is not on disk.
     */
    oci_status_pin_code_t sub_code = OCI_STATUS_PIN_OK;
    char *cfg = resolve_config_digest(store, sub_digest, &sub_code, depth + 1);
    free(sub_digest);
    if (!cfg && out_status_code)
        *out_status_code = sub_code;
    return cfg;
}

/* Load the rootfs.diff_ids array from an image-config blob. Returns a fresh
 * NULL-terminated char ** on success (free via free_strv); NULL with errno
 * set on missing / unparseable / OOM. The caller maps the failure to the
 * CORRUPT_CONFIG pin status.
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

/* Add every diff_id and the per-layer ChainID prefix into the accumulators.
 * Returns 0 on success, -1 with errno set on chainid or set-add failure.
 * Mid-walk failures leave partial entries in the sets; status.c treats the
 * caller as "this image's contribution is corrupt" and lets the partial
 * entries stand because they cannot inflate the populated-count beyond
 * reality (the union shape of digest_set means later images naturally dedup).
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

/* ── Disk sweeps for STORE TOTALS ─────────────────────────────────────── */

/* Names whose ascii-hex shape matches the supplied algorithm. Mirrors the
 * filter store.c uses to reject foreign state under blobs/<algo>/.
 */
static bool entry_name_is_digest_hex(oci_digest_algo_t algo, const char *name)
{
    if (!name)
        return false;
    size_t want = oci_digest_hex_len(algo);
    if (strlen(name) != want)
        return false;
    return oci_digest_hex_valid(algo, name);
}

/* Sweep <root>/blobs/<algo>/ and increment count + bytes for every well-formed
 * blob entry. Returns 0 on success; -1 with errno set on opendir failure
 * (except ENOENT, which is the empty-store case). When opts->skip_disk_usage
 * is true the byte total is left at zero but the count still accumulates.
 */
static int sweep_blob_algo(const char *root,
                           oci_digest_algo_t algo,
                           bool skip_bytes,
                           size_t *count,
                           uint64_t *bytes)
{
    const char *algo_name = oci_digest_algo_name(algo);
    if (!algo_name)
        return 0;
    char dir[STATUS_PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s/blobs/%s", root, algo_name);
    if (n < 0 || (size_t) n >= sizeof(dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    DIR *d = opendir(dir);
    if (!d) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        if (!entry_name_is_digest_hex(algo, de->d_name))
            continue;
        char child[STATUS_PATH_MAX];
        int cn = snprintf(child, sizeof(child), "%s/%s", dir, de->d_name);
        if (cn < 0 || (size_t) cn >= sizeof(child))
            continue;
        struct stat st;
        if (lstat(child, &st) < 0)
            continue;
        if (!S_ISREG(st.st_mode))
            continue;
        (*count)++;
        if (!skip_bytes)
            *bytes += (uint64_t) (st.st_size < 0 ? 0 : st.st_size);
    }
    closedir(d);
    return 0;
}

/* Sweep a content-addressed directory family rooted at <root>/<base>/<algo>/
 * where each well-formed child is itself a directory whose recursive
 * st_size sum contributes to bytes. Used for layers/<algo>/ and
 * layers/stacks/<algo>/. Missing <root>/<base>/<algo>/ is the empty case
 * (count == 0), not an error.
 */
static int sweep_tree_family(const char *root,
                             const char *base,
                             oci_digest_algo_t algo,
                             bool skip_bytes,
                             size_t *count,
                             uint64_t *bytes)
{
    const char *algo_name = oci_digest_algo_name(algo);
    if (!algo_name)
        return 0;
    char dir[STATUS_PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s/%s/%s", root, base, algo_name);
    if (n < 0 || (size_t) n >= sizeof(dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    DIR *d = opendir(dir);
    if (!d) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        if (!entry_name_is_digest_hex(algo, de->d_name))
            continue;
        char child[STATUS_PATH_MAX];
        int cn = snprintf(child, sizeof(child), "%s/%s", dir, de->d_name);
        if (cn < 0 || (size_t) cn >= sizeof(child))
            continue;
        struct stat st;
        if (lstat(child, &st) < 0)
            continue;
        if (!S_ISDIR(st.st_mode))
            continue;
        (*count)++;
        if (!skip_bytes)
            *bytes += sum_tree_size(child);
    }
    closedir(d);
    return 0;
}

/* Algorithms swept by the disk pass. Mirrors PRUNE_ALGOS in store.c so the
 * sweep stays consistent with what the GC walker considers a candidate.
 */
static const oci_digest_algo_t STATUS_ALGOS[] = {
    OCI_DIGEST_SHA256,
    OCI_DIGEST_SHA512,
};
#define STATUS_ALGOS_LEN (sizeof(STATUS_ALGOS) / sizeof(STATUS_ALGOS[0]))

/* Probe whether <root>/<base>/<algo>/<hex>/ exists as a directory. Used to
 * compute the populate ratios over the reachable digest sets.
 */
static bool tree_entry_exists(const char *root,
                              const char *base,
                              const char *digest_str)
{
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(digest_str, &algo, hex))
        return false;
    const char *algo_name = oci_digest_algo_name(algo);
    if (!algo_name)
        return false;
    char path[STATUS_PATH_MAX];
    int n =
        snprintf(path, sizeof(path), "%s/%s/%s/%s", root, base, algo_name, hex);
    if (n < 0 || (size_t) n >= sizeof(path))
        return false;
    struct stat st;
    if (stat(path, &st) < 0)
        return false;
    return S_ISDIR(st.st_mode);
}

/* ── Per-pin walk ─────────────────────────────────────────────────────── */

/* Populate one pin entry. Returns 0 on every code path (pin entries record
 * their own status; a per-pin failure is never fatal). diff_acc / chain_acc
 * accumulate the reachable layer / chain sets when the pin resolves cleanly.
 */
static void walk_pin_entry(oci_store_t *store,
                           const oci_pin_entry_t *pin,
                           oci_status_pin_entry_t *out,
                           oci_digest_set_t *diff_acc,
                           oci_digest_set_t *chain_acc)
{
    memset(out, 0, sizeof(*out));
    out->last_seen_mtime = -1;
    out->name = strdup(pin->name ? pin->name : "");
    out->digest = strdup(pin->digest ? pin->digest : "");
    if (!out->name || !out->digest) {
        /* Allocation failure for the row identity strings is rare enough
         * that surfacing it as MISSING_MANIFEST gives the operator a hint
         * without complicating the failure model.
         */
        out->status = OCI_STATUS_PIN_MISSING_MANIFEST;
        return;
    }

    oci_blob_store_t *blobs = oci_store_blobs(store);

    /* Manifest blob size / mtime first. A miss here short-circuits all later
     * steps to MISSING_MANIFEST without polluting the per-pin row.
     */
    if (stat_blob(blobs, out->digest, &out->manifest_size,
                  &out->last_seen_mtime) < 0) {
        out->manifest_size = 0;
        out->last_seen_mtime = -1;
        out->status = OCI_STATUS_PIN_MISSING_MANIFEST;
        return;
    }

    oci_status_pin_code_t resolve_code = OCI_STATUS_PIN_OK;
    char *config_digest =
        resolve_config_digest(store, out->digest, &resolve_code, 0);
    if (!config_digest) {
        out->status = resolve_code;
        return;
    }

    /* Capture image-config blob size when present. A missing config blob is
     * the CORRUPT_CONFIG sentinel: the manifest was readable but the image
     * is structurally incomplete. */
    uint64_t cfg_size = 0;
    if (stat_blob(blobs, config_digest, &cfg_size, NULL) < 0) {
        free(config_digest);
        out->status = OCI_STATUS_PIN_CORRUPT_CONFIG;
        return;
    }
    out->config_size = cfg_size;

    char **diff_ids = load_diff_ids(store, config_digest);
    free(config_digest);
    if (!diff_ids) {
        out->status = OCI_STATUS_PIN_CORRUPT_CONFIG;
        return;
    }
    size_t layer_count = 0;
    while (diff_ids[layer_count])
        layer_count++;
    out->layer_count = layer_count;

    /* Accumulate union sets so the populate ratios can run later. A failure
     * inside accumulate_chain is treated as CORRUPT_CONFIG for the row but
     * the partial entries stay in the accumulators: the union shape means
     * a partial walk only ever inflates "reachable" honestly without
     * over-reporting "populated".
     */
    if (accumulate_chain(diff_ids, diff_acc, chain_acc) < 0) {
        free_strv(diff_ids);
        out->status = OCI_STATUS_PIN_CORRUPT_CONFIG;
        return;
    }
    free_strv(diff_ids);
    out->status = OCI_STATUS_PIN_OK;
}

/* ── Per-unpacked-tree walk ───────────────────────────────────────────── */

static void walk_unpacked_entry(const char *tree_path,
                                bool skip_disk_usage,
                                oci_status_unpacked_entry_t *out,
                                oci_digest_set_t *diff_acc,
                                oci_digest_set_t *chain_acc)
{
    memset(out, 0, sizeof(*out));
    out->path = strdup(tree_path ? tree_path : "");
    if (!out->path) {
        out->status = OCI_STATUS_UNPACKED_MISSING_ORIGIN;
        return;
    }
    if (!skip_disk_usage)
        out->tree_bytes = sum_tree_size(tree_path);

    oci_origin_t origin = {0};
    if (oci_origin_read(tree_path, &origin, NULL) < 0) {
        out->status = (errno == ENOENT) ? OCI_STATUS_UNPACKED_MISSING_ORIGIN
                                        : OCI_STATUS_UNPACKED_CORRUPT_ORIGIN;
        return;
    }
    if (origin.manifest_digest) {
        out->manifest_digest = strdup(origin.manifest_digest);
        /* strdup failure for the digest is rare; surface as corrupt-origin
         * so the row is still listed.
         */
        if (!out->manifest_digest) {
            oci_origin_free(&origin);
            out->status = OCI_STATUS_UNPACKED_CORRUPT_ORIGIN;
            return;
        }
    }
    if (origin.layer_diffids) {
        size_t n = 0;
        while (origin.layer_diffids[n])
            n++;
        out->layer_count = n;
        if (n > 0 &&
            accumulate_chain(origin.layer_diffids, diff_acc, chain_acc) < 0) {
            oci_origin_free(&origin);
            out->status = OCI_STATUS_UNPACKED_CORRUPT_ORIGIN;
            return;
        }
    }
    oci_origin_free(&origin);
    out->status = OCI_STATUS_UNPACKED_OK;
}

/* ── Public entry point ───────────────────────────────────────────────── */

void oci_status_free(oci_status_t *out)
{
    if (!out)
        return;
    if (out->pins) {
        for (size_t i = 0; i < out->pin_count; i++) {
            free(out->pins[i].name);
            free(out->pins[i].digest);
        }
        free(out->pins);
    }
    if (out->unpacked) {
        for (size_t i = 0; i < out->unpacked_count; i++) {
            free(out->unpacked[i].path);
            free(out->unpacked[i].manifest_digest);
        }
        free(out->unpacked);
    }
    memset(out, 0, sizeof(*out));
}

int oci_status_compute(oci_store_t *store,
                       const oci_status_options_t *opts,
                       oci_status_t *out,
                       const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;

    if (!store || !out) {
        *err = "status_compute: NULL argument";
        errno = EINVAL;
        return -1;
    }
    memset(out, 0, sizeof(*out));

    bool skip_du = opts && opts->skip_disk_usage;
    out->disk_usage_skipped = skip_du;
    const char *volume_root = opts ? opts->volume_root : NULL;

    oci_digest_set_t diff_acc = {0};
    oci_digest_set_t chain_acc = {0};

    /* 1. Pin walk. An unreadable index.json (or a missing one) is treated
     * as the empty case here: the rest of the snapshot still has value
     * (store totals, layer caches) and surfacing the failure would be a
     * regression vs the rest of the OCI CLI which all treat missing
     * pins as empty.
     */
    oci_pin_list_t pins = {0};
    const char *list_err = NULL;
    if (oci_store_list_refs(store, &pins, &list_err) == 0 && pins.count > 0) {
        out->pins = calloc(pins.count, sizeof(*out->pins));
        if (!out->pins) {
            oci_pin_list_free(&pins);
            oci_digest_set_free(&diff_acc);
            oci_digest_set_free(&chain_acc);
            *err = "status_compute: out of memory allocating pin rows";
            errno = ENOMEM;
            return -1;
        }
        out->pin_count = pins.count;
        for (size_t i = 0; i < pins.count; i++) {
            walk_pin_entry(store, &pins.items[i], &out->pins[i], &diff_acc,
                           &chain_acc);
        }
    }
    oci_pin_list_free(&pins);

    /* 2. Unpacked sysroots when volume_root is provided. */
    if (volume_root) {
        oci_volume_list_t trees = {0};
        if (oci_volume_list_unpacked(volume_root, &trees, NULL) == 0 &&
            trees.count > 0) {
            out->unpacked = calloc(trees.count, sizeof(*out->unpacked));
            if (!out->unpacked) {
                oci_volume_list_free(&trees);
                oci_digest_set_free(&diff_acc);
                oci_digest_set_free(&chain_acc);
                oci_status_free(out);
                *err = "status_compute: out of memory allocating unpacked rows";
                errno = ENOMEM;
                return -1;
            }
            out->unpacked_count = trees.count;
            for (size_t i = 0; i < trees.count; i++) {
                walk_unpacked_entry(trees.items[i], skip_du, &out->unpacked[i],
                                    &diff_acc, &chain_acc);
            }
        }
        oci_volume_list_free(&trees);
    }

    /* 3. Store totals (counts always; bytes only when not skipped). */
    const char *root = oci_store_root(store);
    if (!root) {
        oci_digest_set_free(&diff_acc);
        oci_digest_set_free(&chain_acc);
        oci_status_free(out);
        *err = "status_compute: store has no root path";
        errno = EINVAL;
        return -1;
    }

    for (size_t i = 0; i < STATUS_ALGOS_LEN; i++) {
        if (sweep_blob_algo(root, STATUS_ALGOS[i], skip_du, &out->blob_count,
                            &out->blob_bytes_total) < 0) {
            int saved = errno;
            oci_digest_set_free(&diff_acc);
            oci_digest_set_free(&chain_acc);
            oci_status_free(out);
            *err = "status_compute: blob sweep failed";
            errno = saved;
            return -1;
        }
    }
    for (size_t i = 0; i < STATUS_ALGOS_LEN; i++) {
        if (sweep_tree_family(root, "layers", STATUS_ALGOS[i], skip_du,
                              &out->layer_cache_count,
                              &out->layer_cache_bytes_total) < 0) {
            int saved = errno;
            oci_digest_set_free(&diff_acc);
            oci_digest_set_free(&chain_acc);
            oci_status_free(out);
            *err = "status_compute: layers/ sweep failed";
            errno = saved;
            return -1;
        }
    }
    for (size_t i = 0; i < STATUS_ALGOS_LEN; i++) {
        if (sweep_tree_family(root, "layers/stacks", STATUS_ALGOS[i], skip_du,
                              &out->stack_cache_count,
                              &out->stack_cache_bytes_total) < 0) {
            int saved = errno;
            oci_digest_set_free(&diff_acc);
            oci_digest_set_free(&chain_acc);
            oci_status_free(out);
            *err = "status_compute: layers/stacks/ sweep failed";
            errno = saved;
            return -1;
        }
    }

    /* 4. Populate ratios. Iterate the reachable diff_id and ChainID sets
     * and probe each against its respective cache family. Each entry is at
     * most one stat(2) so the cost is O(R) where R = reachable count.
     */
    out->diff_ids_reachable = oci_digest_set_size(&diff_acc);
    for (size_t i = 0; i < out->diff_ids_reachable; i++) {
        const char *d = oci_digest_set_at(&diff_acc, i);
        if (d && tree_entry_exists(root, "layers", d))
            out->diff_ids_populated++;
    }
    out->chain_ids_reachable = oci_digest_set_size(&chain_acc);
    for (size_t i = 0; i < out->chain_ids_reachable; i++) {
        const char *c = oci_digest_set_at(&chain_acc, i);
        if (c && tree_entry_exists(root, "layers/stacks", c))
            out->chain_ids_populated++;
    }

    oci_digest_set_free(&diff_acc);
    oci_digest_set_free(&chain_acc);
    (void) list_err; /* swallowed: missing index.json is the empty case */
    return 0;
}
