/* OCI store-wide status unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives oci_status_compute against scratch stores hand-populated through
 * oci_blob_store_put_bytes + oci_store_put_ref + oci_origin_write fixture
 * helpers. The helper is exercised through its public C surface; the CLI
 * render and JSON path are covered by tests/test-oci-compat.sh.
 *
 * Cases:
 *   1. empty_store - every count and ratio is zero
 *   2. single_pin_resolves_layer_count - manifest size, config size,
 *      layer_count, last_seen_mtime, status=OK
 *   3. pin_with_missing_manifest_blob - status=MISSING_MANIFEST, no walk
 *      contribution, no fatal exit
 *   4. pin_with_corrupt_manifest - status=CORRUPT_MANIFEST, sentinel row,
 *      walk keeps going for siblings
 *   5. pin_index_drills_to_arm64_sub - image-index pin resolves to the
 *      linux/arm64 sub-manifest's diff_ids
 *   6. unpacked_tree_listed - volume_root path + manifest_digest + size
 *   7. unpacked_tree_missing_origin - status=MISSING_ORIGIN sentinel
 *   8. skip_disk_usage_zero_sizes - every byte field is zero, counts intact
 *   9. populate_ratio - 5 reachable diff_ids, 3 cached -> 3/5
 *  10. two_images_share_layer_dedupes_union - shared diff_id counted once
 *
 * Helpers mirror the test-oci-dedup-metrics pattern (diff_id_n / put_blob /
 * put_config / put_manifest / put_index_arm64 / pin / populate_raw_cache /
 * populate_stack_cache / seed_unpacked_tree). All scratch directories live
 * under /tmp and are wiped on exit.
 */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "oci/blob-store.h"
#include "oci/digest.h"
#include "oci/origin-meta.h"
#include "oci/ref.h"
#include "oci/status.h"
#include "oci/store.h"

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

static int g_total = 0;
static int g_passed = 0;

static void report_pass(const char *name)
{
    g_total++;
    g_passed++;
    printf("  " GREEN "OK" RESET "   %s\n", name);
}

static void report_fail(const char *name, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void report_fail(const char *name, const char *fmt, ...)
{
    g_total++;
    printf("  " RED "FAIL" RESET " %s", name);
    if (fmt && *fmt) {
        printf(": ");
        va_list ap;
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }
    printf("\n");
}

static int remove_entry(const char *path,
                        const struct stat *st,
                        int typeflag,
                        struct FTW *ftwbuf)
{
    (void) st;
    (void) typeflag;
    (void) ftwbuf;
    return remove(path);
}

static void wipe_dir(const char *root)
{
    (void) nftw(root, remove_entry, 8, FTW_DEPTH | FTW_PHYS);
}

static char *make_scratch_root(void)
{
    char tmpl[] = "/tmp/elfuse-test-oci-status-XXXXXX";
    if (!mkdtemp(tmpl))
        return NULL;
    return strdup(tmpl);
}

/* Synthetic diff_id producer matching dedup-metrics tests. */
static char *diff_id_n(int id)
{
    char *r = malloc(80);
    if (!r)
        return NULL;
    snprintf(r, 80,
             "sha256:00000000000000000000000000000000000000000000000000000000"
             "0000000%x",
             id & 0xf);
    return r;
}

/* Hash body and put it into the blob store; returns "sha256:<hex>". */
static char *put_blob(oci_blob_store_t *blobs, const char *body, size_t len)
{
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (oci_digest_bytes(OCI_DIGEST_SHA256, body, len, hex) == 0)
        return NULL;
    if (oci_blob_store_put_bytes(blobs, OCI_DIGEST_SHA256, hex, body, len) < 0)
        return NULL;
    char *digest = malloc(OCI_DIGEST_HEX_MAX + 16);
    if (!digest)
        return NULL;
    snprintf(digest, OCI_DIGEST_HEX_MAX + 16, "sha256:%s", hex);
    return digest;
}

static char *vformat(size_t *out_len, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static char *vformat(size_t *out_len, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0)
        return NULL;
    char *r = malloc((size_t) n + 1);
    if (!r)
        return NULL;
    va_start(ap, fmt);
    vsnprintf(r, (size_t) n + 1, fmt, ap);
    va_end(ap);
    if (out_len)
        *out_len = (size_t) n;
    return r;
}

static char *put_config(oci_blob_store_t *blobs, char *const *diff_ids)
{
    char *diffs_buf = strdup("");
    if (!diffs_buf)
        return NULL;
    for (size_t i = 0; diff_ids[i]; i++) {
        size_t need = strlen(diffs_buf) + strlen(diff_ids[i]) + 8;
        char *grown = malloc(need);
        if (!grown) {
            free(diffs_buf);
            return NULL;
        }
        snprintf(grown, need, "%s%s\"%s\"", diffs_buf, i == 0 ? "" : ",",
                 diff_ids[i]);
        free(diffs_buf);
        diffs_buf = grown;
    }
    char *body = vformat(NULL,
                         "{\"architecture\":\"arm64\",\"os\":\"linux\","
                         "\"config\":{},\"rootfs\":{\"type\":\"layers\","
                         "\"diff_ids\":[%s]}}",
                         diffs_buf);
    free(diffs_buf);
    if (!body)
        return NULL;
    char *digest = put_blob(blobs, body, strlen(body));
    free(body);
    return digest;
}

static char *put_manifest(oci_blob_store_t *blobs,
                          const char *config_digest,
                          size_t n_layers)
{
    char *layers_buf = strdup("");
    if (!layers_buf)
        return NULL;
    for (size_t i = 0; i < n_layers; i++) {
        char layer_digest[80];
        snprintf(
            layer_digest, sizeof(layer_digest),
            "sha256:11111111111111111111111111111111111111111111111111111111"
            "1111111%x",
            (int) (i & 0xf));
        size_t need = strlen(layers_buf) + 256;
        char *grown = malloc(need);
        if (!grown) {
            free(layers_buf);
            return NULL;
        }
        snprintf(grown, need,
                 "%s%s{\"mediaType\":"
                 "\"application/vnd.oci.image.layer.v1.tar+gzip\","
                 "\"digest\":\"%s\",\"size\":1}",
                 layers_buf, i == 0 ? "" : ",", layer_digest);
        free(layers_buf);
        layers_buf = grown;
    }
    char *body =
        vformat(NULL,
                "{\"schemaVersion\":2,"
                "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
                "\"config\":{\"mediaType\":\"application/"
                "vnd.oci.image.config.v1+json\","
                "\"digest\":\"%s\",\"size\":1},"
                "\"layers\":[%s]}",
                config_digest, layers_buf);
    free(layers_buf);
    if (!body)
        return NULL;
    char *digest = put_blob(blobs, body, strlen(body));
    free(body);
    return digest;
}

static char *put_index_arm64(oci_blob_store_t *blobs,
                             const char *arm64_manifest_digest)
{
    char *body =
        vformat(NULL,
                "{\"schemaVersion\":2,"
                "\"mediaType\":\"application/vnd.oci.image.index.v1+json\","
                "\"manifests\":[{\"mediaType\":"
                "\"application/vnd.oci.image.manifest.v1+json\","
                "\"digest\":\"%s\",\"size\":1,"
                "\"platform\":{\"architecture\":\"arm64\",\"os\":\"linux\","
                "\"variant\":\"v8\"}}]}",
                arm64_manifest_digest);
    if (!body)
        return NULL;
    char *digest = put_blob(blobs, body, strlen(body));
    free(body);
    return digest;
}

static bool pin(oci_store_t *store,
                const char *ref_str,
                const char *manifest_digest)
{
    oci_ref_t ref = {0};
    if (oci_ref_parse(ref_str, &ref, NULL) < 0)
        return false;
    bool ok = oci_store_put_ref(store, &ref, manifest_digest, NULL) == 0;
    oci_ref_free(&ref);
    return ok;
}

/* Mkdir <store_root>/layers/sha256/<hex>/ to simulate a populated raw
 * cache entry. The status walker probes for directory existence and does
 * not require the entry to be non-empty.
 */
static bool populate_raw_cache(const char *store_root, const char *diff_id)
{
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(diff_id, &algo, hex))
        return false;
    char layers[1024];
    snprintf(layers, sizeof(layers), "%s/layers", store_root);
    mkdir(layers, 0755);
    char algo_dir[1024];
    snprintf(algo_dir, sizeof(algo_dir), "%s/layers/sha256", store_root);
    mkdir(algo_dir, 0755);
    char entry[1024];
    snprintf(entry, sizeof(entry), "%s/layers/sha256/%s", store_root, hex);
    if (mkdir(entry, 0755) < 0 && errno != EEXIST)
        return false;
    return true;
}

/* Mkdir <store_root>/layers/stacks/sha256/<hex>/ to simulate a populated
 * stack cache entry. Same shape as populate_raw_cache.
 */
static bool populate_stack_cache(const char *store_root, const char *chain_id)
{
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(chain_id, &algo, hex))
        return false;
    char stacks[1024];
    snprintf(stacks, sizeof(stacks), "%s/layers/stacks", store_root);
    mkdir(stacks, 0755);
    char algo_dir[1024];
    snprintf(algo_dir, sizeof(algo_dir), "%s/layers/stacks/sha256", store_root);
    mkdir(algo_dir, 0755);
    char entry[1024];
    snprintf(entry, sizeof(entry), "%s/layers/stacks/sha256/%s", store_root,
             hex);
    if (mkdir(entry, 0755) < 0 && errno != EEXIST)
        return false;
    return true;
}

static bool seed_unpacked_tree(const char *volume_root,
                               const char *hex_tag,
                               const char *manifest_digest,
                               const char *config_digest,
                               char *const *diff_ids)
{
    char images[1024];
    snprintf(images, sizeof(images), "%s/images", volume_root);
    mkdir(volume_root, 0755);
    mkdir(images, 0755);
    char tree[1024];
    snprintf(tree, sizeof(tree), "%s/sha256-%s", images, hex_tag);
    if (mkdir(tree, 0755) < 0 && errno != EEXIST)
        return false;
    return oci_origin_write(tree, manifest_digest, config_digest, diff_ids,
                            NULL) == 0;
}

/* Locate a pin row whose canonical name contains the given substring. Pin
 * names land as "docker.io/library/<repo>:<tag>" for short refs after the
 * ref parser fills in default registry / library defaults, so substring
 * match keeps the test caller readable ("scratch:garbage") without forcing
 * each case to spell out the canonical prefix.
 */
static const oci_status_pin_entry_t *find_pin(const oci_status_t *st,
                                              const char *needle)
{
    for (size_t i = 0; i < st->pin_count; i++) {
        if (st->pins[i].name && strstr(st->pins[i].name, needle))
            return &st->pins[i];
    }
    return NULL;
}

/* ── Case 1: empty store ─────────────────────────────────────────────── */

static void case_empty_store(const char *scratch)
{
    const char *name = "status: empty store yields zero counters";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-empty", scratch);
    oci_store_t *store = oci_store_open(root);
    if (!store) {
        report_fail(name, "open failed");
        return;
    }
    oci_status_t st = {0};
    const char *err = NULL;
    if (oci_status_compute(store, NULL, &st, &err) < 0) {
        report_fail(name, "rc<0 err=%s", err ? err : "(none)");
    } else if (st.pin_count != 0 || st.unpacked_count != 0 ||
               st.blob_count != 0 || st.layer_cache_count != 0 ||
               st.stack_cache_count != 0 || st.diff_ids_reachable != 0 ||
               st.diff_ids_populated != 0 || st.chain_ids_reachable != 0 ||
               st.chain_ids_populated != 0) {
        report_fail(name, "non-zero counters in empty store");
    } else {
        report_pass(name);
    }
    oci_status_free(&st);
    oci_store_close(store);
}

/* ── Case 2: single pin resolves layer count + sizes ─────────────────── */

static void case_single_pin(const char *scratch)
{
    const char *name = "status: single pin reports layer_count and sizes";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-single-pin", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n(1);
    char *d2 = diff_id_n(2);
    char *diffs[] = {d1, d2, NULL};
    char *cfg = put_config(blobs, diffs);
    char *mf = put_manifest(blobs, cfg, 2);
    pin(store, "scratch:single", mf);

    oci_status_t st = {0};
    const char *err = NULL;
    int rc = oci_status_compute(store, NULL, &st, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
        goto cleanup;
    }
    if (st.pin_count != 1) {
        report_fail(name, "pin_count=%zu (want 1)", st.pin_count);
        goto cleanup;
    }
    const oci_status_pin_entry_t *p = &st.pins[0];
    if (p->status != OCI_STATUS_PIN_OK) {
        report_fail(name, "status=%d (want OK)", (int) p->status);
        goto cleanup;
    }
    if (p->layer_count != 2) {
        report_fail(name, "layer_count=%zu (want 2)", p->layer_count);
        goto cleanup;
    }
    if (p->manifest_size == 0) {
        report_fail(name, "manifest_size=0 (want >0)");
        goto cleanup;
    }
    if (p->config_size == 0) {
        report_fail(name, "config_size=0 (want >0)");
        goto cleanup;
    }
    if (p->last_seen_mtime <= 0) {
        report_fail(name, "last_seen_mtime<=0");
        goto cleanup;
    }
    /* put_manifest only stages the config + manifest blobs (layer descriptors
     * carry synthetic digests never written to disk by put_blob), so the
     * minimum blob_count for one pin is 2.
     */
    if (st.blob_count < 2) {
        report_fail(name, "blob_count=%zu (want >=2)", st.blob_count);
        goto cleanup;
    }
    report_pass(name);

cleanup:
    oci_status_free(&st);
    free(d1);
    free(d2);
    free(cfg);
    free(mf);
    oci_store_close(store);
}

/* ── Case 3: pin with missing manifest blob ──────────────────────────── */

static void case_pin_missing_manifest(const char *scratch)
{
    const char *name = "status: pin with missing manifest reports sentinel";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-pin-missing", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    /* Stage a real blob, pin it, then unlink the blob on disk so the
     * walker hits MISSING_MANIFEST when it tries to stat / parse it.
     */
    char *d1 = diff_id_n(1);
    char *diffs[] = {d1, NULL};
    char *cfg = put_config(blobs, diffs);
    char *mf = put_manifest(blobs, cfg, 1);
    pin(store, "scratch:gone", mf);

    /* Locate and unlink the manifest blob. */
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    oci_digest_parse(mf, &algo, hex);
    char blob_path[1024];
    oci_blob_store_path(blobs, algo, hex, blob_path, sizeof(blob_path));
    unlink(blob_path);

    oci_status_t st = {0};
    int rc = oci_status_compute(store, NULL, &st, NULL);
    if (rc != 0) {
        report_fail(name, "rc=%d (want 0; missing manifest is soft)", rc);
    } else if (st.pin_count != 1) {
        report_fail(name, "pin_count=%zu (want 1)", st.pin_count);
    } else if (st.pins[0].status != OCI_STATUS_PIN_MISSING_MANIFEST) {
        report_fail(name, "status=%d (want MISSING_MANIFEST)",
                    (int) st.pins[0].status);
    } else if (st.pins[0].layer_count != 0) {
        report_fail(name, "layer_count=%zu (want 0 on miss)",
                    st.pins[0].layer_count);
    } else {
        report_pass(name);
    }
    oci_status_free(&st);
    free(d1);
    free(cfg);
    free(mf);
    oci_store_close(store);
}

/* ── Case 4: pin with corrupt manifest blob ──────────────────────────── */

static void case_pin_corrupt_manifest(const char *scratch)
{
    const char *name = "status: pin with corrupt manifest reports sentinel";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-pin-corrupt", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    /* Stage two healthy images, pin each, then overwrite the first manifest
     * blob with garbage bytes. oci_store_put_ref requires a parseable
     * manifest blob to derive mediaType, so corrupt-from-the-start would
     * never make it into index.json; corrupting the blob post-pin is the
     * only way to land a pin that names an unparseable blob.
     */
    char *db1 = diff_id_n(1);
    char *db_diffs[] = {db1, NULL};
    char *bad_cfg = put_config(blobs, db_diffs);
    char *bad_mf = put_manifest(blobs, bad_cfg, 1);
    pin(store, "scratch:garbage", bad_mf);

    char *d1 = diff_id_n(2);
    char *diffs[] = {d1, NULL};
    char *cfg = put_config(blobs, diffs);
    char *good_mf = put_manifest(blobs, cfg, 1);
    pin(store, "scratch:good", good_mf);

    /* Overwrite bad_mf blob with garbage so the walker sees unparseable
     * bytes when it slurps and parses the manifest body.
     */
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    oci_digest_parse(bad_mf, &algo, hex);
    char blob_path[1024];
    oci_blob_store_path(blobs, algo, hex, blob_path, sizeof(blob_path));
    int fd = open(blob_path, O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *garbage = "this is definitely not JSON {{{";
        (void) !write(fd, garbage, strlen(garbage));
        close(fd);
    }

    oci_status_t st = {0};
    int rc = oci_status_compute(store, NULL, &st, NULL);
    if (rc != 0) {
        report_fail(name, "rc=%d (want 0)", rc);
        goto cleanup;
    }
    if (st.pin_count != 2) {
        report_fail(name, "pin_count=%zu (want 2)", st.pin_count);
        goto cleanup;
    }
    const oci_status_pin_entry_t *bad = find_pin(&st, "scratch:garbage");
    const oci_status_pin_entry_t *good = find_pin(&st, "scratch:good");
    if (!bad || !good) {
        report_fail(name, "missing pin row");
        goto cleanup;
    }
    if (bad->status != OCI_STATUS_PIN_CORRUPT_MANIFEST) {
        report_fail(name, "bad.status=%d (want CORRUPT_MANIFEST)",
                    (int) bad->status);
        goto cleanup;
    }
    if (good->status != OCI_STATUS_PIN_OK) {
        report_fail(name, "good.status=%d (want OK)", (int) good->status);
        goto cleanup;
    }
    report_pass(name);

cleanup:
    oci_status_free(&st);
    free(db1);
    free(bad_cfg);
    free(bad_mf);
    free(d1);
    free(cfg);
    free(good_mf);
    oci_store_close(store);
}

/* ── Case 5: image-index pin drills to linux/arm64 sub-manifest ──────── */

static void case_pin_index_drill(const char *scratch)
{
    const char *name = "status: image-index pin drills to linux/arm64";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-pin-index", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n(1);
    char *d2 = diff_id_n(2);
    char *d3 = diff_id_n(3);
    char *diffs[] = {d1, d2, d3, NULL};
    char *cfg = put_config(blobs, diffs);
    char *sub_mf = put_manifest(blobs, cfg, 3);
    char *idx = put_index_arm64(blobs, sub_mf);
    pin(store, "scratch:index", idx);

    oci_status_t st = {0};
    int rc = oci_status_compute(store, NULL, &st, NULL);
    if (rc != 0) {
        report_fail(name, "rc=%d", rc);
    } else if (st.pin_count != 1) {
        report_fail(name, "pin_count=%zu (want 1)", st.pin_count);
    } else if (st.pins[0].status != OCI_STATUS_PIN_OK) {
        report_fail(name, "status=%d (want OK after drill)",
                    (int) st.pins[0].status);
    } else if (st.pins[0].layer_count != 3) {
        report_fail(name, "layer_count=%zu (want 3 via sub-manifest drill)",
                    st.pins[0].layer_count);
    } else {
        report_pass(name);
    }
    oci_status_free(&st);
    free(d1);
    free(d2);
    free(d3);
    free(cfg);
    free(sub_mf);
    free(idx);
    oci_store_close(store);
}

/* ── Case 6: unpacked tree listed ────────────────────────────────────── */

static void case_unpacked_tree_listed(const char *scratch)
{
    const char *name = "status: unpacked sysroot listed with digest and bytes";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-unp-list", scratch);
    char vol[1024];
    snprintf(vol, sizeof(vol), "%s/case-unp-vol", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n(1);
    char *d2 = diff_id_n(2);
    char *diffs[] = {d1, d2, NULL};
    char *cfg = put_config(blobs, diffs);
    char *mf = put_manifest(blobs, cfg, 2);
    /* No pin: this case checks the unpacked source in isolation. */

    const char *hex_tag =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    seed_unpacked_tree(vol, hex_tag, mf, cfg, diffs);

    /* Drop a sentinel byte file inside the tree so tree_bytes can be > 0. */
    char marker_path[1024];
    snprintf(marker_path, sizeof(marker_path), "%s/images/sha256-%s/marker",
             vol, hex_tag);
    int fd = open(marker_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *payload = "0123456789";
        (void) !write(fd, payload, 10);
        close(fd);
    }

    oci_status_options_t opts = {.volume_root = vol};
    oci_status_t st = {0};
    int rc = oci_status_compute(store, &opts, &st, NULL);
    if (rc != 0) {
        report_fail(name, "rc=%d", rc);
    } else if (st.unpacked_count != 1) {
        report_fail(name, "unpacked_count=%zu (want 1)", st.unpacked_count);
    } else if (st.unpacked[0].status != OCI_STATUS_UNPACKED_OK) {
        report_fail(name, "status=%d (want OK)", (int) st.unpacked[0].status);
    } else if (!st.unpacked[0].manifest_digest ||
               strcmp(st.unpacked[0].manifest_digest, mf) != 0) {
        report_fail(name, "manifest_digest mismatch");
    } else if (st.unpacked[0].layer_count != 2) {
        report_fail(name, "layer_count=%zu (want 2)",
                    st.unpacked[0].layer_count);
    } else if (st.unpacked[0].tree_bytes == 0) {
        report_fail(name, "tree_bytes=0 (want >0)");
    } else {
        report_pass(name);
    }
    oci_status_free(&st);
    free(d1);
    free(d2);
    free(cfg);
    free(mf);
    oci_store_close(store);
}

/* ── Case 7: unpacked tree missing origin sidecar ────────────────────── */

static void case_unpacked_tree_missing_origin(const char *scratch)
{
    const char *name = "status: unpacked sysroot with missing origin sentinel";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-unp-missorig", scratch);
    char vol[1024];
    snprintf(vol, sizeof(vol), "%s/case-unp-missorig-vol", scratch);
    oci_store_t *store = oci_store_open(root);

    /* Create the tree dir without writing an origin sidecar. */
    const char *hex_tag =
        "0000000000000000000000000000000000000000000000000000000000000001";
    char images[1024];
    snprintf(images, sizeof(images), "%s/images", vol);
    mkdir(vol, 0755);
    mkdir(images, 0755);
    char tree[1024];
    snprintf(tree, sizeof(tree), "%s/sha256-%s", images, hex_tag);
    mkdir(tree, 0755);

    oci_status_options_t opts = {.volume_root = vol};
    oci_status_t st = {0};
    int rc = oci_status_compute(store, &opts, &st, NULL);
    if (rc != 0) {
        report_fail(name, "rc=%d (want 0)", rc);
    } else if (st.unpacked_count != 1) {
        report_fail(name, "unpacked_count=%zu (want 1)", st.unpacked_count);
    } else if (st.unpacked[0].status != OCI_STATUS_UNPACKED_MISSING_ORIGIN) {
        report_fail(name, "status=%d (want MISSING_ORIGIN)",
                    (int) st.unpacked[0].status);
    } else {
        report_pass(name);
    }
    oci_status_free(&st);
    oci_store_close(store);
}

/* ── Case 8: --no-disk-usage skips byte sums ─────────────────────────── */

static void case_skip_disk_usage(const char *scratch)
{
    const char *name = "status: skip_disk_usage zeroes byte totals";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-skip-du", scratch);
    char vol[1024];
    snprintf(vol, sizeof(vol), "%s/case-skip-du-vol", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n(1);
    char *diffs[] = {d1, NULL};
    char *cfg = put_config(blobs, diffs);
    char *mf = put_manifest(blobs, cfg, 1);
    pin(store, "scratch:du", mf);

    const char *hex_tag =
        "1111111111111111111111111111111111111111111111111111111111111111";
    seed_unpacked_tree(vol, hex_tag, mf, cfg, diffs);

    populate_raw_cache(root, d1);

    oci_status_options_t opts = {
        .volume_root = vol,
        .skip_disk_usage = true,
    };
    oci_status_t st = {0};
    int rc = oci_status_compute(store, &opts, &st, NULL);
    if (rc != 0) {
        report_fail(name, "rc=%d", rc);
    } else if (!st.disk_usage_skipped) {
        report_fail(name, "disk_usage_skipped=false (want true)");
    } else if (st.blob_bytes_total != 0) {
        report_fail(name, "blob_bytes_total=%llu (want 0)",
                    (unsigned long long) st.blob_bytes_total);
    } else if (st.layer_cache_bytes_total != 0) {
        report_fail(name, "layer_cache_bytes=%llu (want 0)",
                    (unsigned long long) st.layer_cache_bytes_total);
    } else if (st.unpacked_count > 0 && st.unpacked[0].tree_bytes != 0) {
        report_fail(name, "tree_bytes=%llu (want 0)",
                    (unsigned long long) st.unpacked[0].tree_bytes);
    } else if (st.blob_count == 0) {
        report_fail(name, "blob_count=0 (counts must still populate)");
    } else if (st.layer_cache_count == 0) {
        report_fail(name, "layer_cache_count=0 (counts must still populate)");
    } else {
        report_pass(name);
    }
    oci_status_free(&st);
    free(d1);
    free(cfg);
    free(mf);
    oci_store_close(store);
}

/* ── Case 9: populate ratio computation ──────────────────────────────── */

static void case_populate_ratio(const char *scratch)
{
    const char *name = "status: populate ratio counts cached entries only";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-ratio", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n(1);
    char *d2 = diff_id_n(2);
    char *d3 = diff_id_n(3);
    char *d4 = diff_id_n(4);
    char *d5 = diff_id_n(5);
    char *diffs[] = {d1, d2, d3, d4, d5, NULL};
    char *cfg = put_config(blobs, diffs);
    char *mf = put_manifest(blobs, cfg, 5);
    pin(store, "scratch:ratio", mf);

    /* Populate 3 of 5 raw cache entries. The other 2 must be missing so
     * diff_ids_populated == 3 and diff_ids_reachable == 5.
     */
    populate_raw_cache(root, d1);
    populate_raw_cache(root, d3);
    populate_raw_cache(root, d5);

    /* Stack cache: populate the terminating ChainID only (1 of 5 reachable
     * prefixes) so chain_ids_populated == 1 and chain_ids_reachable == 5.
     */
    char chain_prev[OCI_DIGEST_HEX_MAX + 16] = "";
    char chains[5][OCI_DIGEST_HEX_MAX + 16];
    char *layer_strs[] = {d1, d2, d3, d4, d5};
    for (size_t i = 0; i < 5; i++) {
        const char *prev = i == 0 ? NULL : chain_prev;
        if (oci_chainid_compute(prev, layer_strs[i], chains[i],
                                sizeof(chains[i])) < 0) {
            report_fail(name, "chainid_compute failed at i=%zu", i);
            goto cleanup;
        }
        memcpy(chain_prev, chains[i], strlen(chains[i]) + 1);
    }
    populate_stack_cache(root, chains[4]);

    oci_status_t st = {0};
    int rc = oci_status_compute(store, NULL, &st, NULL);
    if (rc != 0) {
        report_fail(name, "rc=%d", rc);
    } else if (st.diff_ids_reachable != 5) {
        report_fail(name, "diff_ids_reachable=%zu (want 5)",
                    st.diff_ids_reachable);
    } else if (st.diff_ids_populated != 3) {
        report_fail(name, "diff_ids_populated=%zu (want 3)",
                    st.diff_ids_populated);
    } else if (st.chain_ids_reachable != 5) {
        report_fail(name, "chain_ids_reachable=%zu (want 5)",
                    st.chain_ids_reachable);
    } else if (st.chain_ids_populated != 1) {
        report_fail(name, "chain_ids_populated=%zu (want 1)",
                    st.chain_ids_populated);
    } else if (st.layer_cache_count != 3) {
        report_fail(name, "layer_cache_count=%zu (want 3)",
                    st.layer_cache_count);
    } else if (st.stack_cache_count != 1) {
        report_fail(name, "stack_cache_count=%zu (want 1)",
                    st.stack_cache_count);
    } else {
        report_pass(name);
    }
    oci_status_free(&st);

cleanup:
    free(d1);
    free(d2);
    free(d3);
    free(d4);
    free(d5);
    free(cfg);
    free(mf);
    oci_store_close(store);
}

/* ── Case 10: two images share a layer; union dedupes ───────────────── */

static void case_two_images_share_layer(const char *scratch)
{
    const char *name = "status: shared diff_id counted once in reachable union";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-share", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n(1); /* shared */
    char *d2 = diff_id_n(2);
    char *d3 = diff_id_n(3);
    char *a_diffs[] = {d1, d2, NULL};
    char *b_diffs[] = {d1, d3, NULL};

    char *a_cfg = put_config(blobs, a_diffs);
    char *a_mf = put_manifest(blobs, a_cfg, 2);
    pin(store, "scratch:a", a_mf);

    char *b_cfg = put_config(blobs, b_diffs);
    char *b_mf = put_manifest(blobs, b_cfg, 2);
    pin(store, "scratch:b", b_mf);

    oci_status_t st = {0};
    int rc = oci_status_compute(store, NULL, &st, NULL);
    if (rc != 0) {
        report_fail(name, "rc=%d", rc);
    } else if (st.diff_ids_reachable != 3) {
        /* d1 shared, d2 and d3 distinct: 3 in the union. */
        report_fail(name, "diff_ids_reachable=%zu (want 3)",
                    st.diff_ids_reachable);
    } else if (st.pin_count != 2) {
        report_fail(name, "pin_count=%zu (want 2)", st.pin_count);
    } else {
        report_pass(name);
    }
    oci_status_free(&st);
    free(d1);
    free(d2);
    free(d3);
    free(a_cfg);
    free(a_mf);
    free(b_cfg);
    free(b_mf);
    oci_store_close(store);
}

int main(void)
{
    printf("== test-oci-status ==\n");
    char *scratch = make_scratch_root();
    if (!scratch) {
        fprintf(stderr, "could not create scratch root: %s\n", strerror(errno));
        return 1;
    }

    case_empty_store(scratch);
    case_single_pin(scratch);
    case_pin_missing_manifest(scratch);
    case_pin_corrupt_manifest(scratch);
    case_pin_index_drill(scratch);
    case_unpacked_tree_listed(scratch);
    case_unpacked_tree_missing_origin(scratch);
    case_skip_disk_usage(scratch);
    case_populate_ratio(scratch);
    case_two_images_share_layer(scratch);

    wipe_dir(scratch);
    free(scratch);

    printf("\n  %d/%d passed\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
