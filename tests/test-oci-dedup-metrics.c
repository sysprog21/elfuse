/* OCI cross-image dedup metrics unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives oci_dedup_metrics_compute against scratch stores hand-populated via
 * oci_blob_store_put_bytes + oci_store_put_ref + (for the volume_root cases)
 * oci_origin_write into a fixture images/sha256-<hex>/ tree. The helper is
 * exercised through its public C surface; the inspect-renderer integration
 * lives in test-oci-inspect.
 *
 * Cases:
 *   1. single image in store - compared_images=0, shared=0
 *   2. two pinned images, 2 of 3 layers shared - shared_layers=2,
 *      shared_bytes>0, deepest_prefix=2
 *   3. two pinned images with disjoint diff_ids - shared=0, deepest=0
 *   4. self-exclusion: re-pin same manifest under another name -
 *      compared_images=0 even though list_refs returns two pins
 *   5. shared layer with reversed order - shared_layers>=1 but
 *      deepest_prefix=0
 *   6. image-index pin: dedup walker resolves linux/arm64 sub-manifest
 *   7. other image's config blob missing - that image is skipped silently
 *
 * Layer raw cache entries are populated by writing a marker file into
 * <store>/layers/sha256/<diff_id_hex>/payload.bin; shared_bytes accumulates
 * st_size of that file. Diff-id values are synthetic
 * "sha256:0000...000<N>" strings: the dedup walker treats them as opaque
 * keys, so the test fixtures do not need to hash real tar payloads.
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
#include "oci/dedup-metrics.h"
#include "oci/digest.h"
#include "oci/origin-meta.h"
#include "oci/ref.h"
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
    char tmpl[] = "/tmp/elfuse-test-oci-dedup-XXXXXX";
    if (!mkdtemp(tmpl))
        return NULL;
    return strdup(tmpl);
}

/* Synthetic diff_id producer: produces "sha256:" followed by 63 zero hex
 * digits and one digit drawn from id, so distinct ids yield distinct
 * canonical digest strings without forcing the test to compute SHA-256
 * over a fixture payload. id must be in [1, 15] so the trailing nibble
 * fits a single hex digit; the caller never needs more than that.
 */
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

/* Hash body and put it into the blob store; returns the canonical
 * "sha256:<hex>" digest string (heap, caller frees).
 */
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

/* Build and put an image-config blob with given diff_ids. */
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

/* Build and put an image-manifest referencing config_digest + n_layers layer
 * descriptors. Layer descriptors point at synthetic layer blob digests that
 * are NEVER read (dedup metrics walks config only); they just need to be
 * valid "<algo>:<hex>" strings. Returns the manifest blob digest.
 */
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

/* Build and put an image-index referencing arm64_manifest_digest. */
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

/* Populate <store_root>/layers/sha256/<hex>/payload.bin with `bytes` bytes
 * of zeros so the dedup walker's stat-tree can compute a non-zero
 * shared_bytes. Returns true on success.
 */
static bool populate_raw_cache(const char *store_root,
                               const char *diff_id,
                               size_t bytes)
{
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(diff_id, &algo, hex))
        return false;
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/layers/sha256/%s", store_root, hex);
    if (mkdir(dir, 0755) < 0 && errno != EEXIST)
        return false;
    char path[1024];
    snprintf(path, sizeof(path), "%s/payload.bin", dir);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return false;
    static const char ZEROS[256] = {0};
    size_t remaining = bytes;
    while (remaining > 0) {
        size_t chunk = remaining > sizeof(ZEROS) ? sizeof(ZEROS) : remaining;
        ssize_t w = write(fd, ZEROS, chunk);
        if (w < 0) {
            int saved = errno;
            close(fd);
            errno = saved;
            return false;
        }
        remaining -= (size_t) w;
    }
    close(fd);
    return true;
}

/* Create <volume_root>/images/sha256-<hex_tag>/ and seed its origin
 * sidecar.
 */
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

/* Case 1: only one image in the store --------------------------------- */

static void case_single_image_no_others(const char *scratch)
{
    const char *name = "dedup: single image in store reports compared=0";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-single", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n(1);
    char *d2 = diff_id_n(2);
    char *diffs[] = {d1, d2, NULL};
    char *cfg = put_config(blobs, diffs);
    char *mf = put_manifest(blobs, cfg, 2);
    pin(store, "scratch:single", mf);

    oci_dedup_metrics_t m = {0};
    const char *err = NULL;
    int rc = oci_dedup_metrics_compute(store, mf, NULL, &m, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
    } else if (m.compared_images != 0) {
        report_fail(name, "compared=%zu (expected 0)", m.compared_images);
    } else if (m.total_layers != 2) {
        report_fail(name, "total_layers=%zu (expected 2)", m.total_layers);
    } else if (m.shared_layers != 0) {
        report_fail(name, "shared=%zu (expected 0)", m.shared_layers);
    } else if (m.deepest_shared_prefix != 0) {
        report_fail(name, "deepest=%zu (expected 0)", m.deepest_shared_prefix);
    } else {
        report_pass(name);
    }

    free(d1);
    free(d2);
    free(cfg);
    free(mf);
    oci_store_close(store);
}

/* Case 2: two pinned images sharing two layers ------------------------ */

static void case_two_images_shared_layers(const char *scratch)
{
    const char *name = "dedup: two images, 2 of 3 layers shared";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-shared", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n(1);
    char *d2 = diff_id_n(2);
    char *d3 = diff_id_n(3); /* target-only */
    char *d4 = diff_id_n(4); /* other-only */

    char *target_diffs[] = {d1, d2, d3, NULL};
    char *target_cfg = put_config(blobs, target_diffs);
    char *target_mf = put_manifest(blobs, target_cfg, 3);
    pin(store, "scratch:target", target_mf);

    char *other_diffs[] = {d1, d2, d4, NULL};
    char *other_cfg = put_config(blobs, other_diffs);
    char *other_mf = put_manifest(blobs, other_cfg, 3);
    pin(store, "scratch:other", other_mf);

    /* Populate raw cache for d1 (shared, 200 B) and d2 (shared, 300 B)
     * so shared_bytes can be checked; d3 / d4 are intentionally absent.
     */
    populate_raw_cache(root, d1, 200);
    populate_raw_cache(root, d2, 300);

    oci_dedup_metrics_t m = {0};
    const char *err = NULL;
    int rc = oci_dedup_metrics_compute(store, target_mf, NULL, &m, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
    } else if (m.compared_images != 1) {
        report_fail(name, "compared=%zu (expected 1)", m.compared_images);
    } else if (m.total_layers != 3) {
        report_fail(name, "total=%zu (expected 3)", m.total_layers);
    } else if (m.shared_layers != 2) {
        report_fail(name, "shared=%zu (expected 2)", m.shared_layers);
    } else if (m.shared_bytes != 500) {
        report_fail(name, "shared_bytes=%llu (expected 500)",
                    (unsigned long long) m.shared_bytes);
    } else if (m.deepest_shared_prefix != 2) {
        report_fail(name, "deepest=%zu (expected 2)", m.deepest_shared_prefix);
    } else {
        report_pass(name);
    }

    free(d1);
    free(d2);
    free(d3);
    free(d4);
    free(target_cfg);
    free(target_mf);
    free(other_cfg);
    free(other_mf);
    oci_store_close(store);
}

/* Case 3: two pinned images with disjoint diff_ids -------------------- */

static void case_two_images_disjoint(const char *scratch)
{
    const char *name = "dedup: two images, disjoint diff_ids -> 0 shared";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-disjoint", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n(1);
    char *d2 = diff_id_n(2);
    char *d5 = diff_id_n(5);
    char *d6 = diff_id_n(6);

    char *target_diffs[] = {d1, d2, NULL};
    char *target_cfg = put_config(blobs, target_diffs);
    char *target_mf = put_manifest(blobs, target_cfg, 2);
    pin(store, "scratch:target", target_mf);

    char *other_diffs[] = {d5, d6, NULL};
    char *other_cfg = put_config(blobs, other_diffs);
    char *other_mf = put_manifest(blobs, other_cfg, 2);
    pin(store, "scratch:other", other_mf);

    oci_dedup_metrics_t m = {0};
    const char *err = NULL;
    int rc = oci_dedup_metrics_compute(store, target_mf, NULL, &m, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
    } else if (m.compared_images != 1) {
        report_fail(name, "compared=%zu (expected 1)", m.compared_images);
    } else if (m.shared_layers != 0) {
        report_fail(name, "shared=%zu (expected 0)", m.shared_layers);
    } else if (m.deepest_shared_prefix != 0) {
        report_fail(name, "deepest=%zu (expected 0)", m.deepest_shared_prefix);
    } else {
        report_pass(name);
    }

    free(d1);
    free(d2);
    free(d5);
    free(d6);
    free(target_cfg);
    free(target_mf);
    free(other_cfg);
    free(other_mf);
    oci_store_close(store);
}

/* Case 4: re-pin same manifest as another tag - self is excluded -------- */

static void case_self_excluded(const char *scratch)
{
    const char *name = "dedup: same manifest pinned twice -> compared=0";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-self", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n(1);
    char *d2 = diff_id_n(2);
    char *diffs[] = {d1, d2, NULL};
    char *cfg = put_config(blobs, diffs);
    char *mf = put_manifest(blobs, cfg, 2);
    pin(store, "scratch:alpha", mf);
    pin(store, "scratch:beta", mf);

    oci_dedup_metrics_t m = {0};
    const char *err = NULL;
    int rc = oci_dedup_metrics_compute(store, mf, NULL, &m, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
    } else if (m.compared_images != 0) {
        report_fail(name, "compared=%zu (expected 0)", m.compared_images);
    } else {
        report_pass(name);
    }

    free(d1);
    free(d2);
    free(cfg);
    free(mf);
    oci_store_close(store);
}

/* Case 5: shared layer in reversed order - no shared prefix ------------ */

static void case_shared_layer_no_prefix(const char *scratch)
{
    const char *name =
        "dedup: shared diff_id at different positions -> deepest=0";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-reorder", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n(1);
    char *d2 = diff_id_n(2);

    /* target = [d1, d2], other = [d2, d1]. The two share both diff_ids
     * (shared_layers=2) but ChainID(target[0])=ChainID(d1) differs from
     * ChainID(other[0])=ChainID(d2), so no prefix lines up.
     */
    char *target_diffs[] = {d1, d2, NULL};
    char *target_cfg = put_config(blobs, target_diffs);
    char *target_mf = put_manifest(blobs, target_cfg, 2);
    pin(store, "scratch:target", target_mf);

    char *other_diffs[] = {d2, d1, NULL};
    char *other_cfg = put_config(blobs, other_diffs);
    char *other_mf = put_manifest(blobs, other_cfg, 2);
    pin(store, "scratch:other", other_mf);

    oci_dedup_metrics_t m = {0};
    const char *err = NULL;
    int rc = oci_dedup_metrics_compute(store, target_mf, NULL, &m, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
    } else if (m.shared_layers != 2) {
        report_fail(name, "shared=%zu (expected 2)", m.shared_layers);
    } else if (m.deepest_shared_prefix != 0) {
        report_fail(name, "deepest=%zu (expected 0)", m.deepest_shared_prefix);
    } else {
        report_pass(name);
    }

    free(d1);
    free(d2);
    free(target_cfg);
    free(target_mf);
    free(other_cfg);
    free(other_mf);
    oci_store_close(store);
}

/* Case 6: image-index pin resolves to arm64 sub-manifest -------------- */

static void case_index_pin_picks_arm64(const char *scratch)
{
    const char *name =
        "dedup: image-index pin contributes via arm64 sub-manifest";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-index", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n(1);
    char *d2 = diff_id_n(2);
    char *target_diffs[] = {d1, d2, NULL};
    char *target_cfg = put_config(blobs, target_diffs);
    char *target_mf = put_manifest(blobs, target_cfg, 2);
    pin(store, "scratch:target", target_mf);

    /* Other image: build an arm64 manifest that shares d1, wrap it in an
     * image-index, and pin the index. The dedup walker must drill into
     * the index, pick linux/arm64, parse the sub-manifest's config, and
     * pull d1 into the accumulator.
     */
    char *d3 = diff_id_n(3);
    char *other_arm_diffs[] = {d1, d3, NULL};
    char *other_arm_cfg = put_config(blobs, other_arm_diffs);
    char *other_arm_mf = put_manifest(blobs, other_arm_cfg, 2);
    char *other_index = put_index_arm64(blobs, other_arm_mf);
    pin(store, "scratch:index-other", other_index);

    oci_dedup_metrics_t m = {0};
    const char *err = NULL;
    int rc = oci_dedup_metrics_compute(store, target_mf, NULL, &m, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
    } else if (m.compared_images != 1) {
        report_fail(name, "compared=%zu (expected 1)", m.compared_images);
    } else if (m.shared_layers != 1) {
        report_fail(name, "shared=%zu (expected 1)", m.shared_layers);
    } else if (m.deepest_shared_prefix != 1) {
        report_fail(name, "deepest=%zu (expected 1)", m.deepest_shared_prefix);
    } else {
        report_pass(name);
    }

    free(d1);
    free(d2);
    free(d3);
    free(target_cfg);
    free(target_mf);
    free(other_arm_cfg);
    free(other_arm_mf);
    free(other_index);
    oci_store_close(store);
}

/* Case 7: other image's config blob missing - skipped silently --------- */

static void case_other_config_missing_skipped(const char *scratch)
{
    const char *name =
        "dedup: other image's config blob missing -> compared excludes it";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-config-missing", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n(1);
    char *d2 = diff_id_n(2);
    char *target_diffs[] = {d1, d2, NULL};
    char *target_cfg = put_config(blobs, target_diffs);
    char *target_mf = put_manifest(blobs, target_cfg, 2);
    pin(store, "scratch:target", target_mf);

    /* Other A: complete, contributes d2. */
    char *other_a_diffs[] = {d2, NULL};
    char *other_a_cfg = put_config(blobs, other_a_diffs);
    char *other_a_mf = put_manifest(blobs, other_a_cfg, 1);
    pin(store, "scratch:other-a", other_a_mf);

    /* Other B: build manifest + config, pin the manifest, then unlink the
     * config blob on disk so the dedup walker hits ENOENT when it tries
     * to read it. Use a synthetic third diff_id so the test can detect
     * whether B's data leaked in by accident.
     */
    char *d_b = diff_id_n(7);
    char *other_b_diffs[] = {d_b, NULL};
    char *other_b_cfg = put_config(blobs, other_b_diffs);
    char *other_b_mf = put_manifest(blobs, other_b_cfg, 1);
    pin(store, "scratch:other-b", other_b_mf);
    /* Unlink the config blob from blobs/sha256/<hex>. */
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    oci_digest_parse(other_b_cfg, &algo, hex);
    char blob_path[1024];
    snprintf(blob_path, sizeof(blob_path), "%s/blobs/sha256/%s", root, hex);
    unlink(blob_path);

    oci_dedup_metrics_t m = {0};
    const char *err = NULL;
    int rc = oci_dedup_metrics_compute(store, target_mf, NULL, &m, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
    } else if (m.compared_images != 1) {
        report_fail(name, "compared=%zu (expected 1: B is skipped)",
                    m.compared_images);
    } else if (m.shared_layers != 1) {
        report_fail(name, "shared=%zu (expected 1: only d2 from A)",
                    m.shared_layers);
    } else {
        report_pass(name);
    }

    free(d1);
    free(d2);
    free(d_b);
    free(target_cfg);
    free(target_mf);
    free(other_a_cfg);
    free(other_a_mf);
    free(other_b_cfg);
    free(other_b_mf);
    oci_store_close(store);
}

/* Case 8: unpacked sysroot contributes via volume_root walk ----------- */

static void case_unpacked_tree_contributes(const char *scratch)
{
    const char *name =
        "dedup: unpacked sysroot at volume_root contributes diff_ids";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-unpacked-store", scratch);
    char volume[1024];
    snprintf(volume, sizeof(volume), "%s/case-unpacked-vol", scratch);
    mkdir(volume, 0755);

    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n(1);
    char *d2 = diff_id_n(2);
    char *target_diffs[] = {d1, d2, NULL};
    char *target_cfg = put_config(blobs, target_diffs);
    char *target_mf = put_manifest(blobs, target_cfg, 2);
    pin(store, "scratch:target", target_mf);

    /* Other image lives purely as an unpacked tree (no pin). Its origin
     * sidecar records a manifest digest that is NEVER on disk; the dedup
     * walker reads diff_ids directly from .elfuse-origin.json so this
     * works regardless.
     */
    char *d3 = diff_id_n(3);
    char *other_diffs[] = {d2, d3, NULL};
    static const char OTHER_M[] =
        "sha256:"
        "dead00000000000000000000000000000000000000000000000000000000beef";
    static const char OTHER_C[] =
        "sha256:"
        "cafe00000000000000000000000000000000000000000000000000000000babe";
    seed_unpacked_tree(
        volume,
        "fa00000000000000000000000000000000000000000000000000000000000001",
        OTHER_M, OTHER_C, other_diffs);

    oci_dedup_metrics_t m = {0};
    const char *err = NULL;
    int rc = oci_dedup_metrics_compute(store, target_mf, volume, &m, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
    } else if (m.compared_images != 1) {
        report_fail(name, "compared=%zu (expected 1)", m.compared_images);
    } else if (m.shared_layers != 1) {
        report_fail(name, "shared=%zu (expected 1: only d2 overlaps)",
                    m.shared_layers);
    } else {
        report_pass(name);
    }

    free(d1);
    free(d2);
    free(d3);
    free(target_cfg);
    free(target_mf);
    oci_store_close(store);
}

int main(void)
{
    char *scratch = make_scratch_root();
    if (!scratch) {
        fprintf(stderr, "scratch root mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }
    printf("OCI dedup metrics unit tests (scratch=%s)\n", scratch);

    case_single_image_no_others(scratch);
    case_two_images_shared_layers(scratch);
    case_two_images_disjoint(scratch);
    case_self_excluded(scratch);
    case_shared_layer_no_prefix(scratch);
    case_index_pin_picks_arm64(scratch);
    case_other_config_missing_skipped(scratch);
    case_unpacked_tree_contributes(scratch);

    wipe_dir(scratch);
    free(scratch);

    printf("\nResults: %d/%d passed\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
