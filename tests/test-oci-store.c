/* Local OCI image store unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives the pin / unpin / open / list invariants of src/oci/store.c against
 * an mkdtemp scratch root. Pin writes go through index.json (OCI image-index
 * v1.0.0 schema), so each test first persists a small manifest-shaped blob
 * under blobs/sha256/ and then pins by its digest. Coverage:
 *
 *   - open layout creation (oci-layout marker + blobs/sha256)
 *   - put + get round trip, with pin descriptor materialized in index.json
 *   - get miss surfaces ENOENT
 *   - digest-only refs are rejected (their digest is the pin)
 *   - malformed digest input is rejected
 *   - deep repository slashes are accepted (annotation key carries them)
 *   - overwrite-same-ref replaces the descriptor in place, no duplicates
 *   - blob + pin share the same store root
 *   - schema validity of the emitted index.json (top-level fields and
 *     descriptor shape)
 *   - enumeration API returns every pin
 *   - concurrent writers are serialized by flock and both pins survive
 *   - layout marker is fresh / backfilled / preserved
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include "oci/blob-store.h"
#include "oci/digest.h"
#include "oci/digest-set.h"
#include "oci/origin-meta.h"
#include "oci/ref.h"
#include "oci/store.h"
#include "oci/volume.h"

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

static int total = 0;
static int passed = 0;

static void report_pass(const char *name)
{
    total++;
    passed++;
    printf("  " GREEN "OK" RESET "   %s\n", name);
}

static void report_fail(const char *name, const char *detail)
{
    total++;
    printf("  " RED "FAIL" RESET " %s: %s\n", name, detail ? detail : "");
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
    char tmpl[] = "/tmp/elfuse-test-oci-store-XXXXXX";
    char *p = mkdtemp(tmpl);
    if (!p)
        return NULL;
    return strdup(p);
}

static bool parse_ref(const char *s, oci_ref_t *out)
{
    const char *err = NULL;
    if (oci_ref_parse(s, out, &err) < 0) {
        fprintf(stderr, "ref parse failed for %s: %s\n", s, err ? err : "?");
        return false;
    }
    return true;
}

/* Stage a manifest-shaped JSON blob under <store>/blobs/sha256/<hex>. The
 * body is hashed by the blob store; the caller receives the resulting
 * "<algo>:<hex>" digest in out_digest. The default body is an OCI image
 * manifest skeleton so infer_manifest_media_type picks the manifest media
 * type; pass NULL/0 to use the default.
 */
static bool stage_manifest_blob(oci_blob_store_t *blobs,
                                const char *body_opt,
                                size_t body_len_opt,
                                char *out_digest,
                                size_t cap)
{
    static const char DEFAULT_BODY[] =
        "{\"schemaVersion\":2,"
        "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"config\":{"
        "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
        "\"digest\":\"sha256:"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\","
        "\"size\":3},"
        "\"layers\":[]}";

    const char *body = body_opt ? body_opt : DEFAULT_BODY;
    size_t body_len = body_opt ? body_len_opt : sizeof(DEFAULT_BODY) - 1;

    oci_digester_t *d = oci_digester_new(OCI_DIGEST_SHA256);
    if (!d)
        return false;
    oci_digester_update(d, body, body_len);
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (oci_digester_finish_hex(d, hex) == 0) {
        oci_digester_free(d);
        return false;
    }
    oci_digester_free(d);
    if (oci_blob_store_put_bytes(blobs, OCI_DIGEST_SHA256, hex, body,
                                 body_len) < 0)
        return false;
    int n = snprintf(out_digest, cap, "sha256:%s", hex);
    if (n < 0 || (size_t) n >= cap)
        return false;
    return true;
}

static bool read_whole(const char *path, char *buf, size_t cap, size_t *out_len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;
    ssize_t got = read(fd, buf, cap - 1);
    close(fd);
    if (got < 0)
        return false;
    buf[got] = '\0';
    if (out_len)
        *out_len = (size_t) got;
    return true;
}

/* Slurp <root>/index.json and cJSON_Parse it. Returns NULL on missing or
 * unparseable. The caller cJSON_Delete()s.
 */
static cJSON *load_index_json(const char *root)
{
    char path[2048];
    snprintf(path, sizeof(path), "%s/index.json", root);
    char buf[8192];
    size_t got = 0;
    if (!read_whole(path, buf, sizeof(buf), &got))
        return NULL;
    return cJSON_Parse(buf);
}

static void test_open_creates_layout(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-open", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("open_creates_layout", "oci_store_open returned NULL");
        return;
    }
    struct stat st;
    char path[2048];
    snprintf(path, sizeof(path), "%s/blobs/sha256", root);
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        report_fail("open_creates_layout", "blobs/sha256 missing");
        oci_store_close(s);
        return;
    }
    snprintf(path, sizeof(path), "%s/oci-layout", root);
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        report_fail("open_creates_layout", "oci-layout missing");
        oci_store_close(s);
        return;
    }
    /* index.json is materialized only on first put; a fresh store should
     * have none on disk so external tools observe an empty image layout
     * rather than a phantom pin set.
     */
    snprintf(path, sizeof(path), "%s/index.json", root);
    if (stat(path, &st) == 0) {
        report_fail("open_creates_layout",
                    "index.json materialized before any pin");
        oci_store_close(s);
        return;
    }
    if (!oci_store_blobs(s)) {
        report_fail("open_creates_layout", "blobs handle is NULL");
        oci_store_close(s);
        return;
    }
    if (strcmp(oci_store_root(s), root) != 0) {
        report_fail("open_creates_layout", "root string mismatch");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("open_creates_layout");
}

static void test_put_get_round_trip(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-roundtrip", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("put_get_round_trip", "open failed");
        return;
    }
    char digest_str[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_manifest_blob(oci_store_blobs(s), NULL, 0, digest_str,
                             sizeof(digest_str))) {
        report_fail("put_get_round_trip", "could not stage manifest blob");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("alpine:3.20", &ref)) {
        report_fail("put_get_round_trip", "ref parse failed");
        oci_store_close(s);
        return;
    }
    const char *err = NULL;
    if (oci_store_put_ref(s, &ref, digest_str, &err) < 0) {
        report_fail("put_get_round_trip", err ? err : "put failed");
        goto cleanup;
    }
    char *got = NULL;
    if (oci_store_get_ref(s, &ref, &got, &err) < 0) {
        report_fail("put_get_round_trip", err ? err : "get failed");
        goto cleanup;
    }
    if (!got || strcmp(got, digest_str) != 0) {
        report_fail("put_get_round_trip", "digest mismatch");
        free(got);
        goto cleanup;
    }
    free(got);

    /* The index.json must exist and contain the canonical pin name. */
    cJSON *idx = load_index_json(root);
    if (!idx) {
        report_fail("put_get_round_trip", "index.json missing or unparseable");
        goto cleanup;
    }
    const cJSON *manifests = cJSON_GetObjectItemCaseSensitive(idx, "manifests");
    if (!cJSON_IsArray(manifests) || cJSON_GetArraySize(manifests) != 1) {
        report_fail("put_get_round_trip", "manifests array shape unexpected");
        cJSON_Delete(idx);
        goto cleanup;
    }
    const cJSON *entry = cJSON_GetArrayItem(manifests, 0);
    const cJSON *annots =
        cJSON_GetObjectItemCaseSensitive(entry, "annotations");
    const cJSON *name = cJSON_GetObjectItemCaseSensitive(
        annots, "org.opencontainers.image.ref.name");
    if (!cJSON_IsString(name) ||
        strcmp(name->valuestring, "docker.io/library/alpine:3.20") != 0) {
        report_fail("put_get_round_trip", "ref.name annotation mismatch");
        cJSON_Delete(idx);
        goto cleanup;
    }
    cJSON_Delete(idx);
    report_pass("put_get_round_trip");

cleanup:
    oci_ref_free(&ref);
    oci_store_close(s);
}

static void test_get_miss_enoent(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-miss", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("get_miss_enoent", "open failed");
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("ghcr.io/owner/img:tag", &ref)) {
        report_fail("get_miss_enoent", "ref parse failed");
        oci_store_close(s);
        return;
    }
    char *got = NULL;
    errno = 0;
    const char *err = NULL;
    int rc = oci_store_get_ref(s, &ref, &got, &err);
    if (rc == 0 || errno != ENOENT) {
        report_fail("get_miss_enoent", "expected -1 with ENOENT");
        free(got);
    } else if (got != NULL) {
        report_fail("get_miss_enoent", "out_digest must be NULL on miss");
    } else {
        report_pass("get_miss_enoent");
    }
    oci_ref_free(&ref);
    oci_store_close(s);
}

static void test_digest_only_ref_rejected(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-digest-only", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("digest_only_ref_rejected", "open failed");
        return;
    }
    oci_ref_t ref = {0};
    const char *err = NULL;
    if (oci_ref_parse(
            "alpine@sha256:"
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            &ref, &err) < 0) {
        report_fail("digest_only_ref_rejected", err ? err : "ref parse failed");
        oci_store_close(s);
        return;
    }
    if (ref.tag != NULL) {
        report_fail("digest_only_ref_rejected",
                    "digest-only ref unexpectedly carries a tag");
        oci_ref_free(&ref);
        oci_store_close(s);
        return;
    }
    err = NULL;
    errno = 0;
    int rc = oci_store_put_ref(
        s, &ref,
        "sha256:"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        &err);
    if (rc == 0 || errno != EINVAL) {
        report_fail("digest_only_ref_rejected", "expected EINVAL on put");
    } else {
        report_pass("digest_only_ref_rejected");
    }
    oci_ref_free(&ref);
    oci_store_close(s);
}

static void test_malformed_digest_rejected(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-bad-digest", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("malformed_digest_rejected", "open failed");
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("alpine:3.20", &ref)) {
        report_fail("malformed_digest_rejected", "ref parse failed");
        oci_store_close(s);
        return;
    }
    const char *err = NULL;
    errno = 0;
    int rc = oci_store_put_ref(s, &ref, "not-a-digest", &err);
    if (rc == 0 || errno != EINVAL) {
        report_fail("malformed_digest_rejected", "expected EINVAL on put");
    } else {
        report_pass("malformed_digest_rejected");
    }
    oci_ref_free(&ref);
    oci_store_close(s);
}

static void test_deep_repository(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-deep", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("deep_repository", "open failed");
        return;
    }
    char digest_str[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_manifest_blob(oci_store_blobs(s), NULL, 0, digest_str,
                             sizeof(digest_str))) {
        report_fail("deep_repository", "could not stage manifest blob");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("ghcr.io/owner/group/sub/img:v1.0", &ref)) {
        report_fail("deep_repository", "ref parse failed");
        oci_store_close(s);
        return;
    }
    const char *err = NULL;
    if (oci_store_put_ref(s, &ref, digest_str, &err) < 0) {
        report_fail("deep_repository", err ? err : "put failed");
        goto cleanup;
    }
    /* The annotation carries the full canonical name verbatim; no path
     * directory tree is created on disk.
     */
    cJSON *idx = load_index_json(root);
    if (!idx) {
        report_fail("deep_repository", "index.json missing");
        goto cleanup;
    }
    const cJSON *manifests = cJSON_GetObjectItemCaseSensitive(idx, "manifests");
    const cJSON *entry = cJSON_GetArrayItem(manifests, 0);
    const cJSON *annots =
        cJSON_GetObjectItemCaseSensitive(entry, "annotations");
    const cJSON *name = cJSON_GetObjectItemCaseSensitive(
        annots, "org.opencontainers.image.ref.name");
    if (!cJSON_IsString(name) ||
        strcmp(name->valuestring, "ghcr.io/owner/group/sub/img:v1.0") != 0) {
        report_fail("deep_repository", "deep ref name annotation mismatch");
        cJSON_Delete(idx);
        goto cleanup;
    }
    cJSON_Delete(idx);
    report_pass("deep_repository");

cleanup:
    oci_ref_free(&ref);
    oci_store_close(s);
}

static void test_overwrite_pin(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-overwrite", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("overwrite_pin", "open failed");
        return;
    }
    /* First pin: default manifest body. */
    char first_digest[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_manifest_blob(oci_store_blobs(s), NULL, 0, first_digest,
                             sizeof(first_digest))) {
        report_fail("overwrite_pin", "could not stage first blob");
        oci_store_close(s);
        return;
    }
    /* Second pin: same shape but different bytes so the digest differs. */
    static const char SECOND_BODY[] =
        "{\"schemaVersion\":2,"
        "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"config\":{"
        "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
        "\"digest\":\"sha256:"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\","
        "\"size\":3},"
        "\"layers\":[],\"variant\":\"second\"}";
    char second_digest[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_manifest_blob(oci_store_blobs(s), SECOND_BODY,
                             sizeof(SECOND_BODY) - 1, second_digest,
                             sizeof(second_digest))) {
        report_fail("overwrite_pin", "could not stage second blob");
        oci_store_close(s);
        return;
    }
    if (strcmp(first_digest, second_digest) == 0) {
        report_fail("overwrite_pin",
                    "test setup error: both bodies hashed identically");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("alpine:3.20", &ref)) {
        report_fail("overwrite_pin", "ref parse failed");
        oci_store_close(s);
        return;
    }
    const char *err = NULL;
    if (oci_store_put_ref(s, &ref, first_digest, &err) < 0) {
        report_fail("overwrite_pin", err ? err : "first put failed");
        goto cleanup;
    }
    if (oci_store_put_ref(s, &ref, second_digest, &err) < 0) {
        report_fail("overwrite_pin", err ? err : "second put failed");
        goto cleanup;
    }
    char *got = NULL;
    if (oci_store_get_ref(s, &ref, &got, &err) < 0) {
        report_fail("overwrite_pin", err ? err : "get failed");
        goto cleanup;
    }
    if (!got || strcmp(got, second_digest) != 0) {
        report_fail("overwrite_pin", "pin was not overwritten");
        free(got);
        goto cleanup;
    }
    free(got);

    /* The manifests array must still have exactly one entry for this pin. */
    cJSON *idx = load_index_json(root);
    if (!idx) {
        report_fail("overwrite_pin", "index.json missing");
        goto cleanup;
    }
    const cJSON *manifests = cJSON_GetObjectItemCaseSensitive(idx, "manifests");
    if (!cJSON_IsArray(manifests) || cJSON_GetArraySize(manifests) != 1) {
        report_fail("overwrite_pin", "duplicate descriptor after overwrite");
        cJSON_Delete(idx);
        goto cleanup;
    }
    cJSON_Delete(idx);
    report_pass("overwrite_pin");

cleanup:
    oci_ref_free(&ref);
    oci_store_close(s);
}

static void test_pin_blob_share_root(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-share", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("pin_blob_share_root", "open failed");
        return;
    }
    oci_blob_store_t *blobs = oci_store_blobs(s);
    char digest_str[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_manifest_blob(blobs, NULL, 0, digest_str, sizeof(digest_str))) {
        report_fail("pin_blob_share_root", "stage manifest blob failed");
        oci_store_close(s);
        return;
    }
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(digest_str, &algo, hex)) {
        report_fail("pin_blob_share_root", "digest parse failed");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("alpine:3.20", &ref)) {
        report_fail("pin_blob_share_root", "ref parse failed");
        oci_store_close(s);
        return;
    }
    const char *err = NULL;
    if (oci_store_put_ref(s, &ref, digest_str, &err) < 0) {
        report_fail("pin_blob_share_root", err ? err : "put_ref failed");
        goto cleanup;
    }
    if (!oci_blob_store_has(blobs, algo, hex)) {
        report_fail("pin_blob_share_root", "blob disappeared after pin");
        goto cleanup;
    }
    char *got = NULL;
    if (oci_store_get_ref(s, &ref, &got, &err) < 0 ||
        strcmp(got, digest_str) != 0) {
        report_fail("pin_blob_share_root", "pin disappeared after blob");
        free(got);
        goto cleanup;
    }
    free(got);
    report_pass("pin_blob_share_root");

cleanup:
    oci_ref_free(&ref);
    oci_store_close(s);
}

/* Pull three distinct tags into the same store; verify index.json schema is
 * OCI image-index v1.0.0 shaped and contains all three pins.
 */
static void test_three_pins_schema(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-three-pins", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("three_pins_schema", "open failed");
        return;
    }
    const char *tags[] = {"alpine:3.18", "alpine:3.19", "alpine:3.20"};
    /* Stage a distinct manifest body per tag so each pin has a unique digest
     * and index.json must carry three independent entries.
     */
    for (int i = 0; i < 3; i++) {
        char body[512];
        int n = snprintf(
            body, sizeof(body),
            "{\"schemaVersion\":2,"
            "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
            "\"config\":{"
            "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
            "\"digest\":\"sha256:"
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\""
            ","
            "\"size\":3},"
            "\"layers\":[],\"tag\":\"%s\"}",
            tags[i]);
        char digest_str[OCI_DIGEST_HEX_MAX + 16];
        if (!stage_manifest_blob(oci_store_blobs(s), body, (size_t) n,
                                 digest_str, sizeof(digest_str))) {
            report_fail("three_pins_schema", "stage failed");
            oci_store_close(s);
            return;
        }
        oci_ref_t ref = {0};
        if (!parse_ref(tags[i], &ref)) {
            report_fail("three_pins_schema", "ref parse failed");
            oci_store_close(s);
            return;
        }
        const char *err = NULL;
        if (oci_store_put_ref(s, &ref, digest_str, &err) < 0) {
            report_fail("three_pins_schema", err ? err : "put failed");
            oci_ref_free(&ref);
            oci_store_close(s);
            return;
        }
        oci_ref_free(&ref);
    }

    cJSON *idx = load_index_json(root);
    if (!idx) {
        report_fail("three_pins_schema", "index.json missing");
        oci_store_close(s);
        return;
    }
    const cJSON *sv = cJSON_GetObjectItemCaseSensitive(idx, "schemaVersion");
    const cJSON *mt = cJSON_GetObjectItemCaseSensitive(idx, "mediaType");
    const cJSON *manifests = cJSON_GetObjectItemCaseSensitive(idx, "manifests");
    if (!cJSON_IsNumber(sv) || sv->valueint != 2) {
        report_fail("three_pins_schema", "schemaVersion != 2");
        cJSON_Delete(idx);
        oci_store_close(s);
        return;
    }
    if (!cJSON_IsString(mt) ||
        strcmp(mt->valuestring, "application/vnd.oci.image.index.v1+json") !=
            0) {
        report_fail("three_pins_schema", "top-level mediaType mismatch");
        cJSON_Delete(idx);
        oci_store_close(s);
        return;
    }
    if (!cJSON_IsArray(manifests) || cJSON_GetArraySize(manifests) != 3) {
        report_fail("three_pins_schema", "manifests array size != 3");
        cJSON_Delete(idx);
        oci_store_close(s);
        return;
    }
    /* Every descriptor must carry mediaType + digest + size + the ref.name
     * annotation. Validate one field at a time so a failure points at the
     * exact missing piece.
     */
    for (int i = 0; i < 3; i++) {
        const cJSON *entry = cJSON_GetArrayItem(manifests, i);
        const cJSON *dmt = cJSON_GetObjectItemCaseSensitive(entry, "mediaType");
        const cJSON *dig = cJSON_GetObjectItemCaseSensitive(entry, "digest");
        const cJSON *sz = cJSON_GetObjectItemCaseSensitive(entry, "size");
        const cJSON *an =
            cJSON_GetObjectItemCaseSensitive(entry, "annotations");
        const cJSON *nm = cJSON_IsObject(an)
                              ? cJSON_GetObjectItemCaseSensitive(
                                    an, "org.opencontainers.image.ref.name")
                              : NULL;
        if (!cJSON_IsString(dmt) || !cJSON_IsString(dig) ||
            !cJSON_IsNumber(sz) || sz->valuedouble <= 0 ||
            !cJSON_IsString(nm)) {
            char buf[160];
            snprintf(buf, sizeof(buf), "entry %d missing required field", i);
            report_fail("three_pins_schema", buf);
            cJSON_Delete(idx);
            oci_store_close(s);
            return;
        }
    }
    cJSON_Delete(idx);
    report_pass("three_pins_schema");
    oci_store_close(s);
}

/* Drive oci_store_list_refs over the same three-pin store as above and
 * verify every name + digest is reported back.
 */
static void test_list_refs(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-list", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("list_refs", "open failed");
        return;
    }

    /* Empty store reports zero entries, not an error. */
    oci_pin_list_t empty = {0};
    const char *err = NULL;
    if (oci_store_list_refs(s, &empty, &err) < 0 || empty.count != 0 ||
        empty.items != NULL) {
        report_fail("list_refs", "empty store did not report zero pins");
        oci_pin_list_free(&empty);
        oci_store_close(s);
        return;
    }

    const char *tags[] = {"alpine:3.18", "alpine:3.19", "alpine:3.20"};
    char digests[3][OCI_DIGEST_HEX_MAX + 16];
    for (int i = 0; i < 3; i++) {
        char body[512];
        int n = snprintf(
            body, sizeof(body),
            "{\"schemaVersion\":2,"
            "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
            "\"config\":{"
            "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
            "\"digest\":\"sha256:"
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\""
            ","
            "\"size\":3},"
            "\"layers\":[],\"tag\":\"%s\"}",
            tags[i]);
        if (!stage_manifest_blob(oci_store_blobs(s), body, (size_t) n,
                                 digests[i], sizeof(digests[i]))) {
            report_fail("list_refs", "stage failed");
            oci_store_close(s);
            return;
        }
        oci_ref_t ref = {0};
        if (!parse_ref(tags[i], &ref) ||
            oci_store_put_ref(s, &ref, digests[i], NULL) < 0) {
            report_fail("list_refs", "put failed");
            oci_ref_free(&ref);
            oci_store_close(s);
            return;
        }
        oci_ref_free(&ref);
    }

    oci_pin_list_t list = {0};
    err = NULL;
    if (oci_store_list_refs(s, &list, &err) < 0) {
        report_fail("list_refs", err ? err : "list failed");
        oci_store_close(s);
        return;
    }
    if (list.count != 3) {
        report_fail("list_refs", "count != 3");
        oci_pin_list_free(&list);
        oci_store_close(s);
        return;
    }

    /* For each expected pin, find a list entry with matching name +
     * digest. Linear lookup is fine at three entries.
     */
    for (int i = 0; i < 3; i++) {
        char want_name[128];
        snprintf(want_name, sizeof(want_name), "docker.io/library/%s", tags[i]);
        bool found = false;
        for (size_t k = 0; k < list.count; k++) {
            if (strcmp(list.items[k].name, want_name) == 0 &&
                strcmp(list.items[k].digest, digests[i]) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            char buf[160];
            snprintf(buf, sizeof(buf), "missing pin %s in list output",
                     want_name);
            report_fail("list_refs", buf);
            oci_pin_list_free(&list);
            oci_store_close(s);
            return;
        }
    }
    oci_pin_list_free(&list);
    report_pass("list_refs");
    oci_store_close(s);
}

/* Concurrent writer test: two threads each pin a distinct tag against the
 * same store. flock must serialize the read-modify-write of index.json so
 * both descriptors land in the final document.
 */
typedef struct {
    oci_store_t *store;
    const char *ref_str;
    const char *digest_str;
    int rc;
    const char *err;
} concurrent_writer_arg_t;

static void *concurrent_writer(void *opaque)
{
    concurrent_writer_arg_t *a = (concurrent_writer_arg_t *) opaque;
    oci_ref_t ref = {0};
    if (!parse_ref(a->ref_str, &ref)) {
        a->rc = -1;
        a->err = "ref parse failed";
        return NULL;
    }
    a->rc = oci_store_put_ref(a->store, &ref, a->digest_str, &a->err);
    oci_ref_free(&ref);
    return NULL;
}

static void test_concurrent_writers(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-concurrent", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("concurrent_writers", "open failed");
        return;
    }
    /* Two distinct manifest blobs / digests, one per tag. */
    char body_a[512];
    int na = snprintf(
        body_a, sizeof(body_a),
        "{\"schemaVersion\":2,"
        "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"config\":{"
        "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
        "\"digest\":\"sha256:"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\","
        "\"size\":3},"
        "\"layers\":[],\"writer\":\"a\"}");
    char digest_a[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_manifest_blob(oci_store_blobs(s), body_a, (size_t) na, digest_a,
                             sizeof(digest_a))) {
        report_fail("concurrent_writers", "stage A failed");
        oci_store_close(s);
        return;
    }
    char body_b[512];
    int nb = snprintf(
        body_b, sizeof(body_b),
        "{\"schemaVersion\":2,"
        "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"config\":{"
        "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
        "\"digest\":\"sha256:"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\","
        "\"size\":3},"
        "\"layers\":[],\"writer\":\"b\"}");
    char digest_b[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_manifest_blob(oci_store_blobs(s), body_b, (size_t) nb, digest_b,
                             sizeof(digest_b))) {
        report_fail("concurrent_writers", "stage B failed");
        oci_store_close(s);
        return;
    }

    concurrent_writer_arg_t arg_a = {
        .store = s, .ref_str = "alpine:writer-a", .digest_str = digest_a};
    concurrent_writer_arg_t arg_b = {
        .store = s, .ref_str = "alpine:writer-b", .digest_str = digest_b};

    /* Launch both threads concurrently. flock guarantees the read-modify-
     * write of index.json is serialized; both pins must end up in the final
     * document regardless of which thread won the race.
     */
    pthread_t ta, tb;
    pthread_create(&ta, NULL, concurrent_writer, &arg_a);
    pthread_create(&tb, NULL, concurrent_writer, &arg_b);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    if (arg_a.rc != 0 || arg_b.rc != 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "writer rc a=%d b=%d (a=%s b=%s)", arg_a.rc,
                 arg_b.rc, arg_a.err ? arg_a.err : "(none)",
                 arg_b.err ? arg_b.err : "(none)");
        report_fail("concurrent_writers", buf);
        oci_store_close(s);
        return;
    }

    cJSON *idx = load_index_json(root);
    if (!idx) {
        report_fail("concurrent_writers", "index.json missing");
        oci_store_close(s);
        return;
    }
    const cJSON *manifests = cJSON_GetObjectItemCaseSensitive(idx, "manifests");
    if (!cJSON_IsArray(manifests) || cJSON_GetArraySize(manifests) != 2) {
        report_fail("concurrent_writers",
                    "expected 2 manifests after concurrent put");
        cJSON_Delete(idx);
        oci_store_close(s);
        return;
    }
    bool saw_a = false, saw_b = false;
    int n = cJSON_GetArraySize(manifests);
    for (int i = 0; i < n; i++) {
        const cJSON *entry = cJSON_GetArrayItem(manifests, i);
        const cJSON *annots =
            cJSON_GetObjectItemCaseSensitive(entry, "annotations");
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(
            annots, "org.opencontainers.image.ref.name");
        if (!cJSON_IsString(name))
            continue;
        if (strcmp(name->valuestring, "docker.io/library/alpine:writer-a") == 0)
            saw_a = true;
        else if (strcmp(name->valuestring,
                        "docker.io/library/alpine:writer-b") == 0)
            saw_b = true;
    }
    cJSON_Delete(idx);
    if (!saw_a || !saw_b) {
        report_fail("concurrent_writers", "one of the two writers lost");
        oci_store_close(s);
        return;
    }
    report_pass("concurrent_writers");
    oci_store_close(s);
}

/* OCI image-layout 1.0.0 marker payload that oci_store_open writes when the
 * store root is missing the marker. Kept in sync with src/oci/store.c.
 */
static const char EXPECTED_LAYOUT[] = "{\"imageLayoutVersion\":\"1.0.0\"}\n";

static void test_layout_marker_fresh(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-layout-fresh", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("layout_marker_fresh", "open failed");
        return;
    }
    char path[2048];
    snprintf(path, sizeof(path), "%s/oci-layout", root);
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        report_fail("layout_marker_fresh", "oci-layout file missing");
        oci_store_close(s);
        return;
    }
    char buf[256];
    size_t got = 0;
    if (!read_whole(path, buf, sizeof(buf), &got)) {
        report_fail("layout_marker_fresh", "could not read marker");
        oci_store_close(s);
        return;
    }
    if (got != sizeof(EXPECTED_LAYOUT) - 1 ||
        memcmp(buf, EXPECTED_LAYOUT, got) != 0) {
        report_fail("layout_marker_fresh", "marker payload mismatch");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("layout_marker_fresh");
}

static void test_layout_marker_added_on_existing(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-layout-backfill", scratch);
    /* Simulate a pre-marker store: open + close once to materialize the
     * directory layout, then unlink the marker so the next open must
     * backfill it from scratch. blobs/sha256/ stays in place, matching a
     * store laid down by an elfuse build that predates the marker.
     */
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("layout_marker_backfill", "initial open failed");
        return;
    }
    oci_store_close(s);
    char marker[2048];
    snprintf(marker, sizeof(marker), "%s/oci-layout", root);
    if (unlink(marker) != 0) {
        report_fail("layout_marker_backfill", "could not unlink seed marker");
        return;
    }
    struct stat st;
    if (stat(marker, &st) == 0) {
        report_fail("layout_marker_backfill", "marker survived unlink");
        return;
    }
    s = oci_store_open(root);
    if (!s) {
        report_fail("layout_marker_backfill", "reopen failed");
        return;
    }
    if (stat(marker, &st) != 0 || !S_ISREG(st.st_mode)) {
        report_fail("layout_marker_backfill", "marker not restored on reopen");
        oci_store_close(s);
        return;
    }
    char buf[256];
    size_t got = 0;
    if (!read_whole(marker, buf, sizeof(buf), &got) ||
        got != sizeof(EXPECTED_LAYOUT) - 1 ||
        memcmp(buf, EXPECTED_LAYOUT, got) != 0) {
        report_fail("layout_marker_backfill", "restored marker payload bad");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("layout_marker_backfill");
}

static void test_layout_marker_preserved(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-layout-preserve", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("layout_marker_preserve", "initial open failed");
        return;
    }
    oci_store_close(s);

    char marker[2048];
    snprintf(marker, sizeof(marker), "%s/oci-layout", root);
    /* Overwrite the marker with a future imageLayoutVersion stand-in so a
     * silent rewrite would clobber it. The store must leave the bytes
     * untouched on subsequent open: idempotent contract.
     */
    static const char OVERRIDE[] = "{\"imageLayoutVersion\":\"9.9.9\"}\n";
    int fd = open(marker, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        report_fail("layout_marker_preserve", "could not reopen marker");
        return;
    }
    if (write(fd, OVERRIDE, sizeof(OVERRIDE) - 1) !=
        (ssize_t) (sizeof(OVERRIDE) - 1)) {
        close(fd);
        report_fail("layout_marker_preserve", "could not seed override");
        return;
    }
    close(fd);

    struct stat before;
    if (stat(marker, &before) != 0) {
        report_fail("layout_marker_preserve", "marker missing after override");
        return;
    }

    s = oci_store_open(root);
    if (!s) {
        report_fail("layout_marker_preserve", "reopen failed");
        return;
    }

    struct stat after;
    if (stat(marker, &after) != 0) {
        report_fail("layout_marker_preserve", "marker missing after reopen");
        oci_store_close(s);
        return;
    }
    if (before.st_ino != after.st_ino) {
        report_fail("layout_marker_preserve", "marker inode changed");
        oci_store_close(s);
        return;
    }
    char buf[256];
    size_t got = 0;
    if (!read_whole(marker, buf, sizeof(buf), &got) ||
        got != sizeof(OVERRIDE) - 1 || memcmp(buf, OVERRIDE, got) != 0) {
        report_fail("layout_marker_preserve", "marker bytes changed");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("layout_marker_preserve");
}

static void test_default_root_from_env(void)
{
    /* Save and clear environment so the default-root computation is fully
     * deterministic within the test. */
    char *saved_xdg = NULL;
    const char *cur_xdg = getenv("XDG_DATA_HOME");
    if (cur_xdg)
        saved_xdg = strdup(cur_xdg);
    char *saved_home = NULL;
    const char *cur_home = getenv("HOME");
    if (cur_home)
        saved_home = strdup(cur_home);

    /* XDG path takes precedence. */
    setenv("XDG_DATA_HOME", "/tmp/elfuse-xdg-test", 1);
    setenv("HOME", "/tmp/elfuse-home-test", 1);
    char *r1 = oci_store_default_root();
    if (!r1 || strcmp(r1, "/tmp/elfuse-xdg-test/elfuse/store") != 0) {
        report_fail("default_root_from_env",
                    "XDG_DATA_HOME path not respected");
        free(r1);
        goto restore;
    }
    free(r1);

    /* Fall back to HOME when XDG is unset. */
    unsetenv("XDG_DATA_HOME");
    char *r2 = oci_store_default_root();
    if (!r2 ||
        strcmp(
            r2,
            "/tmp/elfuse-home-test/Library/Application Support/elfuse/store") !=
            0) {
        report_fail("default_root_from_env",
                    "HOME fallback path not respected");
        free(r2);
        goto restore;
    }
    free(r2);

    /* Neither set: errno=ENOENT. */
    unsetenv("HOME");
    errno = 0;
    char *r3 = oci_store_default_root();
    if (r3 || errno != ENOENT) {
        report_fail("default_root_from_env",
                    "expected NULL with ENOENT when no env present");
        free(r3);
        goto restore;
    }
    report_pass("default_root_from_env");

restore:
    if (saved_xdg)
        setenv("XDG_DATA_HOME", saved_xdg, 1);
    else
        unsetenv("XDG_DATA_HOME");
    if (saved_home)
        setenv("HOME", saved_home, 1);
    else
        unsetenv("HOME");
    free(saved_xdg);
    free(saved_home);
}

/* ── oci_store_collect_roots tests ──────────────────────────────────── */

/* Heap-owned descriptor for one synthesized image. Layer digests are
 * heap-allocated and the array itself is heap-allocated; layer payloads
 * are slurped + hashed by stage_image so the caller picks the bytes
 * via the layer_payloads argument.
 */
typedef struct {
    char *manifest_digest;
    char *config_digest;
    char **layer_digests;
    size_t n_layers;
} stage_image_t;

static void stage_image_free(stage_image_t *im)
{
    if (!im)
        return;
    free(im->manifest_digest);
    free(im->config_digest);
    if (im->layer_digests) {
        for (size_t i = 0; i < im->n_layers; i++)
            free(im->layer_digests[i]);
        free(im->layer_digests);
    }
    memset(im, 0, sizeof(*im));
}

/* Synthesize a minimal image (n layer blobs + config blob + manifest
 * referencing both) and store all blobs in the blob store. Returns
 * true on success with *out populated; caller frees via
 * stage_image_free. layer_payloads is a pointer array of n_layers
 * NUL-terminated C strings; identical payloads across calls share a
 * blob in the store, which is how the shared-layer test case
 * exercises dedup.
 */
static bool stage_image(oci_blob_store_t *blobs,
                        const char *config_payload,
                        const char *const *layer_payloads,
                        size_t n_layers,
                        stage_image_t *out)
{
    memset(out, 0, sizeof(*out));
    out->n_layers = n_layers;
    out->layer_digests =
        calloc(n_layers ? n_layers : 1, sizeof(*out->layer_digests));
    if (!out->layer_digests)
        return false;

    int64_t *layer_sizes =
        calloc(n_layers ? n_layers : 1, sizeof(*layer_sizes));
    if (!layer_sizes) {
        stage_image_free(out);
        return false;
    }

    for (size_t i = 0; i < n_layers; i++) {
        char digest[OCI_DIGEST_HEX_MAX + 16];
        if (!stage_manifest_blob(blobs, layer_payloads[i],
                                 strlen(layer_payloads[i]), digest,
                                 sizeof(digest))) {
            free(layer_sizes);
            stage_image_free(out);
            return false;
        }
        out->layer_digests[i] = strdup(digest);
        layer_sizes[i] = (int64_t) strlen(layer_payloads[i]);
        if (!out->layer_digests[i]) {
            free(layer_sizes);
            stage_image_free(out);
            return false;
        }
    }

    /* Stage an image-config JSON whose architecture/os/rootfs.diff_ids are
     * all valid so the layer mark walker can parse the blob without
     * surfacing the test fixture as a fatal-mark scenario. The
     * config_payload string is folded into the config JSON as an opaque
     * "author" annotation so each test still gets a distinct config digest
     * by varying the payload. rootfs.diff_ids stays empty because this
     * helper is used by the mark-walk and prune-filter tests that
     * exercise blob mark only and do not care which diff_ids end up in
     * the keep set.
     */
    char config_digest[OCI_DIGEST_HEX_MAX + 16];
    {
        cJSON *cfg_root = cJSON_CreateObject();
        cJSON_AddStringToObject(cfg_root, "architecture", "arm64");
        cJSON_AddStringToObject(cfg_root, "os", "linux");
        cJSON_AddStringToObject(cfg_root, "author", config_payload);
        cJSON *rootfs = cJSON_AddObjectToObject(cfg_root, "rootfs");
        cJSON_AddStringToObject(rootfs, "type", "layers");
        cJSON_AddArrayToObject(rootfs, "diff_ids");
        char *cfg_body = cJSON_PrintUnformatted(cfg_root);
        cJSON_Delete(cfg_root);
        if (!cfg_body) {
            free(layer_sizes);
            stage_image_free(out);
            return false;
        }
        bool cfg_ok = stage_manifest_blob(blobs, cfg_body, strlen(cfg_body),
                                          config_digest, sizeof(config_digest));
        free(cfg_body);
        if (!cfg_ok) {
            free(layer_sizes);
            stage_image_free(out);
            return false;
        }
    }
    out->config_digest = strdup(config_digest);
    if (!out->config_digest) {
        free(layer_sizes);
        stage_image_free(out);
        return false;
    }

    cJSON *m = cJSON_CreateObject();
    cJSON_AddNumberToObject(m, "schemaVersion", 2);
    cJSON_AddStringToObject(m, "mediaType",
                            "application/vnd.oci.image.manifest.v1+json");
    cJSON *cfg = cJSON_AddObjectToObject(m, "config");
    cJSON_AddStringToObject(cfg, "mediaType",
                            "application/vnd.oci.image.config.v1+json");
    cJSON_AddStringToObject(cfg, "digest", config_digest);
    cJSON_AddNumberToObject(cfg, "size", (double) strlen(config_payload));
    cJSON *layers = cJSON_AddArrayToObject(m, "layers");
    for (size_t i = 0; i < n_layers; i++) {
        cJSON *l = cJSON_CreateObject();
        cJSON_AddStringToObject(l, "mediaType",
                                "application/vnd.oci.image.layer.v1.tar");
        cJSON_AddStringToObject(l, "digest", out->layer_digests[i]);
        cJSON_AddNumberToObject(l, "size", (double) layer_sizes[i]);
        cJSON_AddItemToArray(layers, l);
    }
    char *json = cJSON_PrintUnformatted(m);
    cJSON_Delete(m);
    free(layer_sizes);
    if (!json) {
        stage_image_free(out);
        return false;
    }

    char manifest_digest[OCI_DIGEST_HEX_MAX + 16];
    bool ok = stage_manifest_blob(blobs, json, strlen(json), manifest_digest,
                                  sizeof(manifest_digest));
    free(json);
    if (!ok) {
        stage_image_free(out);
        return false;
    }
    out->manifest_digest = strdup(manifest_digest);
    if (!out->manifest_digest) {
        stage_image_free(out);
        return false;
    }
    return true;
}

/* Create <volume_root>/images/sha256-<hex>/ and seed it with an origin
 * sidecar pointing at the given image. hex must be a 64-char lowercase
 * hex string; the test caller picks an arbitrary value because the
 * directory name does not need to match the manifest digest for
 * oci_store_collect_roots (the walker reads the origin file, not the
 * directory name).
 */
static bool seed_unpacked_tree(const char *volume_root,
                               const char *hex_tag,
                               const stage_image_t *im)
{
    char images[1024];
    snprintf(images, sizeof(images), "%s/images", volume_root);
    mkdir(volume_root, 0755);
    mkdir(images, 0755);
    char tree[1024];
    snprintf(tree, sizeof(tree), "%s/sha256-%s", images, hex_tag);
    if (mkdir(tree, 0755) < 0 && errno != EEXIST)
        return false;
    char *diff_ids[3] = {NULL, NULL, NULL};
    /* Origin diff_ids array is not part of the collect_roots blob keep
     * set, but it has to be valid JSON; reuse the manifest's layer
     * digests as stand-ins for the diff_id field.
     */
    if (im->n_layers > 0)
        diff_ids[0] = im->layer_digests[0];
    if (im->n_layers > 1)
        diff_ids[1] = im->layer_digests[1];
    const char *err = NULL;
    if (oci_origin_write(tree, im->manifest_digest, im->config_digest, diff_ids,
                         &err) < 0)
        return false;
    return true;
}

static void test_collect_empty(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-collect-empty", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("collect_empty", "open failed");
        return;
    }
    oci_digest_set_t set = {0};
    const char *err = NULL;
    if (oci_store_collect_roots(s, &set, NULL, &err) < 0) {
        report_fail("collect_empty", err ? err : "collect failed");
        oci_digest_set_free(&set);
        oci_store_close(s);
        return;
    }
    if (oci_digest_set_size(&set) != 0) {
        report_fail("collect_empty", "expected empty set");
        oci_digest_set_free(&set);
        oci_store_close(s);
        return;
    }
    oci_digest_set_free(&set);
    oci_store_close(s);
    report_pass("collect_empty");
}

static void test_collect_single_pin(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-collect-single-pin", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("collect_single_pin", "open failed");
        return;
    }
    const char *layers[] = {"single-pin-layer-A"};
    stage_image_t im = {0};
    if (!stage_image(oci_store_blobs(s), "single-pin-config", layers, 1, &im)) {
        report_fail("collect_single_pin", "stage_image failed");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("docker.io/library/alpine:3.20", &ref)) {
        report_fail("collect_single_pin", "ref parse failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    const char *perr = NULL;
    if (oci_store_put_ref(s, &ref, im.manifest_digest, &perr) < 0) {
        report_fail("collect_single_pin", perr ? perr : "put_ref failed");
        oci_ref_free(&ref);
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    oci_ref_free(&ref);

    oci_digest_set_t set = {0};
    const char *err = NULL;
    if (oci_store_collect_roots(s, &set, NULL, &err) < 0) {
        report_fail("collect_single_pin", err ? err : "collect failed");
        goto cleanup;
    }
    if (oci_digest_set_size(&set) != 3) {
        report_fail("collect_single_pin",
                    "expected 3 entries (manifest, "
                    "config, 1 layer)");
        goto cleanup;
    }
    if (!oci_digest_set_contains(&set, im.manifest_digest) ||
        !oci_digest_set_contains(&set, im.config_digest) ||
        !oci_digest_set_contains(&set, im.layer_digests[0])) {
        report_fail("collect_single_pin", "missing expected digest");
        goto cleanup;
    }
    report_pass("collect_single_pin");

cleanup:
    oci_digest_set_free(&set);
    stage_image_free(&im);
    oci_store_close(s);
}

static void test_collect_shared_layer_dedups(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-collect-shared", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("collect_shared_layer_dedups", "open failed");
        return;
    }
    /* Image A: layer "shared-base" + "alpha". Image B: layer
     * "shared-base" + "beta". stage_manifest_blob hashes the payload,
     * so identical payloads collapse to one on-disk blob; the
     * collect_roots set must also collapse them to a single entry.
     */
    const char *layers_a[] = {"shared-base", "alpha-private"};
    const char *layers_b[] = {"shared-base", "beta-private"};
    stage_image_t a = {0}, b = {0};
    if (!stage_image(oci_store_blobs(s), "config-A", layers_a, 2, &a) ||
        !stage_image(oci_store_blobs(s), "config-B", layers_b, 2, &b)) {
        report_fail("collect_shared_layer_dedups", "stage_image failed");
        goto cleanup;
    }
    if (strcmp(a.layer_digests[0], b.layer_digests[0]) != 0) {
        report_fail("collect_shared_layer_dedups",
                    "shared layer digest mismatch (test setup bug)");
        goto cleanup;
    }
    oci_ref_t r1 = {0}, r2 = {0};
    if (!parse_ref("docker.io/library/a:1", &r1) ||
        !parse_ref("docker.io/library/b:1", &r2)) {
        report_fail("collect_shared_layer_dedups", "ref parse failed");
        goto cleanup;
    }
    const char *perr = NULL;
    if (oci_store_put_ref(s, &r1, a.manifest_digest, &perr) < 0 ||
        oci_store_put_ref(s, &r2, b.manifest_digest, &perr) < 0) {
        report_fail("collect_shared_layer_dedups", perr ? perr : "put failed");
        oci_ref_free(&r1);
        oci_ref_free(&r2);
        goto cleanup;
    }
    oci_ref_free(&r1);
    oci_ref_free(&r2);

    oci_digest_set_t set = {0};
    const char *err = NULL;
    if (oci_store_collect_roots(s, &set, NULL, &err) < 0) {
        report_fail("collect_shared_layer_dedups",
                    err ? err : "collect failed");
        oci_digest_set_free(&set);
        goto cleanup;
    }
    /* Expected: m_a, c_a, m_b, c_b, shared_layer, alpha_layer, beta_layer
     * minus the shared one being counted once: 7 - 0 dedup of shared = 7
     * unique. Wait, both images list the shared layer; the set must
     * contain it once. So uniques = 2*manifest + 2*config + 3 layer
     * (shared + alpha + beta) = 7.
     */
    if (oci_digest_set_size(&set) != 7) {
        report_fail("collect_shared_layer_dedups",
                    "expected 7 unique digests across two images");
        oci_digest_set_free(&set);
        goto cleanup;
    }
    if (!oci_digest_set_contains(&set, a.layer_digests[0]) ||
        !oci_digest_set_contains(&set, a.layer_digests[1]) ||
        !oci_digest_set_contains(&set, b.layer_digests[1])) {
        report_fail("collect_shared_layer_dedups",
                    "missing expected layer digest");
        oci_digest_set_free(&set);
        goto cleanup;
    }
    oci_digest_set_free(&set);
    report_pass("collect_shared_layer_dedups");

cleanup:
    stage_image_free(&a);
    stage_image_free(&b);
    oci_store_close(s);
}

static void test_collect_unpacked_tree(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-collect-unpacked", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("collect_unpacked_tree", "open failed");
        return;
    }
    const char *layers[] = {"unpacked-layer-X"};
    stage_image_t im = {0};
    if (!stage_image(oci_store_blobs(s), "unpacked-config", layers, 1, &im)) {
        report_fail("collect_unpacked_tree", "stage_image failed");
        oci_store_close(s);
        return;
    }
    char volume[1024];
    snprintf(volume, sizeof(volume), "%s/vol-unpacked", root);
    /* The test passes a 64-char hex name unrelated to the manifest
     * digest because collect_roots reads .elfuse-origin.json rather
     * than parsing the directory name.
     */
    if (!seed_unpacked_tree(
            volume,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            &im)) {
        report_fail("collect_unpacked_tree", "seed_unpacked_tree failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    oci_digest_set_t set = {0};
    const char *err = NULL;
    if (oci_store_collect_roots(s, &set, volume, &err) < 0) {
        report_fail("collect_unpacked_tree", err ? err : "collect failed");
        oci_digest_set_free(&set);
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    if (oci_digest_set_size(&set) != 3 ||
        !oci_digest_set_contains(&set, im.manifest_digest) ||
        !oci_digest_set_contains(&set, im.config_digest) ||
        !oci_digest_set_contains(&set, im.layer_digests[0])) {
        report_fail("collect_unpacked_tree",
                    "expected manifest+config+layer harvested via origin");
        oci_digest_set_free(&set);
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    oci_digest_set_free(&set);
    stage_image_free(&im);
    oci_store_close(s);
    report_pass("collect_unpacked_tree");
}

static void test_collect_pin_plus_unpacked(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-collect-mixed", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("collect_pin_plus_unpacked", "open failed");
        return;
    }
    const char *layers_p[] = {"mixed-pin-layer"};
    const char *layers_u[] = {"mixed-unpacked-layer"};
    stage_image_t p = {0}, u = {0};
    if (!stage_image(oci_store_blobs(s), "config-pin", layers_p, 1, &p) ||
        !stage_image(oci_store_blobs(s), "config-unp", layers_u, 1, &u)) {
        report_fail("collect_pin_plus_unpacked", "stage_image failed");
        goto cleanup;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("docker.io/library/p:1", &ref)) {
        report_fail("collect_pin_plus_unpacked", "ref parse failed");
        goto cleanup;
    }
    const char *perr = NULL;
    if (oci_store_put_ref(s, &ref, p.manifest_digest, &perr) < 0) {
        report_fail("collect_pin_plus_unpacked", perr ? perr : "put failed");
        oci_ref_free(&ref);
        goto cleanup;
    }
    oci_ref_free(&ref);

    char volume[1024];
    snprintf(volume, sizeof(volume), "%s/vol-mixed", root);
    if (!seed_unpacked_tree(
            volume,
            "1111111111111111111111111111111111111111111111111111111111111111",
            &u)) {
        report_fail("collect_pin_plus_unpacked", "seed failed");
        goto cleanup;
    }

    oci_digest_set_t set = {0};
    const char *err = NULL;
    if (oci_store_collect_roots(s, &set, volume, &err) < 0) {
        report_fail("collect_pin_plus_unpacked", err ? err : "collect failed");
        oci_digest_set_free(&set);
        goto cleanup;
    }
    if (oci_digest_set_size(&set) != 6) {
        report_fail("collect_pin_plus_unpacked",
                    "expected 6 entries (3 per image)");
        oci_digest_set_free(&set);
        goto cleanup;
    }
    bool all_present = oci_digest_set_contains(&set, p.manifest_digest) &&
                       oci_digest_set_contains(&set, p.config_digest) &&
                       oci_digest_set_contains(&set, p.layer_digests[0]) &&
                       oci_digest_set_contains(&set, u.manifest_digest) &&
                       oci_digest_set_contains(&set, u.config_digest) &&
                       oci_digest_set_contains(&set, u.layer_digests[0]);
    oci_digest_set_free(&set);
    if (!all_present) {
        report_fail("collect_pin_plus_unpacked", "missing expected digest");
        goto cleanup;
    }
    report_pass("collect_pin_plus_unpacked");

cleanup:
    stage_image_free(&p);
    stage_image_free(&u);
    oci_store_close(s);
}

static void test_collect_origin_corrupt_fails(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-collect-bad-origin", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("collect_origin_corrupt_fails", "open failed");
        return;
    }
    char volume[1024];
    snprintf(volume, sizeof(volume), "%s/vol-bad-origin", root);
    char images[1024];
    snprintf(images, sizeof(images), "%s/images", volume);
    char tree[1024];
    snprintf(
        tree, sizeof(tree), "%s/sha256-%s", images,
        "2222222222222222222222222222222222222222222222222222222222222222");
    mkdir(volume, 0755);
    mkdir(images, 0755);
    if (mkdir(tree, 0755) < 0 && errno != EEXIST) {
        report_fail("collect_origin_corrupt_fails", "mkdir tree failed");
        oci_store_close(s);
        return;
    }
    /* Write garbage in place of valid JSON. */
    char origin[1024];
    snprintf(origin, sizeof(origin), "%s/.elfuse-origin.json", tree);
    FILE *fp = fopen(origin, "w");
    if (!fp) {
        report_fail("collect_origin_corrupt_fails", "fopen origin failed");
        oci_store_close(s);
        return;
    }
    fputs("not-valid-json{", fp);
    fclose(fp);

    oci_digest_set_t set = {0};
    const char *err = NULL;
    int rc = oci_store_collect_roots(s, &set, volume, &err);
    if (rc == 0) {
        report_fail("collect_origin_corrupt_fails",
                    "expected -1 on malformed origin");
        oci_digest_set_free(&set);
        oci_store_close(s);
        return;
    }
    if (oci_digest_set_size(&set) != 0) {
        report_fail("collect_origin_corrupt_fails",
                    "expected set to be left empty on failure");
        oci_digest_set_free(&set);
        oci_store_close(s);
        return;
    }
    oci_digest_set_free(&set);
    oci_store_close(s);
    report_pass("collect_origin_corrupt_fails");
}

static void test_collect_missing_manifest_blob_fails(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-collect-missing-blob", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("collect_missing_manifest_blob_fails", "open failed");
        return;
    }
    const char *layers[] = {"missing-blob-layer"};
    stage_image_t im = {0};
    if (!stage_image(oci_store_blobs(s), "missing-blob-config", layers, 1,
                     &im)) {
        report_fail("collect_missing_manifest_blob_fails",
                    "stage_image failed");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("docker.io/library/gone:1", &ref)) {
        report_fail("collect_missing_manifest_blob_fails", "ref parse failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    const char *perr = NULL;
    if (oci_store_put_ref(s, &ref, im.manifest_digest, &perr) < 0) {
        report_fail("collect_missing_manifest_blob_fails",
                    perr ? perr : "put failed");
        oci_ref_free(&ref);
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    oci_ref_free(&ref);

    /* Unlink the manifest blob from blobs/sha256/. The pin still
     * references it via index.json; collect_roots must fail so a
     * subsequent prune does not run on a store whose keep set is
     * incomplete.
     */
    char hex[OCI_DIGEST_HEX_MAX + 1];
    oci_digest_algo_t algo;
    if (!oci_digest_parse(im.manifest_digest, &algo, hex)) {
        report_fail("collect_missing_manifest_blob_fails",
                    "digest parse failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    char path[1024];
    snprintf(path, sizeof(path), "%s/blobs/sha256/%s", root, hex);
    if (unlink(path) < 0) {
        report_fail("collect_missing_manifest_blob_fails",
                    "unlink manifest blob failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }

    oci_digest_set_t set = {0};
    const char *err = NULL;
    int rc = oci_store_collect_roots(s, &set, NULL, &err);
    if (rc == 0) {
        report_fail("collect_missing_manifest_blob_fails",
                    "expected -1 when pinned manifest blob is missing");
        oci_digest_set_free(&set);
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    if (oci_digest_set_size(&set) != 0) {
        report_fail("collect_missing_manifest_blob_fails",
                    "expected set freed on failure");
        oci_digest_set_free(&set);
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    oci_digest_set_free(&set);
    stage_image_free(&im);
    oci_store_close(s);
    report_pass("collect_missing_manifest_blob_fails");
}

/* ── oci_store_prune tests ──────────────────────────────────────────── */

/* Count regular files under <root>/blobs/sha256/. Used by every prune
 * test to assert what the sweep did or did not touch on disk.
 */
static size_t count_sha256_blobs(const char *root)
{
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/blobs/sha256", root);
    DIR *dp = opendir(dir);
    if (!dp)
        return 0;
    size_t n = 0;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        char p[1024];
        snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        struct stat st;
        if (lstat(p, &st) == 0 && S_ISREG(st.st_mode))
            n++;
    }
    closedir(dp);
    return n;
}

/* Stage a payload as a free-standing blob (not referenced by any
 * manifest) and write the resulting "<algo>:<hex>" digest into
 * out_digest. The blob lives at <root>/blobs/sha256/<hex>; the caller
 * uses count_sha256_blobs to assert it survives or is reclaimed.
 */
static bool stage_dangling(oci_blob_store_t *blobs,
                           const char *payload,
                           char *out_digest,
                           size_t cap)
{
    return stage_manifest_blob(blobs, payload, strlen(payload), out_digest,
                               cap);
}

static void test_prune_dry_run_preserves_disk(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-dry-run", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("prune_dry_run_preserves_disk", "open failed");
        return;
    }
    const char *layers[] = {"prune-dry-layer"};
    stage_image_t im = {0};
    if (!stage_image(oci_store_blobs(s), "prune-dry-config", layers, 1, &im)) {
        report_fail("prune_dry_run_preserves_disk", "stage_image failed");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("docker.io/library/dry:1", &ref)) {
        report_fail("prune_dry_run_preserves_disk", "ref parse failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    const char *perr = NULL;
    if (oci_store_put_ref(s, &ref, im.manifest_digest, &perr) < 0) {
        report_fail("prune_dry_run_preserves_disk",
                    perr ? perr : "put_ref failed");
        oci_ref_free(&ref);
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    oci_ref_free(&ref);

    char dangling_a[OCI_DIGEST_HEX_MAX + 16];
    char dangling_b[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_dangling(oci_store_blobs(s), "dangling-a", dangling_a,
                        sizeof(dangling_a)) ||
        !stage_dangling(oci_store_blobs(s), "dangling-b", dangling_b,
                        sizeof(dangling_b))) {
        report_fail("prune_dry_run_preserves_disk", "stage_dangling failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }

    size_t before = count_sha256_blobs(root);
    if (before != 5) {
        report_fail("prune_dry_run_preserves_disk",
                    "expected 5 blobs on disk before prune");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }

    oci_store_prune_options_t opts = {0};
    const char *err = NULL;
    int rc = oci_store_prune(s, &opts, &err);
    if (rc < 0) {
        report_fail("prune_dry_run_preserves_disk",
                    err ? err : "prune returned -1");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    if (opts.kept_blobs != 3 || opts.pruned_blobs != 2 ||
        opts.pruned_bytes == 0) {
        report_fail("prune_dry_run_preserves_disk",
                    "stats mismatch (want kept=3 pruned=2 bytes>0)");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    size_t after = count_sha256_blobs(root);
    if (after != 5) {
        report_fail("prune_dry_run_preserves_disk", "dry-run touched the disk");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    stage_image_free(&im);
    oci_store_close(s);
    report_pass("prune_dry_run_preserves_disk");
}

static void test_prune_commit_unlinks_dangling(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-commit", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("prune_commit_unlinks_dangling", "open failed");
        return;
    }
    const char *layers[] = {"prune-commit-layer"};
    stage_image_t im = {0};
    if (!stage_image(oci_store_blobs(s), "prune-commit-config", layers, 1,
                     &im)) {
        report_fail("prune_commit_unlinks_dangling", "stage_image failed");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("docker.io/library/commit:1", &ref)) {
        report_fail("prune_commit_unlinks_dangling", "ref parse failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    const char *perr = NULL;
    if (oci_store_put_ref(s, &ref, im.manifest_digest, &perr) < 0) {
        report_fail("prune_commit_unlinks_dangling",
                    perr ? perr : "put_ref failed");
        oci_ref_free(&ref);
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    oci_ref_free(&ref);

    char dangling_a[OCI_DIGEST_HEX_MAX + 16];
    char dangling_b[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_dangling(oci_store_blobs(s), "danga", dangling_a,
                        sizeof(dangling_a)) ||
        !stage_dangling(oci_store_blobs(s), "dangb", dangling_b,
                        sizeof(dangling_b))) {
        report_fail("prune_commit_unlinks_dangling", "stage_dangling failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }

    oci_store_prune_options_t opts = {.commit = true};
    const char *err = NULL;
    int rc = oci_store_prune(s, &opts, &err);
    if (rc < 0) {
        report_fail("prune_commit_unlinks_dangling",
                    err ? err : "prune returned -1");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    if (opts.kept_blobs != 3 || opts.pruned_blobs != 2) {
        report_fail("prune_commit_unlinks_dangling",
                    "stats mismatch (want kept=3 pruned=2)");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    if (count_sha256_blobs(root) != 3) {
        report_fail("prune_commit_unlinks_dangling",
                    "dangling blobs survived commit");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    /* Reachable blobs (manifest, config, layer) must all still be on
     * disk. Check each one explicitly so a future regression that
     * deletes a reachable blob does not slip past the count check.
     */
    char path[1024];
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    const char *keep_digests[3] = {im.manifest_digest, im.config_digest,
                                   im.layer_digests[0]};
    for (size_t i = 0; i < 3; i++) {
        if (!oci_digest_parse(keep_digests[i], &algo, hex)) {
            report_fail("prune_commit_unlinks_dangling", "digest parse");
            stage_image_free(&im);
            oci_store_close(s);
            return;
        }
        snprintf(path, sizeof(path), "%s/blobs/sha256/%s", root, hex);
        struct stat st;
        if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
            report_fail("prune_commit_unlinks_dangling",
                        "reachable blob missing after commit");
            stage_image_free(&im);
            oci_store_close(s);
            return;
        }
    }
    stage_image_free(&im);
    oci_store_close(s);
    report_pass("prune_commit_unlinks_dangling");
}

static void test_prune_no_pins_no_volume(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-no-pins", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("prune_no_pins_no_volume", "open failed");
        return;
    }
    char digest[OCI_DIGEST_HEX_MAX + 16];
    for (int i = 0; i < 5; i++) {
        char payload[32];
        snprintf(payload, sizeof(payload), "free-blob-%d", i);
        if (!stage_dangling(oci_store_blobs(s), payload, digest,
                            sizeof(digest))) {
            report_fail("prune_no_pins_no_volume", "stage_dangling failed");
            oci_store_close(s);
            return;
        }
    }
    if (count_sha256_blobs(root) != 5) {
        report_fail("prune_no_pins_no_volume", "expected 5 staged dangling");
        oci_store_close(s);
        return;
    }

    oci_store_prune_options_t opts = {.commit = true};
    const char *err = NULL;
    int rc = oci_store_prune(s, &opts, &err);
    if (rc < 0) {
        report_fail("prune_no_pins_no_volume", err ? err : "prune returned -1");
        oci_store_close(s);
        return;
    }
    if (opts.kept_blobs != 0 || opts.pruned_blobs != 5) {
        report_fail("prune_no_pins_no_volume",
                    "stats mismatch (want kept=0 pruned=5)");
        oci_store_close(s);
        return;
    }
    if (count_sha256_blobs(root) != 0) {
        report_fail("prune_no_pins_no_volume",
                    "blobs/sha256/ not empty after commit");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("prune_no_pins_no_volume");
}

static void test_prune_with_unpacked_tree(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-unpacked", scratch);
    char volume[1024];
    snprintf(volume, sizeof(volume), "%s/case-prune-unpacked-vol", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("prune_with_unpacked_tree", "open failed");
        return;
    }
    const char *layers[] = {"unp-layer"};
    stage_image_t im = {0};
    if (!stage_image(oci_store_blobs(s), "unp-config", layers, 1, &im)) {
        report_fail("prune_with_unpacked_tree", "stage_image failed");
        oci_store_close(s);
        return;
    }
    /* No pin: only the unpacked sysroot keeps the image reachable. */
    if (!seed_unpacked_tree(
            volume,
            "0000000000000000000000000000000000000000000000000000000000000001",
            &im)) {
        report_fail("prune_with_unpacked_tree", "seed_unpacked_tree failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }

    char dangling_a[OCI_DIGEST_HEX_MAX + 16];
    char dangling_b[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_dangling(oci_store_blobs(s), "danga2", dangling_a,
                        sizeof(dangling_a)) ||
        !stage_dangling(oci_store_blobs(s), "dangb2", dangling_b,
                        sizeof(dangling_b))) {
        report_fail("prune_with_unpacked_tree", "stage_dangling failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }

    oci_store_prune_options_t opts = {.commit = true, .volume_root = volume};
    const char *err = NULL;
    int rc = oci_store_prune(s, &opts, &err);
    if (rc < 0) {
        report_fail("prune_with_unpacked_tree",
                    err ? err : "prune returned -1");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    if (opts.kept_blobs != 3 || opts.pruned_blobs != 2) {
        report_fail("prune_with_unpacked_tree",
                    "stats mismatch (want kept=3 pruned=2)");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    if (count_sha256_blobs(root) != 3) {
        report_fail("prune_with_unpacked_tree", "blob count != 3 after commit");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    stage_image_free(&im);
    oci_store_close(s);
    report_pass("prune_with_unpacked_tree");
}

static void test_prune_collect_failure_aborts(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-collect-fail", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("prune_collect_failure_aborts", "open failed");
        return;
    }
    const char *layers[] = {"collect-fail-layer"};
    stage_image_t im = {0};
    if (!stage_image(oci_store_blobs(s), "collect-fail-config", layers, 1,
                     &im)) {
        report_fail("prune_collect_failure_aborts", "stage_image failed");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("docker.io/library/cf:1", &ref)) {
        report_fail("prune_collect_failure_aborts", "ref parse failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    const char *perr = NULL;
    if (oci_store_put_ref(s, &ref, im.manifest_digest, &perr) < 0) {
        report_fail("prune_collect_failure_aborts", perr ? perr : "put failed");
        oci_ref_free(&ref);
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    oci_ref_free(&ref);

    char dangling_a[OCI_DIGEST_HEX_MAX + 16];
    char dangling_b[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_dangling(oci_store_blobs(s), "abort-a", dangling_a,
                        sizeof(dangling_a)) ||
        !stage_dangling(oci_store_blobs(s), "abort-b", dangling_b,
                        sizeof(dangling_b))) {
        report_fail("prune_collect_failure_aborts", "stage_dangling failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }

    /* Unlink the pinned manifest blob so collect_roots fails on its
     * mark walk. prune must not enter the sweep phase after that.
     */
    char hex[OCI_DIGEST_HEX_MAX + 1];
    oci_digest_algo_t algo;
    if (!oci_digest_parse(im.manifest_digest, &algo, hex)) {
        report_fail("prune_collect_failure_aborts", "digest parse");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    char path[1024];
    snprintf(path, sizeof(path), "%s/blobs/sha256/%s", root, hex);
    if (unlink(path) < 0) {
        report_fail("prune_collect_failure_aborts", "unlink manifest blob");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    size_t before = count_sha256_blobs(root);

    oci_store_prune_options_t opts = {.commit = true};
    const char *err = NULL;
    int rc = oci_store_prune(s, &opts, &err);
    if (rc != -1) {
        report_fail("prune_collect_failure_aborts",
                    "expected -1 on mark failure");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    if (opts.pruned_blobs != 0) {
        report_fail("prune_collect_failure_aborts",
                    "sweep ran despite mark failure");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    if (count_sha256_blobs(root) != before) {
        report_fail("prune_collect_failure_aborts",
                    "disk state changed despite mark failure");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    stage_image_free(&im);
    oci_store_close(s);
    report_pass("prune_collect_failure_aborts");
}

static void test_prune_idempotent(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-idempotent", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("prune_idempotent", "open failed");
        return;
    }
    const char *layers[] = {"idem-layer"};
    stage_image_t im = {0};
    if (!stage_image(oci_store_blobs(s), "idem-config", layers, 1, &im)) {
        report_fail("prune_idempotent", "stage_image failed");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("docker.io/library/idem:1", &ref)) {
        report_fail("prune_idempotent", "ref parse failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    const char *perr = NULL;
    if (oci_store_put_ref(s, &ref, im.manifest_digest, &perr) < 0) {
        report_fail("prune_idempotent", perr ? perr : "put failed");
        oci_ref_free(&ref);
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    oci_ref_free(&ref);

    /* First sweep is a no-op already (no dangling), but run it
     * anyway so the second call has a known baseline.
     */
    oci_store_prune_options_t opts1 = {.commit = true};
    const char *err = NULL;
    if (oci_store_prune(s, &opts1, &err) < 0) {
        report_fail("prune_idempotent", err ? err : "first prune failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    oci_store_prune_options_t opts2 = {.commit = true};
    if (oci_store_prune(s, &opts2, &err) < 0) {
        report_fail("prune_idempotent", err ? err : "second prune failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    if (opts2.kept_blobs != 3 || opts2.pruned_blobs != 0 ||
        opts2.pruned_bytes != 0) {
        report_fail("prune_idempotent", "second prune saw work to do");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    stage_image_free(&im);
    oci_store_close(s);
    report_pass("prune_idempotent");
}

static void test_prune_decoy_subdir_ignored(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-decoy", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("prune_decoy_subdir_ignored", "open failed");
        return;
    }
    const char *layers[] = {"decoy-layer"};
    stage_image_t im = {0};
    if (!stage_image(oci_store_blobs(s), "decoy-config", layers, 1, &im)) {
        report_fail("prune_decoy_subdir_ignored", "stage_image failed");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("docker.io/library/decoy:1", &ref)) {
        report_fail("prune_decoy_subdir_ignored", "ref parse failed");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    const char *perr = NULL;
    if (oci_store_put_ref(s, &ref, im.manifest_digest, &perr) < 0) {
        report_fail("prune_decoy_subdir_ignored", perr ? perr : "put failed");
        oci_ref_free(&ref);
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    oci_ref_free(&ref);

    /* Drop a decoy subdirectory and a non-hex regular file in
     * blobs/sha256/. Both must be ignored by sweep: a subdirectory
     * cannot be a blob and a wrongly-named file is not addressable as
     * a digest. Either being touched would break interoperability
     * with external tools that scribble metadata in the same dir.
     */
    char decoy_dir[1024];
    snprintf(decoy_dir, sizeof(decoy_dir), "%s/blobs/sha256/decoydir", root);
    if (mkdir(decoy_dir, 0755) < 0) {
        report_fail("prune_decoy_subdir_ignored", "mkdir decoy");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    char decoy_file[1024];
    snprintf(decoy_file, sizeof(decoy_file), "%s/blobs/sha256/not-a-blob",
             root);
    int fd = open(decoy_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        report_fail("prune_decoy_subdir_ignored", "create decoy file");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    (void) write(fd, "x", 1);
    close(fd);

    oci_store_prune_options_t opts = {.commit = true};
    const char *err = NULL;
    int rc = oci_store_prune(s, &opts, &err);
    if (rc < 0) {
        report_fail("prune_decoy_subdir_ignored",
                    err ? err : "prune returned -1");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    if (opts.kept_blobs != 3 || opts.pruned_blobs != 0) {
        report_fail("prune_decoy_subdir_ignored",
                    "stats mismatch (want kept=3 pruned=0)");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    struct stat st;
    if (lstat(decoy_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        report_fail("prune_decoy_subdir_ignored", "decoy subdir disappeared");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    if (lstat(decoy_file, &st) != 0 || !S_ISREG(st.st_mode)) {
        report_fail("prune_decoy_subdir_ignored", "decoy file disappeared");
        stage_image_free(&im);
        oci_store_close(s);
        return;
    }
    stage_image_free(&im);
    oci_store_close(s);
    report_pass("prune_decoy_subdir_ignored");
}

/* ── oci_store_prune filter tests ───────────────────────────────────── */

/* Adjust the on-disk mtime of a finalized blob to want_epoch. The
 * prune filters (older-than veto, keep-bytes LRU) sort by mtime, so
 * staging tests need to drive that field deterministically rather
 * than relying on wall-clock blob commit times. atime is set to
 * match modtime so utimes does not bump it asymmetrically.
 */
static bool set_blob_mtime(const char *root,
                           const char *digest_str,
                           time_t want_epoch)
{
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(digest_str, &algo, hex))
        return false;
    char path[1024];
    snprintf(path, sizeof(path), "%s/blobs/sha256/%s", root, hex);
    struct timeval times[2];
    times[0].tv_sec = want_epoch;
    times[0].tv_usec = 0;
    times[1].tv_sec = want_epoch;
    times[1].tv_usec = 0;
    return utimes(path, times) == 0;
}

/* Stage one dangling blob whose body contains tag so the hash is
 * unique per call site, then backdate its mtime by seconds_ago.
 * out_digest receives the canonical "<algo>:<hex>" digest.
 */
static bool stage_dated_dangling(oci_blob_store_t *blobs,
                                 const char *root,
                                 const char *tag,
                                 time_t seconds_ago,
                                 char *out_digest,
                                 size_t cap)
{
    if (!stage_dangling(blobs, tag, out_digest, cap))
        return false;
    time_t now = time(NULL);
    return set_blob_mtime(root, out_digest, now - seconds_ago);
}

static void test_prune_older_than_grace_window(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-older-than", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("prune_older_than_grace_window", "open failed");
        return;
    }
    char fresh_a[OCI_DIGEST_HEX_MAX + 16];
    char fresh_b[OCI_DIGEST_HEX_MAX + 16];
    char stale[OCI_DIGEST_HEX_MAX + 16];
    /* 1 hour ago => well below the 7-day cutoff. 8 days ago => well
     * above. Tagged payloads keep the three digests distinct.
     */
    if (!stage_dated_dangling(oci_store_blobs(s), root, "older-fresh-a", 3600,
                              fresh_a, sizeof(fresh_a)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "older-fresh-b", 3600,
                              fresh_b, sizeof(fresh_b)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "older-stale",
                              8 * 86400, stale, sizeof(stale))) {
        report_fail("prune_older_than_grace_window", "stage failed");
        oci_store_close(s);
        return;
    }

    oci_store_prune_options_t opts = {
        .commit = true,
        .older_than_sec = 7 * 86400,
    };
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail("prune_older_than_grace_window",
                    err ? err : "prune failed");
        oci_store_close(s);
        return;
    }
    if (opts.pruned_blobs != 1 || opts.skipped_blobs != 2 ||
        opts.kept_blobs != 0) {
        report_fail("prune_older_than_grace_window",
                    "stats mismatch (want pruned=1 skipped=2 kept=0)");
        oci_store_close(s);
        return;
    }
    if (count_sha256_blobs(root) != 2) {
        report_fail("prune_older_than_grace_window",
                    "expected 2 fresh blobs to survive on disk");
        oci_store_close(s);
        return;
    }
    /* Spot check: the stale blob is the one that was unlinked. */
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(stale, &algo, hex)) {
        report_fail("prune_older_than_grace_window", "digest parse");
        oci_store_close(s);
        return;
    }
    char path[1024];
    snprintf(path, sizeof(path), "%s/blobs/sha256/%s", root, hex);
    struct stat st;
    if (lstat(path, &st) == 0) {
        report_fail("prune_older_than_grace_window",
                    "stale blob survived despite older-than cutoff");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("prune_older_than_grace_window");
}

static void test_prune_older_than_zero_disables(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-older-zero", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("prune_older_than_zero_disables", "open failed");
        return;
    }
    char d1[OCI_DIGEST_HEX_MAX + 16];
    char d2[OCI_DIGEST_HEX_MAX + 16];
    char d3[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_dated_dangling(oci_store_blobs(s), root, "zero-a", 3600, d1,
                              sizeof(d1)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "zero-b", 3600, d2,
                              sizeof(d2)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "zero-c", 8 * 86400, d3,
                              sizeof(d3))) {
        report_fail("prune_older_than_zero_disables", "stage failed");
        oci_store_close(s);
        return;
    }

    oci_store_prune_options_t opts = {
        .commit = true,
        .older_than_sec = 0,
    };
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail("prune_older_than_zero_disables",
                    err ? err : "prune failed");
        oci_store_close(s);
        return;
    }
    if (opts.pruned_blobs != 3 || opts.skipped_blobs != 0) {
        report_fail("prune_older_than_zero_disables",
                    "stats mismatch (want pruned=3 skipped=0)");
        oci_store_close(s);
        return;
    }
    if (count_sha256_blobs(root) != 0) {
        report_fail("prune_older_than_zero_disables",
                    "blobs survived despite zero-filter");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("prune_older_than_zero_disables");
}

static void test_prune_keep_bytes_evicts_oldest_first(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-keep-bytes", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("prune_keep_bytes_evicts_oldest_first", "open failed");
        return;
    }
    /* Four blobs with strictly ascending mtimes (t1 < t2 < t3 < t4).
     * Tag-suffixed payloads keep digests distinct; sizes do not need
     * to match because keep-bytes is in bytes, not blob count, and
     * the test just asserts which digests survive.
     */
    char d1[OCI_DIGEST_HEX_MAX + 16];
    char d2[OCI_DIGEST_HEX_MAX + 16];
    char d3[OCI_DIGEST_HEX_MAX + 16];
    char d4[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_dated_dangling(oci_store_blobs(s), root, "kb-t1", 4000, d1,
                              sizeof(d1)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "kb-t2", 3000, d2,
                              sizeof(d2)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "kb-t3", 2000, d3,
                              sizeof(d3)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "kb-t4", 1000, d4,
                              sizeof(d4))) {
        report_fail("prune_keep_bytes_evicts_oldest_first", "stage failed");
        oci_store_close(s);
        return;
    }
    /* Measure d3 + d4's combined on-disk size and set the budget to
     * exactly that so the newest two fit and the oldest two evict.
     */
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    uint64_t budget = 0;
    const char *newest[2] = {d3, d4};
    for (int i = 0; i < 2; i++) {
        if (!oci_digest_parse(newest[i], &algo, hex)) {
            report_fail("prune_keep_bytes_evicts_oldest_first", "digest parse");
            oci_store_close(s);
            return;
        }
        char path[1024];
        snprintf(path, sizeof(path), "%s/blobs/sha256/%s", root, hex);
        struct stat st;
        if (lstat(path, &st) != 0) {
            report_fail("prune_keep_bytes_evicts_oldest_first", "lstat");
            oci_store_close(s);
            return;
        }
        budget += (uint64_t) st.st_size;
    }

    oci_store_prune_options_t opts = {
        .commit = true,
        .keep_bytes = budget,
    };
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail("prune_keep_bytes_evicts_oldest_first",
                    err ? err : "prune failed");
        oci_store_close(s);
        return;
    }
    if (opts.pruned_blobs != 2 || opts.skipped_blobs != 2 ||
        opts.kept_blobs != 0) {
        report_fail("prune_keep_bytes_evicts_oldest_first",
                    "stats mismatch (want pruned=2 skipped=2 kept=0)");
        oci_store_close(s);
        return;
    }
    /* d3 and d4 (newest) must survive; d1 and d2 (oldest) must be gone. */
    const char *survive[2] = {d3, d4};
    const char *evict[2] = {d1, d2};
    for (int i = 0; i < 2; i++) {
        if (!oci_digest_parse(survive[i], &algo, hex)) {
            report_fail("prune_keep_bytes_evicts_oldest_first", "parse");
            oci_store_close(s);
            return;
        }
        char path[1024];
        snprintf(path, sizeof(path), "%s/blobs/sha256/%s", root, hex);
        struct stat st;
        if (lstat(path, &st) != 0) {
            report_fail("prune_keep_bytes_evicts_oldest_first",
                        "newest evicted");
            oci_store_close(s);
            return;
        }
    }
    for (int i = 0; i < 2; i++) {
        if (!oci_digest_parse(evict[i], &algo, hex)) {
            report_fail("prune_keep_bytes_evicts_oldest_first", "parse");
            oci_store_close(s);
            return;
        }
        char path[1024];
        snprintf(path, sizeof(path), "%s/blobs/sha256/%s", root, hex);
        struct stat st;
        if (lstat(path, &st) == 0) {
            report_fail("prune_keep_bytes_evicts_oldest_first",
                        "oldest survived");
            oci_store_close(s);
            return;
        }
    }
    oci_store_close(s);
    report_pass("prune_keep_bytes_evicts_oldest_first");
}

static void test_prune_keep_bytes_zero_is_unlimited(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-keep-zero", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("prune_keep_bytes_zero_is_unlimited", "open failed");
        return;
    }
    char d1[OCI_DIGEST_HEX_MAX + 16];
    char d2[OCI_DIGEST_HEX_MAX + 16];
    char d3[OCI_DIGEST_HEX_MAX + 16];
    char d4[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_dated_dangling(oci_store_blobs(s), root, "kz-a", 4000, d1,
                              sizeof(d1)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "kz-b", 3000, d2,
                              sizeof(d2)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "kz-c", 2000, d3,
                              sizeof(d3)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "kz-d", 1000, d4,
                              sizeof(d4))) {
        report_fail("prune_keep_bytes_zero_is_unlimited", "stage failed");
        oci_store_close(s);
        return;
    }
    oci_store_prune_options_t opts = {
        .commit = true,
        .keep_bytes = 0,
    };
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail("prune_keep_bytes_zero_is_unlimited",
                    err ? err : "prune failed");
        oci_store_close(s);
        return;
    }
    if (opts.pruned_blobs != 4 || opts.skipped_blobs != 0) {
        report_fail("prune_keep_bytes_zero_is_unlimited",
                    "stats mismatch (want pruned=4 skipped=0)");
        oci_store_close(s);
        return;
    }
    if (count_sha256_blobs(root) != 0) {
        report_fail("prune_keep_bytes_zero_is_unlimited",
                    "blobs survived despite zero-budget");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("prune_keep_bytes_zero_is_unlimited");
}

static void test_prune_combined_older_then_budget(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-combined", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("prune_combined_older_then_budget", "open failed");
        return;
    }
    /* Three fresh (1 hour ago) plus two expired (10 days, 8 days
     * ago). older-than 7d skips all three fresh blobs. The remaining
     * two expired candidates feed keep-bytes; budget = newest-
     * expired's size so the newer-expired survives and the older-
     * expired alone gets pruned.
     */
    char fresh_a[OCI_DIGEST_HEX_MAX + 16];
    char fresh_b[OCI_DIGEST_HEX_MAX + 16];
    char fresh_c[OCI_DIGEST_HEX_MAX + 16];
    char old_newer[OCI_DIGEST_HEX_MAX + 16];
    char old_older[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_dated_dangling(oci_store_blobs(s), root, "cmb-fresh-a", 3600,
                              fresh_a, sizeof(fresh_a)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "cmb-fresh-b", 3600,
                              fresh_b, sizeof(fresh_b)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "cmb-fresh-c", 3600,
                              fresh_c, sizeof(fresh_c)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "cmb-old-newer",
                              8 * 86400, old_newer, sizeof(old_newer)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "cmb-old-older",
                              10 * 86400, old_older, sizeof(old_older))) {
        report_fail("prune_combined_older_then_budget", "stage failed");
        oci_store_close(s);
        return;
    }
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(old_newer, &algo, hex)) {
        report_fail("prune_combined_older_then_budget", "digest parse");
        oci_store_close(s);
        return;
    }
    char path[1024];
    snprintf(path, sizeof(path), "%s/blobs/sha256/%s", root, hex);
    struct stat st;
    if (lstat(path, &st) != 0) {
        report_fail("prune_combined_older_then_budget", "lstat newer-expired");
        oci_store_close(s);
        return;
    }
    uint64_t budget = (uint64_t) st.st_size;

    oci_store_prune_options_t opts = {
        .commit = true,
        .older_than_sec = 7 * 86400,
        .keep_bytes = budget,
    };
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail("prune_combined_older_then_budget",
                    err ? err : "prune failed");
        oci_store_close(s);
        return;
    }
    if (opts.pruned_blobs != 1 || opts.skipped_blobs != 4 ||
        opts.kept_blobs != 0) {
        report_fail("prune_combined_older_then_budget",
                    "stats mismatch (want pruned=1 skipped=4 kept=0)");
        oci_store_close(s);
        return;
    }
    /* old_older must be gone; the other four (fresh + old_newer) survive. */
    if (!oci_digest_parse(old_older, &algo, hex)) {
        report_fail("prune_combined_older_then_budget", "parse old_older");
        oci_store_close(s);
        return;
    }
    snprintf(path, sizeof(path), "%s/blobs/sha256/%s", root, hex);
    if (lstat(path, &st) == 0) {
        report_fail("prune_combined_older_then_budget",
                    "oldest expired survived");
        oci_store_close(s);
        return;
    }
    if (count_sha256_blobs(root) != 4) {
        report_fail("prune_combined_older_then_budget",
                    "expected 4 blobs to survive on disk");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("prune_combined_older_then_budget");
}

static void test_prune_dry_run_with_filters_no_disk_touch(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-dry-filters", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("prune_dry_run_with_filters_no_disk_touch", "open failed");
        return;
    }
    char fresh_a[OCI_DIGEST_HEX_MAX + 16];
    char fresh_b[OCI_DIGEST_HEX_MAX + 16];
    char stale[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_dated_dangling(oci_store_blobs(s), root, "dryf-a", 3600, fresh_a,
                              sizeof(fresh_a)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "dryf-b", 3600, fresh_b,
                              sizeof(fresh_b)) ||
        !stage_dated_dangling(oci_store_blobs(s), root, "dryf-stale", 8 * 86400,
                              stale, sizeof(stale))) {
        report_fail("prune_dry_run_with_filters_no_disk_touch", "stage failed");
        oci_store_close(s);
        return;
    }
    oci_store_prune_options_t opts = {
        .commit = false,
        .older_than_sec = 7 * 86400,
    };
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail("prune_dry_run_with_filters_no_disk_touch",
                    err ? err : "prune failed");
        oci_store_close(s);
        return;
    }
    if (opts.pruned_blobs != 1 || opts.skipped_blobs != 2) {
        report_fail("prune_dry_run_with_filters_no_disk_touch",
                    "stats mismatch (want pruned=1 skipped=2)");
        oci_store_close(s);
        return;
    }
    if (count_sha256_blobs(root) != 3) {
        report_fail("prune_dry_run_with_filters_no_disk_touch",
                    "dry-run touched the disk");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("prune_dry_run_with_filters_no_disk_touch");
}

static void test_prune_invalid_args_rejected(const char *scratch)
{
    (void) scratch;
    const char *err = NULL;
    int rc = oci_store_prune(NULL, NULL, &err);
    if (rc != -1 || errno != EINVAL) {
        report_fail("prune_invalid_args_rejected",
                    "NULL args should fail with EINVAL");
        return;
    }
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-null-opts", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("prune_invalid_args_rejected", "open failed");
        return;
    }
    err = NULL;
    rc = oci_store_prune(s, NULL, &err);
    if (rc != -1 || errno != EINVAL) {
        report_fail("prune_invalid_args_rejected",
                    "NULL opts should fail with EINVAL");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("prune_invalid_args_rejected");
}

/* ── oci_store_collect_layer_roots + prune sweep tests ───────────────── */

/* Heap-owned descriptor for an image whose image-config blob is a real
 * parseable OCI image-config (architecture / os / rootfs.diff_ids), so the
 * mark walker can drill into rootfs.diff_ids. stage_image_v2 differs
 * from stage_image in that the config payload is real JSON instead of an
 * opaque test string; the rest of the manifest shape is identical.
 */
typedef struct {
    char *manifest_digest;
    char *config_digest;
    char **layer_digests; /* manifest layer descriptor digests */
    size_t n_layers;
    /* The diff_ids the caller injected into the image-config; not freed by
     * the helper (the strings are owned by the test driver). */
} stage_image_v2_t;

static void stage_image_v2_free(stage_image_v2_t *im)
{
    if (!im)
        return;
    free(im->manifest_digest);
    free(im->config_digest);
    if (im->layer_digests) {
        for (size_t i = 0; i < im->n_layers; i++)
            free(im->layer_digests[i]);
        free(im->layer_digests);
    }
    memset(im, 0, sizeof(*im));
}

/* Build a parseable image-config JSON whose rootfs.diff_ids equals the
 * supplied array, store it as a blob, and return its canonical
 * "<algo>:<hex>" digest in out_digest. Used as the configurable image-config
 * source for the mark walker tests.
 */
static bool stage_image_config_blob(oci_blob_store_t *blobs,
                                    const char *const *diff_ids,
                                    size_t n_diff_ids,
                                    char *out_digest,
                                    size_t cap)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "architecture", "arm64");
    cJSON_AddStringToObject(root, "os", "linux");
    cJSON *rootfs = cJSON_AddObjectToObject(root, "rootfs");
    cJSON_AddStringToObject(rootfs, "type", "layers");
    cJSON *arr = cJSON_AddArrayToObject(rootfs, "diff_ids");
    for (size_t i = 0; i < n_diff_ids; i++)
        cJSON_AddItemToArray(arr, cJSON_CreateString(diff_ids[i]));
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body)
        return false;
    bool ok = stage_manifest_blob(blobs, body, strlen(body), out_digest, cap);
    free(body);
    return ok;
}

static bool stage_image_v2(oci_blob_store_t *blobs,
                           const char *const *layer_payloads,
                           const char *const *diff_ids,
                           size_t n_layers,
                           stage_image_v2_t *out)
{
    memset(out, 0, sizeof(*out));
    out->n_layers = n_layers;
    out->layer_digests =
        calloc(n_layers ? n_layers : 1, sizeof(*out->layer_digests));
    if (!out->layer_digests)
        return false;
    int64_t *layer_sizes =
        calloc(n_layers ? n_layers : 1, sizeof(*layer_sizes));
    if (!layer_sizes) {
        stage_image_v2_free(out);
        return false;
    }
    for (size_t i = 0; i < n_layers; i++) {
        char digest[OCI_DIGEST_HEX_MAX + 16];
        if (!stage_manifest_blob(blobs, layer_payloads[i],
                                 strlen(layer_payloads[i]), digest,
                                 sizeof(digest))) {
            free(layer_sizes);
            stage_image_v2_free(out);
            return false;
        }
        out->layer_digests[i] = strdup(digest);
        layer_sizes[i] = (int64_t) strlen(layer_payloads[i]);
        if (!out->layer_digests[i]) {
            free(layer_sizes);
            stage_image_v2_free(out);
            return false;
        }
    }
    char config_digest[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_image_config_blob(blobs, diff_ids, n_layers, config_digest,
                                 sizeof(config_digest))) {
        free(layer_sizes);
        stage_image_v2_free(out);
        return false;
    }
    out->config_digest = strdup(config_digest);
    if (!out->config_digest) {
        free(layer_sizes);
        stage_image_v2_free(out);
        return false;
    }
    cJSON *m = cJSON_CreateObject();
    cJSON_AddNumberToObject(m, "schemaVersion", 2);
    cJSON_AddStringToObject(m, "mediaType",
                            "application/vnd.oci.image.manifest.v1+json");
    cJSON *cfg = cJSON_AddObjectToObject(m, "config");
    cJSON_AddStringToObject(cfg, "mediaType",
                            "application/vnd.oci.image.config.v1+json");
    cJSON_AddStringToObject(cfg, "digest", config_digest);
    /* The image-config blob's exact byte count drives the descriptor's
     * size field. stage_image_config_blob already wrote those bytes into
     * the store, but we do not know its length here without re-serializing;
     * the walker does not validate descriptor size against blob size, so
     * passing 0 is acceptable for this fixture. */
    cJSON_AddNumberToObject(cfg, "size", 0);
    cJSON *layers = cJSON_AddArrayToObject(m, "layers");
    for (size_t i = 0; i < n_layers; i++) {
        cJSON *l = cJSON_CreateObject();
        cJSON_AddStringToObject(l, "mediaType",
                                "application/vnd.oci.image.layer.v1.tar");
        cJSON_AddStringToObject(l, "digest", out->layer_digests[i]);
        cJSON_AddNumberToObject(l, "size", (double) layer_sizes[i]);
        cJSON_AddItemToArray(layers, l);
    }
    char *json = cJSON_PrintUnformatted(m);
    cJSON_Delete(m);
    free(layer_sizes);
    if (!json) {
        stage_image_v2_free(out);
        return false;
    }
    char manifest_digest[OCI_DIGEST_HEX_MAX + 16];
    bool ok = stage_manifest_blob(blobs, json, strlen(json), manifest_digest,
                                  sizeof(manifest_digest));
    free(json);
    if (!ok) {
        stage_image_v2_free(out);
        return false;
    }
    out->manifest_digest = strdup(manifest_digest);
    if (!out->manifest_digest) {
        stage_image_v2_free(out);
        return false;
    }
    return true;
}

/* Compose <root>/layers/sha256/<hex>/ for the diff_id whose canonical form
 * is supplied (assumed "sha256:<64hex>"); the directory is created with
 * 0755 if absent. Returns true on success.
 */
static bool seed_layer_dir(const char *store_root, const char *diff_id)
{
    if (strncmp(diff_id, "sha256:", 7) != 0)
        return false;
    char path[1280];
    snprintf(path, sizeof(path), "%s/layers/sha256/%s", store_root,
             diff_id + 7);
    if (mkdir(path, 0755) < 0 && errno != EEXIST)
        return false;
    return true;
}

static bool seed_stack_dir(const char *store_root, const char *chain_id)
{
    if (strncmp(chain_id, "sha256:", 7) != 0)
        return false;
    char path[1280];
    snprintf(path, sizeof(path), "%s/layers/stacks/sha256/%s", store_root,
             chain_id + 7);
    if (mkdir(path, 0755) < 0 && errno != EEXIST)
        return false;
    return true;
}

/* Drop a regular file of `size` bytes inside `dir`. Used by the size-
 * accounting test to drive pruned_layer_bytes deterministically.
 */
static bool seed_file_in_dir(const char *dir, const char *name, size_t size)
{
    char path[1408];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return false;
    char buf[256];
    memset(buf, 'x', sizeof(buf));
    size_t left = size;
    while (left > 0) {
        size_t want = left > sizeof(buf) ? sizeof(buf) : left;
        ssize_t got = write(fd, buf, want);
        if (got <= 0) {
            close(fd);
            return false;
        }
        left -= (size_t) got;
    }
    close(fd);
    return true;
}

static bool path_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* Force the on-disk mtime of an arbitrary path (file or directory) to a
 * specific epoch. utimes works on directories on Darwin so this drives the
 * older-than / keep-bytes filter sort keys deterministically for the new
 * tree-cache cases.
 */
static bool set_path_mtime(const char *path, time_t want_epoch)
{
    struct timeval times[2] = {
        {.tv_sec = want_epoch, .tv_usec = 0},
        {.tv_sec = want_epoch, .tv_usec = 0},
    };
    return utimes(path, times) == 0;
}

static void test_collect_layer_roots_empty_store(const char *scratch)
{
    const char *name = "collect_layer_roots_empty_store";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-clr-empty", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    oci_digest_set_t diffs = {0};
    oci_digest_set_t chains = {0};
    const char *err = NULL;
    if (oci_store_collect_layer_roots(s, &diffs, &chains, NULL, &err) < 0) {
        report_fail(name, err ? err : "collect failed");
        oci_digest_set_free(&diffs);
        oci_digest_set_free(&chains);
        oci_store_close(s);
        return;
    }
    if (oci_digest_set_size(&diffs) != 0 || oci_digest_set_size(&chains) != 0) {
        report_fail(name, "expected both sets empty");
        oci_digest_set_free(&diffs);
        oci_digest_set_free(&chains);
        oci_store_close(s);
        return;
    }
    oci_digest_set_free(&diffs);
    oci_digest_set_free(&chains);
    oci_store_close(s);
    report_pass(name);
}

static void test_collect_layer_roots_single_pin_layer(const char *scratch)
{
    const char *name = "collect_layer_roots_single_pin_layer";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-clr-single", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    /* A made-up but well-formed diff_id. The walker treats it as opaque
     * once it has parsed the image-config blob, so any valid 64-hex
     * suffix works.
     */
    const char *diff_ids[1] = {
        "sha256:"
        "1111111111111111111111111111111111111111111111111111111111111111"};
    const char *layer_payloads[1] = {"clr-single-layer-payload"};
    stage_image_v2_t im = {0};
    if (!stage_image_v2(oci_store_blobs(s), layer_payloads, diff_ids, 1, &im)) {
        report_fail(name, "stage_image_v2 failed");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("docker.io/library/clr-single:1", &ref)) {
        report_fail(name, "ref parse failed");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    const char *perr = NULL;
    if (oci_store_put_ref(s, &ref, im.manifest_digest, &perr) < 0) {
        report_fail(name, perr ? perr : "put_ref failed");
        oci_ref_free(&ref);
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    oci_ref_free(&ref);

    oci_digest_set_t diffs = {0};
    oci_digest_set_t chains = {0};
    const char *err = NULL;
    if (oci_store_collect_layer_roots(s, &diffs, &chains, NULL, &err) < 0) {
        report_fail(name, err ? err : "collect failed");
        oci_digest_set_free(&diffs);
        oci_digest_set_free(&chains);
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    /* L0 case: ChainID(L0) == DiffID(L0). Both sets must contain exactly
     * the one diff_id. */
    if (oci_digest_set_size(&diffs) != 1 ||
        !oci_digest_set_contains(&diffs, diff_ids[0])) {
        report_fail(name, "diff set missing diff_id");
        oci_digest_set_free(&diffs);
        oci_digest_set_free(&chains);
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    if (oci_digest_set_size(&chains) != 1 ||
        !oci_digest_set_contains(&chains, diff_ids[0])) {
        report_fail(name, "chain set missing L0 chain_id");
        oci_digest_set_free(&diffs);
        oci_digest_set_free(&chains);
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    oci_digest_set_free(&diffs);
    oci_digest_set_free(&chains);
    stage_image_v2_free(&im);
    oci_store_close(s);
    report_pass(name);
}

static void test_collect_layer_roots_three_layer_prefix_chains(
    const char *scratch)
{
    const char *name = "collect_layer_roots_three_layer_prefix_chains";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-clr-three", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    const char *diff_ids[3] = {
        "sha256:"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "sha256:"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    };
    const char *layer_payloads[3] = {"clr-l0", "clr-l1", "clr-l2"};
    stage_image_v2_t im = {0};
    if (!stage_image_v2(oci_store_blobs(s), layer_payloads, diff_ids, 3, &im)) {
        report_fail(name, "stage_image_v2 failed");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("docker.io/library/clr-three:1", &ref)) {
        report_fail(name, "ref parse failed");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    const char *perr = NULL;
    if (oci_store_put_ref(s, &ref, im.manifest_digest, &perr) < 0) {
        report_fail(name, perr ? perr : "put_ref failed");
        oci_ref_free(&ref);
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    oci_ref_free(&ref);

    oci_digest_set_t diffs = {0};
    oci_digest_set_t chains = {0};
    const char *err = NULL;
    if (oci_store_collect_layer_roots(s, &diffs, &chains, NULL, &err) < 0) {
        report_fail(name, err ? err : "collect failed");
        oci_digest_set_free(&diffs);
        oci_digest_set_free(&chains);
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    if (oci_digest_set_size(&diffs) != 3) {
        report_fail(name, "diff set size != 3");
        oci_digest_set_free(&diffs);
        oci_digest_set_free(&chains);
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    /* Recompute the prefix chains independently and assert each prefix is
     * in chain_set. This guards against a walker that only recorded the
     * terminal chain (which would break unpack-write semantics).
     */
    char expected[3][OCI_DIGEST_HEX_MAX + 16];
    char prev[OCI_DIGEST_HEX_MAX + 16] = "";
    for (size_t i = 0; i < 3; i++) {
        const char *prev_arg = (i == 0) ? NULL : prev;
        if (oci_chainid_compute(prev_arg, diff_ids[i], expected[i],
                                sizeof(expected[i])) < 0) {
            report_fail(name, "chainid_compute helper failed");
            oci_digest_set_free(&diffs);
            oci_digest_set_free(&chains);
            stage_image_v2_free(&im);
            oci_store_close(s);
            return;
        }
        memcpy(prev, expected[i], strlen(expected[i]) + 1);
    }
    if (oci_digest_set_size(&chains) != 3) {
        report_fail(name, "chain set size != 3");
        oci_digest_set_free(&diffs);
        oci_digest_set_free(&chains);
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    for (size_t i = 0; i < 3; i++) {
        if (!oci_digest_set_contains(&chains, expected[i])) {
            report_fail(name, "chain set missing a prefix chain_id");
            oci_digest_set_free(&diffs);
            oci_digest_set_free(&chains);
            stage_image_v2_free(&im);
            oci_store_close(s);
            return;
        }
    }
    oci_digest_set_free(&diffs);
    oci_digest_set_free(&chains);
    stage_image_v2_free(&im);
    oci_store_close(s);
    report_pass(name);
}

/* Build an unpacked tree fixture wired to a specific diff_id list, then
 * verify both sets reflect those diff_ids. Distinct from
 * collect_layer_roots_single_pin_layer because the walker reads the origin
 * sidecar directly instead of drilling through an image-config blob.
 */
static void test_collect_layer_roots_unpacked_tree(const char *scratch)
{
    const char *name = "collect_layer_roots_unpacked_tree";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-clr-unpacked", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    char vol[1024];
    snprintf(vol, sizeof(vol), "%s/case-clr-unpacked-vol", scratch);
    char images[1280];
    snprintf(images, sizeof(images), "%s/images", vol);
    mkdir(vol, 0755);
    mkdir(images, 0755);
    char tree[1408];
    snprintf(tree, sizeof(tree),
             "%s/sha256-"
             "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
             images);
    if (mkdir(tree, 0755) < 0 && errno != EEXIST) {
        report_fail(name, "tree mkdir failed");
        oci_store_close(s);
        return;
    }
    char *diff_ids[3] = {
        "sha256:"
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "sha256:"
        "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
        NULL,
    };
    const char *oerr = NULL;
    if (oci_origin_write(tree, diff_ids[0], diff_ids[1], diff_ids, &oerr) < 0) {
        report_fail(name, oerr ? oerr : "origin_write failed");
        oci_store_close(s);
        return;
    }

    oci_digest_set_t diffs = {0};
    oci_digest_set_t chains = {0};
    const char *err = NULL;
    if (oci_store_collect_layer_roots(s, &diffs, &chains, vol, &err) < 0) {
        report_fail(name, err ? err : "collect failed");
        oci_digest_set_free(&diffs);
        oci_digest_set_free(&chains);
        oci_store_close(s);
        return;
    }
    if (oci_digest_set_size(&diffs) != 2 ||
        !oci_digest_set_contains(&diffs, diff_ids[0]) ||
        !oci_digest_set_contains(&diffs, diff_ids[1])) {
        report_fail(name, "diff set missing origin diff_ids");
        oci_digest_set_free(&diffs);
        oci_digest_set_free(&chains);
        oci_store_close(s);
        return;
    }
    /* Two prefix chains: ChainID(L0) == DiffID(L0); ChainID(L1) =
     * sha256(L0 chain + " " + DiffID(L1)). */
    char chain1[OCI_DIGEST_HEX_MAX + 16];
    if (oci_chainid_compute(diff_ids[0], diff_ids[1], chain1, sizeof(chain1)) <
        0) {
        report_fail(name, "chainid_compute helper failed");
        oci_digest_set_free(&diffs);
        oci_digest_set_free(&chains);
        oci_store_close(s);
        return;
    }
    if (oci_digest_set_size(&chains) != 2 ||
        !oci_digest_set_contains(&chains, diff_ids[0]) ||
        !oci_digest_set_contains(&chains, chain1)) {
        report_fail(name, "chain set missing prefix chains");
        oci_digest_set_free(&diffs);
        oci_digest_set_free(&chains);
        oci_store_close(s);
        return;
    }
    oci_digest_set_free(&diffs);
    oci_digest_set_free(&chains);
    oci_store_close(s);
    report_pass(name);
}

/* A pin whose manifest blob is present but whose image-config blob is
 * absent must surface as a fatal mark failure so prune does not later
 * delete reachable cache entries on the false belief that nothing is
 * referenced.
 */
static void test_collect_layer_roots_missing_config_blob_fails(
    const char *scratch)
{
    const char *name = "collect_layer_roots_missing_config_blob_fails";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-clr-missing-cfg", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    const char *diff_ids[1] = {
        "sha256:"
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"};
    const char *layer_payloads[1] = {"clr-missing-cfg-layer"};
    stage_image_v2_t im = {0};
    if (!stage_image_v2(oci_store_blobs(s), layer_payloads, diff_ids, 1, &im)) {
        report_fail(name, "stage_image_v2 failed");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("docker.io/library/clr-missing-cfg:1", &ref)) {
        report_fail(name, "ref parse failed");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    const char *perr = NULL;
    if (oci_store_put_ref(s, &ref, im.manifest_digest, &perr) < 0) {
        report_fail(name, perr ? perr : "put_ref failed");
        oci_ref_free(&ref);
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    oci_ref_free(&ref);
    /* Unlink the image-config blob to simulate corrupted store state. */
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(im.config_digest, &algo, hex)) {
        report_fail(name, "digest parse failed");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    char cfg_path[1280];
    snprintf(cfg_path, sizeof(cfg_path), "%s/blobs/sha256/%s", root, hex);
    if (unlink(cfg_path) < 0) {
        report_fail(name, "unlink config blob failed");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    oci_digest_set_t diffs = {0};
    oci_digest_set_t chains = {0};
    const char *err = NULL;
    int rc = oci_store_collect_layer_roots(s, &diffs, &chains, NULL, &err);
    if (rc != -1) {
        report_fail(name, "expected -1 on missing config blob");
        oci_digest_set_free(&diffs);
        oci_digest_set_free(&chains);
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    /* Sets must be freed back to empty on failure. */
    if (oci_digest_set_size(&diffs) != 0 || oci_digest_set_size(&chains) != 0) {
        report_fail(name, "sets not freed on failure");
        oci_digest_set_free(&diffs);
        oci_digest_set_free(&chains);
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    oci_digest_set_free(&diffs);
    oci_digest_set_free(&chains);
    stage_image_v2_free(&im);
    oci_store_close(s);
    report_pass(name);
}

static void test_prune_sweeps_dangling_layer_entry(const char *scratch)
{
    const char *name = "prune_sweeps_dangling_layer_entry";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-dangling-layer", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    const char *dangling =
        "sha256:"
        "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
    if (!seed_layer_dir(root, dangling)) {
        report_fail(name, "seed_layer_dir failed");
        oci_store_close(s);
        return;
    }
    char path[1280];
    snprintf(path, sizeof(path), "%s/layers/sha256/%s", root, dangling + 7);
    if (!seed_file_in_dir(path, "payload", 17)) {
        report_fail(name, "seed_file_in_dir failed");
        oci_store_close(s);
        return;
    }

    oci_store_prune_options_t opts = {.commit = true};
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail(name, err ? err : "prune failed");
        oci_store_close(s);
        return;
    }
    if (opts.pruned_layers != 1 || opts.pruned_layer_bytes != 17 ||
        opts.kept_layers != 0) {
        report_fail(name, "layer stats mismatch");
        oci_store_close(s);
        return;
    }
    if (path_exists(path)) {
        report_fail(name, "dangling layer dir survived commit");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

static void test_prune_keeps_layer_referenced_by_pin(const char *scratch)
{
    const char *name = "prune_keeps_layer_referenced_by_pin";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-keep-layer-pin", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    const char *diff_id =
        "sha256:"
        "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f";
    const char *diff_ids[1] = {diff_id};
    const char *layer_payloads[1] = {"keep-layer-pin-payload"};
    stage_image_v2_t im = {0};
    if (!stage_image_v2(oci_store_blobs(s), layer_payloads, diff_ids, 1, &im)) {
        report_fail(name, "stage_image_v2 failed");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("docker.io/library/klp:1", &ref)) {
        report_fail(name, "ref parse failed");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    const char *perr = NULL;
    if (oci_store_put_ref(s, &ref, im.manifest_digest, &perr) < 0) {
        report_fail(name, perr ? perr : "put_ref failed");
        oci_ref_free(&ref);
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    oci_ref_free(&ref);
    if (!seed_layer_dir(root, diff_id)) {
        report_fail(name, "seed_layer_dir failed");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }

    oci_store_prune_options_t opts = {.commit = true};
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail(name, err ? err : "prune failed");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    if (opts.kept_layers != 1 || opts.pruned_layers != 0) {
        report_fail(name, "expected kept=1 pruned=0 for the reachable layer");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    char path[1280];
    snprintf(path, sizeof(path), "%s/layers/sha256/%s", root, diff_id + 7);
    if (!path_exists(path)) {
        report_fail(name, "reachable layer dir was deleted");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    stage_image_v2_free(&im);
    oci_store_close(s);
    report_pass(name);
}

static void test_prune_keeps_layer_referenced_by_unpacked_tree(
    const char *scratch)
{
    const char *name = "prune_keeps_layer_referenced_by_unpacked_tree";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-keep-layer-unp", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    /* Stage a real image so the blob mark walker can resolve the manifest
     * digest the origin sidecar references; the layer mark walker reads
     * diff_ids directly from origin.layer_diffids so they need not match
     * the image-config rootfs.diff_ids. */
    const char *diff_ids_unused[1] = {
        "sha256:"
        "0000000000000000000000000000000000000000000000000000000000000000"};
    const char *layer_payloads[1] = {"unpacked-keep-layer"};
    stage_image_v2_t im = {0};
    if (!stage_image_v2(oci_store_blobs(s), layer_payloads, diff_ids_unused, 1,
                        &im)) {
        report_fail(name, "stage_image_v2 failed");
        oci_store_close(s);
        return;
    }

    char vol[1024];
    snprintf(vol, sizeof(vol), "%s/case-prune-keep-layer-unp-vol", scratch);
    char images[1280];
    snprintf(images, sizeof(images), "%s/images", vol);
    mkdir(vol, 0755);
    mkdir(images, 0755);
    char tree[1408];
    snprintf(tree, sizeof(tree),
             "%s/sha256-"
             "9999999999999999999999999999999999999999999999999999999999999999",
             images);
    if (mkdir(tree, 0755) < 0 && errno != EEXIST) {
        report_fail(name, "tree mkdir failed");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    char *diff_ids[2] = {
        "sha256:"
        "2222222222222222222222222222222222222222222222222222222222222222",
        NULL};
    const char *oerr = NULL;
    if (oci_origin_write(tree, im.manifest_digest, im.config_digest, diff_ids,
                         &oerr) < 0) {
        report_fail(name, oerr ? oerr : "origin_write failed");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    if (!seed_layer_dir(root, diff_ids[0])) {
        report_fail(name, "seed_layer_dir failed");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }

    oci_store_prune_options_t opts = {
        .commit = true,
        .volume_root = vol,
    };
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail(name, err ? err : "prune failed");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    if (opts.kept_layers != 1 || opts.pruned_layers != 0) {
        report_fail(name, "stats mismatch for unpacked-tree contribution");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    char path[1280];
    snprintf(path, sizeof(path), "%s/layers/sha256/%s", root, diff_ids[0] + 7);
    if (!path_exists(path)) {
        report_fail(name, "reachable layer dir was deleted");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    stage_image_v2_free(&im);
    oci_store_close(s);
    report_pass(name);
}

static void test_prune_sweeps_dangling_stack_entry(const char *scratch)
{
    const char *name = "prune_sweeps_dangling_stack_entry";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-dangling-stack", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    const char *dangling =
        "sha256:"
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    if (!seed_stack_dir(root, dangling)) {
        report_fail(name, "seed_stack_dir failed");
        oci_store_close(s);
        return;
    }
    oci_store_prune_options_t opts = {.commit = true};
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail(name, err ? err : "prune failed");
        oci_store_close(s);
        return;
    }
    if (opts.pruned_stacks != 1 || opts.kept_stacks != 0) {
        report_fail(name, "stack stats mismatch");
        oci_store_close(s);
        return;
    }
    char path[1280];
    snprintf(path, sizeof(path), "%s/layers/stacks/sha256/%s", root,
             dangling + 7);
    if (path_exists(path)) {
        report_fail(name, "dangling stack dir survived commit");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

static void test_prune_keeps_stack_for_each_prefix_chain(const char *scratch)
{
    const char *name = "prune_keeps_stack_for_each_prefix_chain";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-stack-prefixes", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    const char *diff_ids[3] = {
        "sha256:"
        "3030303030303030303030303030303030303030303030303030303030303030",
        "sha256:"
        "3131313131313131313131313131313131313131313131313131313131313131",
        "sha256:"
        "3232323232323232323232323232323232323232323232323232323232323232",
    };
    const char *layer_payloads[3] = {"stk-l0", "stk-l1", "stk-l2"};
    stage_image_v2_t im = {0};
    if (!stage_image_v2(oci_store_blobs(s), layer_payloads, diff_ids, 3, &im)) {
        report_fail(name, "stage_image_v2 failed");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("docker.io/library/stk:1", &ref)) {
        report_fail(name, "ref parse failed");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    const char *perr = NULL;
    if (oci_store_put_ref(s, &ref, im.manifest_digest, &perr) < 0) {
        report_fail(name, perr ? perr : "put_ref failed");
        oci_ref_free(&ref);
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    oci_ref_free(&ref);
    /* Materialize all three prefix chains on disk. The walker must keep
     * every one because oci_unpack writes each prefix during the apply
     * loop. */
    char chains[3][OCI_DIGEST_HEX_MAX + 16];
    char prev[OCI_DIGEST_HEX_MAX + 16] = "";
    for (size_t i = 0; i < 3; i++) {
        const char *prev_arg = (i == 0) ? NULL : prev;
        if (oci_chainid_compute(prev_arg, diff_ids[i], chains[i],
                                sizeof(chains[i])) < 0) {
            report_fail(name, "chainid compute failed");
            stage_image_v2_free(&im);
            oci_store_close(s);
            return;
        }
        memcpy(prev, chains[i], strlen(chains[i]) + 1);
        if (!seed_stack_dir(root, chains[i])) {
            report_fail(name, "seed_stack_dir failed");
            stage_image_v2_free(&im);
            oci_store_close(s);
            return;
        }
    }

    oci_store_prune_options_t opts = {.commit = true};
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail(name, err ? err : "prune failed");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    if (opts.kept_stacks != 3 || opts.pruned_stacks != 0) {
        report_fail(name, "stats mismatch (want kept=3 pruned=0)");
        stage_image_v2_free(&im);
        oci_store_close(s);
        return;
    }
    for (size_t i = 0; i < 3; i++) {
        char path[1280];
        snprintf(path, sizeof(path), "%s/layers/stacks/sha256/%s", root,
                 chains[i] + 7);
        if (!path_exists(path)) {
            report_fail(name, "prefix chain dir deleted");
            stage_image_v2_free(&im);
            oci_store_close(s);
            return;
        }
    }
    stage_image_v2_free(&im);
    oci_store_close(s);
    report_pass(name);
}

static void test_prune_dry_run_keeps_layer_and_stack_on_disk(
    const char *scratch)
{
    const char *name = "prune_dry_run_keeps_layer_and_stack_on_disk";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-dry-c33d", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    const char *layer_id =
        "sha256:"
        "4040404040404040404040404040404040404040404040404040404040404040";
    const char *stack_id =
        "sha256:"
        "5050505050505050505050505050505050505050505050505050505050505050";
    if (!seed_layer_dir(root, layer_id) || !seed_stack_dir(root, stack_id)) {
        report_fail(name, "seed_* failed");
        oci_store_close(s);
        return;
    }
    char lp[1280];
    char sp[1280];
    snprintf(lp, sizeof(lp), "%s/layers/sha256/%s", root, layer_id + 7);
    snprintf(sp, sizeof(sp), "%s/layers/stacks/sha256/%s", root, stack_id + 7);

    oci_store_prune_options_t opts = {0}; /* dry-run */
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail(name, err ? err : "prune failed");
        oci_store_close(s);
        return;
    }
    if (opts.pruned_layers != 1 || opts.pruned_stacks != 1) {
        report_fail(name, "expected pruned_layers=1 pruned_stacks=1");
        oci_store_close(s);
        return;
    }
    if (!path_exists(lp) || !path_exists(sp)) {
        report_fail(name, "dry-run touched disk");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

static void test_prune_layer_size_counted_in_pruned_bytes(const char *scratch)
{
    const char *name = "prune_layer_size_counted_in_pruned_bytes";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-layer-bytes", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    const char *layer_id =
        "sha256:"
        "6060606060606060606060606060606060606060606060606060606060606060";
    if (!seed_layer_dir(root, layer_id)) {
        report_fail(name, "seed_layer_dir failed");
        oci_store_close(s);
        return;
    }
    char dir[1280];
    snprintf(dir, sizeof(dir), "%s/layers/sha256/%s", root, layer_id + 7);
    if (!seed_file_in_dir(dir, "a", 100) || !seed_file_in_dir(dir, "b", 250)) {
        report_fail(name, "seed_file_in_dir failed");
        oci_store_close(s);
        return;
    }

    oci_store_prune_options_t opts = {.commit = true};
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail(name, err ? err : "prune failed");
        oci_store_close(s);
        return;
    }
    if (opts.pruned_layers != 1 || opts.pruned_layer_bytes != 350) {
        report_fail(name, "pruned_layer_bytes != 350");
        oci_store_close(s);
        return;
    }
    if (path_exists(dir)) {
        report_fail(name, "layer dir not removed");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

static void test_prune_older_than_skips_fresh_layer_entry(const char *scratch)
{
    const char *name = "prune_older_than_skips_fresh_layer_entry";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-otl", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    const char *fresh_id =
        "sha256:"
        "7070707070707070707070707070707070707070707070707070707070707070";
    const char *stale_id =
        "sha256:"
        "8181818181818181818181818181818181818181818181818181818181818181";
    if (!seed_layer_dir(root, fresh_id) || !seed_layer_dir(root, stale_id)) {
        report_fail(name, "seed_layer_dir failed");
        oci_store_close(s);
        return;
    }
    char fresh_path[1280];
    char stale_path[1280];
    snprintf(fresh_path, sizeof(fresh_path), "%s/layers/sha256/%s", root,
             fresh_id + 7);
    snprintf(stale_path, sizeof(stale_path), "%s/layers/sha256/%s", root,
             stale_id + 7);
    time_t now = time(NULL);
    if (!set_path_mtime(fresh_path, now - 3600) ||
        !set_path_mtime(stale_path, now - 8 * 86400)) {
        report_fail(name, "set_path_mtime failed");
        oci_store_close(s);
        return;
    }

    oci_store_prune_options_t opts = {
        .commit = true,
        .older_than_sec = 7 * 86400,
    };
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail(name, err ? err : "prune failed");
        oci_store_close(s);
        return;
    }
    if (opts.pruned_layers != 1 || opts.skipped_layers != 1) {
        report_fail(name, "expected pruned=1 skipped=1 for layers");
        oci_store_close(s);
        return;
    }
    if (path_exists(stale_path) || !path_exists(fresh_path)) {
        report_fail(name, "wrong layer was unlinked");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

static void test_prune_keep_bytes_evicts_oldest_layer_first(const char *scratch)
{
    const char *name = "prune_keep_bytes_evicts_oldest_layer_first";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-prune-kbl", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    /* Three dangling layer dirs sized 100 / 200 / 300, mtimes 4000s / 3000s
     * / 2000s ago. With keep_bytes=500 the newest two (200+300=500) survive
     * and the oldest (100 bytes) is evicted regardless of fit. */
    const char *ids[3] = {
        "sha256:"
        "abababababababababababababababababababababababababababababababab",
        "sha256:"
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "sha256:"
        "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
    };
    size_t sizes[3] = {100, 200, 300};
    time_t ages[3] = {4000, 3000, 2000};
    time_t now = time(NULL);
    for (size_t i = 0; i < 3; i++) {
        if (!seed_layer_dir(root, ids[i])) {
            report_fail(name, "seed_layer_dir failed");
            oci_store_close(s);
            return;
        }
        char dp[1280];
        snprintf(dp, sizeof(dp), "%s/layers/sha256/%s", root, ids[i] + 7);
        if (!seed_file_in_dir(dp, "payload", sizes[i])) {
            report_fail(name, "seed_file_in_dir failed");
            oci_store_close(s);
            return;
        }
        if (!set_path_mtime(dp, now - ages[i])) {
            report_fail(name, "set_path_mtime failed");
            oci_store_close(s);
            return;
        }
    }

    oci_store_prune_options_t opts = {
        .commit = true,
        .keep_bytes = 500,
    };
    const char *err = NULL;
    if (oci_store_prune(s, &opts, &err) < 0) {
        report_fail(name, err ? err : "prune failed");
        oci_store_close(s);
        return;
    }
    if (opts.pruned_layers != 1 || opts.skipped_layers != 2) {
        report_fail(name, "expected pruned=1 skipped=2");
        oci_store_close(s);
        return;
    }
    /* ids[0] is the oldest; it must be the one that lost. ids[1] / ids[2]
     * must still be on disk. */
    char p0[1280];
    char p1[1280];
    char p2[1280];
    snprintf(p0, sizeof(p0), "%s/layers/sha256/%s", root, ids[0] + 7);
    snprintf(p1, sizeof(p1), "%s/layers/sha256/%s", root, ids[1] + 7);
    snprintf(p2, sizeof(p2), "%s/layers/sha256/%s", root, ids[2] + 7);
    if (path_exists(p0) || !path_exists(p1) || !path_exists(p2)) {
        report_fail(name, "wrong layer was evicted");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

/* --- layer cache directory layout + helpers ----------------------------- */

static void test_open_creates_layer_dirs(const char *scratch)
{
    const char *name = "open_creates_layer_dirs";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-layer-init", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "store_open");
        return;
    }
    struct stat st;
    char path[2048];
    snprintf(path, sizeof(path), "%s/layers", root);
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        report_fail(name, "layers/ missing");
        oci_store_close(s);
        return;
    }
    snprintf(path, sizeof(path), "%s/layers/sha256", root);
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        report_fail(name, "layers/sha256/ missing");
        oci_store_close(s);
        return;
    }
    snprintf(path, sizeof(path), "%s/layers/stacks", root);
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        report_fail(name, "layers/stacks/ missing");
        oci_store_close(s);
        return;
    }
    snprintf(path, sizeof(path), "%s/layers/stacks/sha256", root);
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        report_fail(name, "layers/stacks/sha256/ missing");
        oci_store_close(s);
        return;
    }
    snprintf(path, sizeof(path), "%s/layers/.staging", root);
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        report_fail(name, "layers/.staging/ missing");
        oci_store_close(s);
        return;
    }
    /* Reopen idempotently: mkdir EEXIST must not surface as an error. */
    oci_store_close(s);
    s = oci_store_open(root);
    if (!s) {
        report_fail(name, "reopen failed (EEXIST not handled)");
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

static void test_layer_resolve_format(const char *scratch)
{
    const char *name = "layer_resolve_format";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-layer-resolve", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "store_open");
        return;
    }
    char out[1024];
    if (oci_store_layer_resolve(
            s,
            "sha256:"
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            out, sizeof(out)) < 0) {
        report_fail(name, "resolve returned -1");
        oci_store_close(s);
        return;
    }
    char want[1280];
    snprintf(
        want, sizeof(want),
        "%s/layers/sha256/"
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789/",
        root);
    if (strcmp(out, want) != 0) {
        report_fail(name, "resolved path mismatch");
        oci_store_close(s);
        return;
    }
    /* Malformed diff_id must be rejected with EINVAL. */
    errno = 0;
    if (oci_store_layer_resolve(s, "not-a-digest", out, sizeof(out)) != -1 ||
        errno != EINVAL) {
        report_fail(name, "malformed diff_id not rejected");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

static void test_layer_has_present_absent(const char *scratch)
{
    const char *name = "layer_has_present_absent";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-layer-has", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "store_open");
        return;
    }
    const char *diff_id =
        "sha256:"
        "1111111111111111111111111111111111111111111111111111111111111111";
    int rc = oci_store_layer_has(s, diff_id);
    if (rc != 0) {
        report_fail(name, "absent layer reported as present");
        oci_store_close(s);
        return;
    }
    /* Materialize the cache directory and re-probe. */
    char dir[1280];
    snprintf(dir, sizeof(dir), "%s/layers/sha256/%s", root, diff_id + 7);
    if (mkdir(dir, 0755) < 0) {
        report_fail(name, "mkdir cache_dir failed");
        oci_store_close(s);
        return;
    }
    rc = oci_store_layer_has(s, diff_id);
    if (rc != 1) {
        report_fail(name, "present layer reported as absent");
        oci_store_close(s);
        return;
    }
    /* Malformed diff_id is rejected without touching disk. */
    errno = 0;
    if (oci_store_layer_has(s, "sha256:not-hex") != -1 || errno != EINVAL) {
        report_fail(name, "malformed diff_id not rejected");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

static void test_layer_commit_rename_race_benign(const char *scratch)
{
    const char *name = "layer_commit_rename_race_benign";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-layer-commit", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "store_open");
        return;
    }
    const char *diff_id =
        "sha256:"
        "2222222222222222222222222222222222222222222222222222222222222222";

    /* Pre-seed the destination so the rename below races with a "winner". */
    char dest[1280];
    snprintf(dest, sizeof(dest), "%s/layers/sha256/%s", root, diff_id + 7);
    if (mkdir(dest, 0755) < 0) {
        report_fail(name, "mkdir dest failed");
        oci_store_close(s);
        return;
    }

    /* Stage a directory with a marker file so the loser-cleanup path has
     * something to recursively remove.
     */
    char stage[1280];
    if (oci_store_layer_stage_path(s, diff_id, stage, sizeof(stage)) < 0) {
        report_fail(name, "stage_path failed");
        oci_store_close(s);
        return;
    }
    if (mkdir(stage, 0755) < 0) {
        report_fail(name, "stage mkdir failed");
        oci_store_close(s);
        return;
    }
    char marker[1408];
    snprintf(marker, sizeof(marker), "%s/marker", stage);
    int fd = open(marker, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        report_fail(name, "stage marker open failed");
        oci_store_close(s);
        return;
    }
    close(fd);

    const char *err = NULL;
    int rc = oci_store_layer_commit(s, stage, diff_id, &err);
    if (rc != 0) {
        report_fail(name, err ? err : "commit returned -1 on race");
        oci_store_close(s);
        return;
    }
    /* Staging dir must be gone after the loser-cleanup branch. */
    struct stat st;
    if (stat(stage, &st) == 0) {
        report_fail(name, "stage dir not cleaned up after race loss");
        oci_store_close(s);
        return;
    }
    /* Pre-existing dest must remain untouched. */
    if (stat(dest, &st) != 0 || !S_ISDIR(st.st_mode)) {
        report_fail(name, "winner cache dir removed by commit");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

/* --- ChainID stack cache tests ------------------------------------------- */

static void test_stack_resolve_format(const char *scratch)
{
    const char *name = "stack_resolve_format";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-stack-resolve", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "store_open");
        return;
    }
    static const char CHAIN[] =
        "sha256:"
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    char out[1280];
    if (oci_store_stack_resolve(s, CHAIN, out, sizeof(out)) < 0) {
        report_fail(name, "resolve returned -1");
        oci_store_close(s);
        return;
    }
    char want[1408];
    snprintf(
        want, sizeof(want),
        "%s/layers/stacks/sha256/"
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789/",
        root);
    if (strcmp(out, want) != 0) {
        report_fail(name, "resolved path mismatch");
        oci_store_close(s);
        return;
    }
    errno = 0;
    if (oci_store_stack_resolve(s, "not-a-digest", out, sizeof(out)) != -1 ||
        errno != EINVAL) {
        report_fail(name, "malformed chain_id not rejected");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

static void test_stack_has_present_absent(const char *scratch)
{
    const char *name = "stack_has_present_absent";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-stack-has", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "store_open");
        return;
    }
    const char *chain_id =
        "sha256:"
        "3333333333333333333333333333333333333333333333333333333333333333";
    int rc = oci_store_stack_has(s, chain_id);
    if (rc != 0) {
        report_fail(name, "absent stack reported as present");
        oci_store_close(s);
        return;
    }
    char dir[1408];
    snprintf(dir, sizeof(dir), "%s/layers/stacks/sha256/%s", root,
             chain_id + 7);
    if (mkdir(dir, 0755) < 0) {
        report_fail(name, "mkdir stack_dir failed");
        oci_store_close(s);
        return;
    }
    rc = oci_store_stack_has(s, chain_id);
    if (rc != 1) {
        report_fail(name, "present stack reported as absent");
        oci_store_close(s);
        return;
    }
    errno = 0;
    if (oci_store_stack_has(s, "sha256:not-hex") != -1 || errno != EINVAL) {
        report_fail(name, "malformed chain_id not rejected");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

static void test_stack_stage_path_uniqueness(const char *scratch)
{
    const char *name = "stack_stage_path_uniqueness";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-stack-stage", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "store_open");
        return;
    }
    const char *chain_id =
        "sha256:"
        "4444444444444444444444444444444444444444444444444444444444444444";
    char a[1280];
    char b[1280];
    if (oci_store_stack_stage_path(s, chain_id, a, sizeof(a)) < 0 ||
        oci_store_stack_stage_path(s, chain_id, b, sizeof(b)) < 0) {
        report_fail(name, "stage_path failed");
        oci_store_close(s);
        return;
    }
    /* Both paths must sit under <root>/layers/.staging/stack-... so a
     * shared staging dir suffices for both raw and stack writers, and the
     * random suffix prevents collisions inside a single process.
     */
    char prefix[1280];
    snprintf(prefix, sizeof(prefix), "%s/layers/.staging/stack-sha256-", root);
    if (strncmp(a, prefix, strlen(prefix)) != 0 ||
        strncmp(b, prefix, strlen(prefix)) != 0) {
        report_fail(name, "stage path prefix mismatch");
        oci_store_close(s);
        return;
    }
    if (strcmp(a, b) == 0) {
        report_fail(name, "two stage paths collided");
        oci_store_close(s);
        return;
    }
    errno = 0;
    if (oci_store_stack_stage_path(s, "garbage", a, sizeof(a)) != -1 ||
        errno != EINVAL) {
        report_fail(name, "malformed chain_id not rejected");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

static void test_stack_commit_round_trip(const char *scratch)
{
    const char *name = "stack_commit_round_trip";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-stack-commit", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "store_open");
        return;
    }
    const char *chain_id =
        "sha256:"
        "5555555555555555555555555555555555555555555555555555555555555555";

    char stage[1280];
    if (oci_store_stack_stage_path(s, chain_id, stage, sizeof(stage)) < 0) {
        report_fail(name, "stage_path failed");
        oci_store_close(s);
        return;
    }
    if (mkdir(stage, 0755) < 0) {
        report_fail(name, "stage mkdir failed");
        oci_store_close(s);
        return;
    }
    char marker[1408];
    snprintf(marker, sizeof(marker), "%s/marker", stage);
    int fd = open(marker, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        report_fail(name, "stage marker open failed");
        oci_store_close(s);
        return;
    }
    close(fd);

    const char *err = NULL;
    if (oci_store_stack_commit(s, stage, chain_id, &err) < 0) {
        report_fail(name, err ? err : "commit returned -1");
        oci_store_close(s);
        return;
    }
    /* stage_path is gone, dest is in place with the marker preserved. */
    struct stat st;
    if (stat(stage, &st) == 0) {
        report_fail(name, "stage dir survived a successful commit");
        oci_store_close(s);
        return;
    }
    if (oci_store_stack_has(s, chain_id) != 1) {
        report_fail(name, "stack_has reports absent after commit");
        oci_store_close(s);
        return;
    }
    char dest[1408];
    snprintf(dest, sizeof(dest), "%s/layers/stacks/sha256/%s/marker", root,
             chain_id + 7);
    if (stat(dest, &st) != 0 || !S_ISREG(st.st_mode)) {
        report_fail(name, "marker missing in committed stack dir");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

static void test_stack_commit_rename_race_benign(const char *scratch)
{
    const char *name = "stack_commit_rename_race_benign";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-stack-race", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "store_open");
        return;
    }
    const char *chain_id =
        "sha256:"
        "6666666666666666666666666666666666666666666666666666666666666666";

    char dest[1408];
    snprintf(dest, sizeof(dest), "%s/layers/stacks/sha256/%s", root,
             chain_id + 7);
    if (mkdir(dest, 0755) < 0) {
        report_fail(name, "mkdir dest failed");
        oci_store_close(s);
        return;
    }
    /* Drop a sentinel inside the pre-seeded dest so we can assert the
     * winner survives the race.
     */
    char winner_marker[1536];
    snprintf(winner_marker, sizeof(winner_marker), "%s/winner", dest);
    int fd = open(winner_marker, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        report_fail(name, "winner sentinel open failed");
        oci_store_close(s);
        return;
    }
    close(fd);

    char stage[1280];
    if (oci_store_stack_stage_path(s, chain_id, stage, sizeof(stage)) < 0) {
        report_fail(name, "stage_path failed");
        oci_store_close(s);
        return;
    }
    if (mkdir(stage, 0755) < 0) {
        report_fail(name, "stage mkdir failed");
        oci_store_close(s);
        return;
    }
    char loser_marker[1408];
    snprintf(loser_marker, sizeof(loser_marker), "%s/loser", stage);
    fd = open(loser_marker, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        report_fail(name, "loser marker open failed");
        oci_store_close(s);
        return;
    }
    close(fd);

    const char *err = NULL;
    if (oci_store_stack_commit(s, stage, chain_id, &err) < 0) {
        report_fail(name, err ? err : "commit returned -1 on race");
        oci_store_close(s);
        return;
    }
    struct stat st;
    if (stat(stage, &st) == 0) {
        report_fail(name, "stage dir not cleaned up after race loss");
        oci_store_close(s);
        return;
    }
    if (stat(winner_marker, &st) != 0 || !S_ISREG(st.st_mode)) {
        report_fail(name, "winner sentinel removed by losing commit");
        oci_store_close(s);
        return;
    }
    /* Loser's marker never made it across because rename failed and the
     * loser tree was rm'd; the destination must contain only the winner.
     */
    char loser_in_dest[1536];
    snprintf(loser_in_dest, sizeof(loser_in_dest), "%s/loser", dest);
    if (stat(loser_in_dest, &st) == 0) {
        report_fail(name, "loser marker leaked into dest");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass(name);
}

/* --- layer cache schema marker tests ------------------------------------- */

static void test_layer_schema_written_on_fresh_open(const char *scratch)
{
    const char *name = "layer_schema_written_on_fresh_open";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-layer-schema-fresh", scratch);

    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    oci_store_close(s);

    char marker_path[2048];
    snprintf(marker_path, sizeof(marker_path), "%s/layers/.schema", root);
    struct stat st;
    if (stat(marker_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        report_fail(name, "marker missing or not a regular file");
        return;
    }
    char body[4096];
    size_t got = 0;
    if (!read_whole(marker_path, body, sizeof(body), &got) || got == 0) {
        report_fail(name, "read marker failed");
        return;
    }
    cJSON *json = cJSON_Parse(body);
    if (!json) {
        report_fail(name, "marker JSON unparseable");
        return;
    }
    cJSON *v = cJSON_GetObjectItemCaseSensitive(json, "schemaVersion");
    if (!cJSON_IsNumber(v) || v->valueint != 2) {
        report_fail(name, "schemaVersion missing or not 2");
        cJSON_Delete(json);
        return;
    }
    cJSON *d = cJSON_GetObjectItemCaseSensitive(json, "description");
    if (!cJSON_IsString(d) || !d->valuestring || d->valuestring[0] == '\0') {
        report_fail(name, "description missing");
        cJSON_Delete(json);
        return;
    }
    cJSON_Delete(json);
    report_pass(name);
}

static void test_layer_schema_idempotent_reopen(const char *scratch)
{
    const char *name = "layer_schema_idempotent_reopen";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-layer-schema-idem", scratch);

    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    oci_store_close(s);

    char marker_path[2048];
    snprintf(marker_path, sizeof(marker_path), "%s/layers/.schema", root);
    struct stat before;
    char before_buf[4096];
    size_t before_len = 0;
    if (stat(marker_path, &before) != 0 ||
        !read_whole(marker_path, before_buf, sizeof(before_buf), &before_len)) {
        report_fail(name, "pre-reopen snapshot failed");
        return;
    }

    s = oci_store_open(root);
    if (!s) {
        report_fail(name, "reopen failed");
        return;
    }
    oci_store_close(s);

    struct stat after;
    char after_buf[4096];
    size_t after_len = 0;
    if (stat(marker_path, &after) != 0 ||
        !read_whole(marker_path, after_buf, sizeof(after_buf), &after_len)) {
        report_fail(name, "post-reopen snapshot failed");
        return;
    }
    if (before.st_ino != after.st_ino || before_len != after_len ||
        memcmp(before_buf, after_buf, before_len) != 0) {
        report_fail(name, "marker rewritten on reopen");
        return;
    }
    report_pass(name);
}

static void test_layer_schema_unknown_version_fail_fast(const char *scratch)
{
    const char *name = "layer_schema_unknown_version_fail_fast";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-layer-schema-unknown", scratch);

    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail(name, "open failed");
        return;
    }
    oci_store_close(s);

    char marker_path[2048];
    snprintf(marker_path, sizeof(marker_path), "%s/layers/.schema", root);
    int fd = open(marker_path, O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        report_fail(name, "open marker for rewrite failed");
        return;
    }
    static const char body[] = "{\"schemaVersion\":99}\n";
    size_t body_len = sizeof(body) - 1;
    if (write(fd, body, body_len) != (ssize_t) body_len) {
        close(fd);
        report_fail(name, "write forward marker failed");
        return;
    }
    close(fd);

    errno = 0;
    s = oci_store_open(root);
    if (s != NULL) {
        report_fail(name, "open did not fail on unknown schemaVersion");
        oci_store_close(s);
        return;
    }
    if (errno != EINVAL) {
        report_fail(name, "open errno != EINVAL on rejected schemaVersion");
        return;
    }

    /* The marker file itself must remain untouched on the rejection path. */
    char got[4096];
    size_t got_len = 0;
    if (!read_whole(marker_path, got, sizeof(got), &got_len) ||
        got_len != body_len || memcmp(got, body, got_len) != 0) {
        report_fail(name, "marker content modified by rejected open");
        return;
    }
    report_pass(name);
}

int main(void)
{
    printf("OCI store unit tests\n");
    char *scratch = make_scratch_root();
    if (!scratch) {
        fprintf(stderr, "could not create scratch dir: %s\n", strerror(errno));
        return 1;
    }

    test_open_creates_layout(scratch);
    test_put_get_round_trip(scratch);
    test_get_miss_enoent(scratch);
    test_digest_only_ref_rejected(scratch);
    test_malformed_digest_rejected(scratch);
    test_deep_repository(scratch);
    test_overwrite_pin(scratch);
    test_pin_blob_share_root(scratch);
    test_three_pins_schema(scratch);
    test_list_refs(scratch);
    test_concurrent_writers(scratch);
    test_layout_marker_fresh(scratch);
    test_layout_marker_added_on_existing(scratch);
    test_layout_marker_preserved(scratch);
    test_default_root_from_env();
    test_collect_empty(scratch);
    test_collect_single_pin(scratch);
    test_collect_shared_layer_dedups(scratch);
    test_collect_unpacked_tree(scratch);
    test_collect_pin_plus_unpacked(scratch);
    test_collect_origin_corrupt_fails(scratch);
    test_collect_missing_manifest_blob_fails(scratch);
    test_prune_dry_run_preserves_disk(scratch);
    test_prune_commit_unlinks_dangling(scratch);
    test_prune_no_pins_no_volume(scratch);
    test_prune_with_unpacked_tree(scratch);
    test_prune_collect_failure_aborts(scratch);
    test_prune_idempotent(scratch);
    test_prune_decoy_subdir_ignored(scratch);
    test_prune_invalid_args_rejected(scratch);
    test_prune_older_than_grace_window(scratch);
    test_prune_older_than_zero_disables(scratch);
    test_prune_keep_bytes_evicts_oldest_first(scratch);
    test_prune_keep_bytes_zero_is_unlimited(scratch);
    test_prune_combined_older_then_budget(scratch);
    test_prune_dry_run_with_filters_no_disk_touch(scratch);
    test_collect_layer_roots_empty_store(scratch);
    test_collect_layer_roots_single_pin_layer(scratch);
    test_collect_layer_roots_three_layer_prefix_chains(scratch);
    test_collect_layer_roots_unpacked_tree(scratch);
    test_collect_layer_roots_missing_config_blob_fails(scratch);
    test_prune_sweeps_dangling_layer_entry(scratch);
    test_prune_keeps_layer_referenced_by_pin(scratch);
    test_prune_keeps_layer_referenced_by_unpacked_tree(scratch);
    test_prune_sweeps_dangling_stack_entry(scratch);
    test_prune_keeps_stack_for_each_prefix_chain(scratch);
    test_prune_dry_run_keeps_layer_and_stack_on_disk(scratch);
    test_prune_layer_size_counted_in_pruned_bytes(scratch);
    test_prune_older_than_skips_fresh_layer_entry(scratch);
    test_prune_keep_bytes_evicts_oldest_layer_first(scratch);
    test_open_creates_layer_dirs(scratch);
    test_layer_resolve_format(scratch);
    test_layer_has_present_absent(scratch);
    test_layer_commit_rename_race_benign(scratch);
    test_stack_resolve_format(scratch);
    test_stack_has_present_absent(scratch);
    test_stack_stage_path_uniqueness(scratch);
    test_stack_commit_round_trip(scratch);
    test_stack_commit_rename_race_benign(scratch);
    test_layer_schema_written_on_fresh_open(scratch);
    test_layer_schema_idempotent_reopen(scratch);
    test_layer_schema_unknown_version_fail_fast(scratch);

    wipe_dir(scratch);
    free(scratch);

    printf("\n%s/%d store tests passed\n", passed == total ? GREEN : RED,
           total);
    printf("%d/%d\n" RESET, passed, total);
    return passed == total ? 0 : 1;
}
