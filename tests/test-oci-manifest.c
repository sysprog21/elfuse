/* OCI manifest / image-index / image-config parser unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Native macOS test (no HVF, no codesign). Exercises src/oci/manifest.c and
 * src/oci/media-type.c with inline JSON fixtures so the suite stays under
 * one file and the assertions are auditable from the source.
 *
 * Build: see mk/tests.mk target test-oci-manifest.
 * Run:   build/test-oci-manifest
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oci/manifest.h"
#include "oci/media-type.h"

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

#define CHECK(cond, name, detail)        \
    do {                                 \
        if (cond)                        \
            report_pass(name);           \
        else                             \
            report_fail(name, (detail)); \
    } while (0)

/* ── media-type module ─────────────────────────────────────────── */

static void test_media_type_recognized(void)
{
    struct {
        const char *in;
        oci_media_type_t want;
    } cases[] = {
        {"application/vnd.oci.image.manifest.v1+json", OCI_MT_MANIFEST_OCI},
        {"application/vnd.docker.distribution.manifest.v2+json",
         OCI_MT_MANIFEST_DOCKER},
        {"application/vnd.oci.image.index.v1+json", OCI_MT_INDEX_OCI},
        {"application/vnd.docker.distribution.manifest.list.v2+json",
         OCI_MT_INDEX_DOCKER},
        {"application/vnd.oci.image.config.v1+json", OCI_MT_CONFIG_OCI},
        {"application/vnd.docker.container.image.v1+json",
         OCI_MT_CONFIG_DOCKER},
        {"application/vnd.oci.image.layer.v1.tar", OCI_MT_LAYER_OCI_TAR},
        {"application/vnd.oci.image.layer.v1.tar+gzip",
         OCI_MT_LAYER_OCI_TAR_GZIP},
        {"application/vnd.oci.image.layer.v1.tar+zstd",
         OCI_MT_LAYER_OCI_TAR_ZSTD},
        {"application/vnd.docker.image.rootfs.diff.tar.gzip",
         OCI_MT_LAYER_DOCKER_TAR_GZIP},
        {"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
         OCI_MT_LAYER_FOREIGN_OCI_GZIP},
        /* RFC 6838: type/subtype tokens are case-insensitive, so a registry
         * that varies the casing must still resolve to the same kind.
         */
        {"Application/vnd.OCI.image.manifest.v1+JSON", OCI_MT_MANIFEST_OCI},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        oci_media_type_t got = oci_media_type_parse(cases[i].in);
        char name[256];
        snprintf(name, sizeof(name), "media_type parse: %s", cases[i].in);
        CHECK(got == cases[i].want, name, "wrong enum value");
    }
}

static void test_media_type_strip_params(void)
{
    /* charset / boundary parameters and whitespace must not defeat the
     * lookup; the registry sometimes annotates Content-Type with charset.
     */
    oci_media_type_t got = oci_media_type_parse(
        "  application/vnd.oci.image.manifest.v1+json ; charset=utf-8  ");
    CHECK(got == OCI_MT_MANIFEST_OCI, "media_type strips params + whitespace",
          "did not canonicalize");
}

static void test_media_type_unknown(void)
{
    CHECK(oci_media_type_parse(NULL) == OCI_MT_UNKNOWN,
          "media_type NULL -> UNKNOWN", "expected UNKNOWN");
    CHECK(oci_media_type_parse("") == OCI_MT_UNKNOWN,
          "media_type empty -> UNKNOWN", "expected UNKNOWN");
    CHECK(oci_media_type_parse("text/plain") == OCI_MT_UNKNOWN,
          "media_type bogus -> UNKNOWN", "expected UNKNOWN");
}

static void test_media_type_predicates(void)
{
    CHECK(oci_media_type_is_manifest(OCI_MT_MANIFEST_OCI),
          "predicate manifest OCI", NULL);
    CHECK(oci_media_type_is_manifest(OCI_MT_MANIFEST_DOCKER),
          "predicate manifest Docker", NULL);
    CHECK(!oci_media_type_is_manifest(OCI_MT_INDEX_OCI),
          "predicate manifest rejects index", NULL);

    CHECK(oci_media_type_is_index(OCI_MT_INDEX_OCI), "predicate index OCI",
          NULL);
    CHECK(oci_media_type_is_index(OCI_MT_INDEX_DOCKER),
          "predicate index Docker", NULL);

    CHECK(oci_media_type_is_config(OCI_MT_CONFIG_OCI), "predicate config OCI",
          NULL);
    CHECK(oci_media_type_is_layer(OCI_MT_LAYER_OCI_TAR_GZIP), "predicate layer",
          NULL);
    CHECK(oci_media_type_is_layer(OCI_MT_LAYER_FOREIGN_OCI_GZIP),
          "predicate layer includes foreign", NULL);
    CHECK(!oci_media_type_is_layer_supported(OCI_MT_LAYER_FOREIGN_OCI_GZIP),
          "predicate layer_supported excludes foreign", NULL);
    CHECK(oci_media_type_is_layer_supported(OCI_MT_LAYER_OCI_TAR_GZIP),
          "predicate layer_supported true for gzip", NULL);
    CHECK(oci_media_type_is_layer_supported(OCI_MT_LAYER_OCI_TAR_ZSTD),
          "predicate layer_supported true for zstd", NULL);
    CHECK(oci_media_type_is_foreign(OCI_MT_LAYER_FOREIGN_DOCKER_GZIP),
          "predicate foreign true for docker foreign gzip", NULL);
}

static void test_media_type_compression(void)
{
    CHECK(oci_media_type_compression(OCI_MT_LAYER_OCI_TAR_GZIP) ==
              OCI_COMPRESSION_GZIP,
          "compression gzip", NULL);
    CHECK(oci_media_type_compression(OCI_MT_LAYER_OCI_TAR_ZSTD) ==
              OCI_COMPRESSION_ZSTD,
          "compression zstd", NULL);
    CHECK(oci_media_type_compression(OCI_MT_LAYER_OCI_TAR) ==
              OCI_COMPRESSION_NONE,
          "compression none for uncompressed tar", NULL);
}

/* ── manifest parser ────────────────────────────────────────────── */

static const char OCI_MANIFEST_GOOD[] =
    "{"
    "  \"schemaVersion\": 2,"
    "  \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\","
    "  \"config\": {"
    "    \"mediaType\": \"application/vnd.oci.image.config.v1+json\","
    "    \"digest\": "
    "\"sha256:"
    "1f1fa1e4d3a92b2c5e1b7a90d6c7a8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f\","
    "    \"size\": 1234"
    "  },"
    "  \"layers\": ["
    "    {"
    "      \"mediaType\": \"application/vnd.oci.image.layer.v1.tar+gzip\","
    "      \"digest\": "
    "\"sha256:"
    "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd\","
    "      \"size\": 56789"
    "    },"
    "    {"
    "      \"mediaType\": \"application/vnd.oci.image.layer.v1.tar+zstd\","
    "      \"digest\": "
    "\"sha256:"
    "fedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedc\","
    "      \"size\": 1024"
    "    }"
    "  ]"
    "}";

static const char DOCKER_MANIFEST_GOOD[] =
    "{"
    "  \"schemaVersion\": 2,"
    "  \"mediaType\": "
    "\"application/vnd.docker.distribution.manifest.v2+json\","
    "  \"config\": {"
    "    \"mediaType\": \"application/vnd.docker.container.image.v1+json\","
    "    \"digest\": "
    "\"sha256:"
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\","
    "    \"size\": 4096"
    "  },"
    "  \"layers\": ["
    "    {"
    "      \"mediaType\": "
    "\"application/vnd.docker.image.rootfs.diff.tar.gzip\","
    "      \"digest\": "
    "\"sha256:"
    "0123456789012345678901234567890123456789012345678901234567890123\","
    "      \"size\": 99"
    "    }"
    "  ]"
    "}";

static void test_manifest_oci_happy(void)
{
    oci_manifest_t m;
    const char *err = NULL;
    int rc = oci_manifest_parse(OCI_MANIFEST_GOOD,
                                sizeof(OCI_MANIFEST_GOOD) - 1, &m, &err);
    if (rc != 0) {
        report_fail("manifest OCI happy", err ? err : "parse failed");
        return;
    }
    CHECK(m.schema_version == 2, "manifest OCI schemaVersion", NULL);
    CHECK(m.media_type == OCI_MT_MANIFEST_OCI, "manifest OCI mediaType", NULL);
    CHECK(m.config.media_type == OCI_MT_CONFIG_OCI,
          "manifest OCI config mediaType", NULL);
    CHECK(m.config.algo == OCI_DIGEST_SHA256, "manifest OCI config algo", NULL);
    CHECK(m.config.size == 1234, "manifest OCI config size", NULL);
    CHECK(m.nlayers == 2, "manifest OCI two layers", NULL);
    CHECK(m.layers[0].media_type == OCI_MT_LAYER_OCI_TAR_GZIP,
          "manifest OCI layer[0] gzip", NULL);
    CHECK(m.layers[1].media_type == OCI_MT_LAYER_OCI_TAR_ZSTD,
          "manifest OCI layer[1] zstd", NULL);
    CHECK(m.layers[0].size == 56789, "manifest OCI layer[0] size", NULL);
    oci_manifest_free(&m);
}

static void test_manifest_docker_happy(void)
{
    oci_manifest_t m;
    const char *err = NULL;
    int rc = oci_manifest_parse(DOCKER_MANIFEST_GOOD,
                                sizeof(DOCKER_MANIFEST_GOOD) - 1, &m, &err);
    if (rc != 0) {
        report_fail("manifest Docker happy", err ? err : "parse failed");
        return;
    }
    CHECK(m.media_type == OCI_MT_MANIFEST_DOCKER, "manifest Docker mediaType",
          NULL);
    CHECK(m.config.media_type == OCI_MT_CONFIG_DOCKER,
          "manifest Docker config mediaType", NULL);
    CHECK(m.nlayers == 1, "manifest Docker one layer", NULL);
    CHECK(m.layers[0].media_type == OCI_MT_LAYER_DOCKER_TAR_GZIP,
          "manifest Docker layer[0] gzip", NULL);
    oci_manifest_free(&m);
}

static void test_manifest_malformed_json(void)
{
    oci_manifest_t m;
    const char *err = NULL;
    const char bogus[] = "{ this is not json";
    int rc = oci_manifest_parse(bogus, sizeof(bogus) - 1, &m, &err);
    CHECK(rc == -1 && err != NULL, "manifest malformed JSON rejected",
          err ? err : "expected -1 with err");
}

static void test_manifest_wrong_schema(void)
{
    const char j[] =
        "{ \"schemaVersion\": 1,"
        "  \"config\": {"
        "    \"mediaType\": \"application/vnd.oci.image.config.v1+json\","
        "    \"digest\": "
        "\"sha256:"
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\","
        "    \"size\": 1 },"
        "  \"layers\": [] }";
    oci_manifest_t m;
    const char *err = NULL;
    int rc = oci_manifest_parse(j, sizeof(j) - 1, &m, &err);
    CHECK(rc == -1 && err != NULL, "manifest schemaVersion != 2 rejected", err);
}

static void test_manifest_fractional_schema(void)
{
    /* A fractional schemaVersion must not slip through: cJSON's valueint
     * would truncate 2.5 to 2 and pass the == 2 check without an integer
     * round-trip guard.
     */
    const char j[] =
        "{ \"schemaVersion\": 2.5,"
        "  \"config\": {"
        "    \"mediaType\": \"application/vnd.oci.image.config.v1+json\","
        "    \"digest\": "
        "\"sha256:"
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\","
        "    \"size\": 1 },"
        "  \"layers\": [] }";
    oci_manifest_t m;
    const char *err = NULL;
    int rc = oci_manifest_parse(j, sizeof(j) - 1, &m, &err);
    CHECK(rc == -1 && err != NULL, "manifest fractional schemaVersion rejected",
          err);
}

static void test_manifest_missing_config(void)
{
    const char j[] =
        "{ \"schemaVersion\": 2,"
        "  \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\","
        "  \"layers\": [] }";
    oci_manifest_t m;
    const char *err = NULL;
    int rc = oci_manifest_parse(j, sizeof(j) - 1, &m, &err);
    CHECK(rc == -1 && err != NULL, "manifest missing config rejected", err);
}

static void test_manifest_bad_digest(void)
{
    const char j[] =
        "{ \"schemaVersion\": 2,"
        "  \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\","
        "  \"config\": {"
        "    \"mediaType\": \"application/vnd.oci.image.config.v1+json\","
        "    \"digest\": \"sha256:DEADBEEF\","
        "    \"size\": 1 },"
        "  \"layers\": [] }";
    oci_manifest_t m;
    const char *err = NULL;
    int rc = oci_manifest_parse(j, sizeof(j) - 1, &m, &err);
    CHECK(rc == -1 && err != NULL, "manifest uppercase / short digest rejected",
          err);
}

static void test_manifest_negative_size(void)
{
    const char j[] =
        "{ \"schemaVersion\": 2,"
        "  \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\","
        "  \"config\": {"
        "    \"mediaType\": \"application/vnd.oci.image.config.v1+json\","
        "    \"digest\": "
        "\"sha256:"
        "abababababababababababababababababababababababababababababababab\","
        "    \"size\": -1 },"
        "  \"layers\": [] }";
    oci_manifest_t m;
    const char *err = NULL;
    int rc = oci_manifest_parse(j, sizeof(j) - 1, &m, &err);
    CHECK(rc == -1 && err != NULL, "manifest negative size rejected", err);
}

static void test_manifest_fractional_size(void)
{
    const char j[] =
        "{ \"schemaVersion\": 2,"
        "  \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\","
        "  \"config\": {"
        "    \"mediaType\": \"application/vnd.oci.image.config.v1+json\","
        "    \"digest\": "
        "\"sha256:"
        "abababababababababababababababababababababababababababababababab\","
        "    \"size\": 1.5 },"
        "  \"layers\": [] }";
    oci_manifest_t m;
    const char *err = NULL;
    int rc = oci_manifest_parse(j, sizeof(j) - 1, &m, &err);
    CHECK(rc == -1 && err != NULL, "manifest fractional size rejected", err);
}

static void test_manifest_foreign_layer_rejected(void)
{
    const char j[] =
        "{ \"schemaVersion\": 2,"
        "  \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\","
        "  \"config\": {"
        "    \"mediaType\": \"application/vnd.oci.image.config.v1+json\","
        "    \"digest\": "
        "\"sha256:"
        "1f1fa1e4d3a92b2c5e1b7a90d6c7a8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f\","
        "    \"size\": 1 },"
        "  \"layers\": [ {"
        "    \"mediaType\": "
        "\"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip\","
        "    \"digest\": "
        "\"sha256:"
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\","
        "    \"size\": 1 } ] }";
    oci_manifest_t m;
    const char *err = NULL;
    int rc = oci_manifest_parse(j, sizeof(j) - 1, &m, &err);
    CHECK(rc == -1 && err != NULL, "manifest foreign layer rejected", err);
}

static void test_manifest_wrong_config_mediatype(void)
{
    const char j[] =
        "{ \"schemaVersion\": 2,"
        "  \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\","
        "  \"config\": {"
        "    \"mediaType\": \"application/vnd.oci.image.layer.v1.tar+gzip\","
        "    \"digest\": "
        "\"sha256:"
        "1f1fa1e4d3a92b2c5e1b7a90d6c7a8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f\","
        "    \"size\": 1 },"
        "  \"layers\": [] }";
    oci_manifest_t m;
    const char *err = NULL;
    int rc = oci_manifest_parse(j, sizeof(j) - 1, &m, &err);
    CHECK(rc == -1 && err != NULL,
          "manifest config descriptor with non-config mediaType rejected", err);
}

/* ── index parser + platform selection ──────────────────────────── */

static const char OCI_INDEX_MULTIARCH[] =
    "{"
    "  \"schemaVersion\": 2,"
    "  \"mediaType\": \"application/vnd.oci.image.index.v1+json\","
    "  \"manifests\": ["
    "    {"
    "      \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\","
    "      \"digest\": "
    "\"sha256:"
    "1111111111111111111111111111111111111111111111111111111111111111\","
    "      \"size\": 100,"
    "      \"platform\": { \"architecture\": \"amd64\", \"os\": \"linux\" }"
    "    },"
    "    {"
    "      \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\","
    "      \"digest\": "
    "\"sha256:"
    "2222222222222222222222222222222222222222222222222222222222222222\","
    "      \"size\": 200,"
    "      \"platform\": { \"architecture\": \"arm64\", \"os\": \"linux\","
    "                       \"variant\": \"v8\" }"
    "    },"
    "    {"
    "      \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\","
    "      \"digest\": "
    "\"sha256:"
    "3333333333333333333333333333333333333333333333333333333333333333\","
    "      \"size\": 300,"
    "      \"platform\": { \"architecture\": \"ppc64le\", \"os\": \"linux\" }"
    "    }"
    "  ]"
    "}";

static void test_index_oci_pick_v8(void)
{
    oci_index_t idx;
    const char *err = NULL;
    int rc = oci_index_parse(OCI_INDEX_MULTIARCH,
                             sizeof(OCI_INDEX_MULTIARCH) - 1, &idx, &err);
    if (rc != 0) {
        report_fail("index OCI parse", err ? err : "parse failed");
        return;
    }
    CHECK(idx.nentries == 3, "index has three entries", NULL);
    const oci_index_entry_t *pick = oci_index_pick_linux_arm64(&idx);
    CHECK(pick != NULL, "index picks linux/arm64", NULL);
    if (pick) {
        CHECK(strcmp(pick->platform.architecture, "arm64") == 0,
              "picked arch arm64", NULL);
        CHECK(strcmp(pick->platform.variant, "v8") == 0,
              "picked variant v8 wins over no-variant", NULL);
    }
    oci_index_free(&idx);
}

/* When v8 is absent, the entry without an explicit variant is preferred. */
static const char OCI_INDEX_NO_V8[] =
    "{"
    "  \"schemaVersion\": 2,"
    "  \"mediaType\": \"application/vnd.oci.image.index.v1+json\","
    "  \"manifests\": ["
    "    {"
    "      \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\","
    "      \"digest\": "
    "\"sha256:"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
    "      \"size\": 100,"
    "      \"platform\": { \"architecture\": \"arm64\", \"os\": \"linux\","
    "                       \"variant\": \"v7\" }"
    "    },"
    "    {"
    "      \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\","
    "      \"digest\": "
    "\"sha256:"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
    "      \"size\": 200,"
    "      \"platform\": { \"architecture\": \"arm64\", \"os\": \"linux\" }"
    "    }"
    "  ]"
    "}";

static void test_index_oci_pick_empty_variant(void)
{
    oci_index_t idx;
    const char *err = NULL;
    int rc = oci_index_parse(OCI_INDEX_NO_V8, sizeof(OCI_INDEX_NO_V8) - 1, &idx,
                             &err);
    if (rc != 0) {
        report_fail("index parse no-v8", err ? err : "parse failed");
        return;
    }
    const oci_index_entry_t *pick = oci_index_pick_linux_arm64(&idx);
    CHECK(pick != NULL, "index picks linux/arm64 without v8", NULL);
    if (pick)
        CHECK(pick->platform.variant[0] == '\0',
              "no-variant entry wins over v7 when v8 absent", NULL);
    oci_index_free(&idx);
}

static const char OCI_INDEX_NO_LINUX_ARM64[] =
    "{"
    "  \"schemaVersion\": 2,"
    "  \"mediaType\": \"application/vnd.oci.image.index.v1+json\","
    "  \"manifests\": ["
    "    {"
    "      \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\","
    "      \"digest\": "
    "\"sha256:"
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\","
    "      \"size\": 100,"
    "      \"platform\": { \"architecture\": \"amd64\", \"os\": \"linux\" }"
    "    },"
    "    {"
    "      \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\","
    "      \"digest\": "
    "\"sha256:"
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\","
    "      \"size\": 200,"
    "      \"platform\": { \"architecture\": \"arm64\", \"os\": \"darwin\" }"
    "    }"
    "  ]"
    "}";

static void test_index_no_match_returns_null(void)
{
    oci_index_t idx;
    const char *err = NULL;
    int rc = oci_index_parse(OCI_INDEX_NO_LINUX_ARM64,
                             sizeof(OCI_INDEX_NO_LINUX_ARM64) - 1, &idx, &err);
    if (rc != 0) {
        report_fail("index parse no-linux-arm64", err ? err : "parse failed");
        return;
    }
    CHECK(oci_index_pick_linux_arm64(&idx) == NULL,
          "index returns NULL when no linux/arm64 entry exists", NULL);
    oci_index_free(&idx);
}

static const char DOCKER_INDEX_MULTIARCH[] =
    "{"
    "  \"schemaVersion\": 2,"
    "  \"mediaType\": "
    "\"application/vnd.docker.distribution.manifest.list.v2+json\","
    "  \"manifests\": ["
    "    {"
    "      \"mediaType\": "
    "\"application/vnd.docker.distribution.manifest.v2+json\","
    "      \"digest\": "
    "\"sha256:"
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\","
    "      \"size\": 200,"
    "      \"platform\": { \"architecture\": \"arm64\", \"os\": \"linux\","
    "                       \"variant\": \"v8\" }"
    "    }"
    "  ]"
    "}";

static void test_index_docker_happy(void)
{
    oci_index_t idx;
    const char *err = NULL;
    int rc = oci_index_parse(DOCKER_INDEX_MULTIARCH,
                             sizeof(DOCKER_INDEX_MULTIARCH) - 1, &idx, &err);
    if (rc != 0) {
        report_fail("index Docker parse", err ? err : "parse failed");
        return;
    }
    CHECK(idx.media_type == OCI_MT_INDEX_DOCKER, "index Docker mediaType",
          NULL);
    CHECK(idx.nentries == 1, "index Docker entry count", NULL);
    const oci_index_entry_t *pick = oci_index_pick_linux_arm64(&idx);
    CHECK(pick != NULL, "Docker index picks linux/arm64/v8", NULL);
    oci_index_free(&idx);
}

/* If the index's arm64 entry has an unknown manifest media type, the picker
 * skips it: the registry fetch path cannot consume the resulting manifest.
 */
static const char OCI_INDEX_BAD_ARM64_MEDIATYPE[] =
    "{"
    "  \"schemaVersion\": 2,"
    "  \"mediaType\": \"application/vnd.oci.image.index.v1+json\","
    "  \"manifests\": ["
    "    {"
    "      \"mediaType\": \"application/vnd.cncf.helm.config.v1+json\","
    "      \"digest\": "
    "\"sha256:"
    "1212121212121212121212121212121212121212121212121212121212121212\","
    "      \"size\": 50,"
    "      \"platform\": { \"architecture\": \"arm64\", \"os\": \"linux\" }"
    "    }"
    "  ]"
    "}";

static void test_index_skips_unknown_mediatype(void)
{
    oci_index_t idx;
    const char *err = NULL;
    int rc =
        oci_index_parse(OCI_INDEX_BAD_ARM64_MEDIATYPE,
                        sizeof(OCI_INDEX_BAD_ARM64_MEDIATYPE) - 1, &idx, &err);
    if (rc != 0) {
        report_fail("index unknown-mt parse", err ? err : "parse failed");
        return;
    }
    /* Parse must succeed (unknown media type is recorded, not rejected).
     * Picker skips the entry because it cannot be consumed.
     */
    CHECK(idx.nentries == 1,
          "index keeps unknown-mediaType entries during parse", NULL);
    CHECK(oci_index_pick_linux_arm64(&idx) == NULL,
          "picker skips unknown-mediaType arm64 entry", NULL);
    oci_index_free(&idx);
}

/* ── image config parser ────────────────────────────────────────── */

static const char OCI_IMAGE_CONFIG_GOOD[] =
    "{"
    "  \"created\": \"2026-01-02T03:04:05Z\","
    "  \"architecture\": \"arm64\","
    "  \"os\": \"linux\","
    "  \"variant\": \"v8\","
    "  \"config\": {"
    "    \"User\": \"1000:1000\","
    "    \"Env\": [\"PATH=/usr/bin\", \"FOO=bar\"],"
    "    \"Entrypoint\": [\"/bin/sh\"],"
    "    \"Cmd\": [\"-c\", \"echo ok\"],"
    "    \"WorkingDir\": \"/home/alice\""
    "  },"
    "  \"rootfs\": {"
    "    \"type\": \"layers\","
    "    \"diff_ids\": ["
    "      "
    "\"sha256:"
    "4444444444444444444444444444444444444444444444444444444444444444\","
    "      "
    "\"sha256:"
    "5555555555555555555555555555555555555555555555555555555555555555\""
    "    ]"
    "  }"
    "}";

static void test_image_config_happy(void)
{
    oci_image_config_t c;
    const char *err = NULL;
    int rc = oci_image_config_parse(
        OCI_IMAGE_CONFIG_GOOD, sizeof(OCI_IMAGE_CONFIG_GOOD) - 1, &c, &err);
    if (rc != 0) {
        report_fail("image config happy", err ? err : "parse failed");
        return;
    }
    CHECK(strcmp(c.architecture, "arm64") == 0, "image config architecture",
          NULL);
    CHECK(strcmp(c.os, "linux") == 0, "image config os", NULL);
    CHECK(c.variant && strcmp(c.variant, "v8") == 0, "image config variant",
          NULL);
    CHECK(c.config.user && strcmp(c.config.user, "1000:1000") == 0,
          "image config User", NULL);
    CHECK(c.config.working_dir &&
              strcmp(c.config.working_dir, "/home/alice") == 0,
          "image config WorkingDir", NULL);
    CHECK(c.config.env && c.config.env[0] &&
              strcmp(c.config.env[0], "PATH=/usr/bin") == 0,
          "image config Env[0]", NULL);
    CHECK(c.config.env && c.config.env[1] &&
              strcmp(c.config.env[1], "FOO=bar") == 0 && !c.config.env[2],
          "image config Env terminator", NULL);
    CHECK(c.config.entrypoint && c.config.entrypoint[0] &&
              strcmp(c.config.entrypoint[0], "/bin/sh") == 0 &&
              !c.config.entrypoint[1],
          "image config Entrypoint", NULL);
    CHECK(c.config.cmd && c.config.cmd[0] && c.config.cmd[1] &&
              strcmp(c.config.cmd[0], "-c") == 0 &&
              strcmp(c.config.cmd[1], "echo ok") == 0 && !c.config.cmd[2],
          "image config Cmd", NULL);
    CHECK(c.rootfs_diff_ids && c.rootfs_diff_ids[0] && c.rootfs_diff_ids[1] &&
              !c.rootfs_diff_ids[2],
          "image config two diff_ids", NULL);
    oci_image_config_free(&c);
}

static void test_image_config_missing_rootfs(void)
{
    const char j[] = "{ \"architecture\": \"arm64\", \"os\": \"linux\" }";
    oci_image_config_t c;
    const char *err = NULL;
    int rc = oci_image_config_parse(j, sizeof(j) - 1, &c, &err);
    CHECK(rc == -1 && err != NULL, "image config missing rootfs rejected", err);
}

static void test_image_config_bad_rootfs_type(void)
{
    const char j[] =
        "{ \"architecture\": \"arm64\", \"os\": \"linux\","
        "  \"rootfs\": { \"type\": \"snapshot\","
        "                \"diff_ids\": ["
        "                  \"sha256:"
        "4444444444444444444444444444444444444444444444444444444444444444\""
        "                ] } }";
    oci_image_config_t c;
    const char *err = NULL;
    int rc = oci_image_config_parse(j, sizeof(j) - 1, &c, &err);
    CHECK(rc == -1 && err != NULL,
          "image config non-layers rootfs.type rejected", err);
}

static void test_image_config_bad_diff_id(void)
{
    /* rootfs.diff_ids must be lowercase <algo>:<hex>. */
    const char j[] =
        "{ \"architecture\": \"arm64\", \"os\": \"linux\","
        "  \"rootfs\": { \"type\": \"layers\","
        "                \"diff_ids\": [\"sha256:NOTLOWER\"] } }";
    oci_image_config_t c;
    const char *err = NULL;
    int rc = oci_image_config_parse(j, sizeof(j) - 1, &c, &err);
    CHECK(rc == -1 && err != NULL, "image config bad diff_id rejected", err);
}

/* ── main ──────────────────────────────────────────────────────── */

int main(void)
{
    test_media_type_recognized();
    test_media_type_strip_params();
    test_media_type_unknown();
    test_media_type_predicates();
    test_media_type_compression();

    test_manifest_oci_happy();
    test_manifest_docker_happy();
    test_manifest_malformed_json();
    test_manifest_wrong_schema();
    test_manifest_fractional_schema();
    test_manifest_missing_config();
    test_manifest_bad_digest();
    test_manifest_negative_size();
    test_manifest_fractional_size();
    test_manifest_foreign_layer_rejected();
    test_manifest_wrong_config_mediatype();

    test_index_oci_pick_v8();
    test_index_oci_pick_empty_variant();
    test_index_no_match_returns_null();
    test_index_docker_happy();
    test_index_skips_unknown_mediatype();

    test_image_config_happy();
    test_image_config_missing_rootfs();
    test_image_config_bad_rootfs_type();
    test_image_config_bad_diff_id();

    printf("\n%d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
