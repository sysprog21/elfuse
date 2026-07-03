/* elfuse oci inspect renderer unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives oci_inspect against a pre-populated scratch store. The store is
 * built directly via oci_blob_store_put_bytes + oci_store_put_ref so the
 * cases stay independent of the slice 4 fetcher and the slice 5a pull
 * pipeline. open_memstream captures stdout and the assertions grep for
 * distinctive substrings (digest prefixes, section headers, "[arm64]" tag)
 * so output format tweaks do not cause spurious failures unless the
 * semantically-relevant fields disappear.
 *
 * Cases:
 *   1. Direct manifest pull + pin: config + layers section, layer count,
 *      runtime block (user, workingdir, entrypoint, cmd, env all populated)
 *   2. Index + arm64 picked: platform table with [arm64] tag, drill prints
 *      manifest layers
 *   3. Index + --all-platforms: every platform listed, no drill section
 *   4. Pin miss: "(no local manifest...)" on stdout, rc=0
 *   5. ref with digest, blob missing: "error: manifest blob ... not found",
 *      rc=-1 errno=ENOENT
 *   6. Index ok, sub-manifest blob missing: stdout contains the platform
 *      table, rc=-1 errno=ENOENT, err_msg identifies the missing blob
 *   7. Runtime block with Env=[]: explicit empty array renders as "env: []"
 *      while absent fields stay omitted
 */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oci/blob-store.h"
#include "oci/digest.h"
#include "oci/inspect.h"
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
    char tmpl[] = "/tmp/elfuse-test-oci-inspect-XXXXXX";
    if (!mkdtemp(tmpl))
        return NULL;
    return strdup(tmpl);
}

/* Drop the manifest body bytes that the slice 5a pull pipeline would
 * normally have written. Hashes them with SHA-256 so the digest stays
 * consistent with the bytes the store will serve back.
 */
static char *put_manifest_blob(oci_blob_store_t *blobs,
                               const char *body,
                               size_t body_len,
                               char *out_digest_str,
                               size_t out_cap,
                               char *out_hex)
{
    if (oci_digest_bytes(OCI_DIGEST_SHA256, body, body_len, out_hex) == 0) {
        fprintf(stderr, "hash failed\n");
        return NULL;
    }
    snprintf(out_digest_str, out_cap, "sha256:%s", out_hex);
    if (oci_blob_store_put_bytes(blobs, OCI_DIGEST_SHA256, out_hex, body,
                                 body_len) < 0) {
        fprintf(stderr, "blob put failed: %s\n", strerror(errno));
        return NULL;
    }
    return out_hex;
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
    *out_len = (size_t) n;
    return r;
}

/* Run oci_inspect and return the captured stdout bytes via *out_buf (caller
 * frees) plus the rc / saved errno / err_msg.
 */
typedef struct {
    int rc;
    int saved_errno;
    const char *err_msg;
    char *out;
    size_t out_len;
} inspect_result_t;

static void run_inspect(oci_store_t *store,
                        const oci_ref_t *ref,
                        const oci_inspect_options_t *base_opts,
                        inspect_result_t *result)
{
    memset(result, 0, sizeof(*result));
    char *buf = NULL;
    size_t cap = 0;
    FILE *fp = open_memstream(&buf, &cap);
    if (!fp) {
        result->rc = -1;
        result->saved_errno = errno;
        return;
    }
    oci_inspect_options_t opts =
        base_opts ? *base_opts : (oci_inspect_options_t) {0};
    opts.out = fp;
    const char *err = NULL;
    errno = 0;
    result->rc = oci_inspect(store, ref, &opts, &err);
    result->saved_errno = errno;
    result->err_msg = err;
    fflush(fp);
    fclose(fp);
    result->out = buf;
    result->out_len = cap;
}

static bool contains(const char *haystack, const char *needle)
{
    return haystack && needle && strstr(haystack, needle) != NULL;
}

/* ── Case 1: direct manifest ─────────────────────────────────────── */

static void case_direct_manifest(const char *scratch)
{
    const char *name = "inspect: direct manifest renders config + layers";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-direct", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    static const char LAYER1[] = "layer-one-bytes";
    static const char LAYER2[] = "layer-two-bytes-longer";
    char l1_hex[OCI_DIGEST_HEX_MAX + 1];
    char l2_hex[OCI_DIGEST_HEX_MAX + 1];
    char l1_digest[OCI_DIGEST_HEX_MAX + 16];
    char l2_digest[OCI_DIGEST_HEX_MAX + 16];
    put_manifest_blob(blobs, LAYER1, sizeof(LAYER1) - 1, l1_digest,
                      sizeof(l1_digest), l1_hex);
    put_manifest_blob(blobs, LAYER2, sizeof(LAYER2) - 1, l2_digest,
                      sizeof(l2_digest), l2_hex);

    /* Full image-config so inspect's runtime block finds a parseable
     * blob alongside the manifest. The five runtime fields
     * (User, WorkingDir, Entrypoint, Cmd, Env) are all populated; rootfs is
     * the minimum the parser accepts. The diff_id digest is a synthetic
     * 64-hex-char value so oci_digest_parse validates it.
     */
    static const char CONFIG[] =
        "{\"architecture\":\"arm64\",\"os\":\"linux\","
        "\"config\":{"
        "\"User\":\"1000:1000\","
        "\"WorkingDir\":\"/home/app\","
        "\"Entrypoint\":[\"/entrypoint.sh\"],"
        "\"Cmd\":[\"python\",\"main.py\"],"
        "\"Env\":[\"PATH=/usr/local/bin:/usr/bin:/bin\","
        "\"HOME=/home/app\"]},"
        "\"rootfs\":{\"type\":\"layers\",\"diff_ids\":["
        "\"sha256:00000000000000000000000000000000000000000000000000000000"
        "00000001\"]}}";
    char cfg_hex[OCI_DIGEST_HEX_MAX + 1];
    char cfg_digest[OCI_DIGEST_HEX_MAX + 16];
    put_manifest_blob(blobs, CONFIG, sizeof(CONFIG) - 1, cfg_digest,
                      sizeof(cfg_digest), cfg_hex);

    size_t mlen = 0;
    char *manifest = vformat(
        &mlen,
        "{\"schemaVersion\":2,"
        "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"config\":{"
        "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
        "\"digest\":\"%s\",\"size\":%zu},"
        "\"layers\":["
        "{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\","
        "\"digest\":\"%s\",\"size\":%zu},"
        "{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\","
        "\"digest\":\"%s\",\"size\":%zu}]}",
        cfg_digest, sizeof(CONFIG) - 1, l1_digest, sizeof(LAYER1) - 1,
        l2_digest, sizeof(LAYER2) - 1);

    char m_hex[OCI_DIGEST_HEX_MAX + 1];
    char m_digest[OCI_DIGEST_HEX_MAX + 16];
    put_manifest_blob(blobs, manifest, mlen, m_digest, sizeof(m_digest), m_hex);

    oci_ref_t ref = {0};
    const char *parse_err = NULL;
    oci_ref_parse("alpine:3.20", &ref, &parse_err);
    oci_store_put_ref(store, &ref, m_digest, NULL);

    inspect_result_t r;
    run_inspect(store, &ref, NULL, &r);

    if (r.rc != 0) {
        report_fail(name, "rc=%d errno=%d err=%s", r.rc, r.saved_errno,
                    r.err_msg ? r.err_msg : "(none)");
    } else if (!contains(r.out, "pinned:")) {
        report_fail(name, "missing pinned line");
    } else if (!contains(r.out, m_digest)) {
        report_fail(name, "missing manifest digest in output");
    } else if (!contains(r.out, "type:       image manifest")) {
        report_fail(name, "missing type line");
    } else if (!contains(r.out, "config:")) {
        report_fail(name, "missing config line");
    } else if (!contains(r.out, "layers:")) {
        report_fail(name, "missing layers section");
    } else if (!contains(r.out, "[0]")) {
        report_fail(name, "missing layer index [0]");
    } else if (!contains(r.out, "[1]")) {
        report_fail(name, "missing layer index [1]");
    } else if (contains(r.out, "[2]")) {
        report_fail(name, "unexpected layer index [2]");
    } else if (!contains(r.out, "runtime:")) {
        report_fail(name, "missing runtime section header");
    } else if (!contains(r.out, "user:        1000:1000")) {
        report_fail(name, "runtime user line missing or misaligned");
    } else if (!contains(r.out, "workingdir:  /home/app")) {
        report_fail(name, "runtime workingdir line missing or misaligned");
    } else if (!contains(r.out, "entrypoint:  [\"/entrypoint.sh\"]")) {
        report_fail(name, "runtime entrypoint not JSON-array quoted");
    } else if (!contains(r.out, "cmd:         [\"python\", \"main.py\"]")) {
        report_fail(name, "runtime cmd not JSON-array quoted with comma+space");
    } else if (!contains(r.out, "env:         PATH=/usr/local/bin")) {
        report_fail(name, "runtime env first line missing PATH");
    } else if (!contains(r.out, "               HOME=/home/app")) {
        report_fail(name,
                    "runtime env continuation line missing HOME or"
                    " misindented");
    } else {
        report_pass(name);
    }

    free(r.out);
    free(manifest);
    oci_ref_free(&ref);
    oci_store_close(store);
}

/* ── Helpers for index-based cases ───────────────────────────────── */

/* Three-platform index where linux/arm64/v8 references manifest_digest. The
 * other two entries point at digests the test never stores; the renderer does
 * not need them for the default-mode drill.
 */
static char *build_index_three_platforms(size_t *out_len,
                                         const char *arm64_digest,
                                         size_t arm64_size)
{
    return vformat(
        out_len,
        "{\"schemaVersion\":2,"
        "\"mediaType\":\"application/vnd.oci.image.index.v1+json\","
        "\"manifests\":["
        "{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"digest\":\"sha256:"
        "1111111111111111111111111111111111111111111111111111111111111111\","
        "\"size\":1024,"
        "\"platform\":{\"architecture\":\"amd64\",\"os\":\"linux\"}},"
        "{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"digest\":\"%s\",\"size\":%zu,"
        "\"platform\":{\"architecture\":\"arm64\",\"os\":\"linux\","
        "\"variant\":\"v8\"}},"
        "{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"digest\":\"sha256:"
        "3333333333333333333333333333333333333333333333333333333333333333\","
        "\"size\":1024,"
        "\"platform\":{\"architecture\":\"s390x\",\"os\":\"linux\"}}]}",
        arm64_digest, arm64_size);
}

/* Build a minimal manifest body and persist it. Returns the manifest digest
 * string (heap, caller frees) for the index to reference.
 */
static char *build_and_store_manifest(oci_blob_store_t *blobs, size_t *out_len)
{
    static const char BODY[] =
        "{\"schemaVersion\":2,"
        "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"config\":{"
        "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
        "\"digest\":\"sha256:00000000000000000000000000000000000000000000"
        "00000000000000000000\",\"size\":1},"
        "\"layers\":["
        "{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\","
        "\"digest\":\"sha256:00000000000000000000000000000000000000000000"
        "00000000000000000001\",\"size\":2},"
        "{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\","
        "\"digest\":\"sha256:00000000000000000000000000000000000000000000"
        "00000000000000000002\",\"size\":3}]}";
    size_t len = sizeof(BODY) - 1;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    char digest[OCI_DIGEST_HEX_MAX + 16];
    if (!put_manifest_blob(blobs, BODY, len, digest, sizeof(digest), hex))
        return NULL;
    *out_len = len;
    return strdup(digest);
}

/* ── Case 2: index drills arm64 ──────────────────────────────────── */

static void case_index_default_drills_arm64(const char *scratch)
{
    const char *name = "inspect: index drills linux/arm64 manifest";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-idx-default", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    size_t m_len = 0;
    char *m_digest = build_and_store_manifest(blobs, &m_len);

    size_t idx_len = 0;
    char *idx_body = build_index_three_platforms(&idx_len, m_digest, m_len);
    char idx_hex[OCI_DIGEST_HEX_MAX + 1];
    char idx_digest[OCI_DIGEST_HEX_MAX + 16];
    put_manifest_blob(blobs, idx_body, idx_len, idx_digest, sizeof(idx_digest),
                      idx_hex);

    oci_ref_t ref = {0};
    const char *parse_err = NULL;
    oci_ref_parse("alpine:3.20", &ref, &parse_err);
    oci_store_put_ref(store, &ref, idx_digest, NULL);

    inspect_result_t r;
    run_inspect(store, &ref, NULL, &r);

    if (r.rc != 0) {
        report_fail(name, "rc=%d errno=%d err=%s", r.rc, r.saved_errno,
                    r.err_msg ? r.err_msg : "(none)");
    } else if (!contains(r.out, "type:       image index")) {
        report_fail(name, "missing type=index line");
    } else if (!contains(r.out, "platforms:")) {
        report_fail(name, "missing platforms section");
    } else if (!contains(r.out, "[arm64]")) {
        report_fail(name, "missing [arm64] tag");
    } else if (!contains(r.out, "linux/arm64/v8")) {
        report_fail(name, "missing linux/arm64/v8 platform string");
    } else if (contains(r.out, "linux/amd64")) {
        report_fail(name, "amd64 listed in default mode (should be hidden)");
    } else if (!contains(r.out, "manifest:")) {
        report_fail(name, "missing drill manifest section");
    } else if (!contains(r.out, "config:")) {
        report_fail(name, "missing config line from drill");
    } else if (!contains(r.out, "layers:")) {
        report_fail(name, "missing layers section from drill");
    } else {
        report_pass(name);
    }

    free(r.out);
    free(m_digest);
    free(idx_body);
    oci_ref_free(&ref);
    oci_store_close(store);
}

/* ── Case 3: index --all-platforms ───────────────────────────────── */

static void case_index_all_platforms(const char *scratch)
{
    const char *name = "inspect: --all-platforms lists every entry, no drill";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-idx-all", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    size_t m_len = 0;
    char *m_digest = build_and_store_manifest(blobs, &m_len);
    size_t idx_len = 0;
    char *idx_body = build_index_three_platforms(&idx_len, m_digest, m_len);
    char idx_hex[OCI_DIGEST_HEX_MAX + 1];
    char idx_digest[OCI_DIGEST_HEX_MAX + 16];
    put_manifest_blob(blobs, idx_body, idx_len, idx_digest, sizeof(idx_digest),
                      idx_hex);

    oci_ref_t ref = {0};
    const char *parse_err = NULL;
    oci_ref_parse("alpine:3.20", &ref, &parse_err);
    oci_store_put_ref(store, &ref, idx_digest, NULL);

    oci_inspect_options_t opts = {.show_all_platforms = true};
    inspect_result_t r;
    run_inspect(store, &ref, &opts, &r);

    if (r.rc != 0) {
        report_fail(name, "rc=%d errno=%d err=%s", r.rc, r.saved_errno,
                    r.err_msg ? r.err_msg : "(none)");
    } else if (!contains(r.out, "linux/amd64")) {
        report_fail(name, "missing linux/amd64 entry");
    } else if (!contains(r.out, "linux/arm64/v8")) {
        report_fail(name, "missing linux/arm64/v8 entry");
    } else if (!contains(r.out, "linux/s390x")) {
        report_fail(name, "missing linux/s390x entry");
    } else if (!contains(r.out, "[arm64]")) {
        report_fail(name, "missing [arm64] tag");
    } else if (contains(r.out, "manifest:")) {
        /* The drill section starts with "manifest:". --all-platforms must
         * not include it.
         */
        report_fail(name, "drill section unexpectedly present");
    } else {
        report_pass(name);
    }

    free(r.out);
    free(m_digest);
    free(idx_body);
    oci_ref_free(&ref);
    oci_store_close(store);
}

/* ── Case 4: pin miss ────────────────────────────────────────────── */

static void case_pin_miss(const char *scratch)
{
    const char *name = "inspect: pin miss prints informational line, rc=0";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-miss", scratch);
    oci_store_t *store = oci_store_open(root);

    oci_ref_t ref = {0};
    const char *parse_err = NULL;
    oci_ref_parse("alpine:never-pulled", &ref, &parse_err);

    inspect_result_t r;
    run_inspect(store, &ref, NULL, &r);

    if (r.rc != 0) {
        report_fail(name, "rc=%d (expected 0)", r.rc);
    } else if (!contains(r.out, "(no local manifest")) {
        report_fail(name, "missing informational text");
    } else {
        report_pass(name);
    }

    free(r.out);
    oci_ref_free(&ref);
    oci_store_close(store);
}

/* ── Case 5: digest ref but blob missing ─────────────────────────── */

static void case_digest_blob_missing(const char *scratch)
{
    const char *name = "inspect: digest ref with missing blob errors out";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-digest-missing", scratch);
    oci_store_t *store = oci_store_open(root);

    /* Use a synthetic digest that the store has never seen. */
    oci_ref_t ref = {0};
    const char *parse_err = NULL;
    oci_ref_parse(
        "alpine@sha256:00000000000000000000000000000000000000000000000000000000"
        "00000000",
        &ref, &parse_err);

    inspect_result_t r;
    run_inspect(store, &ref, NULL, &r);

    if (r.rc != -1) {
        report_fail(name, "rc=%d (expected -1)", r.rc);
    } else if (r.saved_errno != ENOENT) {
        report_fail(name, "errno=%d (expected ENOENT)", r.saved_errno);
    } else if (!contains(r.out, "error: manifest blob")) {
        report_fail(name, "missing error line on stdout");
    } else if (!contains(r.out, "(digest reference)")) {
        report_fail(name, "missing digest reference annotation");
    } else {
        report_pass(name);
    }

    free(r.out);
    oci_ref_free(&ref);
    oci_store_close(store);
}

/* ── Case 6: index ok, sub-manifest missing ──────────────────────── */

static void case_sub_manifest_missing(const char *scratch)
{
    const char *name =
        "inspect: index ok but sub-manifest blob missing -> rc=-1, table"
        " still shown";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-sub-missing", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    /* Reference a manifest digest that is NOT in the store. */
    static const char ABSENT[] =
        "sha256:dead00000000000000000000000000000000000000000000000000000000be"
        "ef";
    size_t idx_len = 0;
    char *idx_body = build_index_three_platforms(&idx_len, ABSENT, 1024);
    char idx_hex[OCI_DIGEST_HEX_MAX + 1];
    char idx_digest[OCI_DIGEST_HEX_MAX + 16];
    put_manifest_blob(blobs, idx_body, idx_len, idx_digest, sizeof(idx_digest),
                      idx_hex);

    oci_ref_t ref = {0};
    const char *parse_err = NULL;
    oci_ref_parse("alpine:3.20", &ref, &parse_err);
    oci_store_put_ref(store, &ref, idx_digest, NULL);

    /* Redirect stderr to /dev/null so the warning line does not pollute the
     * test driver output. The function under test still writes the warning;
     * scripts key on rc + errno.
     */
    int saved_stderr = dup(STDERR_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    }

    inspect_result_t r;
    run_inspect(store, &ref, NULL, &r);

    if (saved_stderr >= 0) {
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }

    if (r.rc != -1) {
        report_fail(name, "rc=%d (expected -1)", r.rc);
    } else if (r.saved_errno != ENOENT) {
        report_fail(name, "errno=%d (expected ENOENT)", r.saved_errno);
    } else if (!contains(r.out, "platforms:")) {
        report_fail(name, "platform table not on stdout");
    } else if (!contains(r.out, "[arm64]")) {
        report_fail(name, "[arm64] tag missing");
    } else if (!r.err_msg ||
               !contains(r.err_msg, "indexed manifest blob missing")) {
        report_fail(name, "err_msg unexpected: %s",
                    r.err_msg ? r.err_msg : "(null)");
    } else {
        report_pass(name);
    }

    free(r.out);
    free(idx_body);
    oci_ref_free(&ref);
    oci_store_close(store);
}

/* Case 7: runtime block with Env=[] -------------------------------- */

static void case_runtime_empty_env(const char *scratch)
{
    const char *name =
        "inspect: runtime block renders empty Env as [] and omits absent"
        " bullets";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-runtime-empty-env", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    static const char LAYER[] = "single-layer-bytes";
    char l_hex[OCI_DIGEST_HEX_MAX + 1];
    char l_digest[OCI_DIGEST_HEX_MAX + 16];
    put_manifest_blob(blobs, LAYER, sizeof(LAYER) - 1, l_digest,
                      sizeof(l_digest), l_hex);

    /* Env present but explicitly empty; User and WorkingDir omitted entirely
     * so the renderer must skip their bullets. Cmd populated so the runtime
     * section still has structural content beyond the empty Env line.
     */
    static const char CONFIG[] =
        "{\"architecture\":\"arm64\",\"os\":\"linux\","
        "\"config\":{"
        "\"Cmd\":[\"/bin/echo\",\"hi\"],"
        "\"Env\":[]},"
        "\"rootfs\":{\"type\":\"layers\",\"diff_ids\":["
        "\"sha256:00000000000000000000000000000000000000000000000000000000"
        "00000002\"]}}";
    char cfg_hex[OCI_DIGEST_HEX_MAX + 1];
    char cfg_digest[OCI_DIGEST_HEX_MAX + 16];
    put_manifest_blob(blobs, CONFIG, sizeof(CONFIG) - 1, cfg_digest,
                      sizeof(cfg_digest), cfg_hex);

    size_t mlen = 0;
    char *manifest = vformat(
        &mlen,
        "{\"schemaVersion\":2,"
        "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"config\":{"
        "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
        "\"digest\":\"%s\",\"size\":%zu},"
        "\"layers\":["
        "{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\","
        "\"digest\":\"%s\",\"size\":%zu}]}",
        cfg_digest, sizeof(CONFIG) - 1, l_digest, sizeof(LAYER) - 1);

    char m_hex[OCI_DIGEST_HEX_MAX + 1];
    char m_digest[OCI_DIGEST_HEX_MAX + 16];
    put_manifest_blob(blobs, manifest, mlen, m_digest, sizeof(m_digest), m_hex);

    oci_ref_t ref = {0};
    const char *parse_err = NULL;
    oci_ref_parse("scratch:empty-env", &ref, &parse_err);
    oci_store_put_ref(store, &ref, m_digest, NULL);

    inspect_result_t r;
    run_inspect(store, &ref, NULL, &r);

    if (r.rc != 0) {
        report_fail(name, "rc=%d errno=%d err=%s", r.rc, r.saved_errno,
                    r.err_msg ? r.err_msg : "(none)");
    } else if (!contains(r.out, "runtime:")) {
        report_fail(name, "missing runtime section");
    } else if (contains(r.out, "user:")) {
        report_fail(name, "absent User must not render a bullet");
    } else if (contains(r.out, "workingdir:")) {
        report_fail(name, "absent WorkingDir must not render a bullet");
    } else if (contains(r.out, "entrypoint:")) {
        report_fail(name, "absent Entrypoint must not render a bullet");
    } else if (!contains(r.out, "cmd:         [\"/bin/echo\", \"hi\"]")) {
        report_fail(name, "Cmd line missing or not JSON-array quoted");
    } else if (!contains(r.out, "env:         []")) {
        report_fail(name, "empty Env must render as []");
    } else {
        report_pass(name);
    }

    free(r.out);
    free(manifest);
    oci_ref_free(&ref);
    oci_store_close(store);
}

/* Layer-reuse fixtures -------------------------------------------------- */

/* Compose an image-config blob carrying the given NULL-terminated diff_id
 * list. The runtime block is intentionally empty so the runtime section
 * does not appear in inspect output; that keeps the layer reuse assertions
 * independent of runtime rendering details.
 */
static char *put_reuse_config(oci_blob_store_t *blobs,
                              char *const *diff_ids,
                              size_t *out_len)
{
    char *diffs = strdup("");
    if (!diffs)
        return NULL;
    for (size_t i = 0; diff_ids[i]; i++) {
        size_t need = strlen(diffs) + strlen(diff_ids[i]) + 8;
        char *grown = malloc(need);
        if (!grown) {
            free(diffs);
            return NULL;
        }
        snprintf(grown, need, "%s%s\"%s\"", diffs, i == 0 ? "" : ",",
                 diff_ids[i]);
        free(diffs);
        diffs = grown;
    }
    size_t body_len = 0;
    char *body = vformat(&body_len,
                         "{\"architecture\":\"arm64\",\"os\":\"linux\","
                         "\"config\":{},\"rootfs\":{\"type\":\"layers\","
                         "\"diff_ids\":[%s]}}",
                         diffs);
    free(diffs);
    if (!body)
        return NULL;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (oci_digest_bytes(OCI_DIGEST_SHA256, body, body_len, hex) == 0) {
        free(body);
        return NULL;
    }
    if (oci_blob_store_put_bytes(blobs, OCI_DIGEST_SHA256, hex, body,
                                 body_len) < 0) {
        free(body);
        return NULL;
    }
    char *digest = malloc(OCI_DIGEST_HEX_MAX + 16);
    if (!digest) {
        free(body);
        return NULL;
    }
    snprintf(digest, OCI_DIGEST_HEX_MAX + 16, "sha256:%s", hex);
    if (out_len)
        *out_len = body_len;
    free(body);
    return digest;
}

/* Compose a single-layer image-manifest pointing at config_digest. The
 * layer descriptor digest is synthetic ("sha256:11...1") because the
 * dedup walker only reads the config blob. */
static char *put_reuse_manifest(oci_blob_store_t *blobs,
                                const char *config_digest)
{
    static const char LAYER_DIGEST[] =
        "sha256:11111111111111111111111111111111111111111111111111111111"
        "11111111";
    size_t body_len = 0;
    char *body =
        vformat(&body_len,
                "{\"schemaVersion\":2,"
                "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
                "\"config\":{\"mediaType\":\"application/"
                "vnd.oci.image.config.v1+json\","
                "\"digest\":\"%s\",\"size\":1},"
                "\"layers\":[{\"mediaType\":"
                "\"application/vnd.oci.image.layer.v1.tar+gzip\","
                "\"digest\":\"%s\",\"size\":1}]}",
                config_digest, LAYER_DIGEST);
    if (!body)
        return NULL;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    char *digest = malloc(OCI_DIGEST_HEX_MAX + 16);
    if (!digest) {
        free(body);
        return NULL;
    }
    if (!put_manifest_blob(blobs, body, body_len, digest,
                           OCI_DIGEST_HEX_MAX + 16, hex)) {
        free(body);
        free(digest);
        return NULL;
    }
    free(body);
    return digest;
}

static char *diff_id_n_reuse(int id)
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

static bool pin_helper(oci_store_t *store,
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

/* Case 8: two pinned images share layers -> reuse section renders ----- */

static void case_layer_reuse_shared_section_renders(const char *scratch)
{
    const char *name =
        "inspect: layer reuse section renders shared/total/compared";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-reuse-shared", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n_reuse(1);
    char *d2 = diff_id_n_reuse(2);
    char *d3 = diff_id_n_reuse(3);
    char *d4 = diff_id_n_reuse(4);

    char *target_diffs[] = {d1, d2, d3, NULL};
    char *target_cfg = put_reuse_config(blobs, target_diffs, NULL);
    char *target_mf = put_reuse_manifest(blobs, target_cfg);

    char *other_diffs[] = {d1, d2, d4, NULL};
    char *other_cfg = put_reuse_config(blobs, other_diffs, NULL);
    char *other_mf = put_reuse_manifest(blobs, other_cfg);

    pin_helper(store, "scratch:target", target_mf);
    pin_helper(store, "scratch:other", other_mf);

    oci_ref_t ref = {0};
    oci_ref_parse("scratch:target", &ref, NULL);
    inspect_result_t r;
    run_inspect(store, &ref, NULL, &r);

    if (r.rc != 0) {
        report_fail(name, "rc=%d", r.rc);
    } else if (!contains(r.out, "layer reuse:")) {
        report_fail(name, "missing layer reuse section header");
    } else if (!contains(
                   r.out,
                   "raw cache:   2/3 layers shared with 1 other image(s)")) {
        report_fail(name, "raw cache line shape mismatch (got: %s)", r.out);
    } else if (!contains(r.out,
                         "stack cache: deepest shared prefix reaches"
                         " layer 2/3")) {
        report_fail(name, "stack cache line shape mismatch");
    } else {
        report_pass(name);
    }

    free(r.out);
    free(d1);
    free(d2);
    free(d3);
    free(d4);
    free(target_cfg);
    free(target_mf);
    free(other_cfg);
    free(other_mf);
    oci_ref_free(&ref);
    oci_store_close(store);
}

/* Case 9: two pinned images, disjoint diff_ids -> zero shared --------- */

static void case_layer_reuse_zero_shared(const char *scratch)
{
    const char *name = "inspect: zero overlap renders 0/N with no prefix";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-reuse-zero", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n_reuse(1);
    char *d2 = diff_id_n_reuse(2);
    char *d5 = diff_id_n_reuse(5);
    char *d6 = diff_id_n_reuse(6);

    char *target_diffs[] = {d1, d2, NULL};
    char *target_cfg = put_reuse_config(blobs, target_diffs, NULL);
    char *target_mf = put_reuse_manifest(blobs, target_cfg);

    char *other_diffs[] = {d5, d6, NULL};
    char *other_cfg = put_reuse_config(blobs, other_diffs, NULL);
    char *other_mf = put_reuse_manifest(blobs, other_cfg);

    pin_helper(store, "scratch:target", target_mf);
    pin_helper(store, "scratch:other", other_mf);

    oci_ref_t ref = {0};
    oci_ref_parse("scratch:target", &ref, NULL);
    inspect_result_t r;
    run_inspect(store, &ref, NULL, &r);

    if (r.rc != 0) {
        report_fail(name, "rc=%d", r.rc);
    } else if (!contains(
                   r.out,
                   "raw cache:   0/2 layers shared with 1 other image(s)")) {
        report_fail(name, "raw cache zero-shared shape mismatch");
    } else if (!contains(r.out, "stack cache: no shared prefix")) {
        report_fail(name, "missing no-shared-prefix line");
    } else {
        report_pass(name);
    }

    free(r.out);
    free(d1);
    free(d2);
    free(d5);
    free(d6);
    free(target_cfg);
    free(target_mf);
    free(other_cfg);
    free(other_mf);
    oci_ref_free(&ref);
    oci_store_close(store);
}

/* Case 10: only one image in the store -> "no other images to compare" */

static void case_layer_reuse_single_image_in_store(const char *scratch)
{
    const char *name =
        "inspect: single pinned image renders no-others sentinel";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-reuse-single", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n_reuse(1);
    char *diffs[] = {d1, NULL};
    char *cfg = put_reuse_config(blobs, diffs, NULL);
    char *mf = put_reuse_manifest(blobs, cfg);
    pin_helper(store, "scratch:lonely", mf);

    oci_ref_t ref = {0};
    oci_ref_parse("scratch:lonely", &ref, NULL);
    inspect_result_t r;
    run_inspect(store, &ref, NULL, &r);

    if (r.rc != 0) {
        report_fail(name, "rc=%d", r.rc);
    } else if (!contains(r.out, "layer reuse: (no other images to compare)")) {
        report_fail(name, "missing no-others sentinel");
    } else {
        report_pass(name);
    }

    free(r.out);
    free(d1);
    free(cfg);
    free(mf);
    oci_ref_free(&ref);
    oci_store_close(store);
}

/* Case 11: target's image-config blob missing -> degrade gracefully --- */

static void case_layer_reuse_config_missing_degrades(const char *scratch)
{
    const char *name =
        "inspect: target image-config blob missing -> degrade sentinel";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-reuse-cfg-missing", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n_reuse(1);
    char *diffs[] = {d1, NULL};
    char *cfg = put_reuse_config(blobs, diffs, NULL);
    char *mf = put_reuse_manifest(blobs, cfg);
    pin_helper(store, "scratch:degrade", mf);

    /* Unlink the config blob so the dedup walker hits ENOENT on the
     * target's config read. inspect itself still renders the manifest
     * tree because try_render_runtime degrades silently.
     */
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    oci_digest_parse(cfg, &algo, hex);
    char blob_path[1024];
    snprintf(blob_path, sizeof(blob_path), "%s/blobs/sha256/%s", root, hex);
    unlink(blob_path);

    oci_ref_t ref = {0};
    oci_ref_parse("scratch:degrade", &ref, NULL);
    inspect_result_t r;
    run_inspect(store, &ref, NULL, &r);

    if (r.rc != 0) {
        report_fail(name, "rc=%d (expected 0 even on degrade)", r.rc);
    } else if (!contains(r.out, "layer reuse: (image-config unavailable)")) {
        report_fail(name, "missing degrade sentinel");
    } else if (!contains(r.out, "layers:")) {
        report_fail(name, "manifest tree should still render");
    } else {
        report_pass(name);
    }

    free(r.out);
    free(d1);
    free(cfg);
    free(mf);
    oci_ref_free(&ref);
    oci_store_close(store);
}

/* Case 12: --all-platforms suppresses the reuse section --------------- */

static void case_layer_reuse_all_platforms_skips_section(const char *scratch)
{
    const char *name =
        "inspect: --all-platforms on image index suppresses reuse section";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-reuse-all-platforms", scratch);
    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    /* Build the same fixture case 3 uses, but assert absence of the
     * layer reuse section. The drill is skipped under --all-platforms, so
     * there is no manifest to feed the dedup walker.
     */
    size_t m_len = 0;
    char *m_digest = build_and_store_manifest(blobs, &m_len);
    size_t idx_len = 0;
    char *idx_body = build_index_three_platforms(&idx_len, m_digest, m_len);
    char idx_hex[OCI_DIGEST_HEX_MAX + 1];
    char idx_digest[OCI_DIGEST_HEX_MAX + 16];
    put_manifest_blob(blobs, idx_body, idx_len, idx_digest, sizeof(idx_digest),
                      idx_hex);

    oci_ref_t ref = {0};
    oci_ref_parse("alpine:3.20", &ref, NULL);
    oci_store_put_ref(store, &ref, idx_digest, NULL);

    oci_inspect_options_t opts = {.show_all_platforms = true};
    inspect_result_t r;
    run_inspect(store, &ref, &opts, &r);

    if (r.rc != 0) {
        report_fail(name, "rc=%d", r.rc);
    } else if (contains(r.out, "layer reuse:")) {
        report_fail(name,
                    "reuse section must not render under --all-platforms");
    } else {
        report_pass(name);
    }

    free(r.out);
    free(m_digest);
    free(idx_body);
    oci_ref_free(&ref);
    oci_store_close(store);
}

/* Case 13: volume_root walk counts an unpacked sysroot -------------- */

static void case_layer_reuse_with_volume_root_counts_unpacked(
    const char *scratch)
{
    const char *name =
        "inspect: --volume DIR counts unpacked sysroot in reuse compare";
    char root[1024];
    char volume[1024];
    snprintf(root, sizeof(root), "%s/case-reuse-volume-store", scratch);
    snprintf(volume, sizeof(volume), "%s/case-reuse-volume-vol", scratch);
    mkdir(volume, 0755);

    oci_store_t *store = oci_store_open(root);
    oci_blob_store_t *blobs = oci_store_blobs(store);

    char *d1 = diff_id_n_reuse(1);
    char *d2 = diff_id_n_reuse(2);
    char *diffs[] = {d1, d2, NULL};
    char *cfg = put_reuse_config(blobs, diffs, NULL);
    char *mf = put_reuse_manifest(blobs, cfg);
    pin_helper(store, "scratch:target", mf);

    /* Unpacked tree shares d2; its synthetic manifest_digest is NOT on
     * disk, exercising the origin-sidecar-only path.
     */
    char *d7 = diff_id_n_reuse(7);
    char *other_diffs[] = {d2, d7, NULL};
    static const char OM[] =
        "sha256:"
        "dead00000000000000000000000000000000000000000000000000000000beef";
    static const char OC[] =
        "sha256:"
        "cafe00000000000000000000000000000000000000000000000000000000babe";
    char images_dir[1024];
    snprintf(images_dir, sizeof(images_dir), "%s/images", volume);
    mkdir(images_dir, 0755);
    char tree[1024];
    snprintf(tree, sizeof(tree),
             "%s/"
             "sha256-"
             "fa00000000000000000000000000000000000000000000000000000000000001",
             images_dir);
    mkdir(tree, 0755);
    oci_origin_write(tree, OM, OC, other_diffs, NULL);

    oci_ref_t ref = {0};
    oci_ref_parse("scratch:target", &ref, NULL);

    oci_inspect_options_t opts = {.volume_root = volume};
    inspect_result_t r;
    run_inspect(store, &ref, &opts, &r);

    if (r.rc != 0) {
        report_fail(name, "rc=%d", r.rc);
    } else if (!contains(
                   r.out,
                   "raw cache:   1/2 layers shared with 1 other image(s)")) {
        report_fail(name, "raw cache line should report 1/2 shared with 1");
    } else {
        report_pass(name);
    }

    free(r.out);
    free(d1);
    free(d2);
    free(d7);
    free(cfg);
    free(mf);
    oci_ref_free(&ref);
    oci_store_close(store);
}

int main(void)
{
    char *scratch = make_scratch_root();
    if (!scratch) {
        fprintf(stderr, "scratch root mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }
    printf("OCI inspect unit tests (scratch=%s)\n", scratch);

    case_direct_manifest(scratch);
    case_index_default_drills_arm64(scratch);
    case_index_all_platforms(scratch);
    case_pin_miss(scratch);
    case_digest_blob_missing(scratch);
    case_sub_manifest_missing(scratch);
    case_runtime_empty_env(scratch);
    case_layer_reuse_shared_section_renders(scratch);
    case_layer_reuse_zero_shared(scratch);
    case_layer_reuse_single_image_in_store(scratch);
    case_layer_reuse_config_missing_degrades(scratch);
    case_layer_reuse_all_platforms_skips_section(scratch);
    case_layer_reuse_with_volume_root_counts_unpacked(scratch);

    wipe_dir(scratch);
    free(scratch);

    printf("\nResults: %d/%d passed\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
