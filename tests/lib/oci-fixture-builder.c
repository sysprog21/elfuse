/* OCI store fixture builder for compat tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Command-line tool that synthesises a complete OCI-layout store from
 * a set of uncompressed-tar layers plus image-config flags. Used by
 * tests/test-oci-compat.sh and by hand for one-off "shape an image
 * from local files" experiments.
 *
 * Usage:
 *
 *   oci-fixture-builder \
 *       --store DIR \
 *       --ref REF \
 *       [--entrypoint PROG] \
 *       [--cmd ARG ...] (repeatable; each --cmd appends one element) \
 *       [--env KEY=VAL ...] (repeatable) \
 *       [--workdir DIR] \
 *       [--user UID[:GID]] \
 *       --layer TAR_FILE [--layer TAR_FILE ...]
 *
 * Behavior:
 *   - Each --layer is read verbatim, hashed, stored at
 *     blobs/sha256/<hex>, and listed in the manifest with mediaType
 *     application/vnd.oci.image.layer.v1.tar (uncompressed). The same
 *     digest is used as the rootfs.diff_id for that layer; OCI spec
 *     says diff_id is the uncompressed-tar digest, and an uncompressed
 *     layer has manifest-digest == diff_id by construction.
 *   - Image-config JSON is assembled from the CLI flags and the
 *     computed diff_ids, then hashed and stored.
 *   - Manifest JSON references the config + every layer in order.
 *     Hashed and stored.
 *   - The ref pin is recorded in <root>/index.json as a manifests[]
 *     descriptor whose org.opencontainers.image.ref.name annotation
 *     carries the canonical "<registry>/<repository>:<tag>" form and
 *     whose digest field points at the manifest digest.
 *
 * Exit codes:
 *   0  fixture built and pinned successfully
 *   1  store / IO / parse failure (a diagnostic was printed to stderr)
 *   2  argument error
 *
 * The tool is offline. It never touches the network or the host
 * filesystem outside the store root and the input layer files.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "oci/blob-store.h"
#include "oci/digest.h"
#include "oci/ref.h"
#include "oci/store.h"

static void die(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("error: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputs("\n", stderr);
    va_end(ap);
    exit(1);
}

/* Geometric-grow string vector for the repeatable --cmd / --env / --layer
 * flags. Holds shallow pointers into argv since the binary lives for the
 * duration of the build call and we never mutate the strings.
 */
typedef struct {
    const char **items;
    size_t n;
    size_t cap;
} svec_t;

static void svec_push(svec_t *v, const char *s)
{
    if (v->n + 1 > v->cap) {
        size_t newcap = v->cap ? v->cap * 2 : 8;
        const char **np = realloc((void *) v->items, newcap * sizeof(*np));
        if (!np)
            die("out of memory");
        v->items = np;
        v->cap = newcap;
    }
    v->items[v->n++] = s;
}

static void svec_free(svec_t *v)
{
    free((void *) v->items);
    v->items = NULL;
    v->n = 0;
    v->cap = 0;
}

/* Read an entire file into a heap buffer. Returns NULL on miss / IO
 * failure. *out_len is set on success. The caller frees.
 */
static char *slurp_file(const char *path, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return NULL;
    if (fseek(fp, 0, SEEK_END) < 0) {
        fclose(fp);
        return NULL;
    }
    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    char *buf = malloc((size_t) sz + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t) sz, fp);
    fclose(fp);
    if (got != (size_t) sz) {
        free(buf);
        return NULL;
    }
    buf[sz] = '\0';
    *out_len = (size_t) sz;
    return buf;
}

/* Compute SHA-256 of buf and store as blobs/sha256/<hex>. Returns a
 * heap-allocated "sha256:<hex>" digest string (caller frees) plus the
 * hex (without the algo prefix) via out_hex.
 */
static char *put_blob(oci_blob_store_t *blobs,
                      const char *buf,
                      size_t len,
                      char out_hex[OCI_DIGEST_HEX_MAX + 1])
{
    if (oci_digest_bytes(OCI_DIGEST_SHA256, buf, len, out_hex) == 0)
        die("oci_digest_bytes failed");
    if (oci_blob_store_put_bytes(blobs, OCI_DIGEST_SHA256, out_hex, buf, len) <
        0)
        die("blob store put failed for sha256:%s: %s", out_hex,
            strerror(errno));
    char *digest_str = malloc(strlen(out_hex) + 8);
    if (!digest_str)
        die("out of memory");
    sprintf(digest_str, "sha256:%s", out_hex);
    return digest_str;
}

static void usage(FILE *out, const char *progname)
{
    fprintf(out,
            "usage: %s --store DIR --ref REF --layer FILE [OPTIONS]\n"
            "\n"
            "Options:\n"
            "  --entrypoint PROG       Image config Entrypoint (single arg)\n"
            "  --cmd ARG               Append one arg to image Cmd (repeat)\n"
            "  --env KEY=VAL           Append one env entry (repeat)\n"
            "  --workdir DIR           Image config WorkingDir\n"
            "  --user UID[:GID]        Image config User (numeric only)\n"
            "  --layer TAR_FILE        Add an uncompressed-tar layer\n"
            "                          (repeat; layers apply in CLI order)\n",
            progname);
}

int main(int argc, char **argv)
{
    const char *store_root = NULL;
    const char *ref_str = NULL;
    const char *entrypoint = NULL;
    const char *workdir = NULL;
    const char *user = NULL;
    svec_t cmds = {0};
    svec_t envs = {0};
    svec_t layers = {0};

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout, argv[0]);
            return 0;
        }
#define ARG_OPT(name, dst)                                      \
    if (!strcmp(a, name)) {                                     \
        if (++i >= argc) {                                      \
            fprintf(stderr, "error: %s needs a value\n", name); \
            usage(stderr, argv[0]);                             \
            return 2;                                           \
        }                                                       \
        (dst) = argv[i];                                        \
        continue;                                               \
    }
        ARG_OPT("--store", store_root)
        ARG_OPT("--ref", ref_str)
        ARG_OPT("--entrypoint", entrypoint)
        ARG_OPT("--workdir", workdir)
        ARG_OPT("--user", user)
#undef ARG_OPT
        if (!strcmp(a, "--cmd")) {
            if (++i >= argc)
                die("--cmd needs a value");
            svec_push(&cmds, argv[i]);
            continue;
        }
        if (!strcmp(a, "--env")) {
            if (++i >= argc)
                die("--env needs a value");
            svec_push(&envs, argv[i]);
            continue;
        }
        if (!strcmp(a, "--layer")) {
            if (++i >= argc)
                die("--layer needs a value");
            svec_push(&layers, argv[i]);
            continue;
        }
        fprintf(stderr, "error: unknown option: %s\n", a);
        usage(stderr, argv[0]);
        return 2;
    }
    if (!store_root || !ref_str) {
        fputs("error: --store and --ref are required\n", stderr);
        usage(stderr, argv[0]);
        return 2;
    }
    if (layers.n == 0) {
        fputs("error: at least one --layer is required\n", stderr);
        return 2;
    }

    oci_store_t *store = oci_store_open(store_root);
    if (!store)
        die("oci_store_open(%s): %s", store_root, strerror(errno));
    oci_blob_store_t *blobs = oci_store_blobs(store);

    /* Read each layer, hash + store, collect digest + size. */
    char **layer_digests = calloc(layers.n, sizeof(*layer_digests));
    int64_t *layer_sizes = calloc(layers.n, sizeof(*layer_sizes));
    if (!layer_digests || !layer_sizes)
        die("out of memory");
    char hex[OCI_DIGEST_HEX_MAX + 1];
    for (size_t i = 0; i < layers.n; i++) {
        size_t len = 0;
        char *bytes = slurp_file(layers.items[i], &len);
        if (!bytes)
            die("cannot read layer %zu (%s): %s", i, layers.items[i],
                strerror(errno));
        layer_digests[i] = put_blob(blobs, bytes, len, hex);
        layer_sizes[i] = (int64_t) len;
        free(bytes);
    }

    /* Assemble image-config JSON. */
    cJSON *config = cJSON_CreateObject();
    cJSON_AddStringToObject(config, "architecture", "arm64");
    cJSON_AddStringToObject(config, "os", "linux");

    cJSON *cfg_inner = cJSON_AddObjectToObject(config, "config");
    if (entrypoint) {
        cJSON *arr = cJSON_CreateArray();
        cJSON_AddItemToArray(arr, cJSON_CreateString(entrypoint));
        cJSON_AddItemToObject(cfg_inner, "Entrypoint", arr);
    }
    if (cmds.n > 0) {
        cJSON *arr = cJSON_CreateArray();
        for (size_t i = 0; i < cmds.n; i++)
            cJSON_AddItemToArray(arr, cJSON_CreateString(cmds.items[i]));
        cJSON_AddItemToObject(cfg_inner, "Cmd", arr);
    }
    if (envs.n > 0) {
        cJSON *arr = cJSON_CreateArray();
        for (size_t i = 0; i < envs.n; i++)
            cJSON_AddItemToArray(arr, cJSON_CreateString(envs.items[i]));
        cJSON_AddItemToObject(cfg_inner, "Env", arr);
    }
    if (workdir)
        cJSON_AddStringToObject(cfg_inner, "WorkingDir", workdir);
    if (user)
        cJSON_AddStringToObject(cfg_inner, "User", user);

    cJSON *rootfs = cJSON_AddObjectToObject(config, "rootfs");
    cJSON_AddStringToObject(rootfs, "type", "layers");
    cJSON *diff_ids = cJSON_CreateArray();
    for (size_t i = 0; i < layers.n; i++)
        cJSON_AddItemToArray(diff_ids, cJSON_CreateString(layer_digests[i]));
    cJSON_AddItemToObject(rootfs, "diff_ids", diff_ids);

    char *config_str = cJSON_PrintUnformatted(config);
    cJSON_Delete(config);
    if (!config_str)
        die("config JSON print failed");
    size_t config_len = strlen(config_str);
    char config_hex[OCI_DIGEST_HEX_MAX + 1];
    char *config_digest = put_blob(blobs, config_str, config_len, config_hex);

    /* Assemble manifest JSON referencing the config + layer descriptors. */
    cJSON *manifest = cJSON_CreateObject();
    cJSON_AddNumberToObject(manifest, "schemaVersion", 2);
    cJSON_AddStringToObject(manifest, "mediaType",
                            "application/vnd.oci.image.manifest.v1+json");

    cJSON *m_config = cJSON_AddObjectToObject(manifest, "config");
    cJSON_AddStringToObject(m_config, "mediaType",
                            "application/vnd.oci.image.config.v1+json");
    cJSON_AddStringToObject(m_config, "digest", config_digest);
    cJSON_AddNumberToObject(m_config, "size", (double) config_len);

    cJSON *m_layers = cJSON_AddArrayToObject(manifest, "layers");
    for (size_t i = 0; i < layers.n; i++) {
        cJSON *l = cJSON_CreateObject();
        cJSON_AddStringToObject(l, "mediaType",
                                "application/vnd.oci.image.layer.v1.tar");
        cJSON_AddStringToObject(l, "digest", layer_digests[i]);
        cJSON_AddNumberToObject(l, "size", (double) layer_sizes[i]);
        cJSON_AddItemToArray(m_layers, l);
    }

    char *manifest_str = cJSON_PrintUnformatted(manifest);
    cJSON_Delete(manifest);
    if (!manifest_str)
        die("manifest JSON print failed");
    size_t manifest_len = strlen(manifest_str);
    char manifest_hex[OCI_DIGEST_HEX_MAX + 1];
    char *manifest_digest =
        put_blob(blobs, manifest_str, manifest_len, manifest_hex);

    /* Pin ref to the manifest digest. */
    oci_ref_t ref = {0};
    const char *parse_err = NULL;
    if (oci_ref_parse(ref_str, &ref, &parse_err) < 0)
        die("ref parse failed: %s", parse_err ? parse_err : "?");
    const char *put_err = NULL;
    if (oci_store_put_ref(store, &ref, manifest_digest, &put_err) < 0)
        die("store put_ref failed: %s", put_err ? put_err : strerror(errno));

    /* Echo the manifest digest to stdout so the caller can grep it. */
    printf("%s\n", manifest_digest);

    /* Cleanup. */
    oci_ref_free(&ref);
    free(manifest_digest);
    free(manifest_str);
    free(config_digest);
    free(config_str);
    for (size_t i = 0; i < layers.n; i++)
        free(layer_digests[i]);
    free(layer_digests);
    free(layer_sizes);
    svec_free(&cmds);
    svec_free(&envs);
    svec_free(&layers);
    oci_store_close(store);
    return 0;
}
