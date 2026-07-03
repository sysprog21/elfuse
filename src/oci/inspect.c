/* Offline manifest tree renderer for elfuse oci inspect
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reads the blob the local pin points at, classifies it as an image index or
 * image manifest, and prints a tree. No network, no fetcher. The manifest
 * model from slice 3 enforces every digest is lowercase and every descriptor
 * size is non-negative, so the renderer can trust its inputs once the parse
 * returns 0.
 *
 * Detection between index and manifest is structural: oci_index_parse refuses
 * a body that has no "manifests" array, oci_manifest_parse refuses a body
 * that has no "config" + "layers" pair. The two parsers therefore reject
 * disjoint shapes, and trying one then the other is unambiguous. Image
 * configs never reach this code path because pins point at manifest-shaped
 * blobs (slice 5a stores the manifest body it received from the registry).
 */

#include "inspect.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "blob-store.h"
#include "dedup-metrics.h"
#include "digest.h"
#include "manifest.h"
#include "media-type.h"

/* Upper bound on a manifest/index body. Real manifests are well under 1 MiB;
 * a 64 MiB cap is generous and prevents a corrupted store from forcing a
 * pathological malloc.
 */
#define INSPECT_BODY_MAX ((size_t) 64 * 1024 * 1024)

/* Render a digest in two compact forms:
 *
 *   - short_digest("sha256:abcdef0123456789...")
 *       -> "sha256:abcdef012345..."   (first 19 chars + "...")
 *
 * Matches the slice 5a pull progress line so the two surfaces stay visually
 * consistent. The caller-supplied buffer keeps the function reentrant; using
 * one static buffer would clobber on the second %s in a single printf.
 */
static void short_digest(const char *full, char out[24])
{
    if (!full) {
        snprintf(out, 24, "(null)");
        return;
    }
    size_t len = strlen(full);
    if (len <= 22) {
        snprintf(out, 24, "%s", full);
        return;
    }
    snprintf(out, 24, "%.19s...", full);
}

/* Compose a "linux/arm64/v8" string from a parsed platform descriptor. The
 * variant suffix is omitted when the variant field is empty so a platform
 * with no variant prints as "linux/amd64" rather than "linux/amd64/".
 */
static void render_platform(const oci_platform_t *p, char out[64])
{
    const char *os = p->os && *p->os ? p->os : "?";
    const char *arch =
        p->architecture && *p->architecture ? p->architecture : "?";
    if (p->variant && *p->variant) {
        snprintf(out, 64, "%s/%s/%s", os, arch, p->variant);
    } else {
        snprintf(out, 64, "%s/%s", os, arch);
    }
}

/* Open <store-root>/blobs/<algo>/<hex> and slurp the contents into a fresh
 * heap buffer. NUL-terminates the buffer so the slice 3 parsers (which accept
 * exact-length bytes) can also be fed as C strings if a caller wants. On
 * miss returns -1 with errno=ENOENT; on read failure returns -1 with errno
 * preserved or set to EIO.
 */
static int read_blob_file(oci_blob_store_t *blobs,
                          oci_digest_algo_t algo,
                          const char *hex,
                          char **out_body,
                          size_t *out_len)
{
    char path[4096];
    int n = oci_blob_store_path(blobs, algo, hex, path, sizeof(path));
    if (n < 0 || (size_t) n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (st.st_size < 0 || (uintmax_t) st.st_size > INSPECT_BODY_MAX) {
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

/* Emit one entry of a JSON-style string array with backslash and double-quote
 * escaping. Control characters pass through verbatim: image-config Entrypoint
 * and Cmd entries are container argv strings, which in practice never carry
 * raw control bytes, and a partial JSON escape table would mislead a reader
 * who expects strict RFC 8259 conformance. Callers downstream of inspect
 * (commit 2 onward) reparse the array via the cJSON-backed image-config
 * loader, not by scanning the human-readable inspect output.
 */
static void print_quoted_token(FILE *out, const char *s)
{
    fputc('"', out);
    for (const char *p = s; *p; p++) {
        if (*p == '"' || *p == '\\')
            fputc('\\', out);
        fputc(*p, out);
    }
    fputc('"', out);
}

/* Render a NULL-terminated string array as ["a", "b", "c"]. Empty array
 * (arr[0] == NULL) renders as []. Caller has already pre-checked arr != NULL.
 */
static void print_json_string_array(FILE *out, char *const *arr)
{
    fputc('[', out);
    for (size_t i = 0; arr[i] != NULL; i++) {
        if (i > 0)
            fputs(", ", out);
        print_quoted_token(out, arr[i]);
    }
    fputc(']', out);
}

/* Render the image-config runtime block (User, WorkingDir, Entrypoint, Cmd,
 * Env). Absent fields (NULL pointer in the parsed model) skip the bullet
 * entirely; empty arrays still print "[]" because that is the
 * spec-defined "explicit empty" shape and silently hiding it would
 * misrepresent the image. Label column width is 13 so values align with the
 * preceding "  config:   " column from render_manifest.
 *
 * Multi-line Env: the first var sits on the "env:" line; remaining vars
 * indent to the value column on continuation lines. Output stays grep-friendly
 * (each VAR=value on its own line) without sacrificing the leading section
 * header.
 */
static void render_runtime(FILE *out, const oci_image_runtime_t *rt)
{
    fprintf(out, "runtime:\n");
    if (rt->user)
        fprintf(out, "  user:        %s\n", rt->user);
    if (rt->working_dir)
        fprintf(out, "  workingdir:  %s\n", rt->working_dir);
    if (rt->entrypoint) {
        fprintf(out, "  entrypoint:  ");
        print_json_string_array(out, rt->entrypoint);
        fputc('\n', out);
    }
    if (rt->cmd) {
        fprintf(out, "  cmd:         ");
        print_json_string_array(out, rt->cmd);
        fputc('\n', out);
    }
    if (rt->env) {
        if (rt->env[0] == NULL) {
            fprintf(out, "  env:         []\n");
        } else {
            for (size_t i = 0; rt->env[i] != NULL; i++) {
                fprintf(out, "%s%s\n",
                        i == 0 ? "  env:         " : "               ",
                        rt->env[i]);
            }
        }
    }
}

/* Best-effort read+parse of the image-config blob referenced by a manifest's
 * config descriptor; on success, emits the runtime block. Failure (blob
 * missing, parse rejects the body) is silent: the surrounding inspect output
 * already names the config digest in the layer table, so a reader can chase
 * it via 'elfuse oci pull' or by inspecting the store directly. Inspect's
 * primary contract is to render the manifest tree, not to fail when a
 * pulled image is missing the auxiliary config blob.
 */
static void try_render_runtime(FILE *out,
                               oci_blob_store_t *blobs,
                               const oci_descriptor_t *config_desc)
{
    char *body = NULL;
    size_t body_len = 0;
    if (read_blob_file(blobs, config_desc->algo, config_desc->hex, &body,
                       &body_len) < 0)
        return;
    oci_image_config_t cfg = {0};
    if (oci_image_config_parse(body, body_len, &cfg, NULL) == 0) {
        render_runtime(out, &cfg.config);
        oci_image_config_free(&cfg);
    }
    free(body);
}

/* Print the config + layer table for a parsed manifest. When manifest_digest
 * is non-NULL, a "manifest: <full digest> (<media type>)" header line goes
 * first; the direct-manifest path passes NULL so it does not duplicate the
 * already-printed pin line. After the layer table, attempt to render the
 * image-config runtime block (User, Env, Entrypoint, Cmd, WorkingDir) when
 * the config blob can be loaded; absent/unreadable config blobs leave the
 * runtime section out, since the manifest tree itself is the primary signal.
 */
static void render_manifest(FILE *out,
                            oci_blob_store_t *blobs,
                            const oci_manifest_t *mf,
                            const char *manifest_digest)
{
    if (manifest_digest) {
        const char *mt = oci_media_type_name(mf->media_type);
        fprintf(out, "manifest:   %s (%s)\n", manifest_digest,
                mt ? mt : "unknown");
    }
    char buf[24];
    short_digest(mf->config.digest_str, buf);
    const char *config_mt = oci_media_type_name(mf->config.media_type);
    fprintf(out, "  config:   %-22s %12" PRId64 "B  %s\n", buf, mf->config.size,
            config_mt ? config_mt : "unknown");
    fprintf(out, "  layers:\n");
    for (size_t i = 0; i < mf->nlayers; i++) {
        const oci_descriptor_t *l = &mf->layers[i];
        short_digest(l->digest_str, buf);
        const char *lmt = oci_media_type_name(l->media_type);
        fprintf(out, "    [%zu]     %-22s %12" PRId64 "B  %s\n", i, buf,
                l->size, lmt ? lmt : "unknown");
    }
    try_render_runtime(out, blobs, &mf->config);
}

/* Render the "layer reuse:" section. Compares the target manifest's
 * diff_id list and ChainID chain against every other image recorded in the
 * store (pins plus, when volume_root is set, unpacked sysroots) and prints
 * a two-line summary:
 *
 *   layer reuse:
 *     raw cache:   N/M layers shared with K other image(s)[, X on cache]
 *     stack cache: deepest shared prefix reaches layer P/M (sha256:...)
 *
 * Failure modes are intentionally soft: a missing or malformed image-config
 * for the target prints "layer reuse: (image-config unavailable)" without
 * disturbing the surrounding manifest tree output. An empty store (no other
 * images to compare against) prints "(no other images to compare)" so the
 * operator can tell "0 shared because nothing to share with" apart from
 * "0 shared because nothing overlaps".
 *
 * Bytes formatting: values >= 1 MiB render as "~X.Y MiB on cache"; smaller
 * non-zero values render in bytes; zero bytes are omitted (still print the
 * layer count, just without a bytes clause) because a 0 B clause would imply
 * the raw cache is populated when it isn't.
 */
static void render_layer_reuse(FILE *out,
                               oci_store_t *store,
                               const char *manifest_digest,
                               const char *volume_root)
{
    oci_dedup_metrics_t m = {0};
    const char *err = NULL;
    if (oci_dedup_metrics_compute(store, manifest_digest, volume_root, &m,
                                  &err) < 0) {
        fprintf(out, "layer reuse: (image-config unavailable)\n");
        return;
    }
    if (m.compared_images == 0) {
        fprintf(out, "layer reuse: (no other images to compare)\n");
        return;
    }
    fprintf(out, "layer reuse:\n");
    fprintf(out, "  raw cache:   %zu/%zu layers shared with %zu other image(s)",
            m.shared_layers, m.total_layers, m.compared_images);
    if (m.shared_bytes >= (uint64_t) 1024 * 1024) {
        double mib = (double) m.shared_bytes / (1024.0 * 1024.0);
        fprintf(out, ", ~%.1f MiB on cache", mib);
    } else if (m.shared_bytes > 0) {
        fprintf(out, ", %" PRIu64 " B on cache", m.shared_bytes);
    }
    fputc('\n', out);
    if (m.deepest_shared_prefix > 0) {
        char short_chain[24];
        short_digest(m.deepest_shared_chainid, short_chain);
        fprintf(out,
                "  stack cache: deepest shared prefix reaches layer %zu/%zu"
                " (%s)\n",
                m.deepest_shared_prefix, m.total_layers, short_chain);
    } else {
        fprintf(out, "  stack cache: no shared prefix\n");
    }
}

/* Render the index entry table. Default mode prints only the picked
 * linux/arm64 entry (with a "[arm64]" tag); --all-platforms prints every
 * entry, tagging the picked one so users still see which one elfuse will
 * resolve.
 */
static void render_index_platforms(FILE *out,
                                   const oci_index_t *idx,
                                   const oci_index_entry_t *picked,
                                   bool show_all)
{
    fprintf(out, "platforms:\n");
    for (size_t i = 0; i < idx->nentries; i++) {
        const oci_index_entry_t *e = &idx->entries[i];
        bool is_picked = (e == picked);
        if (!show_all && !is_picked)
            continue;
        char digest_buf[24];
        short_digest(e->desc.digest_str, digest_buf);
        char platform_buf[64];
        render_platform(&e->platform, platform_buf);
        const char *mt = oci_media_type_name(e->desc.media_type);
        fprintf(out, "  %-9s %-22s %-22s %12" PRId64 "B  %s\n",
                is_picked ? "[arm64]" : "", platform_buf, digest_buf,
                e->desc.size, mt ? mt : "unknown");
    }
    fprintf(out, "\n");
}

int oci_inspect(oci_store_t *store,
                const oci_ref_t *ref,
                const oci_inspect_options_t *opts,
                const char **err_msg)
{
    if (!store || !ref || !ref->registry || !ref->repository) {
        if (err_msg)
            *err_msg = "invalid arguments";
        errno = EINVAL;
        return -1;
    }
    FILE *out = opts && opts->out ? opts->out : stdout;
    bool show_all = opts && opts->show_all_platforms;

    /* 1. Resolve manifest digest from ref. */
    char *pinned = NULL;
    bool from_pin = false;
    if (ref->digest) {
        pinned = strdup(ref->digest);
        if (!pinned) {
            errno = ENOMEM;
            if (err_msg)
                *err_msg = "out of memory";
            return -1;
        }
    } else if (ref->tag) {
        const char *get_err = NULL;
        int gr = oci_store_get_ref(store, ref, &pinned, &get_err);
        if (gr < 0) {
            if (errno == ENOENT) {
                fprintf(out,
                        "pinned:     (no local manifest; run 'elfuse oci "
                        "pull' first)\n");
                return 0;
            }
            if (err_msg)
                *err_msg = get_err ? get_err : "failed to read pin";
            return -1;
        }
        from_pin = true;
    } else {
        /* The slice 1 ref parser defaults tag to "latest" when no digest is
         * given, so this branch is structurally unreachable through the CLI.
         * Guard it anyway so a hand-constructed ref does not segfault.
         */
        if (err_msg)
            *err_msg = "ref has neither tag nor digest";
        errno = EINVAL;
        return -1;
    }

    /* 2. Print the pin line. The digest reference annotation tells the user
     * this came from ref->digest rather than the local pin file.
     */
    if (from_pin) {
        fprintf(out, "pinned:     %s\n", pinned);
    } else {
        fprintf(out, "pinned:     %s (digest reference)\n", pinned);
    }

    /* 3. Validate the digest and read the blob. */
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(pinned, &algo, hex)) {
        if (err_msg)
            *err_msg = "pinned digest is malformed";
        errno = EINVAL;
        free(pinned);
        return -1;
    }

    char *body = NULL;
    size_t body_len = 0;
    if (read_blob_file(oci_store_blobs(store), algo, hex, &body, &body_len) <
        0) {
        if (errno == ENOENT) {
            fprintf(out, "error: manifest blob %s not found in local store\n",
                    pinned);
            if (err_msg)
                *err_msg = "manifest blob missing from local store";
            free(pinned);
            errno = ENOENT;
            return -1;
        }
        int saved = errno;
        if (err_msg)
            *err_msg = "failed to read manifest blob";
        free(pinned);
        errno = saved;
        return -1;
    }

    /* 4. Classify: try index first, then manifest. The two parsers reject
     * disjoint shapes (one requires "manifests", the other requires "config"
     * + "layers"), so a successful parse is unambiguous.
     */
    oci_index_t idx = {0};
    oci_manifest_t mf = {0};
    bool is_index = false;
    bool is_manifest = false;
    if (oci_index_parse(body, body_len, &idx, NULL) == 0) {
        is_index = true;
    } else if (oci_manifest_parse(body, body_len, &mf, NULL) == 0) {
        is_manifest = true;
    } else {
        if (err_msg)
            *err_msg = "manifest blob is neither a valid index nor manifest";
        errno = EPROTO;
        free(body);
        free(pinned);
        return -1;
    }

    /* 5. Render. */
    int rc = 0;
    if (is_index) {
        const char *imt = oci_media_type_name(idx.media_type);
        fprintf(out, "type:       image index (%s)\n\n", imt ? imt : "unknown");

        const oci_index_entry_t *picked = oci_index_pick_linux_arm64(&idx);
        render_index_platforms(out, &idx, picked, show_all);

        /* Default mode drills into the picked linux/arm64 sub-manifest. The
         * --all-platforms request is "show me the cover", not "drill"; skip
         * the sub-manifest read entirely.
         */
        if (!show_all) {
            if (!picked) {
                fprintf(out, "error: index has no linux/arm64 entry\n");
                if (err_msg)
                    *err_msg = "index has no linux/arm64 entry";
                errno = ENOENT;
                rc = -1;
            } else {
                char *sub_body = NULL;
                size_t sub_len = 0;
                if (read_blob_file(oci_store_blobs(store), picked->desc.algo,
                                   picked->desc.hex, &sub_body, &sub_len) < 0) {
                    if (errno == ENOENT) {
                        fprintf(stderr,
                                "warning: linux/arm64 manifest blob %s not "
                                "in local store\n",
                                picked->desc.digest_str);
                        if (err_msg)
                            *err_msg =
                                "indexed manifest blob missing from local "
                                "store";
                        errno = ENOENT;
                        rc = -1;
                    } else {
                        int saved = errno;
                        if (err_msg)
                            *err_msg = "failed to read sub-manifest blob";
                        errno = saved;
                        rc = -1;
                    }
                } else {
                    oci_manifest_t sub_mf = {0};
                    if (oci_manifest_parse(sub_body, sub_len, &sub_mf, NULL) ==
                        0) {
                        render_manifest(out, oci_store_blobs(store), &sub_mf,
                                        picked->desc.digest_str);
                        if (!opts || !opts->suppress_layer_reuse) {
                            render_layer_reuse(out, store,
                                               picked->desc.digest_str,
                                               opts ? opts->volume_root : NULL);
                        }
                        oci_manifest_free(&sub_mf);
                    } else {
                        fprintf(out,
                                "error: sub-manifest blob %s is malformed\n",
                                picked->desc.digest_str);
                        if (err_msg)
                            *err_msg = "sub-manifest is malformed";
                        errno = EPROTO;
                        rc = -1;
                    }
                    free(sub_body);
                }
            }
        }
    } else if (is_manifest) {
        const char *mmt = oci_media_type_name(mf.media_type);
        fprintf(out, "type:       image manifest (%s)\n\n",
                mmt ? mmt : "unknown");
        render_manifest(out, oci_store_blobs(store), &mf, NULL);
        if (!opts || !opts->suppress_layer_reuse) {
            render_layer_reuse(out, store, pinned,
                               opts ? opts->volume_root : NULL);
        }
    }

    /* errno preserved across cleanup, like slice 5a oci_pull. */
    int saved_errno = errno;
    oci_index_free(&idx);
    oci_manifest_free(&mf);
    free(body);
    free(pinned);
    if (rc != 0)
        errno = saved_errno;
    return rc;
}
