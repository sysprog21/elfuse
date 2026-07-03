/* OCI layer unpack orchestrator implementation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <copyfile.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "oci/blob-store.h"
#include "oci/digest.h"
#include "oci/layer-apply.h"
#include "oci/layer-meta.h"
#include "oci/manifest.h"
#include "oci/media-type.h"
#include "oci/origin-meta.h"
#include "oci/ref.h"
#include "oci/store.h"
#include "oci/tar.h"
#include "oci/unpack.h"
#include "oci/volume.h"
#include "oci/util.h"

#define UN_PATH_MAX 4096
#define UN_BLOB_BUF 65536

typedef struct {
    int fd;
} unpack_stream_ctx_t;

/* Raw blob reads: the libarchive-backed tar reader auto-detects gzip /
 * zstd / uncompressed streams, so no decompress stage sits in between.
 */
static ssize_t unpack_stream_read_cb(void *ctx, void *buf, size_t cap)
{
    unpack_stream_ctx_t *c = ctx;
    ssize_t n;
    do {
        n = read(c->fd, buf, cap);
    } while (n < 0 && errno == EINTR);
    return n;
}

static int rand_hex(char *out, size_t n_hex)
{
    size_t need = n_hex / 2;
    uint8_t buf[16];
    if (need > sizeof(buf))
        return -1;
    if (getentropy(buf, need) < 0)
        return -1;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < need; i++) {
        out[i * 2] = hex[buf[i] >> 4];
        out[i * 2 + 1] = hex[buf[i] & 0xf];
    }
    out[n_hex] = '\0';
    return 0;
}

static int read_blob(oci_blob_store_t *bs,
                     oci_digest_algo_t algo,
                     const char *hex,
                     uint8_t **out_buf,
                     size_t *out_len,
                     const char **err)
{
    char path[UN_PATH_MAX];
    if (oci_blob_store_path(bs, algo, hex, path, sizeof(path)) < 0)
        return set_err(err, "unpack: blob path resolve failed", errno);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return set_err(err, "unpack: blob open failed", errno);
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return set_err(err, "unpack: blob fstat failed", errno);
    }
    if (st.st_size < 0 || st.st_size > (off_t) (256 * 1024 * 1024)) {
        close(fd);
        return set_err(err, "unpack: blob size out of bounds", EINVAL);
    }
    uint8_t *buf = malloc((size_t) st.st_size + 1);
    if (!buf) {
        close(fd);
        return set_err(err, "unpack: blob buffer alloc failed", ENOMEM);
    }
    ssize_t got = read(fd, buf, (size_t) st.st_size);
    close(fd);
    if (got != st.st_size) {
        free(buf);
        return set_err(err, "unpack: blob short read", EIO);
    }
    buf[got] = '\0';
    /* Same local-tamper guard reverify_layer_digest applies to layers:
     * the manifest / index / config bytes decide which layers, config,
     * entrypoint, env, and user to trust, so confirm the content still
     * hashes to the digest that named it before parsing.
     */
    oci_digester_t *d = oci_digester_new(algo);
    if (!d) {
        free(buf);
        return set_err(err, "unpack: digester alloc failed", ENOMEM);
    }
    oci_digester_update(d, buf, (size_t) got);
    char got_hex[OCI_DIGEST_HEX_MAX + 1];
    oci_digester_finish_hex(d, got_hex);
    oci_digester_free(d);
    if (strcmp(got_hex, hex) != 0) {
        free(buf);
        return set_err(err, "unpack: blob digest mismatch", EINVAL);
    }
    *out_buf = buf;
    *out_len = (size_t) got;
    return 0;
}

/* Open the on-disk blob path and confirm its sha256 hash matches the
 * descriptor's expected digest. The blob was already verified when it
 * was written into the store, but unpack re-verifies in case a
 * host-side tool modified it since.
 */
static int reverify_layer_digest(oci_blob_store_t *bs,
                                 const oci_descriptor_t *desc,
                                 const char **err)
{
    char path[UN_PATH_MAX];
    if (oci_blob_store_path(bs, desc->algo, desc->hex, path, sizeof(path)) < 0)
        return set_err(err, "unpack: layer path resolve failed", errno);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return set_err(err, "unpack: layer open failed", errno);

    oci_digester_t *d = oci_digester_new(desc->algo);
    if (!d) {
        close(fd);
        return set_err(err, "unpack: digester alloc failed", ENOMEM);
    }
    uint8_t buf[UN_BLOB_BUF];
    uint64_t total = 0;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            oci_digester_free(d);
            close(fd);
            return set_err(err, "unpack: layer read failed", errno);
        }
        if (n == 0)
            break;
        oci_digester_update(d, buf, (size_t) n);
        total += (uint64_t) n;
    }
    close(fd);
    char got_hex[OCI_DIGEST_HEX_MAX + 1];
    oci_digester_finish_hex(d, got_hex);
    oci_digester_free(d);
    if (strcmp(got_hex, desc->hex) != 0)
        return set_err(err, "unpack: layer blob digest mismatch", EINVAL);
    /* The descriptor carries a declared size alongside the digest;
     * requiring both to match costs nothing extra and catches a
     * truncated or padded blob a bare hash comparison could miss.
     */
    if (total != (uint64_t) desc->size)
        return set_err(err, "unpack: layer blob size mismatch", EINVAL);
    return 0;
}

/* Shared reverify + apply pipeline for the two
 * single-layer entry points. UNPACK_MODE_OVERLAY drives
 * oci_layer_apply (whiteout / opaque interpreted against root_dir);
 * UNPACK_MODE_RAW drives oci_layer_apply_raw_tar (whiteout markers
 * preserved as zero-byte regular files for the raw per-layer cache
 * populate path).
 */
typedef enum {
    UNPACK_MODE_OVERLAY,
    UNPACK_MODE_RAW,
} unpack_mode_t;

static int unpack_layer_impl(oci_blob_store_t *bs,
                             const oci_descriptor_t *desc,
                             const char *root_dir,
                             unpack_mode_t mode,
                             oci_layer_apply_stats_t *stats,
                             oci_meta_table_t *meta,
                             const char *log_label,
                             const char **err)
{
    if (!bs || !desc || !root_dir)
        return set_err(err, "unpack_layer: NULL argument", EINVAL);

    if (oci_media_type_is_foreign(desc->media_type))
        return set_err(err, "unpack: layer is foreign / nondistributable",
                       ENOTSUP);

    if (reverify_layer_digest(bs, desc, err) < 0)
        return -1;
    char path[UN_PATH_MAX];
    if (oci_blob_store_path(bs, desc->algo, desc->hex, path, sizeof(path)) < 0)
        return set_err(err, "unpack: layer path resolve failed", errno);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return set_err(err, "unpack: layer open failed", errno);

    unpack_stream_ctx_t tctx = {.fd = fd};
    oci_tar_reader_t *r = oci_tar_reader_new(unpack_stream_read_cb, &tctx);
    if (!r) {
        close(fd);
        return set_err(err, "unpack: tar reader alloc failed", ENOMEM);
    }

    if (log_label)
        fprintf(stderr, "  %s: %s\n", log_label, desc->digest_str);

    oci_layer_apply_stats_t local_stats = {0};
    int rc;
    if (mode == UNPACK_MODE_OVERLAY)
        rc = oci_layer_apply(r, root_dir, &local_stats, meta, err);
    else
        rc = oci_layer_apply_raw_tar(r, root_dir, &local_stats, meta, err);

    oci_tar_reader_free(r);
    close(fd);

    if (rc < 0)
        return -1;
    if (stats) {
        stats->files += local_stats.files;
        stats->dirs += local_stats.dirs;
        stats->symlinks += local_stats.symlinks;
        stats->hardlinks += local_stats.hardlinks;
        stats->whiteouts += local_stats.whiteouts;
        stats->opaques += local_stats.opaques;
    }
    if (log_label)
        fprintf(stderr,
                "    +files=%zu dirs=%zu symlinks=%zu hardlinks=%zu "
                "whiteouts=%zu opaques=%zu\n",
                local_stats.files, local_stats.dirs, local_stats.symlinks,
                local_stats.hardlinks, local_stats.whiteouts,
                local_stats.opaques);
    return 0;
}

int oci_unpack_layer(oci_blob_store_t *bs,
                     const oci_descriptor_t *desc,
                     const char *stage_dir,
                     oci_layer_apply_stats_t *stats,
                     oci_meta_table_t *meta,
                     const char *log_label,
                     const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    return unpack_layer_impl(bs, desc, stage_dir, UNPACK_MODE_OVERLAY, stats,
                             meta, log_label, err);
}

int oci_unpack_layer_raw(oci_blob_store_t *bs,
                         const oci_descriptor_t *desc,
                         const char *raw_dir,
                         oci_layer_apply_stats_t *stats,
                         oci_meta_table_t *meta,
                         const char *log_label,
                         const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    return unpack_layer_impl(bs, desc, raw_dir, UNPACK_MODE_RAW, stats, meta,
                             log_label, err);
}

/* --- two-pass overlay assembler ----------------------------------------- */

#define UN_RAW_META_SIDECAR ".elfuse-meta.layer.json"

static bool is_whiteout_name(const char *name)
{
    return strncmp(name, ".wh.", 4) == 0;
}

/* Remove every direct child of path, leaving path itself in place. Used
 * to honour the OCI ".wh..wh..opq" opaque marker: the parent directory
 * stays so this layer's siblings can land on top.
 */
static int clear_dir_contents(const char *path, const char **err)
{
    DIR *d = opendir(path);
    if (!d) {
        if (errno == ENOENT)
            return 0;
        return set_err(err, "assemble: clear opendir failed", errno);
    }
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char child[UN_PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        if (n < 0 || (size_t) n >= sizeof(child)) {
            rc = set_err(err, "assemble: clear path overflow", ENAMETOOLONG);
            break;
        }
        if (oci_rm_recursive(child) < 0) {
            rc = set_err(err, "assemble: clear rm child failed", errno);
            break;
        }
    }
    closedir(d);
    return rc;
}

static int assembly_walk_whiteouts(const char *raw_dir,
                                   const char *stage_dir,
                                   const char **err)
{
    DIR *d = opendir(raw_dir);
    if (!d)
        return set_err(err, "assemble: whiteout opendir failed", errno);
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (strcmp(de->d_name, UN_RAW_META_SIDECAR) == 0)
            continue;
        char raw_child[UN_PATH_MAX];
        char stage_child[UN_PATH_MAX];
        int n1 = snprintf(raw_child, sizeof(raw_child), "%s/%s", raw_dir,
                          de->d_name);
        int n2 = snprintf(stage_child, sizeof(stage_child), "%s/%s", stage_dir,
                          de->d_name);
        if (n1 < 0 || (size_t) n1 >= sizeof(raw_child) || n2 < 0 ||
            (size_t) n2 >= sizeof(stage_child)) {
            rc = set_err(err, "assemble: whiteout path overflow", ENAMETOOLONG);
            break;
        }
        struct stat st;
        if (lstat(raw_child, &st) < 0) {
            rc = set_err(err, "assemble: whiteout lstat failed", errno);
            break;
        }
        if (S_ISDIR(st.st_mode)) {
            /* Recurse: subdirectories may carry their own markers. The
             * stage_child counterpart may not exist yet (pass 2 creates
             * the missing directories), which is fine: descending into
             * the raw side still finds the markers, and the rm-r /
             * clear-contents calls below tolerate a missing target.
             */
            if (assembly_walk_whiteouts(raw_child, stage_child, err) < 0) {
                rc = -1;
                break;
            }
            continue;
        }
        if (!S_ISREG(st.st_mode))
            continue;
        if (strcmp(de->d_name, ".wh..wh..opq") == 0) {
            if (clear_dir_contents(stage_dir, err) < 0) {
                rc = -1;
                break;
            }
            continue;
        }
        if (is_whiteout_name(de->d_name)) {
            char target[UN_PATH_MAX];
            int nt = snprintf(target, sizeof(target), "%s/%s", stage_dir,
                              de->d_name + 4);
            if (nt < 0 || (size_t) nt >= sizeof(target)) {
                rc = set_err(err, "assemble: whiteout target overflow",
                             ENAMETOOLONG);
                break;
            }
            if (oci_rm_recursive(target) < 0) {
                rc = set_err(err, "assemble: whiteout rm failed", errno);
                break;
            }
        }
    }
    closedir(d);
    return rc;
}

static int assembly_walk_content(const char *raw_dir,
                                 const char *stage_dir,
                                 const char **err)
{
    DIR *d = opendir(raw_dir);
    if (!d)
        return set_err(err, "assemble: content opendir failed", errno);
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (strcmp(de->d_name, UN_RAW_META_SIDECAR) == 0)
            continue;
        if (is_whiteout_name(de->d_name))
            continue;
        char raw_child[UN_PATH_MAX];
        char stage_child[UN_PATH_MAX];
        int n1 = snprintf(raw_child, sizeof(raw_child), "%s/%s", raw_dir,
                          de->d_name);
        int n2 = snprintf(stage_child, sizeof(stage_child), "%s/%s", stage_dir,
                          de->d_name);
        if (n1 < 0 || (size_t) n1 >= sizeof(raw_child) || n2 < 0 ||
            (size_t) n2 >= sizeof(stage_child)) {
            rc = set_err(err, "assemble: content path overflow", ENAMETOOLONG);
            break;
        }
        struct stat raw_st;
        if (lstat(raw_child, &raw_st) < 0) {
            rc = set_err(err, "assemble: content lstat failed", errno);
            break;
        }
        if (S_ISDIR(raw_st.st_mode)) {
            struct stat dst;
            if (lstat(stage_child, &dst) < 0) {
                if (errno != ENOENT) {
                    rc = set_err(err, "assemble: stage dir stat failed", errno);
                    break;
                }
                if (mkdir(stage_child, 0755) < 0) {
                    rc = set_err(err, "assemble: stage mkdir failed", errno);
                    break;
                }
            } else if (!S_ISDIR(dst.st_mode)) {
                /* Lower-layer non-dir collides with this layer's dir.
                 * Overlay semantics: this layer's dir wins. unlink the
                 * lower entry and create the dir.
                 */
                if (unlink(stage_child) < 0) {
                    rc = set_err(err, "assemble: stage unlink-for-dir failed",
                                 errno);
                    break;
                }
                if (mkdir(stage_child, 0755) < 0) {
                    rc = set_err(err, "assemble: stage mkdir-replace failed",
                                 errno);
                    break;
                }
            }
            if (assembly_walk_content(raw_child, stage_child, err) < 0) {
                rc = -1;
                break;
            }
            continue;
        }
        /* Regular file or symlink (or any other non-directory): unlink
         * any existing destination then copyfile with COPYFILE_CLONE
         * so APFS COW keeps the byte cost flat when raw cache and
         * stage share a volume, and falls back to a byte copy when
         * they do not (default elfuse layout puts the store on the
         * root volume and the stage on a sparsebundle, so the EXDEV
         * fallback is the steady-state path for fresh unpacks until
         * the layouts are unified). Per D8, hardlink relationships
         * from the tar are not reconstructed (each copyfile produces
         * an independent inode). COPYFILE_NOFOLLOW copies a symlink
         * as a symlink instead of following it, matching the stack
         * restore / snapshot calls below; without it a link in the
         * raw cache would pull host target content into the stage.
         */
        struct stat dst;
        if (lstat(stage_child, &dst) == 0) {
            if (oci_rm_recursive(stage_child) < 0) {
                rc = set_err(err, "assemble: unlink dst failed", errno);
                break;
            }
        } else if (errno != ENOENT) {
            rc = set_err(err, "assemble: dst lstat failed", errno);
            break;
        }
        if (copyfile(raw_child, stage_child, NULL,
                     COPYFILE_CLONE | COPYFILE_NOFOLLOW | COPYFILE_ALL) < 0) {
            rc = set_err(err, "assemble: copyfile failed", errno);
            break;
        }
    }
    closedir(d);
    return rc;
}

int oci_unpack_assemble_layer(const char *raw_dir,
                              const char *stage_dir,
                              const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!raw_dir || !stage_dir)
        return set_err(err, "assemble: NULL argument", EINVAL);
    struct stat st;
    if (lstat(raw_dir, &st) < 0 || !S_ISDIR(st.st_mode))
        return set_err(err, "assemble: raw_dir is not a directory", ENOTDIR);
    if (lstat(stage_dir, &st) < 0 || !S_ISDIR(st.st_mode))
        return set_err(err, "assemble: stage_dir is not a directory", ENOTDIR);
    if (assembly_walk_whiteouts(raw_dir, stage_dir, err) < 0)
        return -1;
    if (assembly_walk_content(raw_dir, stage_dir, err) < 0)
        return -1;
    return 0;
}

/* Resolve the manifest digest for ref: prefer ref->digest_str when
 * present, else read the pin file via oci_store_get_ref.
 */
static int resolve_manifest_digest(oci_store_t *store,
                                   const oci_ref_t *ref,
                                   char *out_str,
                                   size_t out_cap,
                                   const char **err)
{
    if (ref->digest && ref->digest[0]) {
        if (strlen(ref->digest) + 1 > out_cap)
            return set_err(err, "unpack: digest string overflow", ENAMETOOLONG);
        memcpy(out_str, ref->digest, strlen(ref->digest) + 1);
        return 0;
    }
    char *pin = NULL;
    const char *perr = NULL;
    if (oci_store_get_ref(store, ref, &pin, &perr) < 0) {
        if (errno == ENOENT)
            return set_err(
                err, "unpack: tag pin missing; run 'elfuse oci pull' first",
                ENOENT);
        return set_err(err, perr ? perr : "unpack: tag pin read failed",
                       errno ? errno : EIO);
    }
    if (strlen(pin) + 1 > out_cap) {
        free(pin);
        return set_err(err, "unpack: pin string overflow", ENAMETOOLONG);
    }
    memcpy(out_str, pin, strlen(pin) + 1);
    free(pin);
    return 0;
}

int oci_unpack(oci_store_t *store,
               const oci_ref_t *ref,
               const oci_unpack_options_t *opts,
               char **out_image_dir,
               const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!store || !ref || !out_image_dir)
        return set_err(err, "unpack: NULL argument", EINVAL);
    *out_image_dir = NULL;

    bool quiet = opts && opts->quiet;
    bool force = opts && opts->force_relayer;

    /* Resolve / provision the sysroot volume. */
    char *volume_root = NULL;
    if (oci_volume_ensure(opts ? opts->volume_root : NULL, &volume_root, err) <
        0)
        return -1;

    /* Ensure images/ and images/.staging/ exist. */
    char *images_dir = NULL;
    char *staging_dir = NULL;
    if (oci_volume_subdir(volume_root, "images", &images_dir, err) < 0)
        goto fail_volume;
    if (oci_volume_subdir(volume_root, "images/.staging", &staging_dir, err) <
        0)
        goto fail_images;

    /* Resolve the manifest digest. */
    char manifest_digest[OCI_DIGEST_HEX_MAX + 16];
    if (resolve_manifest_digest(store, ref, manifest_digest,
                                sizeof(manifest_digest), err) < 0)
        goto fail_staging;

    oci_digest_algo_t algo;
    char manifest_hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(manifest_digest, &algo, manifest_hex))
        return set_err(err, "unpack: manifest digest parse failed", EINVAL);

    /* Read the manifest blob. If it is an image-index, pick linux/arm64
     * and re-read the sub-manifest.
     */
    oci_blob_store_t *bs = oci_store_blobs(store);
    if (!bs) {
        set_err(err, "unpack: blob store unavailable", EIO);
        goto fail_staging;
    }
    uint8_t *body = NULL;
    size_t body_len = 0;
    if (read_blob(bs, algo, manifest_hex, &body, &body_len, err) < 0)
        goto fail_staging;

    oci_manifest_t manifest = {0};
    oci_index_t index = {0};
    const char *perr = NULL;
    char *image_hex = NULL;
    /* Try manifest first; if it fails, try index. */
    if (oci_manifest_parse((const char *) body, body_len, &manifest, &perr) <
        0) {
        memset(&manifest, 0, sizeof(manifest));
        if (oci_index_parse((const char *) body, body_len, &index, &perr) < 0) {
            set_err(err, perr ? perr : "unpack: manifest parse failed", EINVAL);
            free(body);
            goto fail_staging;
        }
        free(body);
        const oci_index_entry_t *pick = oci_index_pick_linux_arm64(&index);
        if (!pick) {
            oci_index_free(&index);
            set_err(err, "unpack: no linux/arm64 entry in image index", ENOENT);
            goto fail_staging;
        }
        char sub_digest[OCI_DIGEST_HEX_MAX + 16];
        if (strlen(pick->desc.digest_str) >= sizeof(sub_digest)) {
            oci_index_free(&index);
            set_err(err, "unpack: sub-manifest digest overflow", ENAMETOOLONG);
            goto fail_staging;
        }
        memcpy(sub_digest, pick->desc.digest_str,
               strlen(pick->desc.digest_str) + 1);
        oci_digest_algo_t sub_algo;
        char sub_hex[OCI_DIGEST_HEX_MAX + 1];
        if (!oci_digest_parse(sub_digest, &sub_algo, sub_hex)) {
            oci_index_free(&index);
            set_err(err, "unpack: sub-manifest digest parse failed", EINVAL);
            goto fail_staging;
        }
        oci_index_free(&index);
        if (read_blob(bs, sub_algo, sub_hex, &body, &body_len, err) < 0)
            goto fail_staging;
        if (oci_manifest_parse((const char *) body, body_len, &manifest,
                               &perr) < 0) {
            set_err(err, perr ? perr : "unpack: sub-manifest parse failed",
                    EINVAL);
            free(body);
            goto fail_staging;
        }
        image_hex = strdup(sub_hex);
    } else {
        image_hex = strdup(manifest_hex);
    }
    free(body);

    if (!image_hex) {
        oci_manifest_free(&manifest);
        set_err(err, "unpack: image hex strdup failed", ENOMEM);
        goto fail_staging;
    }

    /* Final target: <volume>/images/sha256-<hex>/. The directory has
     * '-' instead of ':' to keep the path filesystem-friendly.
     */
    char final_dir[UN_PATH_MAX];
    if ((size_t) snprintf(final_dir, sizeof(final_dir), "%s/sha256-%s",
                          images_dir, image_hex) >= sizeof(final_dir)) {
        free(image_hex);
        oci_manifest_free(&manifest);
        set_err(err, "unpack: final dir overflow", ENAMETOOLONG);
        goto fail_staging;
    }

    struct stat st;
    if (lstat(final_dir, &st) == 0 && !force) {
        /* Idempotent rerun: reuse the existing image sysroot only when
         * its sidecar attests the current OCI_META_VERSION tree layout.
         * Version-1 trees stored absolute symlink targets verbatim
         * (host-escaping); silently reusing one would keep handing the
         * guest a rootfs whose /bin/sh resolves against the host.
         */
        oci_meta_table_t *probe = NULL;
        const char *merr = NULL;
        if (oci_meta_read(final_dir, &probe, &merr) == 0) {
            oci_meta_table_free(probe);
            free(image_hex);
            oci_manifest_free(&manifest);
            size_t want = strlen(final_dir) + 2;
            char *dup = malloc(want);
            if (!dup) {
                set_err(err, "unpack: strdup final path failed", ENOMEM);
                goto fail_staging;
            }
            snprintf(dup, want, "%s/", final_dir);
            *out_image_dir = dup;
            free(staging_dir);
            free(images_dir);
            free(volume_root);
            return 0;
        }
        if (!quiet)
            fprintf(stderr,
                    "elfuse oci unpack: stale image sysroot sha256-%s (%s); "
                    "rebuilding\n",
                    image_hex, merr ? merr : strerror(errno));
        errno = 0;
        force = true; /* fall into the rm + full re-stage path below */
    }
    if (force) {
        /* Remove any prior commit so the staging rename does not race. */
        (void) oci_rm_recursive(final_dir);
    }

    /* Stage under <volume>/images/.staging/<random>/ */
    char stage_id[13];
    if (rand_hex(stage_id, 12) < 0) {
        free(image_hex);
        oci_manifest_free(&manifest);
        set_err(err, "unpack: getentropy failed", errno);
        goto fail_staging;
    }
    char stage_dir[UN_PATH_MAX];
    if ((size_t) snprintf(stage_dir, sizeof(stage_dir), "%s/%s", staging_dir,
                          stage_id) >= sizeof(stage_dir)) {
        free(image_hex);
        oci_manifest_free(&manifest);
        set_err(err, "unpack: stage dir overflow", ENAMETOOLONG);
        goto fail_staging;
    }
    if (oci_mkdir_p(stage_dir) < 0) {
        free(image_hex);
        oci_manifest_free(&manifest);
        set_err(err, "unpack: mkdir stage failed", errno);
        goto fail_staging;
    }

    if (!quiet)
        fprintf(stderr, "elfuse oci unpack: applying %zu layer(s)\n",
                manifest.nlayers);

    /* Read + parse the image-config blob up-front so per-layer diff_ids
     * are available to the cache hook in oci_unpack_layer. The origin
     * sidecar still consumes the same struct later in this
     * function, so the read happens exactly once.
     */
    oci_image_config_t cfg = {0};
    {
        uint8_t *cfg_body = NULL;
        size_t cfg_len = 0;
        if (read_blob(bs, manifest.config.algo, manifest.config.hex, &cfg_body,
                      &cfg_len, err) < 0) {
            free(image_hex);
            oci_manifest_free(&manifest);
            goto fail_stage_dir;
        }
        const char *cparse_err = NULL;
        if (oci_image_config_parse((const char *) cfg_body, cfg_len, &cfg,
                                   &cparse_err) < 0) {
            set_err(
                err,
                cparse_err ? cparse_err : "unpack: image config parse failed",
                EINVAL);
            free(cfg_body);
            free(image_hex);
            oci_manifest_free(&manifest);
            goto fail_stage_dir;
        }
        free(cfg_body);
    }

    /* Validate that diff_ids[] length matches manifest.layers[] length. A
     * mismatch is a malformed image (the OCI image-spec mandates one
     * diff_id per layer in order); fail-fast so the cache never associates
     * a diff_id with the wrong layer payload.
     */
    size_t diff_ids_count = 0;
    if (cfg.rootfs_diff_ids)
        while (cfg.rootfs_diff_ids[diff_ids_count])
            diff_ids_count++;
    if (diff_ids_count != manifest.nlayers) {
        set_err(err, "unpack: image config rootfs.diff_ids count mismatch",
                EINVAL);
        oci_image_config_free(&cfg);
        free(image_hex);
        oci_manifest_free(&manifest);
        goto fail_stage_dir;
    }

    /* Orchestrator state. cum_meta accumulates the running
     * cumulative meta table (uid/gid/mode per guest path); layer_meta
     * is reset to a fresh table at the start of every loop iteration;
     * chains holds the precomputed OCI ChainID strings for every
     * layer so the stack-cache prefix search is one stat(2) per layer.
     */
    oci_meta_table_t *cum_meta = NULL;
    oci_meta_table_t *layer_meta = NULL;
    char (*chains)[OCI_DIGEST_HEX_MAX + 16] = NULL;

    cum_meta = oci_meta_table_new();
    if (!cum_meta) {
        set_err(err, "unpack: meta table alloc failed", ENOMEM);
        goto fail_orch;
    }

    if (manifest.nlayers > 0) {
        chains = malloc(manifest.nlayers * sizeof(*chains));
        if (!chains) {
            set_err(err, "unpack: chain array alloc failed", ENOMEM);
            goto fail_orch;
        }
        const char *prev = NULL;
        for (size_t i = 0; i < manifest.nlayers; i++) {
            if (oci_chainid_compute(prev, cfg.rootfs_diff_ids[i], chains[i],
                                    sizeof(chains[i])) < 0) {
                set_err(err, "unpack: chain compute failed",
                        errno ? errno : EINVAL);
                goto fail_orch;
            }
            prev = chains[i];
        }
    }

    /* Search the stack cache backwards for the longest matching prefix
     * snapshot. On hit, clonefile-restore the assembled stage_dir
     * straight from cache and continue with the trailing layers only.
     * No hit -> stage_dir stays at the empty mkdir_p state and the
     * orchestrator iterates over every layer.
     */
    size_t start_i = 0;
    for (size_t k = manifest.nlayers; k-- > 0;) {
        int hit = oci_store_stack_has(store, chains[k]);
        if (hit < 0) {
            set_err(err, "unpack: stack lookup failed", errno);
            goto fail_orch;
        }
        if (hit != 1)
            continue;
        char stack_dir[UN_PATH_MAX];
        if (oci_store_stack_resolve(store, chains[k], stack_dir,
                                    sizeof(stack_dir)) < 0) {
            set_err(err, "unpack: stack resolve failed", errno);
            goto fail_orch;
        }
        size_t sl = strlen(stack_dir);
        if (sl > 0 && stack_dir[sl - 1] == '/')
            stack_dir[sl - 1] = '\0';
        /* copyfile with COPYFILE_CLONE prefers an APFS clone (cheap
         * COW) and falls back to a recursive byte copy on EXDEV, so
         * stack restore works whether the store and stage share a
         * volume or not. COPYFILE_CLONE implies an exclusive
         * destination; the rm_recursive above prepares an absent
         * target for both code paths.
         */
        if (oci_rm_recursive(stage_dir) < 0) {
            set_err(err, "unpack: stage rm-for-stack failed", errno);
            goto fail_orch;
        }
        if (copyfile(stack_dir, stage_dir, NULL,
                     COPYFILE_CLONE | COPYFILE_RECURSIVE | COPYFILE_NOFOLLOW |
                         COPYFILE_ALL) < 0) {
            int saved = errno;
            set_err(err, "unpack: stack restore copyfile failed", saved);
            goto fail_orch;
        }
        /* Re-load the cumulative meta sidecar the stack snapshot
         * persisted so trailing layers accumulate on top. A sidecar that
         * is missing or does not parse to OCI_META_VERSION marks a
         * snapshot whose TREE predates this elfuse (version 1 stored
         * absolute symlink targets verbatim; restoring such a tree would
         * resurrect host-escaping links). Treat it as a cache miss:
         * retire the stale snapshot so the post-apply commit re-publishes
         * it, reset the stage, and keep probing shorter prefixes.
         */
        oci_meta_table_t *restored = NULL;
        const char *merr = NULL;
        if (oci_meta_read(stage_dir, &restored, &merr) < 0) {
            if (!quiet)
                fprintf(stderr,
                        "elfuse oci unpack: stale stack snapshot for chain "
                        "%zu (%s); rebuilding\n",
                        k + 1, merr ? merr : strerror(errno));
            errno = 0;
            (void) oci_rm_recursive(stack_dir);
            if (oci_rm_recursive(stage_dir) < 0 || oci_mkdir_p(stage_dir) < 0) {
                set_err(err, "unpack: stage reset failed", errno);
                goto fail_orch;
            }
            continue;
        }
        int mrc = oci_meta_merge(cum_meta, restored);
        int saved = errno;
        oci_meta_table_free(restored);
        if (mrc < 0) {
            set_err(err, "unpack: stack meta merge failed", saved);
            goto fail_orch;
        }
        start_i = k + 1;
        if (!quiet)
            fprintf(stderr, "elfuse oci unpack: stack hit at chain %zu/%zu\n",
                    start_i, manifest.nlayers);
        break;
    }

    if (!quiet && manifest.nlayers > 0)
        fprintf(stderr,
                "elfuse oci unpack: applying %zu layer(s) (cache start %zu)\n",
                manifest.nlayers - start_i, start_i);

    for (size_t i = start_i; i < manifest.nlayers; i++) {
        char label[32];
        const char *log_label = NULL;
        if (!quiet) {
            snprintf(label, sizeof(label), "layer %zu", i + 1);
            log_label = label;
        }

        layer_meta = oci_meta_table_new();
        if (!layer_meta) {
            set_err(err, "unpack: layer meta alloc failed", ENOMEM);
            goto fail_orch;
        }

        const char *diff_id = cfg.rootfs_diff_ids[i];
        char raw_cache_dir[UN_PATH_MAX];
        int raw_hit = oci_store_layer_has(store, diff_id);
        if (raw_hit < 0) {
            set_err(err, "unpack: raw cache lookup failed", errno);
            goto fail_orch;
        }
        if (raw_hit == 1) {
            if (oci_store_layer_resolve(store, diff_id, raw_cache_dir,
                                        sizeof(raw_cache_dir)) < 0) {
                set_err(err, "unpack: raw cache resolve failed", errno);
                goto fail_orch;
            }
            size_t rl = strlen(raw_cache_dir);
            if (rl > 0 && raw_cache_dir[rl - 1] == '/')
                raw_cache_dir[rl - 1] = '\0';
            /* Load the per-layer sidecar so cum_meta picks up the
             * uid/gid/mode entries the cache writer recorded at populate
             * time. Missing or pre-OCI_META_VERSION sidecars mark a raw
             * tree extracted before the absolute-symlink rewrite; drop
             * the stale entry and fall through to the re-extract path.
             */
            oci_meta_table_t *loaded = NULL;
            const char *merr = NULL;
            if (oci_meta_read_named(raw_cache_dir, UN_RAW_META_SIDECAR, &loaded,
                                    &merr) < 0) {
                if (!quiet)
                    fprintf(stderr,
                            "elfuse oci unpack: stale raw cache for %s (%s); "
                            "re-extracting\n",
                            manifest.layers[i].digest_str,
                            merr ? merr : strerror(errno));
                errno = 0;
                (void) oci_rm_recursive(raw_cache_dir);
                raw_hit = 0;
            } else {
                oci_meta_table_free(layer_meta);
                layer_meta = loaded;
            }
            if (raw_hit == 1 && log_label)
                fprintf(stderr, "  %s: %s (raw cached)\n", log_label,
                        manifest.layers[i].digest_str);
        }
        if (raw_hit != 1) {
            char raw_stage[UN_PATH_MAX];
            if (oci_store_layer_stage_path(store, diff_id, raw_stage,
                                           sizeof(raw_stage)) < 0) {
                set_err(err, "unpack: raw stage_path resolve failed", errno);
                goto fail_orch;
            }
            if (mkdir(raw_stage, 0755) < 0) {
                set_err(err, "unpack: raw stage mkdir failed", errno);
                goto fail_orch;
            }
            if (oci_unpack_layer_raw(bs, &manifest.layers[i], raw_stage, NULL,
                                     layer_meta, log_label, err) < 0) {
                (void) oci_rm_recursive(raw_stage);
                goto fail_orch;
            }
            const char *mwerr = NULL;
            if (oci_meta_write_named(layer_meta, raw_stage, UN_RAW_META_SIDECAR,
                                     &mwerr) < 0) {
                set_err(err, mwerr ? mwerr : "unpack: raw meta write failed",
                        errno);
                (void) oci_rm_recursive(raw_stage);
                goto fail_orch;
            }
            const char *cerr = NULL;
            if (oci_store_layer_commit(store, raw_stage, diff_id, &cerr) < 0) {
                int saved = errno;
                set_err(err, cerr ? cerr : "unpack: raw cache commit failed",
                        saved);
                (void) oci_rm_recursive(raw_stage);
                goto fail_orch;
            }
            if (oci_store_layer_resolve(store, diff_id, raw_cache_dir,
                                        sizeof(raw_cache_dir)) < 0) {
                set_err(err, "unpack: raw cache resolve failed", errno);
                goto fail_orch;
            }
            size_t rl = strlen(raw_cache_dir);
            if (rl > 0 && raw_cache_dir[rl - 1] == '/')
                raw_cache_dir[rl - 1] = '\0';
        }

        if (oci_unpack_assemble_layer(raw_cache_dir, stage_dir, err) < 0)
            goto fail_orch;

        int mrc = oci_meta_merge(cum_meta, layer_meta);
        int saved_errno = errno;
        oci_meta_table_free(layer_meta);
        layer_meta = NULL;
        if (mrc < 0) {
            set_err(err, "unpack: cum meta merge failed", saved_errno);
            goto fail_orch;
        }

        /* Snapshot stage_dir into the per-prefix stack cache so future
         * unpacks sharing this chain prefix short-circuit. Failure here
         * is fatal: silently degrading the cache would defeat the
         * dedup path.
         */
        if (oci_meta_write(cum_meta, stage_dir, err) < 0)
            goto fail_orch;
        char stack_stage[UN_PATH_MAX];
        if (oci_store_stack_stage_path(store, chains[i], stack_stage,
                                       sizeof(stack_stage)) < 0) {
            set_err(err, "unpack: stack stage_path resolve failed", errno);
            goto fail_orch;
        }
        /* Same copyfile + COPYFILE_CLONE rationale as the stack
         * restore: prefer APFS clone, fall back to recursive byte
         * copy on EXDEV so the cache populates regardless of which
         * volume holds the stage.
         */
        if (copyfile(stage_dir, stack_stage, NULL,
                     COPYFILE_CLONE | COPYFILE_RECURSIVE | COPYFILE_NOFOLLOW |
                         COPYFILE_ALL) < 0) {
            int saved = errno;
            set_err(err, "unpack: stack snapshot copyfile failed", saved);
            goto fail_orch;
        }
        const char *scerr = NULL;
        if (oci_store_stack_commit(store, stack_stage, chains[i], &scerr) < 0) {
            int saved = errno;
            (void) oci_rm_recursive(stack_stage);
            set_err(err, scerr ? scerr : "unpack: stack commit failed", saved);
            goto fail_orch;
        }
    }

    /* The per-iteration writes already produced an up-to-date sidecar
     * on disk. On the full-stack-hit path (no iterations ran) the
     * clonefile-restored stage_dir also already carries the snapshot's
     * sidecar, so a final write would only re-emit identical bytes.
     */
    oci_meta_table_free(cum_meta);
    cum_meta = NULL;
    free(chains);
    chains = NULL;

    /* Origin sidecar: records manifest_digest + config_digest + diff_ids
     * the garbage collector's keep-set walker reads. A failure here aborts the
     * commit because a missing origin file would let prune silently delete
     * layer blobs still backing this unpacked tree.
     */
    {
        char manifest_full[OCI_DIGEST_HEX_MAX + 16];
        if ((size_t) snprintf(manifest_full, sizeof(manifest_full), "sha256:%s",
                              image_hex) >= sizeof(manifest_full)) {
            oci_image_config_free(&cfg);
            set_err(err, "unpack: manifest digest overflow", ENAMETOOLONG);
            free(image_hex);
            oci_manifest_free(&manifest);
            goto fail_stage_dir;
        }

        const char *origin_err = NULL;
        if (oci_origin_write(stage_dir, manifest_full,
                             manifest.config.digest_str, cfg.rootfs_diff_ids,
                             &origin_err) < 0) {
            set_err(err,
                    origin_err ? origin_err : "unpack: origin write failed",
                    errno ? errno : EIO);
            oci_image_config_free(&cfg);
            free(image_hex);
            oci_manifest_free(&manifest);
            goto fail_stage_dir;
        }
    }
    oci_image_config_free(&cfg);

    oci_manifest_free(&manifest);

    /* Atomic commit. */
    if (rename(stage_dir, final_dir) < 0) {
        set_err(err, "unpack: stage rename failed", errno);
        free(image_hex);
        goto fail_stage_dir;
    }
    free(image_hex);

    size_t want = strlen(final_dir) + 2;
    char *dup = malloc(want);
    if (!dup) {
        set_err(err, "unpack: strdup final path failed", ENOMEM);
        goto fail_staging;
    }
    snprintf(dup, want, "%s/", final_dir);
    *out_image_dir = dup;

    free(staging_dir);
    free(images_dir);
    free(volume_root);
    return 0;

fail_orch:
    oci_meta_table_free(layer_meta);
    oci_meta_table_free(cum_meta);
    free(chains);
    oci_image_config_free(&cfg);
    free(image_hex);
    oci_manifest_free(&manifest);
fail_stage_dir:
    (void) oci_rm_recursive(stage_dir);
fail_staging:
    free(staging_dir);
fail_images:
    free(images_dir);
fail_volume:
    free(volume_root);
    return -1;
}
