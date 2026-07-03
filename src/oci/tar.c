/* OCI tar reader — libarchive adapter
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Thin pull-based adapter that keeps the oci_tar_reader_t streaming
 * interface (a read callback feeding oci_tar_next / payload calls, as
 * consumed by oci/layer-apply.c) while delegating all format work —
 * ustar, GNU long-name, PAX — to libarchive. Decompression rides along:
 * gzip, zstd, and uncompressed layer blobs are auto-detected by
 * libarchive's filter probe, so callers hand the raw blob byte stream
 * straight to the read callback with no separate decompress stage.
 *
 * Only the OCI-relevant entry kinds surface: regular files, dirs,
 * symlinks, and hardlinks. Block, char, fifo, and socket entries
 * collapse to OCI_TAR_UNSUPPORTED so the applier can emit a precise
 * refusal without re-decoding the typeflag.
 */

#include "oci/tar.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <archive.h>
#include <archive_entry.h>

/* One filesystem-page-ish gulp per callback round trip: large enough to
 * amortize the indirection, small enough to keep the reader allocation
 * trivial.
 */
#define TAR_READ_CHUNK (64 * 1024)

struct oci_tar_reader {
    struct archive *a;
    oci_tar_read_fn read_fn;
    void *ctx;
    bool opened;
    char buf[TAR_READ_CHUNK];
};

static la_ssize_t la_read_cb(struct archive *a, void *ctx, const void **out)
{
    oci_tar_reader_t *r = ctx;
    ssize_t n = r->read_fn(r->ctx, r->buf, sizeof(r->buf));
    if (n < 0) {
        archive_set_error(a, errno ? errno : EIO, "source read failed");
        return ARCHIVE_FATAL;
    }
    *out = r->buf;
    return (la_ssize_t) n;
}

static void apply_whiteout_flags(oci_tar_entry_t *e)
{
    e->is_whiteout = false;
    e->is_opaque_whiteout = false;
    if (!e->path)
        return;
    const char *slash = strrchr(e->path, '/');
    const char *base = slash ? slash + 1 : e->path;
    if (strcmp(base, ".wh..wh..opq") == 0)
        e->is_opaque_whiteout = true;
    else if (strncmp(base, ".wh.", 4) == 0)
        e->is_whiteout = true;
}

oci_tar_reader_t *oci_tar_reader_new(oci_tar_read_fn read_fn, void *ctx)
{
    if (!read_fn)
        return NULL;
    oci_tar_reader_t *r = calloc(1, sizeof(*r));
    if (!r)
        return NULL;
    r->read_fn = read_fn;
    r->ctx = ctx;
    r->a = archive_read_new();
    if (!r->a) {
        free(r);
        return NULL;
    }
    /* The two compressions the OCI image spec admits plus passthrough;
     * archive_read's probe picks per stream, so media-type dispatch is
     * unnecessary. Format tar covers ustar, GNU extensions, and PAX.
     */
    archive_read_support_filter_gzip(r->a);
    archive_read_support_filter_zstd(r->a);
    archive_read_support_filter_none(r->a);
    archive_read_support_format_tar(r->a);
    return r;
}

void oci_tar_reader_free(oci_tar_reader_t *r)
{
    if (!r)
        return;
    if (r->a)
        archive_read_free(r->a);
    free(r);
}

static const char *la_err(oci_tar_reader_t *r)
{
    const char *msg = archive_error_string(r->a);
    return msg ? msg : "tar: libarchive error";
}

int oci_tar_next(oci_tar_reader_t *r, oci_tar_entry_t *out, const char **err)
{
    if (!r || !out) {
        if (err)
            *err = "tar: NULL argument";
        errno = EINVAL;
        return -1;
    }

    if (!r->opened) {
        if (archive_read_open2(r->a, r, NULL, la_read_cb, NULL, NULL) !=
            ARCHIVE_OK) {
            if (err)
                *err = la_err(r);
            errno = archive_errno(r->a) ? archive_errno(r->a) : EIO;
            return -1;
        }
        r->opened = true;
    }

    struct archive_entry *ae = NULL;
    int rc = archive_read_next_header(r->a, &ae);
    if (rc == ARCHIVE_EOF)
        return 0;
    if (rc < ARCHIVE_WARN) {
        if (err)
            *err = la_err(r);
        errno = archive_errno(r->a) ? archive_errno(r->a) : EPROTO;
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->path = archive_entry_pathname(ae);
    if (!out->path || !out->path[0]) {
        if (err)
            *err = "tar: entry with empty name";
        errno = EPROTO;
        return -1;
    }
    /* archive_entry_size returns -1 when the size is unknown; casting
     * that straight to uint64_t would turn it into UINT64_MAX and make
     * the regular-file copy loop run to EOF before noticing truncation.
     */
    int64_t entry_size = (int64_t) archive_entry_size(ae);
    if (entry_size < 0) {
        if (err)
            *err = "tar: entry with negative or unknown size";
        errno = EPROTO;
        return -1;
    }
    out->size = (uint64_t) entry_size;
    out->mode = (uint32_t) archive_entry_perm(ae);
    out->uid = (uint64_t) archive_entry_uid(ae);
    out->gid = (uint64_t) archive_entry_gid(ae);
    out->mtime = (uint64_t) archive_entry_mtime(ae);

    /* Hardlinks may carry any filetype in the header; the linkname
     * being set is the discriminator, mirroring tar's typeflag '1'.
     */
    const char *hard = archive_entry_hardlink(ae);
    if (hard) {
        out->type = OCI_TAR_HARDLINK;
        out->linkname = hard;
    } else {
        switch (archive_entry_filetype(ae)) {
        case AE_IFREG:
            out->type = OCI_TAR_REG;
            break;
        case AE_IFDIR:
            out->type = OCI_TAR_DIR;
            break;
        case AE_IFLNK:
            out->type = OCI_TAR_SYMLINK;
            out->linkname = archive_entry_symlink(ae);
            break;
        default:
            out->type = OCI_TAR_UNSUPPORTED;
            break;
        }
    }
    apply_whiteout_flags(out);
    return 1;
}

int oci_tar_read_payload(oci_tar_reader_t *r,
                         void *buf,
                         size_t cap,
                         size_t *got,
                         const char **err)
{
    if (!r || !buf || !got) {
        if (err)
            *err = "tar: NULL argument";
        errno = EINVAL;
        return -1;
    }
    la_ssize_t n = archive_read_data(r->a, buf, cap);
    if (n < 0) {
        if (err)
            *err = la_err(r);
        errno = archive_errno(r->a) ? archive_errno(r->a) : EIO;
        return -1;
    }
    *got = (size_t) n;
    return 0;
}

int oci_tar_skip_payload(oci_tar_reader_t *r, const char **err)
{
    if (!r) {
        if (err)
            *err = "tar: NULL argument";
        errno = EINVAL;
        return -1;
    }
    if (archive_read_data_skip(r->a) != ARCHIVE_OK) {
        if (err)
            *err = la_err(r);
        errno = archive_errno(r->a) ? archive_errno(r->a) : EIO;
        return -1;
    }
    return 0;
}
