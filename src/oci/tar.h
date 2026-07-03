/* OCI tar reader (libarchive-backed: ustar, GNU long-name, PAX)
 *
 * Streams tar entries out of a generic byte source. Format and filter
 * work is delegated to libarchive (see tar.c), which also auto-detects
 * gzip / zstd / uncompressed layer blobs, so callers feed the raw blob
 * byte stream into the read callback with no separate decompress
 * stage. The applier in oci/layer-apply.c walks entries in order,
 * dispatching by oci_tar_type_t.
 *
 * Block, char, fifo, and socket entries collapse to OCI_TAR_UNSUPPORTED
 * so the applier can emit a precise refusal without re-decoding the
 * typeflag.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
    OCI_TAR_REG,
    OCI_TAR_DIR,
    OCI_TAR_SYMLINK,
    OCI_TAR_HARDLINK,
    OCI_TAR_UNSUPPORTED,
} oci_tar_type_t;

typedef struct {
    /* path and linkname are owned by the reader and remain valid until
     * the next oci_tar_next call. They are const to the caller: the backing
     * storage belongs to the reader, so callers must not mutate it, and any
     * value kept past the next iteration must be duplicated.
     */
    const char *path;
    const char *linkname;
    uint64_t size;
    uint32_t mode;
    uint64_t uid;
    uint64_t gid;
    uint64_t mtime;
    oci_tar_type_t type;
    bool is_whiteout;
    bool is_opaque_whiteout;
} oci_tar_entry_t;

/* Byte source callback. Returns >=0 bytes read into buf (0 means EOF)
 * or -1 on I/O error with errno set. Short reads are tolerated; the
 * reader retries until a full 512-byte block is available.
 */
typedef ssize_t (*oci_tar_read_fn)(void *ctx, void *buf, size_t cap);

typedef struct oci_tar_reader oci_tar_reader_t;

oci_tar_reader_t *oci_tar_reader_new(oci_tar_read_fn read_fn, void *ctx);
void oci_tar_reader_free(oci_tar_reader_t *r);

/* Pull the next header.
 *   returns 1: entry populated; payload available via read or skip
 *   returns 0: clean EOF (two zero blocks or stream end)
 *   returns -1: protocol or I/O error; *err points to a static string
 *
 * Caller must call exactly one of oci_tar_read_payload or
 * oci_tar_skip_payload (or read until *got == 0) before the next
 * oci_tar_next so the reader can realign to the next 512-byte block.
 */
int oci_tar_next(oci_tar_reader_t *r, oci_tar_entry_t *out, const char **err);

/* Copy up to cap bytes of the current entry's payload into buf.
 * Returns 0 on success; *got carries the byte count (0 once the
 * payload is exhausted). Returns -1 on read error with *err set.
 */
int oci_tar_read_payload(oci_tar_reader_t *r,
                         void *buf,
                         size_t cap,
                         size_t *got,
                         const char **err);

/* Discard the rest of the current entry's payload plus its 512-byte
 * block padding so the next oci_tar_next sees a fresh header.
 */
int oci_tar_skip_payload(oci_tar_reader_t *r, const char **err);
