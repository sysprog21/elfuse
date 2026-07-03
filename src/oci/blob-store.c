/* Content-addressable blob store for OCI image data
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The commit path uses link(2) rather than rename(2) so that a second writer
 * racing on the same digest cannot silently overwrite a blob that another
 * process already finalized. link returning EEXIST is treated as a dedup
 * hit; both clients then unlink their staging file and report success. This
 * matches the content-addressable invariant: identical bytes map to one
 * inode, regardless of how many concurrent writers raced to produce them.
 */

#include "blob-store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "digest.h"
#include "util.h"

/* Largest path the store will materialize. Comfortably above PATH_MAX so
 * snprintf truncation never silently corrupts a path; callers that pass an
 * out_size smaller than this can still recover via the returned length.
 */
#define STORE_PATH_MAX 4096

struct oci_blob_store {
    char *root;
};

static int join2(char *out, size_t out_size, const char *a, const char *b)
{
    int n = snprintf(out, out_size, "%s/%s", a, b);
    if (n < 0 || (size_t) n >= out_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return n;
}

static int ensure_layout(const char *root)
{
    char path[STORE_PATH_MAX];
    if (oci_mkdir_p(root) < 0)
        return -1;
    if (join2(path, sizeof(path), root, "blobs") < 0 || oci_mkdir_p(path) < 0)
        return -1;
    if (join2(path, sizeof(path), root, "tmp") < 0 || oci_mkdir_p(path) < 0)
        return -1;

    static const char *const algos[] = {"sha256", "sha512"};
    for (size_t i = 0; i < sizeof(algos) / sizeof(algos[0]); i++) {
        int n = snprintf(path, sizeof(path), "%s/blobs/%s", root, algos[i]);
        if (n < 0 || (size_t) n >= sizeof(path)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        if (oci_mkdir_p(path) < 0)
            return -1;
    }
    return 0;
}

oci_blob_store_t *oci_blob_store_open(const char *root)
{
    if (!root || !*root) {
        errno = EINVAL;
        return NULL;
    }
    if (ensure_layout(root) < 0)
        return NULL;

    oci_blob_store_t *s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->root = strdup(root);
    if (!s->root) {
        free(s);
        return NULL;
    }
    return s;
}

void oci_blob_store_close(oci_blob_store_t *s)
{
    if (!s)
        return;
    free(s->root);
    free(s);
}

int oci_blob_store_path(const oci_blob_store_t *s,
                        oci_digest_algo_t algo,
                        const char *hex,
                        char *out,
                        size_t out_size)
{
    if (!s || !out || out_size == 0) {
        if (out && out_size)
            out[0] = '\0';
        return -1;
    }
    const char *name = oci_digest_algo_name(algo);
    if (!name || !oci_digest_hex_valid(algo, hex)) {
        out[0] = '\0';
        return -1;
    }
    int n = snprintf(out, out_size, "%s/blobs/%s/%s", s->root, name, hex);
    if (n < 0) {
        out[0] = '\0';
        return -1;
    }
    return n;
}

bool oci_blob_store_has(const oci_blob_store_t *s,
                        oci_digest_algo_t algo,
                        const char *hex)
{
    char path[STORE_PATH_MAX];
    int n = oci_blob_store_path(s, algo, hex, path, sizeof(path));
    if (n < 0 || (size_t) n >= sizeof(path))
        return false;
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static void fsync_parent_dir(const char *path)
{
    const char *slash = strrchr(path, '/');
    char dir[STORE_PATH_MAX];
    if (!slash) {
        dir[0] = '.';
        dir[1] = '\0';
    } else if (slash == path) {
        dir[0] = '/';
        dir[1] = '\0';
    } else {
        size_t n = (size_t) (slash - path);
        if (n >= sizeof(dir))
            return;
        memcpy(dir, path, n);
        dir[n] = '\0';
    }
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0)
        return;
    (void) fsync(dfd);
    (void) close(dfd);
}

/* Whole-buffer store: hash, verify against expected_hex, stage under
 * tmp/ via mkstemp, fsync, publish via link(2). The streaming /
 * resumable writer this store once carried existed for the in-tree
 * registry client's interrupted downloads; skopeo owns blob transfer
 * now, so the store only writes its own small documents (manifests,
 * configs) and test fixtures -- always whole buffers.
 */
int oci_blob_store_put_bytes(oci_blob_store_t *s,
                             oci_digest_algo_t algo,
                             const char *expected_hex,
                             const void *buf,
                             size_t len)
{
    if (!s || !oci_digest_hex_valid(algo, expected_hex) || (!buf && len > 0)) {
        errno = EINVAL;
        return -1;
    }

    char got_hex[OCI_DIGEST_HEX_MAX + 1];
    oci_digester_t *d = oci_digester_new(algo);
    if (!d)
        return -1;
    oci_digester_update(d, buf, len);
    if (oci_digester_finish_hex(d, got_hex) == 0) {
        oci_digester_free(d);
        errno = EIO;
        return -1;
    }
    oci_digester_free(d);
    if (strcmp(got_hex, expected_hex) != 0) {
        errno = EINVAL;
        return -1;
    }

    char tmp_path[STORE_PATH_MAX];
    int n =
        snprintf(tmp_path, sizeof(tmp_path), "%s/tmp/blob-put-XXXXXX", s->root);
    if (n < 0 || (size_t) n >= sizeof(tmp_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = mkstemp(tmp_path);
    if (fd < 0)
        return -1;
    (void) fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (fchmod(fd, 0644) < 0)
        goto fail_fd;

    const char *p = buf;
    size_t left = len;
    while (left > 0) {
        ssize_t wrote = write(fd, p, left);
        if (wrote < 0) {
            if (errno == EINTR)
                continue;
            goto fail_fd;
        }
        p += wrote;
        left -= (size_t) wrote;
    }
    if (fsync(fd) < 0 || close(fd) < 0) {
        fd = -1;
        goto fail_fd;
    }
    fd = -1;

    char final_path[STORE_PATH_MAX];
    n = oci_blob_store_path(s, algo, expected_hex, final_path,
                            sizeof(final_path));
    if (n < 0 || (size_t) n >= sizeof(final_path)) {
        (void) unlink(tmp_path);
        errno = ENAMETOOLONG;
        return -1;
    }

    if (link(tmp_path, final_path) < 0 && errno != EEXIST) {
        /* EEXIST is a dedup hit: identical bytes already finalized. */
        int saved = errno;
        (void) unlink(tmp_path);
        errno = saved;
        return -1;
    }
    /* Persist the directory entry just created by link(2); without this
     * a crash can leave the blob's data on disk but unreferenced.
     */
    fsync_parent_dir(final_path);
    (void) unlink(tmp_path);
    return 0;

fail_fd:;
    int saved = errno;
    if (fd >= 0)
        (void) close(fd);
    (void) unlink(tmp_path);
    errno = saved;
    return -1;
}
