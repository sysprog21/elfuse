/* OCI sysroot volume enumeration implementation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Sibling of volume.c. The split keeps the read-only directory walker
 * (used by garbage collection and status reporting) free of the
 * sparsebundle / case-sensitivity provisioning chain pulled in
 * by oci_volume_ensure. That chain depends on core/sysroot.o, hdiutil,
 * and the host-side log subsystem; the GC enumerator only needs
 * opendir / lstat. Putting them in the same translation unit would
 * force every store-linking test binary to pull in the whole sysroot
 * stack just to walk a directory.
 */

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "oci/volume.h"
#include "oci/util.h"

/* True when name has the shape "sha256-<64-lowercase-hex>". The unpack
 * orchestrator at src/oci/unpack.c writes the final tree under exactly
 * this pattern; anything else under images/ (an alien tool's checkout,
 * a half-renamed staging dir, a dotfile) is ignored.
 */
static bool name_is_sha256_dir(const char *name)
{
    if (!name)
        return false;
    static const char PREFIX[] = "sha256-";
    static const size_t PREFIX_LEN = sizeof(PREFIX) - 1;
    if (strncmp(name, PREFIX, PREFIX_LEN) != 0)
        return false;
    const char *hex = name + PREFIX_LEN;
    size_t hex_len = 0;
    for (const char *p = hex; *p; p++, hex_len++) {
        char c = *p;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return hex_len == 64;
}

static int append_path(oci_volume_list_t *list,
                       size_t *cap,
                       char *path,
                       const char **err)
{
    if (list->count == *cap) {
        size_t newcap = *cap ? *cap * 2 : 8;
        void *raw = realloc((void *) list->items, newcap * sizeof(char *));
        if (!raw) {
            free(path);
            return set_err(err, "volume list: items realloc failed", ENOMEM);
        }
        list->items = (char **) raw;
        *cap = newcap;
    }
    list->items[list->count++] = path;
    return 0;
}

int oci_volume_list_unpacked(const char *volume_root,
                             oci_volume_list_t *out,
                             const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!volume_root || !out)
        return set_err(err, "volume list: NULL argument", EINVAL);
    out->items = NULL;
    out->count = 0;

    /* Resolve <volume_root>/images. A missing directory is the
     * fresh-store case (nothing has been unpacked yet); return an
     * empty list without surfacing as an error so the garbage
     * collector can still walk pin roots in that state.
     */
    size_t want = strlen(volume_root) + sizeof("/images");
    char *images_dir = malloc(want);
    if (!images_dir)
        return set_err(err, "volume list: path alloc failed", ENOMEM);
    snprintf(images_dir, want, "%s/images", volume_root);

    DIR *dp = opendir(images_dir);
    if (!dp) {
        int saved = errno;
        if (saved == ENOENT) {
            free(images_dir);
            return 0;
        }
        free(images_dir);
        return set_err(err, "volume list: opendir failed", saved);
    }

    size_t cap = 0;
    struct dirent *de;
    int rc = 0;
    for (;;) {
        /* Clear errno before each readdir so a NULL return can be classified
         * as EOF (errno unchanged) versus a read error (errno set) below.
         */
        errno = 0;
        de = readdir(dp);
        if (!de)
            break;
        const char *name = de->d_name;
        if (!name_is_sha256_dir(name))
            continue;
        size_t plen = strlen(images_dir) + 1 + strlen(name) + 1;
        char *child = malloc(plen);
        if (!child) {
            rc = set_err(err, "volume list: child alloc failed", ENOMEM);
            break;
        }
        snprintf(child, plen, "%s/%s", images_dir, name);
        struct stat st;
        if (lstat(child, &st) < 0) {
            int saved = errno;
            free(child);
            rc = set_err(err, "volume list: lstat failed", saved);
            break;
        }
        if (!S_ISDIR(st.st_mode)) {
            free(child);
            continue;
        }
        if (append_path(out, &cap, child, err) < 0) {
            rc = -1;
            break;
        }
    }
    /* readdir returns NULL on both EOF and error; a non-zero errno after the
     * loop (and no earlier failure) means the directory read aborted partway,
     * which must not be reported as a complete, empty-tail listing.
     */
    if (rc == 0 && errno != 0)
        rc = set_err(err, "volume list: readdir failed", errno);
    closedir(dp);
    free(images_dir);
    if (rc < 0) {
        oci_volume_list_free(out);
        return -1;
    }
    return 0;
}

void oci_volume_list_free(oci_volume_list_t *list)
{
    if (!list)
        return;
    if (list->items) {
        for (size_t i = 0; i < list->count; i++)
            free(list->items[i]);
        free((void *) list->items);
    }
    list->items = NULL;
    list->count = 0;
}
