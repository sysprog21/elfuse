/* OCI per-run rootfs via clonefile(2)
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
#include <sys/clonefile.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oci/clone-rootfs.h"
#include "oci/util.h"

#define CR_PATH_MAX 4096

static int rand_hex(char *out, size_t n_hex)
{
    /* n_hex is the number of hex chars in the output; the helper reads
     * n_hex/2 random bytes from getentropy and prints them.
     */
    size_t need = n_hex / 2;
    uint8_t buf[32];
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

int oci_clone_rootfs(const char *src_image_dir,
                     const char *volume_root,
                     char **out_run_dir,
                     const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!src_image_dir || !volume_root || !out_run_dir)
        return set_err(err, "clone: NULL argument", EINVAL);
    *out_run_dir = NULL;

    /* Image dir must exist and be a directory. */
    struct stat sb;
    if (stat(src_image_dir, &sb) < 0)
        return set_err(err, "clone: src image stat failed", errno);
    if (!S_ISDIR(sb.st_mode))
        return set_err(err, "clone: src image is not a directory", ENOTDIR);

    /* Provision volume_root/runs/. */
    char runs_dir[CR_PATH_MAX];
    if ((size_t) snprintf(runs_dir, sizeof(runs_dir), "%s/runs", volume_root) >=
        sizeof(runs_dir))
        return set_err(err, "clone: runs path overflow", ENAMETOOLONG);
    if (oci_mkdir_p(runs_dir) < 0)
        return set_err(err, "clone: cannot create runs dir", errno);

    /* Pick a fresh run id. 12 hex chars = 48 bits of randomness; ample
     * for elfuse process lifetimes.
     */
    char id[13];
    if (rand_hex(id, 12) < 0)
        return set_err(err, "clone: getentropy failed", errno);

    char run_dir[CR_PATH_MAX];
    if ((size_t) snprintf(run_dir, sizeof(run_dir), "%s/%s", runs_dir, id) >=
        sizeof(run_dir))
        return set_err(err, "clone: run path overflow", ENAMETOOLONG);

    /* clonefile creates the destination atomically: pass dst that does
     * NOT exist (the call itself creates the directory). Use
     * CLONE_NOFOLLOW so a symlink at the src root is not followed off
     * the immutable image.
     */
    if (clonefile(src_image_dir, run_dir, CLONE_NOFOLLOW) < 0)
        return set_err(err, "clone: clonefile failed", errno);

    char *dup = strdup(run_dir);
    if (!dup) {
        /* Roll back the clone so the caller sees no half-state. */
        (void) oci_clone_rootfs_remove(run_dir, NULL);
        return set_err(err, "clone: strdup failed", ENOMEM);
    }
    *out_run_dir = dup;
    return 0;
}

int oci_clone_rootfs_remove(const char *run_dir, const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!run_dir)
        return set_err(err, "clone remove: NULL path", EINVAL);

    struct stat st;
    if (lstat(run_dir, &st) < 0) {
        if (errno == ENOENT)
            return 0;
        return set_err(err, "clone remove: lstat failed", errno);
    }
    if (!S_ISDIR(st.st_mode)) {
        if (unlink(run_dir) < 0)
            return set_err(err, "clone remove: unlink failed", errno);
        return 0;
    }
    DIR *d = opendir(run_dir);
    if (!d)
        return set_err(err, "clone remove: opendir failed", errno);
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char child[CR_PATH_MAX];
        if ((size_t) snprintf(child, sizeof(child), "%s/%s", run_dir,
                              de->d_name) >= sizeof(child)) {
            rc = -1;
            errno = ENAMETOOLONG;
            break;
        }
        if (oci_clone_rootfs_remove(child, NULL) < 0) {
            rc = -1;
            break;
        }
    }
    closedir(d);
    if (rc == 0 && rmdir(run_dir) < 0)
        return set_err(err, "clone remove: rmdir failed", errno);
    return rc;
}

int oci_clone_rootfs_gc(const char *volume_root,
                        time_t older_than,
                        const char **err)
{
    (void) volume_root;
    (void) older_than;
    if (err)
        *err = NULL;
    /* Stub: `elfuse oci prune` does not yet sweep stale runs. A future
     * change will walk volume_root/runs/ and unlink entries older than
     * older_than. The stub returns 0 so the CLI can call it
     * unconditionally without a feature gate.
     */
    return 0;
}
