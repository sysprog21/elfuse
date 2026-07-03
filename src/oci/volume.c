/* OCI sysroot volume provisioning implementation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "core/sysroot.h"
#include "oci/volume.h"
#include "oci/util.h"

/* The default sparsebundle stays mounted across multiple oci subcommand
 * invocations within one elfuse process. OCI subcommands are short
 * lived; a long-running daemon would extend this to track refcount and
 * detach on idle.
 */
static pthread_mutex_t g_volume_lock = PTHREAD_MUTEX_INITIALIZER;
static sysroot_mount_t g_volume_mount;
static bool g_volume_ready;

static int default_volume_path(char *out, size_t cap, const char **err)
{
    const char *home = getenv("HOME");
    if (!home || home[0] == '\0')
        return set_err(err, "volume: $HOME not set", EINVAL);
    int n = snprintf(out, cap, "%s/Library/Application Support/elfuse/sysroots",
                     home);
    if (n < 0 || (size_t) n >= cap)
        return set_err(err, "volume: default path overflow", ENAMETOOLONG);
    return 0;
}

static int provision_default(char **out_volume_root, const char **err)
{
    pthread_mutex_lock(&g_volume_lock);
    if (g_volume_ready) {
        char *dup = strdup(g_volume_mount.mount_path);
        pthread_mutex_unlock(&g_volume_lock);
        if (!dup)
            return set_err(err, "volume: strdup failed", ENOMEM);
        *out_volume_root = dup;
        return 0;
    }

    char path[1024];
    if (default_volume_path(path, sizeof(path), err) < 0) {
        pthread_mutex_unlock(&g_volume_lock);
        return -1;
    }
    if (sysroot_create_mount(path, &g_volume_mount) < 0) {
        pthread_mutex_unlock(&g_volume_lock);
        return set_err(err, "volume: sysroot_create_mount failed", errno);
    }
    g_volume_ready = true;
    char *dup = strdup(g_volume_mount.mount_path);
    pthread_mutex_unlock(&g_volume_lock);
    if (!dup)
        return set_err(err, "volume: strdup failed", ENOMEM);
    *out_volume_root = dup;
    return 0;
}

int oci_volume_ensure(const char *override_dir,
                      char **out_volume_root,
                      const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!out_volume_root)
        return set_err(err, "volume: NULL out param", EINVAL);
    *out_volume_root = NULL;

    if (!override_dir)
        return provision_default(out_volume_root, err);

    /* Override must exist and be case-sensitive. The probe also
     * validates that the path is reachable; non-existence surfaces as
     * the probe's own errno (typically ENOENT).
     */
    struct stat st;
    if (stat(override_dir, &st) < 0)
        return set_err(err, "volume: override path stat failed", errno);
    if (!S_ISDIR(st.st_mode))
        return set_err(err, "volume: override path is not a directory",
                       ENOTDIR);

    bool case_sensitive = false;
    bool case_preserving = false;
    if (sysroot_probe_case_sensitivity(override_dir, &case_sensitive,
                                       &case_preserving) < 0)
        return set_err(err, "volume: case-sensitivity probe failed", errno);
    if (!case_sensitive)
        return set_err(err, "volume: override path is not case-sensitive",
                       EINVAL);

    char *dup = strdup(override_dir);
    if (!dup)
        return set_err(err, "volume: strdup failed", ENOMEM);
    *out_volume_root = dup;
    return 0;
}

int oci_volume_subdir(const char *volume_root,
                      const char *name,
                      char **out_path,
                      const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!volume_root || !name || !out_path)
        return set_err(err, "volume subdir: NULL argument", EINVAL);
    *out_path = NULL;

    size_t want = strlen(volume_root) + 1 + strlen(name) + 1;
    char *path = malloc(want);
    if (!path)
        return set_err(err, "volume subdir: alloc failed", ENOMEM);
    snprintf(path, want, "%s/%s", volume_root, name);

    /* mkdir each component; existing dirs are fine. */
    char *p = path + strlen(volume_root) + 1;
    while (*p) {
        char *slash = strchr(p, '/');
        if (slash)
            *slash = '\0';
        if (mkdir(path, 0755) < 0 && errno != EEXIST) {
            int saved = errno;
            free(path);
            return set_err(err, "volume subdir: mkdir failed", saved);
        }
        if (slash) {
            *slash = '/';
            p = slash + 1;
        } else {
            break;
        }
    }
    *out_path = path;
    return 0;
}
