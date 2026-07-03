/*
 * Sysroot capability probing and provisioning
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug/log.h"
#include "utils.h"

#include "core/sysroot.h"

extern char **environ;

#define CASE_COLLISION_SENTINEL_A "net/netfilter/xt_CONNMARK.h"
#define CASE_COLLISION_SENTINEL_B "net/netfilter/xt_connmark.h"

typedef struct {
    uint32_t length;
    vol_capabilities_attr_t caps;
} volume_caps_buf_t;

/* Validate that path names an existing directory, not a symlink.
 *
 * Returns 0 if so, else -1 with errno set: ELOOP for a symlink, ENOTDIR for a
 * non-directory, or the lstat errno (ENOENT when the component does not exist).
 * Shared by the symlink-rejecting sysroot dir walkers; ensure_dir_exists_follow
 * deliberately follows symlinks and does not use it.
 */
static int validate_existing_dir(const char *path)
{
    struct stat st;
    if (lstat(path, &st) < 0)
        return -1;
    if (S_ISLNK(st.st_mode)) {
        errno = ELOOP;
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    return 0;
}

static int ensure_dir_exists_follow(const char *path)
{
    if (!path || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    char buf[LINUX_PATH_MAX];
    size_t len = str_copy_trunc(buf, path, sizeof(buf));
    if (len >= sizeof(buf)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0755) < 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }

    if (mkdir(buf, 0755) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

int sysroot_ensure_dir_exists(const char *path)
{
    if (!path || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    char buf[LINUX_PATH_MAX];
    size_t len = str_copy_trunc(buf, path, sizeof(buf));
    if (len >= sizeof(buf)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0755) < 0) {
            if (errno != EEXIST)
                return -1;
            if (validate_existing_dir(buf) < 0)
                return -1;
        }
        *p = '/';
    }

    if (mkdir(buf, 0755) < 0) {
        if (errno != EEXIST)
            return -1;
        if (validate_existing_dir(buf) < 0)
            return -1;
    }
    return 0;
}

int sysroot_validate_dir_prefix(const char *path)
{
    if (!path || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    char buf[LINUX_PATH_MAX];
    size_t len = str_copy_trunc(buf, path, sizeof(buf));
    if (len >= sizeof(buf)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';

        if (validate_existing_dir(buf) < 0) {
            /* A not-yet-existing component means the prefix is valid so far. */
            if (errno == ENOENT) {
                *p = '/';
                return 0;
            }
            return -1;
        }
        *p = '/';
    }

    if (validate_existing_dir(buf) < 0) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }

    return 0;
}

static int spawn_capture_stdout(char *const argv[],
                                char *buf,
                                size_t bufsz,
                                int *status_out)
{
    int pipefd[2] = {-1, -1};
    if (pipe(pipefd) < 0)
        return -1;

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipefd[0]);
    posix_spawn_file_actions_addclose(&actions, pipefd[1]);

    pid_t pid = -1;
    int spawn_ret = posix_spawnp(&pid, argv[0], &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(pipefd[1]);
    if (spawn_ret != 0) {
        close(pipefd[0]);
        errno = spawn_ret;
        return -1;
    }

    size_t off = 0;
    while (buf && off + 1 < bufsz) {
        ssize_t n = read(pipefd[0], buf + off, bufsz - off - 1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        off += (size_t) n;
    }
    if (buf && bufsz > 0)
        buf[off] = '\0';
    close(pipefd[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    if (status_out)
        *status_out = status;
    return 0;
}

static int spawn_simple_common(char *const argv[], bool silence_stdout)
{
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_t *actions_ptr = NULL;
    if (silence_stdout) {
        /* hdiutil prints messages like '"diskN" ejected.' to stdout,
         * even on success. Callers that promise a clean stdout contract
         * (oci unpack / oci clone) must not inherit that noise, so
         * redirect the child's fd 1 to /dev/null. stderr is left alone
         * so genuine error messages still surface for diagnostics.
         */
        if (posix_spawn_file_actions_init(&actions) != 0) {
            errno = ENOMEM;
            return -1;
        }
        if (posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO,
                                             "/dev/null", O_WRONLY, 0) != 0) {
            posix_spawn_file_actions_destroy(&actions);
            errno = EIO;
            return -1;
        }
        actions_ptr = &actions;
    }

    pid_t pid = -1;
    int spawn_ret =
        posix_spawnp(&pid, argv[0], actions_ptr, NULL, argv, environ);
    if (actions_ptr)
        posix_spawn_file_actions_destroy(actions_ptr);
    if (spawn_ret != 0) {
        errno = spawn_ret;
        return -1;
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int spawn_simple_silent(char *const argv[])
{
    return spawn_simple_common(argv, true);
}

static int parse_attach_mountpoint(const char *plist,
                                   char *mount_path,
                                   size_t mount_path_sz)
{
    static const char *key = "<key>mount-point</key>";
    static const char *open_tag = "<string>";
    static const char *close_tag = "</string>";

    const char *p = strstr(plist, key);
    if (!p) {
        errno = EPROTO;
        return -1;
    }
    p = strstr(p, open_tag);
    if (!p) {
        errno = EPROTO;
        return -1;
    }
    p += strlen(open_tag);
    const char *end = strstr(p, close_tag);
    if (!end) {
        errno = EPROTO;
        return -1;
    }

    size_t len = (size_t) (end - p);
    if (len + 1 > mount_path_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(mount_path, p, len);
    mount_path[len] = '\0';
    return 0;
}

static int probe_case_sensitivity_getattrlist(const char *path,
                                              bool *case_sensitive,
                                              bool *case_preserving)
{
    struct attrlist attrs;
    memset(&attrs, 0, sizeof(attrs));
    attrs.bitmapcount = ATTR_BIT_MAP_COUNT;
    attrs.volattr = ATTR_VOL_CAPABILITIES;

    volume_caps_buf_t caps;
    memset(&caps, 0, sizeof(caps));
    if (getattrlist(path, &attrs, &caps, sizeof(caps), 0) < 0)
        return -1;

    uint32_t valid_format = caps.caps.valid[VOL_CAPABILITIES_FORMAT];
    uint32_t caps_format = caps.caps.capabilities[VOL_CAPABILITIES_FORMAT];
    if ((valid_format & VOL_CAP_FMT_CASE_SENSITIVE) == 0 ||
        (valid_format & VOL_CAP_FMT_CASE_PRESERVING) == 0) {
        errno = ENOTSUP;
        return -1;
    }

    *case_sensitive = (caps_format & VOL_CAP_FMT_CASE_SENSITIVE) != 0;
    *case_preserving = (caps_format & VOL_CAP_FMT_CASE_PRESERVING) != 0;
    return 0;
}

static int probe_case_sensitivity_pathconf(const char *path,
                                           bool *case_sensitive,
                                           bool *case_preserving)
{
    errno = 0;
    long sensitive = pathconf(path, _PC_CASE_SENSITIVE);
    if (sensitive < 0 && errno != 0)
        return -1;

    errno = 0;
    long preserving = pathconf(path, _PC_CASE_PRESERVING);
    if (preserving < 0 && errno != 0)
        return -1;

    if (sensitive < 0 || preserving < 0) {
        errno = ENOTSUP;
        return -1;
    }

    *case_sensitive = sensitive != 0;
    *case_preserving = preserving != 0;
    return 0;
}

int sysroot_probe_case_sensitivity(const char *path,
                                   bool *case_sensitive,
                                   bool *case_preserving)
{
    if (probe_case_sensitivity_pathconf(path, case_sensitive,
                                        case_preserving) == 0) {
        return 0;
    }
    return probe_case_sensitivity_getattrlist(path, case_sensitive,
                                              case_preserving);
}

/* Returns 1 if both sentinel paths exist under sysroot, 0 if at least one is
 * absent, -1 on error (e.g. path truncation). Truncation must fail closed:
 * returning 0 would silently admit a case-insensitive sysroot that should be
 * rejected for colliding Linux pathnames.
 */
static int collision_pair_exists(const char *sysroot,
                                 const char *rel_a,
                                 const char *rel_b)
{
    char a[LINUX_PATH_MAX];
    char b[LINUX_PATH_MAX];

    if (snprintf(a, sizeof(a), "%s/%s", sysroot, rel_a) >= (int) sizeof(a) ||
        snprintf(b, sizeof(b), "%s/%s", sysroot, rel_b) >= (int) sizeof(b)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    struct stat st_a;
    struct stat st_b;
    return (lstat(a, &st_a) == 0 && lstat(b, &st_b) == 0) ? 1 : 0;
}

int sysroot_validate_case_sensitivity(const char *path)
{
    if (!path || path[0] == '\0')
        return 0;

    bool case_sensitive = false;
    bool case_preserving = false;
    if (sysroot_probe_case_sensitivity(path, &case_sensitive,
                                       &case_preserving) < 0) {
        log_warn("sysroot: could not probe case sensitivity for %s: %s", path,
                 strerror(errno));
        return 0;
    }

    if (!case_preserving) {
        log_error(
            "sysroot %s is not case-preserving; guest pathnames cannot "
            "round-trip safely on this volume",
            path);
        return -1;
    }

    if (case_sensitive)
        return 0;

    int collide = collision_pair_exists(path, CASE_COLLISION_SENTINEL_A,
                                        CASE_COLLISION_SENTINEL_B);
    if (collide < 0) {
        log_error("sysroot %s: cannot probe case-collision sentinels: %s", path,
                  strerror(errno));
        return -1;
    }
    if (collide > 0) {
        log_error(
            "sysroot %s is case-insensitive and contains colliding Linux "
            "kernel paths (%s and %s); refuse to run this workload on a "
            "case-insensitive volume",
            path, CASE_COLLISION_SENTINEL_A, CASE_COLLISION_SENTINEL_B);
        return -1;
    }

    log_warn(
        "sysroot %s is case-insensitive; workloads with colliding guest "
        "names such as Linux kernel trees may fail. Use --create-sysroot "
        "to run inside a case-sensitive APFS sparsebundle.",
        path);
    return 0;
}

static int sysroot_detach_mountpoint_force(const char *mount_path, bool force)
{
    if (force) {
        char *const argv[] = {"hdiutil", "detach", "-force",
                              (char *) mount_path, NULL};
        return spawn_simple_silent(argv);
    }

    char *const argv[] = {"hdiutil", "detach", (char *) mount_path, NULL};
    return spawn_simple_silent(argv);
}

static bool sysroot_mountpoint_is_active(const char *mount_path)
{
    if (!mount_path || mount_path[0] == '\0')
        return false;

    struct statfs *mntbuf = NULL;
    int count = getmntinfo(&mntbuf, MNT_NOWAIT);
    if (count <= 0 || !mntbuf)
        return false;

    for (int i = 0; i < count; i++) {
        if (!strcmp(mount_path, mntbuf[i].f_mntonname))
            return true;
    }

    return false;
}

static int write_spotlight_marker(const char *mount_path)
{
    char marker[LINUX_PATH_MAX];
    if (snprintf(marker, sizeof(marker), "%s/.metadata_never_index",
                 mount_path) >= (int) sizeof(marker)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = open(marker, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0)
        return -1;
    close(fd);
    return 0;
}

int sysroot_create_mount(const char *mount_path, sysroot_mount_t *mount)
{
    if (!mount || !mount_path || mount_path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    memset(mount, 0, sizeof(*mount));

    if (strlen(mount_path) + strlen(".sparsebundle") >=
        sizeof(mount->image_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    str_copy_trunc(mount->mount_path, mount_path, sizeof(mount->mount_path));
    snprintf(mount->image_path, sizeof(mount->image_path), "%s.sparsebundle",
             mount_path);

    if (ensure_dir_exists_follow(mount_path) < 0)
        return -1;

    if (sysroot_mountpoint_is_active(mount_path) &&
        sysroot_detach_mountpoint_force(mount_path, false) < 0 &&
        errno != EIO && errno != ENOENT) {
        log_warn("sysroot: stale detach of %s failed: %s", mount_path,
                 strerror(errno));
    }

    struct stat st;
    if (lstat(mount->image_path, &st) < 0) {
        if (errno != ENOENT)
            return -1;

        char *const create_argv[] = {"hdiutil",
                                     "create",
                                     "-fs",
                                     "Case-sensitive APFS",
                                     "-size",
                                     "16g",
                                     "-type",
                                     "SPARSEBUNDLE",
                                     "-volname",
                                     "elfuse_sysroot",
                                     mount->image_path,
                                     NULL};
        if (spawn_simple_silent(create_argv) < 0) {
            log_error("sysroot: hdiutil create failed for %s: %s",
                      mount->image_path, strerror(errno));
            return -1;
        }
    }

    /* hdiutil attach -plist emits a property list that can run to tens of KiB;
     * keep it off the stack.
     */
    const size_t plistsz = 32768;
    char *plist = malloc(plistsz);
    if (!plist)
        return -1;
    int status = 0;
    char *const attach_argv[] = {
        "hdiutil", "attach",          "-mountpoint", mount->mount_path,
        "-plist",  mount->image_path, NULL};
    if (spawn_capture_stdout(attach_argv, plist, plistsz, &status) < 0 ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        log_error("sysroot: hdiutil attach failed for %s", mount->image_path);
        free(plist);
        return -1;
    }

    char attached_mount[LINUX_PATH_MAX];
    if (parse_attach_mountpoint(plist, attached_mount, sizeof(attached_mount)) <
        0) {
        log_error(
            "sysroot: could not parse mount point from hdiutil attach "
            "plist for %s",
            mount->image_path);
        sysroot_detach_mountpoint_force(mount->mount_path, true);
        free(plist);
        return -1;
    }
    free(plist);

    str_copy_trunc(mount->mount_path, attached_mount,
                   sizeof(mount->mount_path));
    mount->active = true;
    mount->detach_on_cleanup = true;

    if (write_spotlight_marker(mount->mount_path) < 0) {
        log_warn("sysroot: failed to create Spotlight marker in %s: %s",
                 mount->mount_path, strerror(errno));
    }

    return 0;
}

void sysroot_cleanup_mount(sysroot_mount_t *mount)
{
    if (!mount || !mount->active || !mount->detach_on_cleanup)
        return;

    if (sysroot_detach_mountpoint_force(mount->mount_path, true) < 0) {
        log_warn("sysroot: detach %s failed: %s", mount->mount_path,
                 strerror(errno));
    }

    mount->active = false;
}
