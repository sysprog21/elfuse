/* Process metadata state helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>

#include "utils.h"

#include "core/sysroot.h"

#include "runtime/thread.h"

#include "syscall/internal.h"
#include "syscall/proc.h"
#include "syscall/proc-state.h"

/* Shim blob reference (set by startup/bootstrap) */
static const unsigned char *shim_blob_ptr = NULL;
static unsigned int shim_blob_size = 0;
static bool shim_blob_owned = false;

/* Current ELF and launcher paths. */
static char elf_path[LINUX_PATH_MAX] = {0};
static char elfuse_path[LINUX_PATH_MAX] = {0};
/* Serializes proc_set_elf_path against readers that consume the string. Without
 * this, an execve on one vCPU can tear the buffer underneath a sibling vCPU
 * resolving /proc/self/exe.
 */
static pthread_mutex_t elf_path_lock = PTHREAD_MUTEX_INITIALIZER;

/* Guest process metadata snapshots. */
static char cmdline_buf[8192] = {0};
static size_t cmdline_len = 0;
static char environ_buf[65536] = {0};
static size_t environ_len = 0;
static uint8_t auxv_buf[1024] = {0};
static size_t auxv_len = 0;
static char sysroot_path[LINUX_PATH_MAX] = {0};

/* Serializes proc_set_sysroot against path-helper snapshots. Without this, a
 * sibling vCPU running chroot during another vCPU's path resolution can tear
 * the snprintf input buffer underneath that thread.
 */
static pthread_mutex_t sysroot_lock = PTHREAD_MUTEX_INITIALIZER;
static bool sysroot_casefold = false;

/* Cached current working directory for getcwd() and /proc/self/cwd. */
static pthread_mutex_t cwd_lock = PTHREAD_MUTEX_INITIALIZER;
static char cwd_path[LINUX_PATH_MAX] = {0};
static size_t cwd_len = 0;
static bool cwd_valid = false;

void proc_state_init(void)
{
    elf_path[0] = '\0';
    elfuse_path[0] = '\0';
    cmdline_buf[0] = '\0';
    cmdline_len = 0;
    environ_buf[0] = '\0';
    environ_len = 0;
    auxv_len = 0;
    sysroot_path[0] = '\0';
    sysroot_casefold = false;

    pthread_mutex_lock(&cwd_lock);
    cwd_path[0] = '\0';
    cwd_len = 0;
    cwd_valid = false;
    pthread_mutex_unlock(&cwd_lock);
}

int proc_cwd_refresh(void)
{
    char cwd[LINUX_PATH_MAX];
    const char *guest_cwd = cwd;
    if (!getcwd(cwd, sizeof(cwd)))
        return -1;

    char sr[LINUX_PATH_MAX];
    if (proc_sysroot_snapshot(sr, sizeof(sr))) {
        size_t sr_len = strlen(sr);
        if (!strncmp(cwd, sr, sr_len) &&
            (cwd[sr_len] == '\0' || cwd[sr_len] == '/')) {
            guest_cwd = cwd + sr_len;
            if (*guest_cwd == '\0')
                guest_cwd = "/";
        }
    }

    size_t len = strlen(guest_cwd);
    pthread_mutex_lock(&cwd_lock);
    memcpy(cwd_path, guest_cwd, len + 1);
    cwd_len = len;
    cwd_valid = true;
    pthread_mutex_unlock(&cwd_lock);
    return 0;
}

void proc_cwd_set_virtual(const char *path)
{
    if (!path) {
        proc_cwd_invalidate();
        return;
    }

    size_t len = strnlen(path, sizeof(cwd_path));
    pthread_mutex_lock(&cwd_lock);
    if (len >= sizeof(cwd_path)) {
        cwd_valid = false;
        cwd_path[0] = '\0';
        cwd_len = 0;
    } else {
        memcpy(cwd_path, path, len);
        cwd_path[len] = '\0';
        cwd_len = len;
        cwd_valid = true;
    }
    pthread_mutex_unlock(&cwd_lock);
}

void proc_cwd_invalidate(void)
{
    pthread_mutex_lock(&cwd_lock);
    cwd_valid = false;
    cwd_path[0] = '\0';
    cwd_len = 0;
    pthread_mutex_unlock(&cwd_lock);
}

int proc_acquire_cwd_view(proc_cwd_view_t *view)
{
    if (!view) {
        errno = EINVAL;
        return -1;
    }

    view->locked = false;

    if (thread_is_single_active()) {
        if (!cwd_valid && proc_cwd_refresh() < 0)
            return -1;
        view->path = cwd_path;
        view->len = cwd_len;
        return 0;
    }

    pthread_mutex_lock(&cwd_lock);
    if (cwd_valid) {
        view->path = cwd_path;
        view->len = cwd_len;
        view->locked = true;
        return 0;
    }
    pthread_mutex_unlock(&cwd_lock);

    if (proc_cwd_refresh() < 0)
        return -1;

    pthread_mutex_lock(&cwd_lock);
    view->path = cwd_path;
    view->len = cwd_len;
    view->locked = true;
    return 0;
}

void proc_release_cwd_view(proc_cwd_view_t *view)
{
    if (view && view->locked) {
        view->locked = false;
        pthread_mutex_unlock(&cwd_lock);
    }
}

static ssize_t proc_get_cwd(char *buf, size_t bufsz)
{
    if (bufsz == 0)
        return -1;

    pthread_mutex_lock(&cwd_lock);
    bool valid = cwd_valid;
    size_t len = cwd_len;
    if (valid) {
        if (len + 1 > bufsz) {
            pthread_mutex_unlock(&cwd_lock);
            errno = ERANGE;
            return -1;
        }
        memcpy(buf, cwd_path, len + 1);
    }
    pthread_mutex_unlock(&cwd_lock);

    if (valid)
        return (ssize_t) len;

    if (proc_cwd_refresh() < 0)
        return -1;

    pthread_mutex_lock(&cwd_lock);
    len = cwd_len;
    if (len + 1 > bufsz) {
        pthread_mutex_unlock(&cwd_lock);
        errno = ERANGE;
        return -1;
    }
    memcpy(buf, cwd_path, len + 1);
    pthread_mutex_unlock(&cwd_lock);
    return (ssize_t) len;
}

void proc_set_shim(const unsigned char *blob, unsigned int len)
{
    if (shim_blob_owned && shim_blob_ptr)
        free((void *) shim_blob_ptr);
    shim_blob_ptr = blob;
    shim_blob_size = len;
    shim_blob_owned = false;
}

void proc_set_shim_owned(unsigned char *blob, unsigned int len)
{
    if (shim_blob_owned && shim_blob_ptr)
        free((void *) shim_blob_ptr);
    shim_blob_ptr = blob;
    shim_blob_size = len;
    shim_blob_owned = true;
}

const unsigned char *proc_get_shim_blob(void)
{
    return shim_blob_ptr;
}

unsigned int proc_get_shim_size(void)
{
    return shim_blob_size;
}

void proc_set_elf_path(const char *path)
{
    pthread_mutex_lock(&elf_path_lock);
    if (path) {
        if (path[0] == '/') {
            str_copy_trunc(elf_path, path, sizeof(elf_path));
        } else {
            char cwd[LINUX_PATH_MAX];
            if (proc_get_cwd(cwd, sizeof(cwd)) >= 0)
                snprintf(elf_path, sizeof(elf_path), "%s/%s", cwd, path);
            else
                str_copy_trunc(elf_path, path, sizeof(elf_path));
        }
    } else {
        elf_path[0] = '\0';
    }
    pthread_mutex_unlock(&elf_path_lock);
}

/* Returns the elf_path buffer pointer. Boolean-test callers tolerate the racy
 * read since the first byte transitions atomically. Callers that consume the
 * string content must use proc_elf_path_snapshot() to avoid a torn read against
 * a concurrent proc_set_elf_path().
 */
const char *proc_get_elf_path(void)
{
    return elf_path[0] ? elf_path : NULL;
}

bool proc_elf_path_snapshot(char *out, size_t outsz)
{
    if (!out || outsz == 0)
        return false;
    pthread_mutex_lock(&elf_path_lock);
    bool ok = false;
    if (elf_path[0]) {
        size_t need = strlen(elf_path) + 1;
        if (need <= outsz) {
            memcpy(out, elf_path, need);
            ok = true;
        }
    }
    pthread_mutex_unlock(&elf_path_lock);
    if (!ok)
        out[0] = '\0';
    return ok;
}

void proc_set_elfuse_path(const char *path)
{
    if (path)
        str_copy_trunc(elfuse_path, path, sizeof(elfuse_path));
}

const char *proc_get_elfuse_path(void)
{
    return elfuse_path[0] ? elfuse_path : NULL;
}

void proc_set_cmdline(int argc, const char **argv)
{
    size_t off = 0;
    for (int i = 0; i < argc && off < sizeof(cmdline_buf) - 1; i++) {
        size_t len = strlen(argv[i]);
        if (off + len + 1 > sizeof(cmdline_buf))
            break;
        memcpy(cmdline_buf + off, argv[i], len);
        off += len;
        cmdline_buf[off++] = '\0';
    }
    cmdline_len = off;
}

void proc_set_cmdline_raw(const char *buf, size_t len)
{
    if (len > sizeof(cmdline_buf))
        len = sizeof(cmdline_buf);
    memcpy(cmdline_buf, buf, len);
    cmdline_len = len;
}

const char *proc_get_cmdline(size_t *len_out)
{
    if (cmdline_len == 0)
        return NULL;
    if (len_out)
        *len_out = cmdline_len;
    return cmdline_buf;
}

void proc_set_environ(const char **envp)
{
    size_t off = 0;
    environ_buf[0] = '\0';
    environ_len = 0;
    if (!envp)
        return;
    for (int i = 0; envp[i] && off < sizeof(environ_buf) - 1; i++) {
        size_t len = strlen(envp[i]);
        if (off + len + 1 > sizeof(environ_buf))
            break;
        memcpy(environ_buf + off, envp[i], len);
        off += len;
        environ_buf[off++] = '\0';
    }
    environ_len = off;
}

const char *proc_get_environ(size_t *len_out)
{
    if (environ_len == 0)
        return NULL;
    if (len_out)
        *len_out = environ_len;
    return environ_buf;
}

void proc_set_auxv(const void *data, size_t len)
{
    if (len > sizeof(auxv_buf))
        len = sizeof(auxv_buf);
    memcpy(auxv_buf, data, len);
    auxv_len = len;
}

const void *proc_get_auxv(size_t *len_out)
{
    if (auxv_len == 0)
        return NULL;
    if (len_out)
        *len_out = auxv_len;
    return auxv_buf;
}

void proc_set_sysroot(const char *path)
{
    pthread_mutex_lock(&sysroot_lock);
    if (path && path[0]) {
        str_copy_trunc(sysroot_path, path, sizeof(sysroot_path));
        size_t len = strlen(sysroot_path);
        while (len > 1 && sysroot_path[len - 1] == '/')
            sysroot_path[--len] = '\0';
        char resolved[LINUX_PATH_MAX];
        if (realpath(sysroot_path, resolved))
            str_copy_trunc(sysroot_path, resolved, sizeof(sysroot_path));
    } else {
        sysroot_path[0] = '\0';
    }
    pthread_mutex_unlock(&sysroot_lock);
}

const char *proc_get_sysroot(void)
{
    /* Boolean-test callers (path[0] != '/' fast paths) tolerate the racy read:
     * the first byte transitions atomically and a missed update only causes one
     * extra resolution attempt. Callers that consume the string content must
     * use proc_sysroot_snapshot() instead.
     */
    return sysroot_path[0] ? sysroot_path : NULL;
}

bool proc_sysroot_snapshot(char *out, size_t outsz)
{
    if (!out || outsz == 0)
        return false;
    pthread_mutex_lock(&sysroot_lock);
    bool ok = false;
    if (sysroot_path[0]) {
        size_t need = strlen(sysroot_path) + 1;
        if (need <= outsz) {
            memcpy(out, sysroot_path, need);
            ok = true;
        }
    }
    pthread_mutex_unlock(&sysroot_lock);
    if (!ok)
        out[0] = '\0';
    return ok;
}

void proc_set_sysroot_casefold(bool enabled)
{
    pthread_mutex_lock(&sysroot_lock);
    sysroot_casefold = enabled;
    pthread_mutex_unlock(&sysroot_lock);
}

bool proc_sysroot_casefold_enabled(void)
{
    bool enabled;
    pthread_mutex_lock(&sysroot_lock);
    enabled = sysroot_casefold;
    pthread_mutex_unlock(&sysroot_lock);
    return enabled;
}

/* Confirm resolved_path canonicalizes inside sysroot. This is a check-then-use
 * sequence: callers issue the actual syscall after this returns, so a symlink
 * swapped in between will not be re-validated. openat2
 * RESOLVE_{BENEATH,IN_ROOT} close that race for callers willing to opt in. For
 * the legacy *at() surface this is best-effort defense at the boundary; the
 * guest is in the host user's trust domain.
 */
static bool sysroot_path_is_contained(const char *resolved_path,
                                      const char *sysroot,
                                      bool follow_final)
{
    char real_sysroot[LINUX_PATH_MAX], real_path[LINUX_PATH_MAX];

    if (!realpath(sysroot, real_sysroot))
        return false;

    if (follow_final) {
        if (!realpath(resolved_path, real_path))
            return false;
    } else {
        const char *base = strrchr(resolved_path, '/');
        /* "." and ".." basenames navigate the directory tree and cannot
         * themselves be symlinks, so realpath the full path: appending the
         * literal basename onto realpath(parent) would let "${sysroot}/x/.."
         * pass the prefix check while the kernel resolves the syscall target
         * above sysroot.
         */
        if (base && (!strcmp(base + 1, "..") || !strcmp(base + 1, "."))) {
            if (!realpath(resolved_path, real_path))
                return false;
        } else {
            char parent[LINUX_PATH_MAX];
            char *slash;

            str_copy_trunc(parent, resolved_path, sizeof(parent));
            slash = strrchr(parent, '/');
            /* resolved_path is always ${sysroot}${guest_path} where sysroot is
             * non-empty (caller short-circuits otherwise) and guest_path starts
             * with '/'. The result therefore contains at least two '/' bytes,
             * so the basename slash is never at parent[0]. Reject anything that
             * violates the invariant rather than carrying dead code for it.
             */
            if (!slash || slash == parent)
                return false;

            *slash = '\0';
            if (!realpath(parent, real_path))
                return false;
            size_t parent_len = strlen(real_path);
            if (snprintf(real_path + parent_len, sizeof(real_path) - parent_len,
                         "/%s",
                         slash + 1) >= (int) (sizeof(real_path) - parent_len))
                return false;
        }
    }

    size_t sr_len = strlen(real_sysroot);
    if (strncmp(real_path, real_sysroot, sr_len) != 0)
        return false;
    if (sr_len == 1 && real_sysroot[0] == '/')
        return true;
    return real_path[sr_len] == '\0' || real_path[sr_len] == '/';
}

static bool sysroot_path_exists(const char *resolved_path, bool follow_final)
{
    if (follow_final)
        return access(resolved_path, F_OK) == 0;

    struct stat st;
    return lstat(resolved_path, &st) == 0;
}

/* Resolve an absolute guest path against --sysroot. This keeps absolute guest
 * filesystem syscalls inside the sysroot when the target exists there, and
 * otherwise falls back to the literal host path so apps can still reach host
 * resources such as /tmp or /etc/resolv.conf. Containment via realpath() is
 * enforced only when the path actually resolves under sysroot, to prevent
 * symlink escape from a tree the caller intended to stay inside.
 */
static const char *proc_resolve_sysroot_path_flags(const char *path,
                                                   char *buf,
                                                   size_t bufsz,
                                                   bool follow_final)
{
    char sr[LINUX_PATH_MAX];
    if (!proc_sysroot_snapshot(sr, sizeof(sr)) || !path || path[0] != '/')
        return path;
    if (bufsz == 0) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    int n = snprintf(buf, bufsz, "%s%s", sr, path);
    if (n < 0) {
        if (errno == 0)
            errno = EINVAL;
        return NULL;
    }
    bool full_path_truncated = (size_t) n >= bufsz;
    if (!full_path_truncated && sysroot_path_exists(buf, follow_final)) {
        if (!sysroot_path_is_contained(buf, sr, follow_final)) {
            errno = ELOOP;
            return NULL;
        }
        return buf;
    }

    if (full_path_truncated) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    char parent[LINUX_PATH_MAX];
    str_copy_trunc(parent, buf, sizeof(parent));
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent)
        return buf;
    *slash = '\0';

    if (sysroot_validate_dir_prefix(parent) < 0)
        return NULL;
    return buf;
}

const char *proc_resolve_sysroot_path(const char *path, char *buf, size_t bufsz)
{
    return proc_resolve_sysroot_path_flags(path, buf, bufsz, true);
}

const char *proc_resolve_sysroot_nofollow_path(const char *path,
                                               char *buf,
                                               size_t bufsz)
{
    return proc_resolve_sysroot_path_flags(path, buf, bufsz, false);
}

const char *proc_resolve_sysroot_create_path(const char *path,
                                             char *buf,
                                             size_t bufsz,
                                             bool create_parents)
{
    char sr[LINUX_PATH_MAX];
    if (!proc_sysroot_snapshot(sr, sizeof(sr)) || !path || path[0] != '/')
        return path;
    if (bufsz == 0) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    int n = snprintf(buf, bufsz, "%s%s", sr, path);
    if (n < 0) {
        if (errno == 0)
            errno = EINVAL;
        return NULL;
    }
    if ((size_t) n >= bufsz) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    char parent[LINUX_PATH_MAX];
    str_copy_trunc(parent, buf, sizeof(parent));
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent)
        return buf;

    *slash = '\0';
    if (access(parent, F_OK) == 0) {
        if (!sysroot_path_is_contained(parent, sr, true)) {
            errno = ELOOP;
            return NULL;
        }
        return buf;
    }

    /* access() failed for a reason other than "parent missing" (e.g. EACCES,
     * ELOOP, ENAMETOOLONG, EIO). Treating those as "parent absent" would let
     * the redirect logic auto-create or silently fall back to the host literal,
     * which can bypass sysroot resolution. Surface the real error.
     */
    if (errno != ENOENT && errno != ENOTDIR)
        return NULL;

    if (!create_parents) {
        if (sysroot_validate_dir_prefix(parent) < 0)
            return NULL;
        return buf;
    }
    if (sysroot_ensure_dir_exists(parent) < 0)
        return NULL;
    if (!sysroot_path_is_contained(parent, sr, true)) {
        errno = ELOOP;
        return NULL;
    }
    return buf;
}
