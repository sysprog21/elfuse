/*
 * Process metadata state helpers
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
#include "syscall/casefold-walk.h"

#include "runtime/thread.h"

#include "syscall/internal.h"
#include "syscall/proc.h"
#include "syscall/proc-state.h"
#include "syscall/path.h"

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
    char guest[LINUX_PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)))
        return -1;

    /* One conversion, shared with the rest of the path layer: a private
     * prefix-strip here would not know a component can be stored escaped, and
     * would hand the guest a cwd it cannot chdir back into.
     */
    if (path_host_to_guest(cwd, guest, sizeof(guest)) < 0)
        return -1;
    const char *guest_cwd = guest;

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

/* True when realpath(3) failed because the path stopped resolving rather than
 * because it resolves somewhere it should not. A sibling thread or process can
 * unlink or rename the entry between the resolver's existence probe and this
 * recheck, and canonicalizing a vanished path dies with ENOENT (or ENOTDIR
 * when a component was replaced by a file). Nothing can be reached through a
 * path that no longer resolves, so the caller may keep the sysroot spelling
 * and let its own syscall report the truth; turning the failure into a veto
 * manufactures ELOOP for a plain concurrent unlink. Every other realpath
 * errno stays a veto: a loop really is ELOOP, and denying on EACCES or EIO is
 * the conservative side of a containment check.
 *
 * The reasoning covers the sysroot argument as much as the path under it: a
 * sysroot renamed out from under a running guest leaves nothing reachable
 * beneath it either, so the caller's own syscall owes the same ENOENT. There
 * is no containment question left to answer once the root of the comparison
 * is gone.
 */
static bool realpath_vanished(void)
{
    return errno == ENOENT || errno == ENOTDIR;
}

/* Confirm @resolved_path canonicalizes inside @sysroot. This is a
 * check-then-use sequence: callers issue the actual syscall after this returns,
 * so a symlink swapped in between will not be re-validated. openat2
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
        return realpath_vanished();

    if (follow_final) {
        if (!realpath(resolved_path, real_path))
            return realpath_vanished();
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
                return realpath_vanished();
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
                return realpath_vanished();
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
 * resources such as /etc/resolv.conf. The temp roots
 * (is_sysroot_backed_temp_path) and the guest system directories
 * (is_guest_system_path) are excluded from that fallback and stay on the
 * sysroot spelling whether or not they exist there. Containment via realpath()
 * is enforced only when the path actually resolves under sysroot, to prevent
 * symlink escape from a tree the caller intended to stay inside.
 */
static bool lexical_normalize_absolute_path(char *dest,
                                            const char *src,
                                            size_t dest_sz)
{
    if (!src || src[0] != '/' || dest_sz == 0)
        return false;
    dest[0] = '/';
    dest[1] = '\0';
    size_t dest_len = 1;

    const char *scan = src;
    const char *comp;
    size_t len;
    while (path_next_component(&scan, &comp, &len)) {
        if (len == 1 && comp[0] == '.') {
            /* Do nothing */
        } else if (len == 2 && comp[0] == '.' && comp[1] == '.') {
            /* Pop the last component */
            if (dest_len > 1) {
                while (dest_len > 1 && dest[dest_len - 1] == '/')
                    dest[--dest_len] = '\0';
                while (dest_len > 1 && dest[dest_len - 1] != '/')
                    dest[--dest_len] = '\0';
                if (dest_len > 1 && dest[dest_len - 1] == '/')
                    dest[--dest_len] = '\0';
                if (dest_len == 0) {
                    dest[0] = '/';
                    dest[1] = '\0';
                    dest_len = 1;
                }
            }
        } else {
            /* Push the component */
            if (dest_len > 1 && dest[dest_len - 1] != '/') {
                if (dest_len + 1 >= dest_sz)
                    return false;
                dest[dest_len++] = '/';
            }
            if (dest_len + len >= dest_sz)
                return false;
            memcpy(dest + dest_len, comp, len);
            dest_len += len;
            dest[dest_len] = '\0';
        }
    }
    if (dest_len == 0) {
        dest[0] = '/';
        dest[1] = '\0';
    } else {
        while (dest_len > 1 && dest[dest_len - 1] == '/')
            dest[--dest_len] = '\0';
    }
    return true;
}

/* Rewrite the '..' components that would climb above the guest root, and only
 * those. Linux clamps '..' at the root a process resolves from
 * (path_resolution(7)), but the sysroot is a directory on the host, so the
 * host kernel would happily walk out of it.
 *
 * Everything else is copied byte for byte, including interior '..', '.', and
 * runs of slashes. Collapsing those would hand the host a path whose popped
 * components it never resolves, and their existence and type are part of the
 * answer: "/absent/../b" owes ENOENT and "/file/../b" owes ENOTDIR, both of
 * which only the host walk can report.
 *
 * @dest is never longer than @src, since components are only dropped, and the
 * one byte written back for a fully consumed path replaces at least the three
 * that "/.." occupied.
 */
static bool clamp_dotdot_at_guest_root(char *dest,
                                       const char *src,
                                       size_t dest_sz)
{
    if (!src || src[0] != '/' || dest_sz == 0)
        return false;

    const char *scan = src;
    const char *comp;
    /* The separators before the component about to be read, which travel with
     * it: a dropped component must not leave its slashes behind. Once the walk
     * ends this is the trailing run, which states that the path names a
     * directory and must survive for the host to answer ENOTDIR when it does
     * not.
     */
    const char *sep = scan;
    size_t len;
    size_t out = 0;
    size_t depth = 0;

    while (path_next_component(&scan, &comp, &len)) {
        size_t sep_len = (size_t) (comp - sep);
        bool dotdot = len == 2 && comp[0] == '.' && comp[1] == '.';

        if (dotdot && depth == 0) {
            sep = scan;
            continue;
        }
        if (dotdot)
            depth--;
        else if (len != 1 || comp[0] != '.')
            depth++;

        if (out + sep_len + len >= dest_sz)
            return false;
        memcpy(dest + out, sep, sep_len + len);
        out += sep_len + len;
        sep = scan;
    }

    size_t tail = strlen(sep);
    if (out + tail >= dest_sz)
        return false;
    memcpy(dest + out, sep, tail);
    out += tail;

    if (out == 0)
        dest[out++] = '/';
    dest[out] = '\0';
    return true;
}

/* Snapshot the sysroot, clamp @path, and spell the host path it names.
 * Returns 1 with @buf, @sr, and @clamped filled, 0 when sysroot resolution
 * does not apply and the caller owes its input back, or -1 with errno set.
 */
static int sysroot_seed_host_path(const char *path,
                                  char *buf,
                                  size_t bufsz,
                                  char sr[LINUX_PATH_MAX],
                                  char clamped[LINUX_PATH_MAX])
{
    if (!proc_sysroot_snapshot(sr, LINUX_PATH_MAX) || !path || path[0] != '/')
        return 0;
    if (bufsz == 0 ||
        !clamp_dotdot_at_guest_root(clamped, path, LINUX_PATH_MAX)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int n = snprintf(buf, bufsz, "%s%s", sr, clamped);
    if (n < 0) {
        if (errno == 0)
            errno = EINVAL;
        return -1;
    }
    if ((size_t) n >= bufsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 1;
}

static bool is_guest_system_path(const char *path)
{
    if (!path || path[0] != '/')
        return false;

    /* Check prefix patterns (path/...) and exact root matches (path) */
    static const char *const dirs[] = {
        "/usr/", "/bin/",  "/sbin/", "/lib/",  "/lib64/",
        "/opt/", "/boot/", "/srv/",  "/root/", "/home/",
    };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        size_t n = strlen(dirs[i]);
        if (strncmp(path, dirs[i], n) == 0)
            return true;
        /* Also match the bare directory name (e.g., "/usr") */
        if (strncmp(path, dirs[i], n - 1) == 0 && path[n - 1] == '\0')
            return true;
    }
    if (strncmp(path, "/var/", 5) == 0 || !strcmp(path, "/var")) {
        if (strncmp(path, "/var/folders/", 13) == 0 ||
            !strcmp(path, "/var/folders"))
            return false;
        return true;
    }
    if (strncmp(path, "/etc/", 5) == 0 || !strcmp(path, "/etc")) {
        if (!strcmp(path, "/etc/resolv.conf") || !strcmp(path, "/etc/hosts"))
            return false;
        return true;
    }
    return false;
}

/* The temp roots are sysroot-backed for every operation, lookup as much as
 * create. Creates redirect so a guest's temp files cannot collide on the host's
 * case-insensitive /tmp; a lookup falling back to the host would then surface
 * entries that no create-resolved unlink or rename could touch, leaving them
 * readable but not removable. The roots match as directories too, not only as
 * prefixes of their children, so a listing cannot enumerate host entries whose
 * children resolve into the sysroot.
 *
 * /var/tmp also lands in is_guest_system_path(), which claims all of /var for
 * macOS SIP reasons; it belongs here on its own terms as a temp root, so the
 * two rules stay independent. ccache matches by component because HOME may be a
 * macOS home directory (/Users/<user>/.ccache) that no other rule covers; the
 * component test is deliberately generous, matching a final leaf or a regular
 * file too, an over-match that only widens what resolves into the sysroot.
 */
static bool is_sysroot_backed_temp_path(const char *path)
{
    if (path_prefix_match(path, "/tmp", 4) ||
        path_prefix_match(path, "/var/tmp", 8))
        return true;

    static const char ccache_dir[] = ".ccache";
    const char *scan = path;
    const char *comp;
    size_t len;
    while (path_next_component(&scan, &comp, &len))
        if (len == sizeof(ccache_dir) - 1 && !memcmp(comp, ccache_dir, len))
            return true;
    return false;
}

/* Resolve @path under @sr, following every symlink the walk has to pass
 * through, and report the guest path it finally names in @guest_out.
 *
 * A link records the bytes the guest wrote, and readlink(2) owes those bytes
 * back, so a target cannot be rewritten on the way in. Following it therefore
 * has to happen in the guest's namespace: a relative target is joined to the
 * directory holding the link, an absolute one replaces the path outright, and
 * either way the result re-enters resolution as an ordinary guest path. That is
 * what makes an absolute target behave like the same path typed by the guest
 * rather than like a host path, which is what the host kernel would make of it.
 *
 * Iterative because a chain may be MAXSYMLINKS deep and each step needs a whole
 * path buffer; recursing would put 40 of them on the stack.
 */
static casefold_verdict_t resolve_through_links(const char *sr,
                                                const char *path,
                                                bool follow_final,
                                                char *buf,
                                                size_t bufsz,
                                                casefold_walk_t *walk,
                                                char *guest_out,
                                                size_t guest_outsz,
                                                bool *followed_relative_out)
{
    char splice[LINUX_PATH_MAX];
    char norm[LINUX_PATH_MAX];
    const char *cur = path;

    for (int depth = 0;; depth++) {
        casefold_verdict_t verdict;
        char target[LINUX_PATH_MAX];
        const char *rest;
        ssize_t n;

        verdict = casefold_resolve_at(AT_FDCWD, sr, cur, follow_final, buf,
                                      bufsz, walk);
        if (verdict != CASEFOLD_SYMLINK) {
            if (str_copy_trunc(guest_out, cur, guest_outsz) >= guest_outsz) {
                errno = ENAMETOOLONG;
                return CASEFOLD_ERROR;
            }
            return verdict;
        }

        /* @depth counts links actually crossed, so the guard sits with the
         * readlink it bounds; the terminal iteration resolves without
         * following anything and consumes no budget. Linux resolves a 40-link
         * chain and fails following the 41st (path_resolution(7)), the same
         * accounting path_openat2_crosses_mount uses.
         */
        if (depth >= MAXSYMLINKS) {
            errno = ELOOP;
            return CASEFOLD_ERROR;
        }

        /* buf names the link itself, in the spelling the volume stores, so the
         * host can read it even when the name had to be escaped.
         */
        n = readlink(buf, target, sizeof(target) - 1);
        if (n < 0)
            return CASEFOLD_ERROR;
        target[n] = '\0';

        rest = cur + walk->link_rest_offset;

        /* A relative target is measured from the directory holding the link,
         * which is the guest path up to the link component.
         */
        if (path_splice_link_target(cur, walk->link_guest_offset, target, rest,
                                    splice, sizeof(splice)) < 0)
            return CASEFOLD_ERROR;
        if (followed_relative_out && target[0] != '/')
            *followed_relative_out = true;
        /* A target may carry '..' that climbs above the guest root, which
         * the walk would append literally and follow out of the sysroot. Clamp
         * it exactly as an entry path is clamped; an interior '..' stays for
         * the host to resolve against the directory the link named.
         */
        if (!clamp_dotdot_at_guest_root(norm, splice, sizeof(norm))) {
            errno = ENAMETOOLONG;
            return CASEFOLD_ERROR;
        }
        cur = norm;
    }
}

/* After a walk that may have followed links, point @path at the guest path it
 * finally named. Reports whether a link was actually crossed, because the
 * host-fallback decision downstream is different for a path the guest typed
 * and one a link handed it; shared by both resolvers so the two cannot drift.
 */
static bool rebase_after_link(const char **path, const char *followed)
{
    if (!strcmp(*path, followed))
        return false;
    *path = followed;
    return true;
}

static const char *proc_resolve_sysroot_path_flags(const char *path,
                                                   char *buf,
                                                   size_t bufsz,
                                                   bool follow_final)
{
    char sr[LINUX_PATH_MAX], clamped[LINUX_PATH_MAX];
    int seeded = sysroot_seed_host_path(path, buf, bufsz, sr, clamped);
    if (seeded <= 0)
        return seeded < 0 ? NULL : path;
    /* Moves to the link's target once one is followed, so everything below
     * decides from where resolution actually ended up.
     */
    const char *lookup = clamped;

    /* Does this path name something under the sysroot, and if so under what
     * host spelling? On a volume that folds case those are one question: the
     * walk decides each component's stored spelling and reports whether the
     * whole path resolved, so its verdict is the existence answer and its
     * output is the host path. On a byte-exact volume the guest spelling is
     * the host spelling, and a concatenation plus one probe answers both.
     */
    bool present;
    bool folded = false;
    bool followed_link = false;
    bool followed_relative_link = false;
    char followed[LINUX_PATH_MAX];
    if (casefold_active()) {
        casefold_walk_t walk;
        casefold_verdict_t verdict = resolve_through_links(
            sr, lookup, follow_final, buf, bufsz, &walk, followed,
            sizeof(followed), &followed_relative_link);

        if (verdict == CASEFOLD_ERROR)
            return NULL;
        present = verdict == CASEFOLD_FOUND;
        folded = walk.folded;
        /* The walk stopped at a component that is not a directory, which is
         * the answer the byte-exact branch below reads off ENOTDIR: resolution
         * fails there (path_resolution(7)) and the host fallback must not run,
         * or "file/tail" would be reported against an unrelated host path,
         * ENOENT where Linux owes ENOTDIR. The caller's own syscall against
         * the sysroot spelling reproduces the right errno. The containment
         * check is skipped for the reason the folded return below gives:
         * nothing past the offending component is ever reached.
         */
        if (!present && walk.notdir)
            return buf;
        /* An all-slash guest path names the root, which always exists, is
         * trivially contained, and has no parent for the containment check
         * to split off: with the sysroot at "/" the resolved path is the
         * one-character prefix itself, and treating that shape as impossible
         * reports ELOOP for lstat("/").
         */
        if (present && walk.leaf_offset == 0)
            return buf;
        /* Everything below decides between the sysroot and the host, and after
         * a link that decision belongs to where the link pointed, not to where
         * the guest started. An absolute target is then treated exactly like
         * the same absolute path from the guest: the sysroot when it is there,
         * the host when it is not and the path is not a guest system directory.
         */
        followed_link = rebase_after_link(&lookup, followed);
    } else {
        int n = snprintf(buf, bufsz, "%s%s", sr, lookup);
        if (n < 0) {
            if (errno == 0)
                errno = EINVAL;
            return NULL;
        }
        if ((size_t) n >= bufsz) {
            errno = ENAMETOOLONG;
            return NULL;
        }
        present = sysroot_path_exists(buf, follow_final);
        /* A probe that dies with ENOTDIR found a sysroot component that is
         * not a directory. Linux resolves left to right and fails there with
         * ENOTDIR (path_resolution(7)), so the sysroot has answered: the
         * host fallback below must not run, or "file/" and "file/tail" would
         * be reported against an unrelated host path, ENOENT where Linux
         * owes ENOTDIR. The caller's own syscall against the sysroot
         * spelling reproduces the right errno on the host. The containment
         * check is skipped for the reason the folded return below gives:
         * resolution never reaches anything past the offending component.
         */
        if (!present && errno == ENOTDIR)
            return buf;
    }

    if (present) {
        if (!sysroot_path_is_contained(buf, sr, follow_final)) {
            errno = ELOOP;
            return NULL;
        }
        return buf;
    }

    /* The sysroot holds an entry where this path asked, spelled differently,
     * so the path is absent to a byte-exact reader but the sysroot has a claim
     * on it, and the answer Linux owes is ENOENT. Falling through would open an
     * unrelated host file that merely shares the name, which is how a
     * wrong-case lookup escapes the tree entirely.
     *
     * Returning before the containment check above is deliberate: a folded
     * component's escape does not exist, every component before it resolved
     * case-exactly without passing through a link, and resolution proceeds
     * component by component from the left (path_resolution(7)), so the
     * caller's syscall dies with ENOENT at the folded component before
     * anything after it could be reached, contained or not.
     */
    if (folded)
        return buf;

    /* Prevent escaping guest system paths to macOS host paths, which leads
     * to host contamination and permission failures (e.g. SIP/EPERM).
     * Classification reads the fully collapsed spelling, so "/usr/../home/x"
     * is judged as "/home/x" rather than prefix-matching "/usr".
     * Resolution stops at the sysroot spelling for both classes. The caller's
     * own syscall reports the path absent when the sysroot does not hold it,
     * which is what it is in the guest's namespace.
     */
    char norm_path[LINUX_PATH_MAX];
    bool has_norm =
        lexical_normalize_absolute_path(norm_path, lookup, sizeof(norm_path));
    const char *path_to_check = has_norm ? norm_path : lookup;
    if (is_guest_system_path(path_to_check) ||
        is_sysroot_backed_temp_path(path_to_check))
        return buf;

    /* A path reached by following a symlink has already been rebased to the
     * target's guest spelling. For non-forced paths, keep the same host
     * fallback rule as a path the guest typed directly: if the target exists
     * on the host, hand that resolved target to the caller; otherwise leave
     * the syscall on the sysroot spelling so dangling links report normally.
     */
    if (followed_link) {
        if (!followed_relative_link &&
            sysroot_path_exists(path_to_check, follow_final))
            return path_to_check;

        if (followed_relative_link &&
            sysroot_path_exists(path_to_check, follow_final)) {
            errno = ELOOP;
            return NULL;
        }
        return buf;
    }

    return path;
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
    char sr[LINUX_PATH_MAX], clamped[LINUX_PATH_MAX];
    int seeded = sysroot_seed_host_path(path, buf, bufsz, sr, clamped);
    if (seeded <= 0)
        return seeded < 0 ? NULL : path;
    /* Moves to the link's target once one is followed, so everything below
     * decides from where resolution actually ended up.
     */
    const char *lookup = clamped;

    /* An all-slash guest path ("/", "///", and anything clamping to them)
     * names the root, which always exists and has no parent to check; trimming
     * it would walk strrchr into the sysroot prefix and trip the containment
     * guard.
     *
     * Return buf as-is.
     */
    if (lookup[strspn(lookup, "/")] == '\0')
        return buf;

    char parent[LINUX_PATH_MAX];
    bool parent_present;

    /* The target does not exist yet, so what has to be decided is where it
     * would go: the host spelling of every component leading to it, and
     * whether that parent is there. On a folding volume a concatenated parent
     * answers neither: a parent stored escaped reads as absent, and a
     * wrong-case one folds onto a directory the create would then land in.
     */
    bool followed_link = false;
    bool followed_relative_link = false;
    char followed[LINUX_PATH_MAX];
    if (casefold_active()) {
        casefold_walk_t walk;

        /* Intermediate links have to be followed here as well. Lookup and
         * create are separate resolvers, and a follow rule taught to only one
         * of them lets a create below a link land beside the link instead of
         * inside the directory the link names.
         */
        if (resolve_through_links(sr, lookup, false, buf, bufsz, &walk,
                                  followed, sizeof(followed),
                                  &followed_relative_link) == CASEFOLD_ERROR)
            return NULL;
        followed_link = rebase_after_link(&lookup, followed);
        if (str_copy_trunc(parent, buf, sizeof(parent)) >= sizeof(parent)) {
            errno = ENAMETOOLONG;
            return NULL;
        }
        /* An all-slash guest path names the root, which always exists and has
         * no parent to check.
         */
        if (walk.leaf_offset == 0)
            return buf;
        /* The walk records where the parent's spelling ends, so truncating
         * there needs no correction for the separator: only the walk knows
         * whether it inserted one, and with the sysroot at "/" it did not:
         * the parent is the root, not the empty string a leaf_offset - 1
         * truncation would leave.
         */
        parent[walk.parent_offset] = '\0';
        parent_present = walk.parent_found;

        /* A fold above the leaf means the parent the guest named is not the
         * entry the volume matched, so that parent does not exist. Both other
         * answers are wrong: falling through puts the create on the host, and
         * returning the sysroot spelling puts it inside the folded entry,
         * which is a directory this sysroot did not create under that name.
         */
        if (walk.folded && !parent_present) {
            errno = ENOENT;
            return NULL;
        }
    } else {
        int n = snprintf(buf, bufsz, "%s%s", sr, lookup);
        if (n < 0) {
            if (errno == 0)
                errno = EINVAL;
            return NULL;
        }
        if ((size_t) n >= bufsz) {
            errno = ENAMETOOLONG;
            return NULL;
        }

        /* An all-slash guest path ("/", "///") names the root, which always
         * exists and has no parent to check; trimming it would walk strrchr
         * into the sysroot prefix and trip the containment guard.
         *
         * Return buf as-is.
         */
        if (lookup[strspn(lookup, "/")] == '\0')
            return buf;

        str_copy_trunc(parent, buf, sizeof(parent));
        /* Trailing slashes name the same directory (POSIX); drop them so the
         * final separator splits off the leaf component rather than matching
         * the trailing slash itself, which would leave the target as its own
         * parent.
         */
        size_t plen = strlen(parent);
        while (plen > 1 && parent[plen - 1] == '/')
            parent[--plen] = '\0';
        char *slash = strrchr(parent, '/');
        if (!slash || slash == parent)
            return buf;

        *slash = '\0';
        parent_present = access(parent, F_OK) == 0;
        /* access() failed for a reason other than "parent missing" (e.g.
         * EACCES, ELOOP, ENAMETOOLONG, EIO). Treating those as "parent absent"
         * would let the redirect logic auto-create or silently fall back to
         * the host literal, which can bypass sysroot resolution. Surface the
         * real error.
         */
        if (!parent_present && errno != ENOENT && errno != ENOTDIR)
            return NULL;
    }

    if (parent_present) {
        if (!sysroot_path_is_contained(parent, sr, true)) {
            errno = ELOOP;
            return NULL;
        }
        return buf;
    }

    /* Parent doesn't exist in sysroot. Only the temp roots and the guest system
     * directories are forced to resolve there; everything else falls back to
     * the host literal.
     */
    char norm_path[LINUX_PATH_MAX];
    bool has_norm =
        lexical_normalize_absolute_path(norm_path, lookup, sizeof(norm_path));
    const char *path_to_check = has_norm ? norm_path : lookup;

    if (!is_sysroot_backed_temp_path(path_to_check) &&
        !is_guest_system_path(path_to_check)) {
        /* As in the lookup resolver: a path reached by following a link may not
         * fall through to the host, and after a link the guest path lives in a
         * local buffer, so the input pointer is no longer the input.
         */
        if (followed_link) {
            errno = ELOOP;
            return NULL;
        }
        return path;
    }

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
