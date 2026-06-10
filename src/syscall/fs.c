/* Filesystem syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Stat, open, close, directory, permissions, and other filesystem operations.
 * All functions are called from syscall_dispatch() in syscall/syscall.c.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <pthread.h>

#include "debug/log.h"
#include "utils.h"

#include "core/shim-globals.h" /* shim_globals_mark_urandom_fd */

#include "runtime/procemu.h"

#include "syscall/abi.h"
#include "syscall/fd.h" /* eventfd_dup_fd */
#include "syscall/fuse.h"
#include "syscall/fs.h"
#include "syscall/internal.h"
#include "syscall/net.h" /* absock_unregister_fd */
#include "syscall/path.h"
#include "syscall/proc.h"
#include "syscall/sidecar.h"

/* Linux dirent64 layout. */
typedef struct {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    /* char d_name[] follows */
} PACKED linux_dirent64_t;

static int opened_fd_type(int host_fd, int linux_flags)
{
    struct stat st;
    if (fstat(host_fd, &st) < 0)
        return -1;
    bool is_dir = S_ISDIR(st.st_mode);
    if ((linux_flags & LINUX_O_DIRECTORY) && !is_dir) {
        errno = ENOTDIR;
        return -1;
    }
    if (linux_flags & LINUX_O_PATH)
        return FD_PATH;
    if (is_dir)
        return FD_DIR;

    return FD_REGULAR;
}

static int intercepted_fd_type(const char *path, int host_fd, int linux_flags)
{
    int type = opened_fd_type(host_fd, linux_flags);
    if (type < 0)
        return type;
    if (type == FD_REGULAR && path && !strcmp(path, "/dev/urandom"))
        return FD_URANDOM;
    return type;
}

static const char *proc_virtual_dir_path(const char *path,
                                         char *buf,
                                         size_t bufsz);

static const char *proc_stateful_file_path(const char *path)
{
    if (!path || strncmp(path, "/proc/", 6) != 0)
        return NULL;

    if (!strcmp(path, "/proc/self/oom_score_adj") ||
        !strcmp(path, "/proc/self/oom_adj") ||
        !strcmp(path, "/proc/self/oom_score")) {
        return path;
    }

    char *endp;
    long pid = strtol(path + 6, &endp, 10);
    if (endp == path + 6 || pid != (long) proc_get_pid())
        return NULL;

    if (!strcmp(endp, "/oom_score_adj"))
        return "/proc/self/oom_score_adj";
    if (!strcmp(endp, "/oom_adj"))
        return "/proc/self/oom_adj";
    if (!strcmp(endp, "/oom_score"))
        return "/proc/self/oom_score";

    return NULL;
}

/* Resolve the proc_path the fd table should record for an intercepted path.
 * Returns true and fills *out when a mapping exists; false otherwise so the
 * caller can skip the install entirely. Pure string work; safe to call before
 * any lock acquisition.
 */
static bool resolve_virtual_path(const char *path, char *out, size_t out_size)
{
    if (!path || out_size == 0)
        return false;

    if (!strcmp(path, "/dev/ptmx")) {
        str_copy_trunc(out, path, out_size);
        return true;
    }

    if (strncmp(path, "/proc", 5) != 0)
        return false;

    char virt_buf[64];
    const char *virt = proc_virtual_dir_path(path, virt_buf, sizeof(virt_buf));
    if (!virt)
        virt = proc_stateful_file_path(path);
    if (!virt)
        return false;

    str_copy_trunc(out, virt, out_size);
    return true;
}

static const char *proc_virtual_dir_path(const char *path,
                                         char *buf,
                                         size_t bufsz)
{
    if (!path || strncmp(path, "/proc", 5) != 0)
        return NULL;

    const char *virt = NULL;
    if (!strcmp(path, "/proc") || !strcmp(path, "/proc/")) {
        virt = "/proc";
    } else if (!strcmp(path, "/proc/self") || !strcmp(path, "/proc/self/")) {
        virt = "/proc/self";
    } else if (!strcmp(path, "/proc/net") || !strcmp(path, "/proc/net/")) {
        virt = "/proc/net";
    } else if (!strcmp(path, "/proc/self/fd") ||
               !strcmp(path, "/proc/self/fd/")) {
        virt = "/proc/self/fd";
    } else if (!strcmp(path, "/proc/self/fdinfo") ||
               !strcmp(path, "/proc/self/fdinfo/")) {
        virt = "/proc/self/fdinfo";
    } else if (!strcmp(path, "/proc/self/task") ||
               !strcmp(path, "/proc/self/task/")) {
        virt = "/proc/self/task";
    } else if (!strncmp(path, "/proc/self/task/", 16)) {
        char *endp;
        long tid = strtol(path + 16, &endp, 10);
        if (endp != path + 16 && tid > 0 &&
            (*endp == '\0' || !strcmp(endp, "/"))) {
            snprintf(buf, bufsz, "/proc/self/task/%ld", tid);
            virt = buf;
        }
    } else if (!strncmp(path, "/proc/", 6)) {
        char *endp;
        long pid = strtol(path + 6, &endp, 10);
        if (endp != path + 6 && pid == (long) proc_get_pid() &&
            (*endp == '\0' || !strcmp(endp, "/"))) {
            virt = "/proc/self";
        } else if (endp != path + 6 && pid == (long) proc_get_pid() &&
                   (!strcmp(endp, "/fdinfo") || !strcmp(endp, "/fdinfo/"))) {
            virt = "/proc/self/fdinfo";
        } else if (endp != path + 6 && pid == (long) proc_get_pid() &&
                   !strcmp(endp, "/fd")) {
            virt = "/proc/self/fd";
        } else if (endp != path + 6 && pid == (long) proc_get_pid() &&
                   !strcmp(endp, "/task")) {
            virt = "/proc/self/task";
        } else if (endp != path + 6 && pid == (long) proc_get_pid() &&
                   !strncmp(endp, "/task/", 6)) {
            char *tid_endp;
            long tid = strtol(endp + 6, &tid_endp, 10);
            if (tid_endp != endp + 6 &&
                (*tid_endp == '\0' || !strcmp(tid_endp, "/"))) {
                snprintf(buf, bufsz, "/proc/self/task/%ld", tid);
                virt = buf;
            }
        }
    }

    return virt;
}

static int fd_alloc_opened_host(int host_fd,
                                int type,
                                int linux_flags,
                                int min_guest_fd,
                                void (*cleanup)(int),
                                const char *virtual_path)
{
    DIR *dir = NULL;

    if (type == FD_DIR) {
        int dup_fd = dup(host_fd);
        if (dup_fd < 0)
            return -1;

        dir = fdopendir(dup_fd);
        if (!dir) {
            close_keep_errno(dup_fd);
            return -1;
        }
    }

    int guest_fd =
        min_guest_fd >= 0
            ? fd_alloc_from_relaxed(min_guest_fd, type, host_fd, cleanup)
            : fd_alloc_from_relaxed(0, type, host_fd, cleanup);
    if (guest_fd < 0) {
        int saved_errno = errno;
        if (dir)
            closedir(dir);
        errno = saved_errno;
        return -1;
    }

    /* Resolve the virtual-path stamp before taking fd_lock; the helper is pure
     * string work and must not run inside the critical section.
     */
    char proc_path_buf[FD_VIRTUAL_PATH_MAX];
    bool have_proc_path = resolve_virtual_path(virtual_path, proc_path_buf,
                                               sizeof(proc_path_buf));

    /* Publish linux_flags, dir, proc_path, and the urandom bitmap bit
     * atomically with respect to the slot's identity. fd_alloc_*_relaxed drops
     * fd_lock before returning, so a sibling vCPU's pathological
     * close(guest_fd) + open() could reuse the slot between alloc and the
     * metadata install below. Re-acquire fd_lock and verify the (type, host_fd)
     * tuple still matches what just got allocated; if it does not, the slot
     * belongs to a different file now and any install would clobber the
     * sibling's entry. The sibling's close path already cleaned up the host_fd
     * of this side via fd_cleanup_entry, so this side only owns dir, which gets
     * closed below.
     */
    bool installed = false;
    pthread_mutex_lock(&fd_lock);
    if (fd_table[guest_fd].type == type &&
        fd_table[guest_fd].host_fd == host_fd) {
        fd_table[guest_fd].linux_flags = linux_flags;
        if (dir)
            fd_table[guest_fd].dir = dir;
        if (have_proc_path)
            memcpy(fd_table[guest_fd].proc_path, proc_path_buf,
                   sizeof(proc_path_buf));
        bool readable_urandom =
            type == FD_URANDOM &&
            (linux_flags & LINUX_O_ACCMODE) != LINUX_O_WRONLY;
        shim_globals_mark_urandom_fd(guest_fd, readable_urandom);
        installed = true;
    }
    pthread_mutex_unlock(&fd_lock);

    if (!installed && dir)
        closedir(dir);

    return guest_fd;
}

static int64_t read_translated_path(guest_t *g,
                                    int dirfd,
                                    uint64_t path_gva,
                                    unsigned int tx_flags,
                                    char path[LINUX_PATH_MAX],
                                    path_translation_t *tx)
{
    if (guest_read_str(g, path_gva, path, LINUX_PATH_MAX) < 0)
        return -LINUX_EFAULT;
    if (path_translate_at(dirfd, path, tx_flags, tx) < 0)
        return linux_errno();
    return 0;
}

static int64_t reject_unsupported_fuse_path_op(const path_translation_t *tx)
{
    return tx && tx->fuse_path ? -LINUX_ENOSYS : INT64_MIN;
}

static int path_parent_copy(const char *path, char *out, size_t outsz)
{
    size_t len = str_copy_trunc(out, path, outsz);
    if (len >= outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }

    char *slash = strrchr(out, '/');
    if (!slash) {
        str_copy_trunc(out, ".", outsz);
    } else if (slash == out) {
        out[1] = '\0';
    } else {
        *slash = '\0';
    }
    return 0;
}

static int append_path_part(char *out,
                            size_t outsz,
                            size_t *used,
                            const char *part,
                            size_t part_len)
{
    if (*used + part_len >= outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out + *used, part, part_len);
    *used += part_len;
    out[*used] = '\0';
    return 0;
}

static int relative_path_between(const char *from_dir,
                                 const char *to_path,
                                 char *out,
                                 size_t outsz)
{
    size_t common = 0;
    for (size_t i = 0; from_dir[i] && to_path[i] && from_dir[i] == to_path[i];
         i++) {
        if (from_dir[i] == '/')
            common = i;
    }

    if (common == 0) {
        errno = EXDEV;
        return -1;
    }

    const char *from_tail = from_dir + common;
    while (*from_tail == '/')
        from_tail++;
    const char *to_tail = to_path + common;
    while (*to_tail == '/')
        to_tail++;

    size_t used = 0;
    out[0] = '\0';
    for (const char *p = from_tail; *p;) {
        while (*p == '/')
            p++;
        if (!*p)
            break;
        const char *next = strchr(p, '/');
        if (append_path_part(out, outsz, &used, "../", 3) < 0)
            return -1;
        p = next ? next + 1 : p + strlen(p);
    }

    if (*to_tail) {
        if (append_path_part(out, outsz, &used, to_tail, strlen(to_tail)) < 0)
            return -1;
    } else if (used == 0) {
        if (append_path_part(out, outsz, &used, ".", 1) < 0)
            return -1;
    } else if (used >= 1 && out[used - 1] == '/') {
        out[used - 1] = '\0';
    }
    return 0;
}

static const char *host_relative_symlink_target(const char *guest_target,
                                                host_fd_ref_t *dir_ref,
                                                const path_translation_t *tx,
                                                char *buf,
                                                size_t bufsz)
{
    char sysroot[LINUX_PATH_MAX];
    if (!guest_target || guest_target[0] != '/' ||
        !proc_sysroot_snapshot(sysroot, sizeof(sysroot)))
        return guest_target;

    char target_host[LINUX_PATH_MAX];
    int n = snprintf(target_host, sizeof(target_host), "%s%s", sysroot,
                     guest_target);
    if (n < 0 || (size_t) n >= sizeof(target_host)) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    char link_host[LINUX_PATH_MAX];
    if (tx->host_path[0] == '/') {
        if (str_copy_trunc(link_host, tx->host_path, sizeof(link_host)) >=
            sizeof(link_host)) {
            errno = ENAMETOOLONG;
            return NULL;
        }
    } else {
        char dir_host[LINUX_PATH_MAX];
        if (fcntl(dir_ref->fd, F_GETPATH, dir_host) < 0)
            return NULL;
        n = snprintf(link_host, sizeof(link_host), "%s/%s", dir_host,
                     tx->host_path);
        if (n < 0 || (size_t) n >= sizeof(link_host)) {
            errno = ENAMETOOLONG;
            return NULL;
        }
    }

    char link_parent[LINUX_PATH_MAX];
    if (path_parent_copy(link_host, link_parent, sizeof(link_parent)) < 0)
        return NULL;
    if (relative_path_between(link_parent, target_host, buf, bufsz) < 0)
        return NULL;
    return buf;
}

/* open/close. */

int64_t sys_openat_path(guest_t *g,
                        int dirfd,
                        const char *pathp,
                        int linux_flags,
                        int mode)
{
    if (linux_flags & LINUX_O_CREAT) {
        int sidecar_fd =
            sidecar_openat(dirfd, pathp, linux_flags, (mode_t) mode);
        if (sidecar_fd != (int) SIDECAR_NOT_HANDLED) {
            if (sidecar_fd < 0)
                return linux_errno();
            int type = opened_fd_type(sidecar_fd, linux_flags);
            if (type < 0) {
                close_keep_errno(sidecar_fd);
                return linux_errno();
            }
            int guest_fd = fd_alloc_opened_host(sidecar_fd, type, linux_flags,
                                                -1, NULL, NULL);
            if (guest_fd < 0) {
                close_keep_errno(sidecar_fd);
                return linux_errno();
            }
            return guest_fd;
        }
    }

    path_translation_t tx;
    unsigned int tx_flags =
        (linux_flags & LINUX_O_NOFOLLOW) ? PATH_TR_NOFOLLOW : PATH_TR_NONE;
    if (linux_flags & LINUX_O_CREAT)
        tx_flags = PATH_TR_CREATE | PATH_TR_CREATE_PARENTS;
    if (path_translate_at(dirfd, pathp, tx_flags, &tx) < 0)
        return linux_errno();

    int flags = translate_open_flags(linux_flags);
    if (!tx.fuse_path && tx.proc_resolved == 0 && dirfd == LINUX_AT_FDCWD &&
        pathp[0] != '/' && !proc_get_sysroot()) {
        int host_fd = openat(AT_FDCWD, pathp, flags, mode);
        if (host_fd < 0)
            return linux_errno();

        int type = opened_fd_type(host_fd, linux_flags);
        if (type < 0) {
            close_keep_errno(host_fd);
            return linux_errno();
        }
        int guest_fd =
            fd_alloc_opened_host(host_fd, type, linux_flags, -1, NULL, NULL);
        if (guest_fd < 0) {
            close_keep_errno(host_fd);
            return linux_errno();
        }
        return guest_fd;
    }

    /* Intercept /proc and /dev paths before touching the host filesystem */
    if (path_might_use_open_intercept(tx.intercept_path)) {
        if (!strcmp(tx.intercept_path, "/dev/fuse"))
            return fuse_proc_open(linux_flags);
        int64_t fuse_fd =
            fuse_open_path(g, tx.intercept_path, linux_flags, mode);
        if (fuse_fd != INT64_MIN)
            return fuse_fd;
        int intercepted =
            proc_intercept_open(g, tx.intercept_path, linux_flags, mode);
        if (intercepted >= 0) {
            /* Got a host fd from the intercept. Device nodes (/dev/...) use
             * fd_alloc() for POSIX lowest-fd semantics because busybox sh
             * relies on close(0)+open("/dev/null") returning fd 0. Synthetic
             * /proc files use fd_alloc_from(128) to avoid races with concurrent
             * GC finalizers that may close stale low-numbered fds.
             */
            int type = intercepted_fd_type(tx.intercept_path, intercepted,
                                           linux_flags);
            if (type < 0) {
                /* /dev/ptmx registers a keepalive slave under intercepted
                 * before this point; without dropping it here the slave fd
                 * leaks because nothing else has the master in fd_table.
                 * proc_pty_close_keepalive is a no-op for other paths.
                 */
                proc_pty_close_keepalive(intercepted);
                close_keep_errno(intercepted);
                return linux_errno();
            }
            int min_guest_fd =
                (!strncmp(tx.intercept_path, "/dev/", 5)) ? -1 : 128;
            int guest_fd = fd_alloc_opened_host(
                intercepted, type, linux_flags, min_guest_fd,
                fd_cleanup_for_type(type), tx.intercept_path);
            if (guest_fd < 0) {
                proc_pty_close_keepalive(intercepted);
                close_keep_errno(intercepted);
                return linux_errno();
            }
            return guest_fd;
        }
        if (intercepted == -1) {
            /* Intercept matched but failed */
            return linux_errno();
        }
        /* intercepted == PROC_NOT_INTERCEPTED: fall through to real openat */
    }

    if (dirfd == LINUX_AT_FDCWD) {
        int host_fd = open(tx.host_path, flags, mode);
        if (host_fd < 0)
            return linux_errno();

        int type = opened_fd_type(host_fd, linux_flags);
        if (type < 0) {
            close_keep_errno(host_fd);
            return linux_errno();
        }
        int guest_fd =
            fd_alloc_opened_host(host_fd, type, linux_flags, -1, NULL, NULL);
        if (guest_fd < 0) {
            close_keep_errno(host_fd);
            return linux_errno();
        }
        return guest_fd;
    }

    host_fd_ref_t dir_ref;
    if (host_dirfd_ref_open(dirfd, &dir_ref) < 0)
        return -LINUX_EBADF;

    int host_fd = openat(dir_ref.fd, tx.host_path, flags, mode);
    host_fd_ref_close(&dir_ref);
    if (host_fd < 0)
        return linux_errno();

    int type = opened_fd_type(host_fd, linux_flags);
    if (type < 0) {
        close_keep_errno(host_fd);
        return linux_errno();
    }
    int guest_fd =
        fd_alloc_opened_host(host_fd, type, linux_flags, -1, NULL, NULL);
    if (guest_fd < 0) {
        close_keep_errno(host_fd);
        return linux_errno();
    }
    return guest_fd;
}

int64_t sys_openat(guest_t *g,
                   int dirfd,
                   uint64_t path_gva,
                   int linux_flags,
                   int mode)
{
    char short_path[64];
    char path[LINUX_PATH_MAX];
    const char *pathp;
    if (guest_read_path(g, path_gva, short_path, sizeof(short_path), path,
                        sizeof(path), &pathp) < 0)
        return -LINUX_EFAULT;
    return sys_openat_path(g, dirfd, pathp, linux_flags, mode);
}

int64_t sys_close(int fd)
{
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
        return -LINUX_EBADF;

    /* Clean up abstract socket filesystem entry if this fd owns one */
    absock_unregister_fd(fd);

    int host_fd = -1;
    if (fd_close_regular_relaxed(fd, &host_fd)) {
        /* The fast path bypasses fd_cleanup_entry, so any side tables keyed by
         * host_fd that the slow path drops must be drained here too.
         * proc_pty_close_keepalive is a cheap no-op for non-pty fds and
         * prevents the keepalive slave from leaking past a /dev/ptmx close when
         * no per-type cleanup is registered.
         */
        proc_pty_close_keepalive(host_fd);
        if (close(host_fd) < 0)
            return linux_errno();
        return 0;
    }

    /* Atomically snapshot and mark closed under fd_lock. This prevents a TOCTOU
     * race where two concurrent sys_close() calls both read the same open entry
     * and double-close the host fd.
     */
    fd_entry_t snap;
    if (!fd_snapshot_and_close_relaxed(fd, &snap))
        return -LINUX_EBADF;

    fd_cleanup_entry(fd, &snap);
    return 0;
}

/* dup/fcntl. */

static void discard_allocated_fd(int guest_fd)
{
    fd_entry_t snap;
    if (fd_snapshot_and_close(guest_fd, &snap))
        fd_cleanup_entry(guest_fd, &snap);
}

/* Open a DIR stream over a dup of dst_host_fd if the source was an FD_DIR.
 *
 * Returns NULL on success-but-no-stream-needed (non-dir source) or on
 * dup/fdopendir failure with errno preserved. Pulled out of the critical
 * section in install_fd_alias_metadata_atomic because dup and fdopendir are
 * slow syscalls that must not hold fd_lock.
 */
static DIR *clone_dir_stream(const fd_entry_t *src_snap,
                             int dst_host_fd,
                             bool *out_failed)
{
    *out_failed = false;
    if (src_snap->type != FD_DIR)
        return NULL;

    int dir_fd = dup(dst_host_fd);
    if (dir_fd < 0) {
        *out_failed = true;
        return NULL;
    }
    DIR *dir = fdopendir(dir_fd);
    if (!dir) {
        int saved_errno = errno;
        close(dir_fd);
        errno = saved_errno;
        *out_failed = true;
        return NULL;
    }
    return dir;
}

/* Install dup-alias metadata atomically with the slot identity. Uses the (type,
 * host_fd) tuple as proof that the slot still belongs to the in-flight
 * duplicate_guest_fd call; a sibling vCPU's pathological close + open between
 * the relaxed allocator's lock release and this call could otherwise clobber
 * the sibling's freshly-installed entry.
 * Returns true on successful install, false if the slot was reallocated (caller
 * must closedir any cloned dir to avoid a leak).
 */
static bool install_fd_alias_metadata_atomic(int dst_fd,
                                             int expected_type,
                                             int expected_host_fd,
                                             const fd_entry_t *src_snap,
                                             int linux_flags,
                                             DIR *dir)
{
    /* LINUX_O_NONBLOCK is a file-status flag preserved by dup(2)/dup2(2).
     * Required for FD_TIMERFD (and any other type that stores NONBLOCK in
     * linux_flags rather than on the host fd) so a duplicated non-blocking
     * timerfd does not silently turn blocking.
     */
    int preserved_flags =
        src_snap->linux_flags &
        (LINUX_O_ACCMODE | LINUX_O_PATH | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
         LINUX_O_DIRECT | LINUX_O_LARGEFILE | LINUX_O_NONBLOCK);
    int final_flags = preserved_flags | linux_flags;

    bool installed = false;
    pthread_mutex_lock(&fd_lock);
    if (fd_table[dst_fd].type == expected_type &&
        fd_table[dst_fd].host_fd == expected_host_fd) {
        fd_table[dst_fd].linux_flags = final_flags;
        fd_table[dst_fd].seals = src_snap->seals;
        memcpy(fd_table[dst_fd].proc_path, src_snap->proc_path,
               sizeof(fd_table[dst_fd].proc_path));
        if (dir)
            fd_table[dst_fd].dir = dir;
        bool readable_urandom =
            expected_type == FD_URANDOM &&
            (final_flags & LINUX_O_ACCMODE) != LINUX_O_WRONLY;
        shim_globals_mark_urandom_fd(dst_fd, readable_urandom);
        installed = true;
    }
    pthread_mutex_unlock(&fd_lock);
    return installed;
}

/* Duplicate a guest fd into either the next free slot >= min_guest_fd or a
 * fixed slot. The helper keeps fd metadata copying and directory-stream cloning
 * in one place so dup(), dup3(), and fcntl(F_DUPFD*) stay consistent.
 */
static int duplicate_guest_fd(int src_fd,
                              int min_guest_fd,
                              int fixed_guest_fd,
                              bool fixed_slot,
                              int linux_flags)
{
    /* Hold pty_keepalive_lock across the source snapshot, host dup, and
     * keepalive mirror so a concurrent sys_close on src_fd cannot remove the
     * source's keepalive entry between fd_snapshot_and_dup and
     * proc_pty_dup_keepalive_locked. Without this bracket the alias would land
     * in fd_table with no keepalive of its own.
     *
     * Lock order is pty_keepalive_lock -> fd_lock (fd_snapshot_and_dup takes
     * fd_lock internally); proc_pty_master_adopt's joint-locked publish uses
     * the same order so the two paths do not deadlock.
     */
    proc_pty_lock_for_dup();
    fd_entry_t src_snap;
    int new_host_fd = fd_snapshot_and_dup(src_fd, &src_snap);
    if (new_host_fd < 0 && src_snap.type == FD_CLOSED) {
        proc_pty_unlock_for_dup();
        errno = EBADF;
        return -1;
    }
    if (src_snap.type == FD_FUSE_DEV || src_snap.type == FD_FUSE_FILE ||
        src_snap.type == FD_FUSE_DIR) {
        proc_pty_unlock_for_dup();
        if (new_host_fd >= 0)
            close_keep_errno(new_host_fd);
        return fuse_dup_fd(src_fd, min_guest_fd, fixed_guest_fd, fixed_slot,
                           linux_flags);
    }
    /* eventfd dup must share the underlying counter and pipe state across the
     * source and destination fds (Linux contract). Pass src_snap's host_fd
     * through so eventfd_dup_fd can verify the source fd still refers to the
     * same live eventfd between the snapshot here and the bind there.
     */
    if (src_snap.type == FD_EVENTFD) {
        proc_pty_unlock_for_dup();
        if (new_host_fd >= 0)
            close_keep_errno(new_host_fd);
        return eventfd_dup_fd(src_fd, src_snap.host_fd, min_guest_fd,
                              fixed_guest_fd, fixed_slot, linux_flags);
    }
    if (new_host_fd < 0) {
        proc_pty_unlock_for_dup();
        return -1;
    }

    /* Mirror any /dev/ptmx keepalive BEFORE fd_alloc publishes guest_fd. Once
     * the guest fd exists, a sibling thread can close it; that runs
     * fd_cleanup_entry which calls proc_pty_close_keepalive(new_host_fd). For
     * that cleanup to drop the freshly-duped keepalive, the keepalive entry
     * must already be in the table; registering after fd_alloc would lose the
     * race and leak the slave fd. No-op when the source has no keepalive.
     */
    proc_pty_dup_keepalive_locked(src_snap.host_fd, new_host_fd);
    proc_pty_unlock_for_dup();

    int new_type = (src_snap.type == FD_STDIO) ? FD_REGULAR : src_snap.type;
    void (*cleanup)(int) = fd_cleanup_for_type(new_type);
    int guest_fd = fixed_slot ? fd_alloc_at_relaxed(fixed_guest_fd, new_type,
                                                    new_host_fd, cleanup)
                              : fd_alloc_from_relaxed(min_guest_fd, new_type,
                                                      new_host_fd, cleanup);
    if (guest_fd < 0) {
        if (fixed_slot)
            errno = EBADF;
        /* fd_cleanup_entry never ran on new_host_fd (no guest fd was
         * registered), so the keepalive must be dropped explicitly here.
         */
        proc_pty_close_keepalive(new_host_fd);
        close_keep_errno(new_host_fd);
        return -1;
    }

    /* Clone the DIR stream outside fd_lock (dup + fdopendir would block other
     * fd ops), then install everything atomically under fd_lock with a tuple
     * verification so a sibling close + reopen on the same guest_fd cannot make
     * this install land on an unrelated slot.
     */
    bool dir_clone_failed = false;
    DIR *dir = clone_dir_stream(&src_snap, new_host_fd, &dir_clone_failed);
    if (dir_clone_failed) {
        int saved_errno = errno;
        discard_allocated_fd(guest_fd);
        errno = saved_errno;
        return -1;
    }

    if (!install_fd_alias_metadata_atomic(guest_fd, new_type, new_host_fd,
                                          &src_snap, linux_flags, dir)) {
        /* Slot was reallocated by a sibling while metadata install was pending;
         * the sibling's close path already cleaned up new_host_fd via
         * fd_cleanup_entry, so the only resource this side still owns is the
         * cloned DIR stream.
         */
        if (dir)
            closedir(dir);
    }

    return guest_fd;
}

static void fd_set_seals_for_aliases(int fd, int host_fd, int seals)
{
    struct stat target;
    if (fstat(host_fd, &target) < 0) {
        fd_table[fd].seals = seals;
        return;
    }

    pthread_mutex_lock(&fd_lock);
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (fd_table[i].type == FD_CLOSED)
            continue;

        struct stat candidate;
        if (fstat(fd_table[i].host_fd, &candidate) == 0 &&
            candidate.st_dev == target.st_dev &&
            candidate.st_ino == target.st_ino) {
            fd_table[i].seals = seals;
        }
    }
    pthread_mutex_unlock(&fd_lock);
}

int64_t sys_dup(int oldfd)
{
    int guest_fd = duplicate_guest_fd(oldfd, 0, -1, false, 0);
    if (guest_fd < 0)
        return linux_errno();
    return guest_fd;
}

int64_t sys_dup3(int oldfd, int newfd, int linux_flags)
{
    if (linux_flags & ~LINUX_O_CLOEXEC)
        return -LINUX_EINVAL;
    if (!RANGE_CHECK(oldfd, 0, FD_TABLE_SIZE))
        return -LINUX_EBADF;
    if (!RANGE_CHECK(newfd, 0, FD_TABLE_SIZE))
        return -LINUX_EBADF;
    /* Linux dup3(2): EINVAL if oldfd == newfd (unlike dup2 which is a no-op) */
    if (oldfd == newfd)
        return -LINUX_EINVAL;
    if (duplicate_guest_fd(oldfd, 0, newfd, true,
                           linux_flags & LINUX_O_CLOEXEC) < 0)
        return linux_errno();
    return newfd;
}

int64_t sys_fcntl(guest_t *g, int fd, int cmd, uint64_t arg)
{
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
        return -LINUX_EBADF;

    /* Snapshot the slot under fd_lock once; readers use fd_snap below, and
     * writers reacquire fd_lock and revalidate against fd_snap.generation so a
     * close+reopen between the snapshot and the RMW returns EBADF instead of
     * mutating an unrelated fd.
     */
    fd_entry_t fd_snap;
    if (!fd_snapshot(fd, &fd_snap))
        return -LINUX_EBADF;

    int fd_type = fd_snap.type;
    bool fuse_fd = (fd_type == FD_FUSE_DEV || fd_type == FD_FUSE_FILE ||
                    fd_type == FD_FUSE_DIR);

    /* Linux F_DUPFD=0, F_GETFD=1, F_SETFD=2, F_GETFL=3, F_SETFL=4,
     * F_DUPFD_CLOEXEC=1030
     */
    switch (cmd) {
    case 0: /* F_DUPFD */
    case 1030: /* F_DUPFD_CLOEXEC */ {
        if ((int) arg < 0) {
            return -LINUX_EINVAL;
        }
        int dup_flags = fd_snap.linux_flags & ~LINUX_O_CLOEXEC;
        if (cmd == 1030)
            dup_flags |= LINUX_O_CLOEXEC;
        int gfd = duplicate_guest_fd(fd, (int) arg, -1, false, dup_flags);
        if (gfd < 0) {
            if (errno == EBADF)
                return -LINUX_EBADF;
            if (errno == EOPNOTSUPP)
                return -LINUX_EOPNOTSUPP;
            return -LINUX_EMFILE;
        }
        return gfd;
    }
    case 1: /* F_GETFD */
        return (fd_snap.linux_flags & LINUX_O_CLOEXEC) ? LINUX_FD_CLOEXEC : 0;
    case 2: /* F_SETFD */
        /* Hold fd_lock across the read-modify-write so the CLOEXEC flip is
         * atomic against a concurrent F_SETFL on the same shadow word and
         * against any fd_lock-protected reader. Revalidate against the snapshot
         * generation so a close+reopen returns EBADF.
         */
        pthread_mutex_lock(&fd_lock);
        if (fd_table[fd].type == FD_CLOSED ||
            fd_table[fd].generation != fd_snap.generation) {
            pthread_mutex_unlock(&fd_lock);
            return -LINUX_EBADF;
        }
        if ((int) arg & LINUX_FD_CLOEXEC)
            fd_table[fd].linux_flags |= LINUX_O_CLOEXEC;
        else
            fd_table[fd].linux_flags &= ~LINUX_O_CLOEXEC;
        pthread_mutex_unlock(&fd_lock);
        return 0;
    case 3: { /* F_GETFL */
        if (fuse_fd)
            return fd_snap.linux_flags;
        /* Linux timerfd F_GETFL reports O_RDWR plus the writable status bits
         * the kernel honors. Surface only those bits from the shadow rather
         * than echoing arbitrary linux_flags bits so stray F_SETFL args cannot
         * leak through here. O_ASYNC stays off because timerfd_fops lacks
         * ->fasync, so generic_setfl drops it.
         */
        if (fd_type == FD_TIMERFD)
            return LINUX_O_RDWR |
                   (fd_snap.linux_flags &
                    (LINUX_O_APPEND | LINUX_O_NONBLOCK | LINUX_O_NOATIME));
        host_fd_ref_t host_ref;
        if (host_fd_ref_open(fd, &host_ref) < 0)
            return -LINUX_EBADF;
        int mac_fl = fcntl(host_ref.fd, F_GETFL);
        host_fd_ref_close(&host_ref);
        if (mac_fl < 0)
            return linux_errno();
        int linux_fl = mac_to_linux_status_flags(mac_fl);
        if (fd_snap.type == FD_REGULAR || fd_snap.type == FD_DIR ||
            fd_snap.type == FD_PATH || fd_snap.type == FD_URANDOM)
            linux_fl = (linux_fl & ~O_ACCMODE) | (fd_snap.linux_flags & 3);
        linux_fl |= fd_snap.linux_flags &
                    (LINUX_O_PATH | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
                     LINUX_O_DIRECT | LINUX_O_LARGEFILE);
        return linux_fl;
    }
    case 4: /* F_SETFL */
    {
        if (fuse_fd) {
            /* Preserve LINUX_O_ACCMODE: F_SETFL is not allowed to change the
             * access mode in the Linux kernel, and without preserving it here a
             * stray F_SETFL(0) would silently flip an O_RDWR FUSE shadow to
             * O_RDONLY, surfacing the wrong mode through F_GETFL.
             *
             * Hold fd_lock across the read-modify-write so the update is atomic
             * against a concurrent F_SETFD and any fd_lock-protected reader.
             * Revalidate against the snapshot generation so a close+reopen
             * returns EBADF.
             */
            pthread_mutex_lock(&fd_lock);
            if (fd_table[fd].type != fd_type ||
                fd_table[fd].generation != fd_snap.generation) {
                pthread_mutex_unlock(&fd_lock);
                return -LINUX_EBADF;
            }
            int preserved = fd_table[fd].linux_flags &
                            (LINUX_O_ACCMODE | LINUX_O_CLOEXEC | LINUX_O_PATH |
                             LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
                             LINUX_O_DIRECT | LINUX_O_LARGEFILE);
            fd_table[fd].linux_flags =
                preserved | ((int) arg & ~(LINUX_O_ACCMODE | LINUX_O_CLOEXEC |
                                           LINUX_O_PATH | LINUX_O_DIRECTORY |
                                           LINUX_O_NOFOLLOW | LINUX_O_DIRECT |
                                           LINUX_O_LARGEFILE));
            pthread_mutex_unlock(&fd_lock);
            return 0;
        }
        /* Timerfd: kqueue host fd rejects fcntl(F_SETFL), so mirror Linux's
         * file-status word in the linux_flags shadow. Of Linux's writable
         * status flags (O_APPEND, O_ASYNC, O_DIRECT, O_NOATIME, O_NONBLOCK) the
         * timerfd kernel object honors O_APPEND, O_NONBLOCK, and O_NOATIME.
         * O_ASYNC is silently dropped (timerfd_fops lacks ->fasync). O_DIRECT
         * returns -EINVAL because the inode lacks FMODE_CAN_ODIRECT. Bits
         * outside the writable set (access mode, CLOEXEC,
         * O_PATH/DIRECTORY/NOFOLLOW/etc.) are silently ignored, matching how
         * Linux F_SETFL drops them.
         */
        if (fd_type == FD_TIMERFD) {
            const int setfl_mask =
                LINUX_O_APPEND | LINUX_O_NONBLOCK | LINUX_O_NOATIME;
            pthread_mutex_lock(&fd_lock);
            if (fd_table[fd].type != FD_TIMERFD ||
                fd_table[fd].generation != fd_snap.generation) {
                pthread_mutex_unlock(&fd_lock);
                return -LINUX_EBADF;
            }
            if ((int) arg & LINUX_O_DIRECT) {
                pthread_mutex_unlock(&fd_lock);
                return -LINUX_EINVAL;
            }
            fd_table[fd].linux_flags =
                (fd_table[fd].linux_flags & ~setfl_mask) |
                ((int) arg & setfl_mask);
            pthread_mutex_unlock(&fd_lock);
            return 0;
        }
        host_fd_ref_t host_ref;
        if (host_fd_ref_open(fd, &host_ref) < 0)
            return -LINUX_EBADF;
        int rc =
            fcntl(host_ref.fd, F_SETFL, linux_to_mac_status_flags((int) arg));
        host_fd_ref_close(&host_ref);
        return rc < 0 ? linux_errno() : 0;
    }
    case 5:   /* F_GETLK */
    case 6:   /* F_SETLK */
    case 7: { /* F_SETLKW */
        host_fd_ref_t host_ref;
        if (host_fd_ref_open(fd, &host_ref) < 0)
            return -LINUX_EBADF;
        /* Translate Linux struct flock (aarch64) to macOS struct flock. Linux
         * aarch64 layout: {short l_type, short l_whence,
         *   long l_start, long l_len, int l_pid, pad[4]}
         * macOS layout: {off_t l_start, off_t l_len, pid_t l_pid,
         *   short l_type, short l_whence}
         * Use guest_read/guest_write (not guest_ptr) to safely handle structs
         * that span 2MiB page table block boundaries.
         */
        uint8_t lflock[32]; /* Linux struct flock is 32 bytes on aarch64 */
        if (guest_read_small(g, arg, lflock, sizeof(lflock)) < 0)
            return -LINUX_EFAULT;

        /* Read Linux flock fields */
        int16_t l_type, l_whence;
        int64_t l_start, l_len;
        memcpy(&l_type, lflock + 0, 2);
        memcpy(&l_whence, lflock + 2, 2);
        memcpy(&l_start, lflock + 8, 8); /* offset 8 due to padding */
        memcpy(&l_len, lflock + 16, 8);

        /* l_type constants differ between Linux and macOS/BSD:
         *   Linux: F_RDLCK=0, F_WRLCK=1, F_UNLCK=2
         *   macOS: F_RDLCK=1, F_UNLCK=2, F_WRLCK=3
         * Passing the Linux value straight through makes a Linux F_RDLCK (0) an
         * invalid type on macOS, which fcntl() rejects with EINVAL. This is the
         * lock POSIX databases (e.g. SQLite) take first, so it must map.
         */
        short mac_type;
        switch (l_type) {
        case 0: /* LINUX_F_RDLCK */
            mac_type = F_RDLCK;
            break;
        case 1: /* LINUX_F_WRLCK */
            mac_type = F_WRLCK;
            break;
        case 2: /* LINUX_F_UNLCK */
            mac_type = F_UNLCK;
            break;
        default:
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }

        struct flock mac_fl = {
            .l_start = l_start,
            .l_len = l_len,
            .l_pid = 0,
            .l_type = mac_type,
            .l_whence = l_whence, /* SEEK_SET=0, SEEK_CUR=1, SEEK_END=2 same */
        };

        int mac_cmd = (cmd == 5) ? F_GETLK : (cmd == 6) ? F_SETLK : F_SETLKW;
        if (fcntl(host_ref.fd, mac_cmd, &mac_fl) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }

        /* For F_GETLK, write back the result */
        if (cmd == 5) {
            /* Map macOS l_type back to Linux constants (see above). */
            int16_t rt;
            switch (mac_fl.l_type) {
            case F_RDLCK:
                rt = 0; /* LINUX_F_RDLCK */
                break;
            case F_WRLCK:
                rt = 1; /* LINUX_F_WRLCK */
                break;
            default:
                rt = 2; /* LINUX_F_UNLCK */
                break;
            }
            int16_t rw = mac_fl.l_whence;
            int64_t rs = mac_fl.l_start, rl = mac_fl.l_len;
            int32_t rp = mac_fl.l_pid;
            memset(lflock, 0, sizeof(lflock));
            memcpy(lflock + 0, &rt, 2);
            memcpy(lflock + 2, &rw, 2);
            memcpy(lflock + 8, &rs, 8);
            memcpy(lflock + 16, &rl, 8);
            memcpy(lflock + 24, &rp, 4);
            if (guest_write_small(g, arg, lflock, sizeof(lflock)) < 0) {
                host_fd_ref_close(&host_ref);
                return -LINUX_EFAULT;
            }
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }
    case 1024: /* F_GETPIPE_SZ */
        /* macOS does not support pipe size queries; return default 64KiB */
        return 65536;
    case 1031: /* F_SETPIPE_SZ */
        /* macOS does not support pipe size setting; pretend success */
        return (int64_t) arg;
    case LINUX_F_GET_SEALS:
        return fd_table[fd].seals;
    case LINUX_F_ADD_SEALS: {
        host_fd_ref_t host_ref;
        if (host_fd_ref_open(fd, &host_ref) < 0)
            return -LINUX_EBADF;
        int cur = fd_table[fd].seals;
        /* Cannot add seals if F_SEAL_SEAL is already set */
        if (cur & LINUX_F_SEAL_SEAL) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EPERM;
        }
        int new_seals = (int) arg;
        /* Only allow valid seal bits */
        if (new_seals &
            ~(LINUX_F_SEAL_SEAL | LINUX_F_SEAL_SHRINK | LINUX_F_SEAL_GROW |
              LINUX_F_SEAL_WRITE | LINUX_F_SEAL_FUTURE_WRITE)) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
        fd_set_seals_for_aliases(fd, host_ref.fd, cur | new_seals);
        host_fd_ref_close(&host_ref);
        return 0;
    }
    default:
        return -LINUX_EINVAL;
    }
}

#define LINUX_CLOSE_RANGE_CLOEXEC 4

int64_t sys_close_range(unsigned int first,
                        unsigned int last,
                        unsigned int flags)
{
    /* Linux returns EINVAL when first > last (even if both are valid) */
    if (first > last)
        return -LINUX_EINVAL;
    /* Reject unknown flags */
    if (flags & ~(unsigned) LINUX_CLOSE_RANGE_CLOEXEC)
        return -LINUX_EINVAL;
    /* Clamp to FD table size (Linux clamps ~0U to NR_OPEN_MAX) */
    if (last >= (unsigned) FD_TABLE_SIZE)
        last = FD_TABLE_SIZE - 1;

    /* CLOSE_RANGE_CLOEXEC: mark FDs as CLOEXEC without closing them. Hold
     * fd_lock to prevent races with concurrent fd_alloc/close.
     */
    if (flags & LINUX_CLOSE_RANGE_CLOEXEC) {
        pthread_mutex_lock(&fd_lock);
        for (unsigned int i = first; i <= last && i < (unsigned) FD_TABLE_SIZE;
             i++) {
            if (fd_table[i].type != FD_CLOSED)
                fd_table[i].linux_flags |= LINUX_O_CLOEXEC;
        }
        pthread_mutex_unlock(&fd_lock);
        return 0;
    }

    for (unsigned int i = first; i <= last && i < (unsigned) FD_TABLE_SIZE;
         i++) {
        fd_entry_t snap;
        if (!fd_snapshot_and_close((int) i, &snap))
            continue;

        fd_cleanup_entry((int) i, &snap);
    }
    return 0;
}

/* directory operations. */

/* getdents64: read directory entries from a guest directory fd. Uses the
 * persistent DIR* stored in fd_table (created by openat).
 */
int64_t sys_getdents64(guest_t *g, int fd, uint64_t buf_gva, uint64_t count)
{
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
        return -LINUX_EBADF;
    if (fd_table[fd].type == FD_CLOSED)
        return -LINUX_EBADF;
    if (fuse_is_dir_fd(fd))
        return fuse_getdents64(g, fd, buf_gva, count);
    /* Linux: getdents on an O_PATH fd returns EBADF, even when the underlying
     * inode is a directory. The early gate keeps the next NOTDIR fallback
     * specific to non-directory regular fds.
     */
    if (fd_table[fd].type == FD_PATH)
        return -LINUX_EBADF;

    DIR *dir = (DIR *) fd_table[fd].dir;
    if (!dir)
        return -LINUX_ENOTDIR;

    if (!guest_ptr(g, buf_gva))
        return -LINUX_EFAULT;

    size_t guest_pos = 0;
    struct dirent *de;

    /* Temp buffer for dirent serialization. Max dirent64 is 280 bytes (19-byte
     * header + NAME_MAX=255 + null + padding to 8). Using a stack buffer avoids
     * guest_ptr boundary issues: guest_write() handles 2MiB block crossings
     * that raw memcpy into guest_ptr() cannot.
     */
    uint8_t entry_buf[280];

    while (1) {
        /* Save position BEFORE readdir so getdents emulation can rewind if the
         * entry does not fit. macOS telldir returns an opaque cookie --
         * arithmetic on it (e.g. telldir()-1) is undefined.
         */
        long saved_pos = telldir(dir);
        de = readdir(dir);
        if (!de)
            break;

        char guest_name[NAME_MAX + 1];
        int name_rc = path_translate_dirent_name(fd, de->d_name, guest_name,
                                                 sizeof(guest_name));
        if (name_rc > 0)
            continue;
        if (name_rc < 0)
            return guest_pos > 0 ? (int64_t) guest_pos : linux_errno();

        size_t name_len = strlen(guest_name);
        /* Linux dirent64: 19-byte header + name + null, padded to 8 */
        size_t reclen = (19 + name_len + 1 + 7) & ~7ULL;

        if (guest_pos + reclen > count) {
            /* Entry does not fit; rewind so next call gets it */
            seekdir(dir, saved_pos);
            break;
        }

        linux_dirent64_t lde;
        lde.d_ino = de->d_ino;
        lde.d_off = telldir(dir);
        lde.d_reclen = (uint16_t) reclen;
        lde.d_type = de->d_type;

        /* Serialize entry into temp buffer, then copy to guest via
         * guest_write() which handles 2MiB block boundary crossings.
         */
        memcpy(entry_buf, &lde, sizeof(lde));
        memcpy(entry_buf + 19, guest_name, name_len + 1);
        size_t pad_start = 19 + name_len + 1;
        if (pad_start < reclen)
            memset(entry_buf + pad_start, 0, reclen - pad_start);

        if (guest_write(g, buf_gva + guest_pos, entry_buf, reclen) < 0)
            return guest_pos > 0 ? (int64_t) guest_pos : -LINUX_EFAULT;

        guest_pos += reclen;
    }

    return (int64_t) guest_pos;
}

int64_t sys_chdir(guest_t *g, uint64_t path_gva)
{
    char path[LINUX_PATH_MAX];
    path_translation_t tx;
    int64_t rc = read_translated_path(g, LINUX_AT_FDCWD, path_gva, PATH_TR_NONE,
                                      path, &tx);
    if (rc < 0)
        return rc;

    char proc_virt[64];
    const char *virt =
        proc_virtual_dir_path(tx.guest_path, proc_virt, sizeof(proc_virt));
    if (virt) {
        int host_fd =
            proc_intercept_open(g, tx.intercept_path, LINUX_O_DIRECTORY, 0);
        if (host_fd < 0)
            return linux_errno();
        int chdir_rc = fchdir(host_fd);
        int saved_errno = errno;
        close_keep_errno(host_fd);
        if (chdir_rc < 0) {
            errno = saved_errno;
            return linux_errno();
        }
        proc_cwd_set_virtual(virt);
        return 0;
    }

    if (tx.intercept_path && fuse_path_matches_mount(tx.intercept_path)) {
        struct stat st;
        /* chdir() always follows symlinks, so do not pass AT_SYMLINK_NOFOLLOW.
         */
        int stat_rc = fuse_stat_path(tx.intercept_path, &st, 0);
        if (stat_rc < 0)
            return stat_rc;
        if (!S_ISDIR(st.st_mode))
            return -LINUX_ENOTDIR;
        if (chdir(tx.host_path) < 0)
            return linux_errno();
        proc_cwd_set_virtual(tx.intercept_path);
        return 0;
    }

    if (chdir(tx.host_path) < 0)
        return linux_errno();

    if (proc_cwd_refresh() < 0)
        proc_cwd_invalidate();
    return 0;
}

int64_t sys_fchdir(int fd)
{
    int64_t fuse_rc = fuse_fchdir(fd);
    if (fuse_rc != INT64_MIN)
        return fuse_rc;

    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    char proc_virt[64];
    const char *proc_virtual = proc_virtual_dir_path(
        fd_table[fd].proc_path, proc_virt, sizeof(proc_virt));
    if (fchdir(host_ref.fd) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }
    host_fd_ref_close(&host_ref);
    if (proc_virtual) {
        proc_cwd_set_virtual(proc_virtual);
    } else if (proc_cwd_refresh() < 0) {
        proc_cwd_invalidate();
    }
    return 0;
}

int64_t sys_chroot(guest_t *g, uint64_t path_gva)
{
    char path[LINUX_PATH_MAX];
    if (guest_read_str(g, path_gva, path, sizeof(path)) < 0)
        return -LINUX_EFAULT;
    /* Only accept chroot("/") as a no-op. The original motivation was coreutils
     * stdbuf (fork -> chroot("/") -> exec) which never changes roots in
     * practice. Accepting an arbitrary path was a containment escape: a guest
     * already running under --sysroot=/opt/sr could call chroot("/etc") and
     * pivot to the host's /etc with no boundary check. Real chroot() requires
     * CAP_SYS_CHROOT, which the guest does not have in elfuse's single-process
     * VM model.
     */
    if (strcmp(path, "/") == 0)
        return 0;
    return -LINUX_EPERM;
}

/* pipe/seek. */

int64_t sys_pipe2(guest_t *g, uint64_t fds_gva, int linux_flags)
{
    if (linux_flags & ~(LINUX_O_CLOEXEC | LINUX_O_NONBLOCK | LINUX_O_DIRECT))
        return -LINUX_EINVAL;

    int host_fds[2];
    if (pipe(host_fds) < 0)
        return linux_errno();

#ifdef F_SETNOSIGPIPE
    (void) fcntl(host_fds[1], F_SETNOSIGPIPE, 1);
#endif

    int guest_fds[2];
    guest_fds[0] = fd_alloc(FD_PIPE, host_fds[0], NULL);
    if (guest_fds[0] < 0) {
        int saved_errno = errno;
        close(host_fds[0]);
        close(host_fds[1]);
        errno = saved_errno;
        return linux_errno();
    }

    guest_fds[1] = fd_alloc(FD_PIPE, host_fds[1], NULL);
    if (guest_fds[1] < 0) {
        int saved_errno = errno;
        fd_mark_closed(guest_fds[0]);
        close(host_fds[0]);
        close(host_fds[1]);
        errno = saved_errno;
        return linux_errno();
    }

    /* Apply O_NONBLOCK to host FDs if requested */
    if (linux_flags & LINUX_O_NONBLOCK) {
        fcntl(host_fds[0], F_SETFL, O_NONBLOCK);
        fcntl(host_fds[1], F_SETFL, O_NONBLOCK);
    }

    /* Propagate O_CLOEXEC if set in flags */
    fd_table[guest_fds[0]].linux_flags = linux_flags & LINUX_O_CLOEXEC;
    fd_table[guest_fds[1]].linux_flags = linux_flags & LINUX_O_CLOEXEC;

    int32_t fds[2] = {guest_fds[0], guest_fds[1]};
    if (guest_write_small(g, fds_gva, fds, sizeof(fds)) < 0) {
        fd_mark_closed(guest_fds[0]);
        fd_mark_closed(guest_fds[1]);
        close(host_fds[0]);
        close(host_fds[1]);
        return -LINUX_EFAULT;
    }

    return 0;
}

int64_t sys_lseek(int fd, int64_t offset, int whence)
{
    int64_t frc = fuse_lseek_fd(fd, offset, whence);
    if (frc != INT64_MIN)
        return frc;

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_io(fd, &host_ref);
    if (err < 0)
        return err;

    off_t ret = lseek(host_ref.fd, offset, whence);
    host_fd_ref_close(&host_ref);
    return ret < 0 ? linux_errno() : (int64_t) ret;
}

/* path operations. */

int64_t sys_readlinkat(guest_t *g,
                       int dirfd,
                       uint64_t path_gva,
                       uint64_t buf_gva,
                       uint64_t bufsiz)
{
    char path[LINUX_PATH_MAX];
    path_translation_t tx;
    int64_t rc =
        read_translated_path(g, dirfd, path_gva, PATH_TR_NOFOLLOW, path, &tx);
    if (rc < 0)
        return rc;

    /* Intercept /proc paths (e.g. /proc/self/exe, /proc/self/fd/N) */
    char link[LINUX_PATH_MAX];
    int intercepted =
        proc_intercept_readlink(tx.intercept_path, link, sizeof(link));
    if (intercepted >= 0) {
        size_t copy_len =
            (size_t) intercepted < bufsiz ? (size_t) intercepted : bufsiz;
        if (guest_write(g, buf_gva, link, copy_len) < 0)
            return -LINUX_EFAULT;
        return (int64_t) copy_len;
    }
    if (intercepted == -1) {
        return linux_errno();
    }
    /* intercepted == PROC_NOT_INTERCEPTED: fall through */

    if (tx.fuse_path)
        return -LINUX_ENOSYS;

    host_fd_ref_t dir_ref;
    if (host_dirfd_ref_open(dirfd, &dir_ref) < 0)
        return -LINUX_EBADF;

    /* Apply sysroot redirect for absolute paths */
    ssize_t len = readlinkat(dir_ref.fd, tx.host_path, link, sizeof(link) - 1);
    host_fd_ref_close(&dir_ref);
    if (len < 0)
        return linux_errno();

    size_t copy_len = (size_t) len < bufsiz ? (size_t) len : bufsiz;
    if (guest_write(g, buf_gva, link, copy_len) < 0)
        return -LINUX_EFAULT;

    return (int64_t) copy_len;
}

int64_t sys_unlinkat(guest_t *g, int dirfd, uint64_t path_gva, int flags)
{
    char path[LINUX_PATH_MAX];
    if (guest_read_str(g, path_gva, path, sizeof(path)) < 0)
        return -LINUX_EFAULT;

    if (!validate_at_flags(flags, LINUX_AT_REMOVEDIR))
        return -LINUX_EINVAL;

    int64_t sidecar_rc = sidecar_unlinkat(dirfd, path, flags);
    if (sidecar_rc != SIDECAR_NOT_HANDLED)
        return sidecar_rc;

    path_translation_t tx;
    int64_t rc =
        read_translated_path(g, dirfd, path_gva, PATH_TR_CREATE, path, &tx);
    if (rc < 0)
        return rc;
    rc = reject_unsupported_fuse_path_op(&tx);
    if (rc != INT64_MIN)
        return rc;

    host_fd_ref_t dir_ref;
    if (host_dirfd_ref_open(dirfd, &dir_ref) < 0)
        return -LINUX_EBADF;

    /* Rewrite /dev/shm/<name> to the host temp directory so shm_unlink works */
    const char *unlink_path;
    char shm_host[LINUX_PATH_MAX];
    if (!strncmp(tx.guest_path, "/dev/shm/", 9)) {
        if (proc_dev_shm_resolve(tx.guest_path + 9, shm_host,
                                 sizeof(shm_host)) < 0) {
            host_fd_ref_close(&dir_ref);
            return linux_errno();
        }
        unlink_path = shm_host;
        host_fd_ref_close(&dir_ref);
        dir_ref.fd = AT_FDCWD;
        dir_ref.owned = 0;
    } else {
        unlink_path = tx.host_path;
    }

    int host_flags = translate_at_flags(flags);
    if (unlinkat(dir_ref.fd, unlink_path, host_flags) < 0) {
        host_fd_ref_close(&dir_ref);
        return linux_errno();
    }

    host_fd_ref_close(&dir_ref);
    return 0;
}

int64_t sys_mkdirat(guest_t *g, int dirfd, uint64_t path_gva, int mode)
{
    char path[LINUX_PATH_MAX];
    if (guest_read_str(g, path_gva, path, sizeof(path)) < 0)
        return -LINUX_EFAULT;

    int64_t sidecar_rc = sidecar_mkdirat(dirfd, path, (mode_t) mode);
    if (sidecar_rc != SIDECAR_NOT_HANDLED)
        return sidecar_rc;

    path_translation_t tx;
    int64_t rc = read_translated_path(
        g, dirfd, path_gva, PATH_TR_CREATE | PATH_TR_CREATE_PARENTS, path, &tx);
    if (rc < 0)
        return rc;
    rc = reject_unsupported_fuse_path_op(&tx);
    if (rc != INT64_MIN)
        return rc;

    host_fd_ref_t dir_ref;
    if (host_dirfd_ref_open(dirfd, &dir_ref) < 0)
        return -LINUX_EBADF;

    if (mkdirat(dir_ref.fd, tx.host_path, (mode_t) mode) < 0) {
        host_fd_ref_close(&dir_ref);
        return linux_errno();
    }

    host_fd_ref_close(&dir_ref);
    return 0;
}

static int64_t close_dir_refs_result(host_fd_ref_t *old_ref,
                                     host_fd_ref_t *new_ref,
                                     int64_t result)
{
    host_fd_ref_close(old_ref);
    host_fd_ref_close(new_ref);
    return result;
}

/* Linux RENAME_* flags for renameat2 */
#define LINUX_RENAME_NOREPLACE (1 << 0)
#define LINUX_RENAME_EXCHANGE (1 << 1)

int64_t sys_renameat2(guest_t *g,
                      int olddirfd,
                      uint64_t oldpath_gva,
                      int newdirfd,
                      uint64_t newpath_gva,
                      int flags)
{
    char oldpath[LINUX_PATH_MAX], newpath[LINUX_PATH_MAX];
    path_translation_t old_tx, new_tx;
    if (guest_read_str(g, oldpath_gva, oldpath, sizeof(oldpath)) < 0 ||
        guest_read_str(g, newpath_gva, newpath, sizeof(newpath)) < 0)
        return -LINUX_EFAULT;

    if ((flags & ~(LINUX_RENAME_NOREPLACE | LINUX_RENAME_EXCHANGE)) ||
        ((flags & LINUX_RENAME_NOREPLACE) && (flags & LINUX_RENAME_EXCHANGE))) {
        return -LINUX_EINVAL;
    }

    int64_t sidecar_rc =
        sidecar_renameat(olddirfd, oldpath, newdirfd, newpath, flags);
    if (sidecar_rc != SIDECAR_NOT_HANDLED)
        return sidecar_rc;

    if (path_translate_at(olddirfd, oldpath, PATH_TR_NONE, &old_tx) < 0 ||
        path_translate_at(newdirfd, newpath, PATH_TR_CREATE, &new_tx) < 0)
        return linux_errno();
    if (old_tx.fuse_path || new_tx.fuse_path)
        return -LINUX_ENOSYS;

    host_fd_ref_t olddir_ref, newdir_ref;
    if (host_dirfd_ref_open(olddirfd, &olddir_ref) < 0)
        return -LINUX_EBADF;
    if (host_dirfd_ref_open(newdirfd, &newdir_ref) < 0) {
        host_fd_ref_close(&olddir_ref);
        return -LINUX_EBADF;
    }

    /* Apply sysroot resolution for absolute paths */
    /* RENAME_NOREPLACE: fail if destination exists. macOS renamex_np supports
     * RENAME_EXCL for the same semantics. Only supported for AT_FDCWD paths
     * (renamex_np does not take dirfd arguments).
     */
    if (flags & LINUX_RENAME_NOREPLACE) {
        if (olddirfd == LINUX_AT_FDCWD && newdirfd == LINUX_AT_FDCWD) {
            if (renamex_np(old_tx.host_path, new_tx.host_path, RENAME_EXCL) <
                0) {
                return close_dir_refs_result(&olddir_ref, &newdir_ref,
                                             linux_errno());
            }
            return close_dir_refs_result(&olddir_ref, &newdir_ref, 0);
        }
        /* For non-CWD dirfds, emulate with link+unlink. This is not atomic, but
         * linkat() still preserves the "destination must not exist"
         * requirement. This path still cannot handle directories because
         * hardlinking directories is not allowed.
         */
        if (linkat(olddir_ref.fd, old_tx.host_path, newdir_ref.fd,
                   new_tx.host_path, 0) < 0) {
            return close_dir_refs_result(&olddir_ref, &newdir_ref,
                                         linux_errno());
        }
        if (unlinkat(olddir_ref.fd, old_tx.host_path, 0) < 0) {
            int err = errno;
            (void) unlinkat(newdir_ref.fd, new_tx.host_path, 0);
            errno = err;
            return close_dir_refs_result(&olddir_ref, &newdir_ref,
                                         linux_errno());
        }
        return close_dir_refs_result(&olddir_ref, &newdir_ref, 0);
    }

    /* RENAME_EXCHANGE: swap two paths. macOS renamex_np supports RENAME_SWAP.
     */
    if (flags & LINUX_RENAME_EXCHANGE) {
        if (olddirfd == LINUX_AT_FDCWD && newdirfd == LINUX_AT_FDCWD) {
            if (renamex_np(old_tx.host_path, new_tx.host_path, RENAME_SWAP) <
                0) {
                return close_dir_refs_result(&olddir_ref, &newdir_ref,
                                             linux_errno());
            }
            return close_dir_refs_result(&olddir_ref, &newdir_ref, 0);
        }
        return close_dir_refs_result(
            &olddir_ref, &newdir_ref,
            -LINUX_EINVAL); /* RENAME_EXCHANGE requires AT_FDCWD on macOS */
    }

    if (olddirfd == LINUX_AT_FDCWD && newdirfd == LINUX_AT_FDCWD) {
        if (rename(old_tx.host_path, new_tx.host_path) < 0) {
            return close_dir_refs_result(&olddir_ref, &newdir_ref,
                                         linux_errno());
        }
        return close_dir_refs_result(&olddir_ref, &newdir_ref, 0);
    }

    if (renameat(olddir_ref.fd, old_tx.host_path, newdir_ref.fd,
                 new_tx.host_path) < 0) {
        return close_dir_refs_result(&olddir_ref, &newdir_ref, linux_errno());
    }
    return close_dir_refs_result(&olddir_ref, &newdir_ref, 0);
}

int64_t sys_mknodat(guest_t *g, int dirfd, uint64_t path_gva, int mode, int dev)
{
    (void) dev;
    char path[LINUX_PATH_MAX];
    path_translation_t tx;
    int64_t rc = read_translated_path(
        g, dirfd, path_gva, PATH_TR_CREATE | PATH_TR_CREATE_PARENTS, path, &tx);
    if (rc < 0)
        return rc;
    rc = reject_unsupported_fuse_path_op(&tx);
    if (rc != INT64_MIN)
        return rc;

    host_fd_ref_t dir_ref;
    if (host_dirfd_ref_open(dirfd, &dir_ref) < 0)
        return -LINUX_EBADF;

    /* Only support FIFO creation; other node types need root */
    if (S_ISFIFO(mode)) {
        if (mkfifoat(dir_ref.fd, tx.host_path, mode & 0777) < 0) {
            host_fd_ref_close(&dir_ref);
            return linux_errno();
        }
        host_fd_ref_close(&dir_ref);
        return 0;
    }

    /* Regular files: create an empty file */
    if (S_ISREG(mode) || (mode & S_IFMT) == 0) {
        int fd = openat(dir_ref.fd, tx.host_path, O_CREAT | O_WRONLY | O_EXCL,
                        mode & 0777);
        host_fd_ref_close(&dir_ref);
        if (fd < 0)
            return linux_errno();
        close(fd);
        return 0;
    }

    host_fd_ref_close(&dir_ref);
    return -LINUX_ENOSYS;
}

int64_t sys_symlinkat(guest_t *g,
                      uint64_t target_gva,
                      int dirfd,
                      uint64_t linkpath_gva)
{
    char target[LINUX_PATH_MAX], linkpath[LINUX_PATH_MAX];
    if (guest_read_str(g, target_gva, target, sizeof(target)) < 0)
        return -LINUX_EFAULT;
    path_translation_t tx;
    int64_t rc = read_translated_path(g, dirfd, linkpath_gva,
                                      PATH_TR_CREATE | PATH_TR_CREATE_PARENTS,
                                      linkpath, &tx);
    if (rc < 0)
        return rc;
    rc = reject_unsupported_fuse_path_op(&tx);
    if (rc != INT64_MIN)
        return rc;

    host_fd_ref_t dir_ref;
    if (host_dirfd_ref_open(dirfd, &dir_ref) < 0)
        return -LINUX_EBADF;

    char relative_target[LINUX_PATH_MAX];
    const char *host_target = host_relative_symlink_target(
        target, &dir_ref, &tx, relative_target, sizeof(relative_target));
    if (!host_target) {
        host_fd_ref_close(&dir_ref);
        return linux_errno();
    }

    /* Resolve linkpath (the new symlink location) through sysroot. */
    if (symlinkat(host_target, dir_ref.fd, tx.host_path) < 0) {
        host_fd_ref_close(&dir_ref);
        return linux_errno();
    }

    host_fd_ref_close(&dir_ref);
    return 0;
}

int64_t sys_linkat(guest_t *g,
                   int olddirfd,
                   uint64_t oldpath_gva,
                   int newdirfd,
                   uint64_t newpath_gva,
                   int flags)
{
    char oldpath[LINUX_PATH_MAX], newpath[LINUX_PATH_MAX];
    path_translation_t old_tx, new_tx;
    if (guest_read_str(g, oldpath_gva, oldpath, sizeof(oldpath)) < 0 ||
        guest_read_str(g, newpath_gva, newpath, sizeof(newpath)) < 0)
        return -LINUX_EFAULT;

    if (!validate_at_flags(flags, LINUX_AT_SYMLINK_FOLLOW))
        return -LINUX_EINVAL;

    int64_t sidecar_rc =
        sidecar_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
    if (sidecar_rc != SIDECAR_NOT_HANDLED)
        return sidecar_rc;

    if (path_translate_at(olddirfd, oldpath, PATH_TR_NONE, &old_tx) < 0 ||
        path_translate_at(newdirfd, newpath, PATH_TR_CREATE, &new_tx) < 0)
        return linux_errno();
    if (old_tx.fuse_path || new_tx.fuse_path)
        return -LINUX_ENOSYS;

    host_fd_ref_t olddir_ref, newdir_ref;
    if (host_dirfd_ref_open(olddirfd, &olddir_ref) < 0)
        return -LINUX_EBADF;
    if (host_dirfd_ref_open(newdirfd, &newdir_ref) < 0) {
        host_fd_ref_close(&olddir_ref);
        return -LINUX_EBADF;
    }

    /* Resolve both paths through sysroot */
    int mac_flags = translate_at_flags(flags);
    if (linkat(olddir_ref.fd, old_tx.host_path, newdir_ref.fd, new_tx.host_path,
               mac_flags) < 0) {
        host_fd_ref_close(&olddir_ref);
        host_fd_ref_close(&newdir_ref);
        return linux_errno();
    }

    host_fd_ref_close(&olddir_ref);
    host_fd_ref_close(&newdir_ref);
    return 0;
}

int64_t sys_faccessat(guest_t *g,
                      int dirfd,
                      uint64_t path_gva,
                      int mode,
                      int flags)
{
    if (dirfd == LINUX_AT_FDCWD) {
        char dot_path[2];
        if (guest_read_small(g, path_gva, dot_path, sizeof(dot_path)) == 0 &&
            dot_path[0] == '.' && dot_path[1] == '\0') {
            proc_cwd_view_t view;
            if (proc_acquire_cwd_view(&view) == 0) {
                if (view.path && view.path[0] == '/' &&
                    fuse_path_matches_mount(view.path)) {
                    char cwd_path[LINUX_PATH_MAX];
                    str_copy_trunc(cwd_path, view.path, sizeof(cwd_path));
                    proc_release_cwd_view(&view);
                    return fuse_access_path(cwd_path, mode, flags);
                }
                proc_release_cwd_view(&view);
            }
            int mac_flags = translate_faccessat_flags(flags);
            if (faccessat(AT_FDCWD, ".", mode, mac_flags) < 0)
                return linux_errno();
            return 0;
        }
    }

    char path[LINUX_PATH_MAX];
    path_translation_t tx;
    int64_t rc = read_translated_path(
        g, dirfd, path_gva,
        (flags & LINUX_AT_SYMLINK_NOFOLLOW) ? PATH_TR_NOFOLLOW : PATH_TR_NONE,
        path, &tx);
    if (rc < 0)
        return rc;

    if (!validate_at_flags(flags, LINUX_AT_EACCESS | LINUX_AT_SYMLINK_NOFOLLOW))
        return -LINUX_EINVAL;

    if (tx.fuse_path)
        return fuse_access_path(tx.intercept_path, mode, flags);

    if (tx.proc_resolved == 0 && dirfd == LINUX_AT_FDCWD && path[0] != '/') {
        int mac_flags = translate_faccessat_flags(flags);
        if (faccessat(AT_FDCWD, path, mode, mac_flags) < 0)
            return linux_errno();
        return 0;
    }

    host_fd_ref_t dir_ref;
    if (host_dirfd_ref_open(dirfd, &dir_ref) < 0)
        return -LINUX_EBADF;

    /* Check intercepted stat paths first since macOS has no /proc filesystem
     * and the sysfs CPU tree is synthetic. Access must reflect the synthetic
     * mode bits, not just path existence.
     */
    struct stat intercepted_st;
    if (path_might_use_stat_intercept(tx.intercept_path) &&
        proc_intercept_stat(tx.intercept_path, &intercepted_st) == 0) {
        host_fd_ref_close(&dir_ref);
        if (path_check_intercept_access(&intercepted_st, mode, flags) < 0)
            return linux_errno();
        return 0;
    }

    int mac_flags = translate_faccessat_flags(flags);
    if (faccessat(dir_ref.fd, tx.host_path, mode, mac_flags) < 0) {
        host_fd_ref_close(&dir_ref);
        return linux_errno();
    }

    host_fd_ref_close(&dir_ref);
    return 0;
}

/* truncate. */

int64_t sys_ftruncate(int fd, int64_t length)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap))
        return -LINUX_EBADF;
    /* Linux: ftruncate on an O_PATH fd returns EBADF. */
    if (snap.type == FD_PATH)
        return -LINUX_EBADF;

    /* Enforce memfd seals on truncate. */
    int seals = snap.seals;
    if (seals & LINUX_F_SEAL_WRITE)
        return -LINUX_EPERM;

    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    if (seals & (LINUX_F_SEAL_SHRINK | LINUX_F_SEAL_GROW)) {
        struct stat st;
        if (fstat(host_ref.fd, &st) == 0) {
            if ((seals & LINUX_F_SEAL_SHRINK) && length < st.st_size) {
                host_fd_ref_close(&host_ref);
                return -LINUX_EPERM;
            }
            if ((seals & LINUX_F_SEAL_GROW) && length > st.st_size) {
                host_fd_ref_close(&host_ref);
                return -LINUX_EPERM;
            }
        }
    }

    if (ftruncate(host_ref.fd, length) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }
    host_fd_ref_close(&host_ref);
    return 0;
}

int64_t sys_truncate(guest_t *g, uint64_t path_gva, int64_t length)
{
    char path[LINUX_PATH_MAX];
    path_translation_t tx;
    int64_t rc = read_translated_path(g, LINUX_AT_FDCWD, path_gva, PATH_TR_NONE,
                                      path, &tx);
    if (rc < 0)
        return rc;
    rc = reject_unsupported_fuse_path_op(&tx);
    if (rc != INT64_MIN)
        return rc;

    if (truncate(tx.host_path, length) < 0)
        return linux_errno();
    return 0;
}

/* permissions/ownership. */

int64_t sys_fchmod(int fd, uint32_t mode)
{
    /* O_PATH fds do not support fchmod (Linux returns EBADF) */
    fd_entry_t snap;
    if (fd_snapshot(fd, &snap) && snap.type == FD_PATH)
        return -LINUX_EBADF;
    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;
    if (fchmod(host_ref.fd, mode) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }
    host_fd_ref_close(&host_ref);
    return 0;
}

int64_t sys_fchmodat(guest_t *g,
                     int dirfd,
                     uint64_t path_gva,
                     uint32_t mode,
                     int flags)
{
    char path[LINUX_PATH_MAX];
    if (!validate_at_flags(flags, LINUX_AT_SYMLINK_NOFOLLOW))
        return -LINUX_EINVAL;
    path_translation_t tx;
    int64_t rc = read_translated_path(
        g, dirfd, path_gva,
        (flags & LINUX_AT_SYMLINK_NOFOLLOW) ? PATH_TR_NOFOLLOW : PATH_TR_NONE,
        path, &tx);
    if (rc < 0)
        return rc;
    rc = reject_unsupported_fuse_path_op(&tx);
    if (rc != INT64_MIN)
        return rc;

    host_fd_ref_t dir_ref;
    if (host_dirfd_ref_open(dirfd, &dir_ref) < 0)
        return -LINUX_EBADF;

    int mac_flags = translate_at_flags(flags);
    if (fchmodat(dir_ref.fd, tx.host_path, mode, mac_flags) < 0) {
        host_fd_ref_close(&dir_ref);
        return linux_errno();
    }

    host_fd_ref_close(&dir_ref);
    return 0;
}

/* Fake success on EPERM: emulated-root guests expect chown to succeed. */
static int64_t chown_result(int rc)
{
    if (rc < 0)
        return (errno == EPERM) ? 0 : linux_errno();
    return 0;
}

int64_t sys_fchownat(guest_t *g,
                     int dirfd,
                     uint64_t path_gva,
                     uint32_t owner,
                     uint32_t group,
                     int flags)
{
    char path[LINUX_PATH_MAX];
    if (!validate_at_flags(flags, LINUX_AT_SYMLINK_NOFOLLOW))
        return -LINUX_EINVAL;
    path_translation_t tx;
    int64_t rc = read_translated_path(
        g, dirfd, path_gva,
        (flags & LINUX_AT_SYMLINK_NOFOLLOW) ? PATH_TR_NOFOLLOW : PATH_TR_NONE,
        path, &tx);
    if (rc < 0)
        return rc;
    rc = reject_unsupported_fuse_path_op(&tx);
    if (rc != INT64_MIN)
        return rc;

    host_fd_ref_t dir_ref;
    if (host_dirfd_ref_open(dirfd, &dir_ref) < 0)
        return -LINUX_EBADF;

    int mac_flags = translate_at_flags(flags);
    int64_t out = chown_result(
        fchownat(dir_ref.fd, tx.host_path, owner, group, mac_flags));
    host_fd_ref_close(&dir_ref);
    return out;
}

int64_t sys_fchown(int fd, uint32_t owner, uint32_t group)
{
    /* O_PATH fds do not support fchown (Linux returns EBADF) */
    fd_entry_t snap;
    if (fd_snapshot(fd, &snap) && snap.type == FD_PATH)
        return -LINUX_EBADF;
    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;
    int64_t out = chown_result(fchown(host_ref.fd, owner, group));
    host_fd_ref_close(&host_ref);
    return out;
}

int64_t sys_utimensat(guest_t *g,
                      int dirfd,
                      uint64_t path_gva,
                      uint64_t times_gva,
                      int flags)
{
    struct timespec ts[2];
    bool all_omit = false;
    if (times_gva != 0) {
        /* Read two linux_timespec_t from guest */
        linux_timespec_t lts[2];
        if (guest_read_small(g, times_gva, lts, sizeof(lts)) < 0)
            return -LINUX_EFAULT;

        ts[0].tv_sec = lts[0].tv_sec;
        ts[1].tv_sec = lts[1].tv_sec;
        all_omit = (lts[0].tv_nsec == LINUX_UTIME_OMIT &&
                    lts[1].tv_nsec == LINUX_UTIME_OMIT);
        ts[0].tv_nsec = (lts[0].tv_nsec == LINUX_UTIME_NOW)    ? UTIME_NOW
                        : (lts[0].tv_nsec == LINUX_UTIME_OMIT) ? UTIME_OMIT
                                                               : lts[0].tv_nsec;
        ts[1].tv_nsec = (lts[1].tv_nsec == LINUX_UTIME_NOW)    ? UTIME_NOW
                        : (lts[1].tv_nsec == LINUX_UTIME_OMIT) ? UTIME_OMIT
                                                               : lts[1].tv_nsec;
    }

    if (all_omit)
        return 0;

    if (!validate_at_flags(flags,
                           LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH))
        return -LINUX_EINVAL;

    host_fd_ref_t dir_ref;
    if (host_dirfd_ref_open(dirfd, &dir_ref) < 0)
        return -LINUX_EBADF;

    /* If path is NULL (path_gva == 0), operate on the dirfd itself */
    const char *path_arg = NULL;
    char path[LINUX_PATH_MAX];
    path_translation_t tx;
    if (path_gva != 0) {
        int64_t rc = read_translated_path(g, dirfd, path_gva,
                                          (flags & LINUX_AT_SYMLINK_NOFOLLOW)
                                              ? PATH_TR_NOFOLLOW
                                              : PATH_TR_NONE,
                                          path, &tx);
        if (rc < 0) {
            host_fd_ref_close(&dir_ref);
            return rc;
        }
        rc = reject_unsupported_fuse_path_op(&tx);
        if (rc != INT64_MIN) {
            host_fd_ref_close(&dir_ref);
            return rc;
        }
        path_arg = tx.host_path;
    }

    int mac_flags = 0;
    if (flags & LINUX_AT_SYMLINK_NOFOLLOW)
        mac_flags |= AT_SYMLINK_NOFOLLOW;

    /* macOS utimensat() does not support NULL path (Linux extension). When path
     * is NULL, the caller wants to operate on dirfd itself, so use futimens()
     * instead. Linux's do_utimes_fd rejects any flags with EINVAL, and
     * utimensat(AT_FDCWD, NULL, ...) returns EFAULT because there is no real fd
     * to apply timestamps to; mirror both here rather than letting
     * futimens(AT_FDCWD, ...) be invoked with macOS's AT_FDCWD sentinel (-2),
     * which returns EBADF and would not match Linux semantics.
     */
    if (!path_arg) {
        if (flags) {
            host_fd_ref_close(&dir_ref);
            return -LINUX_EINVAL;
        }
        if (dir_ref.fd == AT_FDCWD) {
            host_fd_ref_close(&dir_ref);
            return -LINUX_EFAULT;
        }
        if (futimens(dir_ref.fd, times_gva ? ts : NULL) < 0) {
            host_fd_ref_close(&dir_ref);
            return linux_errno();
        }
    } else {
        if (utimensat(dir_ref.fd, path_arg, times_gva ? ts : NULL, mac_flags) <
            0) {
            host_fd_ref_close(&dir_ref);
            return linux_errno();
        }
    }

    host_fd_ref_close(&dir_ref);
    return 0;
}
