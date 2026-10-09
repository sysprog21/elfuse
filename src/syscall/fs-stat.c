/*
 * Filesystem stat/statx/statfs handlers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "debug/log.h"

#include "runtime/procemu.h"

#include "syscall/linux-wire.h"
#include "syscall/chown-overlay.h"
#include "syscall/fuse.h"
#include "syscall/fs.h"
#include "syscall/internal.h"
#include "syscall/usbdev.h"
#include "syscall/path.h"
#include "syscall/proc.h"
#include "utils.h"

static uint64_t mac_to_linux_dev(dev_t dev)
{
    unsigned int maj = ((unsigned int) dev >> 24) & 0xFF;
    unsigned int min = (unsigned int) dev & 0xFFFFFF;
    return (uint64_t) ((min & 0xFF) | (maj << 8) | ((min & ~0xFFU) << 12));
}

static uint32_t linux_dev_major(uint64_t dev)
{
    return (uint32_t) (((dev & 0x00000000000FFF00ULL) >> 8) |
                       ((dev & 0xFFFFF00000000000ULL) >> 32));
}

static uint32_t linux_dev_minor(uint64_t dev)
{
    return (uint32_t) ((dev & 0x00000000000000FFULL) |
                       ((dev & 0x00000FFFFFF00000ULL) >> 12));
}

static void translate_stat(const struct stat *mac, linux_stat_t *lin)
{
    memset(lin, 0, sizeof(*lin));
    lin->st_dev = mac_to_linux_dev(mac->st_dev);
    lin->st_ino = mac->st_ino;
    lin->st_mode = mac->st_mode;
    lin->st_nlink = (uint32_t) mac->st_nlink;
    lin->st_uid = mac->st_uid;
    lin->st_gid = mac->st_gid;
    lin->st_rdev = mac_to_linux_dev(mac->st_rdev);
    lin->st_size = mac->st_size;
    lin->st_blksize = (int32_t) mac->st_blksize;
    lin->st_blocks = mac->st_blocks;
    lin->st_atime_sec = mac->st_atimespec.tv_sec;
    lin->st_atime_nsec = mac->st_atimespec.tv_nsec;
    lin->st_mtime_sec = mac->st_mtimespec.tv_sec;
    lin->st_mtime_nsec = mac->st_mtimespec.tv_nsec;
    lin->st_ctime_sec = mac->st_ctimespec.tv_sec;
    lin->st_ctime_nsec = mac->st_ctimespec.tv_nsec;
}

static uint32_t normalize_statx_mask(unsigned int requested_mask)
{
    uint32_t mask = requested_mask & (STATX_BASIC_STATS | STATX_BTIME);
    if (mask == 0)
        mask = STATX_BASIC_STATS;
    return mask;
}

static void translate_statx(const struct stat *mac,
                            linux_statx_t *sx,
                            uint32_t mask)
{
    uint64_t linux_rdev = mac_to_linux_dev(mac->st_rdev);
    uint64_t linux_dev = mac_to_linux_dev(mac->st_dev);

    memset(sx, 0, sizeof(*sx));
    sx->stx_mask = mask;
    sx->stx_blksize = (uint32_t) mac->st_blksize;

    if (mask & (STATX_TYPE | STATX_MODE))
        sx->stx_mode = (uint16_t) mac->st_mode;
    if (mask & STATX_NLINK)
        sx->stx_nlink = (uint32_t) mac->st_nlink;
    if (mask & STATX_UID)
        sx->stx_uid = mac->st_uid;
    if (mask & STATX_GID)
        sx->stx_gid = mac->st_gid;
    if (mask & STATX_INO)
        sx->stx_ino = mac->st_ino;
    if (mask & STATX_SIZE)
        sx->stx_size = mac->st_size;
    if (mask & STATX_BLOCKS)
        sx->stx_blocks = mac->st_blocks;
    if (mask & STATX_ATIME) {
        sx->stx_atime_sec = mac->st_atimespec.tv_sec;
        sx->stx_atime_nsec = (uint32_t) mac->st_atimespec.tv_nsec;
    }
    if (mask & STATX_MTIME) {
        sx->stx_mtime_sec = mac->st_mtimespec.tv_sec;
        sx->stx_mtime_nsec = (uint32_t) mac->st_mtimespec.tv_nsec;
    }
    if (mask & STATX_CTIME) {
        sx->stx_ctime_sec = mac->st_ctimespec.tv_sec;
        sx->stx_ctime_nsec = (uint32_t) mac->st_ctimespec.tv_nsec;
    }
    if (mask & STATX_BTIME) {
        sx->stx_btime_sec = mac->st_birthtimespec.tv_sec;
        sx->stx_btime_nsec = (uint32_t) mac->st_birthtimespec.tv_nsec;
    }

    sx->stx_rdev_major = linux_dev_major(linux_rdev);
    sx->stx_rdev_minor = linux_dev_minor(linux_rdev);
    sx->stx_dev_major = linux_dev_major(linux_dev);
    sx->stx_dev_minor = linux_dev_minor(linux_dev);
}

static int write_linux_stat(guest_t *g,
                            uint64_t stat_gva,
                            const struct stat *mac_st)
{
    struct stat overlaid = *mac_st;
    chown_overlay_apply(&overlaid);

    linux_stat_t lin_st;

    translate_stat(&overlaid, &lin_st);
    return guest_write_small(g, stat_gva, &lin_st, sizeof(lin_st));
}

static int write_linux_statx(guest_t *g,
                             uint64_t statx_gva,
                             const struct stat *mac_st,
                             unsigned int mask)
{
    struct stat overlaid = *mac_st;
    chown_overlay_apply(&overlaid);

    linux_statx_t sx;

    translate_statx(&overlaid, &sx, normalize_statx_mask(mask));
    return guest_write_small(g, statx_gva, &sx, sizeof(sx));
}

/* Whether a descriptor's identity comes from the stamp rather than from the
 * host object underneath it: O_PATH, /sys and /dev/bus do, /proc does not. See
 * docs/internals.md, "Filesystem Identity Of A Descriptor", for why.
 */
static bool fd_stat_answers_from_stamp(const fd_entry_t *snap)
{
    if (snap->proc_path[0] == '\0')
        return false;
    return snap->type == FD_PATH ||
           path_prefix_match(snap->proc_path, "/sys", 4) ||
           path_prefix_match(snap->proc_path, "/dev/bus", 8);
}

static void translate_statfs(const struct statfs *mac, linux_statfs_t *lin)
{
    memset(lin, 0, sizeof(*lin));
    lin->f_type = mac->f_type;
    lin->f_bsize = mac->f_bsize;
    lin->f_blocks = mac->f_blocks;
    lin->f_bfree = mac->f_bfree;
    lin->f_bavail = mac->f_bavail;
    lin->f_files = mac->f_files;
    lin->f_ffree = mac->f_ffree;
    lin->f_fsid[0] = mac->f_fsid.val[0];
    lin->f_fsid[1] = mac->f_fsid.val[1];
    lin->f_namelen = 255;
    lin->f_frsize = mac->f_bsize;
}

/* Stat the descriptor an *at-style call names with AT_EMPTY_PATH and an empty
 * path.
 *
 * The empty path names the descriptor rather than anything beneath it, so it
 * resolves nothing and must be answered before a resolver ever sees it. A
 * resolver measures a relative name against dirfd, and the empty path is
 * relative, so it owes ENOTDIR for a dirfd that is not a directory -- correct
 * for a name, wrong for the descriptor itself, and glibc has spelled fstat(fd)
 * as fstatat(fd, "", AT_EMPTY_PATH) since 2.33. sys_fchmodat and sys_fchownat
 * short-circuit ahead of translation for the same reason.
 *
 * The order mirrors sys_fstat, since this answers the same question: the FUSE
 * shim first, because a FUSE descriptor is answered by the emulation layer
 * rather than by a host file; then the /proc intercept, which an O_PATH
 * descriptor needs because its host fd cannot be stat'ed for the emulated
 * object; then the host.
 *
 * sys_fstat calls this rather than keeping a body of its own, since glibc's
 * spelling makes this the form most fstat() calls arrive in and there is no
 * second policy worth having. The classification and the descriptor come from
 * one fd_lock window here, so a sibling thread cannot close and reuse the slot
 * between the two: answering the /proc intercept for one object and then
 * stat'ing another is what separate reads allow.
 *
 * AT_FDCWD is not handled here -- it names the current directory, which always
 * has a base path to resolve against, so the caller keeps answering it the way
 * Linux specifies it.
 *
 * Returns 0 on success or a negative Linux errno.
 */
static int64_t stat_empty_path_fd(int dirfd, struct stat *mac_st)
{
    int frc = fuse_fstat_fd(dirfd, mac_st);
    if (frc == 0)
        return 0;
    if (frc != -LINUX_EBADF)
        return frc;

    fd_entry_t snap;
    host_fd_ref_t ref = HOST_FD_REF_INIT;
    if (thread_is_single_active()) {
        /* No sibling can mutate the slot, so the pin has nothing to defend
         * against and the snapshot alone is already consistent -- the rule
         * fd_block_state states for the same reason. A closed slot, or one
         * carrying no host descriptor, is the EBADF that fd_to_host would have
         * reported on this path before.
         */
        if (!fd_snapshot(dirfd, &snap) || snap.host_fd < 0)
            return -LINUX_EBADF;
        ref.fd = snap.host_fd;
    } else {
        /* Pin, not dup: the descriptor has to stay valid across the stat, not
         * become private, and retiring a dup would drop the guest's record
         * locks on the file (fcntl(2)).
         */
        if (fd_host_ref_acquire(dirfd, &snap, &ref.lifetime) < 0)
            return linux_errno(); /* EBADF or ENOMEM; the helper picks. */
        ref.fd = snap.host_fd;
    }

    int64_t rc = 0;

    /* usbdevfs fds are char device 189:minor and the host fd behind them is a
     * pipe, whose fstat must not leak through. Ahead of the stamp branch for
     * the same reason the FUSE shim is ahead of both: the descriptor is
     * answered by the emulation layer that owns it, not by re-resolving the
     * name it was opened under. Behind it the branch was unreachable -- every
     * FD_USBDEV fd carries a /dev/bus stamp, so fd_stat_answers_from_stamp
     * claimed all of them and answered from the path.
     */
    if (snap.type == FD_USBDEV) {
        rc = usbdev_fstat(dirfd, mac_st);
        goto done;
    }

    if (fd_stat_answers_from_stamp(&snap)) {
        /* The descriptor already names one object: an O_PATH open that followed
         * refers to the target, one made with O_NOFOLLOW to the link itself, so
         * the open's flag is what selects here.
         */
        bool follow = !(snap.linux_flags & LINUX_O_NOFOLLOW);
        int intercepted =
            proc_intercept_stat_at(snap.proc_path, mac_st, follow);
        if (intercepted == 0)
            goto done;
        if (intercepted == -1) {
            rc = linux_errno();
            goto done;
        }
    }

    if (fstat(ref.fd, mac_st) < 0)
        rc = linux_errno();

done:
    host_fd_ref_close(&ref);
    return rc;
}

/* Resolve the directory + path arguments of a *at-style stat operation and fill
 * *mac_st via the appropriate host call (proc intercept where applicable).
 * Shared by sys_newfstatat and sys_statx; the caller copies the result into the
 * guest's struct stat or struct statx layout.
 * Returns 0 on success or a negative Linux errno.
 */
static int64_t stat_at_path(guest_t *g,
                            int dirfd,
                            uint64_t path_gva,
                            int flags,
                            struct stat *mac_st)
{
    if (dirfd == LINUX_AT_FDCWD) {
        char dot_path[2];
        if (guest_read_small(g, path_gva, dot_path, sizeof(dot_path)) == 0 &&
            dot_path[0] == '.' && dot_path[1] == '\0') {
            int mac_flags = translate_at_flags(flags);
            if (fstatat(AT_FDCWD, ".", mac_st, mac_flags) < 0)
                return linux_errno();
            return 0;
        }
    }

    char short_path[64];
    char path[LINUX_PATH_MAX];
    const char *pathp;
    if (guest_read_path(g, path_gva, short_path, sizeof(short_path), path,
                        sizeof(path), &pathp) < 0)
        return -LINUX_EFAULT;

    if ((flags & LINUX_AT_EMPTY_PATH) && pathp[0] == '\0' &&
        dirfd != LINUX_AT_FDCWD)
        return stat_empty_path_fd(dirfd, mac_st);

    /* Without AT_EMPTY_PATH an empty name is ENOENT whatever dirfd is. The host
     * would say ENOTDIR for a dirfd that is not a directory.
     */
    if (pathp[0] == '\0' && !(flags & LINUX_AT_EMPTY_PATH))
        return -LINUX_ENOENT;

    if (pathp[0] == '/' && fuse_path_matches_mount(pathp)) {
        int frc = fuse_stat_path(pathp, mac_st, flags);
        if (frc < 0)
            return frc;
        return 0;
    }

    path_translation_t tx;
    if (path_translate_at(dirfd, pathp,
                          path_tr_nofollow(flags & LINUX_AT_SYMLINK_NOFOLLOW),
                          &tx) < 0)
        return linux_errno();

    if (tx.fuse_path) {
        int frc = fuse_stat_path(tx.intercept_path, mac_st, flags);
        if (frc < 0)
            return frc;
        return 0;
    }

    if (tx.proc_resolved == 0 && dirfd == LINUX_AT_FDCWD && pathp[0] != '/' &&
        pathp[0] != '\0' && !proc_get_sysroot()) {
        int mac_flags = translate_at_flags(flags);
        if (fstatat(AT_FDCWD, pathp, mac_st, mac_flags) < 0)
            return linux_errno();
        return 0;
    }

    int64_t rc = 0;
    host_fd_ref_t dir_ref = HOST_FD_REF_INIT;
    if ((flags & LINUX_AT_EMPTY_PATH) && pathp[0] == '\0') {
        /* Linux: AT_EMPTY_PATH with dirfd == AT_FDCWD operates on the current
         * working directory. Every other descriptor was answered by
         * stat_empty_path_fd above, before anything tried to resolve the empty
         * path against it.
         */
        dir_ref.fd = AT_FDCWD;
        int mac_flags = translate_at_flags(flags);
        if (fstatat(AT_FDCWD, ".", mac_st, mac_flags) < 0) {
            rc = linux_errno();
            goto done;
        }
    } else {
        int64_t ref_err = host_dirfd_ref_open(dirfd, &dir_ref);
        if (ref_err < 0)
            return ref_err;

        int intercepted = PROC_NOT_INTERCEPTED;
        if (path_might_use_stat_intercept(tx.intercept_path)) {
            intercepted =
                proc_intercept_stat_at(tx.intercept_path, mac_st,
                                       !(flags & LINUX_AT_SYMLINK_NOFOLLOW));
            if (intercepted == -1) {
                rc = linux_errno();
                goto done;
            }
        }
        if (intercepted == PROC_NOT_INTERCEPTED) {
            int mac_flags =
                path_translation_at_flags(&tx, translate_at_flags(flags));
            if (fstatat(path_translation_dirfd(&tx, &dir_ref), tx.host_path,
                        mac_st, mac_flags) < 0) {
                rc = linux_errno();
                goto done;
            }
        }
    }

done:
    host_fd_ref_close(&dir_ref);
    return rc;
}

int64_t sys_fstat(guest_t *g, int fd, uint64_t stat_gva)
{
    /* Zero-init so callees that fill only matched fields (FUSE shim, /proc
     * emulators) leave the rest as defined zeros. Also keeps clang's
     * core.CallAndMessage checker happy: it cannot see across fuse_fstat_fd /
     * fstat to verify the buffer is fully written before translate_stat reads
     * from it.
     */
    struct stat mac_st = {0};

    /* fstat(fd) and fstatat(fd, "", AT_EMPTY_PATH) are the same question --
     * glibc has spelled the first as the second since 2.33 -- so they are
     * answered by one body rather than two that can drift.
     */
    int64_t rc = stat_empty_path_fd(fd, &mac_st);
    if (rc < 0) {
        log_debug("fstat(%d): failed rc=%lld", fd, (long long) rc);
        return rc;
    }

    if (write_linux_stat(g, stat_gva, &mac_st) < 0)
        return -LINUX_EFAULT;

    return 0;
}

int64_t sys_newfstatat(guest_t *g,
                       int dirfd,
                       uint64_t path_gva,
                       uint64_t stat_gva,
                       int flags)
{
    if (!validate_at_flags(flags, LINUX_AT_SYMLINK_NOFOLLOW |
                                      LINUX_AT_EMPTY_PATH |
                                      LINUX_AT_NO_AUTOMOUNT))
        return -LINUX_EINVAL;

    /* See sys_fstat comment on the zero-init rationale. */
    struct stat mac_st = {0};
    int64_t rc = stat_at_path(g, dirfd, path_gva, flags, &mac_st);
    if (rc < 0)
        return rc;

    if (write_linux_stat(g, stat_gva, &mac_st) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* True when path (already translated/normalized by path_translate_at) names
 * /proc itself or something under it. Boundary-checked so "/procfoo" does not
 * false-positive the way a bare strncmp(path, "/proc", 5) would.
 */
static bool statfs_path_is_proc(const char *path)
{
    if (!path || path[0] != '/')
        return false;
    return !strncmp(path, "/proc", 5) && (path[5] == '\0' || path[5] == '/');
}

/* /dev/pts itself and the pty slaves under it. /dev/ptmx is the multiplexer
 * that hands out those slaves; Linux reports devpts for a master fd too. How
 * statfs should answer for a path under the virtual devpts mount.
 */
typedef enum {
    DEVPTS_UNRELATED = 0, /* not under /dev/pts; carry on */
    DEVPTS_MOUNT,         /* the mount point or a live slave: synthesize */
    DEVPTS_ABSENT,        /* under /dev/pts but no such slave: ENOENT */
} devpts_class_t;

static devpts_class_t statfs_devpts_class(const char *path)
{
    if (!path || strncmp(path, "/dev/pts", 8) != 0)
        return DEVPTS_UNRELATED;
    if (path[8] != '\0' && path[8] != '/')
        return DEVPTS_UNRELATED; /* "/dev/ptsfoo" is an ordinary name */

    const char *tail = path + 8;
    while (*tail == '/')
        tail++;
    if (!*tail)
        return DEVPTS_MOUNT; /* "/dev/pts", "/dev/pts/", "/dev/pts//" */

    /* The mount point exists for as long as the pty layer does. A particular
     * slave does not: Linux answers ENOENT for an unallocated or malformed
     * /dev/pts/N. Report that rather than falling through to the host, so the
     * answer cannot depend on whether the sysroot happens to carry a file of
     * the same name -- the devpts mount shadows whatever is underneath it, and
     * the stat and open intercepts already treat the directory that way.
     *
     * Only the canonical spelling of a slave resolves, matching those
     * intercepts: "/dev/pts/0" is the dentry, "/dev/pts/00" and "/dev/pts/./0"
     * are not. Non-canonical spellings land here as ENOENT rather than
     * resolving, which diverges from a real kernel for the "." form and is
     * consistent across every /dev/pts intercept.
     *
     * /dev/ptmx is deliberately not claimed. Which filesystem backs it depends
     * on whether it resolves to /dev/pts/ptmx or to the devtmpfs node, the same
     * ambiguity that keeps sys_fstatfs from answering for a master fd, and
     * nothing asks: glibc's getpt statfs's /dev/pts and /dev, never /dev/ptmx.
     */
    return proc_pty_slave_stat(path, NULL) ? DEVPTS_MOUNT : DEVPTS_ABSENT;
}

/* devpts is virtualized rather than host-backed, so answer synthetically.
 * Matches what Linux reports for a devpts mount: no blocks, no inodes.
 */
static void fill_devpts_statfs(linux_statfs_t *lin)
{
    memset(lin, 0, sizeof(*lin));
    lin->f_type = 0x1cd1; /* DEVPTS_SUPER_MAGIC */
    lin->f_bsize = 4096;
    lin->f_blocks = 0;
    lin->f_bfree = 0;
    lin->f_bavail = 0;
    lin->f_files = 0;
    lin->f_ffree = 0;
    lin->f_namelen = 255;
    lin->f_frsize = 4096;
}

static void fill_proc_statfs(linux_statfs_t *lin)
{
    memset(lin, 0, sizeof(*lin));
    lin->f_type = 0x9fa0; /* PROC_SUPER_MAGIC */
    lin->f_bsize = 4096;
    lin->f_blocks = 0;
    lin->f_bfree = 0;
    lin->f_bavail = 0;
    lin->f_files = 0;
    lin->f_ffree = 0;
    lin->f_namelen = 255;
    lin->f_frsize = 4096;
}

/* Boundary-checked "/sys or under it", applied to the folded name, which is
 * also published so the caller can act on the same spelling it classified.
 *
 * Fold before deciding, and resolve a relative name against the cwd first: the
 * kernel decides which filesystem answers a path after resolving it, so
 * statfs("/sys/../etc") is /etc's filesystem and statfs("sys") from / is
 * /sys's. See docs/internals.md, "Filesystem Identity Of A Descriptor".
 *
 * path_openat2_normalize_in_root clamps '..' at the root, which is what the
 * kernel does with a leading "/..", and yields a root-relative spelling --
 * "sys/bus" for /sys/bus, "etc" for /sys/../etc, "." for /.
 */
static bool statfs_path_is_sysfs(const char *path, char *abs, size_t abssz)
{
    if (!path || path[0] == '\0')
        return false;

    char joined[LINUX_PATH_MAX];
    if (path[0] != '/') {
        proc_cwd_view_t view;
        if (proc_acquire_cwd_view(&view) < 0)
            return false;
        int jn = snprintf(joined, sizeof(joined), "%s/%s", view.path, path);
        proc_release_cwd_view(&view);
        if (jn < 0 || (size_t) jn >= sizeof(joined))
            return false;
        path = joined;
    }

    char folded[LINUX_PATH_MAX];
    if (path_openat2_normalize_in_root(path, folded, sizeof(folded)) < 0)
        return false;
    if (strncmp(folded, "sys", 3) != 0 ||
        (folded[3] != '\0' && folded[3] != '/'))
        return false;
    int n = snprintf(abs, abssz, "/%s", folded);
    return n > 0 && (size_t) n < abssz;
}

/* What the synthetic USB tree answers for a /dev/bus name: 0 when it serves the
 * name, -1 with errno set when it owns the name and the lookup failed, and
 * PROC_NOT_INTERCEPTED when the name is not ours at all.
 *
 * The tree has no host backing, so the pass-through statfs reported ENOENT for
 * a node stat() and open() both answer for, while fstatfs on the descriptor
 * open() handed back reported the filesystem of elfuse's staging file. Linux
 * serves usbfs nodes from the devtmpfs that carries the rest of /dev and
 * reports TMPFS_MAGIC for them (0x01021994, measured on 6.x alongside /dev and
 * /dev/null, which report the same). Both entry points ask this one question so
 * they agree on every /dev/bus name either can reach.
 *
 * The last two answers stay distinct because collapsing them is the bug
 * sys_faccessat had: a sysroot carrying a name inside /dev/bus/usb -- on a bus
 * number no device has -- would otherwise have its file answer statfs while
 * open, stat and access all report ENOENT for the same path. Only
 * PROC_NOT_INTERCEPTED means "ask the backing".
 */
static int statfs_dev_bus_class(const char *path)
{
    if (!path || !path_prefix_match(path, "/dev/bus", 8))
        return PROC_NOT_INTERCEPTED;
    struct stat st;
    return proc_intercept_stat_at(path, &st, true);
}

static void fill_dev_statfs(linux_statfs_t *lin)
{
    memset(lin, 0, sizeof(*lin));
    lin->f_type = 0x01021994; /* TMPFS_MAGIC, what devtmpfs reports */
    lin->f_bsize = 4096;
    lin->f_namelen = 255;
    lin->f_frsize = 4096;
}

static void fill_sysfs_statfs(linux_statfs_t *lin)
{
    memset(lin, 0, sizeof(*lin));
    lin->f_type = 0x62656572; /* SYSFS_MAGIC */
    lin->f_bsize = 4096;
    lin->f_blocks = 0;
    lin->f_bfree = 0;
    lin->f_bavail = 0;
    lin->f_files = 0;
    lin->f_ffree = 0;
    lin->f_namelen = 255;
    lin->f_frsize = 4096;
}

static int64_t sys_statfs_impl(guest_t *g,
                               const char *path,
                               uint64_t buf_gva,
                               int depth)
{
    if (depth > 40)
        return -LINUX_ELOOP;

    path_translation_t tx;
    if (path_translate_at(LINUX_AT_FDCWD, path, PATH_TR_NONE, &tx) < 0)
        return linux_errno();
    if (tx.fuse_path)
        return -LINUX_ENOSYS;

    /* The directory requirement of a trailing slash or ".", applied before the
     * classification below, which reads the bare name: a served file under it
     * is ENOTDIR, and a served directory is classified as itself.
     */
    char bare[LINUX_PATH_MAX];
    const char *name = path_bare_name(tx.intercept_path, bare, sizeof(bare));
    if (name != tx.intercept_path &&
        path_might_use_stat_intercept(tx.intercept_path)) {
        struct stat st;
        if (proc_intercept_stat_at(tx.intercept_path, &st, true) == -1)
            return linux_errno();
    }

    if (statfs_path_is_proc(name)) {
        if (proc_path_is_symlink(name)) {
            char link[LINUX_PATH_MAX];
            int len = proc_intercept_readlink(name, link, sizeof(link) - 1);
            if (len < 0)
                return linux_errno();
            link[len] = '\0';
            return sys_statfs_impl(g, link, buf_gva, depth + 1);
        }

        struct stat mac_st;
        int intercepted = proc_intercept_stat_at(name, &mac_st, true);
        if (intercepted == 0) {
            linux_statfs_t lin_st;
            fill_proc_statfs(&lin_st);
            if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0)
                return -LINUX_EFAULT;
            return 0;
        }
        if (intercepted == -1)
            return linux_errno();

        /* It might be /proc itself or a host-backed file/directory under /proc
         */
        if (stat(tx.host_path, &mac_st) == 0) {
            linux_statfs_t lin_st;
            fill_proc_statfs(&lin_st);
            if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0)
                return -LINUX_EFAULT;
            return 0;
        }
    }

    /* /sys is sysfs. libusb refuses to enumerate through the synthetic
     * /sys/bus/usb tree unless statfs("/sys") reports SYSFS_MAGIC
     * (linux_usbfs.c:398-408), and passing through to the host either fails (no
     * /sys on macOS) or leaks the sysroot's filesystem magic. The mount point
     * itself always answers; paths under it answer when the intercept layer (or
     * the host/sysroot backing, e.g. an empty /sys skeleton) knows them, and
     * report the same ENOENT a real Linux kernel would for the rest.
     */
    char sys_abs[LINUX_PATH_MAX];
    if (statfs_path_is_sysfs(name, sys_abs, sizeof(sys_abs))) {
        /* Classifying the folded name and then probing the raw one asked two
         * different questions of two different spellings: "/sys/../sys" is
         * sysfs, but no intercept and no host backing carries that literal
         * name, so the probe answered ENOENT for a directory that exists.
         * Re-enter on the folded spelling so the existence probe, the host
         * fallback and the answer all describe the same object. Folding is
         * idempotent, so this recurses at most once.
         */
        if (strcmp(sys_abs, name) != 0)
            return sys_statfs_impl(g, sys_abs, buf_gva, depth + 1);

        bool exists = sys_abs[4] == '\0'; /* "/sys" itself */
        if (!exists) {
            struct stat sys_st;
            int intercepted = proc_intercept_stat_at(sys_abs, &sys_st, true);
            if (intercepted == 0)
                exists = true;
            else if (intercepted == -1)
                return linux_errno();
            else
                exists = stat(tx.host_path, &sys_st) == 0;
        }
        if (!exists)
            return -LINUX_ENOENT;
        linux_statfs_t lin_st;
        fill_sysfs_statfs(&lin_st);
        if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    int dev_bus = statfs_dev_bus_class(name);
    if (dev_bus == -1)
        return linux_errno();
    if (dev_bus == 0) {
        linux_statfs_t lin_st;
        fill_dev_statfs(&lin_st);
        if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    /* glibc's posix_openpt() opens /dev/ptmx and then confirms devpts is
     * mounted before handing the master back (sysdeps/unix/sysv/linux/getpt.c).
     * /dev/pts has no host backing here, so a pass-through statfs fails and
     * glibc closes a perfectly good master -- breaking Unix98 pty allocation
     * for every glibc program. Answer from the virtual filesystem instead.
     */
    devpts_class_t devpts = statfs_devpts_class(name);
    if (devpts == DEVPTS_ABSENT)
        return -LINUX_ENOENT;
    if (devpts == DEVPTS_MOUNT) {
        linux_statfs_t lin_st;
        fill_devpts_statfs(&lin_st);
        if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    /* Report /dev/shm and its leaves as tmpfs, from the backing dir. statfs()
     * on the leaf would follow a symlink onto the host and leak the host fs
     * identity, so answer synthetically; lstat is the nofollow existence probe.
     */
    bool shm_root = !strcmp(name, "/dev/shm");
    if (tx.is_dev_shm || shm_root) {
        const char *shm_dir = proc_get_shm_dir();
        if (!shm_dir)
            return linux_errno();
        if (tx.is_dev_shm) {
            struct stat leaf_st;
            if (lstat(tx.host_path, &leaf_st) < 0)
                return linux_errno();
        }
        struct statfs shm_fs;
        if (statfs(shm_dir, &shm_fs) < 0)
            return linux_errno();
        linux_statfs_t lin_st;
        translate_statfs(&shm_fs, &lin_st); /* sets f_namelen = 255 */
        lin_st.f_type = 0x01021994;         /* TMPFS_MAGIC */
        if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    struct statfs mac_st;
    if (statfs(tx.host_path, &mac_st) < 0)
        return linux_errno();

    linux_statfs_t lin_st;
    translate_statfs(&mac_st, &lin_st);
    if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0)
        return -LINUX_EFAULT;

    return 0;
}

int64_t sys_statfs(guest_t *g, uint64_t path_gva, uint64_t buf_gva)
{
    char path[LINUX_PATH_MAX];
    if (guest_read_str_small(g, path_gva, path, sizeof(path)) < 0)
        return -LINUX_EFAULT;

    return sys_statfs_impl(g, path, buf_gva, 0);
}

/* Widen the window between reading a descriptor's stamp and pinning the host fd
 * it names, off unless ELFUSE_FD_IDENTITY_WINDOW_US is set to a positive
 * microsecond count.
 *
 * The window is real and far too narrow to reach from a test: unaided, over 160
 * runs at four delays, a sibling close-and-reopen between the two lookups was
 * never distinguishable in the answer. What lives in it is a guest fd number
 * whose slot can be replaced while this call is deciding what filesystem to
 * report for it, so the identity would come from one description and the
 * descriptor from another. tests/test-fstatfs-fd-identity drives it. Same shape
 * and the same reasoning as dir_backing_window_delay in syscall/fs.c; no effect
 * at all when unset.
 */
static void fd_identity_window_delay(void)
{
    static _Atomic long cached = -1; /* -1 = unread */
    long v = atomic_load_explicit(&cached, memory_order_relaxed);
    if (v < 0) {
        const char *env = getenv("ELFUSE_FD_IDENTITY_WINDOW_US");
        long long n = env ? strtoll(env, NULL, 10) : 0;
        v = (n > 0 && n < 1000000) ? (long) n : 0;
        atomic_store_explicit(&cached, v, memory_order_relaxed);
    }
    if (v > 0)
        usleep((useconds_t) v);
}

int64_t sys_fstatfs(guest_t *g, int fd, uint64_t buf_gva)
{
    /* Deliberately no devpts case for a pty master fd: Linux answers from
     * whatever filesystem provides /dev/ptmx, which is devpts only when it is
     * the bind-mounted /dev/pts/ptmx and tmpfs or devtmpfs otherwise. There is
     * no single correct value to report, and nothing needs one. The stamp and
     * the descriptor come out of one fd_lock window. They are two facts about
     * one open file description, and read separately a close and reopen between
     * them gave the stamp of the description the caller named and the
     * descriptor of whatever took the number afterwards -- so every branch
     * below, /proc included, could answer for an object this call is not
     * holding. Measured with the window widened: a plain sysroot file whose
     * slot was replaced mid-call by a /sys descriptor was reported as sysfs.
     */
    fd_entry_t snap;
    host_fd_ref_t host_ref;
    int64_t ref_err = host_fd_ref_open_entry(fd, &host_ref, &snap);
    if (ref_err < 0)
        return ref_err;
    fd_identity_window_delay();

    if (statfs_path_is_proc(snap.proc_path)) {
        host_fd_ref_close(&host_ref);
        linux_statfs_t proc_st;
        fill_proc_statfs(&proc_st);
        if (guest_write_small(g, buf_gva, &proc_st, sizeof(proc_st)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    /* Descriptors under /sys are sysfs whichever side served them, and the
     * spelling to test comes from the stamp when the fd carries one and from
     * the descriptor's own host path otherwise -- a fall-through open stamps
     * nothing. Both go to statfs_path_is_sysfs, the test the path side uses.
     * See docs/internals.md, "Filesystem Identity Of A Descriptor".
     */
    char fd_guest[LINUX_PATH_MAX];
    const char *fd_name = NULL;
    if (snap.proc_path[0]) {
        fd_name = snap.proc_path;
    } else {
        char fd_host[PATH_MAX];
        if (fcntl(host_ref.fd, F_GETPATH, fd_host) == 0 &&
            path_host_to_guest(fd_host, fd_guest, sizeof(fd_guest)) == 0)
            fd_name = fd_guest;
    }

    char fd_sys_abs[LINUX_PATH_MAX];
    if (fd_name &&
        statfs_path_is_sysfs(fd_name, fd_sys_abs, sizeof(fd_sys_abs))) {
        host_fd_ref_close(&host_ref);
        linux_statfs_t sys_st;
        fill_sysfs_statfs(&sys_st);
        if (guest_write_small(g, buf_gva, &sys_st, sizeof(sys_st)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    /* Only the "we serve it" answer applies here: an open descriptor stays a
     * valid one whatever became of its name, so a claimed-and-failed lookup is
     * no reason to fail fstatfs, and the host answers as it did before.
     */
    if (fd_name && statfs_dev_bus_class(fd_name) == 0) {
        host_fd_ref_close(&host_ref);
        linux_statfs_t dev_st;
        fill_dev_statfs(&dev_st);
        if (guest_write_small(g, buf_gva, &dev_st, sizeof(dev_st)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    struct statfs mac_st;
    if (fstatfs(host_ref.fd, &mac_st) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }

    linux_statfs_t lin_st;
    translate_statfs(&mac_st, &lin_st);
    if (guest_write_small(g, buf_gva, &lin_st, sizeof(lin_st)) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    host_fd_ref_close(&host_ref);
    return 0;
}

int64_t sys_statx(guest_t *g,
                  int dirfd,
                  uint64_t path_gva,
                  int flags,
                  unsigned int mask,
                  uint64_t statxbuf_gva)
{
    if (!validate_at_flags(
            flags, LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH |
                       LINUX_AT_NO_AUTOMOUNT | LINUX_AT_STATX_SYNC_TYPE))
        return -LINUX_EINVAL;

    /* See sys_fstat comment on the zero-init rationale. */
    struct stat mac_st = {0};
    int64_t rc = stat_at_path(g, dirfd, path_gva, flags, &mac_st);
    if (rc < 0)
        return rc;

    if (write_linux_statx(g, statxbuf_gva, &mac_st, mask) < 0)
        return -LINUX_EFAULT;
    return 0;
}
