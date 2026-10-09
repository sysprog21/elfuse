/*
 * Shared guest/host path handling
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

#include "utils.h"

#include "runtime/procemu.h"
#include "runtime/usb-sysfs.h"
#include "syscall/linux-wire.h"
#include "syscall/casefold-walk.h"
#include "syscall/fuse.h"
#include "proved/pathdepth.h"

#include "syscall/internal.h" /* host_dirfd_ref_open */
#include "syscall/path.h"
#include "syscall/proc.h"

#define PROC_PATH_COMPONENTS_MAX (LINUX_PATH_MAX / 2)

bool path_prefix_match(const char *path, const char *prefix, size_t plen)
{
    if (strncmp(path, prefix, plen) != 0)
        return false;
    return path[plen] == '\0' || path[plen] == '/';
}

/* The whole sysfs view: the USB layer answers /sys, /sys/bus, /sys/class and
 * everything under them (usb-sysfs.c), with /sys/devices/system/cpu carved out
 * for the older CPU-topology stub. Every gate below -- open, stat, poll --
 * reaches the whole view through SYSFS_PREFIX; the carve-out is about which
 * module answers, not about what the filesystem can do.
 */
#define SYSFS_PREFIX "/sys"
#define DEV_USB_PREFIX "/dev/bus"

static size_t bare_len(const char *path)
{
    size_t end = strlen(path);
    for (;;) {
        if (end >= 2 && path[end - 1] == '.' && path[end - 2] == '/')
            end -= 1;
        else if (end >= 2 && path[end - 1] == '/')
            end -= 1;
        else
            break;
    }
    return end;
}

bool path_dir_required(const char *path)
{
    return bare_len(path) != strlen(path);
}

const char *path_bare_name(const char *path, char *buf, size_t bufsz)
{
    size_t end = bare_len(path);
    if (end == strlen(path) || end + 1 > bufsz)
        return path;
    memcpy(buf, path, end);
    buf[end] = '\0';
    return buf;
}

/* Both gates read the name without its directory requirement, which the
 * intercepts enforce for themselves: an exact-match test below would otherwise
 * miss "/dev/fuse/" and hand a name the intercepts serve to the host.
 */
bool path_might_use_open_intercept(const char *path)
{
    if (!path || path[0] != '/')
        return false;
    char bare[LINUX_PATH_MAX];
    path = path_bare_name(path, bare, sizeof(bare));

    if (!strncmp(path, "/proc", 5))
        return true;
    if (!strncmp(path, "/dev", 4))
        return true;
    if (fuse_path_matches_mount(path))
        return true;
    if (path_prefix_match(path, SYSFS_PREFIX, sizeof(SYSFS_PREFIX) - 1))
        return true;
    if (!strcmp(path, "/etc/mtab"))
        return true;
    if (!strcmp(path, "/etc/passwd") || !strcmp(path, "/etc/group")) {
        char sr[LINUX_PATH_MAX];
        if (proc_sysroot_snapshot(sr, sizeof(sr))) {
            char sysroot_file[LINUX_PATH_MAX];
            if (snprintf(sysroot_file, sizeof(sysroot_file), "%s%s", sr, path) <
                (int) sizeof(sysroot_file)) {
                struct stat st;
                if (stat(sysroot_file, &st) == 0)
                    return false;
            }
        }
        return true;
    }
    if (!strcmp(path, "/var/run/utmp") || !strcmp(path, "/run/utmp"))
        return true;

    return false;
}

/* The part of a guest /proc path that follows the process directory, or NULL
 * when the path names no process directory at all: "/proc/self/stat" and
 * "/proc/41/stat" both yield "stat", "/proc/self" yields "", and
 * "/proc/meminfo" yields NULL.
 *
 * A "task/<tid>/" segment is stripped with the process directory it sits in, so
 * "/proc/41/task/41/mounts" yields "mounts" too. Linux answers the thread
 * spelling of these names the way it answers the process one, measured on 6.12
 * over mounts, mountinfo, net/dev and stat.
 */
static const char *proc_pid_dir_suffix(const char *path)
{
    if (strncmp(path, "/proc/", 6) != 0)
        return NULL;

    const char *p = path + 6;
    if (!strncmp(p, "self", 4) && (p[4] == '\0' || p[4] == '/')) {
        p += 4;
    } else if (!strncmp(p, "thread-self", 11) &&
               (p[11] == '\0' || p[11] == '/')) {
        p += 11;
    } else {
        const char *d = p;
        while (*d >= '0' && *d <= '9')
            d++;
        if (d == p || (*d != '\0' && *d != '/'))
            return NULL;
        p = d;
    }
    if (*p == '/')
        p++;

    if (!strncmp(p, "task/", 5)) {
        const char *d = p + 5;
        const char *tid = d;
        while (*d >= '0' && *d <= '9')
            d++;
        if (d != tid && (*d == '\0' || *d == '/'))
            p = (*d == '/') ? d + 1 : d;
    }
    return p;
}

/* Whether Linux gives the file behind this intercepted guest path a poll
 * method, which is the only thing epoll_ctl reads EPERM off. fstat cannot
 * answer it: elfuse serves several intercepted trees from ordinary host files,
 * so the host object describes elfuse's staging rather than the file the guest
 * named, and the path is what still knows.
 *
 * The answer per family was measured against Linux 6.12 rather than reasoned
 * from the file's contents, because the two do not track each other: a
 * per-process procfs file is opened through proc_single_file_operations, which
 * carries no poll, while every proc_create entry gets proc_reg_poll whether or
 * not it has anything to report. /proc/<pid>/mounts and mountinfo are the
 * exception that makes the split visible -- they go through mounts_operations
 * so a guest can wait for the mount table to change, while mountstats next to
 * them does not and is refused. The /proc/<pid>/net subtree is the other
 * exception, measured on Linux rather than reached here: elfuse serves
 * /proc/net but not yet the per-process spelling of it, so that arm is
 * unreachable today and is present so it does not become wrong the day it is.
 */
bool path_intercept_poll_capable(const char *path)
{
    if (!path || path[0] != '/')
        return false;

    const char *pid_rel = proc_pid_dir_suffix(path);
    if (pid_rel)
        return !strcmp(pid_rel, "mounts") || !strcmp(pid_rel, "mountinfo") ||
               !strncmp(pid_rel, "net/", 4);

    /* sysfs attributes are pollable through kernfs, and /etc/mtab is a symlink
     * onto the mount table. What is left of the intercept surface --
     * /etc/passwd and /etc/group, the utmp files, most of /dev and the FUSE
     * mounts -- is a plain file, a character device or a fifo, all of which the
     * host object describes correctly, so the caller's fstat and kqueue probe
     * answer for them.
     *
     * /dev/random is the exception, and it does not extend to the /dev/urandom
     * beside it. random_fops carries .poll and urandom_fops does not, since a
     * read from urandom never waits, so Linux 6.12 answers 0 for the first and
     * EPERM for the second. macOS refuses a knote on both, which leaves the
     * host object unable to tell them apart.
     */
    if (!strncmp(path, "/proc/", 6))
        return true;

    /* Every sysfs attribute, not the CPU subtree alone: pollability comes from
     * kernfs_fop_poll, which sysfs_file_operations installs on all of them, so
     * a real /sys answers epoll_ctl(ADD) with 0 for net/lo/mtu and for
     * bus/usb/devices/1-1/idVendor alike (measured on 6.19). Naming one subtree
     * made every attribute the USB layer added report EPERM, which is the
     * answer for a file that cannot be polled at all -- and udev-style readers
     * arm `uevent` before they read it.
     */
    if (path_prefix_match(path, SYSFS_PREFIX, sizeof(SYSFS_PREFIX) - 1))
        return true;
    if (!strcmp(path, "/dev/random"))
        return true;
    return !strcmp(path, "/etc/mtab");
}

bool path_might_use_stat_intercept(const char *path)
{
    if (!path || path[0] != '/')
        return false;
    char bare[LINUX_PATH_MAX];
    path = path_bare_name(path, bare, sizeof(bare));

    if (!strncmp(path, "/proc", 5))
        return true;
    if (!strncmp(path, "/dev/shm", 8))
        return true;
    if (!strcmp(path, "/dev/fuse"))
        return true;

    /* glibc ptsname(3) stats /dev/pts/N after TIOCGPTN to confirm the slave
     * exists and is a char device; without this the stat falls through to the
     * host where /dev/pts is absent and ptsname returns ENOENT.
     */
    if (!strncmp(path, "/dev/pts/", 9) || !strcmp(path, "/dev/pts") ||
        !strcmp(path, "/dev/pts/"))
        return true;
    if (fuse_path_matches_mount(path))
        return true;
    if (path_prefix_match(path, SYSFS_PREFIX, sizeof(SYSFS_PREFIX) - 1))
        return true;
    if (path_prefix_match(path, DEV_USB_PREFIX, sizeof(DEV_USB_PREFIX) - 1))
        return true;

    /* Synthesized on open, so it has to exist for stat too. */
    return !strcmp(path, "/etc/mtab");
}

int path_check_intercept_access(const struct stat *st, int mode, int flags)
{
    if ((mode & ~(F_OK | R_OK | W_OK | X_OK)) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (mode == F_OK)
        return 0;

    mode_t granted = 0;
    uint32_t uid =
        (flags & LINUX_AT_EACCESS) ? proc_get_euid() : proc_get_uid();
    uint32_t gid =
        (flags & LINUX_AT_EACCESS) ? proc_get_egid() : proc_get_gid();

    if (uid == 0) {
        /* CAP_DAC_OVERRIDE: root reads and writes any file regardless of mode
         * bits. Execute still requires at least one x-bit set so non-executable
         * files cannot be run as root. Matches Linux generic_permission() in
         * fs/namei.c.
         */
        granted |= R_OK | W_OK;
        if (st->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
            granted |= X_OK;
    } else {
        mode_t bits;
        if (uid == st->st_uid)
            bits = (st->st_mode >> 6) & 7;
        else if (gid == st->st_gid)
            bits = (st->st_mode >> 3) & 7;
        else
            bits = st->st_mode & 7;

        if (bits & 4)
            granted |= R_OK;
        if (bits & 2)
            granted |= W_OK;
        if (bits & 1)
            granted |= X_OK;
    }

    if ((mode & granted) == mode)
        return 0;

    errno = EACCES;
    return -1;
}

/* Splice a symlink target back into a path being resolved: @target, then
 * whatever of the original path was left unconsumed. @prefix is prepended only
 * for a relative target, and names the directory the link sits in; a caller
 * that re-anchors some other way (by resetting a descriptor, say) passes NULL.
 *
 * Shared because two walkers follow links and the concatenation is where the
 * truncation checks live. A second copy of it would be a second place for a
 * spliced path to be silently shortened into one naming a different file.
 *
 * Returns 0, or -1 with errno set to ENAMETOOLONG.
 */
int path_splice_link_target(const char *prefix,
                            size_t prefix_len,
                            const char *target,
                            const char *rest,
                            char *out,
                            size_t outsz)
{
    int n;

    while (*rest == '/')
        rest++;

    if (target[0] == '/' || !prefix)
        n = snprintf(out, outsz, "%s%s%s", target, *rest ? "/" : "", rest);
    else
        n = snprintf(out, outsz, "%.*s%s%s%s", (int) prefix_len, prefix, target,
                     *rest ? "/" : "", rest);

    if (n < 0 || (size_t) n >= outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* True when @path names a directory by ending in one or more separators. "/"
 * itself does not count: it is the root, not an assertion about a leaf.
 */
static bool path_has_trailing_slash(const char *path)
{
    size_t len = path ? strlen(path) : 0;

    return len > 1 && path[len - 1] == '/';
}

/* Forward-declared: defined below dirfd_guest_base_path(), which it needs. */
static int path_check_relative_sysroot_containment(guest_fd_t dirfd,
                                                   const char *path,
                                                   unsigned int flags,
                                                   bool *in_sysroot,
                                                   char *host_out,
                                                   size_t host_outsz);

int path_parse_proc_name(const char *name)
{
    if (!name || !*name)
        return -1;

    /* Linux rejects a leading zero on any name longer than one character, so
     * "0" names descriptor 0 but "00" and "03" name nothing.
     */
    if (name[0] == '0' && name[1] != '\0')
        return -1;

    long n = 0;
    for (const char *p = name; *p; p++) {
        if (*p < '0' || *p > '9')
            return -1;
        n = n * 10 + (*p - '0');
        if (n > INT_MAX)
            return -1;
    }
    return (int) n;
}

/* Parse an absolute fd magic link to the guest descriptor it names. This
 * accepts "/proc/self/fd/<n>", the equivalent spelling with this process's own
 * pid, and the /dev aliases Linux exposes as symlinks to procfs.
 *
 * Linux makes that a magic symlink, so a path-based syscall against it acts on
 * the file the descriptor holds. It is the standard way to reach a file through
 * an fd when no f*() variant applies -- systemd's fchmod_opath() chmods
 * /proc/self/fd/<n> precisely because fchmod() rejects O_PATH descriptors, and
 * reads ENOENT there as "this fd is not valid" (reporting EBADF) rather than as
 * a missing file.
 *
 * Returns the guest descriptor, or -1 when the path is not that shape.
 */
static int parse_fd_magiclink(const char *path)
{
    const char *rest = NULL;

    if (strncmp(path, "/proc/", 6) == 0) {
        rest = path + 6;
        if (!strncmp(rest, "self/", 5)) {
            rest += 5;
        } else {
            /* The pid component gets the same strict rules as the fd leaf:
             * Linux resolves /proc/<pid> through name_to_int as well, so
             * "/proc/+1234/fd/3" names nothing there even when 1234 is this
             * process. A component too long for the buffer is not a pid either.
             */
            const char *slash = strchr(rest, '/');
            if (!slash)
                return -1;
            char pid_name[16];
            if (path_component_copy(pid_name, sizeof(pid_name), rest,
                                    (size_t) (slash - rest)) < 0)
                return -1;
            if (path_parse_proc_name(pid_name) != (int) proc_get_pid())
                return -1;
            rest = slash + 1;
        }

        if (strncmp(rest, "fd/", 3) != 0)
            return -1;
        rest += 3;
    } else if (strncmp(path, "/dev/fd/", 8) == 0) {
        rest = path + 8;
    } else if (!strcmp(path, "/dev/stdin")) {
        rest = "0";
    } else if (!strcmp(path, "/dev/stdout")) {
        rest = "1";
    } else if (!strcmp(path, "/dev/stderr")) {
        rest = "2";
    } else {
        return -1;
    }

    /* Only a bare descriptor number names the file itself. Anything trailing
     * ("/proc/self/fd/3/x" or "/dev/fd/3/x") walks through it, which the host
     * path cannot express here, and a leaf Linux would not accept as a procfs
     * fd name is not this shape at all.
     */
    return path_parse_proc_name(rest);
}

int path_fd_magiclink_guest_fd(const char *path)
{
    return parse_fd_magiclink(path);
}

/* Whether an f*() call on the slot's host fd acts on the file the magic link
 * names. A FUSE or synthetic fd is served by an emulation layer rather than by
 * the host file behind it, so those keep the path form and the intercepts that
 * go with it.
 */
static inline bool magiclink_type_acts_on_host_fd(int type)
{
    return type == FD_REGULAR || type == FD_DIR || type == FD_PATH ||
           type == FD_STDIO;
}

int path_fd_magiclink_open(const char *path, host_fd_ref_t *ref)
{
    fd_entry_t entry;
    return path_fd_magiclink_open_entry(path, ref, &entry);
}

int path_fd_magiclink_open_entry(const char *path,
                                 host_fd_ref_t *ref,
                                 fd_entry_t *entry)
{
    ref->fd = -1;
    ref->lifetime = NULL;

    int fd = parse_fd_magiclink(path);
    if (fd < 0)
        return -1;

    /* Pin rather than dup. A sibling vCPU closing this slot would otherwise
     * leave the number free for the next open to claim, which is the only
     * reason a second descriptor was ever taken here; the pin covers it without
     * one. It also has to be a pin rather than a dup because the caller acts on
     * a file the guest may hold record locks on, and retiring a dup would drop
     * every one of them (fcntl(2)): a guest chmod of its own /proc/self/fd/N
     * would silently unlock the file.
     *
     * The classification below and the pin have to come out of the same fd_lock
     * hold. Taking them separately leaves a window where a sibling closes the
     * slot and the next open claims the number, and the caller then acts on the
     * replacement while the type it was admitted on describes the object that
     * is gone.
     */
    if (thread_is_single_active()) {
        if (!fd_snapshot(fd, entry) || entry->host_fd < 0)
            return -1;
        if (!magiclink_type_acts_on_host_fd(entry->type))
            return -1;
        ref->fd = entry->host_fd;
        return 0;
    }

    int host_fd = fd_host_ref_acquire(fd, entry, &ref->lifetime);
    if (host_fd < 0)
        return -1;
    if (!magiclink_type_acts_on_host_fd(entry->type)) {
        host_fd_ref_close(ref);
        return -1;
    }
    ref->fd = host_fd;
    return 0;
}

/* Resolve an absolute fd magic link to the host path its descriptor is open on.
 *
 * Returns 1 and fills out on success, 0 when the path is not that shape or the
 * descriptor has no host path (a pipe, socket, or anonymous fd, where F_GETPATH
 * fails and the caller's own /proc intercepts remain the right answer).
 *
 * Callers that can act on a descriptor should prefer path_fd_magiclink_open():
 * a pathname taken here and used later is a TOCTOU, since a rename or an
 * unlink-and-recreate in between leaves it naming a different inode, where
 * Linux resolves the link inside the syscall and cannot be redirected.
 */
static bool resolve_fd_magiclink_host_path(const char *path,
                                           char *out,
                                           size_t outsz)
{
    host_fd_ref_t ref;
    if (path_fd_magiclink_open(path, &ref) < 0)
        return false;

    char resolved[PATH_MAX];
    int rc = fcntl(ref.fd, F_GETPATH, resolved);
    host_fd_ref_close(&ref);
    if (rc < 0)
        return false;

    size_t len = strlen(resolved);
    if (len >= outsz)
        return false;
    memcpy(out, resolved, len + 1);
    return true;
}

/* Whether an absolute name holds anything path_fold_components would remove: a
 * "//" run, or a "." component with a slash after it.
 */
static bool path_has_foldable(const char *p)
{
    for (; *p; p++) {
        if (p[0] == '/' && (p[1] == '/' || (p[1] == '.' && p[2] == '/')))
            return true;
    }
    return false;
}

/* Fold "//" runs and "." components out of an absolute name, the way the Linux
 * path walk steps over them.
 *
 * A "." that is the last component stays, with the slash after it if it has
 * one, because the last component is where Linux gives it a meaning of its own:
 * rmdir("d/.") is EINVAL where rmdir("d/") removes d. ".." is left alone,
 * because Linux applies it to what the component before it resolved to, which
 * is not a lexical question.
 *
 * @out may be @path: the result is never longer than what has been read.
 */
static void path_fold_components(const char *path, char *out)
{
    const char *p = path;
    size_t w = 0;

    for (;;) {
        bool slash = *p == '/';
        while (*p == '/')
            p++;
        if (!*p) {
            if (slash)
                out[w++] = '/';
            break;
        }

        const char *seg = p;
        while (*p && *p != '/')
            p++;
        size_t n = (size_t) (p - seg);

        const char *next = p;
        while (*next == '/')
            next++;
        if (n == 1 && seg[0] == '.' && *next)
            continue;

        out[w++] = '/';
        memmove(out + w, seg, n);
        w += n;
    }
    out[w] = '\0';
}

int path_translate_at(guest_fd_t dirfd,
                      const char *path,
                      unsigned int flags,
                      path_translation_t *tx)
{
    if (!tx) {
        errno = EINVAL;
        return -1;
    }

    /* Only the fields read on the no-rewrite fast path need explicit defaults;
     * proc_path / guest_buf / host_buf are read-after-written by their
     * respective resolvers. memset of all three 4 KiB buffers would add ~12 KiB
     * of zeroing per call, which is visible at ~30 calls per dynamic-linker
     * startup.
     */
    tx->guest_path = path;
    tx->intercept_path = path;
    tx->host_path = path;
    tx->proc_resolved = 0;
    tx->fuse_path = false;
    tx->is_dev_shm = false;

    if (!path)
        return 0;

    tx->proc_resolved =
        resolve_proc_at_path(dirfd, path, tx->proc_path, sizeof(tx->proc_path));
    if (tx->proc_resolved < 0)
        return -1;
    if (tx->proc_resolved > 0) {
        tx->guest_path = tx->proc_path;
        tx->intercept_path = tx->proc_path;
    } else {
        int fuse_rc = fuse_resolve_at_path(dirfd, path, tx->guest_buf,
                                           sizeof(tx->guest_buf));
        if (fuse_rc < 0)
            return -1;
        if (fuse_rc > 0) {
            tx->guest_path = tx->guest_buf;
            tx->intercept_path = tx->guest_buf;
            tx->fuse_path = true;
        }
    }

    /* Linux folds "//" runs and "." components in the one walk every path
     * syscall shares, so no filesystem is handed them. The intercepts match
     * literal prefixes, here and behind this function, so the name is folded
     * here once rather than by each of them. A relative name needs nothing: the
     * two resolvers above fold what they join, and what they decline goes to
     * the host as written.
     */
    if (tx->guest_path[0] == '/' && path_has_foldable(tx->guest_path)) {
        char *folded =
            tx->guest_path == tx->proc_path ? tx->proc_path : tx->guest_buf;
        if (folded == tx->guest_path ||
            strlen(tx->guest_path) < sizeof(tx->guest_buf)) {
            path_fold_components(tx->guest_path, folded);
            tx->guest_path = folded;
            tx->intercept_path = folded;
        }
    }

    /* A /sys walk that passes through one of the synthetic USB `subsystem`
     * symlinks is rewritten to the canonical guest spelling of where it lands,
     * before anything decides whose name it is. The links exist only in the
     * synthetic tree, so no other layer can resolve them: the sysroot has no
     * such link, and a lexical fold puts the walk back in the device directory
     * it had just left. Doing it here, once, is what makes open, stat, lstat,
     * readlink and getdents64 answer from one name -- the union listing of
     * `<dev>/subsystem/..` offered /sys/bus/pci while every lookup of
     * `<dev>/subsystem/../pci` denied it, because each entry point folded the
     * name for itself.
     *
     * Cheap for everything else: the prefix test rejects every path that cannot
     * contain such a link before the USB layer is called at all.
     */
    if (!strncmp(tx->guest_path, "/sys/bus/usb/devices/", 21)) {
        /* Through a local buffer, not straight into guest_buf: guest_path may
         * already be guest_buf (the FUSE resolver above puts it there), and the
         * rewrite reads its input while writing its output.
         */
        char resolved[LINUX_PATH_MAX];
        if (usb_sysfs_resolve_guest_path(tx->guest_path, resolved,
                                         sizeof(resolved)) == 1) {
            str_copy_trunc(tx->guest_buf, resolved, sizeof(tx->guest_buf));
            tx->guest_path = tx->guest_buf;
            tx->intercept_path = tx->guest_buf;
        }
    }

    /* /dev/shm/<leaf> maps into the per-UID host backing dir, through the same
     * validated resolver as the open and stat intercepts. Only a non-empty flat
     * leaf is redirected; bare "/dev/shm" and "/dev/shm/" stay on the sysroot
     * path so the synthetic-directory intercepts keep answering for them. The
     * resolver rejects "..", embedded '/', and empty names with EACCES. The
     * early return skips sysroot resolution, the relative-containment recheck,
     * and the casefold walk: the backing path is absolute, self-contained, and
     * must never be escape-mapped. is_dev_shm signals the redirect to callers,
     * which must force nofollow on the host call; see dev_shm_resolve_path()
     * for that invariant.
     */
    if (!strncmp(tx->guest_path, "/dev/shm/", 9) && tx->guest_path[9] != '\0' &&
        !path_dir_required(tx->guest_path + 8)) {
        if (proc_dev_shm_resolve(tx->guest_path + 9, tx->host_buf,
                                 sizeof(tx->host_buf)) < 0)
            return -1;
        tx->host_path = tx->host_buf;
        tx->is_dev_shm = true;
        return 0;
    }

    /* "/dev/stdout/" names the directory the descriptor's file would be, which
     * a pipe, a terminal or a regular file is not. The host walk applies that
     * rule to every other name; a magic link it never sees, and on a pipe it
     * has no path to see it by.
     */
    char link_bare[LINUX_PATH_MAX];
    const char *link_name =
        path_bare_name(tx->guest_path, link_bare, sizeof(link_bare));
    if (link_name != tx->guest_path && tx->guest_path[0] == '/') {
        host_fd_ref_t ref;
        if (path_fd_magiclink_open(link_name, &ref) == 0) {
            struct stat st;
            bool is_dir = fstat(ref.fd, &st) == 0 && S_ISDIR(st.st_mode);
            host_fd_ref_close(&ref);
            if (!is_dir) {
                errno = ENOTDIR;
                return -1;
            }
        }
    }

    /* Only host_path moves; guest_path and intercept_path keep the /proc
     * spelling. open, stat and readlink never reach host_path for these paths:
     * proc_intercept_open dups the descriptor, proc_intercept_stat fstats it,
     * and proc_intercept_readlink reports its path, and none of the three fall
     * through to the host on a fd magic link that names an open slot (a closed
     * one fails as EBADF rather than falling through). What this changes is
     * every other follow-style operation -- chmod, chown, utimensat, truncate,
     * access -- which now acts on the file the descriptor holds, the way Linux
     * does when it resolves the magic link.
     *
     * Returning before sysroot resolution is not a containment claim about the
     * path: F_GETPATH reports where the descriptor's file actually lives, which
     * is regularly outside the sysroot -- an emulated character device, a
     * /dev/shm backing file, inherited stdio. Re-resolving one of those as a
     * guest path would be wrong, since it is already a host path. Nothing is
     * widened by it either: the guest holds the descriptor, so this reaches
     * only what it could already reach through it.
     *
     * Follow-style only. Linux resolves the link for an operation that follows
     * the final component and acts on the link itself otherwise, so a no-follow
     * or create-style caller -- unlinkat, renameat, chmod with
     * AT_SYMLINK_NOFOLLOW -- must not be handed the descriptor's file, or
     * unlinkat("/proc/self/fd/<n>") would delete it instead of failing on the
     * /proc entry.
     */
    if (tx->guest_path[0] == '/' &&
        !(flags & (PATH_TR_NOFOLLOW | PATH_TR_CREATE)) &&
        resolve_fd_magiclink_host_path(link_name, tx->host_buf,
                                       sizeof(tx->host_buf))) {
        tx->host_path = tx->host_buf;
        return 0;
    }

    unsigned int lookup_flags = flags;
    if (path_has_trailing_slash(tx->guest_path))
        lookup_flags &= ~PATH_TR_NOFOLLOW;

    errno = 0;
    if (lookup_flags & PATH_TR_CREATE) {
        tx->host_path = path_resolve_sysroot_create_path(
            tx->guest_path, tx->host_buf, sizeof(tx->host_buf),
            (lookup_flags & PATH_TR_CREATE_PARENTS) != 0);
    } else if (lookup_flags & PATH_TR_NOFOLLOW) {
        tx->host_path = path_resolve_sysroot_nofollow_path(
            tx->guest_path, tx->host_buf, sizeof(tx->host_buf));
    } else {
        tx->host_path = path_resolve_sysroot_path(tx->guest_path, tx->host_buf,
                                                  sizeof(tx->host_buf));
    }

    /* The resolvers above key off guest_path[0] == '/': a relative path is
     * handed back untouched because they have no dirfd context to rebuild a
     * host location from, so it never gets the sysroot-prefix + realpath()
     * containment check that absolute paths get. That leaves the actual
     * openat(dirfd, name) to the host kernel's own resolution, which is not
     * confined to dirfd's subtree -- a symlink reachable through dirfd (a
     * relative target with enough ".." components, or an absolute target) walks
     * straight out of the sysroot with no check at all. Reconstruct the
     * equivalent absolute guest path from dirfd's guest base path and run it
     * back through the same containment-checked resolver; its realpath() call
     * collapses ".." and any symlink indirection, including an absolute target,
     * before the prefix check runs.
     */
    bool climbed_root = false;
    bool relative_in_sysroot = false;
    char relative_host[LINUX_PATH_MAX];
    if (tx->host_path && tx->guest_path[0] != '/' && proc_get_sysroot()) {
        int recheck = path_check_relative_sysroot_containment(
            dirfd, tx->guest_path, lookup_flags, &relative_in_sysroot,
            relative_host, sizeof(relative_host));
        if (recheck < 0) {
            tx->host_path = NULL;
            if (errno == 0)
                errno = ELOOP;
        } else if (recheck > 0) {
            /* The reconstructed path clamped at the guest root, so the host
             * must not walk the guest's own spelling from dirfd: its ".." runs
             * out of the sysroot, where the guest's stops. Hand over the
             * absolute host path the recheck already resolved; POSIX has the
             * kernel ignore dirfd for an absolute path, so the two agree.
             */
            str_copy_trunc(tx->host_buf, relative_host, sizeof(tx->host_buf));
            tx->host_path = tx->host_buf;
            climbed_root = true;
        }
    }

    /* A relative name has no leading component for the resolvers above to key
     * on, so they hand it back untouched, but it still names a file that may be
     * stored under an escaped spelling. Resolve it the same way, seeded from
     * the descriptor it is measured against rather than from the sysroot.
     * Without this the two ways of naming one file disagree: a create through a
     * relative name lands beside the entry an absolute create already made, and
     * O_EXCL on a name that exists succeeds.
     *
     * Only for a name the sysroot actually claims. Outside it the guest is
     * looking at the host filesystem, where an absolute path is passed through
     * untouched and a relative one has to match; escaping here would leave
     * elfuse's spellings in directories it does not own. The containment check
     * above already made that call, and now reports it.
     *
     * Runs after that check, so a path it rejected is not resolved to a usable
     * spelling afterwards.
     */
    if (tx->host_path && relative_in_sysroot && !climbed_root &&
        casefold_active()) {
        /* The caller's follow decision applies to the final component here
         * exactly as it does in the absolute resolvers: a create names the
         * link, not the target (proc-state.c passes the same false), and
         * everything else follows unless it asked not to. Stopping short
         * unconditionally would hand the link's stored target bytes to the host
         * kernel, which cannot spell them.
         */
        bool follow_final =
            !(lookup_flags & (PATH_TR_NOFOLLOW | PATH_TR_CREATE));
        host_fd_ref_t ref;
        casefold_verdict_t verdict;

        int64_t ref_err = host_dirfd_ref_open(dirfd, &ref);
        if (ref_err < 0) {
            errno = (ref_err == -LINUX_ENOMEM) ? ENOMEM : EBADF;
            return -1;
        }
        verdict = casefold_resolve_at(ref.fd, "", tx->guest_path, follow_final,
                                      tx->host_buf, sizeof(tx->host_buf), NULL);
        host_fd_ref_close(&ref);
        if (verdict == CASEFOLD_ERROR)
            return -1;

        /* A link on the way needs the target resolved in the guest namespace,
         * and a target may be absolute, which a descriptor-relative walk has no
         * anchor for. The containment check already resolved the reconstructed
         * absolute path with the caller's own flag mapping and handed the host
         * spelling back; using it keeps one mapping for both legs instead of a
         * second copy that can drift. Only paths that actually cross a link
         * take this arm; everything else keeps the descriptor-relative walk,
         * whose descriptor is the anchor openat(2) semantics are measured from.
         */
        if (verdict == CASEFOLD_SYMLINK &&
            str_copy_trunc(tx->host_buf, relative_host, sizeof(tx->host_buf)) >=
                sizeof(tx->host_buf)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        tx->host_path = tx->host_buf;
    }

    if (!tx->host_path) {
        /* Resolvers set errno on every failure path; only synthesize one if a
         * future caller forgets, so the error class survives instead of being
         * flattened to ENAMETOOLONG.
         */
        if (errno == 0)
            errno = ENAMETOOLONG;
        return -1;
    }

    /* A trailing slash asserts the target is a directory (POSIX 4.13, and
     * path_resolution(7)), so "file/" owes ENOTDIR. The component walk skips
     * separators, so the assertion is lost by the time the host path is built.
     * Put it back rather than re-stat here: Darwin enforces trailing-slash
     * semantics itself, so the kernel answers on the caller's own syscall,
     * which is both free and atomic with the operation being performed.
     */
    if (path_has_trailing_slash(tx->guest_path) &&
        !path_has_trailing_slash(tx->host_path)) {
        size_t len = strlen(tx->host_path);

        if (tx->host_path != tx->host_buf) {
            if (str_copy_trunc(tx->host_buf, tx->host_path,
                               sizeof(tx->host_buf)) >= sizeof(tx->host_buf)) {
                errno = ENAMETOOLONG;
                return -1;
            }
            tx->host_path = tx->host_buf;
        }
        if (len + 2 > sizeof(tx->host_buf)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        tx->host_buf[len] = '/';
        tx->host_buf[len + 1] = '\0';
    }

    return 0;
}

bool path_dirent_dir_holds_escapes(host_fd_t host_dirfd)
{
    char sr[LINUX_PATH_MAX], dirpath[LINUX_PATH_MAX];

    if (!casefold_active() || !proc_sysroot_snapshot(sr, sizeof(sr)))
        return false;
    if (fcntl(host_dirfd, F_GETPATH, dirpath) < 0)
        return false;
    size_t sr_len = strlen(sr);

    /* "--sysroot /" is the one prefix that is a bare separator: it owns every
     * host path, but path_prefix_match on it accepts only "/" itself.
     */
    if (sr_len == 1)
        return true;

    /* proc_set_sysroot stores a realpath()-canonical prefix and F_GETPATH
     * reports canonical paths, so a byte compare is sound; the residual
     * folding-volume caveat is the accepted gap the NO_XDEV checker documents
     * (path.h).
     */
    return path_prefix_match(dirpath, sr, sr_len);
}

int path_translate_dirent_name(bool dir_holds_escapes,
                               const char *host_name,
                               char *guest_name,
                               size_t guest_name_sz)
{
    if (!host_name || !guest_name || guest_name_sz == 0) {
        errno = EINVAL;
        return -1;
    }

    /* Only a directory the sysroot owns can hold escaped spellings, and the
     * process-wide fold switch cannot say which side of that boundary these
     * entries came from; the caller answers it from the directory's own host
     * identity. Outside the sysroot the guest is looking at the host filesystem
     * directly, where a name merely shaped like an escape is an ordinary file
     * that means itself; decoding it would report a name the directory does not
     * contain and that no later open could resolve, while hiding the entry's
     * real name behind it.
     */
    if (!dir_holds_escapes) {
        if (str_copy_trunc(guest_name, host_name, guest_name_sz) >=
            guest_name_sz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return 0;
    }

    /* Decoding an on-disk name needs nothing beyond the name itself: no
     * bookkeeping entry to hide, and no failure mode beyond a caller buffer too
     * small for the result.
     */
    return casefold_to_guest(host_name, guest_name, guest_name_sz);
}

static bool path_component_is_dot(const char *comp, size_t len)
{
    return len == 1 && comp[0] == '.';
}

static bool path_component_is_dotdot(const char *comp, size_t len)
{
    return len == 2 && comp[0] == '.' && comp[1] == '.';
}

/* Lexical depth of a guest path: components pushed minus the '..' that pop
 * them, floored at zero the way resolution floors at the root
 * (path_resolution(7)).
 */
static size_t path_lexical_depth(const char *path)
{
    const char *scan = path;
    const char *comp;
    size_t len;
    size_t depth = 0;

    while (path_next_component(&scan, &comp, &len)) {
        if (path_component_is_dot(comp, len))
            continue;
        if (path_component_is_dotdot(comp, len)) {
            uint64_t popped;
            if (path_depth_pop(depth, &popped))
                depth = popped;
            continue;
        }
        depth++;
    }
    return depth;
}

/* Forward-declared: defined below with the other dirfd reconstruction helpers,
 * which sys_path_has_symlink() needs for its '..' clamp.
 */
static int dirfd_guest_base_path(guest_fd_t dirfd, char *out, size_t outsz);

const char *path_resolve_sysroot_path(const char *path, char *buf, size_t bufsz)
{
    return proc_resolve_sysroot_path(path, buf, bufsz);
}

const char *path_resolve_sysroot_nofollow_path(const char *path,
                                               char *buf,
                                               size_t bufsz)
{
    return proc_resolve_sysroot_nofollow_path(path, buf, bufsz);
}

const char *path_resolve_sysroot_create_path(const char *path,
                                             char *buf,
                                             size_t bufsz,
                                             bool create_parents)
{
    return proc_resolve_sysroot_create_path(path, buf, bufsz, create_parents);
}

int sys_path_has_symlink(guest_fd_t dirfd, const char *path)
{
    if (!path || path[0] == '\0')
        return 0;

    host_fd_t base_fd;
    bool owned_base_fd = false;
    const char *scan = path;
    char sysroot_buf[LINUX_PATH_MAX];
    bool clamp = false;
    size_t depth = 0;

    /* Function-scoped because base_fd borrows dir_ref.fd for the whole walk:
     * the pin has to outlive every use of the descriptor it keeps open.
     */
    host_fd_ref_t dir_ref = HOST_FD_REF_INIT;

    if (path[0] == '/') {
        /* The resolver splices an intermediate link into its target, so its
         * output cannot reveal the link to the component walk below. Ask the
         * case-exact walk first: it stops at exactly the link this precheck
         * exists to refuse. An absent or folded path keeps the resolver's
         * answer: no in-sysroot component of those is ever spliced, so the walk
         * below still sees whatever the host side holds.
         */
        if (casefold_active()) {
            char sr[LINUX_PATH_MAX];

            if (proc_sysroot_snapshot(sr, sizeof(sr))) {
                casefold_verdict_t verdict =
                    casefold_resolve_at(AT_FDCWD, sr, path, false, sysroot_buf,
                                        sizeof(sysroot_buf), NULL);

                if (verdict == CASEFOLD_ERROR)
                    return -1;
                if (verdict == CASEFOLD_SYMLINK) {
                    errno = ELOOP;
                    return -1;
                }
            }
        }
        const char *host_path = path_resolve_sysroot_nofollow_path(
            path, sysroot_buf, sizeof(sysroot_buf));
        if (!host_path) {
            errno = ENAMETOOLONG;
            return -1;
        }
        base_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (base_fd < 0)
            return -1;
        owned_base_fd = true;
        scan = host_path;
    } else {
        /* The fd walk below follows '..' onto the real host parent, which above
         * the guest root is the sysroot's own parent: entries there, including
         * the host's symlinks, are not the guest's, so Linux's clamp at the
         * root (path_resolution(7)) has to be applied here. Seed it with the
         * descriptor's lexical guest depth; a walk that never dips above the
         * descriptor cannot reach the root and skips the reconstruction.
         */
        if (proc_get_sysroot() && !path_openat2_stays_beneath(path, false)) {
            char base[LINUX_PATH_MAX];
            if (dirfd_guest_base_path(dirfd, base, sizeof(base)) < 0)
                return -1;
            depth = path_lexical_depth(base);
            clamp = true;
        }

        int64_t ref_err = host_dirfd_ref_open(dirfd, &dir_ref);
        if (ref_err < 0) {
            errno = (ref_err == -LINUX_ENOMEM) ? ENOMEM : EBADF;
            return -1;
        }
        if (dir_ref.fd == AT_FDCWD) {
            base_fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (base_fd < 0) {
                host_fd_ref_close(&dir_ref);
                return -1;
            }
            owned_base_fd = true;
        } else {
            /* Borrowed, not owned: dir_ref holds the pin and the close at out:
             * drops it. Claiming ownership here would close the table's own
             * host fd, which every other alias of this description still uses.
             */
            base_fd = dir_ref.fd;
            owned_base_fd = false;
        }
    }

    host_fd_t current_fd = base_fd;
    bool owned_current_fd = owned_base_fd;
    const char *comp;
    size_t len;
    int rc = 0;

    /* An absolute path arrived already translated. A relative one is still
     * spelled the guest's way, and the walk below asks the volume for each
     * component by name, so inside a sysroot it needs the stored spelling, the
     * same translation path_translate_at applies. Without it this walker and
     * that one disagree, and a guest gets two answers for one path: openat
     * opens the file while openat2 reports it missing.
     *
     * Gated on containment for the reason path_translate_at is: outside the
     * sysroot the names on disk are the guest's own, and escaping one would
     * look for a file nobody wrote.
     */
    if (path[0] != '/' && casefold_active()) {
        bool in_sysroot = false;

        int recheck = path_check_relative_sysroot_containment(
            dirfd, path, PATH_TR_NOFOLLOW, &in_sysroot, NULL, 0);
        if (recheck < 0) {
            rc = -1;
            goto out;
        }

        /* A climbed path is walked with the depth clamp below; the casefold
         * walk would hand the volume the unclamped '..' spelling again, the
         * exact walk the clamp replaces. path_translate_at makes the same call
         * through its !climbed_root gate.
         */
        if (in_sysroot && recheck == 0) {
            casefold_verdict_t verdict =
                casefold_resolve_at(current_fd, "", path, false, sysroot_buf,
                                    sizeof(sysroot_buf), NULL);

            if (verdict == CASEFOLD_ERROR) {
                rc = -1;
                goto out;
            }

            /* The walk stopping at a link is the answer this function exists to
             * give: RESOLVE_NO_SYMLINKS refuses a path that passes through one,
             * so there is nothing further to spell out.
             */
            if (verdict == CASEFOLD_SYMLINK) {
                errno = ELOOP;
                rc = -1;
                goto out;
            }
            scan = sysroot_buf;
        }
    }

    /* No symlink budget here: the loop reports ELOOP at the first link rather
     * than following one, so nothing accumulates against MAXSYMLINKS, and a
     * link-free path has no component limit to enforce (path_resolution(7)).
     */
    while (path_next_component(&scan, &comp, &len)) {
        if (path_component_is_dot(comp, len))
            continue;
        if (clamp) {
            if (path_component_is_dotdot(comp, len)) {
                uint64_t popped;
                if (!path_depth_pop(depth, &popped))
                    continue; /* '..' at the guest root names the root */
                depth = popped;
            } else {
                depth++;
            }
        }

        /* Sized for the stored spelling, not the guest one: both branches above
         * leave host-spelled components in @scan, and an escape runs past
         * NAME_MAX for a name Linux still allows.
         */
        char name[CASEFOLD_STORED_NAME_MAX];
        if (path_component_copy(name, sizeof(name), comp, len) < 0) {
            rc = -1;
            goto out;
        }

        struct stat st;
        if (fstatat(current_fd, name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
            rc = -1;
            goto out;
        }
        if (S_ISLNK(st.st_mode)) {
            errno = ELOOP;
            rc = -1;
            goto out;
        }

        const char *rest = scan;
        while (*rest == '/')
            rest++;
        if (*rest == '\0')
            break;
        if (!S_ISDIR(st.st_mode)) {
            errno = ENOTDIR;
            rc = -1;
            goto out;
        }

        host_fd_t next_fd =
            openat(current_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (next_fd < 0) {
            rc = -1;
            goto out;
        }
        if (owned_current_fd)
            close(current_fd);
        current_fd = next_fd;
        owned_current_fd = true;
    }

out:
    if (owned_current_fd && current_fd >= 0)
        close(current_fd);
    host_fd_ref_close(&dir_ref);
    return rc;
}

static int proc_push_component(char *out,
                               size_t outsz,
                               size_t marks[],
                               size_t *depth,
                               const char *comp,
                               size_t len)
{
    size_t cur = strlen(out);
    size_t write_pos = cur;

    if (cur == 1 && out[0] == '/') {
        if (cur + len >= outsz)
            return -1;
        marks[*depth] = cur;
        memcpy(out + cur, comp, len);
        out[cur + len] = '\0';
        return 0;
    }

    if (cur + 1 + len >= outsz)
        return -1;

    marks[*depth] = write_pos;
    out[write_pos] = '/';
    memcpy(out + write_pos + 1, comp, len);
    out[write_pos + 1 + len] = '\0';
    return 0;
}

static int proc_apply_components(const char *path,
                                 char *out,
                                 size_t outsz,
                                 size_t marks[],
                                 size_t marks_cap,
                                 size_t *depth)
{
    const char *seg = path;
    while (*seg) {
        while (*seg == '/')
            seg++;
        if (*seg == '\0')
            break;

        const char *end = seg;
        while (*end != '\0' && *end != '/')
            end++;

        size_t len = (size_t) (end - seg);
        if (len == 1 && seg[0] == '.') {
            seg = end;
            continue;
        }
        if (len == 2 && seg[0] == '.' && seg[1] == '.') {
            uint64_t popped;
            if (path_depth_pop(*depth, &popped)) {
                *depth = popped;
                out[marks[*depth]] = '\0';
            }
            seg = end;
            continue;
        }

        /* The bound and the advance are one step: path_depth_push refuses at
         * capacity, so the marks[] write inside proc_push_component is in range
         * by postcondition rather than by a check the caller repeats. The depth
         * advances only after the write succeeds, as before.
         */
        uint64_t pushed;
        if (!path_depth_push(*depth, marks_cap, &pushed)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        if (proc_push_component(out, outsz, marks, depth, seg, len) < 0)
            return -1;
        *depth = pushed;
        seg = end;
    }
    return 0;
}

static int proc_seed_absolute_path(const char *path,
                                   char *out,
                                   size_t outsz,
                                   size_t marks[],
                                   size_t marks_cap,
                                   size_t *depth)
{
    *depth = 0;
    str_copy_trunc(out, "/", outsz);
    return proc_apply_components(path, out, outsz, marks, marks_cap, depth);
}

/* Does this O_PATH descriptor name a directory?
 *
 * The stamped path is the FD_PATH identity: a synthetic entry's host_fd is only
 * a backing placeholder, so the intercepts are asked first and the host fd is
 * consulted only for descriptors they do not serve. The open's O_NOFOLLOW
 * decides whether the descriptor refers to a symlink or to its target, exactly
 * as it does for fstat.
 *
 * Undecidable cases answer true: leaving the walk as it was is the conservative
 * outcome, whereas inventing an ENOTDIR would break a resolution that works.
 */
static bool proc_path_fd_is_dir(const fd_entry_t *snap)
{
    struct stat st;
    bool follow = !(snap->linux_flags & LINUX_O_NOFOLLOW);
    int intercepted = proc_intercept_stat_at(snap->proc_path, &st, follow);
    if (intercepted == 0)
        return S_ISDIR(st.st_mode);
    if (intercepted == PROC_NOT_INTERCEPTED && snap->host_fd >= 0 &&
        fstat(snap->host_fd, &st) == 0)
        return S_ISDIR(st.st_mode);
    return true;
}

int resolve_proc_dirfd_path(guest_fd_t dirfd,
                            const char *path,
                            char *out,
                            size_t outsz)
{
    if (dirfd == LINUX_AT_FDCWD || !path || path[0] == '/')
        return 0;

    /* FD_PATH joins FD_DIR: O_PATH directory descriptors are how systemd's
     * chase() walks a path one openat per component, and a stamped O_PATH dirfd
     * must keep resolving through the intercepts or the walk falls off the
     * synthetic tree onto its host backing (and loses the stamp for every later
     * component).
     */
    fd_entry_t snap;
    if (!fd_snapshot(dirfd, &snap) ||
        (snap.type != FD_DIR && snap.type != FD_PATH) ||
        snap.proc_path[0] == '\0')
        return 0;

    /* Linux resolves a relative name against a dirfd only when the dirfd is a
     * directory: openat() with an O_PATH descriptor on a regular file or on a
     * symlink is ENOTDIR, decided before the name is looked up. FD_DIR is a
     * directory by construction, so only FD_PATH has to be asked.
     *
     * The empty path is deliberately excluded: it is AT_EMPTY_PATH territory,
     * where the descriptor names itself rather than a child, and fstatat() on
     * an O_PATH fd of a regular file has to keep working.
     */
    if (snap.type == FD_PATH && path[0] != '\0' &&
        !proc_path_fd_is_dir(&snap)) {
        errno = ENOTDIR;
        return -1;
    }

    size_t marks[PROC_PATH_COMPONENTS_MAX];
    size_t depth;
    if (proc_seed_absolute_path(snap.proc_path, out, outsz, marks,
                                ARRAY_SIZE(marks), &depth) < 0 ||
        proc_apply_components(path, out, outsz, marks, ARRAY_SIZE(marks),
                              &depth) < 0) {
        errno = ENAMETOOLONG;
        return -1;
    }

    return 1;
}

static int resolve_proc_cwd_path(const char *path, char *out, size_t outsz)
{
    if (!path || path[0] == '\0' || path[0] == '/')
        return 0;

    proc_cwd_view_t view;
    if (proc_acquire_cwd_view(&view) < 0)
        return 0;

    /* /dev/pts and the synthetic USB trees join /proc here: all are served from
     * host directories whose contents are not what the guest names, so a
     * relative path measured against one has to be rebuilt as a guest path and
     * re-offered to the intercepts. Without the /sys and /dev/bus arms a cwd
     * set by fchdir() onto a synthetic USB directory would resolve relative
     * names straight against the scratch tree. The component walk below is
     * base-agnostic.
     */
    int rc = 0;
    if (!strncmp(view.path, "/proc", 5) || !strncmp(view.path, "/dev/pts", 8) ||
        !strncmp(view.path, "/sys", 4) || !strncmp(view.path, "/dev/bus", 8)) {
        size_t marks[PROC_PATH_COMPONENTS_MAX];
        size_t depth;
        if (proc_seed_absolute_path(view.path, out, outsz, marks,
                                    ARRAY_SIZE(marks), &depth) < 0 ||
            proc_apply_components(path, out, outsz, marks, ARRAY_SIZE(marks),
                                  &depth) < 0) {
            errno = ENAMETOOLONG;
            rc = -1;
        } else {
            rc = 1;
        }
    }

    proc_release_cwd_view(&view);
    return rc;
}

int resolve_proc_at_path(guest_fd_t dirfd,
                         const char *path,
                         char *out,
                         size_t outsz)
{
    if (!path || path[0] == '\0' || path[0] == '/')
        return 0;

    int rc = resolve_proc_dirfd_path(dirfd, path, out, outsz);
    if (rc != 0 || dirfd != LINUX_AT_FDCWD)
        return rc;

    return resolve_proc_cwd_path(path, out, outsz);
}

/* Rebase a relative path against the host directory a descriptor points at,
 * producing the guest-visible absolute spelling: F_GETPATH names where the
 * directory lives on the host, path_host_to_guest strips the sysroot, and the
 * component walk folds "." and "..".
 *
 * This exists for relative walkers (systemd's chase() opens "/", then "sys",
 * then "bus", one openat per component) stepping from a host-backed directory
 * into a synthetic subtree the host does not carry: the host openat fails
 * ENOENT even though the guest path is served by an intercept. Callers rebase
 * on that failure and re-offer the absolute path to the intercept gates.
 *
 * Returns 1 with out filled, 0 when the descriptor's path cannot be mapped (not
 * an error: the caller keeps the host result).
 */
int path_rebase_hostdirfd(int host_dirfd,
                          const char *rel,
                          char *out,
                          size_t outsz)
{
    if (!rel || rel[0] == '/' || rel[0] == '\0')
        return 0;
    char host_dir[LINUX_PATH_MAX];
    if (fcntl(host_dirfd, F_GETPATH, host_dir) < 0)
        return 0;

    /* Only a descriptor inside the sysroot has a guest spelling. With a sysroot
     * configured, path_host_to_guest passes a host path that is not under it
     * through unchanged, so a dirfd on the host's /dev -- reachable through any
     * sysroot symlink pointing out of the tree -- rebased to the guest-absolute
     * "/dev", and the retry then handed the walk to the /dev/bus/usb intercept.
     * The name the guest asked for lives outside the namespace the intercepts
     * describe, so the ENOENT the host already gave is the answer; without a
     * sysroot the guest root is the host root and every host path does have a
     * guest spelling.
     */
    char sysroot[LINUX_PATH_MAX];
    if (proc_sysroot_snapshot(sysroot, sizeof(sysroot))) {
        size_t sl = strlen(sysroot);
        if (strncmp(host_dir, sysroot, sl) != 0 ||
            (host_dir[sl] != '\0' && host_dir[sl] != '/'))
            return 0;
    }

    char guest_dir[LINUX_PATH_MAX];
    if (path_host_to_guest(host_dir, guest_dir, sizeof(guest_dir)) < 0)
        return 0;
    size_t marks[PROC_PATH_COMPONENTS_MAX];
    size_t depth;
    if (proc_seed_absolute_path(guest_dir, out, outsz, marks, ARRAY_SIZE(marks),
                                &depth) < 0 ||
        proc_apply_components(rel, out, outsz, marks, ARRAY_SIZE(marks),
                              &depth) < 0)
        return 0;
    return 1;
}

bool path_openat2_stays_beneath(const char *path, bool clamp_at_root)
{
    int depth = 0;
    const char *p = path;

    while (*p) {
        while (*p == '/')
            p++;
        if (*p == '\0')
            break;

        const char *start = p;
        while (*p && *p != '/')
            p++;
        size_t len = (size_t) (p - start);

        if (len == 1 && start[0] == '.')
            continue;
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            if (depth == 0) {
                if (!clamp_at_root)
                    return false;
            } else {
                depth--;
            }
            continue;
        }
        depth++;
    }

    return true;
}

int path_openat2_normalize_in_root(const char *path, char *out, size_t outsz)
{
    size_t depth = 0;
    size_t marks[LINUX_PATH_MAX / 2];
    size_t out_len = 0;
    const char *p = path;

    if (outsz == 0)
        return -1;
    out[0] = '\0';

    while (*p) {
        while (*p == '/')
            p++;
        if (*p == '\0')
            break;

        const char *start = p;
        while (*p && *p != '/')
            p++;
        size_t len = (size_t) (p - start);

        if (len == 1 && start[0] == '.')
            continue;
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            if (depth > 0) {
                out_len = marks[depth - 1];
                out[out_len] = '\0';
                depth--;
            }
            continue;
        }

        if (depth >= (LINUX_PATH_MAX / 2))
            return -1;

        marks[depth] = out_len;
        if (out_len != 0) {
            if (out_len + 1 >= outsz)
                return -1;
            out[out_len++] = '/';
        }
        if (out_len + len >= outsz)
            return -1;
        memcpy(out + out_len, start, len);
        out_len += len;
        out[out_len] = '\0';
        depth++;
    }

    if (out_len == 0) {
        if (outsz < 2)
            return -1;
        out[0] = '.';
        out[1] = '\0';
    }

    return 0;
}

static int path_openat2_dirfd_host_path(guest_fd_t dirfd,
                                        char *out,
                                        size_t outsz)
{
    if (dirfd == LINUX_AT_FDCWD) {
        /* getcwd into a provably non-NULL local buffer, then copy. Writing
         * straight into the caller pointer trips a false-positive leak in
         * static analyzers that model getcwd(NULL, ...) as allocating.
         */
        char cwd[LINUX_PATH_MAX];
        if (!getcwd(cwd, sizeof(cwd)))
            return -1;
        size_t n = strlen(cwd) + 1;
        if (n > outsz) {
            errno = ERANGE;
            return -1;
        }
        memcpy(out, cwd, n);
        return 0;
    }

    host_fd_ref_t dir_ref;
    int64_t ref_err = host_dirfd_ref_open(dirfd, &dir_ref);
    if (ref_err < 0) {
        errno = (ref_err == -LINUX_ENOMEM) ? ENOMEM : EBADF;
        return -1;
    }
    int rc = fcntl(dir_ref.fd, F_GETPATH, out);
    host_fd_ref_close(&dir_ref);
    return rc < 0 ? -1 : 0;
}

int path_openat2_resolved_within_root(guest_fd_t dirfd,
                                      const char *path,
                                      uint64_t oflags,
                                      bool in_root)
{
    char root_path[LINUX_PATH_MAX], joined[LINUX_PATH_MAX];
    char real_root[LINUX_PATH_MAX], real_path[LINUX_PATH_MAX];
    const char *rel = path;
    char normalized[LINUX_PATH_MAX];

    if (path_openat2_dirfd_host_path(dirfd, root_path, sizeof(root_path)) < 0)
        return -1;
    if (!realpath(root_path, real_root))
        return -1;

    if (in_root) {
        if (path_openat2_normalize_in_root(path, normalized,
                                           sizeof(normalized)) < 0) {
            errno = ENAMETOOLONG;
            return -1;
        }
        rel = normalized;
    } else if (path[0] == '/') {
        errno = EXDEV;
        return -1;
    }

    if (*rel == '\0')
        rel = ".";

    if (snprintf(joined, sizeof(joined), "%s/%s", real_root, rel) >=
        (int) sizeof(joined)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    bool follow_final = true;
    if (oflags & LINUX_O_NOFOLLOW)
        follow_final = false;
    if (oflags & LINUX_O_CREAT)
        follow_final = false;

    if (follow_final) {
        if (!realpath(joined, real_path))
            return -1;
    } else {
        char parent[LINUX_PATH_MAX];
        char *slash;

        str_copy_trunc(parent, joined, sizeof(parent));
        slash = strrchr(parent, '/');
        if (!slash)
            return -1;
        if (slash == parent) {
            parent[1] = '\0';
        } else {
            *slash = '\0';
        }
        if (!realpath(parent, real_path))
            return -1;

        size_t parent_len = strlen(real_path);
        const char *tail = (slash == parent) ? joined + 1 : slash + 1;
        if (snprintf(real_path + parent_len, sizeof(real_path) - parent_len,
                     "/%s", tail) >= (int) (sizeof(real_path) - parent_len)) {
            errno = ENAMETOOLONG;
            return -1;
        }
    }

    size_t root_len = strlen(real_root);
    if (strncmp(real_path, real_root, root_len) != 0 ||
        (real_path[root_len] != '\0' && real_path[root_len] != '/')) {
        errno = EXDEV;
        return -1;
    }

    return 0;
}

/* Mount-class taxonomy used by RESOLVE_NO_XDEV. Distinct return values mean
 * distinct logical filesystems from the guest's perspective. FUSE mounts encode
 * mount_id into the high bits so two distinct FUSE mounts compare unequal.
 */
#define PATH_MOUNT_ROOT 0
#define PATH_MOUNT_PROC 1
#define PATH_MOUNT_DEV 2
#define PATH_MOUNT_SYS 3
#define PATH_MOUNT_TMP 4
#define PATH_MOUNT_DEV_SHM 5

/* fuse_next_mount_id is a monotonic int starting at 100 (see fuse.c). The base
 * is sized well clear of any realistic mount_id so the four non-FUSE classes
 * never collide with the FUSE class numbers even after hundreds of millions of
 * mount cycles. mount_id values that ever do approach this bound would
 * represent a runtime that long outlived elfuse's intended lifetime.
 */
#define PATH_MOUNT_FUSE_BASE 0x10000000

static int classify_guest_path_mount(const char *guest_path)
{
    if (!guest_path || guest_path[0] != '/')
        return -1;

    int fuse_id = fuse_path_mount_id(guest_path);
    if (fuse_id >= 0)
        return PATH_MOUNT_FUSE_BASE + fuse_id;

    if (path_prefix_match(guest_path, "/proc", 5))
        return PATH_MOUNT_PROC;
    if (path_prefix_match(guest_path, "/tmp", 4))
        return PATH_MOUNT_TMP;
    if (path_prefix_match(guest_path, "/dev/shm", 8))
        return PATH_MOUNT_DEV_SHM;
    if (path_prefix_match(guest_path, "/dev", 4))
        return PATH_MOUNT_DEV;
    if (path_prefix_match(guest_path, "/sys", 4))
        return PATH_MOUNT_SYS;

    return PATH_MOUNT_ROOT;
}

/* Rewrite each component of an absolute host-relative path into its guest
 * spelling. A guest-created name whose spelling the volume cannot hold sits on
 * disk under its escape, so publishing the stripped remainder as-is would show
 * the guest a name it has never seen and cannot open.
 */
static int path_decode_components(const char *host_rel, char *out, size_t outsz)
{
    const char *scan = host_rel;
    const char *comp;
    size_t comp_len;
    size_t len = 0;

    while (path_next_component(&scan, &comp, &comp_len)) {
        /* Both sized for a name the volume can hand back, not for an escape.
         * CASEFOLD_HOST_NAME_MAX bounds only what elfuse writes; a literal
         * component the host already holds (a full-length CJK name, say) is
         * longer than any escape, and decoding leaves such a name unchanged so
         * the guest side needs the same room.
         */
        char host_name[CASEFOLD_STORED_NAME_MAX];
        char guest_name[CASEFOLD_STORED_NAME_MAX];

        if (path_component_copy(host_name, sizeof(host_name), comp, comp_len) <
            0)
            return -1;
        if (casefold_to_guest(host_name, guest_name, sizeof(guest_name)) < 0)
            return -1;
        if (len + 1 + strlen(guest_name) + 1 > outsz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        out[len++] = '/';
        len += (size_t) snprintf(out + len, outsz - len, "%s", guest_name);
    }
    if (len == 0) {
        if (outsz < 2) {
            errno = ENAMETOOLONG;
            return -1;
        }
        out[len++] = '/';
    }
    out[len] = '\0';
    return 0;
}

int path_host_to_guest(const char *host_path, char *out, size_t outsz)
{
    char sysroot[LINUX_PATH_MAX];
    const char *guest_path = host_path;

    if (proc_sysroot_snapshot(sysroot, sizeof(sysroot))) {
        size_t sysroot_len = strlen(sysroot);
        if (!strncmp(host_path, sysroot, sysroot_len) &&
            (host_path[sysroot_len] == '\0' || host_path[sysroot_len] == '/')) {
            guest_path = host_path + sysroot_len;
            if (*guest_path == '\0')
                guest_path = "/";

            /* Only a volume that folds case holds escaped names. On a
             * byte-exact sysroot the stored spelling is already the guest's,
             * and decoding would rename a host-staged file that merely looks
             * like an escape.
             */
            else if (casefold_active())
                return path_decode_components(guest_path, out, outsz);
        }
    }

    size_t len = str_copy_trunc(out, guest_path, outsz);
    if (len >= outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int dirfd_guest_base_path(guest_fd_t dirfd, char *out, size_t outsz)
{
    if (dirfd == LINUX_AT_FDCWD) {
        proc_cwd_view_t view;
        if (proc_acquire_cwd_view(&view) < 0) {
            errno = EBADF;
            return -1;
        }
        size_t len = str_copy_trunc(out, view.path, outsz);
        proc_release_cwd_view(&view);
        if (len >= outsz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return 0;
    }

    fd_entry_t snap;
    if (!fd_snapshot(dirfd, &snap)) {
        errno = EBADF;
        return -1;
    }
    if (snap.proc_path[0] != '\0') {
        if (snap.type != FD_DIR) {
            errno = ENOTDIR;
            return -1;
        }
        size_t len = str_copy_trunc(out, snap.proc_path, outsz);
        if (len >= outsz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return 0;
    }

    if (snap.type == FD_FUSE_DIR) {
        int rc = fuse_resolve_at_path(dirfd, ".", out, outsz);
        if (rc < 0)
            return -1;
        if (rc > 0)
            return 0;
    }

    char host_path[LINUX_PATH_MAX];
    if (path_openat2_dirfd_host_path(dirfd, host_path, sizeof(host_path)) == 0)
        return path_host_to_guest(host_path, out, outsz);

    /* fd_snapshot already proved dirfd is open, so a valid-but-wrong-type fd
     * (pipe, socket, epoll, ...) belongs here, not in the "bad fd" case: Linux
     * resolves a relative path against such a dirfd with ENOTDIR, reserving
     * EBADF for a closed or out-of-range descriptor.
     */
    if (snap.type != FD_DIR) {
        errno = ENOTDIR;
        return -1;
    }

    /* Some host-backed directory handles cannot be named back through
     * F_GETPATH. Keep a root-class fallback for those rare cases so regular
     * relative paths can still proceed.
     */
    out[0] = '/';
    out[1] = '\0';
    return 0;
}

/* Spell the absolute guest path that @path names from @dirfd's guest base path.
 * Purely lexical: no component is resolved or checked.
 */
static int dirfd_reconstruct_abs_path(guest_fd_t dirfd,
                                      const char *path,
                                      char *out,
                                      size_t outsz)
{
    char base[LINUX_PATH_MAX];
    if (dirfd_guest_base_path(dirfd, base, sizeof(base)) < 0)
        return -1;

    int n = snprintf(out, outsz, "%s/%s", base, path);
    if (n < 0 || (size_t) n >= outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int dirfd_realpath_relative(guest_fd_t dirfd,
                                   const char *path,
                                   char *out,
                                   size_t outsz)
{
    char base[LINUX_PATH_MAX];
    char joined[LINUX_PATH_MAX];

    if (path_openat2_dirfd_host_path(dirfd, base, sizeof(base)) < 0)
        return -1;
    int n = snprintf(joined, sizeof(joined), "%s/%s", base, path);
    if (n < 0 || (size_t) n >= sizeof(joined)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (!realpath(joined, out))
        return -1;
    if (strlen(out) >= outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int dirfd_symlink_chain_reaches_absolute_target(guest_fd_t dirfd,
                                                       const char *path)
{
    host_fd_ref_t ref;
    int64_t ref_err = host_dirfd_ref_open(dirfd, &ref);
    if (ref_err < 0) {
        errno = (ref_err == -LINUX_ENOMEM) ? ENOMEM : EBADF;
        return -1;
    }

    host_fd_t current_fd = ref.fd;
    bool current_owned = false;
    const char *scan = path;
    char pending[LINUX_PATH_MAX];
    const char *comp;
    size_t len;
    int symlink_count = 0;
    int rc = 0;

    while (path_next_component(&scan, &comp, &len)) {
        char name[NAME_MAX + 1];
        struct stat st;

        if (path_component_copy(name, sizeof(name), comp, len) < 0) {
            rc = -1;
            goto out;
        }
        if (!strcmp(name, "."))
            continue;
        if (!strcmp(name, "..")) {
            host_fd_t parent_fd =
                openat(current_fd, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (parent_fd < 0) {
                rc = -1;
                goto out;
            }
            if (current_owned)
                close(current_fd);
            current_fd = parent_fd;
            current_owned = true;
            continue;
        }

        if (fstatat(current_fd, name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
            rc = -1;
            goto out;
        }
        if (S_ISLNK(st.st_mode)) {
            char target[LINUX_PATH_MAX];
            ssize_t n =
                readlinkat(current_fd, name, target, sizeof(target) - 1);
            if (n < 0) {
                rc = -1;
                goto out;
            }
            if (++symlink_count > MAXSYMLINKS) {
                errno = ELOOP;
                rc = -1;
                goto out;
            }
            if (n > 0 && target[0] == '/') {
                rc = 1;
                goto out;
            }
            target[n] = '\0';

            const char *rest = scan;
            while (*rest == '/')
                rest++;
            if (path_splice_link_target(NULL, 0, target, rest, pending,
                                        sizeof(pending)) < 0) {
                rc = -1;
                goto out;
            }
            scan = pending;
            continue;
        }

        if (!S_ISDIR(st.st_mode))
            break;
        host_fd_t next_fd =
            openat(current_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (next_fd < 0) {
            rc = -1;
            goto out;
        }
        if (current_owned)
            close(current_fd);
        current_fd = next_fd;
        current_owned = true;
    }

out:
    if (current_owned)
        close(current_fd);
    host_fd_ref_close(&ref);
    return rc;
}

/* Returns 1 when the reconstruction climbed the guest root, so the caller opens
 * @host_out instead of walking from dirfd; 0 when it stays beneath; -1 with
 * errno set. @in_sysroot reports whether the sysroot claims the path; @host_out
 * is filled for a climbed or in-sysroot path, NULL to opt out.
 */
static int path_check_relative_sysroot_containment(guest_fd_t dirfd,
                                                   const char *path,
                                                   unsigned int flags,
                                                   bool *in_sysroot,
                                                   char *host_out,
                                                   size_t host_outsz)
{
    *in_sysroot = false;

    char abs_path[LINUX_PATH_MAX];
    if (dirfd_reconstruct_abs_path(dirfd, path, abs_path, sizeof(abs_path)) < 0)
        return -1;

    /* Does resolving this from dirfd leave the guest's own root? Linux clamps
     * such a path at "/", the host kernel would keep climbing, and only the
     * absolute spelling the resolver returns below reconciles the two.
     */
    bool climbed = !path_openat2_stays_beneath(abs_path, false);

    char host_buf[LINUX_PATH_MAX];
    const char *checked;

    /* CREATE outranks NOFOLLOW, exactly as in path_translate_at's absolute
     * ladder: a create decides where an absent leaf goes, which the create
     * resolver anchors in the sysroot, while the lookup resolvers fall through
     * to the host for an absent path. Testing NOFOLLOW first sends a renameat
     * destination (translated with both flags) through the lookup fallback, so
     * an in-sysroot target below an escaped directory reads as outside and the
     * caller skips the escape walk entirely. Nofollow semantics are not lost:
     * the create resolver never follows a final link either.
     */
    if (flags & PATH_TR_CREATE) {
        /* A pure containment probe must not mkdir() anything: its result is
         * discarded. A climbed resolution is the path the caller actually
         * opens, so it owes the caller's create-parents semantics, or the
         * create fails ENOENT where the absolute spelling succeeds.
         */
        bool create_parents = climbed && (flags & PATH_TR_CREATE_PARENTS) != 0;
        checked = path_resolve_sysroot_create_path(
            abs_path, host_buf, sizeof(host_buf), create_parents);
    } else if (flags & PATH_TR_NOFOLLOW) {
        checked = path_resolve_sysroot_nofollow_path(abs_path, host_buf,
                                                     sizeof(host_buf));
    } else {
        checked =
            path_resolve_sysroot_path(abs_path, host_buf, sizeof(host_buf));
    }

    char fallback_buf[LINUX_PATH_MAX];
    if (!checked && errno == ELOOP && !(flags & PATH_TR_CREATE) &&
        dirfd_symlink_chain_reaches_absolute_target(dirfd, path) > 0) {
        if (dirfd_realpath_relative(dirfd, path, fallback_buf,
                                    sizeof(fallback_buf)) == 0) {
            checked = fallback_buf;
        }
    }

    if (!checked)
        return -1;

    /* The resolver returns its own buffer for a path the sysroot claims and the
     * input pointer for one that falls through to the host, so this comparison
     * is the sysroot-or-host decision, already taken. Report it rather than
     * discard it: a relative name is measured from a descriptor and has no
     * prefix of its own to make that call from.
     */
    *in_sysroot = checked != abs_path;

    /* Handing the resolution back rather than letting a caller re-derive it
     * keeps the two flag mappings from drifting. A path that clamped at the
     * guest root needs it either way: both spellings are absolute, so the
     * descriptor drops out of the walk.
     */
    if (host_out && (*in_sysroot || climbed) &&
        str_copy_trunc(host_out, checked, host_outsz) >= host_outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return climbed ? 1 : 0;
}

static bool normalized_proc_self_fd_anchor(const char *path)
{
    if (!strncmp(path, "proc/self/fd/", 13))
        return true;
    if (strncmp(path, "proc/", 5))
        return false;

    char *endp;
    const char *pid_start = path + sizeof("proc/") - 1;
    errno = 0;
    long long pid = strtoll(pid_start, &endp, 10);
    if (endp == pid_start || errno == ERANGE ||
        pid != (long long) proc_get_pid())
        return false;
    return strncmp(endp, "/fd/", 4) == 0;
}

bool path_openat2_is_fd_magiclink_anchor(guest_fd_t dirfd, const char *path)
{
    if (!path)
        return false;

    char normalized[LINUX_PATH_MAX];

    if (path[0] == '/') {
        if (path_openat2_normalize_in_root(path, normalized,
                                           sizeof(normalized)) < 0)
            return false;
    } else {
        char base[LINUX_PATH_MAX];
        char joined[LINUX_PATH_MAX];
        if (dirfd_guest_base_path(dirfd, base, sizeof(base)) < 0)
            return false;
        if (snprintf(joined, sizeof(joined), "%s/%s", base, path) >=
            (int) sizeof(joined))
            return false;
        if (path_openat2_normalize_in_root(joined, normalized,
                                           sizeof(normalized)) < 0)
            return false;
    }

    return strncmp(normalized, "dev/fd/", 7) == 0 ||
           normalized_proc_self_fd_anchor(normalized);
}

/* Pop one trailing component from an absolute path, refusing to drop below the
 * supplied floor length. floor_len is strlen of the walk root (1 == "/" for the
 * bare-absolute case, dirfd-base length for IN_ROOT resolution). At the floor
 * the path is left unchanged, matching Linux's ".." at "/" semantics and
 * RESOLVE_IN_ROOT's clamp-at-dirfd rule.
 */
static void guest_path_pop(char *current, size_t floor_len)
{
    size_t len = strlen(current);
    if (len <= floor_len)
        return;
    char *slash = strrchr(current, '/');
    if (!slash || slash == current) {
        current[0] = '/';
        current[1] = '\0';
        return;
    }
    if ((size_t) (slash - current) < floor_len)
        return;
    *slash = '\0';
}

static int guest_path_append(char *current,
                             size_t currentsz,
                             const char *comp,
                             size_t len)
{
    size_t cur_len = strlen(current);
    bool need_slash = (cur_len == 0 || current[cur_len - 1] != '/');
    size_t want = cur_len + (need_slash ? 1 : 0) + len + 1;
    if (want > currentsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (need_slash)
        current[cur_len++] = '/';
    memcpy(current + cur_len, comp, len);
    current[cur_len + len] = '\0';
    return 0;
}

static int open_guest_walk_root_fd(guest_fd_t dirfd,
                                   bool absolute,
                                   host_fd_t *out)
{
    if (absolute) {
        char sysroot[LINUX_PATH_MAX];
        const char *root = "/";
        if (proc_sysroot_snapshot(sysroot, sizeof(sysroot)))
            root = sysroot;
        *out = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        return *out < 0 ? -1 : 0;
    }

    host_fd_ref_t dir_ref;
    int64_t ref_err = host_dirfd_ref_open(dirfd, &dir_ref);
    if (ref_err < 0) {
        errno = (ref_err == -LINUX_ENOMEM) ? ENOMEM : EBADF;
        return -1;
    }

    if (dir_ref.fd == AT_FDCWD)
        *out = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    else
        *out = dup(dir_ref.fd);
    host_fd_ref_close(&dir_ref);
    return *out < 0 ? -1 : 0;
}

static int replace_walk_fd(host_fd_t *current_fd, host_fd_t next_fd)
{
    if (next_fd < 0)
        return -1;
    if (*current_fd >= 0)
        close(*current_fd);
    *current_fd = next_fd;
    return 0;
}

static int reset_walk_fd(host_fd_t *current_fd, host_fd_t root_fd)
{
    host_fd_t next_fd = dup(root_fd);
    if (next_fd < 0)
        return -1;
    return replace_walk_fd(current_fd, next_fd);
}

/* Spell one component the way the volume stores it, for a probe measured from
 * @dirfd. A walker that asks the host for a name has to use the stored
 * spelling; the guest's own would find nothing wherever an escape applies, and
 * the walker would then report the absence rather than what is actually there.
 * Outside a sysroot, and for any name needing no escape, this is the name
 * itself.
 *
 * @is_link: -1 unknown (the caller must stat), 0 not a symlink or not there, 1
 * a symlink. Only the readdir fallback, whose listing carries no type, leaves
 * it unknown.
 */
static int host_component_spelling(host_fd_t dirfd,
                                   const char *guest,
                                   char *out,
                                   size_t outsz,
                                   int *is_link)
{
    casefold_walk_t walk;

    *is_link = -1;
    if (!casefold_active()) {
        if (str_copy_trunc(out, guest, outsz) >= outsz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return 0;
    }
    casefold_verdict_t verdict =
        casefold_resolve_at(dirfd, "", guest, false, out, outsz, &walk);
    if (verdict == CASEFOLD_ERROR)
        return -1;

    /* Any non-FOUND verdict here means not there: @guest is one component with
     * follow_final false, so CASEFOLD_SYMLINK, which the walk returns only for
     * a link it must pass through, cannot come back.
     */
    if (verdict != CASEFOLD_FOUND)
        *is_link = 0;
    else if (walk.leaf_type_known)
        *is_link = walk.leaf_is_link;
    return 0;
}

int path_openat2_crosses_mount(guest_fd_t dirfd,
                               const char *path,
                               bool in_root,
                               int *out_start_class)
{
    if (out_start_class)
        *out_start_class = -1;
    if (!path) {
        errno = EINVAL;
        return -1;
    }

    char current[LINUX_PATH_MAX];
    const char *walk = path;
    char pending[LINUX_PATH_MAX];
    host_fd_t current_fd = -1;
    host_fd_t root_fd = -1;
    host_fd_t absolute_root_fd = -1;
    bool host_walk = true;
    int symlink_count = 0;
    int rc = -1;

    /* The walk has to track every intermediate prefix because lexical
     * collapsing of ".." would erase a transient mount crossing (e.g.
     * "/proc/self/../../tmp" passes through /proc before the upward components
     * apply, and Linux NO_XDEV detects that). The start frame matches how the
     * kernel anchors resolution: absolute paths begin at "/" regardless of
     * dirfd; relative paths and RESOLVE_IN_ROOT begin at the dirfd's tracked
     * guest path.
     */
    if (path[0] == '/' && !in_root) {
        current[0] = '/';
        current[1] = '\0';
    } else if (dirfd_guest_base_path(dirfd, current, sizeof(current)) < 0) {
        goto out;
    }

    /* IN_ROOT clamps ".." at dirfd; outside IN_ROOT the walker can traverse up
     * to "/" so a transition like /proc/1 -> /proc -> / surfaces as the
     * expected cross. The floor matches whichever rule applies so the precheck
     * never out-rejects the actual resolution that follows in
     * path_openat2_normalize_in_root.
     */
    size_t floor_len = in_root ? strlen(current) : 1;

    int start_class = classify_guest_path_mount(current);
    if (start_class < 0) {
        errno = EINVAL;
        goto out;
    }
    if (out_start_class)
        *out_start_class = start_class;

    if (open_guest_walk_root_fd(dirfd, path[0] == '/' && !in_root,
                                &current_fd) < 0) {
        if (path[0] == '/' || errno != EBADF)
            goto out;
        host_walk = false;
        errno = 0;
    }
    if (host_walk) {
        root_fd = dup(current_fd);
        if (root_fd < 0)
            goto out;
        if (open_guest_walk_root_fd(LINUX_AT_FDCWD, true, &absolute_root_fd) <
            0)
            goto out;
    }

    while (*walk) {
        while (*walk == '/')
            walk++;
        if (!*walk)
            break;

        const char *comp = walk;
        while (*walk && *walk != '/')
            walk++;
        size_t len = (size_t) (walk - comp);

        if (len == 1 && comp[0] == '.')
            continue;

        /* The component's stored spelling, resolved once per component: the
         * symlink probe below and the descent that follows it both address the
         * same entry through the same descriptor, and each resolution costs a
         * host probe.
         */
        char host_name[CASEFOLD_STORED_NAME_MAX];

        if (len == 2 && comp[0] == '.' && comp[1] == '.') {
            size_t before_len = strlen(current);
            guest_path_pop(current, floor_len);
            if (host_walk && strlen(current) < before_len) {
                host_fd_t parent_fd = openat(
                    current_fd, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                if (replace_walk_fd(&current_fd, parent_fd) < 0)
                    goto out;
            }
        } else {
            char name[NAME_MAX + 1];
            char parent[LINUX_PATH_MAX];
            if (path_component_copy(name, sizeof(name), comp, len) < 0)
                goto out;
            if (str_copy_trunc(parent, current, sizeof(parent)) >=
                sizeof(parent)) {
                errno = ENAMETOOLONG;
                goto out;
            }

            int leaf_link = -1;
            if (host_walk &&
                host_component_spelling(current_fd, name, host_name,
                                        sizeof(host_name), &leaf_link) < 0)
                goto out;

            /* ENOENT still yields a verdict: nothing there can be a link. Any
             * other errno leaves link-ness undecided, and an undecided
             * component must not be walked through as a directory.
             */
            if (host_walk && leaf_link < 0) {
                struct stat st;

                if (fstatat(current_fd, host_name, &st, AT_SYMLINK_NOFOLLOW) ==
                    0)
                    leaf_link = S_ISLNK(st.st_mode) ? 1 : 0;
                else if (errno != ENOENT)
                    goto out;
                else
                    leaf_link = 0;
            }
            if (host_walk && leaf_link == 1) {
                if (guest_path_append(current, sizeof(current), comp, len) < 0)
                    goto out;

                int cls = classify_guest_path_mount(current);
                if (cls < 0) {
                    errno = EINVAL;
                    goto out;
                }
                if (cls != start_class) {
                    rc = 1;
                    goto out;
                }
                str_copy_trunc(current, parent, sizeof(current));

                char target[LINUX_PATH_MAX];
                ssize_t target_len = readlinkat(current_fd, host_name, target,
                                                sizeof(target) - 1);
                if (target_len < 0)
                    goto out;
                if (++symlink_count > MAXSYMLINKS) {
                    errno = ELOOP;
                    goto out;
                }
                target[target_len] = '\0';

                /* No prefix: an absolute target re-anchors the walk fd below,
                 * and a relative one continues from current_fd, which already
                 * names the link's directory.
                 */
                if (path_splice_link_target(NULL, 0, target, walk, pending,
                                            sizeof(pending)) < 0)
                    goto out;
                walk = pending;

                if (target[0] == '/') {
                    host_fd_t reset_fd = in_root ? root_fd : absolute_root_fd;
                    if (reset_walk_fd(&current_fd, reset_fd) < 0)
                        goto out;
                    if (in_root) {
                        if (dirfd_guest_base_path(dirfd, current,
                                                  sizeof(current)) < 0)
                            goto out;
                    } else {
                        current[0] = '/';
                        current[1] = '\0';
                    }
                }
                continue;
            }

            if (guest_path_append(current, sizeof(current), comp, len) < 0)
                goto out;
        }

        int cls = classify_guest_path_mount(current);
        if (cls < 0) {
            errno = EINVAL;
            goto out;
        }
        if (cls != start_class) {
            rc = 1;
            goto out;
        }

        const char *rest = walk;
        while (*rest == '/')
            rest++;
        if (host_walk && *rest != '\0' &&
            !(len == 2 && comp[0] == '.' && comp[1] == '.')) {
            host_fd_t next_fd = openat(current_fd, host_name,
                                       O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (replace_walk_fd(&current_fd, next_fd) < 0)
                goto out;
        }
    }

    rc = 0;

out:
    if (current_fd >= 0)
        close(current_fd);
    if (root_fd >= 0)
        close(root_fd);
    if (absolute_root_fd >= 0)
        close(absolute_root_fd);
    return rc;
}

int path_openat2_check_fd_xdev(int guest_fd, int start_class)
{
    if (start_class < 0) {
        errno = EINVAL;
        return -1;
    }

    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap)) {
        errno = EBADF;
        return -1;
    }

    /* Synthetic /dev fds (FD_URANDOM) and FUSE fds have no resolvable host
     * path, but their semantic class is fixed by the fd type; classify those
     * without F_GETPATH so a NO_XDEV resolution that intended to land outside
     * /dev or outside the originating FUSE mount catches them.
     *
     * The post-check is only meaningful for resolutions that started in the
     * root class. For PROC/DEV/SYS/TMP/DEV_SHM/FUSE the precheck's walker
     * already classified the dirfd against the right intercept, and any
     * successful open went through the intercept layer (procfs emulation backs
     * FD_REGULAR with a /tmp/elfuse-proc-XXXXXX temp file whose F_GETPATH would
     * mis-classify as /tmp). Trust the precheck in those cases and only
     * re-derive the class when the resolution started at root: that is
     * precisely the window where a symlink can escape into an intercept class
     * without the walker seeing it (a link stored under an escaped spelling is
     * invisible to a walker probing the guest spelling).
     *
     * The /proc/self/fd/N magic-link case (where snap.proc_path stamps the
     * resulting fd with a PROC label even though the real mount of the dup
     * target may be elsewhere) is closed at the precheck by rejecting magic
     * links under NO_XDEV, so this post-check does not have to second-guess
     * proc_path here.
     */
    if (start_class != PATH_MOUNT_ROOT)
        return 0;

    char guest_path[LINUX_PATH_MAX];
    int end_class;
    if (snap.proc_path[0] != '\0') {
        end_class = classify_guest_path_mount(snap.proc_path);
    } else if (snap.type == FD_URANDOM) {
        end_class = PATH_MOUNT_DEV;
    } else if (snap.type == FD_FUSE_DIR || snap.type == FD_FUSE_FILE ||
               snap.type == FD_FUSE_DEV) {
        int mnt_id;
        if (fuse_fd_mnt_id(guest_fd, &mnt_id) < 0)
            return -1;
        end_class = PATH_MOUNT_FUSE_BASE + mnt_id;
    } else if (snap.host_fd >= 0) {
        char host_path[LINUX_PATH_MAX];
        if (fcntl(snap.host_fd, F_GETPATH, host_path) < 0)
            return -1;
        if (path_host_to_guest(host_path, guest_path, sizeof(guest_path)) < 0)
            return -1;
        end_class = classify_guest_path_mount(guest_path);
    } else {
        errno = EBADF;
        return -1;
    }
    if (end_class < 0) {
        errno = EINVAL;
        return -1;
    }

    return (end_class != start_class) ? 1 : 0;
}
