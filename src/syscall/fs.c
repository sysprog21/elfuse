/*
 * Filesystem syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Stat, open, close, directory, permissions, and other filesystem operations.
 * All functions are called from syscall_dispatch() in syscall/syscall.c.
 */

#include <stdbool.h>
#include <stdatomic.h>
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

#include "proved/dirent.h"

/* dirent_record_bounds' precondition is name_len <= DIRENT64_NAME_MAX, and the
 * translation buffer below is sized from the host's NAME_MAX. proved/dirent.h
 * deliberately does not take that constant from limits.h, since the 255 it
 * states is the guest's limit; this ties the two so a host with a larger
 * NAME_MAX cannot slip a filename past the proof and overrun entry_buf.
 */
_Static_assert(NAME_MAX == DIRENT64_NAME_MAX,
               "the dirent name bound must match the proved one");

#include "core/shim-globals.h" /* shim_globals_mark_urandom_fd */

#include "runtime/procemu.h"
#include "runtime/usb-sysfs.h"

#include "syscall/linux-wire.h"
#include "syscall/asyncio.h"
#include "syscall/chown-overlay.h"
#include "syscall/fd.h" /* eventfd_dup_fd */
#include "syscall/fuse.h"
#include "syscall/fs.h"
#include "syscall/internal.h"
#include "syscall/io.h"  /* io_retry_backoff */
#include "syscall/net.h" /* absock_unregister_fd */
#include "syscall/path.h"
#include "syscall/usbdev.h"
#include "syscall/poll.h" /* epoll_dup_fd */
#include "syscall/proc.h"

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

    /* Both spellings, because procemu already serves them from one host device
     * and Linux gives them one file_operations: /dev/random keeps O_ASYNC
     * through random_fasync exactly as /dev/urandom does, and typing only one
     * of them left the other reporting the flag cleared.
     */
    if (type == FD_REGULAR && path &&
        (!strcmp(path, "/dev/urandom") || !strcmp(path, "/dev/random")))
        return FD_URANDOM;
    return type;
}

static bool same_stat_identity(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

typedef struct removed_overlay_identity {
    struct removed_overlay_identity *next;
    uint64_t dev;
    uint64_t ino;
} removed_overlay_identity_t;

static pthread_mutex_t removed_overlay_lock = PTHREAD_MUTEX_INITIALIZER;
static removed_overlay_identity_t *removed_overlay_identities;

static bool stat_identity_will_disappear(const struct stat *st)
{
    return S_ISDIR(st->st_mode) || st->st_nlink <= 1;
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

bool proc_path_is_symlink(const char *path)
{
    if (!path)
        return false;

    if (!strcmp(path, "/proc/self/exe") || !strcmp(path, "/proc/self/cwd") ||
        !strcmp(path, "/proc/self/root")) {
        return true;
    }

    if (!strncmp(path, "/proc/self/fd/", 14)) {
        char *endp;
        long n = strtol(path + 14, &endp, 10);
        if (endp != path + 14 && *endp == '\0' && n >= 0)
            return true;
    }

    if (!strncmp(path, "/proc/self/task/", 16)) {
        char *endp;
        strtol(path + 16, &endp, 10);
        if (endp != path + 16 && *endp == '/') {
            const char *sub = endp + 1;
            if (!strcmp(sub, "exe") || !strcmp(sub, "cwd") ||
                !strcmp(sub, "root")) {
                return true;
            }
            if (!strncmp(sub, "fd/", 3)) {
                long n = strtol(sub + 3, &endp, 10);
                if (endp != sub + 3 && *endp == '\0' && n >= 0)
                    return true;
            }
        }
    }

    return false;
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

    /* /dev/pts is served from a host staging directory holding one empty
     * placeholder file per live slave, which is what makes getdents64 list the
     * right names. The placeholders are names and nothing else: opening one
     * yields a 0444 regular file rather than a tty, and the openat/fstatat
     * intercepts key on an absolute path, so a descriptor opened on the
     * directory used to reach them directly. Stamping the guest spelling lets
     * resolve_proc_dirfd_path rebuild /dev/pts/N for a relative call measured
     * against this descriptor, which puts it back through the intercept that
     * opens the real slave and accounts for it.
     */
    if (!strcmp(path, "/dev/pts") || !strcmp(path, "/dev/pts/")) {
        str_copy_trunc(out, "/dev/pts", out_size);
        return true;
    }

    /* The synthetic USB trees (usb-sysfs.c) are scratch-dir backed like
     * /dev/pts, and their consumers walk them with per-component relative
     * openat (systemd chase()) and then fstatfs the result expecting
     * SYSFS_MAGIC. Both need the guest spelling on the descriptor: the former
     * so resolve_proc_dirfd_path keeps the walk on the intercepts, the latter
     * so sys_fstatfs can answer synthetically instead of leaking the /tmp
     * filesystem.
     */
    if (path_prefix_match(path, "/sys", 4) ||
        path_prefix_match(path, "/dev/bus", 8)) {
        /* Refuse a name that does not fit rather than stamp a truncated one.
         * The stamp is FD_VIRTUAL_PATH_MAX bytes and str_copy_trunc cuts
         * silently, which for a long spelling ends the stamp mid-component --
         * and every consumer then acts on that name as if it were whole: the
         * relative-walk rebase resolves off a directory the guest never named,
         * and getcwd and /proc/self/fd/N report it. No spelling the synthetic
         * tree produces reaches the cap today (the longest canonical one is 47
         * bytes for an interface attribute, and a deep hub chain adds a few),
         * so this is the guard for the day one does: an unstamped descriptor
         * loses an identity, a mis-stamped one invents a different one, and
         * sys_fstatfs already recovers the sysfs answer from the descriptor
         * itself when the stamp is absent.
         */
        if (str_copy_trunc(out, path, out_size) >= out_size)
            return false;
        return true;
    }

    if (strncmp(path, "/proc", 5) != 0)
        return false;

    char virt_buf[64];
    const char *virt = proc_virtual_dir_path(path, virt_buf, sizeof(virt_buf));
    if (!virt)
        virt = proc_stateful_file_path(path);

    if (virt) {
        str_copy_trunc(out, virt, out_size);
        return true;
    }

    /* If it has a valid /proc prefix, normalize it and record it. */
    if (path[5] == '\0' || path[5] == '/') {
        if (strncmp(path, "/proc/", 6) == 0) {
            char *endp;
            long pid = strtol(path + 6, &endp, 10);
            if (endp != path + 6 && pid == (long) proc_get_pid() &&
                (*endp == '\0' || *endp == '/')) {
                snprintf(out, out_size, "/proc/self%s", endp);
                if (proc_path_is_symlink(out))
                    return false;
                return true;
            }
        }
        if (proc_path_is_symlink(path))
            return false;
        str_copy_trunc(out, path, out_size);
        return true;
    }

    return false;
}

/* Every /proc virtual directory this loader answers for, other than
 * /proc/self/task/<tid> below, which needs numeric parsing instead of a literal
 * match.
 */
static const char *const PROC_VIRTUAL_DIRS[] = {
    "/proc",         "/proc/self",        "/proc/net",
    "/proc/self/fd", "/proc/self/fdinfo", "/proc/self/task",
};

static const char *proc_virtual_dir_path(const char *path,
                                         char *buf,
                                         size_t bufsz)
{
    if (!path || strncmp(path, "/proc", 5) != 0)
        return NULL;

    /* "/proc/<mypid>/..." names the same things as "/proc/self/...": rewrite
     * the prefix up front so the table below only has to know the "self"
     * spelling once instead of duplicating every entry for the numeric-pid one.
     * A pid that fails to parse (not "/proc/<digits>...", including
     * "/proc/self...") leaves lookup at the original path untouched, since
     * strtol's endp stops at the first non-digit and never advances past
     * "/proc/" for a non-numeric next component.
     */
    char normalized[64];
    const char *lookup = path;
    if (!strncmp(path, "/proc/", 6)) {
        char *endp;
        long pid = strtol(path + 6, &endp, 10);
        if (endp != path + 6 && pid == (long) proc_get_pid()) {
            int n =
                snprintf(normalized, sizeof(normalized), "/proc/self%s", endp);

            /* A truncated rewrite must not be used as a lookup key: it would
             * silently match a different, shorter virtual path than the one
             * actually requested. Fall through with the untranslated pid
             * spelling instead, which the table below simply will not match.
             */
            if (n >= 0 && (size_t) n < sizeof(normalized))
                lookup = normalized;
        }
    }

    /* Tolerate exactly one trailing slash, same as the literal-match chain this
     * replaced; a table of full canonical paths only has to list one spelling
     * per entry this way.
     */
    char stripped[64];
    size_t len = strlen(lookup);
    if (len > 1 && lookup[len - 1] == '/' && len < sizeof(stripped)) {
        memcpy(stripped, lookup, len - 1);
        stripped[len - 1] = '\0';
        lookup = stripped;
    }

    for (size_t i = 0; i < ARRAY_SIZE(PROC_VIRTUAL_DIRS); i++)
        if (!strcmp(lookup, PROC_VIRTUAL_DIRS[i]))
            return PROC_VIRTUAL_DIRS[i];

    if (!strncmp(lookup, "/proc/self/task/", 16)) {
        char *endp;
        long tid = strtol(lookup + 16, &endp, 10);
        if (endp != lookup + 16 && tid > 0 && *endp == '\0') {
            snprintf(buf, bufsz, "/proc/self/task/%ld", tid);
            return buf;
        }
    }

    return NULL;
}

/* One entry read out of a union directory's backing, held after that
 * directory's stream has been closed. The name is the host spelling, not yet
 * put through path_translate_dirent_name: translation depends on the backing's
 * escape policy, which is recorded once per drain, and a host name may be
 * longer than Linux NAME_MAX -- the emit path is where that is already
 * diagnosed, and keeping it there keeps one copy of the rule.
 */
typedef struct {
    uint64_t ino;
    unsigned char type;
    char name[]; /* NUL-terminated */
} backing_name_t;

/* Reference-counted wrapper around a directory stream. See the declaration in
 * syscall/internal.h for why this exists: a raw DIR* stored in fd_table[fd].dir
 * would let a sibling close()/dup2()/fork-restore free it via closedir() while
 * sys_getdents64() is still mid-loop reading it. The struct itself is private
 * to this file; every other module only ever sees the opaque void* that
 * fd_table[].dir already stores.
 */
typedef struct {
    DIR *dir;

    /* The tail of the listing for a synthetic directory that must extend its
     * backing rather than replace it (see usb_sysfs_dir_unions_backing): the
     * names of the host/sysroot directory that backs the same guest name, read
     * out of it in one pass and held here as data.
     *
     * Names rather than a second open stream, because a stream would be a
     * second host descriptor charged to one guest fd for as long as the fd
     * lives, and elfuse sizes its host budget as one descriptor per guest fd
     * (FD_TABLE_SIZE + HOST_FD_RESERVE, src/elfuse-limits.h). The backing
     * stream is opened and closed inside the single getdents64 call that first
     * needs it -- see dir_backing_drain -- so the extra descriptor is transient
     * and never spans a return to the guest.
     *
     * Filled lazily, when the primary stream runs out, so a directory that is
     * never read to the end never pays for it and a directory that has no
     * backing never opens one. Guarded by `lock` along with the walk itself.
     */
    backing_name_t **backing; /* NULL until the drain has run */
    size_t backing_count;
    size_t backing_pos;   /* how much of `backing` the walk has emitted */
    bool backing_drained; /* the one-shot drain has run; do not retry */
    bool backing_private; /* this stream may not read a backing of its own:
                           * another stream on the same open file description
                           * owns the backing half of this listing. Set only on
                           * the stream a forked child builds over an inherited
                           * descriptor -- see dir_stream_open_inherited. It
                           * stops the drain and nothing else; the primary walk
                           * runs exactly as it does on any other stream,
                           * because the primary position IS shared through the
                           * description and splitting it is the one part of
                           * Linux's answer this can give.
                           */
    bool backing_escapes; /* path_dirent_dir_holds_escapes for the backing,
                           * recorded while its descriptor still existed
                           */
    int listing_errno;    /* non-zero when this listing is incomplete and can
                           * never be completed. Sticky: set once and never
                           * cleared, because the stream has lost names it can
                           * no longer produce. sys_getdents64 reads it at the
                           * top of every call and returns it, so the failure
                           * outlives the call that hit it instead of being
                           * swallowed by that call's partial return.
                           *
                           * Set from either half of the walk. The drain sets it
                           * when the backing could not be read; the primary
                           * walk sets it when readdir() on the synthetic stream
                           * fails. Both are the same defect from the guest's
                           * side -- names that exist and were not delivered --
                           * so they answer through one field and one delivery
                           * point rather than one being reported and the other
                           * spelled as an end of directory.
                           */

    size_t primary_seen; /* Entries readdir() has returned from the synthetic
                          * stream over this stream's whole life. Only the
                          * fault hook reads it (see dir_primary_fault_after);
                          * the walk itself needs no count, because the primary
                          * side keeps its position in the DIR* rather than in
                          * an index. Guarded by `lock` with the walk.
                          */

    pthread_mutex_t lock; /* Serializes the telldir/readdir/seekdir walk in
                           * sys_getdents64. The refcount below only pins the
                           * wrapper's lifetime; two guest threads issuing
                           * getdents64 on the same fd would otherwise
                           * interleave their walks on the shared DIR* and see
                           * an undefined entry split (Linux serializes
                           * getdents64 through the struct file's f_pos_lock).
                           * Only ever taken by reference holders, so it is
                           * never destroyed while held.
                           */
    int refcount;         /* Guarded by fd_lock. Starts at 1 (the fd-table's
                           * own reference), gains one per guest fd that dup'd
                           * its way onto the same open file description, and
                           * one per in-flight sys_getdents64 that pinned it via
                           * dir_stream_acquire(). Freed only when the count
                           * reaches zero.
                           */
} dir_stream_t;

/* Release the drained backing names. Safe on a stream that never drained one.
 */
static void dir_backing_free(dir_stream_t *ds)
{
    for (size_t i = 0; i < ds->backing_count; i++)
        free(ds->backing[i]);
    free((void *) ds->backing);
    ds->backing = NULL;
    ds->backing_count = 0;
    ds->backing_pos = 0;
}

/* Open a stream over host_fd and take ownership of the descriptor.
 *
 * Returns NULL with errno set on failure, in which case host_fd is untouched
 * and still the caller's to close. The wrapper is allocated before fdopendir
 * for exactly that reason: once fdopendir succeeds the descriptor is inside the
 * DIR* and nothing short of closedir() -- which closes it -- gets it back, so
 * there must be no failure left after that point.
 */
static dir_stream_t *dir_stream_new(int host_fd)
{
    dir_stream_t *ds = malloc(sizeof(*ds));
    if (!ds) {
        errno = ENOMEM;
        return NULL;
    }

    /* Darwin's fdopendir sets FD_CLOEXEC on the descriptor it adopts. That was
     * invisible while the stream ran on a private duplicate; on the guest's own
     * descriptor it silently flips a flag elfuse never asked for, so the flag
     * is read before the call and put back after.
     *
     * Only the bit fdopendir added is taken back, which is why the before value
     * is needed rather than an unconditional clear: an open the guest made with
     * O_CLOEXEC reaches the host open as O_CLOEXEC too (translate_open_flags),
     * and that descriptor is meant to carry the flag. When the flag cannot be
     * read the descriptor is left as fdopendir set it, since clearing on a
     * guess is the direction that loses information.
     */
    int flags_before = fcntl(host_fd, F_GETFD);

    DIR *dir = fdopendir(host_fd);
    if (!dir) {
        int saved_errno = errno;
        free(ds);
        errno = saved_errno;
        return NULL;
    }

    if (flags_before >= 0 && !(flags_before & FD_CLOEXEC)) {
        int flags_after = fcntl(host_fd, F_GETFD);
        if (flags_after >= 0 && (flags_after & FD_CLOEXEC))
            fcntl(host_fd, F_SETFD, flags_after & ~FD_CLOEXEC);
    }

    ds->dir = dir;
    ds->backing = NULL;
    ds->backing_count = 0;
    ds->backing_pos = 0;
    ds->backing_drained = false;
    ds->backing_private = false;
    ds->backing_escapes = false;
    ds->listing_errno = 0;
    ds->primary_seen = 0;
    pthread_mutex_init(&ds->lock, NULL);
    ds->refcount = 1;
    return ds;
}

void *dir_stream_open(int host_fd)
{
    return dir_stream_new(host_fd);
}

/* A stream for an inherited descriptor: the same wrapper, forbidden to read a
 * backing of its own. See internal.h for which half of the listing the child
 * shares with its parent and which half it must leave alone.
 *
 * Only the backing half is suppressed. The primary is read normally, because
 * the primary lives in the shared open file description and reading it is what
 * splits the listing between the two processes instead of losing part of it.
 */
void *dir_stream_open_inherited(int host_fd)
{
    dir_stream_t *ds = dir_stream_new(host_fd);
    if (ds)
        ds->backing_private = true;
    return ds;
}

/* Take an extra reference. Caller holds fd_lock. */
void dir_stream_ref_locked(void *ds_ptr)
{
    dir_stream_t *ds = ds_ptr;
    if (ds)
        ds->refcount++;
}

/* Tear down a wrapper that was never published to fd_table (an allocation or
 * install failure between dir_stream_open() and the point the pointer would
 * have been written to fd_table[].dir). No other thread can have acquired a
 * reference yet, so this always closes and frees unconditionally -- including
 * the host descriptor the stream owns, which the caller must therefore not
 * close again.
 */
static void dir_stream_discard(void *ds_ptr)
{
    dir_stream_t *ds = ds_ptr;
    dir_backing_free(ds);
    closedir(ds->dir);
    pthread_mutex_destroy(&ds->lock);
    free(ds);
}

/* Pin fd's directory stream against a concurrent close()/dup2() so
 * sys_getdents64 can safely walk it, and stamp the walk with the guest path
 * that slot carried at the moment it was pinned.
 *
 * The stamp is copied out here, under the same fd_lock that proved the slot is
 * this stream's, because it is the only moment at which the fd number and the
 * stream are known to belong together. Everything the walk needs to know about
 * the descriptor's identity therefore travels with the pinned stream instead of
 * being re-read from fd_table[fd] later: a sibling's close()+open() can put a
 * different file behind that number while this walk still holds the original
 * stream, and a re-read would then drain some other directory's backing into it
 * -- or, when the number is merely closed, find no stamp at all and end the
 * union listing early with the backing half silently missing and success
 * reported.
 *
 * @proc_path_out receives that stamp, empty when the slot carried none.
 *
 * Returns the pinned wrapper, or NULL if fd is not (or no longer) an open
 * FD_DIR. Balance every non-NULL return with dir_stream_release().
 */
static dir_stream_t *dir_stream_acquire(int fd,
                                        char *proc_path_out,
                                        size_t proc_path_sz)
{
    proc_path_out[0] = '\0';
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
        return NULL;
    pthread_mutex_lock(&fd_lock);
    dir_stream_t *ds = NULL;
    if (fd_table[fd].type == FD_DIR) {
        ds = (dir_stream_t *) fd_table[fd].dir;
        if (ds) {
            ds->refcount++;
            str_copy_trunc(proc_path_out, fd_table[fd].proc_path, proc_path_sz);
        }
    }
    pthread_mutex_unlock(&fd_lock);
    return ds;
}

/* Drop a reference taken by dir_stream_acquire(), by an fd_lifetime pin, or the
 * fd-table's own reference from fd_cleanup_entry(). No-op when passed NULL. The
 * decrement happens under fd_lock; the actual closedir()/free() runs after
 * releasing it, matching fd_cleanup_entry's own "do not hold fd_lock across
 * slow syscalls" convention.
 *
 * The closedir() here is what closes the guest fd's host descriptor, so this is
 * the single point where a directory fd is given back to the host.
 */
void dir_stream_release(void *ds_ptr)
{
    dir_stream_t *ds = ds_ptr;
    if (!ds)
        return;
    pthread_mutex_lock(&fd_lock);
    bool last = --ds->refcount == 0;
    pthread_mutex_unlock(&fd_lock);
    if (last) {
        dir_backing_free(ds);
        closedir(ds->dir);
        pthread_mutex_destroy(&ds->lock);
        free(ds);
    }
}

/* spec is the description this fd inherits from, or NULL for a fresh one. Only
 * the magic-link open passes one: it implements the open as a dup, so the host
 * flags are shared with the source and must not be probed or changed.
 *
 * Takes ownership of host_fd unconditionally: every failure path below closes
 * it, so callers hand the descriptor over and never close it themselves. A
 * directory makes that mandatory rather than merely tidy -- its stream adopts
 * the same descriptor (see dir_stream_open) and from then on only the stream
 * can give it back.
 */
static int fd_alloc_opened_host(int host_fd,
                                int type,
                                int linux_flags,
                                int min_guest_fd,
                                void (*cleanup)(int),
                                const char *virtual_path,
                                const fd_alias_spec_t *spec)
{
    dir_stream_t *ds = NULL;

    if (type == FD_DIR) {
        ds = dir_stream_open(host_fd);
        if (!ds) {
            proc_pty_forget_host_fd(host_fd);
            close_keep_errno(host_fd);
            return -1;
        }
    }

    /* A directory publishes its stream in the same fd_lock window as the slot,
     * so the slot is never visible as FD_DIR with a NULL dir while this call is
     * still holding the only reference. Sharing one descriptor is what forces
     * that: in the gap, a sibling's close would find a directory slot whose
     * descriptor looks plain, close it, and leave this side's stream sitting on
     * a number the next open can claim. The other types keep the relaxed
     * allocator and install their metadata below.
     */
    int minfd = min_guest_fd >= 0 ? min_guest_fd : 0;
    uint64_t alloc_gen = 0;
    int guest_fd = ds ? fd_alloc_alias_dir(spec, -1, minfd, type, host_fd,
                                           cleanup, ds, linux_flags, &alloc_gen)
                      : fd_alloc_alias_relaxed(spec, -1, minfd, type, host_fd,
                                               cleanup, &alloc_gen);
    if (guest_fd < 0) {
        int saved_errno = errno;
        proc_pty_forget_host_fd(host_fd);
        if (ds)
            dir_stream_discard(ds); /* closes host_fd */
        else
            close(host_fd);
        errno = saved_errno;
        return -1;
    }

    /* Resolve the virtual-path stamp before taking fd_lock; the helper is pure
     * string work and must not run inside the critical section.
     */
    char proc_path_buf[FD_VIRTUAL_PATH_MAX];
    bool have_proc_path = resolve_virtual_path(virtual_path, proc_path_buf,
                                               sizeof(proc_path_buf));

    /* Publish linux_flags, proc_path, and the urandom bitmap bit atomically
     * with respect to the slot's identity. The allocator drops fd_lock before
     * returning, so a sibling vCPU's pathological close(guest_fd) + open()
     * could reuse the slot between alloc and the metadata install below.
     * Re-acquire fd_lock and verify the generation stamped at alloc still
     * matches; if it does not, the slot belongs to a different file now and any
     * install would clobber the sibling's entry. A (type, host_fd) tuple alone
     * cannot tell a close+reopen that landed on the same number, so it stays
     * only as the cheap early-out.
     *
     * Nothing is left to unwind on that path: the sibling's close ran
     * fd_cleanup_entry over this side's slot, which released the stream (and
     * with it the descriptor) exactly once, because the stream was published
     * with the slot rather than installed here.
     */
    pthread_mutex_lock(&fd_lock);
    if (fd_table[guest_fd].type == type &&
        fd_table[guest_fd].host_fd == host_fd &&
        fd_table[guest_fd].generation == alloc_gen) {
        fd_table[guest_fd].linux_flags = linux_flags;
        if (have_proc_path)
            memcpy(fd_table[guest_fd].proc_path, proc_path_buf,
                   sizeof(proc_path_buf));

        /* An alias already carries the description's answer, and the path would
         * describe the magic link rather than the file behind it:
         * /proc/self/fd/N is a per-process procfs name whatever it points at.
         */
        if (!spec)
            fd_table[guest_fd].path_poll_capable =
                path_intercept_poll_capable(virtual_path);
        bool readable_urandom =
            type == FD_URANDOM &&
            (linux_flags & LINUX_O_ACCMODE) != LINUX_O_WRONLY;
        shim_globals_mark_urandom_fd(guest_fd, readable_urandom);
    }
    pthread_mutex_unlock(&fd_lock);

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

/* open/close. */


/* openat, without parking the vCPU thread in a host call no teardown wake
 * reaches. A write-only open of a FIFO with no reader blocks until one arrives;
 * O_NONBLOCK reports that state as ENXIO instead, which is unambiguous (no
 * other file type produces it here), so poll for the reader and restore the
 * blocking flag once the open succeeds. The guest-visible result is the same.
 *
 * The read-only side keeps the blocking open, which is a known teardown hazard
 * rather than an oversight: a thread parked in it is reachable by no teardown
 * wake, so an execve de_thread running concurrently counts it as a thread that
 * would not leave and takes its fatal path. It cannot be emulated the same way
 * as the write side: an O_RDONLY | O_NONBLOCK open of a FIFO succeeds
 * immediately whether or not a writer exists, and macOS poll() reports revents
 * == 0 on the read end in every state (measured), so there is nothing to wait
 * on that would reproduce "return once a writer arrives". Lifting it needs the
 * open to run on a thread that owns no vCPU.
 */
static int open_nonblocking_writer(int dirfd,
                                   const char *path,
                                   int flags,
                                   mode_t mode)
{
    bool guest_wants_nonblock = (flags & O_NONBLOCK) != 0;
    bool may_block_for_reader =
        !guest_wants_nonblock && (flags & O_ACCMODE) == O_WRONLY;

    if (!may_block_for_reader) {
        return (dirfd == AT_FDCWD) ? open(path, flags, mode)
                                   : openat(dirfd, path, flags, mode);
    }

    unsigned backoff = 0;
    for (;;) {
        int fd = (dirfd == AT_FDCWD)
                     ? open(path, flags | O_NONBLOCK, mode)
                     : openat(dirfd, path, flags | O_NONBLOCK, mode);
        if (fd >= 0) {
            /* Restore the blocking mode the guest asked for. Nothing observed
             * the O_NONBLOCK window: no guest-visible I/O has run on this fd.
             */
            if (fd_update_status_flag(fd, O_NONBLOCK, false) < 0) {
                /* The guest asked for a blocking fd; handing it a non-blocking
                 * one would surface as spurious EAGAIN later.
                 */
                close_keep_errno(fd);
                return -1;
            }
            return fd;
        }
        if (errno != ENXIO)
            return -1;

        /* ENXIO also means "special file, no device configured", which is
         * permanent: retrying it would spin forever. Only a FIFO can become
         * openable later, when a reader arrives.
         */
        struct stat st;
        int strc = (dirfd == AT_FDCWD) ? stat(path, &st)
                                       : fstatat(dirfd, path, &st, 0);
        if (strc != 0 || !S_ISFIFO(st.st_mode)) {
            errno = ENXIO;
            return -1;
        }

        if (io_retry_backoff(&backoff) < 0) {
            errno = EINTR;
            return -1;
        }
    }
}

int64_t sys_openat_path(guest_t *g,
                        int dirfd,
                        const char *pathp,
                        int linux_flags,
                        int mode)
{
    /* Linux rejects O_DIRECTORY|O_CREAT while it is still building the open
     * flags, before the path is resolved and before the dirfd is validated:
     * EINVAL for a name that exists, one that does not, a directory, and a bad
     * dirfd alike (measured on 6.19; macOS open(2) agrees, so host-backed names
     * already answered this and only the intercepts did not). Deciding it here
     * rather than inside each intercept keeps the one answer in the one place
     * the kernel decides it, and stops a synthetic directory from reporting
     * EISDIR for a request the kernel never got far enough to look at.
     *
     * O_PATH does not reach that test at all: the same function first masks
     * the flags down to O_DIRECTORY|O_NOFOLLOW|O_PATH, so the creation bit is
     * gone before the pair is looked at and O_PATH|O_DIRECTORY|O_CREAT opens
     * the directory and hands back a descriptor, behaving exactly like
     * O_PATH|O_DIRECTORY on a present name, an absent one and a regular file
     * alike (measured). Dropping the bit here rather than only skipping the
     * test is what makes the rest of the path agree: left set, it reads as
     * write intent, and the read-only sysfs gate answered EISDIR for a
     * descriptor the kernel hands out.
     */
    if (linux_flags & LINUX_O_PATH)
        linux_flags &= ~LINUX_O_CREAT;

    if ((linux_flags & (LINUX_O_DIRECTORY | LINUX_O_CREAT)) ==
        (LINUX_O_DIRECTORY | LINUX_O_CREAT))
        return -LINUX_EINVAL;

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
        int host_fd =
            open_nonblocking_writer(AT_FDCWD, tx.host_path, flags, mode);
        if (host_fd < 0)
            return linux_errno();

        int type = opened_fd_type(host_fd, linux_flags);
        if (type < 0) {
            close_keep_errno(host_fd);
            return linux_errno();
        }
        int guest_fd = fd_alloc_opened_host(host_fd, type, linux_flags, -1,
                                            NULL, NULL, NULL);
        if (guest_fd < 0)
            return linux_errno();
        return guest_fd;
    }

    /* Intercept /proc and /dev paths before touching the host filesystem */
    if (path_might_use_open_intercept(tx.intercept_path)) {
        if (!strcmp(tx.intercept_path, "/dev/fuse"))
            return fuse_proc_open(linux_flags);

        /* /dev/bus/usb/BBB/DDD: typed FD_USBDEV constructor (any access mode
         * except O_PATH, which the stage-1 placeholder serves).
         */
        int64_t usb_fd = usbdev_open_path(tx.intercept_path, linux_flags);
        if (usb_fd != INT64_MIN)
            return usb_fd;
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
                proc_pty_forget_host_fd(intercepted);
                close_keep_errno(intercepted);
                return linux_errno();
            }
            int min_guest_fd =
                (!strncmp(tx.intercept_path, "/dev/", 5)) ? -1 : 128;

            /* An fd magic link (/dev/stdin, /dev/fd/N, /proc/self/fd/N) is
             * served by dup'ing a descriptor this process already holds, so the
             * new slot aliases an open file description that already exists.
             * Say so, or the allocator probes it: taking O_NONBLOCK ownership
             * of the launcher's terminal leaves it nonblocking after elfuse
             * exits, and re-probing a description elfuse already owns would
             * answer the same thing twice.
             */
            fd_entry_t alias_src;
            fd_alias_spec_t spec = {0};
            int alias_fd = path_fd_magiclink_guest_fd(tx.intercept_path);
            bool aliased = alias_fd >= 0 && fd_snapshot(alias_fd, &alias_src);
            if (aliased) {
                /* Ownership yes, identity no. Linux gives an opened magic link
                 * its own open file description with its own status flags, so
                 * this must not join the source's alias set: an F_SETFL on
                 * /proc/self/fd/0 would otherwise sweep onto fd 0. elfuse
                 * implements the open as a dup, so the host flags really are
                 * shared and the description really is foreign, which is
                 * exactly what fd_alias_host_shared claims and no more.
                 */
                spec = fd_alias_host_shared(&alias_src);
            }

            /* The virtual-path stamp follows the same dup: opening a magic link
             * reopens the underlying file, so the new descriptor must inherit
             * the target fd's stamped identity, not the literal magic-link
             * spelling. fstatfs on a reopened /sys directory has to keep
             * answering SYSFS_MAGIC (systemd's sd-device reopens every chased
             * syspath this way and gates on it), and a reopened regular file
             * must not masquerade as procfs -- so a magic link whose target
             * carries no virtual identity stamps nothing at all.
             */
            const char *stamp = tx.intercept_path;

            /* Under /sys the request and the result can name different objects:
             * opening <dev>/subsystem without O_NOFOLLOW hands back the
             * directory the link resolves to, and Linux's fd then reports that
             * directory -- /proc/self/fd/N names it, and openat(fd, "..") pops
             * *its* parent. Stamping the guest's spelling made every relative
             * walk off such a descriptor restart from the link's own directory
             * instead. Ask the descriptor what it holds; it names the link
             * itself for the O_PATH|O_NOFOLLOW open that asked for the link,
             * and the target for every open that followed one.
             */
            char sys_stamp[LINUX_PATH_MAX];
            if (usb_sysfs_guest_path_for_fd(intercepted, sys_stamp,
                                            sizeof(sys_stamp)) > 0)
                stamp = sys_stamp;

            if (alias_fd >= 0)
                stamp = (aliased && alias_src.proc_path[0] != '\0')
                            ? alias_src.proc_path
                            : NULL;
            int guest_fd = fd_alloc_opened_host(
                intercepted, type, linux_flags, min_guest_fd,
                fd_cleanup_for_type(type), stamp, aliased ? &spec : NULL);
            if (guest_fd < 0)
                return linux_errno();
            return guest_fd;
        }
        if (intercepted == -1) {
            /* Intercept matched but failed */
            return linux_errno();
        }
        /* intercepted == PROC_NOT_INTERCEPTED: fall through to real openat */
    }

    if (dirfd == LINUX_AT_FDCWD) {
        int host_fd =
            open_nonblocking_writer(AT_FDCWD, tx.host_path, flags, mode);
        if (host_fd < 0)
            return linux_errno();

        int type = opened_fd_type(host_fd, linux_flags);
        if (type < 0) {
            close_keep_errno(host_fd);
            return linux_errno();
        }
        int guest_fd = fd_alloc_opened_host(host_fd, type, linux_flags, -1,
                                            NULL, NULL, NULL);
        if (guest_fd < 0)
            return linux_errno();
        return guest_fd;
    }

    host_fd_ref_t dir_ref;
    int64_t ref_err = host_dirfd_ref_open(dirfd, &dir_ref);
    if (ref_err < 0)
        return ref_err;

    int host_fd =
        open_nonblocking_writer(dir_ref.fd, tx.host_path, flags, mode);
    if (host_fd < 0 && errno == ENOENT) {
        /* Relative walkers (systemd chase() opens one component per openat)
         * step from host-backed directories into synthetic subtrees the host
         * does not carry -- openat(<sysroot>/sys fd, "bus") is ENOENT on the
         * host while /sys/bus is served by an intercept. Rebase the relative
         * path to its guest-absolute spelling and, only when that spelling is
         * gated for interception, retry through the normal absolute-path flow.
         * Host semantics for everything else are unchanged: the fallback runs
         * only after a host ENOENT.
         */
        char rebased[LINUX_PATH_MAX];
        if (path_rebase_hostdirfd(dir_ref.fd, tx.host_path, rebased,
                                  sizeof(rebased)) > 0 &&
            path_might_use_open_intercept(rebased)) {
            host_fd_ref_close(&dir_ref);
            return sys_openat_path(g, LINUX_AT_FDCWD, rebased, linux_flags,
                                   mode);
        }
        errno = ENOENT;
    }
    host_fd_ref_close(&dir_ref);
    if (host_fd < 0)
        return linux_errno();

    int type = opened_fd_type(host_fd, linux_flags);
    if (type < 0) {
        close_keep_errno(host_fd);
        return linux_errno();
    }
    int guest_fd =
        fd_alloc_opened_host(host_fd, type, linux_flags, -1, NULL, NULL, NULL);
    if (guest_fd < 0)
        return linux_errno();
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

static bool stat_identity_has_open_fd(const struct stat *target)
{
    bool found = false;

    pthread_mutex_lock(&fd_lock);
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (fd_table[i].type == FD_CLOSED)
            continue;

        struct stat candidate;
        if (fstat(fd_table[i].host_fd, &candidate) == 0 &&
            same_stat_identity(target, &candidate)) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&fd_lock);

    return found;
}

static bool removed_overlay_identity_contains(const struct stat *st)
{
    bool found = false;
    uint64_t dev = (uint64_t) st->st_dev;
    uint64_t ino = (uint64_t) st->st_ino;

    pthread_mutex_lock(&removed_overlay_lock);
    for (removed_overlay_identity_t *e = removed_overlay_identities; e;
         e = e->next) {
        if (e->dev == dev && e->ino == ino) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&removed_overlay_lock);

    return found;
}

static void removed_overlay_identity_remove(const struct stat *st)
{
    uint64_t dev = (uint64_t) st->st_dev;
    uint64_t ino = (uint64_t) st->st_ino;

    pthread_mutex_lock(&removed_overlay_lock);
    removed_overlay_identity_t **prev = &removed_overlay_identities;
    for (removed_overlay_identity_t *e = *prev; e;
         prev = &e->next, e = e->next) {
        if (e->dev == dev && e->ino == ino) {
            *prev = e->next;
            free(e);
            break;
        }
    }
    pthread_mutex_unlock(&removed_overlay_lock);
}

static void removed_overlay_identity_add(const struct stat *st)
{
    uint64_t dev = (uint64_t) st->st_dev;
    uint64_t ino = (uint64_t) st->st_ino;

    pthread_mutex_lock(&removed_overlay_lock);
    for (removed_overlay_identity_t *e = removed_overlay_identities; e;
         e = e->next) {
        if (e->dev == dev && e->ino == ino) {
            pthread_mutex_unlock(&removed_overlay_lock);
            return;
        }
    }

    removed_overlay_identity_t *e = calloc(1, sizeof(*e));
    if (e) {
        e->dev = dev;
        e->ino = ino;
        e->next = removed_overlay_identities;
        removed_overlay_identities = e;
    }
    pthread_mutex_unlock(&removed_overlay_lock);
}

static void chown_overlay_clear_removed_identity(const struct stat *st)
{
    if (stat_identity_has_open_fd(st)) {
        removed_overlay_identity_add(st);
        if (!stat_identity_has_open_fd(st)) {
            removed_overlay_identity_remove(st);
            chown_overlay_clear((uint64_t) st->st_dev, (uint64_t) st->st_ino);
        }
        return;
    }

    chown_overlay_clear((uint64_t) st->st_dev, (uint64_t) st->st_ino);
}

static void chown_overlay_clear_closed_unlinked_fd(int host_fd)
{
    struct stat st;
    if (fstat(host_fd, &st) < 0)
        return;

    if (st.st_nlink == 0 && !stat_identity_has_open_fd(&st)) {
        removed_overlay_identity_remove(&st);
        chown_overlay_clear((uint64_t) st.st_dev, (uint64_t) st.st_ino);
        return;
    }

    if (removed_overlay_identity_contains(&st) &&
        !stat_identity_has_open_fd(&st)) {
        removed_overlay_identity_remove(&st);
        chown_overlay_clear((uint64_t) st.st_dev, (uint64_t) st.st_ino);
    }
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
         * host_fd that the slow path drops must be drained here too. A no-op
         * for anything that is not a pty, and a pty slave is an ordinary
         * FD_REGULAR slot, so every guest close of one lands here.
         */
        proc_pty_forget_host_fd(host_fd);
        chown_overlay_clear_closed_unlinked_fd(host_fd);
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

    chown_overlay_clear_closed_unlinked_fd(snap.host_fd);
    fd_cleanup_entry(fd, &snap);
    return 0;
}

/* dup/fcntl. */

/* Install dup-alias metadata atomically with the slot identity. Uses the (type,
 * host_fd) tuple as proof that the slot still belongs to the in-flight
 * duplicate_guest_fd call; a sibling vCPU's pathological close + open between
 * the relaxed allocator's lock release and this call could otherwise clobber
 * the sibling's freshly-installed entry.
 *
 * The directory stream is not among the fields installed here: it is published
 * by the allocator, in the window that creates the slot, because it owns the
 * slot's host descriptor and a gap would leave that descriptor looking
 * ownerless to a concurrent close.
 *
 * Returns true on successful install, false if the slot was reallocated, which
 * leaves this side owning nothing.
 */
static bool install_fd_alias_metadata_atomic(int dst_fd,
                                             int expected_type,
                                             int expected_host_fd,
                                             const fd_entry_t *src_snap,
                                             int linux_flags,
                                             uint64_t expected_gen)
{
    bool installed = false;
    pthread_mutex_lock(&fd_lock);

    /* Generation is the unique discriminator: a close+reopen can reuse the same
     * (type, host_fd) tuple, so only the monotonic generation stamped at alloc
     * proves this is still the slot this dup created (matches asyncio_apply /
     * fasync_owner_set). The tuple check stays as a cheap early-out.
     */
    if (fd_table[dst_fd].type == expected_type &&
        fd_table[dst_fd].host_fd == expected_host_fd &&
        fd_table[dst_fd].generation == expected_gen) {
        /* linux_flags and ofd_id are not written here: the allocator installed
         * both from the alias spec, in the window that published the slot.
         */
        fd_table[dst_fd].fasync_owner_type = src_snap->fasync_owner_type;
        fd_table[dst_fd].fasync_owner = src_snap->fasync_owner;
        fd_table[dst_fd].seals = src_snap->seals;
        memcpy(fd_table[dst_fd].proc_path, src_snap->proc_path,
               sizeof(fd_table[dst_fd].proc_path));

        /* Read the mode back from the slot the allocator published rather than
         * from a local copy of it, so there is one answer to what this fd's
         * access mode is.
         */
        bool readable_urandom =
            expected_type == FD_URANDOM &&
            (fd_table[dst_fd].linux_flags & LINUX_O_ACCMODE) != LINUX_O_WRONLY;
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
    bool shared_dir = false;
    int new_host_fd =
        fd_snapshot_and_dup_or_share_dir(src_fd, &src_snap, &shared_dir);
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

    /* TODO(stage 3): explicit usbdev alias sharing the side-table entry
     * (fuse_dup_fd pattern). Refusing the dup beats handing out an alias whose
     * ioctls would miss the side table keyed by the original fd.
     */
    if (src_snap.type == FD_USBDEV) {
        proc_pty_unlock_for_dup();
        if (new_host_fd >= 0)
            close_keep_errno(new_host_fd);
        errno = EBADF;
        return -1;
    }

    /* eventfd dup must share the underlying counter and pipe state across the
     * source and destination fds (Linux contract). Pass src_snap's identity
     * through so eventfd_dup_fd can reject a close+reopen ABA between the
     * snapshot here and the bind there.
     */
    if (src_snap.type == FD_EVENTFD) {
        proc_pty_unlock_for_dup();
        if (new_host_fd >= 0)
            close_keep_errno(new_host_fd);
        return eventfd_dup_fd(src_fd, src_snap.host_fd, src_snap.generation,
                              min_guest_fd, fixed_guest_fd, fixed_slot,
                              linux_flags);
    }

    /* epoll dup must share the source's eventpoll instance so the alias sees
     * the same interest list. Pass src_snap's identity so epoll_dup_fd can
     * reject a close+reopen ABA before pinning the shared instance.
     */
    if (src_snap.type == FD_EPOLL) {
        proc_pty_unlock_for_dup();
        if (new_host_fd >= 0)
            close_keep_errno(new_host_fd);
        return epoll_dup_fd(src_fd, src_snap.host_fd, src_snap.generation,
                            min_guest_fd, fixed_guest_fd, fixed_slot,
                            linux_flags);
    }
    if (new_host_fd < 0) {
        proc_pty_unlock_for_dup();
        return -1;
    }

    /* Not for a shared directory descriptor: source and alias are the one
     * descriptor there, so there is no second reference for either table to
     * record, and registering a descriptor as its own duplicate would count it
     * twice. A directory is never a pty either way.
     */
    if (!shared_dir) {
        /* Mirror any /dev/ptmx keepalive BEFORE fd_alloc publishes guest_fd.
         * Once the guest fd exists, a sibling thread can close it; that runs
         * fd_cleanup_entry which calls proc_pty_close_keepalive(new_host_fd).
         * For that cleanup to drop the freshly-duped keepalive, the keepalive
         * entry must already be in the table; registering after fd_alloc would
         * lose the race and leak the slave fd. No-op when the source has no
         * keepalive.
         */
        proc_pty_dup_keepalive_locked(src_snap.host_fd, new_host_fd);

        /* Same reasoning for the slave side: the alias is a live reference to
         * the pty and must be on the books before the guest fd is published, or
         * the source's close will retire the only counted reference.
         */
        proc_pty_dup_guest_slave_locked(src_snap.host_fd, new_host_fd);
    }
    proc_pty_unlock_for_dup();

    int new_type = (src_snap.type == FD_STDIO) ? FD_REGULAR : src_snap.type;
    void (*cleanup)(int) = fd_cleanup_for_type(new_type);
    uint64_t alloc_gen = 0;

    /* The new slot aliases src_snap's description, whatever type it ends up
     * with, so the allocator inherits its status-flag answers instead of
     * probing a description it does not own. The dup's own bits ride along with
     * the description's, so the allocator publishes the final value inside the
     * window that creates the slot and install_fd_alias_metadata_atomic no
     * longer writes flags or identity at all. Two writers of one field is how a
     * dup'd epoll lost its ofd_id.
     */
    fd_alias_spec_t spec = fd_alias_of(src_fd, &src_snap);
    spec.linux_flags |= linux_flags;

    /* A directory alias publishes the source's own stream, referenced in the
     * window that snapshotted the slot. Nothing is opened here: the alias is
     * the same open file description as the source, so it must be the same
     * position, the same union state, and the same descriptor -- which is also
     * why a dup costs no second host descriptor, as it does not on Linux.
     */
    dir_stream_t *ds = shared_dir ? (dir_stream_t *) src_snap.dir : NULL;

    int guest_fd =
        ds ? fd_alloc_alias_dir(&spec, fixed_slot ? fixed_guest_fd : -1,
                                min_guest_fd, new_type, new_host_fd, cleanup,
                                ds, spec.linux_flags, &alloc_gen)
           : fd_alloc_alias_relaxed(&spec, fixed_slot ? fixed_guest_fd : -1,
                                    min_guest_fd, new_type, new_host_fd,
                                    cleanup, &alloc_gen);
    if (guest_fd < 0) {
        if (fixed_slot)
            errno = EBADF;

        /* fd_cleanup_entry never ran on new_host_fd (no guest fd was
         * registered), so both halves of the pty bookkeeping must be dropped
         * explicitly here. Leaving the slave counted would keep a host fd that
         * is about to be closed on the books, and the master would never see
         * its last slave go.
         */
        int saved_errno = errno;
        if (shared_dir) {
            /* The descriptor is the source's and stays open with it; only this
             * side's reference on the shared stream is given back.
             */
            dir_stream_release(ds);
        } else {
            proc_pty_forget_host_fd(new_host_fd);
            close(new_host_fd);
        }
        errno = saved_errno;
        return -1;
    }

    /* A false return means a sibling reallocated the slot while the metadata
     * install was pending. Nothing to unwind: that sibling's close path already
     * ran fd_cleanup_entry over new_host_fd, stream included, so this side owns
     * nothing either way.
     */
    if (install_fd_alias_metadata_atomic(guest_fd, new_type, new_host_fd,
                                         &src_snap, linux_flags, alloc_gen) &&
        ((src_snap.linux_flags & LINUX_O_ASYNC) ||
         (src_snap.type == FD_SOCKET &&
          src_snap.fasync_owner_type != FASYNC_OWNER_NONE))) {
        /* dup shares O_ASYNC (per open-file-description); register the alias
         * with the readiness watcher. install only returns true when the slot
         * still carries alloc_gen, so arming with it drops any stale event from
         * a sibling close+reuse in this window.
         */
        asyncio_arm(guest_fd, alloc_gen, new_host_fd, new_type);
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

/* Translate a Linux struct flock (aarch64) at `arg` to macOS layout, run
 * fcntl(host_fd, mac_cmd, ...), and for a GETLK command write the result back
 * translated to Linux layout. Shared by the traditional (F_GETLK/
 * F_SETLK/F_SETLKW) and OFD (F_OFD_GETLK/F_OFD_SETLK/F_OFD_SETLKW) lock
 * commands, which differ only in the macOS cmd values and in how l_pid is
 * reported back for a GETLK conflict.
 *
 * Linux aarch64 layout: {short l_type, short l_whence,
 *   long l_start, long l_len, int l_pid, pad[4]}
 * macOS layout: {off_t l_start, off_t l_len, pid_t l_pid,
 *   short l_type, short l_whence}
 * Use guest_read/guest_write (not guest_ptr) to safely handle structs that span
 * 2MiB page table block boundaries.
 */
/* Read the guest's struct flock once and translate it to the host's.
 *
 * Split out so a waiting command can decode before it starts polling: rereading
 * guest memory on every retry lets another thread change the request underneath
 * the wait, which would silently switch which region is being locked, turn a
 * lock into an unlock, or fail with EFAULT after the mapping went away.
 */
static int64_t fcntl_flock_decode(guest_t *g,
                                  uint64_t arg,
                                  bool is_ofd,
                                  struct flock *out)
{
    uint8_t lflock[32]; /* Linux struct flock is 32 bytes on aarch64 */
    if (guest_read_small(g, arg, lflock, sizeof(lflock)) < 0)
        return -LINUX_EFAULT;

    int16_t l_type, l_whence;
    int64_t l_start, l_len;
    int32_t l_pid;
    memcpy(&l_type, lflock + 0, 2);
    memcpy(&l_whence, lflock + 2, 2);
    memcpy(&l_start, lflock + 8, 8); /* offset 8 due to padding */
    memcpy(&l_len, lflock + 16, 8);
    memcpy(&l_pid, lflock + 24, 4);

    /* Linux rejects F_OFD_GETLK/SETLK/SETLKW requests with a nonzero l_pid: OFD
     * locks are owned by the open file description, not a process, so the field
     * is reserved on input (fs/locks.c fcntl_getlk/fcntl_setlk both return
     * -EINVAL on a nonzero request l_pid for these commands).
     */
    if (is_ofd && l_pid != 0)
        return -LINUX_EINVAL;

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
        return -LINUX_EINVAL;
    }

    *out = (struct flock) {
        .l_start = l_start,
        .l_len = l_len,
        .l_pid = 0,
        .l_type = mac_type,
        .l_whence = l_whence, /* SEEK_SET=0, SEEK_CUR=1, SEEK_END=2 same */
    };
    return 0;
}

static int64_t fcntl_flock_op(guest_t *g,
                              host_fd_ref_t *host_ref,
                              uint64_t arg,
                              int mac_cmd,
                              bool is_getlk,
                              bool is_ofd)
{
    struct flock mac_fl;
    int64_t decoded = fcntl_flock_decode(g, arg, is_ofd, &mac_fl);
    if (decoded < 0)
        return decoded;

    if (fcntl(host_ref->fd, mac_cmd, &mac_fl) < 0)
        return linux_errno();

    if (!is_getlk)
        return 0;

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
    int32_t rp;
    if (is_ofd) {
        /* OFD locks are owned by the open file description, not a single
         * process, so Linux always reports l_pid=-1 on a conflicting
         * F_OFD_GETLK lock instead of leaking a host PID to the guest.
         */
        rp = (rt == 2) ? 0 : -1;
    } else if (rt == 2) {
        rp = (int32_t) mac_fl.l_pid; /* F_UNLCK: no conflict to translate */
    } else {
        /* mac_fl.l_pid is a raw host PID, meaningless to guest code that treats
         * it as a real PID (e.g. a liveness check via kill(pid, 0)). Translate
         * it to the conflicting process's guest PID when it is part of this
         * guest's fork family; fall back to the host PID only when the lock
         * holder cannot be resolved (e.g. an unrelated host process), since no
         * guest identity exists for it to report.
         */
        int64_t gpid = proc_host_to_guest_pid((pid_t) mac_fl.l_pid);
        rp = (gpid > 0) ? (int32_t) gpid : (int32_t) mac_fl.l_pid;
    }

    /* The decode reads into its own buffer, so the GETLK answer needs one of
     * its own to pack into.
     */
    uint8_t lflock[32];
    memset(lflock, 0, sizeof(lflock));
    memcpy(lflock + 0, &rt, 2);
    memcpy(lflock + 2, &rw, 2);
    memcpy(lflock + 8, &rs, 8);
    memcpy(lflock + 16, &rl, 8);
    memcpy(lflock + 24, &rp, 4);
    if (guest_write_small(g, arg, lflock, sizeof(lflock)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* F_SETLKW / F_OFD_SETLKW, without parking the vCPU thread in a host call that
 * no teardown wake reaches. Polls the non-waiting command instead: macOS
 * reports a conflicting lock as EAGAIN, and POSIX allows EACCES for the same
 * condition, so both mean "retry". One thing polling cannot recover: F_SETLK
 * does no deadlock detection, so a guest that deadlocks on POSIX record locks
 * waits here instead of one participant getting EDEADLK. waiting is false for
 * the GETLK and SETLK commands, which never block and pass straight through.
 */
static int64_t fcntl_flock_wait(guest_t *g,
                                host_fd_ref_t *host_ref,
                                uint64_t arg,
                                int mac_cmd,
                                bool is_getlk,
                                bool is_ofd,
                                bool waiting)
{
    if (!waiting)
        return fcntl_flock_op(g, host_ref, arg, mac_cmd, is_getlk, is_ofd);

    struct flock mac_fl;
    int64_t decoded = fcntl_flock_decode(g, arg, is_ofd, &mac_fl);
    if (decoded < 0)
        return decoded;

    int poll_cmd = is_ofd ? F_OFD_SETLK : F_SETLK;
    unsigned backoff = 0;
    for (;;) {
        if (fcntl(host_ref->fd, poll_cmd, &mac_fl) == 0)
            return 0;
        int64_t rc = linux_errno();
        if (rc != -LINUX_EAGAIN && rc != -LINUX_EACCES)
            return rc;

        int64_t wait_rc = io_retry_backoff(&backoff);
        if (wait_rc < 0)
            return wait_rc;
    }
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
        /* One rule: the host answers for the bits it is authoritative for, the
         * shadow for the rest. fd_host_flag_mask names the first set from the
         * type; O_NONBLOCK leaves it per fd, since ownership is not a property
         * of the type alone.
         */
        int host_mask = fd_host_flag_mask(fd_snap.type);
        if (fd_nonblock_shadowed(fd_snap.type, fd_snap.nonblock_owned))
            host_mask &= ~LINUX_O_NONBLOCK;

        int shadow_fl = fd_snap.linux_flags & ~FD_GETFL_HIDDEN;
        if (!host_mask)
            return shadow_fl;

        host_fd_ref_t host_ref;
        int64_t ref_err = host_fd_ref_open(fd, &host_ref);
        if (ref_err < 0)
            return ref_err;
        int mac_fl = fcntl(host_ref.fd, F_GETFL);
        host_fd_ref_close(&host_ref);
        if (mac_fl < 0)
            return linux_errno();
        return (shadow_fl & ~host_mask) |
               (mac_to_linux_status_flags(mac_fl) & host_mask);
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
            asyncio_apply(fd, fd_snap.generation, ((int) arg & LINUX_O_ASYNC));
            return 0;
        }

        /* An fd elfuse emulates whole has no host description to tell. The fd
         * behind it is elfuse's own pipe or kqueue, held at the flags the
         * emulation needs, and a kqueue rejects fcntl(F_SETFL) outright: this
         * used to be a hand-written timerfd branch, while signalfd, inotify,
         * eventfd, epoll, pidfd and netlink fell through to the host call below
         * and set flags on elfuse's own descriptor. fd_host_flag_mask says
         * which types those are, and answers the same question F_GETFL asks it.
         *
         * Of Linux's writable status flags (O_APPEND, O_ASYNC, O_DIRECT,
         * O_NOATIME, O_NONBLOCK) these anon-inode objects honor O_APPEND,
         * O_NONBLOCK and O_NOATIME. O_DIRECT is refused because the inode lacks
         * FMODE_CAN_ODIRECT. Bits outside the writable set (access mode,
         * CLOEXEC, O_PATH and friends) are silently dropped, as Linux drops
         * them.
         */
        if (fd_host_flag_mask(fd_snap.type) == 0) {
            const int setfl_mask =
                LINUX_O_APPEND | LINUX_O_NONBLOCK | LINUX_O_NOATIME;
            if ((int) arg & LINUX_O_DIRECT)
                return -LINUX_EINVAL;

            /* The sweep below revalidates the generation and does nothing when
             * it moved, which would report success for a write that never
             * happened; a closed or reopened slot owes the guest EBADF.
             */
            pthread_mutex_lock(&fd_lock);
            bool live = fd_table[fd].type == fd_snap.type &&
                        fd_table[fd].generation == fd_snap.generation;
            pthread_mutex_unlock(&fd_lock);
            if (!live)
                return -LINUX_EBADF;

            /* Every bit here is answered from the shadow, and each one is per
             * open file description, so the sweep has to reach every alias
             * rather than only the name the guest passed. O_NONBLOCK needs no
             * second pass for that: it is in setfl_mask like the rest.
             *
             * The sweep revalidates the generation itself, so a close+reopen
             * between the snapshot and here changes nothing and the separate
             * lock-and-check this replaced is gone.
             */
            fd_set_shadow_flags(fd, fd_snap.generation, setfl_mask, (int) arg);
            asyncio_apply(fd, fd_snap.generation, ((int) arg & LINUX_O_ASYNC));
            return 0;
        }

        /* A socket has no O_DIRECT to set: Linux answers EINVAL, since the
         * inode has no FMODE_CAN_ODIRECT. A pipe does accept it -- that is
         * packet mode, not a filesystem property -- so the reject is by type
         * and not by "regular files only". Measured against qemu-aarch64: pipe
         * rc=0 reported=1, socket rc=-1 errno=22, regular rc=0.
         *
         * Rejected before anything is applied, as Linux rejects it: setfl()
         * checks O_DIRECT ahead of the flag store, so a call that fails here
         * must not have landed the other bits it carried.
         */
        if (((int) arg & LINUX_O_DIRECT) && fd_snap.type == FD_SOCKET)
            return -LINUX_EINVAL;

        host_fd_ref_t host_ref;
        int64_t ref_err = host_fd_ref_open(fd, &host_ref);
        if (ref_err < 0)
            return ref_err;

        /* An owned fd keeps O_NONBLOCK on the host whatever the guest asks; the
         * request is recorded in the shadow below and the transfer paths read
         * it from there.
         */
        int mac_fl = linux_to_mac_status_flags((int) arg);

        /* The host flag is not the guest's to change on these: elfuse holds it
         * set, either to keep the transfer non-parking or because the host fd
         * is its own pipe behind a synthetic fd. The request is recorded in the
         * shadow below instead.
         */
        if (fd_nonblock_shadowed(fd_snap.type, fd_snap.nonblock_owned))
            mac_fl |= O_NONBLOCK;
        int rc = fcntl(host_ref.fd, F_SETFL, mac_fl);
        if (rc < 0) {
            int64_t err = linux_errno();
            host_fd_ref_close(&host_ref);
            return err;
        }

        /* The settable bits macOS has no equivalent for are answered from the
         * shadow (fd_host_flag_mask), so F_SETFL has to write them there or
         * F_GETFL keeps reporting whatever open() recorded. O_DIRECT and
         * O_NOATIME are those two; O_NONBLOCK and O_ASYNC have their own paths
         * below. Measured before this: Linux takes O_NOATIME from 0 to 1 and
         * back, elfuse stayed at 0 throughout.
         */
        int shadow_setfl = (LINUX_O_DIRECT | LINUX_O_NOATIME) &
                           ~fd_host_flag_mask(fd_snap.type);
        if (shadow_setfl)
            fd_set_shadow_flags(fd, fd_snap.generation, shadow_setfl,
                                (int) arg);

        /* The guest's O_NONBLOCK for an owned fd lives in the shadow, which is
         * what the transfer paths and F_GETFL read. It reaches every dup alias
         * because Linux keeps O_NONBLOCK on the open file description.
         */
        fd_apply_guest_nonblock(fd, ((int) arg & LINUX_O_NONBLOCK) != 0);

        /* O_ASYNC is elfuse-managed: track the armed bit and (dis)arm the SIGIO
         * watcher. asyncio_apply rescans the slot under fd_lock and uses each
         * alias's real backing fd rather than the one this call pinned.
         */
        asyncio_apply(fd, fd_snap.generation, ((int) arg & LINUX_O_ASYNC));
        host_fd_ref_close(&host_ref);
        return 0;
    }
    case 5:   /* F_GETLK */
    case 6:   /* F_SETLK */
    case 7: { /* F_SETLKW */
        host_fd_ref_t host_ref;
        int64_t ref_err = host_fd_ref_open(fd, &host_ref);
        if (ref_err < 0)
            return ref_err;
        int mac_cmd = (cmd == 5) ? F_GETLK : (cmd == 6) ? F_SETLK : F_SETLKW;
        int64_t rc = fcntl_flock_wait(g, &host_ref, arg, mac_cmd, cmd == 5,
                                      false, cmd == 7);
        host_fd_ref_close(&host_ref);
        return rc;
    }
#if defined(F_OFD_GETLK) && defined(F_OFD_SETLK) && defined(F_OFD_SETLKW)
    case 36:   /* F_OFD_GETLK */
    case 37:   /* F_OFD_SETLK */
    case 38: { /* F_OFD_SETLKW */
        host_fd_ref_t host_ref;
        int64_t ref_err = host_fd_ref_open(fd, &host_ref);
        if (ref_err < 0)
            return ref_err;
        int mac_cmd = (cmd == 36)   ? F_OFD_GETLK
                      : (cmd == 37) ? F_OFD_SETLK
                                    : F_OFD_SETLKW;
        int64_t rc = fcntl_flock_wait(g, &host_ref, arg, mac_cmd, cmd == 36,
                                      true, cmd == 38);
        host_fd_ref_close(&host_ref);
        return rc;
    }
#endif
    case 8: { /* F_SETOWN */
        /* SIGIO/SIGURG delivery owner. The arg is a signed value passed by
         * value: pid > 0 targets a process, pid < 0 targets a process group,
         * pid == 0 clears the owner. Stored per open-file-description so the
         * async watcher (asyncio.c) can resolve the recipient on readiness.
         */
        int a = (int) arg;
        int otype, owner;
        if (a > 0) {
            otype = FASYNC_OWNER_PID;
            owner = a;
        } else if (a < 0) {
            /* Guard INT_MIN: -a would overflow (signed UB). A process group id
             * with no representable magnitude cannot name a real pgrp.
             */
            if (a == INT32_MIN)
                return -LINUX_EINVAL;
            otype = FASYNC_OWNER_PGRP;
            owner = -a;
        } else {
            otype = FASYNC_OWNER_NONE;
            owner = 0;
        }
        fasync_owner_set(fd, fd_snap.generation, otype, owner);
        return 0;
    }
    case 15: { /* F_SETOWN_EX */
        /* Struct f_owner_ex { int type; int pid; } pointer. Read it through so
         * a bad guest pointer faults with EFAULT, translate the Linux owner
         * type, and store it. pid == 0 clears the owner.
         */
        int32_t owner_ex[2];
        if (guest_read_small(g, arg, owner_ex, sizeof(owner_ex)) < 0)
            return -LINUX_EFAULT;
        int otype;
        switch (owner_ex[0]) {
        case LINUX_F_OWNER_TID:
            otype = FASYNC_OWNER_TID;
            break;
        case LINUX_F_OWNER_PID:
            otype = FASYNC_OWNER_PID;
            break;
        case LINUX_F_OWNER_PGRP:
            otype = FASYNC_OWNER_PGRP;
            break;
        default:
            return -LINUX_EINVAL;
        }

        /* F_SETOWN_EX carries the recipient in the type field, so the pid is a
         * plain positive identifier: a negative pid is invalid (Linux owner
         * semantics), and 0 clears the owner.
         */
        if (owner_ex[1] < 0)
            return -LINUX_EINVAL;
        if (owner_ex[1] == 0)
            otype = FASYNC_OWNER_NONE;
        fasync_owner_set(fd, fd_snap.generation, otype, owner_ex[1]);
        return 0;
    }
    case 9: { /* F_GETOWN */
        /* Derive the signed owner from the stored f_owner_ex: pid for PID/TID,
         * negated pgrp for PGRP, 0 when unowned.
         */
        int otype, owner;
        fasync_owner_get(fd, fd_snap.generation, &otype, &owner);
        if (otype == FASYNC_OWNER_PGRP)
            return -owner;
        if (otype == FASYNC_OWNER_NONE)
            return 0;
        return owner;
    }
    case 16: { /* F_GETOWN_EX */
        /* struct f_owner_ex { int type; int pid; }. Report the stored owner;
         * unowned reads back as {F_OWNER_PID, 0} to stay coherent with the
         * F_GETOWN path glibc layers on top of this.
         */
        int otype, owner;
        fasync_owner_get(fd, fd_snap.generation, &otype, &owner);
        int32_t owner_ex[2];
        switch (otype) {
        case FASYNC_OWNER_TID:
            owner_ex[0] = LINUX_F_OWNER_TID;
            break;
        case FASYNC_OWNER_PGRP:
            owner_ex[0] = LINUX_F_OWNER_PGRP;
            break;
        default:
            owner_ex[0] = LINUX_F_OWNER_PID;
            break;
        }
        owner_ex[1] = (otype == FASYNC_OWNER_NONE) ? 0 : owner;
        if (guest_write_small(g, arg, owner_ex, sizeof(owner_ex)) < 0)
            return -LINUX_EFAULT;
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
        int64_t ref_err = host_fd_ref_open(fd, &host_ref);
        if (ref_err < 0)
            return ref_err;
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

/* Widen the window between pinning the stream and looking the backing up, off
 * unless ELFUSE_DIR_UNION_BACKING_DELAY_US is set to a positive microsecond
 * count.
 *
 * The window is real but far too narrow to reach from a test: two threads
 * hammering close and dup2 on the walked fd produced no cross-listing in 353k
 * walks. What lives in it is a guest fd number that can be closed, or reopened
 * onto a different file, while this walk still holds the stream that number
 * used to name -- and the outcome that has to be pinned is that the walk keeps
 * answering for the directory it pinned, rather than reading someone else's
 * backing into it or quietly returning a listing missing its backing half.
 * tests/test-dir-union-fd-reuse drives it. Same shape and the same reasoning as
 * the drain's fault hook; no effect at all when unset.
 */
static void dir_backing_window_delay(void)
{
    static _Atomic long cached = -1; /* -1 = unread */
    long v = atomic_load_explicit(&cached, memory_order_relaxed);
    if (v < 0) {
        const char *env = getenv("ELFUSE_DIR_UNION_BACKING_DELAY_US");
        long long n = env ? strtoll(env, NULL, 10) : 0;
        v = (n > 0 && n < 1000000) ? (long) n : 0;
        atomic_store_explicit(&cached, v, memory_order_relaxed);
    }
    if (v > 0)
        usleep((useconds_t) v);
}

/* Open the host/sysroot directory that backs the same guest name as @fd, for a
 * synthetic directory whose listing has to extend its backing instead of
 * replacing it. See docs/internals.md, "Union Directory Listings".
 *
 * @guest_path is the stamp as dir_stream_acquire read it, not as fd_table holds
 * it now: the stream was pinned by fd number and can outlive the slot that
 * number names, so the number must never be consulted again.
 *
 * Returns the stream, or NULL when there is no backing listing to add. NULL
 * splits two ways and *@hard_errno tells them apart. Left at 0, no readable
 * backing was ever there to lose -- no union here, the guest path does not
 * translate, the backing is behind FUSE, ENOENT, or ENOTDIR. ENOENT covers the
 * backing being unlinked between the guest's open and this drain, which is a
 * name vanishing mid-walk: POSIX leaves that unspecified and Linux does not
 * report it either.
 *
 * Set, the backing exists and could not be read -- EACCES, EMFILE/ENFILE, ELOOP
 * -- and the caller must report rather than hand back a listing quietly missing
 * those names. Linux never answers that case short: measured in docker (gcc:13,
 * Linux 6.19 aarch64), an unprivileged open() of a chmod 000 directory fails
 * EACCES outright. elfuse cannot refuse the open, because the synthetic half
 * opened fine and the guest already holds the fd, so it reports on the read.
 */
static DIR *dir_backing_stream(const char *guest_path, int *hard_errno)
{
    *hard_errno = 0;
    dir_backing_window_delay();

    if (guest_path[0] != '/')
        return NULL;
    if (!usb_sysfs_dir_unions_backing(guest_path))
        return NULL;

    path_translation_t tx;
    if (path_translate_at(LINUX_AT_FDCWD, guest_path, PATH_TR_NONE, &tx) < 0)
        return NULL;
    if (tx.fuse_path)
        return NULL;

    int host_fd = open(tx.host_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (host_fd < 0) {
        if (errno != ENOENT && errno != ENOTDIR)
            *hard_errno = errno;
        return NULL;
    }
    DIR *dir = fdopendir(host_fd);
    if (!dir) {
        *hard_errno = errno;
        close_keep_errno(host_fd);
    }
    return dir;
}

/* Fault-injection hook for the drain, off unless ELFUSE_DIR_BACKING_FAULT is
 * set to a positive count: the drain then fails with ENOMEM once it has
 * buffered that many names. It exists because the failure it drives -- a
 * malloc/realloc that comes back NULL part-way through a real backing listing
 * -- cannot be provoked on demand, and the behavior on that path (the guest is
 * told, and never handed a short listing it reads as complete) is exactly what
 * regressed once already and so has to be pinned by a test rather than argued
 * about. tests/test-dir-backing-drain-error drives it. Same shape as the
 * ELFUSE_USB_FIXTURE hook in src/runtime/usb-sysfs.c: read from the
 * environment, no effect at all when unset.
 */
static size_t dir_backing_fault_after(void)
{
    static _Atomic size_t cached = 0; /* 0 = unread, SIZE_MAX = off */
    size_t v = atomic_load_explicit(&cached, memory_order_relaxed);
    if (v != 0)
        return v;

    const char *env = getenv("ELFUSE_DIR_BACKING_FAULT");
    long long n = env ? strtoll(env, NULL, 10) : -1;
    v = (n > 0) ? (size_t) n : SIZE_MAX;
    atomic_store_explicit(&cached, v, memory_order_relaxed);
    return v;
}

/* Fault-injection hook for the primary (synthetic) stream, off unless
 * ELFUSE_DIR_PRIMARY_READ_FAULT is set to a positive count: readdir() on the
 * primary then fails with EIO once it has returned that many entries.
 *
 * Same reason the drain has one, and the same shape: a readdir() that fails
 * part-way through a directory elfuse itself materialized cannot be provoked
 * from a test, and the behavior on that path -- the guest is told, and is never
 * handed a listing that stops early but reads as complete -- is exactly what
 * regressed on the backing side and has to be pinned rather than argued about.
 * tests/test-dir-primary-read-error drives it. No effect at all when unset.
 */
static size_t dir_primary_fault_after(void)
{
    static _Atomic size_t cached = 0; /* 0 = unread, SIZE_MAX = off */
    size_t v = atomic_load_explicit(&cached, memory_order_relaxed);
    if (v != 0)
        return v;

    const char *env = getenv("ELFUSE_DIR_PRIMARY_READ_FAULT");
    long long n = env ? strtoll(env, NULL, 10) : -1;
    v = (n > 0) ? (size_t) n : SIZE_MAX;
    atomic_store_explicit(&cached, v, memory_order_relaxed);
    return v;
}

/* Read the whole backing listing for @fd into @ds and close the backing stream
 * before returning, so the second host descriptor exists only for the duration
 * of this call and never spans a return to the guest. That is the whole point:
 * elfuse promises one host descriptor per guest fd (tests/test-dir-fd-budget),
 * and a resident second stream would charge union directories two.
 *
 * Names already present in the primary (synthetic) directory are dropped here
 * rather than at emit time, which is both the deduplication the union needs --
 * synthetic wins, and "." / ".." therefore appear once -- and what keeps the
 * buffer to the names that will actually be emitted. Asking the primary
 * directory itself rather than remembering the names already emitted keeps that
 * state out of the stream: the backing is only ever read once the primary is
 * exhausted, so a name that is in the primary has already been offered.
 *
 * There is no ceiling on what this buffers. A cap invents a failure Linux never
 * returns -- getdents64 on a directory of any size succeeds -- and spells it
 * ENOMEM, which is a lie about what went wrong. The memory is not the memory
 * that matters either: this buffer replaced a host descriptor held for the
 * whole life of the guest fd, and the widest sysfs directory on a real Linux
 * host (/sys/kernel/slab, 496 names, 5883 bytes of them) is a few tens of KiB,
 * freed at close. Grow until the allocator says no, and let a real ENOMEM be
 * the only ENOMEM.
 *
 * Always marks the drain as done, so it runs at most once per stream. Sets
 * ds->listing_errno when it could not deliver the whole backing listing -- a
 * failed allocation, a readdir that errored part-way, or a backing that exists
 * but could not be opened. The caller turns that into an error return rather
 * than a short one. A backing that was never there is not a failure: it means
 * there is nothing to add (see dir_backing_stream).
 */
static void dir_backing_drain(dir_stream_t *ds, const char *guest_path, int fd)
{
    ds->backing_drained = true;

    int open_failed = 0;
    DIR *backing = dir_backing_stream(guest_path, &open_failed);
    if (!backing) {
        ds->listing_errno = open_failed;
        if (open_failed)
            log_warn(
                "getdents64: the backing directory for fd %d exists but "
                "could not be read (%s); reporting the listing as "
                "incomplete rather than dropping its names",
                fd, strerror(open_failed));
        return;
    }

    ds->backing_escapes = path_dirent_dir_holds_escapes(dirfd(backing));

    size_t cap = 0, count = 0;
    backing_name_t **names = NULL;
    int failed = 0;
    const size_t fault_after = dir_backing_fault_after();

    for (;;) {
        /* readdir returns NULL for both end-of-stream and error, and only errno
         * separates them. Left unread, a readdir that failed part-way would end
         * the drain as if the backing had simply run out and the names past the
         * failure would go missing with nothing said -- the same silent
         * truncation the ceiling used to cause.
         */
        errno = 0;
        struct dirent *de = readdir(backing);
        if (!de) {
            failed = errno; /* 0 on a genuine end of stream */
            break;
        }

        struct stat dup_st;
        if (fstatat(dirfd(ds->dir), de->d_name, &dup_st, AT_SYMLINK_NOFOLLOW) ==
            0)
            continue;

        if (count >= fault_after) {
            failed = ENOMEM;
            break;
        }

        size_t len = strlen(de->d_name);

        if (count == cap) {
            size_t want = cap ? cap * 2 : 16;
            backing_name_t **grown = (backing_name_t **) realloc(
                (void *) names, want * sizeof(*grown));
            if (!grown) {
                failed = ENOMEM;
                break;
            }
            names = grown;
            cap = want;
        }

        backing_name_t *entry = malloc(sizeof(*entry) + len + 1);
        if (!entry) {
            failed = ENOMEM;
            break;
        }
        entry->ino = de->d_ino;
        entry->type = de->d_type;
        memcpy(entry->name, de->d_name, len + 1);
        names[count++] = entry;
    }

    closedir(backing); /* the transient descriptor goes back here */

    if (failed) {
        log_warn(
            "getdents64: the backing directory for fd %d could not be read "
            "to the end (%s) after %zu names; reporting the listing as "
            "incomplete rather than truncating it",
            fd, strerror(failed), count);
        for (size_t i = 0; i < count; i++)
            free(names[i]);
        free((void *) names);
        ds->listing_errno = failed;
        return;
    }

    ds->backing = names;
    ds->backing_count = count;
}

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

    /* Pin the directory stream so a concurrent close()/dup2() cannot free it
     * while this call is still walking it -- see dir_stream_t in fs.c.
     */
    char walk_path[FD_VIRTUAL_PATH_MAX];
    dir_stream_t *ds = dir_stream_acquire(fd, walk_path, sizeof(walk_path));
    if (!ds)
        return -LINUX_ENOTDIR;

    uint64_t prefault_len =
        count < DIRENT64_MAX_RECLEN ? count : DIRENT64_MAX_RECLEN;
    (void) guest_lazy_faultin(g, buf_gva, prefault_len);

    /* Serialize the walk against a concurrent getdents64 pinning the same
     * stream -- see the lock field in dir_stream_t.
     */
    pthread_mutex_lock(&ds->lock);

    int64_t ret;

    uint64_t avail = 0;
    if (!guest_ptr_avail_nofault(g, buf_gva, &avail, MEM_PERM_R)) {
        ret = -LINUX_EFAULT;
        goto out;
    }

    /* A stream that lost names it can never produce again fails here, before
     * the walk, and goes on failing: the errno is sticky. Without this the
     * stream came back with nothing buffered and returned 0, an end of
     * directory the guest cannot tell from a real one. See docs/internals.md,
     * "Union Directory Listings", for the contract and why it is not one-shot.
     */
    if (ds->listing_errno) {
        errno = ds->listing_errno;
        ret = linux_errno();
        goto out;
    }

    size_t guest_pos = 0;
    struct dirent *de;

    /* Temp buffer for dirent serialization. dirent_record_bounds proves every
     * record it accepts fits DIRENT64_MAX_RECLEN, so nothing below re-checks
     * the extent. Using a stack buffer avoids guest_ptr boundary issues:
     * guest_write() handles 2MiB block crossings that raw memcpy into
     * guest_ptr() cannot.
     *
     * guest_pos <= count holds on every iteration, which is what lets the call
     * below meet its precondition: it starts at 0 and only advances by a reclen
     * the same call proved fits in count - guest_pos.
     */
    uint8_t entry_buf[DIRENT64_MAX_RECLEN];

    /* The walk runs over the primary stream and then, for a synthetic directory
     * that has a backing, over the names drained out of the backing. Which side
     * it is on survives the return to the guest, in the stream: the drain is
     * what exhausts the primary, so a stream that has drained is a stream whose
     * remaining entries are all on the backing side.
     */
    bool on_backing = ds->backing_drained;

    /* One answer per stream, not per entry: which side of the sysroot boundary
     * the stream reads from is a property of the directory. The backing's
     * answer was recorded by the drain, while its descriptor still existed.
     */
    bool dir_holds_escapes =
        on_backing ? ds->backing_escapes
                   : path_dirent_dir_holds_escapes(dirfd(ds->dir));

    while (1) {
        const char *host_name;
        uint64_t entry_ino;
        unsigned char entry_type;
        int64_t entry_off = 0; /* backing side only; the primary asks telldir */
        long saved_pos = 0;

        if (on_backing) {
            if (ds->backing_pos >= ds->backing_count)
                break;
            const backing_name_t *bn = ds->backing[ds->backing_pos];
            host_name = bn->name;
            entry_ino = bn->ino;
            entry_type = bn->type;

            /* The backing side numbers its entries from one. d_off is an opaque
             * cookie the guest may only hand back, so the primary's telldir
             * cookies and these indices share one space, exactly as the two
             * streams' separate cookie spaces did before.
             */
            entry_off = (int64_t) (ds->backing_pos + 1);
        } else {
            /* Save position BEFORE readdir so getdents emulation can rewind if
             * the entry does not fit. macOS telldir returns an opaque cookie --
             * arithmetic on it (e.g. telldir()-1) is undefined.
             */
            saved_pos = telldir(ds->dir);

            /* readdir() reports end-of-stream and failure the same way -- NULL
             * -- and only errno separates them, so errno has to be cleared
             * first or a value left by an earlier call would read as this one's
             * failure. Left unchecked, a primary readdir that failed part-way
             * was taken for exhaustion: the walk unioned the backing in as if
             * the synthetic half were finished, dropped every synthetic name
             * past the failure, and handed the result back as a clean end of
             * directory. That is the same silent truncation the drain side was
             * repaired for, on the other half of the union.
             */
            errno = 0;
            de = readdir(ds->dir);
            if (de && ++ds->primary_seen > dir_primary_fault_after()) {
                de = NULL;
                errno = EIO;
            }
            if (!de && errno) {
                int primary_errno = errno;
                ds->listing_errno = primary_errno;
                log_warn(
                    "getdents64: the directory behind fd %d could not be read "
                    "to the end (%s); reporting the listing as incomplete "
                    "rather than ending it early",
                    fd, strerror(primary_errno));

                /* Linux's two-part shape, the same one the drain failure uses:
                 * a call that has already written entries returns their count
                 * and leaves the error for the next call, which the sticky
                 * listing_errno delivers at the top of this function; a call
                 * that has written nothing returns -1 with the errno.
                 */
                errno = primary_errno;
                ret = guest_pos > 0 ? (int64_t) guest_pos : linux_errno();
                goto out;
            }
            if (!de) {
                if (ds->backing_drained || ds->backing_private)
                    break;

                /* Primary exhausted: pull in the backing's names. The drain
                 * opens the backing directory and closes it before returning,
                 * so the second descriptor does not outlive this call.
                 */
                dir_backing_drain(ds, walk_path, fd);
                if (ds->listing_errno) {
                    /* Linux's two-part shape: a call that has written entries
                     * returns their count and leaves the error for the next
                     * call, which the sticky listing_errno delivers at the top
                     * of this function; a call that has written nothing is the
                     * guest_pos == 0 arm here and returns -1. Measured before
                     * the repair, with the drain failed after two names against
                     * a backing of six: the guest got 3 of 9 names and errno 0
                     * at every buffer size from 24 bytes to 32KiB.
                     */
                    errno = ds->listing_errno;
                    ret = guest_pos > 0 ? (int64_t) guest_pos : linux_errno();
                    goto out;
                }
                on_backing = true;
                dir_holds_escapes = ds->backing_escapes;
                continue;
            }
            host_name = de->d_name;
            entry_ino = de->d_ino;
            entry_type = de->d_type;
        }

        char guest_name[NAME_MAX + 1];
        int name_rc = path_translate_dirent_name(
            dir_holds_escapes, host_name, guest_name, sizeof(guest_name));
        if (name_rc < 0) {
            /* A host name a guest libc cannot represent is skipped and the rest
             * of the stream delivered -- an elfuse policy with no Linux
             * counterpart; see docs/internals.md, "Union Directory Listings".
             *
             * ENAMETOOLONG is the only failure the translator can raise here:
             * its other arm is an EINVAL guarding null arguments and a
             * zero-sized output, and this call site passes the entry's own name
             * and a NAME_MAX + 1 array with its own sizeof. The exit below is
             * therefore unreachable rather than a second policy, and it rewinds
             * the way the does-not-fit path does, so that no exit from this
             * walk can consume an entry without putting it back.
             */
            if (errno == ENAMETOOLONG) {
                static _Atomic bool overlong_warned;
                if (!atomic_exchange_explicit(&overlong_warned, true,
                                              memory_order_relaxed))
                    log_warn(
                        "getdents64: skipping host dirent whose name "
                        "exceeds Linux NAME_MAX (%u); first hit was "
                        "%zu bytes on fd %d",
                        NAME_MAX, strlen(host_name), fd);
                if (on_backing)
                    ds->backing_pos++;
                continue;
            }
            if (!on_backing)
                seekdir(ds->dir, saved_pos);
            ret = guest_pos > 0 ? (int64_t) guest_pos : linux_errno();
            goto out;
        }

        /* path_translate_dirent_name wrote into a NAME_MAX + 1 buffer, so the
         * length is within dirent_record_bounds' precondition.
         */
        uint64_t name_len = strlen(guest_name);
        uint64_t reclen, pad_start;

        if (!dirent_record_bounds(name_len, guest_pos, count, &reclen,
                                  &pad_start)) {
            /* Entry does not fit; rewind so next call gets it. The backing side
             * rewinds by simply not advancing its cursor.
             */
            if (!on_backing)
                seekdir(ds->dir, saved_pos);

            /* Nothing written yet means the buffer is too small for this one
             * entry, and no larger call will ever be made on a stream the guest
             * believes has ended. Linux answers EINVAL -- measured in docker
             * (gcc 14.4, Linux 6.19 aarch64) over a directory holding one
             * twelve-byte name and one two-byte name: 8 and 16 bytes report at
             * once, and 24 bytes delivers the three names a 24-byte record can
             * hold, one to a call, and then reports. Returning the count, zero
             * here, is an end of directory the guest cannot tell from a real
             * one. A call that has already written entries keeps the other half
             * of the shape and returns their count -- the break below.
             */
            if (guest_pos == 0) {
                ret = -LINUX_EINVAL;
                goto out;
            }
            break;
        }

        linux_dirent64_t lde;
        lde.d_ino = entry_ino;
        lde.d_off = on_backing ? entry_off : telldir(ds->dir);
        lde.d_reclen = (uint16_t) reclen;
        lde.d_type = entry_type;

        memcpy(entry_buf, &lde, sizeof(lde));
        memcpy(entry_buf + DIRENT64_HDR_BYTES, guest_name, name_len + 1);
        if (pad_start < reclen)
            memset(entry_buf + pad_start, 0, reclen - pad_start);

        if (guest_write_nofault(g, buf_gva + guest_pos, entry_buf, reclen) <
            0) {
            /* readdir has already handed this entry over, so leaving now
             * without putting it back resumes the next call past it: the guest
             * gets a listing one name short that still ends at 0, which is the
             * silent truncation this walk was repaired for on its other paths.
             *
             * Rewind, the shape the does-not-fit path above uses, rather than
             * setting ds->listing_errno. The two shapes answer different
             * questions. listing_errno is for a name the stream can never
             * produce again -- a failed drain, a primary that stopped reading
             * -- and it is sticky, so every later call on the fd fails. Nothing
             * is lost here: the guest buffer could not take one entry, which is
             * the same thing the record-does-not-fit break says, and Linux
             * answers it the same way, by returning the short count and
             * delivering the entry on the following call. Measured over a
             * 96-name directory read through a buffer whose tail is unmapped,
             * at gaps of 120, 410 and 700 bytes: Linux (docker gcc:14, 6.19
             * aarch64) delivers all 96 names at every gap, and elfuse before
             * this rewind lost the entry at the fault -- 97 of the 98 names the
             * directory holds, errno 0, ending at a clean 0. The backing side
             * rewinds by not advancing backing_pos, which it has not done yet.
             */
            if (!on_backing)
                seekdir(ds->dir, saved_pos);
            ret = guest_pos > 0 ? (int64_t) guest_pos : -LINUX_EFAULT;
            goto out;
        }

        if (on_backing)
            ds->backing_pos++;
        guest_pos += reclen;
    }

    ret = (int64_t) guest_pos;

out:
    pthread_mutex_unlock(&ds->lock);
    dir_stream_release(ds);
    return ret;
}

/* Reach a shm leaf via an fd for truncate/chdir, which have no nofollow path
 * variant. O_NOFOLLOW keeps a symlink leaf contained, O_NONBLOCK stops a FIFO
 * leaf from blocking the vCPU thread, O_CLOEXEC covers the short-lived fd. See
 * dev_shm_resolve_path().
 */
static int shm_open_leaf(const path_translation_t *tx, int oflags)
{
    return open(tx->host_path, oflags | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
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

    /* fchdir on a nofollow fd instead of chdir(), which would follow a symlink
     * leaf. Set the virtual cwd to the guest path so getcwd never leaks the
     * backing location, like the proc and fuse branches above.
     */
    if (tx.is_dev_shm) {
        int fd = shm_open_leaf(&tx, O_RDONLY | O_DIRECTORY);
        if (fd < 0)
            return linux_errno();
        int chdir_rc = fchdir(fd);
        close_keep_errno(fd);
        if (chdir_rc < 0)
            return linux_errno();
        proc_cwd_set_virtual(tx.guest_path);
        return 0;
    }

    /* The synthetic /sys and /dev/bus directories are reached by an intercept,
     * never by the host walk: chdir(tx.host_path) looks for them in the sysroot
     * or on the host, neither of which carries the tree, so chdir answered
     * ENOENT for every directory open() and fchdir() both reach -- and reported
     * ENOENT rather than ENOTDIR for the attributes and device nodes inside it.
     * Route it through the same open the descriptor path uses so the three
     * agree, and publish the descriptor's own guest spelling as the virtual
     * cwd, which is what makes a chdir onto a `subsystem` link land where Linux
     * lands rather than in the directory the link sits in.
     *
     * A name the intercept does not claim falls through to the host chdir
     * below, unchanged.
     */
    if (tx.intercept_path &&
        (path_prefix_match(tx.intercept_path, "/sys", 4) ||
         path_prefix_match(tx.intercept_path, "/dev/bus", 8))) {
        int host_fd =
            proc_intercept_open(g, tx.intercept_path, LINUX_O_DIRECTORY, 0);
        if (host_fd >= 0) {
            char virt_buf[LINUX_PATH_MAX];
            const char *virt_path = tx.intercept_path;
            if (usb_sysfs_guest_path_for_fd(host_fd, virt_buf,
                                            sizeof(virt_buf)) > 0)
                virt_path = virt_buf;
            int chdir_rc = fchdir(host_fd);
            int saved_errno = errno;
            close_keep_errno(host_fd);
            if (chdir_rc < 0) {
                errno = saved_errno;
                return linux_errno();
            }
            proc_cwd_set_virtual(virt_path);
            return 0;
        }
        if (host_fd == -1)
            return linux_errno();
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
    int64_t ref_err = host_fd_ref_open(fd, &host_ref);
    if (ref_err < 0)
        return ref_err;

    char proc_virt[64];
    const char *proc_virtual = proc_virtual_dir_path(
        fd_table[fd].proc_path, proc_virt, sizeof(proc_virt));

    /* /dev/pts is not a /proc path, so proc_virtual_dir_path does not name it,
     * but it is virtual for the same reason: the host directory behind it holds
     * placeholder files, not the slaves. Publishing the guest spelling is what
     * lets a relative open resolved against this cwd re-derive /dev/pts/N and
     * reach the intercept, exactly as a directory fd does.
     */
    if (!proc_virtual && !strcmp(fd_table[fd].proc_path, "/dev/pts"))
        proc_virtual = "/dev/pts";

    /* The synthetic USB trees are virtual for the same reason as /dev/pts: the
     * scratch directory behind a /sys or /dev/bus descriptor is not what the
     * guest named, and its host location is not a name the guest may see. Left
     * to proc_cwd_refresh() the fd's real cwd would surface through getcwd, and
     * a relative open resolved against it would land in the scratch tree --
     * writing into a read-only view and reporting the wrong statfs magic.
     * Publishing the stamped guest spelling instead keeps the cwd on the
     * intercepts, exactly as chdir() does for these paths.
     * resolve_proc_cwd_path knows the same two prefixes.
     */
    if (!proc_virtual && fd_table[fd].proc_path[0] &&
        (path_prefix_match(fd_table[fd].proc_path, "/sys", 4) ||
         path_prefix_match(fd_table[fd].proc_path, "/dev/bus", 8)))
        proc_virtual = fd_table[fd].proc_path;
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
        fd_retire_published(guest_fds[0], host_fds[0]);
        close(host_fds[1]);
        errno = saved_errno;
        return linux_errno();
    }

    /* The host fds are already nonblocking: fd_alloc owns O_NONBLOCK on a pipe
     * so a transfer can report EAGAIN instead of parking a vCPU thread. Record
     * what the guest asked for, which is what F_GETFL and the wait paths read.
     */
    int shadow = linux_flags & (LINUX_O_CLOEXEC | LINUX_O_NONBLOCK);
    fd_publish_linux_flags(guest_fds[0], shadow);
    fd_publish_linux_flags(guest_fds[1], shadow);

    /* fd_alloc owns O_NONBLOCK on a pipe, so the guest's request is recorded
     * above and the host fds are already nonblocking. If ownership was refused
     * -- only a failing fcntl does that -- the guest's request still has to
     * reach the host fd, since nothing else will answer for it.
     */
    if (linux_flags & LINUX_O_NONBLOCK) {
        for (int i = 0; i < 2; i++) {
            if (!fd_block_state(guest_fds[i]).nonblock_owned)
                fd_set_nonblock(host_fds[i]);
        }
    }

    int32_t fds[2] = {guest_fds[0], guest_fds[1]};
    if (guest_write_small(g, fds_gva, fds, sizeof(fds)) < 0) {
        fd_retire_published(guest_fds[0], host_fds[0]);
        fd_retire_published(guest_fds[1], host_fds[1]);
        return -LINUX_EFAULT;
    }

    return 0;
}

int64_t sys_lseek(int fd, int64_t offset, int whence)
{
    int64_t frc = fuse_lseek_fd(fd, offset, whence);
    if (frc != INT64_MIN)
        return frc;
    frc = usbdev_lseek_fd(fd, offset, whence);
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
    int64_t ref_err = host_dirfd_ref_open(dirfd, &dir_ref);
    if (ref_err < 0)
        return ref_err;

    /* Apply sysroot redirect for absolute paths */
    ssize_t len = readlinkat(path_translation_dirfd(&tx, &dir_ref),
                             tx.host_path, link, sizeof(link) - 1);
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

    path_translation_t tx;
    int64_t rc =
        read_translated_path(g, dirfd, path_gva, PATH_TR_CREATE, path, &tx);
    if (rc < 0)
        return rc;
    rc = reject_unsupported_fuse_path_op(&tx);
    if (rc != INT64_MIN)
        return rc;

    host_fd_ref_t dir_ref;
    int64_t ref_err = host_dirfd_ref_open(dirfd, &dir_ref);
    if (ref_err < 0)
        return ref_err;

    /* path_translate_at rewrites /dev/shm/<name> to the absolute backing path,
     * so shm_unlink works; path_translation_dirfd drops the guest dirfd there.
     */
    host_fd_t unlink_dirfd = path_translation_dirfd(&tx, &dir_ref);

    struct stat removed_st;
    bool clear_removed_overlay =
        fstatat(unlink_dirfd, tx.host_path, &removed_st, AT_SYMLINK_NOFOLLOW) ==
            0 &&
        (removed_st.st_nlink <= 1 || (flags & LINUX_AT_REMOVEDIR));

    int host_flags = translate_at_flags(flags);
    if (unlinkat(unlink_dirfd, tx.host_path, host_flags) < 0) {
        host_fd_ref_close(&dir_ref);
        return linux_errno();
    }

    if (clear_removed_overlay)
        chown_overlay_clear_removed_identity(&removed_st);

    host_fd_ref_close(&dir_ref);
    return 0;
}

int64_t sys_mkdirat(guest_t *g, int dirfd, uint64_t path_gva, int mode)
{
    char path[LINUX_PATH_MAX];
    if (guest_read_str(g, path_gva, path, sizeof(path)) < 0)
        return -LINUX_EFAULT;

    path_translation_t tx;
    int64_t rc = read_translated_path(
        g, dirfd, path_gva, PATH_TR_CREATE | PATH_TR_CREATE_PARENTS, path, &tx);
    if (rc < 0)
        return rc;
    rc = reject_unsupported_fuse_path_op(&tx);
    if (rc != INT64_MIN)
        return rc;

    host_fd_ref_t dir_ref;
    int64_t ref_err = host_dirfd_ref_open(dirfd, &dir_ref);
    if (ref_err < 0)
        return ref_err;

    if (mkdirat(path_translation_dirfd(&tx, &dir_ref), tx.host_path,
                (mode_t) mode) < 0) {
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

    if (path_translate_at(olddirfd, oldpath, PATH_TR_NOFOLLOW, &old_tx) < 0 ||
        path_translate_at(newdirfd, newpath, PATH_TR_CREATE | PATH_TR_NOFOLLOW,
                          &new_tx) < 0)
        return linux_errno();
    if (old_tx.fuse_path || new_tx.fuse_path)
        return -LINUX_ENOSYS;

    host_fd_ref_t olddir_ref, newdir_ref;
    int64_t ref_err =
        host_dirfd_ref_open_pair(olddirfd, newdirfd, &olddir_ref, &newdir_ref);
    if (ref_err < 0)
        return ref_err;
    host_fd_t old_host_dirfd = path_translation_dirfd(&old_tx, &olddir_ref);
    host_fd_t new_host_dirfd = path_translation_dirfd(&new_tx, &newdir_ref);

    /* Apply sysroot resolution for absolute paths RENAME_NOREPLACE: fail if
     * destination exists. macOS renamex_np supports RENAME_EXCL for the same
     * semantics. Only supported for AT_FDCWD paths (renamex_np does not take
     * dirfd arguments).
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
        if (linkat(old_host_dirfd, old_tx.host_path, new_host_dirfd,
                   new_tx.host_path, 0) < 0) {
            return close_dir_refs_result(&olddir_ref, &newdir_ref,
                                         linux_errno());
        }
        if (unlinkat(old_host_dirfd, old_tx.host_path, 0) < 0) {
            int err = errno;
            (void) unlinkat(new_host_dirfd, new_tx.host_path, 0);
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

    struct stat old_st;
    bool have_old_st = fstatat(old_host_dirfd, old_tx.host_path, &old_st,
                               AT_SYMLINK_NOFOLLOW) == 0;
    struct stat overwritten_st;
    bool clear_overwritten_overlay =
        fstatat(new_host_dirfd, new_tx.host_path, &overwritten_st,
                AT_SYMLINK_NOFOLLOW) == 0 &&
        stat_identity_will_disappear(&overwritten_st) &&
        (!have_old_st || !same_stat_identity(&old_st, &overwritten_st));

    if (olddirfd == LINUX_AT_FDCWD && newdirfd == LINUX_AT_FDCWD) {
        if (rename(old_tx.host_path, new_tx.host_path) < 0) {
            return close_dir_refs_result(&olddir_ref, &newdir_ref,
                                         linux_errno());
        }
        if (clear_overwritten_overlay)
            chown_overlay_clear_removed_identity(&overwritten_st);
        return close_dir_refs_result(&olddir_ref, &newdir_ref, 0);
    }

    if (renameat(old_host_dirfd, old_tx.host_path, new_host_dirfd,
                 new_tx.host_path) < 0) {
        return close_dir_refs_result(&olddir_ref, &newdir_ref, linux_errno());
    }
    if (clear_overwritten_overlay)
        chown_overlay_clear_removed_identity(&overwritten_st);
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
    int64_t ref_err = host_dirfd_ref_open(dirfd, &dir_ref);
    if (ref_err < 0)
        return ref_err;

    /* FIFO via mkfifoat and regular files via openat are supported; device
     * nodes need root
     */
    if (S_ISFIFO(mode)) {
        if (mkfifoat(path_translation_dirfd(&tx, &dir_ref), tx.host_path,
                     mode & 0777) < 0) {
            host_fd_ref_close(&dir_ref);
            return linux_errno();
        }
        host_fd_ref_close(&dir_ref);
        return 0;
    }

    /* Regular files: create an empty file */
    if (S_ISREG(mode) || (mode & S_IFMT) == 0) {
        int fd = openat(path_translation_dirfd(&tx, &dir_ref), tx.host_path,
                        O_CREAT | O_WRONLY | O_EXCL, mode & 0777);
        host_fd_ref_close(&dir_ref);
        if (fd < 0)
            return linux_errno();
        close(fd);
        return 0;
    }

    host_fd_ref_close(&dir_ref);
    return -LINUX_ENOSYS;
}

typedef enum {
    SYMLINK_TARGET_VERBATIM,  /* store the guest's target unchanged */
    SYMLINK_TARGET_REWRITTEN, /* store the composed relative path */
    SYMLINK_TARGET_FAILED,    /* must rewrite but cannot; errno is set */
} symlink_target_rewrite_t;

/* Absolute host path of the new symlink itself.
 *
 * path_translate_at() only rewrites absolute guest paths; a relative linkpath
 * is handed back untouched because the resolvers have no dirfd context (see the
 * comment in path_translate_at). Measuring depth against that bare name would
 * silently skip the rewrite and leave an escaping absolute target on disk, so
 * rebuild the location from the dirfd first.
 */
static bool symlink_host_location(int dirfd,
                                  const host_fd_ref_t *dir_ref,
                                  const char *host_path,
                                  char *out,
                                  size_t outsz)
{
    if (host_path[0] == '/') {
        if (str_copy_trunc(out, host_path, outsz) >= outsz) {
            errno = ENAMETOOLONG;
            return false;
        }
        return true;
    }

    char base[LINUX_PATH_MAX];
    if (dirfd == LINUX_AT_FDCWD) {
        if (!getcwd(base, sizeof(base)))
            return false;
    } else if (dir_ref->fd < 0 || fcntl(dir_ref->fd, F_GETPATH, base) < 0) {
        return false;
    }

    int n = snprintf(out, outsz, "%s/%s", base, host_path);
    if (n < 0 || (size_t) n >= outsz) {
        errno = ENAMETOOLONG;
        return false;
    }
    return true;
}

/* Express absolute guest path @target as a path relative to the directory that
 * holds the new symlink, so a native follow stays inside the sysroot. ".." is
 * normalized away first, clamped at "/" the way a chroot resolves it, so the
 * result can never climb above the sysroot.
 *
 * VERBATIM covers the cases where no rewrite is owed: a relative target, no
 * sysroot configured, or a symlink created outside the sysroot, where the guest
 * is deliberately working against host paths. Anything that must be rewritten
 * but cannot is FAILED rather than VERBATIM, not a fallback to the literal
 * target there would hand back the very escape this closes.
 */
static symlink_target_rewrite_t symlink_rewrite_target(const char *target,
                                                       int dirfd,
                                                       const host_fd_ref_t *ref,
                                                       const char *host_path,
                                                       char *out,
                                                       size_t outsz)
{
    char sr[LINUX_PATH_MAX], norm[LINUX_PATH_MAX], link_host[LINUX_PATH_MAX];
    if (target[0] != '/' || !proc_sysroot_snapshot(sr, sizeof(sr)))
        return SYMLINK_TARGET_VERBATIM;

    if (!symlink_host_location(dirfd, ref, host_path, link_host,
                               sizeof(link_host)))
        return SYMLINK_TARGET_FAILED;

    size_t sr_len = strlen(sr);
    if (strncmp(link_host, sr, sr_len) != 0 || link_host[sr_len] != '/')
        return SYMLINK_TARGET_VERBATIM;

    if (path_openat2_normalize_in_root(target, norm, sizeof(norm)) != 0)
        return SYMLINK_TARGET_FAILED;

    /* One ".." per directory between the sysroot and the symlink itself.
     * Counting components rather than separators keeps repeated or trailing
     * slashes ("/a//b/link") from inflating the depth and walking out above the
     * sysroot: host_path is a plain concatenation with no normalization.
     */
    size_t components = 0;
    for (const char *p = link_host + sr_len; *p;) {
        while (*p == '/')
            p++;
        if (!*p)
            break;
        components++;
        while (*p && *p != '/')
            p++;
    }
    size_t depth = components ? components - 1 : 0;

    size_t norm_len = strlen(norm);
    if (depth * 3 + norm_len + 1 > outsz) {
        errno = ENAMETOOLONG;
        return SYMLINK_TARGET_FAILED;
    }

    char *w = out;
    for (size_t i = 0; i < depth; i++, w += 3)
        memcpy(w, "../", 3);
    memcpy(w, norm, norm_len + 1);
    return SYMLINK_TARGET_REWRITTEN;
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
    int64_t ref_err = host_dirfd_ref_open(dirfd, &dir_ref);
    if (ref_err < 0)
        return ref_err;

    /* An absolute target is stored verbatim, but the host kernel resolves it
     * against the real host root -- not --sysroot -- whenever anything follows
     * the symlink natively, so the follow escapes the guest tree. Store it
     * relative to the symlink's own directory instead: it stays inside the
     * sysroot and survives the tree being moved, where "<sysroot><target>"
     * would strand every such link.
     *
     * Two divergences the guest can see: readlink() reports the rewritten form,
     * since nothing on disk tells a rewritten target from a relative one the
     * guest wrote; and an absolute target loses the host fallback a direct
     * open() would get, the choice being made once at creation rather than at
     * follow time.
     */
    const char *host_target = target;
    char rel_target[LINUX_PATH_MAX];
    switch (symlink_rewrite_target(target, dirfd, &dir_ref, tx.host_path,
                                   rel_target, sizeof(rel_target))) {
    case SYMLINK_TARGET_REWRITTEN:
        host_target = rel_target;
        break;
    case SYMLINK_TARGET_FAILED:
        host_fd_ref_close(&dir_ref);
        return linux_errno();
    case SYMLINK_TARGET_VERBATIM:
        break;
    }

    /* Resolve linkpath (the new symlink location) through sysroot */
    if (symlinkat(host_target, path_translation_dirfd(&tx, &dir_ref),
                  tx.host_path) < 0) {
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

    unsigned int old_flags =
        (flags & LINUX_AT_SYMLINK_FOLLOW) ? PATH_TR_NONE : PATH_TR_NOFOLLOW;
    if (path_translate_at(olddirfd, oldpath, old_flags, &old_tx) < 0 ||
        path_translate_at(newdirfd, newpath, PATH_TR_CREATE | PATH_TR_NOFOLLOW,
                          &new_tx) < 0)
        return linux_errno();
    if (old_tx.fuse_path || new_tx.fuse_path)
        return -LINUX_ENOSYS;

    host_fd_ref_t olddir_ref, newdir_ref;
    int64_t ref_err =
        host_dirfd_ref_open_pair(olddirfd, newdirfd, &olddir_ref, &newdir_ref);
    if (ref_err < 0)
        return ref_err;
    host_fd_t old_host_dirfd = path_translation_dirfd(&old_tx, &olddir_ref);
    host_fd_t new_host_dirfd = path_translation_dirfd(&new_tx, &newdir_ref);

    /* Resolve both paths through sysroot */
    int mac_flags = translate_at_flags(flags);

    /* Clear AT_SYMLINK_FOLLOW so a shm symlink is hard-linked as the leaf
     * itself, never dereferenced to its host target (see dev_shm_resolve_path).
     */
    if (old_tx.is_dev_shm)
        mac_flags &= ~AT_SYMLINK_FOLLOW;
    if (linkat(old_host_dirfd, old_tx.host_path, new_host_dirfd,
               new_tx.host_path, mac_flags) < 0) {
        /* Darwin's linkat(2) man page: without AT_SYMLINK_FOLLOW, hard-linking
         * a symlink itself (rather than its target) "may result in some file
         * systems returning an error" -- reproduced here as ENOTSUP on
         * Case-sensitive HFS+ (EPERM has also been reported on other
         * filesystems/macOS versions for the same condition), unlike APFS which
         * allows it. Linux allows it unconditionally, so recreate the same
         * effect with a plain symlink to the same target: a new directory entry
         * that resolves identically, even though it is a distinct inode rather
         * than a second link to the original.
         */
        if ((errno != EPERM && errno != ENOTSUP && errno != EINVAL) ||
            (flags & LINUX_AT_SYMLINK_FOLLOW)) {
            host_fd_ref_close(&olddir_ref);
            host_fd_ref_close(&newdir_ref);
            return linux_errno();
        }

        struct stat old_st;
        char target[LINUX_PATH_MAX];
        ssize_t target_len;
        if (fstatat(old_host_dirfd, old_tx.host_path, &old_st,
                    AT_SYMLINK_NOFOLLOW) < 0 ||
            !S_ISLNK(old_st.st_mode) ||
            (target_len = readlinkat(old_host_dirfd, old_tx.host_path, target,
                                     sizeof(target) - 1)) < 0) {
            host_fd_ref_close(&olddir_ref);
            host_fd_ref_close(&newdir_ref);
            return -LINUX_EPERM;
        }
        target[target_len] = '\0';

        if (symlinkat(target, new_host_dirfd, new_tx.host_path) < 0) {
            host_fd_ref_close(&olddir_ref);
            host_fd_ref_close(&newdir_ref);
            return linux_errno();
        }
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
        g, dirfd, path_gva, path_tr_nofollow(flags & LINUX_AT_SYMLINK_NOFOLLOW),
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
    int64_t ref_err = host_dirfd_ref_open(dirfd, &dir_ref);
    if (ref_err < 0)
        return ref_err;

    /* Check intercepted stat paths first since macOS has no /proc filesystem
     * and the sysfs CPU tree is synthetic. Access must reflect the synthetic
     * mode bits, not just path existence.
     */
    struct stat intercepted_st;
    if (path_might_use_stat_intercept(tx.intercept_path)) {
        int intercepted =
            proc_intercept_stat_at(tx.intercept_path, &intercepted_st,
                                   !(flags & LINUX_AT_SYMLINK_NOFOLLOW));
        if (intercepted == 0) {
            host_fd_ref_close(&dir_ref);
            if (path_check_intercept_access(&intercepted_st, mode, flags) < 0)
                return linux_errno();
            return 0;
        }

        /* An intercept that claimed the name and then failed is the answer.
         * Only PROC_NOT_INTERCEPTED means "ask the backing": treating the
         * failure as one too let access(2) answer OK from the host for a name
         * whose open and stat both said ENOENT, so the three disagreed about
         * the same path.
         */
        if (intercepted == -1) {
            host_fd_ref_close(&dir_ref);
            return linux_errno();
        }
    }

    int mac_flags =
        path_translation_at_flags(&tx, translate_faccessat_flags(flags));
    if (faccessat(path_translation_dirfd(&tx, &dir_ref), tx.host_path, mode,
                  mac_flags) < 0) {
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
    int64_t ref_err = host_fd_ref_open(fd, &host_ref);
    if (ref_err < 0)
        return ref_err;

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

    /* truncate(2) has no nofollow variant; reach the leaf via shm_open_leaf +
     * ftruncate.
     */
    if (tx.is_dev_shm) {
        int fd = shm_open_leaf(&tx, O_WRONLY);
        if (fd < 0) {
            /* A FIFO leaf yields ENXIO (O_NONBLOCK write-open, no reader);
             * Linux truncate(2) on a FIFO returns EINVAL, so match it.
             */
            if (errno == ENXIO)
                return -LINUX_EINVAL;
            return linux_errno();
        }
        if (ftruncate(fd, length) < 0) {
            close_keep_errno(fd);
            return linux_errno();
        }
        close(fd);
        return 0;
    }

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
    int64_t ref_err = host_fd_ref_open(fd, &host_ref);
    if (ref_err < 0)
        return ref_err;
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
    if (!validate_at_flags(flags,
                           LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH))
        return -LINUX_EINVAL;
    if (guest_read_str(g, path_gva, path, sizeof(path)) < 0)
        return -LINUX_EFAULT;

    /* AT_EMPTY_PATH with an empty path chmods dirfd itself; see the identical
     * branch in sys_fchownat above for the O_PATH/AT_FDCWD rationale. Neither
     * sub-case below goes through path_translate_at, so the FUSE and /proc
     * interception normally applied by reject_unsupported_fuse_path_op and
     * stat_at_path's proc_intercept_stat has to be checked by hand here.
     */
    if ((flags & LINUX_AT_EMPTY_PATH) && path[0] == '\0') {
        if (dirfd == LINUX_AT_FDCWD) {
            char fuse_buf[LINUX_PATH_MAX];
            int fuse_rc = fuse_resolve_at_path(LINUX_AT_FDCWD, ".", fuse_buf,
                                               sizeof(fuse_buf));
            if (fuse_rc < 0)
                return linux_errno();
            if (fuse_rc > 0)
                return -LINUX_ENOSYS;
            if (fchmodat(AT_FDCWD, ".", mode, translate_at_flags(flags)) < 0)
                return linux_errno();
            return 0;
        }

        fd_entry_t snap;
        if (!fd_snapshot(dirfd, &snap))
            return -LINUX_EBADF;
        if (snap.type == FD_FUSE_DEV || snap.type == FD_FUSE_FILE ||
            snap.type == FD_FUSE_DIR)
            return -LINUX_ENOSYS;
        if (snap.type == FD_PATH && snap.proc_path[0] != '\0')
            return -LINUX_EPERM;

        host_fd_ref_t ref;
        int64_t ref_err = host_dirfd_ref_open(dirfd, &ref);
        if (ref_err < 0)
            return ref_err;
        if (fchmod(ref.fd, mode) < 0) {
            host_fd_ref_close(&ref);
            return linux_errno();
        }
        host_fd_ref_close(&ref);
        return 0;
    }

    /* An fd magic link names the descriptor's file, and Linux resolves it
     * inside the syscall. Act on the descriptor so nothing can redirect the
     * chmod between resolution and use; see path_fd_magiclink_open().
     */
    if (!(flags & LINUX_AT_SYMLINK_NOFOLLOW)) {
        host_fd_ref_t magic;
        if (path_fd_magiclink_open(path, &magic) == 0) {
            int mrc = fchmod(magic.fd, mode);
            host_fd_ref_close(&magic);
            return mrc < 0 ? linux_errno() : 0;
        }
    }

    path_translation_t tx;
    if (path_translate_at(dirfd, path,
                          path_tr_nofollow(flags & LINUX_AT_SYMLINK_NOFOLLOW),
                          &tx) < 0)
        return linux_errno();
    int64_t rc = reject_unsupported_fuse_path_op(&tx);
    if (rc != INT64_MIN)
        return rc;

    /* A pty slave has no host file to chmod -- its mode comes from the pty
     * layer. Passing this through would hit the host and fail with ENOENT,
     * which is what grantpt(3) does when it decides the slave's mode needs
     * adjusting: it would then fall back to the pt_chown helper and fail.
     *
     * The requested mode is accepted but not retained, so a later stat still
     * reports the 0620 the pty layer synthesizes. grantpt only ever asks for
     * the owner-access bits it is about to hand out, so nothing observes the
     * difference; keeping it would need per-slave state that also has to cross
     * the fork-IPC boundary.
     */
    if (proc_pty_slave_stat(tx.intercept_path, NULL))
        return 0;

    host_fd_ref_t dir_ref;
    int64_t ref_err = host_dirfd_ref_open(dirfd, &dir_ref);
    if (ref_err < 0)
        return ref_err;

    int mac_flags = path_translation_at_flags(&tx, translate_at_flags(flags));
    if (fchmodat(path_translation_dirfd(&tx, &dir_ref), tx.host_path, mode,
                 mac_flags) < 0) {
        host_fd_ref_close(&dir_ref);
        return linux_errno();
    }

    host_fd_ref_close(&dir_ref);
    return 0;
}

/* Update the virtual-owner overlay for the file the chown call just touched.
 * host_rc is the return value of fchown/fchownat, host_st is a fresh stat of
 * the same file (NULL if the host stat failed: the file is gone and an empty
 * entry would not survive a follow-up access anyway).
 *
 * Maps a host EPERM to no-op success because macOS only lets the superuser
 * chown to an arbitrary uid/gid, but an emulated-root guest expects chown(2) to
 * succeed. The overlay then ensures the next stat round-trip returns the value
 * the guest intended.
 *
 * The success and EPERM cases share the same update so a partial chown (e.g.
 * owner=-1) preserves the prior override for the field the caller did not
 * touch, even when the host actually changed the other field.
 */
static int64_t chown_result(int host_rc,
                            const struct stat *host_st,
                            uint32_t owner,
                            uint32_t group)
{
    if (host_rc < 0 && errno != EPERM)
        return linux_errno();
    if (host_st) {
        /* cur_uid/cur_gid must be the owner the guest *currently sees*, not the
         * raw host stat values. The two differ on macOS where the host user UID
         * (e.g. 501) does not match GUEST_UID (1000), and whenever the file
         * already has an overlay entry that virtualises its owner.
         * chown_overlay_set uses cur_uid/cur_gid for both the early-exit no-op
         * guard and the stale-entry removal guard; passing the physical UID
         * evaluates those guards in the wrong ID namespace.
         *
         * Apply the existing overlay to a temporary copy of the host stat to
         * obtain the guest-visible owner before forwarding to
         * chown_overlay_set.
         */
        struct stat guest_st = *host_st;
        chown_overlay_apply(&guest_st);
        if (chown_overlay_set((uint64_t) host_st->st_dev,
                              (uint64_t) host_st->st_ino, owner, group,
                              guest_st.st_uid, guest_st.st_gid) < 0) {
            /* Override allocation failed; reporting success would lie about the
             * post-call stat round-trip. Linux's chown(2) lists ENOMEM among
             * its possible errors for related allocation paths, so surface that
             * to the guest instead.
             */
            return -LINUX_ENOMEM;
        }
    }
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
    if (!validate_at_flags(flags,
                           LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH))
        return -LINUX_EINVAL;
    if (guest_read_str(g, path_gva, path, sizeof(path)) < 0)
        return -LINUX_EFAULT;

    /* AT_EMPTY_PATH with an empty path chowns dirfd itself rather than a name
     * beneath it. This is the only way to chown an O_PATH fd (plain fchown()
     * rejects FD_PATH, matching Linux's EBADF there), so unlike the other *at()
     * flag validation here it has to actually be handled, not just accepted.
     * dirfd == AT_FDCWD resolves to the current directory, mirroring
     * stat_at_path's identical AT_EMPTY_PATH branch in fs-stat.c. Neither
     * sub-case below goes through path_translate_at, so FUSE and /proc
     * interception has to be checked by hand, same as sys_fchmodat above.
     */
    if ((flags & LINUX_AT_EMPTY_PATH) && path[0] == '\0') {
        if (dirfd == LINUX_AT_FDCWD) {
            char fuse_buf[LINUX_PATH_MAX];
            int fuse_rc = fuse_resolve_at_path(LINUX_AT_FDCWD, ".", fuse_buf,
                                               sizeof(fuse_buf));
            if (fuse_rc < 0)
                return linux_errno();
            if (fuse_rc > 0)
                return -LINUX_ENOSYS;

            /* Open "." once so fchown and the follow-up stat operate on the
             * same descriptor. Resolving "." twice (fchownat then fstatat)
             * would let a concurrent chdir() on another thread of this guest
             * record the overlay against a different directory's dev/ino.
             */
            int fd = open(".", O_RDONLY);
            if (fd < 0)
                return linux_errno();
            int host_rc = fchown(fd, owner, group);
            int saved_errno = errno;
            struct stat host_st;
            const struct stat *st_ptr =
                fstat(fd, &host_st) == 0 ? &host_st : NULL;
            errno = saved_errno;
            int64_t out = chown_result(host_rc, st_ptr, owner, group);
            close_keep_errno(fd);
            return out;
        }

        fd_entry_t snap;
        if (!fd_snapshot(dirfd, &snap))
            return -LINUX_EBADF;
        if (snap.type == FD_FUSE_DEV || snap.type == FD_FUSE_FILE ||
            snap.type == FD_FUSE_DIR)
            return -LINUX_ENOSYS;
        if (snap.type == FD_PATH && snap.proc_path[0] != '\0')
            return -LINUX_EPERM;

        host_fd_ref_t ref;
        int64_t ref_err = host_dirfd_ref_open(dirfd, &ref);
        if (ref_err < 0)
            return ref_err;

        int host_rc = fchown(ref.fd, owner, group);
        int saved_errno = errno;
        struct stat host_st;
        const struct stat *st_ptr =
            fstat(ref.fd, &host_st) == 0 ? &host_st : NULL;
        errno = saved_errno;
        int64_t out = chown_result(host_rc, st_ptr, owner, group);
        host_fd_ref_close(&ref);
        return out;
    }

    /* Same reasoning as the fd magic link branch in sys_fchmodat: act on the
     * descriptor, not on a pathname resolved from it a moment earlier.
     */
    if (!(flags & LINUX_AT_SYMLINK_NOFOLLOW)) {
        host_fd_ref_t magic;
        if (path_fd_magiclink_open(path, &magic) == 0) {
            int host_rc = fchown(magic.fd, owner, group);
            int saved_errno = errno;
            struct stat host_st;
            const struct stat *st_ptr =
                fstat(magic.fd, &host_st) == 0 ? &host_st : NULL;
            errno = saved_errno;
            int64_t out = chown_result(host_rc, st_ptr, owner, group);
            host_fd_ref_close(&magic);
            return out;
        }
    }

    path_translation_t tx;
    if (path_translate_at(dirfd, path,
                          path_tr_nofollow(flags & LINUX_AT_SYMLINK_NOFOLLOW),
                          &tx) < 0)
        return linux_errno();
    int64_t rc = reject_unsupported_fuse_path_op(&tx);
    if (rc != INT64_MIN)
        return rc;

    /* A pty slave has no host file to chown -- its owner comes from the pty
     * layer. Accept only a request that leaves the reported owner alone;
     * anything else would have to be remembered to be observable, so refuse
     * rather than report a success the next stat() contradicts.
     *
     * Not for grantpt(3): the synthesized stat already reports proc_get_uid(),
     * so glibc's "chown only when st_uid != getuid()" test is false by
     * construction and musl's grantpt is a no-op. This exists so that a request
     * naming some other owner is refused instead of silently lost. The known
     * divergence is a privileged guest -- login(1) or sshd handing a tty to a
     * user -- which Linux would allow and which is refused here, because
     * reporting success without retaining the owner would be the worse lie.
     */
    struct stat pty_st;
    if (proc_pty_slave_stat(tx.intercept_path, &pty_st)) {
        bool keeps_owner =
            owner == (uint32_t) -1 || owner == (uint32_t) pty_st.st_uid;
        bool keeps_group =
            group == (uint32_t) -1 || group == (uint32_t) pty_st.st_gid;
        return (keeps_owner && keeps_group) ? 0 : -LINUX_EPERM;
    }

    host_fd_ref_t dir_ref;
    int64_t ref_err = host_dirfd_ref_open(dirfd, &dir_ref);
    if (ref_err < 0)
        return ref_err;

    int mac_flags = path_translation_at_flags(&tx, translate_at_flags(flags));
    host_fd_t host_dirfd = path_translation_dirfd(&tx, &dir_ref);
    struct stat before_st;
    bool before_ok =
        fstatat(host_dirfd, tx.host_path, &before_st, mac_flags) == 0;

    int host_rc = fchownat(host_dirfd, tx.host_path, owner, group, mac_flags);
    int saved_errno = errno;

    struct stat after_st;
    const struct stat *st_ptr = NULL;
    if (fstatat(dir_ref.fd, tx.host_path, &after_st, mac_flags) == 0 &&
        before_ok && same_stat_identity(&before_st, &after_st)) {
        st_ptr = &after_st;
    }

    errno = saved_errno;
    int64_t out;
    if (host_rc < 0 && saved_errno == EPERM && !st_ptr) {
        /* fchownat does not give us a stable handle to the object it checked.
         * If the path was replaced while the host syscall was in flight, a
         * post-call stat could attach the virtual owner to the replacement
         * inode. Refuse the fakeroot success in that race instead.
         */
        out = -LINUX_EAGAIN;
    } else {
        out = chown_result(host_rc, st_ptr, owner, group);
    }
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
    int64_t ref_err = host_fd_ref_open(fd, &host_ref);
    if (ref_err < 0)
        return ref_err;

    int host_rc = fchown(host_ref.fd, owner, group);
    int saved_errno = errno;

    struct stat host_st;
    const struct stat *st_ptr = NULL;
    if (fstat(host_ref.fd, &host_st) == 0)
        st_ptr = &host_st;

    errno = saved_errno;
    int64_t out = chown_result(host_rc, st_ptr, owner, group);
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
    int64_t ref_err = host_dirfd_ref_open(dirfd, &dir_ref);
    if (ref_err < 0)
        return ref_err;

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

        /* Same reasoning as the fd magic link branch in sys_fchmodat: act on
         * the descriptor, not on a pathname resolved from it a moment earlier.
         */
        if (!(flags & LINUX_AT_SYMLINK_NOFOLLOW)) {
            host_fd_ref_t magic;
            if (path_fd_magiclink_open(path, &magic) == 0) {
                int mrc = futimens(magic.fd, times_gva ? ts : NULL);
                host_fd_ref_close(&magic);
                host_fd_ref_close(&dir_ref);
                return mrc < 0 ? linux_errno() : 0;
            }
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
        mac_flags = path_translation_at_flags(&tx, mac_flags);
        if (utimensat(path_translation_dirfd(&tx, &dir_ref), path_arg,
                      times_gva ? ts : NULL, mac_flags) < 0) {
            host_fd_ref_close(&dir_ref);
            return linux_errno();
        }
    }

    host_fd_ref_close(&dir_ref);
    return 0;
}
