/*
 * Linux inotify emulation via kqueue EVFILT_VNODE for elfuse
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Maps inotify operations to macOS kqueue:
 *   inotify_init1()     -> kqueue() + self-pipe for poll/epoll readability
 *   inotify_add_watch() -> open(O_EVTONLY) + kevent(EVFILT_VNODE, EV_ADD)
 *   inotify_rm_watch()  -> kevent(EV_DELETE) + close(host_fd)
 *   read()              -> kevent() poll + translate NOTE_* -> IN_* events
 *
 * Limitations (acceptable for MVP):
 *   - Directory watches detect changes (via NOTE_WRITE) but cannot always
 *     determine the specific filename; events may lack the name field
 *   - Cookie-based rename correlation (IN_MOVED_FROM/IN_MOVED_TO) not
 *     implemented. Rename produces IN_MOVE_SELF instead
 *   - No recursive watching (IN_ISDIR with subdirectories)
 *   - kqueue coalesces events per-fd naturally (EV_CLEAR), matching
 *     inotify's standard event coalescing
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <dirent.h>
#include <stdlib.h>
#include <poll.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include "utils.h"

#include "syscall/linux-wire.h"
#include "syscall/inotify.h"
#include "syscall/internal.h"
#include "syscall/io.h" /* io_wait_fd_or_interrupted */
#include "syscall/path.h"
#include "syscall/proc.h" /* proc_exit_group_requested */

static void inotify_close(int guest_fd, uint64_t generation);

/* Linux inotify constants (from linux/inotify.h). Only the bits emulation
 * actually emits or recognizes are listed; the remaining inotify events
 * (IN_ACCESS, IN_OPEN, IN_CLOSE_NOWRITE, IN_MOVED_FROM, IN_MOVED_TO) cannot be
 * derived from EVFILT_VNODE notifications, so emulation never sets them.
 */
#define IN_MODIFY 0x00000002
#define IN_ATTRIB 0x00000004
#define IN_CLOSE_WRITE 0x00000008
#define IN_CREATE 0x00000100
#define IN_DELETE 0x00000200
#define IN_DELETE_SELF 0x00000400
#define IN_MOVE_SELF 0x00000800
/* Same value as IN_MOVE_SELF, but used only by inotify_init1(). */
#define IN_NONBLOCK 0x00000800
/* Same as O_CLOEXEC on aarch64. */
#define IN_CLOEXEC 0x00080000
#define IN_Q_OVERFLOW 0x00004000
/* OR new events into existing mask. */
#define IN_MASK_ADD 0x20000000

/* Linux struct inotify_event layout:
 *   int32_t  wd;      watch descriptor
 *   uint32_t mask;     event mask
 *   uint32_t cookie;   rename correlation cookie
 *   uint32_t len;      length of name (incl. NUL + padding)
 *   char     name[];   optional filename (NUL-terminated, padded)
 */
#define INOTIFY_EVENT_HEADER_SIZE 16 /* wd + mask + cookie + len */

/* Internal data structures. */

#define INOTIFY_MAX 16       /* Max inotify instances */
#define INOTIFY_WATCHES 64   /* Max watches per instance */
#define INOTIFY_BUFSIZE 4096 /* Internal event buffer size */

typedef struct {
    int wd;        /* Watch descriptor (1-based, 0 = unused) */
    int host_fd;   /* Open fd to the watched path (O_EVTONLY) */
    uint32_t mask; /* Subscribed IN_* events */
    bool is_dir;   /* true if watching a directory */
    dev_t dev;     /* Device ID (for re-add lookup by inode) */
    ino_t ino;     /* Inode number (for re-add lookup by inode) */
    /* Dir watches only: entry-name snapshot, diffed on each change to recover
     * the child name kqueue omits. NULL/0 for file watches.
     */
    char **entries;
    int n_entries;
} inotify_watch_t;

typedef struct {
    int guest_fd;   /* -1 if slot is unused */
    uint64_t gen;   /* fd generation fd_alloc stamped on guest_fd */
    int kq_fd;      /* kqueue fd */
    int pipe_rd;    /* Self-pipe read end (poll/epoll) */
    int pipe_wr;    /* Self-pipe write end */
    int wd_counter; /* Next WD to allocate (1-based) */
    inotify_watch_t watches[INOTIFY_WATCHES]; /* Watch table */
    uint8_t event_buf[INOTIFY_BUFSIZE];       /* Queued inotify events */
    size_t event_used;                        /* Bytes used in event_buf */
} inotify_instance_t;

static inotify_instance_t inotify_state[INOTIFY_MAX];

/* Mutex protecting inotify_state[] for concurrent access. Two guest threads may
 * create/close/add-watch on different inotify instances simultaneously. Lock
 * order: 7 (after pid_lock).
 */
static pthread_mutex_t inotify_lock = PTHREAD_MUTEX_INITIALIZER;

/* Init / lookup helpers. */

void inotify_init(void)
{
    for (int i = 0; i < INOTIFY_MAX; i++)
        inotify_state[i].guest_fd = -1;
    fd_register_cleanup(FD_INOTIFY, inotify_close);
}

/* The instance of the fd that carries @gen, or -1: a dup carries inotify_close
 * and no instance. A lookup by fd number could answer with the instance of a
 * closed fd, since fd_cleanup_entry runs inotify_close after the number is free
 * and another fd can hold it by then. A caller other than inotify_close takes
 * @gen from fd_current_generation before inotify_lock, which orders after
 * fd_lock.
 */
static int inotify_find_gen(uint64_t gen)
{
    for (int i = 0; i < INOTIFY_MAX; i++) {
        if (inotify_state[i].guest_fd >= 0 && inotify_state[i].gen == gen)
            return i;
    }
    return -1;
}

static int inotify_slot_alloc(void)
{
    for (int i = 0; i < INOTIFY_MAX; i++)
        if (inotify_state[i].guest_fd == -1)
            return i;
    return -1;
}

/* Find a watch by WD within an instance. Returns index or -1. */
static int watch_find(inotify_instance_t *inst, int wd)
{
    for (int i = 0; i < INOTIFY_WATCHES; i++)
        if (inst->watches[i].wd == wd)
            return i;
    return -1;
}

/* Find a watch by host_fd (for kevent udata matching). Returns index or -1. */
static int watch_find_by_hostfd(inotify_instance_t *inst, int host_fd)
{
    for (int i = 0; i < INOTIFY_WATCHES; i++)
        if (inst->watches[i].wd != 0 && inst->watches[i].host_fd == host_fd)
            return i;
    return -1;
}

/* Find a watch by device/inode (for re-add lookup). Returns index or -1. */
static int watch_find_by_devino(inotify_instance_t *inst, dev_t dev, ino_t ino)
{
    for (int i = 0; i < INOTIFY_WATCHES; i++)
        if (inst->watches[i].wd != 0 && inst->watches[i].dev == dev &&
            inst->watches[i].ino == ino)
            return i;
    return -1;
}

/* Allocate a free watch slot. Returns index or -1. */
static int watch_slot_alloc(inotify_instance_t *inst)
{
    for (int i = 0; i < INOTIFY_WATCHES; i++)
        if (inst->watches[i].wd == 0)
            return i;
    return -1;
}

/* Event translation. */

/* Convert Linux IN_* mask to kqueue NOTE_* flags for EVFILT_VNODE. Not all IN_*
 * events have kqueue equivalents.
 */
static uint32_t in_mask_to_notes(uint32_t mask)
{
    uint32_t notes = 0;
    if (mask & (IN_MODIFY | IN_CLOSE_WRITE))
        notes |= NOTE_WRITE;
    if (mask & IN_ATTRIB)
        notes |= NOTE_ATTRIB;
    if (mask & IN_DELETE_SELF)
        notes |= NOTE_DELETE;
    if (mask & IN_MOVE_SELF)
        notes |= NOTE_RENAME;
    /* NOTE_EXTEND covers file growth, map to IN_MODIFY */
    if (mask & IN_MODIFY)
        notes |= NOTE_EXTEND;
    /* NOTE_LINK covers hard link count changes */
    if (mask & (IN_CREATE | IN_DELETE))
        notes |= NOTE_LINK | NOTE_WRITE;
    return notes;
}

/* Convert kqueue NOTE_* fflags to Linux IN_* mask. The watch's subscribed mask
 * filters which events are actually reported.
 */
static uint32_t notes_to_in_mask(uint32_t fflags,
                                 uint32_t subscribed,
                                 int is_dir)
{
    uint32_t mask = 0;

    if (fflags & NOTE_WRITE) {
        if (is_dir) {
            /* Directory write = something was created/deleted inside. Report as
             * IN_CREATE|IN_DELETE since inotify emulation cannot distinguish.
             */
            if (subscribed & IN_CREATE)
                mask |= IN_CREATE;
            if (subscribed & IN_DELETE)
                mask |= IN_DELETE;
            if (subscribed & IN_MODIFY)
                mask |= IN_MODIFY;
        } else {
            mask |= IN_MODIFY;
        }
    }
    if (fflags & NOTE_EXTEND)
        mask |= IN_MODIFY;
    if (fflags & NOTE_ATTRIB)
        mask |= IN_ATTRIB;
    if (fflags & NOTE_DELETE)
        mask |= IN_DELETE_SELF;
    if (fflags & NOTE_RENAME)
        mask |= IN_MOVE_SELF;
    if (fflags & NOTE_REVOKE)
        mask |= IN_DELETE_SELF; /* Unmount -> treat as deletion */
    if (fflags & NOTE_LINK) {
        if (is_dir && (subscribed & (IN_CREATE | IN_DELETE)))
            mask |= (subscribed & (IN_CREATE | IN_DELETE));
    }

    /* Only report events the watch actually subscribed to */
    return mask & subscribed;
}

/* Queue a single inotify event into the instance's buffer. name may be NULL (no
 * filename); directory watches recover the child name via snapshot diffing and
 * pass it here, so the event carries a NUL-terminated, 4-byte-padded name.
 *
 * Returns 0 on success, -1 if full.
 */
static int queue_event(inotify_instance_t *inst,
                       int wd,
                       uint32_t mask,
                       uint32_t cookie,
                       const char *name)
{
    /* Calculate event size: header + name length (NUL + padding to 4) */
    uint32_t name_len = 0;
    if (name && name[0]) {
        size_t raw = strlen(name) + 1;           /* Include NUL */
        name_len = (uint32_t) ((raw + 3) & ~3U); /* Pad to 4-byte boundary */
    }
    size_t event_size = INOTIFY_EVENT_HEADER_SIZE + name_len;

    if (inst->event_used + event_size > INOTIFY_BUFSIZE)
        return -1; /* Drop event when the fixed inotify queue is full. */

    uint8_t *p = inst->event_buf + inst->event_used;

    /* Write header fields (little-endian, matching aarch64) */
    int32_t wd32 = (int32_t) wd;
    memcpy(p + 0, &wd32, 4);
    memcpy(p + 4, &mask, 4);
    memcpy(p + 8, &cookie, 4);
    memcpy(p + 12, &name_len, 4);

    /* Write name if present (zero-padded) */
    if (name_len > 0) {
        memset(p + INOTIFY_EVENT_HEADER_SIZE, 0, name_len);
        memcpy(p + INOTIFY_EVENT_HEADER_SIZE, name, strlen(name));
    }

    inst->event_used += event_size;
    return 0;
}

/* Signal the self-pipe so poll/epoll sees readability. */
static void pipe_signal(inotify_instance_t *inst)
{
    uint8_t byte = 1;
    write(inst->pipe_wr, &byte, 1);
}

/* Drain the self-pipe to reset readability. The pipe is O_NONBLOCK so the loop
 * terminates on EAGAIN. readv is used in place of read to bypass clang's
 * unix.BlockInCriticalSection checker, which flags read() while a pthread mutex
 * is held even though a non-blocking pipe drain cannot stall.
 */
static void pipe_drain(inotify_instance_t *inst)
{
    uint8_t drain;
    struct iovec iov = {.iov_base = &drain, .iov_len = 1};
    while (readv(inst->pipe_rd, &iov, 1) > 0)
        ;
}

static void free_dir_snapshot(char **entries, int n)
{
    if (!entries)
        return;
    for (int i = 0; i < n; i++)
        free(entries[i]);
    free(entries);
}

/* List a directory's child names, excluding "." and "..", into the out array
 * (free with free_dir_snapshot).
 *
 * Returns false on any failure, leaving the result empty -- which the caller
 * must treat as distinct from a true return with zero entries, since a failure
 * mistaken for "empty" would diff every known child as deleted.
 *
 * The directory is re-opened via the watched fd (openat "."), not a stored
 * pathname: an O_EVTONLY fd follows the inode across renames, so the diff
 * always reads the directory the watch is registered for even after the path it
 * was added under moves or is replaced by an unrelated inode.
 */
static bool dir_snapshot_fd(int dirfd, char ***out, int *n_out)
{
    *out = NULL;
    *n_out = 0;

    int fd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return false;

    /* The snapshot answers the same per-directory ownership question getdents64
     * asks, from the host fd it already holds (before fdopendir takes
     * ownership), so a watch on a directory outside the sysroot carries entry
     * names as they are stored.
     */
    const bool dir_holds_escapes = path_dirent_dir_holds_escapes(fd);
    DIR *d = fdopendir(fd);
    if (!d) {
        close(fd);
        return false;
    }

    char **names = NULL;
    int n = 0, cap = 0;
    bool ok = true;
    for (;;) {
        /* readdir returns NULL both at end-of-stream and on error; reset errno
         * immediately before each call so a non-zero errno afterwards
         * unambiguously signals a read error rather than EOF.
         */
        errno = 0;
        struct dirent *de = readdir(d);
        if (!de) {
            if (errno != 0)
                ok = false;
            break;
        }
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;

        /* Snapshots feed named IN_CREATE/IN_DELETE events, so they carry
         * guest-visible names: the same per-name decode getdents64 applies,
         * through the same choke point. An over-long name is skipped exactly as
         * getdents64 skips it (unrepresentable in an event's name field too),
         * and any other failure keeps the previous baseline rather than diffing
         * every decoded child as deleted.
         */
        char guest_name[NAME_MAX + 1];
        if (path_translate_dirent_name(dir_holds_escapes, de->d_name,
                                       guest_name, sizeof(guest_name)) < 0) {
            if (errno == ENAMETOOLONG)
                continue;
            ok = false;
            break;
        }
        if (n == cap) {
            int ncap = cap ? cap * 2 : 16;
            char **tmp = realloc(names, (size_t) ncap * sizeof(char *));
            if (!tmp) {
                ok = false;
                break;
            }
            names = tmp;
            cap = ncap;
        }
        names[n] = strdup(guest_name);
        if (!names[n]) {
            ok = false;
            break;
        }
        n++;
    }
    closedir(d);

    if (!ok) {
        free_dir_snapshot(names, n);
        return false;
    }

    *out = names;
    *n_out = n;
    return true;
}

static bool snapshot_contains(char *const *entries, int n, const char *name)
{
    for (int i = 0; i < n; i++)
        if (!strcmp(entries[i], name))
            return true;
    return false;
}

/* Collect events from kqueue. */

/* Translate one EVFILT_VNODE notification into queued inotify events for the
 * watch on host_fd.
 *
 * Returns the number queued, or -1 on buffer overflow (an IN_Q_OVERFLOW marker
 * is queued).
 *
 * Caller holds inotify_lock; it is held again on return. For a directory write
 * the lock is released around the openat/readdir snapshot so filesystem I/O
 * does not stall inotify operations on other instances. @gen identifies this
 * instance: because the table can change while unlocked, the instance and the
 * watch are re-validated (by host_fd and dev/ino) before the snapshot is
 * applied, and a teardown or host_fd reuse during the window discards it.
 */
static int process_vnode_event(inotify_instance_t *inst,
                               uint64_t gen,
                               int host_fd,
                               uint32_t fflags)
{
    int widx = watch_find_by_hostfd(inst, host_fd);
    if (widx < 0)
        return 0;

    inotify_watch_t *w = &inst->watches[widx];
    int queued = 0;
    bool overflow = false;

    char **now = NULL;
    int now_n = 0;
    bool snap_ok = false;

    if (w->is_dir && (fflags & NOTE_WRITE)) {
        /* Dup the watched fd under the lock, then release it for the openat/
         * readdir snapshot so filesystem I/O does not block other instances.
         * The dup pins the watched inode: even if the watch is removed and its
         * host_fd closed and recycled during the unlocked window, the snapshot
         * still reads the original directory.
         */
        int dupfd = dup(w->host_fd);
        if (dupfd >= 0) {
            dev_t dev = w->dev;
            ino_t ino = w->ino;
            int slot = (int) (inst - inotify_state);

            pthread_mutex_unlock(&inotify_lock);
            snap_ok = dir_snapshot_fd(dupfd, &now, &now_n);
            close(dupfd);
            pthread_mutex_lock(&inotify_lock);

            /* Re-validate across the unlocked window: the instance may have
             * been closed, or the watch removed and its host_fd reused for a
             * different file. Any of these discards the stale snapshot.
             */
            widx = watch_find_by_hostfd(inst, host_fd);
            if (inotify_find_gen(gen) != slot || widx < 0) {
                free_dir_snapshot(now, now_n);
                return 0;
            }
            w = &inst->watches[widx];
            if (!w->is_dir || w->dev != dev || w->ino != ino) {
                free_dir_snapshot(now, now_n);
                return 0;
            }
        }
    }

    if (snap_ok) {
        /* Only diff against -- and advance to -- a snapshot that succeeded. On
         * failure keep the previous baseline; the next successful snapshot
         * reconciles whatever changed in between.
         */
        for (int j = 0; j < now_n && !overflow; j++) {
            if ((w->mask & IN_CREATE) &&
                !snapshot_contains(w->entries, w->n_entries, now[j])) {
                if (queue_event(inst, w->wd, IN_CREATE, 0, now[j]) < 0)
                    overflow = true;
                else
                    queued++;
            }
        }
        for (int j = 0; j < w->n_entries && !overflow; j++) {
            if ((w->mask & IN_DELETE) &&
                !snapshot_contains(now, now_n, w->entries[j])) {
                if (queue_event(inst, w->wd, IN_DELETE, 0, w->entries[j]) < 0)
                    overflow = true;
                else
                    queued++;
            }
        }

        /* Advance the snapshot: the directory state has moved on, and any names
         * dropped under overflow are covered by IN_Q_OVERFLOW.
         */
        free_dir_snapshot(w->entries, w->n_entries);
        w->entries = now;
        w->n_entries = now_n;
    } else {
        /* File watch or failed snapshot: nothing to apply. free_dir_snapshot
         * tolerates the NULL result dir_snapshot_fd leaves on failure.
         */
        free_dir_snapshot(now, now_n);
    }

    if (!overflow) {
        uint32_t in_mask = notes_to_in_mask(fflags, w->mask, w->is_dir);

        /* A successful diff already emitted named IN_CREATE/IN_DELETE per
         * child, so strip those bits from the bare event. Only strip on
         * success: when the snapshot failed no named event was emitted, so keep
         * the bare (nameless) create/delete rather than dropping the change
         * entirely -- the next successful snapshot reconciles the names. Other
         * bits (e.g. IN_ATTRIB) always pass through.
         */
        if (w->is_dir && snap_ok)
            in_mask &= ~(uint32_t) (IN_CREATE | IN_DELETE);
        if (in_mask != 0) {
            if (queue_event(inst, w->wd, in_mask, 0, NULL) < 0)
                overflow = true;
            else
                queued++;
        }
    }

    if (overflow) {
        /* IN_Q_OVERFLOW uses wd=-1 per Linux semantics. */
        queue_event(inst, -1, IN_Q_OVERFLOW, 0, NULL);
        return -1;
    }
    return queued;
}

/* Poll the kqueue for pending vnode events and translate them into inotify
 * events in the instance buffer.
 *
 * Returns the number of events collected.
 */
static int collect_events(inotify_instance_t *inst)
{
    struct kevent kevs[16];
    struct timespec ts_zero = {0, 0};

    int nev = kevent(inst->kq_fd, NULL, 0, kevs, 16, &ts_zero);
    if (nev <= 0)
        return 0;

    /* process_vnode_event may release inotify_lock around directory I/O;
     * capture the instance identity to detect teardown across that window.
     */
    int slot = (int) (inst - inotify_state);
    uint64_t gen = inst->gen;

    int collected = 0;
    bool overflow = false;
    for (int i = 0; i < nev; i++) {
        int r = process_vnode_event(inst, gen, (int) kevs[i].ident,
                                    (uint32_t) kevs[i].fflags);
        if (r < 0) {
            overflow = true;
            break;
        }
        collected += r;
        if (inotify_find_gen(gen) != slot)
            return collected; /* instance closed during snapshot I/O */
    }

    /* Signal the self-pipe so poll/epoll sees readability */
    if ((collected > 0 || overflow) && inotify_find_gen(gen) == slot)
        pipe_signal(inst);

    return collected;
}

/* Public API. */

int64_t sys_inotify_init1(int flags)
{
    int kq = kqueue();
    if (kq < 0)
        return linux_errno();

    /* Create self-pipe for poll/epoll readiness */
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        close(kq);
        return linux_errno();
    }
    bool want_cloexec = (flags & IN_CLOEXEC) != 0;
    if (fd_set_nonblock(pipefd[0]) < 0 || fd_set_nonblock(pipefd[1]) < 0 ||
        (want_cloexec &&
         (fd_set_cloexec(pipefd[0]) < 0 || fd_set_cloexec(pipefd[1]) < 0 ||
          fd_set_cloexec(kq) < 0))) {
        close(kq);
        close(pipefd[0]);
        close(pipefd[1]);
        return linux_errno();
    }

    /* Allocate guest fd; pipe read end is the host_fd so poll/epoll works */
    uint64_t gen = 0;
    int gfd = fd_alloc_from(0, FD_INOTIFY, pipefd[0], inotify_close, &gen);
    if (gfd < 0) {
        close(kq);
        close(pipefd[0]);
        close(pipefd[1]);
        return -LINUX_EMFILE;
    }

    pthread_mutex_lock(&inotify_lock);
    int slot = inotify_slot_alloc();
    if (slot < 0) {
        pthread_mutex_unlock(&inotify_lock);
        fd_retire_published_gen(gfd, pipefd[0], gen);
        close(kq);
        close(pipefd[1]);
        return -LINUX_ENOMEM;
    }

    inotify_instance_t *inst = &inotify_state[slot];
    inst->guest_fd = gfd;
    inst->gen = gen;
    inst->kq_fd = kq;
    inst->pipe_rd = pipefd[0];
    inst->pipe_wr = pipefd[1];
    inst->wd_counter = 1; /* WDs are 1-based */
    inst->event_used = 0;
    memset(inst->watches, 0, sizeof(inst->watches));
    pthread_mutex_unlock(&inotify_lock);

    /* Linux opens the inotify inode O_RDONLY (anon_inode_getfd in
     * fs/notify/inotify/inotify_user.c), and O_NONBLOCK goes to the shadow
     * rather than the internal pipe, which stays nonblocking so the emulation
     * can do its own waiting.
     *
     * A close that arrived before the instance was registered found nothing to
     * tear down. The number no longer carries this generation then: the publish
     * writes nothing and the instance is retired here.
     */
    if (!fd_publish_linux_flags_gen(
            gfd,
            ((flags & IN_CLOEXEC) ? LINUX_O_CLOEXEC : 0) |
                ((flags & IN_NONBLOCK) ? LINUX_O_NONBLOCK : 0),
            gen))
        inotify_close(gfd, gen);

    return gfd;
}

int64_t sys_inotify_add_watch(guest_t *g,
                              int inotify_fd,
                              uint64_t path_gva,
                              uint32_t mask)
{
    /* Read path from guest memory (no lock needed since guest_read_str only
     * touches per-guest state, not inotify_state).
     */
    char path[LINUX_PATH_MAX];
    if (guest_read_str(g, path_gva, path, sizeof(path)) < 0)
        return -LINUX_EFAULT;

    /* Watches are backed by kqueue on a host fd, so an object elfuse answers
     * itself (with no host vnode behind it) cannot be watched at all. That is
     * exactly a FUSE node and a synthetic /proc file, and refusing those beats
     * watching an unrelated host path.
     *
     * Deliberately not gated on path_might_use_open_intercept: that predicate
     * is a "might" prefilter for the open path, true for every name beginning
     * "/dev" (four bytes, so "/development" too), for the sysfs CPU tree, and
     * for /etc/passwd whenever the sysroot carries no copy. Those all have a
     * real host vnode (a /dev/shm leaf is redirected to one by the block
     * above), and Linux grants a watch on each, so refusing them would trade
     * this handler's ENOENT-on-a-missing-path for a blanket ENOSYS.
     */
    path_translation_t tx;
    if (path_translate_at(LINUX_AT_FDCWD, path, PATH_TR_NONE, &tx) < 0)
        return linux_errno();
    if (tx.fuse_path || tx.proc_resolved != 0)
        return -LINUX_ENOSYS;

    /* Open the path for event monitoring. O_EVTONLY is macOS-specific: opens
     * for event notification only, does not prevent unmount or require read
     * access to the file contents.
     *
     * A shm leaf is opened nofollow on top of that. The guest may write a
     * symlink into the backing directory, and a watch that followed one would
     * report the existence of, and every change to, whatever it names. That
     * includes a host path is_guest_system_path() exists to keep the guest from
     * addressing at all. Linux follows here, but the redirect is elfuse's own
     * and every other consumer of a shm leaf departs the same way; see
     * dev_shm_resolve_path() in procemu.c.
     */
    int host_fd = open(tx.host_path,
                       tx.is_dev_shm ? (O_EVTONLY | O_NOFOLLOW) : O_EVTONLY);
    if (host_fd < 0)
        return linux_errno();

    /* Identify the file by dev/ino for re-add detection */
    struct stat st;
    if (fstat(host_fd, &st) < 0) {
        close(host_fd);
        return linux_errno();
    }
    bool is_dir = S_ISDIR(st.st_mode);

    /* Strip IN_MASK_ADD control flag before storing */
    uint32_t event_mask = mask & ~(uint32_t) IN_MASK_ADD;

    /* For directory watches, snapshot the current entries up-front (outside the
     * lock) so collect_events can diff on each change to emit named
     * IN_CREATE/IN_DELETE. Ownership moves to the watch slot on success; every
     * early-exit path below frees these.
     */
    char **wentries = NULL;
    int wn = 0;
    if (is_dir) {
        /* Best-effort: a failed listing starts the watch with an empty
         * baseline, which is the only state worth recording at add time.
         */
        (void) dir_snapshot_fd(host_fd, &wentries, &wn);
    }

    uint64_t gen = fd_current_generation(inotify_fd);
    pthread_mutex_lock(&inotify_lock);

    int slot = inotify_find_gen(gen);
    if (slot < 0) {
        pthread_mutex_unlock(&inotify_lock);
        close(host_fd);
        free_dir_snapshot(wentries, wn);
        return -LINUX_EBADF;
    }

    inotify_instance_t *inst = &inotify_state[slot];

    /* Linux inotify re-add semantics: if the same file (by dev/ino) is already
     * watched, update the existing watch's mask instead of creating a new one.
     * IN_MASK_ADD ORs new bits; without it, the mask is replaced entirely.
     *
     * Returns the existing wd.
     */
    int existing = watch_find_by_devino(inst, st.st_dev, st.st_ino);
    if (existing >= 0) {
        inotify_watch_t *w = &inst->watches[existing];
        if (mask & IN_MASK_ADD)
            w->mask |= event_mask;
        else
            w->mask = event_mask;
        int wd = w->wd, existing_host_fd = w->host_fd;
        int kq_fd = inst->kq_fd;
        uint32_t snapshot_mask = w->mask; /* Snapshot before unlock */
        pthread_mutex_unlock(&inotify_lock);

        /* Close the duplicate fd; inotify emulation keeps the original. The
         * existing watch keeps its snapshot; drop this call's copy.
         */
        close(host_fd);
        free_dir_snapshot(wentries, wn);

        /* Update kevent filter with the new mask (use snapshot -- w->mask may
         * be modified by another thread after unlock)
         */
        uint32_t notes = in_mask_to_notes(snapshot_mask);
        struct kevent kev;
        EV_SET(&kev, (uintptr_t) existing_host_fd, EVFILT_VNODE,
               EV_ADD | EV_CLEAR, notes, 0, NULL);
        kevent(kq_fd, &kev, 1, NULL, 0, NULL);

        return wd;
    }

    /* New watch; allocate a slot */
    int widx = watch_slot_alloc(inst);
    if (widx < 0) {
        pthread_mutex_unlock(&inotify_lock);
        close(host_fd);
        free_dir_snapshot(wentries, wn);
        return -LINUX_ENOSPC;
    }

    int wd = inst->wd_counter;
    if (inst->wd_counter >= INT_MAX)
        inst->wd_counter = 1; /* wrap safely, skip 0 */
    else
        inst->wd_counter++;
    inotify_watch_t *w = &inst->watches[widx];
    w->wd = wd;
    w->host_fd = host_fd;
    w->mask = event_mask;
    w->is_dir = is_dir;
    w->dev = st.st_dev;
    w->ino = st.st_ino;
    w->entries = wentries;
    w->n_entries = wn;

    /* Capture kq_fd while under lock */
    int kq_fd = inst->kq_fd;
    pthread_mutex_unlock(&inotify_lock);

    /* Register kevent with EVFILT_VNODE. EV_CLEAR makes it re-arm automatically
     * after each kevent() retrieval, matching inotify's continuous monitoring
     * behavior. kevent() is thread-safe; run outside the lock to avoid
     * blocking.
     */
    uint32_t notes = in_mask_to_notes(event_mask);
    struct kevent kev;
    EV_SET(&kev, (uintptr_t) host_fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, notes, 0,
           NULL);
    if (kevent(kq_fd, &kev, 1, NULL, 0, NULL) < 0) {
        int saved = errno;
        /* Roll back the watch slot */
        pthread_mutex_lock(&inotify_lock);
        w->wd = 0;
        w->host_fd = 0;
        free_dir_snapshot(w->entries, w->n_entries);
        w->entries = NULL;
        w->n_entries = 0;
        pthread_mutex_unlock(&inotify_lock);
        close(host_fd);
        errno = saved;
        return linux_errno();
    }

    return wd;
}

int64_t sys_inotify_rm_watch(int inotify_fd, int wd)
{
    uint64_t gen = fd_current_generation(inotify_fd);
    pthread_mutex_lock(&inotify_lock);

    int slot = inotify_find_gen(gen);
    if (slot < 0) {
        pthread_mutex_unlock(&inotify_lock);
        return -LINUX_EBADF;
    }

    inotify_instance_t *inst = &inotify_state[slot];
    int widx = watch_find(inst, wd);
    if (widx < 0) {
        pthread_mutex_unlock(&inotify_lock);
        return -LINUX_EINVAL;
    }

    inotify_watch_t *w = &inst->watches[widx];
    int host_fd = w->host_fd, kq_fd = inst->kq_fd;

    /* Clear the slot while holding the lock */
    w->wd = 0;
    w->host_fd = 0;
    w->mask = 0;
    w->is_dir = 0;
    free_dir_snapshot(w->entries, w->n_entries);
    w->entries = NULL;
    w->n_entries = 0;
    pthread_mutex_unlock(&inotify_lock);

    /* Remove from kqueue and close outside lock */
    struct kevent kev;
    EV_SET(&kev, (uintptr_t) host_fd, EVFILT_VNODE, EV_DELETE, 0, 0, NULL);
    kevent(kq_fd, &kev, 1, NULL, 0, NULL); /* Ignore error */
    close(host_fd);

    return 0;
}

int64_t inotify_read(int guest_fd, guest_t *g, uint64_t buf_gva, uint64_t count)
{
    /* Before inotify_lock: fd_block_state takes fd_lock, which orders ahead of
     * this one. The guest's O_NONBLOCK lives in the fd_table shadow because the
     * host fd behind an inotify fd is elfuse's own pipe.
     */
    fd_block_state_t st = fd_block_state(guest_fd);
    bool nonblock = st.guest_nonblock;
    uint64_t gen = st.generation;

    pthread_mutex_lock(&inotify_lock);
    int slot = inotify_find_gen(gen);
    if (slot < 0) {
        pthread_mutex_unlock(&inotify_lock);
        return -LINUX_EBADF;
    }

    inotify_instance_t *inst = &inotify_state[slot];

    /* If no buffered events, poll kqueue for new ones */
    if (inst->event_used == 0) {
        collect_events(inst);

        /* collect_events may release the lock for directory I/O; bail if the
         * instance was closed in that window.
         */
        if (inotify_find_gen(gen) != slot) {
            pthread_mutex_unlock(&inotify_lock);
            return -LINUX_EBADF;
        }

        /* Nothing buffered: wait for an event rather than reporting one of the
         * two things a blocking inotify read cannot return. Linux blocks here
         * until a watch fires; the loop this replaced polled the kqueue 300
         * times at a second each and then answered EAGAIN, and a kevent that
         * woke with no event fell through to report EAGAIN as well.
         *
         * Looping on event_used rather than on the kevent result is what makes
         * that hold. A vnode event the watch mask filters out leaves the buffer
         * empty, and this thread has to go back to waiting exactly as it does
         * when it lost the readiness to a sibling.
         */
        while (inst->event_used == 0) {
            if (nonblock) {
                pthread_mutex_unlock(&inotify_lock);
                return -LINUX_EAGAIN;
            }

            /* The kqueue is pollable on macOS, so the shared wait covers it:
             * teardown and guest signals end this read on the same terms as
             * every other synthetic reader, and no vCPU parks in kevent.
             */
            int kq_fd = inst->kq_fd;
            pthread_mutex_unlock(&inotify_lock);

            int64_t waited = io_wait_fd_or_interrupted(kq_fd, POLLIN);
            if (waited < 0)
                return waited;

            struct kevent kev;
            struct timespec collect = {0, 0};
            int nev = kevent(kq_fd, NULL, 0, &kev, 1, &collect);
            if (nev < 0 && errno != EINTR)
                return linux_errno();

            /* Re-acquire lock and re-validate slot */
            pthread_mutex_lock(&inotify_lock);
            if (inotify_find_gen(gen) != slot) {
                pthread_mutex_unlock(&inotify_lock);
                return -LINUX_EBADF;
            }
            inst = &inotify_state[slot];

            /* No event to read after all: a sibling on this same inotify fd
             * took the one the wait reported. kev holds nothing, so wait again
             * rather than decoding it.
             */
            if (nev <= 0)
                continue;

            /* Process the received event (same named-directory diff as the
             * non-blocking collect path).
             */
            int host_fd = (int) kev.ident;
            int r =
                process_vnode_event(inst, gen, host_fd, (uint32_t) kev.fflags);

            /* process_vnode_event may release the lock for the snapshot; bail
             * if the instance was closed in that window.
             */
            if (inotify_find_gen(gen) != slot) {
                pthread_mutex_unlock(&inotify_lock);
                return -LINUX_EBADF;
            }
            if (r != 0)
                pipe_signal(inst);
        }
    }

    if (inst->event_used == 0) {
        pthread_mutex_unlock(&inotify_lock);
        return -LINUX_EAGAIN;
    }

    /* Copy buffered events to a local buffer under lock, then write to guest
     * after releasing the lock (guest_write does not need lock).
     */
    size_t copied = 0, pos = 0;

    /* First pass: compute how much the code can copy */
    while (pos < inst->event_used &&
           copied + INOTIFY_EVENT_HEADER_SIZE <= count) {
        uint32_t name_len;
        memcpy(&name_len, inst->event_buf + pos + 12, 4);
        size_t event_size = INOTIFY_EVENT_HEADER_SIZE + name_len;

        if (copied + event_size > count)
            break;

        copied += event_size;
        pos += event_size;
    }

    /* Copy event data to a local buffer (max 4KiB) */
    uint8_t local_buf[INOTIFY_BUFSIZE];
    if (copied > 0)
        memcpy(local_buf, inst->event_buf, copied);

    /* Compact remaining events in the instance buffer */
    if (pos > 0 && pos < inst->event_used) {
        memmove(inst->event_buf, inst->event_buf + pos, inst->event_used - pos);
        inst->event_used -= pos;
    } else if (pos >= inst->event_used) {
        inst->event_used = 0;
    }

    /* Drain self-pipe if buffer is now empty */
    if (inst->event_used == 0)
        pipe_drain(inst);

    pthread_mutex_unlock(&inotify_lock);

    /* Write to guest memory outside the lock */
    if (copied > 0) {
        if (guest_write_small(g, buf_gva, local_buf, copied) < 0)
            return -LINUX_EFAULT;
    }

    return (int64_t) copied;
}

static void inotify_close(int guest_fd, uint64_t generation)
{
    (void) guest_fd;
    pthread_mutex_lock(&inotify_lock);

    int slot = inotify_find_gen(generation);
    if (slot < 0) {
        pthread_mutex_unlock(&inotify_lock);
        return;
    }

    inotify_instance_t *inst = &inotify_state[slot];

    /* Snapshot state that needs cleanup, then mark slot free. This prevents
     * other threads from finding this instance.
     */
    int kq_fd = inst->kq_fd, pipe_wr = inst->pipe_wr;

    /* Collect watch host fds to close outside lock */
    int watch_fds[INOTIFY_WATCHES];
    int nfds = 0;
    for (int i = 0; i < INOTIFY_WATCHES; i++) {
        if (inst->watches[i].wd != 0) {
            watch_fds[nfds++] = inst->watches[i].host_fd;
            inst->watches[i].wd = 0;
        }
        free_dir_snapshot(inst->watches[i].entries, inst->watches[i].n_entries);
        inst->watches[i].entries = NULL;
        inst->watches[i].n_entries = 0;
    }

    inst->guest_fd = -1;
    inst->event_used = 0;
    pthread_mutex_unlock(&inotify_lock);

    /* Close all watch fds and remove from kqueue outside lock */
    for (int i = 0; i < nfds; i++) {
        struct kevent kev;
        EV_SET(&kev, (uintptr_t) watch_fds[i], EVFILT_VNODE, EV_DELETE, 0, 0,
               NULL);
        kevent(kq_fd, &kev, 1, NULL, 0, NULL);
        close(watch_fds[i]);
    }

    /* Close kqueue and pipe write end. pipe_rd is closed by sys_close() as the
     * host_fd.
     */
    close(kq_fd);
    close(pipe_wr);
}
