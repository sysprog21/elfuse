/*
 * FD table: bitmap allocator, alloc/close/snapshot helpers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * File descriptor table management for the guest. Uses a bitmap allocator for
 * O(1) lowest-free-FD lookup, with alloc/close/snapshot helpers that serialize
 * access through fd_lock.
 */

#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>

#include "utils.h"

#include "proved/fdset.h"

#include "core/shim-globals.h"
#include "runtime/procemu.h"
#include "syscall/linux-wire.h"
#include "syscall/asyncio.h"
#include "syscall/internal.h"
#include "syscall/poll.h"

/* Protects the FD table (fd_alloc, fd_alloc_at, fd_alloc_from, sys_close). File
 * descriptor operations from concurrent threads must be serialized.
 */
pthread_mutex_t fd_lock = PTHREAD_MUTEX_INITIALIZER; /* Lock order: 3 */

/* FD table. */
fd_entry_t fd_table[FD_TABLE_SIZE];
static uint64_t fd_next_generation = 1;
static uint64_t fd_next_ofd_id = 1;

struct fd_lifetime {
    _Atomic unsigned int refs;
    int host_fd;
    int type;

    /* FD_DIR only: the directory stream that owns host_fd. fdopendir() adopted
     * the descriptor and only closedir() releases it, so a pin on a directory
     * cannot close host_fd itself -- it holds a reference on the stream and
     * lets the stream's last release do it. NULL for every other type, which
     * closes host_fd directly.
     */
    void *dir;
};

/* RLIMIT_NOFILE tracking. Guest-side soft limit for RLIMIT_NOFILE. fd_alloc
 * checks this. Default matches typical Linux default (1024). Updated by
 * prlimit64.
 */
static _Atomic int rlimit_nofile_cur = FD_TABLE_SIZE;

void fd_set_rlimit_nofile(int cur)
{
    if (cur > FD_TABLE_SIZE)
        cur = FD_TABLE_SIZE;
    if (cur < 0)
        cur = 0;
    rlimit_nofile_cur = cur;
}

/* Bitmap for O(1) lowest-free-FD allocation. A set bit means the FD is free
 * (FD_CLOSED). bit_ctz64 on each word finds the lowest free FD in O(1) per
 * word, vs O(FD_TABLE_SIZE) linear scan.
 */
#define FD_BITMAP_WORDS (FD_TABLE_SIZE / 64)
static uint64_t fd_free_bitmap[FD_BITMAP_WORDS];

/* fd_bitmap_find_free leans on fdset_slot for both halves of its bound: that a
 * rejected minfd is one this table has no slot for, and that an accepted one
 * yields a word inside fd_free_bitmap. Neither holds if the proved bound and
 * this table stop describing the same range.
 */
_Static_assert(FDSET_MAX_FDS == FD_TABLE_SIZE,
               "the proved fd bound must be this table's bound");
_Static_assert(FD_BITMAP_WORDS == FDSET_MAX_WORDS,
               "the free-fd bitmap and the proved split must span the same "
               "number of words");

/* Callers own the range check: fd_bitmap_find_free hands back a bounded fd,
 * fd_mark_closed_unlocked's caller checks, and fdtable_init passes literals.
 * Checking here instead would guard the bitmap word while leaving the
 * fd_table[fd] write in fd_init_entry, one line later, just as exposed.
 *
 * Same shift and mask as the shim's inline bitmap test (see shim.S), and
 * unsigned for the same reason: on a signed fd the compiler has to bias the
 * value before dividing, for a negative case the callers rule out.
 */
static inline void fd_bitmap_set_free(int fd)
{
    fd_free_bitmap[(unsigned) fd >> 6] |= BIT64((unsigned) fd & 63);
}

static inline void fd_bitmap_set_used(int fd)
{
    fd_free_bitmap[(unsigned) fd >> 6] &= ~BIT64((unsigned) fd & 63);
}

/* A host read/write blocks only on non-regular, non-directory fds (pipe,
 * socket, fifo, char/tty). Callers cache this so the interruptible wait path
 * can skip fds that never block.
 */
static bool host_fd_may_block(int host_fd)
{
    struct stat st;
    return host_fd >= 0 && fstat(host_fd, &st) == 0 && !S_ISREG(st.st_mode) &&
           !S_ISDIR(st.st_mode);
}

/* Whether a read/write on a newly allocated fd of this type can block. Pipes
 * and sockets always can; regular-file slots may actually be a fifo or char
 * device (opened_fd_type does not split those out) and stdio may be a tty, so
 * both need an fstat; everything else (dir, path, urandom, fuse, synthetic)
 * never reaches the blocking wait path.
 *
 * Resolving the common pipe/socket/synthetic cases from the type keeps an fstat
 * off the fd-creation lock hold, but does not empty it: fd_init_entry still
 * takes O_NONBLOCK ownership with two fcntls in the same window. Measured
 * against a build that skips them, the whole cost of both is 4.4% of a
 * pipe()+close pair and 2.7% of an open()+close, so hoisting them out of the
 * lock was not done -- it would not remove the syscalls, only the lock hold,
 * and nothing measures a contended fd-creation path today.
 */
static bool type_may_block(int type, int host_fd)
{
    switch (type) {
    case FD_PIPE:
    case FD_SOCKET:
        return true;
    case FD_STDIO:
    case FD_REGULAR:
        return host_fd_may_block(host_fd);
    default:
        return false;
    }
}

/* The pending alias inheritance, handed from an fd_alloc_alias_* wrapper to the
 * fd_init_entry call it makes. Thread-local because the allocators take fd_lock
 * themselves and cannot take a parameter through it without changing all eight
 * signatures; private to this file because a caller that could set it directly
 * could also forget to clear it. Every wrapper below clears it on the way out,
 * including when the allocation fails.
 */
static _Thread_local bool fd_alias_pending;
static _Thread_local fd_alias_spec_t fd_alias_spec;

static void fd_alias_begin(const fd_alias_spec_t *spec)
{
    fd_alias_pending = spec != NULL;
    if (spec)
        fd_alias_spec = *spec;
}

static int fd_alias_end(int fd)
{
    fd_alias_pending = false;
    return fd;
}

/* The access mode Linux reports for an fd elfuse serves out of its own host
 * description. A synthetic fd is backed by a pipe or a kqueue elfuse opened, so
 * F_GETFL cannot ask the host what the guest opened; the answer is a property
 * of the type and belongs in one table rather than at each creation site. Three
 * types were missed when it was the creators' job, and each reported O_RDONLY
 * where Linux reports O_RDWR.
 *
 * A type absent from here answers from the host description, which is right for
 * regular files, directories, sockets and inherited stdio.
 */
static int fd_type_accmode(int type)
{
    switch (type) {
    case FD_EVENTFD:  /* anon_inode_getfd(O_RDWR), fs/eventfd.c */
    case FD_SIGNALFD: /* fs/signalfd.c */
    case FD_TIMERFD:  /* fs/timerfd.c */
    case FD_EPOLL:    /* fs/eventpoll.c */
    case FD_PIDFD:    /* kernel/pid.c */
    case FD_NETLINK:  /* a socket: O_RDWR */
        return LINUX_O_RDWR;
    case FD_INOTIFY: /* anon_inode_getfd(O_RDONLY), inotify_user.c */
        return LINUX_O_RDONLY;
    default:
        return -1;
    }
}

/* Status flags a creator wants to publish, with the type's access mode forced
 * back in. Publishing overwrites the field, so a creator that passes only its
 * CLOEXEC/NONBLOCK bits would otherwise erase the mode fd_init_entry seeded --
 * which is how three synthetic types came to report O_RDONLY.
 */
static int fd_flags_with_accmode(int type, int linux_flags)
{
    int accmode = fd_type_accmode(type);
    if (accmode < 0)
        return linux_flags;
    return (linux_flags & ~LINUX_O_ACCMODE) | accmode;
}

/* The two answers fd_init_entry needs from the host descriptor, taken before
 * fd_lock rather than under it.
 *
 * Both are host syscalls: type_may_block fstats a regular or stdio fd, and
 * fd_set_nonblock is an F_GETFL/F_SETFL pair. Holding the table lock across
 * them puts up to three host calls in front of every read, write and close that
 * wants the table, and the design note above fd_alloc says the lock is held for
 * table mutation only.
 *
 * Nothing races: the host fd is not published until fd_init_entry writes the
 * slot, so this thread is the only one that can see it. The alias state is
 * thread-local for the same reason, and an alias needs no probe at all -- it
 * shares a description whose flag the source already answers for.
 */
typedef struct {
    bool can_block;
    bool nonblock_owned;

    /* The host status flags to put back if no slot is published after all, or
     * -1 when the probe changed nothing. Taking the answers before the lock
     * means taking them before the allocation can fail, and the probe is not a
     * pure question: it sets O_NONBLOCK. A call that then returns EMFILE would
     * leave the caller's descriptor mutated by a function that did nothing
     * else, so the mutation is undone on the way out.
     */
    int restore_flags;
} fd_host_probe_t;

/* Put back what fd_probe_host changed, for a caller whose allocation failed. */
static void fd_probe_rollback(const fd_host_probe_t *probe, int host_fd)
{
    if (probe->restore_flags < 0)
        return;
    int saved_errno = errno;
    (void) fcntl(host_fd, F_SETFL, probe->restore_flags);
    errno = saved_errno;
}

static fd_host_probe_t fd_probe_host(int type, int host_fd)
{
    fd_host_probe_t probe = {.can_block = type_may_block(type, host_fd),
                             .restore_flags = -1};

    if (fd_alias_pending) {
        probe.nonblock_owned = fd_alias_spec.nonblock_owned;
        return probe;
    }

    bool foreign = (type == FD_STDIO);
    if (!probe.can_block || foreign)
        return probe;

    /* Remember the flags only when this call is the one adding O_NONBLOCK. A
     * descriptor that already carried it is left alone on rollback, since
     * putting back what was already there is not this function's to undo.
     */
    int old_flags = fcntl(host_fd, F_GETFL);
    probe.nonblock_owned = fd_set_nonblock(host_fd) >= 0;
    if (probe.nonblock_owned && old_flags >= 0 && !(old_flags & O_NONBLOCK))
        probe.restore_flags = old_flags;
    return probe;
}

static inline void fd_init_entry(int fd,
                                 int type,
                                 int host_fd,
                                 void (*cleanup)(int, uint64_t),
                                 const fd_host_probe_t *probe)
{
    fd_bitmap_set_used(fd);
    fd_table[fd].type = type;
    fd_table[fd].host_fd = host_fd;
    fd_table[fd].lifetime = NULL;

    /* Take the description state again, here, from the live source. The spec
     * carries a snapshot the caller made before this lock was held, and an
     * F_SETFL that lands in between sweeps the aliases that exist at that
     * moment -- which cannot include the one being built. Publishing from the
     * snapshot would leave the new name holding flags the rest of the
     * description has already moved past, for the life of the description, with
     * no generation change for a later check to notice.
     *
     * The generation is what makes this safe to do at all: a close+reopen in
     * the same window puts a different description behind the same number, and
     * copying from it would be worse than the staleness. When it has moved the
     * snapshot stands, which is exactly the behaviour this replaces.
     */
    if (fd_alias_pending && fd_alias_spec.src_guest_fd >= 0 &&
        RANGE_CHECK(fd_alias_spec.src_guest_fd, 0, FD_TABLE_SIZE)) {
        const fd_entry_t *src = &fd_table[fd_alias_spec.src_guest_fd];
        if (src->type != FD_CLOSED &&
            src->generation == fd_alias_spec.src_generation) {
            fd_alias_spec.ofd_id = src->ofd_id;

            /* Only the description's own bits. The caller may have ORed its own
             * on top of the snapshot -- a dup3 asking for CLOEXEC -- and those
             * belong to the new descriptor, not to the description, so a
             * wholesale overwrite would drop them.
             */
            fd_alias_spec.linux_flags =
                (fd_alias_spec.linux_flags & ~FD_DESCRIPTION_FLAGS) |
                (src->linux_flags & FD_DESCRIPTION_FLAGS);
            fd_alias_spec.foreign_description = src->foreign_description;
            fd_alias_spec.nonblock_owned = src->nonblock_owned;
            fd_alias_spec.path_poll_capable = src->path_poll_capable;
        }
    }

    /* An alias names the description it was made from. Installed here, inside
     * the same fd_lock window that publishes the slot, so there is no gap in
     * which the slot is visible with a fresh identity: a close+reopen in such a
     * gap would take the alias's ofd_id and be swept as though it shared a
     * description it never saw.
     */
    fd_table[fd].ofd_id = (fd_alias_pending && fd_alias_spec.ofd_id)
                              ? fd_alias_spec.ofd_id
                              : fd_next_ofd_id++;
    fd_table[fd].generation = fd_next_generation++;

    /* Seed the guest-visible flags with what the type alone decides. Creators
     * OR in their own CLOEXEC/NONBLOCK afterwards; none of them has to know the
     * access mode.
     *
     * An alias says its flags up front instead, and they land here rather than
     * in a second window after the slot is published. That ordering is not
     * cosmetic: the new slot joins an alias set other threads sweep by ofd_id,
     * so a concurrent F_SETFL on the source can reach it in the gap and have
     * its write clobbered by a publish that follows.
     */
    int accmode = fd_type_accmode(type);
    if (fd_alias_pending && fd_alias_spec.linux_flags)
        fd_table[fd].linux_flags =
            fd_flags_with_accmode(type, fd_alias_spec.linux_flags);
    else
        fd_table[fd].linux_flags = accmode < 0 ? 0 : accmode;
    fd_table[fd].dir = NULL;
    fd_table[fd].proc_path[0] = '\0';

    /* An alias shares the description, so it shares the answer: a dup of an
     * intercepted open is the same file by another name, and epoll_ctl on the
     * two names has to agree. Only an open that resolved a path decides this
     * from scratch, which is why fd_alloc_opened_host leaves an alias alone.
     */
    fd_table[fd].path_poll_capable =
        fd_alias_pending && fd_alias_spec.path_poll_capable;
    fd_table[fd].seals = 0;

    /* Whether a host read/write can block, so the fast-path and slow-path
     * readers can decide whether to divert into the interruptible wait without
     * re-stating it on every call. Taken by fd_probe_host before the lock.
     */
    fd_table[fd].can_block = probe->can_block;

    /* Own O_NONBLOCK on every fd whose host transfer could otherwise park a
     * vCPU thread, and emulate the guest's blocking semantics on top of it
     * (io_xfer). A readiness poll reserves nothing: the bytes it promised can
     * be taken by a sibling thread or a forked process before the transfer
     * runs, and a transfer that blocks there is reachable by neither
     * hv_vcpus_exit nor the wakeup pipe. From here on linux_flags carries what
     * the guest asked for, and sys_fcntl reports it from there.
     *
     * Sockets are owned like everything else that can block. They used to be
     * excluded on the grounds that a per-call MSG_DONTWAIT made ownership
     * unnecessary, and macOS does not honour that flag on AF_UNIX: a send on a
     * full stream socket writes what fits and then blocks in the kernel for the
     * rest, flag set, so the parked vCPU this whole mechanism exists to prevent
     * was still reachable through every socket write.
     *
     * The inherited stdio descriptors are still left alone, because their open
     * file description belongs to whoever launched elfuse -- a shell handing
     * over its terminal would keep the flag long after elfuse exits. A dup of
     * one of those descriptors is typed FD_REGULAR and so escapes the type
     * test; an fd_alias_spec_t is how the dup path, and the fork restore, say
     * the description is one that already exists. A socket that arrived over
     * SCM_RIGHTS comes in the same way and stays unowned for the same reason:
     * elfuse did not open it.
     */
    fd_table[fd].foreign_description =
        fd_alias_pending ? fd_alias_spec.foreign_description : type == FD_STDIO;

    /* An alias takes it from the spec, which the refresh above may have moved
     * on from what fd_probe_host saw: the probe runs before this lock and for
     * an alias only copies the caller's snapshot, so publishing the probe's
     * copy here would quietly undo the one field the refresh had to work for.
     * The two agree in every case measured so far -- ownership is decided when
     * a description is created and F_SETFL does not change it -- which is
     * exactly why it would have sat here unnoticed.
     */
    fd_table[fd].nonblock_owned =
        fd_alias_pending ? fd_alias_spec.nonblock_owned : probe->nonblock_owned;
    fd_table[fd].fasync_owner_type = FASYNC_OWNER_NONE;
    fd_table[fd].fasync_owner = 0;
    sock_opt_clear(&fd_table[fd]);
    fd_table[fd].cleanup = cleanup;

    /* Start conservative. Callers that set linux_flags after allocation
     * republish the readable-urandom state once the access mode is known.
     */
    shim_globals_mark_urandom_fd(fd, false);
}

void fd_refresh_urandom_bitmap(int fd)
{
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
        return;

    /* Hold fd_lock across both the read of (type, linux_flags) AND the
     * shim_globals bitmap publish. Dropping the lock before the publish would
     * let a concurrent sys_close flip the slot to FD_CLOSED in the gap; the
     * subsequent mark would then stomp a stale 'readable urandom' bit onto a
     * freed slot, and the EL1 fast path honors that bitmap.
     * shim_globals_mark_urandom_fd is itself atomic on the bitmap word, but
     * atomicity is meaningless without an in-lock source-to-publish window.
     */
    pthread_mutex_lock(&fd_lock);
    int type = fd_table[fd].type;
    int linux_flags = fd_table[fd].linux_flags;
    bool readable_urandom =
        type == FD_URANDOM && (linux_flags & LINUX_O_ACCMODE) != LINUX_O_WRONLY;
    shim_globals_mark_urandom_fd(fd, readable_urandom);
    pthread_mutex_unlock(&fd_lock);
}

/* Find the lowest free FD >= minfd using the bitmap.
 * Returns -1 if no free FD exists at or above minfd. Caller must hold fd_lock.
 */
static int fd_bitmap_find_free(int minfd)
{
    if (minfd < 0)
        minfd = 0;

    /* A guest chooses minfd through fcntl(F_DUPFD), which forwards the argument
     * having rejected only negatives, so this rejection is a real case and not
     * a restatement of something already checked. It is also what puts word
     * inside fd_free_bitmap.
     */
    uint64_t word, bit;
    if (!fdset_slot(minfd, &word, &bit))
        return -1;

    /* Bits below minfd drop out of the first word; every later word is whole. A
     * word index under FD_BITMAP_WORDS and a bit index under 64 put the result
     * below FD_TABLE_SIZE, so no ceiling is needed on the way out.
     */
    for (uint64_t mask = ~0ULL << bit; word < FD_BITMAP_WORDS;
         word++, mask = ~0ULL) {
        uint64_t free_bits = fd_free_bitmap[word] & mask;
        if (free_bits)
            return (int) (word * FDSET_BITS_PER_WORD +
                          (uint64_t) bit_ctz64(free_bits));
    }
    return -1;
}

/* fdtable_init. */

/* Initialize the FD table and bitmap, pre-open stdin/stdout/stderr. Extracted
 * from syscall_init(); call before any guest code runs.
 */
void fdtable_init(void)
{
    memset(fd_table, 0, sizeof(fd_table));

    /* Mark all FDs as free in bitmap */
    memset(fd_free_bitmap, 0xFF, sizeof(fd_free_bitmap));

    /* Pre-open stdin/stdout/stderr */
    fd_next_generation = 1;
    fd_next_ofd_id = 1;
    fd_table[0] = (fd_entry_t) {.type = FD_STDIO,
                                .host_fd = STDIN_FILENO,
                                .ofd_id = fd_next_ofd_id++,
                                .generation = fd_next_generation++};
    fd_table[1] = (fd_entry_t) {.type = FD_STDIO,
                                .host_fd = STDOUT_FILENO,
                                .ofd_id = fd_next_ofd_id++,
                                .generation = fd_next_generation++};
    fd_table[2] = (fd_entry_t) {.type = FD_STDIO,
                                .host_fd = STDERR_FILENO,
                                .ofd_id = fd_next_ofd_id++,
                                .generation = fd_next_generation++};

    /* The compound literals above zero can_block; recover the real value so a
     * terminal stdin still routes reads through the interruptible wait. Same
     * for foreign_description, which fd_init_entry derives from the type and
     * nothing derives here: these three descriptions belong to whoever launched
     * elfuse, and every alias of them reads the answer from this entry.
     */
    for (int i = 0; i < 3; i++)
        fd_table[i].foreign_description = true;
    fd_table[0].can_block = host_fd_may_block(STDIN_FILENO);
    fd_table[1].can_block = host_fd_may_block(STDOUT_FILENO);
    fd_table[2].can_block = host_fd_may_block(STDERR_FILENO);
    fd_bitmap_set_used(0);
    fd_bitmap_set_used(1);
    fd_bitmap_set_used(2);
}

/* FD helpers. */

/* Find and populate the lowest free FD >= minfd.
 *
 * Returns -1 with errno=EMFILE if no slot is available within RLIMIT_NOFILE.
 * Caller must hold fd_lock.
 */
static int fd_alloc_locked(int minfd,
                           int type,
                           int host_fd,
                           void (*cleanup)(int, uint64_t),
                           const fd_host_probe_t *probe)
{
    int fd = fd_bitmap_find_free(minfd);
    if (fd >= 0 && fd >= rlimit_nofile_cur)
        fd = -1; /* RLIMIT_NOFILE exceeded */
    if (fd < 0) {
        /* No slot, so nothing is published and the probe's O_NONBLOCK has to
         * come back off: the caller asked for an allocation, got EMFILE, and
         * should not also find its descriptor changed. This runs an fcntl under
         * fd_lock, which the probe exists to avoid, but only on the path that
         * is failing anyway.
         */
        fd_probe_rollback(probe, host_fd);
        errno = EMFILE;
        return -1;
    }
    fd_init_entry(fd, type, host_fd, cleanup, probe);
    return fd;
}

/* Allocate the lowest available FD.
 *
 * Returns -1 if table is full or RLIMIT_NOFILE would be exceeded (sets errno to
 * EMFILE).
 */
int fd_alloc(int type, int host_fd, void (*cleanup)(int, uint64_t))
{
    fd_host_probe_t probe = fd_probe_host(type, host_fd);
    pthread_mutex_lock(&fd_lock);
    int fd = fd_alloc_locked(0, type, host_fd, cleanup, &probe);
    pthread_mutex_unlock(&fd_lock);
    return fd;
}

int fd_alloc_dir(int type,
                 int host_fd,
                 void (*cleanup)(int, uint64_t),
                 void *dir,
                 int linux_flags)
{
    fd_host_probe_t probe = fd_probe_host(type, host_fd);
    pthread_mutex_lock(&fd_lock);
    int fd = fd_alloc_locked(0, type, host_fd, cleanup, &probe);
    if (fd >= 0) {
        fd_table[fd].dir = dir;
        fd_table[fd].linux_flags =
            fd_flags_with_accmode(fd_table[fd].type, linux_flags);
    }
    pthread_mutex_unlock(&fd_lock);
    return fd;
}

/* Like fd_alloc_from() but publishes dir + linux_flags in the same fd_lock
 * critical section as the slot identity, so the slot is never observable with
 * the target type but a stale/NULL dir. Required for FD_EPOLL, where dir
 * carries the shared eventpoll instance and the close hooks key their behavior
 * off it.
 */
int fd_alloc_dir_from(int minfd,
                      int type,
                      int host_fd,
                      void (*cleanup)(int, uint64_t),
                      void *dir,
                      int linux_flags,
                      uint64_t *out_gen)
{
    fd_host_probe_t probe = fd_probe_host(type, host_fd);
    pthread_mutex_lock(&fd_lock);
    int fd = fd_alloc_locked(minfd, type, host_fd, cleanup, &probe);
    if (fd >= 0) {
        fd_table[fd].dir = dir;
        fd_table[fd].linux_flags =
            fd_flags_with_accmode(fd_table[fd].type, linux_flags);
        if (out_gen)
            *out_gen = fd_table[fd].generation;
    }
    pthread_mutex_unlock(&fd_lock);
    return fd;
}

/* Fixed-slot counterpart of fd_alloc_dir_from(): overwrites fd with the new
 * (type, host_fd, dir, flags) atomically, cleaning up any prior occupant
 * outside fd_lock like fd_alloc_at().
 */
int fd_alloc_dir_at(int fd,
                    int type,
                    int host_fd,
                    void (*cleanup)(int, uint64_t),
                    void *dir,
                    int linux_flags,
                    uint64_t *out_gen)
{
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
        return -1;
    if (fd >= rlimit_nofile_cur)
        return -1;

    fd_entry_t old = {.type = FD_CLOSED};
    fd_host_probe_t probe = fd_probe_host(type, host_fd);
    pthread_mutex_lock(&fd_lock);
    if (fd_table[fd].type != FD_CLOSED) {
        old = fd_table[fd];
        epoll_note_fd_closed(fd, old.ofd_id);
    }
    fd_init_entry(fd, type, host_fd, cleanup, &probe);
    fd_table[fd].dir = dir;
    fd_table[fd].linux_flags =
        fd_flags_with_accmode(fd_table[fd].type, linux_flags);
    if (out_gen)
        *out_gen = fd_table[fd].generation;
    pthread_mutex_unlock(&fd_lock);

    if (old.type != FD_CLOSED)
        fd_cleanup_entry(fd, &old);

    return fd;
}

/* Allocate the lowest available FD >= minfd.
 *
 * Returns -1 if none available or RLIMIT_NOFILE would be exceeded.
 */
int fd_alloc_from(int minfd,
                  int type,
                  int host_fd,
                  void (*cleanup)(int, uint64_t),
                  uint64_t *out_gen)
{
    fd_host_probe_t probe = fd_probe_host(type, host_fd);
    pthread_mutex_lock(&fd_lock);
    int fd = fd_alloc_locked(minfd, type, host_fd, cleanup, &probe);

    /* Capture the freshly-stamped generation inside the allocating critical
     * section. Callers (dup) later revalidate it under fd_lock to prove the
     * slot still holds this allocation and was not closed+reopened in the
     * window, which a (type, host_fd) tuple alone cannot detect.
     */
    if (out_gen && fd >= 0)
        *out_gen = fd_table[fd].generation;
    pthread_mutex_unlock(&fd_lock);
    return fd;
}

/* The alias-aware entry points. Each is the plain allocator with the
 * inheritance bracketed around it, so a caller states what it is claiming and
 * cannot leave the claim set behind.
 */
int fd_alloc_alias(const fd_alias_spec_t *spec,
                   int type,
                   int host_fd,
                   void (*cleanup)(int, uint64_t))
{
    fd_alias_begin(spec);
    return fd_alias_end(fd_alloc(type, host_fd, cleanup));
}

int fd_alloc_alias_at(const fd_alias_spec_t *spec,
                      int fd,
                      int type,
                      int host_fd,
                      void (*cleanup)(int, uint64_t),
                      uint64_t *out_gen)
{
    fd_alias_begin(spec);
    return fd_alias_end(fd_alloc_at(fd, type, host_fd, cleanup, out_gen));
}

int fd_alloc_alias_relaxed(const fd_alias_spec_t *spec,
                           int fixed_fd,
                           int minfd,
                           int type,
                           int host_fd,
                           void (*cleanup)(int, uint64_t),
                           uint64_t *out_gen)
{
    fd_alias_begin(spec);
    int fd =
        fixed_fd >= 0
            ? fd_alloc_at_relaxed(fixed_fd, type, host_fd, cleanup, out_gen)
            : fd_alloc_from_relaxed(minfd, type, host_fd, cleanup, out_gen);
    return fd_alias_end(fd);
}

int fd_alloc_alias_dir(const fd_alias_spec_t *spec,
                       int fixed_fd,
                       int minfd,
                       int type,
                       int host_fd,
                       void (*cleanup)(int, uint64_t),
                       void *dir,
                       int linux_flags,
                       uint64_t *out_gen)
{
    fd_alias_begin(spec);
    int fd = fixed_fd >= 0 ? fd_alloc_dir_at(fixed_fd, type, host_fd, cleanup,
                                             dir, linux_flags, out_gen)
                           : fd_alloc_dir_from(minfd, type, host_fd, cleanup,
                                               dir, linux_flags, out_gen);
    return fd_alias_end(fd);
}

int fd_alloc_from_relaxed(int minfd,
                          int type,
                          int host_fd,
                          void (*cleanup)(int, uint64_t),
                          uint64_t *out_gen)
{
    if (!thread_is_single_active())
        return fd_alloc_from(minfd, type, host_fd, cleanup, out_gen);

    /* Single active thread: no sibling can race the slot, so the unlocked
     * generation read is safe.
     */
    fd_host_probe_t probe = fd_probe_host(type, host_fd);
    int fd = fd_alloc_locked(minfd, type, host_fd, cleanup, &probe);
    if (out_gen && fd >= 0)
        *out_gen = fd_table[fd].generation;
    return fd;
}

/* Report whether a guest fd slot >= minfd will be free for a fresh allocation
 * once execve's CLOEXEC sweep has run. rosetta_finalize claims that slot for
 * the pre-opened x86_64 binary past execve's point of no return, where an
 * EMFILE is fatal; sys_execve calls this before guest_reset so an exhausted
 * table fails gracefully with -EMFILE instead. The guest fd ceiling
 * (FD_TABLE_SIZE) sits far below the host RLIMIT_NOFILE, so a guest can fill
 * its table while the host still has fds, meaning the host open in elf_load
 * does not catch this first.
 *
 * A slot qualifies if it is free now, or if it is open but CLOEXEC (the sweep
 * closes it before rosetta_finalize allocates).
 *
 * Returns true if at least one such slot exists within RLIMIT_NOFILE.
 */
bool fd_reexec_slot_available(int minfd)
{
    if (minfd < 0)
        minfd = 0;
    pthread_mutex_lock(&fd_lock);
    int limit = rlimit_nofile_cur;
    if (limit > FD_TABLE_SIZE)
        limit = FD_TABLE_SIZE;
    bool available = false;
    for (int i = minfd; i < limit; i++) {
        if (fd_table[i].type == FD_CLOSED ||
            (fd_table[i].linux_flags & LINUX_O_CLOEXEC)) {
            available = true;
            break;
        }
    }
    pthread_mutex_unlock(&fd_lock);
    return available;
}

/* Allocate a specific FD slot. Enforces RLIMIT_NOFILE. Properly cleans up any
 * existing entry (including DIR* for directory FDs) before overwriting.
 *
 * Returns -1 if out of range.
 */
int fd_alloc_at(int fd,
                int type,
                int host_fd,
                void (*cleanup)(int, uint64_t),
                uint64_t *out_gen)
{
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
        return -1;
    if (fd >= rlimit_nofile_cur)
        return -1;

    /* Snapshot old slot state under fd_lock, then replace atomically. Cleanup
     * happens AFTER releasing fd_lock to avoid lock ordering violation: cleanup
     * functions acquire sfd_lock/inotify_lock.
     */
    fd_entry_t old = {.type = FD_CLOSED};

    fd_host_probe_t probe = fd_probe_host(type, host_fd);
    pthread_mutex_lock(&fd_lock);
    if (fd_table[fd].type != FD_CLOSED) {
        old = fd_table[fd];

        /* dup2/dup3 over an open slot retires the old open file description at
         * this fd number without routing through fd_mark_closed_unlocked, so
         * clear its epoll registrations here too (see epoll_note_fd_closed).
         */
        epoll_note_fd_closed(fd, old.ofd_id);
    }
    fd_init_entry(fd, type, host_fd, cleanup, &probe);
    if (out_gen)
        *out_gen = fd_table[fd].generation;
    pthread_mutex_unlock(&fd_lock);

    /* Clean up old resources outside fd_lock */
    if (old.type != FD_CLOSED)
        fd_cleanup_entry(fd, &old);

    return fd;
}

int fd_alloc_at_relaxed(int fd,
                        int type,
                        int host_fd,
                        void (*cleanup)(int, uint64_t),
                        uint64_t *out_gen)
{
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
        return -1;
    if (fd >= rlimit_nofile_cur)
        return -1;
    if (!thread_is_single_active())
        return fd_alloc_at(fd, type, host_fd, cleanup, out_gen);

    if (fd_table[fd].type != FD_CLOSED)
        return fd_alloc_at(fd, type, host_fd, cleanup, out_gen);

    /* After the early returns, not before: every one of them either rejects the
     * request or hands it to a variant that probes for itself, and the probe
     * sets O_NONBLOCK on the host fd. Probing first would run that on an fd the
     * call is about to refuse, and run it twice on the delegating path.
     */
    fd_host_probe_t probe = fd_probe_host(type, host_fd);

    /* Single active thread: no sibling can race the slot, so the unlocked init
     * and generation read are safe.
     */
    fd_init_entry(fd, type, host_fd, cleanup, &probe);
    if (out_gen)
        *out_gen = fd_table[fd].generation;
    return fd;
}

/* Internal: mark fd closed with fd_lock already held. Requires 0 <= fd <
 * FD_TABLE_SIZE; it indexes fd_table and the free bitmap without rechecking, so
 * a caller that has not established that corrupts both.
 *
 * Clear host_fd and dir BEFORE marking the slot free in the bitmap. Otherwise
 * another thread could fd_alloc() this slot, populate it with a new
 * host_fd/dir, and then the current stale writes would corrupt the new entry.
 */
fd_lifetime_t *fd_mark_closed_unlocked(int fd)
{
    uint64_t closing_ofd_id = fd_table[fd].ofd_id;
    fd_lifetime_t *detached = fd_table[fd].lifetime;

    /* Clear before publishing FD_CLOSED/free. The EL1 urandom read fast path
     * intentionally avoids fd_lock, so it must not observe a stale urandom bit
     * after this slot has become invalid or reusable.
     */
    shim_globals_mark_urandom_fd(fd, false);
    fd_table[fd].type = FD_CLOSED;
    fd_table[fd].host_fd = -1;
    fd_table[fd].lifetime = NULL;
    fd_table[fd].ofd_id = 0;
    fd_table[fd].dir = NULL;
    fd_table[fd].proc_path[0] = '\0';
    fd_table[fd].path_poll_capable = false;
    fd_table[fd].linux_flags = 0;
    fd_table[fd].seals = 0;
    fd_table[fd].fasync_owner_type = FASYNC_OWNER_NONE;
    fd_table[fd].fasync_owner = 0;
    fd_bitmap_set_free(fd);

    /* Drop this fd from any epoll interest table. Matches Linux auto-removal on
     * close and keeps sys_epoll_pwait's active-check honest rather than leaning
     * on the epoll_ctl generation guard. Runs after the slot is FD_CLOSED so a
     * just-closed epoll fd skips itself; caller holds fd_lock (or is
     * single-threaded on the relaxed path).
     */
    epoll_note_fd_closed(fd, closing_ofd_id);
    return detached;
}

fd_lifetime_t *fd_mark_closed(int fd)
{
    pthread_mutex_lock(&fd_lock);
    fd_lifetime_t *detached = fd_mark_closed_unlocked(fd);
    pthread_mutex_unlock(&fd_lock);
    return detached;
}

/* Snapshot fd_table[fd] into *out and optionally close it. Caller must hold
 * fd_lock.
 *
 * Returns true if the slot was open, false if closed.
 */
static bool fd_snapshot_locked(int fd, fd_entry_t *out, bool close_it)
{
    if (fd_table[fd].type == FD_CLOSED)
        return false;
    *out = fd_table[fd];
    if (close_it)
        fd_mark_closed_unlocked(fd);
    return true;
}

/* Atomically snapshot an fd entry and mark it closed.
 *
 * Returns true if the slot was open (snapshot written to *out), false if
 * already closed. This eliminates the TOCTOU race where two concurrent
 * sys_close() calls both snapshot the same open entry and double-close the host
 * fd.
 */
bool fd_snapshot_and_close(int fd, fd_entry_t *out)
{
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
        return false;
    pthread_mutex_lock(&fd_lock);
    bool ok = fd_snapshot_locked(fd, out, true);
    pthread_mutex_unlock(&fd_lock);
    return ok;
}

bool fd_snapshot_and_close_relaxed(int fd, fd_entry_t *out)
{
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
        return false;
    if (!thread_is_single_active())
        return fd_snapshot_and_close(fd, out);
    return fd_snapshot_locked(fd, out, true);
}

bool fd_close_regular_relaxed(int fd, int *host_fd_out)
{
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
        return false;
    if (!thread_is_single_active())
        return false;

    /* Refuse a slot carrying a lifetime. The caller closes *host_fd_out raw and
     * never touches the refcount, so admitting one here would strand the slot's
     * reference and leak the object. The thread_is_single_active() gate above
     * does not subsume this: the lifetime is created on the multi-threaded
     * acquire path and outlives the return to a single active thread.
     */
    fd_entry_t *entry = &fd_table[fd];
    if (entry->type != FD_REGULAR || entry->dir || entry->cleanup ||
        entry->lifetime)
        return false;

    *host_fd_out = entry->host_fd;
    fd_mark_closed_unlocked(fd);
    return true;
}

/* Look up a guest FD.
 *
 * Returns host FD or -1 if invalid. WARNING: unsafe for concurrent use; a
 * concurrent close() can invalidate the returned host fd between this call and
 * use. For race-prone paths, use fd_snapshot() or fd_to_host_dup().
 */
int fd_to_host(int guest_fd)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return -1;
    if (fd_table[guest_fd].type == FD_CLOSED)
        return -1;
    return fd_table[guest_fd].host_fd;
}

/* Take one reference on fd's lifetime with fd_lock held, creating it if this is
 * the slot's first borrower. The single place a lifetime is ever born.
 *
 * spare, when it points at a non-NULL allocation, is one the caller made
 * outside the lock; this consumes it and clears the caller's pointer, or leaves
 * it untouched when the slot already carries a lifetime. A caller passing NULL
 * allocates here instead, with the table lock held, which is only acceptable
 * away from the per-syscall path: see fd_host_ref_acquire for why that one
 * preallocates.
 *
 * Returns NULL when the slot is closed, carries no host descriptor, or the
 * allocation fails. A caller that has already established the first two under
 * this same lock hold can read NULL as out of memory.
 */
static fd_lifetime_t *fd_lifetime_pin_spare(int fd, fd_lifetime_t **spare)
{
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
        return NULL;
    if (fd_table[fd].type == FD_CLOSED || fd_table[fd].host_fd < 0)
        return NULL;

    fd_lifetime_t *lifetime = fd_table[fd].lifetime;
    if (!lifetime) {
        if (spare && *spare) {
            lifetime = *spare;
            *spare = NULL;
        } else {
            lifetime = malloc(sizeof(*lifetime));
            if (!lifetime)
                return NULL;
        }
        atomic_init(&lifetime->refs, 1);
        lifetime->host_fd = fd_table[fd].host_fd;
        lifetime->type = fd_table[fd].type;

        /* Taken once, at the object's birth, and dropped once at its death:
         * every later pin shares this object, so the stream reference is per
         * lifetime rather than per pin. fd_lock is held, which is the lock
         * guarding the stream's own refcount.
         */
        lifetime->dir = fd_table[fd].type == FD_DIR ? fd_table[fd].dir : NULL;
        if (lifetime->dir)
            dir_stream_ref_locked(lifetime->dir);
        fd_table[fd].lifetime = lifetime;
    }

    /* Relaxed: the caller already holds a reference, so this add cannot be what
     * makes the object reachable.
     */
    atomic_fetch_add_explicit(&lifetime->refs, 1, memory_order_relaxed);
    return lifetime;
}

int fd_host_ref_acquire(int guest_fd,
                        fd_entry_t *out,
                        fd_lifetime_t **lifetime_out)
{
    *lifetime_out = NULL;
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE)) {
        errno = EBADF;
        return -1;
    }

    /* Two passes at most. The first runs with no spare and succeeds outright
     * for any fd that already carries a lifetime, which after its first borrow
     * is every fd; only a first borrow drops the lock to allocate and comes
     * back. Allocating up front instead would be simpler, but it would make
     * every multi-threaded fd call pay a malloc/free pair, and sys_ppoll pays
     * it per polled descriptor.
     *
     * The allocation stays outside the lock either way. Inside, it would nest
     * the allocator's own lock under the order-3 table lock, which
     * check-lock-order.py cannot see because it only knows file-scope
     * pthread_mutex_t, and every first touch of an fd would pay a possible
     * allocator stall with the whole table held.
     */
    fd_lifetime_t *spare = NULL;
    for (;;) {
        pthread_mutex_lock(&fd_lock);
        if (!fd_snapshot_locked(guest_fd, out, false) || out->host_fd < 0) {
            pthread_mutex_unlock(&fd_lock);
            free(spare);
            errno = EBADF;
            return -1;
        }

        /* Committing needs either an existing lifetime to share or a spare to
         * install. Without one, fall out and allocate. A slot that acquired a
         * lifetime while the lock was down takes the first branch on the retry
         * and the spare goes back to the allocator untouched.
         */
        if (out->lifetime || spare) {
            fd_lifetime_t *lifetime = fd_lifetime_pin_spare(guest_fd, &spare);
            if (!lifetime) {
                /* Unreachable: the slot checks above passed under this same
                 * lock hold, and this branch never allocates. Handled rather
                 * than asserted so a future change cannot hand back a host fd
                 * with a NULL lifetime, which reads as a successful pin.
                 */
                pthread_mutex_unlock(&fd_lock);
                free(spare);
                errno = ENOMEM;
                return -1;
            }
            out->lifetime = lifetime;
            *lifetime_out = lifetime;
            int host_fd = out->host_fd;
            pthread_mutex_unlock(&fd_lock);
            free(spare);
            return host_fd;
        }
        pthread_mutex_unlock(&fd_lock);

        spare = malloc(sizeof(*spare));
        if (!spare) {
            errno = ENOMEM;
            return -1;
        }
    }
}

void fd_lifetime_release(fd_lifetime_t *lifetime)
{
    /* Release so every use this thread made of the object happens before the
     * decrement, then acquire below before the free, so the thread that runs
     * the destructor sees all of them. Relaxed here would let the close/free
     * race a sibling's last read.
     */
    unsigned int prev =
        atomic_fetch_sub_explicit(&lifetime->refs, 1, memory_order_release);

    /* An unbalanced release wraps refs and the object silently never frees,
     * which surfaces later as an fd leak with no trace of its origin. Catch it
     * where it happens instead.
     */
    assert(prev != 0);
    if (prev != 1)
        return;
    atomic_thread_fence(memory_order_acquire);

    /* A directory's descriptor belongs to its stream; releasing the reference
     * taken at birth is this object's whole share of it. dir_stream_release
     * takes fd_lock, which is why no caller may hold it here.
     */
    if (lifetime->dir)
        dir_stream_release(lifetime->dir);
    else if (lifetime->type != FD_STDIO)
        close(lifetime->host_fd);
    free(lifetime);
}

fd_lifetime_t *fd_lifetime_pin_locked(int fd)
{
    return fd_lifetime_pin_spare(fd, NULL);
}

/* Retire a slot the caller published in fd_table, closing the host fd it owns.
 *
 * Prefer this over fd_mark_closed plus a raw close on the host fd: once a slot
 * is published a sibling can pin it, and a raw close then pulls the descriptor
 * out from under that sibling while stranding the slot's own reference. The
 * close is deferred to the last release when a pin exists.
 *
 * A slot that no longer holds host_fd is left entirely alone, descriptor
 * included. Reaching that means a sibling already closed this guest fd, and
 * that close retired the descriptor on its way out, so closing it here would be
 * a second close of a number the host may since have handed to someone else.
 *
 * host_fd narrows which slot this retires but does not identify it: if the
 * sibling's replacement happens to reuse the same number, the check passes and
 * this retires the replacement. Distinguishing that needs the allocation
 * generation, which the plain fd_alloc does not hand back. The residue is a
 * guest operating on an fd number it was never given, which linux-wire.h
 * already calls a guest-level bug.
 */
void fd_retire_published(int fd, int host_fd)
{
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE)) {
        if (host_fd >= 0)
            close(host_fd);
        return;
    }

    /* A synthetic slot can carry no host descriptor at all (the FUSE file and
     * directory types); retiring one still has to clear the slot.
     */
    pthread_mutex_lock(&fd_lock);
    bool still_ours =
        fd_table[fd].type != FD_CLOSED && fd_table[fd].host_fd == host_fd;
    fd_lifetime_t *lifetime = still_ours ? fd_mark_closed_unlocked(fd) : NULL;
    pthread_mutex_unlock(&fd_lock);

    if (lifetime)
        fd_lifetime_release(lifetime);
    else if (still_ours && host_fd >= 0)
        close(host_fd);
}

/* Snapshot an fd entry under fd_lock.
 *
 * Returns true if the slot was open (entry copied to *out), false if closed or
 * out of range.
 */
bool fd_snapshot(int guest_fd, fd_entry_t *out)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return false;
    pthread_mutex_lock(&fd_lock);
    bool ok = fd_snapshot_locked(guest_fd, out, false);
    pthread_mutex_unlock(&fd_lock);
    return ok;
}

uint64_t fd_current_generation(int guest_fd)
{
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap))
        return 0;
    return snap.generation;
}

int fd_snapshot_and_dup(int guest_fd, fd_entry_t *out)
{
    out->type = FD_CLOSED;
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return -1;
    pthread_mutex_lock(&fd_lock);
    if (!fd_snapshot_locked(guest_fd, out, false)) {
        pthread_mutex_unlock(&fd_lock);
        return -1;
    }
    int host = (out->host_fd >= 0) ? dup(out->host_fd) : -1;
    pthread_mutex_unlock(&fd_lock);
    return host;
}

int fd_snapshot_and_dup_or_share_dir(int guest_fd,
                                     fd_entry_t *out,
                                     bool *out_shared_dir)
{
    *out_shared_dir = false;
    out->type = FD_CLOSED;
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return -1;
    pthread_mutex_lock(&fd_lock);
    if (!fd_snapshot_locked(guest_fd, out, false)) {
        pthread_mutex_unlock(&fd_lock);
        return -1;
    }

    /* Reference and descriptor are taken in the one window that proved the slot
     * is still this directory, so a sibling close cannot free the stream
     * between the snapshot and the reference that keeps it alive.
     */
    int host;
    if (out->type == FD_DIR && out->dir) {
        dir_stream_ref_locked(out->dir);
        *out_shared_dir = true;
        host = out->host_fd;
    } else {
        host = (out->host_fd >= 0) ? dup(out->host_fd) : -1;
    }
    pthread_mutex_unlock(&fd_lock);
    return host;
}

int fd_get_type(int guest_fd)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return FD_CLOSED;
    pthread_mutex_lock(&fd_lock);
    int type = fd_table[guest_fd].type;
    pthread_mutex_unlock(&fd_lock);
    return type;
}

fd_block_state_t fd_block_state(int guest_fd)
{
    fd_block_state_t st = {.type = FD_CLOSED};
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return st;

    /* Same relaxed rule the allocation paths use: with one active thread no
     * sibling can mutate the slot, so the lock buys nothing. This runs on every
     * read and write of a fd that can block, and the whole-entry fd_snapshot it
     * replaces copied a few hundred bytes under a global lock to read three
     * fields.
     */
    bool locked = !thread_is_single_active();
    if (locked)
        pthread_mutex_lock(&fd_lock);
    st = fd_block_state_of(&fd_table[guest_fd]);
    if (locked)
        pthread_mutex_unlock(&fd_lock);
    return st;
}

bool fd_guest_nonblock(int guest_fd)
{
    /* Same field, same relaxed rule as fd_block_state: with one active thread
     * no sibling can mutate the slot, so the lock buys nothing. This runs on
     * every eventfd, signalfd, timerfd and inotify read, which is once per
     * event-loop wakeup.
     */
    return fd_block_state(guest_fd).guest_nonblock;
}

void fd_for_each_alias_locked(int guest_fd,
                              uint64_t generation,
                              void (*fn)(int guest_fd, void *ctx),
                              void *ctx)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return;

    /* A close+reopen in the window makes ofd_id name a description the caller
     * never asked about, so verify the slot first and change nothing if it
     * moved. Generation is the discriminator: a reopen can reuse the same guest
     * fd number, host fd number and type, and only the monotonic generation
     * tells the caller's open from a new one.
     */
    if (fd_table[guest_fd].type == FD_CLOSED ||
        fd_table[guest_fd].generation != generation)
        return;
    uint64_t ofd_id = fd_table[guest_fd].ofd_id;
    if (!ofd_id)
        return;

    /* Walk the allocation bitmap rather than the table: one word rules out 64
     * slots, and the flag sweeps run per fd at event-loop setup.
     */
    for (int w = 0; w < FD_BITMAP_WORDS; w++) {
        uint64_t used = ~fd_free_bitmap[w];
        while (used) {
            int fd = w * 64 + bit_ctz64(used);
            used &= used - 1;
            if (fd_table[fd].type != FD_CLOSED && fd_table[fd].ofd_id == ofd_id)
                fn(fd, ctx);
        }
    }
}

typedef struct {
    int mask, value;
} shadow_bits_ctx_t;

static void set_shadow_bits_slot(int guest_fd, void *ctx)
{
    const shadow_bits_ctx_t *b = ctx;
    fd_table[guest_fd].linux_flags =
        (fd_table[guest_fd].linux_flags & ~b->mask) | (b->value & b->mask);
}

void fd_set_shadow_flags(int guest_fd, uint64_t generation, int mask, int value)
{
    shadow_bits_ctx_t ctx = {.mask = mask, .value = value};
    pthread_mutex_lock(&fd_lock);
    fd_for_each_alias_locked(guest_fd, generation, set_shadow_bits_slot, &ctx);
    pthread_mutex_unlock(&fd_lock);
}

bool fd_apply_guest_nonblock(int guest_fd, bool on)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return false;

    /* One fd_lock window for the question and the answer both. Reading the slot
     * first and sweeping afterwards took the lock twice and revalidated the
     * generation the first read had just produced, on a path every F_SETFL and
     * every FIONBIO runs whatever the fd's type.
     */
    shadow_bits_ctx_t ctx = {.mask = LINUX_O_NONBLOCK,
                             .value = on ? LINUX_O_NONBLOCK : 0};
    pthread_mutex_lock(&fd_lock);
    fd_entry_t *e = &fd_table[guest_fd];
    bool shadowed = e->type != FD_CLOSED &&
                    fd_nonblock_shadowed(e->type, e->nonblock_owned);
    if (shadowed)
        fd_for_each_alias_locked(guest_fd, e->generation, set_shadow_bits_slot,
                                 &ctx);
    pthread_mutex_unlock(&fd_lock);
    return shadowed;
}

void fd_publish_linux_flags(int guest_fd, int linux_flags)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return;
    pthread_mutex_lock(&fd_lock);
    fd_table[guest_fd].linux_flags =
        fd_flags_with_accmode(fd_table[guest_fd].type, linux_flags);
    pthread_mutex_unlock(&fd_lock);
}

/* Sized to cover all FD_* constants in abi.h plus a small headroom. Indexed by
 * type. Each slot defaults to NULL (no per-type cleanup). Modules that own a
 * type call fd_register_cleanup() at init time; dup and fork-restore paths read
 * back the binding via fd_cleanup_for_type().
 */
#define FD_TYPE_REGISTRY_SIZE 32
static void (*fd_type_cleanup[FD_TYPE_REGISTRY_SIZE])(int, uint64_t);

void fd_register_cleanup(int type, void (*cleanup)(int, uint64_t))
{
    if (type < 0 || type >= FD_TYPE_REGISTRY_SIZE)
        return;
    fd_type_cleanup[type] = cleanup;
}

void (*fd_cleanup_for_type(int type))(int, uint64_t)
{
    if (type < 0 || type >= FD_TYPE_REGISTRY_SIZE)
        return NULL;
    return fd_type_cleanup[type];
}

/* Look up a guest FD and return a dup'd host fd that the caller owns. The dup
 * is performed under fd_lock so that close() on another thread cannot
 * invalidate the host fd between lookup and dup. Caller must close the returned
 * fd when done.
 *
 * Returns -1 on failure.
 */
int fd_to_host_dup(int guest_fd)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return -1;
    pthread_mutex_lock(&fd_lock);
    if (fd_table[guest_fd].type == FD_CLOSED) {
        pthread_mutex_unlock(&fd_lock);
        return -1;
    }
    int owned = dup(fd_table[guest_fd].host_fd);
    pthread_mutex_unlock(&fd_lock);
    return owned;
}

/* FD cleanup. */

/* Release all type-specific resources for a closed FD entry. Caller must have
 * already removed the entry from fd_table (via fd_snapshot_and_close or
 * fd_mark_closed). Does NOT hold fd_lock.
 *
 * This consolidates the cleanup logic that was previously duplicated in
 * sys_close, close_guest_fd_snapshot, and the execve CLOEXEC loop.
 */
void fd_cleanup_entry(int guest_fd, const fd_entry_t *snap)
{
    /* Who owns host_fd, in the order the answers are checked below:
     *
     *   a directory with a stream -> the stream (closedir at its last
     *                                reference, which is taken last here so
     *                                the descriptor outlives the teardown
     *                                below that is keyed by its number)
     *   a lifetime pin            -> the pin (close at its last reference)
     *   otherwise                 -> this function
     *
     * A directory *without* a stream is the third case, not the first: the slot
     * is one an in-flight open or fork-restore published and has not adopted
     * yet, so the descriptor is still plain and still closable here.
     */
    bool stream_owns_host_fd = snap->type == FD_DIR && snap->dir;

    /* epoll_instance_t shares the dir field with dir_stream_t. */
    if (snap->dir && snap->type == FD_EPOLL)
        epoll_instance_free(snap->dir);

    /* Type-specific teardown via vtable (replaces per-type switch) */
    if (snap->cleanup)
        snap->cleanup(guest_fd, snap->generation);

    /* Drop this host fd from both pty side tables. Must happen before
     * close(snap->host_fd): both are keyed by the still-live host fd. The
     * master half stops the keepalive slave leaking past a /dev/ptmx close; the
     * slave half is what lets the master see its last slave go, which only this
     * accounting can tell since elfuse's own keepalive slave stays open.
     */
    proc_pty_forget_host_fd(snap->host_fd);

    /* Deregister any SIGIO/SIGURG readiness watch before the host fd closes.
     * Closing the fd auto-removes the knote too, but doing it explicitly avoids
     * a stale event landing on a host fd number reused by a racing open.
     */
    if ((snap->linux_flags & LINUX_O_ASYNC) ||
        (snap->type == FD_SOCKET &&
         snap->fasync_owner_type != FASYNC_OWNER_NONE))
        asyncio_disarm(snap->host_fd);

    if (snap->lifetime)
        fd_lifetime_release(snap->lifetime);
    else if (!stream_owns_host_fd && snap->type != FD_STDIO)
        close(snap->host_fd);

    /* Last: the slot's own reference on the stream, and with it the descriptor
     * when no getdents64 or pin still holds one.
     */
    if (stream_owns_host_fd)
        dir_stream_release(snap->dir);
}
