/*
 * Shared helpers for syscall modules
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Cross-domain declarations: shared locks, the FD table, and translation
 * helpers used by multiple syscall modules.
 *
 * Lock ordering (acquire in ascending order to prevent deadlocks):
 *   mmap_lock    (syscall/mem.c):     mmap/brk allocators + page tables
 *   pt_lock      (core/guest.c):      page table pool allocator
 *   fd_lock      (syscall/fdtable.c): FD table (alloc/close/dup)
 *   epoll inst   (syscall/poll.c):    per-epoll-instance regs[]; taken under
 *                                     fd_lock by the close hook, taken alone
 *                                     (no fd_lock held) by epoll_ctl/pwait
 *   sig_lock     (syscall/signal.c):  signal handlers/pending/blocked
 *   thread_lock  (runtime/thread.c):  thread table
 *   sfd_lock     (syscall/fd.c):      special fd (never held with thread_lock)
 *   pid_lock     (syscall/proc.c):    process table / wait state
 *   futex bucket (runtime/futex.c):   per-bucket, index-ordered if >1
 *   inotify_lock (syscall/inotify.c): inotify watch table
 */

#pragma once

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <unistd.h>

#include "syscall/abi.h"
#include "runtime/thread.h"

/* Named constants */

/* Linux PATH_MAX (4096): used for path buffer sizing in syscall handlers.
 * Literal 4096 in core/guest.c and core/stack.c means actual page size, not
 * this.
 */
#define LINUX_PATH_MAX 4096

typedef int guest_fd_t;
typedef int host_fd_t;

/* Cross-module locks. */
extern pthread_mutex_t mmap_lock; /* Lock order: 1, mmap/brk + page tables */
extern pthread_mutex_t fd_lock;   /* Lock order: 3, FD table */

/* The only supported mmap_lock entry/exit API.  Acquire drains the per-vCPU
 * EL1 mmap rings before any caller can inspect semantic region state.
 */
void mmap_lock_acquire(guest_t *g);
void mmap_lock_release(void);
void mmap_lock_cond_wait(guest_t *g, pthread_cond_t *cond);

/* FD table (defined in syscall/fdtable.c). */
extern fd_entry_t fd_table[FD_TABLE_SIZE];

/* FD table init. */

/* Initialize FD table: clear bitmap, pre-open stdin/stdout/stderr. */
void fdtable_init(void);

/* FD helpers. */

/* Allocate the lowest available FD.
 *
 * Returns -1 if table is full. cleanup is set atomically under fd_lock (pass
 * NULL for plain fds).
 */
int fd_alloc(int type, int host_fd, void (*cleanup)(int));

/* Allocate the lowest available FD and publish type, host_fd, dir, and
 * linux_flags in one fd_lock critical section, so the slot never becomes
 * visible to a concurrent close/scan as type-set-but-dir-NULL. For fds (epoll)
 * whose close hook and refcount rely on dir being present the instant the slot
 * reads FD_EPOLL.
 *
 * Returns -1 (EMFILE) if the table is full.
 */
int fd_alloc_dir(int type,
                 int host_fd,
                 void (*cleanup)(int),
                 void *dir,
                 int linux_flags);

/* fd_alloc_from()/fd_alloc_at() variants that publish dir + linux_flags in the
 * same fd_lock section as the slot identity (see fd_alloc_dir). Used by
 * epoll_dup_fd() so a duped epoll fd never appears as FD_EPOLL with a NULL dir.
 */
int fd_alloc_dir_from(int minfd,
                      int type,
                      int host_fd,
                      void (*cleanup)(int),
                      void *dir,
                      int linux_flags);
int fd_alloc_dir_at(int fd,
                    int type,
                    int host_fd,
                    void (*cleanup)(int),
                    void *dir,
                    int linux_flags);

/* Allocate the lowest available FD >= minfd.
 *
 * Returns -1 if none available. cleanup is set atomically under fd_lock (pass
 * NULL for plain fds). out_gen (nullable) receives the generation stamped on
 * the new slot, captured inside the allocating fd_lock critical section so dup
 * can later prove the slot still holds this allocation and was not
 * closed+reopened in the window.
 */
int fd_alloc_from(int minfd,
                  int type,
                  int host_fd,
                  void (*cleanup)(int),
                  uint64_t *out_gen);

/* Allocate the lowest available FD >= minfd with a single-thread fast path.
 * Falls back to fd_alloc_from() when multiple guest threads are active.
 */
int fd_alloc_from_relaxed(int minfd,
                          int type,
                          int host_fd,
                          void (*cleanup)(int),
                          uint64_t *out_gen);

/* Allocate a specific FD slot.
 * Returns -1 if out of range. cleanup is set atomically under fd_lock (pass
 * NULL for plain fds). out_gen: see fd_alloc_from().
 */
int fd_alloc_at(int fd,
                int type,
                int host_fd,
                void (*cleanup)(int),
                uint64_t *out_gen);

/* Allocate a specific FD slot with a single-thread fast path. Falls back to
 * fd_alloc_at() when replacement/cleanup must stay serialized.
 */
int fd_alloc_at_relaxed(int fd,
                        int type,
                        int host_fd,
                        void (*cleanup)(int),
                        uint64_t *out_gen);

/* Report whether a guest FD slot >= minfd will be free after execve's CLOEXEC
 * sweep runs (free now, or open-but-CLOEXEC). sys_execve uses this before
 * guest_reset so a Rosetta re-bootstrap that would fail fd_alloc_from past the
 * point of no return is rejected gracefully with -EMFILE instead.
 */
bool fd_reexec_slot_available(int minfd);

/* Look up a guest FD.
 *
 * Returns host FD or -1 if invalid. Unsafe for concurrent use; see
 * fd_snapshot/fd_to_host_dup.
 */
int fd_to_host(int guest_fd);

/* Snapshot an fd entry under fd_lock. Thread-safe alternative to direct
 * fd_table[] access.
 * Returns true on success, false if closed.
 */
bool fd_snapshot(int guest_fd, fd_entry_t *out);

/* Snapshot an fd entry AND dup its host fd in a single fd_lock critical
 * section. Eliminates the TOCTOU window between reading the type/metadata and
 * duplicating the host fd in the dup(2) path.
 *
 * Returns the dup'd host fd (owned by the caller) on success, -1 on failure. On
 * success the snapshot in *out is consistent with the dup'd host fd.
 */
int fd_snapshot_and_dup(int guest_fd, fd_entry_t *out);

/* Read just the fd type under fd_lock.
 *
 * Returns FD_CLOSED for out-of-range or closed slots. Cheaper than fd_snapshot
 * when only the type is needed for dispatch (sys_read/sys_readv/sys_writev fast
 * paths).
 */
int fd_get_type(int guest_fd);

/* True when a host read/write on this guest fd may block (pipe, socket, fifo,
 * char/tty). Regular files and directories never block. Callers use this to
 * decide whether to route a blocking I/O through the interruptible wait path.
 */
bool fd_can_block(int guest_fd);

/* Publish linux_flags for a guest fd under fd_lock. Use after fd_alloc when the
 * creating syscall needs to set linux_flags atomically with respect to a
 * concurrent fcntl(F_SETFL/F_SETFD) on the same slot. The fd_alloc-then-
 * publish window is small (the new gfd is not communicated to other threads
 * until the syscall returns) but the lock removes the structural race and keeps
 * every linux_flags writer on one lock domain.
 */
void fd_publish_linux_flags(int guest_fd, int linux_flags);

/* Republish the EL1 urandom read fast-path bit for this fd from the current
 * fd_table type and access mode. Only readable /dev/urandom descriptors are
 * eligible for the bitmap.
 */
void fd_refresh_urandom_bitmap(int fd);

/* Type -> cleanup registry. Modules that own a synthetic fd type register their
 * cleanup at init time; dup and fork-restore paths look up the cleanup from the
 * type so the binding stays consistent without each path re-deriving the
 * dispatch table.
 */
void fd_register_cleanup(int type, void (*cleanup)(int));
void (*fd_cleanup_for_type(int type))(int);

/* True for fd types whose host backing (kqueue for timerfd/inotify, pipe halves
 * for eventfd/signalfd/netlink/pidfd, epoll instance) cannot be meaningfully
 * inherited across fork IPC: macOS SCM_RIGHTS rejects kqueue fds, and the
 * per-class side-table state (eventfd counter, signalfd mask, pidfd target,
 * epoll set, ...) is not serialized. The child must recreate such fds via the
 * appropriate syscall, so the parent filters them from the SCM_RIGHTS payload
 * and the receiver drops any that still arrive.
 */
static inline bool fd_type_is_synthetic(int type)
{
    return type == FD_EVENTFD || type == FD_SIGNALFD || type == FD_TIMERFD ||
           type == FD_INOTIFY || type == FD_NETLINK || type == FD_PIDFD ||
           type == FD_EPOLL;
}

/* Look up a guest FD and return a dup'd host fd owned by the caller.
 * Thread-safe: dup is performed under fd_lock.
 *
 * Returns -1 on failure. Caller MUST close() the returned fd when done.
 */
int fd_to_host_dup(int guest_fd);

/* Mark an FD slot as closed (set type = FD_CLOSED and update bitmap). Does NOT
 * close the host FD or free type-specific resources (DIR*, epoll instance);
 * caller must do that first.
 */
void fd_mark_closed(int fd);

/* Same as fd_mark_closed but requires fd_lock to be already held. Used by
 * sys_execve CLOEXEC loop which holds fd_lock for the entire scan.
 */
void fd_mark_closed_unlocked(int fd);

/* Atomically snapshot an fd entry and mark it closed.
 *
 * Returns true if the slot was open (snapshot written to *out), false if
 * already closed. Prevents the TOCTOU race where two concurrent close() calls
 * both snapshot the same open entry and double-close the host fd.
 */
bool fd_snapshot_and_close(int fd, fd_entry_t *out);

/* Snapshot and close with a single-thread fast path. Uses the unlocked table
 * update when exactly one guest thread is active, otherwise falls back to
 * fd_snapshot_and_close().
 */
bool fd_snapshot_and_close_relaxed(int fd, fd_entry_t *out);

/* Fast-path close for single-threaded plain regular files.
 * Returns true when the slot was closed and the host fd written to
 * *host_fd_out, false when the caller should fall back to the generic close
 * path.
 */
bool fd_close_regular_relaxed(int fd, int *host_fd_out);

/* Release all type-specific resources for a closed FD entry (DIR*, epoll
 * instance, emulated subsystem state) and close the host fd. Caller must have
 * already removed the entry from fd_table.
 */
void fd_cleanup_entry(int guest_fd, const fd_entry_t *snap);

/* Reference-counted wrapper around a directory stream, stored in fd_table[].dir
 * for FD_DIR entries (see syscall/fs.c). A raw DIR* would let a sibling's
 * close()/dup2()/fork-restore free it via closedir() while sys_getdents64() is
 * still mid-loop reading it; the wrapper defers the closedir() until every
 * acquirer -- the fd-table's own reference, plus any in-flight sys_getdents64
 * -- has released it. Guarded by fd_lock, mirroring poll.c's epoll_instance_t
 * refcount.
 *
 * dir_stream_create() takes ownership of dir and returns the wrapper, or NULL
 * on allocation failure (caller still owns dir and must closedir() it itself).
 * dir_stream_release() drops a reference and is a no-op when passed NULL.
 */
void *dir_stream_create(DIR *dir);
void dir_stream_release(void *ds);

/* Translation helpers. */

/* Convert macOS errno to negative Linux errno. */
int64_t linux_errno(void);

/* Translate Linux AT_* flags to macOS equivalents. For unlinkat, fstatat,
 * linkat, fchmodat, fchownat, utimensat.
 */
int translate_at_flags(int linux_flags);

/* Reject any flag bits outside the allowed mask. Caller returns -LINUX_EINVAL
 * on failure. Shared by every *at() handler that validates its flags argument.
 */
static inline int validate_at_flags(int flags, int allowed)
{
    return (flags & ~allowed) == 0;
}

/* Translate Linux faccessat flags to macOS equivalents. Separate from
 * translate_at_flags because Linux AT_EACCESS (0x200) shares the same numeric
 * value as AT_REMOVEDIR; the meaning is context-dependent.
 */
int translate_faccessat_flags(int linux_flags);

/* Translate Linux open flags to macOS equivalents. */
int translate_open_flags(int linux_flags);

/* Translate macOS status flags (F_GETFL result) to Linux equivalents. */
int mac_to_linux_status_flags(int mac_flags);

/* Translate Linux status flags (F_SETFL arg) to macOS equivalents. */
int linux_to_mac_status_flags(int linux_flags);

/* Anonymous mmap for other modules. */

/* Allocate anonymous guest memory. Wraps the static sys_mmap with
 * MAP_PRIVATE|MAP_ANONYMOUS. Caller must hold mmap_lock.
 */
int64_t sys_mmap_anon(guest_t *g, uint64_t addr, uint64_t length, int prot);

/* RLIMIT_NOFILE tracking. */

/* Update the guest RLIMIT_NOFILE soft limit. Called from prlimit64 when
 * resource == RLIMIT_NOFILE. fd_alloc checks this.
 */
void fd_set_rlimit_nofile(int cur);

/* Get the current guest RLIMIT_NOFILE soft limit. */
int fd_get_rlimit_nofile(void);

/* Borrowed-or-owned host fd reference.
 *
 * Single-threaded guests borrow the raw host fd directly (no dup, no close).
 * Multi-threaded guests dup under fd_lock to prevent TOCTOU races with
 * concurrent close() from CLONE_THREAD siblings.
 */
typedef struct {
    host_fd_t fd;
    bool owned;
} host_fd_ref_t;

static inline int host_fd_ref_open(guest_fd_t guest_fd, host_fd_ref_t *ref)
{
    ref->fd = -1;
    ref->owned = false;

    if (thread_is_single_active()) {
        int host_fd = fd_to_host(guest_fd);
        if (host_fd < 0)
            return -1;
        ref->fd = host_fd;
        return 0;
    }

    int host_fd = fd_to_host_dup(guest_fd);
    if (host_fd < 0)
        return -1;
    ref->fd = host_fd;
    ref->owned = true;
    return 0;
}

static inline void host_fd_ref_close(host_fd_ref_t *ref)
{
    /* Preserve errno across close(2). Callers commonly invoke this on the
     * cleanup path after a syscall failed and then read errno to translate the
     * failure; a non-zero close error must not clobber that value.
     */
    int saved_errno = errno;
    if (ref->owned && ref->fd >= 0)
        close(ref->fd);
    ref->fd = -1;
    ref->owned = false;
    errno = saved_errno;
}

/* Open a dirfd reference, treating LINUX_AT_FDCWD as AT_FDCWD. */
static inline int host_dirfd_ref_open(guest_fd_t dirfd, host_fd_ref_t *ref)
{
    if (dirfd == LINUX_AT_FDCWD) {
        ref->fd = AT_FDCWD;
        ref->owned = false;
        return 0;
    }
    return host_fd_ref_open(dirfd, ref);
}

/* Open a host fd reference, rejecting O_PATH (FD_PATH) entries with -EBADF. Use
 * this for syscalls that operate on the underlying file -- read/write, lseek,
 * ftruncate, fsync/fdatasync, flock, fsetxattr/fremovexattr, ioctl, etc. Linux
 * returns EBADF on those calls when the fd was opened O_PATH; the host fd here
 * is a plain O_RDONLY descriptor, so without this gate the host call would
 * silently succeed and diverge from Linux semantics.
 *
 * Calls that are explicitly allowed on O_PATH (fstat, fstatfs, fchdir, close,
 * dup, fcntl get/set CLOEXEC, *at() dirfd) keep using host_{fd,dirfd}_ref_open
 * helpers above.
 */
static inline int64_t host_fd_ref_open_io(guest_fd_t guest_fd,
                                          host_fd_ref_t *ref)
{
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap))
        return -LINUX_EBADF;
    if (snap.type == FD_PATH)
        return -LINUX_EBADF;
    if (host_fd_ref_open(guest_fd, ref) < 0)
        return -LINUX_EBADF;
    return 0;
}

/* iov limits shared between readv/writev/preadv/pwritev and sendmsg/recvmsg.
 * SYSCALL_IOV_MAX matches the Linux UIO_MAXIOV cap; SYSCALL_IOV_STACK_MAX keeps
 * the typical case on the call-site stack.
 */
#define SYSCALL_IOV_MAX 1024
#define SYSCALL_IOV_STACK_MAX 64

/* Resolved host iov vector backed by an inline stack buffer with a heap
 * fallback for large iovcnt. Pair host_iov_prepare with host_iov_free.
 */
typedef struct {
    struct iovec stack[SYSCALL_IOV_STACK_MAX];
    struct iovec *iov;
    struct iovec *heap; /* non-NULL only when iov was heap-allocated */
} host_iov_buf_t;

static inline bool host_iov_has_payload(const host_iov_buf_t *buf, int iovcnt)
{
    for (int i = 0; i < iovcnt; i++) {
        if (buf->iov[i].iov_len > 0)
            return true;
    }
    return false;
}

/* Translate a guest iovec array at iov_gva (iovcnt entries) into the host iovec
 * layout in buf->iov, resolving each guest_base to a contiguous host pointer
 * with the requested permissions. On a non-contiguous iov entry the helper
 * truncates that entry to the contiguous prefix and zeros every subsequent
 * entry; the host readv/writev/sendmsg/recvmsg then returns a POSIX-compliant
 * short I/O instead of silently packing bytes from the next guest buffer into
 * the truncated tail.
 *
 * iovcnt <= 0 or > SYSCALL_IOV_MAX returns -LINUX_EINVAL.
 *
 * Returns 0 on success or a negative Linux errno on failure. The caller must
 * pair every successful prepare with host_iov_free to release any heap
 * spillover.
 */
int64_t host_iov_prepare(guest_t *g,
                         uint64_t iov_gva,
                         int iovcnt,
                         int required_perms,
                         host_iov_buf_t *buf);

/* sendmsg/recvmsg variant: iovcnt == 0 is legal for ancillary-only messages. */
int64_t host_iov_prepare_msg(guest_t *g,
                             uint64_t iov_gva,
                             int iovcnt,
                             int required_perms,
                             host_iov_buf_t *buf);

/* Release any heap spillover backing a host_iov_buf_t. Idempotent. */
void host_iov_free(host_iov_buf_t *buf);

/* Read a guest path string with small-buffer optimization.
 *
 * Tries the stack-allocated short_buf first; falls back to long_buf for paths >
 * short_sz bytes. On success, *out points to whichever buffer contains the path
 * (caller must not free).
 *
 * Returns 0 on success, or -LINUX_EFAULT on failure.
 */
static inline int guest_read_path(guest_t *g,
                                  uint64_t gva,
                                  char *short_buf,
                                  size_t short_sz,
                                  char *long_buf,
                                  size_t long_sz,
                                  const char **out)
{
    if (guest_read_str_small(g, gva, short_buf, short_sz) >= 0) {
        *out = short_buf;
        return 0;
    }
    if (guest_read_str(g, gva, long_buf, long_sz) >= 0) {
        *out = long_buf;
        return 0;
    }
    return -LINUX_EFAULT;
}
