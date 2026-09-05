/*
 * Shared helpers for syscall modules
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Cross-domain declarations: shared locks, the FD table, and translation
 * helpers used by multiple syscall modules.
 *
 * Lock ordering (acquire in ascending order to prevent deadlocks). This is
 * every file-scope lock in the tree that is ever held across another
 * acquisition, whether the inner one is taken directly or through a call. The
 * leaf list below closes it: a lock named there holds nothing beneath it, so
 * the pair of lists is exhaustive rather than "the ones that seemed worth
 * writing down". Adding a mutex or an rwlock means placing it here or in the
 * leaf list, and a leaf that grows a call to another locker moves up here.
 *
 * Per-instance locks (one per epoll instance, futex bucket, FUSE session) are
 * named beside the file-scope lock they nest under. That pairing is the whole
 * of their ordering except for the FUSE session lock, which also holds fd_lock
 * and sig_lock beneath it: fuse_queue_request_locked runs with the session lock
 * held and reaches asyncio_fire, which snapshots an fd and queues a signal.
 * fuse_lock is always dropped before the session lock is used that way, so the
 * two claims do not meet.
 *
 * That path, in acquisition order:
 *
 *            ┌───────────┐
 *            │ fuse_lock │
 *            └───────────┘
 *                  │
 *   ┌──────────────▾──────────────┐
 *   │ pin session, drop fuse_lock │
 *   └─────────────────────────────┘
 *                  └┐
 *                   │
 *           ┌───────▾──────┐
 *           │ session lock │
 *           └──────────────┘
 *          ┌───────┘ └────┐
 *          │              │
 *     ┌────▾────┐   ┌─────▾────┐
 *     │ fd_lock │   │ sig_lock │
 *     └─────────┘   └──────────┘
 *
 * cwd_lock is not drawn above it. It nests fuse_lock beneath it on the one path
 * that pairs them, and fuse_path_matches_mount drops fuse_lock before returning
 * into the cwd view, so cwd_lock is released before any session is pinned and
 * never reaches the rest of this chain.
 *
 * The numbered "Lock order: N" comments at the definitions predate this list
 * and are not indices into it. This list is the document; a number there says
 * only which locks that one was known to precede when it was written.
 *
 *   proc_tmpdir_lock (runtime/procemu.c): lazy /proc snapshot tree; holds
 *                                     mmap_lock beneath it, because
 *                                     ensure_proc_tmpdir builds the
 *                                     /proc/self/maps and smaps snapshots
 *                                     through proc_intercept_open while the
 *                                     lock is held. Above mmap_lock, so
 *                                     mmap_lock's "1" means first among the
 *                                     locks a syscall path takes, not that
 *                                     nothing precedes it
 *   mmap_lock    (syscall/mem.c):     mmap/brk allocators + page tables
 *   pt_lock      (core/guest.c):      page table pool allocator
 *   pty_keepalive_lock (runtime/procemu-pty.c): pty master keepalive table;
 *                                     holds fd_lock beneath it in
 *                                     proc_pty_master_adopt's joint publish
 *                                     window and in duplicate_guest_fd, which
 *                                     brackets fd_snapshot_and_dup. Both paths
 *                                     take it in this direction, which is what
 *                                     keeps them from deadlocking each other
 *   oom_write_lock (runtime/procemu.c): /proc/self/oom_score_adj writer; holds
 *                                     fd_lock beneath it through
 *                                     proc_oom_refresh_live_fds_locked
 *   fd_lock      (syscall/fdtable.c): FD table (alloc/close/dup)
 *   epoll inst   (syscall/poll.c):    per-epoll-instance regs[]; taken under
 *                                     fd_lock by the close hook, taken alone
 *                                     (no fd_lock held) by epoll_ctl/pwait
 *   exec_handoff_lock (syscall/exec.c): the one execve handoff slot; nested
 *                                     under mmap_lock only by
 *                                     exec_handoff_reset, and holds sig_lock
 *                                     beneath it through
 *                                     signal_restore_blocked. sys_execve does
 *                                     not acquire mmap_lock until the point of
 *                                     no return, so a requester waiting for the
 *                                     slot never holds it
 *   sig_lock     (syscall/signal.c):  signal handlers/pending/blocked
 *   thread_lock  (runtime/thread.c):  thread table
 *   sfd_lock     (syscall/fd.c):      special fd (never held with thread_lock)
 *   autoreap_lock (syscall/proc.c):   serializes the whole no-zombie reap
 *                                     sequence against rt_sigaction; holds
 *                                     pid_lock and, through
 *                                     proc_pidfd_notify_exit, pidfd_lock
 *   elf_path_lock (syscall/proc-state.c): cached /proc/self/exe path; holds
 *                                     cwd_lock beneath it through
 *                                     proc_get_cwd, and sysroot_lock through
 *                                     the proc_cwd_refresh that runs with
 *                                     cwd_lock dropped
 *   pid_lock     (syscall/proc.c):    process table / wait state
 *   pidfd_lock   (syscall/proc-pidfd.c): pidfd registry
 *   futex bucket (runtime/futex.c):   per-bucket, index-ordered if >1
 *   cwd_lock     (syscall/proc-state.c): cached guest cwd. A leaf on every
 *                                     path but one: proc_acquire_cwd_view
 *                                     returns still holding it, and both
 *                                     callers that inspect view.path in place
 *                                     (sys_faccessat, fuse_resolve_at_path)
 *                                     call fuse_path_matches_mount inside the
 *                                     view, so fuse_lock nests beneath it
 *   fuse_lock    (syscall/fuse.c):    mount/session registry; holds the
 *                                     per-session session->lock beneath it,
 *                                     which is what pins a session against
 *                                     daemon exit while a request is in flight
 *   inotify_lock (syscall/inotify.c): inotify watch table
 *
 * Leaves. Each of these is the innermost lock on every path that takes it, so
 * it has no position in the order above and cannot be half of an inversion:
 *
 *   absock_lock (net-absock.c)       rlimit_lock (sys.c)
 *   log_mutex (debug/log.c)          rosettad_path_lock (rosetta.c)
 *   nl_lock (netlink.c)              session_lock (proc-identity.c)
 *   overlay_lock (chown-overlay.c)   shm_dir_lock (procemu.c)
 *   proc_scratch_lock (procemu.c)    shm_lock (sysvipc.c)
 *   removed_overlay_lock (fs.c)      syscpu_dir_lock (procemu.c)
 *                                    sysinfo_lock (sys.c)
 *                                    sysroot_lock (proc-state.c)
 *                                    usb_lock (runtime/usb-sysfs.c)
 *
 * log_mutex is the one leaf every other entry may hold: a lock anywhere in
 * either list can log while held. It sits below the whole order rather than
 * beside the rest of the leaves, and it acquires nothing itself, so it closes
 * no cycle.
 *
 * pt_lock, thread_lock, sfd_lock, pid_lock and pidfd_lock are leaves today too.
 * They stay in the ordered list because each is named as an inner lock above,
 * so the order they would be acquired in is the load-bearing fact about them.
 * sig_lock is not one of them: signal_queue_thread_common takes thread_lock
 * under it.
 */

#pragma once

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <unistd.h>

#include "proved/iov.h"
#include "proved/timespec.h"

#include "syscall/linux-wire.h"
#include "linux-limits.h"
#include "runtime/thread.h"

typedef int guest_fd_t;
typedef int host_fd_t;

/* Cross-module locks. */
extern pthread_mutex_t mmap_lock; /* Lock order: 1, mmap/brk + page tables */
extern pthread_mutex_t fd_lock;   /* Lock order: 3, FD table */

/* The only supported mmap_lock entry/exit API. Acquire drains the per-vCPU EL1
 * mmap rings before any caller can inspect semantic region state.
 */
void mmap_lock_acquire(guest_t *g);
void mmap_lock_release(void);
void mmap_lock_cond_wait(guest_t *g, pthread_cond_t *cond);

/* Temporarily drop mmap_lock while retaining the host PT-gate reference, then
 * reacquire without taking a second reference. Used only by lazy zeroing.
 */
void mmap_lock_drop_keep_gate(void);
void mmap_lock_reacquire_with_gate(guest_t *g);

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

/* The status bits that belong to the open file description rather than to the
 * fd slot naming it, so a dup carries them to the alias and an alias sweep may
 * write them to every slot sharing an ofd_id.
 *
 * One list because four hand-written copies of it had already drifted into two
 * memberships, and neither carried O_APPEND or O_NOATIME -- which F_SETFL on a
 * timerfd writes to the shadow, so a dup of one reported the flag on one name
 * for it and not the other. The mode and the open-time bits are here for the
 * same reason O_NONBLOCK is: dup(2) gives the alias the same description, so
 * whatever the shadow answers for one name it has to answer for all of them.
 */
#define FD_DESCRIPTION_FLAGS                                                 \
    (LINUX_O_ACCMODE | LINUX_O_PATH | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW | \
     LINUX_O_DIRECT | LINUX_O_LARGEFILE | LINUX_O_NONBLOCK | LINUX_O_ASYNC | \
     LINUX_O_APPEND | LINUX_O_NOATIME)

/* What a new fd slot inherits from an open file description that already
 * exists. Every field is a separate claim, and a site has to make each one on
 * purpose: build this with one of the constructors below rather than by
 * initializer, so "not set" cannot quietly mean "not foreign, not owned, fresh
 * identity" the way a partial fd_entry_t did. Four of the seven alias sites
 * shipped a defect while it did.
 *
 * Both ownership fields matter. A dup of the launcher's stdin is typed
 * FD_REGULAR, so a type test cannot see what it aliases, and taking O_NONBLOCK
 * ownership there leaves the launching shell's terminal nonblocking after
 * elfuse exits; carrying foreign_description keeps that fact through a dup of a
 * dup, and through fork, which rebuilds the whole table from descriptions the
 * parent already holds. Carrying nonblock_owned also saves the probe: an alias
 * shares the description, so its answer cannot differ from its source's.
 */
typedef struct {
    uint64_t ofd_id; /* 0: mint a fresh description identity */
    int linux_flags; /* guest-visible flags to publish with the slot */
    bool foreign_description;
    bool nonblock_owned;

    /* Whether Linux gives the source's file a poll method. It is a fact about
     * the description, not about the name: every alias of one open
     * /proc/self/mountinfo has to answer epoll_target_supported the same way,
     * and fstat cannot recover the answer from elfuse's staging file.
     */
    bool path_poll_capable;

    /* The live source to re-read under fd_lock, or -1 for a site with no
     * in-process source. The fields above are a snapshot the caller took before
     * the allocation, and an F_SETFL landing in between sweeps the aliases that
     * exist at that moment -- which does not include the one being built.
     * Publishing from the snapshot then gives the new name a shadow the rest of
     * the description has already moved past: a dup of a blocking pipe reports
     * blocking through F_GETFL and waits in io_xfer while every other name for
     * it is nonblocking.
     *
     * src_generation is what makes the re-read safe. A close+reopen in the same
     * window puts a different description behind the same number, and
     * re-reading then would copy identity and flags from a file the caller
     * never saw. When the generation has moved the snapshot is used as-is,
     * which is the behaviour this field replaces rather than a new risk.
     */
    int src_guest_fd;
    uint64_t src_generation;
} fd_alias_spec_t;

/* A full alias: same description, same identity, same status flags. dup(2),
 * dup2, dup3, F_DUPFD and the Rosetta socket upgrade.
 *
 * src_guest_fd is the number the snapshot came from, so the allocator can take
 * the description state again under the lock that publishes the new slot. Pass
 * -1 for a source that is no longer addressable by number -- the Rosetta socket
 * upgrade rebuilds the very slot it snapshotted, so re-reading it would find
 * the replacement it is in the middle of installing.
 */
static inline fd_alias_spec_t fd_alias_of(int src_guest_fd,
                                          const fd_entry_t *src)
{
    return (fd_alias_spec_t) {
        .ofd_id = src->ofd_id,
        .linux_flags = src->linux_flags & FD_DESCRIPTION_FLAGS,
        .foreign_description = src->foreign_description,
        .nonblock_owned = src->nonblock_owned,
        .path_poll_capable = src->path_poll_capable,
        .src_guest_fd = src_guest_fd,
        .src_generation = src->generation,
    };
}

/* The same host description, but an identity of its own: opening a magic link
 * (/proc/self/fd/N, /dev/stdin) dups the descriptor, so the host flags are
 * shared and must not be touched, while Linux gives the result a new open file
 * description. Sweeping the source's aliases from it would be wrong.
 */
static inline fd_alias_spec_t fd_alias_host_shared(const fd_entry_t *src)
{
    return (fd_alias_spec_t) {
        .src_guest_fd = -1,
        .foreign_description = src->foreign_description,
        .nonblock_owned = src->nonblock_owned,
        .path_poll_capable = src->path_poll_capable,
    };
}

/* The same identity, with the flags the caller has already worked out: a dup of
 * a synthetic fd, whose host fd is elfuse's own pipe or kqueue. Not foreign
 * (elfuse opened it) and not owned (fd_nonblock_shadowed answers from the type
 * for those), so the alias sweeps find it and nothing else changes.
 *
 * Passing the flags here rather than writing them after the allocation is the
 * point: a slot published first and patched second is observable in between
 * with the wrong flags, which for an EFD_NONBLOCK eventfd means a sibling
 * reading it as blocking.
 */
static inline fd_alias_spec_t fd_alias_identity(uint64_t ofd_id,
                                                int linux_flags)
{
    return (fd_alias_spec_t) {
        .src_guest_fd = -1, .ofd_id = ofd_id, .linux_flags = linux_flags};
}

/* Ownership facts only, for the two sites with no source slot to point at: a
 * descriptor arriving over SCM_RIGHTS, and the fork rebuild, which remaps
 * identities itself once every slot exists.
 */
static inline fd_alias_spec_t fd_alias_carried(bool foreign, bool owned)
{
    return (fd_alias_spec_t) {
        .src_guest_fd = -1,
        .foreign_description = foreign,
        .nonblock_owned = owned,
    };
}

/* Allocate a slot that inherits from `spec`, applying the inheritance inside
 * the same fd_lock window that publishes the slot: a close+reopen in a gap
 * would otherwise take the alias's identity and be swept as though it shared a
 * description it never saw.
 *
 * fixed_fd >= 0 asks for that exact slot; otherwise the lowest free slot at or
 * above minfd. The _relaxed variant skips the lock for the generation read when
 * this is the only active thread, matching fd_alloc_from_relaxed.
 */
int fd_alloc_alias(const fd_alias_spec_t *spec,
                   int type,
                   int host_fd,
                   void (*cleanup)(int));
int fd_alloc_alias_at(const fd_alias_spec_t *spec,
                      int fd,
                      int type,
                      int host_fd,
                      void (*cleanup)(int),
                      uint64_t *out_gen);
int fd_alloc_alias_relaxed(const fd_alias_spec_t *spec,
                           int fixed_fd,
                           int minfd,
                           int type,
                           int host_fd,
                           void (*cleanup)(int),
                           uint64_t *out_gen);
int fd_alloc_alias_dir(const fd_alias_spec_t *spec,
                       int fixed_fd,
                       int minfd,
                       int type,
                       int host_fd,
                       void (*cleanup)(int),
                       void *dir,
                       int linux_flags,
                       uint64_t *out_gen);

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
                      int linux_flags,
                      uint64_t *out_gen);
int fd_alloc_dir_at(int fd,
                    int type,
                    int host_fd,
                    void (*cleanup)(int),
                    void *dir,
                    int linux_flags,
                    uint64_t *out_gen);

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

/* Read the generation currently published for a guest fd.
 *
 * Returns 0 when the slot is closed or out of range. Generations start at 1 and
 * only ever increase, so 0 never compares equal to a live one and a slot that
 * changed can never compare equal to an earlier reading. Use this to re-check a
 * generation pinned earlier, not to pin one against a host fd resolved in a
 * separate window -- see host_fd_ref_open_io_gen() for that.
 */
uint64_t fd_current_generation(int guest_fd);

/* Snapshot an fd entry AND dup its host fd in a single fd_lock critical
 * section. Eliminates the TOCTOU window between reading the type/metadata and
 * duplicating the host fd in the dup(2) path.
 *
 * Returns the dup'd host fd (owned by the caller) on success, -1 on failure. On
 * success the snapshot in *out is consistent with the dup'd host fd.
 */
int fd_snapshot_and_dup(int guest_fd, fd_entry_t *out);

/* The dup(2) form of the above: snapshot an fd entry and take, in the same
 * fd_lock critical section, whatever the duplicate has to own.
 *
 * A directory is duplicated by sharing its stream rather than by duplicating
 * its descriptor. dup(2) gives the alias the same open file description, so the
 * two guest fds share one listing position -- and, because the union state a
 * synthetic directory carries lives in that same wrapper, one union state as
 * well. Handing the alias its own fdopendir() over a duplicated descriptor gave
 * it a second position and a second, empty union state instead, which is how a
 * dup'd union directory came to re-emit the backing names the source had
 * already delivered.
 *
 * On a shared return the host descriptor is the source's own, already owned by
 * the stream, so the caller must neither close it nor hand it to
 * dir_stream_open(); it installs *out's `dir` pointer as the alias's stream and
 * balances the reference taken here with dir_stream_release().
 *
 * Returns the host fd the duplicate is to be installed with -- a fresh dup for
 * every other type, the source's own when *out_shared_dir is set -- or -1 on
 * failure.
 */
int fd_snapshot_and_dup_or_share_dir(int guest_fd,
                                     fd_entry_t *out,
                                     bool *out_shared_dir);

/* Read just the fd type under fd_lock.
 *
 * Returns FD_CLOSED for out-of-range or closed slots. Cheaper than fd_snapshot
 * when only the type is needed for dispatch (sys_read/sys_readv/sys_writev fast
 * paths).
 */
int fd_get_type(int guest_fd);

/* The fields a transfer needs to decide how to run, read in one go. type is
 * FD_CLOSED when the slot is closed or out of range. guest_nonblock is what the
 * guest asked for, which on an owned fd is the only place it is recorded. seals
 * rides along so a write path can reject a sealed memfd from the state it
 * pinned, rather than from a second lookup that may describe another file.
 */
typedef struct {
    int type;
    uint64_t generation;
    unsigned seals;
    bool can_block;
    bool nonblock_owned;
    bool guest_nonblock;
} fd_block_state_t;

fd_block_state_t fd_block_state(int guest_fd);

/* Set or clear the guest's O_NONBLOCK shadow on every slot sharing guest_fd's
 * open file description, anchored on guest_fd's generation so a close+reopen in
 * the window changes nothing. O_NONBLOCK is a per-description flag on Linux, so
 * a dup alias has to observe what the original asked for. On an fd whose
 * O_NONBLOCK elfuse owns (see fd_init_entry) the host flag can no longer carry
 * that, since elfuse holds it set, which is why the shadow has to be walked by
 * hand. Call fn for every fd sharing guest_fd's open file description,
 * including guest_fd itself, or not at all when the slot moved under the caller
 * (a close+reopen that reused the number). The caller must hold fd_lock, and fn
 * runs under it: the sweeps this serves mutate per-description state, and
 * dropping the lock between finding an alias and touching it would let a
 * sibling close retire the fd in between.
 *
 * Per-description state has no home of its own in this tree. O_NONBLOCK,
 * O_ASYNC and the SIGIO owner all live per fd entry and are kept in step by
 * sweeping the aliases, and this is the one place that knows how.
 *
 * The callers hold fd_lock; the sweep does not take it. Every writer of
 * per-description state goes through here, so the lock covers the whole sweep
 * rather than each slot in turn.
 */
void fd_for_each_alias_locked(int guest_fd,
                              uint64_t generation,
                              void (*fn)(int guest_fd, void *ctx),
                              void *ctx);

/* Apply the bits of value selected by mask to the guest-visible status flags of
 * every fd sharing guest_fd's open file description.
 *
 * Every bit answered from the shadow belongs to the description, not to the
 * slot, so a change through one alias has to reach the rest: F_GETFL on a dup
 * of a timerfd reported stale O_APPEND and O_NOATIME while only O_NONBLOCK was
 * being swept.
 */
void fd_set_shadow_flags(int guest_fd,
                         uint64_t generation,
                         int mask,
                         int value);

/* The guest's O_NONBLOCK for a fd whose host description is elfuse's own: a
 * synthetic fd is backed by a pipe or a kqueue held nonblocking so the
 * emulation can drive the waiting itself, so the host flag says nothing about
 * what the guest asked for and the shadow is the only record.
 *
 * Every synthetic reader answers from here: eventfd, signalfd, timerfd, inotify
 * and netlink. When one of them kept its own copy of the flag instead, a guest
 * that set O_NONBLOCK with fcntl after creating the fd had it reported back
 * correctly and then blocked forever on an empty read.
 *
 * Takes fd_lock, so callers must not already hold a lock that orders after it
 * (sfd_lock=5a, inotify_lock); read the flag before taking those.
 */
bool fd_guest_nonblock(int guest_fd);

/* Route a guest O_NONBLOCK request (F_SETFL, ioctl FIONBIO) to the shadow when
 * elfuse owns the host flag on this fd.
 *
 * Returns false when it does not, and the caller should apply the request to
 * the host fd itself.
 */
bool fd_apply_guest_nonblock(int guest_fd, bool on);

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

/* The status bits the host description is authoritative for. Everything outside
 * this mask is answered from the shadow, which is the inversion of how F_GETFL
 * used to read: it asked the host and then overrode the answer bit by bit,
 * eight special cases deep, taking the access mode from the shadow in two
 * separate places for two disjoint type sets.
 *
 * Zero means the host has nothing to say, which is the honest answer for a type
 * elfuse emulates whole: the fd behind it is elfuse's own pipe or kqueue, so
 * F_GETFL cannot ask it what the guest opened and F_SETFL must not tell it.
 * That second half matters -- a kqueue rejects fcntl(F_SETFL), which is why
 * timerfd already had a hand-written branch to skip the host call while
 * signalfd and inotify fell through to it.
 *
 * O_NONBLOCK is not decided here because it is not a property of the type
 * alone: fd_nonblock_shadowed answers it per fd, and F_GETFL clears the bit
 * from this mask when it does.
 */
static inline int fd_host_flag_mask(int type)
{
    /* An fd elfuse serves out of its own descriptor: nothing to ask. */
    if (fd_type_is_synthetic(type) || type == FD_FUSE_DEV ||
        type == FD_FUSE_FILE || type == FD_FUSE_DIR)
        return 0;

    /* Bits the host description never carries for anyone: elfuse tracks O_ASYNC
     * itself (it is never armed on the host fd), and the open-time bits are
     * Linux spellings macOS has no equivalent for.
     */
    int mask =
        ~(LINUX_O_PATH | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW | LINUX_O_DIRECT |
          LINUX_O_LARGEFILE | LINUX_O_ASYNC | LINUX_O_NOATIME);

    /* And the access mode, for the types elfuse opens on the host with a mode
     * of its own choosing: an O_PATH or directory fd is opened read-only
     * whatever the guest asked for. A pipe, socket or inherited stdio really
     * was opened the way the guest sees it, so the host answers for those.
     */
    switch (type) {
    case FD_REGULAR:
    case FD_DIR:
    case FD_PATH:
    case FD_URANDOM:
        mask &= ~LINUX_O_ACCMODE;
        break;
    default:
        break;
    }
    return mask;
}

/* Bits the shadow holds that F_GETFL must never report: CLOEXEC is a descriptor
 * flag, answered by F_GETFD, and Linux does not surface it here.
 */
#define FD_GETFL_HIDDEN (LINUX_O_CLOEXEC)


/* True when fd_entry_t.linux_flags, not the host description, is where this
 * fd's O_NONBLOCK lives. Two ways to get there: elfuse owns the host flag so a
 * transfer can report EAGAIN instead of parking a vCPU (fd_init_entry), or the
 * host fd is elfuse's own pipe or kqueue and the guest is not talking to it at
 * all, in which case the host flag has to stay as the emulation needs it.
 *
 * Everything that answers or records the flag agrees through this: F_GETFL,
 * F_SETFL, ioctl FIONBIO, the transfer paths, and the synthetic readers.
 */
static inline bool fd_nonblock_shadowed(int type, bool nonblock_owned)
{
    return nonblock_owned || fd_type_is_synthetic(type);
}

/* Look up a guest FD and return a dup'd host fd owned by the caller.
 * Thread-safe: dup is performed under fd_lock.
 *
 * Returns -1 on failure. Caller MUST close() the returned fd when done.
 */
int fd_to_host_dup(int guest_fd);

/* Refcount that keeps a host fd open across a concurrent syscall. Defined in
 * fdtable.c; opaque to every caller.
 */
typedef struct fd_lifetime fd_lifetime_t;

/* Pin the host fd of a live slot and snapshot the entry, in one fd_lock window.
 * The pin keeps the host descriptor open for the duration of a host call even
 * if a sibling closes the guest fd, which is what the per-call dup used to buy;
 * unlike the dup it does not consume a host descriptor, and it leaves POSIX
 * record locks alone (closing any descriptor for an inode drops the process's
 * locks on it, so the old dup released an F_SETLK the moment it went away).
 *
 * The snapshot describes the same description the pin holds: the guest fd
 * number can be reused for another kind of object as soon as fd_lock is
 * dropped, so a classification taken afterwards would describe something the
 * caller is not holding.
 *
 * Returns the host fd, or -1 with errno set to EBADF (no such live slot) or
 * ENOMEM. The caller must pass *lifetime_out to fd_lifetime_release exactly
 * once; the slot holds its own separate reference.
 */
int fd_host_ref_acquire(int guest_fd,
                        fd_entry_t *out,
                        fd_lifetime_t **lifetime_out);

/* Pin a live slot with fd_lock already held.
 *
 * Returns NULL when the slot is closed, carries no host descriptor, or the
 * allocation fails. For a caller already walking the table under the lock;
 * allocates inside it, so fork-scale callers only.
 */
fd_lifetime_t *fd_lifetime_pin_locked(int fd);

/* Drop one reference. The last release closes the host fd (except for FD_STDIO,
 * which elfuse did not open) and frees the object.
 */
void fd_lifetime_release(fd_lifetime_t *lifetime);

/* Mark an FD slot as closed (set type = FD_CLOSED and update bitmap) and detach
 * its lifetime. Does NOT close the host FD or free type-specific resources
 * (DIR*, epoll instance); caller must do that first.
 *
 * Detaching is not releasing. The returned lifetime carries the slot's own
 * reference and the caller now owns it: either hand it to fd_lifetime_release,
 * or ignore the return only because a snapshot taken before this call still
 * carries the same pointer and will reach fd_cleanup_entry. A caller that does
 * neither strands the reference and the host fd never closes.
 *
 * A caller that just wants to retire a published slot and close its host fd
 * should call fd_retire_published instead of open-coding either shape.
 */
fd_lifetime_t *fd_mark_closed(int fd);

/* Same as fd_mark_closed but requires fd_lock to be already held. Used by
 * sys_execve CLOEXEC loop which holds fd_lock for the entire scan.
 */
fd_lifetime_t *fd_mark_closed_unlocked(int fd);

/* Retire a slot the caller published in fd_table and close the host fd it owns,
 * deferring the close to the last in-flight borrower when one holds a pin. The
 * rollback path for a syscall that published a slot and then failed.
 *
 * A slot that no longer holds host_fd is left entirely alone, its descriptor
 * included: reaching that means a sibling already closed this guest fd and that
 * close retired the descriptor. See the definition for what the check does and
 * does not prove.
 */
void fd_retire_published(int fd, int host_fd);

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
 * acquirer has released it. Guarded by fd_lock, mirroring poll.c's
 * epoll_instance_t refcount.
 *
 * The wrapper also owns the host descriptor. fdopendir() adopts the descriptor
 * it is handed and only closedir() gives it back, so an FD_DIR slot cannot also
 * close its own host_fd -- that is what the descriptor doubling this replaced
 * was paying for. (fdclosedir(3) would hand the descriptor back without closing
 * it, but it is macOS 26.4+ and elfuse supports macOS 13+.) Everything that
 * needs the descriptor to stay valid therefore holds a reference here:
 *
 *   - the fd-table slot          (released by fd_cleanup_entry)
 *   - every other fd-table slot  (a dup shares the source's stream rather than
 *     that aliases it           opening one, so the alias is one more slot
 *                               reference on the same wrapper -- see
 *                               fd_snapshot_and_dup_or_share_dir)
 *   - an in-flight getdents64    (dir_stream_acquire, syscall/fs.c)
 *   - an fd_lifetime pin         (fdtable.c, which delegates its close here)
 *
 * dir_stream_open() takes ownership of host_fd and returns the wrapper, or NULL
 * with errno set, in which case host_fd is untouched and still the caller's.
 * dir_stream_ref_locked() takes an extra reference and requires fd_lock.
 * dir_stream_release() drops a reference and is a no-op when passed NULL; it
 * takes fd_lock itself, so no caller may hold it.
 */
void *dir_stream_open(int host_fd);
void dir_stream_ref_locked(void *ds);
void dir_stream_release(void *ds);

/* The same, for the directory fds a forked child inherits.
 *
 * The child receives the parent's descriptor over SCM_RIGHTS, so the two
 * processes hold one open file description, and the two halves of a union
 * listing are worth different things across it.
 *
 * The primary is shared and must be read. Darwin's fdopendir() reads one host
 * block ahead as it builds the stream and leaves the description just past it,
 * so what the parent's open() took is in the parent's memory and the rest of
 * the directory is still in the description for the child to read: measured
 * over the 403-name sysroot directory tests/test-dir-union-alias stages (macOS
 * 15.6, APFS), the parent's open takes 49 names and the child's stream reads
 * the remaining 354. A five-name directory fits inside that one block, which is
 * the whole reason a five-name measurement reads as all-or-nothing; it is not
 * what a directory of any width does. So the child's stream is built like any
 * other and walks its primary normally, and the split that falls out is real --
 * not Linux's split, but a partition, with nothing counted twice and nothing
 * dropped.
 *
 * The backing is not shared and must not be re-read. It is drained into
 * whichever stream first runs out of primary and held there as names, so a
 * child that drained one of its own would emit every backing name a second time
 * -- names the parent's stream still holds and goes on to deliver.
 * dir_stream_open() would do exactly that. This wrapper comes back with the
 * backing half marked private instead: the drain is skipped, the walk ends when
 * the primary does, and the parent delivers the backing once.
 *
 * The gap this leaves is a child whose parent closes its copy of the fd before
 * the backing is ever drained: nobody is left holding the half the parent owns,
 * and the child answers with its primary alone. Measured over the same two
 * fixtures, forking and closing the parent's fd at once gives the child 354 of
 * the plain directory's 403 names -- the 49 the parent's open had taken go with
 * it, which is the loss any inherited stream takes -- and 0 of the union's 405,
 * because that tree's synthetic half fits inside the block that open consumed.
 * Linux gives the child all 403. Closing it would mean keeping the position and
 * the union state in the description rather than in a DIR* one process owns,
 * which is a rewrite of every directory read and is not attempted here.
 *
 * Suppressing the whole walk rather than just the drain is the mistake this
 * interface exists to avoid, and it is not a small one. A stream created
 * already at the end of its listing never reads the primary at all, so the
 * block its own fdopendir() consumed is lost to both sides: measured over that
 * same 403-name directory, an unread fork came back with 352 names across the
 * pair instead of 403, with no error at either end.
 *
 * Linux keeps the position in the description and splits the listing there --
 * measured in docker (gcc 14.4, Linux 6.19 aarch64) over the same fork sequence
 * that lane runs, an unread directory fd forked and drained by the child gives
 * the child all 403 names and the parent 0, and draining the parent first gives
 * the parent all 403 and the child 0. elfuse cannot reproduce which side
 * delivers, because the block the open read ahead lives in a DIR* the opener
 * owns rather than in the description; what it can do, and what this preserves,
 * is deliver each name exactly once across the pair. Measured over that lane's
 * fixtures in all four states a parent can fork in -- unread, part-read, read
 * to the end, and forked then read by the parent first -- the plain 403-name
 * directory and the 405-name union each come back whole and without a repeat.
 */
void *dir_stream_open_inherited(int host_fd);

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

/* Borrowed-or-pinned host fd reference.
 *
 * Single-threaded guests borrow the raw host fd directly (no dup, no close).
 * Multi-threaded guests pin the slot's host fd until the syscall completes.
 */
typedef struct {
    host_fd_t fd;
    fd_lifetime_t *lifetime;
} host_fd_ref_t;

/* An empty ref, safe to hand to host_fd_ref_close without ever opening it.
 *
 * Naming fd is enough: a designated initializer zeroes every member it does not
 * name, so lifetime comes out NULL. Spell it this way rather than listing them,
 * which is how one initializer came to say ".owned = 0" and three others to
 * omit a member added later.
 */
#define HOST_FD_REF_INIT ((host_fd_ref_t) {.fd = -1})

static inline fd_block_state_t fd_block_state_of(const fd_entry_t *e);

/* Returns 0, or a negative Linux errno the caller propagates unchanged. A slot
 * that is closed or out of range is -LINUX_EBADF; an open slot the pin could
 * not be allocated for is -LINUX_ENOMEM, so a caller can tell a bad descriptor
 * from a host that is out of memory. O_PATH entries are accepted here; the
 * calls that Linux rejects on one use host_fd_ref_open_io() instead.
 */
static inline int64_t host_fd_ref_open(guest_fd_t guest_fd, host_fd_ref_t *ref)
{
    ref->fd = -1;
    ref->lifetime = NULL;

    if (thread_is_single_active()) {
        int host_fd = fd_to_host(guest_fd);
        if (host_fd < 0)
            return -LINUX_EBADF;
        ref->fd = host_fd;
        return 0;
    }

    fd_entry_t snap;
    int host_fd = fd_host_ref_acquire(guest_fd, &snap, &ref->lifetime);
    if (host_fd < 0)
        return linux_errno();
    ref->fd = host_fd;
    return 0;
}

/* Pin the host fd and classify the slot together, so a transfer acts on the
 * object it is holding rather than on whatever took that fd number afterwards.
 * With one active thread there is no mutator and the two relaxed reads are
 * already consistent; with siblings alive both come from one fd_lock window.
 */
static inline int64_t host_fd_ref_open_state(guest_fd_t guest_fd,
                                             host_fd_ref_t *ref,
                                             fd_block_state_t *st_out)
{
    ref->fd = -1;
    ref->lifetime = NULL;

    /* Settle the classification before anything can fail. Every failure exit
     * below has to leave one behind, or a caller that reads it after a refused
     * open reads whatever was on its stack.
     */
    *st_out = (fd_block_state_t) {.type = FD_CLOSED};

    if (thread_is_single_active()) {
        int host_fd = fd_to_host(guest_fd);
        if (host_fd < 0)
            return -LINUX_EBADF;
        *st_out = fd_block_state(guest_fd);
        ref->fd = host_fd;
        return 0;
    }

    fd_entry_t snap;
    int host_fd = fd_host_ref_acquire(guest_fd, &snap, &ref->lifetime);
    if (host_fd < 0)
        return linux_errno();
    *st_out = fd_block_state_of(&snap);
    ref->fd = host_fd;
    return 0;
}

/* Pin the host fd and take the slot's whole entry together, for a caller that
 * decides something from the slot's own record -- its stamped virtual path, say
 * -- as well as from the descriptor. Two separate lookups of one guest fd let a
 * close and reopen between them answer from the record of one open file
 * description and the descriptor of another.
 *
 * The same shape as host_fd_ref_open_state, and the same reasoning: with one
 * active thread there is no mutator, and with siblings alive both come from the
 * fd_lock window inside fd_host_ref_acquire.
 */
static inline int64_t host_fd_ref_open_entry(guest_fd_t guest_fd,
                                             host_fd_ref_t *ref,
                                             fd_entry_t *snap_out)
{
    ref->fd = -1;
    ref->lifetime = NULL;

    /* Settle the entry before anything can fail, so a caller that reads it
     * after a refused open reads a closed slot rather than its own stack.
     */
    *snap_out = (fd_entry_t) {.type = FD_CLOSED};

    if (thread_is_single_active()) {
        int host_fd = fd_to_host(guest_fd);
        if (host_fd < 0)
            return -LINUX_EBADF;
        if (!fd_snapshot(guest_fd, snap_out))
            return -LINUX_EBADF;
        ref->fd = host_fd;
        return 0;
    }

    int host_fd = fd_host_ref_acquire(guest_fd, snap_out, &ref->lifetime);
    if (host_fd < 0)
        return linux_errno();
    ref->fd = host_fd;
    return 0;
}

static inline void host_fd_ref_close(host_fd_ref_t *ref)
{
    /* Preserve errno across close(2). Callers commonly invoke this on the
     * cleanup path after a syscall failed and then read errno to translate the
     * failure; a non-zero close error must not clobber that value.
     */
    int saved_errno = errno;
    if (ref->lifetime)
        fd_lifetime_release(ref->lifetime);
    ref->fd = -1;
    ref->lifetime = NULL;
    errno = saved_errno;
}

/* Open a dirfd reference, treating LINUX_AT_FDCWD as AT_FDCWD. */
static inline int64_t host_dirfd_ref_open(guest_fd_t dirfd, host_fd_ref_t *ref)
{
    if (dirfd == LINUX_AT_FDCWD) {
        ref->fd = AT_FDCWD;
        ref->lifetime = NULL;
        return 0;
    }
    return host_fd_ref_open(dirfd, ref);
}

/* Open both dirfd references a two-path *at() call needs, releasing the first
 * if the second fails so no caller has to spell that rollback again. On success
 * both refs are the caller's to close.
 */
static inline int64_t host_dirfd_ref_open_pair(guest_fd_t olddirfd,
                                               guest_fd_t newdirfd,
                                               host_fd_ref_t *old_ref,
                                               host_fd_ref_t *new_ref)
{
    int64_t err = host_dirfd_ref_open(olddirfd, old_ref);
    if (err < 0)
        return err;
    err = host_dirfd_ref_open(newdirfd, new_ref);
    if (err < 0)
        host_fd_ref_close(old_ref);
    return err;
}

/* The transfer classification carried by an entry already in hand. Callers that
 * snapshot and dup in one window get their state from here rather than looking
 * the slot up again, which is what makes the two describe the same object.
 */
static inline fd_block_state_t fd_block_state_of(const fd_entry_t *e)
{
    return (fd_block_state_t) {
        .type = e->type,
        .generation = e->generation,
        .seals = e->seals,
        .can_block = e->can_block,
        .nonblock_owned = e->nonblock_owned,
        .guest_nonblock = (e->linux_flags & LINUX_O_NONBLOCK) != 0,
    };
}

/* host_fd_ref_open_io() that also reports the fd generation the reference was
 * resolved against.
 *
 * The generation is captured in the same fd_lock window as the host fd, so the
 * two always describe one open file. Callers that later re-resolve the guest fd
 * -- the pty hangup checks -- need exactly that pairing: a generation sampled
 * in a separate window can already belong to a replacement file while the
 * reference still points at the original, and the replacement's state would
 * then be reported against the original. fd_entry_t.host_fd is only ever
 * written together with a fresh generation, so the generation alone pins the
 * identity of the file behind ref->fd.
 *
 * *out_gen is 0 on failure.
 *
 * st_out, when given, receives the transfer classification taken in that same
 * window, which is what lets a transfer act on the object it is holding rather
 * than on whatever took the fd number afterwards. Both out-params are optional.
 *
 * Returns 0 on success or a negative Linux errno.
 */
static inline int64_t host_fd_ref_open_io_state(guest_fd_t guest_fd,
                                                host_fd_ref_t *ref,
                                                uint64_t *out_gen,
                                                fd_block_state_t *st_out)
{
    ref->fd = -1;
    ref->lifetime = NULL;
    if (st_out)
        *st_out = (fd_block_state_t) {.type = FD_CLOSED};

    /* Both out-params are optional. Writing through out_gen unconditionally is
     * a null dereference for a caller that wants only the classification, and
     * the compiler is entitled to assume that cannot happen: clang proved the
     * UB and compiled the whole of fuse_dev_read to a single brk #1, so every
     * FUSE read trapped before doing anything.
     */
    if (out_gen)
        *out_gen = 0;

    fd_entry_t snap;
    if (thread_is_single_active()) {
        /* No sibling can race the slot, so a plain snapshot is already
         * consistent with the borrowed host fd.
         */
        if (!fd_snapshot(guest_fd, &snap) || snap.type == FD_PATH ||
            snap.host_fd < 0)
            return -LINUX_EBADF;
        if (st_out)
            *st_out = fd_block_state_of(&snap);
        ref->fd = snap.host_fd;
        if (out_gen)
            *out_gen = snap.generation;
        return 0;
    }

    /* linux_errno rather than a flat EBADF: fd_host_ref_acquire distinguishes a
     * slot that is not open from an allocation it could not make, and a guest
     * under memory pressure must not be told its descriptor is invalid.
     */
    int host_fd = fd_host_ref_acquire(guest_fd, &snap, &ref->lifetime);
    if (host_fd < 0)
        return linux_errno();
    if (snap.type == FD_PATH) {
        fd_lifetime_release(ref->lifetime);
        ref->lifetime = NULL;
        return -LINUX_EBADF;
    }
    if (st_out)
        *st_out = fd_block_state_of(&snap);
    ref->fd = host_fd;
    if (out_gen)
        *out_gen = snap.generation;
    return 0;
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
    /* Hand-rolling the FD_PATH check here would take fd_lock twice and reject
     * on a snapshot the pin does not have to agree with. One window, one
     * decision; the caller just does not want what it classified.
     */
    return host_fd_ref_open_io_state(guest_fd, ref, NULL, NULL);
}

/* The generation-only spelling, for callers that do not run a transfer with the
 * descriptor they pin.
 */
static inline int64_t host_fd_ref_open_io_gen(guest_fd_t guest_fd,
                                              host_fd_ref_t *ref,
                                              uint64_t *out_gen)
{
    return host_fd_ref_open_io_state(guest_fd, ref, out_gen, NULL);
}

/* A guest timeout at or above this many seconds means "wait indefinitely", and
 * the wait path spells indefinite as timeout_ms = -1.
 *
 * That -1 is load-bearing, not a rounding convenience. sys_epoll_pwait reads
 * timeout_ms < 0 as has_timeout = false, which selects the 200 ms re-arm loop
 * that re-checks exit_group, futex interrupts, pending signals and pty hangup
 * between kevent calls. The epoll path registers no wakeup-pipe fd, so that
 * loop is its ONLY interruption mechanism: converting a huge timeout into a
 * finite one instead parks the thread in a single uninterruptible kevent, and a
 * sibling exit_group can no longer wake it.
 *
 * 2000000 seconds is about 23 days, comfortably past any real timeout and short
 * of the arithmetic limits.
 */
#define SYSCALL_TIMEOUT_FOREVER_SEC 2000000LL

/* Guest timespec to a poll(2)/kevent millisecond timeout, mapping an
 * effectively-infinite request onto the -1 that selects the interruptible path.
 *
 * epoll_pwait2 is the only caller, and the mapping is only safe there. ppoll
 * and pselect6 never spelled a timespec as indefinite, and recvmmsg waits in a
 * single poll with nothing to re-arm it, so -1 would strand it rather than
 * making it interruptible. A caller without a re-arm loop wants the saturating
 * conversion instead.
 */
static inline int syscall_timeout_ms_or_forever(int64_t sec, int64_t nsec)
{
    if (sec >= SYSCALL_TIMEOUT_FOREVER_SEC)
        return -1;
    return timespec_to_poll_ms(sec, nsec);
}

/* iov limits shared between readv/writev/preadv/pwritev and sendmsg/recvmsg.
 * SYSCALL_IOV_MAX matches the Linux UIO_MAXIOV cap; SYSCALL_IOV_STACK_MAX keeps
 * the typical case on the call-site stack.
 *
 * The cap is stated twice because the proved copy in proved/iov.h cannot
 * include this header (Frama-C's libc does not model the macOS uio headers it
 * pulls in). The assertion below is what keeps the two from drifting: a proof
 * about a 1024 cap says nothing about a 2048 one.
 */
#define SYSCALL_IOV_MAX 1024
#define SYSCALL_IOV_STACK_MAX 64

_Static_assert(SYSCALL_IOV_MAX == IOV_COUNT_MAX,
               "the iovcnt cap the code enforces must be the one proved");

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

void host_iov_free(host_iov_buf_t *buf);
bool proc_path_is_symlink(const char *path);

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
    int rc = guest_read_str_small(g, gva, short_buf, short_sz);
    if (rc >= 0) {
        *out = short_buf;
        return 0;
    }

    /* -2 means a host SIGBUS on the guest page rather than running out of
     * short_buf. Retrying the same address through the long buffer would only
     * fault again. guest_read_str_small reports it for both its own fast path
     * and the boundary-crossing fallback it delegates to.
     */
    if (rc == -2)
        return -LINUX_EFAULT;

    if (guest_read_str(g, gva, long_buf, long_sz) >= 0) {
        *out = long_buf;
        return 0;
    }
    return -LINUX_EFAULT;
}
