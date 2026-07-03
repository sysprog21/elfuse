/*
 * /proc and /dev path emulation
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Intercepts openat and readlinkat for /proc, /dev, and other synthetic paths.
 * Returns host fds for synthetic content or -2 if not intercepted.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include "core/guest.h"

/* Sentinel return value: path was not intercepted, caller should fall through
 * to the real syscall.
 */
#define PROC_NOT_INTERCEPTED (-2)

/* Intercept openat for /proc and /dev paths. The guest_t pointer is needed to
 * generate /proc/self/maps from region data.
 * Returns a host fd on match (caller should fd_alloc it), -1 on error with
 * errno set, or PROC_NOT_INTERCEPTED if the path is not intercepted.
 */
int proc_intercept_open(const guest_t *g,
                        const char *path,
                        int linux_flags,
                        int mode);

/* Intercept readlinkat for /proc paths.
 * Returns the link length on match, -1 on error, or -2 if not intercepted (fall
 * through to real readlinkat).
 */
int proc_intercept_readlink(const char *path, char *buf, size_t bufsiz);

/* Intercept stat/fstatat for /proc paths.
 * Returns 0 if stat was synthesized (mac_st filled), or -2 if not intercepted
 * (fall through to real fstatat).
 */
int proc_intercept_stat(const char *path, struct stat *mac_st);

/* Intercept writes to synthetic proc files that need stateful behavior.
 * Returns 1 if handled (with *written_out set), 0 if not intercepted, or -1 on
 * error with errno set.
 */
int proc_intercept_write(int guest_fd,
                         int host_fd,
                         const void *buf,
                         size_t count,
                         int64_t offset,
                         int use_pwrite,
                         ssize_t *written_out);

/* Intercept reads from synthetic proc files that must reflect shared state on
 * every read rather than the per-open temp-file snapshot.
 * Returns 1 if handled (with *read_out set), 0 if not intercepted, or -1 on
 * error with errno set.
 */
int proc_intercept_read(int guest_fd,
                        void *buf,
                        size_t count,
                        int64_t offset,
                        ssize_t *read_out);

/* Vector form of proc_intercept_read for readv/preadv. */
int proc_intercept_readv(int guest_fd,
                         const struct iovec *iov,
                         int iovcnt,
                         int64_t offset,
                         ssize_t *read_out);

/* Get the /dev/shm emulation directory path (creating it on first call). Used
 * by sys_unlinkat to rewrite /dev/shm/<name> paths.
 */
const char *proc_get_shm_dir(void);

/* Resolve a /dev/shm/<suffix> guest-path suffix to a host path inside the
 * per-UID /dev/shm emulation directory. Rejects empty, ".."-bearing, or
 * compound suffixes with errno = EACCES.
 *
 * Returns 0 on success and writes the full host path to host_path; returns -1
 * with errno set (EACCES on invalid suffix, ENAMETOOLONG on overflow, or as set
 * by shm_dir_path()).
 */
int proc_dev_shm_resolve(const char *guest_suffix,
                         char *host_path,
                         size_t host_path_sz);

/* Drop the keepalive slave fd paired with a /dev/ptmx master host fd. Called
 * from fd_cleanup_entry when the guest closes the master so the host kernel
 * eventually tears the tty down. Idempotent and safe to call on any host fd
 * (no-op when no keepalive is registered).
 */
void proc_pty_close_keepalive(int master_host_fd);

/* Caller-locked variant of pty keepalive duplication. Brackets the host
 * fd_snapshot_and_dup and the keepalive mirror under one pty_keepalive_lock
 * window so a sibling close cannot run proc_pty_close_keepalive in the gap and
 * leave the alias without a keepalive entry. Caller must wrap the sequence with
 * proc_pty_lock_for_dup / proc_pty_unlock_for_dup.
 */
void proc_pty_lock_for_dup(void);
void proc_pty_unlock_for_dup(void);
void proc_pty_dup_keepalive_locked(int src_master_host_fd,
                                   int dst_master_host_fd);

/* Return the captured Linux pts number for a host master fd, or UINT32_MAX when
 * no keepalive is registered. Lets sys_ioctl TIOCGPTN report the value
 * /dev/pts/N opens / stats round-trip through, instead of independently parsing
 * the macOS slave path and risking divergence with the open table.
 */
uint32_t proc_pty_master_pts_num(int master_host_fd);

/* Best-effort lazy registration for a /dev/ptmx master that elfuse did not open
 * itself (e.g. one received from a peer via SCM_RIGHTS). Takes a guest fd
 * because the canonical host fd would race with sibling close+reuse if passed
 * in directly: this helper snapshots fd_table[guest_fd].host_fd and its
 * generation, performs the slave open against a private dup, and only registers
 * the keepalive after re-verifying the slot still holds the original (host_fd,
 * generation).
 *
 * Returns the pts number on success, or UINT32_MAX if the fd is not a pty
 * master, the slot got closed/recycled mid-adoption, or the keepalive table is
 * full. Idempotent: if the master already has a keepalive entry, returns its
 * stored linux_pts_num.
 */
uint32_t proc_pty_master_adopt(int guest_fd);

/* Max bytes for a captured macOS slave path (e.g. "/dev/ttys004"). Lives in the
 * header so proc_pty_ipc_entry_t below and the in-memory keepalive table in
 * procemu.c share one source of truth; a divergence would silently corrupt the
 * fork-IPC wire format.
 */
#define PTY_SLAVE_PATH_MAX 64

/* Serialized form of a pty keepalive entry, used by fork-IPC. The slave host fd
 * travels separately via SCM_RIGHTS; this struct only carries the
 * lifetime-independent metadata that the child needs to re-register.
 */
typedef struct {
    int32_t master_host_fd;
    uint32_t linux_pts_num;
    char slave_path[PTY_SLAVE_PATH_MAX];
} proc_pty_ipc_entry_t;

/* Snapshot the current pty keepalive table into out_entries / out_slave_fds.
 * dup()s every slave fd under the keepalive lock so the snapshot stays valid
 * across the SCM_RIGHTS send even if the original master gets closed before the
 * IPC drains.
 *
 * Returns the number of live entries written (always <= max_entries); on
 * success the caller owns the duplicated slave fds and must close them after
 * the IPC send completes.
 */
int proc_pty_snapshot_keepalive(proc_pty_ipc_entry_t *out_entries,
                                int *out_slave_fds,
                                int max_entries);

/* Re-register a single keepalive in the child after a fork-IPC. master_host_fd
 * is the child-side host fd that just landed in fd_table (its number is
 * different from the parent's). Takes ownership of slave_host_fd. The slave
 * path is recorded so /dev/pts/N opens in the child resolve to the same macOS
 * tty the parent has been talking to.
 */
void proc_pty_restore_keepalive(int master_host_fd,
                                int slave_host_fd,
                                uint32_t linux_pts_num,
                                const char *slave_path);

/* Returns the canonical proc_path tag for runtime-emulated /dev paths
 * whose write semantics require FD-level dispatch (currently /dev/full,
 * which must answer ENOSPC for any non-zero write), or NULL when the
 * path needs no special tagging. Callers store the tag in
 * fd_entry_t.proc_path so proc_intercept_write can recognise the FD on
 * later writes.
 */
const char *proc_dev_special_path(const char *path);
