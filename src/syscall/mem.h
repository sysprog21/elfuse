/*
 * Guest memory syscall interface
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Declarations for brk, mmap, munmap, mprotect, mremap, madvise, msync. All
 * sys_xxx functions assume mmap_lock is held by the caller, except sys_msync,
 * which is dispatched unlocked (SC_FORWARD, not SC_LOCKED) and manages
 * mmap_lock itself so it can defer fsync(2) until after releasing it.
 */

#pragma once

#include <stdint.h>
#include "core/guest.h"

typedef struct mmap_fork_anon_shared_txn mmap_fork_anon_shared_txn_t;

/* brk: set/query program break */
int64_t sys_brk(guest_t *g, uint64_t addr);

/* Prepare FUSE backing without mmap_lock held. On success the caller owns
 * materialized_fd, or receives -1 when the ordinary fd path applies.
 */
int mmap_prepare_file(guest_t *g,
                      uint64_t addr,
                      uint64_t length,
                      int flags,
                      int fd,
                      int64_t offset,
                      int *materialized_fd);

/* Borrows materialized_fd (-1 for ordinary mappings) with mmap_lock held. */
int64_t sys_mmap(guest_t *g,
                 uint64_t addr,
                 uint64_t length,
                 int prot,
                 int flags,
                 int fd,
                 int64_t offset,
                 int materialized_fd);

/* munmap: unmap pages from guest address space */
int64_t sys_munmap(guest_t *g, uint64_t addr, uint64_t length);

/* mprotect: change page permissions */
int64_t sys_mprotect(guest_t *g, uint64_t addr, uint64_t length, int prot);

/* mremap: remap/resize a mapping */
int64_t sys_mremap(guest_t *g,
                   uint64_t old_addr,
                   uint64_t old_size,
                   uint64_t new_size,
                   int flags,
                   uint64_t new_addr);

/* madvise: advise about memory usage */
int64_t sys_madvise(guest_t *g, uint64_t addr, uint64_t length, int advice);

/* msync: synchronize file-backed mappings to disk */
int64_t sys_msync(guest_t *g, uint64_t addr, uint64_t length, int flags);

/* Apply deferred guest-stack munmap work for an exiting thread. */
void mem_cleanup_deferred_stack_unmaps(guest_t *g, thread_entry_t *t);

/* Fork preparation: convert MAP_SHARED|MAP_ANONYMOUS regions that have no
 * backing fd into memfd-backed overlay regions. Each converted region gets a
 * private mkstemp+unlink temp file seeded from the current host bytes; a host
 * MAP_SHARED|MAP_FIXED overlay is then installed so the parent's subsequent
 * writes flow through the kernel page cache. The region's backing_fd is set to
 * a dup of the temp file so the regular SCM_RIGHTS handover feeds the child a
 * coherent fd.
 *
 * Caller must already hold sibling vCPUs quiesced. mmap_lock is acquired
 * internally. Per-region failures are logged and skipped (snapshot fallback
 * persists for those regions); structural failure returns -errno. Regions whose
 * start address is not host-page-aligned are skipped (overlay-eligibility
 * requirement). On success, *txn_out owns rollback metadata that must later be
 * committed or aborted.
 */
int mmap_fork_prepare_anon_shared(guest_t *g,
                                  mmap_fork_anon_shared_txn_t **txn_out);

/* Finalize or roll back mmap_fork_prepare_anon_shared(). Callers must still
 * have sibling vCPUs quiesced when aborting so the host overlay removal cannot
 * race guest accesses.
 */
void mmap_fork_commit_anon_shared(mmap_fork_anon_shared_txn_t **txn_ptr);
int mmap_fork_abort_anon_shared(guest_t *g,
                                mmap_fork_anon_shared_txn_t **txn_ptr);

/* Fork restore: re-install host MAP_SHARED|MAP_FIXED overlays on the child
 * after IPC restore. parent_active[i] / parent_ovl_start[i] / parent_ovl_end[i]
 * capture each region's parent-side overlay metadata, sampled before
 * fork_ipc_recv_process_state cleared the inherited overlay flags. For each
 * region that was overlay-active in the parent and now has a valid backing_fd
 * (received via SCM_RIGHTS), the function calls hv_vm_unmap + mmap
 * MAP_FIXED|MAP_SHARED + hv_vm_map to bind the host VA to the same backing file
 * so the child observes parent writes (and vice-versa). Caller must hold no
 * locks; the child has not yet created worker vCPUs so no quiesce is needed.
 *
 * Per-region failures are logged and skipped.
 *
 * Returns 0 on full success or the last error encountered (best-effort: a
 * partial failure leaves snapshot semantics intact for the failed regions).
 */
int mmap_fork_restore_overlays(guest_t *g,
                               const bool *parent_active,
                               const uint64_t *parent_ovl_start,
                               const uint64_t *parent_ovl_end);

/* Undo every live MAP_SHARED host overlay before execve resets the address
 * space. guest_reset zeroes each tracked region by writing through its host VA,
 * and an overlay still installed there is the backing file's own page cache, so
 * those zeroes reach the file: a guest that mmaps a file MAP_SHARED and execs
 * truncates its contents to zero on the host. Removing the overlay first
 * restores plain slab backing, which is also what the new image needs, since an
 * overlay left in place would hand it a host file at that VA.
 *
 * Caller holds mmap_lock.
 *
 * Returns 0, or -errno with the overlays that could not be torn down still
 * marked active; the caller must not reset guest memory after a failure.
 */
int mmap_exec_drop_overlays(guest_t *g);
