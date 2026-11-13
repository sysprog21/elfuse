/*
 * Shapes the PT gate capability must reject at compile time
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Never linked. make check-thread-safety compiles each function on its own and
 * fails unless the compiler rejects it for not holding mmap_pt_gate, so the
 * analysis is shown to bite before a clean build is trusted.
 */

#include "core/guest.h"
#include "core/mmap-fastpath.h"
#include "core/mmap-lock.h"

/* A page-table rewrite under the raw lock: EL1 munmap may be clearing the same
 * descriptors.
 */
#if defined(REJECT_RAW_PT_WRITE)
void reject_raw_pt_write(guest_t *g);
void reject_raw_pt_write(guest_t *g)
{
    mmap_lock_acquire_raw();
    (void) guest_split_block(g, 0);
    mmap_lock_release_raw();
}
#endif

/* A revoke under the raw lock: producers are still inside the gate. */
#if defined(REJECT_RAW_REVOKE)
void reject_raw_revoke(guest_t *g);
void reject_raw_revoke(guest_t *g)
{
    mmap_lock_acquire_raw();
    mmap_fastpath_revoke_all_locked(g, false);
    mmap_lock_release_raw();
}
#endif

/* The accepted shape, so a rejection above is the capability and not a build
 * error of this file.
 */
#if defined(ACCEPT_GATED)
void accept_gated(guest_t *g);
void accept_gated(guest_t *g)
{
    mmap_lock_acquire(g);
    (void) guest_split_block(g, 0);
    mmap_fastpath_revoke_all_locked(g, false);
    mmap_lock_release();
}
#endif
