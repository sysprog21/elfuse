/*
 * mmap_lock: serializes mmap/brk and page-table updates
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Kept in core/ so lazy materialization in core/guest.c can take the lock
 * without reaching into the syscall layer. The lock lives in syscall/mem.c; its
 * rank in the lock order is in syscall/internal.h.
 */

#pragma once

#include <pthread.h>
#include <stdbool.h>

#include "core/guest.h"

/* mmap_lock (mmap/brk + page tables) is not recursive. Acquire drains the
 * per-vCPU EL1 mmap rings before inspecting region state. Faultable guest
 * access may acquire this lock on a miss. Prepare buffers before taking
 * lower-ranked locks, then use nofault access while holding them; pre-faulting
 * does not pin the mapping against concurrent changes.
 */
void mmap_lock_acquire(guest_t *g);
void mmap_lock_release(void);
void mmap_lock_cond_wait(guest_t *g, pthread_cond_t *cond);

/* mmap_lock_acquire() for fork, which revokes every arena under the lock: it
 * drains without topping up the caller's arena.
 */
void mmap_lock_acquire_for_fork(guest_t *g);

/* Ownership-tracked mutex access without changing the EL1 gate or rings. */
void mmap_lock_acquire_raw(void);
void mmap_lock_release_raw(void);

/* Whether the calling thread holds mmap_lock. */
bool mmap_lock_held(void);

/* Temporarily drop mmap_lock while retaining the host PT-gate reference, then
 * reacquire without taking a second reference. Used only by lazy zeroing.
 */
void mmap_lock_drop_keep_gate(void);
void mmap_lock_reacquire_with_gate(guest_t *g);
