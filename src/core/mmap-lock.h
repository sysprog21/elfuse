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
 * per-vCPU EL1 mmap rings before any caller can inspect semantic region state.
 */
void mmap_lock_acquire(guest_t *g);
void mmap_lock_release(void);
void mmap_lock_cond_wait(guest_t *g, pthread_cond_t *cond);

/* Ownership-tracked mutex access without draining the EL1 rings. */
void mmap_lock_acquire_raw(void);
void mmap_lock_release_raw(void);

/* Whether the calling thread holds mmap_lock. */
bool mmap_lock_held(void);
