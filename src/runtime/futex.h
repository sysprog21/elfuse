/*
 * Linux futex emulation
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hash table of wait queues keyed by guest virtual address. Supports
 * FUTEX_WAIT, FUTEX_WAKE, FUTEX_WAIT_BITSET, FUTEX_WAKE_BITSET, FUTEX_REQUEUE,
 * FUTEX_CMP_REQUEUE, FUTEX_WAKE_OP, and PI futexes (FUTEX_LOCK_PI,
 * FUTEX_UNLOCK_PI, FUTEX_TRYLOCK_PI). Each waiter has its own condition
 * variable for precise wakeup.
 */

#pragma once

#include <stdint.h>

#include "core/guest.h"
#include "runtime/thread.h"

/* Initialize the futex subsystem. Call once at startup. */
void futex_init(void);

/* Interrupt blocking futex waits without requesting process exit. Used when
 * thread lifecycle events should wake waiters with EINTR.
 */
void futex_interrupt_request(void);
void futex_interrupt_clear(void);
int futex_interrupt_consume(void);

/* Tell @t that a signal it can take was queued, and wake it if it is parked in
 * FUTEX_WAIT or FUTEX_WAIT_BITSET. The kick is remembered, so one that lands
 * before @t parks is answered when it does. FUTEX_LOCK_PI and futex_waitv do
 * not take part and keep their polling quantum.
 */
void futex_kick(thread_entry_t *t);

/* Main futex syscall entry point. op: futex operation (FUTEX_WAIT, FUTEX_WAKE,
 * etc.) uaddr: guest virtual address of the futex word val: expected value
 * (WAIT) or max wakeups (WAKE) timeout_gva: guest pointer to timespec (or 0 for
 * no timeout) uaddr2: second futex address (for REQUEUE/CMP_REQUEUE/WAKE_OP)
 * val3: bitset (for WAIT_BITSET/WAKE_BITSET)
 * Returns 0 on success, negative Linux errno on failure.
 */
int64_t sys_futex(guest_t *g,
                  uint64_t uaddr,
                  int op,
                  uint32_t val,
                  uint64_t timeout_gva,
                  uint64_t uaddr2,
                  uint32_t val3);

/* Wake up to 1 waiter at uaddr. Used by thread exit for CLONE_CHILD_CLEARTID
 * cleanup.
 *
 * Returns number of waiters woken.
 */
int futex_wake_one(guest_t *g, uint64_t uaddr);

/* futex_waitv (SYS 449): batch wait on multiple futex addresses. clockid
 * selects the timeout clock (Linux CLOCK_REALTIME=0 or CLOCK_MONOTONIC=1);
 * ignored when timeout_gva==0.
 * Returns the index of the woken futex, or negative errno.
 */
int64_t sys_futex_waitv(guest_t *g,
                        uint64_t waiters_gva,
                        uint32_t nr_futexes,
                        uint32_t flags,
                        uint64_t timeout_gva,
                        int clockid);

/* Walk the robust futex list on thread exit and set FUTEX_OWNER_DIED on each
 * held lock. Wakes one waiter per lock so a new owner can acquire it and see
 * EOWNERDEAD.
 */
void robust_list_walk(guest_t *g, thread_entry_t *t);
