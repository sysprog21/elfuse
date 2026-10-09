/*
 * pidfd helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>

#include "core/guest.h"

void pidfd_init(void);

/* Create a pidfd on @target_pid. @host_pid is the host process to watch for its
 * exit, or <= 0 when the target lives in this host process and so cannot be
 * watched (the caller itself, or a CLONE_VM child).
 */
int pidfd_create(guest_t *g, int64_t target_pid, pid_t host_pid);

/* Create a pidfd that stands for no task yet, and point it at one later. clone
 * makes the descriptor for a thread or a CLONE_VM child before that task exists
 * and learns the tid only once the task is made.
 *
 * *gen names the new entry for pidfd_set_target. The guest fd number cannot:
 * the slot is visible to the guest from the moment it is made, and a close
 * followed by another pidfd would hand the same number to a different entry.
 */
int pidfd_create_unbound(guest_t *g, uint64_t *gen);
void pidfd_set_target(uint64_t gen, int64_t target_pid);
void proc_pidfd_notify_exit(int64_t exited_pid);
int64_t proc_pidfd_lookup_pid(int guest_fd);
int64_t sys_pidfd_open(guest_t *g, int64_t pid, unsigned int flags);
int64_t sys_pidfd_send_signal(guest_t *g,
                              int pidfd,
                              int sig,
                              uint64_t info_gva,
                              unsigned int flags);
