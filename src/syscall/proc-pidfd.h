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
 * watched (the caller itself, or a CLONE_VM child). @out_gen, when not NULL,
 * receives the fd generation of the new fd, for a caller that may have to close
 * it again with fd_snapshot_and_close_gen.
 */
int pidfd_create(guest_t *g,
                 int64_t target_pid,
                 pid_t host_pid,
                 uint64_t *out_gen);

/* A dup of a pidfd shares the source's entry, in three steps so that the one
 * that can fail runs before the alias exists and a failed dup2 leaves its
 * target open.
 *
 * pidfd_dup_ref takes a reference on the entry behind @src_fd while the number
 * carries @src_gen, and returns a handle to it, or -1 when there is no such
 * entry. pidfd_dup_bind maps the alias @guest_fd, which fd_alloc stamped with
 * @gen, to the entry and hands it the reference. pidfd_dup_unref gives the
 * reference back when the alias was never allocated.
 */
int pidfd_dup_ref(int src_fd, uint64_t src_gen);
void pidfd_dup_bind(int ref, int guest_fd, uint64_t gen);
void pidfd_dup_unref(int ref);
void proc_pidfd_notify_exit(int64_t exited_pid);
int64_t proc_pidfd_lookup_pid(int guest_fd);
int64_t sys_pidfd_open(guest_t *g, int64_t pid, unsigned int flags);
int64_t sys_pidfd_send_signal(guest_t *g,
                              int pidfd,
                              int sig,
                              uint64_t info_gva,
                              unsigned int flags);
