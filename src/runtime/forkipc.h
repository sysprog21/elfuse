/*
 * Fork/clone IPC
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements clone via posix_spawn + IPC state transfer. macOS HVF allows only
 * one VM per process, so fork spawns a new elfuse process and serializes the
 * full VM state (registers, memory, FDs) over a socketpair.
 */

#pragma once

#include <Hypervisor/Hypervisor.h>
#include <stdbool.h>
#include <stdint.h>

#include "core/guest.h"

/* Fork child entry point: receives VM state over IPC socket, creates VM, enters
 * vCPU run loop. Called from main.c when --fork-child is specified.
 * Returns the process exit code.
 */
int fork_child_main(int ipc_fd,
                    int vfork_notify_fd,
                    bool verbose,
                    int timeout_sec);

void fork_notify_vfork_exec(void);

/* Clone syscall: spawn a new host elfuse process with IPC state transfer.
 * Returns child guest PID to parent, or negative Linux errno.
 */
int64_t sys_clone(hv_vcpu_t vcpu,
                  guest_t *g,
                  uint64_t flags,
                  uint64_t child_stack,
                  uint64_t stack_map_start,
                  uint64_t stack_map_end,
                  uint64_t ptid_gva,
                  uint64_t pidfd_gva,
                  uint64_t tls,
                  uint64_t ctid_gva,
                  bool verbose);

/* clone3 syscall: extended clone with clone_args struct. Translates clone_args
 * to sys_clone parameters and delegates.
 * Returns child guest PID to parent, or negative Linux errno.
 */
int64_t sys_clone3(hv_vcpu_t vcpu,
                   guest_t *g,
                   uint64_t cl_args_gva,
                   uint64_t cl_args_size,
                   bool verbose);
