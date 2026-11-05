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

/* Arguments shared by clone(2) and clone3(2). */
typedef struct {
    uint64_t flags;           /* CLONE_* bits, exit signal in the low byte */
    uint64_t child_stack;     /* SP for the child, 0 to keep the parent's */
    uint64_t stack_map_start; /* Mapped range holding the child stack; */
    uint64_t stack_map_end;   /* both 0 when the caller does not know it */
    uint64_t ptid_gva;        /* CLONE_PARENT_SETTID target */
    uint64_t pidfd_gva;       /* CLONE_PIDFD target */
    uint64_t tls;             /* TLS value for CLONE_SETTLS */
    uint64_t ctid_gva;        /* CLONE_CHILD_SETTID / CLEARTID target */
} clone_req_t;

/* Clone syscall: spawn a new host elfuse process with IPC state transfer.
 * Returns child guest PID to parent, or negative Linux errno.
 */
int64_t sys_clone(hv_vcpu_t vcpu,
                  guest_t *g,
                  const clone_req_t *req,
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
