/*
 * Guest bootstrap helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <Hypervisor/Hypervisor.h>
#include <Hypervisor/hv_vcpu.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/elf.h"
#include "core/guest.h"
#include "linux-limits.h"

typedef struct {
    elf_info_t elf_info;
    elf_info_t interp_info;
    char interp_resolved[LINUX_PATH_MAX];
    char interp_display_path[LINUX_PATH_MAX];
    uint64_t elf_load_base;
    uint64_t interp_base;
    uint64_t ttbr0;
    uint64_t stack_pointer;
    uint64_t entry_point;
} guest_bootstrap_t;

int guest_bootstrap_prepare(guest_t *g,
                            const char *elf_host_path,
                            bool elf_host_path_temp,
                            const char *elf_guest_path,
                            const char *sysroot,
                            int guest_argc,
                            const char **guest_argv,
                            char **environ,
                            const unsigned char *shim_bin,
                            size_t shim_bin_len,
                            bool verbose,
                            bool *guest_initialized,
                            guest_bootstrap_t *boot);

/* Lightweight ELF header probe used by CLI preflight checks. */
int guest_bootstrap_probe_elf(const char *elf_path, elf_info_t *info);

int guest_bootstrap_create_vcpu(guest_t *g,
                                const guest_bootstrap_t *boot,
                                bool verbose,
                                hv_vcpu_t *out_vcpu,
                                hv_vcpu_exit_t **out_vexit);

/* Post-reset Rosetta re-bootstrap helper used by sys_execve when an existing
 * guest transitions to (or stays inside) an x86_64-via-Rosetta image. The
 * caller must already have:
 *   - called guest_reset() on g
 *   - restored shim bytes into [g->shim_base, g->shim_base + shim_bin_len)
 *   - if the parent was a non-rosetta guest, set g->is_rosetta = true and
 *     proc_set_rosetta_active(true) so rosetta_prepare and rosettad gates
 *     see the right runtime state
 *
 * elf_host_path is the macOS filesystem path used by rosetta_prepare to open
 * the binary (after sysroot/FUSE resolution). elf_guest_path is the unresolved
 * guest-visible path published through proc_set_elf_path and rosetta_finalize's
 * /proc/self/cmdline rewrite.
 *
 * The helper runs rosetta_prepare, appends every region the page-table builder
 * needs, rebuilds page tables, registers guest_region_t entries for
 * /proc/self/maps, runs rosetta_finalize (pre-opens the binary at the lowest
 * free guest fd >= 3, published as AT_EXECFD; installs the kbuf user alias,
 * publishes the binfmt-misc argv via proc_set_cmdline), and builds the initial
 * Linux stack using the rosetta image as the AT_PHDR/AT_BASE ELF metadata. It
 * does NOT touch the vCPU sysregs; the caller writes TCR_EL1, TTBR0_EL1,
 * TTBR1_EL1, ELR_EL1, SP_EL0, and PC itself once the out_* fields are returned.
 *
 * Returns 0 on success with out_entry_point, out_stack_pointer, out_ttbr0 set.
 *
 * Returns -1 on any internal failure; the caller is past the point of no return
 * and treats that as fatal.
 */
int guest_bootstrap_rosetta_post_reset(guest_t *g,
                                       const char *elf_host_path,
                                       bool elf_host_path_temp,
                                       const char *elf_guest_path,
                                       int guest_argc,
                                       const char **guest_argv,
                                       char **environ,
                                       size_t shim_bin_len,
                                       bool verbose,
                                       uint64_t *out_entry_point,
                                       uint64_t *out_stack_pointer,
                                       uint64_t *out_ttbr0)
    REQUIRES(mmap_pt_gate);
