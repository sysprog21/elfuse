/* Fork IPC state serialization
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "hvutil.h"

#include "core/guest.h"
#include "syscall/abi.h"
#include "syscall/signal.h"

/* Magic values for IPC frame delimiters */
#define IPC_MAGIC_HEADER 0x454C464BU   /* "ELFK" */
#define IPC_MAGIC_SENTINEL 0x454C4F4BU /* "ELOK" */
/* Bumped to 13 when pointer-authentication key registers and the remaining
 * EL0 TLS registers were added so forked children and clone-created vCPUs
 * resume with the same userspace CPU context as the parent. New Ubuntu arm64
 * userspace can use PAC in libc and TLS-adjacent state during fork return.
 *
 * Bumped to 12 when clone_flags/child_tid_gva were added so fork-process
 * children can apply CLONE_CHILD_SETTID/CLEARTID inside their own snapshot.
 *
 * Bumped to 11 when regions_tracker_stale was added to process state so
 * forked children preserve mprotect fast-path correctness.
 *
 * Bumped to 10 when the rosetta placement / kbuf / ttbr1 tuple was added so a
 * rosetta-aware child rejects an older parent's header instead of trying to
 * interpret unknown trailing fields.
 */
#define IPC_VERSION 13

typedef struct {
    uint64_t apiakeylo_el1, apiakeyhi_el1;
    uint64_t apibkeylo_el1, apibkeyhi_el1;
    uint64_t apdakeylo_el1, apdakeyhi_el1;
    uint64_t apdbkeylo_el1, apdbkeyhi_el1;
    uint64_t apgakeylo_el1, apgakeyhi_el1;
} ipc_pauth_keys_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t ipa_bits;
    uint32_t has_shm;
    int64_t child_pid, parent_pid;
    uint64_t guest_size;
    uint64_t elf_load_min;
    uint64_t brk_base, brk_current;
    uint64_t stack_base;
    uint64_t stack_top;
    uint64_t mmap_next, mmap_end, pt_pool_next, ttbr0;
    uint64_t mmap_rx_next;
    uint64_t mmap_rx_end;
    uint32_t uid, euid, suid, gid, egid, sgid;
    int32_t nice;
    uint32_t _pad;
    uint64_t absock_namespace_id;
    int64_t sid, pgid;
    /* Rosetta placement fields. All zero for aarch64 guests; populated when the
     * parent is_rosetta. The child rebuilds the TTBR1 kbuf tree from the PT
     * pool that came across in the memory transfer; rosetta_guest_base /
     * va_base / size pin the segments at the same primary-buffer location so
     * the non-identity page-table mapping remains coherent across the fork.
     */
    uint32_t is_rosetta;
    uint32_t _rosetta_pad;
    uint64_t rosetta_guest_base;
    uint64_t rosetta_va_base;
    uint64_t rosetta_size;
    uint64_t rosetta_entry;
    uint64_t kbuf_gpa;
    uint64_t ttbr1;
    uint64_t clone_flags;
    uint64_t child_tid_gva;
} ipc_header_t;

typedef struct {
    uint64_t elr_el1, sp_el0;
    uint64_t spsr_el1, vbar_el1;
    uint64_t ttbr0_el1;
    /* TTBR1_EL1 is zero for aarch64 guests and carries the rosetta kbuf
     * page-table root for is_rosetta guests. The parent captures the live
     * sysreg so a forked child resumes with the same TTBR1 the parent had after
     * bootstrap_create_vcpu set it; without this the child comes up with
     * TTBR1=0 even though TCR_EL1.EPD1 is cleared, and the first kernel-VA
     * access faults.
     */
    uint64_t ttbr1_el1;
    uint64_t sctlr_el1, tcr_el1, mair_el1, cpacr_el1;
    uint64_t tpidr_el0, tpidrro_el0, tpidr2_el0, sp_el1;
    uint64_t x[31];
    ipc_pauth_keys_t pauth_keys;
    vcpu_simd_state_t simd_state;
} ipc_registers_t;

typedef struct {
    uint64_t offset, size;
} ipc_region_header_t;

typedef struct {
    int32_t guest_fd, type, linux_flags, seals;
    char proc_path[FD_VIRTUAL_PATH_MAX];
} ipc_fd_entry_t;

int fork_ipc_write_all(int fd, const void *buf, size_t len);
int fork_ipc_read_all(int fd, void *buf, size_t len);
int fork_ipc_send_fds(int sock, const int *fds, int count);
int fork_ipc_recv_fds(int sock, int *fds, int max_count, int *out_count);

int fork_ipc_send_memory_regions(int ipc_sock, const guest_t *g, bool use_shm);
int fork_ipc_recv_memory_regions(int ipc_fd, guest_t *g);

int fork_ipc_send_fd_table(int ipc_sock);
int fork_ipc_recv_fd_table(int ipc_fd, guest_t *g);

/* Carry the /dev/ptmx keepalive slave fds across the fork boundary. The fd
 * table batch sends master fds without their hidden keepalive companions, so a
 * child that inherits a master would otherwise hit the macOS ENOTTY /
 * winsize-reset cliff that proc_pty_close_keepalive papers over in the parent.
 * send/recv must run AFTER fork_ipc_send_fd_table / _recv_fd_table so the child
 * can look up its new master host fd from the just-installed fd_table entry.
 */
int fork_ipc_send_pty_keepalives(int ipc_sock);
int fork_ipc_recv_pty_keepalives(int ipc_fd);

int fork_ipc_send_process_state(int ipc_sock,
                                const guest_region_t *regions_snapshot,
                                uint32_t num_guest_regions,
                                bool regions_tracker_stale_snapshot,
                                const guest_region_t *preannounced_snapshot,
                                uint32_t num_preannounced);
int fork_ipc_recv_process_state(int ipc_fd, guest_t *g, signal_state_t *sig);
