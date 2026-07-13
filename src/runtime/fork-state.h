/*
 * Fork IPC state serialization
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "hvutil.h"

#include "core/guest.h"
#include "syscall/linux-wire.h"
#include "syscall/signal.h"

/* Fork IPC protocol identity. Bump this whenever the header layout or ordered
 * fork payload changes incompatibly.
 */
#define FORK_IPC_PROTOCOL_MAGIC 0x454C4652U /* "ELFR" */

#define IPC_MAGIC_HEADER FORK_IPC_PROTOCOL_MAGIC
#define IPC_MAGIC_SENTINEL 0x454C4F4BU /* "ELOK" */

typedef struct {
    uint32_t magic;
    uint32_t ipa_bits;
    bool has_shm;
    int64_t child_pid, parent_pid;
    uint64_t guest_size;
    uint64_t elf_load_min;
    uint64_t brk_base, brk_current;
    uint64_t stack_base;
    uint64_t stack_top;
    uint64_t start_stack;
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
    bool is_rosetta;
    uint64_t rosetta_guest_base;
    uint64_t rosetta_va_base;
    uint64_t rosetta_size;
    uint64_t rosetta_entry;
    uint64_t kbuf_gpa;
    uint64_t ttbr1;

    /* Clone TID-sync state for the fork path. glibc's fork wrapper passes
     * CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID so the child writes its new TID
     * into the TCB and clears it on exit. The posix_spawn child has no access
     * to the original clone() arguments, so the parent forwards them here:
     * clone_flags carries the CHILD_SETTID / CHILD_CLEARTID bits and ctid_gva
     * the guest address. Zero for callers (e.g. raw fork(2)) that pass neither.
     */
    uint64_t clone_flags;
    uint64_t ctid_gva;

    /* Nonzero when the shm fd sent below is an independent fclonefileat clone
     * (not the parent's live fd). Only then may the child map it MAP_SHARED and
     * retain it for its own nested CoW fork; the live-fd fallback must stay
     * MAP_PRIVATE so the child does not share writes with the parent.
     */
    uint32_t shm_is_clone;
    uint32_t _pad2;

    /* Guest-visible NOFILE state is separate from the host capacity reserved by
     * elfuse. The child restores this after installing inherited FDs so
     * descriptors above a subsequently lowered soft limit survive fork.
     */
    uint64_t nofile_cur;
    uint64_t nofile_max;
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
    uint64_t sctlr_el1, tcr_el1, mair_el1, cpacr_el1, tpidr_el0, sp_el1;
    uint64_t x[31];
    vcpu_simd_state_t simd_state;
} ipc_registers_t;

typedef struct {
    uint64_t offset, size;
} ipc_region_header_t;

typedef struct {
    int32_t guest_fd, type, linux_flags, seals;
    uint64_t ofd_id;
    int32_t fasync_owner_type, fasync_owner;

    /* The child rebuilds its table from descriptions this process already
     * holds, so it inherits the status-flag answers rather than probing them
     * again: whether the description came from outside elfuse (the launcher's
     * stdio, or an alias of it) and whether elfuse owns its O_NONBLOCK. See
     * fd_alias_carried.
     *
     * path_poll_capable rides along for the same reason and cannot be rebuilt
     * on the far side: the child holds the descriptor, not the guest path the
     * parent classified it from.
     */
    int32_t foreign_description, nonblock_owned, path_poll_capable;
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
                                const uint64_t *dirty_blocks_snapshot,
                                const guest_region_t *preannounced_snapshot,
                                uint32_t num_preannounced);
int fork_ipc_recv_process_state(int ipc_fd,
                                guest_t *g,
                                signal_state_snapshot_t *sig);
