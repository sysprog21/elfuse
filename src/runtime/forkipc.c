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
 *
 * Registers and the fd table are small. Guest memory is not, and how it crosses
 * is the whole cost of a fork:
 *
 *                      ┌──────────────┐
 *                      │ guest memory │
 *                      └──────────────┘
 *              ┌──────────────┘ └──────────┐
 *              │                           │
 *   ┌──────────▾─────────┐   ┌─────────────▾─────────────┐
 *   │ no shm fd: copy it │   │ shm fd: try an APFS clone │
 *   └────────────────────┘   └───────────────────────────┘
 *                    ┌────────────────────┘ │
 *                    │                      │
 *        ┌───────────▾──────────┐   ┌───────▾──────┐
 *        │ cloned: send that fd │   │ clone failed │
 *        └──────────────────────┘   └──────────────┘
 *              ┌───────────────────────────┘ │
 *              │                             │
 *              │                          ┌──┘
 *    ┌─────────▾────────┐   ┌─────────────▾────────────┐
 *    │ Rosetta: copy it │   │ native: send the live fd │
 *    └──────────────────┘   └──────────────────────────┘
 *
 * What each branch costs, and why the two fallbacks are not interchangeable, is
 * at the CoW block in sys_clone where the choice is made.
 * tests/bench-fork-cost.sh is what measures it on a given host.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <sys/spawn.h> /* POSIX_SPAWN_CLOEXEC_DEFAULT (macOS extension) */
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <dirent.h> /* fdopendir, for DIR* reconstruction in child */
#include <sys/wait.h>
#include <sys/clonefile.h> /* fclonefileat for CoW shm snapshots */
#include <mach-o/dyld.h>

#include "hvutil.h"
#include "utils.h"

#include "core/shim-globals.h"
#include "core/mmap-fastpath.h"

#include "runtime/forkipc.h"
#include "runtime/fork-state.h"
#include "runtime/futex.h"
#include "runtime/procemu.h"

#include "syscall/linux-wire.h"
#include "syscall/chown-overlay.h"
#include "syscall/internal.h"
#include "syscall/mem.h"
#include "syscall/net.h" /* absock namespace IPC state */
#include "syscall/proc.h"
#include "syscall/proc-pidfd.h"
#include "syscall/signal.h"
#include "syscall/sys.h"
#include "syscall/wakeup-pipe.h"

#include "debug/log.h"
#include "debug/syscall-hist.h"

/* Linux clone flags. Shared by the fork-child TID-sync emulation below and
 * sys_clone further down.
 */
#define LINUX_CLONE_VM 0x00000100
#define LINUX_CLONE_VFORK 0x00004000
#define LINUX_CLONE_THREAD 0x00010000
#define LINUX_CLONE_SETTLS 0x00080000
#define LINUX_CLONE_PARENT_SETTID 0x00100000
#define LINUX_CLONE_CHILD_CLEARTID 0x00200000
#define LINUX_CLONE_CHILD_SETTID 0x01000000
/* LINUX_SIGCHLD defined in syscall_signal.h (included above) */

/* fork_child_main. */

static int fork_child_vfork_notify_fd = -1;

void fork_notify_vfork_exec(void)
{
    if (fork_child_vfork_notify_fd < 0)
        return;

    char byte = 'X';
    ssize_t n;
    do {
        n = write(fork_child_vfork_notify_fd, &byte, 1);
    } while (n < 0 && errno == EINTR);
    close(fork_child_vfork_notify_fd);
    fork_child_vfork_notify_fd = -1;
}

/* Over the function-size limit on purpose.
 *
 * The child's whole bring-up in receive order, and the order is the contract:
 * every step depends on the one before it, and the rollback on failure differs
 * per step. Splitting hides which stage a failure came from.
 */
/* NOLINTNEXTLINE(readability-function-size) */
int fork_child_main(int ipc_fd,
                    int vfork_notify_fd,
                    bool verbose,
                    int timeout_sec)
{
    /* Reinitialize logging after posix_spawn (mutex state is undefined). */
    log_init();
    if (verbose)
        log_set_level(LOG_DEBUG);

    /* The startup syscall histogram captures dynamic-linker bring-up of the
     * top-level guest only; the child resumes from the parent's snapshot, so
     * its first syscalls would be steady-state traffic that confuses the dump.
     * Disable before any guest syscall is dispatched.
     */
    syscall_hist_disable();

    /* Reset static process/thread/futex state before receiving the parent
     * snapshot so the incoming metadata survives child restore.
     */
    proc_init();
    fork_child_vfork_notify_fd = vfork_notify_fd;

    /* The header magic identifies the fork IPC protocol before any
     * variable-length state is trusted.
     */
    ipc_header_t hdr = {0};
    if (fork_ipc_read_all(ipc_fd, &hdr, sizeof(hdr)) < 0) {
        log_error("fork-child: failed to read header");
        return 1;
    }
    if (hdr.magic != IPC_MAGIC_HEADER) {
        log_error("fork-child: bad magic 0x%x", hdr.magic);
        return 1;
    }
    if (hdr.nofile_cur > hdr.nofile_max || hdr.nofile_max > FD_TABLE_SIZE) {
        log_error("fork-child: invalid RLIMIT_NOFILE %llu/%llu",
                  (unsigned long long) hdr.nofile_cur,
                  (unsigned long long) hdr.nofile_max);
        return 1;
    }
    log_debug("fork-child: pid=%lld ppid=%lld", (long long) hdr.child_pid,
              (long long) hdr.parent_pid);

    /* Static process identity lives in syscall/proc.c; use its accessor so the
     * child sees the parent-assigned guest PID/PPID.
     */
    proc_set_identity(hdr.child_pid, hdr.parent_pid);
    proc_set_ids(hdr.uid, hdr.euid, hdr.suid, hdr.gid, hdr.egid, hdr.sgid);
    proc_set_nice(hdr.nice);
    absock_set_namespace_id(hdr.absock_namespace_id);
    proc_set_session(hdr.sid, hdr.pgid);

    /* Validate header layout fields before any size-derived arithmetic.
     * guest_init / guest_init_from_shm derive interp_base, mmap_limit, and the
     * high-IPA infra reserve from these inputs; underflow on tiny or malformed
     * values would place pt_pool_base and friends near UINT64_MAX, which then
     * feeds unchecked host-buffer offsets in pt_alloc_page and pt_at. Reject
     * impossible layouts up front.
     *
     * Lower bound: guest_size must leave room for both mmap_limit (size - 8
     * GiB) and interp_base (size - 4 GiB) plus the 16 MiB infra reserve below
     * it. 8 GiB satisfies all three with margin. Upper bound: guest_size must
     * fit in the negotiated IPA width. IPA bits: 36 (M1/M2) and 40 (M3+) for
     * native aarch64; 48 for Rosetta guests, which need the wider Stage-2 width
     * for high VAs (image at 128 TiB) even though their primary slab stays
     * under 40-bit. Reject anything outside [36, 48].
     */
    if (hdr.ipa_bits < 36 || hdr.ipa_bits > 48) {
        log_error("fork-child: invalid ipa_bits %u", (unsigned) hdr.ipa_bits);
        close(ipc_fd);
        return 1;
    }
    if (hdr.guest_size < 0x200000000ULL ||
        hdr.guest_size > (1ULL << hdr.ipa_bits)) {
        log_error("fork-child: invalid guest_size 0x%llx (ipa_bits=%u)",
                  (unsigned long long) hdr.guest_size, (unsigned) hdr.ipa_bits);
        close(ipc_fd);
        return 1;
    }

    /* Create guest memory before receiving state so all incoming offsets can be
     * bounds-checked against the negotiated guest size.
     */
    guest_t g;

    if (hdr.has_shm) {
        /* CoW fork: receive shm fd via SCM_RIGHTS, then map MAP_PRIVATE. This
         * gives the child an instant copy-on-write snapshot of the parent's
         * entire guest memory, with no region enumeration or byte copying.
         */
        int shm_fd = -1, shm_count = 0;
        if (fork_ipc_recv_fds(ipc_fd, &shm_fd, 1, &shm_count) < 0 ||
            shm_count != 1) {
            log_error("fork-child: failed to receive shm fd");
            close(ipc_fd);
            return 1;
        }
        if (guest_init_from_shm(&g, shm_fd, hdr.guest_size, hdr.ipa_bits,
                                hdr.shm_is_clone != 0) < 0) {
            log_error("fork-child: guest_init_from_shm failed");
            close(ipc_fd);
            return 1;
        }
        log_debug("fork-child: CoW fork via shm fd");
    } else {
        /* Legacy fork copies selected guest memory regions over IPC. */
        if (guest_init(&g, hdr.guest_size, hdr.ipa_bits) < 0) {
            log_error("fork-child: failed to init guest");
            close(ipc_fd);
            return 1;
        }
    }

    /* Restore allocator/page-table cursors before mmap/brk can run in child.
     * Validate pt_pool_next and ttbr0 against the child's own page-table pool,
     * which the child just computed from hdr.guest_size + hdr.ipa_bits via
     * compute_infra_layout.
     *
     * Range alone is not enough: pt_alloc_page advances pt_pool_next in
     * GUEST_PAGE_SIZE quanta, and pt_at converts page-table GPAs straight into
     * host-buffer pointers. An unaligned value passes the [base, end) gate but
     * then misaligns the walker. Require:
     *   - pt_pool_next page-aligned relative to pt_pool_base
     *   - ttbr0 strictly inside the in-use pool [pt_pool_base, pt_pool_next)
     *     (parent must have allocated the L0 page) and page-aligned.
     */
    if (hdr.pt_pool_next < g.pt_pool_base || hdr.pt_pool_next > g.pt_pool_end ||
        ((hdr.pt_pool_next - g.pt_pool_base) % GUEST_PAGE_SIZE) != 0) {
        log_error("fork-child: invalid pt_pool_next 0x%llx",
                  (unsigned long long) hdr.pt_pool_next);
        guest_destroy(&g);
        close(ipc_fd);
        return 1;
    }
    uint64_t ttbr0_off = hdr.ttbr0 - g.ipa_base;
    if (ttbr0_off < g.pt_pool_base || ttbr0_off >= hdr.pt_pool_next ||
        ((ttbr0_off - g.pt_pool_base) % GUEST_PAGE_SIZE) != 0) {
        log_error("fork-child: invalid ttbr0 0x%llx",
                  (unsigned long long) hdr.ttbr0);
        guest_destroy(&g);
        close(ipc_fd);
        return 1;
    }
    g.brk_base = hdr.brk_base;
    g.brk_current = hdr.brk_current;
    g.elf_load_min = hdr.elf_load_min;
    g.stack_base = hdr.stack_base;
    g.stack_top = hdr.stack_top;
    g.start_stack = hdr.start_stack;
    g.mmap_next = hdr.mmap_next;
    g.mmap_end = hdr.mmap_end;
    g.pt_pool_next = hdr.pt_pool_next;
    g.ttbr0 = hdr.ttbr0;
    g.mmap_rx_next = hdr.mmap_rx_next;
    g.mmap_rx_end = hdr.mmap_rx_end;

    /* Restore rosetta placement so the non-identity page-table entries that
     * came across in the memory transfer continue to resolve. ttbr1 points at
     * the L0 page the parent's PT pool emitted; that page sits inside the
     * primary buffer and is copied by the region transfer below, so the child
     * can reuse it without rebuilding the tree.
     */
    g.is_rosetta = hdr.is_rosetta;
    proc_set_rosetta_active(g.is_rosetta);
    g.rosetta_guest_base = hdr.rosetta_guest_base;
    g.rosetta_va_base = hdr.rosetta_va_base;
    g.rosetta_size = hdr.rosetta_size;
    g.rosetta_entry = hdr.rosetta_entry;
    g.kbuf_gpa = hdr.kbuf_gpa;
    g.ttbr1 = hdr.ttbr1;
    if (g.is_rosetta && g.kbuf_gpa)
        g.kbuf_base = (uint8_t *) g.host_base + g.kbuf_gpa;

    /* Register state is the fork return frame captured from the parent vCPU. */
    ipc_registers_t regs;
    if (fork_ipc_read_all(ipc_fd, &regs, sizeof(regs)) < 0) {
        log_error("fork-child: failed to read registers");
        guest_destroy(&g);
        return 1;
    }

    if (fork_ipc_recv_memory_regions(ipc_fd, &g) < 0) {
        log_error("fork-child: failed to receive memory regions");
        guest_destroy(&g);
        return 1;
    }

    if (fork_ipc_recv_fd_table(ipc_fd, &g) < 0) {
        log_error("fork-child: failed to receive fd table");
        guest_destroy(&g);
        return 1;
    }

    /* Linux preserves already-open descriptors above a newly lowered soft limit
     * across fork. Install the inherited table under the default table limit
     * first, then restore the parent's guest-visible limit.
     */
    if (sys_nofile_restore(hdr.nofile_cur, hdr.nofile_max) < 0) {
        log_error("fork-child: failed to restore RLIMIT_NOFILE");
        guest_destroy(&g);
        return 1;
    }

    /* Must follow fork_ipc_recv_fd_table: the keepalive recv resolves each
     * payload guest_fd to its (now installed) child-side host master fd.
     */
    if (fork_ipc_recv_pty_keepalives(ipc_fd) < 0) {
        log_error("fork-child: failed to receive pty keepalives");
        guest_destroy(&g);
        return 1;
    }

    /* Both the fd table and the keepalives are in place, which is what this
     * needs to recognize the slave fds inherited from the parent and put them
     * back on the books. Without it the parent's close of its own copy makes
     * the pty look hung up while this child still holds a live slave.
     *
     * From here on every bail gives the credit back before destroying the
     * guest. Nothing below reaches the teardown that normally returns it, and a
     * child that never runs must not leave the pty looking busy to the master
     * the parent still holds.
     */
    proc_pty_adopt_inherited_slaves();

    signal_state_snapshot_t sig;
    if (fork_ipc_recv_process_state(ipc_fd, &g, &sig) < 0) {
        log_error("fork-child: failed to receive process state");

        proc_pty_release_process_slaves();
        guest_destroy(&g);
        return 1;
    }

    if (chown_overlay_recv(ipc_fd) < 0) {
        log_error("fork-child: failed to receive chown overlay");

        proc_pty_release_process_slaves();
        guest_destroy(&g);
        return 1;
    }

    /* Do not enter guest code until the parent has committed both the local
     * process-table slot and the shared lifecycle entry. EOF here means fork
     * admission failed, so this helper exits without exposing a child whose PID
     * the parent cannot later wait for.
     */
    uint8_t admission_ready = 0;
    if (fork_ipc_read_all(ipc_fd, &admission_ready, sizeof(admission_ready)) <
            0 ||
        admission_ready != 1) {
        log_error("fork-child: parent did not commit child admission");

        proc_pty_release_process_slaves();
        guest_destroy(&g);
        return 1;
    }

    /* POSIX: "Signals pending to the parent shall not be pending to the child."
     * Clear the entire shared pending set before applying state. The child's
     * single thread starts with an empty private set (thread_register_main
     * zeroes the slot). signal_set_state() is deferred until after
     * thread_register_main() so that current_thread is non-NULL and per-thread
     * state (blocked mask, altstack) is properly restored.
     */
    memset(&sig.shared, 0, sizeof(sig.shared));

    /* execve in the child needs the shim bytes after guest_reset clears memory.
     * Close IPC socket
     */
    close(ipc_fd);

    /* Create the child vCPU only after all inherited state is available. */
    hv_vcpu_t vcpu;
    hv_vcpu_exit_t *vexit;
    HV_CHECK(hv_vcpu_create(&vcpu, &vexit, NULL));
    g.vcpu = vcpu;
    g.vcpu_valid = true;
    g.exit = vexit;

    /* Restore system registers. For fork children, the child enables the MMU
     * directly via hv_vcpu_set_sys_reg (rather than going through the shim
     * entry point) because:
     * 1. The page tables are already set up (copied from parent via IPC)
     * 2. The shim entry zeros ALL GPRs before ERET, which would destroy
     *    callee-saved registers (X19-X28, FP, LR) that the guest expects
     *    preserved across the clone() syscall
     * 3. The child can restore the exact parent GPR state and only set X0=0
     */
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, regs.vbar_el1));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1, regs.mair_el1));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, regs.tcr_el1));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, regs.ttbr0_el1));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR1_EL1, regs.ttbr1_el1));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, regs.cpacr_el1));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, regs.sp_el0));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL1, regs.sp_el1));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL0, regs.tpidr_el0));

    /* TPIDR_EL1 is set by the host (never inherited from the parent's register
     * snapshot) because it must point at the child's own shim_globals base in
     * the child's IPA; shim_data_base happens to be the same value in both
     * processes (layout derives from guest_size + ipa_bits which match across
     * fork), but installing it explicitly keeps the child consistent with the
     * bootstrap path. CONTEXTIDR_EL1 holds the per-vCPU tid (== child pid for
     * the single-threaded child at this point).
     */
    if (shim_globals_install_per_vcpu(vcpu, &g, hdr.child_pid) < 0) {
        /* Give the pty credit back, as every bail below the adopt does. */
        proc_pty_release_process_slaves();
        guest_destroy(&g);
        return 1;
    }

    /* Enable MMU directly (page tables already in guest memory from IPC). SCTLR
     * must include MMU-enable (M), caches (C, I), RES1 bits, and EL0 cache
     * maintenance access (UCI, UCT) for JIT translators.
     */
    uint64_t sctlr_with_mmu = SCTLR_RES1 | SCTLR_M | SCTLR_C | SCTLR_I |
                              SCTLR_DZE | SCTLR_UCT | SCTLR_UCI;
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, sctlr_with_mmu));

    /* Restore all 31 GPRs from parent state, then override X0=0 (child clone
     * return value). This preserves X1-X30 exactly as they were when the parent
     * called clone(), which is required by the Linux syscall ABI (especially
     * callee-saved X19-X28, FP=X29, LR=X30).
     */
    vcpu_restore_gprs(vcpu, regs.x);
    vcpu_set_gpr(vcpu, 0, 0); /* Child gets 0 from clone */

    vcpu_restore_simd(vcpu, &regs.simd_state);

    /* Start at the clone return point in EL0 (not the shim entry). ELR_EL1
     * points to the guest's clone return site. SPSR_EL1 has the saved EL0
     * state. The child sets PC/CPSR for EL0t execution.
     */
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, regs.elr_el1));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SPSR_EL1, regs.spsr_el1));
    HV_CHECK(hv_vcpu_set_reg(vcpu, HV_REG_PC, regs.elr_el1));
    HV_CHECK(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0)); /* EL0t */

    /* Register the fork child's main thread in the thread table. Without this,
     * current_thread is NULL and any syscall handler that accesses per-thread
     * state (signal masks, ptrace, CLONE_THREAD) will dereference NULL.
     */
    thread_register_main(vcpu, vexit, hdr.child_pid, regs.sp_el1);

    /* Emulate CLONE_CHILD_SETTID for the fork child. glibc's fork wrapper
     * passes CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID so the child's TCB
     * caches its own TID; without the SETTID write the child keeps the parent's
     * cached TID and modern glibc trips stack-canary / TLS checks ("stack
     * smashing detected"). The write goes through guest memory, valid for both
     * the CoW and region-copy paths. A faulting ctid_gva is the guest's own bad
     * pointer: warn and continue, matching how the kernel ignores a
     * child_tidptr fault.
     *
     * CLONE_CHILD_CLEARTID is deliberately not honored here. The clear-and-wake
     * on exit only matters to an in-process joiner waiting on the futex (that
     * is how the worker-thread exit path serves pthread_join). A fork child is
     * a separate process with its own address space, so its ctid lives in
     * memory no other process can observe -- the parent reaps it via
     * wait4/SIGCHLD, not a cross-process futex. Registering clear_child_tid
     * would be inert.
     */
    if (hdr.clone_flags & LINUX_CLONE_CHILD_SETTID) {
        int32_t tid32 = (int32_t) hdr.child_pid;
        if (guest_write_small(&g, hdr.ctid_gva, &tid32, sizeof(tid32)) < 0)
            log_warn("fork-child: CHILD_SETTID write to 0x%llx failed",
                     (unsigned long long) hdr.ctid_gva);
    }

    /* Re-publish identity into the child's shim-globals cache: the CoW / region
     * copy inherits the parent's pid/uid values, and the shim's identity fast
     * path would otherwise return the parent's pid to the child. Identity is
     * now committed via the same path the bootstrap uses.
     */
    shim_globals_init(&g);
    shim_globals_publish_stats_gate(&g);
    shim_globals_set_trace_enabled(&g, verbose);
    shim_globals_publish_pid(&g, hdr.child_pid, hdr.parent_pid);
    shim_globals_publish_creds(&g, hdr.uid, hdr.euid, hdr.gid, hdr.egid);

    /* proc_set_session above committed hdr.pgid/sid into proc-identity; mirror
     * into the shim cache so the child's getpgid(0)/getsid(0) fast paths see
     * the inherited session state from the first syscall. Publish via
     * proc-identity to keep parity with the syscall-time session_lock ordering
     * even though no sibling vCPU exists at this point.
     */
    proc_publish_pgsid_snapshot(&g);

    /* Fresh entropy for the child. Linux's vDSO getrandom epoch-bumps across
     * fork; this path re-fills the ring from arc4random_buf which seeds from
     * the host kernel's RNG, so parent and child do not share future urandom
     * output.
     */
    shim_globals_refill_urandom_ring(&g);

    /* Register the singleton for the child's signal.c so its attention setters
     * know which guest to update.
     */
    signal_set_shim_globals_guest(&g);

    /* The parent may exit after publishing this child but before bootstrap
     * reaches the guest loop. Pull any reparent transaction that arrived in
     * that window after the shim cache is live, so the fork header's original
     * PPID cannot overwrite the adopter selected by the lifecycle registry.
     */
    proc_lifecycle_sync_self(&g);

    /* Same for the fd-table hooks. Must precede any fd_alloc the child performs
     * (the fd-table-restore step has already run above, but those slots are
     * populated via direct memcpy of the parent's entries; subsequent
     * open/dup/close in the child rely on this registration to keep the bitmap
     * in sync).
     */
    shim_globals_set_singleton(&g);

    /* shim_globals_init above zeroed the urandom bitmap. Walk the inherited fd
     * table and re-mark every readable FD_URANDOM slot so the shim's read fast
     * path sees the correct state from the first syscall onward.
     */
    shim_globals_rebuild_urandom_bitmap();

    if (!verbose)
        mmap_fastpath_prepare_vcpu(&g, current_thread);
    else
        mmap_fastpath_disable(&g);

    /* Now that current_thread is set, apply signal state. This must happen
     * after thread_register_main() so the per-thread blocked mask and altstack
     * are properly restored to the thread entry.
     */
    signal_set_state(&sig);

    log_debug("fork-child: entering vCPU loop");

    /* The child resumes from the captured fork frame and returns 0 to EL0. */
    int wait_status = 0;
    int exit_code =
        vcpu_run_loop(vcpu, vexit, &g, verbose, timeout_sec, &wait_status);

    proc_process_exit(wait_status);

    /* Same reason as the main-process path: this child is where a forked shell
     * runs, and its stdio slaves are closed by the kernel rather than by the
     * guest, so they never reach the per-fd close hook. The parent still holds
     * the master and is waiting for exactly this hangup.
     */
    proc_pty_release_process_slaves();

    guest_destroy(&g);
    return exit_code;
}

/* sys_clone. */

/* Namespace flags. elfuse implements no namespace isolation. Both sys_clone and
 * sys_clone3 reject them.
 */
#define LINUX_CLONE_NEWTIME 0x00000080
#define LINUX_CLONE_NEWNS 0x00020000
#define LINUX_CLONE_NEWCGROUP 0x02000000
#define LINUX_CLONE_NEWUTS 0x04000000
#define LINUX_CLONE_NEWIPC 0x08000000
#define LINUX_CLONE_NEWUSER 0x10000000
#define LINUX_CLONE_NEWPID 0x20000000
#define LINUX_CLONE_NEWNET 0x40000000

#define LINUX_CLONE3_NS_FLAGS                                         \
    (LINUX_CLONE_NEWNS | LINUX_CLONE_NEWCGROUP | LINUX_CLONE_NEWUTS | \
     LINUX_CLONE_NEWIPC | LINUX_CLONE_NEWUSER | LINUX_CLONE_NEWPID |  \
     LINUX_CLONE_NEWNET | LINUX_CLONE_NEWTIME)

/* CLONE_THREAD: create a new guest thread in the same VM. */

/* Arguments passed to the worker pthread. Allocated by sys_clone_thread, freed
 * by the worker after vCPU creation and register setup.
 */
typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    bool ready;
    int startup_rc;
} thread_startup_t;

typedef struct {
    thread_entry_t *thread;
    guest_t *guest;
    thread_startup_t *startup;
    bool verbose;
    uint64_t child_stack, flags, tls;
    /* Parent system regs to copy into the new vCPU */
    uint64_t elr, spsr, vbar, ttbr0, sctlr, tcr, mair, cpacr;
    uint64_t tpidr;
    uint64_t gprs[31];
    uint64_t sp_el1;
    vcpu_simd_state_t simd_state;
} thread_create_args_t;

static void resolve_clone_stack_range(guest_t *g,
                                      uint64_t child_stack,
                                      uint64_t *start_out,
                                      uint64_t *end_out)
{
    if (start_out)
        *start_out = 0;
    if (end_out)
        *end_out = 0;
    if (!g || !child_stack || child_stack <= g->ipa_base)
        return;

    uint64_t sp_off = child_stack - g->ipa_base;
    if (sp_off == 0 || sp_off > g->guest_size)
        return;

    /* The region array is mutated under mmap_lock. The acquire also drains EL1
     * mmap publications before clone resolves a newly allocated stack.
     */
    mmap_lock_acquire(g);
    const guest_region_t *r = guest_region_find(g, sp_off - 1);
    if (r) {
        if (start_out)
            *start_out = r->start;
        if (end_out)
            *end_out = r->end;
    }
    mmap_lock_release();
}

/* Forward declaration: worker entry runs after sys_clone_thread */
static void *thread_create_and_run(void *arg);

/* Snapshot the parent vCPU's EL1 sysregs, GPRs, and SIMD into the child's
 * create-args. HVF binds a vCPU to its creating thread, so the worker calls
 * hv_vcpu_create itself and replays this state. The caller fills the remaining
 * fields (thread, guest, flags, tls, child_stack, sp_el1, startup).
 */
static void tca_capture_parent_regs(thread_create_args_t *tca,
                                    hv_vcpu_t parent_vcpu)
{
    tca->elr = vcpu_get_sysreg(parent_vcpu, HV_SYS_REG_ELR_EL1);
    tca->spsr = vcpu_get_sysreg(parent_vcpu, HV_SYS_REG_SPSR_EL1);
    tca->vbar = vcpu_get_sysreg(parent_vcpu, HV_SYS_REG_VBAR_EL1);
    tca->ttbr0 = vcpu_get_sysreg(parent_vcpu, HV_SYS_REG_TTBR0_EL1);
    tca->sctlr = vcpu_get_sysreg(parent_vcpu, HV_SYS_REG_SCTLR_EL1);
    tca->tcr = vcpu_get_sysreg(parent_vcpu, HV_SYS_REG_TCR_EL1);
    tca->mair = vcpu_get_sysreg(parent_vcpu, HV_SYS_REG_MAIR_EL1);
    tca->cpacr = vcpu_get_sysreg(parent_vcpu, HV_SYS_REG_CPACR_EL1);
    tca->tpidr = vcpu_get_sysreg(parent_vcpu, HV_SYS_REG_TPIDR_EL0);
    vcpu_snapshot_gprs(parent_vcpu, tca->gprs);
    vcpu_snapshot_simd(parent_vcpu, &tca->simd_state);
}

typedef struct {
    bool parent_written;
    bool child_written;
    uint64_t parent_gva;
    uint64_t child_gva;
    int32_t parent_old;
    int32_t child_old;
} clone_tid_rollback_t;

static void clone_rollback_tid_flags(guest_t *g,
                                     const clone_tid_rollback_t *rollback)
{
    if (rollback->parent_written)
        (void) guest_write_small(g, rollback->parent_gva, &rollback->parent_old,
                                 sizeof(rollback->parent_old));
    if (rollback->child_written)
        (void) guest_write_small(g, rollback->child_gva, &rollback->child_old,
                                 sizeof(rollback->child_old));
}

/* Apply the CLONE_*_SETTID / CLONE_CHILD_CLEARTID side effects for a new child.
 * Returns true on success, false if a guest TID write faulted so the caller can
 * unwind its own way (the clone-thread and clone-vm paths differ in cleanup).
 * Order matches the kernel: parent ptid, then record ctid for clear-on-exit,
 * then child ctid.
 */
static bool clone_apply_tid_flags(guest_t *g,
                                  thread_entry_t *t,
                                  uint64_t flags,
                                  int64_t child_tid,
                                  uint64_t ptid_gva,
                                  uint64_t ctid_gva,
                                  clone_tid_rollback_t *rollback)
{
    int32_t tid32 = (int32_t) child_tid;
    *rollback = (clone_tid_rollback_t) {0};
    if (flags & LINUX_CLONE_PARENT_SETTID) {
        if (guest_read_small(g, ptid_gva, &rollback->parent_old,
                             sizeof(rollback->parent_old)) < 0)
            return false;
        rollback->parent_gva = ptid_gva;
    }
    if (flags & LINUX_CLONE_CHILD_SETTID) {
        if (guest_read_small(g, ctid_gva, &rollback->child_old,
                             sizeof(rollback->child_old)) < 0)
            return false;
        rollback->child_gva = ctid_gva;
    }
    if (flags & LINUX_CLONE_PARENT_SETTID) {
        if (guest_write_small(g, ptid_gva, &tid32, sizeof(tid32)) < 0)
            return false;
        rollback->parent_written = true;
    }
    if (flags & LINUX_CLONE_CHILD_CLEARTID)
        t->clear_child_tid = ctid_gva;
    if (flags & LINUX_CLONE_CHILD_SETTID) {
        if (guest_write_small(g, ctid_gva, &tid32, sizeof(tid32)) < 0) {
            clone_rollback_tid_flags(g, rollback);
            return false;
        }
        rollback->child_written = true;
    }
    return true;
}

static int64_t sys_clone_thread(hv_vcpu_t parent_vcpu,
                                guest_t *g,
                                uint64_t flags,
                                uint64_t child_stack,
                                uint64_t stack_map_start,
                                uint64_t stack_map_end,
                                uint64_t ptid_gva,
                                uint64_t tls,
                                uint64_t ctid_gva,
                                bool verbose)
{
    thread_startup_t startup = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };

    /* Allocate guest TID */
    int64_t child_tid = proc_alloc_pid();
    if (child_tid < 0)
        return child_tid;

    /* Allocate thread table slot */
    if (stack_map_start >= stack_map_end)
        resolve_clone_stack_range(g, child_stack, &stack_map_start,
                                  &stack_map_end);

    thread_entry_t *t = thread_alloc(child_tid, stack_map_start, stack_map_end);
    if (!t) {
        log_error("clone_thread: thread table full");
        return -LINUX_EAGAIN;
    }

    /* Captured now, while the slot is guaranteed still ours (thread_alloc just
     * marked it active, so no concurrent thread_alloc reuse-scan will touch it
     * until our own worker deactivates it). Passed to thread_set_host_thread
     * below so it can detect whether this exact slot got recycled to a
     * different logical thread before that call runs.
     */
    uint64_t t_generation = t->generation;

    /* Inherit parent's signal mask (POSIX: clone inherits blocked mask) */
    if (current_thread)
        thread_blocked_store(t, thread_blocked_load(current_thread));

    /* Allocate per-thread EL1 stack (records both sp and slot in t). */
    uint64_t child_sp_el1 = thread_alloc_sp_el1(g, t);
    if (child_sp_el1 == 0) {
        thread_deactivate(t);
        return -LINUX_ENOMEM;
    }

    thread_create_args_t *tca = calloc(1, sizeof(*tca));
    if (!tca) {
        thread_deactivate(t);
        pthread_cond_destroy(&startup.cond);
        pthread_mutex_destroy(&startup.lock);
        return -LINUX_ENOMEM;
    }

    tca->thread = t;
    tca->guest = g;
    tca->startup = &startup;
    tca->verbose = verbose;
    tca->child_stack = child_stack;
    tca->flags = flags;
    tca->tls = tls;
    tca->sp_el1 = child_sp_el1;
    tca_capture_parent_regs(tca, parent_vcpu);

    /* CLONE_*_SETTID / CLONE_CHILD_CLEARTID side effects. CHILD_SETTID writes
     * shared guest memory visible to the child thread.
     */
    clone_tid_rollback_t tid_rollback;
    if (!clone_apply_tid_flags(g, t, flags, child_tid, ptid_gva, ctid_gva,
                               &tid_rollback)) {
        free(tca);
        thread_deactivate(t);
        pthread_cond_destroy(&startup.cond);
        pthread_mutex_destroy(&startup.lock);
        return -LINUX_EFAULT;
    }

    /* Create the host pthread (joinable; the main thread joins all live workers
     * via thread_join_workers before guest teardown, and a worker that exits on
     * its own is joined when its table slot is reused by thread_alloc). Threads
     * clean up their TID address via CLONE_CHILD_CLEARTID + futex wake.
     */
    pthread_t host_thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    int err = pthread_create(&host_thread, &attr, thread_create_and_run, tca);
    pthread_attr_destroy(&attr);

    if (err != 0) {
        log_error("clone_thread: pthread_create failed: %s", strerror(err));
        free(tca);
        thread_deactivate(t);
        pthread_cond_destroy(&startup.cond);
        pthread_mutex_destroy(&startup.lock);

        /* Roll back any SETTID writes done before pthread_create. Same
         * rationale as the post-handshake failure path: clone(2) does not leave
         * live-looking TIDs behind for a thread that never started.
         */
        clone_rollback_tid_flags(g, &tid_rollback);
        return -LINUX_EAGAIN;
    }

    /* If this returns false, the worker already hit its startup_failed path and
     * thread_deactivate'd t fast enough for a concurrent clone to recycle the
     * slot before this write -- t no longer refers to our worker, so the write
     * is skipped rather than clobbering the new occupant (a race flagged by
     * review: recording host_thread unconditionally could corrupt the recycled
     * slot's real handle). A mismatch can only happen alongside a startup
     * failure (thread_deactivate is the sole precondition for reuse, and
     * nothing else calls it this early), so the failure branch below is
     * guaranteed to run and is solely responsible for reaping host_thread in
     * that case.
     */
    bool host_thread_recorded =
        thread_set_host_thread(t, host_thread, true, t_generation);

    pthread_mutex_lock(&startup.lock);
    while (!startup.ready)
        pthread_cond_wait(&startup.cond, &startup.lock);
    pthread_mutex_unlock(&startup.lock);
    pthread_cond_destroy(&startup.cond);
    pthread_mutex_destroy(&startup.lock);
    if (startup.startup_rc < 0) {
        /* Worker failed during HVF bring-up after the SETTID writes had already
         * populated the guest TID slots. Linux clone(2) does not leave a
         * live-looking TID behind for a thread that never started, so restore
         * the slots before the parent sees the error.
         */
        if (host_thread_recorded) {
            /* The worker deactivated its slot before signaling the handshake,
             * so a concurrent clone may already have reused the slot and joined
             * the handle at reuse time; claim the join to guarantee exactly one
             * joiner.
             */
            if (thread_claim_worker_join(t, host_thread))
                pthread_join(host_thread, NULL);
        } else {
            /* The write above was rejected: some other clone recycled t before
             * we could record host_thread, so no table entry references it and
             * nobody else will ever join it. We are the only owner. The
             * worker's startup_failed path is a short, non-blocking sequence
             * (no guest code ever ran), so this join returns promptly.
             */
            pthread_join(host_thread, NULL);
        }
        clone_rollback_tid_flags(g, &tid_rollback);
        return startup.startup_rc;
    }

    log_debug("clone_thread: child tid=%lld created", (long long) child_tid);

    return child_tid;
}

/* Destroy this thread's own vCPU and clear the published handle, in that order,
 * with thread_lock held by the caller. HVF vCPUs are thread-affine, so only the
 * owning thread runs this. Destroying before clearing vcpu_valid keeps a
 * concurrent thread_destroy_all_vcpus scan from ever observing this slot as
 * active-and-valid-but-live: it sees either a live handle (and defers) or a
 * fully torn-down slot. The vcpu_valid guard covers the bring-up-failure
 * caller, where hv_vcpu_create failed before any handle was published.
 */
static void thread_destroy_own_vcpu_locked(thread_entry_t *t)
{
    if (t->vcpu_valid)
        hv_vcpu_destroy(t->vcpu);
    t->vcpu_valid = false;
    t->vcpu = 0;
}

/* Worker pthread entry: creates the HVF vCPU on this thread (required by Apple
 * HVF, since the vCPU is bound to the creating thread), configures all
 * registers from parent state, then enters the run loop. On exit, performs
 * CLONE_CHILD_CLEARTID cleanup (write 0 + FUTEX_WAKE).
 */
static void *thread_create_and_run(void *arg)
{
    thread_create_args_t *tca = (thread_create_args_t *) arg;
    thread_entry_t *t = tca->thread;
    guest_t *g = tca->guest;
    thread_startup_t *startup = tca->startup;

    /* Create vCPU on THIS thread (HVF requirement) */
    hv_vcpu_t vcpu;
    hv_vcpu_exit_t *vexit;
    hv_return_t r = hv_vcpu_create(&vcpu, &vexit, NULL);
    if (r != HV_SUCCESS) {
        log_error("thread tid=%lld: hv_vcpu_create failed: %d",
                  (long long) thread_tid(t), (int) r);
        pthread_mutex_lock(&startup->lock);
        startup->startup_rc = -LINUX_EIO;
        startup->ready = true;
        pthread_cond_broadcast(&startup->cond);
        pthread_mutex_unlock(&startup->lock);
        free(tca);
        thread_deactivate(t);
        return NULL;
    }

    /* Publish the vCPU handle under the thread lock. The slot is already active
     * (thread_alloc set active before pthread_create), so thread_interrupt_all,
     * thread_quiesce_siblings, and thread_destroy_all_vcpus can scan it
     * concurrently; they read t->vcpu under thread_lock, so an unlocked store
     * here is a data race (flagged by ThreadSanitizer). Until this store the
     * scanners observe vcpu_valid=false and skip the slot; the startup_failed
     * path below destroys the handle and clears vcpu_valid in one locked
     * section before deactivating, so a scan either observes a live handle (and
     * defers) or a fully torn-down slot, never an inactive-yet-undestroyed
     * vCPU. The separate flag is required because handle value zero is valid
     * for the first vCPU.
     */
    pthread_mutex_t *tlock = thread_get_lock();
    pthread_mutex_lock(tlock);
    t->vcpu = vcpu;
    t->vcpu_valid = true;
    t->vexit = vexit;

    /* A PTRACE_INTERRUPT that raced this bring-up (arrived before the handle
     * was published) recorded a pending request it could not deliver via
     * hv_vcpus_exit. Consume it under the same lock and self-kick below so the
     * first hv_vcpu_run returns CANCELED into the ptrace-stop path.
     */
    bool ptrace_interrupt = t->ptrace_interrupt_pending;
    t->ptrace_interrupt_pending = false;
    pthread_mutex_unlock(tlock);
    if (ptrace_interrupt)
        hv_vcpus_exit(&vcpu, 1);

    /* Sysreg setup uses checked calls instead of HV_CHECK so the parent's
     * startup handshake can roll back cleanly rather than tearing down the
     * whole process on a transient HVF failure here.
     */
#define WORKER_HV(call)                                            \
    do {                                                           \
        hv_return_t _r = (call);                                   \
        if (_r != HV_SUCCESS) {                                    \
            log_error("thread tid=%lld: %s failed: %d",            \
                      (long long) thread_tid(t), #call, (int) _r); \
            goto startup_failed;                                   \
        }                                                          \
    } while (0)

    /* Copy system registers from parent (shared page tables, same MMU config)
     */
    WORKER_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, tca->vbar));
    WORKER_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1, tca->mair));
    WORKER_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, tca->tcr));
    WORKER_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, tca->ttbr0));
    WORKER_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, tca->cpacr));
    WORKER_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTKCTL_EL1,
                                  CNTKCTL_EL1_EL0_TIMER_EN));

    /* All worker vCPUs in the process share the same shim_globals base (one VM
     * per process); a fresh TPIDR_EL1 set is still required because HVF created
     * this vCPU empty. CONTEXTIDR_EL1 holds the per-thread tid that the gettid
     * shim fast path returns.
     */
    if (shim_globals_install_per_vcpu(vcpu, tca->guest, thread_tid(t)) < 0)
        goto startup_failed;

    /* MMU already on, so set SCTLR with M=1 directly (page tables exist) */
    WORKER_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, tca->sctlr));

    /* Per-thread SP_EL1 (each vCPU needs its own EL1 exception stack) */
    WORKER_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL1, tca->sp_el1));

    /* SP_EL0 = child_stack (provided by clone caller) */
    WORKER_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, tca->child_stack));

    /* TPIDR_EL0 = thread-local storage pointer (if CLONE_SETTLS) */
    if (tca->flags & LINUX_CLONE_SETTLS) {
        WORKER_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL0, tca->tls));
    } else {
        WORKER_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL0, tca->tpidr));
    }

    /* ELR_EL1 = clone return point (same as parent) */
    WORKER_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, tca->elr));
    WORKER_HV(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SPSR_EL1, tca->spsr));

    /* Copy all 31 GPRs from parent, then set X0=0 (child clone return). The
     * vcpu_restore_gprs / vcpu_restore_simd helpers in hvutil.h abort the whole
     * process on failure via HV_CHECK, which would defeat the handshake
     * rollback. Open-code the restore here so transient HVF failures fall into
     * the same startup_failed path as the sysreg writes.
     */
    for (unsigned i = 0; i < 31; i++)
        WORKER_HV(hv_vcpu_set_reg(vcpu, HV_REG_X0 + i, tca->gprs[i]));
    WORKER_HV(hv_vcpu_set_reg(vcpu, HV_REG_X0, 0));

    for (int i = 0; i < 32; i++)
        WORKER_HV(hv_vcpu_set_simd_fp_reg(vcpu, HV_SIMD_FP_REG_Q0 + i,
                                          tca->simd_state.v[i]));
    WORKER_HV(hv_vcpu_set_reg(vcpu, HV_REG_FPSR, tca->simd_state.fpsr));
    WORKER_HV(hv_vcpu_set_reg(vcpu, HV_REG_FPCR, tca->simd_state.fpcr));

    /* Start at clone return point in EL0 (not shim entry) */
    WORKER_HV(hv_vcpu_set_reg(vcpu, HV_REG_PC, tca->elr));
    WORKER_HV(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0)); /* EL0t */
#undef WORKER_HV

    bool verbose = tca->verbose;
    free(tca);

    /* Set per-thread TLS pointer. The fork-quiesce barrier is checked at
     * startup_ok (right before guest entry), not here: signaling startup
     * readiness first lets the clone parent return and reach the barrier via
     * the normal kick path, instead of stalling the fork snapshot until this
     * worker's parent unblocks.
     */
    current_thread = t;

    pthread_mutex_lock(&startup->lock);
    startup->startup_rc = 0;
    startup->ready = true;
    pthread_cond_broadcast(&startup->cond);
    pthread_mutex_unlock(&startup->lock);

    goto startup_ok;

startup_failed:
    /* HVF sysreg/GPR setup failed after vCPU creation. The vCPU handle was
     * already published under thread_lock, so destroy it on its owning thread
     * (the only thread allowed to do so) and clear vcpu_valid in the same
     * critical section, then deactivate. Destroying before clearing the flag
     * keeps a concurrent thread_destroy_all_vcpus scan from ever observing an
     * active-and-valid-but-live handle or an inactive-yet-undestroyed one: it
     * either sees the live handle and defers, or sees the slot fully torn down.
     * Finally signal the parent so it observes a fully torn-down state.
     */
    pthread_mutex_lock(tlock);
    thread_destroy_own_vcpu_locked(t);
    pthread_mutex_unlock(tlock);
    thread_deactivate(t);
    free(tca);
    pthread_mutex_lock(&startup->lock);
    startup->startup_rc = -LINUX_EIO;
    startup->ready = true;
    pthread_cond_broadcast(&startup->cond);
    pthread_mutex_unlock(&startup->lock);
    return NULL;

startup_ok:
    /* If a sibling armed a fork snapshot while this worker was still in
     * bring-up, thread_quiesce_siblings could not kick a not-yet-published
     * vCPU, but it still counted this slot in fork_target_count. Check the
     * barrier before touching guest memory so the snapshot cannot be torn by a
     * freshly-created thread. thread_lock serializes this check against the
     * quiesce scan+arm, so the worker was either kicked (it published in time)
     * or observes the armed barrier here and blocks until the fork completes.
     */
    thread_fork_barrier_check();

    log_debug("thread tid=%lld starting on vCPU", (long long) thread_tid(t));

    vcpu_run_loop(vcpu, vexit, g, verbose, 0, NULL);

    /* Robust futex cleanup: walk the robust list and set FUTEX_OWNER_DIED on
     * each held lock, then wake one waiter. Must happen before CLEARTID so
     * waiters see the died bit.
     */
    if (t->robust_list_head != 0)
        robust_list_walk(g, t);

    /* CLONE_CHILD_CLEARTID: write 0 to the address and wake one waiter. This is
     * how pthread_join works in musl: the joining thread does FUTEX_WAIT on
     * this address until it becomes 0.
     *
     * Drain any deferred munmap before publishing clear_child_tid. A joiner
     * may observe the zero without ever sleeping in FUTEX_WAIT, then reuse the
     * freed VA immediately; ordering only the wake after cleanup leaves a
     * window where MAP_FIXED_NOREPLACE still sees the old stack VMA.
     */
    mem_cleanup_deferred_stack_unmaps(g, t);
    bool wake_ctid = false;
    if (t->clear_child_tid != 0) {
        uint32_t zero = 0;
        if (guest_write_small(g, t->clear_child_tid, &zero, sizeof(zero)) ==
            0) {
            wake_ctid = true;
        } else {
            log_warn(
                "thread tid=%lld clear_child_tid "
                "write failed (gva=0x%llx)",
                (long long) thread_tid(t),
                (unsigned long long) t->clear_child_tid);
        }
    }
    if (wake_ctid)
        futex_wake_one(g, t->clear_child_tid);

    log_debug("thread tid=%lld exiting", (long long) thread_tid(t));

    /* Destroy the vCPU on its owning thread while still holding the lock, and
     * only then clear vcpu_valid. thread_destroy_all_vcpus scans under the same
     * lock; keeping the handle valid until it is actually gone means a teardown
     * scan can never observe this slot as active-with-a-live-but-invalid vCPU
     * and tear down the VM/slab out from under an undestroyed vCPU.
     */
    pthread_mutex_lock(tlock);
    thread_destroy_own_vcpu_locked(t);
    pthread_mutex_unlock(tlock);
    thread_deactivate(t);

    /* When all CLONE_THREAD workers have exited and only the main thread
     * remains, interrupt its futex_wait. In real Linux, child exit delivers
     * SIGCHLD which interrupts futex_wait with -EINTR. elfuse simulates this
     * through the futex interrupt API.
     */
    if (thread_active_count() == 1) {
        log_debug(
            "last worker exited, interrupting "
            "main thread futex_wait/poll");
        futex_interrupt_request();
        wakeup_pipe_signal();
        thread_interrupt_all();
    }

    return NULL;
}

/* CLONE_VM creates a thread sharing guest memory and waitable via wait4. */

/* Worker entry for vm-clone child threads. Nearly identical to
 * thread_create_and_run but sets vm-clone exit semantics.
 */
static void *vm_clone_thread_run(void *arg);

static int64_t sys_clone_vm(hv_vcpu_t parent_vcpu,
                            guest_t *g,
                            uint64_t flags,
                            uint64_t child_stack,
                            uint64_t stack_map_start,
                            uint64_t stack_map_end,
                            uint64_t ptid_gva,
                            uint64_t tls,
                            uint64_t ctid_gva,
                            bool verbose)
{
    /* Allocate guest TID */
    int64_t child_tid = proc_alloc_pid();
    if (child_tid < 0)
        return child_tid;

    /* Allocate thread table slot */
    if (stack_map_start >= stack_map_end)
        resolve_clone_stack_range(g, child_stack, &stack_map_start,
                                  &stack_map_end);

    thread_entry_t *t = thread_alloc(child_tid, stack_map_start, stack_map_end);
    if (!t) {
        log_error("clone_vm: thread table full");
        return -LINUX_EAGAIN;
    }
    uint64_t t_generation = t->generation;

    /* Mark as VM-clone child (waitable via wait4, not CLONE_THREAD) */
    t->is_vm_clone = true;
    t->parent_tid = current_thread ? thread_tid(current_thread) : 0;
    t->exit_signal = (int) (flags & 0xFF); /* Low byte = exit signal */
    if (t->exit_signal == 0)
        t->exit_signal = LINUX_SIGCHLD;

    /* Inherit parent's signal mask */
    if (current_thread)
        thread_blocked_store(t, thread_blocked_load(current_thread));

    /* Allocate per-thread EL1 stack (records both sp and slot in t). */
    uint64_t child_sp_el1 = thread_alloc_sp_el1(g, t);
    if (child_sp_el1 == 0) {
        thread_deactivate(t);
        return -LINUX_ENOMEM;
    }

    thread_create_args_t *tca = calloc(1, sizeof(*tca));
    if (!tca) {
        thread_deactivate(t);
        return -LINUX_ENOMEM;
    }

    tca->thread = t;
    tca->guest = g;
    tca->verbose = verbose;
    tca->child_stack = child_stack
                           ? child_stack
                           : vcpu_get_sysreg(parent_vcpu, HV_SYS_REG_SP_EL0);
    tca->flags = flags;
    tca->tls = tls;
    tca->sp_el1 = child_sp_el1;
    tca_capture_parent_regs(tca, parent_vcpu);

    clone_tid_rollback_t tid_rollback;
    if (!clone_apply_tid_flags(g, t, flags, child_tid, ptid_gva, ctid_gva,
                               &tid_rollback)) {
        free(tca);
        thread_deactivate(t);
        return -LINUX_EFAULT;
    }

    /* Create the host pthread */
    pthread_t host_thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    int err = pthread_create(&host_thread, &attr, vm_clone_thread_run, tca);
    pthread_attr_destroy(&attr);

    if (err != 0) {
        log_error("clone_vm: pthread_create failed: %s", strerror(err));
        free(tca);
        thread_deactivate(t);

        /* Roll back the SETTID writes clone_apply_tid_flags made: no child
         * thread was created, so clone(2) must not leave live-looking TIDs.
         */
        clone_rollback_tid_flags(g, &tid_rollback);
        return -LINUX_EAGAIN;
    }

    /* Detached: the pthread runtime reclaims the thread on exit, so the handle
     * must never be joined (host_thread_needs_join stays false). The generation
     * check always succeeds here: unlike sys_clone_thread's worker, a vm-clone
     * worker that fails HVF bring-up (vm_clone_report_bringup_failure) keeps
     * the slot active for wait4 rather than deactivating it, so t cannot be
     * recycled before this call.
     */
    (void) thread_set_host_thread(t, host_thread, false, t_generation);

    log_debug(
        "clone_vm: child tid=%lld created "
        "(parent=%lld, flags=0x%llx)",
        (long long) child_tid, (long long) t->parent_tid,
        (unsigned long long) flags);

    return child_tid;
}

/* Report a vm-clone worker that failed HVF bring-up as an exited child so the
 * parent's wait4 can reap it. sys_clone_vm already returned the child tid, so
 * dropping the slot with thread_deactivate (which clears active) would make
 * wait4 skip it and leave the parent unable to collect a status. Destroy the
 * vCPU and publish the exit status in one critical section, destroy first: the
 * slot only becomes reapable (vm_exited) once the handle is gone, so a parent
 * wait4 that reaps and deactivates it cannot leave a teardown scan racing an
 * undestroyed vCPU. Keep the slot active for wait4. Reports SIGKILL because the
 * child never ran a guest instruction. Does not trigger exit_group: only the
 * child failed. Runs on the child's own thread, so the destroy is owner-local.
 */
static void vm_clone_report_bringup_failure(thread_entry_t *t)
{
    pthread_mutex_t *lock = thread_get_lock();
    pthread_mutex_lock(lock);
    thread_destroy_own_vcpu_locked(t);
    t->vm_exited = true;
    t->vm_exit_status = LINUX_SIGKILL; /* WIFSIGNALED, WTERMSIG == SIGKILL */
    /* The slot stays active for wait4 rather than deactivating, so the fork
     * barrier hand-back that thread_deactivate would otherwise perform must be
     * done here -- else a fork racing this bring-up failure waits the full
     * quiesce timeout for a child that never reaches the barrier.
     */
    thread_fork_release_counted_locked(t);
    pthread_cond_broadcast(&t->ptrace_cond);
    pthread_mutex_unlock(lock);
}

/* Worker entry for vm-clone children. Sets up vCPU, runs guest code, then marks
 * exit status for parent's wait4 to collect.
 */
static void *vm_clone_thread_run(void *arg)
{
    thread_create_args_t *tca = (thread_create_args_t *) arg;
    thread_entry_t *t = tca->thread;
    guest_t *g = tca->guest;

    /* Create vCPU on THIS thread (HVF requirement) */
    hv_vcpu_t vcpu;
    hv_vcpu_exit_t *vexit;
    hv_return_t r = hv_vcpu_create(&vcpu, &vexit, NULL);
    if (r != HV_SUCCESS) {
        log_error("vm_clone tid=%lld: hv_vcpu_create failed: %d",
                  (long long) thread_tid(t), (int) r);
        free(tca);
        vm_clone_report_bringup_failure(t);
        return NULL;
    }

    /* Publish under the thread lock; see thread_create_and_run for the race
     * this closes (concurrent thread_interrupt_all / thread_destroy_all_vcpus
     * read t->vcpu under thread_lock).
     */
    pthread_mutex_t *tlock = thread_get_lock();
    pthread_mutex_lock(tlock);
    t->vcpu = vcpu;
    t->vcpu_valid = true;
    t->vexit = vexit;

    /* Deliver a PTRACE_INTERRUPT that raced bring-up; see
     * thread_create_and_run. vm-clone children are the usual ptrace targets.
     */
    bool ptrace_interrupt = t->ptrace_interrupt_pending;
    t->ptrace_interrupt_pending = false;
    pthread_mutex_unlock(tlock);
    if (ptrace_interrupt)
        hv_vcpus_exit(&vcpu, 1);

    /* Copy system registers from parent */
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, tca->vbar));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1, tca->mair));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, tca->tcr));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, tca->ttbr0));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, tca->cpacr));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTKCTL_EL1,
                                 CNTKCTL_EL1_EL0_TIMER_EN));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, tca->sctlr));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL1, tca->sp_el1));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, tca->child_stack));
    if (shim_globals_install_per_vcpu(vcpu, tca->guest, thread_tid(t)) < 0) {
        free(tca);
        vm_clone_report_bringup_failure(t);
        return NULL;
    }

    /* TLS pointer */
    if (tca->flags & LINUX_CLONE_SETTLS) {
        HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL0, tca->tls));
    } else {
        HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL0, tca->tpidr));
    }

    /* ELR_EL1 = clone return point */
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, tca->elr));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SPSR_EL1, tca->spsr));

    /* Copy all 31 GPRs from parent, set X0=0 (child clone return) */
    vcpu_restore_gprs(vcpu, tca->gprs);
    vcpu_set_gpr(vcpu, 0, 0);

    vcpu_restore_simd(vcpu, &tca->simd_state);

    /* Start at clone return point in EL0 */
    HV_CHECK(hv_vcpu_set_reg(vcpu, HV_REG_PC, tca->elr));
    HV_CHECK(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0)); /* EL0t */

    bool verbose = tca->verbose;
    free(tca);

    /* Set per-thread TLS pointer and enter worker run loop */
    current_thread = t;
    thread_fork_barrier_check();
    log_debug("vm_clone tid=%lld starting on vCPU", (long long) thread_tid(t));

    int wait_status = 0;
    int exit_code = vcpu_run_loop(vcpu, vexit, g, verbose, 0, &wait_status);

    /* CLONE_CHILD_CLEARTID cleanup. Same ordering as thread_entry: the zero
     * itself, not just the futex wake, releases a joiner, so publish it only
     * after the deferred stack mapping is gone.
     */
    mem_cleanup_deferred_stack_unmaps(g, t);
    bool wake_ctid = false;
    if (t->clear_child_tid != 0) {
        uint32_t zero = 0;
        if (guest_write_small(g, t->clear_child_tid, &zero, sizeof(zero)) ==
            0) {
            wake_ctid = true;
        } else {
            log_warn(
                "vm_clone tid=%lld clear_child_tid "
                "write failed (gva=0x%llx)",
                (long long) thread_tid(t),
                (unsigned long long) t->clear_child_tid);
        }
    }
    if (wake_ctid)
        futex_wake_one(g, t->clear_child_tid);

    log_debug("vm_clone tid=%lld exiting (code=%d)", (long long) thread_tid(t),
              exit_code);

    /* Destroy the vCPU and publish exit status in one critical section, destroy
     * first. The slot only becomes reapable (vm_exited) once the handle is
     * gone, so a parent wait4 that reaps and deactivates the slot can never
     * leave a later teardown scan racing an undestroyed vCPU. thread_lock also
     * serializes this against thread_destroy_all_vcpus. Destroying this vCPU
     * ahead of thread_interrupt_all below is fine: the current vCPU already
     * left hv_vcpu_run, and thread_interrupt_all only needs the OTHER vCPUs'
     * handles. vm_exit_status is wait-format: (exit_code << 8) for a normal
     * exit.
     */
    pthread_mutex_t *lock = thread_get_lock();
    pthread_mutex_lock(lock);
    thread_destroy_own_vcpu_locked(t);
    t->vm_exited = true;
    t->vm_exit_status = wait_status;
    pthread_cond_broadcast(&t->ptrace_cond);
    pthread_mutex_unlock(lock);

    /* Slot stays active until the parent collects status with wait4;
     * thread_ptrace_wait frees it when it reads vm_exited.
     */

    /* Last VM-clone child triggers exit_group so the main thread's futex_wait /
     * run loop unblocks (mirrors SIGCHLD on child exit). vm_exited is already
     * set, so this slot excludes itself from the active-clone count.
     */
    int last_clone = (thread_count_active_vm_clones() == 0);
    if (last_clone) {
        log_debug("last vm_clone exited, triggering exit_group");
        proc_request_exit_group(exit_code);

        /* thread_interrupt_all only reaches threads inside hv_vcpu_run; peers
         * parked on fork_cond or another slot's ptrace_cond/resume_cond need
         * the separate broadcast.
         */
        thread_interrupt_all();
        thread_wake_exit_waiters();
    }

    return NULL;
}

/* Create an APFS block-level CoW clone of src_fd via fclonefileat (O(metadata),
 * independent of the source once either side writes).
 *
 * Returns the clone fd on success, -1 with errno set on failure (non-APFS /tmp,
 * ENOSYS, ENOSPC, ...). Callers that issue this snapshot are documented at the
 * call site; the helper itself only owns the clone-path lifecycle.
 */
static int fork_snapshot_shm_via_clonefile(int src_fd)
{
    /* fclonefileat needs a destination path on the same APFS volume as the
     * source. /tmp is APFS on every shipped macOS Apple Silicon configuration;
     * if a user has remapped /tmp to a different filesystem the call fails and
     * the caller drops back to the legacy path.
     *
     * The destination lives inside a fresh mkdtemp directory (mode 0700) so no
     * other local user can race to claim the destination basename between path
     * selection and fclonefileat: an earlier mkstemp + unlink + fclonefileat
     * sequence left a window where /tmp was world-writable for that name and a
     * concurrent process could DoS the fast path via EEXIST.
     */
    char tmpdir[] = "/tmp/elfuse-fork-XXXXXX";
    if (!mkdtemp(tmpdir))
        return -1;
    char clone_path[64];
    snprintf(clone_path, sizeof(clone_path), "%s/snap", tmpdir);
    if (fclonefileat(src_fd, AT_FDCWD, clone_path, 0) < 0) {
        int saved_errno = errno;
        rmdir(tmpdir);
        errno = saved_errno;
        return -1;
    }
    int clone_fd = open(clone_path, O_RDWR | O_CLOEXEC);
    int saved_errno = errno;

    /* Best-effort cleanup: the clone fd alone keeps the inode alive, so any
     * unlink/rmdir failure here is a directory-leak nuisance, not a correctness
     * issue. Caller still gets the open fd.
     */
    (void) unlink(clone_path);
    (void) rmdir(tmpdir);
    if (clone_fd < 0) {
        errno = saved_errno;
        return -1;
    }
    return clone_fd;
}

/* Over the function-size limit on purpose.
 *
 * One transaction. The failure paths unwind state established earlier in the
 * same function (quiesced siblings, promoted overlays, the snapshot fd), so the
 * goto ladder has to see all of it.
 */
/* NOLINTNEXTLINE(readability-function-size) */
int64_t sys_clone(hv_vcpu_t vcpu,
                  guest_t *g,
                  uint64_t flags,
                  uint64_t child_stack,
                  uint64_t stack_map_start,
                  uint64_t stack_map_end,
                  uint64_t ptid_gva,
                  uint64_t tls,
                  uint64_t ctid_gva,
                  bool verbose)
{
    /* Namespaces are not implemented. CLONE_NEWTIME (0x80) lives in the CSIGNAL
     * low byte and, like CLONE_INTO_CGROUP (bit 33) and set_tid, cannot be
     * conveyed through clone(2) at all, so only the higher namespace bits are
     * reachable here.
     */
    if ((flags & ~(uint64_t) 0xff) & LINUX_CLONE3_NS_FLAGS)
        return -LINUX_EINVAL;

    /* CLONE_THREAD: create a new thread in the same VM (not a new process) */
    if (flags & LINUX_CLONE_THREAD) {
        return sys_clone_thread(vcpu, g, flags, child_stack, stack_map_start,
                                stack_map_end, ptid_gva, tls, ctid_gva,
                                verbose);
    }

    /* Rosetta fork takes the helper-process IPC path. The parent cannot remap
     * its live guest memory under the running vCPU because HVF caches VA->PA at
     * hv_vm_map time; instead, the fork path snapshots shm with clonefile when
     * available and otherwise falls back to region copy. The TTBR1 kbuf tree,
     * translator image, and kbuf bytes ride along as primary-buffer used
     * regions; the child restores TCR_EL1 / TTBR1_EL1 from ipc_registers_t and
     * recomputes kbuf_base from kbuf_gpa.
     */

    /* elfuse only supports fork-like clone (SIGCHLD) and posix_spawn-like
     * clone (CLONE_VM|CLONE_VFORK|SIGCHLD)
     */
    bool is_vfork = (flags & LINUX_CLONE_VFORK) != 0;

    /* CLONE_VM without CLONE_THREAD usually creates an in-process VM-clone
     * child that shares guest memory and is waitable via wait4/ptrace. However
     * CLONE_VFORK must go through the helper-process path below so the child's
     * later execve replaces only the child image rather than resetting the
     * parent's shared guest_t.
     */
    if ((flags & LINUX_CLONE_VM) && !(flags & LINUX_CLONE_THREAD) &&
        !is_vfork) {
        return sys_clone_vm(vcpu, g, flags, child_stack, stack_map_start,
                            stack_map_end, ptid_gva, tls, ctid_gva, verbose);
    }

    log_debug("clone(flags=0x%llx, vfork=%d)", (unsigned long long) flags,
              is_vfork);

    /* socketpair provides the control channel used to transfer snapshot state
     * and SCM_RIGHTS file descriptors to the fork-child process.
     */
    int sock_fds[2];
    int vfork_notify_fds[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds) < 0) {
        log_error("clone: socketpair failed: %s", strerror(errno));
        return -LINUX_ENOMEM;
    }

    /* A fork-child that dies mid-handshake makes every send on this socket
     * raise SIGPIPE, which elfuse leaves at its default terminate disposition
     * (only SIGUSR2 and SIGALRM are masked at bring-up), so the whole host
     * process would die instead of the clone failing. Suppress it per-socket
     * the way syscall/net.c does for guest sockets; the option rides on the
     * file description, so the spawned child inherits it.
     *
     * Failing the clone beats continuing without it: proceeding would leave the
     * host one dead child away from being killed by a signal it never handles,
     * which is worse than the guest seeing a fork it can retry.
     */
    int nosigpipe = 1;
    if (setsockopt(sock_fds[0], SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe,
                   sizeof(nosigpipe)) < 0 ||
        setsockopt(sock_fds[1], SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe,
                   sizeof(nosigpipe)) < 0) {
        log_error("clone: SO_NOSIGPIPE failed: %s", strerror(errno));
        close(sock_fds[0]);
        close(sock_fds[1]);
        return -LINUX_ENOMEM;
    }
    if (is_vfork && pipe(vfork_notify_fds) < 0) {
        log_error("clone: vfork notify pipe failed: %s", strerror(errno));
        close(sock_fds[0]);
        close(sock_fds[1]);
        return -LINUX_ENOMEM;
    }

    /* Spawn the same elfuse binary so the child has the same entitlement and
     * build as the parent.
     */
    char self_path[LINUX_PATH_MAX];
    uint32_t path_len = sizeof(self_path);
    if (_NSGetExecutablePath(self_path, &path_len) != 0) {
        log_error("clone: _NSGetExecutablePath failed");
        close(sock_fds[0]);
        close(sock_fds[1]);
        return -LINUX_ENOMEM;
    }

    /* The child starts in --fork-child mode and receives the inherited state on
     * the socket fd.
     */
    char fd_str[32];
    snprintf(fd_str, sizeof(fd_str), "%d", sock_fds[1]);

    /* argv is intentionally minimal; guest argv is restored later from IPC. */
    char notify_fd_str[32];
    char *child_argv[16];
    int ci = 0;
    child_argv[ci++] = self_path;
    if (verbose)
        child_argv[ci++] = "--verbose";

    /* Rosetta is on by default; only propagate the opt-out flag when the parent
     * explicitly disabled it. The child re-reads ELFUSE_NO_ROSETTA from the
     * environment too, so an env-based opt-out is preserved across fork without
     * an explicit argv entry.
     */
    if (!proc_rosetta_enabled())
        child_argv[ci++] = "--no-rosetta";
    if (proc_fakeroot_enabled())
        child_argv[ci++] = "--fakeroot";
    child_argv[ci++] = "--fork-child";
    child_argv[ci++] = fd_str;
    if (is_vfork) {
        snprintf(notify_fd_str, sizeof(notify_fd_str), "%d",
                 vfork_notify_fds[1]);
        child_argv[ci++] = "--vfork-notify-fd";
        child_argv[ci++] = notify_fd_str;
    }
    child_argv[ci] = NULL;

    /* Set up spawn attributes: close all inherited FDs by default.
     * POSIX_SPAWN_CLOEXEC_DEFAULT (macOS extension) marks all FDs as
     * close-on-exec in the child. Without this, ALL parent host FDs (pipes,
     * sockets, etc.) leak into the child elfuse process, wasting file
     * descriptors and potentially preventing pipe EOF detection.
     */
    posix_spawnattr_t spawn_attr;
    posix_spawnattr_init(&spawn_attr);
    posix_spawnattr_setflags(&spawn_attr, POSIX_SPAWN_CLOEXEC_DEFAULT);

    /* Set up file actions: explicitly inherit only needed FDs. With
     * CLOEXEC_DEFAULT, everything is closed unless elfuse opts in.
     */
    posix_spawn_file_actions_t file_actions;
    posix_spawn_file_actions_init(&file_actions);
    posix_spawn_file_actions_addinherit_np(&file_actions, STDIN_FILENO);
    posix_spawn_file_actions_addinherit_np(&file_actions, STDOUT_FILENO);
    posix_spawn_file_actions_addinherit_np(&file_actions, STDERR_FILENO);
    posix_spawn_file_actions_addinherit_np(&file_actions, sock_fds[1]);
    if (is_vfork)
        posix_spawn_file_actions_addinherit_np(&file_actions,
                                               vfork_notify_fds[1]);

    /* Allocate and reserve all guest-visible bookkeeping before creating the
     * host helper. Linux fork failure must not leave a child running, and a
     * successful fork must always return a PID that wait4/waitid can track.
     */
    proc_registry_sync_self_pgid(g);
    int64_t child_pgid = proc_get_pgid();
    int64_t child_guest_pid = proc_alloc_pid();
    if (child_guest_pid < 0) {
        posix_spawn_file_actions_destroy(&file_actions);
        posix_spawnattr_destroy(&spawn_attr);
        close(sock_fds[0]);
        close(sock_fds[1]);
        if (vfork_notify_fds[0] >= 0)
            close(vfork_notify_fds[0]);
        if (vfork_notify_fds[1] >= 0)
            close(vfork_notify_fds[1]);
        return child_guest_pid;
    }
    int reserve_rc = proc_reserve_child(child_guest_pid, child_pgid);
    if (reserve_rc < 0) {
        posix_spawn_file_actions_destroy(&file_actions);
        posix_spawnattr_destroy(&spawn_attr);
        close(sock_fds[0]);
        close(sock_fds[1]);
        if (vfork_notify_fds[0] >= 0)
            close(vfork_notify_fds[0]);
        if (vfork_notify_fds[1] >= 0)
            close(vfork_notify_fds[1]);
        return reserve_rc;
    }
    extern char **environ;
    pid_t child_host_pid;
    int spawn_ret = posix_spawn(&child_host_pid, self_path, &file_actions,
                                &spawn_attr, child_argv, environ);
    posix_spawn_file_actions_destroy(&file_actions);
    posix_spawnattr_destroy(&spawn_attr);

    if (spawn_ret != 0) {
        log_error("clone: posix_spawn failed: %s", strerror(spawn_ret));
        proc_cancel_child(child_guest_pid);
        close(sock_fds[0]);
        close(sock_fds[1]);
        if (vfork_notify_fds[0] >= 0)
            close(vfork_notify_fds[0]);
        if (vfork_notify_fds[1] >= 0)
            close(vfork_notify_fds[1]);
        return -LINUX_ENOMEM;
    }

    /* The parent keeps only its end of the control channel. Reset the closed
     * write end to -1 so the fail_snapshot guarded close at the bottom of the
     * function cannot double-close it. In a multithreaded guest, another vCPU
     * could open a new fd between the two closes and get the same number, which
     * the second close would then steal.
     */
    close(sock_fds[1]);
    if (vfork_notify_fds[1] >= 0) {
        close(vfork_notify_fds[1]);
        vfork_notify_fds[1] = -1;
    }
    int ipc_sock = sock_fds[0];

    mmap_fork_anon_shared_txn_t *anon_shared_txn = NULL;
    guest_region_t *regions_snapshot = NULL;
    uint64_t *dirty_blocks_snapshot = NULL;
    guest_region_t preannounced_snapshot[GUEST_MAX_PREANNOUNCED];
    int snapshot_shm_fd = -1;
    bool siblings_quiesced = false;
    int64_t fail_rc = -LINUX_ENOMEM;

    /* Quiesce sibling vCPUs for snapshot consistency. In multithreaded guests,
     * sibling vCPUs may be actively mutating guest memory during the fork
     * snapshot (CoW or legacy IPC copy). Without quiescing them, the child
     * process can receive a torn snapshot with partially-updated data
     * structures. This matches POSIX fork semantics where only the calling
     * thread survives.
     */
    if (!thread_quiesce_siblings()) {
        /* An execve is reaping this thread. The snapshot would run without the
         * quiet it needs, and the child would outlive a parent that is already
         * gone, so refuse the fork instead.
         */
        fail_rc = -LINUX_EINTR;
        goto fail_snapshot;
    }
    siblings_quiesced = true;

    /* Convert MAP_SHARED|MAP_ANONYMOUS regions that have no backing fd into
     * memfd-backed overlay regions. The conversion seeds a private temp file
     * with the current bytes and installs a host MAP_SHARED|MAP_FIXED overlay
     * on the parent. The child receives the fd via SCM_RIGHTS and re-installs
     * its own overlay so subsequent writes from either side flow through the
     * kernel page cache and reach the other. File-backed MAP_SHARED regions
     * already carry a backing fd and are unaffected. Misaligned shared regions
     * (snapshot-style) remain incoherent across fork by design.
     */
    if (mmap_fork_prepare_anon_shared(g, &anon_shared_txn) < 0)
        goto fail_snapshot;

    /* CoW fast path: if shm_fd >= 0, send a snapshot of guest memory to the
     * child instead of the per-region copy. The child maps that snapshot
     * MAP_PRIVATE; subsequent writes on either side are private.
     *
     * The parent's own mapping cannot be flipped to MAP_PRIVATE here: hv_vm_map
     * caches the host VA->PA mapping, and a MAP_FIXED remap invalidates it (the
     * parent then reads stale memory and writev returns EFAULT). So the parent
     * stays on MAP_SHARED and the snapshot is what isolates the child.
     *
     * Two snapshot sources, in preference order (selected just below):
     *   1. fclonefileat of g->shm_fd to an independent APFS clone. The clone
     *      shares blocks with the parent until either side writes, so the
     *      parent's subsequent writes never reach the child's backing.
     *   2. The live g->shm_fd. Any page the child has not yet COW'd reads the
     *      parent's current bytes -- benign for typical guest state, but
     *      corrupts Rosetta's translator-internal structures (TLS slabs, code
     *      caches, indirect-call tables) on mid-update reads. Issue #45.
     *
     * Rosetta therefore requires path 1 and falls back to region copy if
     * fclonefileat fails; native guests accept path 2 as a fallback so a
     * non-APFS /tmp does not silently slow forks down to per-region copy cost.
     */
    bool use_shm = (g->shm_fd >= 0);

    /* Overlay sync runs before the snapshot so the cloned file picks up the
     * overlay-backed bytes. The parent's host VA for each overlay region maps
     * the overlay file, not shm_fd, so shm_fd's contents at those offsets are
     * stale (typically zero) until the pwrite below copies them in. Both the
     * clone-fd path and the live-shm_fd fallback consume this sync.
     */
    if (use_shm) {
        for (int i = 0; i < g->nregions; i++) {
            const guest_region_t *r = &g->regions[i];
            if (!r->overlay_active)
                continue;
            uint64_t len = r->end - r->start;
            const uint8_t *src = (const uint8_t *) g->host_base + r->start;
            uint64_t off = r->start;
            while (len > 0) {
                size_t chunk = len > (uint64_t) SSIZE_MAX ? (size_t) SSIZE_MAX
                                                          : (size_t) len;
                ssize_t nw = pwrite(g->shm_fd, src, chunk, (off_t) off);
                if (nw < 0) {
                    if (errno == EINTR)
                        continue;
                    log_error("clone: shm overlay sync pwrite failed: %s",
                              strerror(errno));
                    goto fail_snapshot;
                }
                if (nw == 0) {
                    log_error("clone: shm overlay sync pwrite returned 0");
                    goto fail_snapshot;
                }
                src += nw;
                off += (uint64_t) nw;
                len -= (uint64_t) nw;
            }
        }

        /* Attempt the APFS clone snapshot for every guest, not just Rosetta:
         * the clone gives POSIX-style isolation at O(metadata) cost and avoids
         * torn-snapshot reads in guests that snapshot their own state across
         * fork (Redis BGSAVE, checkpointing runtimes). On failure the fallback
         * differs per design above: Rosetta drops use_shm so the region-copy
         * path runs; native guests keep use_shm and send the live g->shm_fd.
         */
        snapshot_shm_fd = fork_snapshot_shm_via_clonefile(g->shm_fd);
        if (snapshot_shm_fd < 0) {
            if (g->is_rosetta) {
                log_warn(
                    "clone: rosetta CoW snapshot via fclonefileat failed "
                    "(%s); falling back to region-copy path",
                    strerror(errno));
                use_shm = false;
            } else {
                log_debug(
                    "clone: CoW snapshot via fclonefileat failed (%s); "
                    "sending live shm fd as fallback",
                    strerror(errno));
            }
        }
    }

    /* Snapshot of the semantic region array, populated after the memory dump
     * but before sibling vCPUs resume. Declared up front so all goto paths to
     * fail_snapshot can free it unconditionally. Header
     */
    uint64_t nofile_cur, nofile_max;
    sys_nofile_snapshot(&nofile_cur, &nofile_max);

    ipc_header_t hdr = {
        .magic = IPC_MAGIC_HEADER,
        .ipa_bits = g->ipa_bits,
        .has_shm = use_shm,
        .child_pid = child_guest_pid,
        .parent_pid = proc_get_pid(),
        .guest_size = g->guest_size,
        .elf_load_min = g->elf_load_min,
        .brk_base = g->brk_base,
        .brk_current = g->brk_current,
        .stack_base = g->stack_base,
        .stack_top = g->stack_top,
        .start_stack = g->start_stack,
        .mmap_next = g->mmap_next,
        .mmap_end = g->mmap_end,
        .pt_pool_next = g->pt_pool_next,
        .ttbr0 = g->ttbr0,
        .mmap_rx_next = g->mmap_rx_next,
        .mmap_rx_end = g->mmap_rx_end,
        .uid = proc_get_uid(),
        .euid = proc_get_euid(),
        .suid = proc_get_suid(),
        .gid = proc_get_gid(),
        .egid = proc_get_egid(),
        .sgid = proc_get_sgid(),
        .nice = proc_get_nice(),
        .absock_namespace_id = absock_get_namespace_id(),
        .sid = proc_get_sid(),
        .pgid = child_pgid,
        .is_rosetta = g->is_rosetta,
        .rosetta_guest_base = g->rosetta_guest_base,
        .rosetta_va_base = g->rosetta_va_base,
        .rosetta_size = g->rosetta_size,
        .rosetta_entry = g->rosetta_entry,
        .kbuf_gpa = g->kbuf_gpa,
        .ttbr1 = g->ttbr1,
        .clone_flags =
            flags & (LINUX_CLONE_CHILD_SETTID | LINUX_CLONE_CHILD_CLEARTID),
        .ctid_gva = ctid_gva,
        .shm_is_clone = (snapshot_shm_fd >= 0) ? 1 : 0,
        .nofile_cur = nofile_cur,
        .nofile_max = nofile_max,
    };
    proc_registry_publish_self();
    if (fork_ipc_write_all(ipc_sock, &hdr, sizeof(hdr)) < 0) {
        log_error("clone: failed to send header");
        goto fail_snapshot;
    }

    /* Send the snapshot fd if fclonefileat succeeded, otherwise the live
     * g->shm_fd. The Rosetta-failure case already cleared use_shm above so it
     * never reaches this branch with snapshot_shm_fd < 0.
     */
    if (use_shm) {
        int fd_to_send = (snapshot_shm_fd >= 0) ? snapshot_shm_fd : g->shm_fd;
        if (fork_ipc_send_fds(ipc_sock, &fd_to_send, 1) < 0) {
            log_error("clone: failed to send shm fd");
            goto fail_snapshot;
        }
    }

    /* Registers: capture current vCPU state */
    ipc_registers_t regs = {0};
    regs.elr_el1 = vcpu_get_sysreg(vcpu, HV_SYS_REG_ELR_EL1);
    regs.sp_el0 = vcpu_get_sysreg(vcpu, HV_SYS_REG_SP_EL0);
    if (child_stack)
        regs.sp_el0 = child_stack;
    regs.spsr_el1 = vcpu_get_sysreg(vcpu, HV_SYS_REG_SPSR_EL1);
    regs.vbar_el1 = vcpu_get_sysreg(vcpu, HV_SYS_REG_VBAR_EL1);
    regs.ttbr0_el1 = vcpu_get_sysreg(vcpu, HV_SYS_REG_TTBR0_EL1);
    regs.ttbr1_el1 = vcpu_get_sysreg(vcpu, HV_SYS_REG_TTBR1_EL1);
    regs.sctlr_el1 = vcpu_get_sysreg(vcpu, HV_SYS_REG_SCTLR_EL1);
    regs.tcr_el1 = vcpu_get_sysreg(vcpu, HV_SYS_REG_TCR_EL1);
    regs.mair_el1 = vcpu_get_sysreg(vcpu, HV_SYS_REG_MAIR_EL1);
    regs.cpacr_el1 = vcpu_get_sysreg(vcpu, HV_SYS_REG_CPACR_EL1);
    regs.tpidr_el0 = vcpu_get_sysreg(vcpu, HV_SYS_REG_TPIDR_EL0);
    regs.sp_el1 = vcpu_get_sysreg(vcpu, HV_SYS_REG_SP_EL1);
    vcpu_snapshot_gprs(vcpu, regs.x);

    vcpu_snapshot_simd(vcpu, &regs.simd_state);

    if (fork_ipc_write_all(ipc_sock, &regs, sizeof(regs)) < 0) {
        log_error("clone: failed to send registers");
        goto fail_snapshot;
    }
    if (fork_ipc_send_memory_regions(ipc_sock, g, use_shm) < 0) {
        log_error("clone: failed to send memory regions");
        goto fail_snapshot;
    }

    /* Snapshot the semantic region array before resuming siblings. Siblings may
     * mmap/munmap/mprotect after resume, so the code needs a stable copy for
     * the IPC send. Heap-allocated because GUEST_MAX_REGIONS *
     * sizeof(guest_region_t) exceeds safe stack limits on worker threads
     * (512KiB default).
     */
    int nregions_snapshot = g->nregions;
    bool regions_tracker_stale_snapshot = g->regions_tracker_stale;
    size_t snap_sz = (size_t) nregions_snapshot * sizeof(guest_region_t);
    if (nregions_snapshot > 0) {
        regions_snapshot = malloc(snap_sz);
        if (!regions_snapshot) {
            goto fail_snapshot;
        }
        memcpy(regions_snapshot, g->regions, snap_sz);
    }
    dirty_blocks_snapshot = malloc(sizeof(g->dirty_blocks));
    if (!dirty_blocks_snapshot)
        goto fail_snapshot;
    memcpy(dirty_blocks_snapshot, g->dirty_blocks, sizeof(g->dirty_blocks));
    int npreannounced_snapshot = g->npreannounced;
    if (npreannounced_snapshot > 0) {
        memcpy(preannounced_snapshot, g->preannounced,
               (size_t) npreannounced_snapshot * sizeof(guest_region_t));
    }

    if (fork_ipc_send_fd_table(ipc_sock) < 0) {
        log_error("clone: failed to send fd table");
        goto fail_snapshot;
    }

    /* Must follow fork_ipc_send_fd_table because the keepalive payload carries
     * a guest_fd that the child resolves through its just-installed fd_table to
     * recover the child-side master host fd.
     */
    if (fork_ipc_send_pty_keepalives(ipc_sock) < 0) {
        log_error("clone: failed to send pty keepalives");
        goto fail_snapshot;
    }

    uint32_t num_guest_regions = (uint32_t) nregions_snapshot;
    uint32_t num_preannounced = (uint32_t) npreannounced_snapshot;
    if (fork_ipc_send_process_state(
            ipc_sock, regions_snapshot, num_guest_regions,
            regions_tracker_stale_snapshot, dirty_blocks_snapshot,
            preannounced_snapshot, num_preannounced) < 0) {
        log_error("clone: failed to send process state");
        goto fail_snapshot;
    }

    if (chown_overlay_send(ipc_sock) < 0) {
        log_error("clone: failed to send chown overlay");
        goto fail_snapshot;
    }

    if (proc_register_child(child_host_pid, child_guest_pid, child_pgid) < 0) {
        log_error("clone: failed to commit child bookkeeping");
        goto fail_snapshot;
    }
    uint8_t admission_ready = 1;
    if (fork_ipc_write_all(ipc_sock, &admission_ready,
                           sizeof(admission_ready)) < 0) {
        log_error("clone: failed to release admitted child");
        goto fail_snapshot;
    }

    /* The child's inherited slave copies are live from the moment fork returns,
     * so they go on the shared count here rather than in the child's own init,
     * which the parent's close of its copy can beat.
     *
     * Deliberately after the last failure exit: every goto above unwinds a
     * child that will never run, and a credit added before them would never be
     * given back -- the pty would then look permanently busy and its master
     * would stop reporting hangups for good. Still before siblings resume, so
     * no guest code can close a slave in between.
     */
    proc_pty_fork_parent_note_inherited();

    /* The process-state payload includes the SCM_RIGHTS handoff for region
     * backing fds. Keep siblings quiesced until that send completes so a
     * concurrent munmap/remap cannot close or recycle the captured fd numbers.
     */
    if (siblings_quiesced)
        thread_resume_siblings();
    mmap_fork_commit_anon_shared(&anon_shared_txn);

    close(ipc_sock);

    /* After CoW fork, parent stays on MAP_SHARED because no remap was done. The
     * shm fd is kept open so subsequent forks can also use CoW. The child has
     * its own MAP_PRIVATE view of the same file.
     */

    /* CLONE_VFORK suspends the parent until the child exits or execs. The
     * emulator cannot observe guest exec completion across the helper process,
     * so it waits for the helper to exit.
     */
    if (is_vfork) {
        char byte;
        ssize_t nr;
        do {
            nr = read(vfork_notify_fds[0], &byte, 1);
        } while (nr < 0 && errno == EINTR);
        close(vfork_notify_fds[0]);

        if (nr <= 0) {
            int status = 0;
            struct rusage ru;
            if (wait4(child_host_pid, &status, 0, &ru) == child_host_pid)
                proc_children_cpu_add(&ru);
            proc_mark_child_exited(child_host_pid, status);
        } else {
            int status;
            struct rusage ru;
            pid_t waited = wait4(child_host_pid, &status, WNOHANG, &ru);
            if (waited == child_host_pid) {
                proc_children_cpu_add(&ru);
                proc_mark_child_exited(child_host_pid, status);
            }
        }
    }

    log_debug("clone: child pid=%lld (host=%d)", (long long) child_guest_pid,
              child_host_pid);

    free(regions_snapshot);
    free(dirty_blocks_snapshot);
    if (snapshot_shm_fd >= 0)
        close(snapshot_shm_fd);
    return child_guest_pid;

fail_snapshot:
    proc_cancel_child(child_guest_pid);
    free(regions_snapshot);
    free(dirty_blocks_snapshot);
    if (snapshot_shm_fd >= 0)
        close(snapshot_shm_fd);

    /* Roll back the in-place anon-shared overlay conversion while siblings are
     * still parked. A partial rollback failure (e.g., region drift past the
     * quiesce timeout) leaves the parent in a mixed state: the originating
     * fork-IPC error is the user-visible one, but log abort failures so
     * post-mortem can spot the lingering overlay without grepping for
     * behavioral symptoms.
     */
    int abort_rc = mmap_fork_abort_anon_shared(g, &anon_shared_txn);
    if (abort_rc < 0)
        log_warn(
            "clone: anon-shared rollback partial failure (%d); parent "
            "may have stale memfd-backed regions",
            abort_rc);
    if (siblings_quiesced)
        thread_resume_siblings();
    close(ipc_sock);
    if (vfork_notify_fds[0] >= 0)
        close(vfork_notify_fds[0]);
    if (vfork_notify_fds[1] >= 0)
        close(vfork_notify_fds[1]);

    /* posix_spawn at the top of sys_clone always succeeds before any goto
     * fail_snapshot fires, so child_host_pid is a live process here. The IPC
     * socket just closed; the child reads EOF on fork_ipc_read_all and returns
     * nonzero from fork_child_main. Without an explicit waitpid the exited
     * child becomes a zombie: proc_register_child only runs on the success
     * path, so neither proc_reap_finished nor sys_wait4 will ever pick this PID
     * up, and the guest's fork(2) already reported failure. Reap it here to
     * keep host PIDs from accumulating across repeated failures.
     */
    pid_t reaped;
    do {
        reaped = waitpid(child_host_pid, NULL, 0);
    } while (reaped < 0 && errno == EINTR);
    if (reaped < 0)
        log_warn("clone: failed to reap fork-child pid=%d: %s",
                 (int) child_host_pid, strerror(errno));
    return fail_rc;
}

/* clone3: extended clone with clone_args struct. */

/* Linux clone_args layout (kernel v5.3+, extensible). Fields beyond the
 * caller-provided size are treated as zero.
 */
struct linux_clone_args {
    uint64_t flags, pidfd;
    uint64_t child_tid, parent_tid;
    uint64_t exit_signal, stack, stack_size, tls, set_tid, set_tid_size, cgroup;
};

#define CLONE_ARGS_SIZE_VER0 64 /* v5.3: first 8 fields (flags..tls) */

/* Unsupported clone3-only flags: reject early rather than silently ignoring. */
#define LINUX_CLONE_PIDFD 0x00001000
#define LINUX_CLONE_INTO_CGROUP 0x200000000ULL

int64_t sys_clone3(hv_vcpu_t vcpu,
                   guest_t *g,
                   uint64_t cl_args_gva,
                   uint64_t cl_args_size,
                   bool verbose)
{
    /* Validate size: must be at least the v5.3 minimum and not absurdly large
     */
    if (cl_args_size < CLONE_ARGS_SIZE_VER0 || cl_args_size > 4096)
        return -LINUX_EINVAL;

    /* Guard against guest address overflow when reading clone_args */
    if (cl_args_gva > UINT64_MAX - cl_args_size)
        return -LINUX_EFAULT;

    /* Read clone_args from guest memory, zero-extending beyond caller's size */
    struct linux_clone_args ca = {0};
    size_t read_size = cl_args_size < sizeof(ca) ? cl_args_size : sizeof(ca);
    if (guest_read(g, cl_args_gva, &ca, read_size) < 0)
        return -LINUX_EFAULT;

    /* If the caller provided a struct larger than elfuse knows about, verify
     * the unknown tail is all zeros (forward compatibility per kernel rule)
     */
    if (cl_args_size > sizeof(ca)) {
        uint64_t tail_start = cl_args_gva + sizeof(ca);
        uint64_t tail_size = cl_args_size - sizeof(ca);
        for (uint64_t off = 0; off < tail_size; off += 8) {
            uint64_t word = 0;
            size_t chunk = (tail_size - off < 8) ? (tail_size - off) : 8;
            if (guest_read(g, tail_start + off, &word, chunk) < 0)
                return -LINUX_EFAULT;
            if (word != 0)
                return -LINUX_E2BIG;
        }
    }

    /* In clone3, the CSIGNAL low byte of flags must be zero because the exit
     * signal is carried exclusively in the exit_signal field.
     */
    if (ca.flags & 0xff)
        return -LINUX_EINVAL;

    /* Reject unsupported features */
    if (ca.flags & LINUX_CLONE_INTO_CGROUP)
        return -LINUX_EINVAL; /* cgroups not implemented */
    if (ca.flags & LINUX_CLONE3_NS_FLAGS)
        return -LINUX_EINVAL; /* namespaces not implemented */
    if (ca.set_tid_size != 0)
        return -LINUX_EINVAL; /* set_tid not implemented */

    /* Validate exit_signal range (0-64 on Linux). CLONE_THREAD requires
     * exit_signal == 0 (threads do not signal on exit).
     */
    if (ca.exit_signal > 64)
        return -LINUX_EINVAL;
    if ((ca.flags & LINUX_CLONE_THREAD) && ca.exit_signal != 0)
        return -LINUX_EINVAL;

    /* Validate stack: both must be zero (fork-like) or both non-zero (thread).
     * Mismatched pairs cause SP underflow or zero-SP threads.
     */
    if ((ca.stack == 0) != (ca.stack_size == 0))
        return -LINUX_EINVAL;

    /* Merge exit_signal into flags for sys_clone compatibility. clone3 moved
     * exit_signal out of the flags field; sys_clone expects it in the low byte.
     * Safe because validation confirmed ca.flags low byte is zero. Strip
     * CLONE_PIDFD before passing to sys_clone (which does not understand it).
     * Pidfd creation happens after the clone returns.
     */
    bool want_pidfd = (ca.flags & LINUX_CLONE_PIDFD) != 0;
    uint64_t flags =
        (ca.flags & ~(uint64_t) LINUX_CLONE_PIDFD) | ca.exit_signal;

    /* Compute child stack pointer. clone: child_stack is the TOP of the stack
     * (SP value). clone3: stack is the BOTTOM, stack_size is the length. SP =
     * stack + stack_size (grows downward on aarch64).
     */
    uint64_t child_stack = 0;
    if (ca.stack != 0) {
        if (ca.stack_size > UINT64_MAX - ca.stack)
            return -LINUX_EINVAL;
        child_stack = ca.stack + ca.stack_size;
    }

    log_debug(
        "clone3(flags=0x%llx, exit_signal=%llu, "
        "stack=0x%llx+0x%llx, "
        "tls=0x%llx, size=%llu)",
        (unsigned long long) ca.flags, (unsigned long long) ca.exit_signal,
        (unsigned long long) ca.stack, (unsigned long long) ca.stack_size,
        (unsigned long long) ca.tls, (unsigned long long) cl_args_size);

    int64_t ret = sys_clone(vcpu, g, flags, child_stack, ca.stack,
                            ca.stack + ca.stack_size, ca.parent_tid, ca.tls,
                            ca.child_tid, verbose);

    /* If clone succeeded and CLONE_PIDFD was requested, create a pidfd for the
     * child and write the guest FD number to ca.pidfd.
     */
    if (ret > 0 && want_pidfd && ca.pidfd != 0) {
        int pfd = pidfd_create(g, ret);
        if (pfd >= 0) {
            int32_t pfd32 = (int32_t) pfd;
            if (guest_write_small(g, ca.pidfd, &pfd32, sizeof(pfd32)) < 0) {
                /* GVA invalid; close the newly created pidfd. */
                fd_entry_t snap;
                if (fd_snapshot_and_close(pfd, &snap))
                    fd_cleanup_entry(pfd, &snap);
            }
        }
    }

    return ret;
}
