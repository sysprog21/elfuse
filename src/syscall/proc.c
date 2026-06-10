/* Process state and management
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Owns all static process state: guest PID/PPID, shim blob reference, ELF path,
 * command line, and the process table for tracking fork children. Provides
 * accessor functions for modules that need this state (forkipc.c,
 * syscall/exec.c, procemu.c).
 *
 * Also contains wait4, waitid, and the vCPU run loop.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h> /* struct rusage, for wait4 rusage population */
#include <sys/sysctl.h>
#include <libproc.h>

#include "debug/log.h"
#include "hvutil.h"
#include "utils.h"

#include "core/shim-globals.h"
#include "core/vdso.h"

#include "runtime/futex.h"

#include "syscall/internal.h"
#include "syscall/proc-identity.h"
#include "syscall/proc.h"
#include "syscall/proc-pidfd.h"
#include "syscall/proc-state.h"
#include "syscall/signal.h"

#include "debug/crashreport.h"
#include "debug/gdbstub.h"

/* Process state. */

/* W^X toggle counters for JIT debugging */
static _Atomic uint64_t wxcount_to_rx = 0; /* RW->RX (exec fault) */
static _Atomic uint64_t wxcount_to_rw = 0; /* RX->RW (write fault) */
static _Atomic uint64_t sysreg_write_count =
    0; /* EC=0x18 Dir=0 (DC CVAU, IC IVAU, etc.) */
/* x86_64-via-Rosetta is on by default: the architecture is auto-detected from
 * the ELF header (EM_X86_64), and rosetta is the only viable path for those
 * binaries on Apple Silicon. The --no-rosetta CLI flag (or ELFUSE_NO_ROSETTA=1)
 * disables it; without rosetta installed, the rosetta loader fails its access()
 * check and surfaces an install hint regardless.
 */
static _Atomic bool rosetta_enabled = true;
/* Runtime indicator: distinct from rosetta_enabled (user opt-in). Set when the
 * active guest_t is actually running under rosetta, so callers without direct
 * guest_t access (proc_intercept_readlink, log paths) can branch on runtime
 * state without threading g through every signature.
 */
static _Atomic bool rosetta_active = false;

/* Process table for tracking fork children */
static proc_entry_t proc_table[PROC_TABLE_SIZE];
static int64_t next_guest_pid = 2;
static pthread_mutex_t pid_lock = PTHREAD_MUTEX_INITIALIZER; /* Lock order: 6 */
static pthread_cond_t pid_cond =
    PTHREAD_COND_INITIALIZER; /* Signaled on child exit */

/* Global flag for exit_group: signals all threads to terminate. Atomic to avoid
 * undefined behavior under C11 memory model when multiple threads read/write
 * concurrently.
 */
static _Atomic int exit_group_requested = 0;

/* Exit code set by the thread that calls exit_group */
static _Atomic int exit_group_code = 0;

/* Public API. */

void proc_init(void)
{
    proc_identity_init();
    next_guest_pid = 2;
    memset(proc_table, 0, sizeof(proc_table));
    proc_state_init();
    thread_init();
    futex_init();
}

void proc_set_rosetta_enabled(bool enabled)
{
    atomic_store(&rosetta_enabled, enabled);
}

bool proc_rosetta_enabled(void)
{
    return atomic_load(&rosetta_enabled);
}

void proc_set_rosetta_active(bool active)
{
    atomic_store(&rosetta_active, active);
}

bool proc_rosetta_active(void)
{
    return atomic_load(&rosetta_active);
}

void proc_request_exit_group(int code)
{
    atomic_store(&exit_group_code, code);
    atomic_store(&exit_group_requested, 1);
}

void proc_clear_exit_group(void)
{
    atomic_store(&exit_group_requested, 0);
    atomic_store(&exit_group_code, 0);
}

int proc_exit_group_requested(void)
{
    return atomic_load(&exit_group_requested);
}

static int proc_exit_group_code(void)
{
    return atomic_load(&exit_group_code);
}

static void proc_init_child_entry(proc_entry_t *entry,
                                  pid_t host_pid,
                                  int64_t guest_pid_val)
{
    entry->active = true;
    entry->host_pid = host_pid;
    entry->guest_pid = guest_pid_val;
    entry->exited = false;
    entry->exit_status = 0;
}

static proc_entry_t *proc_find_free_entry(void)
{
    for (int i = 0; i < PROC_TABLE_SIZE; i++) {
        if (!proc_table[i].active)
            return &proc_table[i];
    }
    return NULL;
}

static proc_entry_t *proc_find_host_entry(pid_t host_pid)
{
    for (int i = 0; i < PROC_TABLE_SIZE; i++) {
        if (proc_table[i].active && proc_table[i].host_pid == host_pid)
            return &proc_table[i];
    }
    return NULL;
}

static proc_entry_t *proc_find_guest_entry(int64_t guest_pid_val)
{
    for (int i = 0; i < PROC_TABLE_SIZE; i++) {
        if (proc_table[i].active && proc_table[i].guest_pid == guest_pid_val)
            return &proc_table[i];
    }
    return NULL;
}

static int proc_write_full(int host_fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t n = write(host_fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        p += (size_t) n;
        remaining -= (size_t) n;
    }
    return 0;
}

int rseq_try_abort(guest_t *g,
                   uint64_t rseq_gva,
                   uint32_t rseq_signature,
                   uint64_t *pc)
{
    if (rseq_gva == 0)
        return 0;

    uint64_t rseq_cs_ptr = 0;
    if (guest_read_small(g, rseq_gva + 8, &rseq_cs_ptr, sizeof(rseq_cs_ptr)) !=
            0 ||
        rseq_cs_ptr == 0)
        return 0;

    int result = 0;
    uint8_t cs_buf[32];
    if (guest_read_small(g, rseq_cs_ptr, cs_buf, sizeof(cs_buf)) == 0) {
        uint64_t start_ip, post_commit_offset, abort_ip;
        memcpy(&start_ip, cs_buf + 8, 8);
        memcpy(&post_commit_offset, cs_buf + 16, 8);
        memcpy(&abort_ip, cs_buf + 24, 8);
        if (*pc >= start_ip && *pc < start_ip + post_commit_offset) {
            uint32_t abort_sig = 0;
            if (abort_ip >= 4)
                guest_read_small(g, abort_ip - 4, &abort_sig,
                                 sizeof(abort_sig));
            if (abort_sig == rseq_signature) {
                *pc = abort_ip;
                result = 1;
            } else {
                result = -1; /* Signature mismatch: SIGSEGV */
            }
        }
    }

    /* Always clear rseq_cs (Linux clears on signal/preemption) */
    uint64_t zero = 0;
    guest_write_small(g, rseq_gva + 8, &zero, sizeof(zero));
    return result;
}

int64_t proc_alloc_pid(void)
{
    pthread_mutex_lock(&pid_lock);
    int64_t pid = next_guest_pid++;
    pthread_mutex_unlock(&pid_lock);
    return pid;
}

/* Try to reap exited children from the process table. Calls waitpid with
 * WNOHANG on each active entry; entries whose host process has exited are
 * freed.
 *
 * Returns the number of slots reclaimed.
 */
static int proc_reap_finished(void)
{
    int reaped = 0;
    for (int i = 0; i < PROC_TABLE_SIZE; i++) {
        if (!proc_table[i].active)
            continue;
        if (proc_table[i].exited) {
            /* Already marked exited but never waited; free the slot */
            proc_table[i].active = false;
            reaped++;
            continue;
        }
        int status;
        pid_t ret = waitpid(proc_table[i].host_pid, &status, WNOHANG);
        if (ret > 0) {
            /* Child exited; free the slot */
            proc_table[i].active = false;
            reaped++;
        }
    }
    return reaped;
}

int proc_register_child(pid_t host_pid, int64_t guest_pid_val)
{
    pthread_mutex_lock(&pid_lock);
    proc_entry_t *entry = proc_find_free_entry();
    if (entry) {
        proc_init_child_entry(entry, host_pid, guest_pid_val);
        pthread_mutex_unlock(&pid_lock);
        return 0;
    }

    /* Table full. Try reaping exited children, then retry. */
    if (proc_reap_finished() > 0)
        entry = proc_find_free_entry();
    if (entry) {
        proc_init_child_entry(entry, host_pid, guest_pid_val);
        pthread_mutex_unlock(&pid_lock);
        return 0;
    }
    pthread_mutex_unlock(&pid_lock);

    log_error("process table full (%d slots), child PID %lld dropped",
              PROC_TABLE_SIZE, (long long) guest_pid_val);
    return -1;
}

void proc_mark_child_exited(pid_t host_pid, int status)
{
    pthread_mutex_lock(&pid_lock);
    proc_entry_t *entry = proc_find_host_entry(host_pid);
    if (entry) {
        entry->exited = true;
        entry->exit_status = status;
        int64_t gpid = entry->guest_pid;
        pthread_cond_broadcast(&pid_cond);
        pthread_mutex_unlock(&pid_lock);
        proc_pidfd_notify_exit(gpid);
        signal_queue(LINUX_SIGCHLD);
        return;
    }
    pthread_mutex_unlock(&pid_lock);
}

pid_t proc_guest_to_host_pid(int64_t gpid)
{
    pid_t result = -1;
    pthread_mutex_lock(&pid_lock);
    proc_entry_t *entry = proc_find_guest_entry(gpid);
    if (entry)
        result = entry->host_pid;
    pthread_mutex_unlock(&pid_lock);
    return result;
}

int proc_send_guest_signal(pid_t host_pid, int signum)
{
    char path[64];
    int path_len =
        snprintf(path, sizeof(path), "/tmp/elfuse-sig-%ld", (long) host_pid);
    if (path_len < 0 || (size_t) path_len >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = open(path, O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;

    char line[16];
    int len = snprintf(line, sizeof(line), "%d\n", signum);
    if (len < 0 || (size_t) len >= sizeof(line)) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    if (proc_write_full(fd, line, (size_t) len) < 0) {
        close(fd);
        return -1;
    }
    if (close(fd) < 0)
        return -1;

    return kill(host_pid, SIGUSR2);
}

int proc_get_child_pids(pid_t *out, int max_pids)
{
    /* Seed with direct children from the process table */
    int count = 0;
    pthread_mutex_lock(&pid_lock);
    for (int i = 0; i < PROC_TABLE_SIZE && count < max_pids; i++) {
        if (proc_table[i].active && !proc_table[i].exited)
            out[count++] = proc_table[i].host_pid;
    }
    pthread_mutex_unlock(&pid_lock);

    /* Recursively collect descendants via proc_listchildpids. Orphaned
     * grandchildren (PPID=1) are not found this way, so also check all host
     * processes with the current elfuse binary name. This is O(n_procs) but
     * /proc/net reads are infrequent.
     */
    pid_t all_pids[4096];
    int n = proc_listpids(PROC_ALL_PIDS, 0, all_pids, sizeof(all_pids));
    if (n <= 0)
        return count;
    int npids = n / (int) sizeof(pid_t);

    /* Get the current binary path for comparison */
    char our_path[PROC_PIDPATHINFO_MAXSIZE];
    int our_len = proc_pidpath(getpid(), our_path, sizeof(our_path));
    if (our_len <= 0)
        return count;

    for (int i = 0; i < npids && count < max_pids; i++) {
        pid_t p = all_pids[i];
        if (p <= 0 || p == getpid())
            continue;
        /* Skip PIDs the output array already has */
        bool dup = false;
        for (int j = 0; j < count; j++)
            if (out[j] == p) {
                dup = true;
                break;
            }
        if (dup)
            continue;
        /* Check if this process is running the same elfuse binary */
        char ppath[PROC_PIDPATHINFO_MAXSIZE];
        int plen = proc_pidpath(p, ppath, sizeof(ppath));
        if (plen > 0 && plen == our_len && !memcmp(ppath, our_path, plen))
            out[count++] = p;
    }
    return count;
}

/* sys_ptrace. */

int64_t sys_ptrace(guest_t *g,
                   uint64_t request,
                   int64_t pid,
                   uint64_t addr,
                   uint64_t data)
{
    switch (request) {
    case LINUX_PTRACE_SEIZE: {
        /* Attach to target thread without stopping it. The tracee can later be
         * stopped via PTRACE_INTERRUPT or BRK-induced ptrace-stop. Unlike
         * PTRACE_ATTACH, SEIZE does not send SIGSTOP.
         */
        thread_entry_t *target = thread_find(pid);
        if (!target)
            return -LINUX_ESRCH;
        if (target->ptraced)
            return -LINUX_EPERM;

        target->ptraced = true;
        target->tracer_tid = current_thread->guest_tid;
        return 0;
    }

    case LINUX_PTRACE_CONT: {
        /* Resume a stopped tracee, optionally injecting a signal. data = signal
         * to inject (0 = none).
         */
        thread_entry_t *target = thread_find(pid);
        if (!target || !target->ptraced)
            return -LINUX_ESRCH;
        if (!target->ptrace_stopped)
            return -LINUX_ESRCH;

        thread_ptrace_cont(target, (int) data);
        return 0;
    }

    case LINUX_PTRACE_INTERRUPT: {
        /* Force a running tracee into ptrace-stop. Uses hv_vcpus_exit to break
         * the tracee out of hv_vcpu_run; the tracee will then enter ptrace-stop
         * in its HV_EXIT_REASON_CANCELED handler.
         */
        thread_entry_t *target = thread_find(pid);
        if (!target || !target->ptraced)
            return -LINUX_ESRCH;
        if (target->ptrace_stopped)
            return 0; /* Already stopped */

        hv_vcpus_exit(&target->vcpu, 1);
        return 0;
    }

    case LINUX_PTRACE_GETREGSET: {
        /* Read tracee registers via iovec. addr = NT_PRSTATUS (1), data = guest
         * pointer to linux iovec_t {base, len}.
         */
        if (addr != LINUX_NT_PRSTATUS)
            return -LINUX_EINVAL;

        thread_entry_t *target = thread_find(pid);
        if (!target || !target->ptraced || !target->ptrace_stopped)
            return -LINUX_ESRCH;

        /* Read guest iovec */
        linux_iovec_t iov;
        if (guest_read_small(g, data, &iov, sizeof(iov)) < 0)
            return -LINUX_EFAULT;

        /* Copy register data (truncate if iovec is smaller) */
        size_t copy_len = sizeof(linux_user_pt_regs_t);
        if (iov.iov_len < copy_len)
            copy_len = iov.iov_len;

        if (guest_write(g, iov.iov_base, &target->ptrace_regs, copy_len) < 0)
            return -LINUX_EFAULT;

        /* Write back actual bytes transferred */
        iov.iov_len = copy_len;
        if (guest_write_small(g, data, &iov, sizeof(iov)) < 0)
            return -LINUX_EFAULT;

        return 0;
    }

    case LINUX_PTRACE_SETREGSET: {
        /* Write tracee registers via iovec. addr = NT_PRSTATUS (1), data =
         * guest pointer to linux iovec_t {base, len}.
         */
        if (addr != LINUX_NT_PRSTATUS)
            return -LINUX_EINVAL;

        thread_entry_t *target = thread_find(pid);
        if (!target || !target->ptraced || !target->ptrace_stopped)
            return -LINUX_ESRCH;

        /* Read guest iovec */
        linux_iovec_t iov;
        if (guest_read_small(g, data, &iov, sizeof(iov)) < 0)
            return -LINUX_EFAULT;

        /* Copy register data from guest */
        size_t copy_len = sizeof(linux_user_pt_regs_t);
        if (iov.iov_len < copy_len)
            copy_len = iov.iov_len;

        if (guest_read(g, iov.iov_base, &target->ptrace_regs, copy_len) < 0)
            return -LINUX_EFAULT;

        target->ptrace_regs_dirty = true;

        /* Write back actual bytes transferred */
        iov.iov_len = copy_len;
        if (guest_write_small(g, data, &iov, sizeof(iov)) < 0)
            return -LINUX_EFAULT;

        return 0;
    }

    default:
        return -LINUX_EINVAL;
    }
}

/* Write a macOS struct rusage to guest memory as linux_rusage_t. Field layout
 * matches on LP64, but ru_maxrss must be converted from macOS bytes to Linux
 * kilobytes.
 */
_Static_assert(sizeof(struct rusage) == sizeof(linux_rusage_t),
               "host and guest rusage layouts must match on LP64");

static int write_rusage_to_guest(guest_t *g,
                                 uint64_t gva,
                                 const struct rusage *ru)
{
    linux_rusage_t lru;
    memcpy(&lru, ru, sizeof(lru));
    lru.ru_maxrss = ru->ru_maxrss / 1024; /* macOS: bytes -> Linux: KB */
    return guest_write_small(g, gva, &lru, sizeof(lru));
}

/* sys_wait4. */

int64_t sys_wait4(guest_t *g,
                  int pid,
                  uint64_t status_gva,
                  int options,
                  uint64_t rusage_gva)
{
    /* First check for ptraced or vm-clone children in the thread table.
     * thread_ptrace_wait handles both ptrace-stopped and vm-exited states.
     */
    if (current_thread) {
        int ptrace_status = 0;
        int64_t ptrace_tid = thread_ptrace_wait(current_thread->guest_tid, pid,
                                                &ptrace_status, options);
        if (ptrace_tid > 0) {
            if (status_gva) {
                int32_t ls = ptrace_status;
                if (guest_write_small(g, status_gva, &ls, sizeof(ls)) < 0)
                    return -LINUX_EFAULT;
            }
            return ptrace_tid;
        }
        /* ptrace_tid == 0: no matching children or WNOHANG; fall through to the
         * process table for regular fork children.
         */
    }

    /* Translate Linux wait options */
    int mac_options = 0;
    if (options & 1)
        mac_options |= WNOHANG; /* WNOHANG = 1 on both */
    if (options & 2)
        mac_options |= WUNTRACED; /* WUNTRACED = 2 on both */
    if (options & 8)
        mac_options |= WCONTINUED; /* WCONTINUED: Linux=8, macOS=0x10 */

    pthread_mutex_lock(&pid_lock);

    if (pid == -1) {
        /* Wait for any child. Always poll with WNOHANG first so wait4 does not
         * block on one specific child while another exits. If blocking (no
         * WNOHANG) and no child is ready, sleep briefly and retry; this gives
         * correct "wait for any" semantics.
         */
        for (;;) {
            bool found_any_child = false;
            for (int i = 0; i < PROC_TABLE_SIZE; i++) {
                if (!proc_table[i].active)
                    continue;
                found_any_child = true;
                if (proc_table[i].exited) {
                    /* Already reaped (from CLONE_VFORK wait) */
                    int64_t gpid = proc_table[i].guest_pid;
                    int32_t linux_status = proc_table[i].exit_status;
                    proc_table[i].active = false;
                    pthread_mutex_unlock(&pid_lock);
                    if (status_gva &&
                        guest_write_small(g, status_gva, &linux_status,
                                          sizeof(linux_status)) < 0)
                        return -LINUX_EFAULT;
                    /* Pre-exited entries have no rusage; zero-fill. */
                    if (rusage_gva)
                        write_rusage_to_guest(g, rusage_gva,
                                              &(struct rusage) {0});
                    return gpid;
                }

                pid_t host_pid = proc_table[i].host_pid;
                int64_t gpid = proc_table[i].guest_pid;
                int slot = i;
                pthread_mutex_unlock(&pid_lock);

                int status;
                struct rusage ru;
                pid_t ret = wait4(host_pid, &status, mac_options | WNOHANG,
                                  rusage_gva ? &ru : NULL);
                if (ret > 0) {
                    if (status_gva) {
                        int32_t linux_status = status;
                        if (guest_write_small(g, status_gva, &linux_status,
                                              sizeof(linux_status)) < 0) {
                            /* Child already reaped. Match Linux: return EFAULT
                             */
                            pthread_mutex_lock(&pid_lock);
                            if (proc_table[slot].active &&
                                proc_table[slot].host_pid == host_pid)
                                proc_table[slot].active = false;
                            pthread_mutex_unlock(&pid_lock);
                            return -LINUX_EFAULT;
                        }
                    }
                    if (rusage_gva &&
                        write_rusage_to_guest(g, rusage_gva, &ru) < 0) {
                        pthread_mutex_lock(&pid_lock);
                        if (proc_table[slot].active &&
                            proc_table[slot].host_pid == host_pid)
                            proc_table[slot].active = false;
                        pthread_mutex_unlock(&pid_lock);
                        return -LINUX_EFAULT;
                    }
                    pthread_mutex_lock(&pid_lock);
                    if (proc_table[slot].active &&
                        proc_table[slot].host_pid == host_pid)
                        proc_table[slot].active = false;
                    pthread_mutex_unlock(&pid_lock);
                    return gpid;
                }
                /* ret == 0 (not exited) or ret < 0 (error): try next */
                pthread_mutex_lock(&pid_lock);
            }

            if (!found_any_child) {
                pthread_mutex_unlock(&pid_lock);
                return -LINUX_ECHILD;
            }
            if (mac_options & WNOHANG) {
                pthread_mutex_unlock(&pid_lock);
                return 0;
            }

            /* Blocking mode: no child exited yet. Wait on condvar for a child
             * exit notification (signaled by proc_mark_child_exited). Use
             * timedwait with 100ms timeout as a safety net; the condvar handles
             * normal exits, the timeout catches edge cases where the host wait4
             * detects exit before proc_mark_child_exited.
             */
            struct timespec ts;
            timespec_deadline_in_ms(&ts, 100);
            pthread_cond_timedwait(&pid_cond, &pid_lock, &ts);
        }
    }

    /* Wait for specific guest PID */
    for (int i = 0; i < PROC_TABLE_SIZE; i++) {
        if (proc_table[i].active && proc_table[i].guest_pid == pid) {
            if (proc_table[i].exited) {
                int64_t gpid = proc_table[i].guest_pid;
                int32_t linux_status = proc_table[i].exit_status;
                proc_table[i].active = false;
                pthread_mutex_unlock(&pid_lock);
                if (status_gva &&
                    guest_write_small(g, status_gva, &linux_status,
                                      sizeof(linux_status)) < 0)
                    return -LINUX_EFAULT;
                /* Pre-exited entries have no rusage; zero-fill. */
                if (rusage_gva)
                    write_rusage_to_guest(g, rusage_gva, &(struct rusage) {0});
                return gpid;
            }

            pid_t host_pid = proc_table[i].host_pid;
            int64_t gpid = proc_table[i].guest_pid;
            int slot = i;
            pthread_mutex_unlock(&pid_lock);

            int status;
            struct rusage ru;
            pid_t ret =
                wait4(host_pid, &status, mac_options, rusage_gva ? &ru : NULL);
            if (ret > 0) {
                if (status_gva) {
                    int32_t linux_status = status;
                    if (guest_write_small(g, status_gva, &linux_status,
                                          sizeof(linux_status)) < 0) {
                        pthread_mutex_lock(&pid_lock);
                        if (proc_table[slot].active &&
                            proc_table[slot].host_pid == host_pid)
                            proc_table[slot].active = false;
                        pthread_mutex_unlock(&pid_lock);
                        return -LINUX_EFAULT;
                    }
                }
                if (rusage_gva &&
                    write_rusage_to_guest(g, rusage_gva, &ru) < 0) {
                    pthread_mutex_lock(&pid_lock);
                    if (proc_table[slot].active &&
                        proc_table[slot].host_pid == host_pid)
                        proc_table[slot].active = false;
                    pthread_mutex_unlock(&pid_lock);
                    return -LINUX_EFAULT;
                }
                pthread_mutex_lock(&pid_lock);
                /* Re-validate slot: another thread may have reaped it */
                if (proc_table[slot].active &&
                    proc_table[slot].host_pid == host_pid)
                    proc_table[slot].active = false;
                pthread_mutex_unlock(&pid_lock);
                /* Queue SIGCHLD for parent process */
                signal_queue(LINUX_SIGCHLD);
                return gpid;
            } else if (ret == 0) {
                return 0; /* WNOHANG */
            }
            return linux_errno();
        }
    }
    pthread_mutex_unlock(&pid_lock);

    return -LINUX_ECHILD;
}

/* sys_waitid. */

/* Linux siginfo_t field offsets on aarch64 (LP64). si_errno (offset 4) is
 * always zero in waitid output and is not written here.
 */
#define SIGINFO_SIZE 128
#define SIGINFO_OFF_SIGNO 0   /* int32_t si_signo */
#define SIGINFO_OFF_CODE 8    /* int32_t si_code */
#define SIGINFO_OFF_PID 16    /* pid_t (int32_t) */
#define SIGINFO_OFF_UID 20    /* uid_t (uint32_t) */
#define SIGINFO_OFF_STATUS 24 /* int32_t si_status */

/* si_code values for SIGCHLD */
#define CLD_EXITED 1
#define CLD_KILLED 2
#define CLD_DUMPED 3

/* waitid idtype values */
#define P_ALL 0
#define P_PID 1
#define P_PGID 2

int64_t sys_waitid(guest_t *g,
                   int idtype,
                   int64_t id,
                   uint64_t infop_gva,
                   int options)
{
    /* Translate options: Linux WEXITED=4, WNOHANG=1, WSTOPPED=2, WCONTINUED=8,
     * WNOWAIT=0x01000000
     */
#define LINUX_WNOWAIT 0x01000000
    int mac_options = 0;
    if (options & 1)
        mac_options |= WNOHANG;
    if (options & 2)
        mac_options |= WUNTRACED;
    if (options & 8)
        mac_options |= WCONTINUED;
    /* WEXITED (4) is implied by waitpid */

    /* Convert idtype+id to a waitpid-compatible pid argument */
    pid_t wait_pid;
    switch (idtype) {
    case P_ALL:
        wait_pid = -1;
        break;
    case P_PID:
        wait_pid = (pid_t) id;
        break;
    case P_PGID:
        wait_pid = -(pid_t) id;
        break;
    case 3: { /* P_PIDFD */
        int64_t resolved = proc_pidfd_lookup_pid((int) id);
        if (resolved < 0)
            return -LINUX_EBADF;
        wait_pid = (pid_t) resolved;
        break;
    }
    default:
        return -LINUX_EINVAL;
    }

    /* Search process table for matching entry. P_ALL must scan all children
     * (not block on the first non-exited one), so the wait loop always use
     * WNOHANG in the inner loop and retry with timedwait if the caller
     * requested blocking.
     */
    pthread_mutex_lock(&pid_lock);
    for (;;) {
        bool found_any = false;

        for (int i = 0; i < PROC_TABLE_SIZE; i++) {
            if (!proc_table[i].active)
                continue;

            /* Match: P_ALL matches any, P_PID/P_PIDFD match guest_pid */
            if ((idtype == P_PID || idtype == 3 /* P_PIDFD */) &&
                proc_table[i].guest_pid != wait_pid)
                continue;

            found_any = true;
            int status;
            pid_t ret;
            int32_t gpid32 = (int32_t) proc_table[i].guest_pid;

            if (proc_table[i].exited) {
                /* Already reaped (from CLONE_VFORK wait) */
                status = proc_table[i].exit_status;
                ret = proc_table[i].host_pid;
            } else {
                pid_t host_pid = proc_table[i].host_pid;
                pthread_mutex_unlock(&pid_lock);
                ret = waitpid(host_pid, &status, WNOHANG);
                if (ret == 0) {
                    /* This child hasn't exited yet; continue checking others
                     * (P_ALL must scan all children).
                     */
                    pthread_mutex_lock(&pid_lock);
                    continue;
                }
                if (ret < 0) {
                    pthread_mutex_lock(&pid_lock);
                    continue; /* Child may have been reaped concurrently */
                }
                pthread_mutex_lock(&pid_lock);
            }

            /* Fill siginfo_t in guest memory */
            if (infop_gva) {
                uint8_t si[SIGINFO_SIZE];
                memset(si, 0, sizeof(si));

                int32_t signo = LINUX_SIGCHLD;
                int32_t si_code, si_status;

                if (WIFEXITED(status)) {
                    si_code = CLD_EXITED;
                    si_status = WEXITSTATUS(status);
                } else if (WIFSIGNALED(status)) {
                    si_code = WCOREDUMP(status) ? CLD_DUMPED : CLD_KILLED;
                    si_status = WTERMSIG(status);
                } else {
                    si_code = CLD_EXITED;
                    si_status = 0;
                }

                memcpy(si + SIGINFO_OFF_SIGNO, &signo, 4);
                memcpy(si + SIGINFO_OFF_CODE, &si_code, 4);
                memcpy(si + SIGINFO_OFF_PID, &gpid32, 4);
                uint32_t uid = 0;
                memcpy(si + SIGINFO_OFF_UID, &uid, 4);
                memcpy(si + SIGINFO_OFF_STATUS, &si_status, 4);

                if (guest_write_small(g, infop_gva, si, SIGINFO_SIZE) < 0) {
                    pthread_mutex_unlock(&pid_lock);
                    return -LINUX_EFAULT;
                }
            }

            /* Keep the table entry when WNOWAIT is set. Re-validate slot after
             * re-locking (another thread may have reused it while the wait loop
             * released the lock for waitpid).
             */
            if (!(options & LINUX_WNOWAIT) && proc_table[i].active &&
                proc_table[i].host_pid == ret)
                proc_table[i].active = false;

            pthread_mutex_unlock(&pid_lock);
            return 0; /* waitid returns 0 on success */
        }

        if (!found_any) {
            pthread_mutex_unlock(&pid_lock);
            return -LINUX_ECHILD;
        }

        if (mac_options & WNOHANG) {
            pthread_mutex_unlock(&pid_lock);
            /* Per POSIX/Linux: zero siginfo when WNOHANG returns with no
             * waitable children, so callers can distinguish via si_pid.
             */
            if (infop_gva) {
                uint8_t zeros[SIGINFO_SIZE] = {0};
                guest_write_small(g, infop_gva, zeros, SIGINFO_SIZE);
            }
            return 0;
        }

        /* Blocking: wait on condvar (100ms timeout as safety net) */
        struct timespec ts;
        timespec_deadline_in_ms(&ts, 100);
        pthread_cond_timedwait(&pid_cond, &pid_lock, &ts);
    }
}

/* vCPU run loop. */

static _Thread_local bool hvc6_yield_requested;

void proc_request_hvc6_yield(void)
{
    hvc6_yield_requested = true;
}

/* Global vCPU handle for the SIGALRM handler (unavoidable global state --
 * signal handlers cannot receive context parameters).
 */
/* Written once by vcpu_run_loop before signal(SIGALRM), then only read by
 * alarm_handler / guest_signal_transport_handler. The write happens-before the
 * signal() call that installs the handlers, so no volatile needed.
 */
static hv_vcpu_t g_timeout_vcpu;
static volatile sig_atomic_t g_timed_out, g_external_guest_signal;

static void alarm_handler(int sig)
{
    (void) sig;
    g_timed_out = 1;
    hv_vcpus_exit(&g_timeout_vcpu, 1);
}

static void guest_signal_transport_handler(int sig, siginfo_t *info, void *ctx)
{
    (void) sig;
    (void) info;
    (void) ctx;
    g_external_guest_signal = 1;
    hv_vcpus_exit(&g_timeout_vcpu, 1);
}

static void install_guest_signal_transport(void)
{
    static int installed;
    if (installed)
        return;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = guest_signal_transport_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR2, &sa, NULL);
    installed = 1;
}

static void drain_external_guest_signal(void)
{
    if (!g_external_guest_signal)
        return;
    g_external_guest_signal = 0;

    char path[64];
    snprintf(path, sizeof(path), "/tmp/elfuse-sig-%ld", (long) getpid());
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return;

    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    unlink(path);
    if (n <= 0)
        return;
    buf[n] = '\0';

    char *p = buf;
    while (*p) {
        char *end;
        long signum = strtol(p, &end, 10);
        if (end == p)
            break;
        if (RANGE_CHECK(signum, 1, LINUX_NSIG))
            signal_queue((int) signum);
        p = end;
        while (*p == '\n' || *p == ' ')
            p++;
    }
}

/* HVC #4 (set sysreg) register index -> hv_sys_reg_t mapping. Index must match
 * the encoding the shim writes to X0 in shim.S; out-of-range IDs trip the HVC
 * #4 default branch in vcpu_run_loop().
 */
static const hv_sys_reg_t hvc4_sysregs[] = {
    HV_SYS_REG_VBAR_EL1,  /* 0 */
    HV_SYS_REG_MAIR_EL1,  /* 1 */
    HV_SYS_REG_TCR_EL1,   /* 2 */
    HV_SYS_REG_TTBR0_EL1, /* 3 */
    HV_SYS_REG_SCTLR_EL1, /* 4 */
    HV_SYS_REG_CPACR_EL1, /* 5 */
    HV_SYS_REG_ELR_EL1,   /* 6 */
    HV_SYS_REG_SPSR_EL1,  /* 7 */
    HV_SYS_REG_TTBR1_EL1, /* 8 */
};

/* Unified vCPU execution loop for both main and worker threads.
 *
 * When timeout_sec > 0 (main thread): uses alarm() for per-iteration safety
 * timeout, logs with "elfuse:" prefix.
 *
 * When timeout_sec == 0 (worker thread): skips alarm() setup (SIGALRM is
 * process-wide and would conflict). Workers are terminated by exit_group
 * setting proc_exit_group_requested and calling hv_vcpus_exit() to cancel
 * pending hv_vcpu_run calls. Logs with "elfuse: worker" prefix.
 *
 * Both modes check proc_exit_group_requested so the main thread also reacts to
 * exit_group called by a worker.
 */
int vcpu_run_loop(hv_vcpu_t vcpu,
                  hv_vcpu_exit_t *vexit,
                  guest_t *g,
                  bool verbose,
                  int timeout_sec)
{
    int exit_code = 0;
    bool running = true;
    int iter = 0;
    const int is_main = (timeout_sec > 0);
    const char *prefix = is_main ? "elfuse" : "elfuse: worker";

    /* Pin vCPU thread to a performance core via QoS class. On Apple Silicon,
     * USER_INTERACTIVE maps to P-cores, avoiding E-core migration that causes
     * measurable jank in HVF workloads.
     */
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    install_guest_signal_transport();

    /* Main thread: set up alarm-based per-iteration timeout. Guest ITIMER_REAL
     * is emulated internally by signal_check_timer() rather than using host
     * setitimer, because macOS shares alarm() and setitimer(ITIMER_REAL) as the
     * same underlying timer.
     */
    if (is_main) {
        g_timeout_vcpu = vcpu;
        g_timed_out = 0;
        signal(SIGALRM, alarm_handler);
    }

    while (running) {
        /* Check if another thread called exit_group */
        if (proc_exit_group_requested()) {
            exit_code = proc_exit_group_code();
            break;
        }

        if (verbose) {
            uint64_t pc;
            hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc);
            log_debug("%s: [%d] vcpu_run PC=0x%llx", prefix, iter,
                      (unsigned long long) pc);
        }
        iter++;

        /* Main: arm per-iteration safety timeout */
        if (is_main)
            alarm((unsigned) timeout_sec);

        HV_CHECK_CTX(hv_vcpu_run(vcpu), vcpu, g);

        drain_external_guest_signal();

        /* Main: disarm timeout */
        if (is_main)
            alarm(0);

        /* Re-check exit_group after waking from hv_vcpu_run */
        if (proc_exit_group_requested()) {
            exit_code = proc_exit_group_code();
            break;
        }

        /* Main: check for alarm timeout */
        if (is_main && g_timed_out) {
            log_error("%s: vCPU execution timed out after %ds", prefix,
                      timeout_sec);

            uint64_t pc, cpsr;
            hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc);
            hv_vcpu_get_reg(vcpu, HV_REG_CPSR, &cpsr);
            log_error("%s: timeout state: PC=0x%llx CPSR=0x%llx", prefix,
                      (unsigned long long) pc, (unsigned long long) cpsr);

            uint64_t esr, far_reg, elr, sctlr_val;
            hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &esr);
            hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, &far_reg);
            hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &elr);
            hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, &sctlr_val);
            log_error(
                "%s: ESR_EL1=0x%llx FAR_EL1=0x%llx "
                "ELR_EL1=0x%llx SCTLR_EL1=0x%llx",
                prefix, (unsigned long long) esr, (unsigned long long) far_reg,
                (unsigned long long) elr, (unsigned long long) sctlr_val);

            crash_report(vcpu, g, CRASH_TIMEOUT, NULL);
            exit_code = 124;
            break;
        }

        if (vexit->reason == HV_EXIT_REASON_EXCEPTION) {
            uint32_t ec = (vexit->exception.syndrome >> 26) & 0x3F;

            if (ec == 0x16) {
                /* HVC exit */
                uint16_t imm = vexit->exception.syndrome & 0xFFFF;

                if (verbose)
                    log_debug("%s: HVC #%u", prefix, imm);

                switch (imm) {
                case 5: {
                    /* HVC #5: Linux syscall forwarding */
                    int ret = syscall_dispatch(vcpu, g, &exit_code, verbose);
                    if (ret == 1)
                        running = false;
                    /* execve replaced the process image; sys_execve already
                     * installed the new X0/syscall-return state.
                     */

                    /* Check guest ITIMER_REAL expiry (queues SIGALRM if due) */
                    signal_check_timer();

                    /* Recompute the shim-globals attention flag now that
                     * signal_check_timer has had a chance to drain pending
                     * work. If nothing is pending and no itimer is armed, drop
                     * the flag back to zero so the identity fast path
                     * re-engages for the next getpid loop. Without this clear,
                     * the attention flag set by signal_queue (e.g., on a
                     * subprocess's SIGCHLD) would stick forever and permanently
                     * disable the fast path.
                     */
                    shim_globals_recompute_attention(g);

                    /* Diagnostic: log signal state after exec/sigreturn to help
                     * debug signal delivery issues.
                     */
                    if (ret == SYSCALL_EXEC_HAPPENED && verbose) {
                        const signal_state_t *ss = signal_get_state();
                        uint64_t tblocked =
                            current_thread ? current_thread->blocked : 0xDEAD;
                        log_debug(
                            "%s: post-sigreturn state: "
                            "pending=0x%llx global_blocked=0x%llx "
                            "thread_blocked=0x%llx signal_pending=%d",
                            prefix, (unsigned long long) ss->pending,
                            (unsigned long long) ss->blocked,
                            (unsigned long long) tblocked, signal_pending());
                    }

                    /* Deliver pending signals after each syscall */
                    if (running && signal_pending()) {
                        int sig_ret = signal_deliver(vcpu, g, &exit_code);
                        if (sig_ret < 0)
                            running = false; /* Default TERM/CORE disposition */
                    }

                    /* After exec, verify critical registers before resuming
                     * vCPU. This closes any gap where signal delivery or other
                     * code between sys_execve's sync flush and hv_vcpu_run
                     * could have modified ELR_EL1.
                     */
                    if (running && ret == SYSCALL_EXEC_HAPPENED) {
                        uint64_t verify_elr;
                        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1,
                                            &verify_elr);
                        if (verify_elr == 0) {
                            log_fatal(
                                "%s: ELR_EL1=0 after exec, register sync "
                                "failed",
                                prefix);
                            crash_report(vcpu, g, CRASH_ELR_ZERO,
                                         "ELR_EL1=0 after exec");
                            exit_code = 128;
                            running = false;
                        }
                    }
                    break;
                }

                case 0: {
                    /* HVC #0: Normal exit */
                    uint64_t x0;
                    hv_vcpu_get_reg(vcpu, HV_REG_X0, &x0);
                    if (verbose)
                        log_debug("%s: guest exit HVC #0 code=%llu", prefix,
                                  (unsigned long long) x0);
                    exit_code = (int) x0;
                    running = false;
                    break;
                }

                case 4: {
                    /* HVC #4: Set system register (from shim). X0 = reg index
                     * into hvc4_sysregs, X1 = value.
                     */
                    uint64_t reg_id, value;
                    hv_vcpu_get_reg(vcpu, HV_REG_X0, &reg_id);
                    hv_vcpu_get_reg(vcpu, HV_REG_X1, &value);

                    if (reg_id >= ARRAY_SIZE(hvc4_sysregs)) {
                        log_error("%s: HVC #4 unknown reg %llu", prefix,
                                  (unsigned long long) reg_id);
                        exit_code = 128;
                        running = false;
                        continue;
                    }
                    if (verbose)
                        log_debug("%s: HVC #4 set reg %llu = 0x%llx", prefix,
                                  (unsigned long long) reg_id,
                                  (unsigned long long) value);
                    HV_CHECK(
                        hv_vcpu_set_sys_reg(vcpu, hvc4_sysregs[reg_id], value));
                    break;
                }

                case 7: {
                    /* HVC #7: MRS trap emulation. Guest EL0 code read a system
                     * register. Extract the register encoding from ESR_EL1's
                     * ISS field and read it via HVF.
                     *
                     * Return value in X0 for the shim to store into the saved
                     * register frame.
                     */
                    uint64_t esr;
                    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &esr);
                    uint32_t iss = (uint32_t) (esr & 0x1FFFFFF);

                    /* ISS encoding for EC=0x18 (MSR/MRS trap):
                     *   [21:20] = Op0    [19:17] = Op2
                     *   [16:14] = Op1    [13:10] = CRn
                     *   [9:5]   = Rt     [4:1]   = CRm
                     *   [0]     = Direction (1=MRS read)
                     */
                    uint32_t op0 = (iss >> 20) & 0x3, op2 = (iss >> 17) & 0x7;
                    uint32_t op1 = (iss >> 14) & 0x7, crn = (iss >> 10) & 0xF;
                    uint32_t crm = (iss >> 1) & 0xF;

                    /* Construct HVF system register ID:
                     *   (Op0<<14) | (Op1<<11) | (CRn<<7) | (CRm<<3) | Op2
                     */
                    hv_sys_reg_t reg =
                        (hv_sys_reg_t) ((op0 << 14) | (op1 << 11) | (crn << 7) |
                                        (crm << 3) | op2);

                    uint64_t value = 0;

                    /* ID register emulation: return VZ-sanitized values
                     * matching a real VZ (Lima) VM BEFORE trying HVF. HVF's
                     * hv_vcpu_get_sys_reg succeeds for ID registers but returns
                     * raw hardware values, which include features the
                     * hypervisor does not actually virtualize.
                     *
                     * Values captured from a Lima VZ VM on Apple Silicon via
                     * inline MRS from EL0 (kernel trap-and-emulate). These are
                     * checked first, before the HVF call.
                     */
                    bool have_vz_override = false;

                    /* ID_AA64MMFR0_EL1 (3,0,0,7,0) */
                    if (op0 == 3 && op1 == 0 && crn == 0 && crm == 7 &&
                        op2 == 0) {
                        value = 0x00000111ff000000ULL;
                        have_vz_override = true;
                    }
                    /* ID_AA64MMFR1_EL1 (3,0,0,7,1): VZ returns 0. Raw hardware
                     * (e.g., 0x11212000) exposes HPDS, PAN, LO, XNX etc. that
                     * VZ does not virtualize.
                     */
                    if (op0 == 3 && op1 == 0 && crn == 0 && crm == 7 &&
                        op2 == 1) {
                        value = 0x0000000000000000ULL;
                        have_vz_override = true;
                    }
                    /* ID_AA64MMFR2_EL1 (3,0,0,7,2): VZ returns 0. */
                    if (op0 == 3 && op1 == 0 && crn == 0 && crm == 7 &&
                        op2 == 2) {
                        value = 0x0000000000000000ULL;
                        have_vz_override = true;
                    }
                    /* ID_AA64ISAR0_EL1 (3,0,0,6,0) */
                    if (op0 == 3 && op1 == 0 && crn == 0 && crm == 6 &&
                        op2 == 0) {
                        value = 0x0021100110212120ULL;
                        have_vz_override = true;
                    }
                    /* ID_AA64ISAR1_EL1 (3,0,0,6,1) */
                    if (op0 == 3 && op1 == 0 && crn == 0 && crm == 6 &&
                        op2 == 1) {
                        value = 0x0000101110211402ULL;
                        have_vz_override = true;
                    }
                    /* ID_AA64PFR0_EL1 (3,0,0,4,0) */
                    if (op0 == 3 && op1 == 0 && crn == 0 && crm == 4 &&
                        op2 == 0) {
                        value = 0x0001000000110011ULL;
                        have_vz_override = true;
                    }
                    /* ID_AA64PFR1_EL1 (3,0,0,4,1): VZ returns 0. */
                    if (op0 == 3 && op1 == 0 && crn == 0 && crm == 4 &&
                        op2 == 1) {
                        value = 0x0000000000000000ULL;
                        have_vz_override = true;
                    }

                    if (have_vz_override) {
                        if (verbose)
                            log_debug(
                                "%s: MRS trap: Op0=%u Op1=%u "
                                "CRn=%u CRm=%u Op2=%u -> 0x%llx (VZ)",
                                prefix, op0, op1, crn, crm, op2,
                                (unsigned long long) value);
                    }

                    hv_return_t ret = have_vz_override ? HV_SUCCESS
                                                       : hv_vcpu_get_sys_reg(
                                                             vcpu, reg, &value);
                    if (ret != HV_SUCCESS) {
                        /* HVF does not expose this register. Provide a
                         * host-side fallback for known registers.
                         */
                        bool have_fallback = false;

                        /* CNTFRQ_EL0 (3,3,14,0,0): counter frequency. Read
                         * directly from host hardware (Apple Silicon uses
                         * 24MHz).
                         */
                        if (op0 == 3 && op1 == 3 && crn == 14 && crm == 0 &&
                            op2 == 0) {
                            __asm__ volatile("mrs %0, cntfrq_el0"
                                             : "=r"(value));
                            have_fallback = true;
                        }

                        /* Non-ID register fallbacks for registers that HVF does
                         * not expose. ID registers are handled above (VZ
                         * overrides).
                         */

                        if (verbose) {
                            if (have_fallback) {
                                log_debug(
                                    "%s: MRS trap: "
                                    "Op0=%u Op1=%u CRn=%u CRm=%u "
                                    "Op2=%u -> 0x%llx (host)",
                                    prefix, op0, op1, crn, crm, op2,
                                    (unsigned long long) value);
                            } else {
                                log_debug(
                                    "%s: MRS trap: unknown reg "
                                    "Op0=%u Op1=%u CRn=%u CRm=%u "
                                    "Op2=%u (hv_reg=0x%x) -> 0",
                                    prefix, op0, op1, crn, crm, op2,
                                    (unsigned) reg);
                            }
                        }
                    } else if (verbose) {
                        log_debug(
                            "%s: MRS trap: Op0=%u Op1=%u "
                            "CRn=%u CRm=%u Op2=%u -> 0x%llx",
                            prefix, op0, op1, crn, crm, op2,
                            (unsigned long long) value);
                    }

                    hv_vcpu_set_reg(vcpu, HV_REG_X0, value);
                    break;
                }

                case 9: {
                    /* HVC #9: W^X page permission toggle for JIT.
                     *
                     * Apple HVF enforces W^X: pages cannot be both writable and
                     * executable simultaneously. JIT code needs to be written
                     * (RW), then executed (RX). The shim detects permission
                     * faults (EC=0x20 instruction abort, EC=0x24 data abort)
                     * and forwards the faulting address here.
                     *
                     * Toggling at 2MiB granularity causes thrashing when the
                     * JIT writes new code and executes existing code within the
                     * same 2MiB block. Instead, the code splits the 2MiB block
                     * into 4KiB L3 pages and toggle only the faulting 4KiB
                     * page. This allows different pages within a 2MiB block to
                     * have independent RW/RX permissions simultaneously.
                     *
                     * x0 = FAR_EL1 (faulting virtual address) x1 = type: 0 =
                     * exec fault -> flip to RX
                     *            1 = write fault -> flip to RW
                     */
                    uint64_t far, type;
                    hv_vcpu_get_reg(vcpu, HV_REG_X0, &far);
                    hv_vcpu_get_reg(vcpu, HV_REG_X1, &type);

                    uint64_t page_start = far & ~(4096ULL - 1);
                    uint64_t page_end = page_start + 4096;
                    int new_perms = (type == 0) ? MEM_PERM_RX : MEM_PERM_RW;

                    /* Hold mmap_lock for page table modifications AND region
                     * lookups to prevent races with concurrent
                     * mmap/mprotect/munmap from other vCPU threads.
                     */
                    pthread_mutex_lock(&mmap_lock);

                    /* Check if this is a genuine permission violation (not a
                     * W^X toggle). If the guest region lacks the required
                     * permission, deliver SIGSEGV instead of toggling. This
                     * handles mprotect(PROT_READ), SHM_RDONLY, PROT_NONE, and
                     * non-exec pages.
                     */
                    {
                        uint64_t off = far - g->ipa_base;
                        const guest_region_t *reg = guest_region_find(g, off);
                        int required =
                            (type == 1) ? LINUX_PROT_WRITE : LINUX_PROT_EXEC;
                        if (reg && !(reg->prot & required)) {
                            pthread_mutex_unlock(&mmap_lock);
                            uint64_t esr;
                            hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &esr);
                            signal_set_fault_info(LINUX_SEGV_ACCERR, far, esr);
                            signal_queue(LINUX_SIGSEGV);
                            int sig_ret = signal_deliver(vcpu, g, &exit_code);
                            if (sig_ret < 0)
                                running = false;
                            break;
                        }
                    }

                    /* Count W^X toggles for JIT debugging */
                    if (type == 0)
                        atomic_fetch_add(&wxcount_to_rx, 1);
                    else
                        atomic_fetch_add(&wxcount_to_rw, 1);

                    if (verbose)
                        log_debug(
                            "%s: W^X toggle at 0x%llx -> %s (page 0x%llx)",
                            prefix, (unsigned long long) far,
                            (type == 0) ? "RX" : "RW",
                            (unsigned long long) page_start);
                    uint64_t block_start = far & ~(BLOCK_2MIB - 1);
                    int sr = guest_split_block(g, block_start);
                    int ur =
                        guest_update_perms(g, page_start, page_end, new_perms);
                    pthread_mutex_unlock(&mmap_lock);
                    if (verbose && (sr < 0 || ur < 0))
                        log_warn(
                            "%s: W^X toggle FAILED "
                            "(split=%d update=%d) far=0x%llx",
                            prefix, sr, ur, (unsigned long long) far);
                    /* TLB flush is done by the shim (tlbi_restore_eret) for the
                     * single faulting page. Clear this thread's pending request
                     * so the next syscall epilogue does not re-flush the W^X
                     * page. cpu_tlbi_req is per-vCPU, so this only touches our
                     * own slot -- concurrent vCPUs are unaffected.
                     */
                    tlbi_request_clear();
                    break;
                }

                case 10: {
                    /* HVC #10: BRK from EL0 -> deliver SIGTRAP or ptrace-stop.
                     *
                     * If the thread is ptraced, the BRK enters a ptrace-stop
                     * (the tracer reads/writes registers then CONT's).
                     * Otherwise the run loop queues SIGTRAP and delivers it via
                     * the signal frame mechanism.
                     *
                     * The shim has already restored all GPRs to their EL0
                     * values, so signal_deliver / ptrace_stop read correct
                     * state.
                     *
                     * The Linux kernel sets si_code=TRAP_BRKPT, si_addr=BRK_PC,
                     * and fault_address=BRK_PC for BRK-triggered SIGTRAP.
                     */
                    uint64_t brk_pc;
                    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &brk_pc);

                    if (verbose) {
                        log_debug("%s: BRK at 0x%llx -> %s", prefix,
                                  (unsigned long long) brk_pc,
                                  current_thread->ptraced ? "ptrace-stop"
                                                          : "SIGTRAP");
                    }

                    if (current_thread->ptraced) {
                        /* Ptrace-stop: suspend vCPU, notify tracer.
                         * thread_ptrace_stop blocks until tracer CONT's.
                         */
                        int cont_sig = thread_ptrace_stop(current_thread, 5);
                        if (cont_sig > 0) {
                            signal_queue(cont_sig);
                            int sr = signal_deliver(vcpu, g, &exit_code);
                            if (sr < 0)
                                running = false;
                        }
                    } else {
                        /* Non-ptraced: deliver SIGTRAP via signal frame. Read
                         * ESR_EL1 to include in sigcontext.
                         */
                        uint64_t brk_esr;
                        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &brk_esr);
                        signal_set_fault_info(LINUX_TRAP_BRKPT, brk_pc,
                                              brk_esr);
                        signal_queue(LINUX_SIGTRAP);
                        if (verbose) {
                            uint64_t thread_blocked =
                                current_thread ? current_thread->blocked
                                               : 0xDEAD;
                            log_debug(
                                "%s: BRK: thread_blocked=0x%llx "
                                "pending=0x%llx",
                                prefix, (unsigned long long) thread_blocked,
                                (unsigned long long) signal_get_state()
                                    ->pending);
                        }
                        int sig_ret = signal_deliver(vcpu, g, &exit_code);
                        if (verbose)
                            log_debug("%s: signal_deliver returned %d", prefix,
                                      sig_ret);
                        if (sig_ret < 0) {
                            /* SIG_DFL for SIGTRAP: terminate */
                            running = false;
                        }
                    }
                    break;
                }

                case 11: {
                    /* HVC #11: EL0 fault -> deliver signal.
                     *
                     * The shim forwards EL0 faults here for signal delivery.
                     * EC-based dispatch determines the signal:
                     *   EC=0x20 (instruction abort) -> SIGSEGV
                     *   EC=0x24 (data abort)        -> SIGSEGV
                     *   EC=0x00 (undefined insn)    -> SIGILL
                     *   Other ECs from EL0           -> SIGILL (catch-all)
                     *
                     * For SIGSEGV, si_code is SEGV_MAPERR (translation fault)
                     * or SEGV_ACCERR (permission fault) based on xFSC[5:2]. For
                     * SIGILL, si_code is ILL_ILLOPC (illegal opcode). si_addr
                     * is FAR_EL1 for aborts, ELR_EL1 for SIGILL (FAR_EL1 is
                     * UNKNOWN for EC=0 per ARM ARM).
                     */
                    uint64_t esr, far_addr, elr_addr;
                    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &esr);
                    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, &far_addr);
                    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &elr_addr);

                    uint32_t fault_ec = (uint32_t) ((esr >> 26) & 0x3F);

                    /* Non-abort EC -> SIGILL. Branch out early so the abort /
                     * SIGSEGV path below stays at the case-body indent rather
                     * than nested inside an else branch. FAR_EL1 is UNKNOWN for
                     * non-abort exceptions, so use ELR_EL1 for si_addr.
                     *
                     * Only EC 0x20 (instruction abort from a lower EL) and EC
                     * 0x24 (data abort from a lower EL) are intentionally
                     * routed to the SIGSEGV path that follows. Every other
                     * forwarded EC -- 0x00 (undefined instruction), 0x18
                     * (system instruction trap), 0x32/0x33 (software step),
                     * 0x3C (BRK), and any unrecognized class -- lands here as
                     * SIGILL. If a future change adds a new lower-EL abort
                     * class (e.g. 0x21 / 0x25 for higher exception levels) that
                     * should map to SIGSEGV, the test below needs explicit
                     * widening; do NOT relax the check casually.
                     */
                    if (fault_ec != 0x20 && fault_ec != 0x24) {
                        if (verbose)
                            log_debug(
                                "%s: EL0 undefined insn at "
                                "PC=0x%llx (ESR=0x%llx EC=0x%x) "
                                "-> SIGILL/ILL_ILLOPC",
                                prefix, (unsigned long long) elr_addr,
                                (unsigned long long) esr, fault_ec);
                        signal_set_fault_info(LINUX_ILL_ILLOPC, elr_addr, esr);
                        signal_queue(LINUX_SIGILL);
                        int sig_ret = signal_deliver(vcpu, g, &exit_code);
                        /* HVC #11 consumes X8 as the post-fault TLBI opcode.
                         * signal_deliver() may leave it unchanged when no
                         * handler is materialized, or set the syscall-path
                         * frame-drop marker when one is. Neither is a TLBI
                         * request here; lazy materialization emits its own
                         * request and exits before this path.
                         */
                        hv_vcpu_set_reg(vcpu, HV_REG_X8, 0);
                        if (verbose)
                            log_debug("%s: signal %d deliver returned %d",
                                      prefix, LINUX_SIGILL, sig_ret);
                        if (sig_ret < 0)
                            running = false; /* SIG_DFL core => terminate. */
                        break;
                    }

                    /* Instruction or data abort. Try lazy page materialization
                     * before declaring SIGSEGV: translation faults (xFSC[5:2]
                     * == 0x1) may come from a MAP_NORESERVE region with
                     * deferred page-table creation.
                     */
                    uint32_t fsc = (uint32_t) (esr & 0x3F);
                    uint32_t fsc_type = (fsc >> 2) & 0xF;
                    if (fsc_type == 0x01) {
                        uint64_t fault_off = far_addr - g->ipa_base;
                        pthread_mutex_lock(&mmap_lock);
                        int mat = guest_materialize_lazy(g, fault_off);
                        pthread_mutex_unlock(&mmap_lock);
                        if (mat == 0) {
                            /* Page materialized; the helpers inside
                             * guest_materialize_lazy populated the per-vCPU
                             * TLBI accumulator with the range just installed
                             * (plus the I-cache hint if the region's prot
                             * includes PROT_EXEC). Drain it through the shared
                             * emit helper so the shim's post-HVC-11 dispatch
                             * (handle_el0_fault) actually issues the TLBI
                             * before ERET. Without this, a PE that caches
                             * translation-fault (negative) entries would
                             * re-fault on the retry, looping until the entry
                             * self-evicts.
                             */
                            tlbi_request_emit_to_vcpu(vcpu);
                            break;
                        }
                    }

                    /* Real SIGSEGV. Permission faults (xFSC[5:2] == 0x3) map to
                     * SEGV_ACCERR; address size, translation, and access-flag
                     * faults map to SEGV_MAPERR for Linux.
                     */
                    int si_code = (fsc_type == 0x03) ? LINUX_SEGV_ACCERR
                                                     : LINUX_SEGV_MAPERR;
                    if (verbose) {
                        const char *fault_type =
                            (fault_ec == 0x20) ? "inst" : "data";
                        const char *code_name = (si_code == LINUX_SEGV_MAPERR)
                                                    ? "MAPERR"
                                                    : "ACCERR";
                        log_debug(
                            "%s: EL0 %s fault at 0x%llx "
                            "PC=0x%llx (ESR=0x%llx FSC=0x%x) "
                            "-> SIGSEGV/%s",
                            prefix, fault_type, (unsigned long long) far_addr,
                            (unsigned long long) elr_addr,
                            (unsigned long long) esr, fsc, code_name);
                    }
                    signal_set_fault_info(si_code, far_addr, esr);
                    signal_queue(LINUX_SIGSEGV);
                    int sig_ret = signal_deliver(vcpu, g, &exit_code);
                    /* HVC #11 consumes X8 as the post-fault TLBI opcode.
                     * signal_deliver() may leave it unchanged when no handler
                     * is materialized, or set the syscall-path frame-drop
                     * marker when one is. Neither is a TLBI request here; lazy
                     * materialization emits its own request and exits before
                     * this path.
                     */
                    hv_vcpu_set_reg(vcpu, HV_REG_X8, 0);
                    if (verbose)
                        log_debug("%s: signal %d deliver returned %d", prefix,
                                  LINUX_SIGSEGV, sig_ret);
                    if (sig_ret < 0)
                        running = false; /* SIG_DFL core => terminate. */
                    break;
                }

                case 12: {
                    /* HVC #12: System instruction trap (EC=0x18 Direction=0).
                     * The shim forwards trapped cache maintenance instructions
                     * (DC CVAU, IC IVAU, etc.) here for logging/counting. It
                     * also passes the original Rt value in X0 so host-side
                     * emulation can handle MSR writes such as TPIDR_EL0. The
                     * shim has already advanced PC and will restore X0 from its
                     * saved frame before returning to EL0.
                     */
                    atomic_fetch_add(&sysreg_write_count, 1);
                    uint64_t rt_value = 0;
                    hv_vcpu_get_reg(vcpu, HV_REG_X0, &rt_value);
                    uint64_t esr;
                    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &esr);
                    uint32_t iss = (uint32_t) (esr & 0x1FFFFFF);
                    /* Decode ISS for system instruction:
                     *   Op0[21:20] Op2[19:17] Op1[16:14]
                     *   CRn[13:10] Rt[9:5] CRm[4:1] Dir[0]
                     */
                    uint32_t op0 = (iss >> 20) & 0x3, op2 = (iss >> 17) & 0x7;
                    uint32_t op1 = (iss >> 14) & 0x7, crn = (iss >> 10) & 0xF;
                    uint32_t crm = (iss >> 1) & 0xF, rt = (iss >> 5) & 0x1F;

                    /* TPIDR_EL0 (S3_3_C13_C0_2): userspace TLS base. Static
                     * glibc writes this during early startup. HVF traps the
                     * MSR, so Linux-compatible execution requires reflecting
                     * the write into the virtual sysreg.
                     */
                    if (op0 == 3 && op1 == 3 && crn == 13 && crm == 0 &&
                        op2 == 2) {
                        HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL0,
                                                     rt_value));
                    }
                    if (verbose) {
                        /* DC CVAU: Op0=1,Op1=3,CRn=7,CRm=11,Op2=1 IC IVAU:
                         * Op0=1,Op1=3,CRn=7,CRm=5,Op2=1
                         */
                        const char *name = "unknown";
                        if (op0 == 1 && op1 == 3 && crn == 7 && crm == 11 &&
                            op2 == 1)
                            name = "DC CVAU";
                        else if (op0 == 1 && op1 == 3 && crn == 7 && crm == 5 &&
                                 op2 == 1)
                            name = "IC IVAU";
                        else if (op0 == 1 && op1 == 3 && crn == 7 &&
                                 crm == 10 && op2 == 1)
                            name = "DC CVAC";
                        else if (op0 == 1 && op1 == 3 && crn == 7 &&
                                 crm == 14 && op2 == 1)
                            name = "DC CIVAC";
                        else if (op0 == 3 && op1 == 3 && crn == 13 &&
                                 crm == 0 && op2 == 2)
                            name = "MSR TPIDR_EL0";
                        log_debug(
                            "%s: sysreg trap #%llu: %s "
                            "(Op0=%u Op1=%u CRn=%u CRm=%u Op2=%u "
                            "Rt=X%u val=0x%llx)",
                            prefix,
                            (unsigned long long) atomic_load(
                                &sysreg_write_count),
                            name, op0, op1, crn, crm, op2, rt,
                            (unsigned long long) rt_value);
                    }
                    break;
                }

                case 2: {
                    /* HVC #2: Bad exception in guest. Shim clobbers X0-X3,X5
                     * with exception info. X4,X6-X30 and SP_EL0 still hold
                     * faulting values.
                     */
                    uint64_t x0, x1, x2, x3, x5;
                    hv_vcpu_get_reg(vcpu, HV_REG_X0, &x0);
                    hv_vcpu_get_reg(vcpu, HV_REG_X1, &x1);
                    hv_vcpu_get_reg(vcpu, HV_REG_X2, &x2);
                    hv_vcpu_get_reg(vcpu, HV_REG_X3, &x3);
                    hv_vcpu_get_reg(vcpu, HV_REG_X5, &x5);
                    log_error(
                        "%s: guest exception vec=0x%03llx "
                        "ESR=0x%llx FAR=0x%llx ELR=0x%llx SPSR=0x%llx",
                        prefix, (unsigned long long) x5,
                        (unsigned long long) x0, (unsigned long long) x1,
                        (unsigned long long) x2, (unsigned long long) x3);

                    /* Dump preserved registers for debugging */
                    uint64_t sp_el0;
                    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL0, &sp_el0);
                    log_error("%s:   SP_EL0=0x%llx", prefix,
                              (unsigned long long) sp_el0);
                    for (int ri = 4; ri <= 30; ri++) {
                        /* Skip X5 (clobbered by shim for vec offset) */
                        if (ri == 5)
                            continue;
                        uint64_t rv;
                        hv_vcpu_get_reg(vcpu, (hv_reg_t) (HV_REG_X0 + ri), &rv);
                        log_error("%s:   X%-2d=0x%016llx", prefix, ri,
                                  (unsigned long long) rv);
                    }

                    /* Check if FAR looks like a tagged pointer */
                    uint64_t far = x1;
                    uint16_t top16 = (uint16_t) (far >> 48);
                    if (top16 != 0x0000 && top16 != 0xFFFF) {
                        log_error(
                            "%s:   FAR tag=0x%04x, extracted addr=0x%llx",
                            prefix, top16,
                            (unsigned long long) (far & 0x0000FFFFFFFFFFFFULL));
                    }

                    {
                        char detail[128];
                        snprintf(detail, sizeof(detail),
                                 "vec=0x%03llx ESR=0x%llx FAR=0x%llx",
                                 (unsigned long long) x5,
                                 (unsigned long long) x0,
                                 (unsigned long long) x1);
                        crash_report(vcpu, g, CRASH_BAD_EXCEPTION, detail);
                    }
                    exit_code = 128;
                    running = false;
                    break;
                }

                case 6: {
                    /* HVC #6: embedder extension hook. X8 = call number, X0-X7
                     * = arguments. If a dispatch function is registered via
                     * elfuse_set_hvc6_handler(), it is called here. Otherwise
                     * falls through as a no-op.
                     */
                    if (g->hvc6_handler) {
                        uint64_t x8 = 0;
                        hv_vcpu_get_reg(vcpu, HV_REG_X8, &x8);
                        uint64_t args[8] = {0};
                        for (int i = 0; i < 8; i++)
                            hv_vcpu_get_reg(vcpu, HV_REG_X0 + i, &args[i]);
                        hvc6_yield_requested = false;
                        uint64_t result =
                            g->hvc6_handler(x8, args, g->hvc6_userdata);
                        hv_vcpu_set_reg(vcpu, HV_REG_X0, result);
                        if (hvc6_yield_requested) {
                            hvc6_yield_requested = false;
                            running = false;
                        }
                    }
                    /* PC already advanced by HVC instruction */
                    break;
                }

                default: {
                    log_error("%s: unexpected HVC #%u", prefix, imm);
                    char detail[64];
                    snprintf(detail, sizeof(detail), "HVC #%u", imm);
                    crash_report(vcpu, g, CRASH_UNEXPECTED_HVC, detail);
                    exit_code = 128;
                    running = false;
                    break;
                }
                }
            } else if (ec == 0x30 || ec == 0x32) {
                /* EC=0x30: Hardware breakpoint from lower EL (EL0). EC=0x32:
                 * Software step exception from lower EL. Both are debug
                 * exceptions trapped to host via
                 * hv_vcpu_set_trap_debug_exceptions(). Forward to GDB.
                 *
                 * TDE causes debug exceptions to bypass EL1 entirely (EL0 ->
                 * EL2), so ELR_EL1 is NOT updated; it still holds the stale
                 * value from the shim's last ERET. Read the actual stop PC from
                 * HV_REG_PC and sync it to ELR_EL1 so the GDB register snapshot
                 * sees the correct value.
                 */
                if (gdb_stub_is_active()) {
                    int reason =
                        (ec == 0x30) ? GDB_STOP_BREAKPOINT : GDB_STOP_STEP;
                    uint64_t stop_pc = vcpu_get_reg(vcpu, HV_REG_PC);
                    /* TDE routes debug exceptions EL0->EL2, bypassing EL1.
                     * ELR_EL1 and SPSR_EL1 are NOT updated; sync them from
                     * HV_REG_PC/HV_REG_CPSR so the GDB register snapshot reads
                     * correct values.
                     */
                    vcpu_set_sysreg(vcpu, HV_SYS_REG_ELR_EL1, stop_pc);
                    vcpu_set_sysreg(vcpu, HV_SYS_REG_SPSR_EL1,
                                    vcpu_get_reg(vcpu, HV_REG_CPSR));
                    if (verbose)
                        log_debug(
                            "%s: debug exception EC=0x%x "
                            "at PC=0x%llx -> GDB",
                            prefix, ec, (unsigned long long) stop_pc);
                    gdb_stub_handle_stop(reason, stop_pc);
                    /* After GDB resumes, re-sync debug registers */
                    gdb_stub_sync_debug_regs(vcpu);
                } else if (verbose) {
                    log_debug("%s: debug exception EC=0x%x (no GDB attached)",
                              prefix, ec);
                }
            } else if (ec == 0x34 || ec == 0x35) {
                /* EC=0x34: Watchpoint from lower EL (EL0, data abort). EC=0x35:
                 * Watchpoint from current EL (shouldn't happen). Same TDE
                 * bypass as breakpoints: ELR_EL1 and FAR_EL1 are stale because
                 * the exception went EL0->EL2. Use HV_REG_PC for the stop PC
                 * and vexit->exception for the watched address.
                 */
                if (gdb_stub_is_active()) {
                    uint64_t wp_pc = vcpu_get_reg(vcpu, HV_REG_PC);
                    vcpu_set_sysreg(vcpu, HV_SYS_REG_ELR_EL1, wp_pc);
                    vcpu_set_sysreg(vcpu, HV_SYS_REG_SPSR_EL1,
                                    vcpu_get_reg(vcpu, HV_REG_CPSR));
                    uint64_t wp_addr = vexit->exception.virtual_address;
                    if (verbose)
                        log_debug("%s: watchpoint at addr=0x%llx -> GDB",
                                  prefix, (unsigned long long) wp_addr);
                    gdb_stub_handle_stop(GDB_STOP_WATCHPOINT, wp_addr);
                    gdb_stub_sync_debug_regs(vcpu);
                } else if (verbose) {
                    log_debug("%s: watchpoint EC=0x%x (no GDB attached)",
                              prefix, ec);
                }
            } else if (ec == 0x01) {
                /* WFI/WFE has no host-side work in this userspace VM. */
                if (verbose)
                    log_debug("%s: WFI/WFE trapped", prefix);
            } else {
                /* Non-HVC exception at EL2 level */
                log_error(
                    "%s: unexpected exception EC=0x%x "
                    "syndrome=0x%llx VA=0x%llx PA=0x%llx",
                    prefix, ec, (unsigned long long) vexit->exception.syndrome,
                    (unsigned long long) vexit->exception.virtual_address,
                    (unsigned long long) vexit->exception.physical_address);
                {
                    char detail[128];
                    snprintf(
                        detail, sizeof(detail),
                        "EC=0x%x syndrome=0x%llx VA=0x%llx", ec,
                        (unsigned long long) vexit->exception.syndrome,
                        (unsigned long long) vexit->exception.virtual_address);
                    crash_report(vcpu, g, CRASH_UNEXPECTED_EC, detail);
                }
                exit_code = 128;
                running = false;
            }
        } else if (vexit->reason == HV_EXIT_REASON_CANCELED) {
            /* Canceled by hv_vcpus_exit(). Can be: alarm timeout, exit_group
             * from another thread, or signal preemption (signal_queue called
             * hv_vcpus_exit to deliver a signal while the guest was in a tight
             * loop).
             */
            if (is_main && g_timed_out) {
                /* Timeout already handled above the exception switch -- loop
                 * back so the timeout check fires.
                 */
                continue;
            }
            if (proc_exit_group_requested()) {
                exit_code = proc_exit_group_code();
                break;
            }

            /* GDB stub: if GDB requested a stop (Ctrl+C or another thread hit a
             * breakpoint), enter GDB stop state.
             */
            if (gdb_stub_stop_requested()) {
                if (verbose)
                    log_debug("%s: GDB stop request -> entering GDB stop",
                              prefix);
                gdb_stub_handle_stop(GDB_STOP_SIGNAL, 0);
                gdb_stub_sync_debug_regs(vcpu);
                continue;
            }

            /* PTRACE_INTERRUPT: if this thread is ptraced and not already
             * stopped, enter ptrace-stop so the tracer can inspect state. This
             * handles hv_vcpus_exit from sys_ptrace PTRACE_INTERRUPT.
             */
            if (current_thread->ptraced && !current_thread->ptrace_stopped) {
                if (verbose)
                    log_debug("%s: ptrace interrupt -> ptrace-stop", prefix);
                int cont_sig = thread_ptrace_stop(current_thread, 5);
                if (cont_sig > 0) {
                    signal_queue(cont_sig);
                    int sr = signal_deliver(vcpu, g, &exit_code);
                    if (sr < 0)
                        running = false;
                }
                continue;
            }

            /* rseq preemption abort: mirrors Linux rseq_ip_fixup() on context
             * switch.
             */
            if (current_thread->rseq_gva != 0) {
                uint64_t cur_pc;
                hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &cur_pc);
                int rseq_rc =
                    rseq_try_abort(g, current_thread->rseq_gva,
                                   current_thread->rseq_signature, &cur_pc);
                if (rseq_rc == 1)
                    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, cur_pc);
                if (rseq_rc == -1) {
                    exit_code = 128 + 11;
                    running = false;
                }
            }

            /* Check guest ITIMER_REAL (may have fired during tight loop) */
            signal_check_timer();

            /* Signal preemption: if a signal is pending, deliver it and resume
             * the vCPU. This enables alarm()/SIGALRM delivery and tgkill-based
             * signals in compute-bound loops.
             */
            if (signal_pending()) {
                int sig_ret = signal_deliver(vcpu, g, &exit_code);
                if (sig_ret < 0)
                    running = false;
                /* sig_ret >= 0: signal delivered or nothing pending, loop back
                 * and resume vCPU execution
                 */
                continue;
            }

            /* Fork quiesce barrier: if a sibling is performing a fork snapshot,
             * block here until the snapshot is complete. This prevents torn
             * memory snapshots in multithreaded guests.
             */
            if (thread_fork_barrier_check())
                continue;

            /* No signal pending; truly unexpected cancelation */
            if (verbose)
                log_debug("%s: vCPU canceled (no signal pending)", prefix);
        } else if (vexit->reason == HV_EXIT_REASON_VTIMER_ACTIVATED) {
            /* Virtual timer fired. The emulator emulates timers host-side, so
             * mask the vtimer and continue. Without this, a pending vtimer
             * would cause an "unexpected exit reason" crash.
             */
            hv_vcpu_set_vtimer_mask(vcpu, true);
        } else {
            log_error("%s: unexpected exit reason 0x%x", prefix, vexit->reason);
            {
                char detail[64];
                snprintf(detail, sizeof(detail), "exit reason 0x%x",
                         vexit->reason);
                crash_report(vcpu, g, CRASH_UNEXPECTED_EXIT, detail);
            }
            exit_code = 128;
            running = false;
        }
    }

    /* Clean up timeout if the run loop sets it up */
    if (is_main) {
        signal(SIGALRM, SIG_DFL);
        alarm(0);
    }

    return exit_code;
}
