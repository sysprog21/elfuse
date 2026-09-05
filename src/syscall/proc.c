/*
 * Process state and management
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
#include <limits.h>
#include <stddef.h>
#include <pthread.h>
#include <signal.h>
#include <sys/file.h> /* flock() */
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h> /* struct rusage, for wait4 rusage population */
#include <libproc.h>

#include "debug/log.h"
#include "hvutil.h"
#include "utils.h"

#include "core/shim-globals.h"
#include "core/mmap-fastpath.h"
#include "core/vdso.h"

#include "runtime/futex.h"
#include "runtime/thread.h"

#include "syscall/abi.h"
#include "syscall/exec.h"
#include "syscall/io.h" /* io_retry_backoff */
#include "syscall/linux-wire.h"
#include "syscall/internal.h"
#include "syscall/net.h"
#include "syscall/proc-identity.h"
#include "syscall/proc.h"
#include "syscall/proc-pidfd.h"
#include "syscall/proc-state.h"
#include "syscall/signal.h"
#include "syscall/wakeup-pipe.h"

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

static bool vcpu_exit_is_fork_family_syscall(hv_vcpu_t vcpu,
                                             const hv_vcpu_exit_t *vexit)
{
    if (vexit->reason != HV_EXIT_REASON_EXCEPTION)
        return false;

    uint64_t syndrome = vexit->exception.syndrome;
    uint32_t ec = (uint32_t) ((syndrome >> 26) & 0x3f);
    uint16_t imm = (uint16_t) (syndrome & 0xffff);
    if (ec != 0x16 || imm != 5)
        return false;

    uint64_t nr = 0;
    hv_vcpu_get_reg(vcpu, HV_REG_X8, &nr);
    return nr == SYS_clone || nr == SYS_clone3;
}

/* Process table for tracking direct and adopted fork children. Start small so
 * lifecycle tests exercise growth deterministically; expand under pid_lock as
 * the fork family grows. No pointer into this array survives unlocking.
 */
#define PROC_TABLE_INITIAL_CAPACITY 8U
static proc_entry_t proc_table_initial[PROC_TABLE_INITIAL_CAPACITY];
static proc_entry_t *proc_table = proc_table_initial;
static size_t proc_table_capacity = PROC_TABLE_INITIAL_CAPACITY;
static pthread_mutex_t pid_lock = PTHREAD_MUTEX_INITIALIZER; /* Lock order: 6 */
static pthread_mutex_t autoreap_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pid_cond =
    PTHREAD_COND_INITIALIZER; /* Signaled on child exit */

/* CPU time of reaped guest children, accumulated at every host reap site and
 * reported by times(2) as tms_cutime/tms_cstime. The emulator also waits on
 * helper subprocesses (rosettad translate, sysroot tooling) whose CPU shows up
 * in the host's RUSAGE_CHILDREN, so times() cannot read that aggregate; only
 * reaps of proc_table children may land here. Relaxed atomics suffice: the
 * counters are monotonic sums and times() tolerates reading utime/stime one
 * reap apart.
 */
static _Atomic uint64_t children_utime_us;
static _Atomic uint64_t children_stime_us;

void proc_children_cpu_add(const struct rusage *ru)
{
    atomic_fetch_add_explicit(&children_utime_us,
                              (uint64_t) ru->ru_utime.tv_sec * 1000000 +
                                  (uint64_t) ru->ru_utime.tv_usec,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&children_stime_us,
                              (uint64_t) ru->ru_stime.tv_sec * 1000000 +
                                  (uint64_t) ru->ru_stime.tv_usec,
                              memory_order_relaxed);
}

void proc_children_cpu_us(uint64_t *utime_us, uint64_t *stime_us)
{
    *utime_us = atomic_load_explicit(&children_utime_us, memory_order_relaxed);
    *stime_us = atomic_load_explicit(&children_stime_us, memory_order_relaxed);
}

/* Global flag for exit_group: signals all threads to terminate. Atomic to avoid
 * undefined behavior under C11 memory model when multiple threads read/write
 * concurrently.
 */
static _Atomic int exit_group_requested = 0;

/* Exit code set by the thread that calls exit_group */
static _Atomic int exit_group_code = 0;

/* Public API. */

static void proc_registry_publish(pid_t host_pid,
                                  int64_t guest_pid_val,
                                  int64_t pgid);
static int flock_retry(int fd, int op);
static void lifecycle_publish_self(void);
static int lifecycle_reserve_child(int64_t guest_pid,
                                   int64_t ppid,
                                   int64_t pgid);
static int lifecycle_publish_child(pid_t host_pid,
                                   int64_t guest_pid,
                                   int64_t ppid,
                                   int64_t pgid);
static void lifecycle_update_pgid(int64_t guest_pid, int64_t pgid);
static void lifecycle_import_children(void);
static bool lifecycle_query_exit(int64_t guest_pid,
                                 int *status,
                                 pid_t *host_pid,
                                 int64_t *pgid,
                                 struct rusage *rusage,
                                 bool *rusage_valid);
static void lifecycle_consume(int64_t guest_pid);
static void lifecycle_ack_reparent(int64_t guest_pid, int64_t ppid);
static bool lifecycle_reparent_complete(int64_t guest_pid, int64_t ppid);
static int proc_send_reparent(pid_t host_pid,
                              int64_t target_guest_pid,
                              int64_t new_ppid);
static void proc_notify_reparent(pid_t host_pid,
                                 int64_t target_guest_pid,
                                 int64_t new_ppid);
static int64_t proc_wait_autoreap_children(int pid, int options);

void proc_init(void)
{
    proc_identity_init();
    if (proc_table != proc_table_initial)
        free(proc_table);
    proc_table = proc_table_initial;
    proc_table_capacity = PROC_TABLE_INITIAL_CAPACITY;
    memset(proc_table_initial, 0, sizeof(proc_table_initial));
    proc_state_init();
    thread_init();
    futex_init();
}

void proc_set_rosetta_enabled(bool enabled)
{
    atomic_store_explicit(&rosetta_enabled, enabled, memory_order_relaxed);
}

bool proc_rosetta_enabled(void)
{
    return atomic_load_explicit(&rosetta_enabled, memory_order_relaxed);
}

void proc_set_rosetta_active(bool active)
{
    atomic_store_explicit(&rosetta_active, active, memory_order_relaxed);
}

bool proc_rosetta_active(void)
{
    return atomic_load_explicit(&rosetta_active, memory_order_relaxed);
}

void proc_request_exit_group(int code)
{
    /* Release on the flag, relaxed on the payload: a vCPU that observes the
     * request through proc_exit_group_requested must also see the code that
     * goes with it. Publishing them in the other order hands a racing thread
     * the previous exit code.
     */
    atomic_store_explicit(&exit_group_code, code, memory_order_relaxed);
    atomic_store_explicit(&exit_group_requested, 1, memory_order_release);
}

void proc_clear_exit_group(void)
{
    atomic_store_explicit(&exit_group_requested, 0, memory_order_relaxed);
    atomic_store_explicit(&exit_group_code, 0, memory_order_relaxed);
}

int proc_exit_group_requested(void)
{
    return atomic_load_explicit(&exit_group_requested, memory_order_acquire);
}

static int proc_exit_group_code(void)
{
    return atomic_load_explicit(&exit_group_code, memory_order_relaxed);
}

static void proc_init_child_entry(proc_entry_t *entry,
                                  pid_t host_pid,
                                  int64_t guest_pid_val,
                                  int64_t pgid)
{
    entry->active = true;
    entry->reserved = false;
    entry->host_pid = host_pid;
    entry->guest_pid = guest_pid_val;

    /* Seed with the group the child inherited at fork. The caller passes the
     * exact value sent in the fork IPC header so the parent's view and the
     * child's own pgid cannot disagree even if a sibling thread changes the
     * parent's group during the fork window.
     */
    entry->pgid = pgid;
    entry->exited = false;
    entry->exit_status = 0;
    entry->rusage_valid = false;
    entry->rusage_accounted = false;
    entry->host_waitable = true;
    memset(&entry->rusage, 0, sizeof(entry->rusage));
}

static proc_entry_t *proc_find_free_entry(void)
{
    /* Scanned in full, not short-circuited on the first free slot: this is
     * called once per fork, already dwarfed by posix_spawn and the guest memory
     * IPC transfer that admission does around it, so the extra comparisons are
     * free. In exchange the same pass answers "is every entry idle right now",
     * which is what lets a table grown for a historical burst of concurrent
     * children shrink back down once none of them are left, instead of taxing
     * every future host_pid/guest_pid scan at the high-water capacity forever.
     */
    proc_entry_t *free_entry = NULL;
    bool any_live = false;
    for (size_t i = 0; i < proc_table_capacity; i++) {
        /* host_reap_pending can be true on an entry that is otherwise idle:
         * proc_process_exit() sets it while publishing an early-seen exit to
         * the lifecycle registry, and sys_wait4 can go on to clear active
         * without clearing it, leaving proc_deferred_reap_poll() as the only
         * thing that still needs this slot (it scans by host_reap_pending
         * alone, not active). Shrinking the table out from under a pending
         * deferred reap would silently strand that host zombie until process
         * exit.
         */
        if (proc_table[i].active || proc_table[i].reserved ||
            proc_table[i].host_reap_pending)
            any_live = true;
        else if (!free_entry)
            free_entry = &proc_table[i];
    }

    if (!any_live && proc_table_capacity > PROC_TABLE_INITIAL_CAPACITY) {
        /* No entry is active or reserved, so nothing anywhere holds a pointer
         * into this table (the invariant this file documents at its top: no
         * pointer survives unlocking, and every caller here holds pid_lock).
         * Safe to drop the grown array and reuse the small static buffer,
         * exactly as proc_init() does at startup.
         */
        free(proc_table);
        proc_table = proc_table_initial;
        proc_table_capacity = PROC_TABLE_INITIAL_CAPACITY;
        memset(proc_table_initial, 0, sizeof(proc_table_initial));
        return &proc_table_initial[0];
    }
    if (free_entry)
        return free_entry;

    if (proc_table_capacity > (size_t) INT_MAX / 2)
        return NULL;
    size_t old_capacity = proc_table_capacity;
    size_t new_capacity = old_capacity * 2;
    proc_entry_t *grown = calloc(new_capacity, sizeof(*grown));
    if (!grown)
        return NULL;
    memcpy(grown, proc_table, old_capacity * sizeof(*grown));
    if (proc_table != proc_table_initial)
        free(proc_table);
    proc_table = grown;
    proc_table_capacity = new_capacity;
    return &proc_table[old_capacity];
}

static proc_entry_t *proc_find_host_entry(pid_t host_pid)
{
    for (size_t i = 0; i < proc_table_capacity; i++) {
        if (proc_table[i].active && proc_table[i].host_pid == host_pid)
            return &proc_table[i];
    }
    return NULL;
}

/* The entry for exactly this (host_pid, guest_pid) pair.
 *
 * Every caller that releases pid_lock across a host wait4 needs this rather
 * than proc_find_host_entry: the host OS can reuse a pid the moment wait4 reaps
 * it, so a second guest fork admitted on another thread during that unlocked
 * window can land an unrelated child in the table under the exact same
 * host_pid. Two active entries then share that host_pid, and a lookup that
 * matches on host_pid alone returns whichever sits at the lower index.
 * Comparing guest_pid after the fact does not save it: when the impostor comes
 * first, the check rejects it and the real entry is never reached, so the
 * caller silently skips work it had to do. Matching on both in one scan finds
 * the intended entry wherever it sits.
 */
static proc_entry_t *proc_find_host_guest_entry(pid_t host_pid,
                                                int64_t guest_pid_val)
{
    for (size_t i = 0; i < proc_table_capacity; i++) {
        if (proc_table[i].active && proc_table[i].host_pid == host_pid &&
            proc_table[i].guest_pid == guest_pid_val)
            return &proc_table[i];
    }
    return NULL;
}

static proc_entry_t *proc_find_guest_entry(int64_t guest_pid_val)
{
    for (size_t i = 0; i < proc_table_capacity; i++) {
        if (proc_table[i].active && proc_table[i].guest_pid == guest_pid_val)
            return &proc_table[i];
    }
    return NULL;
}

static proc_entry_t *proc_find_reserved_guest_entry(int64_t guest_pid_val)
{
    for (size_t i = 0; i < proc_table_capacity; i++) {
        if (proc_table[i].reserved && proc_table[i].guest_pid == guest_pid_val)
            return &proc_table[i];
    }
    return NULL;
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

static bool process_pid_sequence_path(char *out, size_t out_size)
{
    char dir[PATH_MAX];
    size_t n = confstr(_CS_DARWIN_USER_TEMP_DIR, dir, sizeof(dir));
    if (n == 0 || n > sizeof(dir))
        return false;
    int len = snprintf(out, out_size, "%selfuse-pidseq-%llu", dir,
                       (unsigned long long) absock_get_namespace_id());
    return len > 0 && (size_t) len < out_size;
}

int64_t proc_alloc_pid(void)
{
    static _Atomic bool owner_sequence_reset;
    char path[PATH_MAX];
    if (!process_pid_sequence_path(path, sizeof(path)))
        return -LINUX_EAGAIN;

    if (absock_get_namespace_id() == (uint64_t) getpid() &&
        !atomic_exchange_explicit(&owner_sequence_reset, true,
                                  memory_order_relaxed))
        unlink(path);

    int fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return -LINUX_EAGAIN;
    if (flock_retry(fd, LOCK_EX) != 0) {
        close(fd);
        return -LINUX_EAGAIN;
    }

    int64_t result = -LINUX_EAGAIN;
    struct stat st;
    int64_t next = 2;
    if (fstat(fd, &st) != 0)
        goto out;
    if (st.st_size != 0 && st.st_size != (off_t) sizeof(next))
        goto out;
    if (st.st_size == (off_t) sizeof(next)) {
        size_t done = 0;
        while (done < sizeof(next)) {
            ssize_t n = pread(fd, (uint8_t *) &next + done, sizeof(next) - done,
                              (off_t) done);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                goto out;
            done += (size_t) n;
        }
    }
    if (next < 2 || next > INT_MAX)
        goto out;

    int64_t pid = next;
    next++;
    size_t done = 0;
    while (done < sizeof(next)) {
        ssize_t n = pwrite(fd, (const uint8_t *) &next + done,
                           sizeof(next) - done, (off_t) done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            goto out;
        done += (size_t) n;
    }
    if (ftruncate(fd, (off_t) sizeof(next)) != 0)
        goto out;
    result = pid;

out:
    flock_retry(fd, LOCK_UN);
    close(fd);
    return result;
}

int proc_reserve_child(int64_t guest_pid_val, int64_t pgid)
{
    /* Explicit SIG_IGN/SA_NOCLDWAIT children are not guest-waitable. Reclaim
     * any that have already terminated before consuming another table slot, so
     * a workload that intentionally never calls wait does not retain stale
     * bookkeeping entries indefinitely.
     */
    if (signal_sigchld_autoreap())
        (void) proc_wait_autoreap_children(-1, WNOHANG);

    pthread_mutex_lock(&pid_lock);
    proc_entry_t *entry = proc_find_free_entry();
    if (!entry) {
        size_t capacity = proc_table_capacity;
        pthread_mutex_unlock(&pid_lock);
        log_error(
            "cannot grow process table beyond %zu slots for child PID "
            "%lld",
            capacity, (long long) guest_pid_val);
        return -LINUX_EAGAIN;
    }
    memset(entry, 0, sizeof(*entry));
    entry->reserved = true;
    entry->guest_pid = guest_pid_val;
    entry->pgid = pgid;
    pthread_mutex_unlock(&pid_lock);

    if (lifecycle_reserve_child(guest_pid_val, proc_get_pid(), pgid) == 0)
        return 0;

    pthread_mutex_lock(&pid_lock);
    entry = proc_find_reserved_guest_entry(guest_pid_val);
    if (entry)
        memset(entry, 0, sizeof(*entry));
    pthread_mutex_unlock(&pid_lock);
    return -LINUX_EAGAIN;
}

int proc_register_child(pid_t host_pid, int64_t guest_pid_val, int64_t pgid)
{
    if (lifecycle_publish_child(host_pid, guest_pid_val, proc_get_pid(),
                                pgid) != 0)
        return -LINUX_EAGAIN;

    pthread_mutex_lock(&pid_lock);
    proc_entry_t *entry = proc_find_reserved_guest_entry(guest_pid_val);
    if (!entry) {
        pthread_mutex_unlock(&pid_lock);
        return -LINUX_EAGAIN;
    }
    proc_init_child_entry(entry, host_pid, guest_pid_val, pgid);
    pthread_cond_broadcast(&pid_cond);
    pthread_mutex_unlock(&pid_lock);

    proc_registry_publish(host_pid, guest_pid_val, pgid);
    proc_registry_publish_self();
    return 0;
}

void proc_cancel_child(int64_t guest_pid_val)
{
    pthread_mutex_lock(&pid_lock);
    proc_entry_t *entry = proc_find_guest_entry(guest_pid_val);
    if (!entry)
        entry = proc_find_reserved_guest_entry(guest_pid_val);
    if (entry)
        memset(entry, 0, sizeof(*entry));
    pthread_cond_broadcast(&pid_cond);
    pthread_mutex_unlock(&pid_lock);
    lifecycle_consume(guest_pid_val);
}

void proc_mark_child_exited(pid_t host_pid, int status)
{
    int64_t gpid = -1;
    pthread_mutex_lock(&pid_lock);
    proc_entry_t *entry = proc_find_host_entry(host_pid);
    if (entry)
        gpid = entry->guest_pid;
    pthread_mutex_unlock(&pid_lock);

    if (gpid > 0) {
        int guest_status = status;
        if (lifecycle_query_exit(gpid, &guest_status, NULL, NULL, NULL, NULL))
            status = guest_status;
    }

    pthread_mutex_lock(&pid_lock);
    entry = proc_find_host_guest_entry(host_pid, gpid);
    if (entry) {
        entry->exited = true;
        entry->exit_status = status;
        entry->rusage_accounted = true;
        pthread_cond_broadcast(&pid_cond);
        pthread_mutex_unlock(&pid_lock);
        proc_pidfd_notify_exit(gpid);
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

/* Build the path to the cross-process signal-transport file for @host_pid.
 *
 * Files live in the per-user private temp directory macOS provisions (mode
 * 0700, owned by the invoking uid) rather than world-writable /tmp, so another
 * local user cannot pre-plant a symlink to redirect the write or inject signal
 * numbers into the guest. confstr returns the same directory for every process
 * of this uid, so sender and receiver agree on the path. Callers open the
 * result O_NOFOLLOW for defense in depth.
 *
 * Returns false (fail closed) if the private directory cannot be resolved.
 */
static bool signal_transport_path(char *out, size_t out_size, pid_t host_pid)
{
    char dir[PATH_MAX];
    size_t n = confstr(_CS_DARWIN_USER_TEMP_DIR, dir, sizeof(dir));
    if (n == 0 || n > sizeof(dir))
        return false;
    int len = snprintf(out, out_size, "%selfuse-sig-%ld", dir, (long) host_pid);
    return len > 0 && (size_t) len < out_size;
}

static bool process_registry_path(char *out, size_t out_size)
{
    char dir[PATH_MAX];
    size_t n = confstr(_CS_DARWIN_USER_TEMP_DIR, dir, sizeof(dir));
    if (n == 0 || n > sizeof(dir))
        return false;
    int len = snprintf(out, out_size, "%selfuse-procs-%llu", dir,
                       (unsigned long long) absock_get_namespace_id());
    return len > 0 && (size_t) len < out_size;
}

/* The process-group registry above intentionally contains only live host
 * members. Linux lifecycle state has different retention rules: an exited child
 * must remain discoverable until a guest wait consumes it, including after its
 * original host parent exits. Keep that state in a separate binary registry
 * protected by flock so unrelated signal/group readers stay simple.
 */
#define LIFECYCLE_MAGIC 0x454C464CU /* "ELFL" */
#define LIFECYCLE_VERSION 5
#define LIFECYCLE_INITIAL_CAPACITY 8U

typedef struct {
    pid_t host_pid;
    int64_t guest_pid;
    int64_t ppid;
    int64_t pgid;
    bool subreaper;
    bool exited;
    bool reparent_pending;
    bool rusage_valid;
    int exit_status;
    struct rusage rusage;
} lifecycle_entry_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t count;
    uint32_t _capacity; /* Runtime allocation size; ignored when loading. */
    lifecycle_entry_t entries[];
} lifecycle_registry_t;

#define LIFECYCLE_HEADER_SIZE offsetof(lifecycle_registry_t, entries)

static bool lifecycle_registry_path(char *out, size_t out_size)
{
    char dir[PATH_MAX];
    size_t n = confstr(_CS_DARWIN_USER_TEMP_DIR, dir, sizeof(dir));
    if (n == 0 || n > sizeof(dir))
        return false;
    int len = snprintf(out, out_size, "%selfuse-life-%llu", dir,
                       (unsigned long long) absock_get_namespace_id());
    return len > 0 && (size_t) len < out_size;
}

static bool lifecycle_registry_size(uint32_t capacity, size_t *size_out)
{
    if ((size_t) capacity >
        (SIZE_MAX - LIFECYCLE_HEADER_SIZE) / sizeof(lifecycle_entry_t))
        return false;
    *size_out =
        LIFECYCLE_HEADER_SIZE + (size_t) capacity * sizeof(lifecycle_entry_t);
    return true;
}

static lifecycle_registry_t *lifecycle_registry_alloc(uint32_t capacity)
{
    size_t size;
    if (!lifecycle_registry_size(capacity, &size))
        return NULL;
    lifecycle_registry_t *registry = calloc(1, size);
    if (registry)
        registry->_capacity = capacity;
    return registry;
}

static lifecycle_registry_t *lifecycle_registry_empty(void)
{
    lifecycle_registry_t *registry =
        lifecycle_registry_alloc(LIFECYCLE_INITIAL_CAPACITY);
    if (registry) {
        registry->magic = LIFECYCLE_MAGIC;
        registry->version = LIFECYCLE_VERSION;
    }
    return registry;
}

static lifecycle_registry_t *lifecycle_load_locked(int fd)
{
    struct stat st;
    lifecycle_registry_t header = {0};
    if (fstat(fd, &st) != 0)
        return NULL;
    if (st.st_size == 0)
        return lifecycle_registry_empty();
    if (st.st_size < (off_t) LIFECYCLE_HEADER_SIZE ||
        lseek(fd, 0, SEEK_SET) != 0 ||
        read_all(fd, &header, LIFECYCLE_HEADER_SIZE, true) < 0 ||
        header.magic != LIFECYCLE_MAGIC || header.version != LIFECYCLE_VERSION)
        return NULL;

    size_t disk_size;
    if (!lifecycle_registry_size(header.count, &disk_size) ||
        disk_size > (size_t) LLONG_MAX || st.st_size != (off_t) disk_size)
        return NULL;

    uint32_t capacity = header.count > LIFECYCLE_INITIAL_CAPACITY
                            ? header.count
                            : LIFECYCLE_INITIAL_CAPACITY;
    lifecycle_registry_t *registry = lifecycle_registry_alloc(capacity);
    if (!registry)
        return NULL;
    registry->magic = header.magic;
    registry->version = header.version;
    registry->count = header.count;
    if (header.count > 0 &&
        read_all(fd, registry->entries,
                 (size_t) header.count * sizeof(lifecycle_entry_t), true) < 0) {
        free(registry);
        return NULL;
    }
    return registry;
}

static int lifecycle_save_locked(int fd, const lifecycle_registry_t *registry)
{
    size_t disk_size;
    if (registry->count > registry->_capacity ||
        !lifecycle_registry_size(registry->count, &disk_size) ||
        disk_size > (size_t) LLONG_MAX)
        return -1;
    if (ftruncate(fd, 0) != 0 || lseek(fd, 0, SEEK_SET) != 0)
        return -1;
    return write_all(fd, registry, disk_size);
}

static int lifecycle_open_locked(char *path, size_t path_size)
{
    static _Atomic bool owner_reset_done;
    if (!lifecycle_registry_path(path, path_size))
        return -1;
    if (absock_get_namespace_id() == (uint64_t) getpid() &&
        !atomic_exchange_explicit(&owner_reset_done, true,
                                  memory_order_relaxed))
        unlink(path);
    int fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return -1;
    if (flock_retry(fd, LOCK_EX) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static lifecycle_entry_t *lifecycle_find_guest(lifecycle_registry_t *registry,
                                               int64_t guest_pid)
{
    for (uint32_t i = 0; i < registry->count; i++)
        if (registry->entries[i].guest_pid == guest_pid)
            return &registry->entries[i];
    return NULL;
}

static lifecycle_entry_t *lifecycle_upsert(lifecycle_registry_t **registry_ptr,
                                           int64_t guest_pid)
{
    lifecycle_registry_t *registry = *registry_ptr;
    lifecycle_entry_t *entry = lifecycle_find_guest(registry, guest_pid);
    if (entry)
        return entry;
    if (registry->count == registry->_capacity) {
        if (registry->_capacity > UINT32_MAX / 2)
            return NULL;
        uint32_t old_capacity = registry->_capacity;
        uint32_t new_capacity =
            old_capacity ? old_capacity * 2 : LIFECYCLE_INITIAL_CAPACITY;
        size_t new_size;
        if (!lifecycle_registry_size(new_capacity, &new_size))
            return NULL;
        lifecycle_registry_t *grown = realloc(registry, new_size);
        if (!grown)
            return NULL;
        memset(
            &grown->entries[old_capacity], 0,
            (size_t) (new_capacity - old_capacity) * sizeof(lifecycle_entry_t));
        grown->_capacity = new_capacity;
        *registry_ptr = grown;
        registry = grown;
    }
    entry = &registry->entries[registry->count++];
    memset(entry, 0, sizeof(*entry));
    entry->guest_pid = guest_pid;
    return entry;
}

static void lifecycle_unlock_close(int fd)
{
    flock_retry(fd, LOCK_UN);
    close(fd);
}

static int lifecycle_reserve_child(int64_t guest_pid,
                                   int64_t ppid,
                                   int64_t pgid)
{
    int result = -1;
    char path[PATH_MAX];
    int fd = lifecycle_open_locked(path, sizeof(path));
    if (fd < 0)
        return -1;
    lifecycle_registry_t *registry = lifecycle_load_locked(fd);
    if (registry) {
        lifecycle_entry_t *entry = lifecycle_upsert(&registry, guest_pid);
        if (entry) {
            entry->host_pid = 0;
            entry->ppid = ppid;
            entry->pgid = pgid;
            entry->subreaper = false;
            entry->exited = false;
            entry->reparent_pending = false;
            entry->rusage_valid = false;
            entry->exit_status = 0;
            memset(&entry->rusage, 0, sizeof(entry->rusage));
            result = lifecycle_save_locked(fd, registry);
        }
        free(registry);
    }
    lifecycle_unlock_close(fd);
    return result;
}

static int lifecycle_publish_child(pid_t host_pid,
                                   int64_t guest_pid,
                                   int64_t ppid,
                                   int64_t pgid)
{
    int result = -1;
    char path[PATH_MAX];
    int fd = lifecycle_open_locked(path, sizeof(path));
    if (fd < 0)
        return -1;
    lifecycle_registry_t *registry = lifecycle_load_locked(fd);
    if (registry) {
        lifecycle_entry_t *entry = lifecycle_find_guest(registry, guest_pid);
        if (entry) {
            entry->host_pid = host_pid;

            /* The reservation owns the parent/group fields, while an exit or
             * reparent transaction that won this race owns terminal state.
             */
            if (!entry->exited && !entry->reparent_pending) {
                entry->ppid = ppid;
                entry->pgid = pgid;
            }
            result = lifecycle_save_locked(fd, registry);
        }
        free(registry);
    }
    lifecycle_unlock_close(fd);
    return result;
}

static void lifecycle_publish_self(void)
{
    char path[PATH_MAX];
    int fd = lifecycle_open_locked(path, sizeof(path));
    if (fd < 0)
        return;
    lifecycle_registry_t *registry = lifecycle_load_locked(fd);
    if (registry) {
        lifecycle_entry_t *entry = lifecycle_upsert(&registry, proc_get_pid());
        if (entry) {
            entry->host_pid = getpid();

            /* A parent-exit transaction writes the authoritative adopter before
             * notifying this process. Do not let an unrelated publish from the
             * child overwrite that value with its stale local PPID while the
             * reparent control record is still pending.
             */
            if (!entry->reparent_pending)
                entry->ppid = proc_get_ppid();
            entry->pgid = proc_get_pgid();
            entry->subreaper = proc_get_child_subreaper();
            if (!entry->exited)
                entry->exit_status = 0;
            (void) lifecycle_save_locked(fd, registry);
        }
        free(registry);
    }
    lifecycle_unlock_close(fd);
}

static void lifecycle_update_pgid(int64_t guest_pid, int64_t pgid)
{
    char path[PATH_MAX];
    int fd = lifecycle_open_locked(path, sizeof(path));
    if (fd < 0)
        return;
    lifecycle_registry_t *registry = lifecycle_load_locked(fd);
    if (registry) {
        lifecycle_entry_t *entry = lifecycle_find_guest(registry, guest_pid);
        if (entry) {
            entry->pgid = pgid;
            (void) lifecycle_save_locked(fd, registry);
        }
        free(registry);
    }
    lifecycle_unlock_close(fd);
}

static bool lifecycle_query_exit(int64_t guest_pid,
                                 int *status,
                                 pid_t *host_pid,
                                 int64_t *pgid,
                                 struct rusage *rusage,
                                 bool *rusage_valid)
{
    bool exited = false;
    char path[PATH_MAX];
    int fd = lifecycle_open_locked(path, sizeof(path));
    if (fd < 0)
        return false;
    lifecycle_registry_t *registry = lifecycle_load_locked(fd);
    if (registry) {
        lifecycle_entry_t *entry = lifecycle_find_guest(registry, guest_pid);
        if (entry) {
            if (status)
                *status = entry->exit_status;
            if (host_pid)
                *host_pid = entry->host_pid;
            if (pgid)
                *pgid = entry->pgid;
            if (rusage)
                *rusage = entry->rusage;
            if (rusage_valid)
                *rusage_valid = entry->rusage_valid;
            exited = entry->exited;
        }
        free(registry);
    }
    lifecycle_unlock_close(fd);
    return exited;
}

static int lifecycle_guest_terminal_status(int64_t guest_pid, int host_status)
{
    int guest_status = host_status;
    if (lifecycle_query_exit(guest_pid, &guest_status, NULL, NULL, NULL, NULL))
        return guest_status;
    return host_status;
}

static void lifecycle_consume(int64_t guest_pid)
{
    char path[PATH_MAX];
    int fd = lifecycle_open_locked(path, sizeof(path));
    if (fd < 0)
        return;
    lifecycle_registry_t *registry = lifecycle_load_locked(fd);
    if (registry) {
        for (uint32_t i = 0; i < registry->count; i++) {
            if (registry->entries[i].guest_pid != guest_pid)
                continue;
            registry->entries[i] = registry->entries[registry->count - 1];
            registry->count--;
            (void) lifecycle_save_locked(fd, registry);
            break;
        }
        free(registry);
    }
    lifecycle_unlock_close(fd);
}

static void lifecycle_ack_reparent(int64_t guest_pid, int64_t ppid)
{
    char path[PATH_MAX];
    int fd = lifecycle_open_locked(path, sizeof(path));
    if (fd < 0)
        return;
    lifecycle_registry_t *registry = lifecycle_load_locked(fd);
    if (registry) {
        lifecycle_entry_t *entry = lifecycle_find_guest(registry, guest_pid);
        if (entry && entry->ppid == ppid && entry->reparent_pending) {
            entry->reparent_pending = false;
            (void) lifecycle_save_locked(fd, registry);
        }
        free(registry);
    }
    lifecycle_unlock_close(fd);
}

static bool lifecycle_reparent_complete(int64_t guest_pid, int64_t ppid)
{
    bool complete = false;
    char path[PATH_MAX];
    int fd = lifecycle_open_locked(path, sizeof(path));
    if (fd < 0)
        return false;
    lifecycle_registry_t *registry = lifecycle_load_locked(fd);
    if (registry) {
        lifecycle_entry_t *entry = lifecycle_find_guest(registry, guest_pid);

        /* A missing/consumed child or one that has already exited no longer
         * needs its live shim PPID cache updated.
         */
        complete = !entry || entry->exited ||
                   (entry->ppid == ppid && !entry->reparent_pending);
        free(registry);
    }
    lifecycle_unlock_close(fd);
    return complete;
}

void proc_lifecycle_sync_self(guest_t *g)
{
    int64_t ppid = -1;
    bool pending = false;
    char path[PATH_MAX];
    int fd = lifecycle_open_locked(path, sizeof(path));
    if (fd < 0)
        return;
    lifecycle_registry_t *registry = lifecycle_load_locked(fd);
    if (registry) {
        lifecycle_entry_t *entry =
            lifecycle_find_guest(registry, proc_get_pid());
        if (entry) {
            ppid = entry->ppid;
            pending = entry->reparent_pending;
        }
        free(registry);
    }
    lifecycle_unlock_close(fd);

    if (ppid <= 0)
        return;
    proc_set_ppid(ppid);
    shim_globals_publish_pid(g, proc_get_pid(), ppid);
    if (pending)
        lifecycle_ack_reparent(proc_get_pid(), ppid);
}

static void proc_register_adopted_local(const lifecycle_entry_t *source)
{
    bool registered = false;
    pthread_mutex_lock(&pid_lock);
    proc_entry_t *entry = proc_find_guest_entry(source->guest_pid);
    if (entry && entry->host_waitable) {
        /* proc_process_exit() publishes the status and raises SIGCHLD while the
         * host process is still tearing down, so wait4 reports "running" for a
         * moment after the guest was told the child is gone, a skew Linux never
         * has. Copy the status across so a WNOHANG poll from the handler cannot
         * miss it; proc_deferred_reap_poll() does the host reap later so
         * nothing blocks here.
         */
        if (source->exited && !entry->exited) {
            entry->exited = true;
            entry->exit_status = source->exit_status;
            entry->rusage = source->rusage;
            entry->rusage_valid = source->rusage_valid;
            entry->host_reap_pending = true;
            pthread_cond_broadcast(&pid_cond);
        }
        pthread_mutex_unlock(&pid_lock);
        if (source->exited)
            proc_pidfd_notify_exit(source->guest_pid);
        return;
    }

    /* A direct child is visible in the lifecycle registry before its local
     * admission transaction commits. The registry's host PID may already have
     * been published while the local slot is still reserved, so checking only
     * source->host_pid would leave a second race window. The reserved slot is
     * authoritative: proc_register_child() will commit this same PID shortly.
     */
    if (proc_find_reserved_guest_entry(source->guest_pid)) {
        pthread_mutex_unlock(&pid_lock);
        return;
    }
    if (!entry)
        entry = proc_find_free_entry();
    if (entry) {
        if (!entry->active)
            proc_init_child_entry(entry, source->host_pid, source->guest_pid,
                                  source->pgid);
        entry->host_pid = source->host_pid;
        entry->pgid = source->pgid;
        entry->host_waitable = false;
        if (source->exited) {
            entry->exited = true;
            entry->exit_status = source->exit_status;
            entry->rusage = source->rusage;
            entry->rusage_valid = source->rusage_valid;
            pthread_cond_broadcast(&pid_cond);
        }
        registered = true;
    } else {
        /* Both tables grow geometrically, so an adopted child should acquire a
         * local slot unless the host cannot allocate memory. Keep its shared
         * lifecycle record intact and report the failure rather than silently
         * losing wait ownership; a later import may succeed after memory
         * pressure subsides.
         */
        log_error(
            "cannot grow process table while importing adopted child "
            "PID %lld",
            (long long) source->guest_pid);
    }
    pthread_mutex_unlock(&pid_lock);
    if (registered && source->exited)
        proc_pidfd_notify_exit(source->guest_pid);
}

static void lifecycle_import_children(void)
{
    char path[PATH_MAX];
    int fd = lifecycle_open_locked(path, sizeof(path));
    if (fd < 0)
        return;
    lifecycle_registry_t *registry = lifecycle_load_locked(fd);
    if (registry) {
        int64_t self = proc_get_pid();
        for (uint32_t i = 0; i < registry->count; i++) {
            lifecycle_entry_t *entry = &registry->entries[i];

            /* host_pid==0 is a pre-spawn reservation, not a live or waitable
             * child. The local reserved-slot check in
             * proc_register_adopted_local() also closes the later window after
             * lifecycle_publish_child() but before local admission commit.
             */
            if (entry->host_pid > 0 && entry->guest_pid != self &&
                entry->ppid == self)
                proc_register_adopted_local(entry);
        }
        free(registry);
    }
    lifecycle_unlock_close(fd);
}

static void proc_registry_reset_if_owner(const char *path)
{
    static _Atomic bool reset_done;
    if (absock_get_namespace_id() != (uint64_t) getpid())
        return;
    if (atomic_exchange_explicit(&reset_done, true, memory_order_relaxed))
        return;
    unlink(path);
}

/* One live member of a process group registry. */
typedef struct {
    pid_t host_pid;
    int64_t guest_pid;
    int64_t pgid;
} registry_entry_t;

#define REGISTRY_MAX_ENTRIES 4096

/* flock() retrying past EINTR. Returns 0 on success, -1 on failure. */
static int flock_retry(int fd, int op)
{
    int r;
    do {
        r = flock(fd, op);
    } while (r != 0 && errno == EINTR);
    return r;
}

/* Read @fd from its current offset and invoke @cb once per newline-terminated
 * record, passing a NUL-terminated copy. Records must fit in 159 bytes; both
 * the registry ("hostpid guestpid pgid") and signal/control transport records
 * use bounded numeric lines. Overlong records and an unterminated trailing
 * token are dropped -- every writer appends a whole record under an exclusive
 * lock, so a partial line only appears after a crash mid-write.
 */
static void for_each_record(int fd, void (*cb)(char *rec, void *ctx), void *ctx)
{
    char chunk[8192];
    char line[160];
    size_t linelen = 0;
    bool overlong = false;
    ssize_t r;
    while ((r = read(fd, chunk, sizeof(chunk))) > 0) {
        for (ssize_t i = 0; i < r; i++) {
            char c = chunk[i];
            if (c != '\n') {
                if (linelen < sizeof(line) - 1)
                    line[linelen++] = c;
                else
                    overlong = true;
                continue;
            }
            if (!overlong) {
                line[linelen] = '\0';
                cb(line, ctx);
            }
            linelen = 0;
            overlong = false;
        }
    }
}

typedef struct {
    registry_entry_t *entries;
    int max;
    int n;
    bool truncated;
} registry_parse_ctx_t;

/* Upsert one "hostpid guestpid pgid" record, keeping the latest guest_pid/pgid
 * per LIVE host pid. Dead, malformed, and out-of-range records are dropped.
 */
static void registry_parse_cb(char *rec, void *vctx)
{
    registry_parse_ctx_t *c = vctx;
    long hp;
    long long gp, pg;
    if (sscanf(rec, "%ld %lld %lld", &hp, &gp, &pg) != 3)
        return;
    if (hp <= 0 || hp > INT_MAX || pg < 0 || pg > INT_MAX)
        return;
    if (kill((pid_t) hp, 0) != 0)
        return;
    int idx = -1;
    for (int k = 0; k < c->n; k++)
        if (c->entries[k].host_pid == (pid_t) hp) {
            idx = k;
            break;
        }
    if (idx < 0) {
        if (c->n == c->max) {
            c->truncated = true;
            return;
        }
        idx = c->n++;
        c->entries[idx].host_pid = (pid_t) hp;
    }
    c->entries[idx].guest_pid = (int64_t) gp;
    c->entries[idx].pgid = (int64_t) pg;
}

typedef struct {
    pid_t target;
    int64_t guest_pid;
    bool found;
} registry_find_ctx_t;

/* Locate @target's guest pid without registry_parse_cb's per-record kill(2)
 * liveness probe: that check exists to build a filtered live- membership list
 * for group-signal delivery, but a host_pid ->guest_pid lookup is only ever
 * done for a pid the caller just observed to be alive (e.g. it holds a
 * conflicting file lock right now), so it is redundant here.
 * proc_host_to_guest_pid still verifies the match via proc_pidpath to guard
 * against the pid having been recycled.
 */
static void registry_find_by_host_cb(char *rec, void *vctx)
{
    registry_find_ctx_t *c = vctx;
    long hp;
    long long gp, pg;
    if (sscanf(rec, "%ld %lld %lld", &hp, &gp, &pg) != 3)
        return;
    if (hp <= 0 || hp > INT_MAX || pg < 0 || pg > INT_MAX)
        return;
    if ((pid_t) hp != c->target)
        return;
    c->guest_pid = (int64_t) gp;
    c->found = true;
}

/* Parse the whole registry from @fd (caller holds an flock) into @entries,
 * keeping one record per live host pid.
 *
 * Returns the count. @truncated_out, if non-NULL, is set true when the entry
 * array filled up.
 */
static int registry_read_locked(int fd,
                                registry_entry_t *entries,
                                int max,
                                bool *truncated_out)
{
    if (truncated_out)
        *truncated_out = false;
    if (lseek(fd, 0, SEEK_SET) != 0)
        return 0;
    registry_parse_ctx_t ctx = {.entries = entries, .max = max};
    for_each_record(fd, registry_parse_cb, &ctx);
    if (truncated_out)
        *truncated_out = ctx.truncated;
    return ctx.n;
}

/* Publish (host_pid, guest_pid, pgid), compacting the registry in place: read
 * the live set under LOCK_EX, upsert this entry, and rewrite so the file stays
 * bounded by the number of live group members rather than growing per event.
 */
static void proc_registry_publish(pid_t host_pid,
                                  int64_t guest_pid_val,
                                  int64_t pgid)
{
    char path[PATH_MAX];
    if (!process_registry_path(path, sizeof(path)))
        return;
    proc_registry_reset_if_owner(path);
    int fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return;
    if (flock_retry(fd, LOCK_EX) != 0) {
        close(fd);
        return;
    }

    registry_entry_t entries[REGISTRY_MAX_ENTRIES];
    int n = registry_read_locked(fd, entries, REGISTRY_MAX_ENTRIES, NULL);
    int idx = -1;
    for (int i = 0; i < n; i++)
        if (entries[i].host_pid == host_pid) {
            idx = i;
            break;
        }
    if (idx < 0) {
        if (n == REGISTRY_MAX_ENTRIES)

            /* No slot for a new live member: group signals (kill(-1),
             * kill(-pgid), kill(0)) reaching this pid via the registry will
             * miss it. Warn rather than drop silently.
             */
            log_warn(
                "process registry full (%d live members); host pid %ld not "
                "published, group signals may miss it",
                REGISTRY_MAX_ENTRIES, (long) host_pid);
        else {
            idx = n++;
            entries[idx].host_pid = host_pid;
        }
    }
    if (idx >= 0) {
        entries[idx].guest_pid = guest_pid_val;
        entries[idx].pgid = pgid;
    }

    if (ftruncate(fd, 0) == 0 && lseek(fd, 0, SEEK_SET) == 0) {
        for (int i = 0; i < n; i++) {
            char lineb[64];
            int len = snprintf(lineb, sizeof(lineb), "%ld %lld %lld\n",
                               (long) entries[i].host_pid,
                               (long long) entries[i].guest_pid,
                               (long long) entries[i].pgid);
            if (len > 0 && (size_t) len < sizeof(lineb) &&
                write_all(fd, lineb, (size_t) len) < 0)
                break;
        }
    }
    flock_retry(fd, LOCK_UN);
    close(fd);
}

void proc_registry_publish_self(void)
{
    proc_registry_publish(getpid(), proc_get_pid(), proc_get_pgid());
    lifecycle_publish_self();
}

void proc_registry_sync_self_pgid(guest_t *g)
{
    char path[PATH_MAX];
    if (!process_registry_path(path, sizeof(path)))
        return;
    proc_registry_reset_if_owner(path);
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return;
    if (flock_retry(fd, LOCK_SH) != 0) {
        close(fd);
        return;
    }
    registry_entry_t entries[REGISTRY_MAX_ENTRIES];
    int n = registry_read_locked(fd, entries, REGISTRY_MAX_ENTRIES, NULL);
    flock_retry(fd, LOCK_UN);
    close(fd);

    pid_t self = getpid();
    int64_t self_guest = proc_get_pid();
    for (int i = 0; i < n; i++)

        /* Match host pid AND guest pid: a stale same-host-pid record left by a
         * recycled pid must not overwrite this process's group.
         */
        if (entries[i].host_pid == self && entries[i].guest_pid == self_guest) {
            if (entries[i].pgid != proc_get_pgid())
                proc_set_pgid_from_registry(g, entries[i].pgid);
            return;
        }
}

/* Path of this elfuse binary, cached. All elfuse processes run the same
 * executable, so the value is process-independent and safe to keep across fork.
 */
static char elfuse_self_path_buf[PROC_PIDPATHINFO_MAXSIZE];
static int elfuse_self_path_len;
static pthread_once_t elfuse_self_path_once = PTHREAD_ONCE_INIT;

static void elfuse_self_path_init(void)
{
    int l = proc_pidpath(getpid(), elfuse_self_path_buf,
                         sizeof(elfuse_self_path_buf));
    elfuse_self_path_len = (l > 0) ? l : 0;
}

static const char *elfuse_self_path(int *len_out)
{
    pthread_once(&elfuse_self_path_once, elfuse_self_path_init);
    *len_out = elfuse_self_path_len;
    return elfuse_self_path_buf;
}

/* Open the signal-transport file of another elfuse process for append.
 *
 * Refuses a host pid that is not (or is no longer) an elfuse process: if it was
 * recycled onto an unrelated program, a raw SIGUSR2 would terminate it. A
 * sub-microsecond exit and pid reuse between this check and the kill() the
 * caller issues still lands the signal on the wrong process.
 *
 * Sets errno and returns -1 on every failure, so the callers report it as their
 * own.
 */
static int proc_open_transport(pid_t host_pid)
{
    int our_len;
    const char *our_path = elfuse_self_path(&our_len);
    char tpath[PROC_PIDPATHINFO_MAXSIZE];
    int tlen = proc_pidpath(host_pid, tpath, sizeof(tpath));
    if (our_len <= 0 || tlen != our_len ||
        memcmp(tpath, our_path, our_len) != 0) {
        errno = ESRCH;
        return -1;
    }

    char path[PATH_MAX];
    if (!signal_transport_path(path, sizeof(path), host_pid)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return open(path, O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC | O_NOFOLLOW,
                0600);
}

int proc_send_guest_signal(pid_t host_pid, int64_t target_guest_pid, int signum)
{
    int fd = proc_open_transport(host_pid);
    if (fd < 0)
        return -1;

    /* Tag the delivery with our fork-family namespace and the intended guest
     * pid. A recycled host pid in another session sees a mismatched namespace;
     * a host pid recycled onto a different guest inside this same session sees
     * a mismatched guest pid. Either mismatch drops the signal instead of
     * applying it to the wrong process.
     */
    char line[64];
    int len = snprintf(line, sizeof(line), "%llu %lld %d\n",
                       (unsigned long long) absock_get_namespace_id(),
                       (long long) target_guest_pid, signum);
    if (len < 0 || (size_t) len >= sizeof(line)) {
        close(fd);
        errno = EINVAL;
        return -1;
    }

    /* Serialize the append against the receiver's read+truncate drain via an
     * exclusive lock. The receiver holds the same lock and never unlinks the
     * file, so this append either lands before its read (and is consumed) or
     * after its truncate (and the SIGUSR2 below triggers the next drain).
     * Neither side can route this write to an orphaned inode or discard it.
     */
    if (flock_retry(fd, LOCK_EX) != 0) {
        close(fd);
        return -1;
    }
    int wrc = write_all(fd, line, (size_t) len);
    flock_retry(fd, LOCK_UN);
    if (wrc < 0) {
        close(fd);
        return -1;
    }

    /* The line is durably appended under the lock, so ring the doorbell even if
     * close() reports an error; suppressing the kill would leave the queued
     * line waiting for some later unrelated signal.
     */
    close(fd);
    return kill(host_pid, SIGUSR2);
}

void proc_process_exit(int wait_status)
{
    struct rusage self_rusage;
    bool self_rusage_valid = getrusage(RUSAGE_SELF, &self_rusage) == 0;
    char path[PATH_MAX];
    int fd = lifecycle_open_locked(path, sizeof(path));
    if (fd < 0) {
        /* The direct-parent notification still improves SIGCHLD timing if the
         * lifecycle registry is unavailable.
         */
        int64_t parent_guest_pid = proc_get_ppid();
        pid_t parent_host_pid = getppid();
        if (parent_guest_pid > 0 && parent_host_pid > 1)
            (void) proc_send_guest_signal(parent_host_pid, parent_guest_pid,
                                          LINUX_SIGCHLD);
        return;
    }

    lifecycle_registry_t *registry = lifecycle_load_locked(fd);
    if (!registry) {
        lifecycle_unlock_close(fd);
        return;
    }

    int64_t self_pid = proc_get_pid();
    lifecycle_entry_t *self = lifecycle_upsert(&registry, self_pid);
    if (!self) {
        free(registry);
        lifecycle_unlock_close(fd);
        return;
    }
    self->host_pid = getpid();
    if (self->ppid <= 0)
        self->ppid = proc_get_ppid();
    self->pgid = proc_get_pgid();
    self->subreaper = proc_get_child_subreaper();
    self->exited = true;
    self->exit_status = wait_status;
    self->rusage_valid = self_rusage_valid;
    if (self_rusage_valid)
        self->rusage = self_rusage;

    /* Linux adopts descendants at the nearest living subreaper, otherwise at
     * namespace PID 1. Walk the registry's guest-parent chain while holding the
     * namespace lock so concurrent exits cannot produce a split decision.
     */
    int64_t adopter_pid = -1;
    int64_t ancestor = self->ppid;
    for (uint32_t depth = 0; depth < registry->count && ancestor > 0; depth++) {
        lifecycle_entry_t *candidate = lifecycle_find_guest(registry, ancestor);
        if (!candidate)
            break;
        if (!candidate->exited && candidate->subreaper) {
            adopter_pid = candidate->guest_pid;
            break;
        }
        if (candidate->guest_pid == 1)
            break;
        ancestor = candidate->ppid;
    }
    if (adopter_pid < 0) {
        lifecycle_entry_t *init = lifecycle_find_guest(registry, 1);
        if (init && !init->exited)
            adopter_pid = 1;
    }
    pid_t adopter_host_pid = -1;
    lifecycle_entry_t *adopter = lifecycle_find_guest(registry, adopter_pid);
    if (adopter && !adopter->exited)
        adopter_host_pid = adopter->host_pid;

    lifecycle_entry_t *reparented =
        calloc(registry->count ? registry->count : 1, sizeof(*reparented));
    uint32_t nreparented = 0;
    if (adopter_pid > 0 && reparented) {
        for (uint32_t i = 0; i < registry->count; i++) {
            lifecycle_entry_t *child = &registry->entries[i];
            if (child->guest_pid == self_pid || child->ppid != self_pid)
                continue;
            child->ppid = adopter_pid;
            child->reparent_pending = !child->exited;
            reparented[nreparented++] = *child;
        }
    }

    pid_t parent_host_pid = -1;
    int64_t parent_guest_pid = self->ppid;
    lifecycle_entry_t *parent =
        lifecycle_find_guest(registry, parent_guest_pid);
    if (parent && !parent->exited)
        parent_host_pid = parent->host_pid;

    (void) lifecycle_save_locked(fd, registry);
    free(registry);
    lifecycle_unlock_close(fd);

    for (uint32_t i = 0; reparented && i < nreparented; i++) {
        if (reparented[i].exited) {
            /* The exiting process is not necessarily a child of the adopter, so
             * its own SIGCHLD goes elsewhere. Notify the adopter explicitly for
             * every already-terminal child that became waitable there.
             */
            if (adopter_host_pid > 0)
                (void) proc_send_guest_signal(adopter_host_pid, adopter_pid,
                                              LINUX_SIGCHLD);
        } else {
            proc_notify_reparent(reparented[i].host_pid,
                                 reparented[i].guest_pid, adopter_pid);
        }
    }
    free(reparented);

    if (parent_host_pid > 0)
        (void) proc_send_guest_signal(parent_host_pid, parent_guest_pid,
                                      LINUX_SIGCHLD);
}

static int proc_send_reparent(pid_t host_pid,
                              int64_t target_guest_pid,
                              int64_t new_ppid)
{
    int fd = proc_open_transport(host_pid);
    if (fd < 0)
        return -1;

    char line[128];
    int len = snprintf(line, sizeof(line), "R %llu %lld %lld\n",
                       (unsigned long long) absock_get_namespace_id(),
                       (long long) target_guest_pid, (long long) new_ppid);
    if (len < 0 || (size_t) len >= sizeof(line)) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    if (flock_retry(fd, LOCK_EX) != 0) {
        close(fd);
        return -1;
    }
    int wrc = write_all(fd, line, (size_t) len);
    flock_retry(fd, LOCK_UN);
    close(fd);
    if (wrc < 0)
        return -1;
    return kill(host_pid, SIGUSR2);
}

static void proc_notify_reparent(pid_t host_pid,
                                 int64_t target_guest_pid,
                                 int64_t new_ppid)
{
    int last_error = 0;

    /* SIGUSR2 is a standard signal, so multiple doorbells can coalesce. The
     * file record remains durable, but a process exiting immediately after one
     * successful kill must not assume the receiver already updated its shim
     * identity cache. Retry until the child acknowledges the registry's pending
     * transaction, with a bounded 50ms exit-path delay.
     */
    for (int attempt = 0; attempt < 20; attempt++) {
        if (lifecycle_reparent_complete(target_guest_pid, new_ppid))
            return;
        if (proc_send_reparent(host_pid, target_guest_pid, new_ppid) < 0)
            last_error = errno;
        usleep(2500);
    }

    if (!lifecycle_reparent_complete(target_guest_pid, new_ppid)) {
        if (last_error)
            log_warn("reparent notification to guest pid %lld failed: %s",
                     (long long) target_guest_pid, strerror(last_error));
        else
            log_warn("guest pid %lld did not acknowledge reparent to %lld",
                     (long long) target_guest_pid, (long long) new_ppid);
    }
}

int proc_get_direct_child_pids(pid_t *out, int max_pids)
{
    int count = 0;
    pthread_mutex_lock(&pid_lock);
    for (size_t i = 0; i < proc_table_capacity && count < max_pids; i++) {
        if (proc_table[i].active && !proc_table[i].exited)
            out[count++] = proc_table[i].host_pid;
    }
    pthread_mutex_unlock(&pid_lock);
    return count;
}

int proc_set_child_pgid(int64_t guest_pid_val, int64_t pgid)
{
    int ret = -1;
    pid_t host_pid = -1;
    pthread_mutex_lock(&pid_lock);
    proc_entry_t *entry = proc_find_guest_entry(guest_pid_val);
    if (entry) {
        entry->pgid = pgid;
        host_pid = entry->host_pid;
        ret = 0;
    }
    pthread_mutex_unlock(&pid_lock);
    if (host_pid > 0)
        proc_registry_publish(host_pid, guest_pid_val, pgid);
    if (host_pid > 0)
        lifecycle_update_pgid(guest_pid_val, pgid);
    return ret;
}

int proc_get_namespace_targets(proc_signal_target_t *out,
                               int max,
                               int64_t pgid_filter)
{
    /* No republish here: every group change already publishes (fork, setpgid,
     * setsid), and this reader excludes its own entry anyway.
     */
    char path[PATH_MAX];
    if (!process_registry_path(path, sizeof(path)))
        return 0;
    proc_registry_reset_if_owner(path);
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return 0;
    if (flock_retry(fd, LOCK_SH) != 0) {
        close(fd);
        return 0;
    }
    registry_entry_t entries[REGISTRY_MAX_ENTRIES];
    bool truncated = false;
    int nentries =
        registry_read_locked(fd, entries, REGISTRY_MAX_ENTRIES, &truncated);
    flock_retry(fd, LOCK_UN);
    close(fd);
    if (truncated)
        log_warn(
            "process-group registry exceeded %d live members; group "
            "signal delivery may be partial",
            REGISTRY_MAX_ENTRIES);

    int count = 0;
    pid_t self = getpid();
    char our_path[PROC_PIDPATHINFO_MAXSIZE];
    int our_len = proc_pidpath(self, our_path, sizeof(our_path));
    if (our_len <= 0)
        return 0;
    for (int i = 0; i < nentries && count < max; i++) {
        if (entries[i].host_pid == self)
            continue;
        if (pgid_filter != PROC_PGID_ANY && entries[i].pgid != pgid_filter)
            continue;
        char ppath[PROC_PIDPATHINFO_MAXSIZE];
        int plen = proc_pidpath(entries[i].host_pid, ppath, sizeof(ppath));
        if (plen != our_len || memcmp(ppath, our_path, (size_t) our_len))
            continue;
        out[count].host_pid = entries[i].host_pid;
        out[count].guest_pid = entries[i].guest_pid;
        count++;
    }
    return count;
}

int64_t proc_host_to_guest_pid(pid_t host_pid)
{
    pthread_mutex_lock(&pid_lock);
    proc_entry_t *entry = proc_find_host_entry(host_pid);
    int64_t result = entry ? entry->guest_pid : -1;
    pthread_mutex_unlock(&pid_lock);
    if (result != -1)
        return result;

    char path[PATH_MAX];
    if (!process_registry_path(path, sizeof(path)))
        return -1;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (flock_retry(fd, LOCK_SH) != 0) {
        close(fd);
        return -1;
    }
    registry_find_ctx_t ctx = {.target = host_pid};
    for_each_record(fd, registry_find_by_host_cb, &ctx);
    flock_retry(fd, LOCK_UN);
    close(fd);
    if (!ctx.found)
        return -1;

    /* Guard against host pid reuse: only trust the hit if the pid still runs
     * this elfuse binary, same check as proc_get_namespace_targets.
     */
    char our_path[PROC_PIDPATHINFO_MAXSIZE];
    int our_len = proc_pidpath(getpid(), our_path, sizeof(our_path));
    if (our_len <= 0)
        return -1;
    char ppath[PROC_PIDPATHINFO_MAXSIZE];
    int plen = proc_pidpath(host_pid, ppath, sizeof(ppath));
    if (plen != our_len || memcmp(ppath, our_path, (size_t) our_len))
        return -1;
    return ctx.guest_pid;
}

int proc_get_child_pids(pid_t *out, int max_pids)
{
    /* Seed with direct children from the process table */
    int count = proc_get_direct_child_pids(out, max_pids);

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
        target->tracer_tid = thread_tid(current_thread);
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
         *
         * Kick the tracee under thread_lock, not after releasing it: the tracee
         * destroys its own vCPU under the same lock on exit, so snapshotting
         * the handle and calling hv_vcpus_exit outside the lock could hand HVF
         * a freed vCPU. Holding the lock across the kick serializes it against
         * destruction; the kick does not block, so this is safe.
         */
        pthread_mutex_t *tlock = thread_get_lock();
        pthread_mutex_lock(tlock);
        thread_entry_t *target = thread_find_locked(pid);
        if (!target || !target->ptraced) {
            pthread_mutex_unlock(tlock);
            return -LINUX_ESRCH;
        }
        if (target->ptrace_stopped) {
            pthread_mutex_unlock(tlock);
            return 0; /* Already stopped */
        }

        /* Record the stop as owed in every case, then kick. The flag used to
         * mean only "the vCPU was still in bring-up, so hv_vcpus_exit could not
         * reach it"; it now means "a stop is owed", because the kick alone was
         * never sufficient. It can land while the tracee sits at EL1 in a shim
         * fast path, and stopping there snapshots shim scratch as the guest's
         * registers (thread_ptrace_stop reads the live set) and discards
         * whatever the tracer writes back, since the shim restores its own
         * frame over it. The HVC #5 epilogue consumes the flag and then either
         * stops right there, on the tails whose live registers are already the
         * final EL0 set, or asks the shim through X7 to restore the frame and
         * come back at HVC #13. The canceled-exit handler consumes it once it
         * has established the vCPU is at EL0.
         *
         * Attention goes up before the kick, the same order
         * shim_globals_raise_attention uses and for the same reason: a fast
         * path that has already tested it must not be the one that decides. It
         * is what stops a tracee interrupted at EL1 from ERETing to EL0 and
         * computing indefinitely with the stop still owed.
         *
         * Bring-up keeps its own arm of this: a vCPU with no published handle
         * cannot be kicked, and the worker self-kicks at publish. Both run
         * under thread_lock, so exactly one of them delivers.
         */
        target->ptrace_interrupt_pending = true;
        shim_globals_ptrace_attention(g, true);
        if (target->vcpu_valid)
            hv_vcpus_exit(&target->vcpu, 1);
        pthread_mutex_unlock(tlock);
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

int write_rusage_to_guest(guest_t *g, uint64_t gva, const struct rusage *ru)
{
    linux_rusage_t lru;
    memcpy(&lru, ru, sizeof(lru));
    lru.ru_maxrss = ru->ru_maxrss / 1024; /* macOS: bytes -> Linux: KB */
    return guest_write_small(g, gva, &lru, sizeof(lru));
}

/* Deactivate the wait4 process-table entry for @host_pid, iff one still exists
 * AND still belongs to @expect_guest_pid. Looks the entry up by host_pid rather
 * than taking a slot index: callers release pid_lock across the host wait4
 * call, and proc_table itself can be freed and replaced with the small static
 * initial buffer in that window (proc_find_free_entry shrinks it back once
 * every entry is idle, which a sibling reaper finishing during this call's own
 * unlocked wait4 can trigger). A slot index captured before the unlock is not
 * just possibly stale, as the host_pid re-check already accounted for: it can
 * be out of bounds for the table proc_table now points to. Looking up by
 * host_pid sidesteps that regardless of how proc_table_capacity has moved.
 *
 * host_pid alone is not enough to identify the right entry, though: the host OS
 * can reuse a pid number the moment wait4 reaps it, so a second guest fork
 * admitted on another thread during this same unlocked window can land a brand
 * new, unrelated child in a table slot under the exact pid this call is trying
 * to deactivate. Hence the lookup on the pair, whose guest_pid half is what the
 * caller captured from the SAME entry before releasing the lock; see
 * proc_find_host_guest_entry for why the pair has to be one scan rather than a
 * check bolted onto a host_pid hit.
 */
static void proc_deactivate_slot_if_matches(pid_t host_pid,
                                            int64_t expect_guest_pid)
{
    int64_t guest_pid = -1;
    pthread_mutex_lock(&pid_lock);
    proc_entry_t *entry =
        proc_find_host_guest_entry(host_pid, expect_guest_pid);
    if (entry) {
        guest_pid = entry->guest_pid;
        entry->active = false;
    }
    pthread_mutex_unlock(&pid_lock);
    if (guest_pid > 0)
        lifecycle_consume(guest_pid);
}

static bool proc_refresh_external_child(int64_t guest_pid)
{
    int status = 0;
    pid_t host_pid = -1;
    int64_t pgid = 0;
    struct rusage rusage;
    bool rusage_valid = false;
    bool exited = lifecycle_query_exit(guest_pid, &status, &host_pid, &pgid,
                                       &rusage, &rusage_valid);
    if (!exited)
        return false;

    pthread_mutex_lock(&pid_lock);
    proc_entry_t *entry = proc_find_guest_entry(guest_pid);
    if (entry && !entry->host_waitable) {
        entry->host_pid = host_pid;
        entry->pgid = pgid;
        entry->exited = true;
        entry->exit_status = status;
        entry->rusage = rusage;
        entry->rusage_valid = rusage_valid;
        pthread_cond_broadcast(&pid_cond);
    }
    pthread_mutex_unlock(&pid_lock);
    proc_pidfd_notify_exit(guest_pid);
    return true;
}

static void proc_account_entry_locked(proc_entry_t *entry)
{
    if (entry->rusage_valid && !entry->rusage_accounted) {
        proc_children_cpu_add(&entry->rusage);
        entry->rusage_accounted = true;
    }
}

void proc_autoreap_exited_children(void)
{
    /* The signal-drain thread and a guest rt_sigaction thread can both enter
     * here while SIGCHLD is transitioning away from an auto-reap disposition.
     * Serialize the whole host-reap/local-deactivate/registry-consume sequence
     * so rt_sigaction cannot return while another reaper has consumed the
     * shared lifecycle entry but still exposes the local wait slot.
     */
    pthread_mutex_lock(&autoreap_lock);

    /* Adopted descendants may not have a local table slot until their new
     * parent performs a wait. Import them first so an explicit no-zombie
     * disposition applies equally to direct and adopted children.
     */
    lifecycle_import_children();

    for (size_t i = 0;; i++) {
        pthread_mutex_lock(&pid_lock);
        if (i >= proc_table_capacity) {
            pthread_mutex_unlock(&pid_lock);
            break;
        }
        if (!proc_table[i].active) {
            pthread_mutex_unlock(&pid_lock);
            continue;
        }
        int64_t guest_pid = proc_table[i].guest_pid;
        pid_t host_pid = proc_table[i].host_pid;
        bool host_waitable = proc_table[i].host_waitable;
        pthread_mutex_unlock(&pid_lock);

        if (!lifecycle_query_exit(guest_pid, NULL, NULL, NULL, NULL, NULL))
            continue;

        if (!host_waitable) {
            pthread_mutex_lock(&pid_lock);
            proc_entry_t *entry = proc_find_guest_entry(guest_pid);
            if (entry && !entry->host_waitable)
                entry->active = false;
            pthread_mutex_unlock(&pid_lock);
            lifecycle_consume(guest_pid);
            proc_pidfd_notify_exit(guest_pid);
            continue;
        }

        int status = 0;
        struct rusage ru;
        pid_t ret;
        do {
            ret = wait4(host_pid, &status, 0, &ru);
        } while (ret < 0 && errno == EINTR);
        if (ret == host_pid) {
            proc_children_cpu_add(&ru);
            proc_pidfd_notify_exit(guest_pid);
            proc_deactivate_slot_if_matches(host_pid, guest_pid);
        } else if (ret < 0 && errno == ECHILD) {
            /* A concurrent consuming wait won the host reap. The disposition
             * still makes this child non-waitable to subsequent guest waits.
             */
            proc_deactivate_slot_if_matches(host_pid, guest_pid);
        }
    }

    pthread_mutex_unlock(&autoreap_lock);
}

static bool proc_wait_selector_matches(const proc_entry_t *entry,
                                       int pid,
                                       int64_t caller_pgid)
{
    if (!entry->active)
        return false;
    if (pid == -1)
        return true;
    if (pid > 0)
        return entry->guest_pid == pid;

    int64_t target_pgid = pid == 0 ? caller_pgid : -(int64_t) pid;
    return entry->pgid == target_pgid;
}

static int64_t proc_wait_autoreap_children(int pid, int options)
{
    int64_t caller_pgid = proc_get_pgid();
    unsigned backoff = 0;
    for (;;) {
        bool found = false;
        bool still_active = false;

        pthread_mutex_lock(&pid_lock);
        for (size_t i = 0; i < proc_table_capacity; i++) {
            if (!proc_wait_selector_matches(&proc_table[i], pid, caller_pgid))
                continue;
            found = true;
            if (proc_table[i].exited) {
                int64_t guest_pid = proc_table[i].guest_pid;
                proc_account_entry_locked(&proc_table[i]);
                proc_table[i].active = false;
                pthread_mutex_unlock(&pid_lock);
                lifecycle_consume(guest_pid);
                pthread_mutex_lock(&pid_lock);
                continue;
            }

            if (!proc_table[i].host_waitable) {
                int64_t guest_pid = proc_table[i].guest_pid;
                pthread_mutex_unlock(&pid_lock);
                bool exited = proc_refresh_external_child(guest_pid);
                pthread_mutex_lock(&pid_lock);
                proc_entry_t *entry = proc_find_guest_entry(guest_pid);
                if (exited && entry && entry->exited) {
                    proc_account_entry_locked(entry);
                    entry->active = false;
                    pthread_mutex_unlock(&pid_lock);
                    lifecycle_consume(guest_pid);
                    pthread_mutex_lock(&pid_lock);
                } else if (entry) {
                    still_active = true;
                }
                continue;
            }

            pid_t host_pid = proc_table[i].host_pid;
            int64_t guest_pid = proc_table[i].guest_pid;
            pthread_mutex_unlock(&pid_lock);
            int status = 0;
            struct rusage ru;
            pid_t ret = wait4(host_pid, &status, WNOHANG, &ru);
            pthread_mutex_lock(&pid_lock);
            if (ret == host_pid) {
                proc_children_cpu_add(&ru);

                /* Paired lookup: the host OS can reuse host_pid the moment
                 * wait4 reaps it, so a second guest fork admitted on another
                 * thread during this unlocked window could otherwise match an
                 * unrelated child that landed under this same host_pid.
                 */
                proc_entry_t *entry =
                    proc_find_host_guest_entry(host_pid, guest_pid);
                if (entry)
                    entry->active = false;
                pthread_mutex_unlock(&pid_lock);
                lifecycle_consume(guest_pid);
                pthread_mutex_lock(&pid_lock);
            } else if (ret == 0) {
                still_active = true;
            } else {
                proc_entry_t *entry =
                    proc_find_host_guest_entry(host_pid, guest_pid);
                if (entry)
                    entry->active = false;
            }
        }
        pthread_mutex_unlock(&pid_lock);

        if (!found || !still_active)
            return -LINUX_ECHILD;
        if (options & 1) /* WNOHANG */
            return 0;

        int64_t wait_rc = io_retry_backoff(&backoff);
        if (wait_rc < 0) {
            syscall_restart_forbid();
            return wait_rc;
        }
    }
}

/* sys_wait4. */

/* Reap host children whose terminal status the guest already consumed from the
 * lifecycle registry. Their exit was published before the host process finished
 * tearing down, so wait4() had nothing to collect at the time; collecting it
 * later keeps a zombie from being stranded without making any wait path block.
 */
static void proc_deferred_reap_poll(void)
{
    pthread_mutex_lock(&pid_lock);
    for (size_t i = 0; i < proc_table_capacity; i++) {
        if (!proc_table[i].host_reap_pending)
            continue;
        pid_t host_pid = proc_table[i].host_pid;
        int64_t guest_pid = proc_table[i].guest_pid;
        if (host_pid <= 0) {
            proc_table[i].host_reap_pending = false;
            continue;
        }
        pthread_mutex_unlock(&pid_lock);
        int st;
        pid_t r = wait4(host_pid, &st, WNOHANG, NULL);
        pthread_mutex_lock(&pid_lock);

        /* Only clear the flag once the zombie is gone (r > 0) or the child is
         * no longer ours to reap (r < 0, typically ECHILD). The guest_pid check
         * guards against host_pid reuse: the host OS can hand this exact pid to
         * a brand new process the instant wait4 above reaps it, and a second
         * guest fork admitted on another thread during this unlocked window
         * could land that new child in slot i under the same host_pid. Clearing
         * host_reap_pending for it instead of (or in addition to) the original
         * entry would strand a real pending zombie.
         */
        if (r != 0 && i < proc_table_capacity &&
            proc_table[i].host_pid == host_pid &&
            proc_table[i].guest_pid == guest_pid)
            proc_table[i].host_reap_pending = false;
    }
    pthread_mutex_unlock(&pid_lock);
}

/* Publish a wait4 report to the guest and release the slot.
 *
 * Returns the guest pid, or -LINUX_EFAULT when the guest buffers cannot be
 * written. The slot is deactivated on every path, since another thread may have
 * reaped it in the meantime.
 */
static int64_t proc_publish_wait_report(guest_t *g,
                                        pid_t host_pid,
                                        int64_t gpid,
                                        int status,
                                        const struct rusage *ru,
                                        uint64_t status_gva,
                                        uint64_t rusage_gva)
{
    if (WIFEXITED(status) || WIFSIGNALED(status))
        status = lifecycle_guest_terminal_status(gpid, status);

    /* Credit CPU only on a terminal report, and re-test after the translation
     * above rather than reusing its result. mac_options may carry
     * WUNTRACED/WCONTINUED, and a stop or continue report is a snapshot of a
     * still-running child: crediting it here would count the same child again
     * at each of its stop, continue, and final exit reports.
     */
    if (WIFEXITED(status) || WIFSIGNALED(status))
        proc_children_cpu_add(ru);

    /* Short-circuit order matters: a failed status write skips the rusage
     * write, as the two separate exits it replaces did. Child already reaped
     * either way, so the slot is released before reporting EFAULT, which is
     * what Linux returns here.
     */
    int32_t linux_status = status;
    int64_t rc = gpid;
    if ((status_gva && guest_write_small(g, status_gva, &linux_status,
                                         sizeof(linux_status)) < 0) ||
        (rusage_gva && write_rusage_to_guest(g, rusage_gva, ru) < 0))
        rc = -LINUX_EFAULT;
    proc_deactivate_slot_if_matches(host_pid, gpid);
    return rc;
}

/* Reap an entry already marked exited: account it, free the slot, and publish
 * status and rusage to the guest. The caller holds pid_lock; this releases it
 * before touching guest memory and never reacquires it, so every caller returns
 * straight after.
 *
 * Returns the guest pid, or a negative Linux errno when the guest buffers
 * cannot be written.
 */
static int64_t proc_reap_exited_and_unlock(guest_t *g,
                                           proc_entry_t *entry,
                                           uint64_t status_gva,
                                           uint64_t rusage_gva)
{
    int64_t gpid = entry->guest_pid;
    int32_t linux_status = entry->exit_status;
    struct rusage ru = entry->rusage;
    bool ru_valid = entry->rusage_valid;
    proc_account_entry_locked(entry);
    entry->active = false;
    pthread_mutex_unlock(&pid_lock);
    lifecycle_consume(gpid);
    if (status_gva && guest_write_small(g, status_gva, &linux_status,
                                        sizeof(linux_status)) < 0)
        return -LINUX_EFAULT;
    if (rusage_gva &&
        write_rusage_to_guest(g, rusage_gva,
                              ru_valid ? &ru : &(struct rusage) {0}) < 0)
        return -LINUX_EFAULT;
    return gpid;
}

int64_t sys_wait4(guest_t *g,
                  int pid,
                  uint64_t status_gva,
                  int options,
                  uint64_t rusage_gva)
{
    proc_deferred_reap_poll();
    lifecycle_import_children();
    if (signal_sigchld_autoreap())
        return proc_wait_autoreap_children(pid, options);

    /* First check for ptraced or vm-clone children in the thread table.
     * thread_ptrace_wait handles both ptrace-stopped and vm-exited states.
     */
    if (current_thread) {
        int ptrace_status = 0;
        int64_t ptrace_tid = thread_ptrace_wait(thread_tid(current_thread), pid,
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
            for (size_t i = 0; i < proc_table_capacity; i++) {
                if (!proc_table[i].active)
                    continue;
                found_any_child = true;
                if (proc_table[i].exited) {
                    /* Already reaped (from CLONE_VFORK wait) */
                    return proc_reap_exited_and_unlock(g, &proc_table[i],
                                                       status_gva, rusage_gva);
                }

                if (!proc_table[i].host_waitable) {
                    int64_t external_gpid = proc_table[i].guest_pid;
                    pthread_mutex_unlock(&pid_lock);
                    bool ready = proc_refresh_external_child(external_gpid);
                    pthread_mutex_lock(&pid_lock);
                    if (ready) {
                        /* Restart the scan so the newly marked exited entry is
                         * returned immediately instead of falling through to
                         * the blocking sleep below.
                         */
                        i = -1;
                        continue;
                    }
                    continue;
                }

                pid_t host_pid = proc_table[i].host_pid;
                int64_t gpid = proc_table[i].guest_pid;
                pthread_mutex_unlock(&pid_lock);

                int status;
                struct rusage ru;
                pid_t ret =
                    wait4(host_pid, &status, mac_options | WNOHANG, &ru);
                if (ret > 0) {
                    return proc_publish_wait_report(
                        g, host_pid, gpid, status, &ru, status_gva, rusage_gva);
                }
                /* ret == 0 (not exited) or ret < 0 (error): try next */
                pthread_mutex_lock(&pid_lock);
            }

            if (!found_any_child) {
                pthread_mutex_unlock(&pid_lock);
                lifecycle_import_children();
                pthread_mutex_lock(&pid_lock);
                bool imported_child = false;
                for (size_t i = 0; i < proc_table_capacity; i++) {
                    if (proc_table[i].active) {
                        imported_child = true;
                        break;
                    }
                }
                if (imported_child)
                    continue;
                pthread_mutex_unlock(&pid_lock);
                return -LINUX_ECHILD;
            }
            if (mac_options & WNOHANG) {
                pthread_mutex_unlock(&pid_lock);
                return 0;
            }

            /* exit_group teardown: stop re-arming the wait. The 100ms quantum
             * below bounds how stale this check can be, mirroring the futex
             * wait quanta. The errno is never guest-visible: the run loop
             * breaks on the exit-group flag before returning to the guest.
             */
            if (thread_stop_requested()) {
                pthread_mutex_unlock(&pid_lock);
                return -LINUX_EINTR;
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
            pthread_mutex_unlock(&pid_lock);
            lifecycle_import_children();
            pthread_mutex_lock(&pid_lock);
        }
    }

    /* Wait for specific guest PID */
    for (size_t i = 0; i < proc_table_capacity; i++) {
        if (proc_table[i].active && proc_table[i].guest_pid == pid) {
            if (proc_table[i].exited) {
                return proc_reap_exited_and_unlock(g, &proc_table[i],
                                                   status_gva, rusage_gva);
            }

            if (!proc_table[i].host_waitable) {
                int64_t external_gpid = proc_table[i].guest_pid;
                pthread_mutex_unlock(&pid_lock);
                if (proc_refresh_external_child(external_gpid))
                    return sys_wait4(g, pid, status_gva, options, rusage_gva);
                if (mac_options & WNOHANG)
                    return 0;
                if (thread_stop_requested())
                    return -LINUX_EINTR;
                usleep(1000);
                return sys_wait4(g, pid, status_gva, options, rusage_gva);
            }

            pid_t host_pid = proc_table[i].host_pid;
            int64_t gpid = proc_table[i].guest_pid;
            pthread_mutex_unlock(&pid_lock);

            int status;
            struct rusage ru;
            pid_t ret;
            if (mac_options & WNOHANG) {
                ret = wait4(host_pid, &status, mac_options, &ru);
            } else {
                /* A bare blocking wait4 has no re-check point: a worker parked
                 * here past exit_group is invisible to thread_join_workers'
                 * poll cap and touches guest memory (status/rusage writes
                 * below) on an eventual delayed return, well after
                 * guest_destroy may have unmapped it. Poll with WNOHANG under a
                 * bounded retry instead, mirroring the pid==-1 loop above;
                 * proc_mark_child_exited broadcasts pid_cond on every host
                 * child exit.
                 */
                for (;;) {
                    ret = wait4(host_pid, &status, mac_options | WNOHANG, &ru);
                    if (ret != 0)
                        break;
                    if (thread_stop_requested())
                        return -LINUX_EINTR;
                    struct timespec ts;
                    timespec_deadline_in_ms(&ts, 100);
                    pthread_mutex_lock(&pid_lock);
                    pthread_cond_timedwait(&pid_cond, &pid_lock, &ts);
                    pthread_mutex_unlock(&pid_lock);
                }
            }
            if (ret > 0) {
                return proc_publish_wait_report(g, host_pid, gpid, status, &ru,
                                                status_gva, rusage_gva);
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

static int64_t waitid_zero_siginfo(guest_t *g, uint64_t infop_gva)
{
    if (infop_gva == 0)
        return 0;
    uint8_t zeros[SIGINFO_SIZE] = {0};
    if (guest_write_small(g, infop_gva, zeros, sizeof(zeros)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

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
    int64_t wait_pgid = -1;
    switch (idtype) {
    case P_ALL:
        wait_pid = -1;
        break;
    case P_PID:
        wait_pid = (pid_t) id;
        break;
    case P_PGID:
        if (id < 0 || id > INT_MAX)
            return -LINUX_EINVAL;
        wait_pgid = id == 0 ? proc_get_pgid() : id;
        wait_pid = id == 0 ? 0 : -(pid_t) id;
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

    lifecycle_import_children();
    if (signal_sigchld_autoreap()) {
        int64_t result = proc_wait_autoreap_children((int) wait_pid, options);
        if (result == 0)
            return waitid_zero_siginfo(g, infop_gva);
        return result;
    }

    /* Search process table for matching entry. P_ALL must scan all children
     * (not block on the first non-exited one), so the wait loop always use
     * WNOHANG in the inner loop and retry with timedwait if the caller
     * requested blocking.
     */
    pthread_mutex_lock(&pid_lock);
    for (;;) {
        bool found_any = false;

        for (size_t i = 0; i < proc_table_capacity; i++) {
            if (!proc_table[i].active)
                continue;

            /* Match exactly the requested guest PID or process group. */
            if ((idtype == P_PID || idtype == 3 /* P_PIDFD */) &&
                proc_table[i].guest_pid != wait_pid)
                continue;
            if (idtype == P_PGID && proc_table[i].pgid != wait_pgid)
                continue;

            found_any = true;
            int status;
            pid_t ret;
            int64_t entry_gpid = proc_table[i].guest_pid;
            int32_t gpid32 = (int32_t) entry_gpid;

            if (proc_table[i].exited) {
                /* Already reaped (from CLONE_VFORK wait) */
                status = proc_table[i].exit_status;
                ret = proc_table[i].host_pid;
            } else if (!proc_table[i].host_waitable) {
                int64_t external_gpid = proc_table[i].guest_pid;
                pthread_mutex_unlock(&pid_lock);
                bool ready = proc_refresh_external_child(external_gpid);
                pthread_mutex_lock(&pid_lock);
                if (ready) {
                    /* The table now contains the lifecycle-registry status;
                     * rescan to use the common exited/WNOWAIT path.
                     */
                    i = -1;
                }
                continue;
            } else {
                pid_t host_pid = proc_table[i].host_pid;
                pthread_mutex_unlock(&pid_lock);
                struct rusage ru;
                ret = wait4(host_pid, &status, WNOHANG, &ru);
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
                status = lifecycle_guest_terminal_status(entry_gpid, status);
                pthread_mutex_lock(&pid_lock);

                /* Host wait4 necessarily consumes the host zombie. Preserve the
                 * status/rusage in the guest process table so Linux WNOWAIT
                 * remains repeatable and a later consuming wait can account and
                 * remove it exactly once.
                 *
                 * Looked up by host_pid rather than indexed by the stale i:
                 * pid_lock was released across the wait4 above, during which
                 * proc_table can be freed and reassigned to the small initial
                 * static buffer if every entry went idle in the meantime,
                 * making a raw index captured before the unlock potentially out
                 * of bounds for the table it now points to (see
                 * proc_deactivate_slot_if_matches for the same hazard, found
                 * and fixed there first). The entry_gpid half of the lookup
                 * guards that function's other hazard: the host OS can reuse
                 * host_pid the moment wait4 reaps it, so a second guest fork
                 * admitted on another thread during this unlocked window can
                 * land an unrelated child under this exact host_pid.
                 */
                proc_entry_t *reaped =
                    proc_find_host_guest_entry(host_pid, entry_gpid);
                if (reaped) {
                    reaped->exited = true;
                    reaped->exit_status = status;
                    reaped->rusage = ru;
                    reaped->rusage_valid = true;
                }
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

            /* Keep the table entry when WNOWAIT is set. Looked up by host_pid
             * (ret) rather than indexed by i for the same reason as the
             * reap-preservation block above: this path is reachable after the
             * else-arm's unlock/relock around wait4, where a stale index can be
             * out of bounds for a proc_table shrunk in the interim. The
             * "already reaped" arm above also reaches here with ret set to that
             * entry's host_pid, so the lookup is correct for both arms that
             * fall through to this point. The entry_gpid half of the lookup
             * guards the same host_pid-reuse hazard as the reap-preservation
             * block above.
             */
            int64_t consumed_gpid = -1;
            if (!(options & LINUX_WNOWAIT)) {
                proc_entry_t *consumed =
                    proc_find_host_guest_entry(ret, entry_gpid);
                if (consumed) {
                    consumed_gpid = consumed->guest_pid;
                    proc_account_entry_locked(consumed);
                    consumed->active = false;
                }
            }

            pthread_mutex_unlock(&pid_lock);
            if (consumed_gpid > 0)
                lifecycle_consume(consumed_gpid);
            return 0; /* waitid returns 0 on success */
        }

        if (!found_any) {
            pthread_mutex_unlock(&pid_lock);
            lifecycle_import_children();
            pthread_mutex_lock(&pid_lock);
            bool imported_match = false;
            for (size_t i = 0; i < proc_table_capacity; i++) {
                if (!proc_table[i].active)
                    continue;
                if ((idtype == P_PID || idtype == 3) &&
                    proc_table[i].guest_pid != wait_pid)
                    continue;
                if (idtype == P_PGID && proc_table[i].pgid != wait_pgid)
                    continue;
                imported_match = true;
                break;
            }
            if (imported_match)
                continue;
            pthread_mutex_unlock(&pid_lock);
            return -LINUX_ECHILD;
        }

        if (mac_options & WNOHANG) {
            pthread_mutex_unlock(&pid_lock);

            /* Per POSIX/Linux: zero siginfo when WNOHANG returns with no
             * waitable children, so callers can distinguish via si_pid.
             */
            return waitid_zero_siginfo(g, infop_gva);
        }

        /* Same teardown check sys_wait4 makes, and for the same reason: a
         * thread parked here answers neither an exit_group nor the execve
         * de_thread otherwise, so it outlives the bounded join and pushes
         * sys_execve onto its post-PNR exit. A leader parked here also never
         * reaches the run loop to service an execve handed to it. Placed after
         * the reap and WNOHANG answers above so a completed wait is still
         * reported in preference to the interrupt.
         */
        if (thread_stop_requested()) {
            pthread_mutex_unlock(&pid_lock);
            return -LINUX_EINTR;
        }

        /* Blocking: wait on condvar (100ms timeout as safety net) */
        struct timespec ts;
        timespec_deadline_in_ms(&ts, 100);
        pthread_cond_timedwait(&pid_cond, &pid_lock, &ts);
        pthread_mutex_unlock(&pid_lock);
        lifecycle_import_children();
        pthread_mutex_lock(&pid_lock);
    }
}

/* vCPU run loop. */

static _Thread_local bool hvc6_yield_requested;

void proc_request_hvc6_yield(void)
{
    hvc6_yield_requested = true;
}

/* Preemption signals: SIGUSR2 is the cross-process guest-signal doorbell
 * (proc_send_guest_signal), SIGALRM is the main thread's watchdog tick (a
 * repeating timer armed once in vcpu_run_loop). Both are consumed by a
 * dedicated sigwait thread rather than a per-thread signal handler.
 *
 * The reason is Apple HVF: when either signal is delivered to a vCPU thread
 * while it is inside hv_vcpu_run, the run aborts with HV_EXIT_REASON_UNKNOWN
 * instead of the clean HV_EXIT_REASON_CANCELED that hv_vcpus_exit() produces
 * for a vCPU caught between runs. Routing every self-directed hv_vcpus_exit
 * through a thread that never runs a vCPU makes CANCELED the only outcome, so
 * the run loop can treat any UNKNOWN as a hard hypervisor fault.
 *
 * The two flags are a genuine cross-thread handoff (the preempt thread writes,
 * a vCPU thread reads and clears), so they are _Atomic with release/acquire
 * ordering rather than the old volatile sig_atomic_t, which only covered
 * same-thread async signal handlers.
 */
static _Atomic int g_timed_out, g_external_guest_signal;

/* Watchdog progress word, written by the guest main thread's run loop and read
 * by preempt_thread_main. A Linux-style seqlock counter, the same shape the
 * vvar uses in core/vdso.c: odd means the loop is inside hv_vcpu_run, even
 * means it is not, and the value changes on every entry and every return.
 *
 * The loop used to arm and disarm alarm() around every hv_vcpu_run. On macOS
 * alarm() is setitimer(ITIMER_REAL), so that was two real syscalls per guest
 * syscall: measured 693 ns for the pair, against a 1226 ns bare HVF round trip.
 * It made every host-served syscall on the main thread about 38 percent slower
 * than the same syscall on a worker, which passes timeout_sec == 0 and skipped
 * the alarm entirely. Single-threaded guests run wholly on the main thread, so
 * that was most of the emulator's syscall cost.
 *
 * The timer is now a repeating one, armed once with an it_interval, and a tick
 * that finds this word odd and unchanged since the previous tick has seen no
 * progress for a whole period. One word rather than a flag beside a counter is
 * what keeps that decision free of any ordering argument: a single atomic
 * object has one modification order, so relaxed access is enough and there is
 * no pairing to get wrong. An earlier revision split the state in two and got
 * the pairing wrong twice.
 *
 * Detection therefore takes one to two periods rather than exactly one, which
 * for a ten-second backstop is not a property anything depends on.
 */
static _Atomic uint64_t g_vcpu_progress;

static pthread_t g_preempt_thread;
static bool g_preempt_started;

static void drain_external_guest_signal(void);

/* Dedicated sigwait consumer. SIGUSR2/SIGALRM are blocked on every other thread
 * (see proc_preempt_init), so they land here. thread_interrupt_all() kicks
 * every live vCPU off-thread; the signal/queue machinery in the vCPU loop sorts
 * out which guest thread actually receives the delivery.
 */
static void *preempt_thread_main(void *arg)
{
    (void) arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    sigset_t wait_set;
    sigemptyset(&wait_set);
    sigaddset(&wait_set, SIGUSR2);
    sigaddset(&wait_set, SIGALRM);

    for (;;) {
        int sig = 0;
        if (sigwait(&wait_set, &sig) != 0)
            continue;
        if (sig == SIGUSR2) {
            atomic_store_explicit(&g_external_guest_signal, 1,
                                  memory_order_release);
            drain_external_guest_signal();
            wakeup_pipe_signal();
        } else if (sig == SIGALRM) {
            static uint64_t last_progress;
            uint64_t now =
                atomic_load_explicit(&g_vcpu_progress, memory_order_relaxed);
            bool wedged = (now == last_progress) && (now & 1);

            last_progress = now;

            /* Progress since the last tick, or not in the guest at all: say
             * nothing, because interrupting here would hand a spurious EINTR to
             * whatever the guest is waiting on. The timer repeats on its own
             * interval, so there is nothing to re-arm.
             */
            if (!wedged)
                continue;
            atomic_store_explicit(&g_timed_out, 1, memory_order_release);
        }
        thread_interrupt_all();
    }
    return NULL;
}

/* Unlink this process's own (now empty) transport file on normal exit so the
 * truncate-not-unlink drain does not leave a zero-length file per pid. Runs via
 * atexit, so it covers main returning and exit()/exit_group's clean shutdown; a
 * crash leaves the empty file for the OS temp-dir purge, same as before.
 */
static void unlink_own_transport(void)
{
    char path[PATH_MAX];
    if (signal_transport_path(path, sizeof(path), getpid()))
        unlink(path);

    /* The namespace owner cleans the registry, but only once no other live
     * member still needs it: if the owner exits while fork children survive,
     * deleting the file would blind their kill(-1)/kill(0)/kill(-pgid). A rare
     * orphaned family that outlives its owner leaves the file for the next
     * same-pid run's reset (proc_registry_reset_if_owner) or the OS temp-dir
     * purge.
     */
    if (absock_get_namespace_id() != (uint64_t) getpid())
        return;
    if (!process_registry_path(path, sizeof(path)))
        return;
    int fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return;
    if (flock_retry(fd, LOCK_EX) != 0) {
        close(fd);
        return;
    }
    registry_entry_t entries[REGISTRY_MAX_ENTRIES];
    int n = registry_read_locked(fd, entries, REGISTRY_MAX_ENTRIES, NULL);
    pid_t self = getpid();
    bool others = false;
    for (int i = 0; i < n; i++)
        if (entries[i].host_pid != self) {
            others = true;
            break;
        }
    if (!others) {
        unlink(path);

        /* These files share the process-family namespace and have no readers
         * once the owner is the last live host member. Avoid leaving one
         * fixed-size lifecycle registry and PID counter behind per run.
         */
        if (lifecycle_registry_path(path, sizeof(path)))
            unlink(path);
        if (process_pid_sequence_path(path, sizeof(path)))
            unlink(path);
    }
    flock_retry(fd, LOCK_UN);
    close(fd);
}

/* Call once from the main thread before any vCPU thread is created; the
 * fork-child re-runs it in its own process. Not safe against concurrent callers
 * (the g_preempt_started guard is a plain bool), which is fine because every
 * call site is single-threaded process bring-up.
 *
 * Returns 0 on success, -1 if the sigwait thread cannot be started (fatal for
 * this process).
 */
int proc_preempt_init(void)
{
    if (g_preempt_started)
        return 0;

    /* Block the preemption signals on the caller (the main thread) before any
     * vCPU thread exists, so every thread created afterward -- CLONE_THREAD
     * workers and posix_spawn fork-children -- inherits the block and only the
     * sigwait thread ever consumes them. A missed site silently reintroduces
     * HV_EXIT_REASON_UNKNOWN.
     */
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR2);
    sigaddset(&block, SIGALRM);

    /* pthread_sigmask returns the error code directly. If the block fails, vCPU
     * threads would inherit an unblocked mask and a signal landing mid-run
     * could still produce HV_EXIT_REASON_UNKNOWN, so fail bring-up rather than
     * proceed on a false invariant.
     */
    int merr = pthread_sigmask(SIG_BLOCK, &block, NULL);
    if (merr != 0) {
        log_error("elfuse: failed to block preemption signals: %s",
                  strerror(merr));
        return -1;
    }

    int err =
        pthread_create(&g_preempt_thread, NULL, preempt_thread_main, NULL);
    if (err != 0) {
        /* pthread_create returns the error code directly; it does not set
         * errno. Leave the signals blocked (pending, never default-terminate)
         * and fail bring-up -- unblocking would restore the default SIGUSR2
         * disposition and let a cross-process doorbell kill the process.
         */
        log_error("elfuse: failed to start preemption thread: %s",
                  strerror(err));
        return -1;
    }
    g_preempt_started = true;
    atexit(unlink_own_transport);
    return 0;
}

typedef struct {
    uint64_t my_ns;
    int64_t my_guest_pid;
} sig_drain_ctx_t;

/* Parse a signal record ("namespace target_guest_pid signum") or a reparent
 * control record ("R namespace target_guest_pid new_ppid"). Both are accepted
 * only when namespace and target identity match this process.
 */
static void sig_drain_cb(char *rec, void *vctx)
{
    sig_drain_ctx_t *c = vctx;
    if (rec[0] == 'R') {
        char *p = rec + 1, *end;
        errno = 0;
        unsigned long long ns = strtoull(p, &end, 10);
        if (end == p || errno == ERANGE)
            return;
        p = end;
        errno = 0;
        long long tgpid = strtoll(p, &end, 10);
        if (end == p || errno == ERANGE)
            return;
        p = end;
        errno = 0;
        long long new_ppid = strtoll(p, &end, 10);
        if (end == p || errno == ERANGE || *end != '\0')
            return;
        if (ns == c->my_ns && tgpid == c->my_guest_pid && new_ppid > 0) {
            proc_set_ppid((int64_t) new_ppid);
            if (signal_refresh_identity_cache()) {
                lifecycle_publish_self();
                lifecycle_ack_reparent((int64_t) tgpid, (int64_t) new_ppid);
            }
        }
        return;
    }

    char *p = rec, *end;
    unsigned long long ns = strtoull(p, &end, 10);
    if (end == p)
        return;
    p = end;
    long long tgpid = strtoll(p, &end, 10);
    if (end == p)
        return;
    p = end;
    long signum = strtol(p, &end, 10);

    /* Reject any trailing garbage so a forged record like "<ns> <pid> 9junk"
     * from a same-user temp-dir writer cannot be accepted as a bare signal.
     */
    if (end == p || *end != '\0')
        return;
    if (ns == c->my_ns && tgpid == c->my_guest_pid &&
        RANGE_CHECK(signum, 1, LINUX_NSIG)) {
        if (signum == LINUX_SIGCHLD && signal_sigchld_autoreap())
            proc_autoreap_exited_children();
        signal_queue((int) signum);
    }
}

static void drain_external_guest_signal(void)
{
    if (!atomic_exchange_explicit(&g_external_guest_signal, 0,
                                  memory_order_acquire))
        return;

    char path[PATH_MAX];
    if (!signal_transport_path(path, sizeof(path), getpid()))
        return;

    /* O_RDWR (not O_RDONLY) so the drain can truncate under the lock. No
     * O_CREAT: if no sender has written since the last drain, there is nothing
     * to consume.
     */
    int fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return;

    /* Hold the exclusive lock across the whole read+truncate so a sender's
     * locked append is atomic with respect to the drain. The file is truncated
     * to empty rather than unlinked (see proc_send_guest_signal), which avoids
     * reintroducing the unlink-vs-append race; the process unlinks its own
     * empty file at exit (unlink_own_transport) so the temp dir stays clean.
     */
    if (flock_retry(fd, LOCK_EX) != 0) {
        close(fd);
        return;
    }

    sig_drain_ctx_t ctx = {.my_ns = absock_get_namespace_id(),
                           .my_guest_pid = proc_get_pid()};
    for_each_record(fd, sig_drain_cb, &ctx);

    /* Report a failed truncate: the same records would re-drain on the next
     * doorbell and re-queue already-delivered signals. Do not early-return --
     * the lock still has to be released and the fd closed.
     */
    if (ftruncate(fd, 0) != 0)
        log_warn(
            "signal transport truncate failed (%s); queued signals may "
            "re-deliver",
            strerror(errno));
    flock_retry(fd, LOCK_UN);
    close(fd);
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

/* HVC #7: MRS trap emulation. Guest EL0 code read a system register; extract
 * the encoding from ESR_EL1's ISS field, read it via HVF, and leave the value
 * in X0 for the shim to store into the saved register frame.
 *
 * Lifted out of vcpu_run_loop_with_hooks, which every syscall passes through
 * and which had grown past a thousand lines. This case cannot end the loop and
 * reads no loop state beyond the vCPU handle and the two logging arguments, so
 * it moves whole.
 */
static void vcpu_handle_mrs_trap(hv_vcpu_t vcpu,
                                 bool verbose,
                                 const char *prefix)
{
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
    hv_sys_reg_t reg = (hv_sys_reg_t) ((op0 << 14) | (op1 << 11) | (crn << 7) |
                                       (crm << 3) | op2);

    uint64_t value = 0;

    /* ID register emulation: return VZ-sanitized values BEFORE trying HVF.
     * HVF's hv_vcpu_get_sys_reg succeeds for ID registers but returns raw
     * hardware values, which include features the hypervisor does not actually
     * virtualize.
     *
     * Values captured from a Lima VZ VM on Apple Silicon via inline MRS from
     * EL0 (kernel trap-and-emulate). These are checked first, before the HVF
     * call.
     */
    bool have_vz_override = false;

    /* ID_AA64MMFR0_EL1 (3,0,0,7,0) */
    if (op0 == 3 && op1 == 0 && crn == 0 && crm == 7 && op2 == 0) {
        value = 0x00000111ff000000ULL;
        have_vz_override = true;
    }

    /* ID_AA64MMFR1_EL1 (3,0,0,7,1): VZ returns 0. Raw hardware (e.g.,
     * 0x11212000) exposes HPDS, PAN, LO, XNX etc. that VZ does not virtualize.
     */
    if (op0 == 3 && op1 == 0 && crn == 0 && crm == 7 && op2 == 1) {
        value = 0x0000000000000000ULL;
        have_vz_override = true;
    }
    /* ID_AA64MMFR2_EL1 (3,0,0,7,2): VZ returns 0. */
    if (op0 == 3 && op1 == 0 && crn == 0 && crm == 7 && op2 == 2) {
        value = 0x0000000000000000ULL;
        have_vz_override = true;
    }
    /* ID_AA64ISAR0_EL1 (3,0,0,6,0) */
    if (op0 == 3 && op1 == 0 && crn == 0 && crm == 6 && op2 == 0) {
        value = 0x0021100110212120ULL;
        have_vz_override = true;
    }
    /* ID_AA64ISAR1_EL1 (3,0,0,6,1) */
    if (op0 == 3 && op1 == 0 && crn == 0 && crm == 6 && op2 == 1) {
        value = 0x0000101110211402ULL;
        have_vz_override = true;
    }
    /* ID_AA64PFR0_EL1 (3,0,0,4,0) */
    if (op0 == 3 && op1 == 0 && crn == 0 && crm == 4 && op2 == 0) {
        value = 0x0001000000110011ULL;
        have_vz_override = true;
    }
    /* ID_AA64PFR1_EL1 (3,0,0,4,1): VZ returns 0. */
    if (op0 == 3 && op1 == 0 && crn == 0 && crm == 4 && op2 == 1) {
        value = 0x0000000000000000ULL;
        have_vz_override = true;
    }

    if (have_vz_override) {
        if (verbose)
            log_debug(
                "%s: MRS trap: Op0=%u Op1=%u "
                "CRn=%u CRm=%u Op2=%u -> 0x%llx (VZ)",
                prefix, op0, op1, crn, crm, op2, (unsigned long long) value);
    }

    hv_return_t ret =
        have_vz_override ? HV_SUCCESS : hv_vcpu_get_sys_reg(vcpu, reg, &value);
    if (ret != HV_SUCCESS) {
        /* HVF does not expose this register. Provide a host-side fallback for
         * known registers.
         */
        bool have_fallback = false;

        /* CNTFRQ_EL0 (3,3,14,0,0): counter frequency. Read directly from host
         * hardware (Apple Silicon uses 24MHz).
         */
        if (op0 == 3 && op1 == 3 && crn == 14 && crm == 0 && op2 == 0) {
            __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(value));
            have_fallback = true;
        }

        /* Non-ID register fallbacks for registers that HVF does not expose. ID
         * registers are handled above (VZ overrides).
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
                    prefix, op0, op1, crn, crm, op2, (unsigned) reg);
            }
        }
    } else if (verbose) {
        log_debug(
            "%s: MRS trap: Op0=%u Op1=%u "
            "CRn=%u CRm=%u Op2=%u -> 0x%llx",
            prefix, op0, op1, crn, crm, op2, (unsigned long long) value);
    }

    hv_vcpu_set_reg(vcpu, HV_REG_X0, value);
}

/* HVC #12: system instruction trap. The guest executed a cache maintenance
 * instruction HVF traps; log it and step past. Lifted out of
 * vcpu_run_loop_with_hooks with the other self-contained cases: it reads no
 * loop state and cannot end the loop.
 */
static void vcpu_handle_sysinstr_trap(hv_vcpu_t vcpu,
                                      bool verbose,
                                      const char *prefix)
{
    /* HVC #12: System instruction trap (EC=0x18 Direction=0). The shim forwards
     * trapped cache maintenance instructions (DC CVAU, IC IVAU, etc.) here for
     * logging/counting. It also passes the original Rt value in X0 so host-side
     * emulation can handle MSR writes such as TPIDR_EL0. The shim has already
     * advanced PC and will restore X0 from its saved frame before returning to
     * EL0.
     */
    uint64_t seq = atomic_fetch_add_explicit(&sysreg_write_count, 1,
                                             memory_order_relaxed) +
                   1;
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

    /* TPIDR_EL0 (S3_3_C13_C0_2): userspace TLS base. Static glibc writes this
     * during early startup. HVF traps the MSR, so Linux-compatible execution
     * requires reflecting the write into the virtual sysreg.
     */
    if (op0 == 3 && op1 == 3 && crn == 13 && crm == 0 && op2 == 2) {
        HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL0, rt_value));
    }
    if (verbose) {
        /* DC CVAU: Op0=1,Op1=3,CRn=7,CRm=11,Op2=1 IC IVAU:
         * Op0=1,Op1=3,CRn=7,CRm=5,Op2=1
         */
        const char *name = "unknown";
        if (op0 == 1 && op1 == 3 && crn == 7 && crm == 11 && op2 == 1)
            name = "DC CVAU";
        else if (op0 == 1 && op1 == 3 && crn == 7 && crm == 5 && op2 == 1)
            name = "IC IVAU";
        else if (op0 == 1 && op1 == 3 && crn == 7 && crm == 10 && op2 == 1)
            name = "DC CVAC";
        else if (op0 == 1 && op1 == 3 && crn == 7 && crm == 14 && op2 == 1)
            name = "DC CIVAC";
        else if (op0 == 3 && op1 == 3 && crn == 13 && crm == 0 && op2 == 2)
            name = "MSR TPIDR_EL0";
        log_debug(
            "%s: sysreg trap #%llu: %s "
            "(Op0=%u Op1=%u CRn=%u CRm=%u Op2=%u "
            "Rt=X%u val=0x%llx)",
            prefix, (unsigned long long) seq, name, op0, op1, crn, crm, op2, rt,
            (unsigned long long) rt_value);
    }
}

/* HVC #9: W^X toggle. HVF enforces W^X on stage-2, so a guest page that must
 * become executable is flipped RW -> RX here (and back on the first write).
 * Returns false when the fault cannot be served and the vCPU must stop.
 */
static bool vcpu_handle_wx_toggle(guest_t *g,
                                  hv_vcpu_t vcpu,
                                  bool verbose,
                                  const char *prefix,
                                  int *exit_code)
{
    /* HVC #9: W^X page permission toggle for JIT.
     *
     * Apple HVF enforces W^X: pages cannot be both writable and executable
     * simultaneously. JIT code needs to be written (RW), then executed (RX).
     * The shim detects permission faults (EC=0x20 instruction abort, EC=0x24
     * data abort) and forwards the faulting address here.
     *
     * Toggling at 2MiB granularity causes thrashing when the JIT writes new
     * code and executes existing code within the same 2MiB block. Instead, the
     * code splits the 2MiB block into 4KiB L3 pages and toggle only the
     * faulting 4KiB page. This allows different pages within a 2MiB block to
     * have independent RW/RX permissions simultaneously.
     *
     * x0 = FAR_EL1 (faulting virtual address) x1 = type: 0 = exec fault -> flip
     * to RX
     *            1 = write fault -> flip to RW
     */
    uint64_t far, type;
    hv_vcpu_get_reg(vcpu, HV_REG_X0, &far);
    hv_vcpu_get_reg(vcpu, HV_REG_X1, &type);

    uint64_t page_start = far & ~(4096ULL - 1);
    uint64_t page_end = page_start + 4096;
    int new_perms = (type == 0) ? MEM_PERM_RX : MEM_PERM_RW;

    /* Hold mmap_lock for page table modifications AND region lookups to prevent
     * races with concurrent mmap/mprotect/munmap from other vCPU threads.
     */
    pthread_mutex_lock(&mmap_lock);

    /* Check if this is a genuine permission violation (not a W^X toggle). If
     * the guest region lacks the required permission, deliver SIGSEGV instead
     * of toggling. This handles mprotect(PROT_READ), SHM_RDONLY, PROT_NONE, and
     * non-exec pages.
     */
    {
        uint64_t off = far - g->ipa_base;
        const guest_region_t *reg = guest_region_find(g, off);
        int required = (type == 1) ? LINUX_PROT_WRITE : LINUX_PROT_EXEC;
        if (reg && !(reg->prot & required)) {
            pthread_mutex_unlock(&mmap_lock);
            uint64_t esr;
            hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &esr);
            signal_set_fault_info(LINUX_SEGV_ACCERR, far, esr);
            int sig_ret =
                signal_deliver_fault(vcpu, g, LINUX_SIGSEGV, exit_code);
            if (sig_ret < 0)
                return false;
            /* Fault delivered; the loop keeps running. */
            return true;
        }
    }

    /* Count W^X toggles for JIT debugging */
    if (type == 0)
        atomic_fetch_add_explicit(&wxcount_to_rx, 1, memory_order_relaxed);
    else
        atomic_fetch_add_explicit(&wxcount_to_rw, 1, memory_order_relaxed);

    if (verbose)
        log_debug("%s: W^X toggle at 0x%llx -> %s (page 0x%llx)", prefix,
                  (unsigned long long) far, (type == 0) ? "RX" : "RW",
                  (unsigned long long) page_start);
    uint64_t block_start = far & ~(BLOCK_2MIB - 1);
    int sr = guest_split_block(g, block_start);
    int ur = guest_update_perms(g, page_start, page_end, new_perms);
    pthread_mutex_unlock(&mmap_lock);
    if (verbose && (sr < 0 || ur < 0))
        log_warn(
            "%s: W^X toggle FAILED "
            "(split=%d update=%d) far=0x%llx",
            prefix, sr, ur, (unsigned long long) far);

    /* TLB flush is done by the shim (tlbi_restore_eret) for the single faulting
     * page. Clear this thread's pending request so the next syscall epilogue
     * does not re-flush the W^X page. cpu_tlbi_req is per-vCPU, so this only
     * touches our own slot -- concurrent vCPUs are unaffected.
     *
     * The HVC #9 shim now consumes X8 as a post-HVC marker: 0 means W^X
     * succeeded and the shim should run the TLBI retry epilogue; 2 means
     * signal_deliver_fault installed a handler frame and the shim must drop its
     * saved frame. Clear X8 here so a guest's pre-fault X8 value cannot be
     * misread as the frame-drop marker after a normal toggle.
     */
    tlbi_request_clear();
    hv_vcpu_set_reg(vcpu, HV_REG_X8, 0);
    return true;
}

/* HVC #10: BRK from EL0. A guest breakpoint becomes a ptrace-stop when the
 * thread is traced, and SIGTRAP otherwise.
 *
 * Returns false when the vCPU must stop.
 */
static bool vcpu_handle_brk(guest_t *g,
                            hv_vcpu_t vcpu,
                            bool verbose,
                            const char *prefix,
                            int *exit_code)
{
    /* HVC #10: BRK from EL0 -> deliver SIGTRAP or ptrace-stop.
     *
     * If the thread is ptraced, the BRK enters a ptrace-stop (the tracer
     * reads/writes registers then CONT's). Otherwise the run loop queues
     * SIGTRAP and delivers it via the signal frame mechanism.
     *
     * The shim has already restored all GPRs to their EL0 values, so
     * signal_deliver / ptrace_stop read correct state.
     *
     * The Linux kernel sets si_code=TRAP_BRKPT, si_addr=BRK_PC, and
     * fault_address=BRK_PC for BRK-triggered SIGTRAP.
     */
    uint64_t brk_pc;
    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &brk_pc);

    if (verbose) {
        log_debug("%s: BRK at 0x%llx -> %s", prefix,
                  (unsigned long long) brk_pc,
                  current_thread->ptraced ? "ptrace-stop" : "SIGTRAP");
    }

    if (current_thread->ptraced) {
        /* Ptrace-stop: suspend vCPU, notify tracer. thread_ptrace_stop blocks
         * until tracer CONT's.
         */
        int cont_sig = thread_ptrace_stop(current_thread, 5);
        if (cont_sig > 0) {
            signal_queue(cont_sig);
            int sr = signal_deliver(vcpu, g, exit_code);
            if (sr < 0)
                return false;
        }
    } else {
        /* Non-ptraced: deliver SIGTRAP via signal frame. Read ESR_EL1 to
         * include in sigcontext.
         */
        uint64_t brk_esr;
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &brk_esr);
        signal_set_fault_info(LINUX_TRAP_BRKPT, brk_pc, brk_esr);
        if (verbose) {
            uint64_t thread_blocked =
                current_thread ? thread_blocked_load(current_thread) : 0xDEAD;
            log_debug(
                "%s: BRK: thread_blocked=0x%llx "
                "pending=0x%llx",
                prefix, (unsigned long long) thread_blocked,
                (unsigned long long) signal_shared_pending_load());
        }
        int sig_ret = signal_deliver_fault(vcpu, g, LINUX_SIGTRAP, exit_code);
        if (verbose)
            log_debug("%s: signal_deliver returned %d", prefix, sig_ret);
        if (sig_ret < 0) {
            /* SIG_DFL for SIGTRAP: terminate */
            return false;
        }
    }
    return true;
}

/* HVC #2: bad exception from the shim's vector table. Dumps the guest state and
 * stops the vCPU. Its inner continue binds to the register-dump for loop, not
 * the enclosing run loop, so this lifts like cases 9 and 10.
 */
static bool vcpu_handle_bad_exception(guest_t *g,
                                      hv_vcpu_t vcpu,
                                      const char *prefix,
                                      int *exit_code)
{
    /* HVC #2: Bad exception in guest. Shim clobbers X0-X3,X5 with exception
     * info. X4,X6-X30 and SP_EL0 still hold faulting values.
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
        prefix, (unsigned long long) x5, (unsigned long long) x0,
        (unsigned long long) x1, (unsigned long long) x2,
        (unsigned long long) x3);

    /* Dump preserved registers for debugging */
    uint64_t sp_el0;
    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL0, &sp_el0);
    log_error("%s:   SP_EL0=0x%llx", prefix, (unsigned long long) sp_el0);
    for (int ri = 4; ri <= 30; ri++) {
        /* Skip X5 (clobbered by shim for vec offset) */
        if (ri == 5)
            continue;
        uint64_t rv;
        hv_vcpu_get_reg(vcpu, (hv_reg_t) (HV_REG_X0 + ri), &rv);
        log_error("%s:   X%-2d=0x%016llx", prefix, ri, (unsigned long long) rv);
    }

    /* Check if FAR looks like a tagged pointer */
    uint64_t far = x1;
    uint16_t top16 = (uint16_t) (far >> 48);
    if (top16 != 0x0000 && top16 != 0xFFFF) {
        log_error("%s:   FAR tag=0x%04x, extracted addr=0x%llx", prefix, top16,
                  (unsigned long long) (far & 0x0000FFFFFFFFFFFFULL));
    }

    {
        char detail[128];
        snprintf(detail, sizeof(detail), "vec=0x%03llx ESR=0x%llx FAR=0x%llx",
                 (unsigned long long) x5, (unsigned long long) x0,
                 (unsigned long long) x1);
        crash_report(vcpu, g, CRASH_BAD_EXCEPTION, detail);
    }
    *exit_code = 128;
    return false;
}

/* HVC #11: an EL0 fault, resolved into a retry or into a signal.
 *
 * Returns true when the vCPU should resume: the two retry exits that
 * materialize a lazily mapped page or refresh a stale TLB entry, and a fault
 * whose signal reached a handler. False means the disposition terminates the
 * guest, which is the caller's cue to leave the run loop.
 */
static bool vcpu_handle_el0_fault(guest_t *g,
                                  hv_vcpu_t vcpu,
                                  bool verbose,
                                  const char *prefix,
                                  int *exit_code)
{
    /* The shim forwards EL0 faults here for signal delivery. EC-based dispatch
     * determines the signal:
     *   EC=0x20 (instruction abort) -> SIGSEGV
     *   EC=0x24 (data abort)        -> SIGSEGV
     *   EC=0x00 (undefined insn)    -> SIGILL
     *   Other ECs from EL0           -> SIGILL (catch-all)
     *
     * For SIGSEGV, si_code is SEGV_MAPERR (translation fault) or SEGV_ACCERR
     * (permission fault) based on xFSC[5:2]. For SIGILL, si_code is ILL_ILLOPC
     * (illegal opcode). si_addr is FAR_EL1 for aborts, ELR_EL1 for SIGILL
     * (FAR_EL1 is UNKNOWN for EC=0 per ARM ARM).
     */
    uint64_t esr, far_addr, elr_addr;
    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &esr);
    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, &far_addr);
    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &elr_addr);

    uint32_t fault_ec = (uint32_t) ((esr >> 26) & 0x3F);

    /* Non-abort EC -> SIGILL. Branch out early so the abort / SIGSEGV path
     * below stays at the case-body indent rather than nested inside an else
     * branch. FAR_EL1 is UNKNOWN for non-abort exceptions, so use ELR_EL1 for
     * si_addr.
     *
     * Only EC 0x20 (instruction abort from a lower EL) and EC 0x24 (data abort
     * from a lower EL) are intentionally routed to the SIGSEGV path that
     * follows. Every other forwarded EC lands here as SIGILL: 0x00 (undefined
     * instruction), 0x18 (system instruction trap), 0x32/0x33 (software step),
     * 0x3C (BRK), and any unrecognized class. If a future change adds a new
     * lower-EL abort class (e.g. 0x21 / 0x25 for higher exception levels) that
     * should map to SIGSEGV, the test below needs explicit widening; do NOT
     * relax the check casually.
     */
    if (fault_ec != 0x20 && fault_ec != 0x24) {
        if (verbose)
            log_debug(
                "%s: EL0 undefined insn at "
                "PC=0x%llx (ESR=0x%llx EC=0x%x) "
                "-> SIGILL/ILL_ILLOPC",
                prefix, (unsigned long long) elr_addr, (unsigned long long) esr,
                fault_ec);
        signal_set_fault_info(LINUX_ILL_ILLOPC, elr_addr, esr);
        int sig_ret = signal_deliver_fault(vcpu, g, LINUX_SIGILL, exit_code);

        /* HVC #11 consumes X8 as the post-fault TLBI opcode. signal_deliver()
         * may leave it unchanged when no handler is materialized, or set the
         * syscall-path frame-drop marker when one is. Neither is a TLBI request
         * here; lazy materialization emits its own request and exits before
         * this path.
         */
        hv_vcpu_set_reg(vcpu, HV_REG_X8, 0);
        if (verbose)
            log_debug("%s: signal %d deliver returned %d", prefix, LINUX_SIGILL,
                      sig_ret);
        /* A SIG_DFL core disposition ends the guest. */
        return sig_ret >= 0;
    }

    /* Instruction or data abort. Try lazy page materialization before declaring
     * SIGSEGV: translation faults (xFSC[5:2] == 0x1) may come from a
     * MAP_NORESERVE region with deferred page-table creation.
     */
    uint32_t fsc = (uint32_t) (esr & 0x3F);
    uint32_t fsc_type = (fsc >> 2) & 0xF;
    if (fsc_type == 0x01) {
        uint64_t fault_off = far_addr - g->ipa_base;
        mmap_lock_acquire(g);
        int mat = guest_materialize_lazy_fault(g, fault_off);
        mmap_lock_release();
        if (mat == 0) {
            /* Page materialized; the helpers inside guest_materialize_lazy
             * populated the per-vCPU TLBI accumulator with the range just
             * installed (plus the I-cache hint if the region's prot includes
             * PROT_EXEC). Drain it through the shared emit helper so the shim's
             * post-HVC-11 dispatch (handle_el0_fault) actually issues the TLBI
             * before ERET. Without this, a PE that caches translation-fault
             * (negative) entries would re-fault on the retry, looping until the
             * entry self-evicts.
             */
            shim_globals_counter_inc(g, SHIM_COUNTER_FAULT_MATERIALIZE);
            switch ((tlbi_kind_t) cpu_tlbi_req.kind) {
            case TLBI_RANGE:
                shim_globals_counter_inc(g, SHIM_COUNTER_FAULT_TLBI_VAE);
                break;
            case TLBI_RANGE_LARGE:
                shim_globals_counter_inc(g, SHIM_COUNTER_FAULT_TLBI_RVAE);
                break;
            case TLBI_BROADCAST:
                shim_globals_counter_inc(g, SHIM_COUNTER_FAULT_TLBI_BCAST);
                break;
            case TLBI_NONE:
            default:
                break;
            }
            tlbi_request_emit_to_vcpu(vcpu);
            return true;
        }
    }

    /* Bounded retry on a stale-TLB data / instruction abort. Re-walk the live
     * page tables for the faulting VA before declaring SIGSEGV. guest_ptr_avail
     * consults pt_gen, which the mutating vCPU bumps under mmap_lock, so the
     * walk reflects the current mapping regardless of this vCPU's cached
     * (possibly stale) hardware TLB. A non-NULL result means the live PT is
     * valid and grants the faulting access, the signature of a stale TLB entry
     * that a cross-vCPU mprotect + TLBI failed to evict on this PE.
     *
     * On that signature, re-issue a selective TLBI for the faulting page from
     * this vCPU (same accumulator + emit path the lazy-materialization branch
     * uses) and return to EL0 to retry the instruction. A genuinely stale entry
     * clears on the first retry, so the guest makes progress and never
     * re-enters here for that VA.
     *
     * The retry is bounded per vCPU and per (page, faulting PC). If the same
     * instruction keeps faulting on the same page despite the re-issued TLBI,
     * the entry is not actually stale (a walker / hardware permission-model
     * disagreement, or an HVF TLBI that did not take): after
     * STALE_TLB_RETRY_MAX attempts, stop retrying and deliver SIGSEGV so a
     * genuine fault is never silently swallowed. The per-vCPU slot resets when
     * a different page or PC faults or when the cap is hit, so a cap-out cannot
     * poison a later legitimate retry.
     */
    enum { STALE_TLB_RETRY_MAX = 16 };

    /* Only translation (fsc_type 0x01) and permission (0x03) faults are
     * stale-TLB plausible. Alignment, external-abort, and access-flag classes
     * cannot be cleared by re-issuing TLBI, so do not spend the retry budget on
     * them. A translation fault reaches here only after the lazy-
     * materialization branch above already declined the address, so a live PT
     * that still grants access is a stale negative (translation-fault) entry; a
     * permission fault is the classic stale entry left by a cross-vCPU
     * mprotect.
     */
    bool stale_plausible = (fsc_type == 0x01 || fsc_type == 0x03);
    int want_perm = (fault_ec == 0x20)
                        ? MEM_PERM_X
                        : ((esr & (1u << 6)) ? MEM_PERM_W : MEM_PERM_R);
    uint64_t live_avail = 0;
    void *live_pt = NULL;
    if (stale_plausible) {
        mmap_lock_acquire(g);
        live_pt = guest_ptr_avail_nofault(g, far_addr, &live_avail, want_perm);
        mmap_lock_release();
    }
    if (live_pt) {
        /* Bound per vCPU and per (page, faulting PC). A genuinely stuck entry
         * re-faults on the same instruction at the same page, so keying the
         * counter on both distinguishes a non-recovering loop (cap it) from
         * separate successful recoveries (a different PC, or the same page
         * reached from a different instruction) that must each get a fresh
         * budget.
         */
        static _Thread_local uint64_t stale_page;
        static _Thread_local uint64_t stale_elr;
        static _Thread_local int stale_count;
        uint64_t page = far_addr & ~(GUEST_PAGE_SIZE - 1);
        if (page == stale_page && elr_addr == stale_elr) {
            stale_count++;
        } else {
            stale_page = page;
            stale_elr = elr_addr;
            stale_count = 1;
        }
        if (stale_count <= STALE_TLB_RETRY_MAX) {
            static _Thread_local bool stale_warned;
            if (!stale_warned) {
                stale_warned = true;
                log_warn(
                    "%s: EL0 %s fault at 0x%llx (ESR=0x%llx) "
                    "but "
                    "live PT grants access (stale TLB); "
                    "re-issuing TLBI and retrying (cap %d)",
                    prefix, (fault_ec == 0x20) ? "inst" : "data",
                    (unsigned long long) far_addr, (unsigned long long) esr,
                    STALE_TLB_RETRY_MAX);
            }
            tlbi_request_clear();
            tlbi_request_range(page, page + GUEST_PAGE_SIZE);
            if (want_perm & MEM_PERM_X)
                tlbi_request_mark_icache();
            tlbi_request_emit_to_vcpu(vcpu);
            return true;
        }

        /* Retry budget exhausted: the entry is not actually stale. Reset the
         * slot and fall through to SIGSEGV.
         */
        log_warn(
            "%s: stale-TLB retry cap (%d) hit at 0x%llx "
            "(ESR=0x%llx); delivering SIGSEGV",
            prefix, STALE_TLB_RETRY_MAX, (unsigned long long) far_addr,
            (unsigned long long) esr);
        stale_page = 0;
        stale_elr = 0;
        stale_count = 0;
    }

    /* Real SIGSEGV. Permission faults (xFSC[5:2] == 0x3) map to SEGV_ACCERR;
     * address size, translation, and access-flag faults map to SEGV_MAPERR for
     * Linux.
     */
    int si_code = (fsc_type == 0x03) ? LINUX_SEGV_ACCERR : LINUX_SEGV_MAPERR;
    if (verbose) {
        const char *fault_type = (fault_ec == 0x20) ? "inst" : "data";
        const char *code_name =
            (si_code == LINUX_SEGV_MAPERR) ? "MAPERR" : "ACCERR";
        log_debug(
            "%s: EL0 %s fault at 0x%llx "
            "PC=0x%llx (ESR=0x%llx FSC=0x%x) "
            "-> SIGSEGV/%s",
            prefix, fault_type, (unsigned long long) far_addr,
            (unsigned long long) elr_addr, (unsigned long long) esr, fsc,
            code_name);
    }
    signal_set_fault_info(si_code, far_addr, esr);
    int sig_ret = signal_deliver_fault(vcpu, g, LINUX_SIGSEGV, exit_code);

    /* Clear X8 for the same reason as the SIGILL exit above. */
    hv_vcpu_set_reg(vcpu, HV_REG_X8, 0);
    if (verbose)
        log_debug("%s: signal %d deliver returned %d", prefix, LINUX_SIGSEGV,
                  sig_ret);
    /* A SIG_DFL core disposition ends the guest. */
    return sig_ret >= 0;
}

/* Consume this thread's owed stop. The pending scan and attention clear share
 * thread_lock with PTRACE_INTERRUPT so a racing request cannot lose its hint.
 */
static bool ptrace_consume_owed_stop(guest_t *g)
{
    if (!current_thread)
        return false;

    pthread_mutex_t *tlock = thread_get_lock();
    pthread_mutex_lock(tlock);
    bool owed = current_thread->ptrace_interrupt_pending &&
                current_thread->ptraced && !current_thread->ptrace_stopped;
    if (owed)
        current_thread->ptrace_interrupt_pending = false;
    if (owed && !thread_ptrace_interrupt_pending_locked())
        shim_globals_ptrace_attention(g, false);
    pthread_mutex_unlock(tlock);

    return owed;
}

/* Set where the syscall epilogue asks the shim for the HVC #13 detour, cleared
 * where that detour arrives. Per-vCPU like cpu_tlbi_req and for the same
 * reason: the thread that arms it is the thread that takes the stop.
 *
 * The window between the two is the X7 test, the frame restore, and the HVC,
 * with nothing else reachable in between. A canceled exit can land there, and
 * the flag has to survive that, which is why it is not cleared per exit; the
 * canceled handler sees EL1 in CPSR and resumes into the same window. No other
 * HVC is reachable from the SVC tail, and EL0 cannot issue one at all, so an
 * unarmed HVC #13 means the shim and this file disagree.
 */
static _Thread_local bool cpu_ptrace_stop_armed;

/* Take a consumed ptrace-stop and inject the tracer's resume signal. Every
 * caller has already consumed the stop, which establishes current_thread.
 */
static bool ptrace_take_stop(guest_t *g, hv_vcpu_t vcpu, int *exit_code)
{
    int cont_sig = thread_ptrace_stop(current_thread, SIGTRAP);
    if (cont_sig > 0)
        signal_queue(cont_sig);

    /* One delivery covers both the injected resume signal and anything that
     * arrived while the tracee was stopped, so neither caller repeats it.
     */
    return !signal_pending() || signal_deliver(vcpu, g, exit_code) >= 0;
}

/* What a run-loop exit handler tells the loop to do next. VCPU_RESUME means the
 * exit was handled and the vCPU should re-enter the guest; VCPU_STOP means
 * leave the loop with *exit_code, which the handler has already set.
 */
typedef enum {
    VCPU_RESUME,
    VCPU_STOP,
} vcpu_action_t;

/* Guest exception handling, lifted out of vcpu_run_loop_with_hooks alongside
 * the canceled-exit arm.
 *
 * Same reason as its sibling and one more: at 466 lines the loop was still over
 * the 400 the size lint allows, and carried a NOLINT for it. What was left was
 * two unrelated jobs sharing a body, an HVC dispatch and a debug-exception
 * dispatch, neither of which the other's reader needs. Split out, the loop is
 * what its name says: run the vCPU, dispatch on why it stopped.
 *
 * running is local and returned as the action rather than assigned through a
 * pointer, because two arms below read it back (the post-exec ELR check and the
 * signal delivery both skip themselves once something has failed) and a caller
 * flag would not be visible to them.
 */

/* Finish an HVC #5 return: take or defer any owed ptrace-stop, deliver pending
 * signals, and place the shim's X7 detour request.
 *
 * Returns whether the guest keeps running.
 */
static bool syscall_return_epilogue(guest_t *g,
                                    hv_vcpu_t vcpu,
                                    int ret,
                                    bool running,
                                    int *exit_code)
{
    /* Whether the shim's tail restores the saved frame is what decides if X7 is
     * host-only. The vector entry clobbers no GPR below X9, so the live set at
     * HVC #5 is still the guest's, and only that restore puts a host write to
     * X7 back. Two tails skip it: X8 == 2, where the host has rebuilt EL0 state
     * and the live registers are already final, and an execve re-entry, which
     * goes through the MMU-off _start with no tail at all.
     *
     * Only the exec-happened return has to ask the vCPU which of those it is.
     * Everywhere else tlbi_request_emit_to_vcpu has just written X8 itself and
     * never writes 2, so the answer is known without the register read.
     */
    bool frame_restored = ret != SYSCALL_EXEC_HAPPENED;
    bool regs_final = false;
    if (!frame_restored) {
        uint64_t x8_req = 0;
        hv_vcpu_get_reg(vcpu, HV_REG_X8, &x8_req);
        regs_final = x8_req == 2; /* rt_sigreturn, as against execve */
    }

    /* An execve re-entry leaves the stop owed rather than consuming it: there
     * is no tail to carry X7, and stopping on the MMU-off bootstrap state would
     * show the tracer an EL1 PC. Attention stays raised, so the new image's
     * first syscall takes it.
     */
    bool defer_stop = false, stop_taken = false;
    if (running && (frame_restored || regs_final) &&
        ptrace_consume_owed_stop(g)) {
        if (regs_final) {
            /* Live registers are already the architectural EL0 set, which is
             * what the detour exists to produce. Stop here instead.
             */
            running = ptrace_take_stop(g, vcpu, exit_code);
            stop_taken = true;
        } else {
            defer_stop = true;
        }
    }

    /* Deliver pending signals after each syscall. A deferred stop takes its
     * signal in the HVC #13 handler, once the shim has restored the frame.
     * signal_deliver is a once-per-epilogue call by its own contract: it walks
     * past discarded signals to the first the guest can see, and a second call
     * here would stack a frame on the handler the first one just installed.
     * ptrace_take_stop has already made that call on the inline path.
     */
    if (running && !defer_stop && !stop_taken && signal_pending()) {
        int sig_ret = signal_deliver(vcpu, g, exit_code);
        if (sig_ret < 0)
            running = false; /* Default TERM/CORE disposition */
        else if (sig_ret > 0)
            frame_restored = false; /* committed to a handler frame: X8 = 2 */
    }

    /* X7 asks the shim to restore its SVC frame and enter HVC #13 for this
     * stop. Written only on the tails that do restore the frame, which put the
     * guest's own X7 back before the ERET. The flag beside it is what lets the
     * HVC #13 arm say a stop was actually asked for.
     */
    if (frame_restored) {
        hv_vcpu_set_reg(vcpu, HV_REG_X7, defer_stop);
        cpu_ptrace_stop_armed = defer_stop;
    }

    return running;
}

static vcpu_action_t vcpu_handle_exception_exit(guest_t *g,
                                                hv_vcpu_t vcpu,
                                                const hv_vcpu_exit_t *vexit,
                                                bool verbose,
                                                const char *prefix,
                                                int *exit_code)
{
    bool running = true;

    uint32_t ec = (vexit->exception.syndrome >> 26) & 0x3F;

    if (ec == 0x16) {
        /* HVC exit */
        uint16_t imm = vexit->exception.syndrome & 0xFFFF;

        if (verbose)
            log_debug("%s: HVC #%u", prefix, imm);

        switch (imm) {
        case 5: {
            /* HVC #5: Linux syscall forwarding */
            int ret = syscall_dispatch(vcpu, g, exit_code, verbose);
            if (ret == 1)
                running = false;

            /* execve replaced the process image; sys_execve already installed
             * the new X0/syscall-return state.
             */

            /* Check guest ITIMER_REAL expiry (queues SIGALRM if due) */
            signal_check_timer();

            /* Recompute the shim-globals attention flag now that
             * signal_check_timer has had a chance to drain pending work. If
             * nothing is pending and no itimer is armed, drop the flag back to
             * zero so the identity fast path re-engages for the next getpid
             * loop. Without this clear, the attention flag set by signal_queue
             * (e.g., on a subprocess's SIGCHLD) would stick forever and
             * permanently disable the fast path.
             *
             * Before the signal delivery below, not after, which costs one
             * wasted round trip per delivered signal: the recompute still sees
             * the signal queued, so the flag stays up until the next syscall's
             * epilogue clears it. Moving it after the delivery recovers that
             * (ATTN_BAIL fell 9.6 percent on a signal-storm workload) and
             * crashes tests/test-mmap-sigbus-efault, because the fast paths it
             * re-engages have no answer for a stage-2 fault on a truncated
             * MAP_SHARED overlay: EC=0x24 reaches EL2 and no arm handles it.
             * The clear stays here until that gap is closed.
             */
            shim_globals_recompute_attention(g);

            /* Diagnostic: log signal state after exec/sigreturn to help debug
             * signal delivery issues.
             */
            if (ret == SYSCALL_EXEC_HAPPENED && verbose) {
                uint64_t tblocked = current_thread
                                        ? thread_blocked_load(current_thread)
                                        : 0xDEAD;
                log_debug(
                    "%s: post-sigreturn state: "
                    "pending=0x%llx global_blocked=0x%llx "
                    "thread_blocked=0x%llx signal_pending=%d",
                    prefix, (unsigned long long) signal_shared_pending_load(),
                    (unsigned long long) signal_blocked_load(),
                    (unsigned long long) tblocked, signal_pending());
            }

            running = syscall_return_epilogue(g, vcpu, ret, running, exit_code);

            /* After exec, verify critical registers before resuming vCPU. This
             * closes any gap where signal delivery or other code between
             * sys_execve's sync flush and hv_vcpu_run could have modified
             * ELR_EL1.
             */
            if (running && ret == SYSCALL_EXEC_HAPPENED) {
                uint64_t verify_elr;
                hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &verify_elr);
                if (verify_elr == 0) {
                    log_fatal(
                        "%s: ELR_EL1=0 after exec, register sync "
                        "failed",
                        prefix);
                    crash_report(vcpu, g, CRASH_ELR_ZERO,
                                 "ELR_EL1=0 after exec");
                    *exit_code = 128;
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
            *exit_code = (int) x0;
            running = false;
            break;
        }

        case 4: {
            /* HVC #4: Set system register (from shim). X0 = reg index into
             * hvc4_sysregs, X1 = value.
             */
            uint64_t reg_id, value;
            hv_vcpu_get_reg(vcpu, HV_REG_X0, &reg_id);
            hv_vcpu_get_reg(vcpu, HV_REG_X1, &value);

            if (reg_id >= ARRAY_SIZE(hvc4_sysregs)) {
                log_error("%s: HVC #4 unknown reg %llu", prefix,
                          (unsigned long long) reg_id);
                *exit_code = 128;
                return VCPU_STOP;
            }
            if (verbose)
                log_debug("%s: HVC #4 set reg %llu = 0x%llx", prefix,
                          (unsigned long long) reg_id,
                          (unsigned long long) value);
            HV_CHECK(hv_vcpu_set_sys_reg(vcpu, hvc4_sysregs[reg_id], value));
            break;
        }

        case 7: {
            vcpu_handle_mrs_trap(vcpu, verbose, prefix);
            break;
        }

        case 9: {
            running =
                vcpu_handle_wx_toggle(g, vcpu, verbose, prefix, exit_code);
            break;
        }

        case 10: {
            running = vcpu_handle_brk(g, vcpu, verbose, prefix, exit_code);
            break;
        }

        case 11:
            running =
                vcpu_handle_el0_fault(g, vcpu, verbose, prefix, exit_code);
            break;

        case 12: {
            vcpu_handle_sysinstr_trap(vcpu, verbose, prefix);
            break;
        }

        case 13:
            /* Only the epilogue above arms this. Without the check a detour
             * nobody asked for would park the thread in thread_ptrace_stop
             * waiting on a tracer that will never CONT it: a silent hang
             * instead of a report.
             */
            if (!cpu_ptrace_stop_armed) {
                log_fatal("%s: HVC #13 with no ptrace stop armed", prefix);
                crash_report(vcpu, g, CRASH_UNEXPECTED_HVC,
                             "HVC #13 without an armed ptrace stop");
                *exit_code = 128;
                running = false;
                break;
            }
            cpu_ptrace_stop_armed = false;
            running = ptrace_take_stop(g, vcpu, exit_code);
            break;

        case 2: {
            running = vcpu_handle_bad_exception(g, vcpu, prefix, exit_code);
            break;
        }

        case 6: {
            /* HVC #6: embedder extension hook. X8 = call number, X0-X7 =
             * arguments. If a dispatch function is registered via
             * elfuse_set_hvc6_handler(), it is called here. Otherwise falls
             * through as a no-op.
             */
            if (g->hvc6_handler) {
                uint64_t x8 = 0;
                hv_vcpu_get_reg(vcpu, HV_REG_X8, &x8);
                uint64_t args[8] = {0};
                for (int i = 0; i < 8; i++)
                    hv_vcpu_get_reg(vcpu, HV_REG_X0 + i, &args[i]);
                hvc6_yield_requested = false;
                uint64_t result = g->hvc6_handler(x8, args, g->hvc6_userdata);
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
            *exit_code = 128;
            running = false;
            break;
        }
        }
    } else if (ec == 0x30 || ec == 0x32) {
        /* EC=0x30: Hardware breakpoint from lower EL (EL0). EC=0x32: Software
         * step exception from lower EL. Both are debug exceptions trapped to
         * host via hv_vcpu_set_trap_debug_exceptions(). Forward to GDB.
         *
         * TDE causes debug exceptions to bypass EL1 entirely (EL0 -> EL2), so
         * ELR_EL1 is NOT updated; it still holds the stale value from the
         * shim's last ERET. Read the actual stop PC from HV_REG_PC and sync it
         * to ELR_EL1 so the GDB register snapshot sees the correct value.
         */
        if (gdb_stub_is_active()) {
            int reason = (ec == 0x30) ? GDB_STOP_BREAKPOINT : GDB_STOP_STEP;
            uint64_t stop_pc = vcpu_get_reg(vcpu, HV_REG_PC);

            /* TDE routes debug exceptions EL0->EL2, bypassing EL1. ELR_EL1 and
             * SPSR_EL1 are NOT updated; sync them from HV_REG_PC/HV_REG_CPSR so
             * the GDB register snapshot reads correct values.
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
            log_debug("%s: debug exception EC=0x%x (no GDB attached)", prefix,
                      ec);
        }
    } else if (ec == 0x34 || ec == 0x35) {
        /* EC=0x34: Watchpoint from lower EL (EL0, data abort). EC=0x35:
         * Watchpoint from current EL (shouldn't happen). Same TDE bypass as
         * breakpoints: ELR_EL1 and FAR_EL1 are stale because the exception went
         * EL0->EL2. Use HV_REG_PC for the stop PC and vexit->exception for the
         * watched address.
         */
        if (gdb_stub_is_active()) {
            uint64_t wp_pc = vcpu_get_reg(vcpu, HV_REG_PC);
            vcpu_set_sysreg(vcpu, HV_SYS_REG_ELR_EL1, wp_pc);
            vcpu_set_sysreg(vcpu, HV_SYS_REG_SPSR_EL1,
                            vcpu_get_reg(vcpu, HV_REG_CPSR));
            uint64_t wp_addr = vexit->exception.virtual_address;
            if (verbose)
                log_debug("%s: watchpoint at addr=0x%llx -> GDB", prefix,
                          (unsigned long long) wp_addr);
            gdb_stub_handle_stop(GDB_STOP_WATCHPOINT, wp_addr);
            gdb_stub_sync_debug_regs(vcpu);
        } else if (verbose) {
            log_debug("%s: watchpoint EC=0x%x (no GDB attached)", prefix, ec);
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
            snprintf(detail, sizeof(detail),
                     "EC=0x%x syndrome=0x%llx VA=0x%llx", ec,
                     (unsigned long long) vexit->exception.syndrome,
                     (unsigned long long) vexit->exception.virtual_address);
            crash_report(vcpu, g, CRASH_UNEXPECTED_EC, detail);
        }
        *exit_code = 128;
        running = false;
    }
    return running ? VCPU_RESUME : VCPU_STOP;
}

/* Canceled-exit handling, lifted out of vcpu_run_loop_with_hooks.
 *
 * Its own function because every branch below reads or rebuilds the guest's
 * register state, and they only agree about where that state lives if they
 * share one precondition. Inline among the loop's other arms they did not: the
 * signal branch grew an EL1 guard and the ptrace branch above it did not, which
 * is how a stop taken inside the shim came to show the tracer scratch. A guard
 * that has to hold for four consecutive branches belongs at the top of a
 * function they are all inside, not repeated in each.
 *
 * VCPU_RESUME means the exit was handled and the vCPU should re-enter the
 * guest. VCPU_STOP means leave the run loop with *exit_code, which the caller
 * has already been given.
 */
static vcpu_action_t vcpu_handle_canceled_exit(guest_t *g,
                                               hv_vcpu_t vcpu,
                                               bool is_main,
                                               bool verbose,
                                               const char *prefix,
                                               int *exit_code)
{
    /* Canceled by hv_vcpus_exit(). Can be: alarm timeout, exit_group from
     * another thread, or signal preemption (a queued guest signal, a fork
     * barrier, or a ptrace interrupt kicked the vCPU out of a tight loop).
     *
     * Every self-directed hv_vcpus_exit is now issued from the preemption
     * thread (proc_preempt_init), never from a vCPU thread, so hv_vcpu_run
     * always returns CANCELED here. HV_EXIT_REASON_UNKNOWN therefore no longer
     * has a legitimate producer -- it falls through to the "unexpected exit
     * reason" crash path below.
     */
    if (is_main && atomic_load_explicit(&g_timed_out, memory_order_acquire)) {
        /* Timeout already handled above the exception switch -- loop back so
         * the timeout check fires.
         */
        return VCPU_RESUME;
    }
    if (proc_exit_group_requested()) {
        *exit_code = proc_exit_group_code();
        return VCPU_STOP;
    }

    /* An execve tearing this thread down wins over everything below: the GDB
     * stop parks on an unbounded condvar with no teardown predicate, and the
     * ptrace stop and signal delivery both touch guest memory the exec is about
     * to reset. Reaching any of them here would outlive the join cap in
     * thread_exec_de_thread.
     */
    if (!is_main && thread_exec_stop_requested()) {
        *exit_code = 0;
        return VCPU_STOP;
    }

    /* Nothing below may run while the vCPU sits at EL1. The GDB stop, the
     * ptrace stop, the rseq abort and the signal frame all read or rebuild the
     * guest's register state, and inside the shim that state is not live: the
     * guest's values are in the saved SVC frame, the working registers are shim
     * scratch, and ELR_EL1 holds the EL0 return the shim still means to ERET
     * through. A stop taken there shows the tracer scratch and drops what it
     * writes back; a signal frame built there restores that scratch on
     * rt_sigreturn. signal_deliver already splits the EL0-preemption case out
     * for the same reason (see its saved_pc comment); EL1 is the third case and
     * has no correct reading at all.
     *
     * Resuming is what converges, and a self-directed hv_vcpus_exit is not: it
     * is one-shot and takes effect before the next hv_vcpu_run executes
     * anything, so the vCPU would re-exit at the same EL1 PC forever (measured:
     * every threaded test hangs). Instead every EL1 window is short and ends at
     * either HVC #5 or an ERET to EL0, the fast paths test attention on entry,
     * futex_wait_fast re-tests it inside its spin, and both the signal and
     * ptrace kicks raise attention before kicking. So the work lands a
     * microsecond later at HVC #5, which restores the frame before HVC #13
     * takes the stop.
     */
    uint64_t cur_cpsr = 0;
    hv_vcpu_get_reg(vcpu, HV_REG_CPSR, &cur_cpsr);
    if ((cur_cpsr & 0xfULL) != 0)
        return VCPU_RESUME;

    /* GDB stub: if GDB requested a stop (Ctrl+C or another thread hit a
     * breakpoint), enter GDB stop state.
     */
    if (gdb_stub_stop_requested()) {
        if (verbose)
            log_debug("%s: GDB stop request -> entering GDB stop", prefix);
        gdb_stub_handle_stop(GDB_STOP_SIGNAL, 0);
        gdb_stub_sync_debug_regs(vcpu);
        return VCPU_RESUME;
    }

    /* PTRACE_INTERRUPT: take the stop the tracer asked for. The kick that
     * brought the vCPU here may not be the one that owes it, and the flag is
     * what says whether anything is owed at all.
     */
    if (ptrace_consume_owed_stop(g) && !ptrace_take_stop(g, vcpu, exit_code))
        return VCPU_STOP;

    /* rseq preemption abort: mirrors Linux rseq_ip_fixup() on context switch.
     */
    if (current_thread->rseq_gva != 0) {
        /* HV_REG_PC, not ELR_EL1: the guard above established EL0, where the
         * resume runs from PC and ELR_EL1 is stale from the previous syscall
         * return. Redirecting through ELR_EL1 here would be a no-op, and a
         * critical section interrupted at EL0 with no queued signal (a
         * fork-barrier or ptrace wakeup) would never abort.
         */
        uint64_t cur_pc = 0;
        hv_vcpu_get_reg(vcpu, HV_REG_PC, &cur_pc);
        int rseq_rc = rseq_try_abort(g, current_thread->rseq_gva,
                                     current_thread->rseq_signature, &cur_pc);
        if (rseq_rc == 1)
            hv_vcpu_set_reg(vcpu, HV_REG_PC, cur_pc);
        if (rseq_rc == -1) {
            *exit_code = 128 + 11; /* SIGSEGV */
            return VCPU_STOP;
        }
    }

    /* Check guest ITIMER_REAL (may have fired during tight loop) */
    signal_check_timer();

    /* Signal preemption: if a signal is pending, deliver it and resume the
     * vCPU. This enables alarm()/SIGALRM delivery and tgkill-based signals in
     * compute-bound loops.
     */
    if (signal_pending()) {
        if (signal_deliver(vcpu, g, exit_code) < 0)
            return VCPU_STOP;

        /* Delivered, or nothing was pending after all: either way the vCPU
         * resumes.
         */
        return VCPU_RESUME;
    }

    /* Fork quiesce barrier: if a sibling is performing a fork snapshot, block
     * here until the snapshot is complete. This prevents torn memory snapshots
     * in multithreaded guests.
     */
    if (thread_fork_barrier_check())
        return VCPU_RESUME;

    /* No signal pending; truly unexpected cancelation */
    if (verbose)
        log_debug("%s: vCPU canceled (no signal pending)", prefix);
    return VCPU_RESUME;
}

/* Unified vCPU execution loop for both main and worker threads.
 *
 * When timeout_sec > 0 (main thread): arms the repeating watchdog timer and
 * publishes progress to it, logs with "elfuse:" prefix.
 *
 * When timeout_sec == 0 (worker thread): no watchdog (SIGALRM is process-wide
 * and would conflict). Workers are terminated by exit_group setting
 * proc_exit_group_requested and calling hv_vcpus_exit() to cancel pending
 * hv_vcpu_run calls. Logs with "elfuse: worker" prefix.
 *
 * Both modes check proc_exit_group_requested so the main thread also reacts to
 * exit_group called by a worker.
 *
 * The body is the loop and nothing else: run the vCPU, then dispatch on why it
 * stopped. Each reason's handling lives in its own function above, which is
 * what took this from 610 lines and a size-lint suppression down to under 200,
 * and what gave the two handlers that rebuild guest register state one place to
 * state the precondition they share.
 */
int vcpu_run_loop_with_hooks(hv_vcpu_t vcpu,
                             hv_vcpu_exit_t *vexit,
                             guest_t *g,
                             bool verbose,
                             int timeout_sec,
                             int *wait_status_out,
                             const vcpu_run_hooks_t *hooks)
{
    int exit_code = 0;
    (void) signal_take_termination_wait_status();
    bool running = true;

    /* Unsigned, and 64-bit, because the watchdog derives a parity from it
     * below: signed overflow is undefined, and this increments once per guest
     * exit, so a guest making a million syscalls a second reaches 2^31 in about
     * half an hour. Unsigned wrap is defined and preserves the parity, 2^64
     * being even.
     */
    uint64_t iter = 0;
    const int is_main = (timeout_sec > 0);
    const char *prefix = is_main ? "elfuse" : "elfuse: worker";

    /* Pin vCPU thread to a performance core via QoS class. On Apple Silicon,
     * USER_INTERACTIVE maps to P-cores, avoiding E-core migration that causes
     * measurable jank in HVF workloads.
     */
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    /* Main thread: arm the watchdog timer. SIGALRM is blocked here and consumed
     * by the preemption thread (proc_preempt_init), which sets g_timed_out and
     * kicks the vCPU via hv_vcpus_exit. Guest ITIMER_REAL is emulated
     * internally by signal_check_timer() rather than using host setitimer,
     * because macOS shares alarm() and setitimer(ITIMER_REAL) as the same
     * underlying timer.
     *
     * Repeating rather than one-shot: it_interval is what lets the watchdog
     * tick on its own forever instead of re-arming itself from the signal
     * handler. Re-arming would need the period published across threads and
     * would race the loop's own disarm.
     */
    if (is_main) {
        atomic_store_explicit(&g_timed_out, 0, memory_order_relaxed);

        struct itimerval every = {
            .it_interval = {.tv_sec = timeout_sec, .tv_usec = 0},
            .it_value = {.tv_sec = timeout_sec, .tv_usec = 0},
        };
        setitimer(ITIMER_REAL, &every, NULL);
    }

    while (running) {
        /* Check if another thread called exit_group */
        if (proc_exit_group_requested()) {
            exit_code = proc_exit_group_code();
            break;
        }

        /* An execve on a sibling thread is tearing this one down. Leaving the
         * loop takes it through the normal worker exit path (robust list,
         * CLEARTID, own-vCPU destroy) against the still-intact old image; the
         * exec'ing thread waits for that before guest_reset. The main thread is
         * exempt because it owns process teardown: returning from its run loop
         * destroys the guest, which is exactly what the exec'ing thread still
         * needs. This gates re-entry into hv_vcpu_run, so one check per
         * iteration is enough; every path back here is non-blocking for a
         * stopping worker, whose waits now return EINTR.
         */
        if (!is_main && thread_exec_stop_requested()) {
            exit_code = 0;
            break;
        }

        /* A non-leader execve is handed here: the leader owns process teardown,
         * so it is the only thread that can survive one. Running it at the top
         * of the loop puts the rebuilt EL0 state in place before the vCPU is
         * resumed, whether this thread was preempted in guest code or is
         * returning from its own syscall (sys_execve sets the X8=2 frame-drop
         * marker either way).
         */
        if (thread_current_is_leader() && thread_leader_work_pending())
            exec_run_handoff(vcpu, g, verbose);

        if (hooks && hooks->tick) {
            int tick_ret = hooks->tick(g, hooks->opaque);
            if (tick_ret != 0) {
                exit_code = tick_ret;
                break;
            }
            if (proc_exit_group_requested()) {
                exit_code = proc_exit_group_code();
                break;
            }
        }

        if (verbose) {
            uint64_t pc;
            hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc);
            log_debug("%s: [%llu] vcpu_run PC=0x%llx", prefix,
                      (unsigned long long) iter, (unsigned long long) pc);
        }
        iter++;

        /* Main: publish progress to the watchdog. Odd while inside the guest,
         * even outside; see g_vcpu_progress.
         */
        if (is_main)
            atomic_store_explicit(&g_vcpu_progress, iter * 2 + 1,
                                  memory_order_relaxed);

        HV_CHECK_CTX(hv_vcpu_run(vcpu), vcpu, g);

        drain_external_guest_signal();

        /* An HVF return can land inside the EL1 fast path's producer window,
         * with retire.producer_active published for this vCPU's own slot. Only
         * the guest clears that word, and every host path that takes mmap_lock
         * waits for it in mmap_fastpath_host_gate_close(). Waiting there would
         * block this thread on a vCPU that cannot run until this very thread
         * re-enters it. Resume before dispatching either a cancellation or an
         * exception. The producer window is bounded and non-blocking, so it
         * retires at once; pending host attention survives to the next exit.
         */
        while ((vexit->reason == HV_EXIT_REASON_CANCELED ||
                vexit->reason == HV_EXIT_REASON_EXCEPTION) &&
               mmap_fastpath_current_producer_active(g)) {
            HV_CHECK_CTX(hv_vcpu_run(vcpu), vcpu, g);
            drain_external_guest_signal();
        }

        /* Every return from HVF is a natural retirement point. Drain before
         * dispatching syscalls, page faults, MAP_FIXED, fork/exec, signals, or
         * exit so no host path can consult pre-munmap region metadata and
         * rematerialize an EL1-invalidated page. The helper also drains mmap
         * publications before the acquire-snapshotted retire entries.
         */
        if (!mmap_fastpath_current_producer_active(g))
            mmap_fastpath_drain_vmexit(
                g, vcpu_exit_is_fork_family_syscall(vcpu, vexit));

        /* Main: disarm timeout */
        if (is_main)
            atomic_store_explicit(&g_vcpu_progress, iter * 2 + 2,
                                  memory_order_relaxed);

        /* Re-check exit_group after waking from hv_vcpu_run */
        if (proc_exit_group_requested()) {
            exit_code = proc_exit_group_code();
            break;
        }

        /* Main: check for alarm timeout */
        if (is_main &&
            atomic_load_explicit(&g_timed_out, memory_order_acquire)) {
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
            if (vcpu_handle_exception_exit(g, vcpu, vexit, verbose, prefix,
                                           &exit_code) == VCPU_STOP) {
                break;
            }
        } else if (vexit->reason == HV_EXIT_REASON_CANCELED) {
            if (vcpu_handle_canceled_exit(g, vcpu, is_main, verbose, prefix,
                                          &exit_code) == VCPU_STOP) {
                break;
            }
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

    /* Clean up the timeout the run loop armed. Clearing it_interval as well as
     * it_value is what makes the disarm final: the timer repeats on its own
     * interval, so zeroing only the pending shot would leave it ticking for the
     * life of the process with nothing watching it.
     */
    if (is_main) {
        struct itimerval off = {0};
        setitimer(ITIMER_REAL, &off, NULL);
    }

    if (wait_status_out) {
        int signal_status = signal_take_termination_wait_status();
        *wait_status_out =
            signal_status != 0 ? signal_status : (exit_code & 0xff) << 8;
    }
    return exit_code;
}

int vcpu_run_loop(hv_vcpu_t vcpu,
                  hv_vcpu_exit_t *vexit,
                  guest_t *g,
                  bool verbose,
                  int timeout_sec,
                  int *wait_status_out)
{
    return vcpu_run_loop_with_hooks(vcpu, vexit, g, verbose, timeout_sec,
                                    wait_status_out, NULL);
}
