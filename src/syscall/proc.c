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
#include <pthread.h>
#include <signal.h>
#include <sys/file.h> /* flock() */
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
#include "core/mmap-fastpath.h"
#include "core/vdso.h"

#include "runtime/futex.h"

#include "syscall/internal.h"
#include "syscall/net.h"
#include "syscall/proc-identity.h"
#include "syscall/proc.h"
#include "syscall/proc-pidfd.h"
#include "syscall/proc-state.h"
#include "syscall/poll.h"
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
                                  int64_t guest_pid_val,
                                  int64_t pgid)
{
    entry->active = true;
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
        struct rusage ru;
        pid_t ret = wait4(proc_table[i].host_pid, &status, WNOHANG, &ru);
        if (ret > 0) {
            /* Child exited; free the slot */
            proc_children_cpu_add(&ru);
            proc_table[i].active = false;
            reaped++;
        }
    }
    return reaped;
}

int proc_register_child(pid_t host_pid, int64_t guest_pid_val, int64_t pgid)
{
    pthread_mutex_lock(&pid_lock);
    proc_entry_t *entry = proc_find_free_entry();
    if (entry) {
        proc_init_child_entry(entry, host_pid, guest_pid_val, pgid);
        pthread_mutex_unlock(&pid_lock);
        proc_registry_publish(host_pid, guest_pid_val, pgid);
        proc_registry_publish_self();
        return 0;
    }

    /* Table full. Try reaping exited children, then retry. */
    if (proc_reap_finished() > 0)
        entry = proc_find_free_entry();
    if (entry) {
        proc_init_child_entry(entry, host_pid, guest_pid_val, pgid);
        pthread_mutex_unlock(&pid_lock);
        proc_registry_publish(host_pid, guest_pid_val, pgid);
        proc_registry_publish_self();
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

static void proc_registry_reset_if_owner(const char *path)
{
    static _Atomic bool reset_done;
    if (absock_get_namespace_id() != (uint64_t) getpid())
        return;
    if (atomic_exchange(&reset_done, true))
        return;
    unlink(path);
}

/* One live member of a process group registry. */
typedef struct {
    pid_t host_pid;
    int64_t guest_pid;
    int64_t pgid;
} registry_entry_t;

#define REGISTRY_MAX_ENTRIES (PROC_TABLE_SIZE * 4)

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
 * record, passing a NUL-terminated copy. Records must fit in 63 bytes; both the
 * registry ("hostpid guestpid pgid") and the signal transport ("ns tgpid sig")
 * use short numeric lines. Overlong records and an unterminated trailing token
 * are dropped -- every writer appends a whole record under an exclusive lock,
 * so a partial line only appears after a crash mid-write.
 */
static void for_each_record(int fd, void (*cb)(char *rec, void *ctx), void *ctx)
{
    char chunk[8192];
    char line[64];
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

/* Locate @target's guest pid without registry_parse_cb's per-record
 * kill(2) liveness probe: that check exists to build a filtered live-
 * membership list for group-signal delivery, but a host_pid ->guest_pid
 * lookup is only ever done for a pid the caller just observed to be alive
 * (e.g. it holds a conflicting file lock right now), so it is redundant
 * here. proc_host_to_guest_pid still verifies the match via proc_pidpath
 * to guard against the pid having been recycled.
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
                proc_write_full(fd, lineb, (size_t) len) < 0)
                break;
        }
    }
    flock_retry(fd, LOCK_UN);
    close(fd);
}

void proc_registry_publish_self(void)
{
    proc_registry_publish(getpid(), proc_get_pid(), proc_get_pgid());
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

int proc_send_guest_signal(pid_t host_pid, int64_t target_guest_pid, int signum)
{
    /* Refuse to signal a host pid that is not (or is no longer) an elfuse
     * process: if it was recycled onto an unrelated program, a raw SIGUSR2
     * would terminate it. This narrows -- but a sub-microsecond exit+reuse race
     * before kill() remains -- see the signal-transport TODO.
     */
    int our_len;
    const char *our_path = elfuse_self_path(&our_len);
    char tpath[PROC_PIDPATHINFO_MAXSIZE];
    int tlen = proc_pidpath(host_pid, tpath, sizeof(tpath));
    if (our_len <= 0 || tlen != our_len || memcmp(tpath, our_path, our_len)) {
        errno = ESRCH;
        return -1;
    }

    char path[PATH_MAX];
    if (!signal_transport_path(path, sizeof(path), host_pid)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = open(path, O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC | O_NOFOLLOW,
                  0600);
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
    int wrc = proc_write_full(fd, line, (size_t) len);
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

int proc_get_direct_child_pids(pid_t *out, int max_pids)
{
    int count = 0;
    pthread_mutex_lock(&pid_lock);
    for (int i = 0; i < PROC_TABLE_SIZE && count < max_pids; i++) {
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

    /* Guard against host pid reuse: only trust the hit if the pid still
     * runs this elfuse binary, same check as proc_get_namespace_targets.
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
         *
         * Read the vCPU handle under thread_lock: thread_find drops the lock
         * before returning, so touching target->vcpu afterwards would race a
         * concurrent teardown/recycle. Snapshot the handle while locked, then
         * call HVF outside the lock (framework calls must not run under it).
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
        hv_vcpu_t vcpu = target->vcpu;
        /* If the tracee is still in vCPU bring-up (handle not yet published),
         * hv_vcpus_exit cannot reach it, and dropping the interrupt would lose
         * it silently. Record it under thread_lock: the worker checks this flag
         * at publish and self-kicks so the interrupt is delivered before it
         * runs any guest code. This serializes against the worker's publish
         * (also under thread_lock), so exactly one of the two paths delivers
         * it.
         */
        if (!vcpu)
            target->ptrace_interrupt_pending = true;
        pthread_mutex_unlock(tlock);

        if (vcpu)
            hv_vcpus_exit(&vcpu, 1);
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

/* Deactivate the wait4 process-table slot iff it still holds @host_pid.
 * sys_wait4 releases pid_lock across the host wait4 call, so another reaper
 * thread may have recycled the slot in the meantime; the @host_pid re-check
 * guards against clobbering an unrelated child that took the slot. pid_lock
 * must not be held.
 */
static void proc_deactivate_slot_if_matches(int slot, pid_t host_pid)
{
    pthread_mutex_lock(&pid_lock);
    if (proc_table[slot].active && proc_table[slot].host_pid == host_pid)
        proc_table[slot].active = false;
    pthread_mutex_unlock(&pid_lock);
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
                pid_t ret =
                    wait4(host_pid, &status, mac_options | WNOHANG, &ru);
                if (ret > 0) {
                    /* Credit CPU only on a terminal report. mac_options may
                     * carry WUNTRACED/WCONTINUED, and a stop/continue report
                     * is a snapshot of a still-running child: crediting it
                     * here would double- or triple-count the same child
                     * across its stop, continue, and final exit reports.
                     */
                    if (WIFEXITED(status) || WIFSIGNALED(status))
                        proc_children_cpu_add(&ru);
                    if (status_gva) {
                        int32_t linux_status = status;
                        if (guest_write_small(g, status_gva, &linux_status,
                                              sizeof(linux_status)) < 0) {
                            /* Child already reaped. Match Linux: return EFAULT
                             */
                            proc_deactivate_slot_if_matches(slot, host_pid);
                            return -LINUX_EFAULT;
                        }
                    }
                    if (rusage_gva &&
                        write_rusage_to_guest(g, rusage_gva, &ru) < 0) {
                        proc_deactivate_slot_if_matches(slot, host_pid);
                        return -LINUX_EFAULT;
                    }
                    proc_deactivate_slot_if_matches(slot, host_pid);
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

            /* exit_group teardown: stop re-arming the wait. The 100ms quantum
             * below bounds how stale this check can be, mirroring the futex
             * wait quanta. The errno is never guest-visible: the run loop
             * breaks on the exit-group flag before returning to the guest.
             */
            if (proc_exit_group_requested()) {
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
            pid_t ret;
            if (mac_options & WNOHANG) {
                ret = wait4(host_pid, &status, mac_options, &ru);
            } else {
                /* A bare blocking wait4 has no re-check point: a worker
                 * parked here past exit_group is invisible to
                 * thread_join_workers' poll cap and touches guest memory
                 * (status/rusage writes below) on an eventual delayed
                 * return, well after guest_destroy may have unmapped it.
                 * Poll with WNOHANG under a bounded retry instead, mirroring
                 * the pid==-1 loop above; proc_mark_child_exited broadcasts
                 * pid_cond on every host child exit.
                 */
                for (;;) {
                    ret = wait4(host_pid, &status, mac_options | WNOHANG, &ru);
                    if (ret != 0)
                        break;
                    if (proc_exit_group_requested())
                        return -LINUX_EINTR;
                    struct timespec ts;
                    timespec_deadline_in_ms(&ts, 100);
                    pthread_mutex_lock(&pid_lock);
                    pthread_cond_timedwait(&pid_cond, &pid_lock, &ts);
                    pthread_mutex_unlock(&pid_lock);
                }
            }
            if (ret > 0) {
                /* Same terminal-report gate as the P_ALL branch above. */
                if (WIFEXITED(status) || WIFSIGNALED(status))
                    proc_children_cpu_add(&ru);
                if (status_gva) {
                    int32_t linux_status = status;
                    if (guest_write_small(g, status_gva, &linux_status,
                                          sizeof(linux_status)) < 0) {
                        proc_deactivate_slot_if_matches(slot, host_pid);
                        return -LINUX_EFAULT;
                    }
                }
                if (rusage_gva &&
                    write_rusage_to_guest(g, rusage_gva, &ru) < 0) {
                    proc_deactivate_slot_if_matches(slot, host_pid);
                    return -LINUX_EFAULT;
                }
                /* Re-validate slot: another thread may have reaped it */
                proc_deactivate_slot_if_matches(slot, host_pid);
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
                struct rusage ru;
                ret = wait4(host_pid, &status, WNOHANG, &ru);
                /* Credit only a terminal report, and only when this call
                 * actually consumes the reap: WNOWAIT must leave the child
                 * waitable with its CPU uncounted until the later consuming
                 * wait, but this inner wait4() has no WNOWAIT of its own, so
                 * it consumes the host zombie regardless of the guest's
                 * WNOWAIT request.
                 */
                if (ret > 0 && !(options & LINUX_WNOWAIT) &&
                    (WIFEXITED(status) || WIFSIGNALED(status)))
                    proc_children_cpu_add(&ru);
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

/* Preemption signals: SIGUSR2 is the cross-process guest-signal doorbell
 * (proc_send_guest_signal), SIGALRM is the main thread's per-iteration safety
 * timeout (armed by alarm() in vcpu_run_loop). Both are consumed by a dedicated
 * sigwait thread rather than a per-thread signal handler.
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
    if (!others)
        unlink(path);
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

/* Parse one NUL-terminated "namespace target_guest_pid signum" transport record
 * and queue the signal only when both the fork-family namespace and the
 * intended guest pid match this process. A namespace mismatch means the host
 * pid was recycled from an unrelated session; a guest-pid mismatch means it was
 * recycled onto a different guest in this session. Either way the delivery is
 * dropped.
 */
static void sig_drain_cb(char *rec, void *vctx)
{
    sig_drain_ctx_t *c = vctx;
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
        RANGE_CHECK(signum, 1, LINUX_NSIG))
        signal_queue((int) signum);
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

    /* Main thread: arm the alarm-based per-iteration timeout below. SIGALRM is
     * blocked here and consumed by the preemption thread (proc_preempt_init),
     * which sets g_timed_out and kicks the vCPU via hv_vcpus_exit. Guest
     * ITIMER_REAL is emulated internally by signal_check_timer() rather than
     * using host setitimer, because macOS shares alarm() and
     * setitimer(ITIMER_REAL) as the same underlying timer.
     */
    if (is_main)
        atomic_store_explicit(&g_timed_out, 0, memory_order_relaxed);

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

        /* Every return from HVF is a natural retirement point.  Drain before
         * dispatching syscalls, page faults, MAP_FIXED, fork/exec, signals, or
         * exit so no host path can consult pre-munmap region metadata and
         * rematerialize an EL1-invalidated page.  The helper also drains mmap
         * publications before the acquire-snapshotted retire entries.
         */
        bool munmap_producer_active = mmap_fastpath_current_producer_active(g);
        if (!munmap_producer_active)
            mmap_fastpath_drain_vmexit(g);
        else if (vexit->reason == HV_EXIT_REASON_EXCEPTION)
            log_error(
                "%s: exception exit interrupted an active EL1 munmap "
                "producer",
                prefix);

        /* Main: disarm timeout */
        if (is_main)
            alarm(0);

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
                            prefix, (unsigned long long) ss->shared.pending,
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
                    mmap_lock_acquire(g);

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
                            mmap_lock_release();
                            uint64_t esr;
                            hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &esr);
                            signal_set_fault_info(LINUX_SEGV_ACCERR, far, esr);
                            int sig_ret = signal_deliver_fault(
                                vcpu, g, LINUX_SIGSEGV, &exit_code);
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
                    mmap_lock_release();
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
                     *
                     * The HVC #9 shim now consumes X8 as a post-HVC marker:
                     * 0 means W^X succeeded and the shim should run the TLBI
                     * retry epilogue; 2 means signal_deliver_fault installed a
                     * handler frame and the shim must drop its saved frame.
                     * Clear X8 here so a guest's pre-fault X8 value cannot be
                     * misread as the frame-drop marker after a normal toggle.
                     */
                    tlbi_request_clear();
                    hv_vcpu_set_reg(vcpu, HV_REG_X8, 0);
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
                        if (verbose) {
                            uint64_t thread_blocked =
                                current_thread ? current_thread->blocked
                                               : 0xDEAD;
                            log_debug(
                                "%s: BRK: thread_blocked=0x%llx "
                                "pending=0x%llx",
                                prefix, (unsigned long long) thread_blocked,
                                (unsigned long long) signal_get_state()
                                    ->shared.pending);
                        }
                        int sig_ret = signal_deliver_fault(
                            vcpu, g, LINUX_SIGTRAP, &exit_code);
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
                        int sig_ret = signal_deliver_fault(
                            vcpu, g, LINUX_SIGILL, &exit_code);
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
                        mmap_lock_acquire(g);
                        int mat = guest_materialize_lazy_fault(g, fault_off);
                        mmap_lock_release();
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
                            shim_globals_counter_inc(
                                g, SHIM_COUNTER_FAULT_MATERIALIZE);
                            switch ((tlbi_kind_t) cpu_tlbi_req.kind) {
                            case TLBI_RANGE:
                                shim_globals_counter_inc(
                                    g, SHIM_COUNTER_FAULT_TLBI_VAE);
                                break;
                            case TLBI_RANGE_LARGE:
                                shim_globals_counter_inc(
                                    g, SHIM_COUNTER_FAULT_TLBI_RVAE);
                                break;
                            case TLBI_BROADCAST:
                                shim_globals_counter_inc(
                                    g, SHIM_COUNTER_FAULT_TLBI_BCAST);
                                break;
                            case TLBI_NONE:
                            default:
                                break;
                            }
                            tlbi_request_emit_to_vcpu(vcpu);
                            break;
                        }
                    }

                    /* Bounded retry on a stale-TLB data / instruction abort.
                     * Re-walk the live page tables for the faulting VA before
                     * declaring SIGSEGV. guest_ptr_avail consults pt_gen, which
                     * the mutating vCPU bumps under mmap_lock, so the walk
                     * reflects the current mapping regardless of this vCPU's
                     * cached (possibly stale) hardware TLB. A non-NULL result
                     * means the live PT is valid and grants the faulting access
                     * -- the signature of a stale TLB entry that a cross-vCPU
                     * mprotect + TLBI failed to evict on this PE.
                     *
                     * On that signature, re-issue a selective TLBI for the
                     * faulting page from this vCPU (same accumulator + emit
                     * path the lazy-materialization branch uses) and return to
                     * EL0 to retry the instruction. A genuinely stale entry
                     * clears on the first retry, so the guest makes progress
                     * and never re-enters here for that VA.
                     *
                     * The retry is bounded per vCPU and per (page, faulting
                     * PC). If the same instruction keeps faulting on the same
                     * page despite the re-issued TLBI, the entry is not
                     * actually stale (a walker / hardware permission-model
                     * disagreement, or an HVF TLBI that did not take): after
                     * STALE_TLB_RETRY_MAX attempts, stop retrying and deliver
                     * SIGSEGV so a genuine fault is never silently swallowed.
                     * The per-vCPU slot resets when a different page or PC
                     * faults or when the cap is hit, so a cap-out cannot poison
                     * a later legitimate retry.
                     */
                    enum { STALE_TLB_RETRY_MAX = 16 };
                    /* Only translation (fsc_type 0x01) and permission (0x03)
                     * faults are stale-TLB plausible. Alignment,
                     * external-abort, and access-flag classes cannot be cleared
                     * by re-issuing TLBI, so do not spend the retry budget on
                     * them. A translation fault reaches here only after the
                     * lazy- materialization branch above already declined the
                     * address, so a live PT that still grants access is a stale
                     * negative (translation-fault) entry; a permission fault is
                     * the classic stale entry left by a cross-vCPU mprotect.
                     */
                    bool stale_plausible =
                        (fsc_type == 0x01 || fsc_type == 0x03);
                    int want_perm =
                        (fault_ec == 0x20)
                            ? MEM_PERM_X
                            : ((esr & (1u << 6)) ? MEM_PERM_W : MEM_PERM_R);
                    uint64_t live_avail = 0;
                    void *live_pt = NULL;
                    if (stale_plausible) {
                        mmap_lock_acquire(g);
                        live_pt = guest_ptr_avail_nofault(
                            g, far_addr, &live_avail, want_perm);
                        mmap_lock_release();
                    }
                    if (live_pt) {
                        /* Bound per vCPU and per (page, faulting PC). A
                         * genuinely stuck entry re-faults on the same
                         * instruction at the same page, so keying the counter
                         * on both distinguishes a non-recovering loop (cap it)
                         * from separate successful recoveries -- a different
                         * PC, or the same page reached from a different
                         * instruction -- that must each get a fresh budget.
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
                                    "live PT grants access -- stale TLB; "
                                    "re-issuing TLBI and retrying (cap %d)",
                                    prefix,
                                    (fault_ec == 0x20) ? "inst" : "data",
                                    (unsigned long long) far_addr,
                                    (unsigned long long) esr,
                                    STALE_TLB_RETRY_MAX);
                            }
                            tlbi_request_clear();
                            tlbi_request_range(page, page + GUEST_PAGE_SIZE);
                            if (want_perm & MEM_PERM_X)
                                tlbi_request_mark_icache();
                            tlbi_request_emit_to_vcpu(vcpu);
                            break;
                        }
                        /* Retry budget exhausted: the entry is not actually
                         * stale. Reset the slot and fall through to SIGSEGV.
                         */
                        log_warn(
                            "%s: stale-TLB retry cap (%d) hit at 0x%llx "
                            "(ESR=0x%llx); delivering SIGSEGV",
                            prefix, STALE_TLB_RETRY_MAX,
                            (unsigned long long) far_addr,
                            (unsigned long long) esr);
                        stale_page = 0;
                        stale_elr = 0;
                        stale_count = 0;
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
                    int sig_ret = signal_deliver_fault(vcpu, g, LINUX_SIGSEGV,
                                                       &exit_code);
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
             * from another thread, or signal preemption (a queued guest signal,
             * a fork barrier, or a ptrace interrupt kicked the vCPU out of a
             * tight loop).
             *
             * Every self-directed hv_vcpus_exit is now issued from the
             * preemption thread (proc_preempt_init), never from a vCPU thread,
             * so hv_vcpu_run always returns CANCELED here.
             * HV_EXIT_REASON_UNKNOWN therefore no longer has a legitimate
             * producer -- it falls through to the "unexpected exit reason"
             * crash path below.
             */
            if (is_main &&
                atomic_load_explicit(&g_timed_out, memory_order_acquire)) {
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
                /* Same EL0-preemption hazard as signal delivery: when the vCPU
                 * was preempted while executing EL0 code, ELR_EL1 is stale from
                 * the previous syscall return and the resume runs from
                 * HV_REG_PC. Read the interrupted PC -- and write the abort_ip
                 * back -- through whichever register the resume actually
                 * consumes, selected from the live PSTATE (M[3:0]==0 => EL0t).
                 * Otherwise a critical section interrupted at EL0 with no
                 * queued signal (fork-barrier/ptrace wakeups) would never
                 * abort.
                 */
                uint64_t cur_pc, cur_cpsr = 0;
                hv_vcpu_get_reg(vcpu, HV_REG_CPSR, &cur_cpsr);
                bool el0_preempt = (cur_cpsr & 0xfULL) == 0;
                if (el0_preempt)
                    hv_vcpu_get_reg(vcpu, HV_REG_PC, &cur_pc);
                else
                    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &cur_pc);
                int rseq_rc =
                    rseq_try_abort(g, current_thread->rseq_gva,
                                   current_thread->rseq_signature, &cur_pc);
                if (rseq_rc == 1) {
                    if (el0_preempt)
                        hv_vcpu_set_reg(vcpu, HV_REG_PC, cur_pc);
                    else
                        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, cur_pc);
                }
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
    if (is_main)
        alarm(0);

    return exit_code;
}
