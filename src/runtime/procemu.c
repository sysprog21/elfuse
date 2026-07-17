/*
 * /proc and /dev path emulation
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Intercepts openat and readlinkat for /proc, /dev, /etc, and /var/run paths.
 * Returns host fds for synthetic content, or -2 if the path is not intercepted
 * (caller falls through to real syscall).
 */

/*
 * Initial capacity for the transient /proc/self/maps and /proc/self/smaps VMA
 * snapshot. The region tracker documents that coalescing leaves typical
 * workloads at roughly 50 tracked regions (see core/guest.h), so 64 avoids an
 * immediate growth in that case. The array grows as needed while mmap_lock is
 * held; keep a hard ceiling tied to the guest's region tables so maps/smaps can
 * enumerate every tracked VMA while keeping transient snapshot memory bounded.
 */
#define MAPS_ENTRY_INITIAL_CAP 64
#define MAPS_ENTRY_MAX \
    (GUEST_MAX_REGIONS + GUEST_MAX_PREANNOUNCED * (GUEST_MAX_REGIONS + 1))

/* Bound the transient host-PID snapshot used by /proc/net enumeration. This is
 * an output-work limit, not the dynamically growing lifecycle-table cap.
 */
#define PROC_NET_PID_SNAPSHOT_MAX 1024

/* Column at which the region name starts in /proc/self/maps output. Matches
 * observed Linux kernel formatting (verified via strace).
 */
#define MAPS_NAME_COLUMN 73

#include <ctype.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <libproc.h>
#include <mach/mach.h>

#include "utils.h"

#include "proved/slice.h"

#include "debug/log.h"
#include "runtime/procemu.h"
#include "runtime/procemu-internal.h"
#include "runtime/usb-sysfs.h"
#include "core/rosetta.h"
#include "runtime/thread.h"

#include "syscall/linux-wire.h"
#include "syscall/fd.h"
#include "syscall/fuse.h"
#include "syscall/internal.h"
#include "syscall/net-identity.h"
#include "syscall/path.h"
#include "syscall/proc.h"
#include "syscall/sys.h"

/* Return the shared /dev/shm emulation directory, creating it on first call.
 * Linux POSIX shm names live in one namespace, so this must not be keyed by the
 * host process id.
 *
 * Uses a mutex for thread-safe lazy initialization while still allowing retries
 * after transient failures. The mkdir+lstat sequence has an inherent TOCTOU
 * window, but the lstat ownership check limits the impact to directories
 * already owned by this UID.
 */
static char shm_dir[128];
static bool shm_dir_ok;
static int shm_dir_errno;
static pthread_mutex_t shm_dir_lock = PTHREAD_MUTEX_INITIALIZER;

/* Synthetic /proc directory backing store. Lazily initialized by
 * ensure_proc_tmpdir() on first access to any /proc path that needs directory
 * enumeration (find, ls, etc.). Protected by proc_tmpdir_lock for thread safety
 * (multiple vCPUs can reach proc_intercept_open concurrently without holding a
 * global lock).
 */
static char proc_tmpdir[128];
static bool proc_tmpdir_ok;
static pthread_mutex_t proc_tmpdir_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    uint64_t start, end;
    int prot, flags;
    uint64_t offset;
    bool inherited_at_fork;
    char name[64];

    /* Preserve the producer order for equal-start entries when qsort() is used
     * below. Existing snapshots placed equal-start entries after one another in
     * append order, and keeping that order avoids changing the handling of
     * malformed/overlapping shadow metadata.
     */
    size_t order;
} maps_entry_t;

/* A growable VMA snapshot. The generated facade keeps element-size and
 * allocation bookkeeping in the generic array implementation.
 */
DYNAMIC_ARRAY_DEFINE(maps_entries, maps_entry_t)

/* Round a VMA endpoint up to the 4 KiB granularity exposed by procfs without
 * allowing the addition to wrap. There is no representable page-aligned
 * endpoint above UINT64_MAX - 0xFFF, so saturate to UINT64_MAX and let the
 * caller's normal end <= start validation handle an empty interval.
 */
static uint64_t maps_align_up_page(uint64_t value)
{
    const uint64_t mask = 0xFFFULL;
    if (value > UINT64_MAX - mask)
        return UINT64_MAX;
    return (value + mask) & ~mask;
}

/* Translate a shadow VMA's cursor into its file offset. A wrapped offset would
 * produce a syntactically valid but semantically wrong maps entry, so surface
 * the overflow to the intercepted open instead.
 */
static int maps_shadow_offset(const guest_region_t *shadow,
                              uint64_t shadow_start,
                              uint64_t cursor,
                              uint64_t *offset_out)
{
    uint64_t delta = cursor - shadow_start;
    if (delta > UINT64_MAX - shadow->offset) {
        errno = EOVERFLOW;
        return -1;
    }
    *offset_out = shadow->offset + delta;
    return 0;
}

static int maps_entries_append_entry(maps_entries_t *entries,
                                     uint64_t start,
                                     uint64_t end,
                                     int prot,
                                     int flags,
                                     uint64_t offset,
                                     const char *name,
                                     bool inherited_at_fork)
{
    if (end <= start)
        return 0;
    if (maps_entries_count(entries) >= MAPS_ENTRY_MAX) {
        errno = ENOMEM;
        return -1;
    }
    if (maps_entries_count(entries) == 0 &&
        maps_entries_reserve(entries, MAPS_ENTRY_INITIAL_CAP) < 0)
        return -1;

    maps_entry_t value = {
        .start = start,
        .end = end,
        .prot = prot,
        .flags = flags,
        .offset = offset,
        .inherited_at_fork = inherited_at_fork,
        .order = maps_entries_count(entries),
    };
    if (name && name[0])
        str_copy_trunc(value.name, name, sizeof(value.name));
    else
        value.name[0] = '\0';

    return maps_entries_append_value(entries, value);
}

/* The live-region and shadow-gap producers are each ordered, but their outputs
 * interleave. Append both streams while holding mmap_lock and sort once after
 * all gaps have been generated. This avoids shifting an already populated array
 * for every split shadow gap (the old insertion path was quadratic for
 * fragmented snapshots).
 */
static int maps_entries_compare_start(const void *lhs, const void *rhs)
{
    const maps_entry_t *a = lhs;
    const maps_entry_t *b = rhs;
    if (a->start < b->start)
        return -1;
    if (a->start > b->start)
        return 1;
    if (a->order < b->order)
        return -1;
    if (a->order > b->order)
        return 1;
    return 0;
}

static void maps_entries_merge_adjacent(maps_entries_t *entries)
{
    size_t count = maps_entries_count(entries);
    if (count <= 1)
        return;

    size_t out = 0;
    for (size_t i = 1; i < count; i++) {
        maps_entry_t *current = maps_entries_at(entries, i);
        maps_entry_t *previous = maps_entries_at(entries, out);
        if (current->start == previous->end &&
            current->prot == previous->prot &&
            current->flags == previous->flags &&
            current->offset == previous->offset &&
            current->inherited_at_fork == previous->inherited_at_fork &&
            strcmp(current->name, previous->name) == 0) {
            previous->end = current->end;
            continue;
        }
        ++out;
        if (out != i)
            *maps_entries_at(entries, out) = *current;
    }
    (void) maps_entries_resize(entries, out + 1);
}

/* Add only the portions of a preannounced interval not covered by live VMAs. A
 * shadow VMA must never overlap a realized VMA: strict smaps consumers treat
 * overlapping headers as a malformed snapshot. Both inputs are page-rounded
 * because that is the granularity exposed by /proc/self/maps.
 */
static int maps_entries_append_shadow_gaps(maps_entries_t *entries,
                                           const guest_region_t *shadow,
                                           const guest_region_t *live_regions,
                                           int nlive)
{
    uint64_t shadow_start = shadow->start & ~0xFFFULL;
    uint64_t shadow_end = maps_align_up_page(shadow->end);
    if (shadow_end <= shadow_start)
        return 0;

    uint64_t cursor = shadow_start;
    for (int i = 0; i < nlive && cursor < shadow_end; i++) {
        uint64_t live_start = live_regions[i].start & ~0xFFFULL;
        uint64_t live_end = maps_align_up_page(live_regions[i].end);
        if (live_end <= live_start || live_end <= cursor)
            continue;
        if (live_start >= shadow_end)
            break;

        if (live_start > cursor) {
            uint64_t gap_end =
                live_start < shadow_end ? live_start : shadow_end;
            uint64_t offset;
            if (maps_shadow_offset(shadow, shadow_start, cursor, &offset) < 0)
                return -1;
            if (maps_entries_append_entry(
                    entries, cursor, gap_end, shadow->prot, shadow->flags,
                    offset, shadow->name, shadow->inherited_at_fork) < 0)
                return -1;
        }
        if (live_end > cursor)
            cursor = live_end;
    }

    if (cursor < shadow_end) {
        uint64_t offset;
        if (maps_shadow_offset(shadow, shadow_start, cursor, &offset) < 0)
            return -1;
        if (maps_entries_append_entry(entries, cursor, shadow_end, shadow->prot,
                                      shadow->flags, offset, shadow->name,
                                      shadow->inherited_at_fork) < 0)
            return -1;
    }
    return 0;
}

/* Synthetic /sys/devices/system/cpu directory backing store. Populated lazily
 * on first access (Java GC, Go runtime, libnuma probe these to size thread
 * pools). Layout matches the minimal subset Linux exposes:
 *   <syscpu_dir>/online    text file: "0\n" or "0-N\n"
 *   <syscpu_dir>/possible  same
 *   <syscpu_dir>/present   same
 *   <syscpu_dir>/cpuN/     one empty dir per CPU (cache/topology stays empty
 *                          until a real consumer asks for those subtrees)
 * Population is a one-shot snapshot taken at first call: the host CPU count
 * does not change at runtime, so refresh is unnecessary.
 *
 * syscpu_owner_pid records the pid that ran mkdtemp so atexit-driven cleanup
 * runs only in that process. clone(CLONE_VM) children inherit the host atexit
 * list and the populated syscpu_dir_ok state, so without the guard a child exit
 * would rmdir the parent's still-active scratch tree.
 */
static char syscpu_dir[128];
static bool syscpu_dir_ok;
static pid_t syscpu_owner_pid;
static pthread_mutex_t syscpu_dir_lock = PTHREAD_MUTEX_INITIALIZER;

/* OOM range constants from Linux include/uapi/linux/oom.h. */
#define LINUX_OOM_SCORE_ADJ_MIN (-1000)
#define LINUX_OOM_SCORE_ADJ_MAX 1000
#define LINUX_OOM_DISABLE (-17)
#define LINUX_OOM_ADJUST_MAX 15

/* Process-wide stub for the OOM score adjustment. The legacy oom_adj interface,
 * the modern oom_score_adj interface, and the read-only oom_score node all
 * derive their displayed values from this single state.
 */
static _Atomic int oom_score_adj_value = 0;

/* Serializes backing-fd rewrites so concurrent writers do not race the
 * truncate+pwrite sequence that publishes the new value to a same-fd reader.
 * The atomic store happens last so a failed rewrite leaves the global state
 * unchanged.
 */
static pthread_mutex_t oom_write_lock = PTHREAD_MUTEX_INITIALIZER;

enum {
    OOM_PATH_NONE = 0,
    OOM_PATH_SCORE_ADJ, /* /proc/self/oom_score_adj: writable, [-1000, 1000] */
    OOM_PATH_ADJ,       /* /proc/self/oom_adj: legacy, writable, [-17, 15] */
    OOM_PATH_SCORE,     /* /proc/self/oom_score: read-only computed score */
};

static int proc_oom_path_kind(const char *path)
{
    if (!strcmp(path, "/proc/self/oom_score_adj"))
        return OOM_PATH_SCORE_ADJ;
    if (!strcmp(path, "/proc/self/oom_adj"))
        return OOM_PATH_ADJ;
    if (!strcmp(path, "/proc/self/oom_score"))
        return OOM_PATH_SCORE;
    return OOM_PATH_NONE;
}

/* Linux fs/proc/base.c oom_adj_write: a write to oom_adj is scaled into the
 * [-1000, 1000] oom_score_adj domain. The kernel special-cases both boundary
 * values so the "disable" and "max" semantics survive the lossy multiply that
 * would otherwise round 15*1000/17 to 882 and lose the "kill me first" intent.
 */
static int oom_adj_to_score_adj(int v)
{
    if (v == LINUX_OOM_DISABLE)
        return LINUX_OOM_SCORE_ADJ_MIN;
    if (v == LINUX_OOM_ADJUST_MAX)
        return LINUX_OOM_SCORE_ADJ_MAX;
    return v * LINUX_OOM_SCORE_ADJ_MAX / -LINUX_OOM_DISABLE;
}

/* Inverse of oom_adj_to_score_adj for legacy oom_adj reads. Clamp to the legacy
 * [-17, 15] range so values outside the representable space (e.g. a guest that
 * wrote -1000 to oom_score_adj) do not surprise readers.
 */
static int oom_score_adj_to_adj(int v)
{
    int s = v * -LINUX_OOM_DISABLE / LINUX_OOM_SCORE_ADJ_MAX;
    if (s < LINUX_OOM_DISABLE)
        s = LINUX_OOM_DISABLE;
    if (s > LINUX_OOM_ADJUST_MAX)
        s = LINUX_OOM_ADJUST_MAX;
    return s;
}

static int proc_oom_format_value(int kind, char *buf, size_t bufsz)
{
    int score_adj =
        atomic_load_explicit(&oom_score_adj_value, memory_order_relaxed);
    int val = 0;
    if (kind == OOM_PATH_SCORE_ADJ)
        val = score_adj;
    else if (kind == OOM_PATH_ADJ)
        val = oom_score_adj_to_adj(score_adj);
    return snprintf(buf, bufsz, "%d\n", val);
}

static int proc_oom_copy_slice(char *dst,
                               size_t count,
                               int64_t offset,
                               const char *src,
                               uint64_t src_len,
                               ssize_t *read_out)
{
    if (offset < 0) {
        errno = EINVAL;
        return -1;
    }
    uint64_t n;
    if (!slice_clamp(src_len, (uint64_t) offset, count, &n)) {
        *read_out = 0;
        return 1;
    }

    memcpy(dst, src + offset, (size_t) n);
    *read_out = (ssize_t) n;
    return 1;
}

typedef struct {
    int fd;
    int kind;
} proc_oom_live_fd_t;

/* OOM proc nodes are opened on per-open temp files so lseek/pread semantics
 * work naturally. After any successful write, republish the current formatted
 * value into every still-open OOM fd so a later seek+read on another fd does
 * not observe the stale snapshot that was materialized at open time.
 */
static void proc_oom_refresh_live_fds_locked(void)
{
    proc_oom_live_fd_t live[FD_TABLE_SIZE];
    int nlive = 0;

    pthread_mutex_lock(&fd_lock);
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        int kind = proc_oom_path_kind(fd_table[i].proc_path);
        if (kind == OOM_PATH_NONE || fd_table[i].type == FD_CLOSED)
            continue;

        int dup_fd = dup(fd_table[i].host_fd);
        if (dup_fd < 0)
            continue;

        live[nlive].fd = dup_fd;
        live[nlive].kind = kind;
        nlive++;
    }
    pthread_mutex_unlock(&fd_lock);

    for (int i = 0; i < nlive; i++) {
        char text[32];
        int len = proc_oom_format_value(live[i].kind, text, sizeof(text));
        if (len > 0 && (size_t) len < sizeof(text)) {
            /* Rewrite the backing temp file as defense in depth for any code
             * path that might bypass proc_intercept_read and fall through to
             * host read(). The dup'd fd shares the open file description with
             * the guest's fd, so a paired lseek to "restore" the offset would
             * clobber a concurrent reader's position; skip the offset dance and
             * let proc_intercept_read (which always pulls from the atomic) be
             * the source of truth for offset-aware reads.
             */
            if (ftruncate(live[i].fd, 0) == 0)
                pwrite(live[i].fd, text, (size_t) len, 0);
        }
        close(live[i].fd);
    }
}

static int proc_lazy_mkdtemp(char *buf, size_t buf_size, const char *template);
static int append_proc_net_row(char *buf,
                               size_t bufsz,
                               int off,
                               bool want_tcp,
                               int sl,
                               const char laddr[33],
                               uint16_t lport,
                               const char raddr[33],
                               uint16_t rport,
                               int st);
static void format_proc_net_addr(char out[33],
                                 const struct in_sockinfo *ini,
                                 int local,
                                 int v6);

/* Per-open scratch dirs for /proc/self/fd and /proc/self/fdinfo.
 *
 * The previous design shared one host directory across every open, which meant
 * a second open could unlink/recreate entries while the first opener was
 * mid-getdents on its dirfd. Each open now allocates its own mkdtemp dir, so
 * concurrent enumerations cannot mutate one another.
 *
 * The tracker keeps the paths so an atexit hook can rmdir them at process exit.
 * The capacity is a soft cap: callers that exceed it leak the dir to /tmp
 * (cleared on host reboot or by tmp janitors).
 */
#define PROC_SCRATCH_DIRS_MAX 128
static char proc_scratch_dirs[PROC_SCRATCH_DIRS_MAX][80];
static int proc_scratch_dirs_count;
static pthread_mutex_t proc_scratch_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t proc_scratch_atexit_once = PTHREAD_ONCE_INIT;

void proc_scratch_remove_one(const char *dir)
{
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *ent;
        char path[160];
        while ((ent = readdir(d))) {
            if (ent->d_name[0] == '.' &&
                (ent->d_name[1] == '\0' ||
                 (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
                continue;
            int n = snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
            if (n > 0 && (size_t) n < sizeof(path))
                unlink(path);
        }
        closedir(d);
    }
    rmdir(dir);
}

static void proc_scratch_cleanup_atexit(void)
{
    pthread_mutex_lock(&proc_scratch_lock);
    for (int i = 0; i < proc_scratch_dirs_count; i++)
        proc_scratch_remove_one(proc_scratch_dirs[i]);
    proc_scratch_dirs_count = 0;
    pthread_mutex_unlock(&proc_scratch_lock);
}

static void proc_scratch_register_atexit(void)
{
    atexit(proc_scratch_cleanup_atexit);
}

/* Record a scratch directory for removal at exit, arming the atexit hook on
 * first use. The registry is private to this file; procemu-pty.c reaches it
 * through here rather than through the five statics behind it.
 */
void proc_scratch_register(const char *dir)
{
    pthread_once(&proc_scratch_atexit_once, proc_scratch_register_atexit);

    pthread_mutex_lock(&proc_scratch_lock);
    if (proc_scratch_dirs_count < PROC_SCRATCH_DIRS_MAX) {
        str_copy_trunc(proc_scratch_dirs[proc_scratch_dirs_count++], dir,
                       sizeof(proc_scratch_dirs[0]));
    }
    pthread_mutex_unlock(&proc_scratch_lock);
}

/* Open a per-call scratch directory populated with one empty file per live
 * guest fd.
 *
 * Returns a host dirfd on success, -1 on failure with errno set.
 *
 * The dirfd is the standard backing for getdents on this synthetic listing. Two
 * concurrent openers get two independent dirs, so neither mutates the other's
 * enumeration.
 */
static int proc_open_fd_scratch(const char *prefix, int linux_flags)
{
    char dir[80];
    int n = snprintf(dir, sizeof(dir), "/tmp/%s-XXXXXX", prefix);
    if (n < 0 || (size_t) n >= sizeof(dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (!mkdtemp(dir))
        return -1;

    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        fd_entry_t snap;
        if (!fd_snapshot(i, &snap))
            continue;
        char entry[160];
        int en = snprintf(entry, sizeof(entry), "%s/%d", dir, i);
        if (en <= 0 || (size_t) en >= sizeof(entry))
            continue;
        int tfd = open(entry, O_CREAT | O_WRONLY, 0444);
        if (tfd >= 0)
            close(tfd);
    }

    proc_scratch_register(dir);

    int fd = proc_open_dir_fd(dir, linux_flags);
    if (fd < 0) {
        int saved = errno;
        proc_scratch_remove_one(dir);
        errno = saved;
    }
    return fd;
}

/* atexit cleanup: remove snapshot files and the temp directory tree. */
static void proc_tmpdir_cleanup(void)
{
    if (!proc_tmpdir_ok || proc_tmpdir[0] == '\0')
        return;

    /* Remove known files inside <tmpdir>/<pid>/ and <tmpdir>/ */
    char path[256];
    const char *files[] = {"stat",  "status", "cmdline", "maps",
                           "smaps", "exe",    NULL};
    char piddir[160];

    /* Reconstruct pid subdir by scanning for the first numeric entry */
    DIR *d = opendir(proc_tmpdir);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d))) {
            if (ent->d_name[0] < '1' || ent->d_name[0] > '9')
                continue;
            snprintf(piddir, sizeof(piddir), "%s/%s", proc_tmpdir, ent->d_name);
            for (const char **f = files; *f; f++) {
                snprintf(path, sizeof(path), "%s/%s", piddir, *f);
                unlink(path);
            }
            /* Remove task subdirectory (may contain TID subdirs) */
            snprintf(path, sizeof(path), "%s/task", piddir);
            rmdir(path);
            rmdir(piddir);
        }
        closedir(d);
    }
    snprintf(path, sizeof(path), "%s/self", proc_tmpdir);
    unlink(path); /* symlink */
    rmdir(proc_tmpdir);
}

static void shm_dir_init(void)
{
    shm_dir_errno = EACCES;
    snprintf(shm_dir, sizeof(shm_dir), "/tmp/elfuse-shm-%u",
             (unsigned) getuid());

    /* create_private_dir rejects a symlink or foreign-owned directory that a
     * local user could have pre-planted at this guessable /tmp path.
     */
    if (create_private_dir(shm_dir) < 0) {
        shm_dir_errno = errno;
        log_error("/dev/shm dir %s: not a private directory: %s", shm_dir,
                  strerror(errno));
        shm_dir[0] = '\0';
        return;
    }
    shm_dir_ok = true;
}

static const char *shm_dir_path(void)
{
    pthread_mutex_lock(&shm_dir_lock);
    if (!shm_dir_ok)
        shm_dir_init();

    int saved_errno = shm_dir_ok ? 0 : (shm_dir_errno ? shm_dir_errno : EACCES);
    const char *result = shm_dir_ok ? shm_dir : NULL;
    pthread_mutex_unlock(&shm_dir_lock);

    if (!result)
        errno = saved_errno;
    return result;
}

const char *proc_get_shm_dir(void)
{
    return shm_dir_path();
}

/* Create a synthetic file from a buffer.
 *
 * Returns a host fd positioned at the start, or -1 on failure. Caller owns the
 * returned fd. Uses a temp file (unlinked immediately) so that pread/lseek
 * work.
 */
static int proc_synthetic_fd(const void *data, size_t len)
{
    int fd = tmpfile_anon("proc");
    if (fd < 0)
        return -1;

    const uint8_t *p = data;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        p += n;
        remaining -= n;
    }
    lseek(fd, 0, SEEK_SET); /* Rewind so first read starts at beginning */
    return fd;
}

/* Lazy mkdtemp into a caller-provided buffer.
 *
 * Returns 0 on success (buf holds the path), or -1 on failure (buf[0] reset to
 * '\0').
 *
 * Caller must hold the lock that protects buf, since the helper runs the "is
 * buf empty?" check and mkdtemp non-atomically. The created directory is reused
 * across calls until process exit.
 */
static int proc_lazy_mkdtemp(char *buf, size_t buf_size, const char *template)
{
    if (buf[0])
        return 0;
    str_copy_trunc(buf, template, buf_size);
    if (!mkdtemp(buf)) {
        buf[0] = '\0';
        return -1;
    }
    return 0;
}

/* Wrap an snprintf-style result into a synthetic fd, clamping the length into
 * the inclusive range zero through capacity-1. Common pattern for /proc/self
 * string files.
 */
static int proc_synthetic_fd_str(const char *buf, int snprintf_ret, size_t cap)
{
    if (snprintf_ret < 0)
        snprintf_ret = 0;
    if ((size_t) snprintf_ret >= cap)
        snprintf_ret = (int) (cap - 1);
    return proc_synthetic_fd(buf, (size_t) snprintf_ret);
}

/* Format a string into a stack buffer and return the synthetic fd in one step.
 * Collapses the recurring three-line pattern:
 *     char buf[N];
 *     int len = snprintf(buf, sizeof(buf), fmt, ...);
 *     return proc_synthetic_fd_str(buf, len, sizeof(buf));
 * 4096-byte cap is the largest formatted /proc payload elfuse emits via this
 * helper (the few handlers that exceed it -- /proc/self/maps, /proc/net/tcp --
 * build their output incrementally and call proc_synthetic_fd directly).
 */
__attribute__((format(printf, 1, 2))) static int proc_emit_fmt(const char *fmt,
                                                               ...)
{
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return proc_synthetic_fd_str(buf, n, sizeof(buf));
}

/* Emit a fixed string literal as a synthetic fd. Used for the handlers that
 * return identical content every time (mountinfo, filesystems, /proc/sys
 * constants); avoids allocating a stack buffer when there is nothing to format.
 */
static int proc_emit_literal(const char *s)
{
    return proc_synthetic_fd(s, strlen(s));
}

static int proc_open_net_dev(void)
{
    linux_net_identity_t ident;
    net_identity_snapshot(&ident);
    linux_netdev_stats_t *lo = &ident.lo_stats;
    linux_netdev_stats_t *eth0 = &ident.eth0_stats;

    return proc_emit_fmt(
        "Inter-|   Receive                                                |  "
        "Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed "
        "multicast|bytes    packets errs drop fifo colls carrier "
        "compressed\n"
        "    lo: %llu %llu %llu %llu %llu %llu %llu %llu "
        "%llu %llu %llu %llu %llu %llu %llu %llu\n"
        "  eth0: %llu %llu %llu %llu %llu %llu %llu %llu "
        "%llu %llu %llu %llu %llu %llu %llu %llu\n",
        (unsigned long long) lo->rx_bytes, (unsigned long long) lo->rx_packets,
        (unsigned long long) lo->rx_errs, (unsigned long long) lo->rx_drop,
        (unsigned long long) lo->rx_fifo, (unsigned long long) lo->rx_frame,
        (unsigned long long) lo->rx_compressed,
        (unsigned long long) lo->rx_multicast,
        (unsigned long long) lo->tx_bytes, (unsigned long long) lo->tx_packets,
        (unsigned long long) lo->tx_errs, (unsigned long long) lo->tx_drop,
        (unsigned long long) lo->tx_fifo, (unsigned long long) lo->tx_colls,
        (unsigned long long) lo->tx_carrier,
        (unsigned long long) lo->tx_compressed,
        (unsigned long long) eth0->rx_bytes,
        (unsigned long long) eth0->rx_packets,
        (unsigned long long) eth0->rx_errs, (unsigned long long) eth0->rx_drop,
        (unsigned long long) eth0->rx_fifo, (unsigned long long) eth0->rx_frame,
        (unsigned long long) eth0->rx_compressed,
        (unsigned long long) eth0->rx_multicast,
        (unsigned long long) eth0->tx_bytes,
        (unsigned long long) eth0->tx_packets,
        (unsigned long long) eth0->tx_errs, (unsigned long long) eth0->tx_drop,
        (unsigned long long) eth0->tx_fifo, (unsigned long long) eth0->tx_colls,
        (unsigned long long) eth0->tx_carrier,
        (unsigned long long) eth0->tx_compressed);
}

/* Return the basename of the loaded ELF binary, falling back to "elfuse" when
 * the path is unavailable. Matches the comm-name semantic Linux uses for
 * /proc/<pid>/comm and the second field of /proc/<pid>/stat. Storage is owned
 * by proc_get_elf_path() (stable for process lifetime) or the literal fallback;
 * caller must not free.
 */
static const char *proc_comm_name(void)
{
    /* Snapshot into a thread-local buffer so a concurrent execve cannot tear
     * the shared elf_path under the basename scan. The TLS lifetime matches the
     * calling thread, which is what callers (printf-style formatters) require.
     */
    static _Thread_local char exe_tls[LINUX_PATH_MAX];
    if (!proc_elf_path_snapshot(exe_tls, sizeof(exe_tls)))
        return "elfuse";
    const char *slash = strrchr(exe_tls, '/');
    return slash ? slash + 1 : exe_tls;
}

/* Parse the numeric tail of a /proc/.../<N> or /dev/fd/<N> path. prefix_len is
 * the length of the leading literal that the caller already matched with
 * strncmp.
 *
 * Returns the parsed fd on success, or -1 with errno set to errno_on_invalid
 * for any malformed input or out-of-range index.
 */
static int proc_parse_fd_index(const char *path,
                               size_t prefix_len,
                               int errno_on_invalid)
{
    int n = path_parse_proc_name(path + prefix_len);
    if (n < 0 || n >= FD_TABLE_SIZE) {
        errno = errno_on_invalid;
        return -1;
    }
    return n;
}

/* Map a guest /dev/shm/<name> path to its host backing path, and gate the name.
 *
 * macOS has no /dev/shm, so elfuse backs POSIX shared memory with a per-UID
 * host directory (/tmp/elfuse-shm-<uid>/). This is the single source of truth
 * for that mapping. Callers proc_intercept_open, proc_intercept_stat, and
 * path_translate_at (which records the hit in path_translation_t.is_dev_shm)
 * all resolve through here, so one guest shm path never resolves two ways (e.g.
 * open landing in the backing dir while chmod falls through to the sysroot).
 *
 * A POSIX shm name is always a single flat component: glibc's __shm_get_name
 * (posix/shm-directory.c) strips the leading slash and rejects an empty name or
 * any embedded '/' with EINVAL. This enforces the same shape, also rejects the
 * ".." component (whole-component compare, so a flat name like "a..b" is fine),
 * and returns EACCES (ENAMETOOLONG on overflow).
 *
 * The never-follow invariant lives here. On Linux /dev/shm is an in-namespace
 * tmpfs, so a symlink planted at a shm leaf resolves inside that namespace.
 * elfuse's backing store is a plain host directory, so the same symlink would
 * resolve onto the host filesystem, escaping the sandbox. A symlink leaf is
 * never legitimate anyway: glibc's shm_open (sysdeps/posix/shm_open.c) opens
 * objects with O_NOFOLLOW. So every shm op must act on the leaf without
 * following it. Because this resolver hands back an absolute host path that
 * bypasses the sysroot, that duty is spread across syscall families and
 * funneled through: path_translation_at_flags() (AT_SYMLINK_NOFOLLOW on the *at
 * metadata calls), shm_open_leaf() (O_NOFOLLOW fd for truncate/chdir), proc
 * open (O_NOFOLLOW), xattr (XATTR_NOFOLLOW), stat (lstat), linkat (clears
 * AT_SYMLINK_FOLLOW), and statfs (answered synthetically, never touching the
 * leaf).
 */
static int dev_shm_resolve_path(const char *guest_suffix,
                                char *host_path,
                                size_t host_path_sz)
{
    const char *shm = shm_dir_path();
    if (!shm)
        return -1;
    if (guest_suffix[0] == '\0' || strchr(guest_suffix, '/') ||
        !strcmp(guest_suffix, "..")) {
        errno = EACCES;
        return -1;
    }
    int n = snprintf(host_path, host_path_sz, "%s/%s", shm, guest_suffix);
    if (n < 0 || (size_t) n >= host_path_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

int proc_dev_shm_resolve(const char *guest_suffix,
                         char *host_path,
                         size_t host_path_sz)
{
    return dev_shm_resolve_path(guest_suffix, host_path, host_path_sz);
}

/* Give synthetic procfs nodes stable identities so directory walkers do not
 * collapse distinct paths into one inode and falsely report filesystem loops.
 */
#define PROC_SYNTH_DEV ((dev_t) 0x504f)

static ino_t proc_synth_ino(const char *path)
{
    /* Masked to a Linux-looking nonzero positive inode. */
    uint64_t h = fnv1a64(path, strlen(path));
    h &= 0x7fffffffffffffffULL;
    if (h == 0)
        h = 1;
    return (ino_t) h;
}

/* Populate *st for a synthetic /proc directory entry. */
static void stat_fill_proc_dir(struct stat *st,
                               mode_t mode,
                               nlink_t nlink,
                               const char *path)
{
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFDIR | mode;
    st->st_nlink = nlink;
    st->st_dev = PROC_SYNTH_DEV;
    st->st_ino = proc_synth_ino(path);
    st->st_uid = proc_get_uid();
    st->st_gid = proc_get_gid();
    st->st_blksize = 4096;
}

/* Resolve a /dev/fd/<N> or /proc/self/fd/<N> path to a fresh dup() of the
 * underlying host fd. prefix_len is the length of the matched literal (8 for
 * "/dev/fd/", 14 for "/proc/self/fd/").
 *
 * Returns the dup or -1 with errno=EBADF for malformed indices or closed slots.
 *
 * fd_to_host_dup duplicates the host fd atomically under fd_lock so a
 * concurrent close+reopen on another vCPU cannot redirect the dup to an
 * unrelated host object that took the freed slot.
 */
static int dev_fd_dup(const char *path, size_t prefix_len)
{
    int n = proc_parse_fd_index(path, prefix_len, EBADF);
    if (n < 0)
        return -1;
    int dup_fd = fd_to_host_dup(n);
    if (dup_fd < 0) {
        errno = EBADF;
        return -1;
    }
    return dup_fd;
}

/* If path matches /proc/<our_pid>[/...], rewrite into alias as /proc/self[...]
 * Used by both proc_intercept_open and proc_intercept_stat so the explicit-pid
 * form aliases through the same /proc/self handlers (Linux treats them
 * equivalent for the calling process). The trailing-character constraint admits
 * the bare /proc/<pid> directory and /proc/<pid>/X files alike.
 *
 * Returns 1 when alias was rewritten (caller should recurse on alias), 0 when
 * path is not a self-alias (caller continues with other handlers), or -1 with
 * errno=ENAMETOOLONG when the rewrite would overflow alias_sz (matches Linux
 * semantics for paths > PATH_MAX rather than letting the intercept fall through
 * to a host syscall that would silently fail).
 */
static int proc_alias_self(const char *path, char *alias, size_t alias_sz)
{
    if (strncmp(path, "/proc/", 6) != 0)
        return 0;
    char *endp;
    long pid = strtol(path + 6, &endp, 10);
    if (endp == path + 6 || pid != (long) proc_get_pid())
        return 0;
    if (*endp != '\0' && *endp != '/')
        return 0;
    int n = snprintf(alias, alias_sz, "/proc/self%s", endp);
    if (n < 0 || (size_t) n >= alias_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 1;
}

/* Populate *st for a synthetic /proc regular-file entry. Linux reports st_size
 * = 0 for proc nodes; mirroring that forces readers to drain to EOF instead of
 * pre-sizing buffers from a stale value.
 */
static void stat_fill_proc_file(struct stat *st, mode_t mode, const char *path)
{
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFREG | mode;
    st->st_nlink = 1;
    st->st_dev = PROC_SYNTH_DEV;
    st->st_ino = proc_synth_ino(path);
    st->st_uid = proc_get_uid();
    st->st_gid = proc_get_gid();
    st->st_size = 0;
    st->st_blksize = 4096;
    st->st_blocks = 0;
}

/* Visitor signature for proc_net_for_each_socket below. Returning false stops
 * the iteration (used when the caller's output buffer is full).
 *   sinfo: kernel socket info for the current fd
 *   pid:   pid that owns the fd (self or a fork child)
 *   fd_index: index within that pid's fdinfo list (used by /proc/net/unix
 *             to synthesize a fake-but-stable inode number)
 *
 * /proc/net/tcp's "sl" column must be dense, counting only emitted rows (not
 * inspected sockets), so the iterator deliberately omits a global serial
 * counter. Visitors that need one track it inside their own ctx and increment
 * it only after a successful emit.
 */
typedef bool (*proc_net_socket_visitor)(const struct socket_fdinfo *sinfo,
                                        pid_t pid,
                                        int fd_index,
                                        void *ctx);

/* Walk every socket fd across self plus active fork children, invoking visit
 * once per socket. Centralizes the proc_pidinfo + proc_pidfdinfo scaffolding
 * shared by /proc/net/{tcp,udp,raw}{,6} and /proc/net/unix.
 */
static void proc_net_for_each_socket(proc_net_socket_visitor visit, void *ctx)
{
    pid_t pids[PROC_NET_PID_SNAPSHOT_MAX + 1];
    pids[0] = getpid();
    int npids = 1 + proc_get_child_pids(pids + 1, PROC_NET_PID_SNAPSHOT_MAX);

    for (int p = 0; p < npids; p++) {
        struct proc_fdinfo fdinfo[512];
        int fdsz =
            proc_pidinfo(pids[p], PROC_PIDLISTFDS, 0, fdinfo, sizeof(fdinfo));
        if (fdsz <= 0)
            continue;
        int nfds = fdsz / (int) PROC_PIDLISTFD_SIZE;
        for (int fi = 0; fi < nfds; fi++) {
            if (fdinfo[fi].proc_fdtype != PROX_FDTYPE_SOCKET)
                continue;
            struct socket_fdinfo sinfo;
            int sz =
                proc_pidfdinfo(pids[p], fdinfo[fi].proc_fd,
                               PROC_PIDFDSOCKETINFO, &sinfo, sizeof(sinfo));
            if (sz < (int) sizeof(sinfo))
                continue;
            if (!visit(&sinfo, pids[p], fi, ctx))
                return;
        }
    }
}

/* Visitor context + callback for /proc/net/{tcp,udp,raw}{,6}. sl counts only
 * emitted rows so the "sl" column stays dense even when the iterator visits
 * other-family sockets that the visitor filters out.
 */
struct proc_net_inet_ctx {
    char *buf;
    size_t bufsz;
    int off;
    int sl;
    int want_af;
    int want_stype;
    bool want_tcp;
    bool want_v6;
};

/* Map macOS TSI_S_* socket states (returned in tcp_connection_info.state) to
 * the 1-based hex values Linux /proc/net/tcp uses (ESTABLISHED=01, LISTEN=0A,
 * etc.). Indexed by macOS state ordinal.
 */
static int proc_net_tcp_state_linux(int kstate)
{
    static const int state_map[] = {
        0x07, /* 0: CLOSED */
        0x0A, /* 1: LISTEN */
        0x02, /* 2: SYN_SENT */
        0x03, /* 3: SYN_RECEIVED */
        0x01, /* 4: ESTABLISHED */
        0x08, /* 5: CLOSE_WAIT */
        0x04, /* 6: FIN_WAIT_1 */
        0x06, /* 7: CLOSING */
        0x09, /* 8: LAST_ACK */
        0x05, /* 9: FIN_WAIT_2 */
        0x0B, /* 10: TIME_WAIT */
    };
    return RANGE_CHECK(kstate, 0, 11) ? state_map[kstate] : 0x07;
}

static bool proc_net_inet_visit(const struct socket_fdinfo *sinfo,
                                pid_t pid,
                                int fd_index,
                                void *ctx_v)
{
    (void) pid;
    (void) fd_index;
    struct proc_net_inet_ctx *c = ctx_v;
    if (c->off >= (int) c->bufsz - 256)
        return false;
    if (sinfo->psi.soi_family != c->want_af ||
        sinfo->psi.soi_type != c->want_stype)
        return true;

    const struct in_sockinfo *ini =
        c->want_tcp ? &sinfo->psi.soi_proto.pri_tcp.tcpsi_ini
                    : &sinfo->psi.soi_proto.pri_in;
    char laddr[33], raddr[33];
    format_proc_net_addr(laddr, ini, 1, c->want_v6);
    format_proc_net_addr(raddr, ini, 0, c->want_v6);
    int st =
        c->want_tcp
            ? proc_net_tcp_state_linux(sinfo->psi.soi_proto.pri_tcp.tcpsi_state)
            : 0x07;
    c->off = append_proc_net_row(c->buf, c->bufsz, c->off, c->want_tcp, c->sl,
                                 laddr, ntohs(ini->insi_lport), raddr,
                                 ntohs(ini->insi_fport), st);
    c->sl++;
    return true;
}

/* Visitor context + callback for /proc/net/unix. */
struct proc_net_unix_ctx {
    char *buf;
    size_t bufsz;
    int off;
};

/* Lock-protected handle to a persistent /tmp directory used to back synthetic
 * /proc subdirectories whose contents must repopulate per open (e.g.
 * /proc/self/task with its dynamic TID set). The static buffer + lazy mkdtemp
 * pattern is shared by multiple handlers so the helper keeps one source of
 * truth for the locking and creation order.
 */
typedef struct {
    char path[128];
    pthread_mutex_t lock;
    const char *template;
} proc_persistent_dir_t;

#define PROC_PERSISTENT_DIR(prefix) \
    {.path = {0}, .lock = PTHREAD_MUTEX_INITIALIZER, .template = prefix}

/* Acquire the persistent dir's lock and ensure the dir exists. Caller owns the
 * lock until proc_persistent_dir_release().
 *
 * Returns the directory path or NULL on failure (lock released, errno set).
 */
static const char *proc_persistent_dir_acquire(proc_persistent_dir_t *d)
{
    pthread_mutex_lock(&d->lock);
    if (proc_lazy_mkdtemp(d->path, sizeof(d->path), d->template) < 0) {
        pthread_mutex_unlock(&d->lock);
        return NULL;
    }
    return d->path;
}

static void proc_persistent_dir_release(proc_persistent_dir_t *d)
{
    pthread_mutex_unlock(&d->lock);
}

static bool proc_net_unix_visit(const struct socket_fdinfo *sinfo,
                                pid_t pid,
                                int fd_index,
                                void *ctx_v)
{
    (void) pid;
    struct proc_net_unix_ctx *c = ctx_v;

    /* A unix row is up to 56 bytes of fixed format plus a sun_path of up to 108
     * bytes plus the trailing newline -- ~165 bytes worst case. The 128-byte
     * margin previously inherited from the inline loop could leave a
     * half-formatted row at the buffer tail; 256 matches the inet visitor and
     * covers the longest possible path.
     */
    if (c->off >= (int) c->bufsz - 256)
        return false;
    if (sinfo->psi.soi_family != AF_UNIX)
        return true;
    int stype = sinfo->psi.soi_type;
    int lt = (stype == SOCK_STREAM)      ? 1
             : (stype == SOCK_DGRAM)     ? 2
             : (stype == SOCK_SEQPACKET) ? 5
                                         : 1;
    const char *spath = sinfo->psi.soi_proto.pri_un.unsi_addr.ua_sun.sun_path;
    c->off += snprintf(c->buf + c->off, c->bufsz - (size_t) c->off,
                       "%016X: %08X %08X %08X %04X %02X %5d %s\n", 0, 3, 0, 0,
                       lt, 3, 10000 + fd_index, spath[0] ? spath : "");
    return true;
}

static int append_proc_net_row(char *buf,
                               size_t bufsz,
                               int off,
                               bool want_tcp,
                               int sl,
                               const char laddr[33],
                               uint16_t lport,
                               const char raddr[33],
                               uint16_t rport,
                               int st)
{
    if (want_tcp) {
        return off + snprintf(buf + off, bufsz - (size_t) off,
                              "%4d: %s:%04X %s:%04X %02X "
                              "00000000:00000000 00:00000000 00000000"
                              "  1000        0 %d 1 0000000000000000 "
                              "100 0 0 10 0\n",
                              sl, laddr, lport, raddr, rport, st, 10000 + sl);
    }

    return off + snprintf(buf + off, bufsz - (size_t) off,
                          "%4d: %s:%04X %s:%04X %02X "
                          "00000000:00000000 00:00000000 00000000"
                          "  1000        0 %d 2 0000000000000000 0\n",
                          sl, laddr, lport, raddr, rport, st, 10000 + sl);
}

static int proc_parse_int_write(const void *buf, size_t count, int *out)
{
    const char *src = (const char *) buf;
    size_t len = count;
    char tmp[64];
    char *end;
    long parsed;

    while (len > 0 && (src[len - 1] == '\n' || src[len - 1] == '\r' ||
                       src[len - 1] == ' ' || src[len - 1] == '\t'))
        len--;
    if (len == 0 || len >= sizeof(tmp)) {
        errno = EINVAL;
        return -1;
    }

    memcpy(tmp, buf, len);
    tmp[len] = '\0';
    parsed = strtol(tmp, &end, 10);
    if (end == tmp || *end != '\0' || parsed < INT_MIN || parsed > INT_MAX) {
        errno = EINVAL;
        return -1;
    }
    *out = (int) parsed;
    return 0;
}

int proc_open_dir_fd(const char *path, int linux_flags)
{
    /* Linux refuses write access to a directory in open(2) itself: O_WRONLY,
     * O_RDWR, O_CREAT or O_TRUNC against a directory is EISDIR, decided before
     * the descriptor exists. Synthesizing the directory does not exempt it -- a
     * guest opening /dev/bus/usb or /proc/self for write must be told EISDIR
     * the way a real mount would, not handed a readable descriptor whose first
     * write then fails with something else.
     *
     * O_PATH is the documented exception: it opens the object for name
     * operations only, and the access mode is ignored rather than checked.
     */
    if (!(linux_flags & LINUX_O_PATH) &&
        ((linux_flags & LINUX_O_ACCMODE) != LINUX_O_RDONLY ||
         (linux_flags & (LINUX_O_CREAT | LINUX_O_TRUNC)))) {
        errno = EISDIR;
        return -1;
    }

    int oflags = O_RDONLY | O_DIRECTORY;

    if (linux_flags & LINUX_O_CLOEXEC)
        oflags |= O_CLOEXEC;

    return open(path, oflags);
}

static int proc_open_numbered_dir(const char *dir, int64_t id, int linux_flags)
{
    char path[128];
    int n = snprintf(path, sizeof(path), "%s/%lld", dir, (long long) id);

    if (n < 0 || (size_t) n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    return proc_open_dir_fd(path, linux_flags);
}

static int copy_fd_to_path(int src_fd, const char *path)
{
    int out = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0444);
    if (out < 0)
        return -1;

    if (lseek(src_fd, 0, SEEK_SET) < 0) {
        close(out);
        return -1;
    }

    char buf[4096];
    for (;;) {
        ssize_t n = read(src_fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(out);
            return -1;
        }
        if (n == 0)
            break;
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t) (n - off));
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                close(out);
                return -1;
            }
            off += w;
        }
    }

    close(out);
    lseek(src_fd, 0, SEEK_SET);
    return 0;
}

static void populate_proc_snapshot(const guest_t *g,
                                   const char *dir,
                                   const char *name,
                                   const char *proc_path)
{
    char path[LINUX_PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int) sizeof(path))
        return;

    int fd = proc_intercept_open(g, proc_path, 0, 0);
    if (fd < 0)
        return;
    copy_fd_to_path(fd, path);
    close(fd);
}

static void populate_proc_placeholder(const char *dir, const char *name)
{
    char path[LINUX_PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int) sizeof(path))
        return;

    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0444);
    if (fd >= 0)
        close(fd);
}

static void format_proc_net_addr(char out[33],
                                 const struct in_sockinfo *ini,
                                 int local,
                                 int v6)
{
    if (!v6) {
        uint32_t addr = local ? ini->insi_laddr.ina_46.i46a_addr4.s_addr
                              : ini->insi_faddr.ina_46.i46a_addr4.s_addr;
        snprintf(out, 33, "%08X", addr);
        return;
    }

    const struct in6_addr *addr =
        local ? &ini->insi_laddr.ina_6 : &ini->insi_faddr.ina_6;
    uint32_t words[4];
    memcpy(words, addr->s6_addr, sizeof(words));
    snprintf(out, 33, "%08X%08X%08X%08X", words[0], words[1], words[2],
             words[3]);
}

/* Lazily create the synthetic /proc directory tree.
 *
 * Returns the path to the temp dir, or NULL on failure. Thread-safe via
 * proc_tmpdir_lock (multiple vCPUs can hit proc_intercept_open concurrently).
 */
static const char *ensure_proc_tmpdir(const guest_t *g)
{
    pthread_mutex_lock(&proc_tmpdir_lock);
    if (proc_tmpdir_ok) {
        pthread_mutex_unlock(&proc_tmpdir_lock);
        return proc_tmpdir;
    }

    str_copy_trunc(proc_tmpdir, "/tmp/elfuse-proc-XXXXXX", sizeof(proc_tmpdir));
    if (!mkdtemp(proc_tmpdir)) {
        proc_tmpdir[0] = '\0';
        pthread_mutex_unlock(&proc_tmpdir_lock);
        return NULL;
    }

    char pidbuf[128], selfbuf[128];
    snprintf(pidbuf, sizeof(pidbuf), "%s/%lld", proc_tmpdir,
             (long long) proc_get_pid());
    if (mkdir(pidbuf, 0755) < 0 && errno != EEXIST) {
        rmdir(proc_tmpdir);
        proc_tmpdir[0] = '\0';
        pthread_mutex_unlock(&proc_tmpdir_lock);
        return NULL;
    }

    char piddir[128];
    str_copy_trunc(piddir, pidbuf, sizeof(piddir));
    populate_proc_snapshot(g, piddir, "stat", "/proc/self/stat");
    populate_proc_snapshot(g, piddir, "status", "/proc/self/status");
    populate_proc_snapshot(g, piddir, "cmdline", "/proc/self/cmdline");
    populate_proc_snapshot(g, piddir, "maps", "/proc/self/maps");
    populate_proc_snapshot(g, piddir, "smaps", "/proc/self/smaps");

    /* Create task subdirectory for /proc/self/task enumeration */
    char taskdir[128];
    snprintf(taskdir, sizeof(taskdir), "%s/task", piddir);
    mkdir(taskdir, 0755);

    char netdir[128];
    snprintf(netdir, sizeof(netdir), "%s/net", proc_tmpdir);
    if (mkdir(netdir, 0755) == 0 || errno == EEXIST) {
        static const char *net_files[] = {
            "dev", "tcp", "tcp6", "udp", "udp6", "raw", "raw6", "unix", NULL,
        };
        for (const char **name = net_files; *name; name++)
            populate_proc_placeholder(netdir, *name);
    }

    char exepath[128];
    snprintf(exepath, sizeof(exepath), "%s/exe", piddir);
    const char *exe = proc_get_elf_path();
    if (exe)
        symlink(exe, exepath);

    snprintf(selfbuf, sizeof(selfbuf), "%s/self", proc_tmpdir);
    snprintf(pidbuf, sizeof(pidbuf), "%lld", (long long) proc_get_pid());
    symlink(pidbuf, selfbuf); /* best-effort */

    atexit(proc_tmpdir_cleanup);
    proc_tmpdir_ok = true;
    pthread_mutex_unlock(&proc_tmpdir_lock);
    return proc_tmpdir;
}

/* Online/possible/present format the kernel uses for cpumask range files:
 *   single CPU -> "0\n"
 *   N CPUs     -> "0-N-1\n"
 * Mirrors Linux bitmap_print_to_pagebuf("%*pbl"), which is what every
 * /sys/devices/system/cpu cpumask file emits.
 */
static int syscpu_format_range(char *buf, size_t bufsz, int ncpu)
{
    if (ncpu <= 1)
        return snprintf(buf, bufsz, "0\n");
    return snprintf(buf, bufsz, "0-%d\n", ncpu - 1);
}

static int syscpu_count(void)
{
    int n = (int) sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1)
        n = 1;
    return n;
}

/* Walk syscpu_dir and remove every entry plus the dir itself. Caller is
 * responsible for any owner/initialized checks; the partial-init recovery path
 * needs to call this even when syscpu_dir_ok is still false.
 */
static void syscpu_dir_remove_tree(void)
{
    if (syscpu_dir[0] == '\0')
        return;

    DIR *d = opendir(syscpu_dir);
    if (d) {
        struct dirent *ent;
        char path[256];
        while ((ent = readdir(d))) {
            if (ent->d_name[0] == '.' &&
                (ent->d_name[1] == '\0' ||
                 (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
                continue;
            int n =
                snprintf(path, sizeof(path), "%s/%s", syscpu_dir, ent->d_name);
            if (n <= 0 || (size_t) n >= sizeof(path))
                continue;

            /* cpuN entries are directories, range files are regular files.
             * rmdir succeeds for the dirs, fails with ENOTDIR for files; unlink
             * covers the latter without an extra stat.
             */
            if (rmdir(path) < 0)
                unlink(path);
        }
        closedir(d);
    }
    rmdir(syscpu_dir);
}

static void syscpu_dir_cleanup(void)
{
    if (!syscpu_dir_ok)
        return;

    /* Only the process that ran mkdtemp may remove the tree. CLONE_VM children
     * inherit this atexit handler and the populated state, but the scratch dir
     * itself belongs to the parent.
     */
    if (getpid() != syscpu_owner_pid)
        return;
    syscpu_dir_remove_tree();
}

static int syscpu_write_file(const char *dir,
                             const char *name,
                             const char *data,
                             size_t len)
{
    char path[160];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int) sizeof(path))
        return -1;
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0444);
    if (fd < 0)
        return -1;
    int rc = 0;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, (const char *) data + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            rc = -1;
            break;
        }
        off += (size_t) w;
    }
    close(fd);
    return rc;
}

/* Lazily build /tmp/elfuse-syscpu-XXXXXX/ with the cpumask files and one empty
 * cpuN directory per host CPU.
 *
 * Returns the temp dir path on success, or NULL on failure with errno set. Any
 * failure mid-population tears down the partial tree so callers never observe a
 * half-built directory. Thread-safe via syscpu_dir_lock.
 */
static const char *ensure_syscpu_dir(void)
{
    pthread_mutex_lock(&syscpu_dir_lock);
    if (syscpu_dir_ok) {
        pthread_mutex_unlock(&syscpu_dir_lock);
        return syscpu_dir;
    }

    str_copy_trunc(syscpu_dir, "/tmp/elfuse-syscpu-XXXXXX", sizeof(syscpu_dir));
    if (!mkdtemp(syscpu_dir)) {
        syscpu_dir[0] = '\0';
        pthread_mutex_unlock(&syscpu_dir_lock);
        return NULL;
    }

    int ncpu = syscpu_count();
    char range[32];
    int range_len = syscpu_format_range(range, sizeof(range), ncpu);
    if (range_len < 0)
        range_len = 0;

    int saved_errno = 0;
    static const char *cpumask_files[] = {"online", "possible", "present",
                                          NULL};
    for (const char **f = cpumask_files; *f; f++) {
        if (syscpu_write_file(syscpu_dir, *f, range, (size_t) range_len) < 0) {
            saved_errno = errno;
            goto fail;
        }
    }

    char cpu_path[160];
    for (int i = 0; i < ncpu; i++) {
        if (snprintf(cpu_path, sizeof(cpu_path), "%s/cpu%d", syscpu_dir, i) >=
            (int) sizeof(cpu_path)) {
            saved_errno = ENAMETOOLONG;
            goto fail;
        }
        if (mkdir(cpu_path, 0555) < 0) {
            saved_errno = errno;
            goto fail;
        }
    }

    /* Record the owner before flipping syscpu_dir_ok so the cleanup hook, if it
     * ever observes the populated state, also sees the right pid.
     */
    syscpu_owner_pid = getpid();
    atexit(syscpu_dir_cleanup);
    syscpu_dir_ok = true;
    pthread_mutex_unlock(&syscpu_dir_lock);
    return syscpu_dir;

fail:
    /* Tear down the partial tree so a later call can mkdtemp a fresh slot.
     * Bypass the syscpu_dir_ok guard since this path runs before the flag is
     * flipped.
     */
    syscpu_dir_remove_tree();
    syscpu_dir[0] = '\0';
    pthread_mutex_unlock(&syscpu_dir_lock);
    errno = saved_errno;
    return NULL;
}

/* Reject any '..' component in suffix so the joined host path cannot escape the
 * scratch dir. The synthetic /sys/devices/system/cpu tree has no use case for
 * parent-directory traversal, and accepting it would let a guest call like
 * open("/sys/devices/system/cpu/../../etc/passwd") drive lstat/open on an
 * arbitrary host path. Empty components and '.' are harmless and pass through
 * unchanged.
 */
static bool syscpu_suffix_safe(const char *suffix)
{
    const char *p = suffix;
    while (*p) {
        const char *seg = p;
        while (*p && *p != '/')
            p++;
        size_t len = (size_t) (p - seg);
        if (len == 2 && seg[0] == '.' && seg[1] == '.')
            return false;
        if (*p == '/')
            p++;
    }
    return true;
}

/* Translate a /sys/devices/system/cpu[/...] path into the path inside the
 * scratch dir.
 *
 * Returns 0 on success (host_path filled), -1 with errno set for malformed
 * inputs (ENOENT for missing init, EACCES for traversal, ENAMETOOLONG for
 * overflow). When the suffix is empty (the root dir itself), host_path receives
 * just the scratch dir.
 */
static int syscpu_resolve_path(const char *suffix,
                               char *host_path,
                               size_t host_path_sz)
{
    if (!syscpu_suffix_safe(suffix)) {
        errno = EACCES;
        return -1;
    }
    const char *dir = ensure_syscpu_dir();
    if (!dir) {
        errno = ENOENT;
        return -1;
    }
    int n;
    if (!*suffix)
        n = snprintf(host_path, host_path_sz, "%s", dir);
    else
        n = snprintf(host_path, host_path_sz, "%s/%s", dir, suffix);
    if (n < 0 || (size_t) n >= host_path_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* The synthetic sysfs CPU tree is read-only. Accept only descriptor flags that
 * make sense for a read-only open and reject mutating flags up front so the
 * guest cannot create, truncate, or request write access anywhere in the stub.
 */
static bool syscpu_open_is_readonly(int linux_flags)
{
    int accmode = translate_open_flags(linux_flags) & O_ACCMODE;
    return accmode == O_RDONLY &&
           !(linux_flags & (LINUX_O_CREAT | LINUX_O_TRUNC));
}

/* Classify a guest path against the synthetic sysfs CPU tree.
 *   SYSCPU_NONE  - unrelated path; *suffix_out unset.
 *   SYSCPU_ROOT  - matches "/sys/devices/system/cpu" or with a trailing '/'.
 *                  *suffix_out is the empty string.
 *   SYSCPU_CHILD - matches "/sys/devices/system/cpu/<rest>"; *suffix_out
 *                  points at <rest> (never a leading '/'; may be empty if
 *                  the caller passed the trailing-slash form, which the
 *                  ROOT branch already absorbed).
 * Centralizes the prefix arithmetic so proc_intercept_open and
 * proc_intercept_stat share one source of truth for the SYSFS_CPU shape.
 */
#define SYSFS_CPU "/sys/devices/system/cpu"
#define SYSFS_CPU_LEN (sizeof(SYSFS_CPU) - 1)

/* Host scratch-dir path buffer size: scratch dir is /tmp/elfuse-syscpu-<6>
 * (under 30 chars) plus a /sys/devices/system/cpu/<suffix> remainder bounded by
 * LINUX_PATH_MAX. 256 is comfortable for the realistic suffixes the stub
 * exposes (cpuN, cpumask range files).
 */
#define SYSCPU_HOST_PATH_MAX 256
typedef enum {
    SYSCPU_NONE,
    SYSCPU_ROOT,
    SYSCPU_CHILD,
} syscpu_match_t;

static syscpu_match_t syscpu_classify(const char *path, const char **suffix_out)
{
    if (strncmp(path, SYSFS_CPU, SYSFS_CPU_LEN) != 0)
        return SYSCPU_NONE;
    char tail = path[SYSFS_CPU_LEN];
    if (tail == '\0' || (tail == '/' && path[SYSFS_CPU_LEN + 1] == '\0')) {
        *suffix_out = "";
        return SYSCPU_ROOT;
    }
    if (tail == '/') {
        *suffix_out = path + SYSFS_CPU_LEN + 1;
        return SYSCPU_CHILD;
    }
    return SYSCPU_NONE;
}

typedef struct {
    int64_t *tids;
    int ntids;
} proc_task_collect_ctx_t;

static void proc_task_collect_cb(thread_entry_t *t, void *arg)
{
    proc_task_collect_ctx_t *c = arg;
    if (c->ntids < MAX_THREADS)
        c->tids[c->ntids++] = thread_tid(t);
}


/* Build the VMA list shared by /proc/self/maps and /proc/self/smaps. Merges
 * contiguous regions[] runs that came from one mmap, then folds in the
 * uncovered pieces of preannounced[] shadow entries around live coverage.
 * Producers append entries while the lock is held; one sort/merge pass puts the
 * interleaved live and shadow streams back into VMA order.
 *
 * The region and preannounced arrays are mutable from guest mmap/mprotect/
 * munmap operations. Snapshot and merge while mmap_lock is held, then release
 * it before formatting output so readers never observe a torn VMA or metadata
 * record and output generation does not block page-table mutations.
 */
static int proc_build_maps_entries(const guest_t *g,
                                   maps_entries_t *entries_out)
{
    if (!g || !entries_out) {
        errno = EINVAL;
        return -1;
    }

    maps_entries_t entries = {0};
    int result = -1;
    int saved_errno = 0;

    mmap_lock_acquire_raw();

    /* Convert regions[] to maps entries. regions[] is already sorted by start
     * address. The MAP_SHARED/MAP_ANONYMOUS/MAP_NORESERVE bits are preserved in
     * r->flags, which is the single source of truth for the proc snapshot.
     */
    int nregions = g->nregions;
    if (nregions < 0)
        nregions = 0;
    if (nregions > GUEST_MAX_REGIONS)
        nregions = GUEST_MAX_REGIONS;
    for (int i = 0; i < nregions; i++) {
        const guest_region_t *r = &g->regions[i];
        uint64_t start = r->start & ~0xFFFULL;
        uint64_t end = maps_align_up_page(r->end);
        size_t count = maps_entries_count(&entries);
        maps_entry_t *last =
            count > 0 ? maps_entries_at(&entries, count - 1) : NULL;
        if (last && last->end == start && last->prot == r->prot &&
            last->flags == r->flags && last->offset == r->offset &&
            last->inherited_at_fork == r->inherited_at_fork &&
            !strcmp(last->name, r->name)) {
            last->end = end;
            continue;
        }
        if (maps_entries_append_entry(&entries, start, end, r->prot, r->flags,
                                      r->offset, r->name,
                                      r->inherited_at_fork) < 0)
            goto out_unlock;
    }

    /* Add only uncovered portions of each preannounced interval. Keeping the
     * shadow VMA whole when a live mapping realizes its middle produces
     * overlapping maps/smaps headers; subtract every covered live interval
     * instead, preserving any reserved-but-not-realized gaps.
     */
    int npreannounced = g->npreannounced;
    if (npreannounced < 0)
        npreannounced = 0;
    if (npreannounced > GUEST_MAX_PREANNOUNCED)
        npreannounced = GUEST_MAX_PREANNOUNCED;
    for (int i = 0; i < npreannounced; i++) {
        const guest_region_t *r = &g->preannounced[i];
        if (maps_entries_append_shadow_gaps(&entries, r, g->regions, nregions) <
            0)
            goto out_unlock;
    }
    if (maps_entries_count(&entries) > 1)
        qsort(maps_entries_data(&entries), maps_entries_count(&entries),
              sizeof(maps_entry_t), maps_entries_compare_start);
    maps_entries_merge_adjacent(&entries);
    result = (int) maps_entries_count(&entries);

out_unlock:
    saved_errno = errno;
    mmap_lock_release_raw();
    if (result < 0) {
        maps_entries_destroy(&entries);
        errno = saved_errno;
        return -1;
    }
    *entries_out = entries;
    return (int) maps_entries_count(&entries);
}

/* Format the common VMA header. The maps and smaps header must stay byte-for-
 * byte compatible so consumers can use either file interchangeably.
 */
static int proc_format_maps_header(const maps_entry_t *e,
                                   char *header,
                                   size_t headersz)
{
    char perms[5];
    perms[0] = (e->prot & LINUX_PROT_READ) ? 'r' : '-';
    perms[1] = (e->prot & LINUX_PROT_WRITE) ? 'w' : '-';
    perms[2] = (e->prot & LINUX_PROT_EXEC) ? 'x' : '-';
    perms[3] = (e->flags & LINUX_MAP_SHARED) ? 's' : 'p';
    perms[4] = '\0';

    int header_len =
        snprintf(header, headersz, "%llx-%llx %s %08llx 00:00 0",
                 (unsigned long long) e->start, (unsigned long long) e->end,
                 perms, (unsigned long long) e->offset);
    if (header_len < 0)
        return -1;
    if ((size_t) header_len >= headersz)
        header_len = (int) headersz - 1;

    if (e->name[0]) {
        while (header_len < MAPS_NAME_COLUMN &&
               (size_t) header_len < headersz - 1)
            header[header_len++] = ' ';
        int n = snprintf(header + header_len, headersz - (size_t) header_len,
                         "%s", e->name);
        if (n > 0) {
            if ((size_t) n >= headersz - (size_t) header_len)
                n = (int) (headersz - (size_t) header_len - 1);
            header_len += n;
        }
    } else if ((size_t) header_len < headersz - 1) {
        header[header_len++] = ' ';
    }
    header[header_len] = '\0';
    return header_len;
}

/* Release the resources shared by maps/smaps output without hiding the errno
 * from the operation that produced result.
 */
static int proc_finish_maps_output(int result,
                                   maps_entries_t *entries,
                                   string_builder_t *builder)
{
    int saved_errno = errno;
    maps_entries_destroy(entries);
    string_builder_destroy(builder);
    errno = saved_errno;
    return result;
}

/* Emit /proc/self/maps into a synthetic fd. Addresses are page-aligned and
 * output matches the Linux maps header format.
 */
static int proc_open_self_maps(const guest_t *g)
{
    maps_entries_t entries = {0};
    int nentries = proc_build_maps_entries(g, &entries);
    if (nentries < 0)
        return -1;

    string_builder_t builder = {0};
    size_t initial_capacity = (size_t) nentries * 256;
    int result = -1;
    if (string_builder_init(&builder, initial_capacity) < 0)
        goto out;

    /* Emit lines after merging so buffer accounting is centralized. */
    for (int i = 0; i < nentries; i++) {
        const maps_entry_t *e = maps_entries_at_const(&entries, (size_t) i);
        char line[256];
        int line_len = proc_format_maps_header(e, line, sizeof(line));
        if (line_len < 0 ||
            string_builder_append_n(&builder, line, (size_t) line_len) < 0 ||
            string_builder_append_n(&builder, "\n", 1) < 0)
            goto out;
    }

    log_debug("/proc/self/maps (%zu bytes):\n%.*s",
              string_builder_length(&builder),
              (int) string_builder_length(&builder),
              string_builder_data_const(&builder)
                  ? string_builder_data_const(&builder)
                  : "");
    result = proc_synthetic_fd(string_builder_data_const(&builder)
                                   ? string_builder_data_const(&builder)
                                   : "",
                               string_builder_length(&builder));

out:
    return proc_finish_maps_output(result, &entries, &builder);
}

/* Emit a Linux-shaped /proc/self/smaps approximation. The runtime tracks guest
 * VMAs and logical fork snapshots, but it cannot observe kernel page residency
 * or dirty bits on the host. Writable private anonymous VMAs that were present
 * in the most recent fork snapshot report their full VMA size as Shared_Dirty,
 * Rss, Pss, and Pss_Dirty; keeping those counters aligned avoids a
 * self-contradictory snapshot while retaining a coarse fork-compatibility
 * signal. Newly-created VMAs are excluded. All other fields that require kernel
 * page accounting are stable zeroes.
 */
static int proc_open_self_smaps(const guest_t *g)
{
    maps_entries_t entries = {0};
    int nentries = proc_build_maps_entries(g, &entries);
    if (nentries < 0)
        return -1;

    string_builder_t builder = {0};
    size_t initial_capacity = (size_t) nentries * 768;
    int result = -1;
    if (string_builder_init(&builder, initial_capacity) < 0)
        goto out;

    for (int i = 0; i < nentries; i++) {
        const maps_entry_t *e = maps_entries_at_const(&entries, (size_t) i);
        char header[256];
        int header_len = proc_format_maps_header(e, header, sizeof(header));
        if (header_len < 0)
            goto out;

        uint64_t size_kb = (e->end - e->start) / 1024;
        bool anonymous = (e->flags & LINUX_MAP_ANONYMOUS) != 0;
        bool shared = (e->flags & LINUX_MAP_SHARED) != 0;
        bool noreserve = (e->flags & LINUX_MAP_NORESERVE) != 0;
        bool private_anon =
            (e->flags & LINUX_MAP_PRIVATE) && anonymous && !shared;
        bool logical_shared_dirty = e->inherited_at_fork && private_anon &&
                                    (e->prot & LINUX_PROT_WRITE);
        uint64_t shared_dirty_kb = logical_shared_dirty ? size_kb : 0;
        uint64_t rss_kb = shared_dirty_kb;
        uint64_t pss_kb = shared_dirty_kb;
        uint64_t pss_dirty_kb = shared_dirty_kb;

        /* Linux writes a separating space after VmFlags:, even when no
         * evidence-based flags are available (for example a PROT_NONE VMA).
         * Start with that space so the empty form is exactly "VmFlags: \n".
         */
        char vmflags[64] = {' '};
        size_t vmflags_len = 1;
#define APPEND_VMFLAG(flag)                                  \
    do {                                                     \
        const char *token = (flag);                          \
        size_t token_len = strlen(token);                    \
        if (vmflags_len + token_len + 1 < sizeof(vmflags)) { \
            if (vmflags_len > 1)                             \
                vmflags[vmflags_len++] = ' ';                \
            memcpy(vmflags + vmflags_len, token, token_len); \
            vmflags_len += token_len;                        \
        }                                                    \
    } while (0)

        /* Only flags directly evidenced by the tracked VMA are reported. In
         * particular, do not invent Linux max-permission/accounting flags
         * (mr/mw/me/ac/sd/etc.) that the emulator cannot observe.
         */
        if (e->prot & LINUX_PROT_READ)
            APPEND_VMFLAG("rd");
        if (e->prot & LINUX_PROT_WRITE)
            APPEND_VMFLAG("wr");
        if (e->prot & LINUX_PROT_EXEC)
            APPEND_VMFLAG("ex");
        if (shared)
            APPEND_VMFLAG("sh");
        if (noreserve)
            APPEND_VMFLAG("nr");
#undef APPEND_VMFLAG
        vmflags[vmflags_len] = '\0';

        if (string_builder_appendf(
                &builder,
                "%.*s\n"
                "Size: %llu kB\n"
                "KernelPageSize: 4 kB\n"
                "MMUPageSize: 4 kB\n"
                "Rss: %llu kB\n"
                "Pss: %llu kB\n"
                "Pss_Dirty: %llu kB\n"
                "Shared_Clean: 0 kB\n"
                "Shared_Dirty: %llu kB\n"
                "Private_Clean: 0 kB\n"
                "Private_Dirty: 0 kB\n"
                "Referenced: 0 kB\n"
                "Anonymous: 0 kB\n"
                "KSM: 0 kB\n"
                "LazyFree: 0 kB\n"
                "AnonHugePages: 0 kB\n"
                "ShmemPmdMapped: 0 kB\n"
                "FilePmdMapped: 0 kB\n"
                "Shared_Hugetlb: 0 kB\n"
                "Private_Hugetlb: 0 kB\n"
                "Swap: 0 kB\n"
                "SwapPss: 0 kB\n"
                "Locked: 0 kB\n"
                "THPeligible: 0\n"
                "VmFlags:%s\n",
                header_len, header, (unsigned long long) size_kb,
                (unsigned long long) rss_kb, (unsigned long long) pss_kb,
                (unsigned long long) pss_dirty_kb,
                (unsigned long long) shared_dirty_kb, vmflags) < 0)
            goto out;
    }

    result = proc_synthetic_fd(string_builder_data_const(&builder)
                                   ? string_builder_data_const(&builder)
                                   : "",
                               string_builder_length(&builder));

out:
    return proc_finish_maps_output(result, &entries, &builder);
}

/* Emit /proc/meminfo from the guest-visible memory figures plus mach
 * vm_statistics64, approximating the Linux fields macOS does not expose.
 *
 * MemTotal and MemFree come from sys_guest_ram_bytes()/sys_guest_ram_free()
 * rather than from a host sample taken here, so this file and sysinfo(2) read
 * one snapshot rather than two: a guest reading both back to back, as busybox
 * free does, sees figures that were measured together. They used to describe
 * two different machines outright, never mind two instants -- meminfo reported
 * the host's real memory while sysinfo capped it at a hardcoded 4GiB -- and
 * that guest underflowed. busybox free takes total and free from sysinfo and
 * buff/cache from here, so a Cached larger than the sysinfo total made used =
 * total - free - cached wrap into a 24-digit figure.
 *
 * Returns a host fd, or -1. Split out of proc_intercept_open to keep that
 * dispatcher readable.
 */
static int proc_open_meminfo(void)
{
    uint64_t total_kb = sys_guest_ram_bytes() / 1024;
    uint64_t free_kb = sys_guest_ram_free() / 1024;

    /* Query host vm_statistics for accurate active/inactive. Falls back to
     * approximations if the mach call fails.
     */
    uint64_t avail_kb, buffers_kb, cached_kb;
    vm_statistics64_data_t vm_stat = {0};
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    uint64_t page_size = 4096;
    if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
                          (host_info64_t) &vm_stat, &count) == KERN_SUCCESS) {
        host_page_size(mach_host_self(), (vm_size_t *) &page_size);
        uint64_t inactive_kb =
            (uint64_t) vm_stat.inactive_count * page_size / 1024;
        uint64_t purgeable_kb =
            (uint64_t) vm_stat.purgeable_count * page_size / 1024;
        /* Available ~= free + inactive + purgeable (Linux heuristic) */
        avail_kb = free_kb + inactive_kb + purgeable_kb;
        if (avail_kb > total_kb)
            avail_kb = total_kb;
        cached_kb = inactive_kb + purgeable_kb;
        buffers_kb = 0; /* macOS does not expose buffer cache separately */
    } else {
        avail_kb = total_kb * 3 / 4;
        buffers_kb = total_kb / 20;
        cached_kb = total_kb / 4;
    }

    /* Cached has to fit in what MemFree leaves, not merely be smaller than the
     * total. The Mach counters do not partition: a purgeable page is also
     * counted in inactive, so free + inactive + purgeable can exceed physical
     * memory however the total is derived. A guest computing used = total -
     * free - cached wraps on that excess, which is the failure reporting one
     * total is meant to end. Cached gives up the precision rather than MemFree,
     * since MemFree is what sysinfo reports as freeram and the two have to keep
     * matching. free_kb needs no clamp of its own: it comes from
     * sys_guest_ram_free(), which is already held below the total.
     */
    if (cached_kb > total_kb - free_kb)
        cached_kb = total_kb - free_kb;

    /* Active is now an exact remainder -- the clamp above makes free + cached
     * fit inside the total. AnonPages still saturates, because Buffers is not
     * part of that clamp and the fallback branch above sets it non-zero.
     */
    uint64_t fc_kb = free_kb + cached_kb;
    uint64_t active_kb = total_kb - fc_kb;
    uint64_t anon_kb =
        total_kb > fc_kb + buffers_kb ? total_kb - fc_kb - buffers_kb : 0;

    return proc_emit_fmt(
        "MemTotal:       %llu kB\n"
        "MemFree:        %llu kB\n"
        "MemAvailable:   %llu kB\n"
        "Buffers:        %llu kB\n"
        "Cached:         %llu kB\n"
        "SwapCached:     0 kB\n"
        "Active:         %llu kB\n"
        "Inactive:       %llu kB\n"
        "SwapTotal:      0 kB\n"
        "SwapFree:       0 kB\n"
        "Dirty:          0 kB\n"
        "Writeback:      0 kB\n"
        "AnonPages:      %llu kB\n"
        "Mapped:         %llu kB\n"
        "Shmem:          0 kB\n"
        "Slab:           0 kB\n"
        "SReclaimable:   0 kB\n"
        "SUnreclaim:     0 kB\n"
        "KernelStack:    0 kB\n"
        "PageTables:     0 kB\n"
        "CommitLimit:    %llu kB\n"
        "Committed_AS:   0 kB\n"
        "VmallocTotal:   0 kB\n"
        "VmallocUsed:    0 kB\n"
        "VmallocChunk:   0 kB\n",
        (unsigned long long) total_kb, (unsigned long long) free_kb,
        (unsigned long long) avail_kb, (unsigned long long) buffers_kb,
        (unsigned long long) cached_kb, (unsigned long long) active_kb,
        (unsigned long long) (cached_kb / 2), (unsigned long long) anon_kb,
        (unsigned long long) (cached_kb / 2),
        (unsigned long long) (total_kb / 2));
}

/* Handle /proc/self/task/<tid>/{stat,status} and the <tid> directory itself.
 * path must start with "/proc/self/task/".
 *
 * Returns a host fd, -1 on a matched failure, or PROC_NOT_INTERCEPTED (-2) when
 * the tid is unparseable or the leaf is unknown. Split out of
 * proc_intercept_open to keep that dispatcher readable.
 */
static uint64_t proc_start_stack(const guest_t *g)
{
    if (g->start_stack != 0)
        return g->start_stack;
    if (g->stack_top > g->stack_base)
        return g->stack_top - 16;
    return 0;
}

static int proc_open_self_task_node(const guest_t *g,
                                    const char *path,
                                    int linux_flags)
{
    char *endp;
    long tid = strtol(path + 16, &endp, 10);
    if (endp == path + 16 || tid <= 0)
        return PROC_NOT_INTERCEPTED;

    /* Verify this TID is actually active */
    if (!thread_tid_alive((int64_t) tid)) {
        errno = ENOENT;
        return -1;
    }

    if (!strcmp(endp, "/stat")) {
        uint64_t start_stack = proc_start_stack(g);
        return proc_emit_fmt(
            "%ld (%.15s) R %lld %lld %lld 0 0 0 "          /* 1-9 */
            "0 0 0 0 0 0 0 0 "                             /* 10-17 */
            "20 0 %d 0 0 0 0 "                             /* 18-24 */
            "18446744073709551615 0 0 %llu 0 0 0 "         /* 25-31 */
            "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", /* 32-52 */
            tid, proc_comm_name(), (long long) proc_get_ppid(),
            (long long) proc_get_pid(), /* pgid */
            (long long) proc_get_sid(), thread_active_count(),
            (unsigned long long) start_stack);
    }

    if (!strcmp(endp, "/status")) {
        return proc_emit_fmt(
            "Name:\t%.15s\n"
            "State:\tR (running)\n"
            "Tgid:\t%lld\n"
            "Pid:\t%ld\n"
            "PPid:\t%lld\n"
            "Uid:\t%u\t%u\t%u\t%u\n"
            "Gid:\t%u\t%u\t%u\t%u\n"
            "Threads:\t%d\n",
            proc_comm_name(), (long long) proc_get_pid(), tid,
            (long long) proc_get_ppid(), proc_get_uid(), proc_get_euid(),
            proc_get_suid(), proc_get_euid(), proc_get_gid(), proc_get_egid(),
            proc_get_sgid(), proc_get_egid(), thread_active_count());
    }

    /* /proc/self/task/<tid> directory itself: synthesize a dir with stat/status
     * placeholder entries. Persistent so getdents sees the entries on macOS
     * (which cannot enumerate unlinked dirs).
     */
    if (*endp == '\0' || !strcmp(endp, "/")) {
        static proc_persistent_dir_t tiddir =
            PROC_PERSISTENT_DIR("/tmp/elfuse-tid-XXXXXX");
        const char *dir = proc_persistent_dir_acquire(&tiddir);
        if (!dir)
            return -1;

        char p[160];
        snprintf(p, sizeof(p), "%s/stat", dir);
        close(open(p, O_CREAT | O_WRONLY, 0444));
        snprintf(p, sizeof(p), "%s/status", dir);
        close(open(p, O_CREAT | O_WRONLY, 0444));

        int fd = proc_open_dir_fd(dir, linux_flags);
        proc_persistent_dir_release(&tiddir);
        return fd;
    }

    return PROC_NOT_INTERCEPTED; /* unknown /proc/self/task/<tid>/XXX */
}

/* Group that owns pty slaves. Linux distributions mount devpts with gid=5
 * ("tty") and glibc's grantpt(3) looks that group up before deciding whether
 * the slave needs chowning. Only this file reports it, so it lives here rather
 * than in the shared header.
 */
#define PTY_SLAVE_TTY_GID 5u

/* Handle the mount-table /proc nodes: /proc/filesystems, /proc/self/mountinfo,
 * and /proc/{mounts,self/mounts} plus /etc/mtab.
 *
 * Returns a host fd, -1 on a matched failure, or PROC_NOT_INTERCEPTED when path
 * is none of them. Split out of proc_intercept_open to keep that dispatcher
 * readable.
 */
static int proc_open_mounts_node(const char *path)
{
    if (!strcmp(path, "/proc/filesystems")) {
        return proc_emit_literal(
            "\tmpfs\n"
            "\tproc\n"
            "\tsysfs\n"
            "\tdevtmpfs\n"
            "\tfuse\n"
            "\text4\n"
            "\tvfat\n");
    }

    /* /proc/self/mountinfo -> Linux mountinfo format (different from
     * /proc/mounts). Format: id parent_id major:minor root mount_point options
     * - type source super_options
     */
    if (!strcmp(path, "/proc/self/mountinfo")) {
        const size_t bufsz = 8192;
        char *buf = malloc(bufsz);
        if (!buf)
            return -1;
        size_t off = (size_t) snprintf(
            buf, bufsz,
            "1 0 0:1 / / rw,relatime - ext4 /dev/root rw\n"
            "2 1 0:2 / /proc rw,nosuid,nodev,noexec - proc proc rw\n"
            "3 1 0:3 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw\n"
            "4 1 0:4 / /dev rw,nosuid - devtmpfs devtmpfs rw\n"
            "5 4 0:5 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw\n");
        if (off >= bufsz || fuse_append_mountinfo(buf, bufsz, &off) < 0) {
            free(buf);
            return -1;
        }
        int fd = proc_synthetic_fd(buf, off);
        free(buf);
        return fd;
    }

    /* /proc/mounts, /etc/mtab -> synthetic mount table */
    if (!strcmp(path, "/proc/mounts") || !strcmp(path, "/proc/self/mounts") ||
        !strcmp(path, "/etc/mtab")) {
        const size_t bufsz = 8192;
        char *buf = malloc(bufsz);
        if (!buf)
            return -1;
        size_t off =
            (size_t) snprintf(buf, bufsz,
                              "/ / ext4 rw,relatime 0 0\n"
                              "proc /proc proc rw,nosuid,nodev,noexec 0 0\n"
                              "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n"
                              "devtmpfs /dev devtmpfs rw,nosuid 0 0\n"
                              "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n");
        if (off >= bufsz || fuse_append_mounts(buf, bufsz, &off) < 0) {
            free(buf);
            return -1;
        }
        int fd = proc_synthetic_fd(buf, off);
        free(buf);
        return fd;
    }

    return PROC_NOT_INTERCEPTED;
}

/* Over the function-size limit on purpose.
 *
 * One arm per intercepted /proc, /sys and /dev path. The arms share only the
 * guest and the buffer, so a split would be a jump table by another name.
 */
/* NOLINTNEXTLINE(readability-function-size) */
int proc_intercept_open(const guest_t *g,
                        const char *path,
                        int linux_flags,
                        int mode)
{
    /* /dev/ptmx -> host /dev/ptmx + keepalive slave (see pty_open_master).
     * O_PATH is path-only on Linux: it must not run the device open hook or
     * allocate a pty pair. Use a harmless backing fd; FD_PATH gates I/O and
     * ioctl, while proc_intercept_stat supplies the visible device metadata.
     */
    if (!strcmp(path, "/dev/ptmx")) {
        if (linux_flags & LINUX_O_PATH) {
            if (linux_flags & LINUX_O_DIRECTORY) {
                errno = ENOTDIR;
                return -1;
            }
            int oflags = O_RDONLY;
            if (linux_flags & LINUX_O_CLOEXEC)
                oflags |= O_CLOEXEC;
            return open("/dev/null", oflags);
        }
        return pty_open_master(linux_flags);
    }

    /* /dev/null, /dev/zero, /dev/(u)random, /dev/tty */
    const char *host_dev = NULL;
    int host_accmode = translate_open_flags(linux_flags) & O_ACCMODE;
    if (!strcmp(path, "/dev/null"))
        host_dev = "/dev/null";
    else if (!strcmp(path, "/dev/zero")) {
        host_dev = "/dev/zero";
        /* macOS rejects O_WRONLY on /dev/zero even though Linux permits it. */
        if (host_accmode == O_WRONLY)
            host_accmode = O_RDWR;
    } else if (!strcmp(path, "/dev/urandom") || !strcmp(path, "/dev/random")) {
        host_dev = "/dev/urandom";

        /* Linux guests may open random devices writable, but macOS requires a
         * readable host fd for those cases.
         */
        if (host_accmode != O_RDONLY)
            host_accmode = O_RDWR;
    } else if (!strcmp(path, "/dev/tty"))
        host_dev = "/dev/tty";

    if (host_dev) {
        /* Restrict to access mode plus descriptor flags. Creation/truncation
         * flags (O_CREAT/O_TRUNC/O_EXCL) and directory/symlink semantics make
         * no sense for a character device and should not influence the host
         * open call; passing O_CREAT without a mode would also be a variadic
         * argument bug.
         */
        int oflags = host_accmode | (translate_open_flags(linux_flags) &
                                     (O_NONBLOCK | O_CLOEXEC));
        return open(host_dev, oflags);
    }

    /* /dev/shm -> tmpfs-backed host temp directory. Linux applications use
     * /dev/shm for shm_open + mmap MAP_SHARED. Redirect to one shared host
     * namespace so named shm works across elfuse processes and fork children.
     */
    if (!strcmp(path, "/dev/shm")) {
        const char *shm = shm_dir_path();
        return shm ? proc_open_dir_fd(shm, linux_flags) : -1;
    }

    if (!strncmp(path, "/dev/shm/", 9)) {
        char host_path[512];
        if (dev_shm_resolve_path(path + 9, host_path, sizeof(host_path)) < 0)
            return -1;
        int oflags = translate_open_flags(linux_flags);

        /* O_NOFOLLOW: do not follow symlinks created by the guest inside the
         * shm directory (prevents symlink-based escape).
         */
        return open(host_path, oflags | O_NOFOLLOW, mode);
    }

    /* /dev/stdin -> dup(0), /dev/stdout -> dup(1), /dev/stderr -> dup(2) */
    if (!strcmp(path, "/dev/stdin"))
        return dup(STDIN_FILENO);
    if (!strcmp(path, "/dev/stdout"))
        return dup(STDOUT_FILENO);
    if (!strcmp(path, "/dev/stderr"))
        return dup(STDERR_FILENO);

    /* /dev/fd/N -> dup(N) */
    if (!strncmp(path, "/dev/fd/", 8))
        return dev_fd_dup(path, 8);

    /* /dev/pts -> synthetic devpts directory. stat/access advertise this
     * directory even on macOS hosts without /dev/pts, so open must be
     * intercepted too or callers that probe then enumerate see inconsistent
     * Linux-visible behavior.
     */
    if (!strcmp(path, "/dev/pts") || !strcmp(path, "/dev/pts/"))
        return pty_open_pts_dir(linux_flags);

    /* /dev/pts/N -> the macOS slave path captured at /dev/ptmx open time.
     * Looking up the exact ptsname(3) string (rather than reformatting
     * /dev/ttys%03lu) keeps the guest correct against any future macOS format
     * change and against tty minor encodings that do not round-trip through
     * plain zero-padding. ENOENT until the owning master is opened matches
     * Linux devpts behavior for an unallocated slave number.
     */
    if (!strncmp(path, "/dev/pts/", 9)) {
        uint32_t n;
        if (!pty_slave_num_from_path(path, &n)) {
            errno = ENOENT;
            return -1;
        }
        /* /dev/pts/N is a character device; strip O_CREAT and friends so the
         * two-argument open(2) never sees a creation-mode-required combination
         * without a mode arg.
         */
        {
            int slave_fd = pty_open_slave((uint32_t) n, linux_flags);
            proc_pty_note_guest_slave(slave_fd, (uint32_t) n);
            return slave_fd;
        }
    }

    /* /proc -> synthetic directory with PID entries for busybox ps, top, etc.
     * Creates a temp dir once (cached for the process lifetime) with entries
     * matching the current single-process model: the current PID directory +
     * "self" symlink. The DIR* created from this allows getdents64 to enumerate
     * /proc like a real procfs. Cleaned up via atexit.
     */
    if (!strcmp(path, "/proc") || !strcmp(path, "/proc/")) {
        const char *dir = ensure_proc_tmpdir(g);
        if (!dir)
            return -1;
        return proc_open_dir_fd(dir, linux_flags);
    }

    /* /proc/self -> directory fd for the PID subdirectory */
    if (!strcmp(path, "/proc/self") || !strcmp(path, "/proc/self/")) {
        const char *dir = ensure_proc_tmpdir(g);
        if (!dir)
            return -1;
        return proc_open_numbered_dir(dir, proc_get_pid(), linux_flags);
    }

    /* /proc/self/fd -> directory listing of guest-visible file descriptors.
     * Each open gets its own scratch dir so concurrent enumerations cannot
     * mutate one another (see proc_open_fd_scratch).
     */
    if (!strcmp(path, "/proc/self/fd") || !strcmp(path, "/proc/self/fd/"))
        return proc_open_fd_scratch("elfuse-fd", linux_flags);

    if (!strcmp(path, "/proc/net") || !strcmp(path, "/proc/net/")) {
        const char *dir = ensure_proc_tmpdir(g);
        if (!dir)
            return -1;
        char netdir[LINUX_PATH_MAX];
        if (snprintf(netdir, sizeof(netdir), "%s/net", dir) >=
            (int) sizeof(netdir)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return proc_open_dir_fd(netdir, linux_flags);
    }

    /* /proc/<our_pid>[/...] -> /proc/self[...].
     * Returns -1 on ENAMETOOLONG so the guest sees the same error a real Linux
     * kernel would produce instead of falling through to a host syscall.
     */
    {
        char alias[LINUX_PATH_MAX];
        int aliased = proc_alias_self(path, alias, sizeof(alias));
        if (aliased < 0)
            return -1;
        if (aliased > 0)
            return proc_intercept_open(g, alias, linux_flags, mode);
    }

    int oom_kind = proc_oom_path_kind(path);
    if (oom_kind == OOM_PATH_SCORE) {
        /* Mirror the non-root Linux open contract for the 0444 proc node:
         * reject writable opens immediately instead of letting the write path
         * fail later against a synthetic temp file.
         */
        int oom_accmode = translate_open_flags(linux_flags) & O_ACCMODE;
        if (oom_accmode != O_RDONLY) {
            errno = EACCES;
            return -1;
        }
    }

    /* /proc/self/exe -> open the actual ELF binary. Unlike readlinkat (which
     * returns the path string), openat needs to return an actual file
     * descriptor to the binary. Under rosetta, the binfmt_misc convention
     * treats rosetta as the interpreter visible to the guest: rosetta opens
     * /proc/self/fd/X via /proc/self/exe to identify itself and then issues the
     * VZ ioctls on that descriptor.
     *
     * Return ROSETTA_PATH so the VZ ioctl gate (rosetta_ioctl_target_fd)
     * recognises the fd.
     */
    if (!strcmp(path, "/proc/self/exe")) {
        if (g && g->is_rosetta)
            return open(ROSETTA_PATH, O_RDONLY);
        char exe[LINUX_PATH_MAX];
        if (!proc_elf_path_snapshot(exe, sizeof(exe))) {
            errno = ENOENT;
            return -1;
        }
        return open(exe, O_RDONLY);
    }

    /* /proc/cpuinfo -> synthetic file with CPU count. Buffer sized dynamically
     * from ncpu (~200 bytes/entry) to avoid silent truncation on hosts with >16
     * CPUs.
     */
    if (!strcmp(path, "/proc/cpuinfo")) {
        int ncpu = (int) sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 1)
            ncpu = 1;
        size_t bufsz = (size_t) ncpu * 256 + 64;
        char stackbuf[4096];
        char *buf = (bufsz <= sizeof(stackbuf)) ? stackbuf : malloc(bufsz);
        if (!buf)
            return -1;
        int off = 0;
        for (int i = 0; i < ncpu && off < (int) bufsz - 256; i++) {
            off += snprintf(
                buf + off, bufsz - off,
                "processor\t: %d\n"
                "BogoMIPS\t: 48.00\n"
                "Features\t: fp asimd aes pmull sha1 sha2 crc32 atomics\n"
                "CPU implementer\t: 0x61\n"
                "CPU architecture: 8\n"
                "CPU variant\t: 0x1\n"
                "CPU part\t: 0x022\n"
                "CPU revision\t: 1\n\n",
                i);
        }
        int fd = proc_synthetic_fd(buf, off);
        if (buf != stackbuf)
            free(buf);
        return fd;
    }

    /* /proc/self/status -> synthetic process status */
    if (!strcmp(path, "/proc/self/status")) {
        /* Compute VmSize from region tracking (total virtual memory) */
        uint64_t vm_size_kb = 0;
        for (int i = 0; i < g->nregions; i++)
            vm_size_kb += (g->regions[i].end - g->regions[i].start);
        vm_size_kb /= 1024;

        /* VmRSS: approximate as non-PROT_NONE regions (HVF cannot query actual
         * residency from HVF, but mapped != PROT_NONE is close)
         */
        uint64_t vm_rss_kb = 0;
        for (int i = 0; i < g->nregions; i++) {
            if (g->regions[i].prot != 0) /* PROT_NONE = 0 */
                vm_rss_kb += (g->regions[i].end - g->regions[i].start);
        }
        vm_rss_kb /= 1024;

        /* Linux uses the comm name (basename truncated to 15 chars). */
        const char *name = proc_comm_name();
        int threads = thread_active_count();
        return proc_emit_fmt(
            "Name:\t%.15s\n"
            "State:\tR (running)\n"
            "Tgid:\t%lld\n"
            "Pid:\t%lld\n"
            "PPid:\t%lld\n"
            "Uid:\t%u\t%u\t%u\t%u\n"
            "Gid:\t%u\t%u\t%u\t%u\n"
            "VmPeak:\t%llu kB\n"
            "VmSize:\t%llu kB\n"
            "VmRSS:\t%llu kB\n"
            "Threads:\t%d\n",
            name, (long long) proc_get_pid(), (long long) proc_get_pid(),
            (long long) proc_get_ppid(), proc_get_uid(), proc_get_euid(),
            proc_get_suid(), proc_get_euid(), proc_get_gid(), proc_get_egid(),
            proc_get_sgid(), proc_get_egid(), (unsigned long long) vm_size_kb,
            (unsigned long long) vm_size_kb, (unsigned long long) vm_rss_kb,
            threads);
    }

    /* /proc/self/limits -> resource limits from prlimit64 cache */
    if (!strcmp(path, "/proc/self/limits")) {
        char buf[2048];
        int len = sys_format_limits(buf, sizeof(buf));
        if (len <= 0)
            return proc_synthetic_fd("", 0);
        return proc_synthetic_fd(buf, len);
    }

    /* /proc/self/cmdline -> NUL-separated argv */
    if (!strcmp(path, "/proc/self/cmdline")) {
        size_t len;
        const char *data = proc_get_cmdline(&len);
        if (!data)
            return proc_synthetic_fd("", 0);
        return proc_synthetic_fd(data, len);
    }

    /* /proc/self/environ -> NUL-separated environment variables */
    if (!strcmp(path, "/proc/self/environ")) {
        size_t len;
        const char *data = proc_get_environ(&len);
        if (!data)
            return proc_synthetic_fd("", 0);
        return proc_synthetic_fd(data, len);
    }

    /* /proc/self/auxv -> raw auxiliary vector (key-value uint64 pairs) */
    if (!strcmp(path, "/proc/self/auxv")) {
        size_t len;
        const void *data = proc_get_auxv(&len);
        if (!data)
            return proc_synthetic_fd("", 0);
        return proc_synthetic_fd(data, len);
    }

    /* /proc/self/task -> directory with per-thread TID entries. Debuggers and
     * runtimes (GDB, LLDB, JVM, Go runtime) probe this at startup to discover
     * thread count and per-thread state.
     *
     * Rebuilds a temp directory on each open (thread set is dynamic). Cannot
     * rmdir before returning the fd because macOS getdents on unlinked dirs
     * returns empty. Uses a static path cleaned up at exit.
     */
    if (!strcmp(path, "/proc/self/task") || !strcmp(path, "/proc/self/task/")) {
        static proc_persistent_dir_t taskdir =
            PROC_PERSISTENT_DIR("/tmp/elfuse-task-XXXXXX");
        const char *dir = proc_persistent_dir_acquire(&taskdir);
        if (!dir)
            return -1;

        int64_t tids[MAX_THREADS];
        proc_task_collect_ctx_t ctx = {tids, 0};
        thread_for_each(proc_task_collect_cb, &ctx);
        for (int i = 0; i < ctx.ntids; i++) {
            char tidpath[128];
            snprintf(tidpath, sizeof(tidpath), "%s/%lld", dir,
                     (long long) tids[i]);
            mkdir(tidpath, 0755);
        }

        int fd = proc_open_dir_fd(dir, linux_flags);
        proc_persistent_dir_release(&taskdir);
        return fd;
    }

    /* /proc/self/task/<tid>/{stat,status} and the <tid> directory. */
    if (!strncmp(path, "/proc/self/task/", 16))
        return proc_open_self_task_node(g, path, linux_flags);

    /* /proc/self/maps -> generated from guest region tracking. Addresses are
     * page-aligned (rounded down/up) to match real Linux behavior. Output
     * merges consecutive regions with the same prot, flags, and name into a
     * single maps line, matching real Linux kernel behavior where a single
     * mmap() call produces one maps entry even when the backing pages span
     * multiple physical frames.
     */
    if (!strcmp(path, "/proc/self/maps"))
        return proc_open_self_maps(g);

    /* /proc/self/smaps -> Linux-shaped VMA blocks with tracked VMA metadata and
     * the coarse fork Shared_Dirty/Rss/Pss/Pss_Dirty compatibility signal.
     */
    if (!strcmp(path, "/proc/self/smaps"))
        return proc_open_self_smaps(g);

    /* /proc/uptime -> synthetic uptime in seconds. Uses sysctl(KERN_BOOTTIME),
     * same as sys_sysinfo() in syscall/sys.c. Idle time is 0 (no meaningful
     * macOS equivalent).
     */
    if (!strcmp(path, "/proc/uptime")) {
        struct timeval boottime;
        size_t bt_len = sizeof(boottime);
        int mib[2] = {CTL_KERN, KERN_BOOTTIME};
        if (sysctl(mib, 2, &boottime, &bt_len, NULL, 0) < 0)
            return -1;
        struct timeval now;
        gettimeofday(&now, NULL);
        double uptime = (double) (now.tv_sec - boottime.tv_sec) +
                        (double) (now.tv_usec - boottime.tv_usec) / 1e6;
        return proc_emit_fmt("%.2f 0.00\n", uptime);
    }

    /* /proc/loadavg -> synthetic load averages. Musl's getloadavg() reads
     * /proc/loadavg, so GNU uptime needs this.
     */
    if (!strcmp(path, "/proc/loadavg")) {
        double loadavg[3] = {0};
        getloadavg(loadavg, 3);
        return proc_emit_fmt("%.2f %.2f %.2f 1/1 %lld\n", loadavg[0],
                             loadavg[1], loadavg[2],
                             (long long) proc_get_pid());
    }

    /* /var/run/utmp, /run/utmp -> synthetic utmp with current user. Creates one
     * USER_PROCESS record for who, users, pinky.
     */
    if (!strcmp(path, "/var/run/utmp") || !strcmp(path, "/run/utmp")) {
        _Static_assert(sizeof(linux_utmpx_t) == 400,
                       "linux_utmpx_t size mismatch");
        linux_utmpx_t entry;
        memset(&entry, 0, sizeof(entry));
        entry.ut_type = LINUX_USER_PROCESS;
        entry.ut_pid = (int32_t) proc_get_pid();
        str_copy_trunc(entry.ut_line, "pts/0", sizeof(entry.ut_line));
        str_copy_trunc(entry.ut_id, "0", sizeof(entry.ut_id));
        const char *user = getenv("USER");
        if (!user)
            user = "user";
        str_copy_trunc(entry.ut_user, user, sizeof(entry.ut_user));
        str_copy_trunc(entry.ut_host, "localhost", sizeof(entry.ut_host));
        struct timeval now;
        gettimeofday(&now, NULL);
        entry.ut_tv_sec = now.tv_sec;
        entry.ut_tv_usec = now.tv_usec;
        return proc_synthetic_fd(&entry, sizeof(entry));
    }

    /* /proc/net: live socket tables. Enumerates sockets from the local FD table
     * AND from all active fork-child processes via macOS proc_pidfdinfo(). This
     * gives system-wide visibility matching real Linux /proc/net semantics.
     */
    if (!strcmp(path, "/proc/net/tcp") || !strcmp(path, "/proc/net/tcp6") ||
        !strcmp(path, "/proc/net/udp") || !strcmp(path, "/proc/net/udp6") ||
        !strcmp(path, "/proc/net/raw") || !strcmp(path, "/proc/net/raw6")) {
        bool want_tcp = !!strstr(path, "tcp"), want_udp = !!strstr(path, "udp");
        bool want_v6 = (path[strlen(path) - 1] == '6');
        struct proc_net_inet_ctx ctx = {
            .buf = NULL, /* set below */
            .bufsz = 16384,
            .off = 0,
            .sl = 0,
            .want_af = want_v6 ? AF_INET6 : AF_INET,
            .want_stype = want_tcp   ? SOCK_STREAM
                          : want_udp ? SOCK_DGRAM
                                     : SOCK_RAW,
            .want_tcp = want_tcp,
            .want_v6 = want_v6,
        };
        char *buf = malloc(ctx.bufsz);
        if (!buf)
            return -1;
        ctx.buf = buf;
        ctx.off = snprintf(
            buf, ctx.bufsz, "%s",
            want_tcp ? "  sl  local_address rem_address   st tx_queue "
                       "rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                     : "  sl  local_address rem_address   st tx_queue "
                       "rx_queue tr tm->when retrnsmt   uid  timeout inode"
                       " ref pointer drops\n");
        proc_net_for_each_socket(proc_net_inet_visit, &ctx);
        int fd = proc_synthetic_fd_str(buf, ctx.off, ctx.bufsz);
        free(buf);
        return fd;
    }
    if (!strcmp(path, "/proc/net/unix")) {
        const size_t bufsz = 8192;
        char *buf = malloc(bufsz);
        if (!buf)
            return -1;
        struct proc_net_unix_ctx ctx = {
            .buf = buf,
            .bufsz = bufsz,
            .off = snprintf(buf, bufsz,
                            "Num       RefCount Protocol Flags    Type St "
                            "Inode Path\n"),
        };
        proc_net_for_each_socket(proc_net_unix_visit, &ctx);
        int fd = proc_synthetic_fd_str(buf, ctx.off, bufsz);
        free(buf);
        return fd;
    }
    if (!strcmp(path, "/proc/net/dev")) {
        return proc_open_net_dev();
    }

    /* /proc/sys/vm/mmap_min_addr -> synthetic mmap minimum address. */
    if (!strcmp(path, "/proc/sys/vm/mmap_min_addr"))
        return proc_emit_literal("32768\n");

    /* /proc/sys/kernel/randomize_va_space -> ASLR enabled (full). */
    if (!strcmp(path, "/proc/sys/kernel/randomize_va_space"))
        return proc_emit_literal("2\n");

    /* /proc/version -> synthetic banner in the kernel's proc_version_show
     * format; the builder and compiler fields are fixed strings.
     */
    if (!strcmp(path, "/proc/version")) {
        return proc_emit_literal(
            "Linux version " GUEST_KERNEL_RELEASE
            " (elfuse@elfuse) (elfuse) " GUEST_KERNEL_VERSION "\n");
    }

    /* /proc/filesystems, /proc/self/mountinfo, /proc/mounts, /etc/mtab. */
    {
        int r = proc_open_mounts_node(path);
        if (r != PROC_NOT_INTERCEPTED)
            return r;
    }

    /* OOM nodes share one stored adjustment.
     *   oom_score_adj: returns the raw adjustment in [-1000, 1000].
     *   oom_adj:       legacy view, scaled into [-17, 15] for compatibility.
     *   oom_score:     stub computed score, currently a fixed 0.
     */
    if (oom_kind != OOM_PATH_NONE) {
        char buf[32];
        int len = proc_oom_format_value(oom_kind, buf, sizeof(buf));
        return proc_synthetic_fd(buf, (size_t) len);
    }

    /* /proc/self/fdinfo/<N> -> per-fd flags/pos/mnt_id plus type-specific
     * fields for fds where Linux exposes additional state (eventfd counter,
     * signalfd mask, timerfd settings).
     */
    if (!strncmp(path, "/proc/self/fdinfo/", 18)) {
        int n = proc_parse_fd_index(path, 18, ENOENT);
        if (n < 0)
            return -1;
        fd_entry_t snap;
        if (!fd_snapshot(n, &snap)) {
            errno = ENOENT;
            return -1;
        }

        /* Pin under fd_lock so a concurrent close+reopen on another vCPU cannot
         * redirect the lseek to an unrelated host fd that took the freed slot.
         * A dup would answer that too, but retiring it would drop the guest's
         * record locks on the file (fcntl(2)), and reading /proc/self/fdinfo
         * must not unlock anything. The probe pollutes errno with ESPIPE on
         * non-seekable fds (sockets, pipes), so save and restore around the
         * call to keep the caller's view clean.
         */
        off_t pos = 0;
        host_fd_ref_t probe_ref;
        if (host_fd_ref_open(n, &probe_ref) == 0) {
            int saved_errno = errno;
            off_t probe = lseek(probe_ref.fd, 0, SEEK_CUR);
            if (probe >= 0)
                pos = probe;
            errno = saved_errno;
            host_fd_ref_close(&probe_ref);
        }

        char extra[160];
        extra[0] = '\0';
        if (snap.type == FD_EVENTFD) {
            uint64_t count;

            /* fs/eventfd.c uses a single space after the colon, matching the
             * timerfd convention (and unlike pos:/flags:/mnt_id: in
             * fs/proc/fd.c which use tabs).
             */
            if (eventfd_fdinfo_snapshot(n, &count))
                snprintf(extra, sizeof(extra), "eventfd-count: %16llx\n",
                         (unsigned long long) count);
        } else if (snap.type == FD_SIGNALFD) {
            uint64_t mask;

            /* fs/signalfd.c uses a tab after the colon (matching the
             * pos:/flags:/mnt_id: convention in fs/proc/fd.c, not the
             * single-space style of eventfd/timerfd). Verified against a real
             * Linux 6.x /proc/self/fdinfo dump.
             */
            if (signalfd_fdinfo_snapshot(n, &mask))
                snprintf(extra, sizeof(extra), "sigmask:\t%016llx\n",
                         (unsigned long long) mask);
        } else if (snap.type == FD_TIMERFD) {
            int clockid;
            uint64_t ticks;
            int64_t value_ns, interval_ns;
            if (timerfd_fdinfo_snapshot(n, &clockid, &ticks, &value_ns,
                                        &interval_ns)) {
                /* Linux fs/timerfd.c emits these fields with single spaces
                 * after the colon, not tabs (unlike pos:/flags:/mnt_id: in
                 * fs/proc/fd.c, which do use tabs). Match the upstream format
                 * so guest readers parsing fdinfo via a "it_value: (" prefix
                 * find the field.
                 */
                snprintf(extra, sizeof(extra),
                         "clockid: %d\n"
                         "ticks: %llu\n"
                         "settime flags: 0\n"
                         "it_value: (%lld, %lld)\n"
                         "it_interval: (%lld, %lld)\n",
                         clockid, (unsigned long long) ticks,
                         (long long) (value_ns / 1000000000LL),
                         (long long) (value_ns % 1000000000LL),
                         (long long) (interval_ns / 1000000000LL),
                         (long long) (interval_ns % 1000000000LL));
            }
        }

        int mnt_id = 0;
        if (fuse_fd_mnt_id(n, &mnt_id) < 0)
            mnt_id = 0;
        return proc_emit_fmt(
            "pos:\t%lld\n"
            "flags:\t0%o\n"
            "mnt_id:\t%d\n"
            "%s",
            (long long) pos, snap.linux_flags, mnt_id, extra);
    }

    /* /proc/self/fdinfo -> directory listing. Each open gets its own scratch
     * dir so concurrent getdents on independent dirfds cannot interfere (the
     * previous shared-dir design unlinked entries under a sibling enumerator).
     * The dirs are tracked for atexit cleanup.
     */
    if (!strcmp(path, "/proc/self/fdinfo") ||
        !strcmp(path, "/proc/self/fdinfo/")) {
        return proc_open_fd_scratch("elfuse-fdinfo", linux_flags);
    }

    /* /proc/self/fd/N -> open the target of the fd (readlink-style) */
    if (!strncmp(path, "/proc/self/fd/", 14))
        return dev_fd_dup(path, 14);

    /* /proc/meminfo -> synthetic memory info from host vm_statistics */
    if (!strcmp(path, "/proc/meminfo"))
        return proc_open_meminfo();

    /* /proc/self/io -> synthetic I/O counters. Some node-style observability
     * runtimes read this for resource monitoring metrics. procfs emulation
     * returns zeroed counters because it does not track per-guest I/O.
     */
    if (!strcmp(path, "/proc/self/io")) {
        return proc_emit_literal(
            "rchar: 0\n"
            "wchar: 0\n"
            "syscr: 0\n"
            "syscw: 0\n"
            "read_bytes: 0\n"
            "write_bytes: 0\n"
            "cancelled_write_bytes: 0\n");
    }

    /* /proc/self/stat -> single-line process stat (man 5 proc). Managed
     * runtimes read this for resource monitoring (utime, stime, rss, vsize).
     * Format: pid (comm) state ppid pgrp session tty_nr tpgid flags ... Fields
     * populated with meaningful values: pid, comm, state, ppid, utime(14),
     * stime(15), vsize(23), rss(24). Rest are zero/defaults.
     */
    if (!strcmp(path, "/proc/self/stat")) {
        /* Get process CPU times for utime/stime fields */
        struct rusage ru;
        getrusage(RUSAGE_SELF, &ru);
        /* Convert to clock ticks (Linux USER_HZ = 100) */
        long utime_ticks =
            ru.ru_utime.tv_sec * 100 + ru.ru_utime.tv_usec / 10000;
        long stime_ticks =
            ru.ru_stime.tv_sec * 100 + ru.ru_stime.tv_usec / 10000;

        /* Compute vsize and rss from guest region tracking */
        uint64_t vsize = 0, rss_pages = 0;
        long page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0)
            page_size = 4096;
        for (int i = 0; i < g->nregions; i++) {
            uint64_t sz = g->regions[i].end - g->regions[i].start;
            vsize += sz;
            if (g->regions[i].prot != 0) /* non-PROT_NONE = resident */
                rss_pages += sz / (uint64_t) page_size;
        }

        uint64_t start_stack = proc_start_stack(g);

        /* Fields: pid(1) (comm)(2) state(3) ppid(4) pgrp(5) session(6)
         *   tty_nr(7) tpgid(8) flags(9) minflt(10) cminflt(11) majflt(12)
         *   cmajflt(13) utime(14) stime(15) cutime(16) cstime(17)
         *   priority(18) nice(19) num_threads(20) itrealvalue(21)
         *   starttime(22) vsize(23) rss(24) rsslim(25) ... (52 fields total)
         */
        /* tty_nr(7) and tpgid(8) follow the controlling-terminal state rather
         * than the constants that stood here. elfuse models no specific tty
         * device, so tty_nr reports the UNIX98 pts major with minor 0 when a
         * terminal is held: readers such as ps only test it against zero to
         * decide whether to print a tty at all. tpgid is the foreground process
         * group, or -1 with no terminal, which is what Linux emits.
         */
        int has_ctty = proc_get_ctty();
        int tty_nr = has_ctty ? (136 << 8) : 0;
        long long tpgid = has_ctty ? (long long) proc_get_fg_pgrp() : -1;

        return proc_emit_fmt(
            "%lld (%.15s) R %lld %lld %lld %d %lld 0 "     /* 1-9 */
            "0 0 0 0 %ld %ld 0 0 "                         /* 10-17 */
            "20 0 %d 0 0 %llu %llu "                       /* 18-24 */
            "18446744073709551615 0 0 %llu 0 0 0 "         /* 25-31 */
            "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", /* 32-52 */
            (long long) proc_get_pid(), proc_comm_name(),
            (long long) proc_get_ppid(),
            (long long) proc_get_pid(), /* pgrp = pid */
            (long long) proc_get_pid(), /* session = pid */
            tty_nr, tpgid, utime_ticks, stime_ticks, thread_active_count(),
            (unsigned long long) vsize, (unsigned long long) rss_pages,
            (unsigned long long) start_stack);
    }

    /* /proc/stat -> synthetic CPU statistics */
    if (!strcmp(path, "/proc/stat")) {
        struct timeval boottime;
        size_t bt_len = sizeof(boottime);
        int mib[2] = {CTL_KERN, KERN_BOOTTIME};
        sysctl(mib, 2, &boottime, &bt_len, NULL, 0);
        int ncpu = (int) sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 1)
            ncpu = 1;
        char buf[4096];
        int off = 0;

        /* Aggregate CPU line (user, nice, system, idle, iowait, irq, softirq)
         */
        off += snprintf(buf + off, sizeof(buf) - off,
                        "cpu  1000 0 500 50000 0 0 0 0 0 0\n");
        /* Per-CPU lines */
        for (int i = 0; i < ncpu && off < (int) sizeof(buf) - 128; i++) {
            off += snprintf(buf + off, sizeof(buf) - off,
                            "cpu%d 100 0 50 5000 0 0 0 0 0 0\n", i);
        }
        off += snprintf(buf + off, sizeof(buf) - (size_t) off,
                        "intr 0\n"
                        "ctxt 0\n"
                        "btime %lld\n"
                        "processes 1\n"
                        "procs_running 1\n"
                        "procs_blocked 0\n",
                        (long long) boottime.tv_sec);
        if (off > (int) sizeof(buf))
            off = (int) sizeof(buf);
        return proc_synthetic_fd(buf, off);
    }

    /* /etc/passwd -> synthetic passwd with root + current user */
    if (!strcmp(path, "/etc/passwd")) {
        return proc_emit_literal(
            "root:x:0:0:root:/root:/bin/sh\n"
            "user:x:1000:1000:user:/home/user:/bin/sh\n");
    }

    /* /etc/group -> synthetic group file */
    if (!strcmp(path, "/etc/group")) {
        return proc_emit_literal(
            "root:x:0:\n"
            "staff:x:20:\n"
            "user:x:1000:\n");
    }

    /* /sys/devices/system/cpu[/...] -> synthetic CPU topology stub. Backs the
     * lazy scratch dir that holds the cpumask range files plus one empty cpuN
     * directory per host CPU. The cache/topology subtrees stay empty so
     * consumers that only need cpu count (Java GC, Go scheduler init, libnuma)
     * succeed; deeper queries return ENOENT.
     */
    {
        const char *suffix;
        syscpu_match_t m = syscpu_classify(path, &suffix);
        if (m != SYSCPU_NONE) {
            if (!syscpu_open_is_readonly(linux_flags)) {
                errno = EACCES;
                return -1;
            }
            if (m == SYSCPU_ROOT) {
                const char *dir = ensure_syscpu_dir();
                if (!dir)
                    return -1;
                return proc_open_dir_fd(dir, linux_flags);
            }
            char host_path[SYSCPU_HOST_PATH_MAX];
            if (syscpu_resolve_path(suffix, host_path, sizeof(host_path)) < 0)
                return -1;

            /* O_NOFOLLOW: the scratch dir contents are owned by elfuse, but a
             * caller could still race a symlink into the tree before this open.
             * Block any cross-tree escape attempt regardless.
             */
            int oflags = translate_open_flags(linux_flags);
            return open(host_path, oflags | O_NOFOLLOW, mode);
        }
    }

    /* /dev/bus/usb and /sys/bus/usb: synthetic USB trees from IOKit. */
    {
        int ufd = usb_sysfs_intercept_open(path, linux_flags, mode);
        if (ufd != PROC_NOT_INTERCEPTED)
            return ufd;
    }

    return PROC_NOT_INTERCEPTED;
}


int proc_intercept_stat(const char *path, struct stat *st)
{
    return proc_intercept_stat_at(path, st, false);
}

int proc_intercept_stat_at(const char *path, struct stat *st, bool follow)
{
    /* Intercept stat for /proc paths emulated via proc_intercept_open. Without
     * this, runtime libraries that probe a file's existence via stat() before
     * opening it would fail on synthetic /proc paths (e.g., a stat() of
     * /proc/self/io would return ENOENT before the caller ever issues open()).
     *
     * procfs emulation returns a minimal regular file stat. Exact values are
     * irrelevant here; callers need stat to succeed before opening the
     * synthetic file.
     */
    if (!strcmp(path, "/dev/fuse"))
        return fuse_proc_stat(st);

    /* Linux /dev/ptmx is the Unix98 pty multiplexer character device (5:2).
     * Keep this synthetic so O_PATH probes can fstat the path fd without
     * forcing a real host /dev/ptmx open, which would allocate a pty.
     */
    if (!strcmp(path, "/dev/ptmx")) {
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFCHR | 0666;
        st->st_nlink = 1;
        st->st_dev = PROC_SYNTH_DEV;
        st->st_ino = proc_synth_ino(path);
        st->st_uid = proc_get_uid();
        st->st_gid = proc_get_gid();
        st->st_rdev = ((dev_t) 5u << 24) | (dev_t) 2u;
        st->st_blksize = 1024;
        return 0;
    }

    /* /dev/shm is a directory */
    if (!strcmp(path, "/dev/shm") || !strcmp(path, "/dev/shm/")) {
        stat_fill_proc_dir(st, 01777, 2,
                           path); /* sticky bit, like real /dev/shm */
        return 0;
    }

    /* /dev/shm/<name> files: check the host backing dir, and lstat rather than
     * stat so a planted symlink leaf is never followed (see
     * dev_shm_resolve_path).
     */
    if (!strncmp(path, "/dev/shm/", 9)) {
        char host_path[512];
        if (dev_shm_resolve_path(path + 9, host_path, sizeof(host_path)) < 0)
            return -1;
        return lstat(host_path, st);
    }

    /* /dev/pts directory and /dev/pts/N slave entries. glibc ptsname(3) stats
     * /dev/pts/N after TIOCGPTN and rejects with ENOENT if absent. Synthesize a
     * minimal char-device stat whose st_rdev decodes to Linux's standard pts
     * major (136) so glibc's major(rdev) == UNIX98_PTY_SLAVE_MAJOR check
     * passes. The numeric tail must round-trip with /dev/ttysN via the open
     * intercept (see proc_intercept_open).
     */
    if (!strcmp(path, "/dev/pts") || !strcmp(path, "/dev/pts/")) {
        stat_fill_proc_dir(st, 0755, 2, path);
        return 0;
    }
    if (!strncmp(path, "/dev/pts/", 9)) {
        uint32_t n;
        if (!pty_slave_num_from_path(path, &n)) {
            errno = ENOENT;
            return -1;
        }

        /* Resolve through the captured-path table: ENOENT unless the
         * corresponding master is currently open. This avoids the host stat
         * false-positive where /dev/ttysNNN happens to exist for an unrelated
         * tty allocated outside elfuse.
         */
        char host_path[PTY_SLAVE_PATH_MAX];
        if (pty_lookup_slave_path((uint32_t) n, host_path, sizeof(host_path)) <
            0)
            return -1;
        struct stat host_st;
        if (stat(host_path, &host_st) < 0) {
            errno = ENOENT;
            return -1;
        }
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFCHR | 0620;
        st->st_nlink = 1;

        /* devpts gives the slave to whoever opened the master, group tty --
         * that is what grantpt(3) expects to find. Reporting the host owner
         * instead makes glibc see a foreign uid, try to chown the slave, fail,
         * and fall back to exec'ing the pt_chown helper, which does not exist
         * on a modern distro: grantpt then fails with ENOENT and no pty can be
         * allocated even though the master opened fine.
         */
        st->st_uid = (uid_t) proc_get_uid();
        st->st_gid = (gid_t) PTY_SLAVE_TTY_GID;

        /* macOS dev_t = (major << 24) | minor; the fs-stat translation layer
         * (mac_to_linux_dev) re-encodes that into Linux's split major/minor
         * layout, so storing 136 in the macOS-major slot makes glibc's
         * major(rdev) yield UNIX98_PTY_SLAVE_MAJOR. Build the value in
         * uint32_t: dev_t is a signed 32-bit int here, so 136 << 24
         * (0x88000000) would overflow it -- undefined behavior flagged by
         * UBSAN. The unsigned shift is well-defined and the conversion to dev_t
         * keeps the same bit pattern.
         */
        st->st_rdev =
            (dev_t) (((uint32_t) 136u << 24) | (uint32_t) (n & 0xFFFFFFu));
        st->st_size = 0;
        st->st_blksize = 1024;
        st->st_blocks = 0;
        st->st_atime = host_st.st_atime;
        st->st_mtime = host_st.st_mtime;
        st->st_ctime = host_st.st_ctime;
        return 0;
    }

    /* /proc and /proc/<our_pid> are directories */
    if (!strcmp(path, "/proc") || !strcmp(path, "/proc/")) {
        stat_fill_proc_dir(st, 0555, 3, path);
        return 0;
    }
    {
        char pidbuf[32], pidslash[32];
        snprintf(pidbuf, sizeof(pidbuf), "/proc/%lld",
                 (long long) proc_get_pid());
        snprintf(pidslash, sizeof(pidslash), "/proc/%lld/",
                 (long long) proc_get_pid());
        if (!strcmp(path, pidbuf) || !strcmp(path, pidslash) ||
            !strcmp(path, "/proc/self") || !strcmp(path, "/proc/self/")) {
            stat_fill_proc_dir(st, 0555, 3, path);
            return 0;
        }
    }
    if (!strcmp(path, "/proc/net") || !strcmp(path, "/proc/net/")) {
        stat_fill_proc_dir(st, 0555, 2, path);
        return 0;
    }

    /* /proc/<our_pid>[/...] -> /proc/self[...]. */
    {
        char alias[LINUX_PATH_MAX];
        int aliased = proc_alias_self(path, alias, sizeof(alias));
        if (aliased < 0)
            return -1;
        if (aliased > 0)
            return proc_intercept_stat_at(alias, st, follow);
    }

    /* /proc/self/task and /proc/self/task/<tid> are directories */
    if (!strcmp(path, "/proc/self/task") || !strcmp(path, "/proc/self/task/")) {
        stat_fill_proc_dir(st, 0555, 2 + (nlink_t) thread_active_count(), path);
        return 0;
    }
    if (!strncmp(path, "/proc/self/task/", 16)) {
        char *endp;
        long tid = strtol(path + 16, &endp, 10);
        if (endp != path + 16 && tid > 0) {
            if (!thread_tid_alive((int64_t) tid)) {
                errno = ENOENT;
                return -1;
            }
            if (*endp == '\0' || !strcmp(endp, "/")) {
                stat_fill_proc_dir(st, 0555, 2, path);
                return 0;
            }
            if (!strcmp(endp, "/stat") || !strcmp(endp, "/status")) {
                stat_fill_proc_file(st, 0444, path);
                return 0;
            }
        }
    }

    {
        int kind = proc_oom_path_kind(path);
        if (kind != OOM_PATH_NONE) {
            stat_fill_proc_file(st, (kind == OOM_PATH_SCORE) ? 0444 : 0644,
                                path);
            return 0;
        }
    }

    if (!strcmp(path, "/proc/self/fdinfo") ||
        !strcmp(path, "/proc/self/fdinfo/") || !strcmp(path, "/proc/self/fd") ||
        !strcmp(path, "/proc/self/fd/")) {
        stat_fill_proc_dir(st, 0555, 2, path);
        return 0;
    }

    if (!strncmp(path, "/proc/self/fdinfo/", 18)) {
        int fd = proc_parse_fd_index(path, 18, ENOENT);
        if (fd < 0)
            return -1;
        fd_entry_t snap;
        if (!fd_snapshot(fd, &snap)) {
            errno = ENOENT;
            return -1;
        }
        stat_fill_proc_file(st, 0444, path);
        return 0;
    }

    static const char *known_proc_files[] = {
        "/proc/self/io",
        "/proc/self/stat",
        "/proc/self/status",
        "/proc/self/cmdline",
        "/proc/self/maps",
        "/proc/self/smaps",
        "/proc/self/exe",
        "/proc/self/environ",
        "/proc/self/auxv",
        "/proc/self/mountinfo",
        "/proc/self/mounts",
        "/proc/cpuinfo",
        "/proc/meminfo",
        "/proc/stat",
        "/proc/uptime",
        "/proc/loadavg",
        "/proc/version",
        "/proc/filesystems",
        "/proc/sys/vm/mmap_min_addr",
        "/proc/sys/kernel/randomize_va_space",
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
        "/proc/net/raw",
        "/proc/net/raw6",
        "/proc/net/unix",
        "/proc/net/dev",
        NULL,
    };

    for (const char **p = known_proc_files; *p; p++) {
        if (!strcmp(path, *p)) {
            stat_fill_proc_file(st, 0444, path);
            return 0;
        }
    }

    /* /proc/self/fd/N: stat the underlying host fd */
    if (!strncmp(path, "/proc/self/fd/", 14)) {
        int n = proc_parse_fd_index(path, 14, EBADF);
        if (n < 0)
            return -1;
        int host_fd = fd_to_host(n);
        if (host_fd < 0) {
            errno = EBADF;
            return -1;
        }
        if (fstat(host_fd, st) < 0)
            return -1;
        return 0;
    }

    /* /sys/devices/system/cpu[/...]: synthesize stat from the lazy scratch dir.
     * Anything not present in the scratch dir (e.g. cpuN/topology, cpuN/cache)
     * returns ENOENT, which matches the "stub-empty" contract.
     */
    {
        const char *suffix;
        syscpu_match_t m = syscpu_classify(path, &suffix);
        if (m == SYSCPU_ROOT) {
            if (!ensure_syscpu_dir())
                return -1;
            stat_fill_proc_dir(st, 0555, 2, path);
            return 0;
        }
        if (m == SYSCPU_CHILD) {
            char host_path[SYSCPU_HOST_PATH_MAX];
            if (syscpu_resolve_path(suffix, host_path, sizeof(host_path)) < 0)
                return -1;
            struct stat host_st;
            if (lstat(host_path, &host_st) < 0)
                return -1;

            /* Replace host inode/dev with the synthetic-procfs convention so
             * the guest sees a stable identity that does not collide with real
             * host files (and so st_size reads as 0 for cpumask files, matching
             * real sysfs).
             */
            if (S_ISDIR(host_st.st_mode))
                stat_fill_proc_dir(st, 0555, 2, path);
            else
                stat_fill_proc_file(st, 0444, path);
            return 0;
        }
    }

    /* /dev/bus/usb and /sys/bus/usb: synthetic USB trees from IOKit. */
    {
        int urc = usb_sysfs_intercept_stat(path, st, follow);
        if (urc != PROC_NOT_INTERCEPTED)
            return urc;
    }

    return PROC_NOT_INTERCEPTED;
}

/* Resolve /proc/self/exe to the guest binary path in buf. Strips the sysroot
 * prefix so a guest running under --sysroot=/opt/sr sees /bin/ls rather than
 * /opt/sr/bin/ls, matching the chroot-like abstraction the rest of the path
 * layer presents.
 *
 * Returns bytes written, or -1 with errno set. Under rosetta this still returns
 * the real guest binary: the rosetta translator is an implementation detail,
 * and guest apps (coreutils multi-call dispatch) expect the true path just as
 * native binfmt_misc + rosetta exposes it.
 */
static int proc_readlink_self_exe(char *buf, size_t bufsiz)
{
    char exe_buf[LINUX_PATH_MAX];
    if (!proc_elf_path_snapshot(exe_buf, sizeof(exe_buf))) {
        errno = ENOENT;
        return -1;
    }
    const char *exe = exe_buf;
    char exe_real[LINUX_PATH_MAX];
    char exe_guest[LINUX_PATH_MAX];

    /* proc_set_sysroot stores a realpath()-canonicalized form, so canonicalize
     * exe before the reverse map or the sysroot strip fails when /var ->
     * /private/var (and similar macOS symlinks) make the two strings diverge.
     * path_host_to_guest also decodes escaped components back to guest
     * spellings, which a bare prefix strip would leak. Only an actual rewrite
     * is adopted: an identity result keeps the original spelling, so a
     * host-literal exe is not silently canonicalized (/tmp -> /private/tmp).
     *
     * With no sysroot configured the reverse map is an identity copy, so the
     * canonicalization would be computed and then discarded; skip it there
     * rather than pay one lstat per path component on every readlink. Testing
     * proc_get_sysroot() for NULL without a snapshot is sanctioned (see
     * proc.h).
     */
    const char *exe_cmp = exe;
    if (proc_get_sysroot() && realpath(exe, exe_real))
        exe_cmp = exe_real;
    if (path_host_to_guest(exe_cmp, exe_guest, sizeof(exe_guest)) == 0 &&
        strcmp(exe_guest, exe_cmp))
        exe = exe_guest;
    size_t len = strlen(exe);
    if (len > bufsiz)
        len = bufsiz;
    memcpy(buf, exe, len);
    return (int) len;
}

int proc_intercept_readlink(const char *path, char *buf, size_t bufsiz)
{
    {
        char alias[LINUX_PATH_MAX];
        int aliased = proc_alias_self(path, alias, sizeof(alias));
        if (aliased < 0)
            return -1;
        if (aliased > 0)
            return proc_intercept_readlink(alias, buf, bufsiz);
    }

    if (!strcmp(path, "/proc/self/exe"))
        return proc_readlink_self_exe(buf, bufsiz);

    /* /proc/self/cwd -> getcwd() */
    if (!strcmp(path, "/proc/self/cwd")) {
        proc_cwd_view_t view;
        if (proc_acquire_cwd_view(&view) < 0)
            return -1;
        size_t copy_len = view.len;
        if (copy_len > bufsiz)
            copy_len = bufsiz;
        memcpy(buf, view.path, copy_len);
        proc_release_cwd_view(&view);
        return (int) copy_len;
    }

    /* /proc/self/fd/N -> path of host fd (via fcntl F_GETPATH on macOS) */
    if (!strncmp(path, "/proc/self/fd/", 14)) {
        char *endptr;
        long n = strtol(path + 14, &endptr, 10);
        if (endptr == path + 14 || *endptr != '\0' || n < 0 ||
            n >= FD_TABLE_SIZE) {
            errno = EBADF;
            return -1;
        }
        int host_fd = fd_to_host((int) n);
        if (host_fd < 0) {
            errno = EBADF;
            return -1;
        }

        /* Descriptors opened through the synthetic USB trees are backed by
         * scratch dirs under /tmp; F_GETPATH would leak that host location, and
         * consumers compare the magic-link target against the guest path they
         * opened (systemd chase() rejects a syspath that does not start with
         * /sys). Report the stamped guest spelling instead. Kept narrow (USB
         * prefixes only) so the pty and shm reporting stays as it was.
         */
        {
            fd_entry_t fd_snap;
            if (fd_snapshot((int) n, &fd_snap) && fd_snap.proc_path[0] == '/' &&
                (path_prefix_match(fd_snap.proc_path, "/sys", 4) ||
                 path_prefix_match(fd_snap.proc_path, "/dev/bus", 8))) {
                size_t plen = strlen(fd_snap.proc_path);
                if (plen > bufsiz)
                    plen = bufsiz;
                memcpy(buf, fd_snap.proc_path, plen);
                return (int) plen;
            }
        }

        char fdpath[MAXPATHLEN];
        if (fcntl(host_fd, F_GETPATH, fdpath) < 0) {
            errno = ENOENT;
            return -1;
        }

        /* Under rosetta, open("/proc/self/exe") returns a host fd pointing at
         * the rosetta translator (needed by the VZ ioctl gate). readlink on
         * that fd must still report the guest binary, not the translator, or
         * coreutils multi-call dispatch reads back "rosetta" as the applet name
         * and aborts.
         */
        if (proc_rosetta_active() && !strcmp(fdpath, ROSETTA_PATH))
            return proc_readlink_self_exe(buf, bufsiz);

        /* F_GETPATH reports the raw host path; the guest must see its own
         * namespace (sysroot stripped, escaped components decoded).
         */
        char guest_view[LINUX_PATH_MAX];
        const char *report = fdpath;
        if (path_host_to_guest(fdpath, guest_view, sizeof(guest_view)) == 0)
            report = guest_view;
        size_t len = strlen(report);
        if (len > bufsiz)
            len = bufsiz;
        memcpy(buf, report, len);
        return (int) len;
    }

    /* /dev/bus/usb and /sys/bus/usb entries are real dirs/files, never
     * symlinks; answer EINVAL for existing paths rather than falling through to
     * the host (where /sys does not exist and the error would be ENOENT).
     */
    {
        int urc = usb_sysfs_intercept_readlink(path, buf, bufsiz);
        if (urc != PROC_NOT_INTERCEPTED)
            return urc;
    }

    return PROC_NOT_INTERCEPTED;
}

int proc_intercept_read(int guest_fd,
                        void *buf,
                        size_t count,
                        int64_t offset,
                        ssize_t *read_out)
{
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap))
        return 0;

    int kind = proc_oom_path_kind(snap.proc_path);
    if (kind == OOM_PATH_NONE)
        return 0;

    /* Recompute from the shared atomic on every read so lseek(0)+read on an
     * already-open fd sees updates written through oom_score_adj or oom_adj.
     */
    char text[32];
    int len = proc_oom_format_value(kind, text, sizeof(text));
    if (len < 0) {
        errno = EIO;
        return -1;
    }
    return proc_oom_copy_slice(buf, count, offset, text, (uint64_t) len,
                               read_out);
}

int proc_intercept_readv(int guest_fd,
                         const struct iovec *iov,
                         int iovcnt,
                         int64_t offset,
                         ssize_t *read_out)
{
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap))
        return 0;

    int kind = proc_oom_path_kind(snap.proc_path);
    if (kind == OOM_PATH_NONE)
        return 0;
    if (offset < 0) {
        errno = EINVAL;
        return -1;
    }

    char text[32];
    int len = proc_oom_format_value(kind, text, sizeof(text));
    if (len < 0) {
        errno = EIO;
        return -1;
    }
    uint64_t src_len = (uint64_t) len;

    uint64_t src_off = (uint64_t) offset;
    ssize_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        uint64_t n;
        if (!slice_clamp(src_len, src_off, iov[i].iov_len, &n))
            break;
        if (n == 0)
            continue;
        memcpy(iov[i].iov_base, text + src_off, (size_t) n);
        src_off += n;
        total += (ssize_t) n;
    }

    *read_out = total;
    return 1;
}

int proc_intercept_write(int guest_fd,
                         int host_fd,
                         const void *buf,
                         size_t count,
                         int64_t offset,
                         int use_pwrite,
                         ssize_t *written_out)
{
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap))
        return 0;
    int kind = proc_oom_path_kind(snap.proc_path);
    if (kind == OOM_PATH_SCORE) {
        /* Linux: oom_score has no write handler. proc_reg_write returns -EIO
         * when the underlying proc_dir_entry exposes no write op, not -EINVAL.
         * Match that so guests probing the error code see the same value as on
         * a real kernel.
         */
        errno = EIO;
        return -1;
    }
    if (kind != OOM_PATH_SCORE_ADJ && kind != OOM_PATH_ADJ)
        return 0;

    /* Linux: zero-byte writes to proc nodes succeed without side effects.
     * Without this short-circuit, sys_writev would funnel a zero-length vector
     * through proc_parse_int_write and get -EINVAL.
     */
    if (count == 0) {
        *written_out = 0;
        return 1;
    }

    int val;
    if (proc_parse_int_write(buf, count, &val) < 0)
        return -1;

    int score_adj;
    if (kind == OOM_PATH_ADJ) {
        if (val < LINUX_OOM_DISABLE || val > LINUX_OOM_ADJUST_MAX) {
            errno = EINVAL;
            return -1;
        }
        score_adj = oom_adj_to_score_adj(val);
    } else {
        if (val < LINUX_OOM_SCORE_ADJ_MIN || val > LINUX_OOM_SCORE_ADJ_MAX) {
            errno = EINVAL;
            return -1;
        }
        score_adj = val;
    }

    /* Both interfaces persist the value the writer supplied: oom_adj keeps the
     * legacy [-17,15] number, oom_score_adj keeps the [-1000,1000] number.
     * proc_oom_refresh_live_fds_locked re-renders each open fd's backing file
     * through proc_oom_format_value, so the kind-specific view stays correct
     * across reads.
     */
    char text[32];
    int len = snprintf(text, sizeof(text), "%d\n", val);

    /* Serialize the backing-fd rewrite so concurrent writers cannot race the
     * truncate+pwrite sequence. Publish to the global atomic last so a
     * partial-rewrite failure leaves the process-wide value unchanged.
     */
    pthread_mutex_lock(&oom_write_lock);
    int rc = -1;
    if (ftruncate(host_fd, 0) < 0)
        goto unlock;
    if (pwrite(host_fd, text, (size_t) len, 0) != len)
        goto unlock;
    if (!use_pwrite && lseek(host_fd, offset + (int64_t) count, SEEK_SET) < 0)
        goto unlock;

    atomic_store_explicit(&oom_score_adj_value, score_adj,
                          memory_order_relaxed);
    proc_oom_refresh_live_fds_locked();
    *written_out = (ssize_t) count;
    rc = 1;
unlock:
    pthread_mutex_unlock(&oom_write_lock);
    return rc;
}
