/* /proc and /dev path emulation
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Intercepts openat and readlinkat for /proc, /dev, /etc, and /var/run paths.
 * Returns host fds for synthetic content, or -2 if the path is not intercepted
 * (caller falls through to real syscall).
 */

/* Maximum /proc/self/maps entries. Array is sized to this; loop bounds use
 * MAPS_ENTRY_MAX - 1 to leave room for safe increment.
 */
#define MAPS_ENTRY_MAX 256

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
#include <sys/ioctl.h>
#include <termios.h>

#include "utils.h"

#include "debug/log.h"
#include "runtime/procemu.h"
#include "core/rosetta.h"
#include "runtime/thread.h"

#include "syscall/abi.h"
#include "syscall/fd.h"
#include "syscall/fuse.h"
#include "syscall/internal.h"
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
    char name[64];
} maps_entry_t;

static void maps_entry_insert(maps_entry_t *entries,
                              int *nentries,
                              uint64_t start,
                              uint64_t end,
                              int prot,
                              int flags,
                              uint64_t offset,
                              const char *name)
{
    if (*nentries >= MAPS_ENTRY_MAX || end <= start)
        return;

    int i = *nentries;
    while (i > 0 && entries[i - 1].start > start) {
        entries[i] = entries[i - 1];
        i--;
    }

    maps_entry_t *e = &entries[i];
    e->start = start;
    e->end = end;
    e->prot = prot;
    e->flags = flags;
    e->offset = offset;
    if (name && name[0])
        str_copy_trunc(e->name, name, sizeof(e->name));
    else
        e->name[0] = '\0';
    (*nentries)++;
}

static void maps_entries_merge_adjacent(maps_entry_t *entries, int *nentries)
{
    if (*nentries <= 1)
        return;

    int out = 0;
    for (int i = 1; i < *nentries; i++) {
        if (entries[i].start == entries[out].end &&
            entries[i].prot == entries[out].prot &&
            entries[i].flags == entries[out].flags &&
            entries[i].offset == entries[out].offset &&
            strcmp(entries[i].name, entries[out].name) == 0) {
            entries[out].end = entries[i].end;
            continue;
        }
        entries[++out] = entries[i];
    }
    *nentries = out + 1;
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
    int score_adj = atomic_load(&oom_score_adj_value);
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
                               size_t src_len,
                               ssize_t *read_out)
{
    if (offset < 0) {
        errno = EINVAL;
        return -1;
    }
    if ((uint64_t) offset >= src_len) {
        *read_out = 0;
        return 1;
    }

    size_t avail = src_len - (size_t) offset;
    size_t n = count < avail ? count : avail;
    memcpy(dst, src + offset, n);
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

static int proc_open_dir_fd(const char *path, int linux_flags);
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

static void proc_scratch_remove_one(const char *dir)
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

    pthread_once(&proc_scratch_atexit_once, proc_scratch_register_atexit);

    pthread_mutex_lock(&proc_scratch_lock);
    if (proc_scratch_dirs_count < PROC_SCRATCH_DIRS_MAX) {
        str_copy_trunc(proc_scratch_dirs[proc_scratch_dirs_count++], dir,
                       sizeof(proc_scratch_dirs[0]));
    }
    pthread_mutex_unlock(&proc_scratch_lock);

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
    const char *files[] = {"stat", "status", "cmdline", "maps", "exe", NULL};
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
    if (mkdir(shm_dir, 0700) < 0 && errno != EEXIST) {
        shm_dir_errno = errno;
        shm_dir[0] = '\0';
        return;
    }
    /* Verify the path is a directory owned by the current UID (not a symlink).
     */
    struct stat st;
    if (lstat(shm_dir, &st) < 0) {
        shm_dir_errno = errno;
        log_error("/dev/shm dir %s: lstat failed: %s", shm_dir,
                  strerror(errno));
        shm_dir[0] = '\0';
        return;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != getuid()) {
        shm_dir_errno = EACCES;
        log_error(
            "/dev/shm dir %s is not a directory owned by "
            "uid %u",
            shm_dir, (unsigned) getuid());
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
    char template[] = "/tmp/elfuse-proc-XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0)
        return -1;
    unlink(template); /* Delete on close; fd keeps it alive */

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
    char *endp;
    long n = strtol(path + prefix_len, &endp, 10);
    if (endp == path + prefix_len || *endp != '\0' || n < 0 ||
        n >= FD_TABLE_SIZE) {
        errno = errno_on_invalid;
        return -1;
    }
    return (int) n;
}

/* Resolve a /dev/shm/<suffix> guest path to a host path inside the per-UID shm
 * dir. Rejects empty, traversing, or compound suffixes with EACCES; reports
 * ENAMETOOLONG when the host path overflows. The same validation runs in
 * proc_intercept_open and proc_intercept_stat, so the helper is one source of
 * truth for the security gate.
 */
static int dev_shm_resolve_path(const char *guest_suffix,
                                char *host_path,
                                size_t host_path_sz)
{
    const char *shm = shm_dir_path();
    if (!shm)
        return -1;
    if (strstr(guest_suffix, "..") || strchr(guest_suffix, '/') ||
        guest_suffix[0] == '\0') {
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
    /* 64-bit FNV-1a with Linux-looking nonzero output. */
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char *p = (const unsigned char *) path; *p; ++p) {
        h ^= (uint64_t) *p;
        h *= 1099511628211ULL;
    }
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
    pid_t pids[PROC_TABLE_SIZE + 1];
    pids[0] = getpid();
    int npids = 1 + proc_get_child_pids(pids + 1, PROC_TABLE_SIZE);

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

static int proc_open_dir_fd(const char *path, int linux_flags)
{
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

    /* Create task subdirectory for /proc/self/task enumeration */
    char taskdir[128];
    snprintf(taskdir, sizeof(taskdir), "%s/task", piddir);
    mkdir(taskdir, 0755);

    char netdir[128];
    snprintf(netdir, sizeof(netdir), "%s/net", proc_tmpdir);
    if (mkdir(netdir, 0755) == 0 || errno == EEXIST) {
        static const char *net_files[] = {
            "tcp", "tcp6", "udp", "udp6", "raw", "raw6", "unix", NULL,
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
        c->tids[c->ntids++] = t->guest_tid;
}

/* Pseudoterminal master side-table.
 *
 * Bridges two host vs guest mismatches in one place:
 *
 * 1. The macOS /dev/ptmx master is not itself a tty. TIOCSWINSZ / TIOCGWINSZ
 *    on the bare master return ENOTTY until something has opened the
 *    corresponding slave once, and the stored winsize gets cleared whenever
 *    the slave refcount drops to zero (verified empirically on macOS 15).
 *    Linux ptmx masters are tty fds in their own right, so guests assume those
 *    ioctls work without an open slave. To bridge the gap, every /dev/ptmx
 *    open eagerly opens one slave host fd that elfuse holds for the lifetime
 *    of the master and never exposes to the guest.
 *
 * 2. macOS slaves live at /dev/ttysNNN; Linux glibc looks for /dev/pts/N where
 *    N comes from TIOCGPTN. Guest opens of /dev/pts/N route back to the
 *    macOS path captured from ptsname(3) at /dev/ptmx open time, not a
 *    re-formatted guess, so format changes in macOS (or unusual minor
 *    encodings) cannot strand the guest with the wrong slave.
 *
 * Entries are keyed by the host master fd because that is what fd_cleanup_entry
 * has when the guest closes a master. Capacity matches the macOS default UNIX98
 * slave count; overflow leaves the entry empty and the guest gets the pre-fix
 * degraded behavior for that one pair instead of an open failure.
 *
 * Fork-restored entries may outlive their master for one /dev/pts/N open. A
 * foot / sshd / posix-compliant child closes the master fd after fork before
 * opening the slave (the child has no use for the master); without retaining
 * the path mapping past close, the subsequent /dev/pts/N open in the child
 * loses its translation and fails with ENOENT even though the parent still
 * holds the master and the macOS slave node is openable. Those stale entries
 * keep the received slave fd until the first translated open attempt, then
 * expire before the minor can be reused for an unrelated host tty. Ordinary
 * local master closes clear the mapping immediately.
 */
#define PTY_KEEPALIVE_MAX 256
#define PTY_KEEPALIVE_FREE (-1)
/* PTY_SLAVE_PATH_MAX lives in procemu.h so this table and the fork-IPC payload
 * (proc_pty_ipc_entry_t) cannot drift apart.
 */
static struct {
    int master_host_fd;
    int slave_host_fd;
    uint32_t linux_pts_num;
    bool stale_open_once;
    char slave_path[PTY_SLAVE_PATH_MAX];
} pty_keepalive_table[PTY_KEEPALIVE_MAX];
static pthread_mutex_t pty_keepalive_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t pty_keepalive_once = PTHREAD_ONCE_INIT;

/* Sentinel-init. Other fields stay BSS-zero; without sentinels a host fd 0
 * close would match slot 0 and close the wrong fd inside elfuse.
 */
static void pty_keepalive_init(void)
{
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        pty_keepalive_table[i].master_host_fd = PTY_KEEPALIVE_FREE;
        pty_keepalive_table[i].slave_host_fd = PTY_KEEPALIVE_FREE;
    }
}

static void pty_keepalive_lock_acquire(void)
{
    pthread_once(&pty_keepalive_once, pty_keepalive_init);
    pthread_mutex_lock(&pty_keepalive_lock);
}

/* Find a slot by master_host_fd; -1 if none. Caller holds the lock. */
static int pty_keepalive_find_master_locked(int master_host_fd)
{
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++)
        if (pty_keepalive_table[i].master_host_fd == master_host_fd)
            return i;
    return -1;
}

static int pty_keepalive_clear_slot_locked(int slot)
{
    int slave = pty_keepalive_table[slot].slave_host_fd;
    pty_keepalive_table[slot].master_host_fd = PTY_KEEPALIVE_FREE;
    pty_keepalive_table[slot].slave_host_fd = PTY_KEEPALIVE_FREE;
    pty_keepalive_table[slot].linux_pts_num = 0;
    pty_keepalive_table[slot].stale_open_once = false;
    pty_keepalive_table[slot].slave_path[0] = '\0';
    return slave;
}

static uint32_t pty_extract_pts_num(const char *slave_path)
{
    /* macOS canonical slave paths are /dev/ttysNNN with a decimal tail. Read
     * the longest decimal suffix and return it as the Linux pts number used by
     * guest /dev/pts/N.
     *
     * Returns UINT32_MAX on parse failure so callers can reject ambiguous names
     * rather than silently aliasing.
     */
    if (!slave_path)
        return UINT32_MAX;
    const char *p = slave_path + strlen(slave_path);
    while (p > slave_path && isdigit((unsigned char) p[-1]))
        p--;
    if (!*p || !isdigit((unsigned char) *p))
        return UINT32_MAX;
    char *endp;
    unsigned long n = strtoul(p, &endp, 10);
    if (endp == p || *endp != '\0' || n > UINT32_MAX)
        return UINT32_MAX;
    return (uint32_t) n;
}

/* Result codes for the locked register helper. */
#define PTY_REG_INSERTED 0 /* new entry installed */
#define PTY_REG_EXISTS 1   /* a matching entry already existed */
#define PTY_REG_FULL (-1)  /* table out of free slots */

/* Caller-holds-lock variant.
 *
 * Returns one of PTY_REG_* and, on PTY_REG_EXISTS, writes the existing entry's
 * pts number to *existing_pts_num. The lock-held variant exists so
 * proc_pty_master_adopt can atomically pair fd-table slot validation with
 * keepalive insertion under fd_lock + pty_keepalive_lock, eliminating the race
 * window where a sibling close+recycle between validate and register would
 * attach the keepalive to the wrong file.
 */
static int pty_keepalive_register_locked(int master_host_fd,
                                         int slave_host_fd,
                                         uint32_t linux_pts_num,
                                         const char *slave_path,
                                         bool stale_open_once,
                                         uint32_t *existing_pts_num)
{
    int empty_slot = -1;
    int stale_path_slot = -1;
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (pty_keepalive_table[i].master_host_fd == master_host_fd) {
            if (existing_pts_num)
                *existing_pts_num = pty_keepalive_table[i].linux_pts_num;
            return PTY_REG_EXISTS;
        }
        if (pty_keepalive_table[i].master_host_fd != PTY_KEEPALIVE_FREE)
            continue;
        /* Prefer a stale-path slot with the same pts number: the macOS minor
         * deterministically maps to the same slave_path string, so reusing
         * keeps lookups path-correct and bounds the table at one slot per live
         * minor instead of accumulating a new entry on every reopen.
         */
        if (pty_keepalive_table[i].slave_path[0] != '\0' &&
            pty_keepalive_table[i].linux_pts_num == linux_pts_num) {
            stale_path_slot = i;
        } else if (empty_slot < 0 &&
                   pty_keepalive_table[i].slave_path[0] == '\0') {
            empty_slot = i;
        }
    }
    int slot = (stale_path_slot >= 0) ? stale_path_slot : empty_slot;
    if (slot < 0) {
        /* Out of empty slots and no stale-path match: evict the lowest-index
         * stale-path entry so the live registration cannot starve. Live entries
         * are never evicted. The eviction policy is approximately LRU: empty
         * slots fill from low indices, so the lowest-index stale slot tends to
         * be the oldest closed. A theoretical race exists with the
         * close-before-open child pattern (a child stales slot K under
         * pty_keepalive_lock and races into open("/dev/pts/N") just as another
         * thread evicts slot K to register a different minor) but needs the
         * keepalive table to be full -- live and stale entries both count --
         * with the staling thread's slot being the lowest-index stale. Well
         * outside the foot / sshd workload that motivated this code.
         */
        for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
            if (pty_keepalive_table[i].master_host_fd == PTY_KEEPALIVE_FREE &&
                pty_keepalive_table[i].slave_path[0] != '\0') {
                slot = i;
                break;
            }
        }
        if (slot < 0)
            return PTY_REG_FULL;
    }
    pty_keepalive_table[slot].master_host_fd = master_host_fd;
    if (pty_keepalive_table[slot].slave_host_fd >= 0 &&
        pty_keepalive_table[slot].slave_host_fd != slave_host_fd)
        close(pty_keepalive_table[slot].slave_host_fd);
    if (stale_open_once) {
        pty_keepalive_table[slot].slave_host_fd = slave_host_fd;
    } else {
        if (slave_host_fd >= 0)
            close(slave_host_fd);
        pty_keepalive_table[slot].slave_host_fd = PTY_KEEPALIVE_FREE;
    }
    pty_keepalive_table[slot].linux_pts_num = linux_pts_num;
    pty_keepalive_table[slot].stale_open_once = stale_open_once;
    if (slave_path)
        str_copy_trunc(pty_keepalive_table[slot].slave_path, slave_path,
                       PTY_SLAVE_PATH_MAX);
    else
        pty_keepalive_table[slot].slave_path[0] = '\0';
    return PTY_REG_INSERTED;
}

/* Lock-acquiring convenience wrapper used by the open-time and fork-restore
 * paths where atomicity with fd_table is not required.
 *
 * Returns 0 on success (including PTY_REG_EXISTS, in which case the caller
 * should close its own redundant slave_host_fd), -1 with errno set on
 * table-full (ENOSPC).
 */
static int pty_keepalive_register(int master_host_fd,
                                  int slave_host_fd,
                                  uint32_t linux_pts_num,
                                  const char *slave_path,
                                  bool stale_open_once)
{
    pty_keepalive_lock_acquire();
    int rc = pty_keepalive_register_locked(master_host_fd, slave_host_fd,
                                           linux_pts_num, slave_path,
                                           stale_open_once, NULL);
    pthread_mutex_unlock(&pty_keepalive_lock);
    if (rc == PTY_REG_FULL) {
        errno = ENOSPC;
        return -1;
    }
    if (rc == PTY_REG_EXISTS)
        errno = EEXIST;
    return 0;
}

uint32_t proc_pty_master_pts_num(int master_host_fd)
{
    if (master_host_fd < 0)
        return UINT32_MAX;
    pty_keepalive_lock_acquire();
    int slot = pty_keepalive_find_master_locked(master_host_fd);
    uint32_t pts_num =
        (slot < 0) ? UINT32_MAX : pty_keepalive_table[slot].linux_pts_num;
    pthread_mutex_unlock(&pty_keepalive_lock);
    return pts_num;
}

/* Re-validate that fd_table[guest_fd] still refers to (host_fd, generation).
 * Returns true when both match the snapshot, false otherwise (slot closed or
 * recycled). Used by proc_pty_master_adopt to bracket every host-fd-number
 * access against the closing-and-reuse race.
 */
static bool pty_fd_still_canonical(int guest_fd,
                                   int canonical_host_fd,
                                   uint64_t canonical_gen)
{
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap))
        return false;
    return snap.host_fd == canonical_host_fd &&
           snap.generation == canonical_gen;
}

uint32_t proc_pty_master_adopt(int guest_fd)
{
    /* Step 1: atomically snapshot (host_fd, generation) and dup the canonical
     * fd in a single fd_lock window. fd_snapshot_and_dup pins the file object
     * behind the canonical host fd, so even if a sibling closes the guest fd
     * and the host fd number is recycled by an unrelated open, host syscalls
     * against the probe still operate on the right tty. The generation captured
     * here is the witness for the subsequent table lookup and register
     * validations.
     */
    fd_entry_t snap;
    int probe = fd_snapshot_and_dup(guest_fd, &snap);
    if (probe < 0)
        return UINT32_MAX;
    int canonical_host_fd = snap.host_fd;
    uint64_t canonical_gen = snap.generation;

    /* Fast path: a keepalive was already registered for this canonical fd
     * (typical case for /dev/ptmx opens that went through pty_open_master). The
     * keepalive table is keyed by host fd number, so re-validate the slot
     * identity before trusting the returned pts_num. If the fd has been
     * recycled to a different file (generation mismatch), the existing entry
     * belongs to that file, not the pinned probe, and the slow path below must
     * register a fresh entry for the pinned probe.
     */
    uint32_t existing = proc_pty_master_pts_num(canonical_host_fd);
    if (existing != UINT32_MAX &&
        pty_fd_still_canonical(guest_fd, canonical_host_fd, canonical_gen)) {
        close(probe);
        return existing;
    }

    /* Step 2: confirm the file really is a /dev/ptmx master. ptsname(3) returns
     * NULL/ENOTTY on non-pty descriptors, so a stray TIOCGPTN against a regular
     * file is rejected without any side effect.
     */
    char slave_path[PTY_SLAVE_PATH_MAX];
    uint32_t pts_num = UINT32_MAX;
    int slave = -1;
    if (ptsname_r(probe, slave_path, sizeof(slave_path)) != 0)
        goto out;
    pts_num = pty_extract_pts_num(slave_path);
    if (pts_num == UINT32_MAX)
        goto out;

    /* unlockpt(3) is harmless if the sender already unlocked. EINVAL means
     * already unlocked; anything else means the slave will not open and we give
     * up cleanly.
     */
    if (unlockpt(probe) < 0 && errno != EINVAL) {
        pts_num = UINT32_MAX;
        goto out;
    }
    slave = open(slave_path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) {
        pts_num = UINT32_MAX;
        goto out;
    }

    /* Step 3: re-validate AND publish under the joint pty_keepalive_lock +
     * fd_lock window. Lock order is pty_keepalive_lock first;
     * duplicate_guest_fd uses the same order when bracketing
     * fd_snapshot_and_dup + proc_pty_dup_keepalive_locked, so the two paths
     * cannot deadlock. With both held, no sibling can flip the fd_table slot
     * between the validation read and the keepalive insert, so the keepalive
     * cannot attach to a recycled canonical host fd.
     */
    pty_keepalive_lock_acquire();
    pthread_mutex_lock(&fd_lock);
    if (fd_table[guest_fd].type == FD_CLOSED ||
        fd_table[guest_fd].host_fd != canonical_host_fd ||
        fd_table[guest_fd].generation != canonical_gen) {
        pthread_mutex_unlock(&fd_lock);
        pthread_mutex_unlock(&pty_keepalive_lock);
        close(slave);
        pts_num = UINT32_MAX;
        goto out;
    }
    uint32_t existing_pts = UINT32_MAX;
    int rc = pty_keepalive_register_locked(canonical_host_fd, slave, pts_num,
                                           slave_path, false, &existing_pts);
    pthread_mutex_unlock(&fd_lock);
    pthread_mutex_unlock(&pty_keepalive_lock);
    if (rc == PTY_REG_FULL) {
        close(slave);
        pts_num = UINT32_MAX;
    } else if (rc == PTY_REG_EXISTS) {
        /* Another adopter registered first; their slave keeps the tty alive.
         * The pts_num came from the locked scan above, so it is the value the
         * winning entry holds and is not subject to a lookup-after-recycle
         * race.
         */
        close(slave);
        pts_num = existing_pts;
    }

out:
    close(probe);
    return pts_num;
}

/* Look up the captured macOS slave path for a Linux pts number.
 *
 * Returns 0 and writes the path on hit, -1 with errno=ENOENT on miss. Used by
 * the /dev/pts/N open and stat intercepts so they hit the exact path returned
 * by ptsname(3) rather than a guessed /dev/ttys%03lu reformat that breaks if
 * macOS changes its naming scheme or uses an unexpected minor encoding.
 */
static int pty_lookup_slave_path(uint32_t linux_pts_num,
                                 char *out,
                                 size_t out_sz)
{
    if (!out || out_sz == 0) {
        errno = EINVAL;
        return -1;
    }
    int hit = -1;
    pty_keepalive_lock_acquire();
    /* Prefer a live entry (master still open in this process) over a stale path
     * entry. Both encode the same slave_path for a given minor on macOS, so the
     * preference only matters if a future change ever lets the two diverge -
     * live wins by breaking out of the scan on first match.
     */
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (pty_keepalive_table[i].linux_pts_num != linux_pts_num)
            continue;
        if (pty_keepalive_table[i].slave_path[0] == '\0')
            continue;
        if (pty_keepalive_table[i].master_host_fd != PTY_KEEPALIVE_FREE) {
            hit = i;
            break;
        }
        if (!pty_keepalive_table[i].stale_open_once ||
            pty_keepalive_table[i].slave_host_fd < 0)
            continue;
        if (hit < 0)
            hit = i;
    }
    if (hit < 0) {
        pthread_mutex_unlock(&pty_keepalive_lock);
        errno = ENOENT;
        return -1;
    }
    size_t len = strlen(pty_keepalive_table[hit].slave_path);
    if (len >= out_sz) {
        pthread_mutex_unlock(&pty_keepalive_lock);
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, pty_keepalive_table[hit].slave_path, len + 1);
    pthread_mutex_unlock(&pty_keepalive_lock);
    return 0;
}

static int pty_open_slave(uint32_t linux_pts_num, int linux_flags)
{
    int oflags = translate_open_flags(linux_flags) &
                 (O_ACCMODE | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
    char host_path[PTY_SLAVE_PATH_MAX];
    int stale_hit = -1;
    int retained_slaves[PTY_KEEPALIVE_MAX];
    int nretained = 0;
    int fd = -1;

    pty_keepalive_lock_acquire();
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (pty_keepalive_table[i].linux_pts_num != linux_pts_num)
            continue;
        if (pty_keepalive_table[i].slave_path[0] == '\0')
            continue;
        if (pty_keepalive_table[i].master_host_fd != PTY_KEEPALIVE_FREE) {
            size_t len = strlen(pty_keepalive_table[i].slave_path);
            if (len >= sizeof(host_path)) {
                pthread_mutex_unlock(&pty_keepalive_lock);
                errno = ENAMETOOLONG;
                return -1;
            }
            memcpy(host_path, pty_keepalive_table[i].slave_path, len + 1);
            pthread_mutex_unlock(&pty_keepalive_lock);
            return open(host_path, oflags);
        }
        if (stale_hit < 0 && pty_keepalive_table[i].stale_open_once &&
            pty_keepalive_table[i].slave_host_fd >= 0)
            stale_hit = i;
    }

    if (stale_hit < 0) {
        pthread_mutex_unlock(&pty_keepalive_lock);
        errno = ENOENT;
        return -1;
    }

    /* Stale fork-child entries are one-shot. The retained slave fd pins the
     * macOS tty while we translate the close-before-open sequence, preventing
     * the cached path from resolving to a reused unrelated minor. Regardless of
     * open success, consume the stale mapping before returning.
     */
    size_t len = strlen(pty_keepalive_table[stale_hit].slave_path);
    if (len >= sizeof(host_path)) {
        int retained_slave = pty_keepalive_clear_slot_locked(stale_hit);
        pthread_mutex_unlock(&pty_keepalive_lock);
        if (retained_slave >= 0)
            close(retained_slave);
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(host_path, pty_keepalive_table[stale_hit].slave_path, len + 1);
    fd = open(host_path, oflags);
    int saved = errno;
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (pty_keepalive_table[i].master_host_fd != PTY_KEEPALIVE_FREE)
            continue;
        if (!pty_keepalive_table[i].stale_open_once)
            continue;
        if (strncmp(pty_keepalive_table[i].slave_path, host_path,
                    PTY_SLAVE_PATH_MAX) != 0)
            continue;
        int retained_slave = pty_keepalive_clear_slot_locked(i);
        if (retained_slave >= 0 && nretained < PTY_KEEPALIVE_MAX)
            retained_slaves[nretained++] = retained_slave;
    }
    pthread_mutex_unlock(&pty_keepalive_lock);
    for (int i = 0; i < nretained; i++)
        close(retained_slaves[i]);
    errno = saved;
    return fd;
}

static int pty_open_pts_dir(int linux_flags)
{
    char dir[80];
    uint32_t pts_nums[PTY_KEEPALIVE_MAX];
    int pts_count = 0;
    int n = snprintf(dir, sizeof(dir), "/tmp/elfuse-pts-XXXXXX");
    if (n < 0 || (size_t) n >= sizeof(dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (!mkdtemp(dir))
        return -1;

    pty_keepalive_lock_acquire();
    /* Enumerate live masters and fork-child one-shot stale entries. The stale
     * entries retain a slave fd until the first open attempt consumes them, so
     * they cannot name a reused unrelated tty while they appear in readdir.
     */
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (pty_keepalive_table[i].slave_path[0] == '\0')
            continue;
        if (pty_keepalive_table[i].master_host_fd == PTY_KEEPALIVE_FREE &&
            (!pty_keepalive_table[i].stale_open_once ||
             pty_keepalive_table[i].slave_host_fd < 0))
            continue;
        /* The recycle/reuse-by-pts_num invariant in
         * pty_keepalive_register_locked keeps at most one entry per minor, so
         * no de-duplication pass is needed here.
         */
        pts_nums[pts_count++] = pty_keepalive_table[i].linux_pts_num;
    }
    pthread_mutex_unlock(&pty_keepalive_lock);

    for (int i = 0; i < pts_count; i++) {
        char entry[160];
        int en = snprintf(entry, sizeof(entry), "%s/%u", dir, pts_nums[i]);
        if (en <= 0 || (size_t) en >= sizeof(entry))
            continue;
        int tfd = open(entry, O_CREAT | O_WRONLY, 0444);
        if (tfd >= 0)
            close(tfd);
    }

    pthread_once(&proc_scratch_atexit_once, proc_scratch_register_atexit);

    pthread_mutex_lock(&proc_scratch_lock);
    if (proc_scratch_dirs_count < PROC_SCRATCH_DIRS_MAX) {
        str_copy_trunc(proc_scratch_dirs[proc_scratch_dirs_count++], dir,
                       sizeof(proc_scratch_dirs[0]));
    }
    pthread_mutex_unlock(&proc_scratch_lock);

    int fd = proc_open_dir_fd(dir, linux_flags);
    if (fd < 0) {
        int saved = errno;
        proc_scratch_remove_one(dir);
        errno = saved;
    }
    return fd;
}

void proc_pty_lock_for_dup(void)
{
    pty_keepalive_lock_acquire();
}

void proc_pty_unlock_for_dup(void)
{
    pthread_mutex_unlock(&pty_keepalive_lock);
}

void proc_pty_dup_keepalive_locked(int src_master_host_fd,
                                   int dst_master_host_fd)
{
    /* Caller-holds-lock variant; see header for the dup race this guards. */
    if (src_master_host_fd < 0 || dst_master_host_fd < 0)
        return;

    int slot = pty_keepalive_find_master_locked(src_master_host_fd);
    if (slot < 0)
        return;
    int dst_slave = -1;
    if (pty_keepalive_table[slot].slave_host_fd >= 0) {
        dst_slave = dup(pty_keepalive_table[slot].slave_host_fd);
        if (dst_slave < 0)
            return;
    }
    uint32_t src_pts_num = pty_keepalive_table[slot].linux_pts_num;
    char src_slave_path[PTY_SLAVE_PATH_MAX];
    memcpy(src_slave_path, pty_keepalive_table[slot].slave_path,
           PTY_SLAVE_PATH_MAX);

    if (dst_slave >= 0) {
        /* dup(2) clears FD_CLOEXEC; the keepalive must not survive exec into
         * a guest child that has no map back to it.
         */
        int fdflags = fcntl(dst_slave, F_GETFD);
        if (fdflags < 0 ||
            fcntl(dst_slave, F_SETFD, fdflags | FD_CLOEXEC) < 0) {
            close(dst_slave);
            return;
        }
    }
    int rc =
        pty_keepalive_register_locked(dst_master_host_fd, dst_slave,
                                      src_pts_num, src_slave_path, false, NULL);
    if (rc != PTY_REG_INSERTED) {
        /* Table full or duplicate entry for dst_master_host_fd; drop the
         * redundant slave. Duplicate is unexpected: dst is a freshly-duped host
         * fd that should not already be in the table unless a prior close
         * skipped proc_pty_close_keepalive.
         */
        if (dst_slave >= 0)
            close(dst_slave);
    }
}

void proc_pty_close_keepalive(int master_host_fd)
{
    /* fd_cleanup_entry calls this for every guest fd close, not just pty
     * masters; pty_keepalive_lock_acquire guarantees sentinel-init first.
     */
    if (master_host_fd < 0)
        return;

    int slave = -1;
    pty_keepalive_lock_acquire();
    int slot = pty_keepalive_find_master_locked(master_host_fd);
    if (slot >= 0) {
        if (pty_keepalive_table[slot].stale_open_once) {
            /* Fork-restored child entry: retain the slave fd and path for one
             * /dev/pts/N open after close(master). pty_open_slave consumes and
             * closes it on the first translated open attempt.
             */
            pty_keepalive_table[slot].master_host_fd = PTY_KEEPALIVE_FREE;
        } else {
            slave = pty_keepalive_clear_slot_locked(slot);
        }
    }
    pthread_mutex_unlock(&pty_keepalive_lock);
    if (slave >= 0)
        close(slave);
}

static void proc_pty_expire_stale_by_path(const char *slave_path)
{
    if (!slave_path || slave_path[0] == '\0')
        return;

    int stale_slaves[PTY_KEEPALIVE_MAX];
    int nslaves = 0;
    pty_keepalive_lock_acquire();
    for (int i = 0; i < PTY_KEEPALIVE_MAX; i++) {
        if (pty_keepalive_table[i].master_host_fd != PTY_KEEPALIVE_FREE)
            continue;
        if (!pty_keepalive_table[i].stale_open_once)
            continue;
        if (strncmp(pty_keepalive_table[i].slave_path, slave_path,
                    PTY_SLAVE_PATH_MAX) != 0)
            continue;
        int slave = pty_keepalive_clear_slot_locked(i);
        if (slave >= 0 && nslaves < PTY_KEEPALIVE_MAX)
            stale_slaves[nslaves++] = slave;
    }
    pthread_mutex_unlock(&pty_keepalive_lock);
    for (int i = 0; i < nslaves; i++)
        close(stale_slaves[i]);
}

static int pty_keepalive_register_recycled(int master_host_fd,
                                           int slave_host_fd,
                                           uint32_t linux_pts_num,
                                           const char *slave_path,
                                           bool stale_open_once)
{
    proc_pty_expire_stale_by_path(slave_path);
    return pty_keepalive_register(master_host_fd, slave_host_fd, linux_pts_num,
                                  slave_path, stale_open_once);
}

int proc_pty_snapshot_keepalive(proc_pty_ipc_entry_t *out_entries,
                                int *out_slave_fds,
                                int max_entries)
{
    if (!out_entries || !out_slave_fds || max_entries <= 0)
        return 0;

    int n = 0;
    pty_keepalive_lock_acquire();
    for (int i = 0; i < PTY_KEEPALIVE_MAX && n < max_entries; i++) {
        if (pty_keepalive_table[i].master_host_fd == PTY_KEEPALIVE_FREE)
            continue;

        /* Live entries keep only the slave path so the master can observe HUP
         * when the real child-side slave closes. Open a temporary slave fd only
         * for SCM_RIGHTS handoff to the fork child; stale one-shot entries may
         * already carry a retained slave fd and can still be duped.
         */
        int duped = -1;
        if (pty_keepalive_table[i].slave_host_fd >= 0) {
            duped = dup(pty_keepalive_table[i].slave_host_fd);
        } else if (pty_keepalive_table[i].slave_path[0] != '\0') {
            duped = open(pty_keepalive_table[i].slave_path,
                         O_RDWR | O_NOCTTY | O_CLOEXEC);
        }
        if (duped < 0)
            continue;

        out_entries[n].master_host_fd = pty_keepalive_table[i].master_host_fd;
        out_entries[n].linux_pts_num = pty_keepalive_table[i].linux_pts_num;
        _Static_assert(sizeof(out_entries[n].slave_path) == PTY_SLAVE_PATH_MAX,
                       "ipc slave_path size must match keepalive table");
        memcpy(out_entries[n].slave_path, pty_keepalive_table[i].slave_path,
               PTY_SLAVE_PATH_MAX);
        out_slave_fds[n] = duped;
        n++;
    }
    pthread_mutex_unlock(&pty_keepalive_lock);
    return n;
}

void proc_pty_restore_keepalive(int master_host_fd,
                                int slave_host_fd,
                                uint32_t linux_pts_num,
                                const char *slave_path)
{
    /* fork-IPC hand-off. SCM_RIGHTS drops FD_CLOEXEC; set it here so the
     * keepalive does not survive exec. Any failure drops the slave fd.
     */
    if (master_host_fd < 0)
        goto drop;

    if (slave_host_fd >= 0) {
        int fdflags = fcntl(slave_host_fd, F_GETFD);
        if (fdflags < 0 ||
            fcntl(slave_host_fd, F_SETFD, fdflags | FD_CLOEXEC) < 0)
            goto drop;
    }

    /* Trust the parent's linux_pts_num verbatim instead of re-parsing
     * slave_path. The wire-format string is bounded to PTY_SLAVE_PATH_MAX - 1
     * bytes; if a future macOS canonical form ever exceeded that, the parent
     * would have truncated and reparsing here would yield the wrong number. On
     * EEXIST the child's fd_table-restore path replayed master_host_fd over a
     * prior recv-keepalive entry; drop the redundant slave so it does not leak.
     */
    errno = 0;
    if (pty_keepalive_register_recycled(master_host_fd, slave_host_fd,
                                        linux_pts_num, slave_path, true) < 0 ||
        errno == EEXIST)
        goto drop;
    return;

drop:
    if (slave_host_fd >= 0)
        close(slave_host_fd);
}

/* Open /dev/ptmx, unlock the slave, and instantiate a keepalive slave fd so the
 * master's tty ioctls work before the guest opens the slave itself.
 * Returns the master host fd on success, -1 with errno set on failure.
 */
static int pty_open_master(int linux_flags)
{
    /* /dev/ptmx is a character device; O_CREAT / O_TRUNC / O_EXCL make no sense
     * here. Strip them and only honor accmode + descriptor flags so the host
     * open(2) never sees a variadic-mode-required combination without a mode
     * arg.
     */
    int oflags = translate_open_flags(linux_flags) &
                 (O_ACCMODE | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
    int master = open("/dev/ptmx", oflags);
    if (master < 0)
        return -1;

    /* grantpt(3) is a no-op on a unix98 pty mount, but call it for clarity and
     * to match what posix_openpt(3)'s callers expect to have happened.
     */
    char slave_path[PTY_SLAVE_PATH_MAX];
    if (grantpt(master) < 0 || unlockpt(master) < 0 ||
        ptsname_r(master, slave_path, sizeof(slave_path)) != 0) {
        close_keep_errno(master);
        return -1;
    }

    /* Establish the (linux_pts_num, slave_path) mapping that /dev/pts/N opens
     * and stats resolve through. If table or slave-fd registration fails after
     * the master is open, report EMFILE rather than silently returning a master
     * fd whose pts number cannot be opened back through /dev/pts/N. The caller
     * can close other pty pairs and retry instead of dealing with a half-broken
     * descriptor.
     */
    uint32_t linux_pts_num = pty_extract_pts_num(slave_path);
    if (linux_pts_num == UINT32_MAX) {
        close(master);
        errno = ENOTTY;
        return -1;
    }
    int slave = open(slave_path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) {
        close_keep_errno(master);
        return -1;
    }
    errno = 0;
    if (pty_keepalive_register_recycled(master, slave, linux_pts_num,
                                        slave_path, false) < 0) {
        close(slave);
        close(master);
        errno = EMFILE;
        return -1;
    }
    /* Defense-in-depth: the freshly-opened master fd should not already have a
     * keepalive (would indicate a stale entry from a prior close that did not
     * run proc_pty_close_keepalive). Drop the redundant slave so it does not
     * leak.
     */
    if (errno == EEXIST)
        close(slave);
    return master;
}

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
        const char *digits = path + 9;
        if (!*digits) {
            errno = ENOENT;
            return -1;
        }
        char *endp;
        unsigned long n = strtoul(digits, &endp, 10);
        if (endp == digits || *endp != '\0' || n > UINT32_MAX) {
            errno = ENOENT;
            return -1;
        }
        /* /dev/pts/N is a character device; strip O_CREAT and friends so the
         * two-argument open(2) never sees a creation-mode-required combination
         * without a mode arg.
         */
        return pty_open_slave((uint32_t) n, linux_flags);
    }

    /* /proc -> synthetic directory with PID entries for busybox ps, top, etc.
     * Creates a temp dir once (cached for the process lifetime) with entries
     * matching the current single-process model: the current PID directory +
     * "self" symlink. The DIR* created from this allows getdents64 to enumerate
     * /proc like a real procfs. Cleaned up via atexit.
     */
    if (!strcmp(path, "/proc")) {
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
            "Uid:\t%d\t%d\t%d\t%d\n"
            "Gid:\t%d\t%d\t%d\t%d\n"
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

    /* /proc/self/task/<tid>/stat -> per-thread stat line */
    if (!strncmp(path, "/proc/self/task/", 16)) {
        char *endp;
        long tid = strtol(path + 16, &endp, 10);
        if (endp == path + 16 || tid <= 0)
            return -2; /* not intercepted */

        /* Verify this TID is actually active */
        if (!thread_tid_alive((int64_t) tid)) {
            errno = ENOENT;
            return -1;
        }

        if (!strcmp(endp, "/stat")) {
            return proc_emit_fmt(
                "%ld (%.15s) R %lld %lld %lld 0 0 0 0 0 0 0 0 0 0 0 "
                "20 0 %d 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
                "0 0 0 0 0 0 0 0\n",
                tid, proc_comm_name(), (long long) proc_get_ppid(),
                (long long) proc_get_pid(), /* pgid */
                (long long) proc_get_sid(), thread_active_count());
        }

        if (!strcmp(endp, "/status")) {
            return proc_emit_fmt(
                "Name:\t%.15s\n"
                "State:\tR (running)\n"
                "Tgid:\t%lld\n"
                "Pid:\t%ld\n"
                "PPid:\t%lld\n"
                "Uid:\t%d\t%d\t%d\t%d\n"
                "Gid:\t%d\t%d\t%d\t%d\n"
                "Threads:\t%d\n",
                proc_comm_name(), (long long) proc_get_pid(), tid,
                (long long) proc_get_ppid(), proc_get_uid(), proc_get_euid(),
                proc_get_suid(), proc_get_euid(), proc_get_gid(),
                proc_get_egid(), proc_get_sgid(), proc_get_egid(),
                thread_active_count());
        }

        /* /proc/self/task/<tid> directory itself: synthesize a dir with
         * stat/status placeholder entries. Persistent so getdents sees the
         * entries on macOS (which cannot enumerate unlinked dirs).
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

        return -2; /* unknown /proc/self/task/<tid>/XXX */
    }

    /* /proc/self/maps -> generated from guest region tracking. Addresses are
     * page-aligned (rounded down/up) to match real Linux behavior. Output
     * merges consecutive regions with the same prot, flags, and name into a
     * single maps line, matching real Linux kernel behavior where a single
     * mmap() call produces one maps entry even when the backing pages span
     * multiple physical frames.
     */
    if (!strcmp(path, "/proc/self/maps")) {
        char buf[16384];
        int off = 0;

        /* Build a flat array of (va_start, va_end, prot, flags, offset, name)
         * from regions[] plus /proc/self/maps-only preannounced[] entries.
         * preannounced[] is intentionally NOT consulted by mmap conflict
         * detection, so advertise-only Rosetta/JIT regions do not trip
         * MAP_FIXED_NOREPLACE with -EEXIST.
         */
        maps_entry_t entries[MAPS_ENTRY_MAX];
        int nentries = 0;

        /* Convert regions[] to maps entries. regions[] is already sorted by
         * start address; merge contiguous runs that came from one mmap.
         */
        for (int i = 0; i < g->nregions && nentries < MAPS_ENTRY_MAX; i++) {
            const guest_region_t *r = &g->regions[i];
            uint64_t start = r->start & ~0xFFFULL;
            uint64_t end = (r->end + 0xFFF) & ~0xFFFULL;

            if (nentries > 0 && entries[nentries - 1].end == start &&
                entries[nentries - 1].prot == r->prot &&
                entries[nentries - 1].flags == r->flags &&
                entries[nentries - 1].offset == r->offset &&
                !strcmp(entries[nentries - 1].name, r->name)) {
                entries[nentries - 1].end = end;
                continue;
            }
            maps_entry_insert(entries, &nentries, start, end, r->prot, r->flags,
                              r->offset, r->name);
        }

        /* Add preannounced entries only while they still have an uncovered
         * tail. Once the union of live regions covers the full advertised
         * interval, suppress the shadow entry so /proc/self/maps shows only the
         * realized split VMAs. A partial union must stay visible because some
         * reserved-but-not-realized span remains to advertise.
         */
        for (int i = 0; i < g->npreannounced && nentries < MAPS_ENTRY_MAX;
             i++) {
            const guest_region_t *r = &g->preannounced[i];
            bool shadowed = false;
            uint64_t covered_end = r->start;

            for (int j = 0; j < g->nregions; j++) {
                const guest_region_t *live = &g->regions[j];

                if (live->end <= covered_end)
                    continue;
                if (live->start > covered_end)
                    break;

                covered_end = live->end;
                if (covered_end >= r->end) {
                    shadowed = true;
                    break;
                }
            }

            if (shadowed)
                continue;

            maps_entry_insert(entries, &nentries, r->start & ~0xFFFULL,
                              (r->end + 0xFFFULL) & ~0xFFFULL, r->prot,
                              r->flags, r->offset, r->name);
        }
        maps_entries_merge_adjacent(entries, &nentries);

        /* Emit lines after merging so buffer accounting is centralized. */
        for (int i = 0; i < nentries && off < (int) sizeof(buf) - 256; i++) {
            const maps_entry_t *e = &entries[i];
            char perms[5];
            perms[0] = (e->prot & 0x1) ? 'r' : '-';
            perms[1] = (e->prot & 0x2) ? 'w' : '-';
            perms[2] = (e->prot & 0x4) ? 'x' : '-';
            perms[3] = (e->flags & 0x01) ? 's' : 'p';
            perms[4] = '\0';

            /* Format matches real Linux /proc/<pid>/maps exactly:
             *   %lx-%lx %s %08lx %02x:%02x %lu  <padding>  %s\n
             * Verified against strace in a real Lima VZ VM.
             */
            char line[256];
            int lineoff = snprintf(
                line, sizeof(line), "%llx-%llx %s %08llx 00:00 0",
                (unsigned long long) e->start, (unsigned long long) e->end,
                perms, (unsigned long long) e->offset);
            /* Cap lineoff to buffer size (snprintf may return more than
             * available on truncation)
             */
            if (lineoff >= (int) sizeof(line))
                lineoff = (int) sizeof(line) - 1;
            if (e->name[0]) {
                while (lineoff < MAPS_NAME_COLUMN &&
                       lineoff < (int) sizeof(line) - 1)
                    line[lineoff++] = ' ';
                int n = snprintf(line + lineoff, sizeof(line) - lineoff, "%s",
                                 e->name);
                if (n > 0)
                    lineoff += n;
                if (lineoff >= (int) sizeof(line))
                    lineoff = (int) sizeof(line) - 1;
            } else if (lineoff < (int) sizeof(line) - 1) {
                line[lineoff++] = ' ';
            }
            int wrote =
                snprintf(buf + off, sizeof(buf) - off, "%.*s\n", lineoff, line);
            if (wrote > 0 && off + wrote < (int) sizeof(buf))
                off += wrote;
            else
                break; /* Stop before truncating a maps line. */
        }

        log_debug("/proc/self/maps (%d bytes):\n%.*s", off, off, buf);
        return proc_synthetic_fd(buf, off);
    }

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
        char buf[16384];
        ctx.buf = buf;
        ctx.off = snprintf(
            buf, sizeof(buf), "%s",
            want_tcp ? "  sl  local_address rem_address   st tx_queue "
                       "rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                     : "  sl  local_address rem_address   st tx_queue "
                       "rx_queue tr tm->when retrnsmt   uid  timeout inode"
                       " ref pointer drops\n");
        proc_net_for_each_socket(proc_net_inet_visit, &ctx);
        return proc_synthetic_fd_str(buf, ctx.off, sizeof(buf));
    }
    if (!strcmp(path, "/proc/net/unix")) {
        char buf[8192];
        struct proc_net_unix_ctx ctx = {
            .buf = buf,
            .bufsz = sizeof(buf),
            .off = snprintf(buf, sizeof(buf),
                            "Num       RefCount Protocol Flags    Type St "
                            "Inode Path\n"),
        };
        proc_net_for_each_socket(proc_net_unix_visit, &ctx);
        return proc_synthetic_fd_str(buf, ctx.off, sizeof(buf));
    }

    /* /proc/sys/vm/mmap_min_addr -> synthetic mmap minimum address. */
    if (!strcmp(path, "/proc/sys/vm/mmap_min_addr"))
        return proc_emit_literal("32768\n");

    /* /proc/sys/kernel/randomize_va_space -> ASLR enabled (full). */
    if (!strcmp(path, "/proc/sys/kernel/randomize_va_space"))
        return proc_emit_literal("2\n");

    /* /proc/version -> synthetic kernel version string */
    if (!strcmp(path, "/proc/version")) {
        return proc_emit_literal(
            "Linux version 6.17.0-20-generic "
            "(buildd@bos03-arm64-051) "
            "(aarch64-linux-gnu-gcc (Ubuntu 15.2.0-4ubuntu4) "
            "15.2.0, GNU ld (GNU Binutils for Ubuntu) 2.45) "
            "#20-Ubuntu SMP PREEMPT_DYNAMIC\n");
    }

    /* /proc/filesystems -> supported filesystem types */
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
        char buf[8192];
        size_t off = (size_t) snprintf(
            buf, sizeof(buf),
            "1 0 0:1 / / rw,relatime - ext4 /dev/root rw\n"
            "2 1 0:2 / /proc rw,nosuid,nodev,noexec - proc proc rw\n"
            "3 1 0:3 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw\n"
            "4 1 0:4 / /dev rw,nosuid - devtmpfs devtmpfs rw\n"
            "5 4 0:5 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw\n");
        if (off >= sizeof(buf) ||
            fuse_append_mountinfo(buf, sizeof(buf), &off) < 0)
            return -1;
        return proc_synthetic_fd(buf, off);
    }

    /* /proc/mounts, /etc/mtab -> synthetic mount table */
    if (!strcmp(path, "/proc/mounts") || !strcmp(path, "/proc/self/mounts") ||
        !strcmp(path, "/etc/mtab")) {
        char buf[8192];
        size_t off =
            (size_t) snprintf(buf, sizeof(buf),
                              "/ / ext4 rw,relatime 0 0\n"
                              "proc /proc proc rw,nosuid,nodev,noexec 0 0\n"
                              "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n"
                              "devtmpfs /dev devtmpfs rw,nosuid 0 0\n"
                              "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n");
        if (off >= sizeof(buf) ||
            fuse_append_mounts(buf, sizeof(buf), &off) < 0)
            return -1;
        return proc_synthetic_fd(buf, off);
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

        /* fd_to_host_dup atomically duplicates under fd_lock so a concurrent
         * close+reopen on another vCPU cannot redirect the lseek to an
         * unrelated host fd that took the freed slot. The probe pollutes errno
         * with ESPIPE on non-seekable fds (sockets, pipes), so save and restore
         * around the call to keep the caller's view clean.
         */
        off_t pos = 0;
        int dup_fd = fd_to_host_dup(n);
        if (dup_fd >= 0) {
            int saved_errno = errno;
            off_t probe = lseek(dup_fd, 0, SEEK_CUR);
            if (probe >= 0)
                pos = probe;
            errno = saved_errno;
            close(dup_fd);
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
    if (!strcmp(path, "/proc/meminfo")) {
        int64_t physmem = 0;
        size_t sz = sizeof(physmem);
        int mib[2] = {CTL_HW, HW_MEMSIZE};
        sysctl(mib, 2, &physmem, &sz, NULL, 0);
        uint64_t total_kb = (uint64_t) physmem / 1024;

        /* Query host vm_statistics for accurate free/active/inactive. Falls
         * back to approximations if the mach call fails.
         */
        uint64_t free_kb, avail_kb, buffers_kb, cached_kb;
        vm_statistics64_data_t vm_stat = {0};
        mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
        uint64_t page_size = 4096;
        if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
                              (host_info64_t) &vm_stat,
                              &count) == KERN_SUCCESS) {
            host_page_size(mach_host_self(), (vm_size_t *) &page_size);
            free_kb = (uint64_t) vm_stat.free_count * page_size / 1024;
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
            free_kb = total_kb / 2;
            avail_kb = total_kb * 3 / 4;
            buffers_kb = total_kb / 20;
            cached_kb = total_kb / 4;
        }

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
            (unsigned long long) cached_kb,
            (unsigned long long) (total_kb - free_kb - cached_kb),
            (unsigned long long) (cached_kb / 2),
            (unsigned long long) (total_kb - free_kb - cached_kb - buffers_kb),
            (unsigned long long) (cached_kb / 2),
            (unsigned long long) (total_kb / 2));
    }

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

        /* Fields: pid(1) (comm)(2) state(3) ppid(4) pgrp(5) session(6)
         *   tty_nr(7) tpgid(8) flags(9) minflt(10) cminflt(11) majflt(12)
         *   cmajflt(13) utime(14) stime(15) cutime(16) cstime(17)
         *   priority(18) nice(19) num_threads(20) itrealvalue(21)
         *   starttime(22) vsize(23) rss(24) rsslim(25) ... (52 fields total)
         */
        return proc_emit_fmt(
            "%lld (%.15s) R %lld %lld %lld 0 -1 0 "        /* 1-9 */
            "0 0 0 0 %ld %ld 0 0 "                         /* 10-17 */
            "20 0 %d 0 0 %llu %llu "                       /* 18-24 */
            "18446744073709551615 0 0 0 0 0 0 "            /* 25-31 */
            "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", /* 32-52 */
            (long long) proc_get_pid(), proc_comm_name(),
            (long long) proc_get_ppid(),
            (long long) proc_get_pid(), /* pgrp = pid */
            (long long) proc_get_pid(), /* session = pid */
            utime_ticks, stime_ticks, thread_active_count(),
            (unsigned long long) vsize, (unsigned long long) rss_pages);
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

    return PROC_NOT_INTERCEPTED;
}

int proc_intercept_stat(const char *path, struct stat *st)
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
    /* /dev/shm/<name> files: check the host temp dir */
    if (!strncmp(path, "/dev/shm/", 9)) {
        char host_path[512];
        if (dev_shm_resolve_path(path + 9, host_path, sizeof(host_path)) < 0)
            return -1;
        return stat(host_path, st);
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
        const char *digits = path + 9;
        if (!*digits) {
            errno = ENOENT;
            return -1;
        }
        char *endp;
        unsigned long n = strtoul(digits, &endp, 10);
        if (endp == digits || *endp != '\0' || n > UINT32_MAX) {
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
        st->st_uid = host_st.st_uid;
        st->st_gid = host_st.st_gid;
        /* macOS dev_t = (major << 24) | minor; the fs-stat translation layer
         * (mac_to_linux_dev) re-encodes that into Linux's split major/minor
         * layout, so storing 136 in the macOS-major slot makes glibc's
         * major(rdev) yield UNIX98_PTY_SLAVE_MAJOR.
         */
        st->st_rdev = ((dev_t) 136u << 24) | (dev_t) (n & 0xFFFFFFu);
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
            return proc_intercept_stat(alias, st);
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

    return PROC_NOT_INTERCEPTED;
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

    /* /proc/self/exe -> path of current ELF binary. Strip the sysroot prefix so
     * a guest running under --sysroot=/opt/sr sees /bin/ls rather than
     * /opt/sr/bin/ls, matching the chroot-like abstraction the rest of the path
     * layer presents.
     */
    if (!strcmp(path, "/proc/self/exe")) {
        /* Under rosetta, readlink("/proc/self/exe") points at the rosetta
         * translator (the binfmt_misc interpreter). Matches the behavior Linux
         * exposes when binfmt_misc dispatch is active.
         */
        if (proc_rosetta_active()) {
            size_t len = strlen(ROSETTA_PATH);
            if (len > bufsiz)
                len = bufsiz;
            memcpy(buf, ROSETTA_PATH, len);
            return (int) len;
        }
        char exe_buf[LINUX_PATH_MAX];
        if (!proc_elf_path_snapshot(exe_buf, sizeof(exe_buf))) {
            errno = ENOENT;
            return -1;
        }
        const char *exe = exe_buf;
        char exe_real[LINUX_PATH_MAX];
        char sysroot_snap[LINUX_PATH_MAX];
        if (proc_sysroot_snapshot(sysroot_snap, sizeof(sysroot_snap))) {
            /* proc_set_sysroot stores a realpath()-canonicalized form, so
             * canonicalize exe before the prefix check or the strip fails when
             * /var -> /private/var (and similar macOS symlinks) make the two
             * strings diverge.
             */
            const char *exe_cmp = exe;
            if (realpath(exe, exe_real))
                exe_cmp = exe_real;
            size_t sr_len = strlen(sysroot_snap);
            if (sr_len > 0 && !strncmp(exe_cmp, sysroot_snap, sr_len) &&
                (exe_cmp[sr_len] == '/' || exe_cmp[sr_len] == '\0')) {
                exe = exe_cmp + sr_len;
                if (*exe == '\0')
                    exe = "/";
            }
        }
        size_t len = strlen(exe);
        if (len > bufsiz)
            len = bufsiz;
        memcpy(buf, exe, len);
        return (int) len;
    }

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

        char fdpath[MAXPATHLEN];
        if (fcntl(host_fd, F_GETPATH, fdpath) < 0) {
            errno = ENOENT;
            return -1;
        }
        size_t len = strlen(fdpath);
        if (len > bufsiz)
            len = bufsiz;
        memcpy(buf, fdpath, len);
        return (int) len;
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
    return proc_oom_copy_slice(buf, count, offset, text, (size_t) len,
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
    size_t src_len = (size_t) len;
    if ((uint64_t) offset >= src_len) {
        *read_out = 0;
        return 1;
    }

    size_t src_off = (size_t) offset;
    ssize_t total = 0;
    for (int i = 0; i < iovcnt && src_off < src_len; i++) {
        size_t n = iov[i].iov_len;
        if (n > src_len - src_off)
            n = src_len - src_off;
        if (n == 0)
            continue;
        memcpy(iov[i].iov_base, text + src_off, n);
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

    atomic_store(&oom_score_adj_value, score_adj);
    proc_oom_refresh_live_fds_locked();
    *written_out = (ssize_t) count;
    rc = 1;
unlock:
    pthread_mutex_unlock(&oom_write_lock);
    return rc;
}
