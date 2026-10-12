/*
 * System info and identity syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Uname, getrandom, getcwd, sched_getaffinity, getgroups, getrusage, sysinfo,
 * and prlimit64. All functions are called from syscall_dispatch() in
 * syscall/syscall.c.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/random.h>
#include <stdlib.h>
#include <mach/mach.h>

#include "debug/log.h"
#include "utils.h"

#include "proved/slice.h"

#include "core/shim-globals.h"
#include "runtime/thread.h"
#include "syscall/linux-wire.h"
#include "syscall/internal.h"
#include "syscall/proc.h"
#include "syscall/signal.h"
#include "syscall/sys.h"

/* System info syscall handlers. */

static pthread_once_t groups_once = PTHREAD_ONCE_INIT;
static uint32_t cached_linux_groups[64];
static int cached_ngroups = -1;
static const linux_utsname_t cached_uname = {
    .sysname = "Linux",
    .nodename = "elfuse",
    .release = GUEST_KERNEL_RELEASE,
    .version = GUEST_KERNEL_VERSION,
    .machine = "aarch64",
    .domainname = "(none)",
};
static const uint8_t cached_affinity_mask[256] = {1}, zero_block[256] = {0};

/* Physical memory to report when sysctl(HW_MEMSIZE) fails. Reporting zero is
 * not an option: a guest computing used = total - free - cached against a zero
 * total wraps, which is the failure sys_guest_ram_bytes() exists to prevent.
 * The figure is one captured from a 4 GiB VZ VM, so the fallback describes a
 * machine that plausibly exists.
 */
#define GUEST_RAM_FALLBACK_BYTES 4094595072ULL

/* sysinfo cache.
 *
 * Process-scoped by intent: the cache mirrors the host's view (totalram from
 * sysctl(HW_MEMSIZE), free pages from host_statistics64, getloadavg). Even if
 * multiple guest_t instances ever coexist in one process they share the same
 * host stats, so a single rwlock-protected cache refreshed at most once per
 * second is the right shape. Deliberately not moved into guest_t.
 */
static pthread_once_t sysinfo_once = PTHREAD_ONCE_INIT;
static pthread_rwlock_t sysinfo_lock = PTHREAD_RWLOCK_INITIALIZER;
static time_t cached_boottime_sec = 0;
static uint64_t cached_totalram = 0;
static uint64_t cached_page_size = 0;
static mach_port_t cached_host_port = MACH_PORT_NULL;
static time_t cached_sysinfo_sec = -1;
static linux_sysinfo_t cached_sysinfo;

/* The full-size assertion lives with write_rusage_to_guest() in proc.c; this
 * offset check guards the fast memcpy translation done there.
 */
_Static_assert(offsetof(struct rusage, ru_maxrss) ==
                   offsetof(linux_rusage_t, ru_maxrss),
               "ru_maxrss offset must stay aligned for fast translation");

static void groups_init_cached_linux_groups(void)
{
    gid_t groups[64];
    int ngroups = getgroups(64, groups);
    if (ngroups < 0)
        return;

    for (int i = 0; i < ngroups; i++)
        cached_linux_groups[i] = (uint32_t) groups[i];
    cached_ngroups = ngroups;
}

static void sysinfo_init_cached_host_state(void)
{
    struct timeval boottime;
    size_t bt_len = sizeof(boottime);
    int mib_bt[2] = {CTL_KERN, KERN_BOOTTIME};
    if (sysctl(mib_bt, 2, &boottime, &bt_len, NULL, 0) == 0)
        cached_boottime_sec = boottime.tv_sec;

    uint64_t memsize = 0;
    size_t ms_len = sizeof(memsize);
    int mib_mem[2] = {CTL_HW, HW_MEMSIZE};
    if (sysctl(mib_mem, 2, &memsize, &ms_len, NULL, 0) != 0 || memsize == 0)
        memsize = GUEST_RAM_FALLBACK_BYTES;
    cached_totalram = memsize;

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size > 0)
        cached_page_size = (uint64_t) page_size;

    cached_host_port = mach_host_self();
}

static void sysinfo_refresh_cached_locked(time_t now_sec)
{
    memset(&cached_sysinfo, 0, sizeof(cached_sysinfo));
    cached_sysinfo.totalram = cached_totalram;
    cached_sysinfo.mem_unit = 1;
    cached_sysinfo.procs = 1; /* Single-process model */

    if (cached_boottime_sec != 0)
        cached_sysinfo.uptime = now_sec - cached_boottime_sec;

    /* Free RAM from vm_statistics64, held below the total unconditionally so
     * that every reader of the pair -- here and /proc/meminfo -- can subtract
     * one from the other without checking.
     */
    vm_statistics64_data_t vmstat = {0};
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    if (cached_host_port != MACH_PORT_NULL &&
        host_statistics64(cached_host_port, HOST_VM_INFO64,
                          (host_info64_t) &vmstat, &count) == KERN_SUCCESS) {
        uint64_t free_bytes = (uint64_t) vmstat.free_count * cached_page_size;
        cached_sysinfo.freeram =
            free_bytes > cached_totalram ? cached_totalram : free_bytes;
    }

    /* Load averages (x 65536 for fixed-point). */
    double loadavg[3];
    if (getloadavg(loadavg, 3) == 3) {
        cached_sysinfo.loads[0] = (uint64_t) (loadavg[0] * 65536.0);
        cached_sysinfo.loads[1] = (uint64_t) (loadavg[1] * 65536.0);
        cached_sysinfo.loads[2] = (uint64_t) (loadavg[2] * 65536.0);
    }

    cached_sysinfo_sec = now_sec;
}

/* Copy out the cached sysinfo, refreshing it first if it has aged past a
 * second. Every guest-visible memory figure comes through here, so that a guest
 * reading two surfaces back to back reads one snapshot rather than two samples.
 */
static void sysinfo_snapshot(linux_sysinfo_t *out)
{
    pthread_once(&sysinfo_once, sysinfo_init_cached_host_state);
    time_t now_sec = time(NULL);

    if (thread_is_single_active()) {
        if (cached_sysinfo_sec != now_sec)
            sysinfo_refresh_cached_locked(now_sec);
        *out = cached_sysinfo;
        return;
    }

    pthread_rwlock_rdlock(&sysinfo_lock);
    if (cached_sysinfo_sec == now_sec) {
        *out = cached_sysinfo;
        pthread_rwlock_unlock(&sysinfo_lock);
        return;
    }
    pthread_rwlock_unlock(&sysinfo_lock);

    pthread_rwlock_wrlock(&sysinfo_lock);
    if (cached_sysinfo_sec != now_sec)
        sysinfo_refresh_cached_locked(now_sec);
    *out = cached_sysinfo;
    pthread_rwlock_unlock(&sysinfo_lock);
}

uint64_t sys_guest_ram_bytes(void)
{
    pthread_once(&sysinfo_once, sysinfo_init_cached_host_state);
    return cached_totalram;
}

uint64_t sys_guest_ram_free(void)
{
    linux_sysinfo_t si;
    sysinfo_snapshot(&si);
    return si.freeram; /* mem_unit is 1, so freeram is already bytes */
}

static int get_cached_linux_groups(void)
{
    if (thread_is_single_active()) {
        if (cached_ngroups >= 0)
            return cached_ngroups;
        groups_init_cached_linux_groups();
        return cached_ngroups;
    }

    pthread_once(&groups_once, groups_init_cached_linux_groups);
    return cached_ngroups;
}

int64_t sys_uname(guest_t *g, uint64_t buf_gva)
{
    if (guest_write_small(g, buf_gva, &cached_uname, sizeof(cached_uname)) < 0)
        return -LINUX_EFAULT;

    return 0;
}

/* Linux getrandom(2) flags. arc4random_buf is always non-blocking and always
 * seeded, so GRND_NONBLOCK / GRND_RANDOM / GRND_INSECURE all collapse to the
 * same behavior here. Unknown flag bits must still return EINVAL per kernel
 * behavior (kernel/random.c rejects flags & ~SUPPORTED_FLAGS) so callers do not
 * silently fossilize wrong assumptions about the elfuse implementation.
 */
#define LINUX_GRND_NONBLOCK 0x0001
#define LINUX_GRND_RANDOM 0x0002
#define LINUX_GRND_INSECURE 0x0004
#define LINUX_GRND_SUPPORTED_MASK \
    (LINUX_GRND_NONBLOCK | LINUX_GRND_RANDOM | LINUX_GRND_INSECURE)

int64_t sys_getrandom(guest_t *g,
                      uint64_t buf_gva,
                      uint64_t buflen,
                      unsigned int flags)
{
    if (flags & ~LINUX_GRND_SUPPORTED_MASK)
        return -LINUX_EINVAL;
    if ((flags & (LINUX_GRND_RANDOM | LINUX_GRND_INSECURE)) ==
        (LINUX_GRND_RANDOM | LINUX_GRND_INSECURE))
        return -LINUX_EINVAL;
    if (buflen == 0)
        return 0;
    if (buf_gva > UINT64_MAX - buflen)
        return -LINUX_EFAULT;

    /* arc4random_buf takes a libc lock, so it cannot be handed a guest pointer:
     * see the lock rule on HOST_SIGBUS_GUARD. Stage, then let guest_write do
     * the copy inside the pad.
     */
    uint8_t stage[512];
    uint64_t offset = 0, chunk;
    while (slice_clamp(buflen, offset, sizeof(stage), &chunk)) {
        arc4random_buf(stage, (size_t) chunk);
        if (guest_write(g, buf_gva + offset, stage, (size_t) chunk) < 0)
            return -LINUX_EFAULT;
        offset += chunk;
    }

    shim_globals_refill_urandom_ring(g);
    return (int64_t) buflen;
}

int64_t sys_getcwd(guest_t *g, uint64_t buf_gva, uint64_t size)
{
    proc_cwd_view_t view;
    if (proc_acquire_cwd_view(&view) < 0)
        return linux_errno();

    size_t write_len = view.len + 1;
    if (write_len > size) {
        proc_release_cwd_view(&view);
        return -LINUX_ERANGE;
    }

    int rc = guest_write_small(g, buf_gva, view.path, write_len);
    proc_release_cwd_view(&view);
    if (rc < 0)
        return -LINUX_EFAULT;

    return (int64_t) write_len;
}

int64_t sys_getcpu(guest_t *g,
                   uint64_t cpu_gva,
                   uint64_t node_gva,
                   uint64_t cache_gva)
{
    (void) cache_gva;

    /* elfuse models one online CPU and one NUMA node. glibc and tools such as
     * file(1) only need a successful query here; the kernel cache pointer is
     * obsolete and may be ignored.
     */
    uint32_t zero = 0;
    if (cpu_gva && guest_write_small(g, cpu_gva, &zero, sizeof(zero)) < 0)
        return -LINUX_EFAULT;
    if (node_gva && guest_write_small(g, node_gva, &zero, sizeof(zero)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

int64_t sys_sched_getaffinity(guest_t *g,
                              int pid,
                              uint64_t size,
                              uint64_t mask_gva)
{
    /* Return a 1-CPU affinity mask for simplicity. sched_setaffinity is not
     * implemented; all threads see CPU 0.
     */
    if (pid < 0)
        return -LINUX_EINVAL;
    if (!proc_pid_alive(pid))
        return -LINUX_ESRCH;
    if (size < 8)
        return -LINUX_EINVAL;

    if (size <= 256) {
        if (guest_write_small(g, mask_gva, cached_affinity_mask,
                              (size_t) size) < 0)
            return -LINUX_EFAULT;
        return 8; /* Returns size of written mask */
    }

    if (guest_write_small(g, mask_gva, cached_affinity_mask,
                          sizeof(cached_affinity_mask)) < 0)
        return -LINUX_EFAULT;

    /* Linux zeroes remaining bytes past the fixed mask. Use guest_write in
     * chunks for bounds safety.
     */
    if (size > sizeof(cached_affinity_mask)) {
        uint64_t off = sizeof(cached_affinity_mask);
        uint64_t rem = size - sizeof(cached_affinity_mask);
        while (rem > 0) {
            size_t chunk =
                (rem > sizeof(zero_block)) ? sizeof(zero_block) : (size_t) rem;
            if (guest_write(g, mask_gva + off, zero_block, chunk) < 0)
                return -LINUX_EFAULT;
            off += chunk;
            rem -= chunk;
        }
    }

    return 8; /* Returns size of written mask */
}

/* Scheduler policy stubs.
 *
 * elfuse models a single SCHED_OTHER thread group. Linux scheduler syscalls are
 * per-thread: the pid argument is actually a TID, and a worker calling
 * sched_getscheduler(gettid()) must reach its own thread entry, not just the
 * thread-group leader. Live TIDs are matched via proc_pid_alive(); pid 0 means
 * "the calling thread" and is always accepted.
 *
 * Any policy transition away from SCHED_OTHER is rejected unless the stub can
 * model it faithfully. Callers branch on the apparent policy, and silently
 * accepting BATCH/IDLE/RT classes while still reporting SCHED_OTHER would hide
 * guest bugs. SCHED_DEADLINE through legacy sched_setscheduler is -EINVAL
 * because the legacy syscall cannot supply the deadline attributes (real Linux
 * requires sched_setattr).
 *
 * Errno ordering follows Linux 6.x kernel/sched/syscalls.c:
 *   1. pid < 0 or NULL param pointer -> EINVAL
 *   2. copy_from_user (setters) -> EFAULT before pid lookup
 *   3. find_process_by_pid -> ESRCH
 *   4. policy/priority validation -> EINVAL or EPERM
 * Getters that only write back leave EFAULT for the final copy_to_user step,
 * matching the kernel's order.
 */
/* Validate a sched_param for the named policy.
 *
 * Returns 0 if accepted by the stub, or a negative Linux errno. EPERM is
 * reserved for "request would be valid on Linux but the stub refuses to honor
 * it" -- RT priority elevation and BATCH/IDLE class transitions away from
 * SCHED_OTHER. EINVAL covers every other out-of-spec input (bad priority range,
 * SCHED_DEADLINE through the legacy entry point, unknown policy bits).
 */
static int sched_check_policy_param(int policy, int prio)
{
    int base_policy = policy & ~LINUX_SCHED_RESET_ON_FORK;

    /* Reject any unknown high bit. The mask 0x7 covers every base policy id the
     * dispatcher recognizes (NORMAL=0, FIFO=1, RR=2, BATCH=3, IDLE=5,
     * DEADLINE=6); the unused 4 and 7 fall through to the default switch arm
     * below.
     */
    if (policy & ~(LINUX_SCHED_RESET_ON_FORK | 0x7))
        return -LINUX_EINVAL;

    switch (base_policy) {
    case LINUX_SCHED_NORMAL:
        return prio == 0 ? 0 : -LINUX_EINVAL;
    case LINUX_SCHED_BATCH:
    case LINUX_SCHED_IDLE:
        return prio == 0 ? -LINUX_EPERM : -LINUX_EINVAL;
    case LINUX_SCHED_FIFO:
    case LINUX_SCHED_RR:
        if (prio < 1 || prio > 99)
            return -LINUX_EINVAL;
        return -LINUX_EPERM;
    case LINUX_SCHED_DEADLINE:
        return -LINUX_EINVAL;
    default:
        return -LINUX_EINVAL;
    }
}

int64_t sys_sched_getscheduler(int pid)
{
    if (pid < 0)
        return -LINUX_EINVAL;
    if (!proc_pid_alive(pid))
        return -LINUX_ESRCH;
    return LINUX_SCHED_NORMAL;
}

int64_t sys_sched_getparam(guest_t *g, int pid, uint64_t param_gva)
{
    if (pid < 0 || param_gva == 0)
        return -LINUX_EINVAL;
    if (!proc_pid_alive(pid))
        return -LINUX_ESRCH;
    linux_sched_param_t param = {0};
    if (guest_write_small(g, param_gva, &param, sizeof(param)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

int64_t sys_sched_setscheduler(guest_t *g,
                               int pid,
                               int policy,
                               uint64_t param_gva)
{
    if (pid < 0 || param_gva == 0)
        return -LINUX_EINVAL;
    linux_sched_param_t param;
    if (guest_read_small(g, param_gva, &param, sizeof(param)) < 0)
        return -LINUX_EFAULT;
    if (!proc_pid_alive(pid))
        return -LINUX_ESRCH;
    return sched_check_policy_param(policy, param.sched_priority);
}

int64_t sys_sched_setparam(guest_t *g, int pid, uint64_t param_gva)
{
    if (pid < 0 || param_gva == 0)
        return -LINUX_EINVAL;
    linux_sched_param_t param;
    if (guest_read_small(g, param_gva, &param, sizeof(param)) < 0)
        return -LINUX_EFAULT;
    if (!proc_pid_alive(pid))
        return -LINUX_ESRCH;

    /* Current policy is SCHED_OTHER, so only priority 0 is valid. Any other
     * value mirrors the kernel's EINVAL for non-RT priority changes.
     */
    if (param.sched_priority != 0)
        return -LINUX_EINVAL;
    return 0;
}

int64_t sys_sched_get_priority_min(int policy)
{
    switch (policy) {
    case LINUX_SCHED_NORMAL:
    case LINUX_SCHED_BATCH:
    case LINUX_SCHED_IDLE:
    case LINUX_SCHED_DEADLINE:
        return 0;
    case LINUX_SCHED_FIFO:
    case LINUX_SCHED_RR:
        return 1;
    default:
        return -LINUX_EINVAL;
    }
}

int64_t sys_sched_get_priority_max(int policy)
{
    switch (policy) {
    case LINUX_SCHED_NORMAL:
    case LINUX_SCHED_BATCH:
    case LINUX_SCHED_IDLE:
    case LINUX_SCHED_DEADLINE:
        return 0;
    case LINUX_SCHED_FIFO:
    case LINUX_SCHED_RR:
        return 99;
    default:
        return -LINUX_EINVAL;
    }
}

int64_t sys_sched_rr_get_interval(guest_t *g, int pid, uint64_t ts_gva)
{
    if (pid < 0)
        return -LINUX_EINVAL;
    if (!proc_pid_alive(pid))
        return -LINUX_ESRCH;
    if (ts_gva == 0)
        return -LINUX_EFAULT;

    /* Linux's fair_sched_class.get_rr_interval returns a CFS-derived slice for
     * SCHED_OTHER tasks whenever the runqueue carries load. Reporting 100 ms
     * (the sched_rr_timeslice default and a typical CFS quantum) gives querying
     * tools a plausible non-zero value without pretending the guest is actually
     * under SCHED_RR.
     */
    linux_timespec_t ts = {.tv_sec = 0, .tv_nsec = 100 * 1000 * 1000L};
    if (guest_write_small(g, ts_gva, &ts, sizeof(ts)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

int64_t sys_getgroups(guest_t *g, int size, uint64_t list_gva)
{
    if (proc_fakeroot_enabled() && proc_get_euid() == 0) {
        if (size == 0)
            return 1;
        uint32_t zero_group = 0;
        if (guest_write_small(g, list_gva, &zero_group, sizeof(zero_group)) < 0)
            return -LINUX_EFAULT;
        return 1;
    }

    int ngroups = get_cached_linux_groups();
    if (ngroups < 0)
        return linux_errno();

    if (size == 0)
        return ngroups;
    if (size < ngroups)
        return -LINUX_EINVAL;

    size_t bytes = (size_t) ngroups * sizeof(cached_linux_groups[0]);
    if (guest_write_small(g, list_gva, cached_linux_groups, bytes) < 0)
        return -LINUX_EFAULT;

    return ngroups;
}

#define LINUX_NGROUPS_MAX 65536

int64_t sys_setgroups(guest_t *g, int size, uint64_t list_gva)
{
    if (proc_get_euid() != 0 && !proc_fakeroot_enabled())
        return -LINUX_EPERM;
    if (size < 0 || size > LINUX_NGROUPS_MAX)
        return -LINUX_EINVAL;
    if (size > 0) {
        size_t bytes = (size_t) size * sizeof(uint32_t);
        uint32_t *groups = malloc(bytes);
        if (!groups)
            return -LINUX_ENOMEM;
        int ret = guest_read(g, list_gva, groups, bytes);
        free(groups);
        if (ret < 0)
            return -LINUX_EFAULT;
    }
    return 0;
}

int64_t sys_getrusage(guest_t *g, int who, uint64_t usage_gva)
{
    /* Linux RUSAGE_SELF=0, RUSAGE_CHILDREN=-1, RUSAGE_THREAD=1. macOS has the
     * same values. Reject unknown values early.
     */
    if (who != 0 && who != -1 && who != 1)
        return -LINUX_EINVAL;

    struct rusage mac_usage;
    if (getrusage(who, &mac_usage) < 0)
        return linux_errno();

    if (write_rusage_to_guest(g, usage_gva, &mac_usage) < 0)
        return -LINUX_EFAULT;

    return 0;
}

int64_t sys_sysinfo(guest_t *g, uint64_t info_gva)
{
    linux_sysinfo_t si;
    sysinfo_snapshot(&si);
    if (guest_write_small(g, info_gva, &si, sizeof(si)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* Resource limits. */

/* Linux RLIMIT_* numbers to the macOS ones, for seeding the guest table from
 * the host. The numbering differs: Linux RLIMIT_NPROC=6 vs macOS
 * RLIMIT_NPROC=7.
 */
static int translate_rlimit_resource(int linux_res)
{
    switch (linux_res) {
    case LINUX_RLIMIT_CPU:
        return RLIMIT_CPU;
    case LINUX_RLIMIT_FSIZE:
        return RLIMIT_FSIZE;
    case LINUX_RLIMIT_DATA:
        return RLIMIT_DATA;
    case LINUX_RLIMIT_STACK:
        return RLIMIT_STACK;
    case LINUX_RLIMIT_CORE:
        return RLIMIT_CORE;
    case LINUX_RLIMIT_RSS:
        return RLIMIT_RSS;
    case LINUX_RLIMIT_NPROC:
        return RLIMIT_NPROC; /* Linux 6 -> macOS 7 */
    case LINUX_RLIMIT_NOFILE:
        return RLIMIT_NOFILE; /* Linux 7 -> macOS 8 */
    case LINUX_RLIMIT_MEMLOCK:
        return RLIMIT_MEMLOCK; /* Linux 8 -> macOS 6 */
    case LINUX_RLIMIT_AS:
        return RLIMIT_AS;
    default:
        return -1;
    }
}

/* MAXSSIZ on arm64 macOS: 64 MiB less one 16 KiB page. */
#define HOST_STACK_HARD_CAP (64ULL * 1024 * 1024 - 16 * 1024)

static linux_rlimit64_t translate_host_rlimit(int resource, struct rlimit rl)
{
    linux_rlimit64_t lim = {0};

    lim.rlim_cur =
        (rl.rlim_cur == RLIM_INFINITY) ? LINUX_RLIM_INFINITY : rl.rlim_cur;
    lim.rlim_max =
        (rl.rlim_max == RLIM_INFINITY) ? LINUX_RLIM_INFINITY : rl.rlim_max;

    /* macOS returns ~8MiB-16KiB for the default stack; round to Linux's
     * conventional 8MiB to keep guest userspace behavior stable.
     */
    if (resource == LINUX_RLIMIT_STACK && lim.rlim_cur > 0 &&
        lim.rlim_cur < 8388608) {
        lim.rlim_cur = 8388608;
        if (lim.rlim_max < lim.rlim_cur)
            lim.rlim_max = lim.rlim_cur;
    }

    /* macOS also caps the hard stack limit, at MAXSSIZ, where Linux starts a
     * process with it unlimited. The cap is about host thread stacks and bounds
     * nothing in the guest, so a host that sits at it reads as unlimited; one
     * whose user lowered it keeps the lower value.
     */
    if (resource == LINUX_RLIMIT_STACK && lim.rlim_max >= HOST_STACK_HARD_CAP)
        lim.rlim_max = LINUX_RLIM_INFINITY;

    return lim;
}

/* Guest rlimit table.
 *
 * prlimit64 reads and writes these slots and never calls host setrlimit, so a
 * guest limit cannot constrain elfuse itself, and RSS keeps a slot of its own
 * although macOS defines RLIMIT_RSS as RLIMIT_AS.
 *
 * A process publishes its table as a file under the per-user temp directory,
 * named by host pid and mapped shared, so prlimit64 on another fork-family
 * member maps that member's file and changes the limits it enforces.
 * rlimit_lock serializes the threads of one process, which share one open file
 * description and so do not exclude each other through flock; flock serializes
 * processes. A site that enforces a limit loads one soft value through
 * sys_rlimit_cur and takes neither.
 *
 * When the file cannot be created the table stays in rlimit_private, and other
 * processes get ESRCH for this pid.
 */
#define RLIMIT_TABLE_MAGIC 0x454C524CU /* "ELRL" */

/* How long prlimit64 waits for a live fork-family member to publish. */
#define RLIMIT_PUBLISH_WAIT_MS 1000

/* Bounds on one sleep of the RLIMIT_CPU sampling thread. */
#define RLIMIT_CPU_SLEEP_MAX_S 86400
#define RLIMIT_CPU_SLEEP_MIN_NS 10000000ULL

/* Order of rlimit_table_t.ids: the three uids, then the three gids. */
enum { RLIMIT_ID_UID, RLIMIT_ID_GID = 3, RLIMIT_ID_COUNT = 6 };

typedef struct {
    uint32_t magic;
    uint32_t count;
    struct {
        _Atomic uint64_t cur, max;
    } slot[LINUX_RLIMIT_COUNT];

    /* Real, effective and saved guest ids of the owner, which prlimit64 in
     * another process compares its own with.
     */
    _Atomic uint32_t ids[RLIMIT_ID_COUNT];
} rlimit_table_t;

static pthread_mutex_t rlimit_lock = PTHREAD_MUTEX_INITIALIZER;

/* What a slot reads before sys_rlimit_init or sys_rlimit_restore has run:
 * nothing is limited, and NOFILE is the table size because a fork child
 * installs its inherited descriptors before sys_rlimit_restore.
 */
#define RLIMIT_SLOT_UNLIMITED {LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY}
static rlimit_table_t rlimit_private = {
    .slot =
        {
            [LINUX_RLIMIT_CPU] = RLIMIT_SLOT_UNLIMITED,
            [LINUX_RLIMIT_FSIZE] = RLIMIT_SLOT_UNLIMITED,
            [LINUX_RLIMIT_DATA] = RLIMIT_SLOT_UNLIMITED,
            [LINUX_RLIMIT_STACK] = RLIMIT_SLOT_UNLIMITED,
            [LINUX_RLIMIT_CORE] = RLIMIT_SLOT_UNLIMITED,
            [LINUX_RLIMIT_RSS] = RLIMIT_SLOT_UNLIMITED,
            [LINUX_RLIMIT_NPROC] = RLIMIT_SLOT_UNLIMITED,
            [LINUX_RLIMIT_NOFILE] = {FD_TABLE_SIZE, FD_TABLE_SIZE},
            [LINUX_RLIMIT_MEMLOCK] = RLIMIT_SLOT_UNLIMITED,
            [LINUX_RLIMIT_AS] = RLIMIT_SLOT_UNLIMITED,
            [LINUX_RLIMIT_LOCKS] = RLIMIT_SLOT_UNLIMITED,
            [LINUX_RLIMIT_SIGPENDING] = RLIMIT_SLOT_UNLIMITED,
            [LINUX_RLIMIT_MSGQUEUE] = RLIMIT_SLOT_UNLIMITED,
            [LINUX_RLIMIT_NICE] = RLIMIT_SLOT_UNLIMITED,
            [LINUX_RLIMIT_RTPRIO] = RLIMIT_SLOT_UNLIMITED,
            [LINUX_RLIMIT_RTTIME] = RLIMIT_SLOT_UNLIMITED,
        },
};

/* Both are written once per process, by rlimit_publish under rlimit_lock. The
 * pointer is released there and acquired in rlimit_table_load because
 * sys_rlimit_cur reads it with no lock.
 */
static rlimit_table_t *_Atomic rlimit_table = &rlimit_private;
static int rlimit_fd = -1;

static rlimit_table_t *rlimit_table_load(void)
{
    return atomic_load_explicit(&rlimit_table, memory_order_acquire);
}

/* Relaxed on both sides: writers hold the table's locks, and the lock-free
 * reader in sys_rlimit_cur wants one word with nothing published behind it.
 */
static linux_rlimit64_t rlimit_slot_load(const rlimit_table_t *t, int resource)
{
    return (linux_rlimit64_t) {
        .rlim_cur =
            atomic_load_explicit(&t->slot[resource].cur, memory_order_relaxed),
        .rlim_max =
            atomic_load_explicit(&t->slot[resource].max, memory_order_relaxed),
    };
}

static void rlimit_slot_store(rlimit_table_t *t,
                              int resource,
                              linux_rlimit64_t lim)
{
    atomic_store_explicit(&t->slot[resource].cur, lim.rlim_cur,
                          memory_order_relaxed);
    atomic_store_explicit(&t->slot[resource].max, lim.rlim_max,
                          memory_order_relaxed);
}

/* Copy this process's guest ids into @t. The caller holds the table's locks. */
static void rlimit_ids_store(rlimit_table_t *t)
{
    const uint32_t ids[RLIMIT_ID_COUNT] = {
        proc_get_uid(), proc_get_euid(), proc_get_suid(),
        proc_get_gid(), proc_get_egid(), proc_get_sgid(),
    };
    for (int i = 0; i < RLIMIT_ID_COUNT; i++)
        atomic_store_explicit(&t->ids[i], ids[i], memory_order_relaxed);
}

static void rlimit_flock(int fd, int op)
{
    if (fd < 0)
        return;
    while (flock(fd, op) < 0 && errno == EINTR)
        ;
}

/* Same directory and the same reasoning as signal_transport_path in proc.c. */
static bool rlimit_file_path(char *out, size_t out_size, pid_t host_pid)
{
    char dir[PATH_MAX];
    size_t n = confstr(_CS_DARWIN_USER_TEMP_DIR, dir, sizeof(dir));
    if (n == 0 || n > sizeof(dir))
        return false;
    int len =
        snprintf(out, out_size, "%selfuse-rlim-%ld", dir, (long) host_pid);
    return len > 0 && (size_t) len < out_size;
}

/* Map the published table of @host_pid.
 *
 * Returns the mapping with its descriptor in @fd_out, or NULL. The size and the
 * header are checked first because the file sits where any process of this user
 * can write it, and a short file would fault on first touch.
 */
static rlimit_table_t *rlimit_file_map(pid_t host_pid, int *fd_out)
{
    char path[PATH_MAX];
    if (!rlimit_file_path(path, sizeof(path), host_pid))
        return NULL;
    int fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return NULL;

    struct stat st;
    rlimit_table_t *t = MAP_FAILED;
    if (fstat(fd, &st) == 0 && st.st_size == (off_t) sizeof(*t))
        t = mmap(NULL, sizeof(*t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (t != MAP_FAILED &&
        (t->magic != RLIMIT_TABLE_MAGIC || t->count != LINUX_RLIMIT_COUNT)) {
        munmap(t, sizeof(*t));
        t = MAP_FAILED;
    }
    if (t == MAP_FAILED) {
        close(fd);
        return NULL;
    }
    *fd_out = fd;
    return t;
}

static void rlimit_file_unlink(void)
{
    char path[PATH_MAX];
    if (rlimit_file_path(path, sizeof(path), getpid()))
        unlink(path);
}

/* Move the table from rlimit_private into a published file. The file is filled
 * under a temporary name and renamed, so a reader never maps a partial table,
 * and a file left by a dead process with this host pid is replaced rather than
 * truncated under a reader that still maps it. Caller holds rlimit_lock.
 */
static void rlimit_publish(void)
{
    char path[PATH_MAX], tmp[PATH_MAX];
    if (rlimit_fd >= 0 || !rlimit_file_path(path, sizeof(path), getpid()))
        return;
    int len = snprintf(tmp, sizeof(tmp), "%s.new", path);
    if (len < 0 || (size_t) len >= sizeof(tmp))
        return;

    unlink(tmp);
    int fd =
        open(tmp, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return;

    rlimit_table_t *t = MAP_FAILED;
    if (ftruncate(fd, sizeof(*t)) == 0)
        t = mmap(NULL, sizeof(*t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (t != MAP_FAILED) {
        t->magic = RLIMIT_TABLE_MAGIC;
        t->count = LINUX_RLIMIT_COUNT;
        for (int r = 0; r < LINUX_RLIMIT_COUNT; r++)
            rlimit_slot_store(t, r, rlimit_slot_load(&rlimit_private, r));
        rlimit_ids_store(t);
    }
    if (t == MAP_FAILED || rename(tmp, path) < 0) {
        if (t != MAP_FAILED)
            munmap(t, sizeof(*t));
        close(fd);
        unlink(tmp);
        return;
    }

    atomic_store_explicit(&rlimit_table, t, memory_order_release);
    rlimit_fd = fd;
    atexit(rlimit_file_unlink);
}

void sys_rlimit_ids_changed(void)
{
    pthread_mutex_lock(&rlimit_lock);
    rlimit_flock(rlimit_fd, LOCK_EX);
    rlimit_ids_store(rlimit_table_load());
    rlimit_flock(rlimit_fd, LOCK_UN);
    pthread_mutex_unlock(&rlimit_lock);
}

void sys_rlimit_forget(pid_t host_pid)
{
    char path[PATH_MAX];
    if (rlimit_file_path(path, sizeof(path), host_pid))
        unlink(path);
}

/* Test hook, off unless ELFUSE_HOST_RLIMIT_CHECK is set: record every host
 * limit of this process and fail its exit when one has moved. Only elfuse can
 * read its own limits, and a guest limit that reached host setrlimit shows
 * nowhere else. tests/test-rlimit-unchanged-host drives it.
 */
#define HOST_RLIMIT_CHECK_EXIT 86

static struct rlimit host_rlimit_start[RLIM_NLIMITS];

static void host_rlimit_check(void)
{
    for (int r = 0; r < RLIM_NLIMITS; r++) {
        struct rlimit now;
        if (getrlimit(r, &now) < 0 ||
            (now.rlim_cur == host_rlimit_start[r].rlim_cur &&
             now.rlim_max == host_rlimit_start[r].rlim_max))
            continue;
        fprintf(stderr,
                "elfuse: host rlimit %d moved during the guest run: "
                "%llu/%llu -> %llu/%llu\n",
                r, (unsigned long long) host_rlimit_start[r].rlim_cur,
                (unsigned long long) host_rlimit_start[r].rlim_max,
                (unsigned long long) now.rlim_cur,
                (unsigned long long) now.rlim_max);
        _exit(HOST_RLIMIT_CHECK_EXIT);
    }
}

static void host_rlimit_check_arm(void)
{
    if (!getenv("ELFUSE_HOST_RLIMIT_CHECK"))
        return;
    for (int r = 0; r < RLIM_NLIMITS; r++)
        getrlimit(r, &host_rlimit_start[r]);
    atexit(host_rlimit_check);
}

static bool rlimit_pair_valid(int resource, linux_rlimit64_t lim)
{
    if (lim.rlim_cur > lim.rlim_max)
        return false;
    return resource != LINUX_RLIMIT_NOFILE || lim.rlim_max <= FD_TABLE_SIZE;
}

/* What Linux gives the resources macOS has no counterpart for: INIT_RLIMITS
 * (include/asm-generic/resource.h) for all but SIGPENDING, which fork_init
 * (kernel/fork.c) sets to the same value as NPROC.
 */
static linux_rlimit64_t rlimit_linux_default(int resource,
                                             linux_rlimit64_t nproc)
{
    switch (resource) {
    case LINUX_RLIMIT_SIGPENDING:
        return nproc;
    case LINUX_RLIMIT_MSGQUEUE:
        return (linux_rlimit64_t) {819200, 819200};
    case LINUX_RLIMIT_NICE:
    case LINUX_RLIMIT_RTPRIO:
        return (linux_rlimit64_t) {0, 0};
    default:
        return (linux_rlimit64_t) {LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY};
    }
}

void sys_rlimit_init(void)
{
    linux_rlimit64_t nproc = {LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY};

    pthread_mutex_lock(&rlimit_lock);
    for (int r = 0; r < LINUX_RLIMIT_COUNT; r++) {
        linux_rlimit64_t lim;
        struct rlimit rl;
        int host_res = translate_rlimit_resource(r);

        /* The host NOFILE limit is elfuse's own capacity (main.c); the guest
         * gets the size of its fd table.
         */
        if (r == LINUX_RLIMIT_NOFILE)
            lim = (linux_rlimit64_t) {FD_TABLE_SIZE, FD_TABLE_SIZE};
        else if (host_res >= 0 && getrlimit(host_res, &rl) == 0)
            lim = translate_host_rlimit(r, rl);
        else
            lim = rlimit_linux_default(r, nproc);
        if (r == LINUX_RLIMIT_NPROC)
            nproc = lim;
        rlimit_slot_store(&rlimit_private, r, lim);
    }
    rlimit_publish();
    pthread_mutex_unlock(&rlimit_lock);
    host_rlimit_check_arm();
    sys_rlimit_cpu_check();
}

uint64_t sys_rlimit_cur(int resource)
{
    return atomic_load_explicit(&rlimit_table_load()->slot[resource].cur,
                                memory_order_relaxed);
}

uint64_t sys_rlimit_max(int resource)
{
    return atomic_load_explicit(&rlimit_table_load()->slot[resource].max,
                                memory_order_relaxed);
}

void sys_rlimit_send_xfsz(void)
{
    if (!current_thread ||
        !signal_queue_thread(thread_tid(current_thread), LINUX_SIGXFSZ))
        signal_queue(LINUX_SIGXFSZ);
}

void sys_rlimit_snapshot(linux_rlimit64_t out[LINUX_RLIMIT_COUNT])
{
    pthread_mutex_lock(&rlimit_lock);
    rlimit_flock(rlimit_fd, LOCK_SH);
    for (int r = 0; r < LINUX_RLIMIT_COUNT; r++)
        out[r] = rlimit_slot_load(rlimit_table_load(), r);
    rlimit_flock(rlimit_fd, LOCK_UN);
    pthread_mutex_unlock(&rlimit_lock);
}

bool sys_rlimit_table_valid(const linux_rlimit64_t in[LINUX_RLIMIT_COUNT])
{
    for (int r = 0; r < LINUX_RLIMIT_COUNT; r++)
        if (!rlimit_pair_valid(r, in[r]))
            return false;
    return true;
}

void sys_rlimit_restore(const linux_rlimit64_t in[LINUX_RLIMIT_COUNT])
{
    pthread_mutex_lock(&rlimit_lock);
    for (int r = 0; r < LINUX_RLIMIT_COUNT; r++)
        rlimit_slot_store(&rlimit_private, r, in[r]);
    rlimit_publish();
    pthread_mutex_unlock(&rlimit_lock);
    host_rlimit_check_arm();
    sys_rlimit_cpu_check();
}

/* RLIMIT_CPU, after check_process_timers (Linux
 * kernel/time/posix-cpu-timers.c): SIGKILL at the hard limit, SIGXCPU at the
 * soft limit, and the soft limit then moves up a second so the signal repeats
 * until the hard limit. Process CPU time is the host's for this process, which
 * charges a vCPU thread's guest time to it as user time.
 *
 * Returns how long the caller may sleep before the next expiry can be due, or 0
 * when there is nothing to wait for. The caller holds the table's locks.
 */
static uint64_t rlimit_cpu_expire(int *sig_out)
{
    rlimit_table_t *t = rlimit_table_load();
    linux_rlimit64_t lim = rlimit_slot_load(t, LINUX_RLIMIT_CPU);
    uint64_t used_ns = clock_gettime_nsec_np(CLOCK_PROCESS_CPUTIME_ID);
    uint64_t used_s = used_ns / NSEC_PER_SEC;

    *sig_out = 0;
    if (lim.rlim_cur == LINUX_RLIM_INFINITY)
        return 0;
    if (used_s >= lim.rlim_max) {
        *sig_out = LINUX_SIGKILL;
        return 0;
    }
    if (used_s >= lim.rlim_cur) {
        *sig_out = LINUX_SIGXCPU;
        lim.rlim_cur = used_s + 1;
        rlimit_slot_store(t, LINUX_RLIMIT_CPU, lim);
    }

    /* CPU time advances at most one second per second on each host CPU, so the
     * limit cannot be reached sooner than this, and the floor bounds how often
     * a process close to its limit is sampled.
     */
    uint64_t left_s = lim.rlim_cur - used_s;
    if (left_s > RLIMIT_CPU_SLEEP_MAX_S)
        left_s = RLIMIT_CPU_SLEEP_MAX_S;
    uint64_t left_ns = left_s * NSEC_PER_SEC - used_ns % NSEC_PER_SEC;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    uint64_t sleep_ns = left_ns / (uint64_t) (ncpu > 0 ? ncpu : 1);
    return sleep_ns < RLIMIT_CPU_SLEEP_MIN_NS ? RLIMIT_CPU_SLEEP_MIN_NS
                                              : sleep_ns;
}

/* Signaled when the CPU limit may have changed. Waits under rlimit_lock. */
static pthread_cond_t rlimit_cpu_cond = PTHREAD_COND_INITIALIZER;

/* Samples process CPU time against RLIMIT_CPU. A host CPU-time timer would need
 * no thread, but with setitimer(ITIMER_PROF) or host RLIMIT_CPU armed
 * hv_vcpu_run stops making guest progress, so the wait is in wall time.
 */
static void *rlimit_cpu_thread_main(void *arg)
{
    (void) arg;

    pthread_mutex_lock(&rlimit_lock);
    for (;;) {
        int sig;
        rlimit_flock(rlimit_fd, LOCK_EX);
        uint64_t sleep_ns = rlimit_cpu_expire(&sig);
        rlimit_flock(rlimit_fd, LOCK_UN);

        /* rlimit_lock is a leaf (internal.h); signal_queue takes sig_lock. */
        if (sig) {
            pthread_mutex_unlock(&rlimit_lock);
            signal_queue(sig);
            pthread_mutex_lock(&rlimit_lock);
        }

        if (sleep_ns == 0) {
            pthread_cond_wait(&rlimit_cpu_cond, &rlimit_lock);
        } else {
            struct timespec ts = {
                .tv_sec = (time_t) (sleep_ns / NSEC_PER_SEC),
                .tv_nsec = (long) (sleep_ns % NSEC_PER_SEC),
            };
            pthread_cond_timedwait_relative_np(&rlimit_cpu_cond, &rlimit_lock,
                                               &ts);
        }
    }
    return NULL;
}

void sys_rlimit_cpu_check(void)
{
    /* Relaxed: written under rlimit_lock, and a stale false only sends the
     * caller through the lock to read it again.
     */
    static _Atomic bool started;
    if (sys_rlimit_cur(LINUX_RLIMIT_CPU) == LINUX_RLIM_INFINITY &&
        !atomic_load_explicit(&started, memory_order_relaxed))
        return;

    pthread_mutex_lock(&rlimit_lock);
    if (atomic_load_explicit(&started, memory_order_relaxed)) {
        pthread_cond_signal(&rlimit_cpu_cond);
    } else {
        pthread_t thr;
        if (pthread_create(&thr, NULL, rlimit_cpu_thread_main, NULL) == 0) {
            pthread_detach(thr);
            atomic_store_explicit(&started, true, memory_order_relaxed);
        } else {
            log_error("elfuse: RLIMIT_CPU is not enforced: no sampling thread");
        }
    }
    pthread_mutex_unlock(&rlimit_lock);
}

/* Read the slot into @old_lim and, when @new_lim is set, replace it under the
 * rules of do_prlimit (Linux kernel/sys.c). The caller holds the table's locks.
 *
 * Returns 0 or a positive Linux errno.
 */
static int rlimit_exchange(rlimit_table_t *t,
                           int resource,
                           const linux_rlimit64_t *new_lim,
                           linux_rlimit64_t *old_lim)
{
    *old_lim = rlimit_slot_load(t, resource);
    if (!new_lim)
        return 0;
    if (new_lim->rlim_cur > new_lim->rlim_max)
        return LINUX_EINVAL;

    /* Raising a hard limit takes CAP_SYS_RESOURCE. NOFILE has no such path: its
     * hard limit is the size of the guest fd table.
     */
    if (new_lim->rlim_max > old_lim->rlim_max &&
        (resource == LINUX_RLIMIT_NOFILE || proc_get_euid() != 0))
        return LINUX_EPERM;

    rlimit_slot_store(t, resource, *new_lim);
    return 0;
}

/* check_prlimit_permission (Linux kernel/sys.c) against the owner of @t: the
 * caller's real uid and gid must equal all three of the owner's, or the caller
 * holds CAP_SYS_RESOURCE, which here is an effective uid of 0. The caller holds
 * the locks of @t.
 */
static bool rlimit_ids_permit(const rlimit_table_t *t)
{
    uint32_t uid = proc_get_uid(), gid = proc_get_gid();
    bool match = true;

    for (int i = 0; i < 3; i++) {
        match &= atomic_load_explicit(&t->ids[RLIMIT_ID_UID + i],
                                      memory_order_relaxed) == uid;
        match &= atomic_load_explicit(&t->ids[RLIMIT_ID_GID + i],
                                      memory_order_relaxed) == gid;
    }
    return match || proc_get_euid() == 0;
}

/* rlimit_exchange on the table of another fork-family member.
 *
 * A fork child publishes its table once the fork header has been restored,
 * which can be after the parent's clone returned, so a missing file is waited
 * for while the registry still lists the target.
 */
static int rlimit_exchange_remote(int64_t guest_pid,
                                  int resource,
                                  const linux_rlimit64_t *new_lim,
                                  linux_rlimit64_t *old_lim)
{
    rlimit_table_t *t = NULL;
    int fd = -1;
    pid_t host_pid;

    for (int tries = 0; !t; tries++) {
        host_pid = proc_resolve_guest_pid(guest_pid);
        if (host_pid < 0)
            return LINUX_ESRCH;
        t = rlimit_file_map(host_pid, &fd);

        /* A target that has exited or gone is ESRCH whether or not a file is
         * there: a host process that was killed leaves its file behind, and the
         * child table keeps naming its host pid after the child has been
         * collected, by which time the pid can belong to something else.
         */
        if (proc_child_exited(guest_pid) || kill(host_pid, 0) < 0) {
            if (t) {
                munmap(t, sizeof(*t));
                close(fd);
            }
            return LINUX_ESRCH;
        }

        /* Without a file of its own this process has no reason to expect one
         * from the target, and a thread being stopped does not wait for it.
         */
        if (!t && (rlimit_fd < 0 || tries == RLIMIT_PUBLISH_WAIT_MS ||
                   thread_stop_requested()))
            return LINUX_ESRCH;
        if (!t)
            usleep(1000);
    }

    rlimit_flock(fd, new_lim ? LOCK_EX : LOCK_SH);
    int err = rlimit_ids_permit(t)
                  ? rlimit_exchange(t, resource, new_lim, old_lim)
                  : LINUX_EPERM;
    rlimit_flock(fd, LOCK_UN);
    munmap(t, sizeof(*t));
    close(fd);

    /* The target arms its own CPU timer; SIGUSR2 has its preemption thread look
     * at the limit again.
     */
    if (!err && new_lim && resource == LINUX_RLIMIT_CPU)
        kill(host_pid, SIGUSR2);
    return err;
}

int64_t sys_prlimit64(guest_t *g,
                      int pid,
                      int resource,
                      uint64_t new_gva,
                      uint64_t old_gva)
{
    if (!RANGE_CHECK(resource, 0, LINUX_RLIMIT_COUNT))
        return -LINUX_EINVAL;

    linux_rlimit64_t new_lim, old_lim;
    if (new_gva != 0 &&
        guest_read_small(g, new_gva, &new_lim, sizeof(new_lim)) < 0)
        return -LINUX_EFAULT;
    const linux_rlimit64_t *set = new_gva ? &new_lim : NULL;

    /* find_task_by_vpid takes any thread id, and limits belong to the thread
     * group, so a tid of this process names this process. A tid of another
     * process does not resolve here, where Linux would reach that process: the
     * registry and the table files are keyed by process, so it is ESRCH.
     */
    int err;
    if (pid == 0 || pid == proc_get_pid() ||
        (pid > 0 && thread_tid_alive(pid))) {
        pthread_mutex_lock(&rlimit_lock);
        rlimit_flock(rlimit_fd, set ? LOCK_EX : LOCK_SH);
        err = rlimit_exchange(rlimit_table_load(), resource, set, &old_lim);
        rlimit_flock(rlimit_fd, LOCK_UN);
        pthread_mutex_unlock(&rlimit_lock);
        if (!err && set && resource == LINUX_RLIMIT_CPU)
            sys_rlimit_cpu_check();
    } else {
        err = rlimit_exchange_remote(pid, resource, set, &old_lim);
    }
    if (err)
        return -err;

    /* As in Linux, a new limit stays applied when the old one cannot be written
     * back.
     */
    if (old_gva != 0 &&
        guest_write_small(g, old_gva, &old_lim, sizeof(old_lim)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* Format /proc/self/limits content into buf.
 * Returns bytes written (excluding NUL) or -1 on error.
 */
int sys_format_limits(char *buf, size_t bufsz)
{
    /* Names, units and order of lnames in Linux fs/proc/base.c, indexed by
     * resource number.
     */
    static const struct {
        const char *name, *units;
    } rows[LINUX_RLIMIT_COUNT] = {
        [LINUX_RLIMIT_CPU] = {"Max cpu time", "seconds"},
        [LINUX_RLIMIT_FSIZE] = {"Max file size", "bytes"},
        [LINUX_RLIMIT_DATA] = {"Max data size", "bytes"},
        [LINUX_RLIMIT_STACK] = {"Max stack size", "bytes"},
        [LINUX_RLIMIT_CORE] = {"Max core file size", "bytes"},
        [LINUX_RLIMIT_RSS] = {"Max resident set", "bytes"},
        [LINUX_RLIMIT_NPROC] = {"Max processes", "processes"},
        [LINUX_RLIMIT_NOFILE] = {"Max open files", "files"},
        [LINUX_RLIMIT_MEMLOCK] = {"Max locked memory", "bytes"},
        [LINUX_RLIMIT_AS] = {"Max address space", "bytes"},
        [LINUX_RLIMIT_LOCKS] = {"Max file locks", "locks"},
        [LINUX_RLIMIT_SIGPENDING] = {"Max pending signals", "signals"},
        [LINUX_RLIMIT_MSGQUEUE] = {"Max msgqueue size", "bytes"},
        [LINUX_RLIMIT_NICE] = {"Max nice priority", ""},
        [LINUX_RLIMIT_RTPRIO] = {"Max realtime priority", ""},
        [LINUX_RLIMIT_RTTIME] = {"Max realtime timeout", "us"},
    };

    /* One snapshot, so every row is from the same instant of the table. */
    linux_rlimit64_t limits[LINUX_RLIMIT_COUNT];
    sys_rlimit_snapshot(limits);

    int off = snprintf(buf, bufsz, "%-26s%-21s%-21s%-10s\n", "Limit",
                       "Soft Limit", "Hard Limit", "Units");
    if (off < 0)
        return -1;
    if ((size_t) off >= bufsz)
        return (int) bufsz - 1;

    for (int i = 0; i < LINUX_RLIMIT_COUNT; i++) {
        char soft[24], hard[24];
        linux_rlimit64_t lim = limits[i];

        if (lim.rlim_cur == LINUX_RLIM_INFINITY)
            snprintf(soft, sizeof(soft), "unlimited");
        else
            snprintf(soft, sizeof(soft), "%llu",
                     (unsigned long long) lim.rlim_cur);
        if (lim.rlim_max == LINUX_RLIM_INFINITY)
            snprintf(hard, sizeof(hard), "unlimited");
        else
            snprintf(hard, sizeof(hard), "%llu",
                     (unsigned long long) lim.rlim_max);

        if ((size_t) off >= bufsz)
            break;
        int n = snprintf(buf + off, bufsz - off, "%-26s%-21s%-21s%-10s\n",
                         rows[i].name, soft, hard, rows[i].units);
        if (n < 0)
            return -1;
        off += n;
        if ((size_t) off >= bufsz) {
            off = (int) bufsz - 1;
            break;
        }
    }

    return off;
}
