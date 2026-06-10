/* System info and identity syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Uname, getrandom, getcwd, sched_getaffinity, getgroups, getrusage, sysinfo,
 * and prlimit64. All functions are called from syscall_dispatch() in
 * syscall/syscall.c.
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/random.h>
#include <stdlib.h>
#include <mach/mach.h>

#include "utils.h"

#include "core/shim-globals.h"
#include "syscall/abi.h"
#include "syscall/internal.h"
#include "syscall/proc.h"
#include "syscall/sys.h"

/* System info syscall handlers. */

static const linux_utsname_t cached_uname = {
    .sysname = "Linux",
    .nodename = "elfuse",
    /* Kernel version: match the lima aarch64 VM kernel to avoid version-gated
     * feature detection mismatches in userspace.
     */
    .release = "6.17.0-20-generic",
    .version = "#20-Ubuntu SMP PREEMPT_DYNAMIC",
    .machine = "aarch64",
    .domainname = "(none)",
};
static const uint8_t cached_affinity_mask[256] = {1}, zero_block[256] = {0};

/* sysinfo cache.
 *
 * Process-scoped by intent: the cache mirrors the host's view (totalram from
 * sysctl(HW_MEMSIZE), free pages from host_statistics64, getloadavg). Even if
 * multiple guest_t instances ever coexist in one process they share the same
 * host stats, so a single rwlock-protected cache refreshed at most once per
 * second is the right shape. Audited under TODO "Static state testability
 * audit" -- intentionally NOT moved into guest_t.
 */
static pthread_once_t sysinfo_once = PTHREAD_ONCE_INIT;
static pthread_rwlock_t sysinfo_lock = PTHREAD_RWLOCK_INITIALIZER;
static time_t cached_boottime_sec = 0;
static uint64_t cached_totalram = 0, cached_real_memsize = 0;
static uint64_t cached_page_size = 0;
static mach_port_t cached_host_port = MACH_PORT_NULL;
static time_t cached_sysinfo_sec = -1;
static linux_sysinfo_t cached_sysinfo;
static pthread_mutex_t rlimit_lock = PTHREAD_MUTEX_INITIALIZER;
static linux_rlimit64_t cached_linux_rlimits[10];
static uint8_t cached_linux_rlimit_valid[10];
#define RLIMIT_CACHE_SIZE ((int) (ARRAY_SIZE(cached_linux_rlimits)))

_Static_assert(sizeof(struct rusage) == sizeof(linux_rusage_t),
               "host and guest rusage layouts must match on LP64");
_Static_assert(offsetof(struct rusage, ru_maxrss) ==
                   offsetof(linux_rusage_t, ru_maxrss),
               "ru_maxrss offset must stay aligned for fast translation");

/* Defined below in the scheduler-policy section; forward-declared so
 * sys_sched_getaffinity (which sits above the policy stubs) can share the same
 * per-thread TID gate.
 */
static bool sched_pid_alive(int pid);

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
    if (sysctl(mib_mem, 2, &memsize, &ms_len, NULL, 0) == 0) {
        const uint64_t vm_ram_cap = 4094595072ULL; /* Match Lima VZ 4GiB VM */
        cached_real_memsize = memsize;
        cached_totalram = (memsize > vm_ram_cap) ? vm_ram_cap : memsize;
    }

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

    /* Free RAM from vm_statistics64. Scale proportionally if totalram is
     * capped.
     */
    vm_statistics64_data_t vmstat = {0};
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    if (cached_host_port != MACH_PORT_NULL &&
        host_statistics64(cached_host_port, HOST_VM_INFO64,
                          (host_info64_t) &vmstat, &count) == KERN_SUCCESS) {
        uint64_t real_free = (uint64_t) vmstat.free_count * cached_page_size;
        if (cached_real_memsize > 0 &&
            cached_real_memsize > cached_sysinfo.totalram) {
            uint64_t scaled_free = real_free;
            scaled_free *= cached_sysinfo.totalram;
            scaled_free /= cached_real_memsize;
            cached_sysinfo.freeram = scaled_free;
        } else {
            cached_sysinfo.freeram = real_free;
        }
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

    uint64_t offset = 0;
    while (offset < buflen) {
        uint64_t remaining = buflen - offset, avail = 0;
        void *dst =
            guest_ptr_bound(g, buf_gva + offset, &avail, MEM_PERM_W, remaining);
        if (!dst)
            return -LINUX_EFAULT;

        size_t chunk = (size_t) remaining;
        if (avail < chunk)
            chunk = (size_t) avail;

        arc4random_buf(dst, chunk);
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
    if (!sched_pid_alive(pid))
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
 * thread-group leader. Live TIDs are matched via thread_tid_alive(); pid 0
 * means "the calling thread" and is always accepted.
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
static bool sched_pid_alive(int pid)
{
    if (pid == 0)
        return true;
    if (pid == (int) proc_get_pid())
        return true;
    return thread_tid_alive((int64_t) pid) != 0;
}

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
    if (!sched_pid_alive(pid))
        return -LINUX_ESRCH;
    return LINUX_SCHED_NORMAL;
}

int64_t sys_sched_getparam(guest_t *g, int pid, uint64_t param_gva)
{
    if (pid < 0 || param_gva == 0)
        return -LINUX_EINVAL;
    if (!sched_pid_alive(pid))
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
    if (!sched_pid_alive(pid))
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
    if (!sched_pid_alive(pid))
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
    if (!sched_pid_alive(pid))
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
    const int ngroups = 1;

    if (size == 0)
        return ngroups;
    if (size < ngroups)
        return -LINUX_EINVAL;

    uint32_t group = proc_get_gid();
    if (guest_write_small(g, list_gva, &group, sizeof(group)) < 0)
        return -LINUX_EFAULT;

    return ngroups;
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

    linux_rusage_t lin_usage;
    memcpy(&lin_usage, &mac_usage, sizeof(lin_usage));
    lin_usage.ru_maxrss =
        mac_usage.ru_maxrss / 1024; /* macOS: bytes -> Linux: KB */

    if (guest_write_small(g, usage_gva, &lin_usage, sizeof(lin_usage)) < 0)
        return -LINUX_EFAULT;

    return 0;
}

int64_t sys_sysinfo(guest_t *g, uint64_t info_gva)
{
    pthread_once(&sysinfo_once, sysinfo_init_cached_host_state);
    time_t now_sec = time(NULL);

    if (thread_is_single_active()) {
        if (cached_sysinfo_sec != now_sec)
            sysinfo_refresh_cached_locked(now_sec);
        if (guest_write_small(g, info_gva, &cached_sysinfo,
                              sizeof(cached_sysinfo)) < 0)
            return -LINUX_EFAULT;
        return 0;
    } else {
        linux_sysinfo_t si;
        pthread_rwlock_rdlock(&sysinfo_lock);
        if (cached_sysinfo_sec == now_sec) {
            si = cached_sysinfo;
            pthread_rwlock_unlock(&sysinfo_lock);
        } else {
            pthread_rwlock_unlock(&sysinfo_lock);
            pthread_rwlock_wrlock(&sysinfo_lock);
            if (cached_sysinfo_sec != now_sec)
                sysinfo_refresh_cached_locked(now_sec);
            si = cached_sysinfo;
            pthread_rwlock_unlock(&sysinfo_lock);
        }
        if (guest_write_small(g, info_gva, &si, sizeof(si)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }
}

/* Resource limits. */

/* Translate Linux RLIMIT_* resource numbers to macOS equivalents. The numbering
 * differs: Linux RLIMIT_NPROC=6 vs macOS RLIMIT_NPROC=7.
 */
static int translate_rlimit_resource(int linux_res)
{
    switch (linux_res) {
    case 0:
        return RLIMIT_CPU;
    case 1:
        return RLIMIT_FSIZE;
    case 2:
        return RLIMIT_DATA;
    case 3:
        return RLIMIT_STACK;
    case 4:
        return RLIMIT_CORE;
    case 5:
        return RLIMIT_RSS;
    case 6:
        return RLIMIT_NPROC; /* Linux 6 -> macOS 7 */
    case 7:
        return RLIMIT_NOFILE; /* Linux 7 -> macOS 8 */
    case 8:
        return RLIMIT_MEMLOCK; /* Linux 8 -> macOS 6 */
    case 9:
        return RLIMIT_AS;
    default:
        return -1;
    }
}

static linux_rlimit64_t translate_host_rlimit(int resource, struct rlimit rl)
{
    linux_rlimit64_t lim = {0};

    lim.rlim_cur = (rl.rlim_cur == RLIM_INFINITY) ? UINT64_MAX : rl.rlim_cur;
    lim.rlim_max = (rl.rlim_max == RLIM_INFINITY) ? UINT64_MAX : rl.rlim_max;

    /* macOS returns ~8MiB-16KiB for the default stack; round to Linux's
     * conventional 8MiB to keep guest userspace behavior stable.
     */
    if (resource == 3 /* RLIMIT_STACK */ && lim.rlim_cur > 0 &&
        lim.rlim_cur < 8388608) {
        lim.rlim_cur = 8388608;
    }

    return lim;
}

static int rlimit_cache_get(int resource, linux_rlimit64_t *lim)
{
    if (!RANGE_CHECK(resource, 0, RLIMIT_CACHE_SIZE) || !lim)
        return 0;

    if (thread_is_single_active()) {
        if (cached_linux_rlimit_valid[resource]) {
            *lim = cached_linux_rlimits[resource];
            return 1;
        }
        return 0;
    }

    pthread_mutex_lock(&rlimit_lock);
    if (cached_linux_rlimit_valid[resource]) {
        *lim = cached_linux_rlimits[resource];
        pthread_mutex_unlock(&rlimit_lock);
        return 1;
    }
    pthread_mutex_unlock(&rlimit_lock);
    return 0;
}

static void rlimit_cache_set(int resource, linux_rlimit64_t lim)
{
    if (!RANGE_CHECK(resource, 0, RLIMIT_CACHE_SIZE))
        return;

    if (thread_is_single_active()) {
        cached_linux_rlimits[resource] = lim;
        cached_linux_rlimit_valid[resource] = 1;
        return;
    }

    pthread_mutex_lock(&rlimit_lock);
    cached_linux_rlimits[resource] = lim;
    cached_linux_rlimit_valid[resource] = 1;
    pthread_mutex_unlock(&rlimit_lock);
}

int64_t sys_prlimit64(guest_t *g,
                      int pid,
                      int resource,
                      uint64_t new_gva,
                      uint64_t old_gva)
{
    (void) pid; /* Ignore PID; single-process model */

    int mac_res = translate_rlimit_resource(resource);
    if (mac_res < 0)
        return -LINUX_EINVAL;

    /* Get old limits BEFORE setting new ones (Linux prlimit64 atomically
     * returns old values and sets new ones; approximate by get-then-set).
     */
    linux_rlimit64_t old_lim = {0};
    if (old_gva != 0) {
        if (!rlimit_cache_get(resource, &old_lim)) {
            struct rlimit rl;
            if (getrlimit(mac_res, &rl) < 0)
                return linux_errno();

            old_lim = translate_host_rlimit(resource, rl);
            rlimit_cache_set(resource, old_lim);
        }
    }

    /* Set new limits if requested */
    if (new_gva != 0) {
        linux_rlimit64_t new_lim;
        if (guest_read_small(g, new_gva, &new_lim, sizeof(new_lim)) < 0)
            return -LINUX_EFAULT;

        /* Translate Linux RLIM_INFINITY (UINT64_MAX) back to macOS
         * RLIM_INFINITY (0x7FFFFFFFFFFFFFFF) for setrlimit.
         */
        struct rlimit rl;
        rl.rlim_cur =
            (new_lim.rlim_cur == UINT64_MAX) ? RLIM_INFINITY : new_lim.rlim_cur;
        rl.rlim_max =
            (new_lim.rlim_max == UINT64_MAX) ? RLIM_INFINITY : new_lim.rlim_max;
        if (setrlimit(mac_res, &rl) < 0)
            return linux_errno();

        rlimit_cache_set(resource, new_lim);

        /* Track RLIMIT_NOFILE in the guest FD table so fd_alloc enforces the
         * limit and returns -EMFILE.
         */
        if (resource == 7 /* RLIMIT_NOFILE */) {
            int cur = (new_lim.rlim_cur == UINT64_MAX) ? FD_TABLE_SIZE
                                                       : (int) new_lim.rlim_cur;
            fd_set_rlimit_nofile(cur);
        }
    }

    /* Write old limits to guest after set (so guest sees pre-set values) */
    if (old_gva != 0) {
        if (guest_write_small(g, old_gva, &old_lim, sizeof(old_lim)) < 0)
            return -LINUX_EFAULT;
    }

    return 0;
}

/* Format /proc/self/limits content into buf.
 * Returns bytes written (excluding NUL) or -1 on error.
 */
int sys_format_limits(char *buf, size_t bufsz)
{
    /* Linux resource names, units, and indices (matching kernel order). */
    static const struct {
        const char *name, *units;
        int linux_res; /* -1 = not tracked, emit unlimited */
    } rows[] = {
        {"Max cpu time", "seconds", 0},
        {"Max file size", "bytes", 1},
        {"Max data size", "bytes", 2},
        {"Max stack size", "bytes", 3},
        {"Max core file size", "bytes", 4},
        {"Max resident set", "bytes", 5},
        {"Max processes", "processes", 6},
        {"Max open files", "files", 7},
        {"Max locked memory", "bytes", 8},
        {"Max address space", "bytes", 9},
        {"Max file locks", "locks", -1},
        {"Max pending signals", "signals", -1},
        {"Max msgqueue size", "bytes", -1},
        {"Max nice priority", "", -1},
        {"Max realtime priority", "", -1},
        {"Max realtime timeout", "us", -1},
    };

    int off = snprintf(buf, bufsz, "%-26s%-21s%-21s%-10s\n", "Limit",
                       "Soft Limit", "Hard Limit", "Units");
    if (off < 0)
        return -1;
    if ((size_t) off >= bufsz)
        return (int) bufsz - 1;

    for (int i = 0; i < (int) (ARRAY_SIZE(rows)); i++) {
        char soft[24], hard[24];
        int res = rows[i].linux_res;

        if (RANGE_CHECK(res, 0, RLIMIT_CACHE_SIZE)) {
            linux_rlimit64_t lim;
            if (!rlimit_cache_get(res, &lim)) {
                /* RLIMIT_NOFILE (Linux 7): use the guest FD table limit rather
                 * than host getrlimit, which may return RLIM_INFINITY on macOS.
                 */
                if (res == 7) {
                    int cur = fd_get_rlimit_nofile();
                    lim.rlim_cur = (uint64_t) cur;
                    lim.rlim_max = (uint64_t) FD_TABLE_SIZE;
                } else {
                    int mac_res = translate_rlimit_resource(res);
                    if (mac_res >= 0) {
                        struct rlimit rl;
                        if (getrlimit(mac_res, &rl) == 0) {
                            lim = translate_host_rlimit(res, rl);
                        } else {
                            lim.rlim_cur = UINT64_MAX;
                            lim.rlim_max = UINT64_MAX;
                        }
                    } else {
                        lim.rlim_cur = UINT64_MAX;
                        lim.rlim_max = UINT64_MAX;
                    }
                }
            }
            if (lim.rlim_cur == UINT64_MAX)
                snprintf(soft, sizeof(soft), "unlimited");
            else
                snprintf(soft, sizeof(soft), "%llu",
                         (unsigned long long) lim.rlim_cur);
            if (lim.rlim_max == UINT64_MAX)
                snprintf(hard, sizeof(hard), "unlimited");
            else
                snprintf(hard, sizeof(hard), "%llu",
                         (unsigned long long) lim.rlim_max);
        } else {
            snprintf(soft, sizeof(soft), "unlimited");
            snprintf(hard, sizeof(hard), "unlimited");
        }

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
