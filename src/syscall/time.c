/*
 * Time and timer syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Clock, nanosleep, gettimeofday, and interval timer operations. All functions
 * are called from syscall_dispatch() in syscall/syscall.c.
 */

#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/time.h>

#include "utils.h"

#include "core/vdso.h"
#include "runtime/thread.h" /* current_thread, guest_tid */

#include "proved/timespec.h"

#include "syscall/linux-wire.h"
#include "syscall/internal.h"
#include "syscall/proc.h" /* proc_exit_group_requested, proc_get_pid */
#include "syscall/signal.h"
#include "syscall/time.h"
#include "syscall/wakeup-pipe.h"

/* Linux TIMER_ABSTIME (not defined on all macOS SDK versions) */
#ifndef TIMER_ABSTIME
#define TIMER_ABSTIME 1
#endif

/* Clock ID translation. */

/* Linux dynamic CPU clock ID encoding (kernel/time/posix-cpu-timers.c):
 *
 *   clockid = ~pid << 3 | type [| CPUCLOCK_PERTHREAD_MASK]
 *
 * Where type is: CPUCLOCK_PROF=0, CPUCLOCK_VIRT=1, CPUCLOCK_SCHED=2
 * CPUCLOCK_PERTHREAD_MASK = 4 (bit 2): set for per-thread, clear for
 * per-process pid = 0 means "self" (current process/thread).
 *
 * Examples: -2 = per-thread SCHED (self), -6 = per-process SCHED (self)
 * Threaded language runtimes use these (via pthread_getcpuclockid()) to measure
 * per-thread CPU time without sampling the whole process.
 */
#define LINUX_CPUCLOCK_PERTHREAD_MASK 4

/* Linux encodes the dynamic-pid clock as ((~pid) << 3) | type. Decoding is
 * ~clockid >> 3, but >> on a signed negative value is implementation-defined.
 * The complement of a negative value (high bit set) is non-negative, so apply ~
 * via unsigned arithmetic and only then cast to int for a well-defined right
 * shift.
 */
#define LINUX_CPUCLOCK_PID(clk) ((int) (~(unsigned int) (clk)) >> 3)

#define SLEEP_CHUNK_NS 100000000LL /* 100ms */

_Static_assert(sizeof(struct timespec) == sizeof(linux_timespec_t),
               "host and guest timespec must match on LP64");
_Static_assert(sizeof(struct timeval) == sizeof(linux_timeval_t),
               "host and guest timeval must match on LP64");

_Static_assert(NSEC_PER_SEC == TIMESPEC_NSEC_PER_SEC,
               "the proved conversions must use this tree's nanosecond scale");

bool linux_timespec_valid(const linux_timespec_t *ts)
{
    return timespec_valid(ts->tv_sec, ts->tv_nsec) != 0;
}

int64_t linux_timespec_to_ns_sat(const linux_timespec_t *ts)
{
    return timespec_to_ns_sat(ts->tv_sec, ts->tv_nsec);
}

static int64_t host_timespec_to_ns_sat(const struct timespec *ts)
{
    linux_timespec_t lts = {
        .tv_sec = ts->tv_sec,
        .tv_nsec = ts->tv_nsec,
    };
    return linux_timespec_to_ns_sat(&lts);
}

static struct timespec ns_to_host_timespec(int64_t ns)
{
    if (ns < 0)
        ns = 0;
    return (struct timespec) {
        .tv_sec = ns / NSEC_PER_SEC,
        .tv_nsec = ns % NSEC_PER_SEC,
    };
}

/* Linux aarch64 sigevent. Thread notification fields are unsupported. */
typedef struct {
    uint64_t value;
    int32_t signum, notify;
    int32_t reserved[12];
} linux_sigevent_t;

_Static_assert(sizeof(linux_sigevent_t) == 64,
               "Linux sigevent must be 64 bytes");

int64_t sys_timer_create(guest_t *g,
                         int clockid,
                         uint64_t event_gva,
                         uint64_t id_gva)
{
    linux_sigevent_t event = {
        .signum = LINUX_SIGALRM,
        .notify = LINUX_SIGEV_SIGNAL,
    };
    if (event_gva && guest_read(g, event_gva, &event, sizeof(event)) < 0)
        return -LINUX_EFAULT;
    int32_t id = signal_posix_timer_create(clockid, event.notify, event.signum,
                                           event.value, event_gva == 0);
    if (id < 0)
        return id;
    if (guest_write_small(g, id_gva, &id, sizeof(id)) < 0) {
        signal_posix_timer_delete(id);
        return -LINUX_EFAULT;
    }
    return 0;
}

int64_t sys_timer_gettime(guest_t *g, int id, uint64_t value_gva)
{
    linux_itimerspec_t value;
    int ret = signal_posix_timer_get(id, &value);
    if (ret < 0)
        return ret;
    if (guest_write(g, value_gva, &value, sizeof(value)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

int64_t sys_timer_settime(guest_t *g,
                          int id,
                          int flags,
                          uint64_t value_gva,
                          uint64_t old_gva)
{
    linux_itimerspec_t value, old;
    if (guest_read(g, value_gva, &value, sizeof(value)) < 0)
        return -LINUX_EFAULT;
    if ((flags & ~LINUX_TIMER_ABSTIME) ||
        !timespec_valid(value.it_value_sec, value.it_value_nsec) ||
        !timespec_valid(value.it_interval_sec, value.it_interval_nsec))
        return -LINUX_EINVAL;
    int ret = signal_posix_timer_set(id, flags, &value, &old);
    if (ret < 0)
        return ret;
    if (old_gva && guest_write(g, old_gva, &old, sizeof(old)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

static int write_remaining_sleep(guest_t *g,
                                 uint64_t rem_gva,
                                 int64_t remaining_ns)
{
    if (!rem_gva)
        return 0;

    if (remaining_ns < 0)
        remaining_ns = 0;

    struct timespec rem = ns_to_host_timespec(remaining_ns);
    return guest_write_small(g, rem_gva, &rem, sizeof(rem));
}

static int64_t interruptible_sleep_ns(guest_t *g,
                                      int64_t remaining_ns,
                                      uint64_t rem_gva,
                                      bool write_rem)
{
    int64_t requested_ns = remaining_ns;

    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) < 0)
        return linux_errno();

    int64_t elapsed_ns = 0;
    int64_t stop_due_ns = 0;

    while (remaining_ns > 0) {
        /* Read the wake counter before testing the predicate, not after. A wake
         * that lands in between then moves the counter and wakeup_wait_ns
         * returns without parking, instead of broadcasting to a thread that has
         * not arrived yet and being lost.
         */
        uint64_t counter = wakeup_counter();

        /* A signal, exit_group and an execve teardown end the sleep on the wake
         * that reports them. An execve handed to this leader is tested once per
         * SLEEP_CHUNK_NS instead: a handoff rings thousands of times a second,
         * and the guest reissues the rest of its interval after every EINTR.
         * test-exec-handoff measured its 400 ms sleep under handoff pressure
         * taking 3150 ms across 29390 returns when every ring was answered,
         * against 432 ms across 3 on this cadence.
         *
         * Teardown is tested before a signal is claimed, because a thread an
         * execve reaps would take a claimed process-directed signal with it.
         */
        bool stop_due = elapsed_ns >= stop_due_ns;
        if (stop_due)
            stop_due_ns = elapsed_ns + SLEEP_CHUNK_NS;

        bool stop = thread_stop_requested() &&
                    (stop_due || !thread_stop_is_leader_work_only());
        if (stop || signal_claim_interruption()) {
            /* Only once part of a relative interval is spent, because the
             * restart re-runs the original request rather than the remainder.
             * This check also runs before the first chunk, where nothing is
             * spent and a restart costs the guest nothing, so forbidding there
             * would manufacture the EINTR no signal explains. An absolute
             * deadline (write_rem false, TIMER_ABSTIME) re-derives the same
             * instant and stays restartable throughout.
             */
            if (write_rem && remaining_ns != requested_ns)
                syscall_restart_forbid();
            if (write_rem &&
                write_remaining_sleep(g, rem_gva, remaining_ns) < 0)
                return -LINUX_EFAULT;
            return -LINUX_EINTR;
        }

        /* Park until whichever comes first, the end of the interval or the next
         * stop test. A wake cuts the park short, so this bounds the stop
         * cadence rather than what the sleep waits on.
         */
        int64_t chunk_ns = stop_due_ns - elapsed_ns;
        if (remaining_ns < chunk_ns)
            chunk_ns = remaining_ns;
        wakeup_wait_ns(chunk_ns, counter);

        /* Charge the time that actually passed. The wake is process-wide, so
         * the park also returns early on another thread's, and a condition
         * variable may return spuriously. Neither the chunk nor the request is
         * a safe measure of what was spent.
         */
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
            return linux_errno();
        elapsed_ns =
            host_timespec_to_ns_sat(&now) - host_timespec_to_ns_sat(&start);
        remaining_ns = requested_ns - elapsed_ns;
    }

    return 0;
}

/* Translate Linux clock IDs to macOS. Linux: REALTIME=0, MONOTONIC=1,
 * PROCESS_CPUTIME=2, THREAD_CPUTIME=3, MONOTONIC_RAW=4 macOS: REALTIME=0,
 * MONOTONIC_RAW=4, MONOTONIC=6, PROCESS_CPUTIME=12, THREAD_CPUTIME=16
 *
 * Negative clock IDs encode Linux dynamic per-process/per-thread CPU clocks.
 * time emulation translates pid=0 (self) clocks to the macOS equivalents; for
 * other pids time emulation returns -1 (no macOS equivalent).
 */
static int translate_clockid(int linux_clockid)
{
    switch (linux_clockid) {
    case 0:
        return CLOCK_REALTIME;
    case 1:
        return CLOCK_MONOTONIC;
    case 2:
        return CLOCK_PROCESS_CPUTIME_ID;
    case 3:
        return CLOCK_THREAD_CPUTIME_ID;
    case 4:
        return CLOCK_MONOTONIC_RAW;
    case 5:
        return CLOCK_REALTIME; /* CLOCK_REALTIME_COARSE */
    case 6:
        return CLOCK_MONOTONIC; /* CLOCK_MONOTONIC_COARSE */
    case 7:
        /* CLOCK_BOOTTIME includes suspend time on Linux; macOS exposes no
         * suspend-aware equivalent, so use monotonic time.
         */
        return CLOCK_MONOTONIC;
    default:
        /* Handle Linux dynamic CPU clock IDs (negative values). Decode: encoded
         * id = ~(clockid >> 3), perthread = clockid & 4, type bits = clockid &
         * 3 (PROF=0, VIRT=1, SCHED=2). Linux's convention:
         *   encoded id == 0    -> "self" (process or thread variant)
         *   encoded id == pid  -> that process
         *   per-thread variant: encoded id == 0 means current thread,
         *                       or the target TID for pthread_getcpuclockid.
         *
         * The macOS host only exposes CLOCK_THREAD_CPUTIME_ID for the calling
         * thread, so cross-thread or cross-process queries are unsupportable.
         * Accept both process and per-thread clocks when they refer to self
         * (encoded 0 or matching self pid/tid). Reject foreign ids and reserved
         * type bits with -EINVAL.
         */
        if (linux_clockid < 0) {
            int type_bits = linux_clockid & 3;
            if (type_bits == 3)
                return -1; /* Reserved type bits in dynamic clock id */
            int encoded_id = LINUX_CPUCLOCK_PID(linux_clockid);
            bool is_perthread = linux_clockid & LINUX_CPUCLOCK_PERTHREAD_MASK;
            int self_pid = (int) proc_get_pid();
            int self_tid =
                current_thread ? (int) thread_tid(current_thread) : self_pid;
            int self_match = is_perthread ? self_tid : self_pid;
            if (encoded_id != 0 && encoded_id != self_match)
                return -1; /* Foreign process/thread clocks unsupported */
            return is_perthread ? CLOCK_THREAD_CPUTIME_ID
                                : CLOCK_PROCESS_CPUTIME_ID;
        }
        return -1;
    }
}

/* Linux itimerval type. */

/* Linux struct itimerval (same layout as macOS on LP64) */
typedef struct {
    linux_timeval_t it_interval, it_value;
} linux_itimerval_t;

/* Time/timer syscall handlers. */

#define LINUX_COARSE_CLOCK_RES_NS 1000000

static bool linux_clock_getres_fixed(int clockid, linux_timespec_t *ts)
{
    switch (clockid) {
    case 0: /* CLOCK_REALTIME */
    case 1: /* CLOCK_MONOTONIC */
    case 4: /* CLOCK_MONOTONIC_RAW */
    case 7: /* CLOCK_BOOTTIME */
        *ts = (linux_timespec_t) {.tv_sec = 0, .tv_nsec = 1};
        return true;
    case 5: /* CLOCK_REALTIME_COARSE */
    case 6: /* CLOCK_MONOTONIC_COARSE */
        *ts = (linux_timespec_t) {.tv_sec = 0,
                                  .tv_nsec = LINUX_COARSE_CLOCK_RES_NS};
        return true;
    default:
        return false;
    }
}

int64_t sys_clock_getres(guest_t *g, int clockid, uint64_t tp_gva)
{
    int mac_clockid = translate_clockid(clockid);
    if (mac_clockid < 0)
        return -LINUX_EINVAL;

    /* Linux permits NULL here as a clock-id validation query. */
    if (!tp_gva)
        return 0;

    linux_timespec_t ts;
    if (!linux_clock_getres_fixed(clockid, &ts)) {
        struct timespec host_ts;
        if (clock_getres(mac_clockid, &host_ts) < 0)
            return linux_errno();
        ts = (linux_timespec_t) {
            .tv_sec = host_ts.tv_sec,
            .tv_nsec = host_ts.tv_nsec,
        };
    }

    if (guest_write_small(g, tp_gva, &ts, sizeof(ts)) < 0)
        return -LINUX_EFAULT;

    return 0;
}

int64_t sys_clock_gettime(guest_t *g, int clockid, uint64_t tp_gva)
{
    int mac_clockid = translate_clockid(clockid);
    if (mac_clockid < 0)
        return -LINUX_EINVAL;

    /* When the trap came from the __kernel_clock_gettime vDSO svc_fallback, the
     * trampoline parked the guest's CNTVCT_EL0 read in X9 before SVC, and
     * ELR_EL1 holds SVC_PC + 4. Use X9 to seed (or refresh) the vvar anchor so
     * subsequent calls hit the fast path. Reject any other trap: X9 would then
     * be arbitrary guest state and seeding from it would poison the anchor.
     *
     * Order matters: read X9 first, then sample host wall clocks back-to-back,
     * then write the guest result and seed. Sampling host clocks before
     * checking X9 would bake a permanent positive bias into the anchor from the
     * HVF round-trip in the seeding gate.
     */
    bool from_trampoline = (clockid == 0 /* CLOCK_REALTIME */ ||
                            clockid == 1 /* CLOCK_MONOTONIC */) &&
                           current_thread;

    uint64_t guest_cntvct = 0;
    if (from_trampoline) {
        uint64_t elr = 0;
        if (hv_vcpu_get_sys_reg(current_thread->vcpu, HV_SYS_REG_ELR_EL1,
                                &elr) != HV_SUCCESS ||
            elr != vdso_clock_gettime_svc_pc() + 4 ||
            hv_vcpu_get_reg(current_thread->vcpu, HV_REG_X9, &guest_cntvct) !=
                HV_SUCCESS ||
            guest_cntvct == 0)
            from_trampoline = false;
    }

    struct timespec ts;
    if (clock_gettime(mac_clockid, &ts) < 0)
        return linux_errno();

    /* Sample the OTHER clockid back-to-back so both anchor pairs reflect
     * roughly the same host moment. If the second clock_gettime fails
     * (defensive; unreachable on macOS), skip seeding rather than fail the
     * user's request.
     */
    struct timespec ts_other;
    bool can_seed = false;
    if (from_trampoline) {
        int other_mac = (clockid == 1) ? CLOCK_REALTIME : CLOCK_MONOTONIC;
        if (clock_gettime(other_mac, &ts_other) == 0)
            can_seed = true;
    }

    if (guest_write_small(g, tp_gva, &ts, sizeof(ts)) < 0)
        return -LINUX_EFAULT;

    if (can_seed) {
        const struct timespec *ts_mono = (clockid == 1) ? &ts : &ts_other;
        const struct timespec *ts_real = (clockid == 0) ? &ts : &ts_other;

        /* Publish when the vvar is unseeded, has aged out, or has drifted
         * relative to the freshly-sampled REALTIME (catches macOS NTP steps).
         */
        if (!vdso_anchor_is_seeded(g) ||
            vdso_anchor_age_exceeded(g, guest_cntvct) ||
            vdso_realtime_drift_exceeded(g, guest_cntvct, ts_real->tv_sec,
                                         ts_real->tv_nsec))
            vdso_seed_anchor(g, guest_cntvct, ts_mono->tv_sec, ts_mono->tv_nsec,
                             ts_real->tv_sec, ts_real->tv_nsec);
    }

    return 0;
}

/* Interruptible nanosleep: break long sleeps into 100ms chunks so exit_group
 * and pending signals can be checked periodically. Without this, a thread
 * blocked in a multi-second nanosleep cannot be interrupted by exit_group
 * because hv_vcpus_exit only breaks hv_vcpu_run, not host-side blocking
 * syscalls.
 */
int64_t sys_nanosleep(guest_t *g, uint64_t req_gva, uint64_t rem_gva)
{
    linux_timespec_t lreq;
    if (guest_read_small(g, req_gva, &lreq, sizeof(lreq)) < 0)
        return -LINUX_EFAULT;

    if (!linux_timespec_valid(&lreq))
        return -LINUX_EINVAL;

    return interruptible_sleep_ns(g, linux_timespec_to_ns_sat(&lreq), rem_gva,
                                  true);
}

int64_t sys_clock_nanosleep(guest_t *g,
                            int clockid,
                            int flags,
                            uint64_t req_gva,
                            uint64_t rem_gva)
{
    linux_timespec_t lreq;
    if (guest_read_small(g, req_gva, &lreq, sizeof(lreq)) < 0)
        return -LINUX_EFAULT;

    if (flags & ~TIMER_ABSTIME)
        return -LINUX_EINVAL;

    /* Linux's hrtimer_nanosleep_clockid validates the timespec via
     * timespec64_valid_strict() (kernel/time/hrtimer.c) before deciding whether
     * the absolute deadline has expired. Negative tv_sec is rejected with
     * EINVAL even when TIMER_ABSTIME is set, not silently treated as 'already
     * expired'. Reject negative tv_sec unconditionally so both relative and
     * absolute callers match the kernel contract.
     */
    if (!linux_timespec_valid(&lreq))
        return -LINUX_EINVAL;

    int mac_clockid = translate_clockid(clockid);
    if (mac_clockid < 0)
        return -LINUX_EINVAL;

    int64_t remaining_ns;

    if (flags & TIMER_ABSTIME) {
        struct timespec now;
        if (clock_gettime(mac_clockid, &now) < 0)
            return linux_errno();

        int64_t target_ns = linux_timespec_to_ns_sat(&lreq);
        int64_t now_ns = host_timespec_to_ns_sat(&now);
        int64_t delta_ns = target_ns - now_ns;
        if (delta_ns <= 0)
            return 0; /* Already past */
        remaining_ns = delta_ns;
    } else {
        remaining_ns = linux_timespec_to_ns_sat(&lreq);
    }

    return interruptible_sleep_ns(g, remaining_ns, rem_gva,
                                  (flags & TIMER_ABSTIME) == 0);
}

int64_t sys_gettimeofday(guest_t *g, uint64_t tv_gva, uint64_t tz_gva)
{
    bool from_trampoline = current_thread;
    uint64_t guest_cntvct = 0;
    if (from_trampoline) {
        uint64_t elr = 0;
        if (hv_vcpu_get_sys_reg(current_thread->vcpu, HV_SYS_REG_ELR_EL1,
                                &elr) != HV_SUCCESS ||
            elr != vdso_gettimeofday_svc_pc() + 4 ||
            hv_vcpu_get_reg(current_thread->vcpu, HV_REG_X9, &guest_cntvct) !=
                HV_SUCCESS ||
            guest_cntvct == 0)
            from_trampoline = false;
    }

    struct timeval tv;
    if (gettimeofday(&tv, NULL) < 0)
        return linux_errno();

    struct timespec ts_mono;
    struct timespec ts_real;
    bool can_seed = false;
    if (from_trampoline && clock_gettime(CLOCK_MONOTONIC, &ts_mono) == 0 &&
        clock_gettime(CLOCK_REALTIME, &ts_real) == 0)
        can_seed = true;

    linux_timeval_t ltv = {
        .tv_sec = tv.tv_sec,
        .tv_usec = tv.tv_usec,
    };
    if (tv_gva && guest_write_small(g, tv_gva, &ltv, sizeof(ltv)) < 0)
        return -LINUX_EFAULT;

    /* tz is obsolete on Linux but the kernel still zeroes a non-null pointer
     * (struct timezone has two int32 fields, 8 bytes total). Matching the vDSO
     * fast path's STR XZR, [tz] here keeps SVC and fast-path callers
     * observationally identical.
     */
    if (tz_gva) {
        const uint64_t tz_zero = 0;
        if (guest_write_small(g, tz_gva, &tz_zero, sizeof(tz_zero)) < 0)
            return -LINUX_EFAULT;
    }

    if (can_seed && (!vdso_anchor_is_seeded(g) ||
                     vdso_anchor_age_exceeded(g, guest_cntvct) ||
                     vdso_realtime_drift_exceeded(
                         g, guest_cntvct, ts_real.tv_sec, ts_real.tv_nsec)))
        vdso_seed_anchor(g, guest_cntvct, ts_mono.tv_sec, ts_mono.tv_nsec,
                         ts_real.tv_sec, ts_real.tv_nsec);

    return 0;
}

/* Linux struct tms: four clock_t fields (long on LP64) counting USER_HZ ticks.
 */
typedef struct {
    int64_t tms_utime;
    int64_t tms_stime;
    int64_t tms_cutime;
    int64_t tms_cstime;
} linux_tms_t;

/* Kernel USER_HZ, the unit of clock_t values returned by times(). Must match
 * the AT_CLKTCK auxv entry in core/stack.c: libc divides these raw tick counts
 * by sysconf(_SC_CLK_TCK), so a mismatch silently rescales every value.
 */
#define LINUX_USER_HZ 100

/* Shared by both the timeval-based self accounting and the raw-microsecond
 * proc-layer accumulator below, so the two paths cannot drift out of step if
 * LINUX_USER_HZ ever changes.
 */
static int64_t usec_to_clock_ticks(uint64_t usec)
{
    return (int64_t) (usec / (1000000ULL / LINUX_USER_HZ));
}

static int64_t timeval_to_clock_ticks(const struct timeval *tv)
{
    return usec_to_clock_ticks((uint64_t) tv->tv_sec * 1000000ULL +
                               (uint64_t) tv->tv_usec);
}

int64_t sys_times(guest_t *g, uint64_t buf_gva)
{
    /* Linux permits a NULL buffer: only the return value (elapsed ticks) is
     * wanted. cutime/cstime come from the proc-layer accumulator fed at each
     * guest-child reap, not from RUSAGE_CHILDREN: the emulator also waits on
     * helper subprocesses (rosettad translate, sysroot tooling) whose CPU would
     * otherwise masquerade as guest child time.
     */
    if (buf_gva) {
        /* getrusage(RUSAGE_SELF) aggregates the whole emulator process: every
         * host thread plus page-table, syscall-servicing, and Rosetta
         * translation overhead, not just the guest task's own execution, so
         * utime/stime over-report relative to what a real guest kernel would
         * charge. Unavoidable given this design (there is no per-guest-thread
         * host accounting to draw from instead).
         */
        struct rusage self;
        if (getrusage(RUSAGE_SELF, &self) < 0)
            return linux_errno();

        uint64_t cutime_us, cstime_us;
        proc_children_cpu_us(&cutime_us, &cstime_us);

        linux_tms_t tms = {
            .tms_utime = timeval_to_clock_ticks(&self.ru_utime),
            .tms_stime = timeval_to_clock_ticks(&self.ru_stime),
            .tms_cutime = usec_to_clock_ticks(cutime_us),
            .tms_cstime = usec_to_clock_ticks(cstime_us),
        };
        if (guest_write_small(g, buf_gva, &tms, sizeof(tms)) < 0)
            return -LINUX_EFAULT;
    }

    /* Linux returns jiffies-since-boot converted to clock_t ticks; POSIX only
     * requires an arbitrary-but-fixed reference point, so host CLOCK_MONOTONIC
     * satisfies callers that difference successive returns.
     */
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return linux_errno();
    return (int64_t) ts.tv_sec * LINUX_USER_HZ +
           ts.tv_nsec / (NSEC_PER_SEC / LINUX_USER_HZ);
}

int64_t sys_setitimer(guest_t *g, int which, uint64_t new_gva, uint64_t old_gva)
{
    /* Linux reads new_gva before dispatching on which, so an invalid pointer
     * takes precedence over an invalid which value (EFAULT > EINVAL).
     */
    linux_itimerval_t lnew;
    bool has_new = false;
    if (new_gva) {
        if (guest_read_small(g, new_gva, &lnew, sizeof(lnew)) < 0)
            return -LINUX_EFAULT;

        /* Linux rejects tv_usec outside [0, 999999] AND negative tv_sec for
         * both value and interval. Accepting a negative tv_sec would cast
         * through (long) below and arm an expired timer instead of returning
         * EINVAL, diverging from the kernel contract.
         */
        if (!RANGE_CHECK(lnew.it_value.tv_usec, 0, 1000000) ||
            !RANGE_CHECK(lnew.it_interval.tv_usec, 0, 1000000) ||
            (int64_t) lnew.it_value.tv_sec < 0 ||
            (int64_t) lnew.it_interval.tv_sec < 0)
            return -LINUX_EINVAL;
        has_new = true;
    }

    if (which != 0 && which != 1 && which != 2)
        return -LINUX_EINVAL;

    struct timeval val = {0}, itv = {0};
    if (has_new) {
        val = (struct timeval) {.tv_sec = (long) lnew.it_value.tv_sec,
                                .tv_usec = (int) lnew.it_value.tv_usec};
        itv = (struct timeval) {.tv_sec = (long) lnew.it_interval.tv_sec,
                                .tv_usec = (int) lnew.it_interval.tv_usec};
    }

    struct timeval old_val = {0}, old_itv = {0};
    struct timeval *new_val_p = has_new ? &val : NULL;
    struct timeval *new_itv_p = has_new ? &itv : NULL;
    struct timeval *old_val_p = old_gva ? &old_val : NULL;
    struct timeval *old_itv_p = old_gva ? &old_itv : NULL;

    /* ITIMER_REAL is emulated internally because macOS shares alarm() and
     * setitimer(ITIMER_REAL) as the same underlying timer, and elfuse needs
     * alarm() for its per-iteration vCPU timeout. ITIMER_VIRTUAL/PROF must also
     * be emulated since SIGVTALRM/SIGPROF would otherwise hit the host process.
     */
    if (which == 0)
        signal_set_itimer(new_val_p, new_itv_p, old_val_p, old_itv_p);
    else
        signal_set_itimer_virt(which, new_val_p, new_itv_p, old_val_p,
                               old_itv_p);

    if (old_gva) {
        linux_itimerval_t lold = {
            .it_interval = {.tv_sec = old_itv.tv_sec,
                            .tv_usec = old_itv.tv_usec},
            .it_value = {.tv_sec = old_val.tv_sec, .tv_usec = old_val.tv_usec},
        };
        if (guest_write_small(g, old_gva, &lold, sizeof(lold)) < 0)
            return -LINUX_EFAULT;
    }
    return 0;
}

int64_t sys_getitimer(guest_t *g, int which, uint64_t val_gva)
{
    /* ITIMER_REAL/VIRTUAL/PROF are all emulated internally (see sys_setitimer
     * comment).
     */
    struct timeval val = {0}, itv = {0};
    if (which == 0)
        signal_get_itimer(&val, &itv);
    else if (which == 1 || which == 2)
        signal_get_itimer_virt(which, &val, &itv);
    else
        return -LINUX_EINVAL;

    linux_itimerval_t lval = {
        .it_interval = {.tv_sec = itv.tv_sec, .tv_usec = itv.tv_usec},
        .it_value = {.tv_sec = val.tv_sec, .tv_usec = val.tv_usec},
    };
    if (guest_write_small(g, val_gva, &lval, sizeof(lval)) < 0)
        return -LINUX_EFAULT;
    return 0;
}
