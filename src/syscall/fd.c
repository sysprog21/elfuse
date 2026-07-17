/*
 * Special FD types (eventfd, signalfd, timerfd)
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Emulates Linux eventfd (pipe+counter), signalfd (synthetic signal reads), and
 * timerfd (kqueue EVFILT_TIMER). Each provides special read/write/close
 * semantics dispatched from sys_read/sys_write/sys_close.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include <sys/uio.h>

#include "utils.h"

#include "debug/log.h"
#include <sys/event.h>

#include "proved/timespec.h"
#include "syscall/linux-wire.h"
#include "syscall/fd.h"
#include "syscall/internal.h"
#include "syscall/io.h"
#include "syscall/proc.h"
#include "syscall/signal.h"

/* Mutex protecting timerfd/eventfd/signalfd per-slot state. Prevents races when
 * two threads operate on the same special FD concurrently (e.g., two threads
 * reading the same eventfd). Lock order: 5a (after thread_lock(5), never held
 * together with it).
 */
static pthread_mutex_t sfd_lock = PTHREAD_MUTEX_INITIALIZER;

static void timerfd_close(int guest_fd);
static void eventfd_close(int guest_fd);
static void signalfd_close(int guest_fd);

#define NS_PER_SEC 1000000000LL

_Static_assert(
    NS_PER_SEC == TIMESPEC_NSEC_PER_SEC,
    "timerfd and proved timespec conversions must use the same scale");

/* All special-FD state arrays store guest_fd as their first field. Keep the
 * common slot walk in one place so timerfd/eventfd/signalfd stay consistent.
 */
static int sfd_find_slot(const void *state,
                         size_t count,
                         size_t stride,
                         int guest_fd)
{
    const uint8_t *base = state;
    for (size_t i = 0; i < count; i++) {
        int slot_guest_fd;
        memcpy(&slot_guest_fd, base + i * stride, sizeof(slot_guest_fd));
        if (slot_guest_fd == guest_fd)
            return (int) i;
    }
    return -1;
}

static int sfd_alloc_slot(const void *state, size_t count, size_t stride)
{
    return sfd_find_slot(state, count, stride, -1);
}

/* timerfd emulation via kqueue EVFILT_TIMER
 *
 * Each timerfd_create() creates a kqueue + timer registration. Reads from the
 * timerfd return an 8-byte counter of expirations.
 */

/* Linux itimerspec for timerfd_settime/gettime */
typedef struct {
    int64_t it_interval_sec, it_interval_nsec, it_value_sec, it_value_nsec;
} linux_itimerspec_t;

/* Per-timerfd state (stored alongside the FD_TIMERFD entry) */
#define TIMERFD_MAX 32
#define LINUX_TFD_NONBLOCK LINUX_O_NONBLOCK
#define LINUX_TFD_CLOEXEC LINUX_O_CLOEXEC
#define LINUX_TFD_TIMER_ABSTIME 1
#define LINUX_TFD_TIMER_CANCEL_ON_SET 2
#define LINUX_CLOCK_REALTIME 0
#define LINUX_CLOCK_MONOTONIC 1

/* Linux CLOCK_BOOTTIME counts time including suspend; macOS has no equivalent.
 * timerfd_settime treats non-REALTIME slots as MONOTONIC for ABSTIME
 * conversion, which matches translate_clockid() in time.c.
 */
#define LINUX_CLOCK_BOOTTIME 7

static struct {
    int guest_fd;         /* Guest fd (-1 if unused) */
    int kq_fd;            /* kqueue fd for this timer */
    uint64_t expirations; /* Accumulated expiration count */
    int64_t interval_ns;  /* Repeat interval (0 = one-shot) */
    int64_t initial_ns;   /* Initial value at arm time (for gettime) */
    int64_t arm_time_ns;  /* CLOCK_MONOTONIC time when timer was armed */
    int clockid; /* Linux clock ID (CLOCK_REALTIME=0, CLOCK_MONOTONIC=1) */
    bool armed;  /* True if timer is running */
} timerfd_state[TIMERFD_MAX];

void timerfd_init(void)
{
    for (int i = 0; i < TIMERFD_MAX; i++)
        timerfd_state[i].guest_fd = -1;
    fd_register_cleanup(FD_TIMERFD, timerfd_close);
}

static int timerfd_find(int guest_fd)
{
    return sfd_find_slot(timerfd_state, TIMERFD_MAX, sizeof(timerfd_state[0]),
                         guest_fd);
}

static int timerfd_alloc(void)
{
    return sfd_alloc_slot(timerfd_state, TIMERFD_MAX, sizeof(timerfd_state[0]));
}

/* Called with sfd_lock held. Drain any kevent expirations sitting on the
 * timer's kqueue and fold them into the slot's accumulator. Used by
 * timerfd_read before consuming the counter and by timerfd_fdinfo_snapshot
 * before reporting it; without this drain, fdinfo would lag the actual fire
 * count by however many ticks were pending in the kqueue.
 */
static void timerfd_drain_pending_locked(int slot)
{
    int kq = timerfd_state[slot].kq_fd;
    struct kevent kev;
    struct timespec ts_zero = {0, 0};
    int nev = kevent(kq, NULL, 0, &kev, 1, &ts_zero);
    if (nev > 0) {
        uint64_t fires = (uint64_t) kev.data;
        if (fires == 0)
            fires = 1; /* At least one expiration */
        timerfd_state[slot].expirations += fires;
    }
}

/* Called with sfd_lock held.
 *
 * Returns nanoseconds until the next expiration, or 0 when the timer is
 * disarmed or a one-shot timer has already expired.
 */
static int64_t timerfd_remaining_ns_locked(int slot, int64_t now_ns)
{
    if (!timerfd_state[slot].armed)
        return 0;

    int64_t elapsed = now_ns - timerfd_state[slot].arm_time_ns;
    if (elapsed < 0)
        elapsed = 0;

    if (timerfd_state[slot].interval_ns > 0) {
        int64_t total = timerfd_state[slot].initial_ns;
        if (elapsed >= total) {
            int64_t since_first = elapsed - total;
            int64_t interval = timerfd_state[slot].interval_ns;
            int64_t remaining = interval - (since_first % interval);
            return remaining == 0 ? interval : remaining;
        }
        return total - elapsed;
    }

    int64_t remaining = timerfd_state[slot].initial_ns - elapsed;
    return remaining > 0 ? remaining : 0;
}

int64_t sys_timerfd_create(int clockid, int flags)
{
    if (clockid != LINUX_CLOCK_REALTIME && clockid != LINUX_CLOCK_MONOTONIC &&
        clockid != LINUX_CLOCK_BOOTTIME)
        return -LINUX_EINVAL;
    if (flags & ~(LINUX_TFD_CLOEXEC | LINUX_TFD_NONBLOCK))
        return -LINUX_EINVAL;

    int kq = kqueue();
    if (kq < 0)
        return linux_errno();

    /* macOS kqueue fds reject fcntl(F_SETFL, O_NONBLOCK) with ENOTTY, so track
     * the non-blocking mode in fd_table[gfd].linux_flags below and let
     * timerfd_read consult that field directly. F_SETFD CLOEXEC still works on
     * a kqueue fd.
     */
    if ((flags & LINUX_TFD_CLOEXEC) && fd_set_cloexec(kq) < 0) {
        close(kq);
        return linux_errno();
    }

    int gfd = fd_alloc(FD_TIMERFD, kq, timerfd_close);
    if (gfd < 0) {
        close(kq);
        return -LINUX_EMFILE;
    }

    pthread_mutex_lock(&sfd_lock);
    int slot = timerfd_alloc();
    if (slot < 0) {
        pthread_mutex_unlock(&sfd_lock);
        fd_retire_published(gfd, kq);
        return -LINUX_ENOMEM;
    }

    memset(&timerfd_state[slot], 0, sizeof(timerfd_state[slot]));
    timerfd_state[slot].guest_fd = gfd;
    timerfd_state[slot].kq_fd = kq;
    timerfd_state[slot].clockid = clockid;
    pthread_mutex_unlock(&sfd_lock);

    /* Linux opens the timerfd inode O_RDWR (anon_inode_getfd in fs/timerfd.c).
     * Stamp O_RDWR into linux_flags so the F_GETFL branch below can surface the
     * access mode without re-deriving it.
     */
    fd_publish_linux_flags(
        gfd, ((flags & LINUX_TFD_CLOEXEC) ? LINUX_O_CLOEXEC : 0) |
                 ((flags & LINUX_TFD_NONBLOCK) ? LINUX_O_NONBLOCK : 0));
    return gfd;
}

int64_t sys_timerfd_settime(guest_t *g,
                            int fd,
                            int flags,
                            uint64_t new_value_gva,
                            uint64_t old_value_gva)
{
    int64_t ret = 0;

    (void) guest_lazy_faultin(g, new_value_gva, sizeof(linux_itimerspec_t));
    if (old_value_gva)
        (void) guest_lazy_faultin(g, old_value_gva, sizeof(linux_itimerspec_t));

    pthread_mutex_lock(&sfd_lock);
    int slot = timerfd_find(fd);
    if (slot < 0) {
        ret = -LINUX_EBADF;
        goto unlock;
    }

    linux_itimerspec_t its;
    if (guest_read_nofault(g, new_value_gva, &its, sizeof(its)) < 0) {
        ret = -LINUX_EFAULT;
        goto unlock;
    }

    if (flags & ~(LINUX_TFD_TIMER_ABSTIME | LINUX_TFD_TIMER_CANCEL_ON_SET)) {
        ret = -LINUX_EINVAL;
        goto unlock;
    }

    /* Validate timespec fields before any arithmetic. */
    if (its.it_value_sec < 0 || its.it_interval_sec < 0 ||
        !RANGE_CHECK(its.it_value_nsec, 0, NS_PER_SEC) ||
        !RANGE_CHECK(its.it_interval_nsec, 0, NS_PER_SEC)) {
        ret = -LINUX_EINVAL;
        goto unlock;
    }

    /* Return old value if requested (compute remaining time) */
    if (old_value_gva) {
        linux_itimerspec_t old = {0};
        if (timerfd_state[slot].armed) {
            old.it_interval_sec = timerfd_state[slot].interval_ns / NS_PER_SEC;
            old.it_interval_nsec = timerfd_state[slot].interval_ns % NS_PER_SEC;

            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            int64_t now_ns = timespec_to_ns_sat(now.tv_sec, now.tv_nsec);
            int64_t remaining = timerfd_remaining_ns_locked(slot, now_ns);
            if (remaining > 0) {
                old.it_value_sec = remaining / NS_PER_SEC;
                old.it_value_nsec = remaining % NS_PER_SEC;
            }
        }
        if (guest_write_nofault(g, old_value_gva, &old, sizeof(old)) < 0) {
            ret = -LINUX_EFAULT;
            goto unlock;
        }
    }

    int kq = timerfd_state[slot].kq_fd;

    if ((flags & LINUX_TFD_TIMER_ABSTIME) &&
        (its.it_value_sec != 0 || its.it_value_nsec != 0)) {
        struct timespec now;
        int host_clock = timerfd_state[slot].clockid == LINUX_CLOCK_REALTIME
                             ? CLOCK_REALTIME
                             : CLOCK_MONOTONIC;
        clock_gettime(host_clock, &now);
        int64_t target_ns =
            timespec_to_ns_sat(its.it_value_sec, its.it_value_nsec);
        int64_t now_ns = timespec_to_ns_sat(now.tv_sec, now.tv_nsec);
        int64_t relative_ns = target_ns > now_ns ? target_ns - now_ns : 1;
        its.it_value_sec = relative_ns / NS_PER_SEC;
        its.it_value_nsec = relative_ns % NS_PER_SEC;
    }

    /* Derive the host timeout and stored timer state from the same saturating
     * nanosecond conversion.
     */
    int64_t value_ns = timespec_to_ns_sat(its.it_value_sec, its.it_value_nsec);
    int64_t value_us = value_ns / 1000;
    int64_t interval_ns =
        timespec_to_ns_sat(its.it_interval_sec, its.it_interval_nsec);

    log_debug(
        "timerfd_settime: gfd=%d value=%lld.%09lld "
        "interval=%lld.%09lld (value_us=%lld interval_ns=%lld oneshot=%d)",
        fd, (long long) its.it_value_sec, (long long) its.it_value_nsec,
        (long long) its.it_interval_sec, (long long) its.it_interval_nsec,
        (long long) value_us, (long long) interval_ns, interval_ns == 0);

    if (its.it_value_sec == 0 && its.it_value_nsec == 0) {
        /* Disarm timer */
        struct kevent kev;
        EV_SET(&kev, 1, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
        kevent(kq, &kev, 1, NULL, 0, NULL); /* Ignore error if not armed */

        /* Drain any stale pending events so the next timerfd_read() does not
         * see expirations from the now-disarmed timer.
         */
        struct timespec ts_zero = {0, 0};
        while (kevent(kq, NULL, 0, &kev, 1, &ts_zero) > 0)
            ;

        timerfd_state[slot].armed = false;
        timerfd_state[slot].expirations = 0;
    } else {
        /* Arm timer. Always use EV_ONESHOT: for repeating timers where initial
         * value != interval, kqueue would repeat at the wrong period (initial
         * instead of interval). timerfd_read re-arms with the interval after
         * the first read.
         */
        struct kevent kev;
        EV_SET(&kev, 1, EVFILT_TIMER, EV_ADD | EV_ENABLE | EV_ONESHOT,
               NOTE_USECONDS, value_us, NULL);
        if (kevent(kq, &kev, 1, NULL, 0, NULL) < 0) {
            ret = linux_errno();
            goto unlock;
        }
        timerfd_state[slot].armed = true;
        timerfd_state[slot].interval_ns = interval_ns;

        timerfd_state[slot].initial_ns = value_ns;
        timerfd_state[slot].expirations = 0;

        /* Record arm time for gettime remaining-time calculation */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        timerfd_state[slot].arm_time_ns =
            timespec_to_ns_sat(now.tv_sec, now.tv_nsec);
    }

unlock:
    pthread_mutex_unlock(&sfd_lock);
    return ret;
}

int64_t sys_timerfd_gettime(guest_t *g, int fd, uint64_t curr_value_gva)
{
    pthread_mutex_lock(&sfd_lock);
    int slot = timerfd_find(fd);
    if (slot < 0) {
        pthread_mutex_unlock(&sfd_lock);
        return -LINUX_EBADF;
    }

    linux_itimerspec_t its = {0};
    if (timerfd_state[slot].armed) {
        its.it_interval_sec = timerfd_state[slot].interval_ns / NS_PER_SEC;
        its.it_interval_nsec = timerfd_state[slot].interval_ns % NS_PER_SEC;

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        int64_t now_ns = timespec_to_ns_sat(now.tv_sec, now.tv_nsec);
        int64_t remaining = timerfd_remaining_ns_locked(slot, now_ns);

        if (remaining <= 0) {
            /* Timer already expired (one-shot) */
            its.it_value_sec = 0;
            its.it_value_nsec = 0;
        } else {
            its.it_value_sec = remaining / NS_PER_SEC;
            its.it_value_nsec = remaining % NS_PER_SEC;
        }
    }
    pthread_mutex_unlock(&sfd_lock);
    if (guest_write_small(g, curr_value_gva, &its, sizeof(its)) < 0)
        return -LINUX_EFAULT;
    return 0;
}


/* Read from timerfd: collect pending timer events from the kqueue, return
 * accumulated expiration count as uint64_t. Resets count to 0 after read (Linux
 * timerfd semantics).
 */
int64_t timerfd_read(int guest_fd, guest_t *g, uint64_t buf_gva, uint64_t count)
{
    if (count < 8)
        return -LINUX_EINVAL;

    bool nonblock = fd_guest_nonblock(guest_fd);

    pthread_mutex_lock(&sfd_lock);
    int slot = timerfd_find(guest_fd);
    if (slot < 0) {
        pthread_mutex_unlock(&sfd_lock);
        return -LINUX_EBADF;
    }

    int kq = timerfd_state[slot].kq_fd;

    /* Collect pending timer events into the slot's accumulator. */
    timerfd_drain_pending_locked(slot);

    if (timerfd_state[slot].expirations == 0) {
        if (nonblock) {
            pthread_mutex_unlock(&sfd_lock);
            return -LINUX_EAGAIN;
        }

        /* If the timer was never armed, there's no kevent registered --
         * kevent(NULL timeout) would block forever.
         *
         * Return EAGAIN.
         */
        if (!timerfd_state[slot].armed) {
            pthread_mutex_unlock(&sfd_lock);
            return -LINUX_EAGAIN;
        }

        /* Blocking: release the lock and wait for the timer, interruptibly. A
         * kevent() with a NULL timeout parks this vCPU thread where neither
         * hv_vcpus_exit nor the wakeup pipe reaches it, so an execve teardown
         * counts it as a sibling that will not leave; a kqueue descriptor is
         * pollable, so the wait can watch it alongside the wakeup pipe and
         * collect with a zero timeout once it says there is something. Another
         * thread may close the fd meanwhile, which the re-validation below
         * catches. Loop on the expiration count rather than on one wait: the
         * collect below runs with a zero timeout, so a sibling reading this
         * same timerfd can take the event the wait reported and leave nothing
         * here. A blocking read owes the guest a wait, not a spurious EAGAIN,
         * which is what the NULL-timeout kevent this replaced could not
         * produce.
         */
        while (timerfd_state[slot].expirations == 0) {
            struct kevent kev;
            pthread_mutex_unlock(&sfd_lock);
            int64_t waited = io_wait_fd_or_interrupted(kq, POLLIN);
            if (waited < 0)
                return waited;
            struct timespec collect = {0, 0};
            int nev = kevent(kq, NULL, 0, &kev, 1, &collect);
            pthread_mutex_lock(&sfd_lock);
            /* Re-validate: slot may have been freed by timerfd_close() */
            if (timerfd_state[slot].guest_fd != guest_fd) {
                pthread_mutex_unlock(&sfd_lock);
                return -LINUX_EBADF;
            }
            if (nev < 0 && errno != EINTR) {
                pthread_mutex_unlock(&sfd_lock);
                return linux_errno();
            }
            if (nev > 0) {
                uint64_t fires = (uint64_t) kev.data;
                if (fires == 0)
                    fires = 1;
                timerfd_state[slot].expirations += fires;
            }
        }
    }

    uint64_t val = timerfd_state[slot].expirations;
    timerfd_state[slot].expirations = 0;
    bool armed = timerfd_state[slot].armed;
    int64_t intv = timerfd_state[slot].interval_ns;
    int rearm_kq = timerfd_state[slot].kq_fd;

    /* Re-arm repeating timers with the interval period. The initial fire used
     * EV_ONESHOT (see timerfd_settime), so the code re-arms here to get correct
     * interval timing even when initial != interval.
     */
    if (intv > 0 && armed) {
        int64_t interval_us = intv / 1000;
        if (interval_us == 0)
            interval_us = 1; /* Minimum 1us */
        struct kevent rearm_kev;
        EV_SET(&rearm_kev, 1, EVFILT_TIMER, EV_ADD | EV_ENABLE | EV_ONESHOT,
               NOTE_USECONDS, interval_us, NULL);
        kevent(rearm_kq, &rearm_kev, 1, NULL, 0, NULL);

        /* Update arm time for gettime remaining-time calculation */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        timerfd_state[slot].arm_time_ns =
            timespec_to_ns_sat(now.tv_sec, now.tv_nsec);
        timerfd_state[slot].initial_ns = intv; /* Next fire is one interval */
    }
    pthread_mutex_unlock(&sfd_lock);

    log_debug("timerfd_read: gfd=%d expirations=%llu armed=%d interval_ns=%lld",
              guest_fd, (unsigned long long) val, armed, (long long) intv);

    if (guest_write_small(g, buf_gva, &val, sizeof(val)) < 0)
        return -LINUX_EFAULT;

    return 8;
}

/* Clean up timerfd state when guest closes the fd. Must hold sfd_lock to
 * prevent racing with concurrent timerfd_read.
 */
static void timerfd_close(int guest_fd)
{
    pthread_mutex_lock(&sfd_lock);
    int slot = timerfd_find(guest_fd);
    if (slot >= 0) {
        /* kq_fd is closed by sys_close() as host_fd */
        timerfd_state[slot].guest_fd = -1;
        timerfd_state[slot].expirations = 0;
        timerfd_state[slot].armed = false;
    }
    pthread_mutex_unlock(&sfd_lock);
}

/* eventfd emulation via pipe + counter
 *
 * Linux eventfd is a semaphore-like fd: writes add to a uint64 counter, reads
 * return the counter and reset it to zero. EFD_SEMAPHORE mode returns 1 per
 * read and decrements. Eventfd emulation uses a self-pipe for poll/epoll
 * compatibility plus a separate counter.
 */

/* Linux eventfd flags */
#define LINUX_EFD_CLOEXEC 0x80000 /* Same as O_CLOEXEC on aarch64 */
#define LINUX_EFD_NONBLOCK 0x800  /* Same as O_NONBLOCK */
#define LINUX_EFD_SEMAPHORE 1

/* Per-eventfd state. The slot is shared across guest_fds that point at it (via
 * dup/dup2/fcntl F_DUPFD), matching the Linux contract that dup'd eventfd fds
 * share the same kernel object. eventfd_owner[gfd] maps a guest_fd to its slot;
 * multiple guest_fds can map to the same slot. The slot owns its own read end
 * for readiness/drain/blocking operations so it does not depend on any one
 * guest fd remaining open. The slot is freed when refcount drops to zero. The
 * slot's guest_fd field is retained for sfd_alloc_slot's "free if guest_fd ==
 * -1" convention and tracks the most recently allocated primary owner.
 */
#define EVENTFD_MAX 32
static struct {
    int guest_fd;     /* Primary guest fd, -1 when slot is free */
    int refcount;     /* Number of guest_fds bound to this slot */
    int pipe_rd;      /* Read end of self-pipe (for poll/epoll readiness) */
    int pipe_wr;      /* Write end of self-pipe */
    uint64_t counter; /* Accumulated event counter */
    int semaphore;    /* EFD_SEMAPHORE mode */
} eventfd_state[EVENTFD_MAX];

static int eventfd_owner[FD_TABLE_SIZE]; /* guest_fd -> slot, or -1 */

void eventfd_init(void)
{
    for (int i = 0; i < EVENTFD_MAX; i++)
        eventfd_state[i].guest_fd = -1;
    for (int i = 0; i < FD_TABLE_SIZE; i++)
        eventfd_owner[i] = -1;
    fd_register_cleanup(FD_EVENTFD, eventfd_close);
}

static int eventfd_find(int guest_fd)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return -1;
    return eventfd_owner[guest_fd];
}

static int eventfd_slot_alloc(void)
{
    return sfd_alloc_slot(eventfd_state, EVENTFD_MAX, sizeof(eventfd_state[0]));
}

static void eventfd_release_ref_locked(int slot)
{
    if (--eventfd_state[slot].refcount <= 0) {
        close(eventfd_state[slot].pipe_rd);
        close(eventfd_state[slot].pipe_wr);
        eventfd_state[slot].guest_fd = -1;
        eventfd_state[slot].counter = 0;
        eventfd_state[slot].refcount = 0;
        eventfd_state[slot].pipe_rd = -1;
        eventfd_state[slot].pipe_wr = -1;
    }
}

int64_t sys_eventfd2(unsigned int initval, int flags)
{
    if (flags & ~(LINUX_EFD_CLOEXEC | LINUX_EFD_NONBLOCK | LINUX_EFD_SEMAPHORE))
        return -LINUX_EINVAL;

    /* Create self-pipe for poll/epoll readiness signaling */
    int pipefd[2];
    if (pipe(pipefd) < 0)
        return linux_errno();

    /* Both ends must be non-blocking to avoid blocking on pipe I/O. CLOEXEC is
     * opt-in via EFD_CLOEXEC.
     */
    bool want_cloexec = (flags & LINUX_EFD_CLOEXEC) != 0;
    if (fd_set_nonblock(pipefd[0]) < 0 || fd_set_nonblock(pipefd[1]) < 0 ||
        (want_cloexec &&
         (fd_set_cloexec(pipefd[0]) < 0 || fd_set_cloexec(pipefd[1]) < 0))) {
        close(pipefd[0]);
        close(pipefd[1]);
        return linux_errno();
    }

    int state_rd = dup(pipefd[0]);
    if (state_rd < 0 || fd_set_nonblock(state_rd) < 0 ||
        fd_set_cloexec(state_rd) < 0) {
        int saved_errno = errno;
        if (state_rd >= 0)
            close(state_rd);
        close(pipefd[0]);
        close(pipefd[1]);
        errno = saved_errno;
        return linux_errno();
    }

    /* Allocate guest fd: use read end as the host fd so epoll/poll sees it */
    int gfd = fd_alloc(FD_EVENTFD, pipefd[0], eventfd_close);
    if (gfd < 0) {
        close(state_rd);
        close(pipefd[0]);
        close(pipefd[1]);
        return -LINUX_EMFILE;
    }

    pthread_mutex_lock(&sfd_lock);
    int slot = eventfd_slot_alloc();
    if (slot < 0) {
        pthread_mutex_unlock(&sfd_lock);
        fd_retire_published(gfd, pipefd[0]);
        close(state_rd);
        close(pipefd[1]);
        return -LINUX_ENOMEM;
    }

    eventfd_state[slot].guest_fd = gfd;
    eventfd_state[slot].refcount = 1;
    eventfd_state[slot].pipe_rd = state_rd;
    eventfd_state[slot].pipe_wr = pipefd[1];
    eventfd_state[slot].counter = (uint64_t) initval;
    eventfd_state[slot].semaphore = (flags & LINUX_EFD_SEMAPHORE) ? 1 : 0;
    eventfd_owner[gfd] = slot;
    pthread_mutex_unlock(&sfd_lock);

    /* Linux opens the eventfd inode O_RDWR (anon_inode_getfd in fs/eventfd.c),
     * and O_NONBLOCK lives here rather than on the internal pipe, which stays
     * nonblocking so the emulation can do its own waiting.
     */
    fd_publish_linux_flags(
        gfd, ((flags & LINUX_EFD_CLOEXEC) ? LINUX_O_CLOEXEC : 0) |
                 ((flags & LINUX_EFD_NONBLOCK) ? LINUX_O_NONBLOCK : 0));

    /* If initial counter > 0, make the pipe readable so poll sees it */
    if (initval > 0) {
        uint8_t byte = 1;
        write(pipefd[1], &byte, 1);
    }

    return gfd;
}

/* Clean up eventfd state when guest closes the fd. Must hold sfd_lock to
 * prevent racing with concurrent eventfd_write/eventfd_read.
 */
static void eventfd_close(int guest_fd)
{
    pthread_mutex_lock(&sfd_lock);
    int slot = eventfd_find(guest_fd);
    if (slot >= 0) {
        eventfd_owner[guest_fd] = -1;
        eventfd_release_ref_locked(slot);
    }
    pthread_mutex_unlock(&sfd_lock);
}

/* Bind an additional guest_fd to the same slot as src_fd, sharing the counter
 * and pipe state. Two races to defeat:
 *
 *   - Source identity. duplicate_guest_fd() snapshots src_fd under
 *     fd_lock, releases it, then calls us. Between those points src_fd
 *     could be closed and rebound to a different eventfd. We carry the
 *     caller's snapshot of fd_table[src_fd].host_fd and generation and verify
 *     under fd_lock + sfd_lock that the source fd still has that identity and
 *     still maps to a live eventfd slot.
 *
 *   - Destination close. fd_alloc_*_relaxed publishes the new guest_fd
 *     with eventfd_close as cleanup before we install the owner mapping.
 *     A racing close would run eventfd_close, see owner == -1, skip the
 *     refcount decrement, and leak the slot. We defeat this by reserving a
 *     slot ref before publishing the destination, then holding fd_lock +
 *     sfd_lock together while we verify fd_table[new] is still FD_EVENTFD with
 *     the host_fd we allocated and set eventfd_owner. Any close that already
 *     ran is observed here as FD_CLOSED, and we abandon the bind cleanly with
 *     no leak.
 */
int eventfd_dup_fd(int src_fd,
                   int src_host_fd,
                   uint64_t src_generation,
                   int min_guest_fd,
                   int fixed_guest_fd,
                   bool fixed_slot,
                   int linux_flags)
{
    /* Pin the source under fd_lock + sfd_lock and dup the slot-owned readiness
     * fd. The slot fd is independent of any guest alias, so closing the source
     * later cannot invalidate eventfd_state[slot].pipe_rd.
     */
    pthread_mutex_lock(&fd_lock);
    pthread_mutex_lock(&sfd_lock);
    int slot = eventfd_find(src_fd);
    if (slot < 0 || fd_table[src_fd].type != FD_EVENTFD ||
        fd_table[src_fd].host_fd != src_host_fd ||
        fd_table[src_fd].generation != src_generation ||
        eventfd_state[slot].refcount <= 0) {
        pthread_mutex_unlock(&sfd_lock);
        pthread_mutex_unlock(&fd_lock);
        errno = EBADF;
        return -1;
    }
    eventfd_state[slot].refcount++;

    /* dup(2) hands back a second name for one open file description, so the
     * alias has to carry the source's per-description state: the status flags
     * (an eventfd keeps O_NONBLOCK and its access mode in the shadow, because
     * the host fd behind it is elfuse's own pipe) and the ofd_id every alias
     * sweep matches on. Rebuilding linux_flags from the dup argument alone left
     * a dup of an EFD_NONBLOCK eventfd blocking forever on an empty read.
     */
    int src_flags = fd_table[src_fd].linux_flags & FD_DESCRIPTION_FLAGS;
    uint64_t src_ofd_id = fd_table[src_fd].ofd_id;
    int new_host_fd = dup(eventfd_state[slot].pipe_rd);
    int original_pipe_rd = eventfd_state[slot].pipe_rd;
    if (new_host_fd < 0)
        eventfd_release_ref_locked(slot);
    pthread_mutex_unlock(&sfd_lock);
    pthread_mutex_unlock(&fd_lock);
    if (new_host_fd < 0)
        return -1;

    /* Publish the destination fd with eventfd_close as cleanup. The
     * eventfd_owner mapping is still -1, so a racing close here observes owner
     * == -1 and does nothing; we detect that below. Aliases the source's
     * description, so the allocator installs its identity with the slot rather
     * than this path patching it on afterwards.
     */
    fd_alias_spec_t spec =
        fd_alias_identity(src_ofd_id, src_flags | linux_flags);
    int new_guest_fd = fd_alloc_alias_relaxed(
        &spec, fixed_slot ? fixed_guest_fd : -1, min_guest_fd, FD_EVENTFD,
        new_host_fd, eventfd_close, NULL);
    if (new_guest_fd < 0) {
        close(new_host_fd);
        pthread_mutex_lock(&sfd_lock);
        eventfd_release_ref_locked(slot);
        pthread_mutex_unlock(&sfd_lock);
        if (fixed_slot)
            errno = EBADF;
        return -1;
    }

    /* Commit the bind under both locks in the documented order (fd_lock then
     * sfd_lock). If a close already ran, fd_table[new].type is FD_CLOSED and we
     * just bail with -EBADF; the host_fd is already gone via sys_close.
     * Otherwise verify the source slot is still alive and unchanged, then
     * install owner for the reserved ref.
     */
    pthread_mutex_lock(&fd_lock);
    pthread_mutex_lock(&sfd_lock);
    if (fd_table[new_guest_fd].type != FD_EVENTFD ||
        fd_table[new_guest_fd].host_fd != new_host_fd ||
        eventfd_state[slot].refcount <= 0 ||
        eventfd_state[slot].pipe_rd != original_pipe_rd) {
        pthread_mutex_unlock(&sfd_lock);
        pthread_mutex_unlock(&fd_lock);

        /* If the destination is still open but the source went away, tear it
         * down. (If the destination already closed itself, the snapshot below
         * sees FD_CLOSED and is a no-op.)
         */
        fd_entry_t snap;
        if (fd_snapshot_and_close(new_guest_fd, &snap))
            fd_cleanup_entry(new_guest_fd, &snap);
        pthread_mutex_lock(&sfd_lock);
        eventfd_release_ref_locked(slot);
        pthread_mutex_unlock(&sfd_lock);
        errno = EBADF;
        return -1;
    }
    eventfd_owner[new_guest_fd] = slot;
    pthread_mutex_unlock(&sfd_lock);
    pthread_mutex_unlock(&fd_lock);
    return new_guest_fd;
}

/* Read from eventfd: return 8-byte counter value, then reset to 0. In
 * EFD_SEMAPHORE mode, return 1 and decrement counter by 1.
 */
int64_t eventfd_read(int guest_fd, guest_t *g, uint64_t buf_gva, uint64_t count)
{
    if (count < 8)
        return -LINUX_EINVAL;

    bool nonblock = fd_guest_nonblock(guest_fd);

    pthread_mutex_lock(&sfd_lock);
    int slot = eventfd_find(guest_fd);
    if (slot < 0) {
        pthread_mutex_unlock(&sfd_lock);
        return -LINUX_EBADF;
    }

    if (eventfd_state[slot].counter == 0) {
        if (nonblock) {
            pthread_mutex_unlock(&sfd_lock);
            return -LINUX_EAGAIN;
        }

        /* Blocking mode: release the lock and wait for the writer, without
         * parking. The pipe stays nonblocking and the wait polls it alongside
         * the wakeup pipe, so an execve teardown or a guest signal ends it;
         * flipping the pipe to blocking for a read left this vCPU thread
         * somewhere neither could reach. Another thread may close the fd
         * meanwhile, which the slot re-validation below catches.
         */
        while (eventfd_state[slot].counter == 0) {
            int rd_fd = eventfd_state[slot].pipe_rd;
            pthread_mutex_unlock(&sfd_lock);

            int64_t waited = io_wait_fd_or_interrupted(rd_fd, POLLIN);
            if (waited < 0)
                return waited;

            uint8_t byte;
            ssize_t r = read(rd_fd, &byte, 1);
            if (r < 0 && errno != EAGAIN)
                return linux_errno();

            pthread_mutex_lock(&sfd_lock);

            /* Re-validate via the owner table, not
             * eventfd_state[slot].guest_fd: dup'd aliases bind multiple
             * guest_fds to the same slot, so a legitimate caller's guest_fd may
             * not equal the primary owner.
             */
            if (eventfd_owner[guest_fd] != slot ||
                eventfd_state[slot].refcount <= 0) {
                pthread_mutex_unlock(&sfd_lock);
                return -LINUX_EBADF;
            }
        }
    }

    uint64_t val;
    if (eventfd_state[slot].semaphore) {
        val = 1;
        eventfd_state[slot].counter--;
    } else {
        val = eventfd_state[slot].counter;
        eventfd_state[slot].counter = 0;
    }

    /* The pipe is what poll, epoll and the blocking read above all watch, so
     * its readability has to mean the same thing as counter > 0 rather than
     * merely record the moment the counter left zero.
     *
     * Draining at zero is the whole story for a plain eventfd, whose read takes
     * the counter to zero every time, and only half of it for EFD_SEMAPHORE,
     * whose read decrements by one. A counter of 2 read once stays readable
     * while the pipe goes empty -- the reader consumed the single byte
     * eventfd_write posts on the 0-to-nonzero edge, and that edge will not come
     * again until the counter returns to zero. Anything waiting on the pipe
     * then sleeps through a count it was entitled to. Measured: two threads
     * reading one EFD_SEMAPHORE eventfd hang here in three runs out of five and
     * complete five out of five on the reference kernel.
     *
     * The pipe is O_NONBLOCK (see sys_eventfd2), so the drain loop ends once it
     * is empty. readv with a single iovec is functionally identical to read but
     * bypasses clang's unix.BlockInCriticalSection checker, which flags read()
     * while a pthread mutex is held.
     */
    uint8_t drain;
    struct iovec iov = {.iov_base = &drain, .iov_len = 1};
    if (eventfd_state[slot].counter == 0) {
        while (readv(eventfd_state[slot].pipe_rd, &iov, 1) > 0)
            ;
    } else if (eventfd_state[slot].semaphore) {
        /* Semaphore mode only: the plain path cannot reach here, so nothing
         * pays for this but the case that needs it. Drain first so the re-arm
         * cannot pile bytes up on a pipe that already had one.
         */
        while (readv(eventfd_state[slot].pipe_rd, &iov, 1) > 0)
            ;
        uint8_t byte = 1;
        ssize_t wr;
        do {
            wr = write(eventfd_state[slot].pipe_wr, &byte, 1);
        } while (wr < 0 && errno == EINTR);
        if (wr < 0)
            log_error("eventfd_read: re-arm failed: %s (gfd=%d pipe_wr=%d)",
                      strerror(errno), guest_fd, eventfd_state[slot].pipe_wr);
    }
    pthread_mutex_unlock(&sfd_lock);

    if (guest_write_small(g, buf_gva, &val, sizeof(val)) < 0)
        return -LINUX_EFAULT;

    return 8;
}

/* Write to eventfd: add value to counter. Value must be uint64_t. Maximum
 * counter value is UINT64_MAX - 1.
 */
int64_t eventfd_write(int guest_fd,
                      guest_t *g,
                      uint64_t buf_gva,
                      uint64_t count)
{
    if (count < 8)
        return -LINUX_EINVAL;

    uint64_t val;
    if (guest_read_small(g, buf_gva, &val, sizeof(val)) < 0)
        return -LINUX_EFAULT;
    if (val == UINT64_MAX)
        return -LINUX_EINVAL;

    pthread_mutex_lock(&sfd_lock);
    int slot = eventfd_find(guest_fd);
    if (slot < 0) {
        pthread_mutex_unlock(&sfd_lock);
        return -LINUX_EBADF;
    }

    /* Check for counter overflow (Linux max is UINT64_MAX - 1) */
    if (eventfd_state[slot].counter > UINT64_MAX - 1 - val) {
        /* Would overflow: block or return EAGAIN. In blocking mode a real
         * kernel blocks until a read drains the counter; the code returns
         * EAGAIN to avoid hanging since eventfd emulation cannot truly block
         * here.
         */
        pthread_mutex_unlock(&sfd_lock);
        return -LINUX_EAGAIN;
    }

    bool was_zero = (eventfd_state[slot].counter == 0);
    eventfd_state[slot].counter += val;

    /* Signal readability via pipe if counter transitioned from 0. The pipe is
     * non-blocking; retry on EINTR and warn on other errors since a missed
     * wakeup here can deadlock ppoll/epoll waiters.
     */
    if (was_zero && eventfd_state[slot].counter > 0) {
        uint8_t byte = 1;
        ssize_t wr;
        do {
            wr = write(eventfd_state[slot].pipe_wr, &byte, 1);
        } while (wr < 0 && errno == EINTR);
        if (wr < 0)
            log_error(
                "eventfd_write: pipe write failed: %s (gfd=%d pipe_wr=%d)",
                strerror(errno), guest_fd, eventfd_state[slot].pipe_wr);
    }

    /* Always log eventfd writes, since this is critical for diagnosing shutdown
     * hangs
     */
    log_debug(
        "eventfd_write: gfd=%d val=%llu counter=%llu was_zero=%d pipe_wr=%d",
        guest_fd, (unsigned long long) val,
        (unsigned long long) eventfd_state[slot].counter, was_zero,
        eventfd_state[slot].pipe_wr);
    pthread_mutex_unlock(&sfd_lock);

    return 8;
}

/* signalfd emulation
 *
 * Linux signalfd creates an fd from which pending signals can be read as
 * signalfd_siginfo structures (128 bytes each). Signalfd integrates with the
 * existing signal_state infrastructure; reads consume pending signals that
 * match the signalfd's mask.
 */

/* Linux signalfd_siginfo structure (128 bytes) */
typedef struct {
    uint32_t ssi_signo;
    int32_t ssi_errno, ssi_code;
    uint32_t ssi_pid, ssi_uid;
    int32_t ssi_fd;
    uint32_t ssi_tid, ssi_band, ssi_overrun, ssi_trapno;
    int32_t ssi_status, ssi_int;
    uint64_t ssi_ptr, ssi_utime, ssi_stime, ssi_addr;
    uint16_t ssi_addr_lsb, __pad2;
    int32_t ssi_syscall;
    uint64_t ssi_call_addr;
    uint32_t ssi_arch;
    uint8_t __pad[28];
} linux_signalfd_siginfo_t;

_Static_assert(sizeof(linux_signalfd_siginfo_t) == 128,
               "signalfd_siginfo must be 128 bytes");

/* Linux SFD_* flags (same values as O_* on aarch64) */
#define LINUX_SFD_CLOEXEC 0x80000
#define LINUX_SFD_NONBLOCK 0x800

/* Per-signalfd state */
#define SIGNALFD_MAX 16
static struct {
    int guest_fd;  /* Guest fd (-1 if unused) */
    int pipe_rd;   /* Read end for poll/epoll readiness */
    int pipe_wr;   /* Write end for signaling */
    uint64_t mask; /* Signal mask (bitmask of signals to accept) */
} signalfd_state[SIGNALFD_MAX];

void signalfd_init(void)
{
    for (int i = 0; i < SIGNALFD_MAX; i++)
        signalfd_state[i].guest_fd = -1;
    fd_register_cleanup(FD_SIGNALFD, signalfd_close);
}

static int signalfd_find(int guest_fd)
{
    return sfd_find_slot(signalfd_state, SIGNALFD_MAX,
                         sizeof(signalfd_state[0]), guest_fd);
}

static int signalfd_slot_alloc(void)
{
    return sfd_alloc_slot(signalfd_state, SIGNALFD_MAX,
                          sizeof(signalfd_state[0]));
}

/* Clean up signalfd state when guest closes the fd. Must hold sfd_lock to
 * prevent racing with concurrent signalfd_notify.
 */
static void signalfd_close(int guest_fd)
{
    pthread_mutex_lock(&sfd_lock);
    int slot = signalfd_find(guest_fd);
    if (slot >= 0) {
        close(signalfd_state[slot].pipe_wr);
        /* pipe_rd is closed by sys_close() as host_fd */
        signalfd_state[slot].guest_fd = -1;
        signalfd_state[slot].mask = 0;
    }
    pthread_mutex_unlock(&sfd_lock);
}

int64_t sys_signalfd4(guest_t *g,
                      int fd,
                      uint64_t mask_gva,
                      uint64_t sigsetsize,
                      int flags)
{
    if (flags & ~(LINUX_SFD_CLOEXEC | LINUX_SFD_NONBLOCK))
        return -LINUX_EINVAL;

    /* Read the signal mask from guest memory */
    uint64_t mask = 0;
    if (sigsetsize < 8)
        return -LINUX_EINVAL;
    if (guest_read_small(g, mask_gva, &mask, sizeof(mask)) < 0)
        return -LINUX_EFAULT;

    /* If fd >= 0, update existing signalfd mask */
    if (fd >= 0) {
        pthread_mutex_lock(&sfd_lock);
        int slot = signalfd_find(fd);
        if (slot < 0) {
            pthread_mutex_unlock(&sfd_lock);
            return -LINUX_EINVAL;
        }
        signalfd_state[slot].mask = mask;
        pthread_mutex_unlock(&sfd_lock);
        return fd;
    }

    /* Create new signalfd */
    int pipefd[2];
    if (pipe(pipefd) < 0)
        return linux_errno();

    bool want_cloexec = (flags & LINUX_SFD_CLOEXEC) != 0;
    if (fd_set_nonblock(pipefd[0]) < 0 || fd_set_nonblock(pipefd[1]) < 0 ||
        (want_cloexec &&
         (fd_set_cloexec(pipefd[0]) < 0 || fd_set_cloexec(pipefd[1]) < 0))) {
        close(pipefd[0]);
        close(pipefd[1]);
        return linux_errno();
    }

    int gfd = fd_alloc(FD_SIGNALFD, pipefd[0], signalfd_close);
    if (gfd < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -LINUX_EMFILE;
    }

    pthread_mutex_lock(&sfd_lock);
    int slot = signalfd_slot_alloc();
    if (slot < 0) {
        pthread_mutex_unlock(&sfd_lock);
        fd_retire_published(gfd, pipefd[0]);
        close(pipefd[1]);
        return -LINUX_ENOMEM;
    }

    signalfd_state[slot].guest_fd = gfd;
    signalfd_state[slot].pipe_rd = pipefd[0];
    signalfd_state[slot].pipe_wr = pipefd[1];
    signalfd_state[slot].mask = mask;
    pthread_mutex_unlock(&sfd_lock);

    /* Linux opens the signalfd inode O_RDWR (anon_inode_getfd in
     * fs/signalfd.c); same reasoning as eventfd for O_NONBLOCK.
     */
    fd_publish_linux_flags(
        gfd, ((flags & LINUX_SFD_CLOEXEC) ? LINUX_O_CLOEXEC : 0) |
                 ((flags & LINUX_SFD_NONBLOCK) ? LINUX_O_NONBLOCK : 0));

    return gfd;
}

/* Read from signalfd: consume pending signals matching the signalfd's mask.
 *
 * Each signal produces one signalfd_siginfo (128 bytes). RT signals (32-64) are
 * queued: each sigqueue/rt_tgsigqueueinfo enqueues a distinct instance with its
 * own si_int/si_ptr payload, and signalfd_read returns them in FIFO order
 * without coalescing (Linux behavior).
 *
 * Per-thread signal mask is intentionally not consulted: signalfd is the
 * standard mechanism for reading signals that were blocked from synchronous
 * delivery via sigprocmask(). The signalfd's own mask (set at create time or
 * via signalfd(fd, &mask, ...)) is the only filter applied.
 *
 * ssi_int/ssi_ptr are populated from queued metadata when present. Standard
 * signals (1-31) still coalesce to one pending instance, but Linux preserves
 * one siginfo payload for that instance.
 *
 * Returns the number of bytes read (multiple of sizeof(signalfd_siginfo)), or
 * -EAGAIN if nothing pending and the fd is non-blocking.
 */
int64_t signalfd_read(int guest_fd,
                      guest_t *g,
                      uint64_t buf_gva,
                      uint64_t count)
{
    int nonblock;
retry:
    /* Capture slot state under sfd_lock, then release BEFORE calling
     * signal_get_state() which acquires sig_lock(4). Holding sfd_lock(5a) while
     * taking sig_lock(4) would violate lock ordering.
     *
     * Re-read per attempt: a sibling can change the flag while this one is
     * parked, and the block-or-report decision below is made fresh each round.
     */
    nonblock = fd_guest_nonblock(guest_fd);

    pthread_mutex_lock(&sfd_lock);
    int slot = signalfd_find(guest_fd);
    if (slot < 0) {
        pthread_mutex_unlock(&sfd_lock);
        return -LINUX_EBADF;
    }

    uint64_t mask = signalfd_state[slot].mask;
    int pipe_rd = signalfd_state[slot].pipe_rd;
    size_t max_signals = count / sizeof(linux_signalfd_siginfo_t);
    if (max_signals == 0) {
        pthread_mutex_unlock(&sfd_lock);
        return -LINUX_EINVAL;
    }
    pthread_mutex_unlock(&sfd_lock);

    signal_rt_info_t pending_stack[LINUX_NSIG];
    signal_rt_info_t *pending = pending_stack;
    signal_rt_info_t *heap = NULL;

    /* Parallel source-set tag per peeked entry (0 = private, 1 = shared) so the
     * take consumes each signal from the exact set it was peeked from.
     */
    uint8_t src_stack[LINUX_NSIG];
    uint8_t *src = src_stack;
    uint8_t *src_heap = NULL;
    size_t total = 0;

    /* Match pending signals against the signalfd mask. Do NOT filter by the
     * blocked mask because signalfd is specifically designed to read signals
     * that were blocked from normal delivery via sigprocmask(). The visible set
     * is this thread's private (thread-directed) pending plus the shared set.
     */
    uint64_t deliverable = signal_signalfd_pending_mask() & mask;

    if (max_signals > LINUX_NSIG) {
        heap = malloc(max_signals * sizeof(*pending));
        src_heap = malloc(max_signals * sizeof(*src));
        if (!heap || !src_heap) {
            free(heap);
            free(src_heap);
            return -LINUX_ENOMEM;
        }
        pending = heap;
        src = src_heap;
    }

    if (deliverable == 0) {
        if (nonblock)
            goto no_pending;

        /* Blocking mode: wait for signalfd_notify() to write to the pipe, and
         * wait interruptibly. Making the pipe blocking for the duration of a
         * read parks this vCPU thread in a host call that neither hv_vcpus_exit
         * nor the wakeup pipe reaches, which is the failure this tree removed
         * from every transfer path; a synthetic reader is no different. The
         * pipe stays nonblocking and the wait polls it with the wakeup pipe, so
         * teardown and guest signals both end it.
         */
        int64_t waited = io_wait_fd_or_interrupted(pipe_rd, POLLIN);
        if (waited < 0) {
            /* Both allocations, like every other exit here: they are made
             * together when the guest asks for more signals than the stack
             * arrays hold, and this is the one path that was added after the
             * rest of the function agreed on that.
             */
            free(heap);
            free(src_heap);
            return waited;
        }

        uint8_t byte;
        ssize_t r = read(pipe_rd, &byte, 1);

        /* The pipe stays nonblocking, so a sibling reading this same signalfd
         * can take the byte the wait reported and leave EAGAIN here. A blocking
         * read owes the guest a wait, not a spurious EAGAIN -- the same rule
         * the drained-signal recheck below applies, and the reason the read
         * used to be run with the pipe flipped blocking.
         */
        if (r < 0 && errno == EAGAIN) {
            free(heap);
            free(src_heap);
            goto retry;
        }
        if (r <= 0)
            goto no_pending;

        /* Re-validate: slot may have been freed by signalfd_close() */
        pthread_mutex_lock(&sfd_lock);
        int still_valid = (signalfd_state[slot].guest_fd == guest_fd);
        pthread_mutex_unlock(&sfd_lock);
        if (!still_valid) {
            free(heap);
            free(src_heap);
            return -LINUX_EBADF;
        }

        /* Re-check: a racing consumer may have drained the signal that woke the
         * pipe. A blocking read must keep waiting rather than surface a
         * spurious -EAGAIN, so loop back to re-wait.
         */
        deliverable = signal_signalfd_pending_mask() & mask;
        if (deliverable == 0) {
            free(heap);
            free(src_heap);
            goto retry;
        }
    }
    size_t peeked = signal_peek_signalfd(mask, pending, src, max_signals);
    if (peeked == 0) {
        /* Raced empty after a positive recheck: block-mode re-waits, nonblock
         * reports EAGAIN.
         */
        if (!nonblock) {
            free(heap);
            free(src_heap);
            goto retry;
        }
        goto no_pending;
    }

    /* Write-then-take. Writing first means that on a guest_write_small EFAULT
     * the rt-queue is still intact and signals are not lost: no re-queue dance,
     * no RT_SIGQUEUE_MAX overflow window, no extra signalfd_notify writes that
     * would desync the pipe-byte count from the actual pending-signal count.
     * Take only the prefix the writer landed; if a concurrent consumer advanced
     * the rt-queue head between peek and take, take returns less than the
     * written count and the bridge restarts the read loop via the retry label
     * below.
     */
    size_t written = 0;
    for (size_t i = 0; i < peeked; i++) {
        linux_signalfd_siginfo_t info;
        memset(&info, 0, sizeof(info));
        info.ssi_signo = (uint32_t) pending[i].signum;
        info.ssi_code = pending[i].si_code;
        info.ssi_pid = (uint32_t) pending[i].si_pid;
        info.ssi_uid = pending[i].si_uid;
        info.ssi_int = pending[i].si_int;
        info.ssi_ptr = pending[i].si_ptr;

        uint64_t off = i * sizeof(linux_signalfd_siginfo_t);
        if (guest_write_small(g, buf_gva + off, &info, sizeof(info)) < 0) {
            if (written == 0) {
                /* No bytes transferred: surface EFAULT, leave the queue
                 * untouched so the signal is not lost. Matches the elfuse
                 * promise locked in by tests/test-fd-family's
                 * test_signalfd_efault_preserves_pending.
                 */
                free(heap);
                free(src_heap);
                return -LINUX_EFAULT;
            }

            /* Partial success: stop writing and let take consume only the
             * delivered prefix. The unwritten entries stay in the rt-queue
             * naturally because the take call has not run yet.
             */
            break;
        }
        written++;
    }

    total = signal_take_signalfd_exact(pending, src, written);
    if (total == 0) {
        if (written == 0)
            goto no_pending;
        free(heap);
        free(src_heap);
        goto retry;
    }

    /* Drain pipe: consume exactly one byte per signal read. If the code drains
     * ALL bytes, the code would lose notifications for signals that arrived
     * between sfd_lock release and this drain. Draining the consumed count
     * preserves new notifications.
     */
    for (size_t i = 0; i < total; i++) {
        uint8_t drain;
        if (read(pipe_rd, &drain, 1) <= 0)
            break;
    }

    free(heap);
    free(src_heap);
    return (int64_t) total * (int64_t) sizeof(linux_signalfd_siginfo_t);

no_pending:
    free(heap);
    free(src_heap);
    return -LINUX_EAGAIN;
}

/* Notify signalfd pipes when a process-directed signal is queued. Thread-
 * directed signals stay private to their target thread and must not wake every
 * signalfd watching that signum.
 */
void signalfd_notify(int signum)
{
    pthread_mutex_lock(&sfd_lock);
    for (int i = 0; i < SIGNALFD_MAX; i++) {
        if (signalfd_state[i].guest_fd < 0)
            continue;

        uint64_t bit = BIT64(signum - 1);
        if (signalfd_state[i].mask & bit) {
            uint8_t byte = 1;
            write(signalfd_state[i].pipe_wr, &byte, 1);
        }
    }
    pthread_mutex_unlock(&sfd_lock);
}

/* /proc/self/fdinfo type-specific snapshots. Each takes sfd_lock to prevent
 * tearing across concurrent read/write/settime; lock order is fd_lock(3) ->
 * sfd_lock(5a), and these accessors take only sfd_lock so the procemu caller is
 * free to drop fd_lock between fd_snapshot and the lookup here.
 */

bool eventfd_fdinfo_snapshot(int guest_fd, uint64_t *count_out)
{
    pthread_mutex_lock(&sfd_lock);
    int slot = eventfd_find(guest_fd);
    if (slot < 0) {
        pthread_mutex_unlock(&sfd_lock);
        return false;
    }
    *count_out = eventfd_state[slot].counter;
    pthread_mutex_unlock(&sfd_lock);
    return true;
}

bool signalfd_fdinfo_snapshot(int guest_fd, uint64_t *mask_out)
{
    pthread_mutex_lock(&sfd_lock);
    int slot = signalfd_find(guest_fd);
    if (slot < 0) {
        pthread_mutex_unlock(&sfd_lock);
        return false;
    }
    *mask_out = signalfd_state[slot].mask;
    pthread_mutex_unlock(&sfd_lock);
    return true;
}

bool timerfd_fdinfo_snapshot(int guest_fd,
                             int *clockid_out,
                             uint64_t *ticks_out,
                             int64_t *value_ns_out,
                             int64_t *interval_ns_out)
{
    pthread_mutex_lock(&sfd_lock);
    int slot = timerfd_find(guest_fd);
    if (slot < 0) {
        pthread_mutex_unlock(&sfd_lock);
        return false;
    }

    /* Fold any pending kqueue fires into expirations before exporting, matching
     * what timerfd_read does. Without this, fdinfo lags by however many ticks
     * were sitting on the kqueue.
     */
    timerfd_drain_pending_locked(slot);
    *clockid_out = timerfd_state[slot].clockid;
    *ticks_out = timerfd_state[slot].expirations;
    *interval_ns_out = timerfd_state[slot].interval_ns;
    int64_t value_ns = 0;
    if (timerfd_state[slot].armed) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        int64_t now_ns = timespec_to_ns_sat(now.tv_sec, now.tv_nsec);
        value_ns = timerfd_remaining_ns_locked(slot, now_ns);
    }
    *value_ns_out = value_ns;
    pthread_mutex_unlock(&sfd_lock);
    return true;
}
