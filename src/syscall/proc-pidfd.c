/*
 * pidfd helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/event.h>
#include <unistd.h>

#include "utils.h"

#include "syscall/internal.h"
#include "syscall/proc.h"
#include "syscall/proc-pidfd.h"
#include "syscall/signal.h"

#define PIDFD_TABLE_SIZE 32

/* An entry belongs to an open file description, not to a guest fd number:
 * dup(2) and F_DUPFD hand the alias the same ofd_id, and the target stays
 * watched until the last name for it closes. Keying by number made a dup report
 * the target exited (the original's close dropped the shared write end) and
 * answer EBADF to pidfd_send_signal and waitid(P_PIDFD).
 */
typedef struct {
    bool active;
    uint64_t ofd_id; /* reserved before the slot is published; never 0 */
    int64_t guest_pid;
    pid_t host_pid; /* what the monitor watches, carried to a fork child */
    int write_end;
    int pins;     /* creations and dups in flight, which no sweep may retire */
    uint64_t gen; /* names this entry for the monitor thread */
} pidfd_entry_t;

static pidfd_entry_t pidfd_table[PIDFD_TABLE_SIZE];
static uint64_t pidfd_next_gen;
static pthread_mutex_t pidfd_lock = PTHREAD_MUTEX_INITIALIZER;

static pidfd_entry_t *pidfd_find_free_entry(void)
{
    for (int i = 0; i < PIDFD_TABLE_SIZE; i++) {
        if (!pidfd_table[i].active)
            return &pidfd_table[i];
    }
    return NULL;
}

static pidfd_entry_t *pidfd_find_ofd_entry(uint64_t ofd_id)
{
    if (ofd_id == 0)
        return NULL;
    for (int i = 0; i < PIDFD_TABLE_SIZE; i++) {
        if (pidfd_table[i].active && pidfd_table[i].ofd_id == ofd_id)
            return &pidfd_table[i];
    }
    return NULL;
}

static pidfd_entry_t *pidfd_find_gen_entry(uint64_t gen)
{
    for (int i = 0; i < PIDFD_TABLE_SIZE; i++) {
        if (pidfd_table[i].active && pidfd_table[i].gen == gen)
            return &pidfd_table[i];
    }
    return NULL;
}

static void pidfd_cleanup(int guest_fd);

/* Caller holds pidfd_lock. */
static void pidfd_complete_entry(pidfd_entry_t *entry)
{
    if (entry->write_end < 0)
        return;
    uint8_t byte = 0;
    (void) write(entry->write_end, &byte, 1);
    close(entry->write_end);
    entry->write_end = -1;
}

/* Complete one pidfd without touching others that watch the same target. */
static void pidfd_complete_one(uint64_t gen)
{
    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_gen_entry(gen);
    if (entry)
        pidfd_complete_entry(entry);
    pthread_mutex_unlock(&pidfd_lock);
}

/* Retire every unpinned entry no fd_table slot names any more. Caller holds
 * fd_lock and then pidfd_lock, so the set of live slots cannot change under the
 * scan. A close hook only learns the number it closed, which by then is already
 * FD_CLOSED, so asking the table is the one way to tell whether that was the
 * last alias.
 */
static void pidfd_sweep_locked(void)
{
    bool live[PIDFD_TABLE_SIZE] = {false};
    for (int fd = 0; fd < FD_TABLE_SIZE; fd++) {
        if (fd_table[fd].type != FD_PIDFD)
            continue;
        pidfd_entry_t *entry = pidfd_find_ofd_entry(fd_table[fd].ofd_id);
        if (entry)
            live[entry - pidfd_table] = true;
    }
    for (int i = 0; i < PIDFD_TABLE_SIZE; i++) {
        pidfd_entry_t *entry = &pidfd_table[i];
        if (!entry->active || entry->pins > 0 || live[i])
            continue;
        if (entry->write_end >= 0)
            close(entry->write_end);
        entry->write_end = -1;
        entry->active = false;
    }
}

static void pidfd_sweep(void)
{
    pthread_mutex_lock(&fd_lock);
    pthread_mutex_lock(&pidfd_lock);
    pidfd_sweep_locked();
    pthread_mutex_unlock(&pidfd_lock);
    pthread_mutex_unlock(&fd_lock);
}

bool pidfd_pin(uint64_t ofd_id)
{
    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_ofd_entry(ofd_id);
    if (entry)
        entry->pins++;
    pthread_mutex_unlock(&pidfd_lock);
    return entry != NULL;
}

void pidfd_unpin(uint64_t ofd_id)
{
    pthread_mutex_lock(&fd_lock);
    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_ofd_entry(ofd_id);
    if (entry)
        entry->pins--;
    pidfd_sweep_locked();
    pthread_mutex_unlock(&pidfd_lock);
    pthread_mutex_unlock(&fd_lock);
}

void pidfd_init(void)
{
    fd_register_cleanup(FD_PIDFD, pidfd_cleanup);
}

static void pidfd_cleanup(int guest_fd)
{
    (void) guest_fd;
    pidfd_sweep();
}

static void *pidfd_monitor_thread(void *arg)
{
    int64_t *ctx = (int64_t *) arg;
    int64_t gpid = ctx[0];
    pid_t hpid = (pid_t) ctx[1];
    uint64_t gen = (uint64_t) ctx[2];
    free(arg);

    if (kill(hpid, 0) < 0 && errno == ESRCH) {
        proc_pidfd_notify_exit(gpid);
        return NULL;
    }

    int kq = kqueue();
    if (kq < 0) {
        pidfd_complete_one(gen);
        return NULL;
    }

    struct kevent ev;
    EV_SET(&ev, hpid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);
    if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0) {
        /* ESRCH means the target exited before registration, which every pidfd
         * on it should see. Any other failure says nothing about the target, so
         * only this fd is completed.
         */
        bool gone = errno == ESRCH;
        close(kq);
        if (gone)
            proc_pidfd_notify_exit(gpid);
        else
            pidfd_complete_one(gen);
        return NULL;
    }

    struct kevent out;
    int n;
    do {
        n = kevent(kq, NULL, 0, &out, 1, NULL);
    } while (n < 0 && errno == EINTR);
    close(kq);

    if (n > 0 && out.filter == EVFILT_PROC)
        proc_pidfd_notify_exit(gpid);
    else
        pidfd_complete_one(gen);

    return NULL;
}

static bool pidfd_start_monitor(int64_t target_pid,
                                pid_t host_pid,
                                uint64_t gen)
{
    int64_t *ctx = malloc(3 * sizeof(int64_t));
    if (!ctx)
        return false;
    ctx[0] = target_pid;
    ctx[1] = (int64_t) host_pid;
    ctx[2] = (int64_t) gen;

    bool ok = false;
    pthread_t thr;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) == 0) {
        ok = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0 &&
             pthread_create(&thr, &attr, pidfd_monitor_thread, ctx) == 0;
        pthread_attr_destroy(&attr);
    }
    if (!ok)
        free(ctx);
    return ok;
}

/* fixed_fd >= 0 installs at that slot (the fork rebuild), otherwise at the
 * lowest free one. exited publishes the fd already complete.
 */
static int pidfd_install(int fixed_fd,
                         int64_t target_pid,
                         pid_t host_pid,
                         bool exited)
{
    int pfd[2];
    if (pipe(pfd) < 0)
        return -LINUX_EMFILE;
    if (fd_set_cloexec(pfd[0]) < 0 || fd_set_cloexec(pfd[1]) < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return linux_errno();
    }

    /* Register and bind before publishing: the slot is visible to every sibling
     * the moment the allocation returns, and a sibling that dups or closes it
     * must find the entry under the description it names. The description id is
     * reserved first so the entry carries it from the start; binding after the
     * publish left a window in which a dup made an alias the registry did not
     * know and a close then retired the entry under it. The pin keeps a close
     * sweep from retiring the entry before the slot exists.
     */
    uint64_t ofd_id = fd_reserve_ofd_id();
    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_free_entry();
    if (!entry) {
        pthread_mutex_unlock(&pidfd_lock);
        close(pfd[0]);
        close(pfd[1]);
        return -LINUX_EMFILE;
    }
    *entry = (pidfd_entry_t) {
        .active = true,
        .guest_pid = target_pid,
        .host_pid = host_pid,
        .write_end = pfd[1],
        .pins = 1,
        .gen = ++pidfd_next_gen,
        .ofd_id = ofd_id,
    };
    uint64_t gen = entry->gen;
    if (exited)
        pidfd_complete_entry(entry);
    pthread_mutex_unlock(&pidfd_lock);

    /* An identity-only alias spec carries the reserved id onto the slot; a
     * pidfd's pipe cannot block, so the probe the alias path skips would have
     * decided nothing.
     */
    fd_alias_spec_t spec = fd_alias_identity(ofd_id, LINUX_O_CLOEXEC);
    int gfd = fixed_fd >= 0
                  ? fd_alloc_alias_at(&spec, fixed_fd, FD_PIDFD, pfd[0],
                                      pidfd_cleanup, NULL)
                  : fd_alloc_alias(&spec, FD_PIDFD, pfd[0], pidfd_cleanup);

    /* Drop the pin. If a sibling already closed every name for the description,
     * or the allocation failed, the sweep retires the entry with its write end.
     */
    pidfd_unpin(ofd_id);

    if (gfd < 0) {
        close(pfd[0]);
        return -LINUX_EMFILE;
    }

    /* host_pid <= 0 means the target lives inside this host process -- the
     * caller itself, or a CLONE_VM child, which holds a guest tid but no host
     * pid of its own. Neither can be watched from here, and neither has exited,
     * so the fd stays unreadable rather than being completed.
     */
    if (exited || host_pid <= 0)
        return gfd;

    /* Nothing will ever mark this fd readable without a monitor behind it, so
     * complete it rather than leave the guest polling forever. Only this fd:
     * other pidfds on the same live target keep their own monitors. A target
     * that has already exited needs no special case: the monitor thread finds
     * it gone and completes the fd the same way.
     */
    if (!pidfd_start_monitor(target_pid, host_pid, gen))
        pidfd_complete_one(gen);

    return gfd;
}

int pidfd_create(guest_t *g, int64_t target_pid, pid_t host_pid)
{
    (void) g;
    return pidfd_install(-1, target_pid, host_pid, false);
}

void pidfd_fork_snapshot_locked(uint64_t ofd_id, pidfd_fork_state_t *out)
{
    *out = (pidfd_fork_state_t) {.target_pid = -1};
    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_ofd_entry(ofd_id);
    if (entry) {
        out->target_pid = entry->guest_pid;
        out->exited = entry->write_end < 0;

        /* A pidfd on this process could not be watched here, but the child is
         * another host process and can watch this one. A CLONE_VM target stays
         * unwatched: it has no host pid, and this process outliving it says
         * nothing about when it exits.
         */
        if (entry->guest_pid == proc_get_pid())
            out->host_pid = getpid();
        else
            out->host_pid = entry->host_pid > 0 ? entry->host_pid : 0;
    }
    pthread_mutex_unlock(&pidfd_lock);
}

int pidfd_fork_restore(int guest_fd, const pidfd_fork_state_t *state)
{
    if (state->target_pid <= 0)
        return -LINUX_EBADF;
    return pidfd_install(guest_fd, state->target_pid, state->host_pid,
                         state->exited != 0);
}

void proc_pidfd_notify_exit(int64_t exited_pid)
{
    pthread_mutex_lock(&pidfd_lock);
    for (int i = 0; i < PIDFD_TABLE_SIZE; i++) {
        if (pidfd_table[i].active && pidfd_table[i].guest_pid == exited_pid)
            pidfd_complete_entry(&pidfd_table[i]);
    }
    pthread_mutex_unlock(&pidfd_lock);
}

int64_t proc_pidfd_lookup_pid(int guest_fd)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return -1;

    /* One window over the slot and the registry, so the type check and the
     * description it names come from the same open: a number closed and reused
     * in between cannot reach the old target.
     */
    int64_t pid = -1;
    pthread_mutex_lock(&fd_lock);
    if (fd_table[guest_fd].type == FD_PIDFD) {
        pthread_mutex_lock(&pidfd_lock);
        pidfd_entry_t *entry = pidfd_find_ofd_entry(fd_table[guest_fd].ofd_id);
        if (entry)
            pid = entry->guest_pid;
        pthread_mutex_unlock(&pidfd_lock);
    }
    pthread_mutex_unlock(&fd_lock);
    return pid;
}

int64_t sys_pidfd_open(guest_t *g, int64_t pid, unsigned int flags)
{
    if (flags != 0)
        return -LINUX_EINVAL;

    /* The kernel rejects a non-positive pid before it looks anything up. */
    if (pid <= 0)
        return -LINUX_EINVAL;

    if (pid == proc_get_pid())
        return pidfd_create(g, pid, 0);

    pid_t host_pid = proc_resolve_guest_pid(pid);
    if (host_pid > 0)
        return pidfd_create(g, pid, host_pid);

    return -LINUX_ESRCH;
}

int64_t sys_pidfd_send_signal(guest_t *g,
                              int pidfd,
                              int sig,
                              uint64_t info_gva,
                              unsigned int flags)
{
    (void) g;
    (void) info_gva;

    if (flags != 0)
        return -LINUX_EINVAL;

    int64_t pid = proc_pidfd_lookup_pid(pidfd);
    if (pid < 0)
        return -LINUX_EBADF;

    if (sig < 0 || sig > 64)
        return -LINUX_EINVAL;

    if (pid == proc_get_pid()) {
        if (sig != 0)
            signal_queue_kill(sig);
        return 0;
    }

    pid_t host_pid = proc_resolve_guest_pid(pid);
    if (host_pid > 0) {
        if (sig == 0) {
            if (kill(host_pid, 0) < 0)
                return -LINUX_ESRCH;
            return 0;
        }
        if (proc_send_guest_signal(host_pid, pid, sig) < 0)
            return linux_errno();
        return 0;
    }

    return -LINUX_ESRCH;
}
