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

typedef struct {
    bool active;
    int guest_fd;
    int64_t guest_pid;
    int write_end;
    uint64_t gen; /* names this open across guest fd number reuse */
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

static pidfd_entry_t *pidfd_find_guest_fd_entry(int guest_fd)
{
    for (int i = 0; i < PIDFD_TABLE_SIZE; i++) {
        if (pidfd_table[i].active && pidfd_table[i].guest_fd == guest_fd)
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
    for (int i = 0; i < PIDFD_TABLE_SIZE; i++) {
        if (pidfd_table[i].active && pidfd_table[i].gen == gen) {
            pidfd_complete_entry(&pidfd_table[i]);
            break;
        }
    }
    pthread_mutex_unlock(&pidfd_lock);
}

void pidfd_init(void)
{
    fd_register_cleanup(FD_PIDFD, pidfd_cleanup);
}

static void pidfd_cleanup(int guest_fd)
{
    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_guest_fd_entry(guest_fd);
    if (entry) {
        if (entry->write_end >= 0)
            close(entry->write_end);
        entry->write_end = -1;
        entry->active = false;
    }
    pthread_mutex_unlock(&pidfd_lock);
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

int pidfd_create(guest_t *g, int64_t target_pid, pid_t host_pid)
{
    (void) g;
    int pfd[2];
    if (pipe(pfd) < 0)
        return -LINUX_EMFILE;
    if (fd_set_cloexec(pfd[0]) < 0 || fd_set_cloexec(pfd[1]) < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return linux_errno();
    }

    int gfd = fd_alloc(FD_PIDFD, pfd[0], pidfd_cleanup);
    if (gfd < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -LINUX_EMFILE;
    }

    /* Linux makes every pidfd close-on-exec, from pidfd_open and from
     * CLONE_PIDFD alike, and has no flag to ask for anything else.
     */
    fd_publish_linux_flags(gfd, LINUX_O_CLOEXEC);

    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_free_entry();
    if (!entry) {
        pthread_mutex_unlock(&pidfd_lock);
        fd_entry_t snap;
        if (fd_snapshot_and_close(gfd, &snap))
            fd_cleanup_entry(gfd, &snap);
        close(pfd[1]);
        return -LINUX_EMFILE;
    }

    entry->active = true;
    entry->guest_fd = gfd;
    entry->guest_pid = target_pid;
    entry->write_end = pfd[1];
    entry->gen = ++pidfd_next_gen;
    uint64_t gen = entry->gen;
    pthread_mutex_unlock(&pidfd_lock);

    /* host_pid <= 0 means the target lives inside this host process -- the
     * caller itself, or a CLONE_VM child, which holds a guest tid but no host
     * pid of its own. Neither can be watched from here, and neither has exited,
     * so the fd stays unreadable rather than being completed.
     */
    if (host_pid <= 0)
        return gfd;

    bool monitor_ok = false;
    {
        int64_t *ctx = malloc(3 * sizeof(int64_t));
        if (ctx) {
            ctx[0] = target_pid;
            ctx[1] = (int64_t) host_pid;
            ctx[2] = (int64_t) gen;
            pthread_t thr;
            pthread_attr_t attr;
            if (pthread_attr_init(&attr) == 0) {
                if (pthread_attr_setdetachstate(&attr,
                                                PTHREAD_CREATE_DETACHED) == 0 &&
                    pthread_create(&thr, &attr, pidfd_monitor_thread, ctx) ==
                        0) {
                    monitor_ok = true;
                } else {
                    free(ctx);
                }
                pthread_attr_destroy(&attr);
            } else {
                free(ctx);
            }
        }
    }

    /* Nothing will ever mark this fd readable without a monitor behind it, so
     * complete it rather than leave the guest polling forever. Only this fd:
     * other pidfds on the same live target keep their own monitors. A target
     * that has already exited needs no special case: the monitor thread finds
     * it gone and completes the fd the same way.
     */
    if (!monitor_ok)
        pidfd_complete_one(gen);

    return gfd;
}

void pidfd_set_target(int guest_fd, int64_t target_pid)
{
    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_guest_fd_entry(guest_fd);
    if (entry)
        entry->guest_pid = target_pid;
    pthread_mutex_unlock(&pidfd_lock);
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
    pthread_mutex_lock(&pidfd_lock);
    pidfd_entry_t *entry = pidfd_find_guest_fd_entry(guest_fd);
    if (entry) {
        int64_t pid = entry->guest_pid;
        pthread_mutex_unlock(&pidfd_lock);
        return pid;
    }
    pthread_mutex_unlock(&pidfd_lock);
    return -1;
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
            signal_queue(sig);
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
