/*
 * A reaped child's SIGCHLD does not reach a handler installed after the wait
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux decides whether a SIGCHLD is discarded when it generates it, at the
 * child's exit or at a kill: a handler installed later never runs for a
 * discarded one, and a kept one stays pending. lmbench's benchmp relies on this
 * between its two lat_fs phases.
 *
 * "late [case]" runs the cases that need ELFUSE_SIGNAL_DRAIN_DELAY_US on
 * elfuse, which keeps the child's record undrained when the parent acts, or
 * keeps a reparent handshake from being acknowledged.
 *
 * "exiting [case]" changes the action while a child is exiting with SIGCHLD
 * blocked; on elfuse it needs ELFUSE_SIGCHLD_DECIDE_DELAY_US, so the child has
 * read the parent's flag file but not yet appended its record.
 */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define ROUNDS 10
#define WATCH_NS (100 * 1000 * 1000L)

static volatile sig_atomic_t handler_runs;

static void on_sigchld(int sig)
{
    (void) sig;
    handler_runs++;
}

/* Sleep for the whole window, resuming after each interruption. */
static void watch_window(void)
{
    struct timespec left = {.tv_sec = 0, .tv_nsec = WATCH_NS};
    while (nanosleep(&left, &left) != 0 && errno == EINTR)
        ;
}

enum mode {
    HANDLER_FIRST, /* handler installed before the fork: runs once per child */
    REAP_DFL,      /* reaped under SIG_DFL, handler installed after: never */
    REAP_IGN,    /* auto-reaped under SIG_IGN, handler installed after: never */
    LATE_DFL,    /* waited with WNOWAIT under SIG_DFL, then a handler: never */
    LATE_MASKED, /* LATE_DFL, blocked before the handler, then unblocked */
    IGN_BLOCKED, /* auto-reaped under SIG_IGN while blocked, then unblocked */
    NO_WAIT,     /* exited under SIG_DFL, no wait, then a handler: never */
};

/* Fork a child that exits and wait for it, ROUNDS times, in @mode. The late
 * modes always wait with waitid and WNOWAIT. NO_WAIT reads the child's byte and
 * then EOF on the pipe, so the child is exiting, and lets two watch windows
 * pass for the exit to finish; it then watches four after the handler before
 * the reap: a wait call drains the record and would hide a decision made too
 * late.
 *
 * Returns the number of rounds whose handler count was wrong, or -1 on a setup
 * failure.
 */
static int bad_rounds(bool use_waitid, enum mode mode)
{
    struct sigaction before, catch;
    memset(&before, 0, sizeof(before));
    sigemptyset(&before.sa_mask);
    before.sa_handler =
        mode == REAP_IGN || mode == IGN_BLOCKED ? SIG_IGN : SIG_DFL;
    memset(&catch, 0, sizeof(catch));
    sigemptyset(&catch.sa_mask);
    catch.sa_handler = on_sigchld;
    catch.sa_flags = SA_RESTART;
    if (mode == HANDLER_FIRST)
        before = catch;
    bool ign = mode == REAP_IGN || mode == IGN_BLOCKED;
    bool late = mode == LATE_DFL || mode == LATE_MASKED;
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);

    int bad = 0;
    for (int round = 0; round < ROUNDS; round++) {
        handler_runs = 0;
        if (sigaction(SIGCHLD, &before, NULL) != 0)
            return -1;
        if (mode == IGN_BLOCKED && sigprocmask(SIG_BLOCK, &chld, NULL) != 0)
            return -1;
        int fds[2] = {-1, -1};
        if (mode == NO_WAIT && pipe(fds) != 0)
            return -1;
        pid_t pid = fork();
        if (pid < 0)
            return -1;
        if (pid == 0) {
            if (mode == NO_WAIT && write(fds[1], "x", 1) != 1)
                _exit(1);
            _exit(0);
        }
        if (mode == NO_WAIT) {
            char c;
            ssize_t n;
            int got = 0;
            close(fds[1]);
            while ((n = read(fds[0], &c, 1)) != 0) {
                if (n < 0 && errno == EINTR)
                    continue;
                if (n < 0 || got++)
                    return -1;
            }
            close(fds[0]);
            if (!got)
                return -1;
            watch_window();
            watch_window();
        }

        /* Under SIG_IGN the kernel reaps the child, and the wait returns ECHILD
         * once it is gone. WNOWAIT leaves the late modes' child a zombie.
         */
        if (mode != NO_WAIT && (use_waitid || late)) {
            siginfo_t info;
            memset(&info, 0, sizeof(info));
            int rc = waitid(P_PID, (id_t) pid, &info,
                            WEXITED | (late ? WNOWAIT : 0));
            if (ign ? rc != -1 || errno != ECHILD
                    : rc != 0 || info.si_pid != pid ||
                          info.si_code != CLD_EXITED)
                return -1;
        } else if (mode != NO_WAIT) {
            int status = 0;
            pid_t rc = waitpid(pid, &status, 0);
            if (ign ? rc != -1 || errno != ECHILD
                    : rc != pid || !WIFEXITED(status))
                return -1;
        }

        /* Linux queues SIGCHLD with the zombie, so the handler has run by the
         * time the wait returns.
         */
        bool late_run = mode == HANDLER_FIRST && handler_runs != 1;
        if (mode == LATE_MASKED && sigprocmask(SIG_BLOCK, &chld, NULL) != 0)
            return -1;
        if (mode != HANDLER_FIRST && sigaction(SIGCHLD, &catch, NULL) != 0)
            return -1;
        if ((mode == LATE_MASKED || mode == IGN_BLOCKED) &&
            sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0)
            return -1;
        for (int w = 0; w < (mode == NO_WAIT ? 4 : 1); w++)
            watch_window();
        /* The reap drains anything still queued for the zombie. */
        if ((late || mode == NO_WAIT) && waitpid(pid, NULL, 0) != pid)
            return -1;
        if (late_run || handler_runs != (mode == HANDLER_FIRST ? 1 : 0))
            bad++;
    }
    return bad;
}

/* Read until EOF; returns false unless exactly @want bytes arrived. */
static bool read_to_eof(int fd, int want)
{
    char c;
    ssize_t n;
    int got = 0;
    while ((n = read(fd, &c, 1)) != 0) {
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            return false;
        got++;
    }
    return got == want;
}

/* The late cases. Up to ADOPTED they run under SIG_DFL with SIGCHLD unblocked
 * in the calling thread; RESETHAND, THREAD_EXIT and VM_REAP run before the
 * unwaited exit, and each leaves SIGCHLD discarded again.
 */
enum event {
    NONE,        /* nothing */
    RESETHAND,   /* an SA_RESETHAND handler runs for a reaped child */
    THREAD_EXIT, /* a thread that blocked SIGCHLD exits */
    VM_REAP,     /* a CLONE_VM child that blocked SIGCHLD is reaped */
    ADOPTED,   /* the exiting child leaves an exited child to this subreaper */
    FLUSH_IGN, /* exit under a handler with SIGCHLD blocked, then SIG_IGN */
    FLUSH_DFL, /* FLUSH_IGN with SIG_DFL in place of SIG_IGN */
    UNBLOCKED, /* exit under SIG_DFL with SIGCHLD blocked, unblock, SIG_DFL */
};

static const char *const event_names[] = {
    "none", "resethand", "thread", "vm", "adopted", "ign", "dfl", "unblock"};

static void *block_and_exit(void *arg)
{
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    (void) arg;
    return (void *) (intptr_t) pthread_sigmask(SIG_BLOCK, &chld, NULL);
}

/* Raw syscalls: the child shares the parent's memory and libc state. */
static int vm_child(void *arg)
{
    (void) arg;
    uint64_t chld = 1ULL << (SIGCHLD - 1);
    long rc = syscall(SYS_rt_sigprocmask, SIG_BLOCK, &chld, NULL, sizeof(chld));
    syscall(SYS_exit, rc == 0 ? 0 : 1);
    return 1;
}

/* Returns false on a setup failure. */
static bool run_event(enum event ev)
{
    if (ev == RESETHAND) {
        /* SA_NODEFER, so the handler runs with SIGCHLD unblocked: only the
         * reset then makes SIGCHLD discarded again, not a mask change.
         */
        struct sigaction once;
        memset(&once, 0, sizeof(once));
        sigemptyset(&once.sa_mask);
        once.sa_handler = on_sigchld;
        once.sa_flags = SA_RESTART | SA_RESETHAND | SA_NODEFER;
        if (sigaction(SIGCHLD, &once, NULL) != 0)
            return false;
        pid_t pid = fork();
        if (pid == 0)
            _exit(0);
        if (pid < 0 || waitpid(pid, NULL, 0) != pid || handler_runs != 1)
            return false;
        handler_runs = 0;
    } else if (ev == THREAD_EXIT) {
        pthread_t t;
        void *blocked = NULL;
        int rc = pthread_create(&t, NULL, block_and_exit, NULL);
        if (rc == 0)
            rc = pthread_join(t, &blocked);
        if (rc == 0)
            rc = (int) (intptr_t) blocked;
        if (rc != 0) {
            errno = rc;
            return false;
        }

        /* pthread_join returns at the clear_child_tid wake, which on elfuse
         * comes before the exited thread's slot stops counting.
         */
        watch_window();
    } else if (ev == VM_REAP) {
        static char stack[64 * 1024];
        pid_t pid =
            clone(vm_child, stack + sizeof(stack), CLONE_VM | SIGCHLD, NULL);
        int status = 0;
        if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)
            return false;
    }
    return true;
}

/* NO_WAIT after @ev, ROUNDS times: the child, forked before @ev because a fork
 * republishes the parent's state, exits unwaited under SIG_DFL once released;
 * one watch window passes, a handler is installed and three more pass before
 * the reap. Under ADOPTED the child first leaves its own exited child, which
 * this process adopts as a subreaper. Under FLUSH_IGN and FLUSH_DFL the child
 * exits under the handler with SIGCHLD blocked, and SIG_IGN or SIG_DFL drops
 * the pending SIGCHLD before the handler is installed again and SIGCHLD is
 * unblocked. Under UNBLOCKED the child exits under SIG_DFL with SIGCHLD
 * blocked, and SIGCHLD is unblocked and SIG_DFL installed again before the
 * handler. The pipe's EOF means every child holding it is exiting.
 *
 * Returns the number of rounds in which the handler ran, or -1 on a setup
 * failure.
 */
static int late_rounds(enum event ev)
{
    struct sigaction dfl, catch, drop;
    memset(&dfl, 0, sizeof(dfl));
    sigemptyset(&dfl.sa_mask);
    dfl.sa_handler = SIG_DFL;
    catch = dfl;
    catch.sa_handler = on_sigchld;
    catch.sa_flags = SA_RESTART;
    drop = dfl;
    if (ev == FLUSH_IGN)
        drop.sa_handler = SIG_IGN;
    bool flush = ev == FLUSH_IGN || ev == FLUSH_DFL;
    bool blocked = flush || ev == UNBLOCKED;
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    if (ev == ADOPTED && prctl(PR_SET_CHILD_SUBREAPER, 1) != 0)
        return -1;

    int bad = 0;
    for (int round = 0; round < ROUNDS; round++) {
        handler_runs = 0;
        if (sigaction(SIGCHLD, flush ? &catch : &dfl, NULL) != 0)
            return -1;
        if (blocked && sigprocmask(SIG_BLOCK, &chld, NULL) != 0)
            return -1;
        int go[2], fds[2];
        if (pipe(go) != 0 || pipe(fds) != 0)
            return -1;
        pid_t pid = fork();
        if (pid < 0)
            return -1;
        if (pid == 0) {
            close(go[1]);
            close(fds[0]);
            if (!read_to_eof(go[0], 0))
                _exit(1);
            if (ev == ADOPTED) {
                int inner[2];
                if (pipe(inner) != 0)
                    _exit(1);
                pid_t grandchild = fork();
                if (grandchild == 0) {
                    close(inner[0]);
                    _exit(0);
                }
                close(inner[1]);
                if (grandchild < 0 || !read_to_eof(inner[0], 0))
                    _exit(1);
            }
            if (write(fds[1], "x", 1) != 1)
                _exit(1);
            _exit(0);
        }
        close(go[0]);
        close(fds[1]);
        bool ok = run_event(ev);
        close(go[1]);
        if (!ok)
            return -1;
        bool exited = read_to_eof(fds[0], 1);
        close(fds[0]);
        if (!exited)
            return -1;
        watch_window();
        if (ev == UNBLOCKED && sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0)
            return -1;
        if (blocked && sigaction(SIGCHLD, &drop, NULL) != 0)
            return -1;
        if (sigaction(SIGCHLD, &catch, NULL) != 0)
            return -1;
        if (flush && sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0)
            return -1;
        for (int w = 0; w < 3; w++)
            watch_window();

        /* Linux 6.18 keeps the zombie across SIG_IGN (measured with a probe);
         * elfuse reaps it when the handler replaces SIG_IGN, so FLUSH_IGN also
         * takes ECHILD.
         */
        if (waitpid(pid, NULL, 0) != pid &&
            !(ev == FLUSH_IGN && errno == ECHILD))
            return -1;
        if (ev == ADOPTED && waitpid(-1, NULL, 0) <= 0)
            return -1;
        if (handler_runs)
            bad++;
    }
    if (ev == ADOPTED && prctl(PR_SET_CHILD_SUBREAPER, 0) != 0)
        return -1;
    return bad;
}

/* A child exits while this process blocks SIGCHLD under the handler, ROUNDS
 * times: the SIGCHLD is pending by the time waitpid, or waitid when
 * @use_waitid, returns the child, because Linux generates it with the zombie.
 *
 * Returns the number of rounds in which it was not, or -1 on a setup failure.
 */
static int waited_rounds(bool use_waitid)
{
    struct sigaction catch, dfl;
    memset(&catch, 0, sizeof(catch));
    sigemptyset(&catch.sa_mask);
    dfl = catch;
    dfl.sa_handler = SIG_DFL;
    catch.sa_handler = on_sigchld;
    catch.sa_flags = SA_RESTART;
    sigset_t chld, pending;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    struct timespec second = {.tv_sec = 1, .tv_nsec = 0};
    if (sigaction(SIGCHLD, &catch, NULL) != 0 ||
        sigprocmask(SIG_BLOCK, &chld, NULL) != 0)
        return -1;

    int bad = 0;
    for (int round = 0; round < ROUNDS; round++) {
        pid_t pid = fork();
        if (pid < 0)
            return -1;
        if (pid == 0)
            _exit(0);
        siginfo_t info;
        memset(&info, 0, sizeof(info));
        if (use_waitid ? waitid(P_PID, (id_t) pid, &info, WEXITED) != 0
                       : waitpid(pid, NULL, 0) != pid)
            return -1;
        if (sigpending(&pending) != 0)
            return -1;
        if (!sigismember(&pending, SIGCHLD))
            bad++;

        /* Take it, or the late one, so the next round starts with none. */
        if (sigtimedwait(&chld, NULL, &second) != SIGCHLD)
            return -1;
    }
    if (sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0 ||
        sigaction(SIGCHLD, &dfl, NULL) != 0)
        return -1;
    return bad;
}

enum kill_mode {
    KILL_FLUSHED, /* blocked under the handler, then SIG_DFL drops it */
    KILL_IGNORED, /* under SIG_DFL, unblocked: discarded at the kill */
    KILL_KEPT,    /* under SIG_IGN, blocked: sig_ignored keeps it pending */
};

/* One child sends SIGCHLD with kill once per round, ROUNDS times, in @mode; one
 * watch window later, KILL_FLUSHED installs SIG_DFL, then each mode installs
 * the handler, and the blocked modes unblock. The handler runs only for
 * KILL_KEPT. The child exits after the last round, under SIG_DFL, so no exit's
 * record is in flight during a round.
 *
 * Returns the number of rounds with the wrong handler count, or -1 on a setup
 * failure.
 */
static int kill_rounds(enum kill_mode mode)
{
    struct sigaction catch, dfl, ign;
    memset(&dfl, 0, sizeof(dfl));
    sigemptyset(&dfl.sa_mask);
    dfl.sa_handler = SIG_DFL;
    ign = dfl;
    ign.sa_handler = SIG_IGN;
    catch = dfl;
    catch.sa_handler = on_sigchld;
    catch.sa_flags = SA_RESTART;
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    int sent[2], go[2];
    if (pipe(sent) != 0 || pipe(go) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        char c;
        close(sent[0]);
        close(go[1]);
        while (read(go[0], &c, 1) == 1) {
            if (kill(getppid(), SIGCHLD) != 0 || write(sent[1], "x", 1) != 1)
                _exit(1);
        }
        _exit(0);
    }
    close(sent[1]);
    close(go[0]);

    int bad = 0;
    for (int round = 0; round < ROUNDS; round++) {
        handler_runs = 0;
        char c;
        ssize_t got;
        const struct sigaction *first = mode == KILL_FLUSHED   ? &catch
                                        : mode == KILL_IGNORED ? &dfl
                                                               : &ign;
        bool blocked = mode != KILL_IGNORED;
        if (sigaction(SIGCHLD, first, NULL) != 0 ||
            (blocked && sigprocmask(SIG_BLOCK, &chld, NULL) != 0) ||
            write(go[1], "x", 1) != 1)
            return -1;
        while ((got = read(sent[0], &c, 1)) < 0 && errno == EINTR)
            ;
        if (got != 1)
            return -1;
        watch_window();
        if ((mode == KILL_FLUSHED && sigaction(SIGCHLD, &dfl, NULL) != 0) ||
            sigaction(SIGCHLD, &catch, NULL) != 0 ||
            (blocked && sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0))
            return -1;
        for (int w = 0; w < 3; w++)
            watch_window();
        if (handler_runs != (mode == KILL_KEPT))
            bad++;
    }
    if (sigaction(SIGCHLD, &dfl, NULL) != 0)
        return -1;
    close(go[1]);
    close(sent[0]);
    return waitpid(pid, NULL, 0) == pid ? bad : -1;
}

/* A fork child inherits the handler with SIGCHLD blocked and changes neither,
 * so it has no flag file and a kill to it is decided when it drains the record.
 * Once the parent's kill has returned, the child installs SIG_IGN, which drops
 * the pending SIGCHLD (do_sigaction), then the handler, and unblocks. A fresh
 * child per round, ROUNDS times.
 *
 * Returns the number of rounds in which the child's handler ran, or -1 on a
 * setup failure.
 */
static int child_kill_rounds(void)
{
    struct sigaction catch, ign;
    memset(&catch, 0, sizeof(catch));
    sigemptyset(&catch.sa_mask);
    catch.sa_handler = on_sigchld;
    ign = catch;
    ign.sa_handler = SIG_IGN;
    sigset_t chld, old;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);

    int bad = 0;
    for (int round = 0; round < ROUNDS; round++) {
        int sent[2];
        if (pipe(sent) != 0 || sigaction(SIGCHLD, &catch, NULL) != 0 ||
            sigprocmask(SIG_BLOCK, &chld, &old) != 0)
            return -1;
        pid_t pid = fork();
        if (pid < 0)
            return -1;
        if (pid == 0) {
            char c;
            handler_runs = 0;
            close(sent[1]);
            if (read(sent[0], &c, 1) != 1 ||
                sigaction(SIGCHLD, &ign, NULL) != 0 ||
                sigaction(SIGCHLD, &catch, NULL) != 0 ||
                sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0)
                _exit(126);
            for (int w = 0; w < 4; w++)
                watch_window();
            _exit(handler_runs != 0);
        }
        close(sent[0]);
        bool sent_ok = kill(pid, SIGCHLD) == 0 && write(sent[1], "x", 1) == 1;
        close(sent[1]);
        int status;
        if (waitpid(pid, &status, 0) != pid || !sent_ok || !WIFEXITED(status) ||
            WEXITSTATUS(status) > 1 || signal(SIGCHLD, SIG_DFL) == SIG_ERR ||
            sigprocmask(SIG_SETMASK, &old, NULL) != 0)
            return -1;
        bad += WEXITSTATUS(status);
    }
    return bad;
}

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif

static long send_self_sigchld(int how, int pidfd)
{
    switch (how) {
    case 0:
        return kill(getpid(), SIGCHLD);
    case 1:
        return kill(0, SIGCHLD);
    case 2:
        return syscall(SYS_pidfd_send_signal, pidfd, SIGCHLD, NULL, 0);
    default: {
        /* Raw, because musl's sigqueue blocks signals around the call. */
        siginfo_t si;
        memset(&si, 0, sizeof(si));
        si.si_signo = SIGCHLD;
        si.si_code = SI_QUEUE;
        si.si_pid = getpid();
        si.si_uid = getuid();
        return syscall(SYS_rt_sigqueueinfo, getpid(), SIGCHLD, &si);
    }
    }
}

/* A child in its own process group sends itself SIGCHLD with kill(getpid()),
 * kill(0), pidfd_send_signal and rt_sigqueueinfo under @disp with SIGCHLD
 * unblocked, ROUNDS times: sig_ignored (kernel/signal.c) discards each at
 * generation, so a signalfd for SIGCHLD never becomes readable.
 *
 * Returns the rounds where one did, or -1.
 */
static int self_kill_rounds(void (*disp)(int))
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        sigset_t chld;
        sigemptyset(&chld);
        sigaddset(&chld, SIGCHLD);
        int pidfd = (int) syscall(SYS_pidfd_open, getpid(), 0);
        int sfd = signalfd(-1, &chld, SFD_NONBLOCK);
        if (setpgid(0, 0) != 0 || pidfd < 0 || sfd < 0 ||
            signal(SIGCHLD, disp) == SIG_ERR ||
            sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0)
            _exit(126);
        int bad = 0;
        for (int round = 0; round < ROUNDS; round++) {
            bool woke = false;
            for (int how = 0; how < 4; how++) {
                long rc = send_self_sigchld(how, pidfd);
                struct pollfd pfd = {.fd = sfd, .events = POLLIN};
                int ready = poll(&pfd, 1, 10);
                if (rc != 0 || ready < 0)
                    _exit(126);
                woke |= ready > 0;
            }
            bad += woke;
        }
        _exit(bad);
    }
    int status;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
        WEXITSTATUS(status) > ROUNDS)
        return -1;
    return WEXITSTATUS(status);
}

/* A SIGCHLD sent to this thread while it blocks SIGCHLD under the handler, then
 * @drop and the handler again before the unblock, ROUNDS times: do_sigaction
 * drops it from each thread's pending set as well.
 *
 * Returns the number of rounds in which the handler ran, or -1 on a setup
 * failure.
 */
static int thread_directed_rounds(void (*drop)(int))
{
    struct sigaction catch, gone;
    memset(&catch, 0, sizeof(catch));
    sigemptyset(&catch.sa_mask);
    catch.sa_handler = on_sigchld;
    gone = catch;
    gone.sa_handler = drop;
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);

    int bad = 0;
    for (int round = 0; round < ROUNDS; round++) {
        handler_runs = 0;
        if (sigaction(SIGCHLD, &catch, NULL) != 0 ||
            sigprocmask(SIG_BLOCK, &chld, NULL) != 0 ||
            syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGCHLD) != 0 ||
            sigaction(SIGCHLD, &gone, NULL) != 0 ||
            sigaction(SIGCHLD, &catch, NULL) != 0 ||
            sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0)
            return -1;
        if (handler_runs)
            bad++;
    }
    return bad;
}

/* A periodic POSIX timer that signals SIGCHLD keeps firing after SIG_IGN drops
 * its pending signal.
 *
 * Returns 1 when the handler never ran, or -1 on a setup failure.
 */
static int timer_after_drop(void)
{
    struct sigaction catch, ign;
    memset(&catch, 0, sizeof(catch));
    sigemptyset(&catch.sa_mask);
    catch.sa_handler = on_sigchld;
    ign = catch;
    ign.sa_handler = SIG_IGN;
    sigset_t chld, pending;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGCHLD;
    struct itimerspec every = {.it_interval = {0, 10 * 1000 * 1000L},
                               .it_value = {0, 10 * 1000 * 1000L}};
    timer_t timer;
    if (sigaction(SIGCHLD, &catch, NULL) != 0 ||
        sigprocmask(SIG_BLOCK, &chld, NULL) != 0 ||
        timer_create(CLOCK_MONOTONIC, &sev, &timer) != 0)
        return -1;
    int rc = -1;
    if (timer_settime(timer, 0, &every, NULL) != 0)
        goto out;
    for (int w = 0; w < 10; w++) {
        if (sigpending(&pending) != 0)
            goto out;
        if (sigismember(&pending, SIGCHLD))
            break;
        watch_window();
    }
    if (!sigismember(&pending, SIGCHLD) ||
        sigaction(SIGCHLD, &ign, NULL) != 0 ||
        sigaction(SIGCHLD, &catch, NULL) != 0)
        goto out;
    handler_runs = 0;
    if (sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0)
        goto out;
    watch_window();
    rc = handler_runs ? 0 : 1;
out:
    timer_delete(timer);
    sigprocmask(SIG_UNBLOCK, &chld, NULL);
    return rc;
}

/* timer_after_drop ROUNDS times; returns the rounds without a run, or -1. */
static int timer_rounds(void)
{
    int bad = 0;
    for (int round = 0; round < ROUNDS; round++) {
        int rc = timer_after_drop();
        if (rc < 0)
            return -1;
        bad += rc;
    }
    return bad;
}

/* With SIGCHLD blocked, SIG_DFL is installed over SIG_DFL and a child exits,
 * ROUNDS times: SIG_DFL keeps the SIGCHLD pending, and the handler installed
 * before the unblock runs once for it.
 *
 * Returns the number of rounds in which the handler did not run exactly once,
 * or -1 on a setup failure.
 */
static int kept_rounds(void)
{
    struct sigaction catch, dfl;
    memset(&dfl, 0, sizeof(dfl));
    sigemptyset(&dfl.sa_mask);
    dfl.sa_handler = SIG_DFL;
    catch = dfl;
    catch.sa_handler = on_sigchld;
    catch.sa_flags = SA_RESTART;
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);

    int bad = 0;
    for (int round = 0; round < ROUNDS; round++) {
        handler_runs = 0;
        if (sigaction(SIGCHLD, &dfl, NULL) != 0 ||
            sigprocmask(SIG_BLOCK, &chld, NULL) != 0 ||
            sigaction(SIGCHLD, &dfl, NULL) != 0)
            return -1;
        pid_t pid = fork();
        if (pid < 0)
            return -1;
        if (pid == 0)
            _exit(0);
        if (waitpid(pid, NULL, 0) != pid)
            return -1;
        watch_window();
        if (sigaction(SIGCHLD, &catch, NULL) != 0 ||
            sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0)
            return -1;
        watch_window();
        if (handler_runs != 1)
            bad++;
    }
    return sigaction(SIGCHLD, &dfl, NULL) == 0 ? bad : -1;
}

/* The exiting cases: the action change made between the child's last write and
 * the end of its exit, with SIGCHLD blocked throughout.
 */
enum exit_race {
    EXIT_IGN,     /* exit under the handler, then SIG_IGN and the handler */
    EXIT_DFL,     /* EXIT_IGN with SIG_DFL in place of SIG_IGN */
    EXIT_UNBLOCK, /* exit under SIG_DFL, then an unblock, SIG_DFL, handler */
};

static const char *const exit_race_names[] = {"ign", "dfl", "unblock"};

/* A child exits with SIGCHLD blocked; one watch window after its last write,
 * @race changes the action and SIGCHLD is unblocked, ROUNDS times: do_sigaction
 * drops the pending SIGCHLD, or under EXIT_UNBLOCK the unblock discards it.
 * Elfuse reaps the child when the handler replaces SIG_IGN, so the reap also
 * takes ECHILD there.
 *
 * Returns the number of rounds in which the handler ran, or -1 on a setup
 * failure.
 */
static int exiting_rounds(enum exit_race race)
{
    struct sigaction catch, drop;
    memset(&catch, 0, sizeof(catch));
    sigemptyset(&catch.sa_mask);
    drop = catch;
    drop.sa_handler = race == EXIT_IGN ? SIG_IGN : SIG_DFL;
    catch.sa_handler = on_sigchld;
    catch.sa_flags = SA_RESTART;
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);

    int bad = 0;
    for (int round = 0; round < ROUNDS; round++) {
        handler_runs = 0;
        int fds[2];
        if (sigaction(SIGCHLD, race == EXIT_UNBLOCK ? &drop : &catch, NULL) !=
                0 ||
            sigprocmask(SIG_BLOCK, &chld, NULL) != 0 || pipe(fds) != 0)
            return -1;
        pid_t pid = fork();
        if (pid < 0)
            return -1;
        if (pid == 0) {
            close(fds[0]);
            _exit(write(fds[1], "x", 1) == 1 ? 0 : 1);
        }
        close(fds[1]);

        /* The byte, not EOF: the child's end closes after its record. */
        char c;
        ssize_t got;
        while ((got = read(fds[0], &c, 1)) < 0 && errno == EINTR)
            ;
        close(fds[0]);
        if (got != 1)
            return -1;
        watch_window();
        bool unblock_first = race == EXIT_UNBLOCK;
        if ((unblock_first && sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0) ||
            sigaction(SIGCHLD, &drop, NULL) != 0 ||
            sigaction(SIGCHLD, &catch, NULL) != 0 ||
            (!unblock_first && sigprocmask(SIG_UNBLOCK, &chld, NULL) != 0))
            return -1;
        for (int w = 0; w < 4; w++)
            watch_window();
        if (waitpid(pid, NULL, 0) != pid &&
            !(race == EXIT_IGN && errno == ECHILD))
            return -1;
        if (handler_runs)
            bad++;
    }
    return bad;
}

/* Block until every write end of @hold is closed, then exit. */
static void hold_until_closed(const int hold[2])
{
    char c;
    close(hold[1]);
    while (read(hold[0], &c, 1) < 0 && errno == EINTR)
        ;
    _exit(0);
}

static double ms_since(const struct timespec *from)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double) (now.tv_sec - from->tv_sec) * 1e3 +
           (double) (now.tv_nsec - from->tv_nsec) / 1e6;
}

/* Under SIG_IGN, a child exits while children of its own are alive. Its host
 * process stays in the reparent handshake, which the drain delay stretches to
 * 50 ms per child, and a waitpid with WNOHANG on another live child must not
 * wait for it. With @busy, a second child exits at once, so its SIGUSR2 starts
 * a drain that reads both records and waits for the first child, and the
 * waitpid calls start while that drain waits. ROUNDS times.
 *
 * Returns the number of rounds with a call of 100 ms or more, or -1 on a setup
 * failure. The stall is at least 4 x 50 ms, and a descheduled call (QEMU, a
 * loaded host) stays under 100 ms.
 */
static int wnohang_rounds(bool busy)
{
    int bad = 0;
    for (int round = 0; round < ROUNDS; round++) {
        int hold[2];
        if (signal(SIGCHLD, SIG_IGN) == SIG_ERR || pipe(hold) != 0)
            return -1;
        pid_t other = fork();
        if (other == 0)
            hold_until_closed(hold);
        pid_t pid = other < 0 ? -1 : fork();
        if (pid == 0) {
            for (int i = 0; i < (busy ? 8 : 4); i++) {
                if (fork() == 0)
                    hold_until_closed(hold);
            }
            _exit(0);
        }
        close(hold[0]);
        if (pid < 0)
            return -1;
        if (busy) {
            pid_t plain = fork();
            if (plain == 0)
                _exit(0);
            if (plain < 0)
                return -1;
        }
        double worst = 0;
        struct timespec start;
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (busy)
            usleep(300 * 1000);
        while (ms_since(&start) < (busy ? 550 : 350)) {
            struct timespec call;
            clock_gettime(CLOCK_MONOTONIC, &call);
            if (waitpid(other, NULL, WNOHANG) != 0)
                return -1;
            double took = ms_since(&call);
            if (took > worst)
                worst = took;
        }
        close(hold[1]);
        while (waitpid(-1, NULL, 0) > 0 || errno == EINTR)
            ;
        if (errno != ECHILD || signal(SIGCHLD, SIG_DFL) == SIG_ERR)
            return -1;
        if (worst >= 100)
            bad++;
    }
    return bad;
}

static void report(const char *name, int bad)
{
    TEST(name);
    if (bad == 0) {
        PASS();
    } else if (bad < 0) {
        FAIL("fork, wait or sigaction failed");
    } else {
        char msg[80];
        snprintf(msg, sizeof(msg), "wrong in %d of %d rounds", bad, ROUNDS);
        FAIL(msg);
    }
}

/* A child exits while SIGCHLD is ignored and blocked, then the handler goes in
 * and SIGCHLD is unblocked, ROUNDS times: do_notify_parent (kernel/exit.c)
 * sends nothing under SIG_IGN, whatever the mask. On elfuse the "fallback" lane
 * sets ELFUSE_EXIT_SKIP_REGISTRY, so the child sends its record without the
 * lifecycle registry.
 *
 * Returns the number of rounds in which SIGCHLD was pending or the handler ran,
 * or -1 on a setup failure.
 */
static int fallback_rounds(void)
{
    struct sigaction catch;
    memset(&catch, 0, sizeof(catch));
    sigemptyset(&catch.sa_mask);
    catch.sa_handler = on_sigchld;
    sigset_t chld, old, pend;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);

    int bad = 0;
    for (int round = 0; round < ROUNDS; round++) {
        if (signal(SIGCHLD, SIG_IGN) == SIG_ERR ||
            sigprocmask(SIG_BLOCK, &chld, &old) != 0)
            return -1;
        pid_t pid = fork();
        if (pid < 0)
            return -1;
        if (pid == 0)
            _exit(0);
        for (int w = 0; w < 3; w++)
            watch_window();
        handler_runs = 0;
        if (sigpending(&pend) != 0)
            return -1;
        bool pending = sigismember(&pend, SIGCHLD);
        if (sigaction(SIGCHLD, &catch, NULL) != 0 ||
            sigprocmask(SIG_SETMASK, &old, NULL) != 0)
            return -1;
        watch_window();
        if (pending || handler_runs)
            bad++;
        if (signal(SIGCHLD, SIG_DFL) == SIG_ERR)
            return -1;
        while (waitpid(-1, NULL, WNOHANG) > 0)
            ;
    }
    return bad;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "exiting") == 0) {
        static const char *const labels[] = {
            "no SIGCHLD after SIG_IGN during the exit",
            "no SIGCHLD after SIG_DFL during the exit",
            "no SIGCHLD after an unblock and SIG_DFL during the exit",
        };
        bool ran = false;
        for (int race = EXIT_IGN; race <= EXIT_UNBLOCK; race++) {
            if (argc > 2 && strcmp(argv[2], exit_race_names[race]) != 0)
                continue;
            report(labels[race], exiting_rounds((enum exit_race) race));
            ran = true;
        }
        if (!ran) {
            fprintf(stderr, "unknown exiting case: %s\n", argv[2]);
            return 2;
        }
        signal(SIGCHLD, SIG_DFL);
        SUMMARY("test-sigchld-after-wait exiting");
        return fails ? 1 : 0;
    }
    if (argc > 1 && strcmp(argv[1], "fallback") == 0) {
        report("no SIGCHLD from an exit under SIG_IGN without the registry",
               fallback_rounds());
        SUMMARY("test-sigchld-after-wait fallback");
        return fails ? 1 : 0;
    }
    if (argc > 1 && strcmp(argv[1], "late") == 0) {
        static const char *const labels[] = {
            "no SIGCHLD for a late handler",
            "no SIGCHLD after an SA_RESETHAND run",
            "no SIGCHLD after a thread that blocked it exits",
            "no SIGCHLD after reaping a CLONE_VM child that blocked it",
            "no SIGCHLD for an adopted exited child",
            "no SIGCHLD after SIG_IGN drops it pending",
            "no SIGCHLD after SIG_DFL drops it pending",
            "no SIGCHLD after an unblock, then SIG_DFL",
        };
        bool ran = false;
        for (int ev = NONE; ev <= UNBLOCKED; ev++) {
            if (argc > 2 && strcmp(argv[2], event_names[ev]) != 0)
                continue;
            report(labels[ev], late_rounds((enum event) ev));
            ran = true;
        }
        static const char *const kills[] = {"kill", "killdfl"};
        for (int k = 0; k < 2; k++) {
            if (argc > 2 && strcmp(argv[2], kills[k]) != 0)
                continue;
            report(k ? "no SIGCHLD from kill under SIG_DFL for a later handler"
                     : "no SIGCHLD from kill after SIG_DFL drops it pending",
                   kill_rounds(k ? KILL_IGNORED : KILL_FLUSHED));
            ran = true;
        }
        if (argc <= 2 || strcmp(argv[2], "killchild") == 0) {
            report("no SIGCHLD from kill to a fork child after SIG_IGN",
                   child_kill_rounds());
            ran = true;
        }
        static const char *const nohangs[] = {"wnohang", "wnohangbusy"};
        for (int n = 0; n < 2; n++) {
            if (argc > 2 && strcmp(argv[2], nohangs[n]) != 0)
                continue;
            report(n ? "no WNOHANG wait behind a drain that waits for a child"
                     : "no WNOHANG wait for an exiting child's host process",
                   wnohang_rounds(n == 1));
            ran = true;
        }
        static const char *const waits[] = {"waitpid", "waitid"};
        for (int w = 0; w < 2; w++) {
            if (argc > 2 && strcmp(argv[2], waits[w]) != 0)
                continue;
            report(w ? "SIGCHLD pending when waitid returns the child"
                     : "SIGCHLD pending when waitpid returns the child",
                   waited_rounds(w == 1));
            ran = true;
        }
        if (!ran) {
            fprintf(stderr, "unknown late case: %s\n", argv[2]);
            return 2;
        }
        signal(SIGCHLD, SIG_DFL);
        SUMMARY("test-sigchld-after-wait late");
        return fails ? 1 : 0;
    }

    report("one SIGCHLD per waitpid child", bad_rounds(false, HANDLER_FIRST));
    report("one SIGCHLD per waitid child", bad_rounds(true, HANDLER_FIRST));
    report("no SIGCHLD after a waitpid reap", bad_rounds(false, REAP_DFL));
    report("no SIGCHLD after a waitid reap", bad_rounds(true, REAP_DFL));
    report("no SIGCHLD after a SIG_IGN waitpid", bad_rounds(false, REAP_IGN));
    report("no SIGCHLD after a SIG_IGN waitid", bad_rounds(true, REAP_IGN));
    report("no SIGCHLD for a handler after WNOWAIT",
           bad_rounds(false, LATE_DFL));
    report("no SIGCHLD after blocking it post-WNOWAIT",
           bad_rounds(false, LATE_MASKED));
    report("no SIGCHLD under SIG_IGN while blocked",
           bad_rounds(false, IGN_BLOCKED));
    report("no SIGCHLD for a handler after an unwaited exit",
           bad_rounds(false, NO_WAIT));
    report("no thread-directed SIGCHLD after SIG_IGN",
           thread_directed_rounds(SIG_IGN));
    report("no thread-directed SIGCHLD after SIG_DFL",
           thread_directed_rounds(SIG_DFL));
    report("a SIGCHLD timer fires again after SIG_IGN drops it",
           timer_rounds());
    report("SIG_DFL keeps a blocked SIGCHLD pending", kept_rounds());
    report("a kill under SIG_IGN keeps a blocked SIGCHLD pending",
           kill_rounds(KILL_KEPT));
    report("no signalfd wake for a SIGCHLD sent to self under SIG_IGN",
           self_kill_rounds(SIG_IGN));
    report("no signalfd wake for a SIGCHLD sent to self under SIG_DFL",
           self_kill_rounds(SIG_DFL));
    signal(SIGCHLD, SIG_DFL);

    SUMMARY("test-sigchld-after-wait");
    return fails ? 1 : 0;
}
