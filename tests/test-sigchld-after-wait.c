/*
 * A reaped child's SIGCHLD does not reach a handler installed after the wait
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux generates SIGCHLD with the zombie, so under SIG_DFL it is discarded
 * before wait4 returns and a handler installed afterwards never runs for that
 * child. lmbench's benchmp relies on this between its two lat_fs phases. The
 * same holds after an exit nobody waited for, after a WNOWAIT wait that leaves
 * the child a zombie, also when SIGCHLD is blocked before the handler, and
 * SIG_IGN discards SIGCHLD even while it is blocked.
 *
 * The late argument runs the unwaited exit alone, after each event that makes
 * SIGCHLD discarded again without a sigaction or sigprocmask call, and with an
 * exited grandchild left to this subreaper; a case name after it runs that case
 * only. On elfuse it needs ELFUSE_SIGNAL_DRAIN_DELAY_US, so the parent drains
 * the child's record only after the handler is installed.
 */

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
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

/* The late cases, under SIG_DFL with SIGCHLD unblocked in the calling thread.
 * RESETHAND, THREAD_EXIT and VM_REAP run before the unwaited exit, and each
 * leaves SIGCHLD discarded again.
 */
enum event {
    NONE,        /* nothing */
    RESETHAND,   /* an SA_RESETHAND handler runs for a reaped child */
    THREAD_EXIT, /* a thread that blocked SIGCHLD exits */
    VM_REAP,     /* a CLONE_VM child that blocked SIGCHLD is reaped */
    ADOPTED, /* the exiting child leaves an exited child to this subreaper */
};

static const char *const event_names[] = {"none", "resethand", "thread", "vm",
                                          "adopted"};

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
        struct sigaction once;
        memset(&once, 0, sizeof(once));
        sigemptyset(&once.sa_mask);
        once.sa_handler = on_sigchld;
        once.sa_flags = SA_RESTART | SA_RESETHAND;
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
 * this process adopts as a subreaper. The pipe's EOF means every child holding
 * it is exiting.
 *
 * Returns the number of rounds in which the handler ran, or -1 on a setup
 * failure.
 */
static int late_rounds(enum event ev)
{
    struct sigaction dfl, catch;
    memset(&dfl, 0, sizeof(dfl));
    sigemptyset(&dfl.sa_mask);
    dfl.sa_handler = SIG_DFL;
    catch = dfl;
    catch.sa_handler = on_sigchld;
    catch.sa_flags = SA_RESTART;
    if (ev == ADOPTED && prctl(PR_SET_CHILD_SUBREAPER, 1) != 0)
        return -1;

    int bad = 0;
    for (int round = 0; round < ROUNDS; round++) {
        handler_runs = 0;
        if (sigaction(SIGCHLD, &dfl, NULL) != 0)
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
        if (sigaction(SIGCHLD, &catch, NULL) != 0)
            return -1;
        for (int w = 0; w < 3; w++)
            watch_window();
        if (waitpid(pid, NULL, 0) != pid)
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

static void report(const char *name, int bad)
{
    TEST(name);
    if (bad == 0) {
        PASS();
    } else if (bad < 0) {
        FAIL("fork, wait or sigaction failed");
    } else {
        char msg[80];
        snprintf(msg, sizeof(msg), "wrong handler count in %d of %d rounds",
                 bad, ROUNDS);
        FAIL(msg);
    }
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "late") == 0) {
        static const char *const labels[] = {
            "no SIGCHLD for a late handler",
            "no SIGCHLD after an SA_RESETHAND run",
            "no SIGCHLD after a blocking thread exits",
            "no SIGCHLD after a blocking CLONE_VM reap",
            "no SIGCHLD for an adopted exited child",
        };
        bool ran = false;
        for (int ev = NONE; ev <= ADOPTED; ev++) {
            if (argc > 2 && strcmp(argv[2], event_names[ev]) != 0)
                continue;
            report(labels[ev], late_rounds((enum event) ev));
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
    signal(SIGCHLD, SIG_DFL);

    SUMMARY("test-sigchld-after-wait");
    return fails ? 1 : 0;
}
