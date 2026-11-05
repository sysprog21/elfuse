/*
 * Test kill(0, sig) and kill(-pgid, sig) process-group delivery
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * POSIX kill(0, sig) signals the caller's whole process group; kill(-pgid, sig)
 * (pid < -1) signals group pgid. Verifies:
 * 1. kill(-childpgid) reaches a child placed in its own group.
 * 2. kill(0) reaches the caller and a child still in the caller's group.
 * 3. kill(0) does NOT reach a child that moved to a different group.
 *
 * SIGWINCH (default-ignore) is the delivery signal so it is harmless to any
 * unrelated process in a full-system guest; our processes install a handler.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t got_winch = 0;

static void winch_handler(int sig)
{
    (void) sig;
    got_winch = 1;
}

static void install(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = winch_handler;
    sigaction(SIGWINCH, &sa, NULL);
}

static bool wait_flag(int max_ms)
{
    for (int i = 0; i < max_ms && !got_winch; i++) {
        struct timespec ts = {0, 1000000}; /* 1 ms */
        nanosleep(&ts, NULL);
    }
    return got_winch != 0;
}

/* Fork a child that arms SIGWINCH, optionally joins its own group, reports
 * readiness on the pipe, then exits 0 if it received the signal within the
 * window (want_signal) or 0 if it did not (when !want_signal).
 */
static pid_t spawn_child(int wfd, bool own_group, bool want_signal, int wait_ms)
{
    pid_t pid = fork();
    if (pid != 0)
        return pid;
    got_winch = 0; /* clear any flag inherited across fork */
    install();
    if (own_group)
        setpgid(0, 0); /* shell idiom: child also sets its group */
    char c = 'R';
    if (write(wfd, &c, 1) != 1)
        _exit(2);
    bool got = wait_flag(wait_ms);
    _exit((got == want_signal) ? 0 : 1);
}

static bool wait_ready(int rfd)
{
    char c = 0;
    return read(rfd, &c, 1) == 1 && c == 'R';
}

static bool child_ok(pid_t pid)
{
    int status = 0;
    if (waitpid(pid, &status, 0) != pid)
        return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static pid_t spawn_group_sender(int ready_wfd, int go_rfd)
{
    pid_t pid = fork();
    if (pid != 0)
        return pid;
    got_winch = 0;
    install();
    char c = 'R';
    if (write(ready_wfd, &c, 1) != 1)
        _exit(2);
    if (read(go_rfd, &c, 1) != 1)
        _exit(2);
    if (kill(0, SIGWINCH) != 0)
        _exit(3);
    _exit(wait_flag(2000) ? 0 : 1);
}

/* Fork a child that calls setsid() to leave the caller's group, then reports
 * readiness and exits 0 only if it did NOT receive the signal in the window.
 * Guards that setsid refreshes the process-group registry: without the refresh
 * the child would linger in the parent's group and be wrongly hit.
 */
static pid_t spawn_setsid_child(int wfd, int wait_ms)
{
    pid_t pid = fork();
    if (pid != 0)
        return pid;
    got_winch = 0;
    install();
    setsid();
    char c = 'R';
    if (write(wfd, &c, 1) != 1)
        _exit(2);
    _exit(wait_flag(wait_ms) ? 1 : 0);
}

static pid_t spawn_setsid_after_parent_setpgid(int ready_wfd, int go_rfd)
{
    pid_t pid = fork();
    if (pid != 0)
        return pid;
    char c = 'R';
    if (write(ready_wfd, &c, 1) != 1)
        _exit(2);
    if (read(go_rfd, &c, 1) != 1)
        _exit(2);
    errno = 0;
    _exit(setsid() == -1 && errno == EPERM ? 0 : 1);
}

/* Fork a group leader that, once the parent has set its group, forks a
 * throwaway grandchild (triggering its own fork-time registry republish) and
 * then waits for the signal. Guards that the republish does not re-stamp the
 * registry with the stale pre-setpgid group: without the sync-before-publish
 * fix, kill(-leaderpgid) would miss this leader after it forks.
 */
static pid_t spawn_leader_then_fork(int ready_wfd, int go_rfd, int forked_wfd)
{
    pid_t pid = fork();
    if (pid != 0)
        return pid;
    got_winch = 0;
    install();
    char c = 'R';
    if (write(ready_wfd, &c, 1) != 1)
        _exit(2);
    if (read(go_rfd, &c, 1) != 1) /* wait until parent did setpgid(self,self) */
        _exit(2);
    pid_t gc = fork(); /* republish happens here */
    if (gc == 0)
        _exit(0);
    if (gc < 0)
        _exit(2);
    waitpid(gc, NULL, 0); /* gc > 0: reap the throwaway grandchild */
    char done = 'R'; /* c was clobbered by the go read; send a fresh byte */
    if (write(forked_wfd, &done, 1) != 1)
        _exit(2);
    _exit(wait_flag(2000) ? 0 : 1);
}

static int failed = 0;

static void test_setpgid_args(void)
{
    /* 0: setpgid argument validation. The kernel defaults pgid==0 to pid before
     * checking pgid < 0, so a negative pid with pgid==0 becomes a negative pgid
     * and fails EINVAL, not ESRCH; ESRCH needs a valid pgid alongside the
     * nonexistent pid.
     */
    if (setpgid(0, -5) != -1 || errno != EINVAL) {
        fprintf(stderr, "FAIL: setpgid(0,-5) should be EINVAL\n");
        failed++;
    }
    if (setpgid(-9, 0) != -1 || errno != EINVAL) {
        fprintf(stderr, "FAIL: setpgid(-9,0) should be EINVAL\n");
        failed++;
    }
    if (setpgid(-9, getpgrp()) != -1 || errno != ESRCH) {
        fprintf(stderr, "FAIL: setpgid(-9,self-pgid) should be ESRCH\n");
        failed++;
    }
}

static int test_own_group_kill(void)
{
    /* 1: kill(-childpgid) reaches a child in its own group. */
    int p1[2];
    if (pipe(p1) != 0)
        return 1;
    pid_t c1 = spawn_child(p1[1], true, true, 2000);
    if (c1 < 0)
        return 1;
    close(p1[1]);
    setpgid(c1, c1); /* parent side of the group-set idiom */
    if (!wait_ready(p1[0])) {
        fprintf(stderr, "child 1 not ready\n");
        return 1;
    }
    close(p1[0]);
    if (kill(-c1, SIGWINCH) != 0) {
        perror("kill(-childpgid)");
        failed++;
    }
    if (!child_ok(c1)) {
        fprintf(stderr, "FAIL: kill(-childpgid) did not reach the child\n");
        failed++;
    }

    /* 2: kill(0) reaches the caller and a child in the caller's group. */
    int p2[2];
    if (pipe(p2) != 0)
        return 1;
    pid_t c2 = spawn_child(p2[1], false, true, 2000); /* inherits our group */
    if (c2 < 0)
        return 1;
    close(p2[1]);
    if (!wait_ready(p2[0])) {
        fprintf(stderr, "child 2 not ready\n");
        return 1;
    }
    close(p2[0]);
    got_winch = 0;
    if (kill(0, SIGWINCH) != 0) {
        perror("kill(0)");
        failed++;
    }
    if (!wait_flag(2000)) {
        fprintf(stderr, "FAIL: kill(0) did not signal the caller\n");
        failed++;
    }
    if (!child_ok(c2)) {
        fprintf(stderr, "FAIL: kill(0) did not reach the in-group child\n");
        failed++;
    }

    /* 3: kill(0) does NOT reach a child that left the caller's group. */
    int p3[2];
    if (pipe(p3) != 0)
        return 1;
    /* want_signal=false: child exits 0 only if it does NOT get the signal. */
    pid_t c3 = spawn_child(p3[1], true, false, 300);
    if (c3 < 0)
        return 1;
    close(p3[1]);
    setpgid(c3, c3);
    if (!wait_ready(p3[0])) {
        fprintf(stderr, "child 3 not ready\n");
        return 1;
    }
    close(p3[0]);
    if (kill(0, SIGWINCH) != 0) {
        perror("kill(0) #3");
        failed++;
    }
    if (!child_ok(c3)) {
        fprintf(stderr,
                "FAIL: kill(0) wrongly reached a child in a different group\n");
        failed++;
    }

    return 0;
}

static int test_pipeline_and_child_origin(void)
{
    /* 4: pipeline. c4 leads group c4; c5 joins group c4. kill(-c4) reaches
     * both, exercising the "join an existing tracked group" path.
     */
    int p4[2], p5[2];
    if (pipe(p4) != 0 || pipe(p5) != 0)
        return 1;
    pid_t c4 = spawn_child(p4[1], true, true, 2000);
    if (c4 < 0)
        return 1;
    close(p4[1]);
    setpgid(c4, c4);
    if (!wait_ready(p4[0])) {
        fprintf(stderr, "child 4 not ready\n");
        return 1;
    }
    close(p4[0]);
    pid_t c5 = spawn_child(p5[1], false, true, 2000);
    if (c5 < 0)
        return 1;
    close(p5[1]);
    setpgid(c5, c4); /* c5 joins c4's existing group */
    if (!wait_ready(p5[0])) {
        fprintf(stderr, "child 5 not ready\n");
        return 1;
    }
    close(p5[0]);
    if (kill(-c4, SIGWINCH) != 0) {
        perror("kill(-c4) pipeline");
        failed++;
    }
    if (!child_ok(c4)) {
        fprintf(stderr, "FAIL: kill(-pgid) did not reach the group leader\n");
        failed++;
    }
    if (!child_ok(c5)) {
        fprintf(stderr, "FAIL: kill(-pgid) did not reach the group joiner\n");
        failed++;
    }

    /* 5: child-origin kill(0) reaches the inherited-group sibling and parent.
     */
    int p6[2], p7[2], go[2];
    if (pipe(p6) != 0 || pipe(p7) != 0 || pipe(go) != 0)
        return 1;
    pid_t c6 = spawn_group_sender(p6[1], go[0]);
    if (c6 < 0)
        return 1;
    close(p6[1]);
    close(go[0]);
    pid_t c7 = spawn_child(p7[1], false, true, 2000);
    if (c7 < 0)
        return 1;
    close(p7[1]);
    if (!wait_ready(p6[0]) || !wait_ready(p7[0])) {
        fprintf(stderr, "child 6/7 not ready\n");
        return 1;
    }
    close(p6[0]);
    close(p7[0]);
    got_winch = 0;
    if (write(go[1], "G", 1) != 1)
        return 1;
    close(go[1]);
    if (!wait_flag(2000)) {
        fprintf(stderr, "FAIL: child kill(0) did not signal the parent\n");
        failed++;
    }
    if (!child_ok(c6)) {
        fprintf(stderr, "FAIL: child kill(0) did not signal the caller\n");
        failed++;
    }
    if (!child_ok(c7)) {
        fprintf(stderr, "FAIL: child kill(0) did not signal the sibling\n");
        failed++;
    }

    return 0;
}

static int test_setsid_and_setpgid(void)
{
    /* 6: a child that calls setsid() leaves the caller's group, so kill(0) (the
     * caller's group) must no longer reach it. Passes only if setsid refreshed
     * the registry entry to the child's new group.
     */
    int p8[2];
    if (pipe(p8) != 0)
        return 1;
    pid_t c8 = spawn_setsid_child(p8[1], 300);
    if (c8 < 0)
        return 1;
    close(p8[1]);
    if (!wait_ready(p8[0])) {
        fprintf(stderr, "child 8 not ready\n");
        return 1;
    }
    close(p8[0]);
    if (kill(0, SIGWINCH) != 0) {
        perror("kill(0) #6");
        failed++;
    }
    if (!child_ok(c8)) {
        fprintf(stderr,
                "FAIL: kill(0) wrongly reached a child that called setsid\n");
        failed++;
    }

    /* 7: parent-side setpgid(child, child) must update the child's local pgid
     * too. Otherwise the child's kill(0) targets the inherited parent group.
     */
    int p9[2], go2[2];
    if (pipe(p9) != 0 || pipe(go2) != 0)
        return 1;
    pid_t c9 = spawn_group_sender(p9[1], go2[0]);
    if (c9 < 0)
        return 1;
    close(p9[1]);
    close(go2[0]);
    setpgid(c9, c9);
    if (!wait_ready(p9[0])) {
        fprintf(stderr, "child 9 not ready\n");
        return 1;
    }
    close(p9[0]);
    got_winch = 0;
    if (write(go2[1], "G", 1) != 1)
        return 1;
    close(go2[1]);
    if (wait_flag(300)) {
        fprintf(stderr,
                "FAIL: child kill(0) after parent setpgid signaled parent\n");
        failed++;
    }
    if (!child_ok(c9)) {
        fprintf(stderr,
                "FAIL: child kill(0) after parent setpgid missed child\n");
        failed++;
    }

    /* 8: parent-side setpgid(child, child) makes the child a group leader, so a
     * later setsid() in that child must fail with EPERM.
     */
    int p10[2], go3[2];
    if (pipe(p10) != 0 || pipe(go3) != 0)
        return 1;
    pid_t c10 = spawn_setsid_after_parent_setpgid(p10[1], go3[0]);
    if (c10 < 0)
        return 1;
    close(p10[1]);
    close(go3[0]);
    if (!wait_ready(p10[0])) {
        fprintf(stderr, "child 10 not ready\n");
        return 1;
    }
    close(p10[0]);
    setpgid(c10, c10);
    if (write(go3[1], "G", 1) != 1)
        return 1;
    close(go3[1]);
    if (!child_ok(c10)) {
        fprintf(stderr,
                "FAIL: setsid succeeded after parent setpgid(child, child)\n");
        failed++;
    }

    /* 9: one child can create a group itself, then a parent can place a sibling
     * into that registry-only group.
     */
    int p11[2], p12[2];
    if (pipe(p11) != 0 || pipe(p12) != 0)
        return 1;
    pid_t c11 = spawn_child(p11[1], true, true, 2000);
    if (c11 < 0)
        return 1;
    close(p11[1]);
    if (!wait_ready(p11[0])) {
        fprintf(stderr, "child 11 not ready\n");
        return 1;
    }
    close(p11[0]);
    pid_t c12 = spawn_child(p12[1], false, true, 2000);
    if (c12 < 0)
        return 1;
    close(p12[1]);
    setpgid(c12, c11);
    if (!wait_ready(p12[0])) {
        fprintf(stderr, "child 12 not ready\n");
        return 1;
    }
    close(p12[0]);
    if (kill(-c11, SIGWINCH) != 0) {
        perror("kill(-child-created-pgid)");
        failed++;
    }
    if (!child_ok(c11)) {
        fprintf(stderr,
                "FAIL: kill(-pgid) missed child-created group leader\n");
        failed++;
    }
    if (!child_ok(c12)) {
        fprintf(stderr,
                "FAIL: kill(-pgid) missed sibling in child-created group\n");
        failed++;
    }

    return 0;
}

static int test_leader_fork(void)
{
    /* 10: a leader forks after the parent set its group. Its fork-time registry
     * republish must not revert the entry to the stale inherited group, so
     * kill(-leaderpgid) still reaches it.
     */
    int p13[2], go4[2], fk[2];
    if (pipe(p13) != 0 || pipe(go4) != 0 || pipe(fk) != 0)
        return 1;
    pid_t c13 = spawn_leader_then_fork(p13[1], go4[0], fk[1]);
    if (c13 < 0)
        return 1;
    close(p13[1]);
    close(go4[0]);
    close(fk[1]);
    if (!wait_ready(p13[0])) {
        fprintf(stderr, "child 13 not ready\n");
        return 1;
    }
    close(p13[0]);
    if (setpgid(c13, c13) != 0) { /* parent sets the leader's group */
        perror("setpgid child 13");
        return 1;
    }
    if (write(go4[1], "G", 1) != 1)
        return 1;
    close(go4[1]);
    if (!wait_ready(
            fk[0])) { /* wait until the leader has forked (republished) */
        fprintf(stderr, "child 13 did not fork\n");
        return 1;
    }
    close(fk[0]);
    if (kill(-c13, SIGWINCH) != 0) {
        perror("kill(-leaderpgid after fork)");
        failed++;
    }
    if (!child_ok(c13)) {
        fprintf(
            stderr,
            "FAIL: kill(-pgid) missed a leader that forked after setpgid\n");
        failed++;
    }

    return 0;
}

int main(void)
{
    install();

    test_setpgid_args();
    if (test_own_group_kill())
        return 1;
    if (test_pipeline_and_child_origin())
        return 1;
    if (test_setsid_and_setpgid())
        return 1;
    if (test_leader_fork())
        return 1;

    printf("%s: %d failed\n", failed == 0 ? "PASS" : "FAIL", failed);
    return failed == 0 ? 0 : 1;
}
