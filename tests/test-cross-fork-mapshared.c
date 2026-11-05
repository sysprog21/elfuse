/*
 * Cross-fork MAP_SHARED coherence tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Verifies live MAP_SHARED visibility across fork(): both file-backed and
 * anonymous shared mappings must continue to propagate writes between parent
 * and child after the IPC handoff. Without the overlay re-establishment in
 * fork-state, the child sees a stale snapshot of the parent's pre-fork contents
 * and writes from each side stay private.
 *
 * Three scenarios:
 *   1. Regular file: shared mmap of a tmp file; parent writes appear
 *      in child mapping AND on disk; child writes appear in parent
 *      mapping AND on disk.
 *   2. shm/dev/shm file: same coherence over an unlinked shm file.
 *   3. MAP_SHARED|MAP_ANONYMOUS: parent and child both see each
 *      other's writes through the kernel-managed memfd that elfuse
 *      installs at fork time.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

/* This test opens a /dev/shm path directly rather than calling shm_open, which
 * returns ENOSYS without trying on glibc 2.28 static.
 */

/* IPC primitives between parent and child: a single byte over a pipe pair
 * signals "go ahead" each direction. Replaces a sleep-based synchronization
 * that the test matrix would race on slow runners.
 */
typedef struct {
    int parent_to_child[2];
    int child_to_parent[2];
} sync_t;

static int sync_init(sync_t *s)
{
    if (pipe(s->parent_to_child) != 0)
        return -1;
    if (pipe(s->child_to_parent) != 0) {
        close(s->parent_to_child[0]);
        close(s->parent_to_child[1]);
        return -1;
    }
    return 0;
}

static void close_fd(int *fd)
{
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

static void sync_fini(sync_t *s)
{
    close_fd(&s->parent_to_child[0]);
    close_fd(&s->parent_to_child[1]);
    close_fd(&s->child_to_parent[0]);
    close_fd(&s->child_to_parent[1]);
}

static void parent_close_child_ends(sync_t *s)
{
    close_fd(&s->parent_to_child[0]);
    close_fd(&s->child_to_parent[1]);
}

static void child_close_parent_ends(sync_t *s)
{
    close_fd(&s->parent_to_child[1]);
    close_fd(&s->child_to_parent[0]);
}

/* Drop the parent's write end so a child blocked in wait_byte() on the
 * parent_to_child read end observes EOF and exits instead of deadlocking with
 * the parent in waitpid(). Must be called on every parent-side failure path
 * that bypasses send_byte(parent_to_child[1]).
 */
static void parent_release_writer(sync_t *s)
{
    close_fd(&s->parent_to_child[1]);
}

/* Reap @pid and report a child that did not exit 0.
 *
 * Returns true only when the child exited cleanly and the parent side had not
 * already failed, so the caller can add its own final check before PASS(). A
 * parent-side failure is already reported; it only has to avoid a second
 * verdict here.
 */
static bool reap_child_ok(pid_t pid, bool failed)
{
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        FAIL("waitpid");
        return false;
    }
    if (failed)
        return false;
    if (!WIFEXITED(status)) {
        FAIL("child terminated abnormally");
        return false;
    }
    if (WEXITSTATUS(status) != 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "child failed at step %d",
                 WEXITSTATUS(status));
        FAIL(buf);
        return false;
    }
    return true;
}

/* Wait for a single byte from the peer; returns true on success. */
static bool wait_byte(int fd)
{
    char b;
    ssize_t n;
    do {
        n = read(fd, &b, 1);
    } while (n < 0 && errno == EINTR);
    return n == 1;
}

static bool send_byte(int fd)
{
    char b = 'x';
    ssize_t n;
    do {
        n = write(fd, &b, 1);
    } while (n < 0 && errno == EINTR);
    return n == 1;
}

/* Test 1: File-backed MAP_SHARED -- parent and child see each other's writes
 * through the same disk file without msync.
 */
static void test_file_backed_cross_fork(void)
{
    TEST("MAP_SHARED file: cross-fork live coherence");

    char tmpl[] = "/tmp/elfuse-cf-mapshared-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }

    /* Keep the file present so child can re-open via /proc semantics is
     * unnecessary -- the child inherits fd from CLOEXEC=off and we map via the
     * inherited fd. Unlink keeps the file on the FS but invisible via path;
     * both sides hold open references.
     */
    unlink(tmpl);

    if (ftruncate(fd, 4096) != 0) {
        FAIL("ftruncate");
        close(fd);
        return;
    }

    char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("parent mmap");
        close(fd);
        return;
    }

    /* Parent seeds with 'P' before fork. Child should observe it. */
    p[0] = 'P';

    sync_t s;
    if (sync_init(&s) < 0) {
        FAIL("sync_init");
        munmap(p, 4096);
        close(fd);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork");
        sync_fini(&s);
        munmap(p, 4096);
        close(fd);
        return;
    }

    if (pid == 0) {
        child_close_parent_ends(&s);
        /* Step 1: child observes parent's pre-fork seed 'P'. */
        if (p[0] != 'P')
            _exit(10);
        /* Step 2: child writes 'C', signals parent. */
        p[1] = 'C';
        if (!send_byte(s.child_to_parent[1]))
            _exit(11);
        /* Step 3: child waits for parent's mid-run write 'M'. */
        if (!wait_byte(s.parent_to_child[0]))
            _exit(12);
        if (p[2] != 'M')
            _exit(13);
        _exit(0);
    }

    parent_close_child_ends(&s);
    bool failed = false;
    /* Step 2: wait for child's write of 'C'. */
    if (!wait_byte(s.child_to_parent[0])) {
        FAIL("child sync recv");
        failed = true;
    } else if (p[1] != 'C') {
        FAIL("parent did not see child write");
        failed = true;
    } else {
        /* Step 3: parent writes 'M' for child to verify. */
        p[2] = 'M';
        if (!send_byte(s.parent_to_child[1])) {
            FAIL("parent sync send");
            failed = true;
        }
    }

    /* Drop the writer so a child blocked in wait_byte() sees EOF when the
     * parent took an early failure exit; without this both processes deadlock
     * and the test driver kills the parent on timeout.
     */
    parent_release_writer(&s);
    if (reap_child_ok(pid, failed)) {
        /* Verify file content reflects both writes. */
        char disk[3] = {0};
        if (pread(fd, disk, 3, 0) != 3)
            FAIL("pread");
        else if (disk[0] == 'P' && disk[1] == 'C' && disk[2] == 'M')
            PASS();
        else
            FAIL("file content does not reflect both sides");
    }

    sync_fini(&s);
    munmap(p, 4096);
    close(fd);
}

/* Test 2: Anonymous MAP_SHARED -- typical parent-child IPC pattern (Postgres,
 * multi-process daemons). elfuse must convert the region to memfd-backed at
 * fork time so both sides observe writes.
 */
static void test_anon_shared_cross_fork(void)
{
    TEST("MAP_SHARED|MAP_ANONYMOUS: cross-fork live coherence");

    char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap MAP_SHARED|MAP_ANONYMOUS");
        return;
    }

    p[0] = 'P';

    sync_t s;
    if (sync_init(&s) < 0) {
        FAIL("sync_init");
        munmap(p, 4096);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork");
        sync_fini(&s);
        munmap(p, 4096);
        return;
    }

    if (pid == 0) {
        child_close_parent_ends(&s);
        if (p[0] != 'P')
            _exit(20);
        p[1] = 'C';
        if (!send_byte(s.child_to_parent[1]))
            _exit(21);
        if (!wait_byte(s.parent_to_child[0]))
            _exit(22);
        if (p[2] != 'M')
            _exit(23);
        _exit(0);
    }

    parent_close_child_ends(&s);
    bool failed = false;
    if (!wait_byte(s.child_to_parent[0])) {
        FAIL("child sync recv");
        failed = true;
    } else if (p[1] != 'C') {
        FAIL("parent did not see child write");
        failed = true;
    } else {
        p[2] = 'M';
        if (!send_byte(s.parent_to_child[1])) {
            FAIL("parent sync send");
            failed = true;
        }
    }

    /* See the file-backed test: drop the writer before waitpid so any failure
     * above does not deadlock both ends of the pipe.
     */
    parent_release_writer(&s);
    if (reap_child_ok(pid, failed))
        PASS();

    sync_fini(&s);
    munmap(p, 4096);
}

/* Test 3: shm-backed MAP_SHARED via /dev/shm -- same as test 1 but exercises
 * the shm path (musl/glibc shm_open emulation in elfuse).
 */
static void test_shm_cross_fork(void)
{
    TEST("MAP_SHARED shm: cross-fork live coherence");

    char name[64] = "/dev/shm/elfuse-cf-shm-XXXXXX";
    int fd = mkstemp(name);
    if (fd < 0) {
        FAIL("mkstemp /dev/shm failed");
        return;
    }
    unlink(name);

    if (ftruncate(fd, 4096) != 0) {
        FAIL("ftruncate");
        close(fd);
        return;
    }

    char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        close(fd);
        return;
    }
    p[0] = 'P';

    sync_t s;
    if (sync_init(&s) < 0) {
        FAIL("sync_init");
        munmap(p, 4096);
        close(fd);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork");
        sync_fini(&s);
        munmap(p, 4096);
        close(fd);
        return;
    }

    if (pid == 0) {
        child_close_parent_ends(&s);
        if (p[0] != 'P')
            _exit(30);
        p[1] = 'C';
        if (!send_byte(s.child_to_parent[1]))
            _exit(31);
        if (!wait_byte(s.parent_to_child[0]))
            _exit(32);
        if (p[2] != 'M')
            _exit(33);
        _exit(0);
    }

    parent_close_child_ends(&s);
    bool failed = false;
    if (!wait_byte(s.child_to_parent[0])) {
        FAIL("child sync recv");
        failed = true;
    } else if (p[1] != 'C') {
        FAIL("parent did not see child write");
        failed = true;
    } else {
        p[2] = 'M';
        if (!send_byte(s.parent_to_child[1])) {
            FAIL("parent sync send");
            failed = true;
        }
    }

    /* See the file-backed test: drop the writer before waitpid so any failure
     * above does not deadlock both ends of the pipe.
     */
    parent_release_writer(&s);
    if (reap_child_ok(pid, failed))
        PASS();

    sync_fini(&s);
    munmap(p, 4096);
    close(fd);
}

int main(void)
{
    printf("test-cross-fork-mapshared: cross-fork MAP_SHARED tests\n\n");
    fflush(stdout);

    test_file_backed_cross_fork();
    fflush(stdout);
    test_anon_shared_cross_fork();
    fflush(stdout);
    test_shm_cross_fork();
    fflush(stdout);

    SUMMARY("test-cross-fork-mapshared");
    return fails ? 1 : 0;
}
