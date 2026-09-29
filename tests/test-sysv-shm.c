/*
 * SysV shared memory protection tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Syscalls: shmget, shmat, shmdt, shmctl, fork, wait4
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

static void test_shm_rdonly_faults_on_write(void)
{
    TEST("SHM_RDONLY faults on write");

    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    if (shmid < 0) {
        FAIL("shmget failed");
        return;
    }

    char *rw = shmat(shmid, NULL, 0);
    if (rw == (void *) -1) {
        FAIL("shmat rw failed");
        shmctl(shmid, IPC_RMID, NULL);
        return;
    }
    rw[0] = 'A';
    shmdt(rw);

    char *ro = shmat(shmid, NULL, SHM_RDONLY);
    if (ro == (void *) -1) {
        FAIL("shmat readonly failed");
        shmctl(shmid, IPC_RMID, NULL);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork failed");
        shmdt(ro);
        shmctl(shmid, IPC_RMID, NULL);
        return;
    }

    if (pid == 0) {
        volatile char *p = ro;
        p[0] = 'B';
        _exit(0);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        FAIL("waitpid failed");
    } else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) {
        PASS();
    } else if (WIFEXITED(status) && WEXITSTATUS(status) == (128 + SIGSEGV)) {
        /* elfuse fork children report signal deaths as exit(128+signum) */
        PASS();
    } else {
        FAIL("readonly shmat write did not fault");
    }

    shmdt(ro);
    shmctl(shmid, IPC_RMID, NULL);
}

static void test_shm_detach_unmapped(void)
{
    TEST("detach after guest munmap");
    const size_t len = 2UL << 20;
    int shmid = shmget(IPC_PRIVATE, len, IPC_CREAT | 0600);
    if (shmid < 0) {
        FAIL("shmget");
        return;
    }
    void *p = shmat(shmid, NULL, 0);
    if (p == (void *) -1) {
        FAIL("shmat");
        shmctl(shmid, IPC_RMID, NULL);
        return;
    }
    int unmapped = munmap(p, len);
    int detached = shmdt(p);
    int detach_errno = errno;
    struct shmid_ds info;
    /* Linux's munmap already detaches; elfuse retains a host attachment. */
    int ok = unmapped == 0 &&
             (detached == 0 || (detached == -1 && detach_errno == EINVAL)) &&
             shmctl(shmid, IPC_STAT, &info) == 0 && info.shm_nattch == 0;
    shmctl(shmid, IPC_RMID, NULL);
    EXPECT_TRUE(ok, "detach hung, failed, or leaked its host attachment");
}

int main(void)
{
    printf("test-sysv-shm: SysV shared memory tests\n\n");

    test_shm_rdonly_faults_on_write();
    test_shm_detach_unmapped();

    SUMMARY("test-sysv-shm");
    return fails > 0 ? 1 : 0;
}
