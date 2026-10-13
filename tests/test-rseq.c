/*
 * Test rseq registration ABI
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests: register, unregister, double-register, unregister-without-register,
 *        invalid length, invalid flags, signature mismatch on unregister, and a
 *        signal delivered while registered (signal delivery reads the rseq area
 *        to abort a critical section, the access make check-locks checks)
 */

#include <signal.h>
#include <unistd.h>

#include "test-harness.h"
#include "raw-syscall.h"

#define __NR_rseq 293
#define RSEQ_FLAG_UNREGISTER 1

/* Minimal struct rseq (32 bytes minimum) */
struct rseq {
    unsigned int cpu_id_start, cpu_id;
    unsigned long long rseq_cs;
    unsigned int flags;
    unsigned int padding[3];
} __attribute__((aligned(32)));

static volatile sig_atomic_t got_usr1;

static void on_usr1(int sig)
{
    (void) sig;
    got_usr1 = 1;
}

int main(void)
{
    int passes = 0, fails = 0;
    struct rseq rs = {0};
    unsigned int sig = 0xdeadbeef;

    printf("test-rseq: rseq registration ABI tests\n");

    /* Registration with valid parameters */
    TEST("register succeeds");
    {
        long rc = raw_syscall4(__NR_rseq, (long) &rs, sizeof(rs), 0, sig);
        EXPECT_TRUE(rc == 0, "register failed");
    }

    /* cpu_id should be set to 0 (elfuse presents single CPU) */
    TEST("cpu_id == 0 after register");
    EXPECT_TRUE(rs.cpu_id == 0, "cpu_id not 0");

    /* rseq_cs should be cleared */
    TEST("rseq_cs == 0 after register");
    EXPECT_TRUE(rs.rseq_cs == 0, "rseq_cs not 0");

    /* Double registration returns -EBUSY */
    TEST("double register returns -EBUSY");
    {
        struct rseq rs2 = {0};
        long rc = raw_syscall4(__NR_rseq, (long) &rs2, sizeof(rs2), 0, sig);
        if (rc == -16) /* -EBUSY */
            PASS();
        else
            FAIL("expected -EBUSY");
    }

    /* Unregistration with correct address and signature */
    TEST("unregister succeeds");
    {
        long rc = raw_syscall4(__NR_rseq, (long) &rs, sizeof(rs),
                               RSEQ_FLAG_UNREGISTER, sig);
        EXPECT_TRUE(rc == 0, "unregister failed");
    }

    /* Unregister without active registration returns -EINVAL */
    TEST("unregister-no-reg returns -EINVAL");
    {
        long rc = raw_syscall4(__NR_rseq, (long) &rs, sizeof(rs),
                               RSEQ_FLAG_UNREGISTER, sig);
        if (rc == -22) /* -EINVAL */
            PASS();
        else
            FAIL("expected -EINVAL");
    }

    /* Re-register after unregister should succeed */
    TEST("re-register after unregister");
    {
        long rc = raw_syscall4(__NR_rseq, (long) &rs, sizeof(rs), 0, sig);
        EXPECT_TRUE(rc == 0, "re-register failed");
    }

    TEST("signal delivered while registered");
    {
        signal(SIGUSR1, on_usr1);
        kill(getpid(), SIGUSR1);
        EXPECT_TRUE(got_usr1, "handler did not run");
        signal(SIGUSR1, SIG_DFL);
    }

    /* Unregister with wrong signature returns -EINVAL */
    TEST("unregister wrong sig returns -EINVAL");
    {
        long rc = raw_syscall4(__NR_rseq, (long) &rs, sizeof(rs),
                               RSEQ_FLAG_UNREGISTER, 0xbaadf00d);
        if (rc == -22) /* -EINVAL */
            PASS();
        else
            FAIL("expected -EINVAL");
    }

    /* Clean up: unregister with correct sig */
    raw_syscall4(__NR_rseq, (long) &rs, sizeof(rs), RSEQ_FLAG_UNREGISTER, sig);

    /* Invalid length < 32 */
    TEST("length < 32 returns -EINVAL");
    {
        long rc = raw_syscall4(__NR_rseq, (long) &rs, 16, 0, sig);
        if (rc == -22) /* -EINVAL */
            PASS();
        else
            FAIL("expected -EINVAL");
    }

    /* Invalid flags (neither 0 nor UNREGISTER) */
    TEST("invalid flags returns -EINVAL");
    {
        long rc = raw_syscall4(__NR_rseq, (long) &rs, sizeof(rs), 0xFF, sig);
        if (rc == -22) /* -EINVAL */
            PASS();
        else
            FAIL("expected -EINVAL");
    }

    SUMMARY("test-rseq");
    return fails ? 1 : 0;
}
