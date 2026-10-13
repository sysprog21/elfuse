/*
 * Test signal delivery and rt_sigreturn
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Verifies:
 * 1. Basic delivery: rt_sigaction installs a handler for SIGUSR1,
 *    kill(getpid(), SIGUSR1) fires it with the correct signum
 * 2. rt_sigreturn restores all callee-saved registers
 *    (aarch64: X19-X28, x86_64: rbx/r12-r15)
 * 3. sigprocmask blocks/unblocks signals correctly
 * 4. SA_RESETHAND resets the handler to SIG_DFL after delivery
 * 5. alarm() interrupts a blocking read with EINTR
 * 6. X7 survives delivery and rt_sigreturn (aarch64: the host uses X7 on the
 *    HVC #5 return to ask the shim for a ptrace detour, and the tails that
 *    rebuild EL0 state never restore it from the saved frame)
 * 7. A bad old-value pointer to rt_sigaction or rt_sigprocmask is EFAULT with
 *    the new action or mask already in place, as in Linux
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>

static volatile sig_atomic_t handler_called = 0;
static volatile int handler_signum = 0;

static void sigusr1_handler(int sig)
{
    handler_called = 1;
    handler_signum = sig;
}

/* Test that callee-saved registers survive signal delivery. The inline asm
 * loads known values into callee-saved registers, sends SIGUSR1 (which triggers
 * delivery + rt_sigreturn), then verifies the registers are unchanged.
 *
 * aarch64 callee-saved: X19-X28 (10 registers) x86_64 callee-saved: rbx,
 * r12-r15 (5 registers; rbp excluded
 *   because GCC needs it as frame pointer in functions with calls)
 */
static int test_callee_saved(void)
{
#if defined(__aarch64__)
    /* cppcheck-suppress syntaxError */
    register long r0 __asm__("x19") = 0xDEAD0019;
    register long r1 __asm__("x20") = 0xDEAD0020;
    register long r2 __asm__("x21") = 0xDEAD0021;
    register long r3 __asm__("x22") = 0xDEAD0022;
    register long r4 __asm__("x23") = 0xDEAD0023;
    register long r5 __asm__("x24") = 0xDEAD0024;
    register long r6 __asm__("x25") = 0xDEAD0025;
    register long r7 __asm__("x26") = 0xDEAD0026;
    register long r8 __asm__("x27") = 0xDEAD0027;
    register long r9 __asm__("x28") = 0xDEAD0028;
#define N_CALLEE_SAVED 10
    long expect[] = {0xDEAD0019, 0xDEAD0020, 0xDEAD0021, 0xDEAD0022,
                     0xDEAD0023, 0xDEAD0024, 0xDEAD0025, 0xDEAD0026,
                     0xDEAD0027, 0xDEAD0028};
    const char *names[] = {"X19", "X20", "X21", "X22", "X23",
                           "X24", "X25", "X26", "X27", "X28"};

    __asm__ volatile(""
                     : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4),
                       "+r"(r5), "+r"(r6), "+r"(r7), "+r"(r8), "+r"(r9));

    kill(getpid(), SIGUSR1);

    __asm__ volatile(""
                     : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4),
                       "+r"(r5), "+r"(r6), "+r"(r7), "+r"(r8), "+r"(r9));

    long actual[] = {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9};

#elif defined(__x86_64__)
    /* cppcheck-suppress syntaxError */
    register long r0 __asm__("rbx") = 0xDEAD0001;
    register long r1 __asm__("r12") = 0xDEAD0002;
    register long r2 __asm__("r13") = 0xDEAD0003;
    register long r3 __asm__("r14") = 0xDEAD0004;
    register long r4 __asm__("r15") = 0xDEAD0005;
#define N_CALLEE_SAVED 5
    long expect[] = {0xDEAD0001, 0xDEAD0002, 0xDEAD0003, 0xDEAD0004,
                     0xDEAD0005};
    const char *names[] = {"rbx", "r12", "r13", "r14", "r15"};

    __asm__ volatile("" : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4));

    kill(getpid(), SIGUSR1);

    __asm__ volatile("" : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4));

    long actual[] = {r0, r1, r2, r3, r4};

#else
#error "Unsupported architecture"
#endif

    bool ok = true;
    for (int i = 0; i < N_CALLEE_SAVED; i++) {
        if (actual[i] != expect[i]) {
            printf("  %s corrupted: 0x%lx\n", names[i], actual[i]);
            ok = false;
        }
    }
#undef N_CALLEE_SAVED
    return ok;
}

#if defined(__aarch64__)
#define X7_CANARY 0x00C0FFEE0000B007ULL
static volatile unsigned long uc_x7 = 0;

static void x7_handler(int sig, siginfo_t *info, void *ucv)
{
    (void) info;
    ucontext_t *uc = ucv;
    uc_x7 = uc->uc_mcontext.regs[7];
    handler_signum = sig;
    handler_called = 1;
}

/* Park the canary in X7, then take an SVC that queues a signal to this thread.
 * Delivery happens on that syscall's return path, so both the handler's
 * ucontext and the state rt_sigreturn resumes on have to show the canary. A
 * host-only flag left in X7 shows up as a zero in one or both.
 */
static unsigned long x7_across_signal(long pid, long sig)
{
    register long x0 __asm__("x0") = pid;
    register long x1 __asm__("x1") = sig;
    register unsigned long x7 __asm__("x7") = X7_CANARY;
    register long x8 __asm__("x8") = 129; /* SYS_kill */

    /* X8 is an in-out operand, not an input. Linux preserves it across SVC and
     * so does the shim's frame restore, but a signal delivered on this return
     * takes the drop-frame tail, and the frame rt_sigreturn restores from
     * snapshotted X8 after the host had already written the TLBI request into
     * it. Letting the compiler assume 129 survives would be wrong here.
     */
    __asm__ volatile("svc #0\n"
                     : "+r"(x0), "+r"(x7), "+r"(x8)
                     : "r"(x1)
                     : "memory", "cc");
    return x7;
}
#endif

int main(void)
{
    int failures = 0;

    /* Test 1: Basic signal delivery */
    printf("test-signal: 1. basic signal delivery... ");
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        printf("FAIL (sigaction: %m)\n");
        return 1;
    }
    kill(getpid(), SIGUSR1);
    if (handler_called && handler_signum == SIGUSR1) {
        printf("PASS\n");
    } else {
        printf("FAIL (called=%d, signum=%d)\n", handler_called, handler_signum);
        failures++;
    }

    /* Test 2: Callee-saved register preservation */
    printf("test-signal: 2. callee-saved register preservation... ");
    handler_called = 0;
    if (test_callee_saved() && handler_called) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        failures++;
    }

    /* Test 3: Signal blocking with sigprocmask */
    printf("test-signal: 3. signal blocking (sigprocmask)... ");
    handler_called = 0;
    sigset_t block_set, old_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &block_set, &old_set);

    kill(getpid(), SIGUSR1); /* Should be queued, not delivered */
    if (handler_called) {
        printf("FAIL (signal delivered while blocked)\n");
        failures++;
    } else {
        /* Unblock; signal should deliver now */
        sigprocmask(SIG_SETMASK, &old_set, NULL);
        if (handler_called) {
            printf("PASS\n");
        } else {
            printf("FAIL (signal not delivered after unblock)\n");
            failures++;
        }
    }

    /* Test 4: SA_RESETHAND */
    printf("test-signal: 4. SA_RESETHAND... ");
    handler_called = 0;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler, sa.sa_flags = SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
    kill(getpid(), SIGUSR1);
    if (!handler_called) {
        printf("FAIL (handler not called)\n");
        failures++;
    } else {
        /* Handler should have been reset to SIG_DFL. Sending SIGUSR1 again
         * should terminate the process, but the test cannot observe that
         * directly. Instead, check that the old action is SIG_DFL now.
         */
        struct sigaction old;
        sigaction(SIGUSR1, NULL, &old);
        if (old.sa_handler == SIG_DFL) {
            printf("PASS\n");
        } else {
            printf("FAIL (handler not reset to SIG_DFL)\n");
            failures++;
        }
    }

    /* Test 5: alarm() interrupts a blocking read. The guest ITIMER_REAL is
     * virtual, so the expiry must be materialized while the thread is parked
     * inside the interruptible wait, not only in the syscall epilogue.
     */
    printf("test-signal: 5. alarm interrupts blocking read (EINTR)... ");
    {
        int p[2];
        if (pipe(p) != 0) {
            printf("FAIL (pipe: %m)\n");
            failures++;
        } else {
            memset(&sa, 0, sizeof(sa));
            sa.sa_handler = sigusr1_handler; /* no SA_RESTART */
            sigemptyset(&sa.sa_mask);
            sigaction(SIGALRM, &sa, NULL);
            handler_called = 0;
            char c;
            alarm(1);
            errno = 0;
            ssize_t n = read(p[0], &c, 1);
            int read_errno = errno;
            alarm(0);
            if (n == -1 && read_errno == EINTR && handler_called &&
                handler_signum == SIGALRM) {
                printf("PASS\n");
            } else {
                printf("FAIL (n=%zd errno=%d handler=%d signum=%d)\n", n,
                       read_errno, (int) handler_called, handler_signum);
                failures++;
            }
            close(p[0]);
            close(p[1]);
        }
    }

#if defined(__aarch64__)
    /* Test 6: X7 is not part of the syscall return ABI */
    printf("test-signal: 6. X7 survives delivery and rt_sigreturn... ");
    {
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = x7_handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR1, &sa, NULL);
        handler_called = 0;
        uc_x7 = 0;
        unsigned long resumed = x7_across_signal(getpid(), SIGUSR1);
        if (handler_called && uc_x7 == X7_CANARY && resumed == X7_CANARY) {
            printf("PASS\n");
        } else {
            printf("FAIL (uc=0x%lx resumed=0x%lx)\n", uc_x7, resumed);
            failures++;
        }
    }
#endif

    /* Test 7: raw syscalls, because libc copies the old value out itself and
     * would fault in user space instead of returning EFAULT.
     */
    printf("test-signal: 7. bad old pointer keeps the new state... ");
    {
        struct {
            unsigned long handler, flags, restorer, mask;
        } kact = {(unsigned long) sigusr1_handler, 0, 0, 0};
        unsigned long set = 1UL << (SIGUSR2 - 1);
        void *bad = (void *) 8;
        errno = 0;
        long a = syscall(SYS_rt_sigaction, SIGUSR2, &kact, bad, 8);
        int a_errno = errno;
        errno = 0;
        long m = syscall(SYS_rt_sigprocmask, SIG_BLOCK, &set, bad, 8);
        int m_errno = errno;

        struct sigaction now;
        sigset_t cur;
        sigaction(SIGUSR2, NULL, &now);
        sigprocmask(SIG_BLOCK, NULL, &cur);
        if (a == -1 && a_errno == EFAULT && m == -1 && m_errno == EFAULT &&
            now.sa_handler == sigusr1_handler && sigismember(&cur, SIGUSR2)) {
            printf("PASS\n");
        } else {
            printf("FAIL (a=%ld/%d m=%ld/%d installed=%d blocked=%d)\n", a,
                   a_errno, m, m_errno, now.sa_handler == sigusr1_handler,
                   sigismember(&cur, SIGUSR2));
            failures++;
        }
        signal(SIGUSR2, SIG_DFL);
        sigemptyset(&cur);
        sigaddset(&cur, SIGUSR2);
        sigprocmask(SIG_UNBLOCK, &cur, NULL);
    }

    if (failures == 0) {
        printf("test-signal: all tests passed -- PASS\n");
        return 0;
    }
    printf("test-signal: %d test(s) failed -- FAIL\n", failures);
    return 1;
}
