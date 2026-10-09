/*
 * Test clone3 syscall in elfuse
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests clone3 for both fork (new process) and thread (CLONE_THREAD) paths,
 * verifying that the clone_args struct is correctly parsed and delegated to the
 * existing clone infrastructure.
 */

#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include "test-harness.h"
#include "raw-syscall.h"
#include "test-util.h"

int passes = 0, fails = 0;
extern char **environ;
static const char *self_path = NULL;

static void check(int cond, const char *fmt, ...)
{
    if (cond) {
        passes++;
        return;
    }

    printf("FAIL: ");
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fails++;
}

#define CHECK(cond, ...) check((cond), __VA_ARGS__)

/* Linux clone3 constants (aarch64 asm-generic) */
#ifndef __NR_clone3
#define __NR_clone3 435
#endif

#define CLONE3_THREAD 0x00010000
#define CLONE3_VM 0x00000100
#define CLONE3_VFORK 0x00004000
#define CLONE3_SIGHAND 0x00000800
#define CLONE3_FILES 0x00000400
#define CLONE3_FS 0x00000200
#define CLONE3_CHILD_CLEARTID 0x00200000
#define CLONE3_CHILD_SETTID 0x01000000

/* clone_args struct matching kernel v5.3+ layout */
struct clone_args {
    uint64_t flags, pidfd;
    uint64_t child_tid, parent_tid;
    uint64_t exit_signal, stack, stack_size, tls, set_tid, set_tid_size, cgroup;
};

#define CLONE_ARGS_SIZE_VER0 64 /* first 8 fields */

/* Shared state for thread test */
static volatile int thread_done = 0;
static volatile int thread_result = 0;
static volatile int thread_tid = 0;
static volatile int vfork_exec_guard = 0x13579bdf;
static volatile int parked_thread_state = 0;

/* Thread entry: sets thread_result and signals done via futex */
static int thread_fn(void)
{
    thread_result = 42;
    __atomic_store_n(&thread_done, 1, __ATOMIC_SEQ_CST);
    raw_syscall6(__NR_futex, (long) &thread_done,
                 FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0, 0, 0);
    raw_exit(0);
    test_unreachable();
}

static int parked_thread_fn(void)
{
    __atomic_store_n(&parked_thread_state, 1, __ATOMIC_SEQ_CST);
    raw_syscall6(__NR_futex, (long) &parked_thread_state,
                 FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0, 0, 0);

    while (__atomic_load_n(&parked_thread_state, __ATOMIC_SEQ_CST) == 1) {
        raw_syscall6(__NR_futex, (long) &parked_thread_state,
                     FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 1, 0, 0, 0);
    }

    raw_exit(0);
    test_unreachable();
}

static uint64_t read_sp(void)
{
    uint64_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    return sp;
}

/* Test 1: clone3 basic fork */
static void test_fork(void)
{
    struct clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.exit_signal = 17; /* SIGCHLD on aarch64 */

    long ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    if (ret < 0) {
        CHECK(0, "clone3 fork failed with %ld", ret);
        return;
    }

    if (ret == 0) {
        /* Child: exit with distinctive code */
        _exit(7);
    }

    /* Parent: wait for child */
    int status = 0;
    pid_t waited = waitpid((pid_t) ret, &status, 0);
    CHECK(waited == (pid_t) ret, "waitpid returned %d, expected %ld", waited,
          ret);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 7,
          "child exit status: 0x%x (expected exit 7)", status);
}

/* Test 2: clone3 with thread */
static void test_thread(void)
{
    /* Allocate a stack for the child thread */
    size_t stack_size = 65536;
    void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(stack != MAP_FAILED, "mmap for thread stack failed");
    if (stack == MAP_FAILED)
        return;

    thread_done = 0;
    thread_result = 0;
    thread_tid = 0;

    struct clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.flags = CLONE3_THREAD | CLONE3_VM | CLONE3_SIGHAND | CLONE3_FILES |
               CLONE3_FS | CLONE3_CHILD_CLEARTID | CLONE3_CHILD_SETTID;
    ca.exit_signal = 0; /* threads do not send signals on exit */
    ca.stack = (uint64_t) stack;
    ca.stack_size = stack_size;
    ca.child_tid = (uint64_t) &thread_tid; /* set_child_tid / clear_child_tid */

    /* Point the child's PC at thread_fn. clone3 with CLONE_THREAD resumes at
     * the parent's PC but with X0=0. The caller needs the child to jump to
     * thread_fn, so the caller sets up the stack with a return address.
     * Actually, clone resumes at parent PC with X0=0 and the new stack, so the
     * caller needs to arrange for the child to call thread_fn from the clone
     * return path.
     *
     * For raw clone, the child returns from the syscall with X0=0. The code
     * checks X0 in the caller. But since this is inline asm returning to the
     * same PC, the test handles it by checking the return value.
     */

    long ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    if (ret == 0) {
        /* Child thread: the child is on the new stack */
        thread_fn();
        __builtin_unreachable();
    }

    CHECK(ret > 0, "clone3 thread returned %ld", ret);
    if (ret < 0) {
        munmap(stack, stack_size);
        return;
    }

    /* Wait for child thread via futex on thread_done */
    int attempts = 0;
    while (__atomic_load_n(&thread_done, __ATOMIC_SEQ_CST) == 0 &&
           attempts < 1000) {
        raw_syscall6(__NR_futex, (long) &thread_done,
                     FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
        attempts++;
    }

    CHECK(thread_done == 1, "thread_done=%d (expected 1)", thread_done);
    CHECK(thread_result == 42, "thread_result=%d (expected 42)", thread_result);

    /* Wait for CLONE_CHILD_CLEARTID before unmapping the child's stack. */
    while (__atomic_load_n(&thread_tid, __ATOMIC_SEQ_CST) != 0) {
        int tid = __atomic_load_n(&thread_tid, __ATOMIC_SEQ_CST);
        raw_syscall6(__NR_futex, (long) &thread_tid,
                     FUTEX_WAIT | FUTEX_PRIVATE_FLAG, tid, 0, 0, 0);
    }

    munmap(stack, stack_size);
}

/* Test 3: clone3 rejects invalid size */
static void test_invalid_size(void)
{
    struct clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.exit_signal = 17;

    /* Size too small */
    long ret = raw_clone3(&ca, 32);
    CHECK(ret == -22 /* EINVAL */,
          "clone3 size=32 returned %ld (expected -EINVAL)", ret);

    /* Size zero */
    ret = raw_clone3(&ca, 0);
    CHECK(ret == -22, "clone3 size=0 returned %ld (expected -EINVAL)", ret);
}

/* Test 4: clone3 rejects unsupported flags */
static void test_unsupported_flags(void)
{
    struct clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.exit_signal = 17;

    /* CLONE_PIDFD: now supported. Clone should succeed (returns child PID in
     * parent, 0 in child). Reap the child to avoid zombies.
     */
    int32_t pidfd_out = -1;
    ca.flags = 0x00001000; /* CLONE_PIDFD */
    ca.pidfd = (uint64_t) &pidfd_out;
    long ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    if (ret == 0) {
        /* child: exit immediately */
        raw_syscall1(__NR_exit, 0);
        __builtin_unreachable();
    }
    CHECK(ret > 0, "clone3 CLONE_PIDFD returned %ld (expected >0)", ret);
    if (ret > 0) {
        /* Reap child */
        raw_syscall4(__NR_wait4, ret, 0, 0, 0);
        if (pidfd_out >= 0)
            raw_syscall1(__NR_close, pidfd_out);
    }
    ca.pidfd = 0;

    /* CLONE_NEWPID not supported */
    ca.flags = 0x20000000; /* CLONE_NEWPID */
    ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    CHECK(ret == -22, "clone3 CLONE_NEWPID returned %ld (expected -EINVAL)",
          ret);
}

/* CLONE_PIDFD and CLONE_PARENT_SETTID may both be asked for, but not into the
 * same word: Linux refuses that before any child exists, and the slot keeps
 * what it held.
 */
static void test_pidfd_parent_tid_alias(void)
{
    struct clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.exit_signal = 17;

    int32_t slot = 0x5a5a5a5a;
    ca.flags = 0x00001000 | 0x00100000; /* CLONE_PIDFD | CLONE_PARENT_SETTID */
    ca.pidfd = (uint64_t) &slot;
    ca.parent_tid = (uint64_t) &slot;
    long ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    if (ret == 0) {
        raw_syscall1(__NR_exit, 0);
        __builtin_unreachable();
    }
    if (ret > 0)
        raw_syscall4(__NR_wait4, ret, 0, 0, 0);
    CHECK(ret == -22,
          "clone3 pidfd == parent_tid returned %ld (expected -EINVAL)", ret);
    CHECK(slot == 0x5a5a5a5a, "clone3 pidfd == parent_tid wrote the slot: %d",
          slot);
}

/* Test 5: clone3 with larger struct (zero tail = ok) */
static void test_larger_struct(void)
{
    /* Allocate a larger buffer, zero-filled */
    char buf[256];
    memset(buf, 0, sizeof(buf));
    struct clone_args *ca = (struct clone_args *) buf;
    ca->exit_signal = 17;

    long ret = raw_clone3(ca, sizeof(buf));
    if (ret < 0) {
        CHECK(0, "clone3 with larger struct failed: %ld", ret);
        return;
    }
    if (ret == 0)
        _exit(0);
    int status = 0;
    waitpid((pid_t) ret, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "child from larger struct exited with 0x%x", status);
}

/* Test 6: clone3 with non-zero tail = E2BIG */
static void test_nonzero_tail(void)
{
    char buf[256];
    memset(buf, 0, sizeof(buf));
    struct clone_args *ca = (struct clone_args *) buf;
    ca->exit_signal = 17;
    /* Set a byte in the unknown tail */
    buf[sizeof(struct clone_args) + 1] = 0xff;

    long ret = raw_clone3(ca, sizeof(buf));
    CHECK(ret == -7 /* E2BIG */,
          "clone3 non-zero tail returned %ld (expected -E2BIG)", ret);
}

/* Test 7: CSIGNAL bits in flags must be zero */
static void test_csignal_in_flags(void)
{
    struct clone_args ca;
    memset(&ca, 0, sizeof(ca));
    /* Put SIGCHLD (17) in the flags low byte; clone3 forbids this */
    ca.flags = 17;
    ca.exit_signal = 0;

    long ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    CHECK(ret == -22, "clone3 flags=17 returned %ld (expected -EINVAL)", ret);

    /* Both flags low byte AND exit_signal set; should also fail */
    ca.flags = 1;
    ca.exit_signal = 17;
    ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    CHECK(ret == -22,
          "clone3 flags=1+exit_signal=17 returned %ld (expected -EINVAL)", ret);
}

/* Test 8: CLONE_THREAD + exit_signal != 0 is invalid */
static void test_thread_with_signal(void)
{
    struct clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.flags =
        CLONE3_THREAD | CLONE3_VM | CLONE3_SIGHAND | CLONE3_FILES | CLONE3_FS;
    ca.exit_signal = 17; /* SIGCHLD, invalid with CLONE_THREAD */
    ca.stack = 0x10000;  /* non-zero to satisfy stack pair check */
    ca.stack_size = 0x10000;

    long ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    CHECK(ret == -22,
          "clone3 CLONE_THREAD+SIGCHLD returned %ld (expected -EINVAL)", ret);
}

/* Test 9: stack/stack_size mismatch */
static void test_stack_mismatch(void)
{
    struct clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.exit_signal = 17;

    /* stack != 0 but stack_size == 0 */
    ca.stack = 0x10000;
    ca.stack_size = 0;
    long ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    CHECK(ret == -22, "clone3 stack!=0,size=0 returned %ld (expected -EINVAL)",
          ret);

    /* stack == 0 but stack_size != 0 */
    ca.stack = 0;
    ca.stack_size = 0x10000;
    ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    CHECK(ret == -22, "clone3 stack=0,size!=0 returned %ld (expected -EINVAL)",
          ret);
}

/* Test 10: stack + stack_size overflow */
static void test_stack_overflow(void)
{
    struct clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.flags =
        CLONE3_THREAD | CLONE3_VM | CLONE3_SIGHAND | CLONE3_FILES | CLONE3_FS;
    ca.exit_signal = 0;
    ca.stack = 0xFFFFFFFFFFFF0000ULL;
    ca.stack_size = 0x20000; /* overflows uint64 */

    long ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    CHECK(ret == -22, "clone3 stack overflow returned %ld (expected -EINVAL)",
          ret);
}

/* Test 11: CLONE_VM|CLONE_VFORK must not reuse the in-process VM-clone path.
 * The child execs this same binary with a marker argument and exits 23.
 */
static void test_vfork_exec(void)
{
    struct clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.flags = CLONE3_VM | CLONE3_VFORK;
    ca.exit_signal = 17; /* SIGCHLD */

    vfork_exec_guard = 0x13579bdf;

    long ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    if (ret < 0) {
        CHECK(0, "clone3 vfork failed with %ld", ret);
        return;
    }

    if (ret == 0) {
        char *child_argv[] = {(char *) self_path,
                              (char *) "--clone3-vfork-child", NULL};
        execve(self_path, child_argv, environ);
        _exit(127);
    }

    int status = 0;
    pid_t waited = waitpid((pid_t) ret, &status, 0);
    CHECK(waited == (pid_t) ret, "vfork waitpid returned %d, expected %ld",
          waited, ret);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 23,
          "vfork+exec child exit status: 0x%x (expected exit 23)", status);
    CHECK(vfork_exec_guard == 0x13579bdf,
          "vfork guard changed to 0x%x after child exec",
          (unsigned int) vfork_exec_guard);
}

/* Test 12: CLONE_VM|CLONE_VFORK with an explicit child stack must resume the
 * child on that stack before it executes guest code.
 */
static void test_vfork_child_stack(void)
{
    size_t stack_size = 65536;
    void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(stack != MAP_FAILED, "mmap for vfork child stack test failed");
    if (stack == MAP_FAILED)
        return;

    struct clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.flags = CLONE3_VM | CLONE3_VFORK;
    ca.exit_signal = 17; /* SIGCHLD */
    ca.stack = (uint64_t) stack;
    ca.stack_size = stack_size;

    long ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    if (ret < 0) {
        CHECK(0, "clone3 vfork with child stack failed with %ld", ret);
        munmap(stack, stack_size);
        return;
    }

    if (ret == 0) {
        uint64_t sp = read_sp();
        _exit((sp >= (uint64_t) stack && sp <= (uint64_t) stack + stack_size)
                  ? 24
                  : 125);
    }

    int status = 0;
    pid_t waited = waitpid((pid_t) ret, &status, 0);
    CHECK(waited == (pid_t) ret,
          "vfork child-stack waitpid returned %d, expected %ld", waited, ret);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 24,
          "vfork child stack exit status: 0x%x (expected exit 24)", status);
    munmap(stack, stack_size);
}

static void test_vfork_exec_unblocks_parent(void)
{
    struct clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.flags = CLONE3_VM | CLONE3_VFORK;
    ca.exit_signal = 17; /* SIGCHLD */

    struct timespec start, end;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0,
          "clock_gettime(start) failed");

    long ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    if (ret < 0) {
        CHECK(0, "clone3 vfork unblock test failed with %ld", ret);
        return;
    }

    if (ret == 0) {
        char *child_argv[] = {(char *) self_path,
                              (char *) "--clone3-vfork-sleep-child", NULL};
        execve(self_path, child_argv, environ);
        _exit(127);
    }

    CHECK(clock_gettime(CLOCK_MONOTONIC, &end) == 0,
          "clock_gettime(end) failed");
    long elapsed_ms = (long) (end.tv_sec - start.tv_sec) * 1000L +
                      (long) (end.tv_nsec - start.tv_nsec) / 1000000L;

    /* The property is that CLONE_VFORK released the parent at the child's
     * execve rather than at its exit. Ask that directly rather than through a
     * stopwatch: the child sleeps a second after exec, so a parent that really
     * was released early finds it still running. The wall-clock form said the
     * same thing less reliably and cost more than it caught, failing at 642 ms
     * and 1137 ms against a 500 ms limit on runs where the behaviour was right
     * and the host was merely busy. The elapsed time is still reported, since
     * it is what a reader wants when this does fail.
     */
    int probe_status = 0;
    pid_t probe = waitpid((pid_t) ret, &probe_status, WNOHANG);
    CHECK(probe == 0,
          "vfork parent resumed only after the child exited "
          "(waitpid(WNOHANG) returned %d after %ld ms)",
          (int) probe, elapsed_ms);

    int status = 0;
    pid_t waited = waitpid((pid_t) ret, &status, 0);
    CHECK(waited == (pid_t) ret,
          "vfork unblock waitpid returned %d, expected %ld", waited, ret);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 25,
          "vfork unblock child exit status: 0x%x (expected exit 25)", status);
}

/* Test 13: munmap overlapping an active clone3 stack must be cleaned up after
 * the thread exits so the same VA can be reused.
 */
static void test_deferred_stack_munmap(void)
{
    size_t stack_size = 65536;
    void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(stack != MAP_FAILED, "mmap for deferred stack test failed");
    if (stack == MAP_FAILED)
        return;

    parked_thread_state = 0;
    thread_tid = 0;

    struct clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.flags = CLONE3_THREAD | CLONE3_VM | CLONE3_SIGHAND | CLONE3_FILES |
               CLONE3_FS | CLONE3_CHILD_CLEARTID | CLONE3_CHILD_SETTID;
    ca.exit_signal = 0;
    ca.stack = (uint64_t) stack;
    ca.stack_size = stack_size;
    ca.child_tid = (uint64_t) &thread_tid;

    long ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    if (ret == 0) {
        parked_thread_fn();
        __builtin_unreachable();
    }

    CHECK(ret > 0, "clone3 parked thread returned %ld", ret);
    if (ret < 0) {
        munmap(stack, stack_size);
        return;
    }

    while (__atomic_load_n(&parked_thread_state, __ATOMIC_SEQ_CST) == 0) {
        raw_syscall6(__NR_futex, (long) &parked_thread_state,
                     FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
    }

    CHECK(munmap(stack, stack_size) == 0,
          "munmap of live child stack failed unexpectedly");

    __atomic_store_n(&parked_thread_state, 2, __ATOMIC_SEQ_CST);
    raw_syscall6(__NR_futex, (long) &parked_thread_state,
                 FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0, 0, 0);

    while (__atomic_load_n(&thread_tid, __ATOMIC_SEQ_CST) != 0) {
        int tid = __atomic_load_n(&thread_tid, __ATOMIC_SEQ_CST);
        raw_syscall6(__NR_futex, (long) &thread_tid,
                     FUTEX_WAIT | FUTEX_PRIVATE_FLAG, tid, 0, 0, 0);
    }

    void *reuse =
        mmap(stack, stack_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    CHECK(reuse == stack, "stack reuse mmap returned %p (expected %p)", reuse,
          stack);
    if (reuse != MAP_FAILED && reuse == stack)
        munmap(reuse, stack_size);
}

/* Test 14: partial munmap overlap with a live clone3 stack must still unmap the
 * non-overlapping portion immediately, then release the deferred slice once the
 * thread exits.
 */
static void test_partial_deferred_stack_munmap(void)
{
    size_t stack_size = 65536;
    size_t span_size = stack_size * 2;
    void *span =
        mmap(NULL, span_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(span != MAP_FAILED,
          "mmap reserve for partial deferred stack test failed");
    if (span == MAP_FAILED)
        return;
    CHECK(munmap(span, span_size) == 0,
          "munmap reserve for partial deferred stack test failed");

    void *other =
        mmap(span, stack_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    CHECK(other == span, "mmap non-stack half returned %p (expected %p)", other,
          span);
    if (other != span) {
        if (other != MAP_FAILED)
            munmap(other, stack_size);
        return;
    }

    void *stack =
        mmap((char *) span + stack_size, stack_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    CHECK(stack == (char *) span + stack_size,
          "mmap stack half returned %p (expected %p)", stack,
          (char *) span + stack_size);
    if (stack != (char *) span + stack_size) {
        if (stack != MAP_FAILED)
            munmap(stack, stack_size);
        munmap(other, stack_size);
        return;
    }

    parked_thread_state = 0;
    thread_tid = 0;

    struct clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.flags = CLONE3_THREAD | CLONE3_VM | CLONE3_SIGHAND | CLONE3_FILES |
               CLONE3_FS | CLONE3_CHILD_CLEARTID | CLONE3_CHILD_SETTID;
    ca.exit_signal = 0;
    ca.stack = (uint64_t) stack;
    ca.stack_size = stack_size;
    ca.child_tid = (uint64_t) &thread_tid;

    long ret = raw_clone3(&ca, CLONE_ARGS_SIZE_VER0);
    if (ret == 0) {
        parked_thread_fn();
        __builtin_unreachable();
    }

    CHECK(ret > 0, "clone3 parked thread for partial unmap returned %ld", ret);
    if (ret < 0) {
        munmap(other, stack_size);
        munmap(stack, stack_size);
        return;
    }

    while (__atomic_load_n(&parked_thread_state, __ATOMIC_SEQ_CST) == 0) {
        raw_syscall6(__NR_futex, (long) &parked_thread_state,
                     FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
    }

    CHECK(munmap(span, span_size) == 0,
          "partial munmap spanning live child stack failed unexpectedly");

    void *reuse_other =
        mmap(span, stack_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    CHECK(reuse_other == span,
          "non-overlapping half reuse mmap returned %p (expected %p)",
          reuse_other, span);
    if (reuse_other == span)
        munmap(reuse_other, stack_size);

    void *reuse_stack =
        mmap((char *) span + stack_size, stack_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    CHECK(reuse_stack == MAP_FAILED,
          "live overlapping stack slice unexpectedly became reusable");
    if (reuse_stack != MAP_FAILED)
        munmap(reuse_stack, stack_size);

    __atomic_store_n(&parked_thread_state, 2, __ATOMIC_SEQ_CST);
    raw_syscall6(__NR_futex, (long) &parked_thread_state,
                 FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0, 0, 0);

    while (__atomic_load_n(&thread_tid, __ATOMIC_SEQ_CST) != 0) {
        int tid = __atomic_load_n(&thread_tid, __ATOMIC_SEQ_CST);
        raw_syscall6(__NR_futex, (long) &thread_tid,
                     FUTEX_WAIT | FUTEX_PRIVATE_FLAG, tid, 0, 0, 0);
    }

    reuse_stack =
        mmap((char *) span + stack_size, stack_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    CHECK(reuse_stack == (char *) span + stack_size,
          "deferred overlapping half reuse mmap returned %p (expected %p)",
          reuse_stack, (char *) span + stack_size);
    if (reuse_stack == (char *) span + stack_size)
        munmap(reuse_stack, stack_size);
}

/* Test 15: legacy clone(2) rejects CLONE_NEW* namespace flags with EINVAL,
 * matching clone3 (issue #44). Before the fix these flags fell through to a
 * plain fork that falsely appeared to succeed. CLONE_NEWTIME is omitted: it
 * lives in the CSIGNAL low byte and is not reachable through clone(2).
 */
static void test_legacy_clone_namespaces(void)
{
    static const struct {
        unsigned long flag;
        const char *name;
    } ns_flags[] = {
        {0x00020000, "CLONE_NEWNS"},   {0x02000000, "CLONE_NEWCGROUP"},
        {0x04000000, "CLONE_NEWUTS"},  {0x08000000, "CLONE_NEWIPC"},
        {0x10000000, "CLONE_NEWUSER"}, {0x20000000, "CLONE_NEWPID"},
        {0x40000000, "CLONE_NEWNET"},
    };
    for (size_t i = 0; i < sizeof(ns_flags) / sizeof(ns_flags[0]); i++) {
        /* SIGCHLD (17) in the low byte makes this a fork-like clone. */
        long ret = raw_clone(ns_flags[i].flag | 17, NULL, NULL, 0, NULL);
        CHECK(ret == -22 /* EINVAL */,
              "clone(%s) returned %ld (expected -EINVAL)", ns_flags[i].name,
              ret);
        if (ret == 0) /* defensive: a leaked child must not run the suite */
            raw_syscall1(__NR_exit, 0);
        else if (ret > 0)
            raw_syscall4(__NR_wait4, ret, 0, 0, 0);
    }
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--clone3-vfork-child"))
        return 23;
    if (argc > 1 && !strcmp(argv[1], "--clone3-vfork-sleep-child")) {
        struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};
        nanosleep(&ts, NULL);
        return 25;
    }

    self_path = argv[0];

    printf("test-clone3: starting\n");

    test_fork();
    test_thread();
    test_invalid_size();
    test_unsupported_flags();
    test_pidfd_parent_tid_alias();
    test_larger_struct();
    test_nonzero_tail();
    test_csignal_in_flags();
    test_thread_with_signal();
    test_stack_mismatch();
    test_stack_overflow();
    test_vfork_exec();
    test_vfork_child_stack();
    test_vfork_exec_unblocks_parent();
    test_deferred_stack_munmap();
    test_partial_deferred_stack_munmap();
    test_legacy_clone_namespaces();

    SUMMARY("test-clone3");
    return fails > 0 ? 1 : 0;
}
