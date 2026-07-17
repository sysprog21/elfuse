/*
 * Futex microbenchmark: every shape the futex path can take.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * futex traffic splits into three cost classes, and a number is only readable
 * once you know which class it is in. The bench measures both boundaries so
 * every other row can be placed between them:
 *
 *   getpid      an EL1 fast path that never leaves the shim.
 *   hvc-floor   FUTEX_FD, which sys_futex does not implement, so it reaches the
 *               host and returns ENOSYS having done nothing but mask the
 *               command. That is the HVC round trip plus dispatch, the price of
 *               admission for anything the host answers. It dominates: host
 *               futex work is a small remainder on top of it, so a row near the
 *               floor has nothing left to optimize and a row near getpid never
 *               left EL1.
 *
 * Sections below, in order: the two references, the shapes the EL1 fast path
 * serves, the shapes it must decline (one per reason, since each declines at a
 * different point), the uncontended wake and requeue family, and finally the
 * contended two-thread handoff, which is the only row that measures wakeup
 * latency rather than call cost.
 *
 * The handoff row absorbs what was tests/bench-futex-pingpong.c, the reference
 * benchmark for issue 315: two threads handing off through FUTEX_WAIT and
 * FUTEX_WAKE on private futexes. It keeps that file's raw_clone spawn rather
 * than pthread_create, so the row measures the futex round trip and not libc
 * thread setup, and it still reports the elapsed milliseconds that file printed
 * so older numbers stay comparable. Its cost is set by the host scheduler
 * rather than by elfuse, so it is the one row that moves several-fold between
 * runs; read its median with the spread, and do not read a single sample of it
 * as a regression.
 *
 * Set BENCH_FUTEX_HANDOFF_BITSET to run the handoff with FUTEX_WAIT_BITSET and
 * MATCH_ANY instead of plain FUTEX_WAIT. Semantically the same wait, but the
 * two take different backends inside elfuse, and that row is how the difference
 * is measured.
 *
 * Run under ELFUSE_SHIM_STATS=1 to attribute the fast-path rows: the host
 * prints FUTEX_EAGAIN_HIT, FUTEX_FAULT_BAIL, FUTEX_SHAPE_BAIL and
 * FUTEX_MATCH_BAIL at exit. Those four sum to every SYS_futex that reached the
 * shape decoder; a call arriving with attention raised lands in ATTN_BAIL
 * instead, since the attention load runs after the decode. Each row runs iters
 * plus a 2000-iteration warmup, and hvc-floor issues a futex command too, so
 * the totals are predictable: a served row adds to EAGAIN_HIT, every declined
 * row and every wake adds to SHAPE_BAIL.
 */

#include <errno.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "raw-syscall.h"

#ifndef __NR_futex_waitv
#define __NR_futex_waitv 449
#endif

#define PAGE_SIZE 4096
#define FUTEX2_SIZE_U32 0x02
#define FUTEX2_PRIVATE 0x80

/* The handoff case costs microseconds per iteration, not nanoseconds, so it
 * runs its own much smaller count.
 */
#define HANDOFF_ITERS_CAP 20000

/* It is also the only row whose cost is decided by the host scheduler rather
 * than by elfuse, and it swings several-fold run to run because of it. One
 * sample is not a number, so it takes several and reports the median with the
 * spread beside it; a reader who ignores the spread would read noise as a
 * regression.
 */
#define HANDOFF_REPS 5

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

/* Held at 1 while every wait below asks for 0, so no wait in this file can
 * block except the handoff case, which uses its own words.
 */
static int word = 1;
static int word2 = 1;
static struct timespec long_timeout = {.tv_sec = 100, .tv_nsec = 0};
static void *unmapped_page;
static uintptr_t tagged_word;

typedef struct {
    uint64_t val, uaddr;
    uint32_t flags, __reserved;
} futex_waitv_t;

static futex_waitv_t waitv_one;

/* references */

static long op_getpid(void)
{
    return raw_syscall6(__NR_getpid, 0, 0, 0, 0, 0, 0);
}

static long op_hvc_floor(void)
{
    return raw_syscall6(__NR_futex, (long) &word, 2 /* FUTEX_FD */, 0, 0, 0, 0);
}

/* shapes the EL1 fast path serves */

static long op_wait_eagain(void)
{
    return raw_futex_wait(&word, 0);
}

static long op_waitbs_eagain(void)
{
    return raw_syscall6(__NR_futex, (long) &word,
                        FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, 0, 0, 0,
                        FUTEX_BITSET_MATCH_ANY);
}

/* shapes it must decline, one per reason */

static long op_wait_timed(void)
{
    /* Word already moved, so only the non-NULL timeout sends this to the host:
     * both host waiters build the deadline before comparing, and a malformed
     * timespec has to keep outranking a moved word.
     */
    return raw_syscall6(__NR_futex, (long) &word,
                        FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0,
                        (long) &long_timeout, 0, 0);
}

static long op_wait_unaligned(void)
{
    return raw_syscall6(__NR_futex, (long) ((char *) &word + 1),
                        FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
}

static long op_wait_zero_bitset(void)
{
    return raw_syscall6(__NR_futex, (long) &word,
                        FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
}

static long op_wait_tagged(void)
{
    /* TCR_EL1.TBI0 makes the EL1 load ignore the top byte while the host's
     * software walker does not, so the fast path declines a tagged address and
     * the host answers EFAULT for it.
     */
    return raw_syscall6(__NR_futex, (long) tagged_word,
                        FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
}

static long op_wait_efault(void)
{
    /* Unmapped, so the EL1 unprivileged load faults and the shim's data-abort
     * recovery tail answers EFAULT without leaving the shim. The only row that
     * exercises that tail, and it lands near the served rows rather than the
     * declined ones: taking the fault is far cheaper than a round trip.
     */
    return raw_syscall6(__NR_futex, (long) unmapped_page,
                        FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
}

/* the wake and requeue family, uncontended */

static long op_wake_nowaiter(void)
{
    return raw_futex_wake(&word, 1);
}

static long op_wake_bitset_nowaiter(void)
{
    return raw_syscall6(__NR_futex, (long) &word,
                        FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1, 0, 0,
                        FUTEX_BITSET_MATCH_ANY);
}

static long op_requeue_empty(void)
{
    /* The timeout argument is val2 here, the requeue budget. */
    return raw_syscall6(__NR_futex, (long) &word,
                        FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG, 1, 1, (long) &word2,
                        0);
}

static long op_cmp_requeue_empty(void)
{
    return raw_syscall6(__NR_futex, (long) &word,
                        FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG, 1, 1,
                        (long) &word2, 1 /* val3 must equal *uaddr */);
}

static long op_wake_op_empty(void)
{
    /* FUTEX_OP_SET 0 on uaddr2, compare EQ 0. It writes rather than leaving
     * uaddr2 alone, so word2 sits at 0 from here on; that is fine because the
     * PI row below acquires and releases it either way and the requeue rows
     * compare against word, not word2. Both buckets are still walked, which is
     * what the row is timing.
     */
    return raw_syscall6(__NR_futex, (long) &word,
                        FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG, 1, 1, (long) &word2,
                        0);
}

/* Two syscalls per iteration, so this row is a pair cost and reads about twice
 * the floor. TRYLOCK_PI leaves the word owned and UNLOCK_PI hands it back;
 * measuring either alone would drift into a permanently held lock.
 */
static long op_trylock_unlock_pi(void)
{
    long rc = raw_syscall6(__NR_futex, (long) &word2,
                           FUTEX_TRYLOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
    raw_syscall6(__NR_futex, (long) &word2,
                 FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
    return rc;
}

static long op_waitv_eagain(void)
{
    return raw_syscall6(__NR_futex_waitv, (long) &waitv_one, 1, 0, 0, 0, 0);
}

/* contended handoff */

/* CLONE_VM|THREAD|SIGHAND|FS|FILES: a bare thread sharing this address space,
 * spawned without libc so nothing but the futex round trip is in the timing.
 */
#define HANDOFF_CLONE_FLAGS 0x00010f00

static int hand_a, hand_b, hand_done;
static unsigned long handoff_total;
static int handoff_stack[16384] __attribute__((aligned(16)));

/* Which spelling of "wait" the handoff uses. Plain FUTEX_WAIT is what a raw
 * handoff issues; FUTEX_WAIT_BITSET with MATCH_ANY is semantically the same
 * wait and is what glibc pthread_cond_timedwait has issued since 2.10, so the
 * two rows say whether the two spellings cost the same inside elfuse.
 */
static int handoff_use_bitset;

static long handoff_wait(int *addr, int val)
{
    if (!handoff_use_bitset)
        return raw_futex_wait(addr, val);
    return raw_syscall6(__NR_futex, (long) addr,
                        FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, val, 0, 0,
                        FUTEX_BITSET_MATCH_ANY);
}

/* The peer runs every rep's handoffs in one loop, so the whole row costs a
 * single clone and no stack is ever reused under a thread that has not finished
 * with it.
 */
static void handoff_peer(void)
{
    for (unsigned long i = 0; i < handoff_total; i++) {
        while (__atomic_load_n(&hand_b, __ATOMIC_ACQUIRE) == 0)
            handoff_wait(&hand_b, 0);
        __atomic_store_n(&hand_b, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&hand_a, 1, __ATOMIC_RELEASE);
        raw_futex_wake(&hand_a, 1);
    }
    __atomic_store_n(&hand_done, 1, __ATOMIC_RELEASE);
    raw_futex_wake(&hand_done, 1);
    raw_exit(0);
}

/* One round trip is this thread waking the peer and being woken back, so it
 * spans two waits and two wakes plus whatever the host scheduler adds. This is
 * the number a threaded guest actually feels; the call-cost rows above are what
 * it is built from.
 */
static double run_handoff_batch(unsigned long iters)
{
    uint64_t start = monotonic_ns();

    for (unsigned long i = 0; i < iters; i++) {
        __atomic_store_n(&hand_b, 1, __ATOMIC_RELEASE);
        raw_futex_wake(&hand_b, 1);
        while (__atomic_load_n(&hand_a, __ATOMIC_ACQUIRE) == 0)
            handoff_wait(&hand_a, 0);
        __atomic_store_n(&hand_a, 0, __ATOMIC_RELEASE);
    }
    return (double) (monotonic_ns() - start) / (double) iters;
}

/* main thread versus worker thread */

/* The same do-nothing round trip, measured on a raw_clone worker as well as on
 * the main thread.
 *
 * These two should read the same. When they do not, the difference is work the
 * main thread does that a worker does not, and it is invisible to every other
 * row here because they all run on the main thread and are all quoted against a
 * floor measured there. That is not hypothetical: the run loop used to arm and
 * disarm alarm() around every hv_vcpu_run for the main thread only, which cost
 * two setitimer syscalls per guest syscall and made the main-thread floor about
 * 38 percent worse. Every ratio in this file divided it out, so it read as
 * "1.00x floor, nothing left to optimize" for as long as nobody compared the
 * two threads.
 *
 * Keep this row. A gap reappearing here is the detector for that class of
 * regression, and it is the only one the suite has.
 */
#define MAINWORKER_STACK 4096

static int mainworker_stack[MAINWORKER_STACK] __attribute__((aligned(16)));
static unsigned long mainworker_iters;
static double mainworker_floor_ns;
static int mainworker_done;

static void mainworker_child(void)
{
    uint64_t start = monotonic_ns();
    for (unsigned long i = 0; i < mainworker_iters; i++)
        op_hvc_floor();
    mainworker_floor_ns =
        (double) (monotonic_ns() - start) / (double) mainworker_iters;

    __atomic_store_n(&mainworker_done, 1, __ATOMIC_RELEASE);
    raw_futex_wake(&mainworker_done, 1);
    raw_exit(0);
}

/* Returns the worker's ns/op for the floor row, or -1 if the spawn failed. */
static double run_mainworker_floor(unsigned long iters)
{
    void *top = (char *) mainworker_stack + sizeof(mainworker_stack);
    long rc;

    mainworker_iters = iters;
    mainworker_done = 0;
    rc = raw_clone(HANDOFF_CLONE_FLAGS, top, NULL, 0, NULL);
    if (rc == 0)
        mainworker_child();
    if (rc < 0)
        return -1.0;

    for (;;) {
        int seen = __atomic_load_n(&mainworker_done, __ATOMIC_ACQUIRE);
        if (seen)
            break;
        raw_futex_wait(&mainworker_done, seen);
    }
    return mainworker_floor_ns;
}

/* concurrent wake scaling */

/* futex_wake takes the hash-bucket lock even when the waiter it is looking for
 * sits on the Darwin address-wait queue rather than in the chain, so threads
 * waking unrelated futexes contend whenever their addresses collide. This row
 * is that collision and nothing else: every thread wakes its own private word
 * and no waiter exists anywhere, so all it measures is a lock acquire and an
 * empty walk. Divide it by the single-threaded wake-nowaiter row to read the
 * contention factor. A bucket table too narrow to keep those two close is what
 * this catches, and nothing else in the suite does.
 */
#define WAKE_SCALE_THREADS 8
#define WAKE_SCALE_STACK 4096

/* One page apart. A power-of-two stride is what real allocators emit, and it is
 * the layout a shift-xor bucket hash aliases on, so this stride is what makes
 * the row able to catch a hash regression rather than only a width one.
 */
static int scale_words[WAKE_SCALE_THREADS][1024];
static int scale_stacks[WAKE_SCALE_THREADS - 1][WAKE_SCALE_STACK]
    __attribute__((aligned(16)));
static unsigned long scale_iters;
static int scale_go;
static int scale_done;

static void scale_worker(int id)
{
    while (__atomic_load_n(&scale_go, __ATOMIC_ACQUIRE) == 0)
        ;
    for (unsigned long i = 0; i < scale_iters; i++)
        raw_futex_wake(&scale_words[id][0], 1);
    __atomic_add_fetch(&scale_done, 1, __ATOMIC_RELEASE);
    raw_futex_wake(&scale_done, 1);
    raw_exit(0);
}

/* Returns ns per wake aggregated over every thread, or -1 on a failed spawn. */
static double run_wake_scale(unsigned long iters)
{
    uint64_t start, elapsed;
    int spawned = 0;

    scale_iters = iters;
    scale_go = 0;
    scale_done = 0;

    for (int i = 1; i < WAKE_SCALE_THREADS; i++) {
        void *top = (char *) scale_stacks[i - 1] + sizeof(scale_stacks[i - 1]);
        long rc = raw_clone(HANDOFF_CLONE_FLAGS, top, NULL, 0, NULL);
        if (rc == 0)
            scale_worker(i);
        if (rc < 0)
            break;
        spawned++;
    }
    if (spawned != WAKE_SCALE_THREADS - 1) {
        /* Release the workers that did start, or they spin on scale_go for ever
         * and the process never exits. They finish their loop against an
         * unmeasured word; the caller discards the run either way.
         */
        __atomic_store_n(&scale_go, 1, __ATOMIC_RELEASE);
        while (__atomic_load_n(&scale_done, __ATOMIC_ACQUIRE) < spawned) {
            int seen = __atomic_load_n(&scale_done, __ATOMIC_ACQUIRE);
            if (seen >= spawned)
                break;
            raw_futex_wait(&scale_done, seen);
        }
        return -1.0;
    }

    start = monotonic_ns();
    __atomic_store_n(&scale_go, 1, __ATOMIC_RELEASE);
    for (unsigned long i = 0; i < iters; i++)
        raw_futex_wake(&scale_words[0][0], 1);
    for (;;) {
        int seen = __atomic_load_n(&scale_done, __ATOMIC_ACQUIRE);
        if (seen >= spawned)
            break;
        raw_futex_wait(&scale_done, seen);
    }
    elapsed = monotonic_ns() - start;

    return (double) elapsed / (double) (iters * WAKE_SCALE_THREADS);
}

/* harness */

typedef long (*bench_fn_t)(void);

typedef struct {
    const char *section; /* non-NULL starts a new section heading */
    const char *name;
    bench_fn_t fn;
} bench_case_t;

static const bench_case_t cases[] = {
    {"reference points", "hvc-floor", op_hvc_floor},
    {NULL, "getpid", op_getpid},

    {"served at EL1", "wait-eagain", op_wait_eagain},
    {NULL, "waitbs-eagain", op_waitbs_eagain},

    {"declined to the host", "wait-timed", op_wait_timed},
    {NULL, "wait-unaligned", op_wait_unaligned},
    {NULL, "wait-zero-bitset", op_wait_zero_bitset},
    {NULL, "wait-tagged", op_wait_tagged},
    {NULL, "wait-efault", op_wait_efault},

    {"wake and requeue", "wake-nowaiter", op_wake_nowaiter},
    {NULL, "wake-bitset-nowaiter", op_wake_bitset_nowaiter},
    {NULL, "requeue-empty", op_requeue_empty},
    {NULL, "cmp-requeue-empty", op_cmp_requeue_empty},
    {NULL, "wake-op-empty", op_wake_op_empty},
    {NULL, "trylock+unlock-pi (2 calls)", op_trylock_unlock_pi},
    {NULL, "waitv-eagain", op_waitv_eagain},
};

static double run_case(const bench_case_t *bc, unsigned long iters, long *last)
{
    uint64_t start, elapsed;

    /* Warm up so the first case in a section does not pay one-time setup. */
    for (unsigned long i = 0; i < 2000; i++)
        *last = bc->fn();

    start = monotonic_ns();
    for (unsigned long i = 0; i < iters; i++)
        *last = bc->fn();
    elapsed = monotonic_ns() - start;

    return (double) elapsed / (double) iters;
}

int main(int argc, char **argv)
{
    unsigned long iters = 200000;
    double floor_ns = 0.0, handoff_ns;
    void *scratch;

    if (argc > 1)
        iters = strtoul(argv[1], NULL, 10);
    if (iters == 0) {
        fprintf(stderr, "usage: %s [iterations]\n", argv[0]);
        return 1;
    }

    /* Line-buffer so each row appears as it completes rather than at exit. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    scratch = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (scratch == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        return 1;
    }
    munmap(scratch, PAGE_SIZE);
    unmapped_page = scratch;
    tagged_word = (uintptr_t) &word | ((uintptr_t) 0xAA << 56);

    waitv_one.uaddr = (uint64_t) (uintptr_t) &word;
    waitv_one.val = 0; /* word is 1, so this is the EAGAIN shape */
    waitv_one.flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;

    printf("=== bench-futex (iters=%lu) ===\n", iters);

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        double ns;
        long last = 0;

        if (cases[i].section)
            printf("\n[%s]\n", cases[i].section);

        ns = run_case(&cases[i], iters, &last);

        /* hvc-floor is row 0 so every later row has a denominator; binding it
         * to an index further in would silently recalibrate every ratio the
         * moment a row is inserted above it.
         */
        if (i == 0)
            floor_ns = ns;

        printf("  %-28s %9.1f ns/op  %6.2fx floor  rc=%ld\n", cases[i].name, ns,
               ns / floor_ns, last);
    }

    printf("\n[main thread versus worker]\n");
    {
        double w = run_mainworker_floor(iters < 40000 ? iters : 40000);

        if (w < 0.0) {
            fprintf(stderr, "  mainworker: clone failed\n");
            return 1;
        }
        printf("  %-28s %9.1f ns/op  %6.2fx floor\n", "hvc-floor on a worker",
               w, w / floor_ns);
        printf("  %-28s %9.1f ns  (main minus worker; a gap here is\n",
               "  main-thread excess", floor_ns - w);
        printf("  %-28s %s\n", "", "work only the main thread does)");
    }

    printf("\n[concurrent wake scaling]\n");
    {
        unsigned long n = iters < 60000 ? iters : 60000;
        double per = run_wake_scale(n);

        if (per < 0.0) {
            fprintf(stderr, "  wake-scale: clone failed\n");
            return 1;
        }
        printf("  %-28s %9.1f ns/wake  %6.2fx floor  (%d threads)\n",
               "wake-nowaiter-concurrent", per, per / floor_ns,
               WAKE_SCALE_THREADS);
    }

    printf("\n[contended handoff]\n");
    {
        unsigned long n = iters < HANDOFF_ITERS_CAP ? iters : HANDOFF_ITERS_CAP;
        double reps[HANDOFF_REPS];
        void *stack_top = (char *) handoff_stack + sizeof(handoff_stack);
        long rc;

        handoff_use_bitset = getenv("BENCH_FUTEX_HANDOFF_BITSET") != NULL;
        handoff_total = n * HANDOFF_REPS;
        rc = raw_clone(HANDOFF_CLONE_FLAGS, stack_top, NULL, 0, NULL);
        if (rc == 0) {
            handoff_peer();
            return 0; /* unreachable: handoff_peer exits the thread */
        }
        if (rc < 0) {
            fprintf(stderr, "  handoff: clone failed: %ld\n", rc);
            return 1;
        }

        for (unsigned r = 0; r < HANDOFF_REPS; r++)
            reps[r] = run_handoff_batch(n);

        /* The peer stores hand_done after its last handoff; wait for it so the
         * process does not exit under a live thread on a shared stack.
         */
        while (__atomic_load_n(&hand_done, __ATOMIC_ACQUIRE) == 0)
            raw_futex_wait(&hand_done, 0);
        /* Insertion sort; HANDOFF_REPS is a handful. */
        for (unsigned i = 1; i < HANDOFF_REPS; i++) {
            double v = reps[i];
            unsigned j = i;
            while (j > 0 && reps[j - 1] > v) {
                reps[j] = reps[j - 1];
                j--;
            }
            reps[j] = v;
        }
        handoff_ns = reps[HANDOFF_REPS / 2];
        printf("  %-28s %9.1f ns/round-trip  %6.2fx floor\n",
               handoff_use_bitset ? "waitbs-wake-handoff" : "wake-wait-handoff",
               handoff_ns, handoff_ns / floor_ns);
        printf("  %-28s %9.1f .. %.1f over %d runs of %lu\n", "  (spread)",
               reps[0], reps[HANDOFF_REPS - 1], HANDOFF_REPS, n);
    }

    return 0;
}
