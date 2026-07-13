/*
 * Comprehensive anonymous-mmap microbenchmark for elfuse.
 *
 * Measures the guest-visible cost of the mmap subsystem in isolation:
 * allocation, teardown, first-touch faults, permission splitting, and remap. It
 * is self-contained -- no external harness -- and is meant to be run under
 * elfuse (./build/elfuse ./build/bench-mmap) but also runs on any aarch64-linux
 * host for a ground-truth comparison.
 *
 * Timing: reads CNTVCT_EL0 directly at EL0 (enabled by CNTKCTL_EL1.EL0VCTEN in
 * bootstrap.c), so a measurement costs an isb + mrs, not a clock_gettime SVC.
 * On Apple Silicon CNTFRQ is ~24 MHz (~41.7 ns/tick); amortizing over an
 * adaptive batch drives the effective resolution well below one tick. This is
 * the key fairness property: clock_gettime on a static guest falls through to
 * the ~2 us SVC path and swamps any sub-us operation.
 *
 * Every case takes one untimed warmup pass (to pay the one-time arena carve and
 * page-table extension) and reports the median and min over ITERS runs.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* CNTVCT timing */

static double ns_per_tick;

static inline uint64_t rd(void)
{
    uint64_t v;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(v));
    return v;
}

static void clock_init(void)
{
    uint64_t f;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(f));
    if (f == 0)
        f = 24000000; /* defensive: assume 24 MHz if RES0 */
    ns_per_tick = 1e9 / (double) f;
}

static double ns(uint64_t ticks)
{
    return (double) ticks * ns_per_tick;
}

static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *) a, y = *(const double *) b;
    return (x > y) - (x < y);
}

static double median(double *v, int n)
{
    qsort(v, n, sizeof(*v), cmp_d);
    return (n & 1) ? v[n / 2] : 0.5 * (v[n / 2 - 1] + v[n / 2]);
}

#define ITERS 15
#define MAXB 64
#define KIB (1ULL << 10)
#define MIB (1ULL << 20)
#define GIB (1ULL << 30)

/* Batch size: amortize the coarse counter over B ops while bounding the live
 * address footprint of one timed batch to ~256 MiB.
 */
static int batch_for(uint64_t size)
{
    uint64_t b = (256 * MIB) / size;
    if (b < 1)
        b = 1;
    if (b > MAXB)
        b = MAXB;
    return (int) b;
}

static const char *human(uint64_t s, char *buf)
{
    if (s >= GIB)
        sprintf(buf, "%llu GiB", (unsigned long long) (s / GIB));
    else if (s >= MIB)
        sprintf(buf, "%llu MiB", (unsigned long long) (s / MIB));
    else
        sprintf(buf, "%llu KiB", (unsigned long long) (s / KIB));
    return buf;
}

/* A. mmap + munmap latency vs size (steady state) NULL-hint allocate then free,
 * batched. Iterations after the first reuse freed address space, so this is the
 * realistic repeated-allocation number a workload sees, not the one-shot fresh
 * case (that is section B).
 */
static void bench_size_sweep(void)
{
    static const uint64_t sizes[] = {
        4 * KIB,  16 * KIB,  64 * KIB, 256 * KIB, MIB,      2 * MIB,  8 * MIB,
        64 * MIB, 256 * MIB, GIB,      4 * GIB,   16 * GIB, 32 * GIB,
    };
    printf(
        "== A. mmap / munmap latency vs size (steady state, NULL hint) ==\n");
    printf("%-10s %6s %12s %12s\n", "size", "batch", "mmap ns", "munmap ns");
    void *ptr[MAXB];
    for (unsigned s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        uint64_t size = sizes[s];
        int b = batch_for(size);
        double mm[ITERS], um[ITERS];
        int ok = 1;
        for (int it = -1; it < ITERS && ok; it++) {
            uint64_t t0 = rd();
            for (int i = 0; i < b; i++)
                ptr[i] = mmap(NULL, size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            uint64_t t1 = rd();
            for (int i = 0; i < b; i++)
                if (ptr[i] == MAP_FAILED)
                    ok = 0;
            if (!ok)
                break;
            uint64_t t2 = rd();
            for (int i = 0; i < b; i++)
                munmap(ptr[i], size);
            uint64_t t3 = rd();
            if (it >= 0) {
                mm[it] = ns(t1 - t0) / b;
                um[it] = ns(t3 - t2) / b;
            }
        }
        char hb[16];
        if (!ok) {
            printf("%-10s %6d %12s %12s\n", human(size, hb), b, "FAILED", "-");
            continue;
        }
        printf("%-10s %6d %12.1f %12.1f\n", human(size, hb), b,
               median(mm, ITERS), median(um, ITERS));
    }
    printf("\n");
}

/* B. fresh bump-tail mmap (isolates the lazy_fresh_range path) Allocate a
 * bounded sequential run WITHOUT freeing, so every mapping lands at or above
 * the arena high-water -- exactly the case lazy_fresh_range skips the stale-PTE
 * scan for. The run is kept small enough (<= 1000 regions, well under
 * GUEST_MAX_REGIONS, footprint <= 2 GiB) that region bookkeeping and page-table
 * extension do not dominate, and every result is failure-checked. Run this
 * binary against an opt-off build to read the skip's contribution as the
 * difference on this identical code path -- a MAP_FIXED "recycled" compare
 * would instead measure the region-snapshot replacement path, not the skip.
 */
static void bench_fresh(void)
{
    static const uint64_t sizes[] = {4 * KIB, 64 * KIB, MIB,
                                     2 * MIB, 8 * MIB,  128 * MIB,
                                     GIB,     8 * GIB,  32 * GIB};
    printf(
        "== B. fresh bump-tail mmap, per-mmap ns (lazy_fresh_range path) ==\n");
    printf("%-10s %8s %14s\n", "size", "count", "fresh mmap ns");
    void *run[1000];
    for (unsigned s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        uint64_t size = sizes[s];
        int n = (int) (2 * GIB / size);
        if (n < 1)
            n = 1;
        if (n > 1000)
            n = 1000;
        /* warmup one fresh mapping so the arena high-water is already primed */
        void *w = mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (w != MAP_FAILED)
            munmap(w, size);
        uint64_t t0 = rd();
        for (int i = 0; i < n; i++)
            run[i] = mmap(NULL, size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        uint64_t t1 = rd();
        int failed = 0;
        for (int i = 0; i < n; i++) {
            if (run[i] == MAP_FAILED)
                failed++;
            else
                munmap(run[i], size);
        }
        char hb[16];
        if (failed) {
            printf("%-10s %8d %14s (%d failed)\n", human(size, hb), n,
                   "PARTIAL", failed);
            continue;
        }
        printf("%-10s %8d %14.1f\n", human(size, hb), n, ns(t1 - t0) / n);
    }
    printf("\n");
}

/* C. first-touch page-fault cost Touch one byte per page at a 16 KiB stride so
 * no two touches share a macOS host page; every touch is a genuine fault (HVC
 * #11 -> host fault handler -> page-table install + zero). Reports per-fault
 * ns.
 */
static void bench_fault(void)
{
    const uint64_t stride = 16 * KIB;
    const int pages = 512;
    uint64_t size = stride * (uint64_t) (pages + 1);
    printf("== C. first-touch fault cost (16 KiB stride, %d pages) ==\n",
           pages);
    double per[ITERS];
    for (int it = -1; it < ITERS; it++) {
        volatile uint8_t *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            printf("  mmap FAILED: %s\n\n", strerror(errno));
            return;
        }
        uint64_t t0 = rd();
        for (int i = 0; i < pages; i++)
            p[(uint64_t) i * stride] = 1;
        uint64_t t1 = rd();
        munmap((void *) p, size);
        if (it >= 0)
            per[it] = ns(t1 - t0) / pages;
    }
    printf("  per-fault: median %.1f ns  min %.1f ns\n\n", median(per, ITERS),
           per[0]);
}

/* D. mprotect split cost Flip the middle 4 KiB of a 2 MiB RW block to
 * PROT_READ, forcing guest_split_block to convert the L2 block into 512 L3
 * pages. Restore between iterations so each run does a fresh split.
 */
static void bench_mprotect_split(void)
{
    printf(
        "== D. mprotect split (2 MiB block -> L3, protect middle 4 KiB) ==\n");
    double sp[ITERS];
    for (int it = -1; it < ITERS; it++) {
        uint8_t *p = mmap(NULL, 2 * MIB, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            printf("  mmap FAILED\n\n");
            return;
        }
        uint8_t *mid = p + MIB;
        uint64_t t0 = rd();
        int rc = mprotect(mid, 4 * KIB, PROT_READ);
        uint64_t t1 = rd();
        munmap(p, 2 * MIB);
        if (rc != 0) {
            printf("  mprotect FAILED: %s\n\n", strerror(errno));
            return;
        }
        if (it >= 0)
            sp[it] = ns(t1 - t0);
    }
    printf("  split: median %.1f ns  min %.1f ns\n\n", median(sp, ITERS),
           sp[0]);
}

/* E. mremap grow: in-place vs forced move */
static void bench_mremap(void)
{
    printf("== E. mremap grow 4 KiB -> 8 KiB ==\n");
    double inp[ITERS], mov[ITERS];

    /* In-place: no blocker, the following page is free. */
    for (int it = -1; it < ITERS; it++) {
        void *p = mmap(NULL, 4 * KIB, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            printf("  mmap FAILED\n\n");
            return;
        }
        uint64_t t0 = rd();
        void *q = mremap(p, 4 * KIB, 8 * KIB, MREMAP_MAYMOVE);
        uint64_t t1 = rd();
        if (q == MAP_FAILED) {
            munmap(p, 4 * KIB);
            printf("  mremap in-place FAILED\n\n");
            return;
        }
        munmap(q, 8 * KIB);
        if (it >= 0)
            inp[it] = ns(t1 - t0);
    }

    /* Forced move: a PROT_READ blocker sits immediately after, so the grow must
     * relocate.
     */
    for (int it = -1; it < ITERS; it++) {
        uint8_t *p = mmap(NULL, 8 * KIB, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            printf("  mmap FAILED\n\n");
            return;
        }
        /* free the tail page and pin it read-only so in-place growth is blocked
         * but the head is still a 4 KiB mapping.
         */
        munmap(p + 4 * KIB, 4 * KIB);
        void *blk = mmap(p + 4 * KIB, 4 * KIB, PROT_READ,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        uint64_t t0 = rd();
        void *q = mremap(p, 4 * KIB, 8 * KIB, MREMAP_MAYMOVE);
        uint64_t t1 = rd();
        if (q == MAP_FAILED) {
            printf("  mremap move FAILED\n\n");
            return;
        }
        munmap(q, 8 * KIB);
        if (blk != MAP_FAILED)
            munmap(blk, 4 * KIB);
        if (it >= 0)
            mov[it] = ns(t1 - t0);
    }
    printf("  in-place: median %.1f ns  min %.1f ns\n", median(inp, ITERS),
           inp[0]);
    printf("  move:     median %.1f ns  min %.1f ns\n\n", median(mov, ITERS),
           mov[0]);
}

/* F. multi-threaded fresh mmap under mmap_lock Several threads hammer fresh
 * bump-tail mmaps concurrently. mmap serializes on mmap_lock, so this exposes
 * both lock contention and any per-mmap TLBI shootdown cost -- the one place a
 * "skip the invalidate on fresh ranges" optimization could pay off that a
 * single-threaded run cannot see. Threads do not free during the timed run
 * (every mapping stays fresh); total live regions are capped under
 * GUEST_MAX_REGIONS. Compare against an opt-off build to read the skip's
 * multi-threaded contribution.
 */
typedef struct {
    uint64_t size;
    int n;
    void **buf;
    double per_op_ns;
    int failed;
} mt_arg_t;

static pthread_barrier_t mt_barrier;

/* CNTVCT_EL0 reads a constant on worker vCPUs (EL0VCTEN is set for the main
 * vCPU only), so the MT worker brackets its whole loop with clock_gettime and
 * amortizes the one SVC pair over n mmaps.
 */
static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}

static void *mt_worker(void *p)
{
    mt_arg_t *a = p;
    pthread_barrier_wait(&mt_barrier);
    uint64_t t0 = mono_ns();
    for (int i = 0; i < a->n; i++)
        a->buf[i] = mmap(NULL, a->size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint64_t t1 = mono_ns();
    a->per_op_ns = (double) (t1 - t0) / a->n;
    for (int i = 0; i < a->n; i++) {
        if (a->buf[i] == MAP_FAILED)
            a->failed++;
        else
            munmap(a->buf[i], a->size);
    }
    return NULL;
}

#define MT_MAX_THREADS 4
#define MT_REGION_CAP 3000 /* keep T*n well under GUEST_MAX_REGIONS (4096) */

static void bench_mt(void)
{
    static const uint64_t sizes[] = {4 * KIB, 2 * MIB};
    static const int threads[] = {2, 4};
    printf(
        "== F. multi-threaded fresh mmap, per-op ns (mmap_lock contention) "
        "==\n");
    printf("%-10s %8s %12s %12s\n", "size", "threads", "mean ns", "max ns");
    for (unsigned s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        uint64_t size = sizes[s];
        for (unsigned t = 0; t < sizeof(threads) / sizeof(threads[0]); t++) {
            int T = threads[t];
            int n = MT_REGION_CAP / T;
            if (n < 1)
                n = 1;
            mt_arg_t arg[MT_MAX_THREADS];
            pthread_t th[MT_MAX_THREADS];
            int ok = 1;
            for (int i = 0; i < T; i++) {
                arg[i].size = size;
                arg[i].n = n;
                arg[i].per_op_ns = 0;
                arg[i].failed = 0;
                arg[i].buf = calloc(n, sizeof(void *));
                if (!arg[i].buf)
                    ok = 0;
            }
            /* prime the arena high-water so the timed run is genuinely fresh */
            void *w = mmap(NULL, size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (w != MAP_FAILED)
                munmap(w, size);
            pthread_barrier_init(&mt_barrier, NULL, (unsigned) T);
            for (int i = 0; i < T && ok; i++)
                if (pthread_create(&th[i], NULL, mt_worker, &arg[i]) != 0)
                    ok = 0;
            double sum = 0, mx = 0;
            int failed = 0;
            for (int i = 0; i < T; i++) {
                pthread_join(th[i], NULL);
                sum += arg[i].per_op_ns;
                if (arg[i].per_op_ns > mx)
                    mx = arg[i].per_op_ns;
                failed += arg[i].failed;
                free(arg[i].buf);
            }
            pthread_barrier_destroy(&mt_barrier);
            char hb[16];
            if (!ok || failed)
                printf("%-10s %8d %12s\n", human(size, hb), T, "FAILED");
            else
                printf("%-10s %8d %12.1f %12.1f\n", human(size, hb), T, sum / T,
                       mx);
        }
    }
    printf("\n");
}

int main(void)
{
    clock_init();
    printf("elfuse mmap benchmark (CNTVCT %.2f ns/tick)\n\n", ns_per_tick);
    bench_size_sweep();
    bench_fresh();
    bench_fault();
    bench_mprotect_split();
    bench_mremap();
    bench_mt();
    return 0;
}
