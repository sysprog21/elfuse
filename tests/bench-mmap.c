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
 * Every in-process case takes one untimed warmup pass (to pay the one-time
 * arena carve and page-table extension). Most sections report aggregate
 * samples; section C retains every operation so its normal latency and long
 * tail remain visible. Section A is driven host-side so every timed mmap and
 * munmap pair gets a new elfuse process.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
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

/* R-7/sample quantile, matching the common (n - 1) * p interpolation. The input
 * must already be sorted.
 */
static double sorted_quantile(const double *v, unsigned n, double p)
{
    double pos = (double) (n - 1) * p;
    unsigned lo = (unsigned) pos;
    unsigned hi = lo + (lo + 1 < n);
    return v[lo] + (v[hi] - v[lo]) * (pos - lo);
}

#define ITERS 15
#define MIN_TIMED_TICKS 4096
#define KIB (1ULL << 10)
#define MIB (1ULL << 20)
#define GIB (1ULL << 30)
#define DIRTY_VMEXIT_STRIDE (8 * MIB)

/* Calibrate the rd()/rd() interval around a timed operation. Its median cost is
 * subtracted from aggregate samples so the counter-read overhead is not
 * attributed to mmap or munmap.
 */
static double rd_pair_ticks(void)
{
    enum { CAL_SAMPLES = 15, CAL_OPS = 4096 };
    double samples[CAL_SAMPLES];
    for (int sample = 0; sample < CAL_SAMPLES; sample++) {
        uint64_t total = 0;
        for (int op = 0; op < CAL_OPS; op++) {
            uint64_t t0 = rd();
            uint64_t t1 = rd();
            total += t1 - t0;
        }
        samples[sample] = (double) total / CAL_OPS;
    }
    return median(samples, CAL_SAMPLES);
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

/* A. One mmap and one munmap fast-path sample in a fresh guest. The host-side
 * driver starts a new elfuse process for every invocation of this function.
 * Prime the requested arena size outside the timed interval, then force a host
 * drain so the arena is empty and its cursor is rewound. The two measured calls
 * can then take the EL1 paths even when size exceeds the initial 64 MiB arena.
 * Raw ticks are returned because one fast call is comparable to the counter
 * period; the driver aggregates independent one-call samples before converting
 * them to nanoseconds.
 */
static int bench_fastpath_once(uint64_t size)
{
    void *warmup = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (warmup == MAP_FAILED || munmap(warmup, size) != 0)
        return 1;

    /* Drain the warmup retirement and rewind the now-empty arena. */
    (void) fcntl(-1, F_GETFD);

    uint64_t mmap_start = rd();
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint64_t mmap_end = rd();
    if (ptr == MAP_FAILED)
        return 1;

    uint64_t munmap_start = rd();
    int rc = munmap(ptr, size);
    uint64_t munmap_end = rd();
    if (rc != 0)
        return 1;

    printf(
        "fast-once size=%llu mmap_ticks=%llu munmap_ticks=%llu "
        "read_ticks=%.6f ns_per_tick=%.12f\n",
        (unsigned long long) size, (unsigned long long) (mmap_end - mmap_start),
        (unsigned long long) (munmap_end - munmap_start), rd_pair_ticks(),
        ns_per_tick);
    return 0;
}

#define HOST_DRAIN_MAX_BATCH 30
#define HOST_DRAIN_DEFAULT_SAMPLES 31

typedef struct {
    double baseline_ns;
    double mmap_extra_ns;
    double mmap_ns_per_op;
    double munmap_extra_ns;
    double munmap_ns_per_op;
} host_drain_result_t;

static bool timed_empty_vmexit(uint64_t *ticks)
{
    errno = 0;
    uint64_t start = rd();
    int rc = fcntl(-1, F_GETFD);
    uint64_t end = rd();
    if (rc != -1 || errno != EBADF)
        return false;
    *ticks = end - start;
    return true;
}

/* Pair a work-bearing fcntl VM exit with an empty one at the same mapping
 * population. The difference leaves only the host's publication or retirement
 * drain. Batches stop below both 32-entry ring limits so no mmap or munmap in
 * the setup triggers an early HVC drain.
 */
static bool bench_host_drain_measure(uint64_t size,
                                     unsigned batch,
                                     unsigned samples,
                                     host_drain_result_t *result)
{
    if (batch == 0 || batch > HOST_DRAIN_MAX_BATCH || samples == 0)
        return false;

    void **mappings = calloc(batch, sizeof(*mappings));
    double *baseline = malloc(2 * samples * sizeof(*baseline));
    double *mmap_extra = malloc(samples * sizeof(*mmap_extra));
    double *munmap_extra = malloc(samples * sizeof(*munmap_extra));
    if (!mappings || !baseline || !mmap_extra || !munmap_extra)
        goto fail;

    void *warmup = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint64_t discard;
    if (warmup == MAP_FAILED || munmap(warmup, size) != 0 ||
        !timed_empty_vmexit(&discard))
        goto fail;

    for (unsigned sample = 0; sample < samples; sample++) {
        uint64_t mmap_base, mmap_work, munmap_base, munmap_work;
        if (!timed_empty_vmexit(&mmap_base))
            goto fail;

        for (unsigned op = 0; op < batch; op++) {
            mappings[op] = mmap(NULL, size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (mappings[op] == MAP_FAILED)
                goto fail;
        }
        if (!timed_empty_vmexit(&mmap_work) ||
            !timed_empty_vmexit(&munmap_base))
            goto fail;

        for (unsigned op = 0; op < batch; op++) {
            if (munmap(mappings[op], size) != 0)
                goto fail;
            mappings[op] = NULL;
        }
        if (!timed_empty_vmexit(&munmap_work))
            goto fail;

        baseline[2 * sample] = (double) mmap_base;
        baseline[2 * sample + 1] = (double) munmap_base;
        mmap_extra[sample] = (double) mmap_work - (double) mmap_base;
        munmap_extra[sample] = (double) munmap_work - (double) munmap_base;
    }

    result->baseline_ns = median(baseline, (int) (2 * samples)) * ns_per_tick;
    result->mmap_extra_ns = median(mmap_extra, (int) samples) * ns_per_tick;
    result->mmap_ns_per_op = result->mmap_extra_ns / batch;
    result->munmap_extra_ns = median(munmap_extra, (int) samples) * ns_per_tick;
    result->munmap_ns_per_op = result->munmap_extra_ns / batch;
    free(munmap_extra);
    free(mmap_extra);
    free(baseline);
    free(mappings);
    return true;

fail:
    if (mappings) {
        for (unsigned op = 0; op < batch; op++) {
            if (mappings[op] && mappings[op] != MAP_FAILED)
                munmap(mappings[op], size);
        }
        (void) fcntl(-1, F_GETFD);
    }
    free(munmap_extra);
    free(mmap_extra);
    free(baseline);
    free(mappings);
    return false;
}

static bool bench_host_drain(unsigned samples)
{
    static const unsigned batches[] = {1, 2, 4, 8, 16, 30};
    const uint64_t size = 4 * KIB;
    bool ok = true;

    printf("== D. host work drained at the next VM exit ==\n");
    printf("Empty fcntl VM exits provide the paired fixed-cost baseline.\n");
    printf("%-10s %8s %8s %12s %14s %12s %14s %12s\n", "size", "batch",
           "samples", "baseline ns", "mmap extra ns", "mmap ns/op",
           "munmap extra ns", "munmap ns/op");
    for (unsigned i = 0; i < sizeof(batches) / sizeof(batches[0]); i++) {
        host_drain_result_t result;
        char hb[16];
        if (!bench_host_drain_measure(size, batches[i], samples, &result)) {
            printf("%-10s %8u %8u %14s\n", human(size, hb), batches[i], samples,
                   "FAILED");
            ok = false;
            continue;
        }
        printf("%-10s %8u %8u %12.1f %14.1f %12.1f %14.1f %12.1f\n",
               human(size, hb), batches[i], samples, result.baseline_ns,
               result.mmap_extra_ns, result.mmap_ns_per_op,
               result.munmap_extra_ns, result.munmap_ns_per_op);
    }
    printf("\n");
    return ok;
}

/* Auxiliary: fresh bump-tail mmap isolates the lazy_fresh_range path. Allocate
 * sequential run WITHOUT freeing, so every mapping lands at or above the arena
 * high-water -- exactly the case lazy_fresh_range skips the stale-PTE scan for.
 * Small mappings use the original 2-GiB footprint cap; large mappings use a
 * minimum count chosen to retain multiple samples without exceeding 64 GiB of
 * live fresh VA. Run this binary against an opt-off build to read the skip's
 * contribution as the difference on this identical code path -- a MAP_FIXED
 * "recycled" compare would instead measure the region-snapshot replacement
 * path, not the skip.
 */
static void bench_fresh(void)
{
    static const uint64_t sizes[] = {4 * KIB, 64 * KIB, MIB,
                                     2 * MIB, 8 * MIB,  128 * MIB,
                                     GIB,     8 * GIB,  32 * GIB};
    printf(
        "== Auxiliary: fresh bump-tail mmap, per-mmap ns "
        "(lazy_fresh_range path) ==\n");
    printf("%-10s %8s %14s\n", "size", "count", "fresh mmap ns");
    void *run[1000];
    for (unsigned s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        uint64_t size = sizes[s];
        int n = (int) (2 * GIB / size);
        if (n < 1)
            n = 1;
        if (n > 1000)
            n = 1000;
        if (size == GIB)
            n = 8;
        else if (size == 8 * GIB)
            n = 4;
        else if (size == 32 * GIB)
            n = 2;
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

/* One fresh bump-tail run for the host-side driver. A new elfuse process is
 * used for each invocation, so the driver can accumulate many counter ticks
 * without exhausting one guest's VA space.
 */
static int bench_fresh_one(uint64_t size, int n)
{
    void *run[1000];
    if (n < 1 || n > (int) (sizeof(run) / sizeof(run[0])))
        return 2;

    void *warmup = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (warmup == MAP_FAILED)
        return 1;
    munmap(warmup, size);

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
    if (failed)
        return 1;

    printf(
        "fresh size=%llu count=%d ticks=%llu read_ticks=%.6f "
        "ns_per_tick=%.12f\n",
        (unsigned long long) size, n, (unsigned long long) (t1 - t0),
        rd_pair_ticks(), ns_per_tick);
    return 0;
}

/* Auxiliary: first-touch cost. Touch one byte per macOS 16 KiB host page. Each
 * demands a distinct physical backing page, but it is not necessarily a
 * distinct HVC: elfuse installs Stage-1 descriptors in 2 MiB windows and the
 * fault-around policy may install several windows per exit. Report both the
 * whole sweep and its per-host-page amortization; calling the latter a
 * "per-fault" cost would substantially overcount guest translation faults.
 */
static void bench_fault(int pages, int drain_between)
{
    const uint64_t stride = 16 * KIB;
    uint64_t size = stride * (uint64_t) (pages + 1);
    printf(
        "== Auxiliary: first-touch fault cost (16 KiB stride, %d pages%s) "
        "==\n",
        pages, drain_between ? ", forced retire drain" : "");
    double sweep[ITERS];
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
        if (drain_between)
            (void) fcntl(-1, F_GETFD);
        if (it >= 0)
            sweep[it] = ns(t1 - t0);
    }
    qsort(sweep, ITERS, sizeof(*sweep), cmp_d);
    printf("  sweep: p50 %.1f us  p95 %.1f us  max %.1f us\n",
           sorted_quantile(sweep, ITERS, 0.50) / 1000.0,
           sorted_quantile(sweep, ITERS, 0.95) / 1000.0,
           sweep[ITERS - 1] / 1000.0);
    printf("  amortized/touch: p50 %.1f ns  p95 %.1f ns  max %.1f ns\n\n",
           sorted_quantile(sweep, ITERS, 0.50) / pages,
           sorted_quantile(sweep, ITERS, 0.95) / pages,
           sweep[ITERS - 1] / pages);
}

/* Auxiliary: mprotect split cost. Flip the middle 4 KiB of a 2 MiB RW block to
 * PROT_READ, forcing guest_split_block to convert the L2 block into 512 L3
 * pages. Restore between iterations so each run does a fresh split.
 */
static void bench_mprotect_split(void)
{
    printf(
        "== Auxiliary: mprotect split "
        "(2 MiB block -> L3, protect middle 4 KiB) ==\n");
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

/* Auxiliary: mremap grow, in-place vs forced move. */
static void bench_mremap(void)
{
    printf("== Auxiliary: mremap grow 4 KiB -> 8 KiB ==\n");
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

/* Auxiliary: multi-threaded mmap and munmap fast paths. Each worker primes its
 * arena before the start barrier, allocates untouched mappings, then retires
 * them after a second barrier. The host-side driver runs each configuration in
 * a fresh elfuse process.
 */
typedef struct {
    uint64_t size;
    int n;
    void **buf;
    uint64_t mmap_start;
    uint64_t mmap_end;
    uint64_t munmap_start;
    uint64_t munmap_end;
    double mmap_ns;
    double munmap_ns;
    int failed;
} mt_arg_t;

typedef struct {
    double mmap_ns;
    double mmap_mops;
    double munmap_ns;
    double munmap_mops;
} mt_result_t;

static pthread_barrier_t mt_barrier;
static pthread_mutex_t mt_start_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t mt_start_cond = PTHREAD_COND_INITIALIZER;
static int mt_start;
static int mt_abort;

/* CNTVCT_EL0 reads a constant on worker vCPUs (EL0VCTEN is set for the main
 * vCPU only), so the MT worker brackets its whole loop with clock_gettime and
 * amortizes each SVC pair over n operations.
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
    pthread_mutex_lock(&mt_start_lock);
    while (!mt_start)
        pthread_cond_wait(&mt_start_cond, &mt_start_lock);
    int run = !mt_abort;
    pthread_mutex_unlock(&mt_start_lock);
    if (!run)
        return NULL;

    void *warmup = mmap(NULL, a->size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (warmup == MAP_FAILED || munmap(warmup, a->size) != 0)
        a->failed++;
    (void) fcntl(-1, F_GETFD);

    pthread_barrier_wait(&mt_barrier);
    a->mmap_start = mono_ns();
    for (int i = 0; i < a->n; i++)
        a->buf[i] = mmap(NULL, a->size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    a->mmap_end = mono_ns();
    a->mmap_ns = (double) (a->mmap_end - a->mmap_start) / a->n;

    pthread_barrier_wait(&mt_barrier);
    a->munmap_start = mono_ns();
    for (int i = 0; i < a->n; i++) {
        if (a->buf[i] == MAP_FAILED)
            a->failed++;
        else if (munmap(a->buf[i], a->size) != 0)
            a->failed++;
    }
    a->munmap_end = mono_ns();
    a->munmap_ns = (double) (a->munmap_end - a->munmap_start) / a->n;
    return NULL;
}

#define MT_MAX_THREADS 8
#define MT_REGION_CAP 3000 /* keep T*n well under GUEST_MAX_REGIONS (4096) */

static int bench_mt_measure(uint64_t size,
                            int thread_count,
                            mt_result_t *result)
{
    int n = MT_REGION_CAP / thread_count;
    mt_arg_t arg[MT_MAX_THREADS] = {0};
    pthread_t th[MT_MAX_THREADS];
    int ok = 1, created = 0;
    for (int i = 0; i < thread_count; i++) {
        arg[i].size = size;
        arg[i].n = n;
        arg[i].buf = calloc((size_t) n, sizeof(void *));
        if (!arg[i].buf)
            ok = 0;
    }

    int barrier_ready = 0;
    if (ok) {
        if (pthread_barrier_init(&mt_barrier, NULL, (unsigned) thread_count) ==
            0)
            barrier_ready = 1;
        else
            ok = 0;
    }
    pthread_mutex_lock(&mt_start_lock);
    mt_start = 0;
    mt_abort = 0;
    pthread_mutex_unlock(&mt_start_lock);
    for (int i = 0; i < thread_count && ok; i++) {
        if (pthread_create(&th[i], NULL, mt_worker, &arg[i]) != 0) {
            ok = 0;
            break;
        }
        created++;
    }
    pthread_mutex_lock(&mt_start_lock);
    mt_abort = !ok;
    mt_start = 1;
    pthread_cond_broadcast(&mt_start_cond);
    pthread_mutex_unlock(&mt_start_lock);

    for (int i = 0; i < created; i++)
        pthread_join(th[i], NULL);

    double mmap_sum = 0, munmap_sum = 0;
    uint64_t mmap_start = UINT64_MAX, mmap_end = 0;
    uint64_t munmap_start = UINT64_MAX, munmap_end = 0;
    int failed = 0;
    for (int i = 0; i < thread_count; i++) {
        mmap_sum += arg[i].mmap_ns;
        munmap_sum += arg[i].munmap_ns;
        if (arg[i].mmap_start < mmap_start)
            mmap_start = arg[i].mmap_start;
        if (arg[i].mmap_end > mmap_end)
            mmap_end = arg[i].mmap_end;
        if (arg[i].munmap_start < munmap_start)
            munmap_start = arg[i].munmap_start;
        if (arg[i].munmap_end > munmap_end)
            munmap_end = arg[i].munmap_end;
        failed += arg[i].failed;
        free(arg[i].buf);
    }
    if (barrier_ready)
        pthread_barrier_destroy(&mt_barrier);
    if (!ok || failed || mmap_end <= mmap_start || munmap_end <= munmap_start)
        return 0;

    double total_ops = (double) n * thread_count;
    result->mmap_ns = mmap_sum / thread_count;
    result->mmap_mops = total_ops * 1000.0 / (double) (mmap_end - mmap_start);
    result->munmap_ns = munmap_sum / thread_count;
    result->munmap_mops =
        total_ops * 1000.0 / (double) (munmap_end - munmap_start);
    return 1;
}

static void bench_mt(void)
{
    static const uint64_t sizes[] = {4 * KIB, 2 * MIB};
    static const int threads[] = {1, 2, 4, 8};
    printf("== Multi-threaded mmap/munmap fast paths ==\n");
    printf("ns is mean per-thread time; Mops/s is aggregate throughput.\n");
    printf("%-10s %8s %8s %12s %12s %12s %12s\n", "size", "threads", "ops/thr",
           "mmap ns", "mmap Mops/s", "munmap ns", "munmap Mops/s");
    for (unsigned s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        for (unsigned t = 0; t < sizeof(threads) / sizeof(threads[0]); t++) {
            int thread_count = threads[t];
            int n = MT_REGION_CAP / thread_count;
            mt_result_t result;
            char hb[16];
            if (!bench_mt_measure(sizes[s], thread_count, &result)) {
                printf("%-10s %8d %8d %12s\n", human(sizes[s], hb),
                       thread_count, n, "FAILED");
                continue;
            }
            printf("%-10s %8d %8d %12.1f %12.3f %12.1f %12.3f\n",
                   human(sizes[s], hb), thread_count, n, result.mmap_ns,
                   result.mmap_mops, result.munmap_ns, result.munmap_mops);
        }
    }
    printf("\n");
}

/* B. Teardown after materialization. The store is deliberately outside the
 * timed interval: it takes the lazy first-touch fault and installs the first
 * page, then the counter brackets only munmap(). Each row has exactly one
 * materialized 4-KiB page; touching every page would instead benchmark faulting
 * and zeroing gigabytes of memory.
 *
 * bench_munmap_materialized_measure() holds the timing loop for exactly one
 * size, shared by the in-process sweep below and the "b-one" isolated-process
 * driver mode (see tests/bench-mmap-isolated).
 */
static int bench_munmap_materialized_measure(uint64_t size,
                                             double timer_ticks,
                                             unsigned *reported_ops,
                                             double *munmap_ns)
{
    double unmap_ns[ITERS];
    int ok = 1;
    for (int it = -1; it < ITERS && ok; it++) {
        uint64_t unmap_ticks = 0;
        unsigned ops = 0;
        do {
            volatile uint8_t *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p == MAP_FAILED) {
                ok = 0;
                break;
            }
            p[0] = 1; /* materialize before starting the timed interval */
            uint64_t t0 = rd();
            int rc = munmap((void *) p, size);
            uint64_t t1 = rd();
            unmap_ticks += t1 - t0;
            if (rc != 0) {
                ok = 0;
                break;
            }
            ops++;
        } while (unmap_ticks < MIN_TIMED_TICKS);

        if (it >= 0 && ok) {
            unmap_ns[it] =
                ((double) unmap_ticks / ops - timer_ticks) * ns_per_tick;
            *reported_ops = ops;
        }
    }
    if (!ok)
        return 0;
    *munmap_ns = median(unmap_ns, ITERS);
    return 1;
}

static void bench_munmap_materialized(void)
{
    double timer_ticks = rd_pair_ticks();
    static const uint64_t sizes[] = {
        4 * KIB,  16 * KIB,  64 * KIB, 256 * KIB, MIB,      2 * MIB,  8 * MIB,
        64 * MIB, 256 * MIB, GIB,      4 * GIB,   16 * GIB, 32 * GIB,
    };

    printf("== B. munmap after materializing one 4 KiB page ==\n");
    printf("%-10s %8s %12s\n", "size", "ops", "munmap ns");
    for (unsigned s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        uint64_t size = sizes[s];
        unsigned reported_ops = 0;
        double munmap_ns = 0;
        char hb[16];
        if (!bench_munmap_materialized_measure(size, timer_ticks, &reported_ops,
                                               &munmap_ns))
            printf("%-10s %8s %12s\n", human(size, hb), "-", "FAILED");
        else
            printf("%-10s %8u %12.1f\n", human(size, hb), reported_ops,
                   munmap_ns);
    }
    printf("\n");
}

/* C. Teardown after every page was dirtied. Page stores happen before the timed
 * interval, so this reports only munmap's handling of the materialized, dirty
 * mapping. Each size has a fixed operation count and every munmap is retained
 * separately. In particular, one slow first operation cannot end an adaptive
 * batch and become the whole sample. Counts decrease with size to bound total
 * dirtying work. The 1-GiB case uses eight operations, and the untimed store
 * loop takes periodic VM exits so every vCPU-run interval stays below elfuse's
 * watchdog; interpolated p95 remains distinct from max.
 *
 * bench_munmap_dirty_measure() holds the timing loop for exactly one size,
 * shared by the in-process sweep below and the "c-one" isolated-process driver
 * mode (see tests/bench-mmap-isolated).
 */
static int bench_munmap_dirty_measure(uint64_t size,
                                      unsigned ops,
                                      double timer_ticks,
                                      double *p50_ns,
                                      double *p95_ns,
                                      double *max_ns)
{
    double *unmap_ns = malloc((size_t) ops * sizeof(*unmap_ns));
    int ok = 1;
    if (!unmap_ns)
        ok = 0;

    /* One full untimed warmup pays setup without consuming an observation. */
    for (int64_t op = -1; op < (int64_t) ops && ok; op++) {
        volatile uint8_t *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            ok = 0;
            break;
        }
        for (uint64_t off = 0; off < size; off += 4 * KIB) {
            p[off] = (uint8_t) (off >> 12);

            /* Large already-backed runs can execute in EL0 long enough for the
             * benchmark's 10-second vCPU watchdog to fire under macOS memory
             * pressure. This deliberately failing fcntl is a guaranteed,
             * side-effect-free HVC outside the timed region. It also drains the
             * preceding retirement in bounded chunks.
             */
            if (off != 0 && (off & (DIRTY_VMEXIT_STRIDE - 1)) == 0)
                (void) fcntl(-1, F_GETFD);
        }

        /* Establish an identical clean host-retirement boundary before every
         * measurement. The interval below then contains EL1's descriptor/TLBI
         * path, never the previous operation's cleanup.
         */
        (void) fcntl(-1, F_GETFD);

        uint64_t t0 = rd();
        int rc = munmap((void *) p, size);
        uint64_t t1 = rd();
        if (rc != 0) {
            ok = 0;
            break;
        }
        if (op >= 0) {
            double ticks = (double) (t1 - t0) - timer_ticks;
            if (ticks < 0.0)
                ticks = 0.0;
            unmap_ns[op] = ticks * ns_per_tick;
        }
    }

    if (!ok) {
        free(unmap_ns);
        return 0;
    }
    qsort(unmap_ns, ops, sizeof(*unmap_ns), cmp_d);
    *p50_ns = sorted_quantile(unmap_ns, ops, 0.50);
    *p95_ns = sorted_quantile(unmap_ns, ops, 0.95);
    *max_ns = unmap_ns[ops - 1];
    free(unmap_ns);
    return 1;
}

static void bench_munmap_dirty(void)
{
    static const struct {
        uint64_t size;
        unsigned ops;
    } cases[] = {
        {4 * KIB, 2048}, {16 * KIB, 2048}, {64 * KIB, 2048}, {256 * KIB, 1024},
        {MIB, 512},      {2 * MIB, 256},   {8 * MIB, 128},   {64 * MIB, 32},
        {256 * MIB, 24}, {GIB, 8},
    };
    double timer_ticks = rd_pair_ticks();

    printf("== C. munmap after dirtying every 4 KiB page ==\n");
    printf("%-10s %8s %12s %12s %12s\n", "size", "ops", "p50 ns", "p95 ns",
           "max ns");
    for (unsigned s = 0; s < sizeof(cases) / sizeof(cases[0]); s++) {
        uint64_t size = cases[s].size;
        unsigned ops = cases[s].ops;
        double p50_ns = 0, p95_ns = 0, max_ns = 0;
        char hb[16];
        if (!bench_munmap_dirty_measure(size, ops, timer_ticks, &p50_ns,
                                        &p95_ns, &max_ns))
            printf("%-10s %8u %12s %12s %12s\n", human(size, hb), ops, "FAILED",
                   "-", "-");
        else
            printf("%-10s %8u %12.1f %12.1f %12.1f\n", human(size, hb), ops,
                   p50_ns, p95_ns, max_ns);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    clock_init();
    if ((argc == 2 || argc == 3) && strcmp(argv[1], "host-drain") == 0) {
        unsigned samples = HOST_DRAIN_DEFAULT_SAMPLES;
        if (argc == 3) {
            char *end = NULL;
            errno = 0;
            unsigned long value = strtoul(argv[2], &end, 0);
            if (errno || !end || *end || value == 0 || value > 100000)
                return 2;
            samples = (unsigned) value;
        }
        printf("elfuse mmap benchmark (CNTVCT %.2f ns/tick)\n\n", ns_per_tick);
        return bench_host_drain(samples) ? 0 : 1;
    }
    if (argc == 2 && strcmp(argv[1], "b") == 0) {
        printf("elfuse mmap benchmark (CNTVCT %.2f ns/tick)\n\n", ns_per_tick);
        bench_munmap_materialized();
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "c") == 0) {
        printf("elfuse mmap benchmark (CNTVCT %.2f ns/tick)\n\n", ns_per_tick);
        bench_munmap_dirty();
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "mt") == 0) {
        printf("elfuse mmap benchmark (CNTVCT %.2f ns/tick)\n\n", ns_per_tick);
        bench_mt();
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "mt-one") == 0) {
        char *end = NULL;
        errno = 0;
        uint64_t size = strtoull(argv[2], &end, 0);
        if (errno || !end || *end || size == 0)
            return 2;
        errno = 0;
        long threads_arg = strtol(argv[3], &end, 0);
        if (errno || !end || *end ||
            (threads_arg != 1 && threads_arg != 2 && threads_arg != 4 &&
             threads_arg != 8))
            return 2;
        int thread_count = (int) threads_arg;
        mt_result_t result;
        if (!bench_mt_measure(size, thread_count, &result)) {
            printf("fastpath-mt size=%llu threads=%d FAILED\n",
                   (unsigned long long) size, thread_count);
            return 1;
        }
        printf(
            "fastpath-mt size=%llu threads=%d ops_per_thread=%d "
            "mmap_ns=%.6f mmap_mops=%.6f munmap_ns=%.6f "
            "munmap_mops=%.6f\n",
            (unsigned long long) size, thread_count,
            MT_REGION_CAP / thread_count, result.mmap_ns, result.mmap_mops,
            result.munmap_ns, result.munmap_mops);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "fault") == 0) {
        printf("elfuse mmap benchmark (CNTVCT %.2f ns/tick)\n\n", ns_per_tick);
        bench_fault(512, 0);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "fault") == 0) {
        char *end = NULL;
        errno = 0;
        long pages = strtol(argv[2], &end, 0);
        if (errno || !end || *end || pages < 1 || pages > 1048576)
            return 2;
        printf("elfuse mmap benchmark (CNTVCT %.2f ns/tick)\n\n", ns_per_tick);
        bench_fault((int) pages, 0);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "fault-drain") == 0) {
        printf("elfuse mmap benchmark (CNTVCT %.2f ns/tick)\n\n", ns_per_tick);
        bench_fault(512, 1);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "fresh") == 0) {
        char *end = NULL;
        errno = 0;
        uint64_t size = strtoull(argv[2], &end, 0);
        if (errno || !end || *end || size == 0)
            return 2;
        errno = 0;
        long count = strtol(argv[3], &end, 0);
        if (errno || !end || *end || count < 1 || count > 1000)
            return 2;
        return bench_fresh_one(size, (int) count);
    }

    /* One section-A sample. The host-side driver starts a new elfuse process
     * for every invocation and aggregates the raw one-call timings.
     */
    if (argc == 3 && strcmp(argv[1], "a-one") == 0) {
        char *end = NULL;
        errno = 0;
        uint64_t size = strtoull(argv[2], &end, 0);
        if (errno || !end || *end || size == 0)
            return 2;
        return bench_fastpath_once(size);
    }
    /* One section-B data point for the host-side driver. */
    if (argc == 3 && strcmp(argv[1], "b-one") == 0) {
        char *end = NULL;
        errno = 0;
        uint64_t size = strtoull(argv[2], &end, 0);
        if (errno || !end || *end || size == 0)
            return 2;
        double timer_ticks = rd_pair_ticks();
        unsigned reported_ops = 0;
        double munmap_ns = 0;
        if (!bench_munmap_materialized_measure(size, timer_ticks, &reported_ops,
                                               &munmap_ns)) {
            printf("munmap-materialized size=%llu FAILED\n",
                   (unsigned long long) size);
            return 1;
        }
        printf("munmap-materialized size=%llu ops=%u munmap_ns=%.6f\n",
               (unsigned long long) size, reported_ops, munmap_ns);
        return 0;
    }

    /* One section-C data point for the host-side driver. The op count is
     * explicit because C's cases[] table pairs it to size, and the driver must
     * pass the same value the table would give.
     */
    if (argc == 4 && strcmp(argv[1], "c-one") == 0) {
        char *end = NULL;
        errno = 0;
        uint64_t size = strtoull(argv[2], &end, 0);
        if (errno || !end || *end || size == 0)
            return 2;
        errno = 0;
        long ops_arg = strtol(argv[3], &end, 0);
        if (errno || !end || *end || ops_arg < 1 || ops_arg > 1000000)
            return 2;
        unsigned ops = (unsigned) ops_arg;
        double timer_ticks = rd_pair_ticks();
        double p50_ns = 0, p95_ns = 0, max_ns = 0;
        if (!bench_munmap_dirty_measure(size, ops, timer_ticks, &p50_ns,
                                        &p95_ns, &max_ns)) {
            printf("munmap-dirty size=%llu FAILED\n",
                   (unsigned long long) size);
            return 1;
        }
        printf(
            "munmap-dirty size=%llu ops=%u p50_ns=%.6f p95_ns=%.6f "
            "max_ns=%.6f\n",
            (unsigned long long) size, ops, p50_ns, p95_ns, max_ns);
        return 0;
    }
    if (argc != 1)
        return 2;
    printf("elfuse mmap benchmark (CNTVCT %.2f ns/tick)\n\n", ns_per_tick);
    bench_munmap_materialized();
    bench_munmap_dirty();
    bench_fresh();
    bench_fault(512, 0);
    bench_mprotect_split();
    bench_mremap();
    bench_mt();
    return 0;
}
