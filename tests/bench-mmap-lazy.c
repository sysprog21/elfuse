/*
 * Guest microbenchmark for anonymous private mmap latency vs size.
 *
 * Measures mmap(), first-touch, and munmap() latency for MAP_PRIVATE |
 * MAP_ANONYMOUS mappings from 4 KiB to 32 GiB. A lazy (deferred page-table)
 * implementation should show size-independent mmap/munmap cost; an eager
 * implementation scales linearly with length and exhausts resources on the
 * multi-GiB sizes.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}

static void bench_size(uint64_t size, int iters)
{
    uint64_t t_map = 0, t_touch = 0, t_unmap = 0;
    int ok = 0;

    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        uint64_t t1 = now_ns();
        if (p == MAP_FAILED) {
            printf("%10llu KiB: mmap failed: %s\n",
                   (unsigned long long) (size >> 10), strerror(errno));
            return;
        }
        /* First touch: one write at the start and one mid-mapping. */
        volatile char *c = p;
        c[0] = 1;
        c[size / 2] = 1;
        uint64_t t2 = now_ns();
        int rc = munmap(p, size);
        uint64_t t3 = now_ns();
        if (rc != 0) {
            printf("%10llu KiB: munmap failed: %s\n",
                   (unsigned long long) (size >> 10), strerror(errno));
            return;
        }
        t_map += t1 - t0;
        t_touch += t2 - t1;
        t_unmap += t3 - t2;
        ok++;
    }
    printf(
        "%10llu KiB: mmap %10llu ns  touch2 %10llu ns  munmap %10llu ns  "
        "(%d iters)\n",
        (unsigned long long) (size >> 10),
        (unsigned long long) (t_map / (uint64_t) ok),
        (unsigned long long) (t_touch / (uint64_t) ok),
        (unsigned long long) (t_unmap / (uint64_t) ok), ok);
}

int main(int argc, char **argv)
{
    static const struct {
        uint64_t size;
        int iters;
    } cases[] = {
        {4ull << 10, 200}, {64ull << 10, 200}, {2ull << 20, 100},
        {64ull << 20, 20}, {512ull << 20, 10}, {2ull << 30, 5},
        {8ull << 30, 3},   {16ull << 30, 3},   {32ull << 30, 3},
        {64ull << 30, 1},  {128ull << 30, 1},  {256ull << 30, 1},
    };
    /* Optional argv[1]: cap size in GiB (eager implementations commit host
     * memory for every byte mapped; the full matrix would thrash small hosts).
     */
    uint64_t cap = ~0ull;
    if (argc > 1)
        cap = (uint64_t) atoll(argv[1]) << 30;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("anon private mmap latency vs size\n");
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        if (cases[i].size <= cap)
            bench_size(cases[i].size, cases[i].iters);

    /* Full-touch throughput sanity: 64 MiB written end to end. */
    uint64_t size = 64ull << 20;
    uint64_t t0 = now_ns();
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        printf("full-touch mmap failed: %s\n", strerror(errno));
        return 1;
    }
    memset(p, 0xa5, size);
    uint64_t t1 = now_ns();
    munmap(p, size);
    printf("mmap+memset 64MiB: %llu ns (%.2f GiB/s)\n",
           (unsigned long long) (t1 - t0),
           (double) size / 1.073741824 / (double) (t1 - t0));
    return 0;
}
