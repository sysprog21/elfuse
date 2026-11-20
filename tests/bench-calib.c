/*
 * Time a fixed single-threaded loop on the host CPU
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * scripts/bench-paired.sh runs this before and after every benchmark round and
 * reruns a pair whose readings disagree. On Apple Silicon a P-core slows down
 * when three or more P-cores are busy, by about 12% on the CI M4, and a pair
 * whose two rounds ran at different levels gives a ratio that measures the host
 * rather than the change.
 *
 * Prints the fastest of RUNS timings in microseconds. On an M5 Pro, a process
 * started on an idle host timed about 26% slower for its first 50 ms or more
 * (2.2 ms against 1.74 ms per timing), so the loop first spins for WARMUP_NS.
 */

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define WARMUP_NS 200000000ULL
#define RUNS 9
#define ITERATIONS 2000000U

static uint64_t now_ns(void)
{
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
}

/* Each step needs the last, so the timing follows the core clock. */
static uint32_t spin(void)
{
    uint32_t x = 1;
    for (uint32_t i = 0; i < ITERATIONS; i++)
        x = (x & 1) ? x * 3 + i : x >> 1;
    return x;
}

int main(void)
{
    volatile uint32_t sink;
    uint64_t start = now_ns();
    while (now_ns() - start < WARMUP_NS)
        sink = spin();

    uint64_t best = UINT64_MAX;
    for (int run = 0; run < RUNS; run++) {
        uint64_t t = now_ns();
        sink = spin();
        t = now_ns() - t;
        if (t < best)
            best = t;
    }
    (void) sink;
    printf("%.1f\n", (double) best / 1000.0);
    return 0;
}
