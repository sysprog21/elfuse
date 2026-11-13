/*
 * EL1 fast munmap against sibling faults, mprotect and cross-thread unmaps
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Code under test: el1_mmap and el1_munmap in src/core/shim-mmap.c and the PT
 * gate, drain and revoke in src/syscall/mem.c.
 *
 * The EL1 producers and the host page-table writers exclude each other through
 * the PT gate. A broken handshake lets the host refill, revoke or rewrite
 * descriptors while EL1 clears them, which surfaces as stale data in a fresh
 * mapping, a lost write, a fault on a live page, or an abort in the retire
 * drain. Every thread here checks the first three; the fourth kills the run.
 *
 * Syscalls exercised: mmap(222), munmap(215), mprotect(226)
 */

#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

#define RUN_MS 1500
#define PAGE 4096UL
#define WORKERS 3
#define HANDOFF_SLOTS 64
#define LAZY_LEN (32UL * 1024 * 1024)

int passes = 0, fails = 0;

static atomic_int stop;
static atomic_int bad_zero, bad_data, faults;
static atomic_ulong ops;

static void on_segv(int sig)
{
    (void) sig;
    atomic_fetch_add(&faults, 1);
    _exit(2);
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

static uint64_t next_rand(uint64_t *s)
{
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    return *s;
}

/* A fresh mapping must read zero; a write must read back until unmapped. */
static void fill_check(uint64_t *p, size_t len, uint64_t tag)
{
    for (size_t off = 0; off < len; off += PAGE)
        if (p[off / 8] != 0)
            atomic_fetch_add(&bad_zero, 1);
    for (size_t off = 0; off < len; off += PAGE)
        p[off / 8] = tag ^ off;
    for (size_t off = 0; off < len; off += PAGE)
        if (p[off / 8] != (tag ^ off))
            atomic_fetch_add(&bad_data, 1);
}

static void *worker(void *arg)
{
    uint64_t seed = 0x9e3779b97f4a7c15ULL * ((uintptr_t) arg + 1);
    while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
        size_t len = PAGE * (1 + next_rand(&seed) % 64);
        uint64_t *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            continue;
        fill_check(p, len, seed);
        munmap(p, len);
        atomic_fetch_add_explicit(&ops, 1, memory_order_relaxed);
    }
    return NULL;
}

/* One thread maps and writes, another verifies and unmaps: the unmap retires a
 * range in an arena the unmapping vCPU does not own.
 */
static struct {
    _Atomic(uint64_t *) ptr;
    size_t len;
    uint64_t tag;
} handoff[HANDOFF_SLOTS];

static void *producer(void *arg)
{
    (void) arg;
    uint64_t seed = 0x1234567;
    unsigned i = 0;
    while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
        unsigned slot = i++ % HANDOFF_SLOTS;
        if (atomic_load_explicit(&handoff[slot].ptr, memory_order_acquire))
            continue;
        size_t len = PAGE * (1 + next_rand(&seed) % 16);
        uint64_t *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            continue;
        fill_check(p, len, seed);
        handoff[slot].len = len;
        handoff[slot].tag = seed;
        atomic_store_explicit(&handoff[slot].ptr, p, memory_order_release);
    }
    return NULL;
}

static void *consumer(void *arg)
{
    (void) arg;
    unsigned i = 0;
    for (;;) {
        bool stopping = atomic_load_explicit(&stop, memory_order_relaxed);
        bool any = false;
        for (unsigned n = 0; n < HANDOFF_SLOTS; n++, i++) {
            unsigned slot = i % HANDOFF_SLOTS;
            uint64_t *p =
                atomic_load_explicit(&handoff[slot].ptr, memory_order_acquire);
            if (!p)
                continue;
            any = true;
            for (size_t off = 0; off < handoff[slot].len; off += PAGE)
                if (p[off / 8] != (handoff[slot].tag ^ off))
                    atomic_fetch_add(&bad_data, 1);
            munmap(p, handoff[slot].len);
            atomic_store_explicit(&handoff[slot].ptr, NULL,
                                  memory_order_release);
            atomic_fetch_add_explicit(&ops, 1, memory_order_relaxed);
        }
        if (stopping && !any)
            return NULL;
    }
}

/* Every mprotect revokes every arena generation. */
static void *protector(void *arg)
{
    (void) arg;
    while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
        uint64_t *q = mmap(NULL, 16 * PAGE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (q == MAP_FAILED)
            continue;
        fill_check(q, 16 * PAGE, 0xabcdef);
        mprotect(q, 16 * PAGE, PROT_READ);
        mprotect(q, 16 * PAGE, PROT_READ | PROT_WRITE);
        q[0] = 1;
        munmap(q, 16 * PAGE);
        atomic_fetch_add_explicit(&ops, 1, memory_order_relaxed);
    }
    return NULL;
}

/* Lazy faults, remapped so reused blocks take the dirty materialization. */
static void *faulter(void *arg)
{
    (void) arg;
    uint64_t seed = 0xfeedface;
    uint8_t round = 0;
    while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
        uint8_t *r = mmap(NULL, LAZY_LEN, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (r == MAP_FAILED)
            continue;
        /* A page drawn twice in one round holds this round's mark. */
        uint8_t mark = (uint8_t) (++round | 0x80);
        for (int n = 0; n < 32; n++) {
            size_t off = (next_rand(&seed) % (LAZY_LEN / PAGE)) * PAGE;
            if (r[off] != 0 && r[off] != mark)
                atomic_fetch_add(&bad_zero, 1);
            r[off] = mark;
        }
        munmap(r, LAZY_LEN);
        atomic_fetch_add_explicit(&ops, 1, memory_order_relaxed);
    }
    return NULL;
}

int main(void)
{
    signal(SIGSEGV, on_segv);
    signal(SIGBUS, on_segv);

    pthread_t t[WORKERS + 4];
    int n = 0;
    for (int i = 0; i < WORKERS; i++)
        pthread_create(&t[n++], NULL, worker, (void *) (uintptr_t) i);
    pthread_create(&t[n++], NULL, producer, NULL);
    pthread_create(&t[n++], NULL, consumer, NULL);
    pthread_create(&t[n++], NULL, protector, NULL);
    pthread_create(&t[n++], NULL, faulter, NULL);

    uint64_t end = now_ms() + RUN_MS;
    while (now_ms() < end)
        usleep(10000);
    atomic_store(&stop, 1);
    for (int i = 0; i < n; i++)
        pthread_join(t[i], NULL);

    printf("  %lu map/unmap rounds\n", (unsigned long) atomic_load(&ops));
    TEST("fresh mappings read zero");
    EXPECT_EQ(atomic_load(&bad_zero), 0, "a fresh mapping held stale data");
    TEST("writes survive until unmap");
    EXPECT_EQ(atomic_load(&bad_data), 0, "a write was lost or overwritten");

    SUMMARY("test-mmap-fastpath-stress");
    return fails == 0 ? 0 : 1;
}
