/*
 * test-noreserve-materialize.c -- first touch of MAP_NORESERVE memory
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * An anonymous MAP_NORESERVE mapping is filled in on first touch. Two things
 * that first touch must not do:
 *
 * Wipe a neighbor. A mapping placed next to one the guest already wrote, with
 * the same protection, can share its 2 MiB block, and the first touch of the
 * new one must leave what the guest wrote into the old one in place.
 *
 * Grant access PROT_NONE refuses. Touching a PROT_NONE reservation is SIGSEGV,
 * on the first touch as on every later one.
 *
 * Map past its own end. A PROT_NONE guard next to the mapping, inside the same
 * 2 MiB block, faults while the mapping is being filled in and after.
 *
 * The threaded case races two first touches of one fresh mapping, so a fill
 * that ran after a page became writable would lose the other thread's store.
 *
 * Every assertion is plain Linux mmap behavior.
 */
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define CHUNK ((size_t) 64 * 1024)
#define BLOCK ((size_t) 2 * 1024 * 1024)
#define ROUNDS 64

static void *lazy_map(size_t len, int prot)
{
    void *p = mmap(NULL, len, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                   -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

/* The wipe needs both mappings in one 2 MiB block. The kernel picks where b
 * goes, so a round that lands it in another block proves nothing and is not
 * counted; if no round shares a block the test fails rather than passing
 * without having looked.
 */
static void test_neighbor_survives(void)
{
    TEST("touching a neighbor keeps data");
    int ok = 1, shared = 0;
    for (int i = 0; i < ROUNDS && ok; i++) {
        volatile uint8_t *a = lazy_map(CHUNK, PROT_READ | PROT_WRITE);
        if (!a) {
            ok = 0;
            break;
        }
        for (size_t off = 0; off < CHUNK; off += 4096)
            a[off] = 0x5a;
        /* Mapped only now, so it joins a range that is already filled in. */
        volatile uint8_t *b = lazy_map(CHUNK, PROT_READ | PROT_WRITE);
        if (!b) {
            ok = 0;
            break;
        }
        if (((uintptr_t) a ^ (uintptr_t) b) / BLOCK != 0)
            continue;
        shared++;
        b[CHUNK / 2] = 1;
        for (size_t off = 0; off < CHUNK; off += 4096)
            if (a[off] != 0x5a)
                ok = 0;
        if (b[0] != 0 || b[CHUNK / 2] != 1)
            ok = 0;
    }
    EXPECT_TRUE(ok && shared > 0,
                "expected the first mapping's bytes to survive");
}

/* Per thread: a SIGSEGV is delivered to the thread that faulted. */
static __thread sigjmp_buf segv_jmp;

static void on_segv(int sig)
{
    (void) sig;
    siglongjmp(segv_jmp, 1);
}

static void test_prot_none(void)
{
    TEST("touching PROT_NONE is SIGSEGV");
    volatile uint8_t *p = lazy_map(CHUNK, PROT_NONE);
    struct sigaction sa = {0}, old;
    sa.sa_handler = on_segv;
    sigaction(SIGSEGV, &sa, &old);
    int faulted = 0;
    if (p && sigsetjmp(segv_jmp, 1) == 0)
        (void) p[0];
    else
        faulted = 1;
    sigaction(SIGSEGV, &old, NULL);
    EXPECT_TRUE(p && faulted, "expected SIGSEGV on the first read");
}

/* One 2 MiB block holding a CHUNK of memory followed by a PROT_NONE guard, so
 * the first touch fills in only part of the block. mmap guarantees only page
 * alignment, so over-reserve and trim. The guard stays reserved rather than
 * unmapped, so nothing else, such as a thread stack, can be placed there.
 */
static volatile uint8_t *guarded_chunk(void)
{
    uint8_t *win = lazy_map(2 * BLOCK, PROT_READ | PROT_WRITE);
    if (!win)
        return NULL;
    uint8_t *blk =
        (uint8_t *) (((uintptr_t) win + BLOCK - 1) & ~(uintptr_t) (BLOCK - 1));
    if (blk > win)
        munmap(win, (size_t) (blk - win));
    if (win + 2 * BLOCK > blk + BLOCK)
        munmap(blk + BLOCK, (size_t) (win + 2 * BLOCK - (blk + BLOCK)));
    if (mprotect(blk + CHUNK, BLOCK - CHUNK, PROT_NONE) != 0) {
        munmap(blk, BLOCK);
        return NULL;
    }
    return blk;
}

static volatile uint8_t *guard_p;
static volatile int guard_go, guard_done, guard_escaped;

/* Reads the guard until the main thread's first touch is done. Every read must
 * fault; one that returns saw the guard mapped while the block was filled in.
 * Best effort: a read that faults then waits for the lock the fill holds, so
 * few reads overlap the fill. The read of the guard after the fill is the check
 * that runs every round.
 */
static void *guard_prober(void *arg)
{
    (void) arg;
    while (!__atomic_load_n(&guard_go, __ATOMIC_ACQUIRE))
        ;
    while (!__atomic_load_n(&guard_done, __ATOMIC_ACQUIRE)) {
        if (sigsetjmp(segv_jmp, 1) == 0) {
            (void) guard_p[CHUNK];
            guard_escaped = 1;
            break;
        }
    }
    return NULL;
}

static void test_guard_after_fill(void)
{
    TEST("guard past a filled mapping is SIGSEGV");
    struct sigaction sa = {0}, old;
    sa.sa_handler = on_segv;
    sigaction(SIGSEGV, &sa, &old);
    volatile int ok = 1;
    for (int i = 0; i < ROUNDS && ok; i++) {
        volatile uint8_t *p = guarded_chunk();
        if (!p) {
            ok = 0;
            break;
        }
        guard_p = p;
        guard_go = guard_done = guard_escaped = 0;
        pthread_t t;
        if (pthread_create(&t, NULL, guard_prober, NULL) != 0) {
            munmap((void *) p, BLOCK);
            ok = 0;
            break;
        }
        __atomic_store_n(&guard_go, 1, __ATOMIC_RELEASE);
        if (sigsetjmp(segv_jmp, 1) == 0)
            p[0] = 1;
        else
            ok = 0; /* The mapping itself faulted. */
        __atomic_store_n(&guard_done, 1, __ATOMIC_RELEASE);
        pthread_join(t, NULL);
        if (guard_escaped)
            ok = 0;
        if (sigsetjmp(segv_jmp, 1) == 0) {
            (void) p[CHUNK];
            ok = 0;
        }
        munmap((void *) p, BLOCK);
    }
    sigaction(SIGSEGV, &old, NULL);
    EXPECT_TRUE(ok, "expected SIGSEGV on the guard during and after the fill");
}

static volatile uint8_t *race_b;
static volatile int race_go;

/* Stores once into every page of the fresh mapping while the main thread's
 * first touch fills it in. A page published before it was zeroed takes this
 * store and then loses it to the zeroing.
 */
static void *toucher(void *arg)
{
    (void) arg;
    while (!__atomic_load_n(&race_go, __ATOMIC_ACQUIRE))
        ;
    for (size_t off = 0; off < CHUNK; off += 4096)
        race_b[off + 8] = 0xee;
    return NULL;
}

static void test_fill_race(void)
{
    TEST("first touch races a store");
    int ok = 1;
    for (int i = 0; i < ROUNDS && ok; i++) {
        race_b = lazy_map(CHUNK, PROT_READ | PROT_WRITE);
        if (!race_b) {
            ok = 0;
            break;
        }
        race_go = 0;
        pthread_t t;
        if (pthread_create(&t, NULL, toucher, NULL) != 0) {
            ok = 0;
            break;
        }
        __atomic_store_n(&race_go, 1, __ATOMIC_RELEASE);
        race_b[0] = 1;
        pthread_join(t, NULL);
        for (size_t off = 0; off < CHUNK; off += 4096)
            if (race_b[off + 8] != 0xee)
                ok = 0;
    }
    EXPECT_TRUE(ok, "expected every store to survive the fill");
}

int main(void)
{
    printf("test-noreserve-materialize: first touch of MAP_NORESERVE\n");
    test_neighbor_survives();
    test_prot_none();
    test_guard_after_fill();
    test_fill_race();
    SUMMARY("test-noreserve-materialize");
    return fails ? 1 : 0;
}
