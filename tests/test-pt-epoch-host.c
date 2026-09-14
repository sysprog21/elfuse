/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * EL1 fast munmap clears descriptors without touching guest_t.pt_gen. A host
 * thread's translation cache must drop an entry taken before that clear as soon
 * as the EL1 PT epoch moves, before any host writer bumps pt_gen.
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>

#include "core/guest.h"
#include "core/mmap-fastpath.h"
#include "syscall/internal.h"
#include "test-harness.h"

int passes, fails;

static guest_t *g;
static const uint64_t block = 2ULL << 20;
static const uint64_t addr = 16ULL << 20;

/* The host's view of el1_munmap: descriptors gone, pt_gen untouched, epoch
 * advanced. A separate thread, so the main thread's cache entry survives the
 * way one on a thread that never drains would.
 */
static void *retire_like_el1(void *arg)
{
    (void) arg;
    _Atomic uint64_t *epoch =
        (_Atomic uint64_t *) ((uint8_t *) g->host_base + g->shim_data_base +
                              SHIM_MMAP_PT_EPOCH_OFF);
    mmap_lock_acquire(g);
    uint64_t gen = atomic_load_explicit(&g->pt_gen, memory_order_acquire);
    int rc = guest_invalidate_ptes(g, addr, addr + block);
    atomic_store_explicit(&g->pt_gen, gen, memory_order_release);
    atomic_fetch_add_explicit(epoch, 1, memory_order_release);
    mmap_lock_release();
    return (void *) (intptr_t) rc;
}

int main(void)
{
    g = calloc(1, sizeof(*g));
    if (!g || guest_init(g, 64ULL << 30, 0) != 0)
        return 1;
    if (!guest_build_page_tables(g, NULL, 0))
        return 1;
    if (guest_region_add(
            g, addr, addr + block, LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_NORESERVE, 0,
            NULL) < 0)
        return 1;

    TEST("EL1 PT epoch retires a cached translation");
    uint64_t avail = 0;
    void *before = guest_ptr_bound(g, addr, &avail, MEM_PERM_W, 1);
    void *cached = guest_ptr_avail_nofault(g, addr, &avail, MEM_PERM_R);
    pthread_t retirer;
    void *rc = NULL;
    if (!before || cached != before ||
        pthread_create(&retirer, NULL, retire_like_el1, NULL) != 0)
        return 1;
    pthread_join(retirer, &rc);
    void *after = guest_ptr_avail_nofault(g, addr, &avail, MEM_PERM_R);
    EXPECT_TRUE(rc == NULL && after == NULL,
                "retired range still served from the host cache");

    TEST("translation resumes after rematerialization");
    void *again = guest_ptr_bound(g, addr, &avail, MEM_PERM_W, 1);
    EXPECT_TRUE(again == before, "rematerialized block moved or failed");

    guest_destroy(g);
    free(g);
    SUMMARY("test-pt-epoch-host");
    return fails != 0;
}
