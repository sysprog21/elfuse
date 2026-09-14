/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include "core/guest.h"
#include "runtime/thread.h"
#include "syscall/internal.h"
#include "syscall/signal.h"
#include "test-harness.h"

int passes, fails;

int main(void)
{
    guest_t *g = calloc(1, sizeof(*g));
    if (!g || guest_init(g, 64ULL << 30, 0) != 0)
        return 1;
    if (!guest_build_page_tables(g, NULL, 0))
        return 1;
    const uint64_t block = 2ULL << 20;
    const uint64_t addr = 16ULL << 20;
    if (guest_region_add(
            g, addr, addr + block, LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_NORESERVE, 0,
            NULL) < 0)
        return 1;

    TEST("zero-length resolve preserves lazy PTEs");
    uint64_t avail = 0;
    void *ptr = guest_ptr_bound(g, addr, &avail, MEM_PERM_R, 0);
    EXPECT_TRUE(ptr == NULL && !guest_va_pte_valid(g, addr) &&
                    g->materialize_stats[GUEST_MATERIALIZE_WINDOW_BYTES] == 0,
                "empty resolve materialized memory");

    TEST("writable materialization remains dirty");
    uint8_t *word = guest_ptr_bound(g, addr, &avail, MEM_PERM_W, 1);
    if (!word)
        return 1;
    *word = 0xa5;
    mmap_lock_acquire(g);
    bool dirty = guest_block_may_be_dirty(g, addr);
    int rc = guest_invalidate_ptes(g, addr, addr + block);
    if (rc == 0)
        rc = guest_materialize_lazy(g, addr);
    bool zero = *word == 0;
    dirty = dirty && guest_block_may_be_dirty(g, addr);
    mmap_lock_release();
    EXPECT_TRUE(rc == 0 && zero && dirty,
                "writable reuse skipped zeroing or lost dirty state");

    TEST("read-only zeroed block can clean-skip on reuse");
    mmap_lock_acquire(g);
    g->regions[0].prot = LINUX_PROT_READ;
    rc = guest_invalidate_ptes(g, addr, addr + block);
    if (rc == 0)
        rc = guest_materialize_lazy(g, addr);
    uint64_t skips = g->materialize_stats[GUEST_MATERIALIZE_CLEAN_SKIP];
    if (rc == 0)
        rc = guest_invalidate_ptes(g, addr, addr + block);
    if (rc == 0)
        rc = guest_materialize_lazy(g, addr);
    bool clean = !guest_block_may_be_dirty(g, addr);
    bool skipped = g->materialize_stats[GUEST_MATERIALIZE_CLEAN_SKIP] > skips;
    mmap_lock_release();
    EXPECT_TRUE(rc == 0 && clean && skipped,
                "clean reuse did not skip zeroing");

    TEST("signal frame fits below low SP without prefault slack");
    if (guest_region_add(
            g, 0, block, LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_NORESERVE, 0,
            NULL) < 0)
        return 1;
    hv_vcpu_exit_t *vexit;
    if (hv_vcpu_create(&g->vcpu, &vexit, NULL) != HV_SUCCESS)
        return 1;
    g->vcpu_valid = true;
    thread_init();
    signal_init();
    signal_state_snapshot_t *state = calloc(1, sizeof(*state));
    if (!state)
        return 1;
    state->actions[LINUX_SIGUSR1 - 1].sa_handler = addr;
    signal_set_state(state);
    free(state);
    hv_vcpu_set_sys_reg(g->vcpu, HV_SYS_REG_SP_EL0,
                        sizeof(linux_rt_sigframe_t));
    signal_queue(LINUX_SIGUSR1);
    int exit_code = 0;
    rc = signal_deliver(g->vcpu, g, &exit_code);
    uint64_t sp = UINT64_MAX;
    hv_vcpu_get_sys_reg(g->vcpu, HV_SYS_REG_SP_EL0, &sp);
    EXPECT_TRUE(rc == 1 && sp == 0 && guest_va_pte_valid(g, 0),
                "low-SP signal frame was not installed");

    guest_destroy(g);
    free(g);
    SUMMARY("test-materialize-host");
    return fails != 0;
}
