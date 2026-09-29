/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <unistd.h>

#include "core/guest.h"
#include "runtime/thread.h"
#include "syscall/internal.h"
#include "syscall/mem.h"
#include "syscall/signal.h"
#include "test-harness.h"
#include "utils.h"

int passes, fails;

typedef struct {
    pthread_cond_t cond;
    bool ready;
} lock_wait_t;

static void *wake_lock_waiter(void *arg)
{
    lock_wait_t *wait = arg;
    mmap_lock_acquire_raw();
    wait->ready = true;
    pthread_cond_signal(&wait->cond);
    mmap_lock_release_raw();
    return NULL;
}

static void test_nofault(guest_t *g)
{
    const uint64_t block = 2ULL << 20;
    const uint64_t addr = 32ULL << 20;
    if (guest_region_add(
            g, addr, addr + 2 * block, LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_NORESERVE, 0,
            NULL) < 0) {
        TEST("nofault setup");
        FAIL("could not add lazy region");
        return;
    }
    uint8_t data[2] = {0xa5, 0x5a};
    TEST("raw mmap lock tracks ownership");
    mmap_lock_acquire_raw();
    bool refused = mmap_lock_held_by_current_thread() &&
                   guest_read(g, addr, data, sizeof(data)) < 0;
    mmap_lock_release_raw();
    EXPECT_TRUE(refused && !mmap_lock_held_by_current_thread(),
                "raw scope allowed recursive materialization");

    TEST("condition wait restores mmap ownership");
    lock_wait_t wait = {.cond = PTHREAD_COND_INITIALIZER};
    pthread_t worker;
    mmap_lock_acquire(g);
    int started = pthread_create(&worker, NULL, wake_lock_waiter, &wait);
    while (started == 0 && !wait.ready)
        mmap_lock_cond_wait(g, &wait.cond);
    refused = mmap_lock_held_by_current_thread() &&
              guest_read(g, addr, data, sizeof(data)) < 0;
    mmap_lock_release();
    if (started == 0)
        pthread_join(worker, NULL);
    pthread_cond_destroy(&wait.cond);
    EXPECT_TRUE(started == 0 && refused, "condwait lost ownership tracking");

    TEST("nofault does not materialize");
    EXPECT_TRUE(guest_read_nofault(g, addr, data, sizeof(data)) < 0 &&
                    guest_write_nofault(g, addr, data, sizeof(data)) < 0 &&
                    !guest_va_pte_valid(g, addr),
                "nofault published a lazy PTE");

    TEST("partial nofault stops at lazy block");
    int rc = guest_lazy_faultin(g, addr, 1);
    size_t copied = guest_write_partial_nofault(g, addr + block - 1, data, 2);
    EXPECT_TRUE(rc == 0 && copied == 1 && !guest_va_pte_valid(g, addr + block),
                "partial copy lost its boundary or faulted in the next block");

    TEST("prefault then nofault crosses blocks");
    rc = guest_lazy_faultin(g, addr + block - 1, 2);
    uint8_t readback[2] = {0};
    mmap_lock_acquire(g);
    bool copied_all = guest_write_nofault(g, addr + block - 1, data, 2) == 0 &&
                      guest_read_nofault(g, addr + block - 1, readback, 2) == 0;
    mmap_lock_release();
    EXPECT_TRUE(rc == 0 && copied_all && readback[0] == data[0] &&
                    readback[1] == data[1],
                "prepared cross-block copy failed");

    TEST("locked missing range returns failure");
    mmap_lock_acquire(g);
    rc = guest_lazy_faultin_locked(g, addr + 4 * block, 1);
    refused = guest_read(g, addr + 4 * block, data, 1) < 0 &&
              guest_read_nofault(g, addr + 4 * block, data, 1) < 0;
    mmap_lock_release();
    EXPECT_TRUE(rc < 0 && refused, "missing range did not fail safely");
}

static void test_prepared_mmap(guest_t *g)
{
    TEST("prepared mmap does not look up guest fd");
    char path[] = "/tmp/elfuse-prepared-mmap-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }
    unlink(path);
    const uint8_t marker = 0xa5;
    bool ok = ftruncate(fd, GUEST_PAGE_SIZE) == 0 && write(fd, &marker, 1) == 1;
    const uint64_t addr = 1ULL << 40;
    g->is_rosetta = true;
    mmap_lock_acquire(g);
    int64_t mapped =
        ok ? sys_mmap(g, addr, GUEST_PAGE_SIZE, LINUX_PROT_READ,
                      LINUX_MAP_PRIVATE | LINUX_MAP_FIXED, -1, 0, fd)
           : -1;
    mmap_lock_release();
    uint8_t value = 0;
    ok = mapped == (int64_t) addr && guest_read(g, addr, &value, 1) == 0 &&
         value == marker;
    if (mapped == (int64_t) addr) {
        mmap_lock_acquire(g);
        int64_t conflict =
            sys_mmap(g, addr, GUEST_PAGE_SIZE, LINUX_PROT_READ,
                     LINUX_MAP_PRIVATE | LINUX_MAP_FIXED_NOREPLACE, -1, 0, fd);
        ok = ok && conflict == -LINUX_EEXIST;
        close(fd);
        fd = -1;
        const guest_region_t *region = guest_region_find(g, addr);
        ok = ok && region && pread(region->backing_fd, &value, 1, 0) == 1 &&
             value == marker;
        ok = sys_munmap(g, addr, GUEST_PAGE_SIZE) == 0 && ok;
        mmap_lock_release();
    }
    if (fd >= 0)
        close(fd);
    g->is_rosetta = false;
    EXPECT_TRUE(ok, "prepared fd or commit-time overlap check failed");
}

static void test_mremap_lazy_source(guest_t *g)
{
    const uint64_t block = 2ULL << 20;
    const uint64_t base = 64ULL << 20;
    const uint64_t source = base + 4 * GUEST_PAGE_SIZE;
    const uint64_t dest = base + 16 * GUEST_PAGE_SIZE;
    const uint64_t len = 3 * GUEST_PAGE_SIZE;
    const int flags =
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_NORESERVE;
    uint8_t *slab = g->host_base;
    TEST("mremap preserves valid L3 pages among dirty lazy holes");
    mmap_lock_acquire(g);
    bool ok =
        guest_region_add(g, source, source + len,
                         LINUX_PROT_READ | LINUX_PROT_WRITE, flags, 0,
                         NULL) == 0 &&
        guest_extend_page_tables(g, base, base + block, MEM_PERM_RW) == 0 &&
        guest_split_block(g, base) == 0 &&
        guest_invalidate_ptes(g, base, base + block) == 0 &&
        guest_update_perms(g, source + GUEST_PAGE_SIZE,
                           source + 2 * GUEST_PAGE_SIZE, MEM_PERM_RW) == 0;
    memset(slab + base, 0xa5, block);
    guest_dirty_mark_range(g, base, base + block);
    int64_t result =
        ok ? sys_mremap(g, source, len, len,
                        LINUX_MREMAP_MAYMOVE | LINUX_MREMAP_FIXED, dest)
           : -1;
    ok = ok && result == (int64_t) dest && !guest_va_pte_valid(g, source) &&
         !guest_va_pte_valid(g, dest - GUEST_PAGE_SIZE) &&
         !guest_va_pte_valid(g, dest + len);
    for (uint64_t off = 0; ok && off < len; off++) {
        uint8_t expected =
            off >= GUEST_PAGE_SIZE && off < 2 * GUEST_PAGE_SIZE ? 0xa5 : 0;
        ok = slab[dest + off] == expected;
    }
    mmap_lock_release();
    EXPECT_TRUE(ok,
                "copy exposed lazy bytes, lost valid data, or mapped a guard");

    TEST("low-address mremap growth zeroes only the source edge block");
    const uint64_t low = 96ULL << 20;
    const uint64_t old_len = 2 * block + GUEST_PAGE_SIZE;
    mmap_lock_acquire(g);
    ok = guest_region_add(g, low, low + old_len,
                          LINUX_PROT_READ | LINUX_PROT_WRITE, flags, 0,
                          NULL) == 0 &&
         guest_invalidate_ptes(g, low, low + old_len + GUEST_PAGE_SIZE) == 0;
    memset(slab + low, 0xa5, old_len + GUEST_PAGE_SIZE);
    guest_dirty_mark_range(g, low, low + old_len + GUEST_PAGE_SIZE);
    result =
        ok ? sys_mremap(g, low, old_len, old_len + GUEST_PAGE_SIZE, 0, 0) : -1;
    ok = ok && result == (int64_t) low && !guest_va_pte_valid(g, low) &&
         slab[low] == 0xa5 &&
         guest_va_pte_valid(g, low + old_len - GUEST_PAGE_SIZE);
    for (uint64_t off = old_len - GUEST_PAGE_SIZE;
         ok && off < old_len + GUEST_PAGE_SIZE; off++)
        ok = slab[low + off] == 0;
    mmap_lock_release();
    EXPECT_TRUE(ok, "growth exposed dirty bytes or materialized the old body");
}

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

    TEST("locked guest access refuses lazy faults");
    uint8_t value = 0xa5;
    mmap_lock_acquire(g);
    bool refused = guest_read(g, addr, &value, sizeof(value)) < 0 &&
                   guest_write(g, addr, &value, sizeof(value)) < 0 &&
                   guest_ptr(g, addr) == NULL && !guest_va_pte_valid(g, addr);
    mmap_lock_release();
    EXPECT_TRUE(refused, "locked resolve entered lazy materialization");

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

    test_nofault(g);
    test_prepared_mmap(g);
    test_mremap_lazy_source(g);

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
