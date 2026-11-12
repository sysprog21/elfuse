/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include "core/guest.h"
#include "core/mmap-lock.h"
#include "runtime/thread.h"
#include "syscall/linux-wire.h"
#include "syscall/mem.h"
#include "test-harness.h"

int passes, fails;

static int read_byte_nofault(const guest_t *g, uint64_t addr, uint8_t *value)
{
    uint64_t avail = 0;
    const uint8_t *p = guest_ptr_avail_nofault(g, addr, &avail, MEM_PERM_R);
    if (!p || avail == 0)
        return -1;
    *value = *p;
    return 0;
}

int main(void)
{
    guest_t *g = calloc(1, sizeof(*g));
    if (!g || guest_init(g, 64ULL << 30, 0) != 0 ||
        !guest_build_page_tables(g, NULL, 0))
        return 1;
    const uint64_t block = 2ULL << 20, page = 4096;
    const uint64_t base = 16ULL << 20;
    const int flags =
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_NORESERVE;
    mmap_lock_acquire(g);
    if (guest_region_add(g, base, base + page,
                         LINUX_PROT_READ | LINUX_PROT_WRITE, flags, 0,
                         NULL) < 0 ||
        guest_region_add(g, base + page, base + 2 * page, LINUX_PROT_READ,
                         flags, 0, NULL) < 0)
        return 1;
    uint8_t marker = 0x5a, value = 0xff;
    if (guest_materialize_lazy(g, base) < 0 ||
        guest_write_nofault(g, base, &marker, 1) < 0)
        return 1;

    TEST("prefault spans adjacent regions within one block");
    int rc = guest_lazy_faultin_locked(g, base, 2 * page);
    EXPECT_TRUE(
        rc == 0 && read_byte_nofault(g, base + page, &value) == 0 && value == 0,
        "the second region remained lazy");

    TEST("prefault reaches an unmaterialized merged suffix");
    rc = guest_region_add(g, base + 2 * page, base + 3 * page, LINUX_PROT_READ,
                          flags, 0, NULL);
    if (rc == 0)
        rc = guest_lazy_faultin_locked(g, base, 3 * page);
    EXPECT_TRUE(rc == 0 && read_byte_nofault(g, base + 2 * page, &value) == 0 &&
                    value == 0 && read_byte_nofault(g, base, &value) == 0 &&
                    value == marker,
                "prefault skipped a suffix or overwrote the resident prefix");

    const uint64_t large = 32ULL << 20, span = 128ULL << 20;
    if (guest_region_add(g, large, large + span,
                         LINUX_PROT_READ | LINUX_PROT_WRITE, flags, 0,
                         NULL) < 0)
        return 1;
    mmap_lock_release();
    TEST("bounded resolve materializes one block");
    uint64_t before = g->materialize_stats[GUEST_MATERIALIZE_WINDOW_BYTES];
    uint64_t avail = 0;
    void *ptr = guest_ptr_bound(g, large, &avail, MEM_PERM_W, span);
    EXPECT_TRUE(
        ptr && avail == block &&
            g->materialize_stats[GUEST_MATERIALIZE_WINDOW_BYTES] - before ==
                block &&
            guest_ptr_avail_nofault(g, large + block, &avail, MEM_PERM_R) ==
                NULL,
        "the requested transfer count committed untouched blocks");

    TEST("mprotect preserves untouched interior blocks");
    mmap_lock_acquire(g);
    rc = (int) sys_mprotect(g, large, span, LINUX_PROT_READ | LINUX_PROT_WRITE);
    if (rc == 0)
        rc = (int) sys_mprotect(g, large + page, span - 2 * page,
                                LINUX_PROT_READ);
    ptr = guest_ptr_avail_nofault(g, large + span / 2, &avail, MEM_PERM_R);
    mmap_lock_release();
    EXPECT_TRUE(rc == 0 && ptr == NULL, "mprotect committed the lazy interior");

    guest_destroy(g);
    free(g);
    SUMMARY("test-materialize-host");
    return fails != 0;
}
