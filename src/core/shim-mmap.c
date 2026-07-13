/*
 * EL1 mmap syscall fast path.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is compiled freestanding and linked into the shim image.  It may
 * not call host code or a C runtime: the only state it consumes is the saved
 * EL0 register frame, TPIDR_EL1's shim-data mapping, and the shared mmap
 * control protocol.  Keep architecture-only operations in the small helper
 * below; the allocator policy remains ordinary C.
 */

#include "core/shim-mmap.h"

#include <stdatomic.h>
#include <stdint.h>

#include "core/mmap-fastpath.h"
#include "core/shim-globals.h"

#define EL1_PAGE_SIZE 0x1000ULL
#define EL1_BLOCK_SIZE 0x200000ULL
#define EL1_SHIM_DATA_SIZE 0x200000ULL

#define EL1_SYS_MMAP 222ULL

#define EL1_PROT_READ 1ULL
#define EL1_PROT_WRITE 2ULL
#define EL1_PROT_RW (EL1_PROT_READ | EL1_PROT_WRITE)

#define EL1_MAP_PRIVATE 0x02ULL
#define EL1_MAP_ANONYMOUS 0x20ULL
#define EL1_MAP_NORESERVE 0x4000ULL

/* The bump path promises 2 MiB-aligned starts at or above this request size,
 * so the host can back them with L2 blocks. */
#define EL1_ALIGN_THRESHOLD EL1_BLOCK_SIZE

typedef struct {
    uint8_t *shim_data;
    shim_mmap_control_t *control;
} el1_mmap_context_t;

_Static_assert(EL1_SAVED_GPRS * sizeof(uint64_t) == 248,
               "saved GPR frame layout changed");
_Static_assert(sizeof(shim_mmap_entry_t) == 24,
               "EL1 mmap publication ABI changed");

static inline uint64_t el1_read_tpidr(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, tpidr_el1" : "=r"(value));
    return value;
}

static inline bool el1_add_overflow(uint64_t left,
                                    uint64_t right,
                                    uint64_t *result)
{
    return __builtin_add_overflow(left, right, result);
}

static bool el1_page_round(uint64_t length, uint64_t *rounded)
{
    uint64_t value;
    if (length == 0 || el1_add_overflow(length, EL1_PAGE_SIZE - 1, &value))
        return false;
    *rounded = value & ~(EL1_PAGE_SIZE - 1);
    return true;
}

/* SP_EL1 stack tops are shim_data_end - slot*4KiB and controls are
 * shim_data + 0x20000 + slot*2KiB, so the saved frame's page locates the
 * control without consuming another system register. */
static el1_mmap_context_t el1_context(uint64_t *saved_gprs)
{
    uintptr_t shim_data = (uintptr_t) el1_read_tpidr();
    uintptr_t frame = (uintptr_t) saved_gprs;
    uintptr_t stack_top =
        (frame + EL1_PAGE_SIZE - 1) & ~(uintptr_t) (EL1_PAGE_SIZE - 1);
    uintptr_t slot_bytes = shim_data + EL1_SHIM_DATA_SIZE - stack_top;
    unsigned slot = (unsigned) (slot_bytes / EL1_PAGE_SIZE);
    return (el1_mmap_context_t) {
        .shim_data = (uint8_t *) shim_data,
        .control = (shim_mmap_control_t *) (shim_data + SHIM_MMAP_CONTROL_BASE +
                                            (uintptr_t) slot *
                                                SHIM_MMAP_CONTROL_STRIDE),
    };
}

static inline bool el1_stats_enabled(const el1_mmap_context_t *context)
{
    return context->shim_data[SHIM_GLOBALS_OFF_STATS_EN] != 0;
}

/* Each vCPU is the sole writer of its own counter slots. */
static inline void el1_counter_increment(_Atomic uint64_t *counter)
{
    uint64_t value = atomic_load_explicit(counter, memory_order_relaxed);
    atomic_store_explicit(counter, value + 1, memory_order_relaxed);
}

static inline void el1_mmap_counter(const el1_mmap_context_t *context,
                                    unsigned counter)
{
    if (el1_stats_enabled(context))
        el1_counter_increment(&context->control->counters[counter]);
}

static inline void el1_attention_counter(const el1_mmap_context_t *context)
{
    if (!el1_stats_enabled(context))
        return;
    _Atomic uint64_t *counter =
        (_Atomic uint64_t *) (context->shim_data + SHIM_COUNTERS_OFF) +
        SHIM_COUNTER_ATTN_BAIL;
    el1_counter_increment(counter);
}

static inline bool el1_attention_pending(const el1_mmap_context_t *context)
{
    return atomic_load_explicit((_Atomic uint32_t *) (context->shim_data +
                                                      SHIM_GLOBALS_OFF_ATTN),
                                memory_order_acquire) != 0;
}

/* Consume a host-prepared, per-vCPU VA arena for the exact anonymous RW shape
 * used by allocators:
 *
 *   mmap(NULL, len, PROT_READ|PROT_WRITE,
 *        MAP_PRIVATE|MAP_ANONYMOUS[|MAP_NORESERVE], fd, off)
 *
 * Each vCPU is the sole producer of its publication ring and cursor.  The host
 * acquire-drains all publications whenever it takes mmap_lock.
 */
static bool el1_mmap(el1_mmap_context_t *context, uint64_t *saved_gprs)
{
    shim_mmap_control_t *control = context->control;

    if (el1_attention_pending(context)) {
        el1_mmap_counter(context, SHIM_MMAP_COUNTER_ATTENTION);
        el1_attention_counter(context);
        return false;
    }

    uint64_t prot = saved_gprs[2];
    uint64_t flags = saved_gprs[3];
    uint64_t length;
    if (saved_gprs[0] != 0 || prot != EL1_PROT_RW ||
        (flags & ~EL1_MAP_NORESERVE) != (EL1_MAP_PRIVATE | EL1_MAP_ANONYMOUS) ||
        !el1_page_round(saved_gprs[1], &length)) {
        el1_mmap_counter(context, SHIM_MMAP_COUNTER_SHAPE_MISS);
        return false;
    }

    uint32_t generation =
        atomic_load_explicit(&control->generation, memory_order_acquire);
    if (generation != atomic_load_explicit(&control->consumer_generation,
                                           memory_order_relaxed)) {
        /* A revocation deliberately leaves the consumer generation stale.  Ack
         * only after the acquire load above, then make this syscall take HVC;
         * the host will either leave the control disabled or publish a fresh
         * arena.
         */
        atomic_store_explicit(&control->consumer_generation, generation,
                              memory_order_relaxed);
        el1_mmap_counter(context, SHIM_MMAP_COUNTER_GENERATION_STALE);
        return false;
    }

    if (!(atomic_load_explicit(&control->flags, memory_order_relaxed) &
          SHIM_MMAP_CTRL_ENABLED)) {
        el1_mmap_counter(context, SHIM_MMAP_COUNTER_CAPACITY_MISS);
        return false;
    }

    uint64_t address =
        atomic_load_explicit(&control->cursor, memory_order_relaxed);
    uint64_t cursor;
    if (length >= EL1_ALIGN_THRESHOLD) {
        if (el1_add_overflow(address, EL1_BLOCK_SIZE - 1, &address)) {
            el1_mmap_counter(context, SHIM_MMAP_COUNTER_CAPACITY_MISS);
            return false;
        }
        address &= ~(EL1_BLOCK_SIZE - 1);
    }
    if (el1_add_overflow(address, length, &cursor) ||
        cursor >
            atomic_load_explicit(&control->arena_limit, memory_order_relaxed)) {
        el1_mmap_counter(context, SHIM_MMAP_COUNTER_CAPACITY_MISS);
        return false;
    }

    uint32_t head = atomic_load_explicit(&control->head, memory_order_acquire);
    uint32_t tail = atomic_load_explicit(&control->tail, memory_order_relaxed);
    if ((uint32_t) (tail - head) >= SHIM_MMAP_RING_SIZE) {
        el1_mmap_counter(context, SHIM_MMAP_COUNTER_RING_FULL);
        return false;
    }

    shim_mmap_entry_t *entry = &control->ring[tail & (SHIM_MMAP_RING_SIZE - 1)];
    entry->addr = address;
    entry->len = length;
    entry->prot = prot;
    /* Publish the bump cursor before the entry. */
    atomic_store_explicit(&control->cursor, cursor, memory_order_relaxed);
    atomic_store_explicit(&control->tail, tail + 1, memory_order_release);

    saved_gprs[0] = address;
    el1_mmap_counter(context, SHIM_MMAP_COUNTER_HIT);
    return true;
}

bool el1_mmap_fastpath(uint64_t saved_gprs[static EL1_SAVED_GPRS])
{
    if (saved_gprs[8] != EL1_SYS_MMAP)
        return false;
    el1_mmap_context_t context = el1_context(saved_gprs);
    return el1_mmap(&context, saved_gprs);
}
