/*
 * EL1 mmap-family syscall fast paths.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is compiled freestanding and linked into the shim image. It may not
 * call host code or a C runtime: the only state it consumes is the saved EL0
 * register frame, TPIDR_EL1's shim-data mapping, TTBR0_EL1, and the shared mmap
 * control protocol. Keep architecture-only operations in the small helpers
 * below; the synchronization and allocator policy remain ordinary C.
 */

#include "core/shim-mmap.h"

#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>

#include "core/mmap-fastpath.h"
#include "core/shim-globals.h"

#define EL1_PAGE_SIZE 0x1000ULL
#define EL1_BLOCK_SIZE 0x200000ULL
#define EL1_WINDOW_1G 0x40000000ULL
#define EL1_SHIM_DATA_SIZE 0x200000ULL

#define EL1_SYS_MUNMAP 215ULL
#define EL1_SYS_MMAP 222ULL

#define EL1_PROT_READ 1ULL
#define EL1_PROT_WRITE 2ULL
#define EL1_PROT_RW (EL1_PROT_READ | EL1_PROT_WRITE)

#define EL1_MAP_PRIVATE 0x02ULL
#define EL1_MAP_ANONYMOUS 0x20ULL
#define EL1_MAP_NORESERVE 0x4000ULL

#define EL1_DESC_ADDR_MASK 0x0000fffffffff000ULL
#define EL1_DESC_TYPE_MASK 0x3ULL
#define EL1_DESC_BLOCK 0x1ULL
#define EL1_DESC_TABLE 0x3ULL

#define EL1_L3_PTES_PER_BATCH 8u
#define EL1_TLBI_LEVEL_L2 2u
#define EL1_TLBI_LEVEL_L3 3u

/* The bump path promises 2 MiB-aligned starts at or above this request size, so
 * the host can back them with L2 blocks.
 */
#define EL1_ALIGN_THRESHOLD EL1_BLOCK_SIZE

/* Arena descriptors are one per vCPU slot. shim-globals.c pins this against
 * MAX_THREADS; the host thread header is not includable freestanding.
 */
#define EL1_ARENA_SLOTS 64u

typedef struct {
    uint8_t *shim_data;
    shim_mmap_control_t *control;
    _Atomic uint32_t *gate;
    unsigned slot;
} el1_mmap_context_t;

typedef enum {
    EL1_GATE_ENTERED,
    EL1_GATE_CLOSED_BEFORE_ANNOUNCE,
    EL1_GATE_CLOSED_AFTER_ANNOUNCE,
} el1_gate_result_t;

_Static_assert(EL1_SAVED_GPRS * sizeof(uint64_t) == 248,
               "saved GPR frame layout changed");
_Static_assert(sizeof(shim_mmap_entry_t) == 24,
               "EL1 mmap publication ABI changed");
_Static_assert(sizeof(munmap_retire_entry_t) == 24,
               "EL1 retire publication ABI changed");

static inline uint64_t el1_read_tpidr(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, tpidr_el1" : "=r"(value));
    return value;
}

static inline uint64_t el1_read_ttbr0(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(value));
    return value;
}

static inline void el1_dsb_ishst(void)
{
    __asm__ volatile("dsb ishst" ::: "memory");
}

static inline void el1_dsb_ish(void)
{
    __asm__ volatile("dsb ish" ::: "memory");
}

static inline void el1_isb(void)
{
    __asm__ volatile("isb" ::: "memory");
}

static inline void el1_tlbi_vale1is(uint64_t operand)
{
    __asm__ volatile("tlbi vale1is, %0" : : "r"(operand) : "memory");
}

static inline void el1_tlbi_rvale1is(uint64_t operand)
{
    __asm__ volatile("tlbi rvale1is, %0" : : "r"(operand) : "memory");
}

static inline void el1_tlbi_all(void)
{
    __asm__ volatile("tlbi vmalle1is" ::: "memory");
}

static inline uint64_t el1_desc_address(uint64_t descriptor)
{
    return descriptor & EL1_DESC_ADDR_MASK;
}

static inline uint64_t el1_desc_type(uint64_t descriptor)
{
    return descriptor & EL1_DESC_TYPE_MASK;
}

/* Guest VA is identity-mapped over the arena, so a descriptor's output address
 * is also the VA of the next table.
 */
static inline _Atomic uint64_t *el1_table(uint64_t descriptor)
{
    return (_Atomic uint64_t *) (uintptr_t) el1_desc_address(descriptor);
}

static inline uint64_t el1_block_start(uint64_t address)
{
    return address & ~(EL1_BLOCK_SIZE - 1);
}

static inline uint64_t el1_next_block(uint64_t address)
{
    return el1_block_start(address) + EL1_BLOCK_SIZE;
}

static inline uint64_t el1_min(uint64_t left, uint64_t right)
{
    return left < right ? left : right;
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

/* SP_EL1 stack tops are shim_data_end - slot*4KiB and controls are shim_data +
 * 0x20000 + slot*4KiB, so the saved frame's page locates the control without
 * consuming another system register.
 */
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
        .gate = (_Atomic uint32_t *) (shim_data + SHIM_MMAP_PT_GATE_OFF),
        .slot = slot,
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

/* Join the host-writer handshake. Arena revoke and refill both run with the
 * gate closed; announcing this per-vCPU producer prevents the host from
 * invalidating a descriptor between the generation check and the publication.
 * The second gate read closes the check-vs-announce race: if the host closed it
 * in between, withdraw without touching a PTE.
 */
static el1_gate_result_t el1_gate_enter(el1_mmap_context_t *context)
{
    if (atomic_load_explicit(context->gate, memory_order_acquire) != 0)
        return EL1_GATE_CLOSED_BEFORE_ANNOUNCE;

    atomic_store_explicit(&context->control->retire.producer_active, 1,
                          memory_order_release);
    if (atomic_load_explicit(context->gate, memory_order_acquire) != 0) {
        atomic_store_explicit(&context->control->retire.producer_active, 0,
                              memory_order_release);
        return EL1_GATE_CLOSED_AFTER_ANNOUNCE;
    }
    return EL1_GATE_ENTERED;
}

static inline void el1_gate_leave(el1_mmap_context_t *context)
{
    atomic_store_explicit(&context->control->retire.producer_active, 0,
                          memory_order_release);
}

/* mmap: consume a host-prepared, per-vCPU VA arena for the exact anonymous RW
 * shape used by allocators:
 *
 *   mmap(NULL, len, PROT_READ|PROT_WRITE,
 *        MAP_PRIVATE|MAP_ANONYMOUS[|MAP_NORESERVE], fd, off)
 *
 * Each vCPU is the sole producer of its mmap publication ring and cursor. The
 * host acquire-drains all publications whenever it takes mmap_lock.
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

    switch (el1_gate_enter(context)) {
    case EL1_GATE_ENTERED:
        break;
    case EL1_GATE_CLOSED_BEFORE_ANNOUNCE:
    case EL1_GATE_CLOSED_AFTER_ANNOUNCE:
        el1_mmap_counter(context, SHIM_MMAP_COUNTER_CAPACITY_MISS);
        return false;
    }

    uint32_t generation =
        atomic_load_explicit(&control->generation, memory_order_acquire);
    if (generation != atomic_load_explicit(&control->consumer_generation,
                                           memory_order_relaxed)) {
        /* A revocation deliberately leaves the consumer generation stale. Ack
         * only after the acquire load above, then make this syscall take HVC;
         * the host will either leave the control disabled or publish a fresh
         * arena.
         */
        atomic_store_explicit(&control->consumer_generation, generation,
                              memory_order_relaxed);
        el1_gate_leave(context);
        el1_mmap_counter(context, SHIM_MMAP_COUNTER_GENERATION_STALE);
        return false;
    }

    if (!(atomic_load_explicit(&control->flags, memory_order_relaxed) &
          SHIM_MMAP_CTRL_ENABLED)) {
        el1_gate_leave(context);
        el1_mmap_counter(context, SHIM_MMAP_COUNTER_CAPACITY_MISS);
        return false;
    }

    /* Reserve publication capacity before mutating the bump cursor. */
    uint32_t head = atomic_load_explicit(&control->head, memory_order_acquire);
    uint32_t tail = atomic_load_explicit(&control->tail, memory_order_relaxed);
    if ((uint32_t) (tail - head) >= SHIM_MMAP_RING_SIZE) {
        el1_gate_leave(context);
        el1_mmap_counter(context, SHIM_MMAP_COUNTER_RING_FULL);
        return false;
    }

    uint64_t address =
        atomic_load_explicit(&control->cursor, memory_order_relaxed);
    uint64_t cursor;
    if (length >= EL1_ALIGN_THRESHOLD) {
        if (el1_add_overflow(address, EL1_BLOCK_SIZE - 1, &address)) {
            el1_gate_leave(context);
            el1_mmap_counter(context, SHIM_MMAP_COUNTER_CAPACITY_MISS);
            return false;
        }
        address &= ~(EL1_BLOCK_SIZE - 1);
    }
    if (el1_add_overflow(address, length, &cursor) ||
        cursor >
            atomic_load_explicit(&control->arena_limit, memory_order_relaxed)) {
        el1_gate_leave(context);
        el1_mmap_counter(context, SHIM_MMAP_COUNTER_CAPACITY_MISS);
        return false;
    }

    shim_mmap_entry_t *entry = &control->ring[tail & (SHIM_MMAP_RING_SIZE - 1)];
    entry->addr = address;
    entry->len = length;
    entry->prot = prot;
    /* publish the bump cursor before the entry */
    atomic_store_explicit(&control->cursor, cursor, memory_order_relaxed);
    atomic_store_explicit(&control->tail, tail + 1, memory_order_release);
    atomic_store_explicit(&control->pending_work, 1, memory_order_release);

    el1_gate_leave(context);
    saved_gprs[0] = address;
    el1_mmap_counter(context, SHIM_MMAP_COUNTER_HIT);
    return true;
}

/* munmap: invalidate an anonymous arena range synchronously at EL1, then
 * release-publish a metadata retirement to this vCPU's SPSC ring. The host
 * consumes it at a later natural VM exit. No shared allocator cursor is
 * modified here.
 *
 * Validation precedes mutation, so clearing cannot discover a need to split
 * after changing an earlier descriptor. A range within one L3 table retains the
 * validated table pointer; other shapes use a second walk. Whole L2 blocks and
 * L3 leaves are the only descriptors this path writes.
 */

/* generation is re-read after bounds so a descriptor publication cannot be
 * observed torn.
 */
static bool el1_munmap_match_arena(shim_mmap_control_t *candidate,
                                   uint64_t start,
                                   uint64_t end,
                                   unsigned slot,
                                   uint32_t *generation_out,
                                   uint32_t *flags_out,
                                   unsigned *slot_out)
{
    uint32_t flags =
        atomic_load_explicit(&candidate->flags, memory_order_acquire);
    if (!(flags & SHIM_MMAP_CTRL_ENABLED))
        return false;
    uint32_t generation =
        atomic_load_explicit(&candidate->generation, memory_order_acquire);
    if (start <
        atomic_load_explicit(&candidate->arena_base, memory_order_relaxed))
        return false;
    if (end > atomic_load_explicit(&candidate->cursor, memory_order_acquire))
        return false;
    if (generation !=
        atomic_load_explicit(&candidate->generation, memory_order_acquire))
        return false;
    *generation_out = generation;
    *flags_out = flags;
    *slot_out = slot;
    return true;
}

/* Locate the one arena generation containing the whole range. Owner-local
 * munmap normally stops at context->control; cross-vCPU retirement scans the
 * remaining descriptors.
 */
static shim_mmap_control_t *el1_munmap_find_arena(
    const el1_mmap_context_t *context,
    uint64_t start,
    uint64_t end,
    uint32_t *generation_out,
    uint32_t *flags_out,
    unsigned *slot_out)
{
    if (el1_munmap_match_arena(context->control, start, end, context->slot,
                               generation_out, flags_out, slot_out))
        return context->control;

    for (unsigned slot = 0; slot < EL1_ARENA_SLOTS; slot++) {
        if (slot == context->slot)
            continue;
        shim_mmap_control_t *candidate =
            (shim_mmap_control_t *) (context->shim_data +
                                     SHIM_MMAP_CONTROL_BASE +
                                     (uintptr_t) slot *
                                         SHIM_MMAP_CONTROL_STRIDE);
        if (el1_munmap_match_arena(candidate, start, end, slot, generation_out,
                                   flags_out, slot_out))
            return candidate;
    }
    return NULL;
}

static inline uint64_t el1_vale_operand(uint64_t address, unsigned level)
{
    uint64_t base = (address >> 12) & ((1ULL << 44) - 1);
    if (level == 0)
        return base;
    /* TTL[3:2]=01 selects the 4 KiB granule; TTL[1:0] selects the level. */
    return base | ((uint64_t) (4u | level) << 44);
}

static inline uint64_t el1_rvale_operand(uint64_t address,
                                         uint64_t units,
                                         unsigned scale,
                                         unsigned level)
{
    uint64_t base = (address >> 12) & ((1ULL << 37) - 1);
    return base | ((uint64_t) level << 37) | ((units - 1) << 39) |
           ((uint64_t) scale << 44) | (1ULL << 46);
}

/* Encode SCALE=0..3 RVALE1IS batches directly from the changed envelope. Each
 * instruction covers up to 32 scale units: 64 pages at SCALE=0, 2048 at
 * SCALE=1, 65536 at SCALE=2, and 2097152 (8 GiB) at SCALE=3. Widening to the
 * scale-unit boundary only invalidates neighboring TLB entries; it cannot
 * change mappings. Ranges larger than one instruction are emitted as adjacent
 * batches while retaining a single completion DSB.
 */
static void el1_tlbi_pages(uint64_t start,
                           uint64_t end,
                           bool range_supported,
                           unsigned level)
{
    uint64_t pages = (end - start) / EL1_PAGE_SIZE;
    if (pages <= 1 || (!range_supported && pages <= 8)) {
        /* The Armv8.4+ range flag also establishes FEAT_TTL. */
        unsigned ttl_level = range_supported ? level : 0;
        uint64_t operand = el1_vale_operand(start, ttl_level);
        for (uint64_t page = 0; page < pages; page++)
            el1_tlbi_vale1is(operand + page);
        return;
    }

    if (!range_supported) {
        el1_tlbi_all();
        return;
    }

    unsigned scale;
    unsigned unit_shift;
    if (pages <= 64) {
        scale = 0;
        unit_shift = 13; /* 2 pages = 8 KiB */
    } else if (pages <= 0x800) {
        scale = 1;
        unit_shift = 18; /* 64 pages = 256 KiB */
    } else if (pages <= 0x10000) {
        scale = 2;
        unit_shift = 23; /* 2048 pages = 8 MiB */
    } else {
        scale = 3;
        unit_shift = 28; /* 65536 pages = 256 MiB */
    }

    uint64_t unit = 1ULL << unit_shift;
    uint64_t mask = unit - 1;
    uint64_t first = start & ~mask;
    uint64_t last;
    if (el1_add_overflow(end, mask, &last)) {
        el1_tlbi_all();
        return;
    }
    last &= ~mask;
    while (first < last) {
        uint64_t units = (last - first) >> unit_shift;
        if (units > 32)
            units = 32;
        el1_tlbi_rvale1is(el1_rvale_operand(first, units, scale, level));
        first += units << unit_shift;
    }
}

typedef enum {
    EL1_VALIDATE_GENERIC,   /* walk per block, mixed L2/L3 shapes */
    EL1_VALIDATE_L2_BLOCKS, /* proven L2-block-only under one L0 slot */
    EL1_VALIDATE_BAD,       /* corrupt or unsupported descriptor shape */
} el1_validate_t;

typedef struct {
    _Atomic uint64_t *single_l3;
    unsigned single_l3_first;
    unsigned single_l3_limit;
    unsigned tlbi_level;
} el1_munmap_pt_plan_t;

/* Common large-anonymous case: the materialized envelope is 2 MiB aligned and
 * consists only of L2 block descriptors (or holes retired by a sibling). Walk
 * L0 once, then L1 once per 1 GiB window and scan the L2 entries linearly. The
 * generic path remains the fallback for any L3 table or unusual upper shape.
 */
static el1_validate_t el1_validate_l2_blocks(uint64_t start, uint64_t end)
{
    if (((start | end) & (EL1_BLOCK_SIZE - 1)) != 0)
        return EL1_VALIDATE_GENERIC;
    if ((((end - 1) ^ start) >> 39) != 0) /* must stay in one L0 slot */
        return EL1_VALIDATE_GENERIC;

    _Atomic uint64_t *l0 = el1_table(el1_read_ttbr0());
    uint64_t l0_desc =
        atomic_load_explicit(&l0[(start >> 39) & 0x1ff], memory_order_acquire);
    uint64_t type = el1_desc_type(l0_desc);
    if (type == 0)
        return EL1_VALIDATE_L2_BLOCKS;
    if (type != EL1_DESC_TABLE)
        return EL1_VALIDATE_GENERIC;

    _Atomic uint64_t *l1 = el1_table(l0_desc);
    uint64_t address = start;
    while (address < end) {
        uint64_t window_end =
            el1_min(((address >> 30) + 1) << 30, end); /* next 1 GiB */
        uint64_t l1_desc = atomic_load_explicit(&l1[(address >> 30) & 0x1ff],
                                                memory_order_acquire);
        uint64_t l1_type = el1_desc_type(l1_desc);
        if (l1_type == 0) {
            address = window_end;
            continue;
        }
        if (l1_type != EL1_DESC_TABLE)
            return EL1_VALIDATE_GENERIC;

        _Atomic uint64_t *l2 = el1_table(l1_desc);
        unsigned index = (unsigned) ((address >> 21) & 0x1ff);
        while (address < window_end) {
            uint64_t l2_desc =
                atomic_load_explicit(&l2[index], memory_order_relaxed);
            uint64_t l2_type = el1_desc_type(l2_desc);
            if (l2_type != 0) {
                if (l2_type != EL1_DESC_BLOCK) /* L2 block, never L3 table */
                    return EL1_VALIDATE_GENERIC;
            }
            index++;
            address += EL1_BLOCK_SIZE;
        }
    }
    return EL1_VALIDATE_L2_BLOCKS;
}

/* Validation records a single-L3 clear range and the known leaf level. The
 * caller charges the materialized-envelope intersection as a conservative upper
 * bound rather than reading every L3 leaf merely to count exact bytes.
 */
static el1_validate_t el1_validate_generic(uint64_t request_start,
                                           uint64_t request_end,
                                           uint64_t start,
                                           uint64_t end,
                                           el1_munmap_pt_plan_t *plan)
{
    bool saw_l2 = false;
    bool saw_l3 = false;
    bool single_block = el1_block_start(start) == el1_block_start(end - 1);
    uint64_t address = start;
    while (address < end) {
        _Atomic uint64_t *l0 = el1_table(el1_read_ttbr0());
        uint64_t l0_desc = atomic_load_explicit(&l0[(address >> 39) & 0x1ff],
                                                memory_order_acquire);
        if (el1_desc_type(l0_desc) == 0) {
            address = el1_next_block(address);
            continue;
        }
        if (el1_desc_type(l0_desc) != EL1_DESC_TABLE)
            return EL1_VALIDATE_BAD;

        _Atomic uint64_t *l1 = el1_table(l0_desc);
        uint64_t l1_desc = atomic_load_explicit(&l1[(address >> 30) & 0x1ff],
                                                memory_order_acquire);
        if (el1_desc_type(l1_desc) == 0) {
            address = el1_next_block(address);
            continue;
        }
        if (el1_desc_type(l1_desc) != EL1_DESC_TABLE)
            return EL1_VALIDATE_BAD;

        _Atomic uint64_t *l2 = el1_table(l1_desc);
        uint64_t l2_desc = atomic_load_explicit(&l2[(address >> 21) & 0x1ff],
                                                memory_order_acquire);
        uint64_t l2_type = el1_desc_type(l2_desc);
        if (l2_type == 0) {
            address = el1_next_block(address);
            continue;
        }
        if (l2_type == EL1_DESC_TABLE) {
            saw_l3 = true;
            uint64_t block_end = el1_min(el1_next_block(address), end);
            if (single_block) {
                plan->single_l3 = el1_table(l2_desc);
                plan->single_l3_first = (unsigned) ((address >> 12) & 0x1ff);
                plan->single_l3_limit =
                    plan->single_l3_first +
                    (unsigned) ((block_end - address) / EL1_PAGE_SIZE);
            }
            address = block_end;
            continue;
        }
        if (l2_type != EL1_DESC_BLOCK)
            return EL1_VALIDATE_BAD;

        saw_l2 = true;
        /* An L2 block can only be cleared as a whole. */
        uint64_t block_start = el1_block_start(address);
        if (request_start > block_start ||
            request_end < block_start + EL1_BLOCK_SIZE)
            return EL1_VALIDATE_BAD;
        address = block_start + EL1_BLOCK_SIZE;
    }
    if (saw_l2 != saw_l3)
        plan->tlbi_level = saw_l2 ? EL1_TLBI_LEVEL_L2 : EL1_TLBI_LEVEL_L3;
    return EL1_VALIDATE_GENERIC;
}

/* Mutation pass. Host writers are gated; sibling fast munmaps can only change
 * the same descriptors to zero, so repeated invalidation is safe.
 */
static inline void el1_clear_l3_batch(_Atomic uint64_t *entry)
{
    __asm__ volatile(
        "stp xzr, xzr, [%0, #0]\n\t"
        "stp xzr, xzr, [%0, #16]\n\t"
        "stp xzr, xzr, [%0, #32]\n\t"
        "stp xzr, xzr, [%0, #48]"
        :
        : "r"(entry)
        : "memory");
}

static inline void el1_clear_l3_pair(_Atomic uint64_t *entry)
{
    __asm__ volatile("stp xzr, xzr, [%0]" : : "r"(entry) : "memory");
}

static void el1_clear_l3_entries(_Atomic uint64_t *l3,
                                 unsigned first,
                                 unsigned limit)
{
    /* Page tables are page-aligned. Peel to a 64-byte group with scalar and
     * paired stores, clear full groups, then clear paired and scalar tails. The
     * caller's DSB ISHST orders every descriptor write before TLBI.
     */
    while (first < limit && (first & (EL1_L3_PTES_PER_BATCH - 1)) != 0) {
        if (((first & 1u) == 0) && (limit - first >= 2)) {
            el1_clear_l3_pair(&l3[first]);
            first += 2;
        } else {
            atomic_store_explicit(&l3[first], 0, memory_order_relaxed);
            first++;
        }
    }
    while (limit - first >= EL1_L3_PTES_PER_BATCH) {
        el1_clear_l3_batch(&l3[first]);
        first += EL1_L3_PTES_PER_BATCH;
    }
    while (limit - first >= 2) {
        el1_clear_l3_pair(&l3[first]);
        first += 2;
    }
    if (first < limit)
        atomic_store_explicit(&l3[first], 0, memory_order_relaxed);
}

static bool el1_clear_generic(uint64_t start, uint64_t end)
{
    uint64_t address = start;
    while (address < end) {
        _Atomic uint64_t *l0 = el1_table(el1_read_ttbr0());
        uint64_t l0_desc = atomic_load_explicit(&l0[(address >> 39) & 0x1ff],
                                                memory_order_acquire);
        if (el1_desc_type(l0_desc) != EL1_DESC_TABLE) {
            address = el1_next_block(address);
            continue;
        }

        _Atomic uint64_t *l1 = el1_table(l0_desc);
        uint64_t l1_desc = atomic_load_explicit(&l1[(address >> 30) & 0x1ff],
                                                memory_order_acquire);
        if (el1_desc_type(l1_desc) != EL1_DESC_TABLE) {
            address = el1_next_block(address);
            continue;
        }

        _Atomic uint64_t *l2 = el1_table(l1_desc);
        _Atomic uint64_t *l2_entry = &l2[(address >> 21) & 0x1ff];
        uint64_t l2_desc = atomic_load_explicit(l2_entry, memory_order_acquire);
        uint64_t l2_type = el1_desc_type(l2_desc);
        if (l2_type == 0) {
            address = el1_next_block(address);
            continue;
        }
        if (l2_type == EL1_DESC_BLOCK) {
            atomic_store_explicit(l2_entry, 0, memory_order_release);
            address = el1_next_block(address);
            continue;
        }
        if (l2_type != EL1_DESC_TABLE)
            return false; /* validation invariant */

        _Atomic uint64_t *l3 = el1_table(l2_desc);
        uint64_t block_end = el1_min(el1_next_block(address), end);
        unsigned first = (unsigned) ((address >> 12) & 0x1ff);
        unsigned limit =
            first + (unsigned) ((block_end - address) / EL1_PAGE_SIZE);
        el1_clear_l3_entries(l3, first, limit);
        address = block_end;
    }
    return true;
}

/* Validation proved one L0 table and L2-block-only leaves. Re-walk L1 once per
 * 1 GiB window, then use ordinary aligned 64-bit stores. Those stores are
 * atomic; the DSB ISHST below supplies the required publication order, so a
 * release store on every descriptor is unnecessary.
 */
static void el1_clear_l2_blocks(uint64_t start, uint64_t end)
{
    _Atomic uint64_t *l0 = el1_table(el1_read_ttbr0());
    uint64_t l0_desc =
        atomic_load_explicit(&l0[(start >> 39) & 0x1ff], memory_order_relaxed);
    if (el1_desc_type(l0_desc) != EL1_DESC_TABLE)
        return;
    _Atomic uint64_t *l1 = el1_table(l0_desc);

    uint64_t address = start;
    while (address < end) {
        uint64_t window_end = el1_min(((address >> 30) + 1) << 30, end);
        uint64_t l1_desc = atomic_load_explicit(&l1[(address >> 30) & 0x1ff],
                                                memory_order_relaxed);
        if (el1_desc_type(l1_desc) == 0) {
            address = window_end;
            continue;
        }

        _Atomic uint64_t *l2 = el1_table(l1_desc);
        unsigned index = (unsigned) ((address >> 21) & 0x1ff);
        while (address < window_end) {
            /* Validation plus the closed host gate proves this slot is a block
             * or already zero. A sibling producer can only move it toward zero,
             * so an unconditional aligned store is safe and avoids a second
             * load/branch.
             */
            atomic_store_explicit(&l2[index], 0, memory_order_relaxed);
            index++;
            address += EL1_BLOCK_SIZE;
        }
    }
}

static bool el1_munmap(el1_mmap_context_t *context, uint64_t *saved_gprs)
{
    shim_mmap_control_t *control = context->control;
    munmap_retire_ring_t *retire = &control->retire;

    if (el1_attention_pending(context)) {
        el1_attention_counter(context);
        return false;
    }

    uint64_t start = saved_gprs[0];
    uint64_t length = saved_gprs[1];
    uint64_t end;
    if (length == 0 || (start & (EL1_PAGE_SIZE - 1)) ||
        (length & (EL1_PAGE_SIZE - 1)) || el1_add_overflow(start, length, &end))
        return false;

    uint32_t head = atomic_load_explicit(&retire->head, memory_order_acquire);
    uint32_t tail = atomic_load_explicit(&retire->tail, memory_order_relaxed);
    if ((uint32_t) (tail - head) >= SHIM_MUNMAP_RETIRE_RING_SIZE - 1) {
        atomic_fetch_add_explicit(&control->munmap_retire_near_full, 1,
                                  memory_order_relaxed);
        return false; /* near-full => batched HVC drain */
    }
    uint64_t produced =
        atomic_load_explicit(&retire->produced_bytes, memory_order_relaxed);

    switch (el1_gate_enter(context)) {
    case EL1_GATE_ENTERED:
        break;
    case EL1_GATE_CLOSED_BEFORE_ANNOUNCE:
    case EL1_GATE_CLOSED_AFTER_ANNOUNCE:
        return false;
    }

    uint32_t generation;
    uint32_t arena_flags;
    unsigned arena_slot;
    shim_mmap_control_t *owner = el1_munmap_find_arena(
        context, start, end, &generation, &arena_flags, &arena_slot);
    if (!owner) {
        el1_gate_leave(context);
        return false;
    }

    /* Reserve and fill, but do not advance tail until PTE+TLBI completion. */
    munmap_retire_entry_t *entry =
        &retire->entries[tail & (SHIM_MUNMAP_RETIRE_RING_SIZE - 1)];
    entry->addr = start;
    entry->length = length;
    entry->arena_generation = generation;
    entry->flags = arena_slot;

    /* Refill invalidates every stale descriptor before publishing a new
     * generation. Until the host records a lazy materialization in that
     * generation, the entire arena is known PTE-empty and no walk/TLBI is
     * needed. The host PT gate makes the generation marker stable here.
     */
    uint64_t charged_pages = 0;
    uint64_t walk_start = 0;
    uint64_t walk_end = 0;
    bool walked = false;
    if (atomic_load_explicit(&owner->materialized_generation,
                             memory_order_acquire) == generation) {
        uint64_t materialized_start = atomic_load_explicit(
            &owner->materialized_start, memory_order_relaxed);
        uint64_t materialized_end = atomic_load_explicit(
            &owner->materialized_end, memory_order_relaxed);
        walk_start = start > materialized_start ? start : materialized_start;
        walk_end = el1_min(end, materialized_end);
        walked = walk_start < walk_end;
    }

    bool l2_blocks = false;
    el1_munmap_pt_plan_t plan = {0};
    if (walked) {
        el1_validate_t verdict = el1_validate_l2_blocks(walk_start, walk_end);
        if (verdict == EL1_VALIDATE_L2_BLOCKS) {
            l2_blocks = true;
            plan.tlbi_level = EL1_TLBI_LEVEL_L2;
        } else {
            verdict =
                el1_validate_generic(start, end, walk_start, walk_end, &plan);
            if (verdict == EL1_VALIDATE_BAD) {
                el1_gate_leave(context);
                return false;
            }
        }

        /* Charge the materialized-envelope intersection rather than walking
         * every L3 leaf to count exact PTE coverage. Holes can only make this
         * an overestimate, which is safe for the advisory cleanup threshold;
         * the host consumes the same bound from this retirement entry.
         */
        charged_pages = (walk_end - walk_start) / EL1_PAGE_SIZE;
        entry->flags =
            (uint32_t) (charged_pages << SHIM_MUNMAP_RETIRE_F_CHARGE_SHIFT) |
            (uint32_t) arena_slot;
    }

    if (walked && charged_pages != 0) {
        uint64_t consumed =
            atomic_load_explicit(&retire->consumed_bytes, memory_order_acquire);
        uint64_t charge = charged_pages << 12;
        uint64_t pending;
        if (el1_add_overflow(produced - consumed, charge, &pending) ||
            el1_add_overflow(produced, charge, &produced)) {
            el1_gate_leave(context);
            return false;
        }

        /* Crossing the soft threshold records cleanup_requested but never
         * forces this producer to HVC; another natural exit consumes the ring.
         */
        if (pending > SHIM_MUNMAP_RETIRE_BYTES_SOFT)
            atomic_store_explicit(&retire->cleanup_requested, 1,
                                  memory_order_release);

        if (l2_blocks) {
            el1_clear_l2_blocks(walk_start, walk_end);
        } else if (plan.single_l3) {
            el1_clear_l3_entries(plan.single_l3, plan.single_l3_first,
                                 plan.single_l3_limit);
        } else if (!el1_clear_generic(walk_start, walk_end)) {
            el1_gate_leave(context);
            return false;
        }

        /* Descriptor stores -> leaf invalidation -> completed visibility before
         * the retire tail release makes metadata cleanup eligible.
         */
        el1_dsb_ishst();
        el1_tlbi_pages(walk_start, walk_end,
                       (arena_flags & SHIM_MMAP_CTRL_TLBIRANGE) != 0,
                       plan.tlbi_level);
        el1_dsb_ish();
        el1_isb();
    }

    atomic_store_explicit(&retire->produced_bytes, produced,
                          memory_order_relaxed);
    atomic_store_explicit(&retire->tail, tail + 1, memory_order_release);
    atomic_store_explicit(&context->control->pending_work, 1,
                          memory_order_release);
    el1_gate_leave(context);
    saved_gprs[0] = 0;
    return true;
}

bool el1_mmap_fastpath(uint64_t saved_gprs[static EL1_SAVED_GPRS])
{
    el1_mmap_context_t context = el1_context(saved_gprs);
    switch (saved_gprs[8]) {
    case EL1_SYS_MMAP:
        return el1_mmap(&context, saved_gprs);
    case EL1_SYS_MUNMAP:
        return el1_munmap(&context, saved_gprs);
    default:
        return false;
    }
}
