/*
 * Per-vCPU EL1 anonymous-mmap consumer rings.
 *
 * The host is the sole producer of arenas and the sole consumer of ring
 * entries.  EL1 only bump-allocates VA and appends descriptions.  Control
 * blocks live in the EL1-only shim-data mapping and are selected from SP_EL1's
 * per-thread stack slot, so no guest-visible register ABI is consumed.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

#include "core/guest.h"

typedef struct thread_entry thread_entry_t;

#define SHIM_MMAP_CONTROL_BASE 0x20000u
#define SHIM_MMAP_CONTROL_STRIDE 0x800u
#define SHIM_MMAP_RING_SIZE 16u
#define SHIM_MMAP_CTRL_ENABLED 0x1u

#define MMAP_FAST_ARENA_MIN (64ULL * 1024 * 1024)
#define MMAP_FAST_ARENA_MAX (1ULL * 1024 * 1024 * 1024)
#define MMAP_FAST_HISTORY_MULTIPLIER 16u

enum {
    SHIM_MMAP_COUNTER_SHAPE_MISS = 0,
    SHIM_MMAP_COUNTER_CAPACITY_MISS,
    SHIM_MMAP_COUNTER_RING_FULL,
    SHIM_MMAP_COUNTER_GENERATION_STALE,
    SHIM_MMAP_COUNTER_ATTENTION,
    SHIM_MMAP_COUNTER_HIT,
    SHIM_MMAP_COUNTERS_N,
};

typedef struct {
    uint64_t addr;
    uint64_t len;
    uint64_t prot;
} shim_mmap_entry_t;

typedef struct {
    _Atomic uint32_t generation;          /* host publish word */
    _Atomic uint32_t consumer_generation; /* EL1 generation ack */
    _Atomic uint32_t flags;               /* host-owned enable bits */
    _Atomic uint32_t head;                /* host consumer cursor */
    _Atomic uint32_t tail;                /* EL1 producer cursor */
    uint32_t _pad0;
    _Atomic uint64_t arena_base;
    _Atomic uint64_t arena_limit;
    _Atomic uint64_t cursor;  /* EL1 bump cursor */
    uint64_t next_arena_size; /* most recently selected generation size */
    uint64_t max_len_seen;    /* outgoing-generation request history */
    shim_mmap_entry_t ring[SHIM_MMAP_RING_SIZE];
    _Atomic uint64_t counters[SHIM_MMAP_COUNTERS_N];
    uint64_t refill_count;
    uint64_t recycle_count;
    uint64_t peak_arena_size;
} shim_mmap_control_t;

/* Provision the main vCPU before guest entry. Worker vCPUs provision lazily on
 * their first eligible mmap so short-lived threads do not allocate an unused
 * arena.
 */
void mmap_fastpath_prepare_vcpu(guest_t *g, thread_entry_t *t);

/* Drain every per-vCPU SPSC ring. Caller holds mmap_lock. */
void mmap_fastpath_drain_locked(guest_t *g);

/* Refill the current vCPU after an eligible mmap slow-path. request_len is
 * page-rounded; requests above MMAP_FAST_ARENA_MAX leave the arena untouched.
 * Caller holds mmap_lock.
 */
void mmap_fastpath_refill_current_locked(guest_t *g, uint64_t request_len);

/* Give an explicit slow-path hint precedence over this stopped vCPU's
 * unconsumed arena tail. Caller holds mmap_lock.
 */
void mmap_fastpath_release_current_hint_locked(guest_t *g,
                                               uint64_t addr,
                                               uint64_t length);

/* Revoke all arenas while sibling vCPUs are quiesced. Caller holds mmap_lock.
 */
void mmap_fastpath_revoke_all_locked(guest_t *g, bool shrink_high_water);

/* Disable the feature before first guest entry (debugger/observability). */
void mmap_fastpath_disable(guest_t *g);

/* Advance *start past an EL1 arena reservation that overlaps length bytes. */
void mmap_fastpath_skip_reserved(const guest_t *g,
                                 uint64_t *start,
                                 uint64_t length,
                                 uint64_t align,
                                 uint64_t max_addr);
