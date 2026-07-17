/*
 * Per-vCPU EL1 anonymous-mmap consumer rings.
 *
 * The host produces arenas, consumes mmap/munmap publications, and returns
 * metadata-committed holes through a reverse SPSC ring. EL1 first-fit consumes
 * those private extents before bump-allocating fresh VA. Control blocks live
 * in the EL1-only shim-data mapping and are selected from SP_EL1's per-thread
 * stack slot, so no guest-visible register ABI is consumed.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#include "core/guest.h"

typedef struct thread_entry thread_entry_t;

#define SHIM_MMAP_CONTROL_BASE 0x20000u
#define SHIM_MMAP_CONTROL_STRIDE 0x1000u
#define SHIM_MMAP_RING_SIZE 32u
#define SHIM_MMAP_CTRL_ENABLED 0x1u
#define SHIM_MMAP_CTRL_TLBIRANGE 0x2u

/* Host page-table writers set this gate before changing an arena descriptor or
 * a stage-1 PTE.  Each EL1 producer announces itself in its private control
 * before rechecking the gate.  This is a writer-vs-per-vCPU-reader handshake,
 * not an allocator lock: fast munmap producers never write a shared cache
 * line or wait for one another.
 */
#define SHIM_MMAP_PT_GATE_OFF 0x1160u

#define SHIM_MUNMAP_RETIRE_RING_SIZE 32u
#define SHIM_MUNMAP_RETIRE_OFF 0x400u
#define SHIM_MUNMAP_RETIRE_BYTES_SOFT (256ULL * 1024 * 1024)
#define SHIM_MUNMAP_RETIRE_F_ARENA_SLOT_MASK 0x3fu
#define SHIM_MUNMAP_RETIRE_F_CHARGE_SHIFT 6u
#define SHIM_MUNMAP_RETIRE_F_CHARGE_MASK 0xffffffc0u

#define SHIM_MMAP_REUSE_RING_SIZE 32u
#define SHIM_MMAP_REUSE_OFF 0x720u

#define MMAP_FAST_ARENA_MIN (64ULL * 1024 * 1024)
#define MMAP_FAST_ARENA_MAX (32ULL * 1024 * 1024 * 1024)
#define MMAP_FAST_ARENA_TARGET_ENTRIES 32u

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

typedef struct munmap_retire_entry {
    uint64_t addr;
    uint64_t length;
    uint32_t arena_generation;
    uint32_t flags;
} munmap_retire_entry_t;

typedef struct munmap_retire_ring {
    _Atomic uint32_t head; /* host consumer */
    _Atomic uint32_t tail; /* EL1 producer */
    _Atomic uint64_t produced_bytes; /* EL1 producer, monotonic */
    _Atomic uint64_t consumed_bytes; /* host consumer, monotonic */
    _Atomic uint32_t producer_active;
    /* Advisory; never forces the producer to exit. */
    _Atomic uint32_t cleanup_requested;
    munmap_retire_entry_t entries[SHIM_MUNMAP_RETIRE_RING_SIZE];
} munmap_retire_ring_t;

typedef struct mmap_reuse_entry {
    uint64_t addr;
    uint64_t length;
} mmap_reuse_entry_t;

/* Host producer -> EL1 consumer.  Entries transfer committed, quarantined VA
 * extents back to their owning arena only after semantic metadata and PTE
 * retirement have completed.  EL1 may shorten an acquired entry in place;
 * the host does not touch its slot again until the release-published head has
 * advanced past it. */
typedef struct mmap_reuse_ring {
    _Atomic uint32_t head; /* EL1 consumer */
    _Atomic uint32_t tail; /* host producer */
    _Atomic uint64_t published;
    _Atomic uint64_t dropped;
    _Atomic uint64_t hits; /* EL1 producer */
    mmap_reuse_entry_t entries[SHIM_MMAP_REUSE_RING_SIZE];
} mmap_reuse_ring_t;

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
    uint64_t max_len_seen;    /* outgoing-generation maximum request length */
    shim_mmap_entry_t ring[SHIM_MMAP_RING_SIZE];
    _Atomic uint64_t counters[SHIM_MMAP_COUNTERS_N];
    uint64_t refill_count;
    uint64_t recycle_count;
    uint64_t peak_arena_size;
    _Atomic uint32_t materialized_generation;
    uint32_t _pad1;
    _Atomic uint64_t materialized_start;
    _Atomic uint64_t materialized_end;
    uint8_t _pad2[SHIM_MUNMAP_RETIRE_OFF - 0x3a0];
    munmap_retire_ring_t retire;
    mmap_reuse_ring_t reuse;
} shim_mmap_control_t;

_Static_assert(offsetof(shim_mmap_control_t, retire) == SHIM_MUNMAP_RETIRE_OFF,
               "shim.S retire-ring offset ABI");
_Static_assert(offsetof(shim_mmap_control_t, reuse) == SHIM_MMAP_REUSE_OFF,
               "shim.S reuse-ring offset ABI");
_Static_assert(sizeof(shim_mmap_control_t) <= SHIM_MMAP_CONTROL_STRIDE,
               "mmap control exceeds per-vCPU stride");

/* Called while initializing a vCPU, before it can enter guest code. */
void mmap_fastpath_prepare_vcpu(guest_t *g, thread_entry_t *t);

/* Drain every per-vCPU SPSC ring. Caller holds mmap_lock. */
void mmap_fastpath_drain_locked(guest_t *g);

/* Opportunistically drain publications and retirements at a natural VM exit.
 * Safe before every exit handler; it acquires mmap_lock internally.
 */
void mmap_fastpath_drain_vmexit(guest_t *g);

/* True when the stopped current vCPU was interrupted in the middle of its EL1
 * producer critical section.  A cancellation exit must resume it before host
 * drain can close the PT gate.
 */
bool mmap_fastpath_current_producer_active(const guest_t *g);

/* Mark every arena intersecting a successfully materialized lazy range. Caller
 * holds mmap_lock. EL1 may skip its PTE walk only while this marker differs
 * from the arena's current generation.
 */
void mmap_fastpath_note_materialized_locked(guest_t *g,
                                            uint64_t start,
                                            uint64_t end);

/* Refill the current vCPU after an eligible mmap slow-path. request_len is
 * page-rounded; requests above MMAP_FAST_ARENA_MAX leave the arena untouched.
 * Caller holds mmap_lock.
 */
void mmap_fastpath_refill_current_locked(guest_t *g, uint64_t request_len);

/* Fulfil an eligible mmap that reached HVC (capacity/ring/generation fallback)
 * directly from the current vCPU's refilled arena. Metadata is committed by
 * the host immediately, so no mmap publication entry is needed. Caller holds
 * mmap_lock.
 */
bool mmap_fastpath_allocate_current_locked(guest_t *g,
                                           uint64_t request_len,
                                           uint64_t *addr_out);
bool mmap_fastpath_allocate_current_publication_only(guest_t *g,
                                                      uint64_t request_len,
                                                      uint64_t *addr_out);

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
