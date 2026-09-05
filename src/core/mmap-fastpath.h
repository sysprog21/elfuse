/*
 * Per-vCPU EL1 anonymous-mmap consumer rings.
 *
 * The host produces arenas, consumes mmap/munmap publications, and returns
 * metadata-committed holes through a reverse SPSC ring. EL1 first-fit consumes
 * those private extents before bump-allocating fresh VA. Control blocks live in
 * the EL1-only shim-data mapping and are selected from SP_EL1's per-thread
 * stack slot, so no guest-visible register ABI is consumed.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#include "core/guest.h"
#include "proved/mmap-fastpath.h"

typedef struct thread_entry thread_entry_t;

#define SHIM_MMAP_CONTROL_BASE 0x20000u
#define SHIM_MMAP_CONTROL_STRIDE 0x1000u
#define SHIM_MMAP_RING_SIZE 32u
#define SHIM_MMAP_CTRL_ENABLED 0x1u
#define SHIM_MMAP_CTRL_TLBIRANGE 0x2u

/* Host page-table writers set this gate before changing an arena descriptor or
 * a stage-1 PTE. Each EL1 producer announces itself in its private control
 * before rechecking the gate. This is a writer-vs-per-vCPU-reader handshake,
 * not an allocator lock: fast munmap producers never write a shared cache line
 * or wait for one another.
 */
#define SHIM_MMAP_PT_GATE_OFF 0x2188u

#define SHIM_MUNMAP_RETIRE_RING_SIZE 32u
#define SHIM_MUNMAP_RETIRE_OFF 0x400u
#define SHIM_MUNMAP_RETIRE_BYTES_SOFT (256ULL * 1024 * 1024)
#define SHIM_MUNMAP_RETIRE_F_ARENA_SLOT_MASK 0x3fu
#define SHIM_MUNMAP_RETIRE_F_CHARGE_SHIFT 6u
#define SHIM_MUNMAP_RETIRE_F_CHARGE_MASK 0xffffffc0u

/* MMAP_FAST_ARENA_MIN/MAX/TARGET_ENTRIES and MMAP_FAST_PUBLICATION_WINDOW are
 * defined in proved/mmap-fastpath.h, included above: that header's sizing
 * arithmetic is proved against those exact values, so this is the one
 * definition rather than a copy a proof cannot see drift from.
 *
 * MMAP_FAST_PUBLICATION_WINDOW must stay a power of two: the sequence counter
 * indexes the window by masking.
 */

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
    /* Monotonic accounting of conservative materialized-byte upper bounds. */
    _Atomic uint64_t produced_bytes; /* EL1 producer */
    _Atomic uint64_t consumed_bytes; /* host consumer */
    _Atomic uint32_t producer_active;
    /* Advisory; never forces the producer to exit. */
    _Atomic uint32_t cleanup_requested;
    munmap_retire_entry_t entries[SHIM_MUNMAP_RETIRE_RING_SIZE];
} munmap_retire_ring_t;


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
    uint64_t publication_seq; /* host-only: registrations, rotates the window */
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

    /* Host-only refill policy history; see MMAP_FAST_PUBLICATION_WINDOW. Kept
     * past the rings so adding it moves no offset the EL1 side depends on.
     */
    uint64_t publication_window[MMAP_FAST_PUBLICATION_WINDOW];

    /* EL1-incremented, host-read: how many munmap() calls found the retirement
     * ring near full (see el1_munmap's near-full check) and fell back to a
     * synchronous host trap instead of publishing into the ring. Placed past
     * every fixed EL1 ABI offset, like publication_window above.
     */
    _Atomic uint64_t munmap_retire_near_full;

    /* EL1 sets this after publishing mmap or munmap work. The host uses it only
     * to avoid an empty opportunistic VM-exit drain; lock-taking paths still
     * drain unconditionally.
     */
    _Atomic uint32_t pending_work;

    /* EL1 consumes before publishing; host replenishes while this producer is
     * stopped, either in HVC or behind the closed gate. metadata_reserved
     * includes credits and undrained publications and is owned by the host
     * under mmap_lock.
     */
    _Atomic uint32_t metadata_credits;
    uint32_t metadata_reserved;
} shim_mmap_control_t;

_Static_assert(offsetof(shim_mmap_control_t, retire) == SHIM_MUNMAP_RETIRE_OFF,
               "EL1 retire-ring offset ABI");
_Static_assert(sizeof(shim_mmap_control_t) <= SHIM_MMAP_CONTROL_STRIDE,
               "mmap control exceeds per-vCPU stride");

/* Provision the main vCPU before guest entry. Worker vCPUs provision lazily on
 * their first eligible mmap so short-lived threads do not allocate an unused
 * arena.
 */
void mmap_fastpath_prepare_vcpu(guest_t *g, thread_entry_t *t);

/* Drain every per-vCPU SPSC ring. Caller holds mmap_lock. */
void mmap_fastpath_drain_locked(guest_t *g);

/* Opportunistically drain publications and retirements at a natural VM exit.
 * Safe before every exit handler; it acquires mmap_lock internally. When a
 * fork-family syscall is pending, skip the arena top-up that the syscall will
 * immediately revoke.
 */
void mmap_fastpath_drain_vmexit(guest_t *g, bool fork_family_pending);

/* True when the stopped current vCPU was interrupted in the middle of its EL1
 * producer critical section. A cancellation exit must resume it before host
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
 * directly from the current vCPU's refilled arena. Metadata is committed by the
 * host immediately, so no mmap publication entry is needed. Caller holds
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
