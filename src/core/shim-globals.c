/*
 * EL1 shim globals: host-side publisher
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * See core/shim-globals.h for the cache layout, threat model, and
 * memory-ordering rules. This file implements the host-side publish and
 * TPIDR_EL1 setup helpers. The shim assembly side is in src/core/shim.S.
 */

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <sched.h>

#include "hvutil.h"
#include "core/guest.h"
#include "core/mmap-fastpath.h"
#include "core/shim-globals.h"
#include "core/vdso.h"
#include "debug/log.h"
#include "runtime/thread.h"
#include "syscall/linux-wire.h"
#include "syscall/fd.h"
#include "syscall/internal.h"
#include "syscall/proc.h"
#include "syscall/signal.h"

#ifndef HV_SYS_REG_TPIDR_EL1
/* Older SDKs (e.g., the Nix-pinned apple-sdk-14.4) may lack the enumerator. The
 * encoding is stable: op0=3, op1=0, CRn=13, CRm=0, op2=4 -> 0xc684. Mirrors the
 * existing ACTLR_EL1 workaround in src/syscall/syscall.c.
 */
#define HV_SYS_REG_TPIDR_EL1 ((hv_sys_reg_t) 0xc684)
#endif

#ifndef HV_SYS_REG_CONTEXTIDR_EL1
/* op0=3, op1=0, CRn=13, CRm=0, op2=1 -> 0xc681. Same SDK-fallback pattern as
 * TPIDR_EL1.
 */
#define HV_SYS_REG_CONTEXTIDR_EL1 ((hv_sys_reg_t) 0xc681)
#endif

/* shim.S hard-codes these offsets and sizes in its urandom-read fast path; if
 * they drift here the shim reads from the wrong place. Catch the drift at
 * compile time.
 */
_Static_assert(SHIM_GLOBALS_OFF_STATS_EN == 0x04,
               "shim.S COUNTER_INC hard-codes STATS_EN byte off 0x04");
_Static_assert(SHIM_GLOBALS_OFF_STATS_EN >= 4 &&
                   SHIM_GLOBALS_OFF_STATS_EN < SHIM_IDENTITY_BASE,
               "STATS_EN byte must sit in the attention/identity padding");
_Static_assert(SHIM_URANDOM_OFF_BITMAP == 0x38,
               "shim.S urandom fast path hard-codes BITMAP off 0x38");
_Static_assert(SHIM_URANDOM_OFF_RING_HEAD == 0xB8,
               "shim.S urandom fast path hard-codes RING_HEAD off 0xB8");
_Static_assert(SHIM_URANDOM_OFF_RING_TAIL == 0xBC,
               "shim.S urandom fast path hard-codes RING_TAIL off 0xBC");
_Static_assert(SHIM_URANDOM_OFF_RING == 0xC0,
               "shim.S urandom fast path hard-codes RING off 0xC0");
_Static_assert(SHIM_URANDOM_RING_SIZE == 4096,
               "shim.S urandom fast path hard-codes RING_SIZE 4096");
_Static_assert(SHIM_URANDOM_OFF_RING_LOCK == 0x10C0,
               "shim.S urandom fast path hard-codes RING_LOCK off 0x10C0");
_Static_assert(FD_TABLE_SIZE == 1024,
               "shim.S urandom fast path hard-codes FD_TABLE_SIZE 1024");
_Static_assert(SHIM_URANDOM_INLINE_LIMIT == 256,
               "shim.S urandom/getrandom fast path hard-codes 256-byte cap");

/* shim.S COUNTER_INC macro hardcodes (SHIM_COUNTERS_OFF & 0xFFF) and the 0x1,
 * lsl #12 carry. Keep the literal in sync so a layout shift fails the build
 * rather than silently routing increments to the wrong slot.
 */
_Static_assert(SHIM_COUNTERS_OFF == 0x10C8,
               "shim.S COUNTER_INC hard-codes SHIM_COUNTERS_OFF=0x10C8");

/* shim.S splits SHIM_COUNTERS_OFF into a shifted-add carry (0x1000) plus an
 * imm12 load/store offset (0xC8 + slot byte). Pin the split so any future
 * layout shift fails the build instead of silently routing increments to the
 * wrong slot.
 */
_Static_assert((SHIM_COUNTERS_OFF & 0xFFF) == 0xC8,
               "shim.S SHIM_COUNTERS_OFF_LO12 hard-coded to 0xC8");
_Static_assert((SHIM_COUNTERS_OFF & ~0xFFF) == 0x1000,
               "shim.S SHIM_COUNTERS_OFF_HI hard-coded to 0x1000");
_Static_assert(SHIM_IDENTITY_OFF_PGID == 0x1178,
               "shim.S getpgid fast path hard-codes PGID off 0x1178");
_Static_assert(SHIM_IDENTITY_OFF_SID == 0x1180,
               "shim.S getsid fast path hard-codes SID off 0x1180");
_Static_assert(SHIM_FUTEX_WAITERS_OFF == 0x1188,
               "shim.S futex_wake_fast hard-codes the waiter array at 0x1188");
_Static_assert(SHIM_IDENTITY_OFF_SID + 8 <= SHIM_FUTEX_WAITERS_OFF,
               "waiter array must not overlap the SID slot");
_Static_assert(SHIM_GLOBALS_SIZE >= SHIM_IDENTITY_OFF_SID + 8,
               "SHIM_GLOBALS_SIZE must cover the PGID/SID slots");
_Static_assert(SHIM_GLOBALS_SIZE <= BLOCK_2MIB,
               "SHIM_GLOBALS_SIZE must fit inside the 2 MiB shim_data block");
_Static_assert(SHIM_COUNTERS_OFF + SHIM_COUNTERS_N * 8 <=
                   SHIM_IDENTITY_OFF_PGID,
               "counter array must not overlap the PGID slot");
_Static_assert(SHIM_MMAP_CONTROL_BASE == 0x20000,
               "shim.S mmap fast path hard-codes control base 0x20000");
_Static_assert(SHIM_MMAP_CONTROL_STRIDE == 0x800,
               "shim.S mmap fast path hard-codes control stride 0x800");
_Static_assert(SHIM_MMAP_RING_SIZE == 16,
               "shim.S mmap fast path hard-codes 16 ring entries");
_Static_assert(offsetof(shim_mmap_control_t, generation) == 0,
               "shim.S mmap generation offset drift");
_Static_assert(offsetof(shim_mmap_control_t, consumer_generation) == 4,
               "shim.S mmap consumer-generation offset drift");
_Static_assert(offsetof(shim_mmap_control_t, flags) == 8,
               "shim.S mmap flags offset drift");
_Static_assert(offsetof(shim_mmap_control_t, head) == 12,
               "shim.S mmap head offset drift");
_Static_assert(offsetof(shim_mmap_control_t, tail) == 16,
               "shim.S mmap tail offset drift");
_Static_assert(offsetof(shim_mmap_control_t, arena_base) == 24,
               "shim.S mmap arena-base offset drift");
_Static_assert(offsetof(shim_mmap_control_t, arena_limit) == 32,
               "shim.S mmap arena-limit offset drift");
_Static_assert(offsetof(shim_mmap_control_t, cursor) == 40,
               "shim.S mmap cursor offset drift");
_Static_assert(offsetof(shim_mmap_control_t, next_arena_size) == 48,
               "mmap next-arena-size offset drift");
_Static_assert(offsetof(shim_mmap_control_t, max_len_seen) == 56,
               "mmap max-len-seen offset drift");
_Static_assert(offsetof(shim_mmap_control_t, ring) == 64,
               "shim.S mmap ring offset drift");
_Static_assert(offsetof(shim_mmap_control_t, counters) == 0x1C0,
               "shim.S mmap counter offset drift");
_Static_assert(sizeof(shim_mmap_control_t) <= SHIM_MMAP_CONTROL_STRIDE,
               "per-vCPU mmap control exceeds its shim-data stride");
_Static_assert(SHIM_MMAP_CONTROL_BASE +
                       MAX_THREADS * SHIM_MMAP_CONTROL_STRIDE <=
                   BLOCK_2MIB - MAX_THREADS * 4096,
               "mmap controls overlap per-vCPU EL1 stacks");

static uint8_t *cache_base(const guest_t *g)
{
    /* The cache lives at the start of the shim_data block, which is mapped into
     * the host buffer at host_base + shim_data_base. Direct buffer access
     * bypasses the guest-page-table walk used by guest_ptr, which is
     * intentional: the host owns shim_data unconditionally.
     */
    return (uint8_t *) g->host_base + g->shim_data_base;
}

static void store_u64(uint8_t *page, uint32_t off, uint64_t value)
{
    _Atomic uint64_t *slot = (_Atomic uint64_t *) (page + off);
    atomic_store_explicit(slot, value, memory_order_release);
}

static void urandom_ring_lock(_Atomic uint32_t *lock_p)
{
    while (atomic_exchange_explicit(lock_p, 1, memory_order_acquire) != 0)
        sched_yield();
}

static void urandom_ring_unlock(_Atomic uint32_t *lock_p)
{
    atomic_store_explicit(lock_p, 0, memory_order_release);
}

void shim_globals_init(guest_t *g)
{
    /* mmap controls occupy a separate low shim-data range.  Init/exec/fork
     * child all call this while no sibling can execute, so clearing the whole
     * control array also prevents a recycled SP_EL1 slot from inheriting an
     * arena published to its previous owner.
     */
    memset(cache_base(g), 0,
           SHIM_MMAP_CONTROL_BASE + MAX_THREADS * SHIM_MMAP_CONTROL_STRIDE);
}

void shim_globals_publish_pid(guest_t *g, int64_t pid, int64_t ppid)
{
    uint8_t *page = cache_base(g);
    store_u64(page, SHIM_IDENTITY_OFF_PID, (uint64_t) pid);
    store_u64(page, SHIM_IDENTITY_OFF_PPID, (uint64_t) ppid);
}

void shim_globals_publish_creds(guest_t *g,
                                uint32_t uid,
                                uint32_t euid,
                                uint32_t gid,
                                uint32_t egid)
{
    uint8_t *page = cache_base(g);
    store_u64(page, SHIM_IDENTITY_OFF_UID, uid);
    store_u64(page, SHIM_IDENTITY_OFF_EUID, euid);
    store_u64(page, SHIM_IDENTITY_OFF_GID, gid);
    store_u64(page, SHIM_IDENTITY_OFF_EGID, egid);
}

void shim_globals_publish_pgsid(guest_t *g, int64_t pgid, int64_t sid)
{
    uint8_t *page = cache_base(g);
    store_u64(page, SHIM_IDENTITY_OFF_PGID, (uint64_t) pgid);
    store_u64(page, SHIM_IDENTITY_OFF_SID, (uint64_t) sid);
}

uint64_t shim_globals_gva(const guest_t *g)
{
    return g->shim_data_base;
}

int shim_globals_self_test(hv_vcpu_t vcpu)
{
    const uint64_t sentinel = 0xCAFEBABEDEADBEEFULL;
    hv_return_t r = hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL1, sentinel);
    if (r != HV_SUCCESS) {
        log_error("shim_globals: TPIDR_EL1 set failed (hv_return=0x%x)", r);
        return -1;
    }
    uint64_t probe = 0;
    r = hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL1, &probe);
    if (r != HV_SUCCESS) {
        log_error("shim_globals: TPIDR_EL1 get failed (hv_return=0x%x)", r);
        return -1;
    }
    if (probe != sentinel) {
        log_error(
            "shim_globals: TPIDR_EL1 round-trip mismatch: wrote 0x%llx, "
            "read 0x%llx",
            (unsigned long long) sentinel, (unsigned long long) probe);
        return -1;
    }
    return 0;
}

int shim_globals_install_tpidr(hv_vcpu_t vcpu, const guest_t *g)
{
    hv_return_t r =
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL1, shim_globals_gva(g));
    if (r != HV_SUCCESS) {
        log_error("shim_globals: install TPIDR_EL1 failed (hv_return=0x%x)", r);
        return -1;
    }
    return 0;
}

int shim_globals_install_tid(hv_vcpu_t vcpu, int64_t tid)
{
    hv_return_t r =
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CONTEXTIDR_EL1, (uint64_t) tid);
    if (r != HV_SUCCESS) {
        log_error(
            "shim_globals: install CONTEXTIDR_EL1 (tid=%lld) failed "
            "(hv_return=0x%x)",
            (long long) tid, r);
        return -1;
    }
    return 0;
}

int shim_globals_install_per_vcpu(hv_vcpu_t vcpu, const guest_t *g, int64_t tid)
{
    if (shim_globals_install_tpidr(vcpu, g) < 0)
        return -1;
    return shim_globals_install_tid(vcpu, tid);
}

/* Singleton guest pointer for the urandom-bitmap hooks called from the fd
 * table. elfuse runs one VM per process so a single global is correct; the
 * NULL-or-same-g assertion catches a lifecycle bug. Mirrors the pattern
 * signal.c uses for the attention-flag singleton.
 */
static guest_t *singleton_g;

void shim_globals_set_singleton(guest_t *g)
{
    if (g && singleton_g && singleton_g != g) {
        log_error(
            "shim_globals: singleton already registered to %p, "
            "refusing to re-register with %p",
            (void *) singleton_g, (void *) g);
        return;
    }
    singleton_g = g;
}

void shim_globals_reset_singleton(void)
{
    singleton_g = NULL;
}

static _Atomic uint64_t *urandom_bitmap_word(int fd)
{
    if (!singleton_g)
        return NULL;
    if (fd < 0 || fd >= FD_TABLE_SIZE)
        return NULL;
    uint8_t *base = cache_base(singleton_g) + SHIM_URANDOM_OFF_BITMAP;
    return (_Atomic uint64_t *) base + (fd / 64);
}

void shim_globals_mark_urandom_fd(int fd, bool is_urandom)
{
    _Atomic uint64_t *word = urandom_bitmap_word(fd);
    if (!word)
        return;
    uint64_t mask = (uint64_t) 1 << (fd & 63);
    if (is_urandom)
        atomic_fetch_or_explicit(word, mask, memory_order_release);
    else
        atomic_fetch_and_explicit(word, ~mask, memory_order_release);
}

void shim_globals_rebuild_urandom_bitmap(void)
{
    if (!singleton_g)
        return;

    /* Wipe the bitmap region first; concurrent fd_alloc / close from other
     * vCPUs is impossible during fork-child init (the child has not yet started
     * executing guest code), so a non-atomic memset is safe here.
     */
    memset(cache_base(singleton_g) + SHIM_URANDOM_OFF_BITMAP, 0,
           SHIM_URANDOM_BITMAP_BYTES);

    /* Walk the fd table; mark every readable FD_URANDOM slot. Reuses the
     * atomic-OR setter so the visible memory order matches the normal fd_alloc
     * path.
     */
    for (int fd = 0; fd < FD_TABLE_SIZE; fd++) {
        fd_refresh_urandom_bitmap(fd);
    }
}

/* Entropy is generated outside ring_lock, into a stack buffer, because
 * arc4random_buf can take microseconds and a sibling vCPU hitting the fast path
 * meanwhile spins on the lock. The lock is taken only to re-read head and copy
 * the publishable prefix in.
 *
 * The recheck under the lock is required, not defensive: a concurrent fast path
 * can advance head while entropy is being generated, which raises the
 * publishable count above the pre-lock estimate.
 */
void shim_globals_refill_urandom_ring(guest_t *g)
{
    uint8_t *base = cache_base(g);
    _Atomic uint32_t *head_p =
        (_Atomic uint32_t *) (base + SHIM_URANDOM_OFF_RING_HEAD);
    _Atomic uint32_t *tail_p =
        (_Atomic uint32_t *) (base + SHIM_URANDOM_OFF_RING_TAIL);
    _Atomic uint32_t *lock_p =
        (_Atomic uint32_t *) (base + SHIM_URANDOM_OFF_RING_LOCK);
    uint8_t *ring = base + SHIM_URANDOM_OFF_RING;

    /* Skip the generate-and-lock when the ring is already full. Both cursors
     * are read relaxed, so a torn snapshot can wrap tail_pre - head_pre to a
     * huge unsigned value; a ">=" test would read that as full and skip a
     * refill that was genuinely needed. Only an exact == RING_SIZE is safe, and
     * everything else falls through to the recheck under the lock.
     */
    uint32_t head_pre = atomic_load_explicit(head_p, memory_order_relaxed);
    uint32_t tail_pre = atomic_load_explicit(tail_p, memory_order_relaxed);
    uint32_t fill_pre = tail_pre - head_pre;
    if (fill_pre == SHIM_URANDOM_RING_SIZE)
        return;

    uint8_t scratch[SHIM_URANDOM_RING_SIZE];
    arc4random_buf(scratch, sizeof(scratch));

    urandom_ring_lock(lock_p);

    uint32_t head = atomic_load_explicit(head_p, memory_order_acquire);
    uint32_t tail = atomic_load_explicit(tail_p, memory_order_relaxed);
    uint32_t fill = tail - head;
    if (fill >= SHIM_URANDOM_RING_SIZE)
        goto out; /* concurrent refill caught up */
    uint32_t to_fill = SHIM_URANDOM_RING_SIZE - fill;

    /* Producer writes from ring[tail & (SIZE-1)] forward, wrapping once when
     * needed. Two memcpys at most.
     */
    uint32_t pos = tail & (SHIM_URANDOM_RING_SIZE - 1);
    uint32_t first = SHIM_URANDOM_RING_SIZE - pos;
    if (first > to_fill)
        first = to_fill;
    memcpy(ring + pos, scratch, first);
    if (to_fill > first)
        memcpy(ring, scratch + first, to_fill - first);

    /* Release-store the new tail so any fast-path consumer that loads tail with
     * an acquiring read sees the bytes already in the ring.
     */
    atomic_store_explicit(tail_p, tail + to_fill, memory_order_release);

out:
    urandom_ring_unlock(lock_p);
}

/* Bitmask helpers. The slot lives at SHIM_GLOBALS_OFF_ATTN as a uint32;
 * ATTN_BIT_SIGTIMER and ATTN_BIT_CRED partition ownership so the signal/timer
 * lane and the cred-publish lane cannot clobber each other.
 */
void shim_globals_attn_or(guest_t *g, uint32_t bits)
{
    _Atomic uint32_t *slot =
        (_Atomic uint32_t *) (cache_base(g) + SHIM_GLOBALS_OFF_ATTN);

    /* SEQ_CST rather than ACQ_REL. CRED_BRACKETED needs the contrapositive of
     * release-acquire: a sibling that LDAR-loads attn and sees 0 must also not
     * yet observe any post-OR publish_creds store. Acquire-release gives only
     * the forward direction; the contrapositive needs a total order across
     * atomics, which SEQ_CST supplies on ARM64 via DMB ISH. This runs on the
     * setuid family only, so the barrier is not on a hot path.
     *
     * attn_and stays RELEASE: it runs after publish_creds and only has to keep
     * those stores ahead of the clear.
     */
    atomic_fetch_or_explicit(slot, bits, memory_order_seq_cst);
    vdso_attention_or(g, bits);
}

void shim_globals_attn_and(guest_t *g, uint32_t mask)
{
    _Atomic uint32_t *slot =
        (_Atomic uint32_t *) (cache_base(g) + SHIM_GLOBALS_OFF_ATTN);

    /* RELEASE is sufficient for the clear path: the bracket runs publish_creds
     * BEFORE this clear, and RELEASE here pairs with the shim's LDAR so any
     * sibling that observes the cleared bit also sees the published cred slots.
     */
    atomic_fetch_and_explicit(slot, mask, memory_order_release);
    vdso_attention_and(g, mask);
}

void shim_globals_ptrace_attention(guest_t *g, bool owed)
{
    /* OR to raise, AND to drop, so the signal and cred lanes are untouched
     * either way. The raise has to be visible before the kick that follows it,
     * which is the same ordering shim_globals_raise_attention documents; the
     * drop only ever costs a spurious HVC, so RELEASE is enough.
     */
    if (owed)
        shim_globals_attn_or(g, ATTN_BIT_PTRACE);
    else
        shim_globals_attn_and(g, ~ATTN_BIT_PTRACE);
}

void shim_globals_raise_attention(guest_t *g)
{
    /* Signal/timer/exit-group lane. OR-only update so a concurrent cred
     * publish's ATTN_BIT_CRED stays set. The release-store pairs with the
     * shim's LDAR on the same address.
     */
    shim_globals_attn_or(g, ATTN_BIT_SIGTIMER);

    /* Kick every sibling vCPU. One spinning on an EL1 fast path never traps, so
     * it never reads the new attention value and a SIGALRM queued for it would
     * wait out its host timeslice. This reuses the signal-preemption helper,
     * which already walks the live vCPU set under thread_lock.
     */
    thread_interrupt_all();
}

void shim_globals_recompute_attention(guest_t *g)
{
    /* Only owns the SIGTIMER lane; CRED and TRACE stay untouched so a
     * concurrent setuid/setgid bracket or persistent verbose-tracing gate
     * cannot be undone by the HVC #5 epilogue dropping signal attention. Set or
     * clear ATTN_BIT_SIGTIMER atomically.
     */
    bool need = proc_exit_group_requested() || signal_attention_needed();
    if (need)
        shim_globals_attn_or(g, ATTN_BIT_SIGTIMER);
    else
        shim_globals_attn_and(g, ~ATTN_BIT_SIGTIMER);
}

void shim_globals_set_trace_enabled(guest_t *g, bool enabled)
{
    if (enabled)
        shim_globals_attn_or(g, ATTN_BIT_TRACE);
    else
        shim_globals_attn_and(g, ~ATTN_BIT_TRACE);
}

/* The shim hardcodes each counter's byte offset as a CB_* .equ; these pin those
 * literals to the slot indices below. Without them the two drift silently, and
 * a wrong offset writes into a neighbouring counter rather than failing to
 * build. Every CB_* in core/shim.S is listed, not just the futex ones: a
 * partial list reads as though the offsets are pinned when most are not.
 */
_Static_assert(SHIM_COUNTER_ATTN_BAIL * 8 == 0, "CB_ATTN_BAIL");
_Static_assert(SHIM_COUNTER_URANDOM_FD_OOR * 8 == 8, "CB_URANDOM_FD_OOR");
_Static_assert(SHIM_COUNTER_URANDOM_FD_BMISS * 8 == 16, "CB_URANDOM_FD_BMISS");
_Static_assert(SHIM_COUNTER_URANDOM_LEN_ZERO * 8 == 24, "CB_URANDOM_LEN_ZERO");
_Static_assert(SHIM_COUNTER_URANDOM_LEN_OVER * 8 == 32, "CB_URANDOM_LEN_OVER");
_Static_assert(SHIM_COUNTER_URANDOM_RING_LOW * 8 == 40, "CB_URANDOM_RING_LOW");
_Static_assert(SHIM_COUNTER_URANDOM_PROBE_FAIL * 8 == 56,
               "CB_URANDOM_PROBE_FAIL");
_Static_assert(SHIM_COUNTER_IDENTITY_HIT * 8 == 64, "CB_IDENTITY_HIT");
_Static_assert(SHIM_COUNTER_URANDOM_HIT * 8 == 72, "CB_URANDOM_HIT");
_Static_assert(SHIM_COUNTER_GETRANDOM_HIT * 8 == 80, "CB_GETRANDOM_HIT");
_Static_assert(SHIM_COUNTER_PGSID_HIT * 8 == 88, "CB_PGSID_HIT");
_Static_assert(SHIM_COUNTER_FUTEX_EAGAIN_HIT * 8 == 96, "CB_FUTEX_EAGAIN_HIT");
_Static_assert(SHIM_COUNTER_FUTEX_EFAULT_HIT * 8 == 104, "CB_FUTEX_EFAULT_HIT");
_Static_assert(SHIM_COUNTER_FUTEX_SHAPE_BAIL * 8 == 112, "CB_FUTEX_SHAPE_BAIL");
_Static_assert(SHIM_COUNTER_FUTEX_MATCH_BAIL * 8 == 120, "CB_FUTEX_MATCH_BAIL");
_Static_assert(SHIM_COUNTER_FUTEX_WAKE_HIT * 8 == 128, "CB_FUTEX_WAKE_HIT");
_Static_assert(SHIM_COUNTER_FUTEX_WAKE_WAITER_BAIL * 8 == 136,
               "CB_FUTEX_WAKE_WAITER_BAIL");

static const char *const counter_names[SHIM_COUNTERS_N] = {
    [SHIM_COUNTER_ATTN_BAIL] = "ATTN_BAIL",
    [SHIM_COUNTER_URANDOM_FD_OOR] = "URANDOM_FD_OOR",
    [SHIM_COUNTER_URANDOM_FD_BMISS] = "URANDOM_FD_BMISS",
    [SHIM_COUNTER_URANDOM_LEN_ZERO] = "URANDOM_LEN_ZERO",
    [SHIM_COUNTER_URANDOM_LEN_OVER] = "URANDOM_LEN_OVER",
    [SHIM_COUNTER_URANDOM_RING_LOW] = "URANDOM_RING_LOW",
    [SHIM_COUNTER_URANDOM_RING_WRAP] = "URANDOM_RING_WRAP",
    [SHIM_COUNTER_URANDOM_PROBE_FAIL] = "URANDOM_PROBE_FAIL",
    [SHIM_COUNTER_IDENTITY_HIT] = "IDENTITY_HIT",
    [SHIM_COUNTER_URANDOM_HIT] = "URANDOM_HIT",
    [SHIM_COUNTER_GETRANDOM_HIT] = "GETRANDOM_HIT",
    [SHIM_COUNTER_PGSID_HIT] = "PGSID_HIT",
    [SHIM_COUNTER_FUTEX_EAGAIN_HIT] = "FUTEX_EAGAIN_HIT",
    [SHIM_COUNTER_FUTEX_EFAULT_HIT] = "FUTEX_EFAULT_HIT",
    [SHIM_COUNTER_FUTEX_SHAPE_BAIL] = "FUTEX_SHAPE_BAIL",
    [SHIM_COUNTER_FUTEX_MATCH_BAIL] = "FUTEX_MATCH_BAIL",
    [SHIM_COUNTER_FUTEX_WAKE_HIT] = "FUTEX_WAKE_HIT",
    [SHIM_COUNTER_FUTEX_WAKE_WAITER_BAIL] = "FUTEX_WAKE_WAITER_BAIL",
    [SHIM_COUNTER_FAULT_MATERIALIZE] = "FAULT_MATERIALIZE",
    [SHIM_COUNTER_FAULT_TLBI_VAE] = "FAULT_TLBI_VAE",
    [SHIM_COUNTER_FAULT_TLBI_RVAE] = "FAULT_TLBI_RVAE",
    [SHIM_COUNTER_FAULT_TLBI_BCAST] = "FAULT_TLBI_BCAST",
};

uint64_t shim_globals_counter_get(const guest_t *g, unsigned slot)
{
    if (slot >= SHIM_COUNTERS_N)
        return 0;
    const uint8_t *page = (const uint8_t *) g->host_base + g->shim_data_base;
    const _Atomic uint64_t *slot_p =
        (const _Atomic uint64_t *) (page + SHIM_COUNTERS_OFF) + slot;
    return atomic_load_explicit(slot_p, memory_order_relaxed);
}

void shim_globals_counter_inc(guest_t *g, unsigned slot)
{
    if (!shim_globals_stats_enabled() || slot >= SHIM_COUNTERS_N)
        return;
    uint8_t *page = (uint8_t *) g->host_base + g->shim_data_base;
    _Atomic uint64_t *slot_p =
        (_Atomic uint64_t *) (page + SHIM_COUNTERS_OFF) + slot;
    atomic_fetch_add_explicit(slot_p, 1, memory_order_relaxed);
}

void shim_globals_counters_dump(const guest_t *g)
{
    fprintf(stderr, "shim-stats (pid=%lld)\n", (long long) proc_get_pid());
    for (unsigned i = 0; i < SHIM_COUNTERS_N; i++) {
        const char *name = counter_names[i];
        uint64_t v = shim_globals_counter_get(g, i);
        if (!name && v == 0)
            continue;
        fprintf(stderr, "  %-20s %llu\n", name ? name : "(reserved)",
                (unsigned long long) v);
    }

    static const char *const mmap_counter_names[SHIM_MMAP_COUNTERS_N] = {
        [SHIM_MMAP_COUNTER_SHAPE_MISS] = "MMAP_SHAPE_MISS",
        [SHIM_MMAP_COUNTER_CAPACITY_MISS] = "MMAP_CAPACITY_MISS",
        [SHIM_MMAP_COUNTER_RING_FULL] = "MMAP_RING_FULL",
        [SHIM_MMAP_COUNTER_GENERATION_STALE] = "MMAP_GENERATION_STALE",
        [SHIM_MMAP_COUNTER_ATTENTION] = "MMAP_ATTENTION",
        [SHIM_MMAP_COUNTER_HIT] = "MMAP_HIT",
    };
    uint64_t mmap_counters[SHIM_MMAP_COUNTERS_N] = {0};
    uint64_t refill_count = 0, recycle_count = 0;
    uint64_t current_max = 0, peak_max = 0;
    const uint8_t *shim_data =
        (const uint8_t *) g->host_base + g->shim_data_base;
    for (int slot = 0; slot < MAX_THREADS; slot++) {
        const shim_mmap_control_t *c =
            (const shim_mmap_control_t *) (shim_data + SHIM_MMAP_CONTROL_BASE +
                                           (uint64_t) slot *
                                               SHIM_MMAP_CONTROL_STRIDE);
        for (unsigned i = 0; i < SHIM_MMAP_COUNTERS_N; i++)
            mmap_counters[i] +=
                atomic_load_explicit(&c->counters[i], memory_order_relaxed);
        refill_count += c->refill_count;
        recycle_count += c->recycle_count;
        if (c->next_arena_size > current_max)
            current_max = c->next_arena_size;
        if (c->peak_arena_size > peak_max)
            peak_max = c->peak_arena_size;
    }
    for (unsigned i = 0; i < SHIM_MMAP_COUNTERS_N; i++)
        fprintf(stderr, "  %-20s %llu\n", mmap_counter_names[i],
                (unsigned long long) mmap_counters[i]);
    fprintf(stderr, "  %-20s %llu\n", "MMAP_REFILL",
            (unsigned long long) refill_count);
    fprintf(stderr, "  %-20s %llu\n", "MMAP_RECYCLE",
            (unsigned long long) recycle_count);
    fprintf(stderr, "  %-20s %llu\n", "MMAP_ARENA_CURRENT",
            (unsigned long long) current_max);
    fprintf(stderr, "  %-20s %llu\n", "MMAP_ARENA_PEAK",
            (unsigned long long) peak_max);
    uint64_t high_water =
        g->mmap_next > MMAP_BASE ? g->mmap_next - MMAP_BASE : 0;
    fprintf(stderr, "  %-20s %llu\n", "MMAP_HIGH_WATER",
            (unsigned long long) high_water);
    fprintf(stderr, "  %-20s %llu\n", "FAULT_CLEAN_SKIP",
            (unsigned long long)
                g->materialize_stats[GUEST_MATERIALIZE_CLEAN_SKIP]);
    fprintf(stderr, "  %-20s %llu\n", "FAULT_DIRTY_MEMSET",
            (unsigned long long)
                g->materialize_stats[GUEST_MATERIALIZE_DIRTY_MEMSET]);
    fprintf(stderr, "  %-20s %llu\n", "FAULT_ALREADY_VALID",
            (unsigned long long)
                g->materialize_stats[GUEST_MATERIALIZE_ALREADY_VALID]);
    fprintf(stderr, "  %-20s %llu\n", "FAULT_WINDOW_BYTES",
            (unsigned long long)
                g->materialize_stats[GUEST_MATERIALIZE_WINDOW_BYTES]);
}

static pthread_once_t stats_once = PTHREAD_ONCE_INIT;
static bool stats_enabled_cache;

static void stats_resolve(void)
{
    const char *v = getenv("ELFUSE_SHIM_STATS");
    stats_enabled_cache = v && v[0] && strcmp(v, "0") != 0;
}

bool shim_globals_stats_enabled(void)
{
    pthread_once(&stats_once, stats_resolve);
    return stats_enabled_cache;
}

uint32_t shim_globals_futex_waiters_get(const guest_t *g, unsigned bucket)
{
    if (!g || bucket >= SHIM_FUTEX_BUCKETS)
        return 0;
    return atomic_load_explicit(
        (_Atomic uint32_t *) (cache_base(g) + SHIM_FUTEX_WAITERS_OFF +
                              bucket * 4u),
        memory_order_seq_cst);
}

void shim_globals_futex_waiters_add(guest_t *g, unsigned bucket, int delta)
{
    if (!g || bucket >= SHIM_FUTEX_BUCKETS)
        return;

    _Atomic uint32_t *slot =
        (_Atomic uint32_t *) (cache_base(g) + SHIM_FUTEX_WAITERS_OFF +
                              bucket * 4u);

    /* seq_cst, not relaxed or acq_rel. The waiter's increment has to be ordered
     * against its own later read of the futex word, and the shim's read of this
     * count against the guest's earlier store to that word: the store-buffer
     * shape, where each side stores one location and loads the other. Only a
     * total order over both makes "count reads zero" imply "the waiter will see
     * the store". This runs once per blocking wait, which already costs a park.
     *
     * One add rather than a branch on the sign: a negative delta is added as
     * its two's complement, which is the subtraction. The branch form applied
     * one whatever the magnitude, so a caller charging two buckets at once
     * would have been under-applied here, and an under-applied increment is the
     * one direction the shim reads as "nobody parked".
     */
    atomic_fetch_add_explicit(slot, (uint32_t) delta, memory_order_seq_cst);
}

void shim_globals_publish_stats_gate(guest_t *g)
{
    _Atomic uint8_t *slot =
        (_Atomic uint8_t *) (cache_base(g) + SHIM_GLOBALS_OFF_STATS_EN);
    uint8_t v = shim_globals_stats_enabled() ? 1 : 0;

    /* One-shot bring-up publish: every caller (bootstrap, fork-child receive,
     * execve) runs before the vCPU executes, so what the shim observes is
     * ordered by the first hv_vcpu_run and the release here is conservative
     * rather than load-bearing.
     *
     * A setter that mutated the gate after guest entry would not be enough on
     * its own: a release-store does not synchronize with the shim's plain ldrb,
     * so that side would have to become ldarb or move behind attention.
     */
    atomic_store_explicit(slot, v, memory_order_release);
}
