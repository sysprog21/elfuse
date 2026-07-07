/*
 * EL1 shim globals -- host publisher.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * See core/shim-globals.h for the cache layout, threat model, and
 * memory-ordering rules. This file implements the host-side publish and
 * TPIDR_EL1 setup helpers. The shim assembly side is in src/core/shim.S.
 */

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>

#include "hvutil.h"
#include "core/guest.h"
#include "core/shim-globals.h"
#include "core/vdso.h"
#include "debug/log.h"
#include "runtime/thread.h"
#include "syscall/abi.h"
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
_Static_assert(SHIM_IDENTITY_OFF_PGID == 0x1148,
               "shim.S getpgid fast path hard-codes PGID off 0x1148");
_Static_assert(SHIM_IDENTITY_OFF_SID == 0x1150,
               "shim.S getsid fast path hard-codes SID off 0x1150");
_Static_assert(SHIM_GLOBALS_SIZE >= SHIM_IDENTITY_OFF_SID + 8,
               "SHIM_GLOBALS_SIZE must cover the PGID/SID slots");
_Static_assert(SHIM_GLOBALS_SIZE <= BLOCK_2MIB,
               "SHIM_GLOBALS_SIZE must fit inside the 2 MiB shim_data block");
_Static_assert(SHIM_COUNTERS_OFF + SHIM_COUNTERS_N * 8 <=
                   SHIM_IDENTITY_OFF_PGID,
               "counter array must not overlap the PGID slot");

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
    uint64_t *slot = (uint64_t *) (page + off);
    __atomic_store_n(slot, value, __ATOMIC_RELEASE);
}

static void urandom_ring_lock(uint32_t *lock_p)
{
    while (__atomic_exchange_n(lock_p, 1, __ATOMIC_ACQUIRE) != 0)
        sched_yield();
}

static void urandom_ring_unlock(uint32_t *lock_p)
{
    __atomic_store_n(lock_p, 0, __ATOMIC_RELEASE);
}

void shim_globals_init(guest_t *g)
{
    memset(cache_base(g), 0, SHIM_GLOBALS_SIZE);
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
    if (g != NULL && singleton_g != NULL && singleton_g != g) {
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

static uint64_t *urandom_bitmap_word(int fd)
{
    if (!singleton_g)
        return NULL;
    if (fd < 0 || fd >= FD_TABLE_SIZE)
        return NULL;
    uint8_t *base = cache_base(singleton_g) + SHIM_URANDOM_OFF_BITMAP;
    return (uint64_t *) base + (fd / 64);
}

void shim_globals_mark_urandom_fd(int fd, bool is_urandom)
{
    uint64_t *word = urandom_bitmap_word(fd);
    if (!word)
        return;
    uint64_t mask = (uint64_t) 1 << (fd & 63);
    if (is_urandom)
        __atomic_fetch_or(word, mask, __ATOMIC_RELEASE);
    else
        __atomic_fetch_and(word, ~mask, __ATOMIC_RELEASE);
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

/* arc4random_buf is documented as deadlock-free and re-entrant. Used by the
 * initial fill at bootstrap and by the slow-path refill that runs from
 * sys_read/sys_getrandom when the shim's fast path falls through due to an
 * empty ring.
 *
 * Entropy is generated OUTSIDE the ring_lock: arc4random_buf can take
 * microseconds, and any sibling vCPU that hits the fast path while the lock is
 * held spins (yield) until release. Generate up to a full ring into a stack
 * scratch buffer, then take the lock only to re-read head/fill and copy the
 * publishable prefix into the ring. The recheck after lock acquire matters: a
 * concurrent fast path may have advanced head while entropy was being
 * generated, raising the publishable count beyond the pre-lock estimate.
 */
void shim_globals_refill_urandom_ring(guest_t *g)
{
    uint8_t *base = cache_base(g);
    uint32_t *head_p = (uint32_t *) (base + SHIM_URANDOM_OFF_RING_HEAD);
    uint32_t *tail_p = (uint32_t *) (base + SHIM_URANDOM_OFF_RING_TAIL);
    uint32_t *lock_p = (uint32_t *) (base + SHIM_URANDOM_OFF_RING_LOCK);
    uint8_t *ring = base + SHIM_URANDOM_OFF_RING;

    /* Pre-lock estimate: skip the arc4random_buf + lock when the ring is
     * already full. Both cursors are read RELAXED so a torn snapshot (head_pre
     * observed past a producer step but tail_pre observed before it) can make
     * tail_pre - head_pre wrap to a huge unsigned value. A loose ">= RING_SIZE"
     * check would treat that garbage as "already full" and skip a
     * genuinely-needed refill. Only the exact == RING_SIZE value is a safe
     * full-detection; any other (valid or torn) reading falls through to the
     * lock-held recheck below.
     */
    uint32_t head_pre = __atomic_load_n(head_p, __ATOMIC_RELAXED);
    uint32_t tail_pre = __atomic_load_n(tail_p, __ATOMIC_RELAXED);
    uint32_t fill_pre = tail_pre - head_pre;
    if (fill_pre == SHIM_URANDOM_RING_SIZE)
        return;

    uint8_t scratch[SHIM_URANDOM_RING_SIZE];
    arc4random_buf(scratch, sizeof(scratch));

    urandom_ring_lock(lock_p);

    uint32_t head = __atomic_load_n(head_p, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(tail_p, __ATOMIC_RELAXED);
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
    __atomic_store_n(tail_p, tail + to_fill, __ATOMIC_RELEASE);

out:
    urandom_ring_unlock(lock_p);
}

/* Bitmask helpers. The slot lives at SHIM_GLOBALS_OFF_ATTN as a uint32;
 * ATTN_BIT_SIGTIMER and ATTN_BIT_CRED partition ownership so the signal/timer
 * lane and the cred-publish lane cannot clobber each other.
 */
void shim_globals_attn_or(guest_t *g, uint32_t bits)
{
    uint32_t *slot = (uint32_t *) (cache_base(g) + SHIM_GLOBALS_OFF_ATTN);
    /* SEQ_CST, not ACQ_REL. The CRED_BRACKETED invariant is the contrapositive
     * of release-acquire: if a sibling vCPU LDAR-loads attn and sees 0, that
     * sibling also does not yet observe any of the post-OR publish_creds
     * stores. Acquire-release only guarantees the forward direction (observing
     * the OR guarantees observing prior stores); the contrapositive needs a
     * total order across atomics, which on ARM64 SEQ_CST provides via DMB ISH.
     * The OR runs only on rare setuid/setgid/etc paths so the extra barrier is
     * not a hot-path cost. shim_globals_attn_and stays RELEASE because it runs
     * after publish_creds and only needs to order those prior stores before the
     * clear.
     */
    __atomic_fetch_or(slot, bits, __ATOMIC_SEQ_CST);
    vdso_attention_or(g, bits);
}

void shim_globals_attn_and(guest_t *g, uint32_t mask)
{
    uint32_t *slot = (uint32_t *) (cache_base(g) + SHIM_GLOBALS_OFF_ATTN);
    /* RELEASE is sufficient for the clear path: the bracket runs publish_creds
     * BEFORE this clear, and RELEASE here pairs with the shim's LDAR so any
     * sibling that observes the cleared bit also sees the published cred slots.
     */
    __atomic_fetch_and(slot, mask, __ATOMIC_RELEASE);
    vdso_attention_and(g, mask);
}

void shim_globals_raise_attention(guest_t *g)
{
    /* Signal/timer/exit-group lane. OR-only update so a concurrent cred
     * publish's ATTN_BIT_CRED stays set. The release-store pairs with the
     * shim's LDAR on the same address.
     */
    shim_globals_attn_or(g, ATTN_BIT_SIGTIMER);

    /* Kick any vCPU spinning in EL0 on the identity fast path. Without the
     * exit, the spinning vCPU never traps into EL1 and never reads the new
     * attention value, so a SIGALRM queued for it waits until its host-thread
     * timeslice ends. Reusing the existing signal-preemption helper (which
     * iterates the live vCPU set under thread_lock) avoids duplicating the
     * iteration logic; on a single-vCPU guest the loop is essentially a no-op.
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
    /* Slots 12..15 (SHIM_COUNTERS_N == 16) are intentionally unnamed; the dump
     * prints "(reserved)" so they appear in the output when non-zero, which
     * would flag an out-of-band increment. Bind a name here when a future EL1
     * service claims one of these slots.
     */
};

uint64_t shim_globals_counter_get(const guest_t *g, unsigned slot)
{
    if (slot >= SHIM_COUNTERS_N)
        return 0;
    const uint8_t *page = (const uint8_t *) g->host_base + g->shim_data_base;
    const uint64_t *slot_p =
        (const uint64_t *) (page + SHIM_COUNTERS_OFF) + slot;
    return __atomic_load_n(slot_p, __ATOMIC_RELAXED);
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
}

void shim_globals_counters_dump_json(FILE *out, const guest_t *g)
{
    fputc('{', out);
    bool first = true;
    for (unsigned i = 0; i < SHIM_COUNTERS_N; i++) {
        const char *name = counter_names[i];
        uint64_t v = shim_globals_counter_get(g, i);
        if (!name && v == 0)
            continue;
        char namebuf[32];
        if (!name) {
            snprintf(namebuf, sizeof(namebuf), "reserved%u", i);
            name = namebuf;
        }
        fprintf(out, "%s\"%s\":%llu", first ? "" : ",", name,
                (unsigned long long) v);
        first = false;
    }
    fputc('}', out);
}

static pthread_once_t stats_once = PTHREAD_ONCE_INIT;
static bool stats_enabled_cache;

static void stats_resolve(void)
{
    const char *v = getenv("ELFUSE_SHIM_STATS");
    const char *rv = getenv("ELFUSE_RUNTIME_STATS");
    stats_enabled_cache = (v && v[0] && strcmp(v, "0") != 0) ||
                          (rv && rv[0] && strcmp(rv, "0") != 0);
}

bool shim_globals_stats_enabled(void)
{
    pthread_once(&stats_once, stats_resolve);
    return stats_enabled_cache;
}

void shim_globals_publish_stats_gate(guest_t *g)
{
    uint8_t *slot = cache_base(g) + SHIM_GLOBALS_OFF_STATS_EN;
    uint8_t v = shim_globals_stats_enabled() ? 1 : 0;
    /* One-shot bring-up publish. Every caller (bootstrap, fork-child receive,
     * execve) runs before the guest vCPU starts executing, so the host-side
     * ordering between this store and the first hv_vcpu_run is what makes the
     * shim observe the published value; the release semantics here are
     * conservative, not load-bearing. A future runtime setter that mutates the
     * gate after guest entry would also need the shim side to upgrade its ldrb
     * to ldarb (or gate the read on the attention flag) -- a release-store
     * alone does not synchronize with a plain ldrb on the same address.
     */
    __atomic_store_n(slot, v, __ATOMIC_RELEASE);
}
