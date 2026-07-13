/*
 * EL1 shim globals: the host-published cache the EL1 fast paths read
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-published values the EL1 shim serves without an HVC round trip: identity
 * (getpid 172 through getegid 177, gettid, getpgid/getsid), an entropy ring for
 * /dev/urandom, and a futex fast path.
 *
 * The cache sits at the start of the shim_data block, inside the infra reserve,
 * addressed through TPIDR_EL1. The host installs that register at every vCPU
 * init site (bootstrap, fork-child, CLONE_THREAD, exec re-init); nothing else
 * in elfuse uses it, and EL1 MRS/MSR of it is untrapped.
 *
 * Guest EL0 cannot reach the cache. The block is MEM_PERM_RW_EL1_ONLY
 * (AP[2:1]=00), so an EL0 dereference faults, and gva_translate_perm refuses
 * EL1-only descriptors on EL0-behalf walks. Remapping it away is refused by
 * sys_mmap MAP_FIXED, munmap, mprotect, mremap and madvise, all of which reject
 * infra ranges. /proc/self/maps discloses the span as PROT_NONE.
 *
 * Ordering: publishes are release-stores; the shim's attention read is LDAR.
 * Identity slots are read with plain LDR, which is sufficient because each is
 * independent and a naturally-aligned 64-bit load is single-copy atomic on
 * AArch64.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "core/guest.h"

/* Offsets are bytes from the cache base, which equals shim_data_base and is
 * what TPIDR_EL1 holds.
 *
 * Attention sits at offset 0 because LDAR takes a register base with no
 * immediate offset, so the shim loads it as 'ldar w_, [x12]' straight off
 * TPIDR_EL1. Zero takes the fast path, any bit set forces HVC. Identity slots
 * follow 8-byte aligned from 0x08, indexed by (X8 - 172) * 8.
 */
#define SHIM_GLOBALS_OFF_ATTN 0x00

/* Stats gate, one byte in the pad between attention and the identity slots.
 * Nonzero enables the COUNTER_INC body; zero reduces it to ldrb + cbz. It
 * shares attention's cache line, so the gate load rides the line the shim's
 * LDAR already pulled in. Published with a plain release-store, which leaves a
 * window after env-var resolution where an in-flight syscall reads the old
 * value; that costs a counter, not correctness.
 */
#define SHIM_GLOBALS_OFF_STATS_EN 0x04

/* Attention is a bitmask rather than a boolean, one bit per owner. The shim
 * still tests the whole word with one cbnz: any bit set forces the slow path. A
 * single boolean did not work, because the HVC #5 epilogue's recompute could
 * drop it to zero mid-publish and reopen the torn-cred window the bracket
 * exists to close.
 *
 *   ATTN_BIT_SIGTIMER  signal_queue, setitimer, exit_group, and
 *                      signal_check_timer's recompute. Set while a signal is
 *                      pending or an itimer is armed.
 *   ATTN_BIT_CRED      CRED_BRACKETED in the setuid/setgid wrappers. Set
 *                      across the four-slot publish so a concurrent reader
 *                      takes HVC instead of a half-updated cred set.
 *   ATTN_BIT_TRACE     --verbose. Set for the run so fast paths bail and
 *                      syscall_dispatch can log them.
 *   ATTN_BIT_PTRACE    A PTRACE_INTERRUPT owes some thread a stop. Set so an
 *                      EL1 fast path takes HVC instead of ERETing to EL0,
 *                      where nothing would trap again until the guest's next
 *                      syscall and the tracer would wait on it. Cleared when a
 *                      stop is taken; process-wide, so with two traced threads
 *                      one clear can drop the hint early, which costs the other
 *                      thread nothing it did not already have (its own kick
 *                      still stands).
 */
#define ATTN_BIT_SIGTIMER 0x00000001u
#define ATTN_BIT_CRED 0x00000002u
#define ATTN_BIT_TRACE 0x00000004u
#define ATTN_BIT_PTRACE 0x00000008u

#define SHIM_IDENTITY_BASE 0x08
#define SHIM_IDENTITY_OFF_PID 0x08
#define SHIM_IDENTITY_OFF_PPID 0x10
#define SHIM_IDENTITY_OFF_UID 0x18
#define SHIM_IDENTITY_OFF_EUID 0x20
#define SHIM_IDENTITY_OFF_GID 0x28
#define SHIM_IDENTITY_OFF_EGID 0x30

/* Urandom fast path: closes the /dev/urandom 1B read band at the HVF round-trip
 * floor.
 *
 * Layout (continues from the identity section):
 *   0x38 .. 0xB7   URANDOM_FD_BITMAP   128 bytes = 1024 bits = FD_TABLE_SIZE
 *   0xB8 .. 0xBB   URANDOM_RING_HEAD   uint32, consumer cursor (atomic)
 *   0xBC .. 0xBF   URANDOM_RING_TAIL   uint32, producer cursor (host-only)
 *   0xC0 .. 0x10BF URANDOM_RING        4096-byte CSPRNG ring
 *   0x10C0..0x10C3 URANDOM_RING_LOCK   uint32, producer/consumer lock
 *
 * Bitmap bit N is set iff guest fd N is an FD_URANDOM entry; the shim checks it
 * before serving, and every other fd type falls through to HVC. The host
 * maintains it from fd_alloc and fd_mark_closed.
 *
 * Head and tail are monotonically growing byte counters, so fill is the uint32
 * difference tail - head and the ring index is head & (SIZE - 1), which
 * requires SIZE to be a power of two. The shim advances head with LDXR/STXR,
 * the host advances tail with a release-store after writing entropy. Both also
 * hold RING_LOCK across the ring itself, so the host cannot overwrite a slice
 * between the shim reserving it and the EL1 copy reading it.
 */
#define SHIM_URANDOM_OFF_BITMAP 0x0038
#define SHIM_URANDOM_BITMAP_BYTES 128
#define SHIM_URANDOM_OFF_RING_HEAD 0x00B8
#define SHIM_URANDOM_OFF_RING_TAIL 0x00BC
#define SHIM_URANDOM_OFF_RING 0x00C0
#define SHIM_URANDOM_RING_SIZE 4096
#define SHIM_URANDOM_OFF_RING_LOCK 0x10C0

/* Per-call cap on the urandom and getrandom fast paths. The bound comes from
 * probe coverage: the shim AT-probes only the first and last byte, which is
 * sound only while the buffer spans at most two host pages, and 256 fits that
 * under both 4 KiB and 16 KiB pages. Ring wrap is handled by splitting the
 * copy, so nothing else constrains the value. The shim hardcodes the literal; a
 * static_assert in shim-globals.c pins this macro to it.
 */
#define SHIM_URANDOM_INLINE_LIMIT 256

/* Fast-path hit / miss counters.
 *
 * 22 uint64 slots after the ring lock, bumped by identity_class_fast,
 * urandom_read_fast, futex_wait_fast and futex_wake_fast at every hit and bail
 * so fast-path activity can be attributed rather than guessed. Slots 0-7 are
 * bail reasons, 8-11 identity and urandom hits, 12-13 futex wait hits, 14-15
 * futex wait bails, 16-17 the futex wake path's hit and its one bail, and
 * 18-21 lazy-fault materializations and the TLBI wire mode they emit.
 *
 * Increments are plain load-add-store, so concurrent bails on separate vCPUs
 * lose a few. These are diagnostic ratios, not accounting.
 *
 * The futex shape bail is counted before the attention load, so a SYS_futex the
 * fast path never serves (a wake, a requeue, a timed wait) lands there whether
 * or not attention was raised, and ATTN_BAIL counts only what attention
 * diverted from an otherwise servable shape. See futex_wait_fast in
 * core/shim.S.
 *
 * The shim hardcodes each slot's byte offset; static_asserts in shim-globals.c
 * keep the two in sync.
 */
#define SHIM_COUNTERS_OFF 0x10C8
#define SHIM_COUNTERS_N 22

#define SHIM_COUNTER_ATTN_BAIL 0
#define SHIM_COUNTER_URANDOM_FD_OOR 1
#define SHIM_COUNTER_URANDOM_FD_BMISS 2
#define SHIM_COUNTER_URANDOM_LEN_ZERO 3
#define SHIM_COUNTER_URANDOM_LEN_OVER 4
#define SHIM_COUNTER_URANDOM_RING_LOW 5
#define SHIM_COUNTER_URANDOM_RING_WRAP 6
#define SHIM_COUNTER_URANDOM_PROBE_FAIL 7
#define SHIM_COUNTER_IDENTITY_HIT 8
#define SHIM_COUNTER_URANDOM_HIT 9
#define SHIM_COUNTER_GETRANDOM_HIT 10
#define SHIM_COUNTER_PGSID_HIT 11
#define SHIM_COUNTER_FUTEX_EAGAIN_HIT 12
#define SHIM_COUNTER_FUTEX_EFAULT_HIT 13
#define SHIM_COUNTER_FUTEX_SHAPE_BAIL 14
#define SHIM_COUNTER_FUTEX_MATCH_BAIL 15
#define SHIM_COUNTER_FUTEX_WAKE_HIT 16
#define SHIM_COUNTER_FUTEX_WAKE_WAITER_BAIL 17
#define SHIM_COUNTER_FAULT_MATERIALIZE 18
#define SHIM_COUNTER_FAULT_TLBI_VAE 19
#define SHIM_COUNTER_FAULT_TLBI_RVAE 20
#define SHIM_COUNTER_FAULT_TLBI_BCAST 21

/* Extended identity slots: pgid and sid.
 *
 * getpgid(0) and getsid(0) are pure cache reads when the argument is zero; the
 * shim serves them out of these slots whenever X0 == 0 and the syscall number
 * matches. The host re-publishes after setpgid / setsid / exec / fork so the
 * slots match guest_pgid / guest_sid in proc-identity.c.
 */
#define SHIM_IDENTITY_OFF_PGID 0x1178
#define SHIM_IDENTITY_OFF_SID 0x1180

/* Per-bucket futex waiter counts, one uint32 per hash bucket of the table in
 * runtime/futex.c. The shim's wake fast path reads one of these to answer a
 * FUTEX_WAKE that has nobody to wake: a zero count for the bucket a uaddr
 * hashes to proves no waiter is parked on that address, and the syscall's whole
 * result is then 0.
 *
 * A count rather than the one-bit-per-slot the urandom bitmap uses, because
 * waiters nest: two threads on one bucket must not let the first to leave clear
 * a bit the second still needs. Making the published word the count itself also
 * removes the set/clear race a separate bit would have.
 *
 * Ordering is what makes this safe, and it is the store-buffer pattern. A
 * waiter publishes its increment before it reads the futex word; the shim
 * issues DMB ISH after the guest's store to that word and before reading the
 * count. If the shim then reads zero, any waiter that exists must load the word
 * after that read, so it sees the store and returns EAGAIN rather than parking.
 * A stale-high count costs one wasted HVC; a stale-low one would lose a wakeup,
 * which is why neither side may weaken.
 *
 * The shim recomputes the bucket index in assembly, so both the multiplier and
 * the table size are pinned by static asserts in runtime/futex.c.
 */
#define SHIM_FUTEX_BUCKETS 1024u
#define SHIM_FUTEX_WAITERS_OFF 0x1188
#define SHIM_FUTEX_WAITERS_BYTES (SHIM_FUTEX_BUCKETS * 4u)

#define SHIM_GLOBALS_SIZE (SHIM_FUTEX_WAITERS_OFF + SHIM_FUTEX_WAITERS_BYTES)

/* Initialize the cache region to all-zero. Called once per process at the same
 * time the shim_data block is set up (initial bootstrap and fork-child). The
 * initial attention=0 means the shim takes the fast path until a setter raises
 * it.
 */
void shim_globals_init(guest_t *g);

/* Publish pid + ppid pair atomically (release-store per slot). Called at
 * process init, after fork-child identity is installed, and after any future
 * PID/PPID mutation. pid and ppid are int64 to match
 * proc_get_pid/proc_get_ppid; values are stored zero/sign-extended.
 */
void shim_globals_publish_pid(guest_t *g, int64_t pid, int64_t ppid);

/* Publish all four credential slots. The writes are independent 64-bit stores,
 * so this alone would let a sibling vCPU witness a half-updated cred set where
 * Linux requires an atomic swap. Callers must publish inside the ATTN_BIT_CRED
 * bracket, which forces concurrent readers to HVC for the duration;
 * CRED_BRACKETED in src/syscall/syscall.c is that bracket, and
 * src/syscall/exec.c open-codes it.
 */
void shim_globals_publish_creds(guest_t *g,
                                uint32_t uid,
                                uint32_t euid,
                                uint32_t gid,
                                uint32_t egid);

/* Publish pgid + sid so the shim's getpgid(0) / getsid(0) inline service sees
 * the current session/process-group state. Call from process init, fork-child
 * receive, exec, setsid, and setpgid. Slot writes are independent 64-bit atomic
 * release stores.
 *
 * No attention bit guards this publish: setpgid / setsid are infrequent and the
 * model accepts a brief window in which a concurrent getpgid(0) / getsid(0) on
 * a sibling vCPU observes the pre-publish value (consistent with Linux's
 * lockless session lookups). Session mutators and cache-initialization callers
 * publish through proc-identity while holding session_lock, so successful
 * setpgid / setsid calls cannot overwrite the cache out of order.
 */
void shim_globals_publish_pgsid(guest_t *g, int64_t pgid, int64_t sid);

/* GVA of the cache base. Equal to g->shim_data_base. Exposed so the TPIDR_EL1
 * setup site and tests can reference one source of truth.
 */
uint64_t shim_globals_gva(const guest_t *g);

/* Write a sentinel to TPIDR_EL1 and read it back through the same HVF accessors
 * bootstrap uses, to catch a broken round trip before it becomes a stale cache
 * base.
 *
 * Returns 0, or -1 after log_error on mismatch.
 *
 * This runs before the first hv_vcpu_run, so it says nothing about whether HVF
 * preserves the register across run/exit. test-shim-identity is the end-to-end
 * check for that: a clobbered TPIDR_EL1 makes every identity fast path read a
 * stale base and fails it on the first iteration.
 */
int shim_globals_self_test(hv_vcpu_t vcpu);

/* Install TPIDR_EL1 = shim_globals_gva(g) on a vCPU. Called from the four vCPU
 * init sites listed in the file header.
 */
int shim_globals_install_tpidr(hv_vcpu_t vcpu, const guest_t *g);

/* Install CONTEXTIDR_EL1 = tid, which is where the gettid fast path reads from:
 * the shim answers SVC #0 with X8 == 178 as one mrs plus an eret. The register
 * is per-vCPU, preserved by HVF across hv_vcpu_run, and unused elsewhere in
 * elfuse, which is why the tid can live there.
 *
 * Set at each vCPU init site: bootstrap for the main thread (tid == pid), and
 * forkipc for the fork child, CLONE_THREAD and CLONE_VM. sys_execve reuses the
 * vCPU and does not change the tid, so it does not re-set this.
 */
int shim_globals_install_tid(hv_vcpu_t vcpu, int64_t tid);

/* Combined install: TPIDR_EL1 = shim_globals base, CONTEXTIDR_EL1 = tid. Used
 * by every vCPU init site (bootstrap, fork-child main, CLONE_THREAD worker,
 * CLONE_VM child).
 *
 * Returns 0 on success, -1 on either failure. sys_execve uses install_tpidr
 * alone because the tid is unchanged across exec.
 */
int shim_globals_install_per_vcpu(hv_vcpu_t vcpu,
                                  const guest_t *g,
                                  int64_t tid);

/* The SIGTIMER lane of the attention word. The shim reads attention with LDAR
 * before anything else and takes HVC #5 when it is nonzero, so the host's
 * epilogue can deliver a pending signal or itimer expiry.
 *
 * raise_attention ORs in ATTN_BIT_SIGTIMER, leaving the other lanes alone, and
 * then interrupts every sibling vCPU. The interrupt is what makes the raise
 * visible promptly: a vCPU spinning on an EL1 fast path never traps, so without
 * it the raise waits for that thread's timeslice to end.
 *
 * recompute_attention re-derives the same bit from signal_pending, any armed
 * guest itimer, and exit_group, and is called from the HVC #5 epilogue after
 * signal_check_timer to clear it once that work has drained.
 *
 * Both take g because the cache is per-guest; signal.c reaches them through the
 * singleton registered at process init (signal_set_shim_globals_guest).
 */
void shim_globals_raise_attention(guest_t *g);

/* Raise or drop the ptrace lane. Separate from the signal lane's
 * raise/recompute pair because the thread consuming the stop drops it.
 */
void shim_globals_ptrace_attention(guest_t *g, bool owed);
void shim_globals_recompute_attention(guest_t *g);
void shim_globals_set_trace_enabled(guest_t *g, bool enabled);

/* OR / AND specific attention bits without disturbing the others. Used by the
 * CRED_BRACKETED macro to set ATTN_BIT_CRED before mutating host credentials
 * and clear it after publish. signal_queue and the itimer setters take the
 * ATTN_BIT_SIGTIMER lane via raise_attention and recompute_attention; --verbose
 * owns ATTN_BIT_TRACE. The lanes do not collide.
 */
void shim_globals_attn_or(guest_t *g, uint32_t bits);
void shim_globals_attn_and(guest_t *g, uint32_t mask);

/* Urandom bitmap maintenance.
 *
 * The fd table updates the bitmap whenever an FD_URANDOM slot opens or closes,
 * dup and fork-IPC restore included; the shim reads it with one 64-bit load and
 * a bit test to decide ring or HVC. Updates are atomic OR/AND on the affected
 * word, so a sibling vCPU dup'ing into a freshly opened slot cannot lose either
 * bit.
 *
 * set_singleton publishes the live guest_t * so the fd-table hooks need not
 * thread g through every fd_alloc and fd_mark_closed. Called from bootstrap and
 * from fork-child after guest_init, with the same NULL-or-same lifecycle
 * assertion as the signal.c singleton.
 */
void shim_globals_set_singleton(guest_t *g);

/* Reset the singleton to NULL. Called from syscall_init() at process start so a
 * stale parent-process pointer cannot survive across a posix_spawn fork-child
 * re-init and silently drop bitmap updates. Mirrors signal_init()'s
 * attention_guest=NULL reset.
 */
void shim_globals_reset_singleton(void);

void shim_globals_mark_urandom_fd(int fd, bool is_urandom);

/* Rebuild the urandom bitmap from the current fd table state. Used by the
 * fork-child path: the inherited fd table holds the parent's FD_URANDOM slots
 * but the child just zeroed its shim-globals via shim_globals_init, so the
 * bitmap must be re-populated to reflect what the child actually has open.
 * Acquires fd_lock internally.
 */
void shim_globals_rebuild_urandom_bitmap(void);

/* Refill the ring from arc4random_buf, bringing tail up to head + RING_SIZE.
 * Called from the sys_read slow path when an FD_URANDOM read finds the ring
 * empty or low.
 *
 * shim_globals_init only zeros the cache, so every bring-up path that wants the
 * fast path must call this after it: bootstrap during VM bring-up, exec.c on
 * execve, forkipc.c on the fork-child receive. An init site that forgets leaves
 * the ring empty and forces the first urandom read through HVC.
 */
void shim_globals_refill_urandom_ring(guest_t *g);

/* Diagnostics. counter_get returns one slot, which must be in [0,
 * SHIM_COUNTERS_N) and is lossy under concurrent bails (see SHIM_COUNTERS_OFF).
 * counters_dump writes the whole table by name, for process exit under
 * ELFUSE_SHIM_STATS.
 */
uint64_t shim_globals_counter_get(const guest_t *g, unsigned slot);
void shim_globals_counter_inc(guest_t *g, unsigned slot);
void shim_globals_counters_dump(const guest_t *g);

/* ELFUSE_SHIM_STATS env-var gate (idempotent / cached). When enabled the exit
 * path dumps the counter table to stderr so a single bench run attributes every
 * fast-path bail without rebuilds. Mirrors the ELFUSE_STARTUP_TRACE pattern in
 * core/startup-trace.h.
 */
bool shim_globals_stats_enabled(void);

/* Publish the stats gate byte from shim_globals_stats_enabled(). Call after
 * every shim_globals_init (bootstrap, fork-child receive, execve): init zeros
 * the byte, and only this restores it, so an init site that skips this leaves
 * counters silently off.
 */
void shim_globals_publish_stats_gate(guest_t *g);

/* Adjust the published waiter count for one futex bucket. delta is +1 on entry
 * to a wait and -1 on the way out, seq_cst both ways: the increment has to be
 * ordered against the waiter's own read of the futex word, which is what lets
 * the shim treat a zero count as proof that nobody is parked.
 *
 * A NULL guest answers rather than faulting, so a caller does not have to test
 * for one. That is the only case handled: a non-NULL guest whose slab is not
 * mapped yet is not, and no wait path can reach here before bring-up, since
 * they all run on behalf of a guest thread that is already executing.
 */
void shim_globals_futex_waiters_add(guest_t *g, unsigned bucket, int delta);
uint32_t shim_globals_futex_waiters_get(const guest_t *g, unsigned bucket);
