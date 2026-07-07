/*
 * EL1 shim globals (identity cache + attention flag)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A small struct of host-published values that the EL1 shim consumes to serve
 * identity syscalls (getpid 172, getppid 173, getuid 174, geteuid 175, getgid
 * 176, getegid 177) without an HVC round-trip.
 *
 * The cache lives at the start of the shim_data block (high IPA, inside the
 * infra reserve). Three layered protections keep guest EL0 code from MAP_FIXED
 * / MREMAP / MADVISE-spoofing the cache:
 *
 *   - sys_mmap MAP_FIXED rejects ranges hitting infra
 *   - sys_munmap and sys_mprotect reject infra ranges
 *   - sys_mremap (all variants) and sys_madvise reject infra ranges
 *
 * Direct EL0 store to the cache GVA is defended: the shim_data block is mapped
 * AP[2:1]=00 (RW at EL1, no EL0 access), so a guest EL0 dereference of the
 * cache base faults to the SIGSEGV path rather than spoofing values.
 * gva_translate_perm refuses MEM_PERM_EL1_ONLY descriptors on EL0-behalf walks,
 * and the EL1 shim retains full RW. /proc/self/maps still lists [shim-data] but
 * reports it PROT_NONE (region tracking is independent of EL0 access), so the
 * layout is disclosed without granting a usable mapping. The elfuse threat
 * model treats the guest as the user's own binary, not adversarial; this
 * mapping closes the direct-write spoofing gap as defense in depth.
 *
 * The shim addresses the cache via TPIDR_EL1, which the host sets at every vCPU
 * init point (bootstrap, fork-child, CLONE_THREAD, exec re-init). TPIDR_EL1 is
 * unused by elfuse aside from this and is not trapped under default HCR_EL2
 * settings at EL1.
 *
 * Memory ordering: each publish uses __ATOMIC_RELEASE. The shim reads the
 * attention flag with LDAR (acquire) to pair with the release. Identity slot
 * reads stay plain LDR -- each is independent and naturally-aligned 64-bit
 * loads are single-copy atomic on AArch64.
 */

#pragma once

#include <stdio.h>

#include <stdbool.h>
#include <stdint.h>

#include "core/guest.h"

/* Layout within shim_data_base (offsets are bytes from the cache base which
 * equals shim_data_base; the shim's TPIDR_EL1 holds exactly this address).
 *
 * Attention flag sits at offset 0 so the shim's LDAR (which only supports a
 * register base with no immediate offset) can load it via 'ldar w_, [x12]'
 * where x12 = mrs tpidr_el1. Identity slots follow 8-byte-aligned, with PID at
 * offset 0x08; the shim adds 8 to the base and then indexes by (X8 - 172) * 8
 * to land on the requested slot. Attention=0 takes the fast path; nonzero
 * forces HVC.
 *
 * Slice A ships attention as always-zero (the setter API exists but is only
 * called from cred publish in Slice B). The fast path is gated already so Slice
 * B can wire signal_queue / setitimer / exit- group setters without further
 * shim changes.
 */
#define SHIM_GLOBALS_OFF_ATTN 0x00

/* Stats gate: single byte at offset 0x04 (inside the natural 4-byte pad between
 * the uint32 attention flag and the 8-byte-aligned identity slots at 0x08).
 * Nonzero enables the COUNTER_INC body in the EL1 shim; zero (the default)
 * makes COUNTER_INC a single ldrb + cbz so disabled stats cost one cache-hot
 * byte load instead of the full load-add-store-to-shared-counter-line that was
 * paid on every fast path before. The byte lives in the same 64-byte cache line
 * as the attention flag, so the gate load piggybacks on the line the shim's
 * LDAR already pulls into L1 -- no extra coherence traffic in the common case.
 *
 * Plain release-store on publish: the gate is read once per fast-path tail with
 * relaxed semantics, and we accept a window after env-var resolution where an
 * in-flight syscall still sees the old value.
 */
#define SHIM_GLOBALS_OFF_STATS_EN 0x04

/* Attention is a bitmask, not a boolean. Splitting it by owner lets the HVC #5
 * epilogue's recompute (which polls signal/itimer state) coexist with the
 * cred-publish bracket without clobbering it. The shim still does a single cbnz
 * on the whole word: any bit set forces the slow path. Bit ownership keeps
 * recompute and cred bracket independent.
 *
 *   ATTN_BIT_SIGTIMER   owned by signal_queue / setitimer / exit_group
 *                       and signal_check_timer's recompute. Set when
 *                       a signal is pending or an itimer is armed.
 *   ATTN_BIT_CRED       owned by CRED_BRACKETED in setuid/setgid
 *                       wrappers. Set across the four-slot publish
 *                       window so concurrent shim readers fall back
 *                       to HVC and see _Atomic-coherent host values.
 *   ATTN_BIT_TRACE      owned by --verbose syscall tracing. Set for the
 *                       lifetime of a verbose run so EL1 shim fast paths
 *                       fall back to HVC and syscall_dispatch can log them.
 *
 * Earlier revisions used a single boolean: a sibling vCPU's recompute dropping
 * it to zero mid-publish reopened the torn-cred window the bracket was meant to
 * close.
 */
#define ATTN_BIT_SIGTIMER 0x00000001u
#define ATTN_BIT_CRED 0x00000002u
#define ATTN_BIT_TRACE 0x00000004u

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
 * The bitmap is bit N == 1 iff guest fd N currently refers to an
 * FD_URANDOM-typed entry. The shim's read fast path consults this before
 * serving from the ring; any other fd type falls through to HVC. Host maintains
 * the bitmap from fd_alloc / fd_mark_closed.
 *
 * Ring head/tail are byte counters that grow monotonically (uint32); fill =
 * tail - head (uint32 subtract) is the available byte count, pos = head &
 * (URANDOM_RING_SIZE - 1) is the index in the ring. Both cursors are atomic.
 * The shim advances head via LDXR/STXR; the host advances tail via
 * release-store after writing fresh entropy. The producer and shim consumer
 * also take RING_LOCK while touching the ring so the host cannot overwrite a
 * slice after the shim reserves it but before the EL1 copy has loaded it.
 *
 * Size must be a power of two so the index mask is AND of (SIZE - 1).
 */
#define SHIM_URANDOM_OFF_BITMAP 0x0038
#define SHIM_URANDOM_BITMAP_BYTES 128
#define SHIM_URANDOM_OFF_RING_HEAD 0x00B8
#define SHIM_URANDOM_OFF_RING_TAIL 0x00BC
#define SHIM_URANDOM_OFF_RING 0x00C0
#define SHIM_URANDOM_RING_SIZE 4096
#define SHIM_URANDOM_OFF_RING_LOCK 0x10C0

/* Upper bound on the per-call byte count served by the shim's urandom/getrandom
 * fast paths. The probe coverage assumes the buffer spans at most two host
 * pages so a first+last byte AT probe suffices; 256 fits comfortably within
 * both 4 KiB and 16 KiB page sizes. The shim itself hardcodes the literal; a
 * static_assert in shim-globals.c pins the C macro to the assembly. Ring wraps
 * are handled inline by splitting the byte copy at the 4 KiB boundary, so this
 * cap is bounded only by probe coverage and per-call ring-fill cost (256 keeps
 * the 4 KiB ring serviceable for 16 sequential reads before host refill).
 */
#define SHIM_URANDOM_INLINE_LIMIT 256

/* Fast-path hit / miss counters.
 *
 * 16 uint64 slots placed after the urandom ring lock. The shim's
 * identity_class_fast and urandom_read_fast paths bump the relevant slot on
 * every entry and at every bail point so the host can attribute fast-path
 * activity instead of guessing. Counters are non-atomic plain load-add-store --
 * under multi-vCPU concurrent bails a small fraction of increments race and are
 * lost, which is acceptable for diagnostic ratios. Slots 0..7 cover the eight
 * bail reasons the shim distinguishes (sticky attention, fd out of range, fd
 * not in urandom bitmap, len zero, len over inline cap, ring fill below
 * request, ring wrap, EL0 buffer probe failure). Slots 8..11 record fast-path
 * hits so bail rates can be computed against a hit denominator. Slots 12..15
 * are reserved.
 *
 * The shim hardcodes the byte offset of each slot; the static_asserts in
 * shim-globals.c keep the C-side macros and the assembly in sync.
 */
#define SHIM_COUNTERS_OFF 0x10C8
#define SHIM_COUNTERS_N 16

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

/* Extended identity slots: pgid and sid.
 *
 * getpgid(0) and getsid(0) are pure cache reads when the argument is zero; the
 * shim serves them out of these slots whenever X0 == 0 and the syscall number
 * matches. The host re-publishes after setpgid / setsid / exec / fork so the
 * slots match guest_pgid / guest_sid in proc-identity.c.
 */
#define SHIM_IDENTITY_OFF_PGID 0x1148
#define SHIM_IDENTITY_OFF_SID 0x1150

#define SHIM_GLOBALS_SIZE 0x1158

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

/* Publish all four credential slots. Slot writes are independent 64-bit atomic
 * stores; concurrent shim reads on another vCPU may see partial updates. Slice
 * B's attention bracket eliminates that race; until then, callers must accept
 * that a concurrent getuid+geteuid sequence on a different vCPU can witness a
 * torn cred set across a setresuid moment. Linux semantics require an atomic
 * cred swap; bracket via attention closes that gap.
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

/* Pre-flight validation that hv_vcpu_set_sys_reg + hv_vcpu_get_sys_reg
 * round-trip on TPIDR_EL1. Writes a sentinel and reads it back via the same HVF
 * accessors the bootstrap uses; aborts (log_error + -1) on mismatch. ARM
 * documents TPIDR_EL1 as ordinary EL1 thread/CPU pointer storage with no HCR
 * trap on the EL1-side MRS/MSR.
 *
 * Note: this test runs BEFORE the first hv_vcpu_run; it does not verify that
 * HVF preserves the register across vCPU run/exit boundaries. The existing
 * test-shim-identity microbench is the end-to-end check for that property -- if
 * HVF clobbered TPIDR_EL1, every identity-class fast path would observe a stale
 * base and test-shim-identity would fail on the first iteration after
 * remap_vdso_page.
 *
 * Returns 0 on success, -1 on failure.
 */
int shim_globals_self_test(hv_vcpu_t vcpu);

/* Install TPIDR_EL1 = shim_globals_gva(g) on a vCPU. Called from the four vCPU
 * init sites listed in the file header.
 */
int shim_globals_install_tpidr(hv_vcpu_t vcpu, const guest_t *g);

/* Install CONTEXTIDR_EL1 = tid for the gettid shim fast path. The register is
 * per-vCPU and unused elsewhere in elfuse (HVF preserves it across hv_vcpu_run
 * alongside the rest of EL1 state). The shim answers SVC #0 with X8 == 178
 * (gettid) by emitting a single 'mrs x0, CONTEXTIDR_EL1' and an 'eret',
 * skipping the HVC #5 round-trip the same way the identity slot loads do for
 * syscalls 172-177. Caller passes the Linux tid; it is zero/sign-extended into
 * the 64-bit sysreg slot.
 *
 * Setup sites:
 *   bootstrap.c                  initial main thread (tid == pid)
 *   forkipc.c fork-child main    tid == child pid
 *   forkipc.c CLONE_THREAD       tid == thread's allocated guest_tid
 *   forkipc.c CLONE_VM           tid == child's guest_tid
 *
 * sys_execve reuses the vCPU and the main thread's tid does not change across
 * exec, so no re-set is required there.
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

/* Attention flag setters (Slice B).
 *
 * The shim's identity fast path reads the attention flag with LDAR before doing
 * anything else. When nonzero, the shim falls back to HVC #5 so the host's
 * post-syscall epilogue can deliver any pending signal or itimer expiry.
 *
 * shim_globals_raise_attention sets the flag to 1 atomically (release) and also
 * issues hv_vcpus_exit on every sibling vCPU so any vCPU already spinning in
 * EL0 drops out of hv_vcpu_run and re-checks the flag on the next entry.
 * Without the exit, a tight identity loop on one vCPU could ignore an attention
 * raise on another vCPU until its timeslice ended.
 *
 * shim_globals_recompute_attention re-derives the flag from (signal_pending OR
 * any guest_itimer active OR exit_group requested). Called from the HVC #5
 * epilogue after signal_check_timer to drop the flag back to zero whenever the
 * slow-path workload has drained.
 *
 * The g pointer in both is necessary because the cache is per-guest. Slice B's
 * signal.c hooks call these via a singleton guest pointer registered at process
 * init (see signal_set_shim_globals_guest in src/syscall/signal.h).
 */
void shim_globals_raise_attention(guest_t *g);
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
 * The fd-type bitmap is updated by the fd table whenever an FD_URANDOM slot
 * opens or closes (including dup, fork-IPC restore, etc.). The shim's
 * read-fast-path consults the bitmap with a single 64-bit load and a bit test
 * to decide whether the requested fd should hit the urandom ring or fall
 * through to HVC.
 *
 * Updates use atomic OR/AND on the affected 64-bit word so concurrent dup races
 * (sibling vCPU dup'ing into a freshly-opened slot) cannot lose either bit.
 * Storing as uint64 rather than per-bit-CAS keeps the host hook trivial.
 *
 * shim_globals_set_singleton publishes the live guest_t * so the fd-table hooks
 * can update the bitmap without threading g through every fd_alloc /
 * fd_mark_closed call site. Same NULL-or-same lifecycle assertion as the
 * signal.c singleton. Call from bootstrap (initial) and fork-child (after
 * guest_init).
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

/* Refill the entropy ring with fresh CSPRNG bytes from arc4random_buf. Called
 * from the host's sys_read slow path when a FD_URANDOM read encounters an empty
 * (or low-water) ring. The fill always brings tail up to head +
 * URANDOM_RING_SIZE so the ring is full after refill.
 *
 * The initial fill is NOT done by shim_globals_init (which only zeros the
 * cache). Every bring-up path that uses the urandom fast path must call this
 * explicitly after shim_globals_init: bootstrap.c does it during VM bring-up,
 * src/syscall/exec.c does it on execve, and src/runtime/forkipc.c does it on
 * the fork-child receive path. Any future init site that forgets this call
 * leaves the ring empty, so the first urandom read on that vCPU is forced
 * through the host SVC.
 */
void shim_globals_refill_urandom_ring(guest_t *g);

/* Counter access for diagnostics. shim_globals_counter_get returns the
 * cumulative slot value (lossy under multi-vCPU bail contention; see the
 * comment block on SHIM_COUNTERS_OFF). slot must be in [0, SHIM_COUNTERS_N).
 * shim_globals_counters_dump writes a one-line-per-slot summary to out with the
 * SHIM_COUNTER_* names and current values; intended for use at process exit
 * when ELFUSE_SHIM_STATS is set.
 */
uint64_t shim_globals_counter_get(const guest_t *g, unsigned slot);
void shim_globals_counters_dump(const guest_t *g);
void shim_globals_counters_dump_json(FILE *out, const guest_t *g);

/* ELFUSE_SHIM_STATS env-var gate (idempotent / cached). When enabled the exit
 * path dumps the counter table to stderr so a single bench run attributes every
 * fast-path bail without rebuilds. Mirrors the ELFUSE_STARTUP_TRACE pattern in
 * core/startup-trace.h.
 */
bool shim_globals_stats_enabled(void);

/* Publish the stats gate byte at SHIM_GLOBALS_OFF_STATS_EN based on
 * shim_globals_stats_enabled(). The EL1 shim's COUNTER_INC loads this byte and
 * skips the counter increment when zero, so an unset ELFUSE_SHIM_STATS pays
 * only a single cache-hot ldrb on each fast-path tail instead of a full
 * load-add-store on a shared counter line. Call after every shim_globals_init:
 * bootstrap, fork-child receive, and execve. The byte stays zero on a fresh
 * shim_globals_init unless this publisher runs.
 */
void shim_globals_publish_stats_gate(guest_t *g);
