/*
 * Dynamic-linker startup / steady-state syscall histogram
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "debug/syscall-hist.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "syscall/abi.h"
#include "dispatch.h"

/* The dispatch table size is fixed in syscall.c. Mirror the literal here
 * instead of pulling syscall.c internals; SC_MAX_SYSCALL_NUM lives in
 * dispatch.h and a static assert below catches any future growth.
 */
#define HIST_TABLE_SIZE 512

#if (SC_MAX_SYSCALL_NUM + 1) > HIST_TABLE_SIZE
#error "HIST_TABLE_SIZE must exceed SC_MAX_SYSCALL_NUM"
#endif

/* Tri-state lifecycle. OFF is the default; RECORD is set by the env-var
 * resolver once it sees "syscalls" or "all"; FROZEN is set when the first
 * execve commits so steady-state traffic does not pollute startup data. Stored
 * as atomic because syscall_hist_enabled is on every dispatch path and
 * syscall_hist_freeze runs on a single vCPU while others may still be
 * recording.
 */
enum {
    HIST_OFF = 0,
    HIST_RECORD = 1,
    HIST_FROZEN = 2,
};
static _Atomic int hist_mode = HIST_OFF;
static bool hist_steady;

/* Resolved once via pthread_once. The resolver is idempotent so multiple
 * dispatch contexts converge on the same answer without locking.
 */
static pthread_once_t hist_init_once = PTHREAD_ONCE_INIT;

/* Reason string survives until the dump runs. Set under the freeze path;
 * read-only afterwards. Atomic store keeps readers from observing a torn
 * pointer when freeze races with dump from a different thread (rare but
 * possible if exit_group fires while another vCPU is mid-syscall).
 */
static const char *_Atomic hist_freeze_reason = NULL;

/* Captured at the first record so the dump can report elapsed wall time even
 * when no execve fires. Set atomically; readers only consult after mode
 * transitions to FROZEN or the process is winding down.
 */
static _Atomic uint64_t hist_first_ns = 0;

/* Count of recorders currently inside the update window. syscall_hist_enter()
 * first does a cheap disabled-mode probe, then bumps this guard and rechecks
 * mode. syscall_hist_dump waits for the guard to drain after flipping mode to
 * OFF, so a sibling vCPU that already passed the guarded probe cannot land its
 * atomic_fetch_add on count / total_ns / max_ns after the dump has read those
 * slots. Without this barrier the dump and a mid-flight recorder race and the
 * dump's totals can silently lose updates or read torn intermediate values.
 */
static _Atomic int hist_active_recorders = 0;

/* Per-syscall counters. Each slot is touched by every vCPU thread, but the
 * atomic-fetch-add pattern keeps updates lock-free and the relaxed memory order
 * is fine because the dump consumes them only after all vCPUs have stopped
 * recording. No false sharing concern at HIST_TABLE_SIZE=512: the working set
 * during dynamic-linker bring-up is dominated by a handful of syscall numbers
 * (openat / mmap / mprotect / fstat / read), so contention already sits on the
 * same cache lines whether we pad or not.
 */
typedef struct {
    _Atomic uint64_t count;
    _Atomic uint64_t total_ns;
    _Atomic uint64_t max_ns;
} hist_slot_t;

static hist_slot_t hist_table[HIST_TABLE_SIZE];

/* Name table generated from dispatch.tbl: reuse the SYSCALL_TABLE_ENTRIES macro
 * so a new dispatch entry automatically gains a name without touching this
 * file. Entries without a name (unreachable indexes) stay NULL and the dump
 * prints the raw number.
 */
static const char *const hist_names[HIST_TABLE_SIZE] = {
#define _(sys_name, sc_handler, extra) [sys_name] = #sys_name,
    SYSCALL_TABLE_ENTRIES(_)
#undef _
};

/* Parse ELFUSE_STARTUP_TRACE. Accepts comma-separated tokens. "syscalls" or
 * "all" turns the startup histogram on. "syscalls-steady" records until guest
 * exit instead of freezing at execve. The legacy "1" value (steps trace) and
 * the "steps" token leave the histogram off so existing scripts keep working.
 * Token matching is whole-word against a fixed allow-list to avoid matching
 * "syscalls_disabled" or similar.
 */
static bool env_contains_token(const char *env, const char *tok)
{
    if (!env || !env[0])
        return false;
    size_t toklen = strlen(tok);
    const char *p = env;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t) (comma - p) : strlen(p);
        if (len == toklen && memcmp(p, tok, toklen) == 0)
            return true;
        if (!comma)
            break;
        p = comma + 1;
    }
    return false;
}

static void hist_init_resolve(void)
{
    const char *env = getenv("ELFUSE_STARTUP_TRACE");
    const char *rt = getenv("ELFUSE_RUNTIME_STATS");
    if ((rt && rt[0] && strcmp(rt, "0") != 0) ||
        env_contains_token(env, "syscalls-steady")) {
        hist_steady = true;
        atomic_store_explicit(&hist_mode, HIST_RECORD, memory_order_release);
    } else if (env_contains_token(env, "syscalls") ||
               env_contains_token(env, "all")) {
        atomic_store_explicit(&hist_mode, HIST_RECORD, memory_order_release);
    }
}

void syscall_hist_init(void)
{
    pthread_once(&hist_init_once, hist_init_resolve);
}

bool syscall_hist_enabled(void)
{
    syscall_hist_init();
    return atomic_load_explicit(&hist_mode, memory_order_acquire) ==
           HIST_RECORD;
}

uint64_t syscall_hist_now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return 0;
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

uint64_t syscall_hist_enter(void)
{
    syscall_hist_init();
    if (atomic_load_explicit(&hist_mode, memory_order_acquire) != HIST_RECORD)
        return 0;

    /* Increment the recorder guard after the cheap disabled probe, then recheck
     * the mode. The first probe keeps normal runs off the global RMW hot path;
     * the second preserves the dump race protection if a dump flips RECORD to
     * OFF between the first probe and the guard increment.
     */
    atomic_fetch_add_explicit(&hist_active_recorders, 1, memory_order_acquire);
    if (atomic_load_explicit(&hist_mode, memory_order_acquire) != HIST_RECORD) {
        atomic_fetch_sub_explicit(&hist_active_recorders, 1,
                                  memory_order_release);
        return 0;
    }
    uint64_t ns = syscall_hist_now_ns();
    if (!ns) {
        atomic_fetch_sub_explicit(&hist_active_recorders, 1,
                                  memory_order_release);
        return 0;
    }
    return ns;
}

void syscall_hist_record(int nr, uint64_t start_ns, uint64_t end_ns)
{
    /* Guard was entered by syscall_hist_enter(); always release on exit. end_ns
     * == 0 or end_ns < start_ns means the end clock failed: skip the slot
     * update but still release the guard so the dump can proceed.
     */
    if (!end_ns || end_ns < start_ns || nr < 0 || nr >= HIST_TABLE_SIZE)
        goto leave;

    uint64_t ns = end_ns - start_ns;

    if (atomic_load_explicit(&hist_first_ns, memory_order_relaxed) == 0) {
        uint64_t expected = 0;
        atomic_compare_exchange_strong_explicit(&hist_first_ns, &expected,
                                                start_ns, memory_order_relaxed,
                                                memory_order_relaxed);
    }

    hist_slot_t *slot = &hist_table[nr];
    atomic_fetch_add_explicit(&slot->count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&slot->total_ns, ns, memory_order_relaxed);

    /* CAS-loop max keeps the slot lock-free under contention from sibling vCPUs
     * racing on the same syscall number.
     */
    uint64_t prev = atomic_load_explicit(&slot->max_ns, memory_order_relaxed);
    while (ns > prev) {
        if (atomic_compare_exchange_weak_explicit(&slot->max_ns, &prev, ns,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed))
            break;
    }
leave:
    atomic_fetch_sub_explicit(&hist_active_recorders, 1, memory_order_release);
}

void syscall_hist_freeze(const char *reason)
{
    if (hist_steady)
        return;

    /* Publish the reason BEFORE the state transition so a concurrent dump that
     * wins the FROZEN -> OFF exchange cannot observe HIST_FROZEN with a NULL
     * reason and print the wrong dump header. The store on hist_freeze_reason
     * uses release ordering; the freeze CAS below pairs with the dump path's
     * acquire load on hist_mode, so any thread that sees the CAS result also
     * sees the reason that preceded it.
     */
    int probe = atomic_load_explicit(&hist_mode, memory_order_acquire);
    if (probe != HIST_RECORD)
        return;
    atomic_store_explicit(&hist_freeze_reason, reason ? reason : "frozen",
                          memory_order_release);
    int expected = HIST_RECORD;
    atomic_compare_exchange_strong_explicit(&hist_mode, &expected, HIST_FROZEN,
                                            memory_order_release,
                                            memory_order_acquire);
}

void syscall_hist_disable(void)
{
    /* Mark init as already-resolved so the lazy path in syscall_hist_enabled
     * does not overwrite the OFF state with a re-read of the env var.
     */
    pthread_once(&hist_init_once, hist_init_resolve);
    atomic_store_explicit(&hist_mode, HIST_OFF, memory_order_release);
}

void syscall_hist_reset(void)
{
    atomic_store_explicit(&hist_mode, HIST_OFF, memory_order_release);
    while (atomic_load_explicit(&hist_active_recorders, memory_order_acquire) >
           0) {
    }
    for (int i = 0; i < HIST_TABLE_SIZE; i++) {
        atomic_store_explicit(&hist_table[i].count, 0, memory_order_relaxed);
        atomic_store_explicit(&hist_table[i].total_ns, 0, memory_order_relaxed);
        atomic_store_explicit(&hist_table[i].max_ns, 0, memory_order_relaxed);
    }
    atomic_store_explicit(&hist_first_ns, 0, memory_order_relaxed);
    atomic_store_explicit(&hist_freeze_reason, NULL, memory_order_release);
    if (hist_steady)
        atomic_store_explicit(&hist_mode, HIST_RECORD, memory_order_release);
}

static uint64_t sat_add_u64(uint64_t a, uint64_t b)
{
    return (a > UINT64_MAX - b) ? UINT64_MAX : a + b;
}

/* Sort key for the dump. Keys carry the slot index so the qsort comparator can
 * resolve names without consulting hist_table again.
 */
typedef struct {
    int nr;
    uint64_t count;
    uint64_t total_ns;
    uint64_t max_ns;
} hist_row_t;

static int hist_row_cmp(const void *a, const void *b)
{
    const hist_row_t *ra = a;
    const hist_row_t *rb = b;
    if (ra->total_ns < rb->total_ns)
        return 1;
    if (ra->total_ns > rb->total_ns)
        return -1;
    if (ra->count < rb->count)
        return 1;
    if (ra->count > rb->count)
        return -1;
    return ra->nr - rb->nr;
}

static int hist_snapshot_rows(hist_row_t rows[HIST_TABLE_SIZE],
                              uint64_t *total_count,
                              uint64_t *total_ns)
{
    int nrows = 0;
    *total_count = 0;
    *total_ns = 0;
    for (int i = 0; i < HIST_TABLE_SIZE; i++) {
        uint64_t cnt =
            atomic_load_explicit(&hist_table[i].count, memory_order_relaxed);
        if (cnt == 0)
            continue;
        rows[nrows].nr = i;
        rows[nrows].count = cnt;
        rows[nrows].total_ns =
            atomic_load_explicit(&hist_table[i].total_ns, memory_order_relaxed);
        rows[nrows].max_ns =
            atomic_load_explicit(&hist_table[i].max_ns, memory_order_relaxed);
        *total_count = sat_add_u64(*total_count, cnt);
        *total_ns = sat_add_u64(*total_ns, rows[nrows].total_ns);
        nrows++;
    }
    qsort(rows, (size_t) nrows, sizeof(rows[0]), hist_row_cmp);
    return nrows;
}

void syscall_hist_dump_json(FILE *out, bool consume)
{
    int mode = atomic_load_explicit(&hist_mode, memory_order_acquire);
    if (mode == HIST_OFF) {
        fputs("{\"total_count\":0,\"total_ns\":0,\"rows\":[]}", out);
        return;
    }

    if (consume) {
        if (mode == HIST_RECORD) {
            int expected = HIST_RECORD;
            atomic_compare_exchange_strong_explicit(
                &hist_mode, &expected, HIST_FROZEN, memory_order_release,
                memory_order_acquire);
        }
        int prev = atomic_exchange_explicit(&hist_mode, HIST_OFF,
                                            memory_order_acq_rel);
        if (prev == HIST_OFF) {
            fputs("{\"total_count\":0,\"total_ns\":0,\"rows\":[]}", out);
            return;
        }
        while (atomic_load_explicit(&hist_active_recorders,
                                    memory_order_acquire) > 0) {
        }
    }

    hist_row_t rows[HIST_TABLE_SIZE];
    uint64_t total_count = 0;
    uint64_t total_ns = 0;
    int nrows = hist_snapshot_rows(rows, &total_count, &total_ns);

    fprintf(out, "{\"total_count\":%llu,\"total_ns\":%llu,\"rows\":[",
            (unsigned long long) total_count, (unsigned long long) total_ns);
    for (int i = 0; i < nrows; i++) {
        const char *name = hist_names[rows[i].nr];
        fprintf(out,
                "%s{\"nr\":%d,\"name\":\"%s\",\"count\":%llu,"
                "\"total_ns\":%llu,\"max_ns\":%llu}",
                i ? "," : "", rows[i].nr, name ? name : "",
                (unsigned long long) rows[i].count,
                (unsigned long long) rows[i].total_ns,
                (unsigned long long) rows[i].max_ns);
    }
    fputs("]}", out);
}

static uint64_t hist_total_for(int nr)
{
    if (nr < 0 || nr >= HIST_TABLE_SIZE)
        return 0;
    return atomic_load_explicit(&hist_table[nr].total_ns, memory_order_relaxed);
}

void syscall_hist_dump_cost_buckets_json(FILE *out)
{
    uint64_t clone_ns =
        sat_add_u64(hist_total_for(SYS_clone), hist_total_for(SYS_clone3));
    uint64_t wait_ns =
        sat_add_u64(hist_total_for(SYS_wait4), hist_total_for(SYS_waitid));
    uint64_t open_ns =
        sat_add_u64(hist_total_for(SYS_openat), hist_total_for(SYS_openat2));
    uint64_t futex_ns =
        sat_add_u64(hist_total_for(SYS_futex), hist_total_for(SYS_futex_waitv));
    uint64_t mem_ns = sat_add_u64(
        sat_add_u64(hist_total_for(SYS_mmap), hist_total_for(SYS_mprotect)),
        hist_total_for(SYS_madvise));

    fprintf(out,
            "\"phase\":{\"process_lifecycle_ns\":%llu,"
            "\"clone_ns\":%llu,\"wait_ns\":%llu,"
            "\"host_vfs_ns\":%llu,\"futex_ns\":%llu,\"mem_ns\":%llu},"
            "\"fd\":{},\"path\":{\"openat_ns\":%llu},"
            "\"futex\":{\"total_ns\":%llu},\"mem\":{\"total_ns\":%llu}",
            (unsigned long long) sat_add_u64(clone_ns, wait_ns),
            (unsigned long long) clone_ns, (unsigned long long) wait_ns,
            (unsigned long long) open_ns, (unsigned long long) futex_ns,
            (unsigned long long) mem_ns, (unsigned long long) open_ns,
            (unsigned long long) futex_ns, (unsigned long long) mem_ns);
}

void syscall_hist_dump(void)
{
    int mode = atomic_load_explicit(&hist_mode, memory_order_acquire);
    if (mode == HIST_OFF)
        return;

    /* One-shot: flip to OFF so a second call (cleanup from forked child after
     * the parent already dumped, etc) is a clean no-op.
     */
    if (mode == HIST_RECORD) {
        int expected = HIST_RECORD;
        atomic_compare_exchange_strong_explicit(
            &hist_mode, &expected, HIST_FROZEN, memory_order_release,
            memory_order_acquire);
    }
    int prev =
        atomic_exchange_explicit(&hist_mode, HIST_OFF, memory_order_acq_rel);
    if (prev == HIST_OFF)
        return;

    /* Wait for any in-flight recorders to retire. A sibling vCPU that already
     * incremented hist_active_recorders and observed the prior RECORD mode must
     * finish its atomic_fetch_add on the slot before we read it; otherwise the
     * dump can lose an update or read torn intermediate values. The spin is
     * bounded by the slowest recorder (a few hundred ns) and only runs during
     * the one-shot dump.
     */
    while (atomic_load_explicit(&hist_active_recorders, memory_order_acquire) >
           0) {
        /* sched_yield is not portable to relaxed memory models the same way
         * pause is on x86; on aarch64 macOS the loop iteration cost is
         * dominated by the atomic load anyway. No need for an explicit yield --
         * the spin terminates as soon as the in-flight recorders retire.
         */
    }

    uint64_t total_count = 0;
    uint64_t total_ns = 0;
    hist_row_t rows[HIST_TABLE_SIZE];
    int nrows = hist_snapshot_rows(rows, &total_count, &total_ns);
    if (nrows == 0)
        return;

    const char *reason =
        atomic_load_explicit(&hist_freeze_reason, memory_order_acquire);
    fprintf(stderr, "=== syscall histogram (%s) ===\n",
            reason ? reason : "guest exit");
    fprintf(stderr, "%6s %12s %10s %10s  %s\n", "count", "total_ms", "avg_us",
            "max_us", "name");
    for (int i = 0; i < nrows; i++) {
        double total_ms = (double) rows[i].total_ns / 1000000.0;
        double avg_us = rows[i].count ? (double) rows[i].total_ns /
                                            (double) rows[i].count / 1000.0
                                      : 0.0;
        double max_us = (double) rows[i].max_ns / 1000.0;
        const char *name = hist_names[rows[i].nr];
        if (name)
            fprintf(stderr, "%6llu %12.3f %10.2f %10.2f  %s\n",
                    (unsigned long long) rows[i].count, total_ms, avg_us,
                    max_us, name);
        else
            fprintf(stderr, "%6llu %12.3f %10.2f %10.2f  SYS_%d\n",
                    (unsigned long long) rows[i].count, total_ms, avg_us,
                    max_us, rows[i].nr);
    }
    fprintf(stderr, "total: %llu syscalls, %.3f ms\n",
            (unsigned long long) total_count, (double) total_ns / 1000000.0);

    /* Wall-clock span from the first record to dump time. Lets the reader
     * compare syscall total against guest wall time and see what fraction of
     * execution was spent inside syscalls. Only meaningful when at least one
     * record landed; first_ns is set exactly once by the first successful
     * record CAS.
     */
    uint64_t first_ns =
        atomic_load_explicit(&hist_first_ns, memory_order_relaxed);
    if (first_ns) {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            uint64_t now_ns =
                (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
            if (now_ns > first_ns)
                fprintf(
                    stderr, "wall:  %.3f ms (syscalls = %.1f%% of wall)\n",
                    (double) (now_ns - first_ns) / 1000000.0,
                    100.0 * (double) total_ns / (double) (now_ns - first_ns));
        }
    }
}
