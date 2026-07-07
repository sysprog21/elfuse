/*
 * Dynamic-linker startup syscall histogram
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Per-syscall count + total + max latency, captured during the EL0 syscall
 * storm that dominates dynamic-linker bring-up. Opt-in via
 * ELFUSE_STARTUP_TRACE=syscalls (or =all alongside the existing per-step VM
 * bring-up tracer). Recording stops at the first successful execve so the dump
 * reflects pre-execve startup; without execve it dumps on guest exit.
 *
 * ELFUSE_STARTUP_TRACE=syscalls-steady records until guest exit instead. This
 * is the measurement gate for steady-state performance work: it includes
 * startup plus the workload, so run a long enough workload for startup to be
 * noise.
 *
 * Disabled cost is one branch + one global load per syscall_dispatch entry
 * because syscall_hist_enabled() resolves the env once and caches the result.
 * Enabled cost is two CLOCK_MONOTONIC reads per syscall plus three relaxed
 * atomic adds.
 */

#ifndef ELFUSE_SYSCALL_HIST_H
#define ELFUSE_SYSCALL_HIST_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* Parse ELFUSE_STARTUP_TRACE once; safe to call repeatedly. Must be called
 * before any syscall is dispatched so the enabled flag is stable for the
 * lifetime of the process.
 */
void syscall_hist_init(void);

/* Returns true while the histogram is in RECORD mode.
 *
 * Returns false after syscall_hist_freeze() in startup mode so recording stops
 * cleanly at the first execve. Steady mode keeps returning true until dump.
 * Callers that need to time a syscall should use syscall_hist_enter() instead,
 * which also enters the recorder guard.
 */
bool syscall_hist_enabled(void);

/* Monotonic timestamp source. Returns 0 on clock failure. */
uint64_t syscall_hist_now_ns(void);

/* Enter the recorder guard and return the current monotonic timestamp.
 * Returns 0 (guard NOT held) when the histogram is disabled or mode is not
 * RECORD. On a non-zero return the caller MUST call syscall_hist_record() to
 * release the guard, even if the elapsed time is unavailable.
 */
uint64_t syscall_hist_enter(void);

/* Record one syscall observation and release the recorder guard entered by
 * syscall_hist_enter(). nr is the Linux syscall number. start_ns and end_ns are
 * monotonic timestamps; end_ns == 0 or end_ns < start_ns skips the slot update
 * but still releases the guard. Called from every vCPU thread.
 */
void syscall_hist_record(int nr, uint64_t start_ns, uint64_t end_ns);

/* Stop recording but keep the captured data ready to dump. Called from the
 * successful-execve path so steady-state syscall traffic does not pollute the
 * startup picture. The reason string survives until syscall_hist_dump runs and
 * appears in the dump header.
 */
void syscall_hist_freeze(const char *reason);

/* Force-disable the histogram in this process even if ELFUSE_STARTUP_TRACE is
 * set. Used by fork-child bring-up: the child resumes from a parent snapshot,
 * so its first syscalls are steady-state, not dynamic-linker bring-up. Without
 * this, the inherited env var would trigger lazy init in the child and pollute
 * the parent's dump if both share stderr.
 */
void syscall_hist_disable(void);
void syscall_hist_reset(void);

/* Emit a human-readable summary to stderr, sorted by total ns descending.
 * Idempotent: subsequent calls are no-ops. Safe to call from cleanup paths that
 * may run more than once.
 */
void syscall_hist_dump(void);
void syscall_hist_dump_json(FILE *out, bool consume);
void syscall_hist_dump_cost_buckets_json(FILE *out);

#endif /* ELFUSE_SYSCALL_HIST_H */
