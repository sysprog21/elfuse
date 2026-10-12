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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* Parse ELFUSE_STARTUP_TRACE once; safe to call repeatedly. Must be called
 * before any syscall is dispatched so the enabled flag is stable for the
 * lifetime of the process.
 */
void syscall_hist_init(void);

/* Fast probe used by syscall_dispatch to decide whether to grab a start
 * timestamp.
 *
 * Returns false after syscall_hist_freeze() so the recording stops cleanly at
 * the first execve. Steady mode never freezes and stays true until the dump.
 */
bool syscall_hist_enabled(void);

/* Monotonic timestamp source.
 *
 * Returns 0 when the histogram is disabled so the caller can short-circuit
 * without a branch on the env-var cache.
 */
uint64_t syscall_hist_now_ns(void);

/* Record one syscall observation. nr is the Linux syscall number; ns is the
 * elapsed time inside the dispatcher. Called from every vCPU thread, so the
 * counters update through C11 atomic fetch-add. No-op if disabled or frozen.
 */
void syscall_hist_record(int nr, uint64_t ns);

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

/* Whether recording runs until guest exit (syscalls-steady, or
 * ELFUSE_RUNTIME_STATS) rather than freezing at the first execve.
 */
bool syscall_hist_steady(void);

/* Emit a human-readable summary to stderr, sorted by total ns descending.
 * Idempotent: subsequent calls are no-ops. Safe to call from cleanup paths that
 * may run more than once.
 */
void syscall_hist_dump(void);
void syscall_hist_dump_json(FILE *out, bool consume);
void syscall_hist_dump_cost_buckets_json(FILE *out);
