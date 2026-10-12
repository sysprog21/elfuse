/*
 * Runtime stats coordinator
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * One gate, ELFUSE_RUNTIME_STATS, over the shim counters, the vCPU exit
 * accounting, and the steady-state syscall histogram. Modes: summary (stderr
 * tables), json (one object per process at exit), jsonl (one object per line,
 * at exit and on each snapshot request). ELFUSE_STATS_SIGNAL=USR1 requests a
 * snapshot from outside; the preemption sigwait thread receives it and a dumper
 * thread writes it, so no handler ever runs on a vCPU thread.
 */

#pragma once

#include <stdbool.h>

#include "core/guest.h"

/* Resolve the env gates. Call before proc_preempt_init so the snapshot signal
 * joins the blocked set every later thread inherits.
 */
void runtime_stats_init(void);
bool runtime_stats_enabled(void);

/* The host signal that requests a snapshot, or 0 when none is configured or
 * stats are off.
 */
int runtime_stats_signal(void);

/* Name the guest whose shim counters the dumps read, and the guest argv the
 * JSON records carry (none for a fork child). Snapshot requests that arrive
 * before this are ignored. Call after proc_preempt_init.
 */
void runtime_stats_attach(const guest_t *g, int argc, const char *const *argv);

/* Emit the final dump and detach the guest; later requests are no-ops. */
void runtime_stats_dump_final(const char *reason);

/* Queue one snapshot. Called from the preemption sigwait thread; never blocks
 * on the dump itself.
 */
void runtime_stats_request_snapshot(void);
