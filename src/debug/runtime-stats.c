/*
 * Runtime stats coordinator.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "debug/runtime-stats.h"

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/shim-globals.h"
#include "debug/syscall-hist.h"
#include "syscall/proc.h"

typedef enum {
    RT_STATS_OFF = 0,
    RT_STATS_SUMMARY,
    RT_STATS_JSON,
    RT_STATS_JSONL,
} rt_stats_mode_t;

static rt_stats_mode_t rt_mode;
static int rt_argc;
static char **rt_argv;
static uint64_t rt_start_ns;
static _Atomic int rt_dump_requested;
static pthread_mutex_t rt_dump_mutex = PTHREAD_MUTEX_INITIALIZER;
static _Atomic bool rt_final_done;

static bool env_on(const char *v)
{
    return v && v[0] && strcmp(v, "0") != 0;
}

static void json_string(FILE *out, const char *s)
{
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *) (s ? s : ""); *p;
         p++) {
        switch (*p) {
        case '"':
            fputs("\\\"", out);
            break;
        case '\\':
            fputs("\\\\", out);
            break;
        case '\n':
            fputs("\\n", out);
            break;
        case '\r':
            fputs("\\r", out);
            break;
        case '\t':
            fputs("\\t", out);
            break;
        default:
            if (*p < 0x20)
                fprintf(out, "\\u%04x", *p);
            else
                fputc(*p, out);
            break;
        }
    }
    fputc('"', out);
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return 0;
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static void stats_signal_handler(int signo)
{
    (void) signo;
    atomic_store_explicit(&rt_dump_requested, 1, memory_order_release);
}

void runtime_stats_init(int argc, char **argv)
{
    rt_start_ns = now_ns();
    const char *v = getenv("ELFUSE_RUNTIME_STATS");
    if (env_on(v)) {
        if (strcmp(v, "json") == 0)
            rt_mode = RT_STATS_JSON;
        else if (strcmp(v, "jsonl") == 0)
            rt_mode = RT_STATS_JSONL;
        else
            rt_mode = RT_STATS_SUMMARY;
    } else if (env_on(getenv("ELFUSE_SHIM_STATS"))) {
        rt_mode = RT_STATS_SUMMARY;
    }
    rt_argc = argc;
    rt_argv = argv;

    const char *sig = getenv("ELFUSE_STATS_SIGNAL");
    if (env_on(sig) && strcmp(sig, "USR1") == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = stats_signal_handler;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR1, &sa, NULL);
    }
}

bool runtime_stats_enabled(void)
{
    return rt_mode != RT_STATS_OFF;
}

void runtime_stats_reset_baseline(void)
{
    if (!runtime_stats_enabled())
        return;
    rt_start_ns = now_ns();
    atomic_store_explicit(&rt_dump_requested, 0, memory_order_release);
    atomic_store_explicit(&rt_final_done, false, memory_order_release);
    proc_reset_vcpu_exit_stats();
    syscall_hist_reset();
}

static void runtime_stats_dump_json(const guest_t *g,
                                    const char *reason,
                                    bool final)
{
    fprintf(stderr, "{\"schema\":\"elfuse-runtime-stats/1\",\"reason\":");
    json_string(stderr, reason ? reason : "dump");
    fprintf(stderr, ",\"final\":%s,\"pid\":%lld,\"time_ns\":%llu,\"argv\":[",
            final ? "true" : "false", (long long) proc_get_pid(),
            (unsigned long long) now_ns());
    for (int i = 0; i < rt_argc; i++) {
        if (i)
            fputc(',', stderr);
        json_string(stderr, rt_argv[i]);
    }
    uint64_t t = now_ns();
    fprintf(stderr, "],\"wall_ns\":%llu,\"guest_run_ns\":0,\"shim\":",
            (unsigned long long) (t > rt_start_ns ? t - rt_start_ns : 0));
    shim_globals_counters_dump_json(stderr, g);
    fputs(",\"vmexit\":", stderr);
    proc_dump_vcpu_exit_stats_json(stderr);
    fputs(",\"syscalls\":", stderr);
    syscall_hist_dump_json(stderr, final);
    fputc(',', stderr);
    syscall_hist_dump_cost_buckets_json(stderr);
    fputs("}\n", stderr);
}

void runtime_stats_dump(const guest_t *g, const char *reason, bool final)
{
    if (!runtime_stats_enabled())
        return;
    /* Suppress any dump once the final dump has completed. */
    if (atomic_load_explicit(&rt_final_done, memory_order_acquire))
        return;

    pthread_mutex_lock(&rt_dump_mutex);
    /* Recheck after acquiring: a concurrent final dump may have just finished.
     */
    if (atomic_load_explicit(&rt_final_done, memory_order_acquire)) {
        pthread_mutex_unlock(&rt_dump_mutex);
        return;
    }

    /* JSON mode is a single top-level object emitted on exit. Drop non-final
     * (signal-triggered) dumps so two objects never land on stderr without an
     * array wrapper. JSONL is line-delimited, so per-signal objects are fine.
     */
    if (rt_mode == RT_STATS_JSON && !final) {
        pthread_mutex_unlock(&rt_dump_mutex);
        return;
    }

    if (rt_mode == RT_STATS_SUMMARY) {
        shim_globals_counters_dump(g);
        proc_dump_vcpu_exit_stats();
        if (final)
            syscall_hist_dump();
    } else {
        runtime_stats_dump_json(g, reason, final);
    }

    if (final)
        atomic_store_explicit(&rt_final_done, true, memory_order_release);
    pthread_mutex_unlock(&rt_dump_mutex);
}

void runtime_stats_maybe_dump_signal(const guest_t *g)
{
    if (!atomic_exchange_explicit(&rt_dump_requested, 0, memory_order_acq_rel))
        return;
    runtime_stats_dump(g, "signal", false);
}
