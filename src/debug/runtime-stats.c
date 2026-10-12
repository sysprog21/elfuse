/*
 * Runtime stats coordinator
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "debug/runtime-stats.h"

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/shim-globals.h"
#include "debug/log.h"
#include "debug/syscall-hist.h"
#include "syscall/proc.h"

typedef enum {
    RT_STATS_OFF = 0,
    RT_STATS_SUMMARY,
    RT_STATS_JSON,
    RT_STATS_JSONL,
} rt_stats_mode_t;

/* Written once by runtime_stats_init before any other thread exists. */
static rt_stats_mode_t rt_mode;
static int rt_signal;
static uint64_t rt_start_ns;

/* The guest and its argv are set by attach and cleared by the final dump, all
 * under the mutex, which also keeps a snapshot from interleaving with the exit
 * dump.
 */
static pthread_mutex_t rt_dump_mutex = PTHREAD_MUTEX_INITIALIZER;
static const guest_t *rt_guest;
static int rt_argc;
static const char *const *rt_argv;

/* Snapshot requests. The sigwait thread that receives the signal also carries
 * the cross-process doorbell and the watchdog, so it only posts here; the
 * dumper thread does the write, which can block on a stalled stderr. The
 * request lock is never held across a dump.
 */
static pthread_mutex_t rt_req_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t rt_req_cond = PTHREAD_COND_INITIALIZER;
static bool rt_req_pending;
static bool rt_dumper_started;

static bool env_on(const char *v)
{
    return v && v[0] && strcmp(v, "0") != 0;
}

/* Length of the well-formed UTF-8 sequence at @p (RFC 3629: no overlongs, no
 * surrogates, nothing past U+10FFFF), or 0 when the bytes there are not one.
 */
static int utf8_seq_len(const unsigned char *p)
{
    unsigned char lo = 0x80, hi = 0xbf;
    int n;
    if (p[0] >= 0xc2 && p[0] <= 0xdf)
        n = 2;
    else if (p[0] >= 0xe0 && p[0] <= 0xef)
        n = 3;
    else if (p[0] >= 0xf0 && p[0] <= 0xf4)
        n = 4;
    else
        return 0;
    if (p[0] == 0xe0)
        lo = 0xa0;
    else if (p[0] == 0xed)
        hi = 0x9f;
    else if (p[0] == 0xf0)
        lo = 0x90;
    else if (p[0] == 0xf4)
        hi = 0x8f;
    if (p[1] < lo || p[1] > hi)
        return 0;
    for (int i = 2; i < n; i++)
        if (p[i] < 0x80 || p[i] > 0xbf)
            return 0;
    return n;
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
            /* Well-formed UTF-8 goes out as is. Any other byte past ASCII is
             * escaped on its own, so an argv that is not UTF-8 still leaves a
             * line every JSON parser accepts.
             */
            if (*p >= 0x80) {
                int n = utf8_seq_len(p);
                if (n) {
                    fwrite(p, 1, (size_t) n, out);
                    p += n - 1;
                    break;
                }
            }
            if (*p < 0x20 || *p >= 0x7f)
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

void runtime_stats_init(void)
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

    /* Only claim the signal when there is something to dump: otherwise it keeps
     * its default action, as a user who set the variable by mistake would
     * expect.
     */
    const char *sig = getenv("ELFUSE_STATS_SIGNAL");
    if (rt_mode != RT_STATS_OFF && sig && strcmp(sig, "USR1") == 0)
        rt_signal = SIGUSR1;
}

bool runtime_stats_enabled(void)
{
    return rt_mode != RT_STATS_OFF;
}

int runtime_stats_signal(void)
{
    return rt_signal;
}

static void dump_locked(const char *reason, bool final);

static void *dumper_main(void *arg)
{
    (void) arg;
    for (;;) {
        pthread_mutex_lock(&rt_req_lock);
        while (!rt_req_pending)
            pthread_cond_wait(&rt_req_cond, &rt_req_lock);
        rt_req_pending = false;
        pthread_mutex_unlock(&rt_req_lock);

        pthread_mutex_lock(&rt_dump_mutex);
        dump_locked("signal", false);
        pthread_mutex_unlock(&rt_dump_mutex);
    }
    return NULL;
}

void runtime_stats_attach(const guest_t *g, int argc, const char *const *argv)
{
    if (!runtime_stats_enabled())
        return;
    pthread_mutex_lock(&rt_dump_mutex);
    rt_guest = g;
    rt_argc = argv ? argc : 0;
    rt_argv = argv;
    pthread_mutex_unlock(&rt_dump_mutex);

    /* Started here rather than at init so it inherits the signal mask
     * proc_preempt_init installed, like every other elfuse thread.
     */
    pthread_mutex_lock(&rt_req_lock);
    if (rt_signal && !rt_dumper_started) {
        pthread_t t;
        int err = pthread_create(&t, NULL, dumper_main, NULL);
        rt_dumper_started = err == 0;
        if (err == 0)
            pthread_detach(t);
        else
            log_warn(
                "runtime stats: no snapshot thread (%s), so "
                "ELFUSE_STATS_SIGNAL requests are dropped",
                strerror(err));
    }
    pthread_mutex_unlock(&rt_req_lock);
}

static void dump_json_to(FILE *out,
                         const guest_t *g,
                         const char *reason,
                         bool final)
{
    uint64_t t = now_ns();
    fprintf(out, "{\"schema\":\"elfuse-runtime-stats/1\",\"reason\":");
    json_string(out, reason);
    fprintf(out, ",\"final\":%s,\"pid\":%lld,\"time_ns\":%llu,\"argv\":[",
            final ? "true" : "false", (long long) proc_get_pid(),
            (unsigned long long) t);
    for (int i = 0; i < rt_argc; i++) {
        if (i)
            fputc(',', out);
        json_string(out, rt_argv[i]);
    }
    fprintf(out, "],\"wall_ns\":%llu,\"shim\":",
            (unsigned long long) (t > rt_start_ns ? t - rt_start_ns : 0));
    shim_globals_counters_dump_json(out, g);
    fputs(",\"vmexit\":", out);
    proc_dump_vcpu_exit_stats_json(out);
    fputs(",\"syscalls\":", out);
    syscall_hist_dump_json(out, final);
    fputc(',', out);
    syscall_hist_dump_cost_buckets_json(out);
    fputs("}\n", out);
}

/* Fork children share the parent's stderr, so a record built through stdio
 * buffers would interleave with theirs mid-object. Build it in memory and hand
 * it to the kernel in one write.
 */
static void dump_json(const guest_t *g, const char *reason, bool final)
{
    char *buf = NULL;
    size_t len = 0;
    FILE *mem = open_memstream(&buf, &len);
    if (!mem)
        return;
    dump_json_to(mem, g, reason, final);
    if (fclose(mem) == 0) {
        fflush(stderr);
        for (size_t off = 0; off < len;) {
            ssize_t n = write(STDERR_FILENO, buf + off, len - off);
            if (n <= 0)
                break;
            off += (size_t) n;
        }
    }
    free(buf);
}

static void dump_locked(const char *reason, bool final)
{
    const guest_t *g = rt_guest;
    if (!g)
        return;

    /* JSON is a single object per process, so a snapshot has nowhere to go
     * without breaking the stream; JSONL takes one per line.
     */
    if (rt_mode == RT_STATS_JSON && !final)
        return;

    if (rt_mode == RT_STATS_SUMMARY) {
        shim_globals_counters_dump(g);
        proc_dump_vcpu_exit_stats();
        if (final)
            syscall_hist_dump();
    } else {
        dump_json(g, reason, final);
    }
    fflush(stderr);
}

void runtime_stats_dump_final(const char *reason)
{
    pthread_mutex_lock(&rt_dump_mutex);
    dump_locked(reason, true);
    rt_guest = NULL;
    rt_argv = NULL;
    rt_argc = 0;
    pthread_mutex_unlock(&rt_dump_mutex);
}

void runtime_stats_request_snapshot(void)
{
    /* Dropped until attach has started the dumper, so a signal sent during
     * bring-up does not surface later as a snapshot nobody asked for then.
     */
    pthread_mutex_lock(&rt_req_lock);
    if (rt_dumper_started) {
        rt_req_pending = true;
        pthread_cond_signal(&rt_req_cond);
    }
    pthread_mutex_unlock(&rt_req_lock);
}
