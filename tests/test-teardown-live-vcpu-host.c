/*
 * Unit test: thread_destroy_all_vcpus live-worker accounting
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * guest_destroy tears down the VM and slab only when thread_destroy_all_vcpus
 * reports the table fully drained. HVF vCPUs are thread-affine, so an active
 * worker slot that has not published vm_exited -- whether its vCPU is published
 * or it is still mid-bring-up (active, vcpu_valid == false, about to create and
 * enter a vCPU on its own thread) -- must be reported live and left untouched,
 * never destroyed from this thread. A regression that used vcpu_valid as the
 * liveness proxy would skip a bring-up worker and let guest_destroy tear the VM
 * down under it. A slot that already published vm_exited (a vm-clone child that
 * self-destroyed its vCPU and stays active only for wait4) holds no live vCPU
 * and must NOT be reported live, or teardown is wrongly deferred.
 *
 * This runs on the host against the real thread.c. It drives only the worker
 * branches, so no hv_vcpu_destroy is ever called (the main-vCPU handle is
 * passed as not-valid); no Hypervisor entitlement or live VM is needed. proc /
 * log / signal hooks that thread.c references are stubbed since none affect the
 * code under test.
 *
 * Guest-side companion: tests/test-teardown-live-vcpu.c drives the same
 * teardown path end-to-end through a running VM.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

#include "runtime/thread.h"

#include "debug/log.h"           /* log_impl prototype */
#include "runtime/futex.h"       /* futex_interrupt_request prototype */
#include "syscall/exec.h"        /* exec_handoff_wake_waiters prototype */
#include "syscall/proc.h"        /* proc_exit_group_requested prototype */
#include "syscall/wakeup-pipe.h" /* wakeup_pipe_signal prototype */

/* thread.c externs not exercised by the code paths under test. */
int proc_exit_group_requested(void)
{
    return 0;
}

void futex_interrupt_request(void) {}

void futex_kick(thread_entry_t *t)
{
    (void) t;
}

void wakeup_pipe_signal(void) {}

void exec_handoff_wake_waiters(void) {}

void signal_refresh_pending_hint(void) {}

void signal_release_claims(struct thread_entry *t)
{
    (void) t;
}

void log_impl(int level, const char *file, int line, const char *fmt, ...)
{
    (void) level;
    (void) file;
    (void) line;
    (void) fmt;
}

static int fails;

#define CHECK(cond)                                                  \
    do {                                                             \
        if (!(cond)) {                                               \
            printf("  FAIL %s:%d: %s\n", __func__, __LINE__, #cond); \
            fails++;                                                 \
        }                                                            \
    } while (0)

/* An empty table is fully drained: nothing live, nothing destroyed. */
static void test_empty_table_drained(void)
{
    thread_init();
    bool live = true;
    bool main_destroyed = thread_destroy_all_vcpus(0, false, &live);
    CHECK(!live);
    CHECK(!main_destroyed);
}

/* A worker still in bring-up (active, vCPU not yet published) must be reported
 * live and left active -- the regression this guards skipped it via
 * !vcpu_valid, leaving live == false. A worker is never decremented from
 * active_thread_count here (only the main slot is).
 */
static void test_bringup_worker_is_live(void)
{
    thread_init();
    thread_entry_t *w = thread_alloc(1000, 0, 0);
    CHECK(w != NULL);
    if (!w)
        return;
    CHECK(w->active);
    CHECK(!w->vcpu_valid);
    int count_before = thread_active_count();

    bool live = false;
    bool main_destroyed = thread_destroy_all_vcpus(0, false, &live);
    CHECK(live);      /* bring-up worker counted as live */
    CHECK(w->active); /* left untouched for process-exit reclamation */
    CHECK(!main_destroyed);
    CHECK(thread_active_count() == count_before); /* worker not decremented */
}

/* A worker that has published its vCPU is likewise reported live and its handle
 * is not destroyed from this (foreign) thread.
 */
static void test_published_worker_not_cross_destroyed(void)
{
    thread_init();
    thread_entry_t *w = thread_alloc(1001, 0, 0);
    CHECK(w != NULL);
    if (!w)
        return;
    w->vcpu = 0x1234; /* a handle this thread does not own */
    w->vcpu_valid = true;
    int count_before = thread_active_count();

    bool live = false;
    bool main_destroyed = thread_destroy_all_vcpus(0, false, &live);
    CHECK(live);
    CHECK(w->active);     /* not deactivated */
    CHECK(w->vcpu_valid); /* not cross-thread destroyed */
    CHECK(!main_destroyed);
    CHECK(thread_active_count() == count_before);
}

/* A vm-clone child that already exited (vCPU self-destroyed on its own thread,
 * vm_exited published) but stays active for wait4 holds no live vCPU, so it
 * must NOT be reported live -- otherwise guest_destroy wrongly defers the
 * explicit HVF teardown for an already-dead slot. Guards the vm_exited
 * exclusion.
 */
static void test_exited_vmclone_worker_not_live(void)
{
    thread_init();
    thread_entry_t *w = thread_alloc(1002, 0, 0);
    CHECK(w != NULL);
    if (!w)
        return;
    w->vm_exited = true; /* vCPU already destroyed; vcpu_valid stays false */

    bool live = true;
    bool main_destroyed = thread_destroy_all_vcpus(0, false, &live);
    CHECK(!live); /* exited slot is not a live worker */
    CHECK(!main_destroyed);
    CHECK(w->active); /* left for wait4; teardown does not touch it */
}

int main(void)
{
    printf(
        "test-teardown-live-vcpu-host: thread_destroy_all_vcpus accounting\n");

    test_empty_table_drained();
    test_bringup_worker_is_live();
    test_published_worker_not_cross_destroyed();
    test_exited_vmclone_worker_not_live();

    if (fails == 0)
        printf("  all checks passed\n");
    return fails > 0 ? 1 : 0;
}
