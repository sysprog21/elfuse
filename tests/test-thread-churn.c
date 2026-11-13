/*
 * Thread churn: force thread-table slot reuse
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse keeps one thread-table slot per guest thread (MAX_THREADS = 64).
 * Creating well over 64 threads across the test's lifetime forces later clones
 * to reuse slots whose previous occupant already exited on its own, which is
 * the only path that reaps the terminated worker's host pthread (issue #157:
 * stale joinable handles leaked on slot reuse).
 *
 * The sequential phase is the sharpest probe: each worker is the last one alive
 * when it exits, so its wind-down runs the last-worker wakeup that takes the
 * thread-table lock AFTER the slot is released. The next clone joins that same
 * pthread at slot-reuse time; joining under the table lock would deadlock here
 * deterministically.
 */

#include <pthread.h>
#include <stdbool.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* Keep this a slot-reuse regression rather than an HVF vCPU lifecycle soak.
 * Eighty sequential workers exceed the 64-slot table by 16, and two 32-worker
 * batches repeat reuse while unrelated workers remain live.
 */
#define SEQUENTIAL_ROUNDS 80
#define BATCH_SIZE 32
#define BATCH_ROUNDS 2

static void *churn_fn(void *arg)
{
    int *out = (int *) arg;
    *out = 1;
    return NULL;
}

/* Phase 1: sequential create+join, one live worker at a time. Every round past
 * the table size reuses the slot freed by the previous round.
 */
static void test_sequential_churn(void)
{
    TEST("sequential churn (80 threads)");

    for (int i = 0; i < SEQUENTIAL_ROUNDS; i++) {
        int ran = 0;
        pthread_t t;
        if (pthread_create(&t, NULL, churn_fn, &ran) != 0) {
            FAIL("pthread_create failed");
            return;
        }
        if (pthread_join(t, NULL) != 0) {
            FAIL("pthread_join failed");
            return;
        }
        if (!ran) {
            FAIL("thread did not run");
            return;
        }
    }
    PASS();
}

/* Phase 2: batches of concurrent workers. Slot reuse happens while other
 * workers are still live, so the reaping clone and unrelated guest threads
 * contend on the thread table.
 */
static void test_batch_churn(void)
{
    TEST("batch churn (2x32 threads)");

    for (int round = 0; round < BATCH_ROUNDS; round++) {
        pthread_t threads[BATCH_SIZE];
        int ran[BATCH_SIZE];
        int created = 0;
        bool ok = true;

        for (int i = 0; i < BATCH_SIZE; i++) {
            ran[i] = 0;
            if (pthread_create(&threads[i], NULL, churn_fn, &ran[i]) != 0) {
                ok = false;
                break;
            }
            created++;
        }

        for (int i = 0; i < created; i++) {
            if (pthread_join(threads[i], NULL) != 0)
                ok = false;
        }

        if (!ok || created != BATCH_SIZE) {
            FAIL("batch create/join failed");
            return;
        }
        for (int i = 0; i < BATCH_SIZE; i++) {
            if (!ran[i]) {
                FAIL("worker did not run");
                return;
            }
        }
    }
    PASS();
}

int main(void)
{
    printf("test-thread-churn: thread-table slot reuse\n");

    test_sequential_churn();
    test_batch_churn();

    SUMMARY("test-thread-churn");
    return fails > 0 ? 1 : 0;
}
