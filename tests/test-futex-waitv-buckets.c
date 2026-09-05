/*
 * futex_waitv over entries that share a bucket
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse locks one bucket per distinct address hash, ascending, and unlocks in
 * reverse. Two guest addresses hashing alike is ordinary: there are 1024
 * buckets and the guest picks the addresses. A repeat in that set locks one
 * non-recursive mutex twice, which is a hang rather than an errno, so every
 * case here is bounded by a deadline the call has to answer.
 *
 * The hash below mirrors proved/futexhash.h. It only names elfuse's buckets; a
 * reference kernel buckets differently, so there the same cases are ordinary
 * wait sets and still have to behave.
 *
 * Syscalls exercised: futex_waitv(449), futex(98), clone(220), exit(93),
 * clock_gettime(113)
 */

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <linux/futex.h>

#include "test-harness.h"
#include "raw-syscall.h"
#include "test-util.h"

int passes = 0, fails = 0;

#define __NR_futex_waitv 449
#define FUTEX2_SIZE_U32 0x02
#define WAITV_MAX 128

/* Mirrors futex_bucket_index in proved/futexhash.h with FUTEX_BUCKETS. */
#define FUTEX_HASH_MULT 0x9E3779B97F4A7C15ULL
#define FUTEX_BUCKETS 1024u

struct futex_waitv {
    uint64_t val;
    uint64_t uaddr;
    uint32_t flags;
    uint32_t __reserved;
};

struct k_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

#define PARK_MS 200
#define EARLY_MS (PARK_MS / 2)

#define ARENA_WORDS (1u << 20)
static uint32_t arena[ARENA_WORDS];
static int32_t first_at[FUTEX_BUCKETS];
static int32_t shared[WAITV_MAX];
static int n_shared;

static uint32_t bucket_of(uint64_t a)
{
    return (uint32_t) (((((a >> 2) * FUTEX_HASH_MULT) >> 32)) % FUTEX_BUCKETS);
}

static long now_ms(void)
{
    struct k_timespec ts;
    raw_syscall2(113, 1 /* CLOCK_MONOTONIC */, (long) &ts);
    return (long) (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static void deadline_in(struct k_timespec *ts, long ms)
{
    raw_syscall2(113, 1, (long) ts);
    ts->tv_nsec += ms * 1000L * 1000L;
    while (ts->tv_nsec >= 1000000000L) {
        ts->tv_nsec -= 1000000000L;
        ts->tv_sec++;
    }
}

static void fill(struct futex_waitv *w, int n, uint32_t *const *addrs)
{
    memset(w, 0, sizeof(*w) * (size_t) n);
    for (int i = 0; i < n; i++) {
        w[i].uaddr = (uint64_t) (uintptr_t) addrs[i];
        w[i].flags = FUTEX2_SIZE_U32;
    }
}

/* Every case waits out its deadline: nothing here is woken. A repeat in the
 * bucket set never gets that far.
 */
static void expect_timeout(const char *name, struct futex_waitv *w, int n)
{
    TEST(name);
    struct k_timespec ts;
    deadline_in(&ts, PARK_MS);
    long t0 = now_ms();
    long rc = raw_syscall5(__NR_futex_waitv, (long) w, n, 0, (long) &ts, 1);
    long elapsed = now_ms() - t0;

    if (rc != -ETIMEDOUT)
        FAIL("a wait set nobody wakes must report ETIMEDOUT");
    else if (elapsed < EARLY_MS)
        FAIL("the wait did not last");
    else
        PASS();
}

int main(void)
{
    printf("=== futex_waitv bucket sharing ===\n\n");

    for (uint32_t i = 0; i < FUTEX_BUCKETS; i++)
        first_at[i] = -1;

    /* One bucket's worth of distinct words, enough to fill a whole wait set. */
    uint32_t target = bucket_of((uint64_t) (uintptr_t) &arena[0]);
    for (uint32_t i = 0; i < ARENA_WORDS && n_shared < WAITV_MAX; i++)
        if (bucket_of((uint64_t) (uintptr_t) &arena[i]) == target)
            shared[n_shared++] = (int32_t) i;

    TEST("arena yields a full shared bucket");
    if (n_shared < WAITV_MAX) {
        FAIL("not enough words share one bucket");
        goto done;
    }
    PASS();

    struct futex_waitv w[WAITV_MAX];
    uint32_t *addrs[WAITV_MAX];

    for (int i = 0; i < 2; i++)
        addrs[i] = &arena[shared[0]];
    fill(w, 2, addrs);
    expect_timeout("one address twice", w, 2);

    addrs[0] = &arena[shared[0]];
    addrs[1] = &arena[shared[1]];
    fill(w, 2, addrs);
    expect_timeout("two addresses, one bucket", w, 2);

    addrs[0] = &arena[shared[1]];
    addrs[1] = &arena[shared[0]];
    fill(w, 2, addrs);
    expect_timeout("the same two, descending", w, 2);

    for (int i = 0; i < WAITV_MAX; i++)
        addrs[i] = &arena[shared[0]];
    fill(w, WAITV_MAX, addrs);
    expect_timeout("one address 128 times", w, WAITV_MAX);

    /* Descending is the insertion's worst case: every entry goes to the front
     * and shifts the whole set.
     */
    for (int i = 0; i < WAITV_MAX; i++)
        addrs[i] = &arena[shared[WAITV_MAX - 1 - i]];
    fill(w, WAITV_MAX, addrs);
    expect_timeout("128 in one bucket, descending", w, WAITV_MAX);

    for (int i = 0; i < WAITV_MAX; i++)
        addrs[i] = &arena[(uint32_t) (WAITV_MAX - 1 - i) * 977u];
    fill(w, WAITV_MAX, addrs);
    expect_timeout("128 spread, descending address", w, WAITV_MAX);

done:
    SUMMARY("test-futex-waitv-buckets");
    return fails > 0 ? 1 : 0;
}
