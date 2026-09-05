/*
 * test-shim-futex-fast.c -- non-blocking futex waits preserve host semantics.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * futex_wait_fast in core/shim.S answers an untimed FUTEX_WAIT /
 * FUTEX_WAIT_BITSET with EAGAIN at EL1 when the word already moved off the
 * expected value, and bails to the host for every other shape. This pins both
 * halves: the answers it gives, and the ones it must decline to give.
 *
 * Every assertion here is plain Linux futex ABI, so the reference kernel
 * adjudicates all of it; the test is registered in tests/test-matrix.sh rather
 * than exempted from it. Whether the EL1 path or the host produced a given
 * answer is not observable from inside the guest by design, and is checked
 * out-of-band by tests/test-shim-futex-stats.sh reading the shim counters.
 */

#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <time.h>

#include "raw-syscall.h"

#define PAGE_SIZE 4096

static int failures;

static void expect(long got, long want, const char *name)
{
    if (got == want)
        return;
    fprintf(stderr, "FAIL %s: got %ld, want %ld\n", name, got, want);
    failures++;
}

#define WAKER_DELAY_MS 200

static int waker_word;

static void *waker(void *arg)
{
    (void) arg;
    struct timespec nap = {.tv_sec = 0, .tv_nsec = WAKER_DELAY_MS * 1000000L};
    nanosleep(&nap, NULL);
    __atomic_store_n(&waker_word, 1, __ATOMIC_RELEASE);
    raw_futex_wake(&waker_word, 1);
    return NULL;
}

/* The word still holds the expected value, so the fast path must decline and
 * let the host enqueue a waiter. Inverting that branch would turn every guest
 * mutex into a spin, which no other case here would catch.
 *
 * Counted rather than checked by return value, and rather than timed. A wait
 * that a sibling wakes may report 0 or EAGAIN depending on whether the word is
 * re-read after the wake, and both are within the futex contract, so the return
 * says nothing about whether the call parked. Elapsed time says nothing either:
 * a wait that never parks spins in the retry loop below until the waker's store
 * lands, which takes the same wall clock as parking for it. The number of trips
 * around that loop is what separates the two, one or two against millions.
 */
#define MAX_WAIT_TRIPS 1000

static void test_matching_word_still_blocks(void)
{
    struct timespec begin, done;
    pthread_t t;
    long elapsed_ms;
    long trips = 0;

    if (pthread_create(&t, NULL, waker, NULL) != 0) {
        fprintf(stderr, "FAIL matching word: pthread_create\n");
        failures++;
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &begin);
    while (__atomic_load_n(&waker_word, __ATOMIC_ACQUIRE) == 0) {
        raw_futex_wait(&waker_word, 0);
        trips++;
    }
    clock_gettime(CLOCK_MONOTONIC, &done);
    pthread_join(t, NULL);

    elapsed_ms = (done.tv_sec - begin.tv_sec) * 1000L +
                 (done.tv_nsec - begin.tv_nsec) / 1000000L;

    /* A wait that parks takes one trip, or a handful once spurious wakeups and
     * quantum re-arms are allowed for. A wait that answers without parking
     * takes as many trips as fit in WAKER_DELAY_MS, which is millions. The
     * bound sits far above the first and far below the second.
     */
    if (trips > MAX_WAIT_TRIPS) {
        fprintf(stderr,
                "FAIL matching word blocks: %ld trips through the wait in %ld "
                "ms, expected to park rather than spin\n",
                trips, elapsed_ms);
        failures++;
    }

    /* The waker sleeps WAKER_DELAY_MS; half of it is slack for a coarse clock.
     * This catches the opposite error, a wait that reports the word moved
     * before the waker ever stored to it.
     */
    if (elapsed_ms < WAKER_DELAY_MS / 2) {
        fprintf(stderr,
                "FAIL matching word blocks: returned after %ld ms, expected to "
                "park until the waker at %d ms\n",
                elapsed_ms, WAKER_DELAY_MS);
        failures++;
    }
}

/* Addresses the EL1 unprivileged load must fault on, each landing on the host's
 * own EFAULT rather than on an EAGAIN the fast path invented.
 */
static void test_unresolvable_addresses(void)
{
    void *gone = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *none =
        mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (gone == MAP_FAILED || none == MAP_FAILED) {
        fprintf(stderr, "FAIL unresolvable: mmap\n");
        failures++;
        return;
    }
    munmap(gone, PAGE_SIZE);

    expect(raw_futex_wait((int *) NULL, 0), -EFAULT, "null uaddr");
    expect(raw_futex_wait((int *) gone, 0), -EFAULT, "unmapped uaddr");
    expect(raw_futex_wait((int *) none, 0), -EFAULT, "PROT_NONE uaddr");
    munmap(none, PAGE_SIZE);
}

/* TCR_EL1.TBI0 makes the EL1 probe and load ignore the top byte; the host's
 * software walker does not. Both must answer the same, which means the fast
 * path has to decline a tagged address instead of resolving one.
 */
static void test_tagged_address(void)
{
    int word = 1;
    uintptr_t tagged = (uintptr_t) &word | ((uintptr_t) 0xAA << 56);

    expect(raw_futex_wait((int *) tagged, 0), -EFAULT, "tagged uaddr mismatch");
    expect(raw_futex_wait((int *) tagged, 1), -EFAULT, "tagged uaddr match");
}

static void test_lazy_wait_case(int op, int timed, uint32_t expected)
{
    const size_t span = 4ULL << 20;
    uint8_t *p = mmap(NULL, 2 * span, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        failures++;
        perror("lazy futex mmap");
        return;
    }

    /* Each call gets untouched word and timeout pages in separate blocks. */
    long word = (long) (p + span);
    long timeout = timed ? (long) p : 0;
    expect(raw_syscall6(__NR_futex, word, op | FUTEX_PRIVATE_FLAG, expected,
                        timeout, 0, FUTEX_BITSET_MATCH_ANY),
           expected ? -EAGAIN : -ETIMEDOUT,
           expected ? "lazy wait mismatch" : "zero lazy timeout");
    expect(munmap(p, 2 * span), 0, "lazy futex munmap");
}

static void test_lazy_wait_inputs(void)
{
    const int ops[] = {FUTEX_WAIT, FUTEX_WAIT_BITSET};
    for (unsigned i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
        test_lazy_wait_case(ops[i], 0, 1);
        test_lazy_wait_case(ops[i], 1, 1);
        test_lazy_wait_case(ops[i], 1, 0);
    }
}

static void test_page_boundary(void)
{
    uint8_t *p = mmap(NULL, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        failures++;
        perror("boundary futex mmap");
        return;
    }
    if (mprotect(p + PAGE_SIZE, PAGE_SIZE, PROT_NONE) != 0) {
        failures++;
        perror("boundary futex mprotect");
        munmap(p, 2 * PAGE_SIZE);
        return;
    }
    const int ops[] = {FUTEX_WAIT, FUTEX_WAIT_BITSET};
    for (unsigned i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
        expect(raw_syscall6(__NR_futex, (long) (p + PAGE_SIZE - 4),
                            ops[i] | FUTEX_PRIVATE_FLAG, 1, 0, 0,
                            FUTEX_BITSET_MATCH_ANY),
               -EAGAIN, "aligned word at readable page end");
        for (unsigned back = 1; back < sizeof(uint32_t); back++) {
            expect(raw_syscall6(__NR_futex, (long) (p + PAGE_SIZE - back),
                                ops[i] | FUTEX_PRIVATE_FLAG, 1, 0, 0,
                                FUTEX_BITSET_MATCH_ANY),
                   -EINVAL, "straddling word is unaligned");
        }
        expect(raw_syscall6(__NR_futex, (long) (p + PAGE_SIZE),
                            ops[i] | FUTEX_PRIVATE_FLAG, 1, 0, 0,
                            FUTEX_BITSET_MATCH_ANY),
               -EFAULT, "aligned word in inaccessible page");
    }
    expect(munmap(p, 2 * PAGE_SIZE), 0, "boundary futex munmap");
}

int main(void)
{
    int word = 1;
    struct timespec invalid_timeout = {.tv_nsec = 1000000000L};

    expect(raw_syscall6(__NR_futex, (long) &word,
                        FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0),
           -EAGAIN, "FUTEX_WAIT mismatch");
    expect(raw_syscall6(__NR_futex, (long) &word,
                        FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, 0, 0, 0,
                        FUTEX_BITSET_MATCH_ANY),
           -EAGAIN, "FUTEX_WAIT_BITSET mismatch");
    expect(raw_syscall6(__NR_futex, (long) &word,
                        FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0),
           -EINVAL, "zero bitset stays host-validated");
    expect(
        raw_syscall6(__NR_futex, (long) &word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
                     0, (long) &invalid_timeout, 0, 0),
        -EINVAL, "malformed timeout still EINVAL");
    expect(raw_syscall6(__NR_futex, (long) ((char *) &word + 1),
                        FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0),
           -EINVAL, "unaligned address stays host-validated");

    test_unresolvable_addresses();
    test_tagged_address();
    test_lazy_wait_inputs();
    test_page_boundary();
    test_matching_word_still_blocks();

    if (failures)
        return 1;
    puts("OK: non-blocking futex waits");
    return 0;
}
