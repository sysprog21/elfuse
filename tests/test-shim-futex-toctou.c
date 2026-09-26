/*
 * test-shim-futex-toctou.c -- futex EL1 fault recovery survives concurrent
 * mprotect(PROT_NONE) of the futex word.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A sibling vCPU revokes the page while the EL1 LDTR reads the futex word. The
 * recovery path must return EFAULT rather than halting the VM.
 *
 * Two phases, because the fast path reaches that LDTR two different ways. Phase
 * one waits on a word that never matches, so every call takes the load once and
 * leaves; that is the shape the path had before it spun. Phase two waits on a
 * word that does match, so the call stays on the same LDTR for up to
 * FUTEX_EL1_SPIN_ITERS iterations, and the revoke lands mid-spin. The recovery
 * slot is pushed once and popped on whichever exit the call takes, so a spin
 * that faults on its four thousandth iteration has to unwind exactly as one
 * that faults on its first.
 *
 * Phase two also drives the third exit, the one the mid-spin attention re-read
 * takes: a signal raises attention, the spin abandons itself to the host, and
 * the call comes back as a wake, EAGAIN, EFAULT or EINTR depending on where the
 * flipper was. The point is that it comes back at all and that the VM survives,
 * not which of the four it is.
 */

#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "raw-syscall.h"

#define PAGE_SIZE 4096
#define ITERATIONS 200000

/* The word is initialized to this and the waits expect 0, so a readable page
 * always answers EAGAIN and the loop never parks.
 */
#define NEVER_EXPECTED 0x11223344

static atomic_int stop;
static void *shared_page;

static void *protect_flipper(void *arg)
{
    (void) arg;
    int prot = PROT_READ | PROT_WRITE;

    while (!atomic_load_explicit(&stop, memory_order_acquire)) {
        prot ^= (PROT_READ | PROT_WRITE);
        if (mprotect(shared_page, PAGE_SIZE, prot) != 0) {
            fprintf(stderr, "mprotect failed: %s\n", strerror(errno));
            return (void *) (uintptr_t) 1;
        }
    }
    /* Leave the page accessible at exit. */
    mprotect(shared_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    return NULL;
}

/* Phase two. The flipper owns the whole cycle so a waiter can never be left
 * parked: it restores the resting value (waiters spin), revokes the page
 * (in-flight spins fault), restores it, moves the word (spins see it), and
 * wakes anyone the host parked. A separate waker would have to write through a
 * page this thread is revoking, which is the one thing the phase cannot do.
 */
#define SPIN_RESTING 0
#define SPIN_MOVED 0x55667788
#define SPIN_ROUNDS 3000

static long spin_eagain, spin_efault, spin_woken, spin_eintr, spin_other;

static void spin_signal_handler(int signum)
{
    (void) signum;
}

static void *spin_waiter(void *arg)
{
    (void) arg;
    int r = 0;
    while (!atomic_load_explicit(&stop, memory_order_acquire)) {
        long rc = raw_futex_wait((int *) shared_page, SPIN_RESTING);
        r++;
        if (rc == 0)
            spin_woken++;
        else if (rc == -EAGAIN)
            spin_eagain++;
        else if (rc == -EFAULT)
            spin_efault++;
        else if (rc == -EINTR)
            spin_eintr++;
        else {
            /* Print the first one. This phase used to count these and say
             * nothing else, and the counter alone cannot tell a wrong errno
             * from an SVC that re-executed as a different syscall, which is
             * what the Tier A item about X8=2 turned out to be
             * (sysprog21/elfuse#379, now closed; tests/test-shim-sigreturn-x8
             * reaches the same window without a race).
             */
            if (spin_other == 0)
                fprintf(stderr, "FAIL: unexpected spin rc %ld (round %d)\n", rc,
                        r);
            spin_other++;
        }
    }
    return NULL;
}

/* Long enough that a waiter reaches the spin, short enough that the phase stays
 * quick. A busy loop rather than nanosleep so the delay does not itself become
 * a syscall the waiter races.
 */
static void spin_delay(void)
{
    for (volatile int i = 0; i < 400; i++) {
    }
}

static int run_spin_phase(void)
{
    struct sigaction sa;
    pthread_t waiter;
    int rc = 1;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = spin_signal_handler;
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        fprintf(stderr, "sigaction failed: %s\n", strerror(errno));
        return 1;
    }

    atomic_store_explicit(&stop, 0, memory_order_release);
    *(int *) shared_page = SPIN_RESTING;
    if (pthread_create(&waiter, NULL, spin_waiter, NULL) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        return 1;
    }

    for (int r = 0; r < SPIN_ROUNDS; r++) {
        *(int *) shared_page = SPIN_RESTING;
        spin_delay();

        if (r % 3 == 0)
            pthread_kill(waiter, SIGUSR1);

        if (mprotect(shared_page, PAGE_SIZE, PROT_NONE) != 0) {
            fprintf(stderr, "mprotect PROT_NONE failed: %s\n", strerror(errno));
            goto out;
        }
        spin_delay();
        if (mprotect(shared_page, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
            fprintf(stderr, "mprotect RW failed: %s\n", strerror(errno));
            goto out;
        }

        *(int *) shared_page = SPIN_MOVED;
        raw_futex_wake((int *) shared_page, 0x7fffffff);
    }
    rc = 0;

out:
    atomic_store_explicit(&stop, 1, memory_order_release);

    /* The word must not rest on the value the waiter waits for, or its last
     * call parks with nobody left to wake it.
     */
    *(int *) shared_page = SPIN_MOVED;
    raw_futex_wake((int *) shared_page, 0x7fffffff);
    pthread_join(waiter, NULL);
    return rc;
}

int main(void)
{
    pthread_t flipper;
    long eagain = 0, efault = 0, other = 0;
    void *flipper_rc;

    shared_page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (shared_page == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        return 1;
    }
    *(int *) shared_page = NEVER_EXPECTED;

    if (pthread_create(&flipper, NULL, protect_flipper, NULL) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        return 1;
    }

    for (int i = 0; i < ITERATIONS; i++) {
        long rc = raw_futex_wait((int *) shared_page, 0);
        if (rc == -EAGAIN)
            eagain++;
        else if (rc == -EFAULT)
            efault++;
        else {
            if (other == 0)
                fprintf(stderr, "FAIL: unexpected rc %ld at iteration %d\n", rc,
                        i);
            other++;
        }
    }

    atomic_store_explicit(&stop, 1, memory_order_release);
    pthread_join(flipper, &flipper_rc);
    if (flipper_rc != NULL)
        return 1;

    if (other) {
        fprintf(stderr, "FAIL: %ld unexpected returns\n", other);
        return 1;
    }

    /* Both outcomes must appear, or the race never landed and the run proved
     * nothing about the recovery path.
     */
    if (eagain == 0 || efault == 0) {
        fprintf(stderr, "FAIL: race did not land (eagain=%ld efault=%ld)\n",
                eagain, efault);
        return 1;
    }

    printf("OK: futex EL1 fault recovery (eagain=%ld efault=%ld)\n", eagain,
           efault);

    if (run_spin_phase() != 0)
        return 1;

    if (spin_other) {
        fprintf(stderr, "FAIL: %ld unexpected returns in the spin phase\n",
                spin_other);
        return 1;
    }
    if (spin_efault == 0) {
        fprintf(stderr,
                "FAIL: revoke never landed inside a spin "
                "(woken=%ld eagain=%ld eintr=%ld)\n",
                spin_woken, spin_eagain, spin_eintr);
        return 1;
    }

    printf(
        "OK: futex EL1 spin recovery (woken=%ld eagain=%ld efault=%ld "
        "eintr=%ld)\n",
        spin_woken, spin_eagain, spin_efault, spin_eintr);
    return 0;
}
