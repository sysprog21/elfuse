/*
 * Does FUTEX_REQUEUE reach a waiter parked by plain FUTEX_WAIT?
 *
 * musl's private condvar (pthread_cond_timedwait.c: lock()/unlock_requeue())
 * parks waiters with a plain FUTEX_WAIT on a per-node "barrier" word, then its
 * broadcast/handoff path uses FUTEX_REQUEUE to move those parked waiters from
 * the barrier word onto the mutex word. Plain FUTEX_WAIT once parked on a
 * Darwin address-wait queue that FUTEX_REQUEUE could not walk, and a requeue
 * that reaches nobody strands the waiter until its 100 ms polling quantum ends.
 *
 * This reproduces the pattern with raw syscalls (libc-agnostic) and measures
 * the wake latency. A correct requeue path wakes the waiter in well under the
 * poll cap; a stranded waiter only surfaces after ~100 ms.
 */

#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int futex(volatile int *u, int op, int val, void *to, int *u2, int v3)
{
    return (int) syscall(SYS_futex, u, op, val, to, u2, v3);
}

/* musl lock() barrier word: waiter blocks while *barrier == 2. */
static volatile int barrier = 2;
static volatile int mutex_word = 0;
static volatile int waiter_returned = 0;
static struct timespec t_wake;

static void *waiter_fn(void *arg)
{
    (void) arg;

    /* musl: do __wait(l,0,2,1); while (a_cas(l,0,2)); -- FUTEX_WAIT on barrier
     * expecting 2, retry while the word is still 2.
     */
    while (__atomic_load_n(&barrier, __ATOMIC_SEQ_CST) == 2) {
        int rc =
            futex(&barrier, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 2, NULL, NULL, 0);
        (void) rc; /* EAGAIN / 0 both loop back to the compare */
    }
    clock_gettime(CLOCK_MONOTONIC, &t_wake);
    __atomic_store_n(&waiter_returned, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

static double ms_since(const struct timespec *a, const struct timespec *b)
{
    return (double) (b->tv_sec - a->tv_sec) * 1e3 +
           (double) (b->tv_nsec - a->tv_nsec) / 1e6;
}

int main(void)
{
    pthread_t th;
    if (pthread_create(&th, NULL, waiter_fn, NULL) != 0) {
        printf(
            "test-osync-requeue: 0 passed, 1 failed - FAIL "
            "(pthread_create)\n");
        return 1;
    }

    /* Let the waiter reach FUTEX_WAIT. Keep this well below the difference
     * between the 100 ms polling quantum (FUTEX_OS_SYNC_POLL_CAP_NS) and the
     * pass threshold below, so a stranded waiter surfaces near the quantum, far
     * above the threshold, instead of landing on it.
     */
    usleep(10 * 1000);

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    /* musl unlock_requeue(): a_store(l,0); FUTEX_REQUEUE(l, 0, 1, r). Store
     * barrier=0 first, then requeue one waiter from barrier to mutex.
     */
    __atomic_store_n(&barrier, 0, __ATOMIC_SEQ_CST);
    int rq = futex(&barrier, FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG, 0, (void *) 1,
                   (int *) &mutex_word, 0);
    /* Then the mutex owner unlock wakes the (requeued) waiter on the mutex. */
    int wk =
        futex(&mutex_word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);

    pthread_join(th, NULL);
    double latency = ms_since(&t0, &t_wake);

    printf("test-osync-requeue: musl-style requeue wake latency\n");
    printf("  requeue rc=%d wake rc=%d\n", rq, wk);
    printf("  wake latency: %.2f ms\n", latency);

    /* A working requeue path wakes well under the 100 ms polling quantum. Allow
     * generous headroom for scheduler jitter; a stranded waiter only comes back
     * on the ~100 ms timeout. Also require the requeue or wake to have reached
     * the waiter (rq/wk > 0): if the waiter had not blocked yet, both reach
     * nobody and the waiter exits fast on its own, which would otherwise show a
     * false sub-threshold PASS.
     */
    int reached = (rq > 0) || (wk > 0);
    int pass = reached && latency < 50.0;
    printf("test-osync-requeue: %d passed, %d failed - %s\n", pass, !pass,
           pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
