/*
 * Lazy anonymous mmap regression tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Private anonymous mappings defer page-table creation and zeroing to first
 * touch. These tests pin down the guest-visible contract of that laziness:
 * huge reservations succeed and read as zeros, address reuse never leaks
 * stale bytes, host-side syscall access (read/write/futex) works on memory
 * the guest never touched, PROT_NONE stays a faulting reservation, data
 * survives PROT_NONE round trips and fork, and concurrent first touch from
 * multiple threads never loses a write to the deferred zeroing.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define BLOCK_2MIB (2ULL << 20)

#ifndef FUTEX_WAIT
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#endif

/* Largest plain anonymous RW mapping the kernel grants. On elfuse the lazy
 * path must take this well past physical memory; on real Linux the result
 * depends on the overcommit heuristic, so the tests only require >= 1 GiB
 * and probe downward.
 */
static void *map_largest(size_t *out_size)
{
    static const size_t sizes[] = {
        64ULL << 30,
        16ULL << 30,
        4ULL << 30,
        1ULL << 30,
    };
    for (unsigned i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        void *p = mmap(NULL, sizes[i], PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            *out_size = sizes[i];
            return p;
        }
    }
    return NULL;
}

static void test_huge_sparse(void)
{
    TEST("huge mmap + sparse touch");
    size_t size = 0;
    volatile uint8_t *p = map_largest(&size);
    if (!p || size < (1ULL << 30)) {
        FAIL("no >=1GiB anonymous mapping granted");
        return;
    }
    /* Sparse probes: start, one per size/8 stride, last page. All must read
     * zero and accept writes.
     */
    for (unsigned i = 0; i < 8; i++) {
        size_t off = (size / 8) * i;
        if (p[off] != 0) {
            FAIL("fresh mapping reads nonzero");
            munmap((void *) p, size);
            return;
        }
        p[off] = (uint8_t) (i + 1);
    }
    if (p[size - 1] != 0) {
        FAIL("last page reads nonzero");
        munmap((void *) p, size);
        return;
    }
    for (unsigned i = 0; i < 8; i++) {
        size_t off = (size / 8) * i;
        if (p[off] != (uint8_t) (i + 1)) {
            FAIL("sparse write lost");
            munmap((void *) p, size);
            return;
        }
    }
    if (munmap((void *) p, size) != 0) {
        FAIL("munmap");
        return;
    }
    PASS();
}

static void test_zero_reuse(void)
{
    TEST("address reuse reads zero");
    size_t size = 4ULL << 20;
    uint8_t *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap 1");
        return;
    }
    memset(p, 0xa5, size);
    munmap(p, size);
    uint8_t *q = mmap(NULL, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (q == MAP_FAILED) {
        FAIL("mmap 2");
        return;
    }
    /* The allocator typically reuses the freed range; either way no byte may
     * be nonzero. Check one page per 2MiB block plus both ends.
     */
    for (size_t off = 0; off < size; off += 4096) {
        if (q[off] != 0) {
            FAIL("stale data after reuse");
            munmap(q, size);
            return;
        }
    }
    munmap(q, size);
    PASS();
}

static void test_partial_block_reuse(void)
{
    TEST("partial-block reuse preserves neighbor");
    const size_t half = BLOCK_2MIB / 2;
    uint8_t *p = mmap(NULL, BLOCK_2MIB, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    p[17] = 0xa5;
    p[half + 17] = 0x5a;
    if (mprotect(p + half, half, PROT_READ) != 0 || munmap(p, half) != 0) {
        FAIL("split/unmap");
        munmap(p, BLOCK_2MIB);
        return;
    }

    uint8_t *q = mmap(p, half, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (q == MAP_FAILED || q != p) {
        FAIL("freed half was not reused at hint");
        if (q != MAP_FAILED)
            munmap(q, half);
        munmap(p + half, half);
        return;
    }
    if (q[17] != 0 || q[half - 1] != 0 || p[half + 17] != 0x5a) {
        FAIL("partial zero clobbered neighbor or leaked stale data");
        munmap(q, half);
        munmap(p + half, half);
        return;
    }
    munmap(q, half);
    munmap(p + half, half);
    PASS();
}

static void test_fork_clean_reuse(void)
{
    TEST("fork child sees zero on clean-block reuse");
    uint8_t *p = mmap(NULL, BLOCK_2MIB, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap 1");
        return;
    }
    memset(p, 0xcc, BLOCK_2MIB);
    if (munmap(p, BLOCK_2MIB) != 0) {
        FAIL("munmap");
        return;
    }
    uint8_t *q = mmap(p, BLOCK_2MIB, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (q == MAP_FAILED) {
        FAIL("mmap 2");
        return;
    }
    pid_t pid = fork();
    if (pid == 0) {
        if (q[0] != 0 || q[BLOCK_2MIB - 1] != 0)
            _exit(1);
        q[123] = 0x77;
        _exit(q[124] == 0 ? 0 : 2);
    }
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) != pid || !WIFEXITED(st) ||
        WEXITSTATUS(st) != 0 || q[123] != 0) {
        FAIL("fork clean-block state");
        munmap(q, BLOCK_2MIB);
        return;
    }
    munmap(q, BLOCK_2MIB);
    PASS();
}

static void test_file_overlay_reuse(void)
{
    TEST("file overlay teardown then lazy reuse");
    char path[] = "/tmp/elfuse-dirty-map.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }
    unlink(path);
    if (ftruncate(fd, BLOCK_2MIB) != 0) {
        FAIL("ftruncate");
        close(fd);
        return;
    }
    uint8_t first = 0xa7, last = 0x5c;
    if (pwrite(fd, &first, 1, 17) != 1 ||
        pwrite(fd, &last, 1, BLOCK_2MIB - 1) != 1) {
        FAIL("pwrite");
        close(fd);
        return;
    }

    uint8_t *reserve = mmap(NULL, 2 * BLOCK_2MIB, PROT_NONE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reserve == MAP_FAILED) {
        FAIL("reserve");
        close(fd);
        return;
    }
    uintptr_t aligned =
        ((uintptr_t) reserve + BLOCK_2MIB - 1) & ~(BLOCK_2MIB - 1);
    munmap(reserve, 2 * BLOCK_2MIB);
    uint8_t *target = (uint8_t *) aligned;

    uint8_t *file = mmap(target, BLOCK_2MIB, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_FIXED, fd, 0);
    if (file != target || file[17] != first || file[BLOCK_2MIB - 1] != last) {
        FAIL("file mmap");
        if (file != MAP_FAILED)
            munmap(file, BLOCK_2MIB);
        close(fd);
        return;
    }
    file[BLOCK_2MIB / 2] = 0xe1;
    if (munmap(file, BLOCK_2MIB) != 0) {
        FAIL("file munmap");
        close(fd);
        return;
    }
    close(fd);

    uint8_t *anon = mmap(target, BLOCK_2MIB, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (anon != target || anon[17] != 0 || anon[BLOCK_2MIB / 2] != 0 ||
        anon[BLOCK_2MIB - 1] != 0) {
        FAIL("stale file bytes after lazy reuse");
        if (anon != MAP_FAILED)
            munmap(anon, BLOCK_2MIB);
        return;
    }
    munmap(anon, BLOCK_2MIB);
    PASS();
}

static void test_read_into_lazy(void)
{
    TEST("read() into untouched mapping");
    size_t size = 6ULL << 20;
    uint8_t *buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int fds[2];
    if (buf == MAP_FAILED || pipe(fds) != 0) {
        FAIL("setup");
        return;
    }
    static const char msg[] = "lazy-host-access-payload";
    /* Unaligned target crossing into the mapping's third 2MiB block. */
    size_t off = (4ULL << 20) + 123;
    if (write(fds[1], msg, sizeof(msg)) != (ssize_t) sizeof(msg) ||
        read(fds[0], buf + off, sizeof(msg)) != (ssize_t) sizeof(msg)) {
        FAIL("pipe copy through untouched buffer");
        goto out;
    }
    if (memcmp(buf + off, msg, sizeof(msg)) != 0) {
        FAIL("payload corrupted");
        goto out;
    }
    /* A guest touch elsewhere in the same 2MiB block must not re-zero the
     * host-written payload (deferred-zeroing idempotence).
     */
    buf[(4ULL << 20) + 64 * 1024] = 7;
    if (memcmp(buf + off, msg, sizeof(msg)) != 0) {
        FAIL("payload clobbered by later fault in same block");
        goto out;
    }
    /* Untouched parts of the mapping still read zero. */
    for (size_t i = 0; i < 4096; i++) {
        if (buf[i] != 0) {
            FAIL("nonzero byte in untouched block");
            goto out;
        }
    }
    PASS();
out:
    close(fds[0]);
    close(fds[1]);
    munmap(buf, size);
}

static void test_write_from_lazy(void)
{
    TEST("write() from untouched mapping");
    size_t size = 2ULL << 20;
    uint8_t *src = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int fds[2];
    if (src == MAP_FAILED || pipe(fds) != 0) {
        FAIL("setup");
        return;
    }
    uint8_t back[512];
    memset(back, 0xff, sizeof(back));
    if (write(fds[1], src + 4096, sizeof(back)) != (ssize_t) sizeof(back) ||
        read(fds[0], back, sizeof(back)) != (ssize_t) sizeof(back)) {
        FAIL("pipe copy from untouched buffer");
        goto out;
    }
    for (size_t i = 0; i < sizeof(back); i++) {
        if (back[i] != 0) {
            FAIL("untouched buffer sent nonzero bytes");
            goto out;
        }
    }
    PASS();
out:
    close(fds[0]);
    close(fds[1]);
    munmap(src, size);
}

static void test_prot_none_roundtrip(void)
{
    TEST("mprotect NONE round trip keeps data");
    size_t size = 4ULL << 20;
    uint8_t *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    memset(p, 0x5c, 8192);
    p[size - 1] = 0x77;
    if (mprotect(p, size, PROT_NONE) != 0 ||
        mprotect(p, size, PROT_READ | PROT_WRITE) != 0) {
        FAIL("mprotect");
        munmap(p, size);
        return;
    }
    if (p[0] != 0x5c || p[8191] != 0x5c || p[size - 1] != 0x77 ||
        p[16384] != 0) {
        FAIL("data lost or stale bytes after round trip");
        munmap(p, size);
        return;
    }
    munmap(p, size);
    PASS();
}

static void test_reserve_commit(void)
{
    TEST("PROT_NONE reserve + mprotect commit");
    size_t size = 1ULL << 30;
    uint8_t *p = mmap(NULL, size, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("reserve");
        return;
    }
    uint8_t *slab = p + (512ULL << 20);
    if (mprotect(slab, 8ULL << 20, PROT_READ | PROT_WRITE) != 0) {
        FAIL("commit");
        munmap(p, size);
        return;
    }
    for (size_t off = 0; off < (8ULL << 20); off += 4096) {
        if (slab[off] != 0) {
            FAIL("committed slab reads nonzero");
            munmap(p, size);
            return;
        }
    }
    slab[0] = 1;
    slab[(8ULL << 20) - 1] = 2;
    if (slab[0] != 1 || slab[(8ULL << 20) - 1] != 2) {
        FAIL("committed slab write lost");
        munmap(p, size);
        return;
    }
    munmap(p, size);
    PASS();
}

static sigjmp_buf segv_jmp;

static void segv_handler(int sig)
{
    (void) sig;
    siglongjmp(segv_jmp, 1);
}

static void test_prot_none_faults(void)
{
    TEST("PROT_NONE|NORESERVE still faults");
    size_t size = 16ULL << 20;
    volatile uint8_t *p =
        mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
             -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    struct sigaction sa = {0}, old_sa;
    sa.sa_handler = segv_handler;
    sigaction(SIGSEGV, &sa, &old_sa);
    int faulted = 0;
    if (sigsetjmp(segv_jmp, 1) == 0) {
        (void) p[BLOCK_2MIB + 5];
    } else {
        faulted = 1;
    }
    sigaction(SIGSEGV, &old_sa, NULL);
    munmap((void *) p, size);
    /* A lazy materializer that ignores prot would silently hand the guest a
     * readable zero page here instead of SIGSEGV.
     */
    EXPECT_TRUE(faulted, "read from PROT_NONE reservation did not fault");
}

static void test_fork_lazy(void)
{
    TEST("fork with partially touched mapping");
    size_t size = 8ULL << 20;
    uint8_t *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    memset(p, 0x42, 4096); /* touch only block 0 */
    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork");
        munmap(p, size);
        return;
    }
    if (pid == 0) {
        /* Child: inherited data intact, untouched block reads zero and is
         * privately writable.
         */
        if (p[0] != 0x42 || p[4095] != 0x42)
            _exit(1);
        if (p[4ULL << 20] != 0)
            _exit(2);
        p[4ULL << 20] = 0x99;
        if (p[(4ULL << 20) + 1] != 0)
            _exit(3);
        _exit(0);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        FAIL("child saw wrong memory");
        munmap(p, size);
        return;
    }
    /* Parent: child's private write must not leak back. */
    if (p[4ULL << 20] != 0) {
        FAIL("child write leaked into parent");
        munmap(p, size);
        return;
    }
    munmap(p, size);
    PASS();
}

static void test_futex_untouched(void)
{
    TEST("futex on untouched mapping");
    size_t size = 4ULL << 20;
    uint8_t *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    uint32_t *word = (uint32_t *) (p + (2ULL << 20) + 256);
    /* WAKE on never-touched memory: no waiters, must not fault. */
    long r = syscall(SYS_futex, word, FUTEX_WAKE, 1, NULL, NULL, 0);
    if (r != 0) {
        FAIL("FUTEX_WAKE on untouched word");
        munmap(p, size);
        return;
    }
    /* WAIT with expected=1: the word reads as zero, so EAGAIN. */
    r = syscall(SYS_futex, word, FUTEX_WAIT, 1, NULL, NULL, 0);
    if (!(r == -1 && errno == EAGAIN)) {
        FAIL("FUTEX_WAIT did not read zero from untouched word");
        munmap(p, size);
        return;
    }
    munmap(p, size);
    PASS();
}

/* Concurrent first touch: every thread writes its own slot in the same fresh
 * 2MiB block, racing the deferred zeroing. A materializer that re-zeros an
 * already-populated block loses some slots.
 */
#define MT_THREADS 4
#define MT_ITERS 64

typedef struct {
    uint8_t *base;
    int idx;
    pthread_barrier_t *barrier;
} mt_arg_t;

static void *mt_touch(void *argp)
{
    mt_arg_t *a = argp;
    pthread_barrier_wait(a->barrier);
    a->base[a->idx * 64] = (uint8_t) (a->idx + 1);
    /* Also touch a private block so several materializations race. */
    a->base[BLOCK_2MIB * (unsigned) (a->idx + 1) + 17] =
        (uint8_t) (0x10 + a->idx);
    return NULL;
}

static void test_mt_first_touch(void)
{
    TEST("concurrent first touch");
    for (int iter = 0; iter < MT_ITERS; iter++) {
        size_t size = BLOCK_2MIB * (MT_THREADS + 2);
        uint8_t *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            FAIL("mmap");
            return;
        }
        pthread_barrier_t barrier;
        pthread_barrier_init(&barrier, NULL, MT_THREADS);
        pthread_t th[MT_THREADS];
        mt_arg_t args[MT_THREADS];
        for (int i = 0; i < MT_THREADS; i++) {
            args[i] = (mt_arg_t) {p, i, &barrier};
            if (pthread_create(&th[i], NULL, mt_touch, &args[i]) != 0) {
                FAIL("pthread_create");
                return;
            }
        }
        for (int i = 0; i < MT_THREADS; i++)
            pthread_join(th[i], NULL);
        pthread_barrier_destroy(&barrier);
        for (int i = 0; i < MT_THREADS; i++) {
            if (p[i * 64] != (uint8_t) (i + 1) ||
                p[BLOCK_2MIB * (unsigned) (i + 1) + 17] !=
                    (uint8_t) (0x10 + i)) {
                FAIL("write lost to concurrent materialization");
                munmap(p, size);
                return;
            }
        }
        munmap(p, size);
    }
    PASS();
}

typedef struct {
    uint8_t *base;
    size_t half;
    int idx;
    pthread_barrier_t *barrier;
    int *error;
} claim_race_arg_t;

static void *claim_race_touch(void *argp)
{
    claim_race_arg_t *a = argp;
    pthread_barrier_wait(a->barrier);
    a->base[64 * (unsigned) a->idx] = (uint8_t) (a->idx + 1);
    return NULL;
}

static void *claim_race_mutate(void *argp)
{
    claim_race_arg_t *a = argp;
    uint8_t *neighbor = a->base + a->half;
    uint8_t *hole = neighbor + 4096;
    pthread_barrier_wait(a->barrier);
    for (int i = 0; i < 16; i++) {
        if (mprotect(neighbor, a->half, PROT_NONE) != 0 ||
            mprotect(neighbor, a->half, PROT_READ) != 0 ||
            munmap(hole, 4096) != 0) {
            *a->error = 1;
            return NULL;
        }
        void *r = mmap(hole, 4096, PROT_READ,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (r != hole) {
            *a->error = 1;
            return NULL;
        }
    }
    return NULL;
}

static void test_claim_mutation_race(void)
{
    TEST("first-touch claim vs adjacent mutations");
    const size_t half = BLOCK_2MIB / 2;
    uint8_t *p = mmap(NULL, BLOCK_2MIB, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    p[half + 17] = 0x6d;
    if (mprotect(p + half, half, PROT_READ) != 0 || munmap(p, half) != 0) {
        FAIL("split/unmap");
        munmap(p, BLOCK_2MIB);
        return;
    }
    uint8_t *q = mmap(p, half, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (q != p) {
        FAIL("reuse");
        if (q != MAP_FAILED)
            munmap(q, half);
        munmap(p + half, half);
        return;
    }

    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, MT_THREADS + 1);
    pthread_t workers[MT_THREADS], mutator;
    claim_race_arg_t args[MT_THREADS + 1];
    int error = 0;
    for (int i = 0; i < MT_THREADS; i++) {
        args[i] = (claim_race_arg_t) {q, half, i, &barrier, &error};
        pthread_create(&workers[i], NULL, claim_race_touch, &args[i]);
    }
    args[MT_THREADS] = (claim_race_arg_t) {q, half, 0, &barrier, &error};
    pthread_create(&mutator, NULL, claim_race_mutate, &args[MT_THREADS]);
    for (int i = 0; i < MT_THREADS; i++)
        pthread_join(workers[i], NULL);
    pthread_join(mutator, NULL);
    pthread_barrier_destroy(&barrier);

    for (int i = 0; i < MT_THREADS; i++) {
        if (q[64 * (unsigned) i] != (uint8_t) (i + 1))
            error = 1;
    }
    if (p[half + 17] != 0x6d)
        error = 1;
    munmap(q, half);
    munmap(p + half, half);
    if (error) {
        FAIL("claim/mutation race corrupted data");
        return;
    }
    PASS();
}

static void test_adjacent_region_extension(void)
{
    TEST("adjacent fast-mmap region extension");
    enum { N_PAGES = 64 };
    uint8_t *pages[N_PAGES];
    int allocated = 0;
    bool ok = true;

    for (int i = 0; i < N_PAGES; i++) {
        pages[i] = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pages[i] == MAP_FAILED) {
            ok = false;
            break;
        }
        allocated++;
        pages[i][0] = (uint8_t) (i + 1);
    }
    for (int i = 0; ok && i < allocated; i++) {
        if (pages[i][0] != (uint8_t) (i + 1))
            ok = false;
    }
    for (int i = 0; i < allocated; i++)
        munmap(pages[i], 4096);

    if (!ok) {
        FAIL("adjacent lazy mappings did not materialize independently");
        return;
    }
    PASS();
}

int main(void)
{
    test_huge_sparse();
    test_zero_reuse();
    test_partial_block_reuse();
    test_fork_clean_reuse();
    test_file_overlay_reuse();
    test_read_into_lazy();
    test_write_from_lazy();
    test_prot_none_roundtrip();
    test_reserve_commit();
    test_prot_none_faults();
    test_fork_lazy();
    test_futex_untouched();
    test_mt_first_touch();
    test_claim_mutation_race();
    test_adjacent_region_extension();

    SUMMARY("test-mmap-lazy");
    return fails ? 1 : 0;
}
