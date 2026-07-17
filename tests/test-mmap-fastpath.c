/*
 * EL1 consumer-mmap fast-path integration tests.
 *
 * Run through the dedicated make target without an ELFUSE_MMAP_FASTPATH
 * override so the default-enabled configuration is exercised.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"
#include "raw-syscall.h"

int passes = 0, fails = 0;

static sigjmp_buf segv_jmp;

static inline void spin_hint(void);

static void segv_handler(int sig)
{
    (void) sig;
    siglongjmp(segv_jmp, 1);
}

static int proc_extent_for(const char *path,
                           uintptr_t needle,
                           uintptr_t *lo_out,
                           uintptr_t *hi_out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    size_t cap = 16384, used = 0;
    char *buf = malloc(cap);
    if (!buf) {
        close(fd);
        return -1;
    }
    for (;;) {
        if (used == cap - 1) {
            if (cap >= 4 * 1024 * 1024) {
                free(buf);
                close(fd);
                return -1;
            }
            size_t next_cap = cap * 2;
            char *next = realloc(buf, next_cap);
            if (!next) {
                free(buf);
                close(fd);
                return -1;
            }
            buf = next;
            cap = next_cap;
        }
        ssize_t n = read(fd, buf + used, cap - used - 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            free(buf);
            close(fd);
            return -1;
        }
        if (n == 0)
            break;
        used += (size_t) n;
    }
    close(fd);
    if (used == 0) {
        free(buf);
        return -1;
    }
    buf[used] = '\0';

    char *line = buf;
    while (*line) {
        unsigned long long lo, hi;
        if (sscanf(line, "%llx-%llx", &lo, &hi) == 2 && needle >= lo &&
            needle < hi) {
            *lo_out = (uintptr_t) lo;
            *hi_out = (uintptr_t) hi;
            free(buf);
            return 1;
        }
        char *nl = strchr(line, '\n');
        if (!nl)
            break;
        line = nl + 1;
    }
    free(buf);
    return 0;
}

static int maps_extent_for(uintptr_t needle,
                           uintptr_t *lo_out,
                           uintptr_t *hi_out)
{
    return proc_extent_for("/proc/self/maps", needle, lo_out, hi_out) == 1 ? 0
                                                                           : -1;
}

static void test_fidelity(void)
{
    TEST("unconsumed arena is absent and faults");
    struct sigaction sa = {.sa_handler = segv_handler};
    struct sigaction old_sa;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, &old_sa) != 0) {
        FAIL("sigaction");
        return;
    }

    uint8_t *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        sigaction(SIGSEGV, &old_sa, NULL);
        return;
    }
    p[0] = 0x5a; /* drains the publication through the fault-side lock */

    volatile uint8_t *unconsumed = p + 4096;
    if (sigsetjmp(segv_jmp, 1) == 0) {
        (void) *unconsumed;
        FAIL("wild read into unconsumed arena did not SIGSEGV");
        munmap(p, 4096);
        sigaction(SIGSEGV, &old_sa, NULL);
        return;
    }

    uintptr_t lo = 0, hi = 0;
    if (maps_extent_for((uintptr_t) p, &lo, &hi) < 0 || lo != (uintptr_t) p ||
        hi != (uintptr_t) p + 4096) {
        FAIL("/proc/self/maps exposed more than the consumed page");
        munmap(p, 4096);
        sigaction(SIGSEGV, &old_sa, NULL);
        return;
    }
    if (munmap(p, 4096) != 0) {
        FAIL("munmap");
        sigaction(SIGSEGV, &old_sa, NULL);
        return;
    }

    /* No syscall may intervene between munmap and this load: EL1 must have
     * invalidated the Stage-1 descriptor and completed broadcast TLBI before
     * returning, even though host region cleanup is still deferred.
     */
    if (sigsetjmp(segv_jmp, 1) == 0) {
        (void) *(volatile uint8_t *) p;
        FAIL("access immediately after munmap did not SIGSEGV");
        sigaction(SIGSEGV, &old_sa, NULL);
        return;
    }
    sigaction(SIGSEGV, &old_sa, NULL);
    PASS();
}

static void test_exhaustion_fallback(void)
{
    TEST("arena exhaustion falls back to host mmap");
    const size_t len = 80ULL << 20; /* larger than the first 64MiB arena */
    uint8_t *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("80MiB mmap");
        return;
    }
    if (p[0] != 0 || p[len - 1] != 0) {
        FAIL("fallback mapping was not zero-filled");
        munmap(p, len);
        return;
    }
    p[0] = 1;
    p[len - 1] = 2;
    if (munmap(p, len) != 0) {
        FAIL("munmap");
        return;
    }
    PASS();
}

typedef struct {
    volatile uint8_t *p;
    _Atomic int ready;
    _Atomic int go;
    _Atomic int result;
} sibling_tlbi_arg_t;

static void *sibling_tlbi_worker(void *opaque)
{
    sibling_tlbi_arg_t *arg = opaque;
    if (sigsetjmp(segv_jmp, 1) == 0) {
        (void) arg->p[0]; /* seed a translation on this sibling vCPU */
        atomic_store_explicit(&arg->ready, 1, memory_order_release);
        while (!atomic_load_explicit(&arg->go, memory_order_acquire))
            spin_hint();
        (void) arg->p[0];
        atomic_store_explicit(&arg->result, -1, memory_order_release);
    } else {
        atomic_store_explicit(&arg->result, 1, memory_order_release);
    }
    return NULL;
}

static const char *run_sibling_tlbi(size_t len, size_t materialize_stride)
{
    struct sigaction sa = {.sa_handler = segv_handler};
    struct sigaction old_sa;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, &old_sa) != 0)
        return "sigaction";

    volatile uint8_t *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        sigaction(SIGSEGV, &old_sa, NULL);
        return "mmap";
    }

    for (size_t off = 0; off < len; off += materialize_stride)
        p[off] = (uint8_t) (off >> 21);

    sibling_tlbi_arg_t arg = {.p = p};
    pthread_t worker;
    if (pthread_create(&worker, NULL, sibling_tlbi_worker, &arg) != 0) {
        munmap((void *) p, len);
        sigaction(SIGSEGV, &old_sa, NULL);
        return "pthread_create";
    }
    while (!atomic_load_explicit(&arg.ready, memory_order_acquire))
        spin_hint();

    if (munmap((void *) p, len) != 0) {
        atomic_store_explicit(&arg.go, 1, memory_order_release);
        pthread_join(worker, NULL);
        sigaction(SIGSEGV, &old_sa, NULL);
        return "munmap";
    }

    /* No syscall may intervene here: the sibling must observe EL1's
     * inner-shareable invalidation before host metadata removal.
     */
    atomic_store_explicit(&arg.go, 1, memory_order_release);
    int result;
    while (!(result = atomic_load_explicit(&arg.result, memory_order_acquire)))
        spin_hint();
    pthread_join(worker, NULL);
    sigaction(SIGSEGV, &old_sa, NULL);
    return result < 0 ? "stale sibling translation survived TLBI" : NULL;
}

static void test_l3_range_tlbi(void)
{
    TEST("RVALE1IS invalidates sibling L3 translation");
    const char *error = run_sibling_tlbi(16ULL << 10, 4096);
    if (error) {
        FAIL(error);
        return;
    }
    PASS();
}

static void test_large_l2_range_tlbi(void)
{
    TEST("SCALE=3 RVALE1IS invalidates sibling L2 translation");
    const size_t len = 320ULL << 20; /* exceeds SCALE=2's 256MiB maximum */
    const char *error = run_sibling_tlbi(len, 2ULL << 20);
    if (error) {
        FAIL(error);
        return;
    }
    PASS();
}

typedef struct {
    _Atomic uintptr_t ptr;
    _Atomic int ready;
    _Atomic int done;
    _Atomic int release;
} handoff_arg_t;

static inline void spin_hint(void)
{
    __asm__ volatile("yield" ::: "memory");
}

static void *handoff_worker(void *opaque)
{
    handoff_arg_t *arg = opaque;
    uint8_t *warm = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (warm == MAP_FAILED) {
        atomic_store_explicit(&arg->done, -1, memory_order_release);
        atomic_store_explicit(&arg->ready, 1, memory_order_release);
        return NULL;
    }
    warm[0] = 1;
    atomic_store_explicit(&arg->ready, 1, memory_order_release);
    uintptr_t ptr;
    while (!(ptr = atomic_load_explicit(&arg->ptr, memory_order_acquire)))
        spin_hint();
    int rc = munmap((void *) ptr, 4096);
    atomic_store_explicit(&arg->done, rc == 0 ? 1 : -1, memory_order_release);
    while (!atomic_load_explicit(&arg->release, memory_order_acquire))
        spin_hint();
    munmap(warm, 4096);
    return NULL;
}

static void test_cross_vcpu_handoff(void)
{
    TEST("cross-vCPU mmap publication then munmap retirement");
    struct sigaction sa = {.sa_handler = segv_handler};
    struct sigaction old_sa;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, &old_sa) != 0) {
        FAIL("sigaction");
        return;
    }

    handoff_arg_t arg = {0};
    pthread_t worker;
    if (pthread_create(&worker, NULL, handoff_worker, &arg) != 0) {
        FAIL("pthread_create");
        sigaction(SIGSEGV, &old_sa, NULL);
        return;
    }
    while (!atomic_load_explicit(&arg.ready, memory_order_acquire))
        spin_hint();

    /* Keep the worker alive after munmap so its next thread-exit syscall cannot
     * drain either ring. The fault below is the first natural VM exit after A's
     * mmap publication and B's retirement.
     */
    uint8_t *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        atomic_store_explicit(&arg.release, 1, memory_order_release);
        pthread_join(worker, NULL);
        FAIL("mmap");
        sigaction(SIGSEGV, &old_sa, NULL);
        return;
    }
    atomic_store_explicit(&arg.ptr, (uintptr_t) p, memory_order_release);
    int done;
    while (!(done = atomic_load_explicit(&arg.done, memory_order_acquire)))
        spin_hint();

    int faulted = 0;
    if (done > 0 && sigsetjmp(segv_jmp, 1) == 0)
        (void) *(volatile uint8_t *) p;
    else if (done > 0)
        faulted = 1;

    atomic_store_explicit(&arg.release, 1, memory_order_release);
    pthread_join(worker, NULL);
    sigaction(SIGSEGV, &old_sa, NULL);
    if (done < 0) {
        FAIL("worker munmap");
        return;
    }
    if (!faulted) {
        FAIL("retired cross-vCPU mapping remained accessible");
        return;
    }
    PASS();
}

static void test_mixed_size_recycled_va_reads_zero(void)
{
    TEST("recycled mixed-size VA reads zero");
    static const size_t sizes[] = {
        64ULL << 10, 3ULL << 20,  20ULL << 10, 1ULL << 20,
        5ULL << 20,  96ULL << 10, 2ULL << 20,  512ULL << 10,
    };

    for (int i = 0; i < 128; i++) {
        size_t len = sizes[i % (int) (sizeof(sizes) / sizeof(sizes[0]))];
        volatile uint8_t *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            FAIL("mmap");
            return;
        }
        if (p[0] != 0 || p[len / 2] != 0 || p[len - 1] != 0) {
            munmap((void *) p, len);
            FAIL("recycled VA exposed stale bytes");
            return;
        }
        p[0] = (uint8_t) (i + 1);
        p[len / 2] = (uint8_t) (i ^ 0x5a);
        p[len - 1] = (uint8_t) (i ^ 0xa5);
        if (munmap((void *) p, len) != 0) {
            FAIL("munmap");
            return;
        }
    }
    PASS();
}

static void test_repeated_munmap_does_not_alias(void)
{
    TEST("repeated munmap does not alias two live mappings");
    const size_t len = 64ULL << 10;
    volatile uint8_t *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("initial mmap");
        return;
    }
    p[0] = 1;
    if (munmap((void *) p, len) != 0 || munmap((void *) p, len) != 0) {
        FAIL("repeated munmap");
        return;
    }

    /* This fault drains both retire records. Only the first still has region
     * coverage, so only it may return VA to the allocator; the second must not
     * hand the same extent out a second time.
     */
    volatile uint8_t *bridge = mmap(NULL, len, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (bridge == MAP_FAILED) {
        FAIL("bridge mmap");
        return;
    }
    bridge[0] = 2;

    volatile uint8_t *a = mmap(NULL, len, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    volatile uint8_t *b = mmap(NULL, len, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (a == MAP_FAILED || b == MAP_FAILED || a == b) {
        if (a != MAP_FAILED)
            munmap((void *) a, len);
        if (b != MAP_FAILED && b != a)
            munmap((void *) b, len);
        munmap((void *) bridge, len);
        FAIL("duplicate extent allocation");
        return;
    }
    a[0] = 0x31;
    b[0] = 0x42;
    if (a[0] != 0x31 || b[0] != 0x42) {
        FAIL("distinct mappings aliased");
        return;
    }
    munmap((void *) a, len);
    munmap((void *) b, len);
    munmap((void *) bridge, len);
    PASS();
}

typedef struct {
    _Atomic uintptr_t ptr;
    _Atomic int state;
    _Atomic int release;
} observer_arg_t;

enum {
    OBSERVER_STARTING,
    OBSERVER_MAPPED,
    OBSERVER_UNMAP_REQUESTED,
    OBSERVER_UNMAPPED,
    OBSERVER_MMAP_FAILED = -1,
    OBSERVER_MUNMAP_FAILED = -2,
};

static void *observer_worker(void *opaque)
{
    observer_arg_t *arg = opaque;
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        atomic_store_explicit(&arg->state, OBSERVER_MMAP_FAILED,
                              memory_order_release);
        return NULL;
    }

    atomic_store_explicit(&arg->ptr, (uintptr_t) p, memory_order_relaxed);
    atomic_store_explicit(&arg->state, OBSERVER_MAPPED, memory_order_release);
    while (atomic_load_explicit(&arg->state, memory_order_acquire) ==
           OBSERVER_MAPPED)
        spin_hint();

    if (munmap(p, 4096) != 0) {
        atomic_store_explicit(&arg->state, OBSERVER_MUNMAP_FAILED,
                              memory_order_release);
        return NULL;
    }
    atomic_store_explicit(&arg->state, OBSERVER_UNMAPPED, memory_order_release);
    while (!atomic_load_explicit(&arg->release, memory_order_acquire))
        spin_hint();
    return NULL;
}

static int observer_wait_for_state(observer_arg_t *arg, int wanted)
{
    int state;
    do {
        state = atomic_load_explicit(&arg->state, memory_order_acquire);
        spin_hint();
    } while (state >= 0 && state != wanted);
    return state;
}

static void observer_release(observer_arg_t *arg, pthread_t worker)
{
    atomic_store_explicit(&arg->release, 1, memory_order_release);
    pthread_join(worker, NULL);
}

static void test_msync_observes_fastpath(void)
{
    TEST("msync observes sibling fast mmap/munmap");
    observer_arg_t arg = {0};
    pthread_t worker;
    if (pthread_create(&worker, NULL, observer_worker, &arg) != 0) {
        FAIL("pthread_create");
        return;
    }
    if (observer_wait_for_state(&arg, OBSERVER_MAPPED) != OBSERVER_MAPPED) {
        pthread_join(worker, NULL);
        FAIL("worker mmap");
        return;
    }

    void *p = (void *) atomic_load_explicit(&arg.ptr, memory_order_relaxed);
    bool mapped_visible = msync(p, 4096, MS_SYNC) == 0;
    atomic_store_explicit(&arg.state, OBSERVER_UNMAP_REQUESTED,
                          memory_order_release);
    int state = observer_wait_for_state(&arg, OBSERVER_UNMAPPED);
    errno = 0;
    bool unmapped_visible = state == OBSERVER_UNMAPPED &&
                            msync(p, 4096, MS_SYNC) == -1 && errno == ENOMEM;

    observer_release(&arg, worker);
    if (!mapped_visible || !unmapped_visible) {
        FAIL("msync used stale fast-path VMA metadata");
        return;
    }
    PASS();
}

static bool proc_paths_contain(uintptr_t address, bool expected)
{
    char pid_maps[64], pid_smaps[64];
    snprintf(pid_maps, sizeof(pid_maps), "/proc/%ld/maps", (long) getpid());
    snprintf(pid_smaps, sizeof(pid_smaps), "/proc/%ld/smaps", (long) getpid());
    const char *paths[] = {
        "/proc/self/maps",
        pid_maps,
        "/proc/self/smaps",
        pid_smaps,
    };

    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        uintptr_t lo = 0, hi = 0;
        int found = proc_extent_for(paths[i], address, &lo, &hi);
        if (found < 0 || (found == 1) != expected)
            return false;
    }
    return true;
}

static void test_proc_observes_fastpath(void)
{
    TEST("maps/smaps observe sibling fast mmap/munmap");
    observer_arg_t arg = {0};
    pthread_t worker;
    if (pthread_create(&worker, NULL, observer_worker, &arg) != 0) {
        FAIL("pthread_create");
        return;
    }
    if (observer_wait_for_state(&arg, OBSERVER_MAPPED) != OBSERVER_MAPPED) {
        pthread_join(worker, NULL);
        FAIL("worker mmap");
        return;
    }

    uintptr_t p = atomic_load_explicit(&arg.ptr, memory_order_relaxed);
    bool mapped_visible = proc_paths_contain(p, true);
    atomic_store_explicit(&arg.state, OBSERVER_UNMAP_REQUESTED,
                          memory_order_release);
    int state = observer_wait_for_state(&arg, OBSERVER_UNMAPPED);
    bool unmapped_visible =
        state == OBSERVER_UNMAPPED && proc_paths_contain(p, false);

    observer_release(&arg, worker);
    if (!mapped_visible || !unmapped_visible) {
        FAIL("maps/smaps used stale fast-path VMA metadata");
        return;
    }
    PASS();
}

typedef struct {
    _Atomic int ready;
    _Atomic int go;
    _Atomic int stop;
    _Atomic int failed;
    _Atomic unsigned churned;
} wx_churn_arg_t;

static void *wx_churn_worker(void *opaque)
{
    wx_churn_arg_t *arg = opaque;
    atomic_fetch_add_explicit(&arg->ready, 1, memory_order_release);
    while (!atomic_load_explicit(&arg->go, memory_order_acquire))
        spin_hint();

    while (!atomic_load_explicit(&arg->stop, memory_order_acquire)) {
        volatile uint8_t *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            atomic_store_explicit(&arg->failed, 1, memory_order_release);
            break;
        }
        p[0] = 0x5a;
        if (munmap((void *) p, 4096) != 0) {
            atomic_store_explicit(&arg->failed, 1, memory_order_release);
            break;
        }
        atomic_fetch_add_explicit(&arg->churned, 1, memory_order_release);
    }
    return NULL;
}

static void test_wx_toggle_during_fastpath_churn(void)
{
    TEST("W^X toggle during sibling fast mmap churn");
    enum { NTHREADS = 4, NCYCLES = 256 };
    pthread_t workers[NTHREADS];
    wx_churn_arg_t arg = {0};
    int made = 0;
    for (; made < NTHREADS; made++) {
        if (pthread_create(&workers[made], NULL, wx_churn_worker, &arg) != 0)
            break;
    }
    if (made != NTHREADS) {
        atomic_store_explicit(&arg.go, 1, memory_order_release);
        atomic_store_explicit(&arg.stop, 1, memory_order_release);
        for (int i = 0; i < made; i++)
            pthread_join(workers[i], NULL);
        FAIL("pthread_create");
        return;
    }

    while (atomic_load_explicit(&arg.ready, memory_order_acquire) != NTHREADS)
        spin_hint();

    uint32_t *code = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    bool ok = code != MAP_FAILED;
    if (ok) {
        code[0] = 0x52800020u; /* mov w0, #1 */
        code[1] = 0xd65f03c0u; /* ret */
        __builtin___clear_cache((char *) code, (char *) (code + 2));
        uint32_t (*fn)(void) = (uint32_t (*)(void)) code;
        ok = mprotect(code, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0 &&
             fn() == 1;

        atomic_store_explicit(&arg.go, 1, memory_order_release);
        while (!atomic_load_explicit(&arg.failed, memory_order_acquire) &&
               atomic_load_explicit(&arg.churned, memory_order_acquire) < 64)
            spin_hint();

        for (uint32_t i = 0; i < NCYCLES && ok; i++) {
            uint32_t imm = (i % 0xfffu) + 1;
            code[0] = 0x52800000u | (imm << 5);
            code[1] = 0xd65f03c0u;
            __builtin___clear_cache((char *) code, (char *) (code + 2));
            if (fn() != imm)
                ok = false;
        }
    } else {
        atomic_store_explicit(&arg.go, 1, memory_order_release);
    }

    atomic_store_explicit(&arg.stop, 1, memory_order_release);
    for (int i = 0; i < NTHREADS; i++)
        pthread_join(workers[i], NULL);
    if (code != MAP_FAILED)
        munmap(code, 4096);

    if (!ok || atomic_load_explicit(&arg.failed, memory_order_acquire) ||
        atomic_load_explicit(&arg.churned, memory_order_acquire) < 64) {
        FAIL("W^X toggle or mmap churn failed");
        return;
    }
    PASS();
}

typedef struct {
    int iterations;
    _Atomic int *failed;
} storm_arg_t;

static void *storm_worker(void *opaque)
{
    storm_arg_t *arg = opaque;
    for (int i = 0; i < arg->iterations; i++) {
        size_t len = (size_t) ((i & 7) + 1) * 4096;
        uint8_t *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            __atomic_store_n(arg->failed, 1, __ATOMIC_RELAXED);
            break;
        }
        p[0] = (uint8_t) i;
        p[len - 1] = (uint8_t) (i ^ 0x5a);
        if (munmap(p, len) != 0) {
            __atomic_store_n(arg->failed, 1, __ATOMIC_RELAXED);
            break;
        }
    }
    return NULL;
}

static void test_mt_storm_and_fork_exec(void)
{
    TEST("multi-vCPU mmap storm with fork+exec revocation");
    enum { NTHREADS = 8 };
    pthread_t threads[NTHREADS];
    _Atomic int failed = 0;
    storm_arg_t arg = {.iterations = 400, .failed = &failed};

    int made = 0;
    for (; made < NTHREADS; made++) {
        if (pthread_create(&threads[made], NULL, storm_worker, &arg) != 0) {
            __atomic_store_n(&failed, 1, __ATOMIC_RELAXED);
            break;
        }
    }

    pid_t pid = fork();
    if (pid == 0) {
        char *const argv[] = {(char *) "/proc/self/exe", NULL};
        char *const envp[] = {(char *) "ELFUSE_FASTPATH_EXEC_CHILD=1", NULL};
        execve(argv[0], argv, envp);
        _exit(111);
    }
    if (pid < 0)
        __atomic_store_n(&failed, 1, __ATOMIC_RELAXED);

    for (int i = 0; i < made; i++)
        pthread_join(threads[i], NULL);

    if (pid > 0) {
        int status = 0;
        if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)
            __atomic_store_n(&failed, 1, __ATOMIC_RELAXED);
    }

    /* The parent's arenas were revoked for the fork snapshot. This pair makes
     * the first call take the generation fallback and verifies service resumes.
     */
    uint8_t *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        __atomic_store_n(&failed, 1, __ATOMIC_RELAXED);
    else {
        p[0] = 7;
        munmap(p, 4096);
    }

    if (__atomic_load_n(&failed, __ATOMIC_RELAXED)) {
        FAIL("storm/fork/exec worker failure");
        return;
    }
    PASS();
}

static int stats_stream(size_t len, int iterations, bool release_each)
{
    for (int i = 0; i < iterations; i++) {
        void *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            return 1;
        if (release_each && munmap(p, len) != 0)
            return 1;
    }
    return 0;
}

static int stats_mixed_churn(void)
{
    static const size_t sizes[] = {
        64ULL << 10, 3ULL << 20,  20ULL << 10, 1ULL << 20,
        5ULL << 20,  96ULL << 10, 2ULL << 20,  512ULL << 10,
    };
    for (int i = 0; i < 160; i++) {
        size_t len = sizes[i % (int) (sizeof(sizes) / sizeof(sizes[0]))];
        volatile uint8_t *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            return 1;
        if (p[0] != 0 || p[len - 1] != 0)
            return 1;
        p[0] = 1;
        p[len - 1] = 2;
        if (munmap((void *) p, len) != 0)
            return 1;
    }
    return 0;
}

static int stats_large_materialized(void)
{
    const size_t len = 32ULL << 30;
    volatile uint8_t *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return 1;
    p[0] = 1;
    return munmap((void *) p, len) != 0;
}

static int stats_fork_no_topup(void)
{
    /* Leave exactly half of the initial 64 MiB arena free. The 32 MiB
     * registration becomes the low-water mark, so the ordinary mmap lock
     * acquire would speculatively refill immediately before fork revokes all
     * arenas.
     */
    void *p = mmap(NULL, 32ULL << 20, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return 1;

    pid_t pid = fork();
    if (pid == 0)
        _exit(0);
    if (pid < 0)
        return 1;

    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return 1;
    return 0;
}

static int stats_invalid_futex(void)
{
    uint32_t *words = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (words == MAP_FAILED)
        return 1;

    long rc = raw_syscall6(__NR_futex, (long) words, 127, 0, 0, 0, 0);
    if (rc != -38)
        return 1;
    rc = raw_syscall6(__NR_futex, (long) words, FUTEX_WAIT_BITSET, 0, 0, 0, 0);
    if (rc != -22)
        return 1;
    rc = raw_syscall6(__NR_futex, (long) words, FUTEX_CMP_REQUEUE, 0, 0,
                      (long) ((uint8_t *) words + 1), 0);
    if (rc != -22)
        return 1;
    rc = raw_syscall6(__NR_futex, (long) words, FUTEX_WAKE_OP, 0, 0,
                      (long) (words + 1), 5L << 28);
    if (rc != -38)
        return 1;

    return munmap(words, 4096) != 0;
}

static int run_observer_semantics(void)
{
    test_msync_observes_fastpath();
    test_wx_toggle_during_fastpath_churn();
    test_proc_observes_fastpath();
    return fails != 0;
}

static int run_stats_case(const char *name)
{
    if (strcmp(name, "observer-semantics") == 0)
        return run_observer_semantics();
    if (strcmp(name, "ring-full") == 0)
        return stats_stream(64ULL << 10, 40, false);
    if (strcmp(name, "np2-10m") == 0)
        return stats_stream(10ULL << 20, 96, false);
    if (strcmp(name, "np2-48m") == 0)
        return stats_stream(48ULL << 20, 48, false);
    if (strcmp(name, "np2-100m") == 0)
        return stats_stream(100ULL << 20, 30, false);
    if (strcmp(name, "escalation") == 0) {
        if (stats_stream(10ULL << 20, 48, false) != 0)
            return 1;
        return stats_stream(512ULL << 20, 3, false);
    }
    if (strcmp(name, "giant-guard") == 0) {
        if (stats_stream(10ULL << 20, 32, false) != 0)
            return 1;
        for (int i = 0; i < 6; i++) {
            if (stats_stream(2ULL << 30, 1, false) != 0 ||
                stats_stream(10ULL << 20, 1, false) != 0)
                return 1;
        }
        return 0;
    }
    if (strcmp(name, "adaptive-small") == 0)
        return stats_stream(64ULL << 10, 1100, false);
    if (strcmp(name, "adaptive-retention") == 0) {
        if (stats_stream(64ULL << 10, 1100, false) != 0)
            return 1;

        /* The first request selects a 16GiB arena, the next 32 consume it, and
         * the last forces a capacity rollover that must retain the target.
         */
        return stats_stream(500ULL << 20, 34, false);
    }
    if (strcmp(name, "adaptive-rewind-growth") == 0)

        /* The first 64MiB arena holds eight 8MiB mappings. The ninth mmap takes
         * the capacity fallback after the matching munmaps let host drain
         * rewind the arena; refill must grow it to the 32-entry target instead
         * of retaining an arena that will miss every eight calls.
         */
        return stats_stream(8ULL << 20, 41, true);
    if (strcmp(name, "recycle") == 0)
        return stats_stream(64ULL << 10, 6000, true);
    if (strcmp(name, "mixed-churn") == 0)
        return stats_mixed_churn();
    if (strcmp(name, "large-materialized") == 0)
        return stats_large_materialized();
    if (strcmp(name, "fork-no-topup") == 0)
        return stats_fork_no_topup();
    if (strcmp(name, "invalid-futex") == 0)
        return stats_invalid_futex();
    return 2;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--observer-semantics") == 0)
        return run_observer_semantics();
    if (argc == 2 && strncmp(argv[1], "--stats-", 8) == 0)
        return run_stats_case(argv[1] + 8);

    if (getenv("ELFUSE_FASTPATH_EXEC_CHILD")) {
        uint8_t *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            return 1;
        p[0] = 0xa5;
        return p[0] == 0xa5 ? 0 : 1;
    }

    test_fidelity();
    test_exhaustion_fallback();
    test_l3_range_tlbi();
    test_large_l2_range_tlbi();
    test_cross_vcpu_handoff();
    test_mixed_size_recycled_va_reads_zero();
    test_repeated_munmap_does_not_alias();
    run_observer_semantics();
    test_mt_storm_and_fork_exec();

    printf("\ntest-mmap-fastpath: %d passed, %d failed - %s\n", passes, fails,
           fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
