/*
 * EL1 consumer-mmap fast-path integration tests.
 *
 * Run through the dedicated make target without an ELFUSE_MMAP_FASTPATH
 * override so the default-enabled configuration is exercised.
 */

#include <fcntl.h>
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

int passes = 0, fails = 0;

static sigjmp_buf segv_jmp;

static void segv_handler(int sig)
{
    (void) sig;
    siglongjmp(segv_jmp, 1);
}

static int maps_extent_for(uintptr_t needle,
                           uintptr_t *lo_out,
                           uintptr_t *hi_out)
{
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0)
        return -1;
    char buf[16384];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';

    char *line = buf;
    while (*line) {
        unsigned long long lo, hi;
        if (sscanf(line, "%llx-%llx", &lo, &hi) == 2 && needle >= lo &&
            needle < hi) {
            *lo_out = (uintptr_t) lo;
            *hi_out = (uintptr_t) hi;
            return 0;
        }
        char *nl = strchr(line, '\n');
        if (!nl)
            break;
        line = nl + 1;
    }
    return -1;
}

static void test_fidelity(void)
{
    TEST("unconsumed arena is absent and faults");
    struct sigaction sa = {.sa_handler = segv_handler};
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        FAIL("sigaction");
        return;
    }

    uint8_t *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    p[0] = 0x5a; /* drains the publication through the fault-side lock */

    volatile uint8_t *unconsumed = p + 4096;
    if (sigsetjmp(segv_jmp, 1) == 0) {
        (void) *unconsumed;
        FAIL("wild read into unconsumed arena did not SIGSEGV");
        munmap(p, 4096);
        return;
    }

    uintptr_t lo = 0, hi = 0;
    if (maps_extent_for((uintptr_t) p, &lo, &hi) < 0 || lo != (uintptr_t) p ||
        hi != (uintptr_t) p + 4096) {
        FAIL("/proc/self/maps exposed more than the consumed page");
        munmap(p, 4096);
        return;
    }
    munmap(p, 4096);
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
    pthread_barrier_t barrier;
    uint8_t *target;
    uint8_t *source;
    int operation;
    int failed;
} fixed_tail_arg_t;

static void *fixed_tail_worker(void *opaque)
{
    fixed_tail_arg_t *arg = opaque;
    pthread_barrier_wait(&arg->barrier);
    void *p;
    if (arg->operation == 3)
        p = mremap(arg->source, 4096, 2U << 20, 0);
    else if (arg->operation == 2)
        p = mremap(arg->source, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED,
                   arg->target);
    else
        p = mmap(arg->target, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS |
                     (arg->operation ? MAP_FIXED_NOREPLACE : MAP_FIXED),
                 -1, 0);
    if (p != arg->target)
        arg->failed = 1;
    else
        memset(p, 0xab, arg->operation == 3 ? 2U << 20 : 4096);
    return NULL;
}

static int fixed_tail_child(int operation, bool sibling)
{
    fixed_tail_arg_t arg = {.operation = operation};
    arg.source = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arg.source == MAP_FAILED)
        return 1;
    pthread_t worker;
    if (pthread_barrier_init(&arg.barrier, NULL, sibling ? 2 : 1) != 0)
        return 1;
    if (sibling && pthread_create(&worker, NULL, fixed_tail_worker, &arg) != 0)
        return 1;

    uint8_t *anchor = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (anchor == MAP_FAILED)
        _exit(1);
    arg.target = anchor + (1U << 20);
    size_t length = operation == 3 ? 2U << 20 : 4096;
    if (operation == 3)
        arg.source = arg.target = anchor;
    if (sibling) {
        pthread_barrier_wait(&arg.barrier);
        pthread_join(worker, NULL);
    } else {
        fixed_tail_worker(&arg);
    }
    if (arg.failed)
        return 1;

    for (unsigned i = 0; i < 4096; i++) {
        uint8_t *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED ||
            ((uintptr_t) p >= (uintptr_t) arg.target &&
             (uintptr_t) p - (uintptr_t) arg.target < length) ||
            p[0] != 0)
            return 1;
    }
    return arg.target[0] != 0xab || arg.target[length - 1] != 0xab;
}

static void test_fixed_tail(int operation, bool sibling)
{
    TEST(sibling          ? "sibling MAP_FIXED revokes an arena tail"
         : operation == 3 ? "in-place mremap revokes an arena tail"
         : operation == 2 ? "MREMAP_FIXED revokes an arena tail"
         : operation == 1 ? "MAP_FIXED_NOREPLACE revokes an arena tail"
                          : "MAP_FIXED revokes an arena tail");
    pid_t pid = fork();
    if (pid == 0)
        _exit(fixed_tail_child(operation, sibling));
    int status;
    if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        FAIL("fixed destination overlaps a later anonymous mmap");
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

static int run_stats_case(const char *name)
{
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
    if (strcmp(name, "adaptive-decay") == 0) {
        if (stats_stream(64ULL << 10, 1100, false) != 0 ||
            stats_stream(500ULL << 20, 1, false) != 0)
            return 1;

        /* Ring-full fallbacks do not consume the arena cursor, so exceed the
         * nominal 16384 pages enough to force a true 1GiB capacity rollover.
         */
        return stats_stream(64ULL << 10, 18000, false);
    }
    if (strcmp(name, "recycle") == 0)
        return stats_stream(64ULL << 10, 6000, true);
    return 2;
}

int main(int argc, char **argv)
{
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
    test_fixed_tail(0, false);
    test_fixed_tail(1, false);
    test_fixed_tail(2, false);
    test_fixed_tail(3, false);
    test_fixed_tail(0, true);
    test_mt_storm_and_fork_exec();

    printf("\ntest-mmap-fastpath: %d passed, %d failed - %s\n", passes, fails,
           fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
