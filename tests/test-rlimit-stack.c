/*
 * Test that the main stack grows on demand, up to RLIMIT_STACK
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux maps the argument block plus 128 KiB at execve and grows the stack one
 * fault at a time, for an access by the program or by a syscall acting on its
 * pointer, until the region would pass the soft limit. The limit also sizes
 * what execve accepts as arguments. Each check sets the limit in a fork child
 * and execs this binary again in the mode named by argv[1], because the limit
 * that counts is the one in force at execve.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define KIB 1024UL
#define MIB (1024UL * 1024)
#define PAGE 4096UL

/* Keep a buffer the optimizer cannot reason about, so its frame is real. */
#define KEEP(p) __asm__ volatile("" ::"r"(p) : "memory")

/* Extent of the "[stack]" line of /proc/self/maps. Returns 0, or -1. */
static int stack_range(unsigned long *lo, unsigned long *hi)
{
    char line[512];
    FILE *f = fopen("/proc/self/maps", "r");
    int rc = -1;

    while (f && fgets(line, sizeof(line), f)) {
        const char *tag = strstr(line, "[stack]");
        if (tag && (tag[7] == '\n' || tag[7] == '\0') &&
            sscanf(line, "%lx-%lx", lo, hi) == 2)
            rc = 0;
    }
    if (f)
        fclose(f);
    return rc;
}

/* Write one byte at @addr in a fork child.
 *
 * Returns the signal that killed the child, or 0.
 */
static int touch_in_child(unsigned long addr)
{
    int status = 0;
    pid_t pid = fork();
    if (pid == 0) {
        *(volatile char *) addr = 1;
        _exit(0);
    }
    if (pid < 0 || waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFSIGNALED(status) ? WTERMSIG(status) : 0;
}

static unsigned long soft_limit(void)
{
    struct rlimit rl;
    return getrlimit(RLIMIT_STACK, &rl) < 0 ? 0 : (unsigned long) rl.rlim_cur;
}

/* Each mode returns the number of the first step that went wrong, 0 if none
 * did, and that is the exit status of the image.
 */

/* The region starts small, and an access below it moves its start to the page
 * accessed, which reads as zero.
 */
static int mode_grow(void)
{
    unsigned long lo, hi, now;
    if (stack_range(&lo, &hi) < 0)
        return 100;

    if (hi - lo > MIB)
        return 1;

    *(volatile char *) (hi - 512 * KIB) = 1;
    if (stack_range(&now, &hi) < 0 || now != hi - 512 * KIB)
        return 2;

    if (*(volatile char *) (hi - 600 * KIB) != 0 ||
        stack_range(&now, &hi) < 0 || now != hi - 600 * KIB)
        return 3;
    return 0;
}

/* A syscall that writes through a pointer under the stack grows it too. */
static int mode_syscall(void)
{
    unsigned long lo, hi, now;
    int pfd[2];
    if (stack_range(&lo, &hi) < 0 || pipe(pfd) < 0 ||
        write(pfd[1], "abc", 3) != 3)
        return 100;

    char *buf = (char *) (hi - 1536 * KIB);
    if (read(pfd[0], buf, 3) != 3 || memcmp(buf, "abc", 3) != 0)
        return 1;
    if (stack_range(&now, &hi) < 0 || now != hi - 1536 * KIB)
        return 2;
    return 0;
}

/* The soft limit is the size of the region: its last byte can be reached and
 * the one below cannot, by the program or by a syscall.
 */
static int mode_edge(void)
{
    unsigned long lo, hi, limit = soft_limit();
    int zero = open("/dev/zero", O_RDONLY);
    if (stack_range(&lo, &hi) < 0 || zero < 0 || limit == 0)
        return 100;

    if (touch_in_child(hi - limit) != 0)
        return 1;
    if (touch_in_child(hi - limit - 1) != SIGSEGV)
        return 2;
    errno = 0;
    if (read(zero, (void *) (hi - limit - PAGE), PAGE) != -1 || errno != EFAULT)
        return 3;
    return 0;
}

/* With no limit the stack passes the 8 MiB a default one stops at, and a fork
 * child has what the parent wrote down there.
 */
static int mode_deep(void)
{
    unsigned long lo, hi, now;
    if (stack_range(&lo, &hi) < 0)
        return 100;

    volatile char *deep = (volatile char *) (hi - 48 * MIB);
    *deep = 0x5a;
    if (stack_range(&now, &hi) < 0 || now != hi - 48 * MIB)
        return 1;

    int status = -1;
    pid_t pid = fork();
    if (pid == 0)
        _exit(*deep == 0x5a ? 0 : 1);
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return 2;
    return 0;
}

/* A limit lowered under the size the stack already has takes nothing away and
 * stops the next growth.
 */
static int mode_lower(void)
{
    unsigned long lo, hi;
    struct rlimit rl;
    if (stack_range(&lo, &hi) < 0 || getrlimit(RLIMIT_STACK, &rl) < 0)
        return 100;

    *(volatile char *) (hi - MIB) = 1;
    rl.rlim_cur = 64 * KIB;
    if (setrlimit(RLIMIT_STACK, &rl) < 0)
        return 101;

    *(volatile char *) (hi - MIB) = 2;
    if (touch_in_child(hi - MIB - 1) != SIGSEGV)
        return 1;
    return 0;
}

/* File offset column of the "[stack]" line, or -1. */
static long stack_offset(void)
{
    char line[512];
    FILE *f = fopen("/proc/self/maps", "r");
    long offset = -1;

    while (f && fgets(line, sizeof(line), f)) {
        const char *tag = strstr(line, "[stack]");
        unsigned long lo, hi, off;
        if (tag && (tag[7] == '\n' || tag[7] == '\0') &&
            sscanf(line, "%lx-%lx %*s %lx", &lo, &hi, &off) == 3)
            offset = (long) off;
    }
    if (f)
        fclose(f);
    return offset;
}

/* What acts on a range of the grown stack acts on that range and no other. @top
 * is where the region started before it grew, so it and the page touched a
 * megabyte down are the two ends of the growth.
 */
static int mode_region(void)
{
    unsigned long top, hi;
    if (stack_range(&top, &hi) < 0)
        return 100;

    volatile char *low = (volatile char *) (hi - MIB);
    volatile char *kept = (volatile char *) top;
    *kept = 0x22;
    *low = 0x11;
    if (stack_offset() != 0)
        return 1;

    /* MADV_DONTNEED empties the page it names. */
    if (madvise((void *) low, PAGE, MADV_DONTNEED) < 0 || *low != 0 ||
        *kept != 0x22)
        return 2;

    /* A page taken away and given back is still that page. */
    if (mprotect((void *) low, PAGE, PROT_NONE) < 0 ||
        mprotect((void *) low, PAGE, PROT_READ | PROT_WRITE) < 0)
        return 101;
    *low = 0x33;
    if (*kept != 0x22)
        return 3;
    return 0;
}

static volatile sig_atomic_t usr1_count;

static void on_usr1(int sig)
{
    (void) sig;
    usr1_count++;
}

/* Signal delivery writes the handler's frame under the stack pointer. Here that
 * is a megabyte under anything the program has touched.
 */
static __attribute__((noinline)) int raise_under_frame(void)
{
    char frame[MIB];
    KEEP(frame);
    return raise(SIGUSR1);
}

static int mode_signal(void)
{
    struct sigaction sa = {.sa_handler = on_usr1};
    if (sigaction(SIGUSR1, &sa, NULL) < 0)
        return 100;
    if (raise_under_frame() != 0 || usr1_count != 1)
        return 1;
    return 0;
}

/* A limit under the usual 128 KiB of headroom is the whole initial region. */
static int mode_small(void)
{
    unsigned long lo, hi;
    if (stack_range(&lo, &hi) < 0)
        return 100;
    return hi - lo == soft_limit() ? 0 : 1;
}

/* Whether the stack starts at @hi - @below after an access there. */
static int grown_to(unsigned long hi, unsigned long below)
{
    unsigned long now, top;
    return stack_range(&now, &top) == 0 && top == hi && now == hi - below;
}

/* Accesses the kernel makes for the program without a fault of the program's
 * own: each one names a page under the stack that nothing has touched, and
 * grows the stack to it. Under elfuse these are the accesses the EL1 shim
 * serves or emulates itself.
 */
static int mode_kernel(void)
{
    unsigned long lo, hi;
    int fd = open("/dev/urandom", O_RDONLY);
    if (stack_range(&lo, &hi) < 0 || fd < 0)
        return 100;

    /* 1 and 2: random bytes, by read and by getrandom. */
    if (read(fd, (void *) (hi - 1 * MIB), 16) != 16 || !grown_to(hi, 1 * MIB))
        return 1;
    if (getrandom((void *) (hi - 2 * MIB), 16, 0) != 16 ||
        !grown_to(hi, 2 * MIB))
        return 2;
    close(fd);

    /* 3: a futex timeout there reads as zero, so a wait that would block on a
     * matching word ends at once. The word itself is not tried: the kernel
     * reads it with page faults off and answers EFAULT without growing.
     */
    static int word;
    errno = 0;
    if (syscall(SYS_futex, &word, FUTEX_WAIT, 0, hi - 3 * MIB, NULL, 0) != -1 ||
        errno != ETIMEDOUT || !grown_to(hi, 3 * MIB))
        return 3;

#ifdef __aarch64__
    /* 4: DC ZVA zeroes a block of 4 << BS bytes, DCZID_EL0[3:0], unless bit 4
     * forbids it.
     */
    unsigned long dczid;
    __asm__("mrs %0, dczid_el0" : "=r"(dczid));
    if (!(dczid & 16) && (4UL << (dczid & 15)) <= PAGE) {
        __asm__ volatile("dc zva, %0" ::"r"(hi - 4 * MIB) : "memory");
        if (!grown_to(hi, 4 * MIB))
            return 4;
    }
#endif
    return 0;
}

/* An address hint just under the stack is not taken: a placed mapping stays
 * stack_guard_gap, 1 MiB, clear of it (vm_start_gap), and the stack still grows
 * to the page the hint named.
 */
static int mode_gap(void)
{
    unsigned long lo, hi, now;
    if (stack_range(&lo, &hi) < 0)
        return 100;

    unsigned long p = (unsigned long) mmap((void *) (lo - 64 * KIB), PAGE,
                                           PROT_READ | PROT_WRITE,
                                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == (unsigned long) MAP_FAILED)
        return 100;
    if (p + PAGE > lo - MIB && p < hi)
        return 1;

    *(volatile char *) (lo - 64 * KIB) = 1;
    if (stack_range(&now, &hi) < 0 || now != lo - 64 * KIB)
        return 2;
    return 0;
}

/* More mappings than elfuse has region records for, which a real kernel takes
 * in its stride. Past that point elfuse no longer knows every mapping, and
 * neither the stack nor an mprotect under a finite RLIMIT_DATA may start
 * failing for it.
 */
static int mode_many(void)
{
    unsigned long lo, hi, now, span = 64 * MIB;
    struct rlimit rl;
    if (stack_range(&lo, &hi) < 0 || getrlimit(RLIMIT_DATA, &rl) < 0)
        return 100;
    rl.rlim_cur = 1024 * MIB;
    if (setrlimit(RLIMIT_DATA, &rl) < 0)
        return 100;

    char *p = mmap(NULL, span, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return 100;

    /* A mapping inside the stack's window, 2 MiB and two pages long. Once the
     * table is full, unmapping all but its first and last page leaves the last
     * one with no record under elfuse.
     */
    char *fixed = mmap((void *) (hi - 7 * MIB), 2 * MIB + 2 * PAGE,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (fixed == MAP_FAILED)
        return 100;
    char *last = fixed + 2 * MIB + PAGE;
    *last = 42;

    /* Every other page becomes a mapping of its own. Under elfuse the break is
     * refused once the table is full, and each split after that logs a line, so
     * stop there.
     */
    for (unsigned long off = 0; off + 2 * PAGE <= span; off += 2 * PAGE) {
        if (mprotect(p + off, PAGE, PROT_READ) != 0)
            break;

        unsigned long cur = (unsigned long) syscall(SYS_brk, 0UL);
        int grew = (unsigned long) syscall(SYS_brk, cur + PAGE) >= cur + PAGE;
        syscall(SYS_brk, cur);
        if (!grew)
            break;
    }

    if (munmap(fixed + PAGE, 2 * MIB) != 0)
        return 100;

    *(volatile char *) (hi - 2 * MIB) = 1;
    if (stack_range(&now, &hi) < 0 || now != hi - 2 * MIB)
        return 1;
    if (mprotect(p, PAGE, PROT_READ | PROT_WRITE) != 0)
        return 2;

    /* The page under that last page is not the stack's to grow into. */
    if (syscall(SYS_getrandom, last - PAGE, 1, 0) != -1 || errno != EFAULT)
        return 3;
    if (*last != 42)
        return 4;
    return 0;
}

static const struct {
    const char *name;
    int (*run)(void);
} modes[] = {
    {"grow", mode_grow},   {"syscall", mode_syscall}, {"edge", mode_edge},
    {"deep", mode_deep},   {"lower", mode_lower},     {"signal", mode_signal},
    {"small", mode_small}, {"region", mode_region},   {"gap", mode_gap},
    {"many", mode_many},   {"kernel", mode_kernel},
};

/* Exec @self with argv[1] = @mode and @arg_bytes of further arguments, under a
 * soft RLIMIT_STACK of @limit.
 *
 * Returns the image's exit status, -1 if a signal ended it, or -2 if execve
 * failed with E2BIG.
 */
static int run_under(char *self, rlim_t limit, char *mode, size_t arg_bytes)
{
    enum { EACH = 100 * 1024 };
    size_t n = arg_bytes / EACH;
    char **argv = calloc(n + 3, sizeof(*argv));
    int status = -1;

    if (!argv)
        return -3;
    argv[0] = self;
    argv[1] = mode;
    for (size_t i = 0; i < n; i++) {
        argv[2 + i] = malloc(EACH);
        if (!argv[2 + i])
            return -3;
        memset(argv[2 + i], 'a', EACH - 1);
        argv[2 + i][EACH - 1] = '\0';
    }

    pid_t pid = fork();
    if (pid == 0) {
        struct rlimit rl;
        if (getrlimit(RLIMIT_STACK, &rl) < 0)
            _exit(120);
        rl.rlim_cur = limit;
        if (setrlimit(RLIMIT_STACK, &rl) < 0)
            _exit(121);

        /* An empty environment, so what fits depends on the arguments alone and
         * not on what the caller of this test had exported.
         */
        char *envp[] = {NULL};
        execve(self, argv, envp);
        _exit(errno == E2BIG ? 122 : 123);
    }
    if (pid > 0)
        waitpid(pid, &status, 0);
    for (size_t i = 0; i < n; i++)
        free(argv[2 + i]);
    free(argv);

    if (!WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status) == 122 ? -2 : WEXITSTATUS(status);
}

static void expect_mode(const char *name, char *self, rlim_t limit, char *mode)
{
    TEST(name);
    int rc = run_under(self, limit, mode, 0);
    if (rc == 0) {
        PASS();
    } else {
        printf("FAIL: status %d\n", rc);
        fails++;
    }
}

/* execve takes @fits bytes of arguments under @limit and refuses @too_big. */
static void expect_args(const char *name,
                        char *self,
                        rlim_t limit,
                        size_t fits,
                        size_t too_big)
{
    TEST(name);
    int ok = run_under(self, limit, "nop", fits);
    int big = run_under(self, limit, "nop", too_big);
    if (ok == 0 && big == -2) {
        PASS();
    } else {
        printf("FAIL: %zu KiB gave %d, %zu KiB gave %d\n", fits / KIB, ok,
               too_big / KIB, big);
        fails++;
    }
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "nop"))
        return 0;
    for (size_t i = 0; argc > 1 && i < sizeof(modes) / sizeof(modes[0]); i++)
        if (!strcmp(argv[1], modes[i].name))
            return modes[i].run();

    printf("test-rlimit-stack: the stack grows up to RLIMIT_STACK\n");

    expect_mode("stack starts small, grows by touch", argv[0], 8 * MIB, "grow");
    expect_mode("a syscall grows the stack", argv[0], 8 * MIB, "syscall");
    expect_mode("a signal frame grows the stack", argv[0], 8 * MIB, "signal");
    expect_mode("random bytes, futex and DC ZVA grow it", argv[0], 8 * MIB,
                "kernel");
    expect_mode("the region follows the stack down", argv[0], 8 * MIB,
                "region");
    expect_mode("a hint under the stack is not taken", argv[0], 8 * MIB, "gap");
    expect_mode("the stack grows past a full table", argv[0], 8 * MIB, "many");
    expect_mode("limit of 1 MiB is the last byte", argv[0], MIB, "edge");
    expect_mode("limit of 8 MiB is the last byte", argv[0], 8 * MIB, "edge");
    expect_mode("limit of 64 MiB is the last byte", argv[0], 64 * MIB, "edge");
    expect_mode("no limit: 48 MiB deep, and in fork", argv[0], RLIM_INFINITY,
                "deep");
    expect_mode("a lowered limit keeps what is mapped", argv[0], 8 * MIB,
                "lower");
    expect_mode("limit of 64 KiB is the initial stack", argv[0], 64 * KIB,
                "small");

    /* A quarter of the limit, between 128 KiB and 6 MiB. */
    expect_args("execve arguments under 1 MiB", argv[0], MIB, 200 * KIB,
                300 * KIB);
    expect_args("execve arguments under 8 MiB", argv[0], 8 * MIB, 1900 * KIB,
                2200 * KIB);
    expect_args("execve arguments under 64 MiB", argv[0], 64 * MIB, 5800 * KIB,
                6200 * KIB);

    SUMMARY("test-rlimit-stack");
    return fails ? 1 : 0;
}
