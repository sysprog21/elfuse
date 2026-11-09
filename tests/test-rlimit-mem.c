/*
 * Test RLIMIT_AS and RLIMIT_DATA on brk, mmap, mremap and mprotect
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A request that would take the mapped total past RLIMIT_AS, or the private
 * writable total past RLIMIT_DATA, fails with ENOMEM, and the break stays where
 * it was. Each limit is lowered in a fork child, so the process that reports
 * the results keeps its own limits.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

int passes = 0, fails = 0;

#define MIB ((size_t) 1 << 20)

/* VmSize from /proc/self/status in bytes, which is what RLIMIT_AS bounds. */
static size_t vm_size(void)
{
    char buf[4096];
    int fd = open("/proc/self/status", O_RDONLY);
    ssize_t n = fd < 0 ? -1 : read(fd, buf, sizeof(buf) - 1);
    if (fd >= 0)
        close(fd);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    char *p = strstr(buf, "VmSize:");
    return p ? (size_t) strtoul(p + 7, NULL, 10) * 1024 : 0;
}

static int set_soft(int resource, rlim_t cur)
{
    struct rlimit rl;
    if (getrlimit(resource, &rl) < 0)
        return -1;
    rl.rlim_cur = cur;
    return setrlimit(resource, &rl);
}

static void *map_anon(void *addr, size_t len, int prot, int flags)
{
    return mmap(addr, len, prot, flags | MAP_ANONYMOUS, -1, 0);
}

/* Linux 6.17 and later check a MREMAP_FIXED move's growth before unmapping the
 * destination; an older kernel unmaps it first and lets the move through.
 * elfuse reports 6.18.0, so the steps that need the newer order still run.
 */
static int mremap_checks_before_unmap(void)
{
    struct utsname u;
    unsigned maj = 0, min = 0;
    return uname(&u) == 0 && sscanf(u.release, "%u.%u", &maj, &min) == 2 &&
           (maj > 6 || (maj == 6 && min >= 17));
}

/* mmap(2) called directly: glibc's mmap fails a misaligned offset without
 * making the syscall.
 */
static long raw_mmap(void *addr,
                     size_t len,
                     int prot,
                     int flags,
                     int fd,
                     long off)
{
    return syscall(SYS_mmap, addr, len, prot, flags, fd, off);
}

/* Runs in a child with RLIMIT_AS 24 MiB above what is mapped. The exit status
 * is the number of the first step that went wrong, 0 if none did.
 */
static int as_child(void)
{
    size_t base = vm_size();
    int rw = PROT_READ | PROT_WRITE;
    if (base == 0 || set_soft(RLIMIT_AS, base + 24 * MIB) < 0)
        return 100;

    /* 1: a mapping that stays below the limit. */
    void *a = map_anon(NULL, 16 * MIB, rw, MAP_PRIVATE);
    if (a == MAP_FAILED)
        return 1;

    /* 2: one that crosses it, with 8 MiB left. */
    errno = 0;
    if (map_anon(NULL, 16 * MIB, rw, MAP_PRIVATE) != MAP_FAILED ||
        errno != ENOMEM)
        return 2;

    /* 3: a shared or read-only mapping is address space too. */
    errno = 0;
    if (map_anon(NULL, 16 * MIB, PROT_READ, MAP_SHARED) != MAP_FAILED ||
        errno != ENOMEM)
        return 3;

    /* 4: MAP_FIXED over the first mapping replaces it and adds nothing. */
    if (map_anon(a, 16 * MIB, rw, MAP_PRIVATE | MAP_FIXED) != a)
        return 4;

    /* 5: growing it by mremap crosses the limit. */
    errno = 0;
    if (mremap(a, 16 * MIB, 32 * MIB, MREMAP_MAYMOVE) != MAP_FAILED ||
        errno != ENOMEM)
        return 5;

    /* 6: what munmap gives back can be mapped again. */
    char *c;
    if (munmap(a, 16 * MIB) < 0 ||
        (c = map_anon(NULL, 16 * MIB, rw, MAP_PRIVATE)) == MAP_FAILED)
        return 6;

    /* 7: a bad descriptor is reported before the limit is, for a hinted, a
     * placed and a fixed request alike, and so is the overlap that
     * MAP_FIXED_NOREPLACE refuses with EEXIST.
     */
    void *at = (char *) a + 16 * MIB;
    int fixed = MAP_PRIVATE | MAP_FIXED;
    errno = 0;
    if (mmap(at, 32 * MIB, PROT_READ, MAP_PRIVATE, -1, 0) != MAP_FAILED ||
        errno != EBADF)
        return 7;
    errno = 0;
    if (mmap(NULL, 32 * MIB, PROT_READ, MAP_PRIVATE, -1, 0) != MAP_FAILED ||
        errno != EBADF)
        return 7;
    errno = 0;
    if (mmap(at, 32 * MIB, PROT_READ, fixed, -1, 0) != MAP_FAILED ||
        errno != EBADF)
        return 7;
    errno = 0;
    if (map_anon(c, 32 * MIB, PROT_READ, MAP_PRIVATE | MAP_FIXED_NOREPLACE) !=
            MAP_FAILED ||
        errno != EEXIST)
        return 7;

    /* 8: MREMAP_FIXED onto a mapping is charged with that mapping still
     * counted, as Linux checks the growth before it unmaps the destination
     * (since v6.17). With the limit reached, moving 4 MiB of the mapping from
     * step 6 onto an 8 MiB one as 8 MiB fails, and the destination stays. On an
     * older kernel the move is skipped, which leaves the same mappings.
     */
    void *d = map_anon(NULL, 8 * MIB, rw, MAP_PRIVATE);
    if (d == MAP_FAILED)
        return 100;
    errno = 0;
    if (mremap_checks_before_unmap() &&
        (mremap(c, 4 * MIB, 8 * MIB, MREMAP_MAYMOVE | MREMAP_FIXED, d) !=
             MAP_FAILED ||
         errno != ENOMEM || msync(d, 4096, MS_ASYNC) < 0))
        return 8;

    /* 9: an unaligned MREMAP_FIXED destination is EINVAL even when the growth
     * would cross the limit.
     */
    void *far = (void *) ((1UL << 46) + 1);
    errno = 0;
    if (mremap(d, 8 * MIB, 16 * MIB, MREMAP_MAYMOVE | MREMAP_FIXED, far) !=
            MAP_FAILED ||
        errno != EINVAL)
        return 9;

    /* 10: the file checks come before the limit, so their errno is the same
     * whether or not the limit refuses the request: a shared writable mapping
     * of a read-only descriptor and a private one of a write-only descriptor
     * (the pipe's write end among them) are EACCES, the pipe's read end and a
     * directory, which have no mmap, are ENODEV, and an O_PATH descriptor,
     * which fget does not return, is EBADF. A socket has an mmap, so it reaches
     * the limit. The second pass raises the soft limit to the hard one, so
     * nothing but the file is in the way.
     */
    char path[] = "/tmp/test-rlimit-mem-XXXXXX";
    int wfd = mkstemp(path);
    int rfd = wfd < 0 ? -1 : open(path, O_RDONLY);
    int ofd = wfd < 0 ? -1 : open(path, O_WRONLY);
    if (wfd >= 0)
        unlink(path);
    int pf[2], sv[2];
    if (rfd < 0 || ofd < 0 || ftruncate(wfd, 32 * MIB) < 0 || pipe(pf) < 0 ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
        return 100;
    int dfd = open("/", O_RDONLY | O_DIRECTORY);
    int pfd = open("/", O_PATH);
    struct rlimit lim;
    if (dfd < 0 || pfd < 0 || getrlimit(RLIMIT_AS, &lim) < 0)
        return 100;
    int fds[] = {rfd, ofd, pf[0], pf[1], dfd, pfd, sv[0]};
    int prots[] = {rw,        PROT_READ, PROT_READ, PROT_READ,
                   PROT_READ, PROT_READ, PROT_READ};
    int flags[] = {MAP_SHARED,  MAP_PRIVATE, MAP_PRIVATE, MAP_PRIVATE,
                   MAP_PRIVATE, MAP_PRIVATE, MAP_PRIVATE};
    int want[] = {EACCES, EACCES, ENODEV, EACCES, ENODEV, EBADF, ENOMEM};
    for (int pass = 0; pass < 2; pass++) {
        if (pass == 1 && set_soft(RLIMIT_AS, lim.rlim_max) < 0)
            return 100;

        /* The socket's errno past the limit comes from its own mmap, which
         * elfuse does not model, so it is checked only against the limit.
         */
        for (int i = 0; i < (pass == 0 ? 7 : 6); i++) {
            errno = 0;
            if (mmap(NULL, 32 * MIB, prots[i], flags[i], fds[i], 0) !=
                    MAP_FAILED ||
                errno != want[i])
                return 10;
        }
    }

    /* The address is checked before the file: a MAP_FIXED request above the
     * user address range is ENOMEM whatever the descriptor.
     */
    void *above = (void *) (1UL << 60);
    void *edge = (void *) ((1UL << 48) - 4096);
    for (int i = 1; i < 5; i++) {
        errno = 0;
        if (mmap(above, 4096, prots[i], flags[i] | MAP_FIXED, fds[i], 0) !=
                MAP_FAILED ||
            errno != ENOMEM)
            return 10;

        /* So is one that starts below it and ends past it, and a non-fixed
         * request longer than the whole range or as long as it, which no gap
         * holds.
         */
        errno = 0;
        if (mmap(edge, 2 * 4096, prots[i], flags[i] | MAP_FIXED, fds[i], 0) !=
                MAP_FAILED ||
            errno != ENOMEM)
            return 10;
        errno = 0;
        if (mmap(NULL, (1UL << 48) + 4096, prots[i], flags[i], fds[i], 0) !=
                MAP_FAILED ||
            errno != ENOMEM)
            return 10;
        errno = 0;
        if (mmap(NULL, 1UL << 48, prots[i], flags[i], fds[i], 0) !=
                MAP_FAILED ||
            errno != ENOMEM)
            return 10;
    }

    /* The descriptor is looked up before the length and the address, as fget
     * comes before do_mmap: a zero, overflowing or huge length and a misaligned
     * or out-of-range MAP_FIXED address are all EBADF for a closed or O_PATH
     * descriptor. Only a misaligned offset, which arm64 sys_mmap checks first,
     * is EINVAL, for an anonymous request too.
     */
    int bad[] = {-1, pfd};
    for (int i = 0; i < 2; i++) {
        struct {
            void *at;
            size_t len;
            int flags;
        } req[] = {
            {NULL, 0, MAP_PRIVATE},
            {NULL, ~(size_t) 0, MAP_PRIVATE},
            {NULL, (1UL << 48) + 4096, MAP_PRIVATE},
            {(char *) edge + 1, 4096, MAP_PRIVATE | MAP_FIXED},
            {above, 4096, MAP_PRIVATE | MAP_FIXED},
        };
        for (size_t j = 0; j < sizeof(req) / sizeof(req[0]); j++) {
            errno = 0;
            if (mmap(req[j].at, req[j].len, PROT_READ, req[j].flags, bad[i],
                     0) != MAP_FAILED ||
                errno != EBADF)
                return 10;
        }
        errno = 0;
        if (raw_mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bad[i], 1) != -1 ||
            errno != EINVAL)
            return 10;
    }
    errno = 0;
    if (raw_mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 1) !=
            -1 ||
        errno != EINVAL)
        return 10;
    close(ofd);
    close(pf[0]);
    close(pf[1]);
    close(sv[0]);
    close(sv[1]);
    close(dfd);
    close(pfd);

    /* 11: so is a MAP_FIXED one. The hole it goes into is reserved with the
     * soft limit raised to the hard one and unmapped again, so the request maps
     * over nothing. A finite hard limit may leave no room for the hole, and the
     * step is then skipped.
     */
    struct rlimit as;
    if (getrlimit(RLIMIT_AS, &as) < 0 || set_soft(RLIMIT_AS, as.rlim_max) < 0)
        return 100;
    void *hole = map_anon(NULL, 32 * MIB, PROT_NONE, MAP_PRIVATE);
    if (hole == MAP_FAILED && as.rlim_max != RLIM_INFINITY) {
        close(wfd);
        close(rfd);
        return 0;
    }
    if (hole == MAP_FAILED || munmap(hole, 32 * MIB) < 0 ||
        set_soft(RLIMIT_AS, base + 24 * MIB) < 0)
        return 100;
    errno = 0;
    if (mmap(hole, 32 * MIB, rw, MAP_SHARED | MAP_FIXED, rfd, 0) !=
            MAP_FAILED ||
        errno != EACCES)
        return 11;

    /* A socket gets past the file checks, so the limit refuses it with ENOMEM
     * before its own mmap runs, as may_expand_vm comes before call_mmap.
     */
    int sk[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sk) < 0)
        return 100;
    errno = 0;
    if (mmap(hole, 32 * MIB, PROT_READ, MAP_PRIVATE | MAP_FIXED, sk[0], 0) !=
            MAP_FAILED ||
        errno != ENOMEM)
        return 11;
    close(sk[0]);
    close(sk[1]);
    close(wfd);
    close(rfd);
    return 0;
}

/* Bytes /proc/self/maps lists, less the elfuse runtime records ([shim],
 * [shim-data]) that a Linux process has no mapping for. With @data_only, only
 * the private writable lines other than [stack], which RLIMIT_DATA counts.
 */
static size_t maps_size(int data_only)
{
    static char buf[64 * 1024];
    size_t len = 0;
    ssize_t n = 0;
    int fd = open("/proc/self/maps", O_RDONLY);
    while (fd >= 0 && len < sizeof(buf) - 1 &&
           (n = read(fd, buf + len, sizeof(buf) - 1 - len)) > 0)
        len += (size_t) n;
    if (fd >= 0)
        close(fd);
    if (fd < 0 || n < 0 || len == sizeof(buf) - 1)
        return 0;
    buf[len] = '\0';

    size_t total = 0;
    for (char *line = buf, *nl; *line; line = nl + 1) {
        char *end;
        unsigned long lo = strtoul(line, &end, 16);
        unsigned long hi = strtoul(end + 1, NULL, 16);
        nl = strchr(line, '\n');
        if (!nl)
            break;
        *nl = '\0';
        char *perms = strchr(line, ' ');
        int data = perms && perms[2] == 'w' && perms[4] == 'p' &&
                   !strstr(line, "[stack]");
        if (!strstr(line, "[shim") && (!data_only || data))
            total += hi - lo;
    }
    return total;
}

/* brk(2) called directly: musl's sbrk fails any non-zero increment without
 * making the syscall.
 */
static unsigned long raw_brk(unsigned long addr)
{
    return (unsigned long) syscall(SYS_brk, addr);
}

/* Runs in a child with RLIMIT_AS 1 MiB above what maps lists. The exit status
 * is the number of the first step that went wrong, 0 if none did.
 */
static int as_exact_child(void)
{
    /* The break is left inside a page, for step 3. */
    unsigned long start = raw_brk(0);
    if (raw_brk(start + 100) != start + 100)
        return 100;

    size_t base = maps_size(0);
    int rw = PROT_READ | PROT_WRITE;
    if (base == 0 || set_soft(RLIMIT_AS, base + MIB) < 0)
        return 100;

    /* 1: the last MiB under the limit. */
    if (map_anon(NULL, MIB, rw, MAP_PRIVATE) == MAP_FAILED)
        return 1;

    /* 2: another MiB past it. */
    errno = 0;
    if (map_anon(NULL, MIB, rw, MAP_PRIVATE) != MAP_FAILED || errno != ENOMEM)
        return 2;

    /* 3: a break that stays inside its last page adds no page, so it passes a
     * limit that ends inside that page.
     */
    if (set_soft(RLIMIT_AS, base + MIB - (4096 - 100)) < 0)
        return 100;
    if (raw_brk(start + 200) != start + 200)
        return 3;

    /* 4: in a fork child, a break grown inside its page starts a second heap
     * record in that page. The page is counted once, so a MAP_FIXED over it
     * fits a limit at the mapped total.
     */
    pid_t pid = fork();
    if (pid == 0) {
        size_t now = maps_size(0);
        if (now == 0 || set_soft(RLIMIT_AS, now) < 0)
            _exit(100);
        void *page = (void *) start;
        if (raw_brk(start + 300) != start + 300 ||
            map_anon(page, 4096, rw, MAP_PRIVATE | MAP_FIXED) != page)
            _exit(4);
        _exit(0);
    }
    int status;
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status))
        return 100;
    if (WEXITSTATUS(status) != 0)
        return WEXITSTATUS(status);

    /* 5: a break that adds a page goes past that limit, though its extent is
     * far under RLIMIT_DATA, so the break stays where it was.
     */
    if (raw_brk(start + 4096 + 200) != start + 200)
        return 5;
    return 0;
}

/* Runs in a child with RLIMIT_DATA at 24 MiB, far above the data this static
 * binary starts with. The sizes stay small enough that the break has room to
 * grow where no limit is set.
 */
static int data_child(void)
{
    int rw = PROT_READ | PROT_WRITE;
    if (set_soft(RLIMIT_DATA, 24 * MIB) < 0)
        return 100;

    /* 1: a break that stays below the limit. */
    unsigned long start = raw_brk(0);
    if (raw_brk(start + 8 * MIB) != start + 8 * MIB)
        return 1;

    /* 2: one that crosses it leaves the break where it was, which brk(2)
     * returns.
     */
    if (raw_brk(start + 40 * MIB) != start + 8 * MIB ||
        raw_brk(0) != start + 8 * MIB)
        return 2;

    /* 3: a private writable mapping is data. */
    errno = 0;
    if (map_anon(NULL, 32 * MIB, rw, MAP_PRIVATE) != MAP_FAILED ||
        errno != ENOMEM)
        return 3;

    /* 4: a read-only or shared mapping of the same size is not, nor is a
     * writable MAP_GROWSDOWN one, which is a stack (VM_STACK is VM_GROWSDOWN on
     * arm64).
     */
    char *ro = map_anon(NULL, 32 * MIB, PROT_READ, MAP_PRIVATE);
    char *shared = map_anon(NULL, 32 * MIB, PROT_READ, MAP_SHARED);
    char *down = map_anon(NULL, 32 * MIB, rw, MAP_PRIVATE | MAP_GROWSDOWN);
    if (ro == MAP_FAILED || shared == MAP_FAILED || down == MAP_FAILED ||
        munmap(down, 32 * MIB) < 0)
        return 4;

    /* 5: making the private one writable turns it into data. */
    errno = 0;
    if (mprotect(ro, 32 * MIB, rw) != -1 || errno != ENOMEM)
        return 5;

    /* 6: a part that fits, and the whole of the shared one, may be. */
    if (mprotect(ro, 4 * MIB, rw) < 0 || mprotect(shared, 32 * MIB, rw) < 0)
        return 6;
    ro[0] = shared[0] = 1;

    /* 7: a range over two mappings stops at the one that does not fit, with the
     * one below it already writable. The first mprotect below splits one
     * mapping into the two.
     */
    char *two = map_anon(NULL, 36 * MIB, PROT_NONE, MAP_PRIVATE);
    int zero = open("/dev/zero", O_RDONLY);
    if (two == MAP_FAILED || zero < 0 ||
        mprotect(two + 4 * MIB, 32 * MIB, PROT_READ) < 0)
        return 100;
    errno = 0;
    if (mprotect(two, 36 * MIB, rw) != -1 || errno != ENOMEM ||
        read(zero, two, 1) != 1 || read(zero, two + 4 * MIB, 1) != -1)
        return 7;
    close(zero);
    if (munmap(ro, 32 * MIB) < 0 || munmap(shared, 32 * MIB) < 0 ||
        munmap(two, 36 * MIB) < 0)
        return 100;

    /* 8: a mapping below the one that does not fit stops the range first with
     * its own error: a shared mapping of a read-only descriptor is EACCES.
     */
    char path[] = "/tmp/test-rlimit-mem-XXXXXX";
    int wfd = mkstemp(path);
    int rfd = wfd < 0 ? -1 : open(path, O_RDONLY);
    if (wfd >= 0)
        unlink(path);
    char *pair = map_anon(NULL, 36 * MIB, PROT_READ, MAP_PRIVATE);
    if (rfd < 0 || ftruncate(wfd, 4 * MIB) < 0 || pair == MAP_FAILED)
        return 100;

    /* The shared mapping goes into a hole cut from the reserved range, so the
     * hint is free to honor. Not MAP_FIXED: elfuse refuses a MAP_FIXED shared
     * mapping of a read-only descriptor with EACCES.
     */
    if (munmap(pair, 4 * MIB) < 0 ||
        mmap(pair, 4 * MIB, PROT_READ, MAP_SHARED, rfd, 0) != pair)
        return 100;
    errno = 0;
    if (mprotect(pair, 36 * MIB, rw) != -1 || errno != EACCES)
        return 8;
    close(wfd);
    close(rfd);
    if (munmap(pair, 36 * MIB) < 0)
        return 100;

    /* 9: a read-only heap is not data, but the break itself is still held to
     * the limit.
     */
    if (mprotect((void *) start, 8 * MIB, PROT_READ) < 0)
        return 100;
    if (raw_brk(start + 26 * MIB) != start + 8 * MIB)
        return 9;

    /* 10: so is a shrink that leaves the break over the limit. */
    if (set_soft(RLIMIT_DATA, 64 * MIB) < 0 ||
        raw_brk(start + 32 * MIB) != start + 32 * MIB ||
        set_soft(RLIMIT_DATA, 24 * MIB) < 0)
        return 100;
    if (raw_brk(start + 32 * MIB - 4096) != start + 32 * MIB ||
        raw_brk(start + 8 * MIB) != start + 8 * MIB)
        return 10;

    /* 11: with the data total at the limit, a private writable MAP_FIXED over a
     * private read-only page is charged nothing, as mmap_region charges the
     * length less every page it replaces, so it fits although data grows by a
     * page. Data is then over the limit, so growing that page by mremap, which
     * is charged as data, fails.
     */
    void *page = map_anon(NULL, 4096, PROT_READ, MAP_PRIVATE);
    size_t data = maps_size(1);
    if (page == MAP_FAILED || data == 0 || set_soft(RLIMIT_DATA, data) < 0)
        return 100;
    if (map_anon(page, 4096, rw, MAP_PRIVATE | MAP_FIXED) != page)
        return 11;
    errno = 0;
    if (mremap(page, 4096, 2 * 4096, MREMAP_MAYMOVE) != MAP_FAILED ||
        errno != ENOMEM)
        return 11;

    /* 12: a MREMAP_FIXED move the limit refuses leaves its destination mapped,
     * as Linux checks the growth before it unmaps the destination (since
     * v6.17). On an older kernel the move is skipped, as in step 8 of as_child.
     */
    void *dst = map_anon(NULL, 8 * MIB, PROT_READ, MAP_PRIVATE);
    if (dst == MAP_FAILED)
        return 100;
    errno = 0;
    if (mremap_checks_before_unmap() &&
        (mremap(page, 4096, 8 * MIB, MREMAP_MAYMOVE | MREMAP_FIXED, dst) !=
             MAP_FAILED ||
         errno != ENOMEM || msync(dst, 4096, MS_ASYNC) < 0))
        return 12;

    return 0;
}

/* Runs in a child with a soft RLIMIT_DATA of 0 and a hard one 4 MiB above the
 * data it has.
 */
static int data_zero_child(void)
{
    int rw = PROT_READ | PROT_WRITE;
    size_t data = maps_size(1);
    struct rlimit rl = {.rlim_cur = 0, .rlim_max = data + 4 * MIB};
    unsigned long brk_now = raw_brk(0);
    if (data == 0 || setrlimit(RLIMIT_DATA, &rl) < 0)
        return 100;

    /* 1: a data mapping may go up to the hard limit, as may_expand_vm allows
     * for Valgrind.
     */
    if (map_anon(NULL, MIB, rw, MAP_PRIVATE) == MAP_FAILED)
        return 1;

    /* 2: and no further. */
    errno = 0;
    if (map_anon(NULL, 8 * MIB, rw, MAP_PRIVATE) != MAP_FAILED ||
        errno != ENOMEM)
        return 2;

    /* 3: brk takes the soft limit as it is, so the break does not grow. */
    if (raw_brk(brk_now + 4096) != brk_now)
        return 3;
    return 0;
}

/* Run @child_main in a fork child and report its first failed step. */
static void expect_child_steps(int (*child_main)(void))
{
    int status = -1;
    pid_t pid = fork();
    if (pid == 0)
        _exit(child_main());
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) {
        FAIL("child did not exit");
    } else if (WEXITSTATUS(status) != 0) {
        printf("FAIL: step %d\n", WEXITSTATUS(status));
        fails++;
    } else {
        PASS();
    }
}

int main(void)
{
    printf("test-rlimit-mem: RLIMIT_AS and RLIMIT_DATA are enforced\n");

    TEST("RLIMIT_AS on mmap and mremap");
    expect_child_steps(as_child);

    TEST("RLIMIT_AS counts only guest mappings");
    expect_child_steps(as_exact_child);

    TEST("RLIMIT_DATA on brk, mmap and mprotect");
    expect_child_steps(data_child);

    TEST("RLIMIT_DATA soft limit of 0");
    expect_child_steps(data_zero_child);

    SUMMARY("test-rlimit-mem");
    return fails ? 1 : 0;
}
