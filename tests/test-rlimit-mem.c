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
#include <sys/ipc.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

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
     * placed and a fixed request alike.
     */
    void *at = (char *) a + 16 * MIB;
    int fixed = MAP_PRIVATE | MAP_FIXED;
    errno = 0;
    if (mmap(NULL, 32 * MIB, PROT_READ, MAP_PRIVATE, -1, 0) != MAP_FAILED ||
        errno != EBADF)
        return 7;
    errno = 0;
    if (mmap(at, 32 * MIB, PROT_READ, fixed, -1, 0) != MAP_FAILED ||
        errno != EBADF)
        return 7;

    /* 8: MREMAP_FIXED onto a mapping is charged with that mapping still
     * counted, as Linux checks the growth before it unmaps the destination
     * (since v6.17). With the limit reached, moving 4 MiB of the mapping from
     * step 6 onto an 8 MiB one as 8 MiB fails, and the destination stays.
     */
    void *d = map_anon(NULL, 8 * MIB, rw, MAP_PRIVATE);
    if (d == MAP_FAILED)
        return 100;
    errno = 0;
    if (mremap(c, 4 * MIB, 8 * MIB, MREMAP_MAYMOVE | MREMAP_FIXED, d) !=
            MAP_FAILED ||
        errno != ENOMEM || msync(d, 4096, MS_ASYNC) < 0)
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

    /* 10: a shared writable mapping of a read-only descriptor is EACCES even
     * when it would also cross the limit.
     */
    char path[] = "/tmp/test-rlimit-mem-XXXXXX";
    int wfd = mkstemp(path);
    int rfd = wfd < 0 ? -1 : open(path, O_RDONLY);
    if (wfd >= 0)
        unlink(path);
    if (rfd < 0 || ftruncate(wfd, 32 * MIB) < 0)
        return 100;
    errno = 0;
    if (mmap(NULL, 32 * MIB, rw, MAP_SHARED, rfd, 0) != MAP_FAILED ||
        errno != EACCES)
        return 10;

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
    return WEXITSTATUS(status);
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

    /* 4: a read-only or shared mapping of the same size is not. */
    char *ro = map_anon(NULL, 32 * MIB, PROT_READ, MAP_PRIVATE);
    char *shared = map_anon(NULL, 32 * MIB, PROT_READ, MAP_SHARED);
    if (ro == MAP_FAILED || shared == MAP_FAILED)
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
     * one below it already writable. The second mprotect below splits one
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
     * private read-only page grows data by a page and is charged that page, not
     * counted twice and not set against a total that left it out.
     */
    void *page = map_anon(NULL, 4096, PROT_READ, MAP_PRIVATE);
    size_t data = maps_size(1);
    if (page == MAP_FAILED || data == 0 || set_soft(RLIMIT_DATA, data) < 0)
        return 100;
    if (map_anon(page, 4096, rw, MAP_PRIVATE | MAP_FIXED) != page)
        return 11;

    /* 12: a MREMAP_FIXED move the limit refuses leaves its destination mapped,
     * as Linux checks the growth before it unmaps the destination (since
     * v6.17).
     */
    void *dst = map_anon(NULL, 8 * MIB, PROT_READ, MAP_PRIVATE);
    if (dst == MAP_FAILED)
        return 100;
    errno = 0;
    if (mremap(page, 4096, 8 * MIB, MREMAP_MAYMOVE | MREMAP_FIXED, dst) !=
            MAP_FAILED ||
        errno != ENOMEM)
        return 12;
    if (msync(dst, 4096, MS_ASYNC) < 0)
        return 12;

    /* 13: a SysV shm attach is shared, so RLIMIT_DATA does not count it. */
    int id = shmget(IPC_PRIVATE, 2 * MIB, IPC_CREAT | 0600);
    data = maps_size(1);
    if (id < 0 || data == 0 || set_soft(RLIMIT_DATA, data + MIB / 2) < 0)
        return 100;
    char *seg = shmat(id, NULL, 0);
    shmctl(id, IPC_RMID, NULL);
    if (seg == (void *) -1)
        return 13;

    /* 14: and a fork child shares it, so its write reaches the parent. */
    seg[0] = 'P';
    pid_t pid = fork();
    if (pid == 0) {
        seg[0] = 'C';
        _exit(0);
    }
    int status;
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status))
        return 100;
    if (seg[0] != 'C')
        return 14;
    shmdt(seg);

    /* 15: a detach releases the attach, so attaching and detaching more than
     * RLIMIT_AS leaves room for in all does not run out.
     */
    id = shmget(IPC_PRIVATE, 2 * MIB, IPC_CREAT | 0600);
    size_t vm = vm_size();
    if (id < 0 || vm == 0 || set_soft(RLIMIT_AS, vm + 8 * MIB) < 0) {
        if (id >= 0)
            shmctl(id, IPC_RMID, NULL);
        return 100;
    }
    for (int i = 0; i < 16; i++) {
        seg = shmat(id, NULL, 0);
        if (seg == (void *) -1 || shmdt(seg) < 0) {
            shmctl(id, IPC_RMID, NULL);
            return 15;
        }
    }

    /* 16: a detach after the attach was mapped over fails with EINVAL and
     * leaves the new mapping in place.
     */
    seg = shmat(id, NULL, 0);
    shmctl(id, IPC_RMID, NULL);
    if (seg == (void *) -1 ||
        map_anon(seg, 2 * MIB, rw, MAP_PRIVATE | MAP_FIXED) != seg)
        return 100;
    seg[0] = 'N';
    errno = 0;
    if (shmdt(seg) != -1 || errno != EINVAL || msync(seg, 4096, MS_ASYNC) < 0 ||
        seg[0] != 'N')
        return 16;

    /* 17: when only part of the attach was mapped over, the detach writes back
     * and unmaps the part that remains and leaves the new mapping alone. The
     * new mapping is data, so the soft RLIMIT_DATA from step 13 is raised.
     */
    struct rlimit dl;
    if (getrlimit(RLIMIT_DATA, &dl) < 0 ||
        set_soft(RLIMIT_DATA, dl.rlim_max) < 0)
        return 100;
    id = shmget(IPC_PRIVATE, 2 * MIB, IPC_CREAT | 0600);
    seg = id < 0 ? (void *) -1 : shmat(id, NULL, 0);
    if (seg == (void *) -1 ||
        map_anon(seg + MIB, MIB, rw, MAP_PRIVATE | MAP_FIXED) != seg + MIB) {
        if (id >= 0)
            shmctl(id, IPC_RMID, NULL);
        return 100;
    }
    seg[0] = 'A';
    seg[MIB] = 'X';
    char *again = shmdt(seg) < 0 ? (void *) -1 : shmat(id, NULL, 0);
    shmctl(id, IPC_RMID, NULL);
    if (again == (void *) -1 || again[0] != 'A' || again[MIB] != 0 ||
        (again != seg + MIB && seg[MIB] != 'X'))
        return 17;

    /* 18: so is a shared anonymous one over the first page, which Linux keeps
     * apart from the attach.
     */
    id = shmget(IPC_PRIVATE, 64 * 1024, IPC_CREAT | 0600);
    seg = id < 0 ? (void *) -1 : shmat(id, NULL, 0);
    if (seg == (void *) -1 || munmap(seg, 4096) < 0 ||
        map_anon(seg, 4096, rw, MAP_SHARED | MAP_FIXED) != seg) {
        if (id >= 0)
            shmctl(id, IPC_RMID, NULL);
        return 100;
    }
    seg[0] = 'S';
    seg[4096] = 'B';
    again = shmdt(seg) < 0 ? (void *) -1 : shmat(id, NULL, 0);
    shmctl(id, IPC_RMID, NULL);
    if (again == (void *) -1 || again[0] != 0 || again[4096] != 'B' ||
        (again != seg && seg[0] != 'S'))
        return 18;

    /* 19: an attach that was unmapped does not hide one made at its address
     * since, which the detach then takes.
     */
    int ida = shmget(IPC_PRIVATE, 64 * 1024, IPC_CREAT | 0600);
    int idb = shmget(IPC_PRIVATE, 64 * 1024, IPC_CREAT | 0600);
    char *sa = ida < 0 ? (void *) -1 : shmat(ida, NULL, 0);
    char *sb = sa == (void *) -1 || munmap(sa, 64 * 1024) < 0 || idb < 0
                   ? (void *) -1
                   : shmat(idb, sa, 0);
    if (ida >= 0)
        shmctl(ida, IPC_RMID, NULL);
    if (idb >= 0)
        shmctl(idb, IPC_RMID, NULL);
    if (sb == (void *) -1)
        return 100;
    if (sb == sa && (shmdt(sa) < 0 || msync(sa, 4096, MS_ASYNC) == 0))
        return 19;

    /* 20: a detach writes back a part the guest made PROT_NONE. */
    id = shmget(IPC_PRIVATE, 64 * 1024, IPC_CREAT | 0600);
    seg = id < 0 ? (void *) -1 : shmat(id, NULL, 0);
    if (seg == (void *) -1) {
        if (id >= 0)
            shmctl(id, IPC_RMID, NULL);
        return 100;
    }
    seg[100] = 'W';
    if (mprotect(seg, 64 * 1024, PROT_NONE) < 0 || shmdt(seg) < 0) {
        shmctl(id, IPC_RMID, NULL);
        return 20;
    }
    again = shmat(id, NULL, 0);
    if (again == (void *) -1 || again[100] != 'W') {
        shmctl(id, IPC_RMID, NULL);
        return 20;
    }

    /* 21: so is an attach that mremap shrank and grew back in place. */
    if (mremap(again, 64 * 1024, 32 * 1024, 0) != again ||
        mremap(again, 32 * 1024, 64 * 1024, 0) != again) {
        shmctl(id, IPC_RMID, NULL);
        return 100;
    }
    again[0] = 'Q';
    if (shmdt(again) < 0 || msync(again, 4096, MS_ASYNC) == 0) {
        shmctl(id, IPC_RMID, NULL);
        return 21;
    }
    seg = shmat(id, NULL, 0);
    shmctl(id, IPC_RMID, NULL);
    if (seg == (void *) -1 || seg[0] != 'Q')
        return 21;

    /* 22: an attach the guest unmapped is detached, so unmapping attaches
     * without shmdt does not run out of them. elfuse keeps 64 records, and the
     * macOS host allows 8 attaches per process by default.
     */
    id = shmget(IPC_PRIVATE, 64 * 1024, IPC_CREAT | 0600);
    if (id < 0)
        return 100;
    for (int i = 0; i < 80; i++) {
        char *a = shmat(id, NULL, 0);
        if (a == (void *) -1 || munmap(a, 64 * 1024) < 0) {
            shmctl(id, IPC_RMID, NULL);
            return 22;
        }
    }
    shmctl(id, IPC_RMID, NULL);

    /* 23: an attach moved with mremap is detached at its new address, with the
     * writes made there, and not at its old one.
     */
    id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    char *to = map_anon(NULL, 4096, rw, MAP_PRIVATE);
    if (id < 0 || to == MAP_FAILED)
        return 100;
    seg = shmat(id, NULL, 0);
    if (seg == (void *) -1 ||
        mremap(seg, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, to) != to) {
        shmctl(id, IPC_RMID, NULL);
        return 23;
    }
    to[0] = 'M';
    errno = 0;
    int old_rc = shmdt(seg);
    int old_errno = errno;
    int new_rc = shmdt(to);
    seg = shmat(id, NULL, 0);
    shmctl(id, IPC_RMID, NULL);
    if (old_rc != -1 || old_errno != EINVAL || new_rc != 0 ||
        seg == (void *) -1 || seg[0] != 'M')
        return 23;
    shmdt(seg);

    /* 24: a fork child's attaches do not take the serials of the attaches it
     * inherited. In a child holding 8 attaches, a grandchild attaches and
     * unmaps 20 times; an attach that shared an inherited one's serial would
     * look still mapped and never be detached.
     */
    id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    if (id < 0)
        return 100;
    pid_t holder = fork();
    if (holder == 0) {
        for (int i = 0; i < 8; i++) {
            if (shmat(id, NULL, 0) == (void *) -1)
                _exit(100);
        }
        pid_t gc = fork();
        if (gc == 0) {
            for (int i = 0; i < 20; i++) {
                char *a = shmat(id, NULL, 0);
                if (a == (void *) -1 || munmap(a, 4096) < 0)
                    _exit(24);
            }
            _exit(0);
        }
        int gst;
        _exit(gc < 0 || waitpid(gc, &gst, 0) < 0 || !WIFEXITED(gst)
                  ? 24
                  : WEXITSTATUS(gst));
    }
    int hst;
    int hrc = holder < 0 || waitpid(holder, &hst, 0) < 0 || !WIFEXITED(hst)
                  ? 24
                  : WEXITSTATUS(hst);
    shmctl(id, IPC_RMID, NULL);
    if (hrc != 0)
        return hrc;
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

    SUMMARY("test-rlimit-mem");
    return fails ? 1 : 0;
}
