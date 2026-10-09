/*
 * One row per syscall flag: what the call answers with the flag and without
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The rows come from tests/flag-matrix.tbl through scripts/gen-flag-matrix.py.
 * This file only knows how to build an argument, issue a raw syscall, and read
 * back one kind of answer; it has no code for any particular syscall. Each row
 * runs twice against a freshly built fixture directory, once with the flag ORed
 * into the flags argument and once without, and both answers are asserted. A
 * flag that elfuse drops on the way to the host therefore fails its "with" run,
 * and a flag it applies unasked fails its "without" run.
 *
 * Every call goes through raw_syscall6 so that libc cannot rewrite the flags or
 * pick a different syscall.
 *
 * Syscalls exercised: the ones tests/flag-matrix.tbl names. The coverage audit
 * reads that list from the generator, not from this comment.
 */

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "raw-syscall.h"
#include "test-harness.h"

int passes = 0, fails = 0;
static int known;

#define FM_MAX_ARGS 6
#define FM_FILE_SIZE 10

enum fm_arg_kind {
    FM_A_INT,
    FM_A_CWD,
    FM_A_PATH,
    FM_A_FD,
    FM_A_BUF,
    FM_A_PAIR,
    FM_A_REGION,
    FM_A_FLAGS,
};
enum fm_path {
    FM_P_FILE,
    FM_P_DIR,
    FM_P_LINK,
    FM_P_DANGLING,
    FM_P_NEW,
    FM_P_EMPTY
};
enum fm_fd { FM_FD_FILE, FM_FD_DIR, FM_FD_LISTENER };

enum fm_expect_kind {
    FM_X_OK,
    FM_X_ERR,
    FM_X_FD,
    FM_X_FD_CLOEXEC,
    FM_X_FD_NOCLOEXEC,
    FM_X_FD_GETFL,
    FM_X_FD_NOGETFL,
    FM_X_PAIR1_GETFL,
    FM_X_PAIR1_NOGETFL,
    FM_X_FD_APPENDS,
    FM_X_FD_OVERWRITES,
    FM_X_FD_READ_EBADF,
    FM_X_EXISTS,
    FM_X_ABSENT,
    FM_X_LSTAT_REG,
    FM_X_LSTAT_LNK,
    FM_X_SIZE,
    FM_X_MODE,
    FM_X_STAT_REG,
    FM_X_STAT_LNK,
    FM_X_STATX_REG,
    FM_X_STATX_LNK,
    FM_X_ARG0_CLOEXEC,
    FM_X_ARG0_NOCLOEXEC,
    FM_X_ARG0_GETFL,
    FM_X_ARG0_NOGETFL,
    FM_X_MAP,
    FM_X_MAP_AT_REGION,
    FM_X_MAP_ELSEWHERE,
    FM_X_MAP_WRITABLE,
    FM_X_MAP_READONLY,
    FM_X_MAP_NOREAD,
    FM_X_MAP_WRITES_FILE,
    FM_X_MAP_KEEPS_FILE,
    FM_X_REGION_WRITABLE,
    FM_X_REGION_READONLY,
    FM_X_REGION_NOREAD,
};

struct fm_arg {
    enum fm_arg_kind kind;
    long val;
};

struct fm_expect {
    enum fm_expect_kind kind;
    long a, b;
};

struct fm_row {
    const char *sys, *flag;
    long nr, bits;
    int pending, nargs;
    struct fm_arg args[FM_MAX_ARGS];
    struct fm_expect with, without;
    int unsupported;
    struct fm_expect elfuse_with;
};

#include "flag-matrix-vectors.h"

static const char *const fm_paths[] = {
    [FM_P_FILE] = "file",         [FM_P_DIR] = "dir", [FM_P_LINK] = "link",
    [FM_P_DANGLING] = "dangling", [FM_P_NEW] = "new", [FM_P_EMPTY] = "",
};

static char fm_buf[4096];
static int fm_pair[2];
static long fm_arg0;

/* A fresh anonymous read-write mapping for the rows that need an address that
 * is already taken, or pages whose protection they change.
 */
#define FM_REGION_SIZE (2 * 65536)
static char *fm_region;

static sigjmp_buf fm_fault_jmp;

static void on_fault(int sig)
{
    (void) sig;
    siglongjmp(fm_fault_jmp, 1);
}

static int can_read(const volatile char *p)
{
    if (sigsetjmp(fm_fault_jmp, 1))
        return 0;
    volatile char c = *p;
    (void) c;
    return 1;
}

static int can_write(volatile char *p)
{
    if (sigsetjmp(fm_fault_jmp, 1))
        return 0;
    *p = 'Z';
    return 1;
}

/* A raw mmap return is an address unless it is one of the top 4095 values. */
static int is_mapping(long rc)
{
    return (unsigned long) rc < (unsigned long) -4095L;
}
static int fm_client = -1;
static char fm_why[160];

/* Put the fixture directory back to its starting state. The previous run may
 * have removed, renamed, or replaced any entry, so each one is removed as
 * whatever it is now before it is made again.
 */
static int fixture_reset(void)
{
    static const char *const names[] = {"file",     "dir", "link",
                                        "dangling", "new", "sock"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (unlink(names[i]) < 0 && errno != ENOENT && rmdir(names[i]) < 0 &&
            errno != ENOENT)
            return -1;
    }

    int fd = open("file", O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, "0123456789", FM_FILE_SIZE);
    close(fd);
    if (n != FM_FILE_SIZE || chmod("file", 0644) < 0)
        return -1;
    if (mkdir("dir", 0755) < 0 || symlink("file", "link") < 0 ||
        symlink("nowhere", "dangling") < 0)
        return -1;
    return 0;
}

/* A listening Unix socket with one connection already queued, so that an accept
 * on it returns at once. The connecting end is kept in fm_client until the run
 * is over.
 */
static long open_listener(void)
{
    struct sockaddr_un addr = {.sun_family = AF_UNIX, .sun_path = "sock"};
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
        listen(fd, 1) < 0)
        goto fail;
    fm_client = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fm_client < 0 ||
        connect(fm_client, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        goto fail;
    return fd;
fail:
    close(fd);
    return -1;
}

static long open_fixture_fd(long which)
{
    if (which == FM_FD_DIR)
        return open("dir", O_RDONLY | O_DIRECTORY);
    if (which == FM_FD_LISTENER)
        return open_listener();
    return open("file", O_RDWR);
}

/* Read back one answer. rc is the raw syscall return. On a mismatch the reason
 * is left in fm_why and 0 is returned.
 */
static int answer_matches(const struct fm_expect *x, long rc)
{
    struct stat st;
    int fl;

#define WHY(...) snprintf(fm_why, sizeof(fm_why), __VA_ARGS__)

    switch (x->kind) {
    case FM_X_OK:
    case FM_X_FD:
        if (rc < 0)
            return WHY("rc=%ld, want >= 0", rc), 0;
        return 1;
    case FM_X_ERR:
        if (rc != -x->a)
            return WHY("rc=%ld, want %ld", rc, -x->a), 0;
        return 1;
    case FM_X_FD_CLOEXEC:
    case FM_X_FD_NOCLOEXEC:
        if (rc < 0)
            return WHY("rc=%ld, want an fd", rc), 0;
        fl = fcntl((int) rc, F_GETFD);
        if (fl < 0)
            return WHY("F_GETFD failed, errno=%d", errno), 0;
        if (!!(fl & FD_CLOEXEC) != (x->kind == FM_X_FD_CLOEXEC))
            return WHY("F_GETFD=%#x", fl), 0;
        return 1;
    case FM_X_FD_GETFL:
    case FM_X_FD_NOGETFL:
    case FM_X_PAIR1_GETFL:
    case FM_X_PAIR1_NOGETFL: {
        int want_set = x->kind == FM_X_FD_GETFL || x->kind == FM_X_PAIR1_GETFL;
        if (rc < 0)
            return WHY("rc=%ld, want an fd", rc), 0;
        fl = fcntl((int) rc, F_GETFL);
        if (fl < 0)
            return WHY("F_GETFL failed, errno=%d", errno), 0;
        if (want_set ? (fl & x->a) != x->a : (fl & x->a) != 0)
            return WHY("F_GETFL=%#x, bits %#lx", fl, x->a), 0;
        return 1;
    }
    case FM_X_FD_APPENDS:
    case FM_X_FD_OVERWRITES:
        if (rc < 0)
            return WHY("rc=%ld, want an fd", rc), 0;
        if (lseek((int) rc, 0, SEEK_SET) != 0 || write((int) rc, "Z", 1) != 1 ||
            fstat((int) rc, &st) < 0)
            return WHY("probe write failed, errno=%d", errno), 0;
        if (st.st_size != FM_FILE_SIZE + (x->kind == FM_X_FD_APPENDS ? 1 : 0))
            return WHY("size %ld after a write at offset 0", (long) st.st_size),
                   0;
        return 1;
    case FM_X_FD_READ_EBADF:
        if (rc < 0)
            return WHY("rc=%ld, want an fd", rc), 0;
        if (read((int) rc, fm_buf, 1) != -1 || errno != EBADF)
            return WHY("read did not give EBADF, errno=%d", errno), 0;
        return 1;
    case FM_X_EXISTS:
    case FM_X_ABSENT:
        if (rc < 0)
            return WHY("rc=%ld, want >= 0", rc), 0;
        if ((lstat(fm_paths[x->a], &st) == 0) != (x->kind == FM_X_EXISTS))
            return WHY("\"%s\" %s", fm_paths[x->a],
                       x->kind == FM_X_EXISTS ? "is missing" : "still exists"),
                   0;
        return 1;
    case FM_X_LSTAT_REG:
    case FM_X_LSTAT_LNK:
        if (rc < 0)
            return WHY("rc=%ld, want >= 0", rc), 0;
        if (lstat(fm_paths[x->a], &st) < 0)
            return WHY("lstat \"%s\" failed, errno=%d", fm_paths[x->a], errno),
                   0;
        if (x->kind == FM_X_LSTAT_REG ? !S_ISREG(st.st_mode)
                                      : !S_ISLNK(st.st_mode))
            return WHY("\"%s\" has mode %#o", fm_paths[x->a],
                       (unsigned) st.st_mode),
                   0;
        return 1;
    case FM_X_SIZE:
    case FM_X_MODE:
        if (rc < 0)
            return WHY("rc=%ld, want >= 0", rc), 0;
        if (stat(fm_paths[x->a], &st) < 0)
            return WHY("stat \"%s\" failed, errno=%d", fm_paths[x->a], errno),
                   0;
        if (x->kind == FM_X_SIZE ? st.st_size != x->b
                                 : (long) (st.st_mode & 07777) != x->b)
            return WHY("\"%s\" has size %ld mode %#o", fm_paths[x->a],
                       (long) st.st_size, (unsigned) st.st_mode),
                   0;
        return 1;
    case FM_X_STAT_REG:
    case FM_X_STAT_LNK: {
        if (rc < 0)
            return WHY("rc=%ld, want >= 0", rc), 0;
        memcpy(&st, fm_buf, sizeof(st));
        if (x->kind == FM_X_STAT_REG ? !S_ISREG(st.st_mode)
                                     : !S_ISLNK(st.st_mode))
            return WHY("st_mode=%#o", (unsigned) st.st_mode), 0;
        return 1;
    }
    case FM_X_ARG0_CLOEXEC:
    case FM_X_ARG0_NOCLOEXEC:
        if (rc < 0)
            return WHY("rc=%ld, want >= 0", rc), 0;
        fl = fcntl((int) fm_arg0, F_GETFD);
        if (fl < 0 || !!(fl & FD_CLOEXEC) != (x->kind == FM_X_ARG0_CLOEXEC))
            return WHY("F_GETFD=%#x", fl), 0;
        return 1;
    case FM_X_ARG0_GETFL:
    case FM_X_ARG0_NOGETFL:
        if (rc < 0)
            return WHY("rc=%ld, want >= 0", rc), 0;
        fl = fcntl((int) fm_arg0, F_GETFL);
        if (fl < 0 || (x->kind == FM_X_ARG0_GETFL ? (fl & x->a) != x->a
                                                  : (fl & x->a) != 0))
            return WHY("F_GETFL=%#x, bits %#lx", fl, x->a), 0;
        return 1;
    case FM_X_MAP:
    case FM_X_MAP_AT_REGION:
    case FM_X_MAP_ELSEWHERE:
    case FM_X_MAP_WRITABLE:
    case FM_X_MAP_READONLY:
    case FM_X_MAP_NOREAD:
    case FM_X_MAP_WRITES_FILE:
    case FM_X_MAP_KEEPS_FILE: {
        char *p = (char *) rc;
        if (!is_mapping(rc))
            return WHY("rc=%ld, want an address", rc), 0;
        if (x->kind == FM_X_MAP)
            return 1;
        if (x->kind == FM_X_MAP_AT_REGION || x->kind == FM_X_MAP_ELSEWHERE) {
            if ((p == fm_region) != (x->kind == FM_X_MAP_AT_REGION))
                return WHY("mapped at %p, region is %p", (void *) p,
                           (void *) fm_region),
                       0;
            return 1;
        }
        if (x->kind == FM_X_MAP_NOREAD) {
            if (can_read(p))
                return WHY("the mapping is readable"), 0;
            return 1;
        }
        if (!can_read(p))
            return WHY("the mapping is not readable"), 0;
        if (x->kind == FM_X_MAP_READONLY) {
            if (can_write(p))
                return WHY("the mapping is writable"), 0;
            return 1;
        }
        if (!can_write(p))
            return WHY("the mapping is not writable"), 0;
        if (x->kind == FM_X_MAP_WRITABLE)
            return 1;

        /* The store above put 'Z' over the first byte. A shared mapping shows
         * it to a read of the file; a private one keeps it to itself.
         */
        char first = 0;
        int fd = open("file", O_RDONLY);
        if (fd < 0 || pread(fd, &first, 1, 0) != 1) {
            if (fd >= 0)
                close(fd);
            return WHY("cannot read the file back, errno=%d", errno), 0;
        }
        close(fd);
        if ((first == 'Z') != (x->kind == FM_X_MAP_WRITES_FILE))
            return WHY("the file starts with '%c'", first), 0;
        return 1;
    }
    case FM_X_REGION_WRITABLE:
    case FM_X_REGION_READONLY:
    case FM_X_REGION_NOREAD:
        if (rc < 0)
            return WHY("rc=%ld, want >= 0", rc), 0;
        if (can_read(fm_region) != (x->kind != FM_X_REGION_NOREAD))
            return WHY("the region is %sreadable",
                       x->kind == FM_X_REGION_NOREAD ? "" : "not "),
                   0;
        if (x->kind != FM_X_REGION_NOREAD &&
            can_write(fm_region) != (x->kind == FM_X_REGION_WRITABLE))
            return WHY("the region is %swritable",
                       x->kind == FM_X_REGION_WRITABLE ? "not " : ""),
                   0;
        return 1;
    case FM_X_STATX_REG:
    case FM_X_STATX_LNK: {
        struct statx sx;
        if (rc < 0)
            return WHY("rc=%ld, want >= 0", rc), 0;
        memcpy(&sx, fm_buf, sizeof(sx));
        if (x->kind == FM_X_STATX_REG ? !S_ISREG(sx.stx_mode)
                                      : !S_ISLNK(sx.stx_mode))
            return WHY("stx_mode=%#o", (unsigned) sx.stx_mode), 0;
        return 1;
    }
    }
#undef WHY
    return 0;
}

static int returns_fd(const struct fm_expect *x)
{
    return x->kind == FM_X_FD ||
           (x->kind >= FM_X_FD_CLOEXEC && x->kind <= FM_X_FD_READ_EBADF);
}

/* Returns 1 when the answer matched. A mismatch on a pending row is reported as
 * known and not counted, unless the run is strict.
 */
static int run_one(const struct fm_row *row, int with, int strict)
{
    const struct fm_expect *x = with ? &row->with : &row->without;
    char label[96];

    /* A flag elfuse declines on purpose has its own recorded answer, which only
     * a strict run sets aside.
     */
    if (with && row->unsupported && !strict)
        x = &row->elfuse_with;
    long a[FM_MAX_ARGS] = {0};
    long opened[FM_MAX_ARGS];
    int nopened = 0, matched = 0, pair = 0;

    snprintf(label, sizeof(label), "%s %s %s", row->sys, row->flag,
             with ? "set" : "clear");
    TEST(label);

    /* A broken fixture says nothing about this row's flag, so it ends the run
     * rather than failing every row after it.
     */
    if (fixture_reset() < 0) {
        printf("FIXTURE BROKEN (errno=%d)\n", errno);
        printf("\ntest-flag-matrix: fixture reset failed - FAIL\n");
        exit(2);
    }
    memset(fm_buf, 0, sizeof(fm_buf));
    fm_region = mmap(NULL, FM_REGION_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fm_region == MAP_FAILED) {
        FAIL("fixture region mmap failed");
        return 0;
    }

    for (int i = 0; i < row->nargs; i++) {
        const struct fm_arg *arg = &row->args[i];
        switch (arg->kind) {
        case FM_A_INT:
            a[i] = arg->val;
            break;
        case FM_A_CWD:
            a[i] = AT_FDCWD;
            break;
        case FM_A_PATH:
            a[i] = (long) fm_paths[arg->val];
            break;
        case FM_A_FD:
            a[i] = open_fixture_fd(arg->val);
            if (a[i] < 0) {
                FAIL("fixture fd open failed");
                goto out;
            }
            opened[nopened++] = a[i];
            break;
        case FM_A_BUF:
            a[i] = (long) fm_buf;
            break;
        case FM_A_PAIR:
            fm_pair[0] = fm_pair[1] = -1;
            a[i] = (long) fm_pair;
            pair = 1;
            break;
        case FM_A_REGION:
            a[i] = (long) fm_region;
            break;
        case FM_A_FLAGS:
            a[i] = arg->val | (with ? row->bits : 0);
            break;
        }
    }

    fm_arg0 = a[0];
    long rc = raw_syscall6(row->nr, a[0], a[1], a[2], a[3], a[4], a[5]);

    /* A call that fills an fd pair answers through both of them, unless the
     * answer names the second one.
     */
    if (pair && rc == 0 &&
        (x->kind == FM_X_PAIR1_GETFL || x->kind == FM_X_PAIR1_NOGETFL))
        matched = answer_matches(x, fm_pair[1]);
    else if (pair && rc == 0 && returns_fd(x))
        matched =
            answer_matches(x, fm_pair[0]) && answer_matches(x, fm_pair[1]);
    else
        matched = answer_matches(x, rc);
    if (matched) {
        PASS();
    } else if (row->pending && !strict) {
        printf("KNOWN: %s\n", fm_why);
        known++;
    } else {
        errno = 0;
        FAIL(fm_why);
    }
    if (pair && rc == 0) {
        close(fm_pair[0]);
        close(fm_pair[1]);
    } else if (rc >= 0 && returns_fd(x)) {
        close((int) rc);
    }

    if (x->kind >= FM_X_MAP && x->kind <= FM_X_MAP_KEEPS_FILE && is_mapping(rc))
        munmap((void *) rc, 4096);

out:
    munmap(fm_region, FM_REGION_SIZE);
    while (nopened > 0)
        close((int) opened[--nopened]);
    if (fm_client >= 0) {
        close(fm_client);
        fm_client = -1;
    }
    return matched;
}

int main(int argc, char **argv)
{
    int strict = argc > 1 && strcmp(argv[1], "strict") == 0;
    char dir[] = "/tmp/flag-matrix-XXXXXX";

    struct sigaction sa = {.sa_handler = on_fault};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    printf("test-flag-matrix: %zu rows\n",
           sizeof(fm_rows) / sizeof(fm_rows[0]));
    if (!mkdtemp(dir) || chdir(dir) < 0) {
        perror("fixture directory");
        return 1;
    }

    for (size_t i = 0; i < sizeof(fm_rows) / sizeof(fm_rows[0]); i++) {
        int ok = run_one(&fm_rows[i], 1, strict);
        ok &= run_one(&fm_rows[i], 0, strict);
        if (ok && fm_rows[i].pending && !strict) {
            char label[96];
            snprintf(label, sizeof(label), "%s %s", fm_rows[i].sys,
                     fm_rows[i].flag);
            TEST(label);
            errno = 0;
            FAIL("row passes; remove \"pending\" from tests/flag-matrix.tbl");
        }
    }

    static const char *const names[] = {"file",     "dir", "link",
                                        "dangling", "new", "sock"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (unlink(names[i]) < 0)
            rmdir(names[i]);
    }
    if (chdir("/") == 0)
        rmdir(dir);

    if (known)
        printf("\n%d known mismatch(es) on pending rows\n", known);
    SUMMARY("test-flag-matrix");
    return fails ? 1 : 0;
}
