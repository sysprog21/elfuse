/*
 * FUSE open: file-slot lifetime and lock order against a guest-thread daemon.
 *
 * fuse_open_path reserves its slot from a 128-entry table before it locks the
 * session, so nothing reaches the daemon for an open that cannot get one, and
 * every way the open can fail afterwards has to hand the slot back.
 *
 *   slots  Each failing open below runs twice as many times as the table has
 *          slots, and then an ordinary open still has to succeed:
 *            - a name the daemon does not know (ENOENT, the path walk)
 *            - O_DIRECTORY on a regular file (ENOTDIR)
 *            - O_WRONLY, which FUSE files do not support yet (EACCES)
 *            - a full descriptor table (EMFILE, fd_alloc)
 *            - a daemon that fails FUSE_OPEN (EIO)
 *          A leaked slot shows up as ENFILE on the final open. Then the
 *          table is filled with open files: every open reports ENFILE, a
 *          missing name included, as Linux does when alloc_empty_file fails,
 *          and the daemon sees no FUSE_OPEN for any of them, so an O_TRUNC
 *          open cannot truncate the file it then fails to open. The daemon
 *          sees a FUSE_RELEASE for every FUSE_OPEN it answered with success.
 *
 *   order  Run with ELFUSE_FUSE_OPEN_LOCK_DELAY_US set, which holds the open
 *          inside the session lock. A stat started inside that window has
 *          taken fuse_lock and waits on the session lock. An open that reached
 *          for fuse_lock while holding the session lock deadlocked here. Both
 *          calls have to finish, and the stat has to have waited, which shows
 *          that the two calls overlapped.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "linux-fuse.h"

#define FILE_SLOTS 128 /* FUSE_MAX_OPEN_FILES */
#define SLOT_ROUNDS (2 * FILE_SLOTS)
#define ORDER_DEADLINE_MS 10000
#define ORDER_ATTEMPTS 5
#define OVERLAP_MIN_MS 50 /* the lane holds the open for 200 ms */

static const char file_data[] = "fuse open lock\n";
static const char good_name[] = "good";
static const char bad_name[] = "bad"; /* FUSE_OPEN answers EIO */

enum { GOOD_NODE = 2, BAD_NODE = 3 };

static char mount_dir[] = "/tmp/elfuse-fuse-open-lock.XXXXXX";
static char good_path[256], bad_path[256], missing_path[256];
static int fusefd = -1;
static _Atomic int opens_seen, opens_answered, releases_seen;

static void die(const char *msg)
{
    perror(msg);
    exit(1);
}

static void fill_attr(struct fuse_attr *attr, uint64_t ino)
{
    memset(attr, 0, sizeof(*attr));
    attr->ino = ino;
    attr->uid = getuid();
    attr->gid = getgid();
    attr->blksize = 4096;
    if (ino == FUSE_ROOT_ID) {
        attr->mode = S_IFDIR | 0755;
        attr->nlink = 2;
    } else {
        attr->mode = S_IFREG | 0644;
        attr->nlink = 1;
        attr->size = sizeof(file_data) - 1;
        attr->blocks = 1;
    }
}

static void reply(uint64_t unique,
                  int32_t error,
                  const void *payload,
                  size_t len)
{
    static uint8_t buf[8192];
    struct fuse_out_header out = {
        .len = (uint32_t) (sizeof(out) + len),
        .error = error,
        .unique = unique,
    };
    memcpy(buf, &out, sizeof(out));
    if (len)
        memcpy(buf + sizeof(out), payload, len);
    if (write(fusefd, buf, sizeof(out) + len) != (ssize_t) (sizeof(out) + len))
        die("write(/dev/fuse)");
}

static void *daemon_main(void *arg)
{
    (void) arg;
    static uint8_t buf[1 << 17];
    for (;;) {
        ssize_t nr = read(fusefd, buf, sizeof(buf));
        if (nr < 0) {
            if (errno == ENOTCONN || errno == EBADF)
                return NULL;
            die("read(/dev/fuse)");
        }
        struct fuse_in_header *in = (struct fuse_in_header *) buf;
        switch (in->opcode) {
        case FUSE_INIT: {
            struct fuse_init_out out = {
                .major = 7,
                .minor = 45,
                .max_readahead = 1024 * 1024,
                .max_write = 65536,
            };
            reply(in->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_GETATTR: {
            struct fuse_attr_out out;
            memset(&out, 0, sizeof(out));
            fill_attr(&out.attr, in->nodeid);
            reply(in->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_LOOKUP: {
            const char *name = (const char *) (in + 1);
            uint64_t node = 0;
            if (in->nodeid == FUSE_ROOT_ID && !strcmp(name, good_name))
                node = GOOD_NODE;
            else if (in->nodeid == FUSE_ROOT_ID && !strcmp(name, bad_name))
                node = BAD_NODE;
            if (!node) {
                reply(in->unique, -ENOENT, NULL, 0);
                break;
            }
            struct fuse_entry_out out;
            memset(&out, 0, sizeof(out));
            out.nodeid = node;
            fill_attr(&out.attr, node);
            reply(in->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_OPEN: {
            opens_seen++;
            if (in->nodeid == BAD_NODE) {
                reply(in->unique, -EIO, NULL, 0);
                break;
            }
            struct fuse_open_out out = {.fh = 7};
            opens_answered++;
            reply(in->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_READ: {
            struct fuse_read_in *rin = (struct fuse_read_in *) (in + 1);
            size_t total = sizeof(file_data) - 1;
            size_t avail = rin->offset < total ? total - rin->offset : 0;
            if (avail > rin->size)
                avail = rin->size;
            reply(in->unique, 0, file_data + rin->offset, avail);
            break;
        }
        case FUSE_RELEASE:
            releases_seen++;
            reply(in->unique, 0, NULL, 0);
            break;
        case FUSE_FORGET:
        case FUSE_BATCH_FORGET:
        case FUSE_INTERRUPT:
            break;
        default:
            reply(in->unique, -ENOSYS, NULL, 0);
            break;
        }
    }
}

static void start_thread(pthread_t *th, void *(*fn)(void *), void *arg)
{
    int rc = pthread_create(th, NULL, fn, arg);
    if (rc != 0) {
        errno = rc;
        die("pthread_create");
    }
}

static int failures;

static void expect_open_fails(const char *path,
                              int flags,
                              int want,
                              const char *what)
{
    errno = 0;
    int fd = open(path, flags);
    if (fd >= 0 || errno != want) {
        fprintf(stderr, "%s: open returned %d errno=%d, want errno=%d\n", what,
                fd, errno, want);
        if (fd >= 0)
            close(fd);
        failures++;
    }
}

static void expect_good_readable(const char *what)
{
    int fd = open(good_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: open(good) failed errno=%d\n", what, errno);
        failures++;
        return;
    }
    char buf[64];
    ssize_t nr = read(fd, buf, sizeof(buf));
    if (nr != (ssize_t) (sizeof(file_data) - 1) ||
        memcmp(buf, file_data, (size_t) nr) != 0) {
        fprintf(stderr, "%s: unexpected read payload (nr=%zd)\n", what, nr);
        failures++;
    }
    close(fd);
}

/* Fill the descriptor table, then a FUSE open has to fail in fd_alloc. */
static void expect_fd_table_full(void)
{
    struct rlimit old;
    if (getrlimit(RLIMIT_NOFILE, &old) < 0)
        die("getrlimit");
    struct rlimit low = {.rlim_cur = 64, .rlim_max = old.rlim_max};
    if (setrlimit(RLIMIT_NOFILE, &low) < 0)
        die("setrlimit");

    int fillers[64], n = 0;
    while (n < 64) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0)
            break;
        fillers[n++] = fd;
    }
    if (errno != EMFILE) {
        fprintf(stderr, "filling the fd table stopped with errno=%d\n", errno);
        failures++;
    } else {
        for (int i = 0; i < SLOT_ROUNDS; i++)
            expect_open_fails(good_path, O_RDONLY, EMFILE, "fd table full");
    }
    while (n > 0)
        close(fillers[--n]);
    if (setrlimit(RLIMIT_NOFILE, &old) < 0)
        die("setrlimit(restore)");
}

/* Fill the file-slot table with open files. Every further open then reports
 * ENFILE before it reaches the daemon, whatever name it gives.
 */
static void expect_slot_table_full(void)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
        die("getrlimit");
    if (rl.rlim_cur < FILE_SLOTS + 32) {
        rl.rlim_cur = FILE_SLOTS + 32;
        if (setrlimit(RLIMIT_NOFILE, &rl) < 0)
            die("setrlimit");
    }

    int held[FILE_SLOTS], n = 0;
    for (; n < FILE_SLOTS; n++) {
        held[n] = open(good_path, O_RDONLY);
        if (held[n] < 0) {
            fprintf(stderr, "open %d of %d failed errno=%d\n", n + 1,
                    FILE_SLOTS, errno);
            failures++;
            break;
        }
    }
    if (n == FILE_SLOTS) {
        int before = opens_seen;
        expect_open_fails(missing_path, O_RDONLY, ENFILE,
                          "slots full, missing");
        expect_open_fails(bad_path, O_RDONLY, ENFILE,
                          "slots full, FUSE_OPEN fails");
        expect_open_fails(good_path, O_RDONLY, ENFILE, "slots full");
        expect_open_fails(good_path, O_RDONLY | O_TRUNC, ENFILE,
                          "slots full, O_TRUNC");
        if (opens_seen != before) {
            fprintf(stderr, "daemon saw %d FUSE_OPEN with the table full\n",
                    opens_seen - before);
            failures++;
        }
    }
    while (n > 0)
        close(held[--n]);
    if (opens_answered != releases_seen) {
        fprintf(stderr,
                "daemon answered %d FUSE_OPEN but saw %d FUSE_RELEASE\n",
                opens_answered, releases_seen);
        failures++;
    }
}

static void run_slots(void)
{
    for (int i = 0; i < SLOT_ROUNDS; i++) {
        expect_open_fails(missing_path, O_RDONLY, ENOENT, "missing name");
        expect_open_fails(good_path, O_RDONLY | O_DIRECTORY, ENOTDIR,
                          "O_DIRECTORY on a file");
        expect_open_fails(good_path, O_WRONLY, EACCES, "O_WRONLY");
        expect_open_fails(bad_path, O_RDONLY, EIO, "FUSE_OPEN fails");
        if (failures)
            return;
    }
    expect_fd_table_full();
    expect_good_readable("after failed opens");
    expect_slot_table_full();
    expect_good_readable("after a full slot table");
}

static _Atomic int open_done, stat_done;
static _Atomic int open_rc, stat_rc;
static _Atomic long stat_ms;

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void *open_main(void *arg)
{
    (void) arg;
    int fd = open(good_path, O_RDONLY);
    open_rc = fd >= 0 ? 0 : errno;
    if (fd >= 0)
        close(fd);
    open_done = 1;
    return NULL;
}

static void *stat_main(void *arg)
{
    (void) arg;
    struct stat st;
    long start = now_ms();
    stat_rc = stat(good_path, &st) == 0 ? 0 : errno;
    stat_ms = now_ms() - start;
    stat_done = 1;
    return NULL;
}

/* One open held inside the session lock and one stat started 50 ms later.
 * Returns whether the stat waited on the open, which is what the attempt is
 * for; on a loaded host the opener can still be walking when the stat starts.
 */
static int order_attempt(void)
{
    open_done = stat_done = 0;
    open_rc = stat_rc = 0;
    pthread_t opener, statter;
    start_thread(&opener, open_main, NULL);
    usleep(50000);
    start_thread(&statter, stat_main, NULL);

    for (int ms = 0; ms < ORDER_DEADLINE_MS; ms += 10) {
        if (open_done && stat_done)
            break;
        usleep(10000);
    }
    if (!open_done || !stat_done) {
        /* The threads are stuck in host locks and cannot be joined. */
        fprintf(stderr, "open %s, stat %s after %d ms: lock-order deadlock\n",
                open_done ? "finished" : "stuck",
                stat_done ? "finished" : "stuck", ORDER_DEADLINE_MS);
        fflush(stderr);
        _exit(1);
    }
    pthread_join(opener, NULL);
    pthread_join(statter, NULL);
    if (open_rc || stat_rc) {
        fprintf(stderr, "open errno=%d, stat errno=%d\n", open_rc, stat_rc);
        failures++;
    }
    return stat_ms >= OVERLAP_MIN_MS;
}

static void run_order(void)
{
    /* Prime the lookup so the open below goes straight to the held window. */
    struct stat st;
    if (stat(good_path, &st) < 0)
        die("stat(prime)");

    for (int i = 0; i < ORDER_ATTEMPTS; i++) {
        int overlapped = order_attempt();
        if (failures || overlapped)
            return;
        fprintf(stderr, "attempt %d: stat took %ld ms, no overlap\n", i + 1,
                (long) stat_ms);
    }
    fprintf(stderr, "stat never waited on the held open (%d attempts)\n",
            ORDER_ATTEMPTS);
    failures++;
}

int main(int argc, char **argv)
{
    int order = argc > 1 && !strcmp(argv[1], "order");
    if (argc > 1 && !order && strcmp(argv[1], "slots") != 0) {
        fprintf(stderr, "usage: %s [slots|order]\n", argv[0]);
        return 2;
    }

    if (!mkdtemp(mount_dir))
        die("mkdtemp");
    snprintf(good_path, sizeof(good_path), "%s/%s", mount_dir, good_name);
    snprintf(bad_path, sizeof(bad_path), "%s/%s", mount_dir, bad_name);
    snprintf(missing_path, sizeof(missing_path), "%s/missing", mount_dir);

    fusefd = open("/dev/fuse", O_RDWR);
    if (fusefd < 0)
        die("open(/dev/fuse)");
    pthread_t daemon;
    start_thread(&daemon, daemon_main, NULL);

    char opts[128];
    snprintf(opts, sizeof(opts), "fd=%d,rootmode=40000,user_id=%u,group_id=%u",
             fusefd, (unsigned) getuid(), (unsigned) getgid());
    if (syscall(SYS_mount, "elfuse-test", mount_dir, "fuse", 0, opts) < 0)
        die("mount(fuse)");

    if (order)
        run_order();
    else
        run_slots();

    close(fusefd);
    pthread_join(daemon, NULL);
    rmdir(mount_dir);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test-fuse-open-lock %s: ok\n", order ? "order" : "slots");
    return 0;
}
