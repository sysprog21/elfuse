#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_mount
#define SYS_mount 40
#endif

#ifndef SYS_getdents64
#define SYS_getdents64 61
#endif

#ifndef O_PATH
#define O_PATH 010000000
#endif

#define FUSE_ROOT_ID 1
#define FUSE_ASYNC_READ (1u << 0)
#define FUSE_BIG_WRITES (1u << 5)
#define FUSE_MAX_PAGES (1u << 22)

enum fuse_opcode {
    FUSE_LOOKUP = 1,
    FUSE_FORGET = 2,
    FUSE_GETATTR = 3,
    FUSE_OPEN = 14,
    FUSE_READ = 15,
    FUSE_RELEASE = 18,
    FUSE_INIT = 26,
    FUSE_OPENDIR = 27,
    FUSE_READDIR = 28,
    FUSE_RELEASEDIR = 29,
    FUSE_INTERRUPT = 36,
    FUSE_BATCH_FORGET = 42,
};

struct fuse_attr {
    uint64_t ino, size, blocks, atime, mtime, ctime;
    uint32_t atimensec, mtimensec, ctimensec;
    uint32_t mode, nlink, uid, gid, rdev, blksize, flags;
};

struct fuse_entry_out {
    uint64_t nodeid, generation, entry_valid, attr_valid;
    uint32_t entry_valid_nsec, attr_valid_nsec;
    struct fuse_attr attr;
};

struct fuse_attr_out {
    uint64_t attr_valid;
    uint32_t attr_valid_nsec;
    uint32_t dummy;
    struct fuse_attr attr;
};

struct fuse_open_out {
    uint64_t fh;
    uint32_t open_flags;
    int32_t backing_id;
};

struct fuse_read_in {
    uint64_t fh;
    uint64_t offset;
    uint32_t size;
    uint32_t read_flags;
    uint64_t lock_owner;
    uint32_t flags;
    uint32_t padding;
};

struct fuse_forget_in {
    uint64_t nlookup;
};

struct fuse_interrupt_in {
    uint64_t unique;
};

struct fuse_batch_forget_in {
    uint32_t count;
    uint32_t dummy;
};

struct fuse_forget_one {
    uint64_t nodeid;
    uint64_t nlookup;
};

struct fuse_init_out {
    uint32_t major, minor, max_readahead, flags;
    uint16_t max_background, congestion_threshold;
    uint32_t max_write, time_gran;
    uint16_t max_pages, map_alignment;
    uint32_t flags2, max_stack_depth;
    uint16_t request_timeout, unused[11];
};

struct fuse_in_header {
    uint32_t len, opcode;
    uint64_t unique, nodeid;
    uint32_t uid, gid, pid;
    uint16_t total_extlen, padding;
};

struct fuse_out_header {
    uint32_t len;
    int32_t error;
    uint64_t unique;
};

struct fuse_dirent {
    uint64_t ino;
    uint64_t off;
    uint32_t namelen;
    uint32_t type;
    char name[];
};

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

/* Byte the over-reply daemon floods with, distinct from anything in hello_data
 * so a canary check can tell a spill apart from stale memory.
 */
#define OVER_REPLY_FILL 0xA5

static const char hello_name[] = "hello";
static const char hello_data[] = "hello from guest fuse\n";
static const char source_name[] = "elfuse-test";

typedef struct {
    int fusefd;
    int saw_release;
    int saw_releasedir;
    int init_error;
    int saw_interrupt;
    int saw_forget;
    uint64_t forget_nlookup_total;
    uint64_t pending_read_unique;
    int stall_read_once;
    int stalled_read_active;

    /* When set, FUSE_READ answers with more bytes than fuse_read_in.size asked
     * for. A daemon is a guest process like any other, so nothing stops it; the
     * transport must not pass the surplus through to the reader's buffer.
     */
    int over_reply_read;
} daemon_ctx_t;

static volatile sig_atomic_t got_usr1;
static volatile sig_atomic_t got_sigio;

static void sigusr1_handler(int signum)
{
    (void) signum;
    got_usr1 = 1;
}

static void sigio_handler(int signum)
{
    (void) signum;
    got_sigio = 1;
}

static void *signal_sender_main(void *arg)
{
    pthread_t *target = arg;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
        perror("pthread_sigmask");
        exit(1);
    }
    usleep(100000);
    if (pthread_kill(*target, SIGUSR1) != 0) {
        perror("pthread_kill");
        exit(1);
    }
    return NULL;
}

static void fill_dir_attr(struct fuse_attr *attr)
{
    memset(attr, 0, sizeof(*attr));
    attr->ino = 1;
    attr->mode = S_IFDIR | 0755;
    attr->nlink = 2;
    attr->uid = getuid();
    attr->gid = getgid();
    attr->blksize = 4096;
}

static void fill_file_attr(struct fuse_attr *attr)
{
    memset(attr, 0, sizeof(*attr));
    attr->ino = 2;
    attr->mode = S_IFREG | 0644;
    attr->nlink = 1;
    attr->uid = getuid();
    attr->gid = getgid();
    attr->size = sizeof(hello_data) - 1;
    attr->blocks = 1;
    attr->blksize = 4096;
}

static int reply_frame(int fd,
                       uint64_t unique,
                       int32_t error,
                       const void *payload,
                       size_t len)
{
    uint8_t buf[4096];
    struct fuse_out_header out = {
        .len = (uint32_t) (sizeof(out) + len),
        .error = error,
        .unique = unique,
    };
    memcpy(buf, &out, sizeof(out));
    if (len)
        memcpy(buf + sizeof(out), payload, len);
    if (write(fd, buf, sizeof(out) + len) != (ssize_t) (sizeof(out) + len)) {
        perror("write(/dev/fuse)");
        return -1;
    }
    return 0;
}

static size_t append_dirent(uint8_t *buf,
                            size_t off,
                            uint64_t ino,
                            uint64_t next_off,
                            unsigned type,
                            const char *name)
{
    struct fuse_dirent *de = (struct fuse_dirent *) (buf + off);
    size_t namelen = strlen(name);
    size_t reclen = (24 + namelen + 7) & ~7ULL;
    de->ino = ino;
    de->off = next_off;
    de->namelen = (uint32_t) namelen;
    de->type = type;
    memcpy(de->name, name, namelen);
    memset(((uint8_t *) de) + 24 + namelen, 0, reclen - (24 + namelen));
    return off + reclen;
}

static void *daemon_main(void *arg)
{
    daemon_ctx_t *ctx = arg;
    const size_t map_len = 4UL << 20;
#if defined(__x86_64__)
    /* Rosetta serializes mmap; allocate before serving a file-mmap request. */
    void *mapping = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        exit(1);
#endif
    for (;;) {
#if !defined(__x86_64__)
        /* Each request must reach a buffer the daemon has never touched. */
        void *mapping = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED)
            exit(1);
#endif
        uint8_t *buf = (uint8_t *) mapping + (2UL << 20);
        ssize_t nr = read(ctx->fusefd, buf, 4096);
        if (nr < 0) {
            if (errno == ENOTCONN || errno == EBADF) {
                munmap(mapping, map_len);
                return NULL;
            }
            perror("read(/dev/fuse)");
            exit(1);
        }

        struct fuse_in_header *in = (struct fuse_in_header *) buf;
        switch (in->opcode) {
        case FUSE_INIT: {
            if (ctx->init_error) {
                if (reply_frame(ctx->fusefd, in->unique, -ctx->init_error, NULL,
                                0) < 0)
                    exit(1);
                munmap(mapping, map_len);
                return NULL;
            }
            struct fuse_init_out out = {
                .major = 7,
                .minor = 45,
                .max_readahead = 1024 * 1024,
                .flags = FUSE_ASYNC_READ | FUSE_BIG_WRITES | FUSE_MAX_PAGES,
                .max_write = 65536,
                .max_pages = 16,
            };
            if (reply_frame(ctx->fusefd, in->unique, 0, &out, sizeof(out)) < 0)
                exit(1);
            break;
        }
        case FUSE_GETATTR: {
            struct fuse_attr_out out;
            memset(&out, 0, sizeof(out));
            if (in->nodeid == FUSE_ROOT_ID)
                fill_dir_attr(&out.attr);
            else if (in->nodeid == 2)
                fill_file_attr(&out.attr);
            else if (reply_frame(ctx->fusefd, in->unique, -ENOENT, NULL, 0) < 0)
                exit(1);
            if (in->nodeid == FUSE_ROOT_ID || in->nodeid == 2) {
                if (reply_frame(ctx->fusefd, in->unique, 0, &out, sizeof(out)) <
                    0)
                    exit(1);
            }
            break;
        }
        case FUSE_LOOKUP: {
            const char *name = (const char *) (buf + sizeof(*in));
            if (in->nodeid != FUSE_ROOT_ID || strcmp(name, hello_name)) {
                if (reply_frame(ctx->fusefd, in->unique, -ENOENT, NULL, 0) < 0)
                    exit(1);
                break;
            }
            struct fuse_entry_out out;
            memset(&out, 0, sizeof(out));
            out.nodeid = 2;
            fill_file_attr(&out.attr);
            if (reply_frame(ctx->fusefd, in->unique, 0, &out, sizeof(out)) < 0)
                exit(1);
            break;
        }
        case FUSE_OPENDIR: {
            struct fuse_open_out out = {.fh = 10};
            if (reply_frame(ctx->fusefd, in->unique, 0, &out, sizeof(out)) < 0)
                exit(1);
            break;
        }
        case FUSE_OPEN: {
            struct fuse_open_out out = {.fh = 11};
            if (reply_frame(ctx->fusefd, in->unique, 0, &out, sizeof(out)) < 0)
                exit(1);
            break;
        }
        case FUSE_READDIR: {
            struct fuse_read_in *rin =
                (struct fuse_read_in *) (buf + sizeof(*in));
            uint8_t out[256];
            size_t out_len = 0;
            if (rin->offset == 0) {
                out_len = append_dirent(out, out_len, 1, 1, DT_DIR, ".");
                out_len = append_dirent(out, out_len, 1, 2, DT_DIR, "..");
                out_len = append_dirent(out, out_len, 2, 3, DT_REG, hello_name);
            }
            if (reply_frame(ctx->fusefd, in->unique, 0, out, out_len) < 0)
                exit(1);
            break;
        }
        case FUSE_READ: {
            struct fuse_read_in *rin =
                (struct fuse_read_in *) (buf + sizeof(*in));
            if (ctx->stall_read_once && !ctx->stalled_read_active) {
                ctx->stalled_read_active = 1;
                ctx->pending_read_unique = in->unique;
                break;
            }
            if (ctx->over_reply_read) {
                /* Deliberately antisocial: answer a small request with a large
                 * payload. reply_frame's buffer caps this at 4096 - 16.
                 */
                static uint8_t flood[4096 - 16];
                memset(flood, OVER_REPLY_FILL, sizeof(flood));
                if (reply_frame(ctx->fusefd, in->unique, 0, flood,
                                sizeof(flood)) < 0)
                    exit(1);
                break;
            }
            size_t len = sizeof(hello_data) - 1;
            if (rin->offset >= len) {
                if (reply_frame(ctx->fusefd, in->unique, 0, NULL, 0) < 0)
                    exit(1);
                break;
            }
            size_t avail = len - (size_t) rin->offset;
            if (avail > rin->size)
                avail = rin->size;
            if (reply_frame(ctx->fusefd, in->unique, 0,
                            hello_data + rin->offset, avail) < 0)
                exit(1);
            break;
        }
        case FUSE_FORGET: {
            struct fuse_forget_in *fin =
                (struct fuse_forget_in *) (buf + sizeof(*in));
            ctx->saw_forget = 1;
            ctx->forget_nlookup_total += fin->nlookup;
            break;
        }
        case FUSE_BATCH_FORGET: {
            struct fuse_batch_forget_in *bin =
                (struct fuse_batch_forget_in *) (buf + sizeof(*in));
            struct fuse_forget_one *items =
                (struct fuse_forget_one *) (bin + 1);
            size_t max_count =
                (size_t) (nr - (ssize_t) sizeof(*in) - (ssize_t) sizeof(*bin)) /
                sizeof(*items);
            if (bin->count > max_count) {
                fprintf(stderr, "short BATCH_FORGET payload\n");
                exit(1);
            }
            ctx->saw_forget = 1;
            for (uint32_t i = 0; i < bin->count; i++)
                ctx->forget_nlookup_total += items[i].nlookup;
            break;
        }
        case FUSE_INTERRUPT: {
            struct fuse_interrupt_in *iin =
                (struct fuse_interrupt_in *) (buf + sizeof(*in));
            if (ctx->pending_read_unique != 0 &&
                iin->unique == ctx->pending_read_unique) {
                ctx->saw_interrupt = 1;
                if (reply_frame(ctx->fusefd, ctx->pending_read_unique, 0,
                                hello_data, sizeof(hello_data) - 1) < 0)
                    exit(1);
                ctx->pending_read_unique = 0;
                ctx->stall_read_once = 0;
                ctx->stalled_read_active = 0;
            }
            break;
        }
        case FUSE_RELEASE:
            ctx->saw_release = 1;
            if (reply_frame(ctx->fusefd, in->unique, 0, NULL, 0) < 0)
                exit(1);
            break;
        case FUSE_RELEASEDIR:
            ctx->saw_releasedir = 1;
            if (reply_frame(ctx->fusefd, in->unique, 0, NULL, 0) < 0)
                exit(1);
            break;
        default:
            if (reply_frame(ctx->fusefd, in->unique, -ENOSYS, NULL, 0) < 0)
                exit(1);
            break;
        }
#if !defined(__x86_64__)
        munmap(mapping, map_len);
#endif
    }
}

static void die(const char *msg)
{
    perror(msg);
    exit(1);
}

static void expect_contains(const char *path, const char *needle)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        die(path);
    char buf[4096];
    ssize_t nr = read(fd, buf, sizeof(buf) - 1);
    if (nr < 0)
        die("read(procfs)");
    buf[nr] = '\0';
    close(fd);
    if (!strstr(buf, needle)) {
        fprintf(stderr, "%s missing '%s'\n", path, needle);
        exit(1);
    }
}

static void expect_hello_fd(int fd)
{
    char buf[64];
    ssize_t nr = read(fd, buf, sizeof(buf));
    if (nr != (ssize_t) (sizeof(hello_data) - 1) ||
        memcmp(buf, hello_data, sizeof(hello_data) - 1) != 0) {
        fprintf(stderr, "unexpected read payload\n");
        exit(1);
    }
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) < 0)
        die("sigaction(SIGUSR1)");

    const char *mount_dir = "/mnt/fuse";
    if (access(mount_dir, F_OK) < 0)
        die("access(mountpoint)");
    if (access("/dev/fuse", F_OK) < 0)
        die("access(/dev/fuse)");

    struct stat st;
    if (stat("/dev/fuse", &st) < 0)
        die("stat(/dev/fuse)");
    if (!S_ISCHR(st.st_mode)) {
        fprintf(stderr, "/dev/fuse is not a character device\n");
        return 1;
    }

    int fusefd = open("/dev/fuse", O_RDWR);
    if (fusefd < 0)
        die("open(/dev/fuse)");
    if (fstat(fusefd, &st) < 0)
        die("fstat(/dev/fuse)");
    if (!S_ISCHR(st.st_mode)) {
        fprintf(stderr, "fstat(/dev/fuse) did not report char device\n");
        return 1;
    }
    close(fusefd);

    int bad_fusefd = open("/dev/fuse", O_RDWR);
    if (bad_fusefd < 0)
        die("open(/dev/fuse bad)");

    daemon_ctx_t bad_ctx = {.fusefd = bad_fusefd, .init_error = EPROTO};
    pthread_t bad_tid;
    if (pthread_create(&bad_tid, NULL, daemon_main, &bad_ctx) != 0) {
        errno = EINVAL;
        die("pthread_create bad daemon");
    }

    char opts[128];
    snprintf(opts, sizeof(opts), "fd=%d,rootmode=40000,user_id=%u,group_id=%u",
             bad_fusefd, (unsigned) getuid(), (unsigned) getgid());
    errno = 0;
    if (syscall(SYS_mount, source_name, mount_dir, "fuse", 0, opts) >= 0 ||
        errno != EPROTO) {
        fprintf(stderr, "expected mount INIT failure as EPROTO, got errno=%d\n",
                errno);
        return 1;
    }
    close(bad_fusefd);
    if (pthread_join(bad_tid, NULL) != 0) {
        errno = EINVAL;
        die("pthread_join bad daemon");
    }

    fusefd = open("/dev/fuse", O_RDWR);
    if (fusefd < 0)
        die("open(/dev/fuse good)");
    struct sigaction sigio_sa;
    memset(&sigio_sa, 0, sizeof(sigio_sa));
    sigio_sa.sa_handler = sigio_handler;
    sigemptyset(&sigio_sa.sa_mask);
    if (sigaction(SIGIO, &sigio_sa, NULL) < 0)
        die("sigaction(SIGIO)");
    if (fcntl(fusefd, F_SETOWN, getpid()) < 0)
        die("fcntl(F_SETOWN fusefd)");
    int fuse_fl = fcntl(fusefd, F_GETFL);
    if (fuse_fl < 0 || fcntl(fusefd, F_SETFL, fuse_fl | O_ASYNC) < 0)
        die("fcntl(F_SETFL O_ASYNC fusefd)");

    /* Route the daemon and the mount through a dup of the device fd: the
     * original is closed after INIT below, and SIGIO must keep flowing since
     * O_ASYNC and the owner live on the shared open-file description.
     */
    int sigio_origfd = fusefd;
    fusefd = dup(sigio_origfd);
    if (fusefd < 0)
        die("dup(/dev/fuse)");

    daemon_ctx_t ctx = {.fusefd = fusefd};
    pthread_t tid;
    if (pthread_create(&tid, NULL, daemon_main, &ctx) != 0) {
        errno = EINVAL;
        die("pthread_create");
    }

    snprintf(opts, sizeof(opts), "fd=%d,rootmode=40000,user_id=%u,group_id=%u",
             fusefd, (unsigned) getuid(), (unsigned) getgid());
    if (syscall(SYS_mount, source_name, mount_dir, "fuse", 0, opts) < 0)
        die("mount(fuse)");
    for (int i = 0; i < 2000 && !got_sigio; i++)
        usleep(1000);
    if (!got_sigio) {
        fprintf(stderr, "no SIGIO on FUSE device readiness\n");
        return 1;
    }

    if (stat(mount_dir, &st) < 0)
        die("stat(mountpoint)");
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "mountpoint is not a directory\n");
        return 1;
    }

    /* Close the original device fd: the session must repoint synchronous SIGIO
     * delivery at the surviving dup, so the next request still raises the
     * signal.
     */
    if (close(sigio_origfd) < 0)
        die("close(original /dev/fuse fd)");
    got_sigio = 0;
    if (stat(mount_dir, &st) < 0)
        die("stat(mountpoint after close)");
    for (int i = 0; i < 2000 && !got_sigio; i++)
        usleep(1000);
    if (!got_sigio) {
        fprintf(stderr, "no SIGIO after closing the original /dev/fuse fd\n");
        return 1;
    }

    /* Disarm O_ASYNC: every later FUSE request would otherwise raise SIGIO, and
     * a non-SA_RESTART handler firing mid-syscall surfaces spurious EINTR in
     * the unrelated tests below.
     */
    fuse_fl = fcntl(fusefd, F_GETFL);
    if (fuse_fl < 0 || fcntl(fusefd, F_SETFL, fuse_fl & ~O_ASYNC) < 0)
        die("fcntl(F_SETFL clear O_ASYNC)");

    expect_contains("/proc/self/mountinfo", mount_dir);
    expect_contains("/proc/self/mountinfo", " - fuse ");
    expect_contains("/proc/mounts", mount_dir);
    expect_contains("/proc/mounts", source_name);

    char hello_path[256];
    snprintf(hello_path, sizeof(hello_path), "%s/%s", mount_dir, hello_name);
    if (stat(hello_path, &st) < 0)
        die("stat(file)");
    if (!S_ISREG(st.st_mode) ||
        st.st_size != (off_t) (sizeof(hello_data) - 1)) {
        fprintf(stderr, "unexpected file stat\n");
        return 1;
    }

    int pathfd = open(hello_path, O_PATH);
    if (pathfd < 0)
        die("open(file O_PATH)");
    char path_buf[8];
    errno = 0;
    if (read(pathfd, path_buf, sizeof(path_buf)) >= 0 || errno != EBADF) {
        fprintf(stderr, "expected read(O_PATH file) to fail with EBADF\n");
        return 1;
    }
    close(pathfd);

    int pathdfd = open(mount_dir, O_PATH | O_DIRECTORY);
    if (pathdfd < 0)
        die("open(dir O_PATH)");
    char path_dents[128];
    errno = 0;
    if (syscall(SYS_getdents64, pathdfd, path_dents, sizeof(path_dents)) >= 0 ||
        errno != EBADF) {
        fprintf(stderr, "expected getdents64(O_PATH dir) to fail with EBADF\n");
        return 1;
    }
    if (fchdir(pathdfd) < 0)
        die("fchdir(O_PATH fuse-dir)");
    if (chdir("/") < 0)
        die("chdir(/ after O_PATH)");
    close(pathdfd);

    int fd = open(hello_path, O_RDONLY);
    if (fd < 0)
        die("open(file)");
    errno = 0;
    int wfd = open(hello_path, O_RDWR);
    if (wfd >= 0 || errno != EACCES) {
        fprintf(stderr, "expected O_RDWR FUSE open to fail with EACCES\n");
        return 1;
    }
    if (fstat(fd, &st) < 0)
        die("fstat(file)");
    char fdinfo_path[64];
    snprintf(fdinfo_path, sizeof(fdinfo_path), "/proc/self/fdinfo/%d", fd);
    expect_contains(fdinfo_path, "mnt_id:\t");
    expect_hello_fd(fd);
    int dupfd = dup(fd);
    if (dupfd < 0)
        die("dup(fuse-file)");
    char eof_probe[8];
    ssize_t dup_nr = read(dupfd, eof_probe, sizeof(eof_probe));
    if (dup_nr != 0) {
        fprintf(stderr, "expected dup'd FUSE file to share EOF offset\n");
        return 1;
    }
    close(dupfd);

    if (lseek(fd, 0, SEEK_SET) < 0)
        die("lseek(fuse-file)");
    ctx.stall_read_once = 1;
    got_usr1 = 0;
    pthread_t sender;
    pthread_t main_tid = pthread_self();
    if (pthread_create(&sender, NULL, signal_sender_main, &main_tid) != 0) {
        errno = EINVAL;
        die("pthread_create(signal sender)");
    }
    char intr_buf[64];
    errno = 0;
    if (read(fd, intr_buf, sizeof(intr_buf)) >= 0 || errno != EINTR) {
        fprintf(stderr, "expected interrupted FUSE read to fail with EINTR\n");
        return 1;
    }
    if (pthread_join(sender, NULL) != 0) {
        errno = EINVAL;
        die("pthread_join(signal sender)");
    }
    if (!got_usr1) {
        fprintf(stderr, "SIGUSR1 handler did not run\n");
        return 1;
    }
    expect_hello_fd(fd);

    /* A daemon that answers with more than it was asked for must not reach past
     * the reader's buffer. Linux sizes the copy from the request, so read(2)
     * can never return more than count; elfuse must match. Canaries around a
     * deliberately small buffer catch a spill in either direction.
     */
    if (lseek(fd, 0, SEEK_SET) < 0)
        die("lseek(fuse-file)");
    ctx.over_reply_read = 1;
    struct {
        uint8_t lead[64];
        uint8_t body[16];
        uint8_t trail[64];
    } guarded;
    memset(&guarded, 0x5C, sizeof(guarded));
    ssize_t over_rc = read(fd, guarded.body, sizeof(guarded.body));
    ctx.over_reply_read = 0;
    if (over_rc < 0)
        die("read(over-replying fuse file)");
    if ((size_t) over_rc > sizeof(guarded.body)) {
        fprintf(stderr, "read returned %zd for a %zu-byte request\n", over_rc,
                sizeof(guarded.body));
        return 1;
    }
    for (size_t i = 0; i < sizeof(guarded.lead); i++) {
        if (guarded.lead[i] != 0x5C || guarded.trail[i] != 0x5C) {
            fprintf(stderr,
                    "FUSE over-reply overran the read buffer at guard byte %zu "
                    "(lead=0x%02x trail=0x%02x)\n",
                    i, guarded.lead[i], guarded.trail[i]);
            return 1;
        }
    }
    if (lseek(fd, 0, SEEK_SET) < 0)
        die("lseek(fuse-file)");
    expect_hello_fd(fd);

    void *map;
#if !defined(__x86_64__)
    map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map != MAP_FAILED || errno != ENODEV) {
        fprintf(stderr,
                "expected mmap ENODEV on FUSE fd, got map=%p errno=%d\n", map,
                errno);
        return 1;
    }
#else
    /* Rosetta materialization waits for this daemon without holding mmap_lock.
     */
    void *fixed = (void *) (uintptr_t) (1ULL << 40);
    map =
        mmap(fixed, 4096, PROT_READ, MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, 0);
    if (map != fixed || memcmp(map, hello_data, sizeof(hello_data) - 1) != 0) {
        fprintf(stderr, "FUSE high-VA materialization failed: %p errno=%d\n",
                map, errno);
        return 1;
    }
    void *conflict =
        mmap(fixed, 4096, PROT_READ, MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, 0);
    if (conflict != MAP_FAILED || errno != EEXIST ||
        memcmp(map, hello_data, sizeof(hello_data) - 1) != 0) {
        fprintf(stderr, "FUSE high-VA NOREPLACE changed an existing mapping\n");
        return 1;
    }
    munmap(map, 4096);
#endif
    close(fd);

    /* Canonicalization: ./ and intermediate-up traversals must collapse to the
     * same file rather than be forwarded as literal FUSE_LOOKUP names. Without
     * canonicalization the daemon would receive LOOKUP for "." and fail.
     */
    char dot_path[256];
    snprintf(dot_path, sizeof(dot_path), "%s/./%s", mount_dir, hello_name);
    int dotfd = open(dot_path, O_RDONLY);
    if (dotfd < 0)
        die("open(./hello)");
    expect_hello_fd(dotfd);
    close(dotfd);

    /* sub/../hello must canonicalize to hello before the FUSE walk; the daemon
     * does not implement sub or "..", so this would fail with ENOENT if the
     * path were forwarded literally.
     */
    char up_path[256];
    snprintf(up_path, sizeof(up_path), "%s/sub/../%s", mount_dir, hello_name);
    int upfd = open(up_path, O_RDONLY);
    if (upfd < 0)
        die("open(sub/../hello)");
    expect_hello_fd(upfd);
    close(upfd);

    int dfd = open(mount_dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0)
        die("open(dir)");
    int dupdfd = dup(dfd);
    if (dupdfd < 0)
        die("dup(fuse-dir)");
    int relfd = openat(dfd, hello_name, O_RDONLY);
    if (relfd < 0)
        die("openat(dirfd, hello)");
    expect_hello_fd(relfd);
    close(relfd);

    if (fchdir(dfd) < 0)
        die("fchdir(fuse-dir)");
    relfd = open(hello_name, O_RDONLY);
    if (relfd < 0)
        die("open(cwd-relative hello)");
    expect_hello_fd(relfd);
    close(relfd);
    if (chdir("/") < 0)
        die("chdir(/)");

    if (chdir(mount_dir) < 0)
        die("chdir(mountpoint)");
    if (access(".", F_OK) < 0)
        die("access(.) inside fuse");
    if (stat(".", &st) < 0)
        die("stat(.) inside fuse");
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "stat(.) inside fuse is not a directory\n");
        return 1;
    }
    relfd = open(hello_name, O_RDONLY);
    if (relfd < 0)
        die("open(chdir-relative hello)");
    expect_hello_fd(relfd);
    close(relfd);
    if (chdir("/") < 0)
        die("chdir(/ restore)");

    char dents[512];
    ssize_t nr = syscall(SYS_getdents64, dfd, dents, sizeof(dents));
    if (nr < 0)
        die("getdents64");

    int found = 0;
    for (size_t off = 0; off < (size_t) nr;) {
        struct linux_dirent64 *de = (struct linux_dirent64 *) (dents + off);
        if (!strcmp(de->d_name, hello_name))
            found = 1;
        off += de->d_reclen;
    }
    if (!found) {
        fprintf(stderr, "readdir did not report %s\n", hello_name);
        return 1;
    }
    nr = syscall(SYS_getdents64, dupdfd, dents, sizeof(dents));
    if (nr != 0) {
        fprintf(stderr, "expected dup'd FUSE dir to share EOF offset\n");
        return 1;
    }

    /* Daemon-death + post-tombstone routing test.
     *
     * Set the virtual cwd to the FUSE mount via fchdir(dfd) so the consumer has
     * a FUSE-rooted relative-path baseline. Close /dev/fuse from the consumer
     * side to simulate daemon death: fuse_fd_cleanup tombstones the mount
     * (mount->session = NULL but the slot path/source/fstype/ mount_id stay
     * intact), wakes any blocked requests, and the daemon thread's next read
     * returns ENOTCONN and the thread exits.
     *
     * After the daemon is gone, a relative open from the still-FUSE-rooted
     * virtual cwd MUST return -LINUX_ENOTCONN rather than silently falling
     * through to host-relative open against the host cwd. The tombstoned mount
     * keeps the path matching FUSE, and fuse_open_path detects session==NULL
     * and returns ENOTCONN.
     */
    if (fchdir(dfd) < 0)
        die("fchdir(dfd) before daemon death");
    int alive_fd = open(hello_name, O_RDONLY);
    if (alive_fd < 0)
        die("open(hello) pre-death sanity");
    close(alive_fd);

    close(fusefd);
    fusefd = -1;
    if (pthread_join(tid, NULL) != 0) {
        errno = EINVAL;
        die("pthread_join after daemon death");
    }

    errno = 0;
    int dead_fd = open(hello_name, O_RDONLY);
    if (dead_fd >= 0 || errno != ENOTCONN) {
        fprintf(stderr,
                "expected ENOTCONN on post-death relative open;"
                " got fd=%d errno=%d (%s)\n",
                dead_fd, errno, strerror(errno));
        if (dead_fd >= 0)
            close(dead_fd);
        return 1;
    }

    if (chdir("/") < 0)
        die("chdir(/) after daemon death");
    close(dupdfd);
    close(dfd);
    if (!ctx.saw_interrupt) {
        fprintf(stderr, "daemon did not observe FUSE_INTERRUPT\n");
        return 1;
    }
    if (!ctx.saw_forget || ctx.forget_nlookup_total == 0) {
        fprintf(stderr, "daemon did not observe FUSE_FORGET traffic\n");
        return 1;
    }
    return 0;
}
