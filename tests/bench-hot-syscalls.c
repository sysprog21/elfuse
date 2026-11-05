/*
 * Guest microbenchmark for hot Linux syscalls.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/uio.h>

#include "raw-syscall.h"

#ifndef RWF_APPEND
#define RWF_APPEND 0x00000010
#endif

#ifndef __NR_epoll_pwait2
#define __NR_epoll_pwait2 441
#endif

#ifndef LINUX_TIOCGSID
#define LINUX_TIOCGSID 0x5429
#endif

#ifndef LINUX_FIONREAD
#define LINUX_FIONREAD 0x541B
#endif

#ifndef LINUX_PR_GET_PDEATHSIG
#define LINUX_PR_GET_PDEATHSIG 2
#endif

typedef long (*bench_fn_t)(void *ctx);

typedef struct {
    const char *name;
    bench_fn_t fn;
    void *ctx;
} bench_case_t;

typedef struct {
    int fd, level, optname, value;
    socklen_t len;
} sockopt_ctx_t;

typedef struct {
    int oldfd, newfd;
} dup_ctx_t;

typedef struct {
    int fd;
    socklen_t len;
    struct sockaddr_un addr;
} sockname_ctx_t;

typedef struct {
    int txfd, rxfd;
    socklen_t addrlen;
    struct sockaddr_un addr;
    char payload[8], drain[8];
} sockaddr_io_ctx_t;

typedef struct {
    struct pollfd pfd;
    struct timespec ts;
} ppoll_ctx_t;

typedef struct {
    struct timespec ts;
} pselect_ctx_t;

typedef struct {
    int epfd;
    struct epoll_event ev;
    struct timespec ts;
} epoll_ctx_t;

typedef struct {
    char cwd[4096];
    char uts[512];
    char sysinfo[128];
    char rlimit[16];
    struct rusage usage;
    int ioctl_value;
    uint32_t resid[3];
} sysquery_ctx_t;

typedef struct {
    unsigned char *buf;
    size_t len;
} getrandom_ctx_t;

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static long bench_getpid(void *ctx)
{
    (void) ctx;
    return raw_getpid();
}

static long bench_getppid(void *ctx)
{
    (void) ctx;
    return raw_syscall0(__NR_getppid);
}

static long bench_gettid(void *ctx)
{
    (void) ctx;
    return raw_gettid();
}

static long bench_getuid(void *ctx)
{
    (void) ctx;
    return raw_syscall0(__NR_getuid);
}

static long bench_geteuid(void *ctx)
{
    (void) ctx;
    return raw_syscall0(__NR_geteuid);
}

static long bench_getgid(void *ctx)
{
    (void) ctx;
    return raw_syscall0(__NR_getgid);
}

static long bench_getegid(void *ctx)
{
    (void) ctx;
    return raw_syscall0(__NR_getegid);
}

static long bench_getpriority(void *ctx)
{
    (void) ctx;
    return raw_syscall2(__NR_getpriority, PRIO_PROCESS, 0);
}

static long bench_fadvise64(void *ctx)
{
    int fd = *(int *) ctx;
    return raw_syscall4(__NR_fadvise64, fd, 0, 0, POSIX_FADV_NORMAL);
}

static long bench_fcntl_getfd(void *ctx)
{
    int fd = *(int *) ctx;
    return raw_syscall3(__NR_fcntl, fd, F_GETFD, 0);
}

static long bench_fcntl_getfl(void *ctx)
{
    int fd = *(int *) ctx;
    return raw_syscall3(__NR_fcntl, fd, F_GETFL, 0);
}

static long bench_dup_close(void *ctx)
{
    int fd = *(int *) ctx;
    long newfd = raw_syscall1(__NR_dup, fd);
    if (newfd >= 0)
        raw_syscall1(__NR_close, newfd);
    return newfd;
}

static long bench_dup3_close(void *ctx)
{
    dup_ctx_t *dup = ctx;
    long newfd = raw_syscall3(__NR_dup3, dup->oldfd, dup->newfd, 0);
    if (newfd >= 0)
        raw_syscall1(__NR_close, newfd);
    return newfd;
}

static long bench_ioctl_tiocgsid(void *ctx)
{
    sysquery_ctx_t *sq = ctx;
    return raw_syscall3(__NR_ioctl, 0, LINUX_TIOCGSID, (long) &sq->ioctl_value);
}

static long bench_ioctl_fionread(void *ctx)
{
    sysquery_ctx_t *sq = ctx;
    return raw_syscall3(__NR_ioctl, sq->ioctl_value, LINUX_FIONREAD,
                        (long) &sq->rlimit);
}

static long bench_prctl_get_pdeathsig(void *ctx)
{
    sysquery_ctx_t *sq = ctx;
    return raw_syscall5(__NR_prctl, LINUX_PR_GET_PDEATHSIG,
                        (long) &sq->ioctl_value, 0, 0, 0);
}

static long bench_getsockname(void *ctx)
{
    sockname_ctx_t *sn = ctx;
    sn->len = sizeof(sn->addr);
    return raw_syscall3(__NR_getsockname, sn->fd, (long) &sn->addr,
                        (long) &sn->len);
}

static long bench_getpeername(void *ctx)
{
    sockname_ctx_t *sn = ctx;
    sn->len = sizeof(sn->addr);
    return raw_syscall3(__NR_getpeername, sn->fd, (long) &sn->addr,
                        (long) &sn->len);
}

static long bench_sendto_unix(void *ctx)
{
    sockaddr_io_ctx_t *sa = ctx;
    return raw_syscall6(__NR_sendto, sa->txfd, (long) sa->payload,
                        sizeof(sa->payload), 0, 0, 0);
}

static long bench_recvfrom_unix(void *ctx)
{
    sockaddr_io_ctx_t *sa = ctx;
    sa->addrlen = sizeof(sa->addr);
    long ret = raw_syscall6(__NR_recvfrom, sa->rxfd, (long) sa->drain,
                            sizeof(sa->drain), 0, (long) &sa->addr,
                            (long) &sa->addrlen);
    if (ret >= 0) {
        long drain = raw_syscall6(__NR_recvfrom, sa->txfd, (long) sa->payload,
                                  sizeof(sa->payload), 0, 0, 0);
        if (drain < 0)
            return drain;
    }
    return ret;
}

static long bench_clock_gettime(void *ctx)
{
    struct timespec *ts = ctx;
    return raw_syscall2(__NR_clock_gettime, CLOCK_MONOTONIC, (long) ts);
}

static long bench_gettimeofday(void *ctx)
{
    struct timeval *tv = ctx;
    return raw_syscall2(__NR_gettimeofday, (long) tv, 0);
}

static long bench_getrandom(void *ctx)
{
    getrandom_ctx_t *gr = ctx;
    return raw_syscall3(__NR_getrandom, (long) gr->buf, gr->len, 0);
}

static long bench_getgroups0(void *ctx)
{
    (void) ctx;
    return raw_syscall2(__NR_getgroups, 0, 0);
}

static long bench_getresuid(void *ctx)
{
    sysquery_ctx_t *sq = ctx;
    return raw_syscall3(__NR_getresuid, (long) &sq->resid[0],
                        (long) &sq->resid[1], (long) &sq->resid[2]);
}

static long bench_getresgid(void *ctx)
{
    sysquery_ctx_t *sq = ctx;
    return raw_syscall3(__NR_getresgid, (long) &sq->resid[0],
                        (long) &sq->resid[1], (long) &sq->resid[2]);
}

static long bench_uname(void *ctx)
{
    sysquery_ctx_t *sq = ctx;
    return raw_syscall1(__NR_uname, (long) sq->uts);
}

static long bench_getcwd(void *ctx)
{
    sysquery_ctx_t *sq = ctx;
    return raw_syscall2(__NR_getcwd, (long) sq->cwd, sizeof(sq->cwd));
}

static long bench_sysinfo(void *ctx)
{
    sysquery_ctx_t *sq = ctx;
    return raw_syscall1(__NR_sysinfo, (long) sq->sysinfo);
}

static long bench_getrlimit_nofile(void *ctx)
{
    sysquery_ctx_t *sq = ctx;
    return raw_syscall2(__NR_getrlimit, RLIMIT_NOFILE, (long) sq->rlimit);
}

static long bench_prlimit64_nofile(void *ctx)
{
    sysquery_ctx_t *sq = ctx;
    return raw_syscall4(__NR_prlimit64, 0, RLIMIT_NOFILE, 0, (long) sq->rlimit);
}

static long bench_getrusage_self(void *ctx)
{
    sysquery_ctx_t *sq = ctx;
    return raw_syscall2(__NR_getrusage, RUSAGE_SELF, (long) &sq->usage);
}

static long bench_getrusage_thread(void *ctx)
{
    sysquery_ctx_t *sq = ctx;
    return raw_syscall2(__NR_getrusage, RUSAGE_THREAD, (long) &sq->usage);
}

static long bench_sched_setaffinity(void *ctx)
{
    uint64_t *mask = ctx;
    return raw_syscall3(__NR_sched_setaffinity, 0, sizeof(*mask), (long) mask);
}

static long bench_setsockopt(void *ctx)
{
    sockopt_ctx_t *opt = ctx;
    return raw_syscall5(__NR_setsockopt, opt->fd, opt->level, opt->optname,
                        (long) &opt->value, opt->len);
}

static long bench_getsockopt(void *ctx)
{
    sockopt_ctx_t *opt = ctx;
    int value = 0;
    socklen_t len = sizeof(value);
    return raw_syscall5(__NR_getsockopt, opt->fd, opt->level, opt->optname,
                        (long) &value, (long) &len);
}

static long bench_ppoll1(void *ctx)
{
    ppoll_ctx_t *poll = ctx;
    return raw_syscall4(__NR_ppoll, (long) &poll->pfd, 1, (long) &poll->ts, 0);
}

static long bench_pselect0(void *ctx)
{
    pselect_ctx_t *ps = ctx;
    return raw_syscall6(__NR_pselect6, 0, 0, 0, 0, (long) &ps->ts, 0);
}

static long bench_epoll_pwait2_0(void *ctx)
{
    epoll_ctx_t *ep = ctx;
    return raw_syscall6(__NR_epoll_pwait2, ep->epfd, (long) &ep->ev, 1,
                        (long) &ep->ts, 0, 8);
}

typedef struct {
    int fd;
    struct iovec iov[2];
} iov_ctx_t;

static long bench_writev1(void *ctx)
{
    iov_ctx_t *iov = ctx;
    return raw_syscall3(__NR_writev, iov->fd, (long) &iov->iov[0], 1);
}

static long bench_writev2(void *ctx)
{
    iov_ctx_t *iov = ctx;
    return raw_syscall3(__NR_writev, iov->fd, (long) &iov->iov[0], 2);
}

static long bench_readv1(void *ctx)
{
    iov_ctx_t *iov = ctx;
    return raw_syscall3(__NR_readv, iov->fd, (long) &iov->iov[0], 1);
}

static long bench_readv2(void *ctx)
{
    iov_ctx_t *iov = ctx;
    return raw_syscall3(__NR_readv, iov->fd, (long) &iov->iov[0], 2);
}

typedef struct {
    int fd, flags;
    struct iovec iov[2];
} pwritev2_ctx_t;

typedef struct {
    const char *path;
    int dirfd;
} path_ctx_t;

typedef struct {
    const char *path;
    int dirfd, flags;
    unsigned int mask;
    unsigned char buf[256];
} statx_ctx_t;

typedef struct {
    int txfd, rxfd;
    struct iovec iov[2];
    struct msghdr msg;
    size_t send_len;
    char payload0[16], payload1[16];
    char drain0[16], drain1[16];
} msg_ctx_t;

typedef struct {
    int txfd, rxfd;
    struct iovec iov;
    struct mmsghdr mmsg;
    size_t send_len;
    char payload[16], drain[16];
} mmsg_ctx_t;

static long bench_pwritev1(void *ctx)
{
    iov_ctx_t *iov = ctx;
    return raw_syscall5(__NR_pwritev, iov->fd, (long) &iov->iov[0], 1, 0, 0);
}

static long bench_pwritev2v(void *ctx)
{
    iov_ctx_t *iov = ctx;
    return raw_syscall5(__NR_pwritev, iov->fd, (long) &iov->iov[0], 2, 0, 0);
}

static long bench_preadv1(void *ctx)
{
    iov_ctx_t *iov = ctx;
    return raw_syscall5(__NR_preadv, iov->fd, (long) &iov->iov[0], 1, 0, 0);
}

static long bench_preadv2v(void *ctx)
{
    iov_ctx_t *iov = ctx;
    return raw_syscall5(__NR_preadv, iov->fd, (long) &iov->iov[0], 2, 0, 0);
}

static long bench_pwritev2_append1(void *ctx)
{
    pwritev2_ctx_t *iov = ctx;
    return raw_syscall6(__NR_pwritev2, iov->fd, (long) &iov->iov[0], 1, 0, 0,
                        iov->flags);
}

static long bench_pwritev2_append2(void *ctx)
{
    pwritev2_ctx_t *iov = ctx;
    return raw_syscall6(__NR_pwritev2, iov->fd, (long) &iov->iov[0], 2, 0, 0,
                        iov->flags);
}

static long bench_newfstatat(void *ctx)
{
    path_ctx_t *path = ctx;
    struct stat st;
    return raw_syscall4(__NR_newfstatat, path->dirfd, (long) path->path,
                        (long) &st, 0);
}

static long bench_statx(void *ctx)
{
    statx_ctx_t *sx = ctx;
    return raw_syscall5(__NR_statx, sx->dirfd, (long) sx->path, sx->flags,
                        sx->mask, (long) sx->buf);
}

static long bench_openat_close(void *ctx)
{
    path_ctx_t *path = ctx;
    long fd =
        raw_syscall4(__NR_openat, path->dirfd, (long) path->path, O_RDONLY, 0);
    if (fd >= 0)
        raw_syscall1(__NR_close, fd);
    return fd;
}

static long bench_sendmsg1_roundtrip(void *ctx)
{
    msg_ctx_t *msg = ctx;
    long ret = raw_syscall3(__NR_sendmsg, msg->txfd, (long) &msg->msg, 0);
    if (ret >= 0) {
        long drain = raw_syscall6(__NR_recvfrom, msg->rxfd, (long) msg->drain0,
                                  sizeof(msg->drain0), 0, 0, 0);
        if (drain < 0)
            return drain;
    }
    return ret;
}

static long bench_recvmsg1_roundtrip(void *ctx)
{
    msg_ctx_t *msg = ctx;
    long sent = raw_syscall3(__NR_write, msg->txfd, (long) msg->payload0,
                             msg->send_len);
    if (sent < 0)
        return sent;
    return raw_syscall3(__NR_recvmsg, msg->rxfd, (long) &msg->msg, 0);
}

static long bench_sendmsg2_roundtrip(void *ctx)
{
    msg_ctx_t *msg = ctx;
    long ret = raw_syscall3(__NR_sendmsg, msg->txfd, (long) &msg->msg, 0);
    if (ret >= 0) {
        /* Drain into drain0 first, then drain1 if needed */
        long drain = raw_syscall6(__NR_recvfrom, msg->rxfd, (long) msg->drain0,
                                  sizeof(msg->drain0), 0, 0, 0);
        if (drain < 0)
            return drain;
    }
    return ret;
}

static long bench_recvmsg2_roundtrip(void *ctx)
{
    msg_ctx_t *msg = ctx;
    long sent = raw_syscall3(__NR_write, msg->txfd, (long) msg->payload0,
                             msg->send_len);
    if (sent < 0)
        return sent;
    return raw_syscall3(__NR_recvmsg, msg->rxfd, (long) &msg->msg, 0);
}

static long bench_sendmmsg1_roundtrip(void *ctx)
{
    mmsg_ctx_t *msg = ctx;
    long ret = raw_syscall4(__NR_sendmmsg, msg->txfd, (long) &msg->mmsg, 1, 0);
    if (ret >= 0) {
        long drain = raw_syscall6(__NR_recvfrom, msg->rxfd, (long) msg->drain,
                                  sizeof(msg->drain), 0, 0, 0);
        if (drain < 0)
            return drain;
    }
    return ret;
}

static long bench_recvmmsg1_roundtrip(void *ctx)
{
    mmsg_ctx_t *msg = ctx;
    long sent =
        raw_syscall3(__NR_write, msg->txfd, (long) msg->payload, msg->send_len);
    if (sent < 0)
        return sent;
    return raw_syscall5(__NR_recvmmsg, msg->rxfd, (long) &msg->mmsg, 1, 0, 0);
}

static void run_case(const bench_case_t *bc, unsigned long iters)
{
    uint64_t start = monotonic_ns();
    long last = 0;

    for (unsigned long i = 0; i < iters; i++)
        last = bc->fn(bc->ctx);

    uint64_t elapsed = monotonic_ns() - start;
    double ns_per_op = (double) elapsed / (double) iters;

    printf("%-20s %10.1f ns/op  last=%ld\n", bc->name, ns_per_op, last);
}

/* Everything the benchmark cases borrow: open descriptors, scratch buffers and
 * the per-case argument records. The descriptors start at -1 so one close
 * function releases whatever setup got as far as opening.
 */
typedef struct {
    int nullfd, sock, zerofd, regfd, epfd;
    int msg_sv[2], dgram_sv[2], pipefd[2], ep_pipefd[2];
    char tmp_path[32];
    struct timespec ts;
    struct timeval tv;
    unsigned char randbuf8[8], randbuf256[256];
    uint64_t affinity_mask;
    getrandom_ctx_t getrandom8_ctx, getrandom256_ctx;
    dup_ctx_t dup3_ctx;
    path_ctx_t path_ctx;
    statx_ctx_t statx_ctx;
    iov_ctx_t writev_ctx, readv_ctx, preadv_ctx, pwritev_ctx;
    pwritev2_ctx_t pwritev2_append_ctx;
    msg_ctx_t sendmsg_ctx, recvmsg_ctx, sendmsg2_ctx, recvmsg2_ctx;
    mmsg_ctx_t sendmmsg_ctx, recvmmsg_ctx;
    sockname_ctx_t getsockname_ctx, getpeername_ctx;
    sockaddr_io_ctx_t sendto_ctx, recvfrom_ctx;
    sockopt_ctx_t reuseaddr, nodelay, sndbuf;
    ppoll_ctx_t ppoll_ctx;
    pselect_ctx_t pselect_ctx;
    sysquery_ctx_t sysquery_ctx;
    epoll_ctx_t epoll_ctx;
} bench_fx_t;

static void close_fd(int *fd)
{
    if (*fd >= 0)
        close(*fd);
    *fd = -1;
}

static void bench_fx_close(bench_fx_t *fx)
{
    close_fd(&fx->epfd);
    close_fd(&fx->ep_pipefd[0]);
    close_fd(&fx->ep_pipefd[1]);
    close_fd(&fx->pipefd[0]);
    close_fd(&fx->pipefd[1]);
    close_fd(&fx->dgram_sv[0]);
    close_fd(&fx->dgram_sv[1]);
    close_fd(&fx->msg_sv[0]);
    close_fd(&fx->msg_sv[1]);
    if (fx->regfd >= 0) {
        close(fx->regfd);
        unlink(fx->tmp_path);
        fx->regfd = -1;
    }
    close_fd(&fx->zerofd);
    close_fd(&fx->sock);
    close_fd(&fx->nullfd);
}

/* Open every descriptor the cases need, in the order the cases were written.
 * Returns 0, or -1 after reporting the failing call; the caller closes whatever
 * was opened.
 */
static int bench_fx_open(bench_fx_t *fx)
{
    fx->nullfd = open("/dev/null", O_RDONLY);
    if (fx->nullfd < 0) {
        perror("open /dev/null");
        return -1;
    }
    fx->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (fx->sock < 0) {
        perror("socket");
        return -1;
    }
    fx->zerofd = open("/dev/zero", O_RDONLY);
    if (fx->zerofd < 0) {
        perror("open /dev/zero");
        return -1;
    }
    memcpy(fx->tmp_path, "/tmp/elfuse-bench-iov-XXXXXX",
           sizeof("/tmp/elfuse-bench-iov-XXXXXX"));
    fx->regfd = mkstemp(fx->tmp_path);
    if (fx->regfd < 0) {
        perror("mkstemp");
        return -1;
    }
    char reg_seed[32];
    memset(reg_seed, 'R', sizeof(reg_seed));
    if (write(fx->regfd, reg_seed, sizeof(reg_seed)) !=
        (ssize_t) sizeof(reg_seed)) {
        perror("seed write");
        return -1;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fx->msg_sv) < 0) {
        perror("socketpair");
        return -1;
    }
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fx->dgram_sv) < 0) {
        perror("socketpair dgram");
        return -1;
    }
    if (pipe(fx->pipefd) < 0 || pipe(fx->ep_pipefd) < 0) {
        perror("pipe");
        return -1;
    }
    fx->epfd = epoll_create1(0);
    if (fx->epfd < 0) {
        perror("epoll_create1");
        return -1;
    }
    struct epoll_event setup_ev = {
        .events = EPOLLIN,
        .data.fd = fx->ep_pipefd[0],
    };
    if (epoll_ctl(fx->epfd, EPOLL_CTL_ADD, fx->ep_pipefd[0], &setup_ev) < 0) {
        perror("epoll_ctl");
        return -1;
    }
    if (write(fx->pipefd[1], "f", 1) != 1) {
        perror("pipe seed");
        return -1;
    }
    return 0;
}

static void bench_fx_init(bench_fx_t *fx)
{
    memset(fx, 0, sizeof(*fx));
    fx->nullfd = fx->sock = fx->zerofd = fx->regfd = fx->epfd = -1;
    fx->msg_sv[0] = fx->msg_sv[1] = -1;
    fx->dgram_sv[0] = fx->dgram_sv[1] = -1;
    fx->pipefd[0] = fx->pipefd[1] = -1;
    fx->ep_pipefd[0] = fx->ep_pipefd[1] = -1;
}

/* Fill the per-case argument records from the descriptors just opened. The
 * records point into fx itself, so fx must not be copied afterwards.
 */
static void bench_fx_setup_ctxs(bench_fx_t *fx)
{
    fx->getrandom8_ctx = (getrandom_ctx_t) {
        .buf = fx->randbuf8,
        .len = sizeof(fx->randbuf8),
    };
    fx->getrandom256_ctx = (getrandom_ctx_t) {
        .buf = fx->randbuf256,
        .len = sizeof(fx->randbuf256),
    };
    fx->affinity_mask = 1;
    fx->dup3_ctx = (dup_ctx_t) {
        .oldfd = fx->nullfd,
        .newfd = 200,
    };

    fx->path_ctx = (path_ctx_t) {
        .path = fx->tmp_path,
        .dirfd = AT_FDCWD,
    };
    fx->statx_ctx = (statx_ctx_t) {
        .path = fx->tmp_path,
        .dirfd = AT_FDCWD,
        .flags = 0,
        .mask = 0x7ff,
    };

    static char writev_buf0[8] = "abcd123", writev_buf1[8] = "WXYZ789";
    static char readv_buf0[8], readv_buf1[8];
    fx->writev_ctx = (iov_ctx_t) {
        .fd = fx->nullfd,
        .iov =
            {
                {.iov_base = writev_buf0, .iov_len = sizeof(writev_buf0)},
                {.iov_base = writev_buf1, .iov_len = sizeof(writev_buf1)},
            },
    };
    fx->readv_ctx = (iov_ctx_t) {
        .fd = fx->zerofd,
        .iov =
            {
                {.iov_base = readv_buf0, .iov_len = sizeof(readv_buf0)},
                {.iov_base = readv_buf1, .iov_len = sizeof(readv_buf1)},
            },
    };
    fx->preadv_ctx = (iov_ctx_t) {
        .fd = fx->regfd,
        .iov =
            {
                {.iov_base = readv_buf0, .iov_len = sizeof(readv_buf0)},
                {.iov_base = readv_buf1, .iov_len = sizeof(readv_buf1)},
            },
    };
    fx->pwritev_ctx = (iov_ctx_t) {
        .fd = fx->regfd,
        .iov =
            {
                {.iov_base = writev_buf0, .iov_len = sizeof(writev_buf0)},
                {.iov_base = writev_buf1, .iov_len = sizeof(writev_buf1)},
            },
    };
    fx->pwritev2_append_ctx = (pwritev2_ctx_t) {
        .fd = fx->regfd,
        .flags = RWF_APPEND,
        .iov =
            {
                {.iov_base = writev_buf0, .iov_len = sizeof(writev_buf0)},
                {.iov_base = writev_buf1, .iov_len = sizeof(writev_buf1)},
            },
    };
    fx->sendmsg_ctx = (msg_ctx_t) {
        .txfd = fx->msg_sv[0],
        .rxfd = fx->msg_sv[1],
        .msg = {.msg_iov = NULL, .msg_iovlen = 1},
        .send_len = 8,
    };
    memcpy(fx->sendmsg_ctx.payload0, "sendmsg1", 8);
    fx->sendmsg_ctx.iov[0].iov_base = fx->sendmsg_ctx.payload0;
    fx->sendmsg_ctx.iov[0].iov_len = fx->sendmsg_ctx.send_len;
    fx->sendmsg_ctx.msg.msg_iov = &fx->sendmsg_ctx.iov[0];

    fx->recvmsg_ctx = (msg_ctx_t) {
        .txfd = fx->msg_sv[0],
        .rxfd = fx->msg_sv[1],
        .msg = {.msg_iov = NULL, .msg_iovlen = 1},
        .send_len = 8,
    };
    memcpy(fx->recvmsg_ctx.payload0, "recvmsg1", 8);
    fx->recvmsg_ctx.iov[0].iov_base = fx->recvmsg_ctx.drain0;
    fx->recvmsg_ctx.iov[0].iov_len = fx->recvmsg_ctx.send_len;
    fx->recvmsg_ctx.msg.msg_iov = &fx->recvmsg_ctx.iov[0];

    fx->sendmsg2_ctx = (msg_ctx_t) {
        .txfd = fx->msg_sv[0],
        .rxfd = fx->msg_sv[1],
        .msg = {.msg_iov = NULL, .msg_iovlen = 2},
        .send_len = 12,
    };
    memcpy(fx->sendmsg2_ctx.payload0, "send", 4);
    memcpy(fx->sendmsg2_ctx.payload1, "msg-2iov", 8);
    fx->sendmsg2_ctx.iov[0].iov_base = fx->sendmsg2_ctx.payload0;
    fx->sendmsg2_ctx.iov[0].iov_len = 4;
    fx->sendmsg2_ctx.iov[1].iov_base = fx->sendmsg2_ctx.payload1;
    fx->sendmsg2_ctx.iov[1].iov_len = 8;
    fx->sendmsg2_ctx.msg.msg_iov = &fx->sendmsg2_ctx.iov[0];

    fx->recvmsg2_ctx = (msg_ctx_t) {
        .txfd = fx->msg_sv[0],
        .rxfd = fx->msg_sv[1],
        .msg = {.msg_iov = NULL, .msg_iovlen = 2},
        .send_len = 12,
    };
    memcpy(fx->recvmsg2_ctx.payload0, "recv", 4);
    memcpy(fx->recvmsg2_ctx.payload1, "msg-2iov", 8);
    fx->recvmsg2_ctx.iov[0].iov_base = fx->recvmsg2_ctx.drain0;
    fx->recvmsg2_ctx.iov[0].iov_len = 4;
    fx->recvmsg2_ctx.iov[1].iov_base = fx->recvmsg2_ctx.drain1;
    fx->recvmsg2_ctx.iov[1].iov_len = 8;
    fx->recvmsg2_ctx.msg.msg_iov = &fx->recvmsg2_ctx.iov[0];
    fx->sendmmsg_ctx = (mmsg_ctx_t) {
        .txfd = fx->msg_sv[0],
        .rxfd = fx->msg_sv[1],
        .send_len = 8,
    };
    memcpy(fx->sendmmsg_ctx.payload, "sendmmsg", 8);
    fx->sendmmsg_ctx.iov.iov_base = fx->sendmmsg_ctx.payload;
    fx->sendmmsg_ctx.iov.iov_len = fx->sendmmsg_ctx.send_len;
    fx->sendmmsg_ctx.mmsg.msg_hdr.msg_iov = &fx->sendmmsg_ctx.iov;
    fx->sendmmsg_ctx.mmsg.msg_hdr.msg_iovlen = 1;

    fx->recvmmsg_ctx = (mmsg_ctx_t) {
        .txfd = fx->msg_sv[0],
        .rxfd = fx->msg_sv[1],
        .send_len = 8,
    };
    memcpy(fx->recvmmsg_ctx.payload, "recvmmsg", 8);
    fx->recvmmsg_ctx.iov.iov_base = fx->recvmmsg_ctx.drain;
    fx->recvmmsg_ctx.iov.iov_len = fx->recvmmsg_ctx.send_len;
    fx->recvmmsg_ctx.mmsg.msg_hdr.msg_iov = &fx->recvmmsg_ctx.iov;
    fx->recvmmsg_ctx.mmsg.msg_hdr.msg_iovlen = 1;
    fx->getsockname_ctx = (sockname_ctx_t) {
        .fd = fx->msg_sv[0],
        .len = sizeof(struct sockaddr_un),
    };
    fx->getpeername_ctx = (sockname_ctx_t) {
        .fd = fx->msg_sv[0],
        .len = sizeof(struct sockaddr_un),
    };
    fx->sendto_ctx = (sockaddr_io_ctx_t) {
        .txfd = fx->dgram_sv[0],
        .rxfd = fx->dgram_sv[1],
        .addrlen = sizeof(struct sockaddr_un),
    };
    memcpy(fx->sendto_ctx.payload, "sendto!!", sizeof(fx->sendto_ctx.payload));
    fx->recvfrom_ctx = (sockaddr_io_ctx_t) {
        .txfd = fx->dgram_sv[0],
        .rxfd = fx->dgram_sv[1],
        .addrlen = sizeof(struct sockaddr_un),
    };
    memcpy(fx->recvfrom_ctx.payload, "reply!!!",
           sizeof(fx->recvfrom_ctx.payload));

    fx->reuseaddr = (sockopt_ctx_t) {
        .fd = fx->sock,
        .level = SOL_SOCKET,
        .optname = SO_REUSEADDR,
        .value = 1,
        .len = sizeof(int),
    };
    fx->nodelay = (sockopt_ctx_t) {
        .fd = fx->sock,
        .level = IPPROTO_TCP,
        .optname = TCP_NODELAY,
        .value = 1,
        .len = sizeof(int),
    };
    fx->sndbuf = (sockopt_ctx_t) {
        .fd = fx->sock,
        .level = SOL_SOCKET,
        .optname = SO_SNDBUF,
        .value = 0,
        .len = sizeof(int),
    };
    fx->ppoll_ctx = (ppoll_ctx_t) {
        .pfd = {.fd = fx->pipefd[1], .events = POLLOUT, .revents = 0},
        .ts = {.tv_sec = 0, .tv_nsec = 0},
    };
    fx->pselect_ctx = (pselect_ctx_t) {
        .ts = {.tv_sec = 0, .tv_nsec = 0},
    };
    fx->sysquery_ctx = (sysquery_ctx_t) {0};
    fx->sysquery_ctx.ioctl_value = fx->pipefd[0];
    fx->epoll_ctx = (epoll_ctx_t) {
        .epfd = fx->epfd,
        .ts = {.tv_sec = 0, .tv_nsec = 0},
    };
}

int main(int argc, char **argv)
{
    /* Line-buffer stdout so each completed case is visible immediately when the
     * bench is piped or redirected. Full buffering hides the progress and turns
     * "the bench is slow" into "the bench appears stuck" until the buffer
     * flushes at exit.
     */
    setvbuf(stdout, NULL, _IOLBF, 0);

    unsigned long iters = 1000000;
    if (argc > 1)
        iters = strtoul(argv[1], NULL, 10);
    if (iters == 0) {
        fprintf(stderr, "iterations must be > 0\n");
        return 1;
    }

    bench_fx_t fxs;
    bench_fx_t *fx = &fxs;
    bench_fx_init(fx);
    if (bench_fx_open(fx) < 0) {
        bench_fx_close(fx);
        return 1;
    }
    bench_fx_setup_ctxs(fx);

    const bench_case_t cases[] = {
        {"getpid", bench_getpid, NULL},
        {"getppid", bench_getppid, NULL},
        {"gettid", bench_gettid, NULL},
        {"getuid", bench_getuid, NULL},
        {"geteuid", bench_geteuid, NULL},
        {"getgid", bench_getgid, NULL},
        {"getegid", bench_getegid, NULL},
        {"getresuid", bench_getresuid, &fx->sysquery_ctx},
        {"getresgid", bench_getresgid, &fx->sysquery_ctx},
        {"getpriority", bench_getpriority, NULL},
        {"fadvise64", bench_fadvise64, &fx->nullfd},
        {"fcntl-getfd", bench_fcntl_getfd, &fx->nullfd},
        {"fcntl-getfl", bench_fcntl_getfl, &fx->nullfd},
        {"dup-close", bench_dup_close, &fx->nullfd},
        {"dup3-close", bench_dup3_close, &fx->dup3_ctx},
        {"ioctl-tiocgsid", bench_ioctl_tiocgsid, &fx->sysquery_ctx},
        {"ioctl-fionread", bench_ioctl_fionread, &fx->sysquery_ctx},
        {"prctl-pdeathsig", bench_prctl_get_pdeathsig, &fx->sysquery_ctx},
        {"getsockname", bench_getsockname, &fx->getsockname_ctx},
        {"getpeername", bench_getpeername, &fx->getpeername_ctx},
        {"sendto-unix", bench_sendto_unix, &fx->sendto_ctx},
        {"recvfrom-unix", bench_recvfrom_unix, &fx->recvfrom_ctx},
        {"sched_setaffinity", bench_sched_setaffinity, &fx->affinity_mask},
        {"clock_gettime", bench_clock_gettime, &fx->ts},
        {"gettimeofday", bench_gettimeofday, &fx->tv},
        {"getrandom8", bench_getrandom, &fx->getrandom8_ctx},
        {"getrandom256", bench_getrandom, &fx->getrandom256_ctx},
        {"uname", bench_uname, &fx->sysquery_ctx},
        {"getcwd", bench_getcwd, &fx->sysquery_ctx},
        {"sysinfo", bench_sysinfo, &fx->sysquery_ctx},
        {"getrlimit-nofile", bench_getrlimit_nofile, &fx->sysquery_ctx},
        {"prlimit64-nofile", bench_prlimit64_nofile, &fx->sysquery_ctx},
        {"getrusage-self", bench_getrusage_self, &fx->sysquery_ctx},
        {"getrusage-thread", bench_getrusage_thread, &fx->sysquery_ctx},
        {"getgroups0", bench_getgroups0, NULL},
        {"setsockopt-reuseaddr", bench_setsockopt, &fx->reuseaddr},
        {"getsockopt-reuseaddr", bench_getsockopt, &fx->reuseaddr},
        {"setsockopt-nodelay", bench_setsockopt, &fx->nodelay},
        {"getsockopt-nodelay", bench_getsockopt, &fx->nodelay},
        {"getsockopt-sndbuf", bench_getsockopt, &fx->sndbuf},
        {"ppoll1-nowait", bench_ppoll1, &fx->ppoll_ctx},
        {"pselect0-nowait", bench_pselect0, &fx->pselect_ctx},
        {"epollpwait2-0", bench_epoll_pwait2_0, &fx->epoll_ctx},
        {"writev1-null", bench_writev1, &fx->writev_ctx},
        {"writev2-null", bench_writev2, &fx->writev_ctx},
        {"readv1-zero", bench_readv1, &fx->readv_ctx},
        {"readv2-zero", bench_readv2, &fx->readv_ctx},
        {"pwritev1-reg", bench_pwritev1, &fx->pwritev_ctx},
        {"pwritev2-reg", bench_pwritev2v, &fx->pwritev_ctx},
        {"preadv1-reg", bench_preadv1, &fx->preadv_ctx},
        {"preadv2-reg", bench_preadv2v, &fx->preadv_ctx},
        {"pwritev2app1", bench_pwritev2_append1, &fx->pwritev2_append_ctx},
        {"pwritev2app2", bench_pwritev2_append2, &fx->pwritev2_append_ctx},
        {"sendmsg1-rt", bench_sendmsg1_roundtrip, &fx->sendmsg_ctx},
        {"recvmsg1-rt", bench_recvmsg1_roundtrip, &fx->recvmsg_ctx},
        {"sendmsg2-rt", bench_sendmsg2_roundtrip, &fx->sendmsg2_ctx},
        {"recvmsg2-rt", bench_recvmsg2_roundtrip, &fx->recvmsg2_ctx},
        {"sendmmsg1-rt", bench_sendmmsg1_roundtrip, &fx->sendmmsg_ctx},
        {"recvmmsg1-rt", bench_recvmmsg1_roundtrip, &fx->recvmmsg_ctx},
        {"newfstatat", bench_newfstatat, &fx->path_ctx},
        {"statx", bench_statx, &fx->statx_ctx},
        {"openat-close", bench_openat_close, &fx->path_ctx},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        run_case(&cases[i], iters);

    bench_fx_close(fx);
    return 0;
}
