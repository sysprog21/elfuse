/*
 * Socket/networking syscalls
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Translates Linux aarch64 socket syscalls into macOS equivalents. Key
 * differences handled:
 *   - Address families: Linux AF_INET6=10, macOS AF_INET6=30
 *   - sockaddr layout: macOS has sa_len byte, Linux does not
 *   - Socket type flags: Linux packs SOCK_NONBLOCK/SOCK_CLOEXEC into type
 *   - Socket options: SOL_SOCKET option constants differ
 */

#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"

#include "core/rosetta.h"
#include "debug/log.h"
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/uio.h>

#include "syscall/internal.h"
#include "syscall/net.h"
#include "syscall/net-abi.h"
#include "syscall/net-absock.h"
#include "syscall/net-sockopt.h"
#include "syscall/proc.h"
#include "syscall/io.h"
#include "syscall/signal.h"

/* Wait for a blocking socket op (recv/accept/connect/send) to become ready or
 * be interrupted by a guest signal, so a vCPU thread parked in the host call
 * stays reachable by hv_vcpus_exit + the wakeup pipe. No-op for nonblocking fds
 * and for MSG_DONTWAIT callers. Pass msg_flags = 0 for ops with no flags
 * argument (accept, connect).
 *
 * Returns 0 to proceed or a negative Linux errno (EINTR) to abort.
 */
int64_t net_wait_or_interrupted(const fd_block_state_t *st,
                                int host_fd,
                                short events,
                                int msg_flags)
{
    if (!sock_op_should_block(st, host_fd, msg_flags))
        return 0;
    return io_wait_fd_or_interrupted(host_fd, events);
}

/* Is there anything for a zero-length receive to return, asked without
 * consuming it?
 *
 * poll answers a different question -- "the descriptor is readable" -- and its
 * answer is already stale by the time the guest's call runs: a sibling on the
 * same socket can take the byte in between, and the zero-length recv then
 * returns 0 to a guest that asked to block until something arrived. A one-byte
 * MSG_PEEK asks the socket buffer itself, atomically against it, and takes
 * nothing away from whoever ends up reading it.
 *
 * A peek of 0 is end of file, which is also a case where Linux lets a
 * zero-length recv through, so it counts as ready. Same for a zero-length
 * datagram, which is indistinguishable here and wants the same answer.
 *
 * Returns 1 ready, 0 nothing there, -1 with errno set on a real failure.
 */
static int zero_len_ready(int host_fd)
{
    char probe;
    ssize_t n = recv(host_fd, &probe, 1, MSG_PEEK | MSG_DONTWAIT);
    if (n >= 0)
        return 1;
    if (errno == EAGAIN)
        return 0;
    return -1;
}

/* Linux clamps a socket receive's low-water target to one byte (sock_rcvlowat
 * returns v ?: 1), so a zero-payload recv/recvfrom/recvmsg on an empty socket
 * blocks -- or fails EAGAIN when nonblocking -- instead of returning 0 the way
 * the macOS host call does. (read() is the exception: sock_read_iter returns 0
 * for a zero count, so sys_read stays untouched.) Gate the host call on
 * readability: an interruptible wait for blocking callers, an immediate probe
 * for nonblocking ones, both answered by zero_len_ready below. EOF counts as
 * ready in both, and the host call then returns 0 like Linux.
 *
 * Returns 0 to proceed or a negative Linux errno (EINTR/EAGAIN).
 */

int64_t net_recv_zero_payload_gate(const fd_block_state_t *st,
                                   int host_fd,
                                   int msg_flags)
{
    /* Linux's urgent-data receive path never waits for readiness: with no
     * urgent data queued, recv(MSG_OOB) fails immediately whether the socket
     * blocks or not (tcp_recv_urg, unix_stream_recv_urg; verified on 6.12).
     * Pass straight to the host call, which also fails immediately.
     *
     * It does not fail with the same errno on AF_UNIX, and this used to claim
     * it did. Linux supports out-of-band data there and answers EINVAL when
     * none is queued; macOS does not support it on AF_UNIX at all and answers
     * EOPNOTSUPP. Measured against the reference kernel, 22 against 95. The
     * errno is left as the host gives it rather than rewritten, because a guest
     * that reads EOPNOTSUPP as "no OOB here" is being told the truth about this
     * host, while EINVAL would invite it to keep asking.
     */
    if (msg_flags & LINUX_MSG_OOB)
        return 0;

    if (sock_op_should_block(st, host_fd, msg_flags)) {
        /* Wait, then ask the buffer, and go back to waiting if a sibling got
         * there first. Each round blocks until the socket says something, so
         * this cannot spin.
         */
        for (;;) {
            int64_t waited = io_wait_fd_or_interrupted(host_fd, POLLIN);
            if (waited < 0)
                return waited;
            int ready = zero_len_ready(host_fd);
            if (ready < 0)
                return linux_errno();
            if (ready > 0)
                return 0;
        }
    }

    int ready = zero_len_ready(host_fd);
    if (ready < 0)
        return linux_errno();
    return ready > 0 ? 0 : -LINUX_EAGAIN;
}

/* True when a socket send/recv should wait interruptibly and retry rather than
 * surface EAGAIN: the guest asked for blocking semantics (no MSG_DONTWAIT, fd
 * not O_NONBLOCK). The send/recv paths loop on EAGAIN when this holds, so a
 * post-readiness buffer-full/steal race retries instead of parking the vCPU in
 * an uninterruptible host call.
 *
 * The answer comes from the pinned state and not from the host descriptor.
 * elfuse owns O_NONBLOCK on the sockets it creates, so their host flag is
 * always set and records nothing about what the guest asked for. Ownership is
 * what makes the retry loop real: this used to lean on a per-call MSG_DONTWAIT
 * instead, and macOS does not honour that flag on AF_UNIX -- a send on a full
 * stream socket writes what fits and then blocks in the kernel for the rest,
 * with the flag set (measured: one send moved 8192 bytes and sat for three
 * seconds).
 *
 * A description elfuse did not create -- one that arrived over SCM_RIGHTS -- is
 * not owned, and there the host flag is still the only record of it.
 */
bool sock_op_should_block(const fd_block_state_t *st,
                          int host_fd,
                          int msg_flags)
{
    if (msg_flags & LINUX_MSG_DONTWAIT)
        return false;
    if (fd_nonblock_shadowed(st->type, st->nonblock_owned))
        return !st->guest_nonblock;
    int fl = fcntl(host_fd, F_GETFL);
    return fl >= 0 && !(fl & O_NONBLOCK);
}

int sock_creation_flags(int nonblock, int cloexec)
{
    return (nonblock ? LINUX_O_NONBLOCK : 0) | (cloexec ? LINUX_O_CLOEXEC : 0);
}

bool net_recv_should_retry(const fd_block_state_t *st,
                           int host_fd,
                           int msg_flags,
                           ssize_t ret)
{
    if (ret >= 0 || errno != EAGAIN)
        return false;

    /* sock_op_should_block may run an fcntl for a description elfuse does not
     * own, and the caller reports the transfer's errno when this says no.
     */
    int saved_errno = errno;
    bool retry = sock_op_should_block(st, host_fd, msg_flags);
    errno = saved_errno;
    return retry;
}

/* Whether a refusal from this socket could be a full backlog rather than the
 * real answer.
 *
 * Only a connection-oriented AF_UNIX socket queues: a datagram socket has no
 * backlog to fill, so its ECONNREFUSED is the final word and retrying would
 * only delay it. The family alone is not the test.
 */
static bool connect_backlog_can_fill(int host_fd, const struct sockaddr *sa)
{
    if (sa->sa_family != AF_UNIX)
        return false;

    int so_type = 0;
    socklen_t so_type_len = sizeof(so_type);
    if (getsockopt(host_fd, SOL_SOCKET, SO_TYPE, &so_type, &so_type_len) < 0)
        return false;
    return so_type == SOCK_STREAM || so_type == SOCK_SEQPACKET;
}

/* Attempts a refused AF_UNIX connect gets before the refusal is believed.
 *
 * The two costs pull opposite ways: too few and a listener still draining its
 * backlog hands the guest a refusal Linux would not have produced, too many and
 * a socket file nobody listens on takes that long to say so. Against the
 * io_retry_backoff ramp this lands under half a second, which covered every run
 * of tests/test-socket-accept-contended under four spinning cores while leaving
 * a dead socket answering well inside any timeout. Measure both sides again
 * before changing it rather than trusting this sentence.
 */
#define CONNECT_BACKLOG_RETRIES 128

/* Drive an already-nonblocking connect to completion or interruption: start it,
 * wait for POLLOUT (or a guest signal), then read SO_ERROR.
 *
 * Returns 0 on success or a negative Linux errno. Assumes the caller set
 * O_NONBLOCK and will restore the original flags.
 */
static int64_t connect_nonblock_wait(int host_fd,
                                     const struct sockaddr *sa,
                                     socklen_t len)
{
    /* macOS answers a full AF_UNIX backlog with ECONNREFUSED. Linux blocks a
     * blocking connect there instead, waiting for the listener to drain
     * (unix_wait_for_peer), and elfuse owns O_NONBLOCK on the sockets it opens,
     * so a guest that asked to wait would see the refusal. This is the
     * connect-shaped instance of the race the accept path already retries.
     *
     * The errno does not separate a full backlog from a socket file nobody
     * listens on, so the wait is bounded and the refusal is reported once the
     * budget runs out. That costs a genuinely refused connect the budget before
     * it hears so, which is the price of not handing the guest a refusal Linux
     * would never have produced. Retrying on the same socket is sound: it stays
     * usable across the refusal and connects once the backlog drains.
     */
    unsigned backoff = 0;
    unsigned refusals = 0;
    int rc;
    while ((rc = connect(host_fd, sa, len)) != 0 && errno == ECONNREFUSED &&
           refusals < CONNECT_BACKLOG_RETRIES &&
           connect_backlog_can_fill(host_fd, sa)) {
        refusals++;
        int64_t backoff_rc = io_retry_backoff(&backoff);
        if (backoff_rc < 0)
            return backoff_rc;
    }
    if (rc == 0)
        return 0;

    /* EALREADY is this same connect still in flight. Linux never reports it to
     * a blocking caller: __inet_stream_connect sets it, then falls through to
     * wait out TCP_SYN_SENT and returns 0. Waiting below does the same.
     *
     * EISCONN is that connect having landed, and it is only swallowed for a
     * restarted SVC. A guest that calls connect twice on a socket whose first
     * connect returned is asking a different question and Linux answers EISCONN
     * (sock->state is SS_CONNECTED by then). After a restart the guest never
     * saw the first attempt return at all, so Linux would be in SS_CONNECTING
     * and would answer 0; reporting EISCONN there would leak elfuse's own retry
     * into a syscall the guest issued once. Measured with a connect loop under
     * a sibling exec loop: 4000/4000 succeed on Linux, and without this gate
     * about 60% came back EISCONN.
     */
    bool resuming = syscall_is_restarted();
    if (errno != EINPROGRESS && errno != EINTR && errno != EALREADY &&
        !(resuming && errno == EISCONN))
        return linux_errno();

    int64_t waited = io_wait_fd_or_interrupted(host_fd, POLLOUT);
    if (waited < 0)
        return waited; /* EINTR: connect continues in the background per Linux
                        */

    int soerr = 0;
    socklen_t slen = sizeof(soerr);
    if (getsockopt(host_fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0)
        soerr = errno;
    if (soerr) {
        errno = soerr;
        return linux_errno();
    }
    return 0;
}

/* Blocking connect that stays interruptible by a guest signal. Flips the socket
 * nonblocking, drives the connect via connect_nonblock_wait, and restores the
 * guest's file-status flags exactly once. A socket already in nonblocking mode,
 * or one that cannot be flipped, falls back to a plain connect (best-effort
 * interruptibility, never a lost connect); its EINPROGRESS surfaces unchanged.
 */
static int64_t connect_or_interrupted(const fd_block_state_t *st,
                                      int host_fd,
                                      const struct sockaddr *sa,
                                      socklen_t len)
{
    /* The guest asked for a nonblocking connect: hand it straight through, and
     * EINPROGRESS with it.
     */
    if (!sock_op_should_block(st, host_fd, 0))
        return connect(host_fd, sa, len) < 0 ? linux_errno() : 0;

    /* An owned socket is already nonblocking at the host and has to stay that
     * way -- the flag is elfuse's, not the guest's, and putting it back would
     * park the next transfer. Nothing to toggle, so just drive the connect.
     *
     * Reading the host flag here instead of the shadow is what broke when
     * sockets became owned: every socket looked nonblocking, so every blocking
     * connect returned EINPROGRESS to a guest that had asked to wait
     * (tests/test-exec-handoff.c caught it).
     */
    if (st->nonblock_owned)
        return connect_nonblock_wait(host_fd, sa, len);

    /* A description elfuse does not own, whose flag really is the guest's:
     * borrow O_NONBLOCK for the wait and give it back.
     */
    int fl = fcntl(host_fd, F_GETFL);
    if (fl < 0 || fcntl(host_fd, F_SETFL, fl | O_NONBLOCK) < 0)
        return connect(host_fd, sa, len) < 0 ? linux_errno() : 0;

    int64_t result = connect_nonblock_wait(host_fd, sa, len);
    fcntl(host_fd, F_SETFL, fl);
    return result;
}

/* Syscall implementations. */

static bool rosetta_socket_shim_enabled(guest_t *g)
{
    if (!g || !g->is_rosetta)
        return false;

    size_t cmdline_len = 0;
    const char *cmdline = proc_get_cmdline(&cmdline_len);
    size_t rosetta_len = strlen(ROSETTA_PATH);

    return cmdline && cmdline_len > rosetta_len &&
           memcmp(cmdline, ROSETTA_PATH, rosetta_len + 1) == 0;
}

static bool rosettad_connect_target(const struct sockaddr_storage *mac_sa)
{
    if (!mac_sa || mac_sa->ss_family != AF_UNIX)
        return false;
    const struct sockaddr_un *sun = (const struct sockaddr_un *) mac_sa;
    return strcmp(sun->sun_path, ROSETTAD_SOCKET_PATH) == 0;
}

static bool rosetta_seqpacket_placeholder(guest_t *g, int guest_fd, int host_fd)
{
    int cached_type = 0;
    if (!rosetta_socket_shim_enabled(g) ||
        !net_socket_cached_int_get(guest_fd, LINUX_SOL_SOCKET, LINUX_SO_TYPE,
                                   &cached_type) ||
        cached_type != LINUX_SOCK_SEQPACKET || rosettad_is_socket(host_fd))
        return false;

    int so_type = 0;
    socklen_t so_type_len = sizeof(so_type);
    if (getsockopt(host_fd, SOL_SOCKET, SO_TYPE, &so_type, &so_type_len) < 0)
        return false;

    return (so_type & 0xF) == SOCK_STREAM;
}

int64_t sys_socket(guest_t *g, int domain, int type, int protocol)
{
    /* AF_NETLINK: synthetic emulation, no macOS equivalent */
    if (domain == LINUX_AF_NETLINK)
        return netlink_socket(protocol, type);

    int mac_domain = translate_af_to_mac(domain);
    int real_type = extract_sock_type(type);
    int nonblock = extract_sock_nonblock(type);
    int cloexec = extract_sock_cloexec(type);

    int original_type = real_type;
    if (mac_domain == AF_UNIX && real_type == LINUX_SOCK_SEQPACKET) {
        real_type = SOCK_STREAM;
    }

    /* Rosetta opens AF_UNIX SOCK_SEQPACKET to talk to rosettad. macOS does not
     * support SOCK_SEQPACKET on AF_UNIX, so while the translator process is
     * active we create an unconnected SOCK_STREAM placeholder instead.
     * sys_connect() upgrades only the specific rosettad path to the private
     * socketpair/handler transport; any other connect on this placeholder fails
     * so unrelated Unix IPC is not silently downgraded to STREAM.
     */
    if (rosetta_socket_shim_enabled(g) && mac_domain == AF_UNIX &&
        original_type == LINUX_SOCK_SEQPACKET) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
            return linux_errno();
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        if ((nonblock && fd_set_nonblock(fd) < 0) ||
            (cloexec && fd_set_cloexec(fd) < 0)) {
            close(fd);
            return linux_errno();
        }

        int gfd = fd_alloc(FD_SOCKET, fd, absock_unregister_fd);
        if (gfd < 0) {
            close(fd);
            return -LINUX_EMFILE;
        }
        fd_table[gfd].linux_flags |= sock_creation_flags(nonblock, cloexec);
        net_socket_cache_init_defaults(gfd, domain, original_type);
        return gfd;
    }

    int fd = socket(mac_domain, real_type, protocol);
    if (fd < 0)
        return linux_errno();

    /* Apply SOCK_NONBLOCK and SOCK_CLOEXEC */
    if ((nonblock && fd_set_nonblock(fd) < 0) ||
        (cloexec && fd_set_cloexec(fd) < 0)) {
        close(fd);
        return linux_errno();
    }

    /* Suppress SIGPIPE on this socket (macOS-specific) */
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));

    int gfd = fd_alloc(FD_SOCKET, fd, absock_unregister_fd);
    if (gfd < 0) {
        close(fd);
        return -LINUX_EMFILE;
    }

    fd_table[gfd].linux_flags = sock_creation_flags(nonblock, cloexec);
    net_socket_cache_init_defaults(gfd, domain, original_type);

    return gfd;
}

int64_t sys_socketpair(guest_t *g,
                       int domain,
                       int type,
                       int protocol,
                       uint64_t sv_gva)
{
    int mac_domain = translate_af_to_mac(domain);
    int real_type = extract_sock_type(type);
    int nonblock = extract_sock_nonblock(type);
    int cloexec = extract_sock_cloexec(type);

    int original_type = real_type;
    if (mac_domain == AF_UNIX && real_type == LINUX_SOCK_SEQPACKET) {
        real_type = SOCK_DGRAM;
    }

    int fds[2];
    if (socketpair(mac_domain, real_type, protocol, fds) < 0)
        return linux_errno();

    /* Apply flags */
    for (int i = 0; i < 2; i++) {
        if ((nonblock && fd_set_nonblock(fds[i]) < 0) ||
            (cloexec && fd_set_cloexec(fds[i]) < 0)) {
            close(fds[0]);
            close(fds[1]);
            return linux_errno();
        }
        int one = 1;
        setsockopt(fds[i], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    }

    int gfd0 = fd_alloc(FD_SOCKET, fds[0], absock_unregister_fd);
    if (gfd0 < 0) {
        close(fds[0]);
        close(fds[1]);
        return -LINUX_EMFILE;
    }
    int gfd1 = fd_alloc(FD_SOCKET, fds[1], absock_unregister_fd);
    if (gfd1 < 0) {
        fd_retire_published(gfd0, fds[0]);
        close(fds[1]);
        return -LINUX_EMFILE;
    }

    int linux_flags = sock_creation_flags(nonblock, cloexec);
    fd_table[gfd0].linux_flags = linux_flags;
    fd_table[gfd1].linux_flags = linux_flags;
    net_socket_cache_init_defaults(gfd0, domain, original_type);
    net_socket_cache_init_defaults(gfd1, domain, original_type);

    int32_t guest_fds[2] = {gfd0, gfd1};
    if (guest_write_small(g, sv_gva, guest_fds, sizeof(guest_fds)) < 0) {
        fd_retire_published(gfd0, fds[0]);
        fd_retire_published(gfd1, fds[1]);
        return -LINUX_EFAULT;
    }

    return 0;
}

int64_t sys_bind(guest_t *g, int fd, uint64_t addr_gva, uint32_t addrlen)
{
    /* Netlink sockets use synthetic fd; dispatch to netlink handler */
    if (fd_get_type(fd) == FD_NETLINK)
        return netlink_bind(fd, g, addr_gva, addrlen);

    host_fd_ref_t host_ref;
    int64_t ref_err = host_fd_ref_open(fd, &host_ref);
    if (ref_err < 0)
        return ref_err;

    uint8_t linux_sa[128];
    if (addrlen > sizeof(linux_sa)) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EINVAL;
    }
    if (guest_read(g, addr_gva, linux_sa, addrlen) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    struct sockaddr_storage mac_sa;
    int mac_len;

    /* Abstract Unix socket: rewrite to filesystem path */
    int absock_idx = -1;
    if (absock_is_abstract_unix(linux_sa, addrlen)) {
        int bind_len;
        absock_idx =
            absock_bind_prepare(linux_sa, addrlen, &mac_sa, fd, &bind_len);
        if (absock_idx == -2) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EADDRINUSE;
        }
        if (absock_idx < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
        mac_len = bind_len;
    } else {
        mac_len = net_sockaddr_to_mac(linux_sa, addrlen, true, &mac_sa);
        if (mac_len < 0) {
            host_fd_ref_close(&host_ref);
            return mac_len;
        }
    }

    if (bind(host_ref.fd, (struct sockaddr *) &mac_sa, (socklen_t) mac_len) <
        0) {
        if (absock_idx >= 0)
            absock_bind_rollback(absock_idx);
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }
    if (absock_idx >= 0)
        absock_bind_commit(absock_idx);

    host_fd_ref_close(&host_ref);
    return 0;
}

int64_t sys_listen(int fd, int backlog)
{
    host_fd_ref_t host_ref;
    int64_t ref_err = host_fd_ref_open(fd, &host_ref);
    if (ref_err < 0)
        return ref_err;

    /* macOS 27.0 loses the urgent mark of the first urgent byte on about half
     * of the connections accepted from a listener with backlog 1, so the guest
     * gets neither SIGURG nor recv(MSG_OOB). Backlog 2 does not show it. Linux
     * queues backlog + 1 connections (sk_acceptq_is_full) where macOS queues
     * backlog, so 2 is also the queue length the guest asked for.
     */
    int host_backlog = backlog == 1 ? 2 : backlog;

    if (listen(host_ref.fd, host_backlog) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }
    host_fd_ref_close(&host_ref);
    net_socket_cache_set_index(fd, SOCK_OPT_ACCEPTCONN, 1);
    return 0;
}

/* Shared implementation for accept and accept4. */
static int64_t do_accept(guest_t *g,
                         int fd,
                         uint64_t addr_gva,
                         uint64_t addrlen_gva,
                         int nonblock,
                         int cloexec)
{
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
        return -LINUX_EBADF;

    host_fd_ref_t host_ref = HOST_FD_REF_INIT;
    uint64_t listener_generation = 0;
    int listener_passcred_fallback = 0;
    int listener_type = FD_CLOSED;
    fd_block_state_t sock_st = {.type = FD_CLOSED};

    if (thread_is_single_active()) {
        int64_t ref_err = host_fd_ref_open_state(fd, &host_ref, &sock_st);
        if (ref_err < 0)
            return ref_err;
        listener_type = fd_table[fd].type;
        listener_generation = fd_table[fd].generation;
        if (listener_type == FD_SOCKET)
            (void) sock_opt_get(&fd_table[fd], SOCK_OPT_PASSCRED,
                                &listener_passcred_fallback);
    } else {
        fd_entry_t listener_snap = {.type = FD_CLOSED};
        int host_fd =
            fd_host_ref_acquire(fd, &listener_snap, &host_ref.lifetime);
        if (host_fd < 0)
            return linux_errno();
        host_ref.fd = host_fd;
        sock_st = fd_block_state_of(&listener_snap);
        listener_type = listener_snap.type;
        listener_generation = listener_snap.generation;
        if (listener_type == FD_SOCKET)
            (void) sock_opt_get(&listener_snap, SOCK_OPT_PASSCRED,
                                &listener_passcred_fallback);
    }

    if (listener_type != FD_SOCKET) {
        host_fd_ref_close(&host_ref);
        return -LINUX_ENOTSOCK;
    }

    struct sockaddr_storage mac_sa;
    socklen_t mac_len;
    int new_fd;

    /* Wait, accept, and retry the EAGAIN a blocking guest must not see. elfuse
     * owns O_NONBLOCK on the listener, so a sibling that takes the connection
     * this wait reported leaves EAGAIN here rather than leaving the accept to
     * block, which is the same race the recv paths run and the same answer: the
     * guest asked to wait, so wait again.
     */
    for (;;) {
        int64_t waited =
            net_wait_or_interrupted(&sock_st, host_ref.fd, POLLIN, 0);
        if (waited < 0) {
            host_fd_ref_close(&host_ref);
            return waited;
        }

        mac_len = sizeof(mac_sa);
        new_fd = accept(host_ref.fd, (struct sockaddr *) &mac_sa, &mac_len);
        if (new_fd >= 0)
            break;
        if (!net_recv_should_retry(&sock_st, host_ref.fd, 0, -1)) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
    }
    host_fd_ref_close(&host_ref);

    int listener_passcred = listener_passcred_fallback;
    (void) net_socket_cached_int_get_if_generation(
        fd, listener_generation, LINUX_SOL_SOCKET, LINUX_SO_PASSCRED,
        &listener_passcred);

    if ((nonblock && fd_set_nonblock(new_fd) < 0) ||
        (cloexec && fd_set_cloexec(new_fd) < 0)) {
        close(new_fd);
        return linux_errno();
    }

    int one = 1;
    setsockopt(new_fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));

    int gfd = fd_alloc(FD_SOCKET, new_fd, absock_unregister_fd);
    if (gfd < 0) {
        close(new_fd);
        return -LINUX_EMFILE;
    }
    fd_table[gfd].linux_flags = sock_creation_flags(nonblock, cloexec);
    net_socket_cache_init_accept(gfd, listener_passcred);

    /* Write back peer address if requested. The accept has already succeeded
     * and gfd is valid; EFAULT here mirrors Linux kernel behavior (close the
     * new fd and return -EFAULT).
     */
    if (addr_gva) {
        if (!addrlen_gva) {
            fd_retire_published(gfd, new_fd);
            return -LINUX_EFAULT;
        }
        uint32_t guest_addrlen;
        if (guest_read_small(g, addrlen_gva, &guest_addrlen,
                             sizeof(guest_addrlen)) < 0) {
            fd_retire_published(gfd, new_fd);
            return -LINUX_EFAULT;
        }
        uint8_t linux_sa[128];
        int out_len =
            net_sockaddr_from_mac((struct sockaddr *) &mac_sa, mac_len,
                                  linux_sa, (uint32_t) sizeof(linux_sa));
        if (out_len > 0) {
            uint32_t actual_len = (uint32_t) out_len;
            uint32_t write_len = actual_len;
            if (write_len > guest_addrlen)
                write_len = guest_addrlen;
            /* Write back actual (not truncated) length per Linux semantics. */
            if (guest_write_small(g, addr_gva, linux_sa, write_len) < 0 ||
                guest_write_small(g, addrlen_gva, &actual_len,
                                  sizeof(actual_len)) < 0) {
                fd_retire_published(gfd, new_fd);
                return -LINUX_EFAULT;
            }
        }
    }

    return gfd;
}

int64_t sys_accept(guest_t *g, int fd, uint64_t addr_gva, uint64_t addrlen_gva)
{
    return do_accept(g, fd, addr_gva, addrlen_gva, 0, 0);
}

int64_t sys_accept4(guest_t *g,
                    int fd,
                    uint64_t addr_gva,
                    uint64_t addrlen_gva,
                    int flags)
{
    int nonblock = (flags & LINUX_SOCK_NONBLOCK) != 0;
    int cloexec = (flags & LINUX_SOCK_CLOEXEC) != 0;
    return do_accept(g, fd, addr_gva, addrlen_gva, nonblock, cloexec);
}

int64_t sys_connect(guest_t *g, int fd, uint64_t addr_gva, uint32_t addrlen)
{
    host_fd_ref_t host_ref;
    fd_block_state_t sock_st;
    int64_t ref_err = host_fd_ref_open_state(fd, &host_ref, &sock_st);
    if (ref_err < 0)
        return ref_err;

    uint8_t linux_sa[128];
    if (addrlen > sizeof(linux_sa)) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EINVAL;
    }
    if (guest_read(g, addr_gva, linux_sa, addrlen) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    struct sockaddr_storage mac_sa;
    int mac_len;

    /* Abstract Unix socket: rewrite to filesystem path */
    if (absock_is_abstract_unix(linux_sa, addrlen)) {
        mac_len = absock_rewrite_connect(linux_sa, addrlen, &mac_sa);
        if (mac_len < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ECONNREFUSED;
        }
    } else {
        mac_len = net_sockaddr_to_mac(linux_sa, addrlen, false, &mac_sa);
        if (mac_len < 0) {
            host_fd_ref_close(&host_ref);
            return mac_len;
        }
    }

    /* glibc probes UDP connect(addr, port 0) during getaddrinfo() source
     * address selection. Linux accepts this; macOS rejects it. Use discard port
     * 9 for the host-only probe so getsockname() can still discover the
     * selected local address.
     */
    int so_type = 0;
    socklen_t so_type_len = sizeof(so_type);
    if (sockaddr_has_zero_port(&mac_sa) &&
        getsockopt(host_ref.fd, SOL_SOCKET, SO_TYPE, &so_type, &so_type_len) ==
            0 &&
        so_type == SOCK_DGRAM) {
        struct sockaddr_storage probe_sa = mac_sa;
        sockaddr_set_port(&probe_sa, htons(9));
        if (connect(host_ref.fd, (struct sockaddr *) &probe_sa,
                    (socklen_t) mac_len) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    /* Upgrade the translator's fake AF_UNIX/SOCK_SEQPACKET placeholder to the
     * private rosettad bridge only when it actually connects to the rosettad
     * Unix path from the VZ_CAPS payload.
     */
    int cached_type = 0;
    bool shimmed_seqpacket = rosetta_seqpacket_placeholder(g, fd, host_ref.fd);
    if (shimmed_seqpacket &&
        net_socket_cached_int_get(fd, LINUX_SOL_SOCKET, LINUX_SO_TYPE,
                                  &cached_type) &&
        rosettad_connect_target(&mac_sa)) {
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }

        int one = 1;
        setsockopt(pair[0], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        setsockopt(pair[1], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));

        /* pair[0] is a fresh description wearing the old slot's identity, so
         * the host flag has to be set here rather than inherited. The alias
         * spec below claims nonblock_owned from the snapshot and the allocator
         * takes that claim at its word -- an alias normally shares a
         * description that already carries the flag, and this one does not.
         * Testing the old host status instead would have been vacuous now that
         * every socket elfuse opens carries O_NONBLOCK.
         */
        fd_entry_t snap;
        bool have_snap = fd_snapshot(fd, &snap);
        if ((have_snap && snap.nonblock_owned &&
             fd_set_nonblock(pair[0]) < 0) ||
            (have_snap && (snap.linux_flags & LINUX_O_CLOEXEC) &&
             fd_set_cloexec(pair[0]) < 0)) {
            close(pair[0]);
            close(pair[1]);
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }

        /* Rebuilding the slot must not mint a fresh description identity: any
         * dup alias of this fd keeps the old ofd_id, and the two would stop
         * being swept together by the O_NONBLOCK, O_ASYNC and SIGIO-owner
         * walks. The aliases still carry the pre-upgrade host fd, a deeper
         * divergence this path does not close; keeping the identity is what
         * stops it from also breaking the sweeps.
         */
        fd_alias_spec_t spec;
        if (have_snap)

            /* -1, not fd: this path is rebuilding the very slot it snapshotted,
             * so re-reading it under the publish lock would find the
             * replacement being installed rather than the source.
             */
            spec = fd_alias_of(-1, &snap);
        int alloc_rc =
            fd_alloc_alias_at(have_snap ? &spec : NULL, fd, FD_SOCKET, pair[0],
                              absock_unregister_fd, NULL);
        if (alloc_rc < 0) {
            close(pair[0]);
            close(pair[1]);
            host_fd_ref_close(&host_ref);
            return -LINUX_EMFILE;
        }
        if (have_snap)
            fd_table[fd].linux_flags = snap.linux_flags;
        net_socket_cache_init_defaults(fd, LINUX_AF_UNIX, cached_type);

        if (rosettad_start_handler(pair[1], pair[0]) < 0) {
            close(pair[1]);
            log_warn(
                "sys_connect: rosettad handler thread failed to start; "
                "rosetta will see EOF on its socketpair");
        }

        host_fd_ref_close(&host_ref);
        return 0;
    }

    if (shimmed_seqpacket) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EPROTOTYPE;
    }

    int64_t crc = connect_or_interrupted(&sock_st, host_ref.fd,
                                         (struct sockaddr *) &mac_sa,
                                         (socklen_t) mac_len);
    host_fd_ref_close(&host_ref);
    return crc;
}

/* Convert a resolved macOS sockaddr to Linux form and write it, plus its actual
 * (untruncated) length, back to the guest, honoring the guest-supplied addrlen
 * cap. Closes host_ref on every path. Shared tail of getsockname/getpeername.
 */
static int64_t sockaddr_writeback(guest_t *g,
                                  host_fd_ref_t *host_ref,
                                  const struct sockaddr_storage *mac_sa,
                                  socklen_t mac_len,
                                  uint64_t addr_gva,
                                  uint64_t addrlen_gva,
                                  uint32_t guest_addrlen)
{
    uint8_t linux_sa[128];
    int out_len =
        net_sockaddr_from_mac((const struct sockaddr *) mac_sa, mac_len,
                              linux_sa, (uint32_t) sizeof(linux_sa));
    if (out_len < 0) {
        host_fd_ref_close(host_ref);
        return -LINUX_EINVAL;
    }

    uint32_t actual_len = (uint32_t) out_len, write_len = actual_len;
    if (write_len > guest_addrlen)
        write_len = guest_addrlen;
    if (guest_write_small(g, addr_gva, linux_sa, write_len) < 0) {
        host_fd_ref_close(host_ref);
        return -LINUX_EFAULT;
    }
    /* Write back actual (not truncated) length per Linux semantics */
    if (guest_write_small(g, addrlen_gva, &actual_len, sizeof(actual_len)) <
        0) {
        host_fd_ref_close(host_ref);
        return -LINUX_EFAULT;
    }

    host_fd_ref_close(host_ref);
    return 0;
}

int64_t sys_getsockname(guest_t *g,
                        int fd,
                        uint64_t addr_gva,
                        uint64_t addrlen_gva)
{
    if (fd_get_type(fd) == FD_NETLINK)
        return netlink_getsockname(fd, g, addr_gva, addrlen_gva);

    host_fd_ref_t host_ref;
    int64_t ref_err = host_fd_ref_open(fd, &host_ref);
    if (ref_err < 0)
        return ref_err;

    struct sockaddr_storage mac_sa;
    socklen_t mac_len = sizeof(mac_sa);

    if (getsockname(host_ref.fd, (struct sockaddr *) &mac_sa, &mac_len) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }

    uint32_t guest_addrlen;
    if (guest_read_small(g, addrlen_gva, &guest_addrlen,
                         sizeof(guest_addrlen)) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    /* Check if this is a filesystem socket backing an abstract socket */
    uint8_t linux_sa[128];
    if (mac_sa.ss_family == AF_UNIX) {
        struct sockaddr_un *sun = (struct sockaddr_un *) &mac_sa;
        uint8_t abs_name[108];
        uint32_t abs_len = 0;
        if (absock_reverse_lookup(sun->sun_path, abs_name, &abs_len)) {
            /* Reconstruct abstract Linux sockaddr */
            uint32_t total = 2 + 1 + abs_len;
            uint16_t fam = LINUX_AF_UNIX;
            memset(linux_sa, 0, sizeof(linux_sa));
            memcpy(linux_sa, &fam, 2);
            memcpy(linux_sa + 3, abs_name, abs_len);

            uint32_t actual_len = total, write_len = actual_len;
            if (write_len > guest_addrlen)
                write_len = guest_addrlen;
            if (guest_write_small(g, addr_gva, linux_sa, write_len) < 0 ||
                guest_write_small(g, addrlen_gva, &actual_len,
                                  sizeof(actual_len)) < 0) {
                host_fd_ref_close(&host_ref);
                return -LINUX_EFAULT;
            }
            host_fd_ref_close(&host_ref);
            return 0;
        }
    }

    return sockaddr_writeback(g, &host_ref, &mac_sa, mac_len, addr_gva,
                              addrlen_gva, guest_addrlen);
}

int64_t sys_getpeername(guest_t *g,
                        int fd,
                        uint64_t addr_gva,
                        uint64_t addrlen_gva)
{
    host_fd_ref_t host_ref;
    int64_t ref_err = host_fd_ref_open(fd, &host_ref);
    if (ref_err < 0)
        return ref_err;

    struct sockaddr_storage mac_sa;
    socklen_t mac_len = sizeof(mac_sa);

    if (getpeername(host_ref.fd, (struct sockaddr *) &mac_sa, &mac_len) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }

    uint32_t guest_addrlen;
    if (guest_read_small(g, addrlen_gva, &guest_addrlen,
                         sizeof(guest_addrlen)) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    return sockaddr_writeback(g, &host_ref, &mac_sa, mac_len, addr_gva,
                              addrlen_gva, guest_addrlen);
}

int64_t sys_sendto(guest_t *g,
                   int fd,
                   uint64_t buf_gva,
                   uint64_t len,
                   int linux_flags,
                   uint64_t dest_gva,
                   uint32_t addrlen)
{
    if (fd_get_type(fd) == FD_NETLINK)
        return netlink_send(fd, g, buf_gva, len);

    host_fd_ref_t host_ref;
    fd_block_state_t send_st;
    int64_t ref_err = host_fd_ref_open_state(fd, &host_ref, &send_st);
    if (ref_err < 0)
        return ref_err;

    uint64_t avail = 0;
    void *buf =
        len > 0 ? guest_ptr_bound(g, buf_gva, &avail, MEM_PERM_R, len) : NULL;
    if (!buf && len > 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    if (len > avail)
        len = avail;

    int mac_flags = translate_msg_flags(linux_flags);

    /* MSG_NOSIGNAL (0x4000): suppress SIGPIPE on EPIPE. macOS has no
     * MSG_NOSIGNAL; elfuse handles it by not queuing SIGPIPE.
     */
    int suppress_sigpipe = (linux_flags & LINUX_MSG_NOSIGNAL);

    /* sendto with a NULL destination is send(); merge both forms. */
    struct sockaddr_storage mac_sa;
    struct sockaddr *dest = NULL;
    socklen_t dest_len = 0;
    if (dest_gva && addrlen > 0) {
        uint8_t linux_sa[128];
        if (addrlen > sizeof(linux_sa)) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
        if (guest_read(g, dest_gva, linux_sa, addrlen) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        int mac_len = net_sockaddr_to_mac(linux_sa, addrlen, false, &mac_sa);
        if (mac_len < 0) {
            host_fd_ref_close(&host_ref);
            return mac_len;
        }
        dest = (struct sockaddr *) &mac_sa;
        dest_len = (socklen_t) mac_len;
    }

    bool blocking =
        len > 0 && sock_op_should_block(&send_st, host_ref.fd, linux_flags);
    int host_flags = mac_flags | (blocking ? MSG_DONTWAIT : 0);
    ssize_t ret;
    for (;;) {
        if (blocking) {
            int64_t waited = io_wait_fd_or_interrupted(host_ref.fd, POLLOUT);
            if (waited < 0) {
                host_fd_ref_close(&host_ref);
                return waited;
            }
        }
        ret = sendto(host_ref.fd, buf, len, host_flags, dest, dest_len);
        if (!(blocking && ret < 0 && errno == EAGAIN))
            break;
    }
    host_fd_ref_close(&host_ref);
    if (ret < 0) {
        if (errno == EPIPE && !suppress_sigpipe)
            signal_queue(LINUX_SIGPIPE);
        return linux_errno();
    }
    return ret;
}

/* MSG_WAITALL never reaches the host, and this says whether elfuse then has to
 * gather the request itself.
 *
 * Two separate things, because the answers differ. macOS does not answer for
 * that flag the way Linux does under any of the shapes measured here, so it is
 * stripped unconditionally by recv_strip_waitall below. Whether to loop
 * afterwards is the narrower question, and only a stream socket without
 * MSG_PEEK says yes.
 *
 * Every rule here is a measurement against the qemu reference kernel, not a
 * reading of the manual page, and two of them contradict what the manual page
 * suggests:
 *
 *   plain stream, 2 of 16 queued: Linux blocks for the rest, macOS blocks
 *     forever even with MSG_DONTWAIT also set. Gathered here.
 *   MSG_PEEK on a stream, 2 of 16 queued: Linux returns 2 and does not wait,
 *     because a peek does not consume and it will not spin re-reading the same
 *     bytes. macOS returns 16, reporting fourteen bytes of whatever the guest
 *     buffer already held as received data. One host call, no gather.
 *   SOCK_SEQPACKET, two 4-byte messages queued, 16 requested: Linux returns 4.
 *     One recv is one message and MSG_WAITALL does not join them. Gathering
 *     would concatenate them and destroy the boundary.
 *   SOCK_DGRAM: Linux ignores MSG_WAITALL entirely.
 */
/* buf + total, with NULL preserved.
 *
 * A zero-length recv passes a NULL buffer, and NULL + 0 is undefined even
 * though every compiler here folds it to NULL; UBSan says so out loud.
 */
static void *recv_at(void *buf, uint64_t total)
{
    return buf ? (char *) buf + total : NULL;
}

bool recv_strip_waitall(int linux_flags)
{
    return (linux_flags & LINUX_MSG_WAITALL) != 0;
}

bool recv_gathers_waitall(int host_fd, int linux_flags)
{
    if (!(linux_flags & LINUX_MSG_WAITALL) || (linux_flags & LINUX_MSG_PEEK))
        return false;

    int sotype = 0;
    socklen_t sotype_len = sizeof(sotype);
    if (getsockopt(host_fd, SOL_SOCKET, SO_TYPE, &sotype, &sotype_len) < 0)
        return false;
    return sotype == SOCK_STREAM;
}


int64_t sys_recvfrom(guest_t *g,
                     int fd,
                     uint64_t buf_gva,
                     uint64_t len,
                     int flags,
                     uint64_t src_gva,
                     uint64_t addrlen_gva)
{
    if (fd_get_type(fd) == FD_NETLINK)
        return netlink_recv(fd, g, buf_gva, len, flags, src_gva, addrlen_gva);

    host_fd_ref_t host_ref;
    fd_block_state_t recv_st;
    int64_t ref_err = host_fd_ref_open_state(fd, &host_ref, &recv_st);
    if (ref_err < 0)
        return ref_err;

    uint64_t avail = 0;
    void *buf =
        len > 0 ? guest_ptr_bound(g, buf_gva, &avail, MEM_PERM_W, len) : NULL;
    if (!buf && len > 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    if (len > avail)
        len = avail;

    int mac_flags = translate_msg_flags(flags);

    /* Wait interruptibly, then retry the recv for as long as the guest asked
     * for blocking semantics. The retry is what preserves them now that elfuse
     * owns O_NONBLOCK on the host socket: the descriptor answers EAGAIN both
     * when a sibling took the readiness this wait reported and when MSG_WAITALL
     * has less than the full request queued. A zero-length recv takes the
     * readiness gate instead: unlike read(), Linux blocks it on an empty
     * socket.
     */
    int64_t waited =
        len > 0 ? net_wait_or_interrupted(&recv_st, host_ref.fd, POLLIN, flags)
                : net_recv_zero_payload_gate(&recv_st, host_ref.fd, flags);
    if (waited < 0) {
        host_fd_ref_close(&host_ref);
        return waited;
    }

    struct sockaddr_storage mac_sa;
    socklen_t mac_len;

    bool gather = recv_gathers_waitall(host_ref.fd, flags);
    if (recv_strip_waitall(flags))
        mac_flags &= ~MSG_WAITALL;

    ssize_t ret;
    uint64_t total = 0;
    for (;;) {
        /* Reset per round: a recvfrom that failed may still have written it. */
        mac_len = sizeof(mac_sa);
        if (src_gva && addrlen_gva) {
            ret = recvfrom(host_ref.fd, recv_at(buf, total), len - total,
                           mac_flags, (struct sockaddr *) &mac_sa, &mac_len);
        } else {
            ret =
                recv(host_ref.fd, recv_at(buf, total), len - total, mac_flags);
        }

        if (ret > 0) {
            total += (uint64_t) ret;

            /* Whole request in hand, or nothing asked us to gather more. */
            if (!gather || total >= len)
                break;

            /* Linux stops a gathering recv at the first partial return when the
             * guest asked not to wait, rather than reporting EAGAIN over bytes
             * it has already moved.
             */
            if (!sock_op_should_block(&recv_st, host_ref.fd, flags))
                break;

            waited =
                net_wait_or_interrupted(&recv_st, host_ref.fd, POLLIN, flags);
            if (waited < 0)
                break; /* interrupted after moving bytes: report the count */
            continue;
        }

        /* EOF, or an error. Either ends the gathering: what has been moved is
         * the answer, and a stream that has closed will not deliver the rest.
         */
        if (ret == 0)
            break;
        if (!net_recv_should_retry(&recv_st, host_ref.fd, flags, ret))
            break;
        waited = net_wait_or_interrupted(&recv_st, host_ref.fd, POLLIN, flags);
        if (waited < 0) {
            if (total > 0)
                break;
            host_fd_ref_close(&host_ref);
            return waited;
        }
    }

    /* Bytes already delivered outrank whatever ended the loop, which is what
     * Linux reports and what keeps a partial gather from being retried by a
     * guest that would then read the same stream twice.
     */
    if (total > 0)
        ret = (ssize_t) total;

    if (ret < 0) {
        int64_t result = recv_eof_or_errno(host_ref.fd, fd);
        if (result < 0) {
            host_fd_ref_close(&host_ref);
            return result;
        }
        ret = 0;
        mac_len = 0;
    }

    /* Write back source address if requested. */
    if (src_gva) {
        if (!addrlen_gva) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        uint32_t guest_addrlen;
        if (guest_read_small(g, addrlen_gva, &guest_addrlen,
                             sizeof(guest_addrlen)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        uint8_t linux_sa[128];
        int out_len =
            net_sockaddr_from_mac((struct sockaddr *) &mac_sa, mac_len,
                                  linux_sa, (uint32_t) sizeof(linux_sa));
        if (out_len > 0 || mac_len == 0) {
            uint32_t actual_len = out_len > 0 ? (uint32_t) out_len : 0;
            uint32_t write_len = actual_len;
            if (write_len > guest_addrlen)
                write_len = guest_addrlen;
            if (guest_write_small(g, src_gva, linux_sa, write_len) < 0) {
                host_fd_ref_close(&host_ref);
                return -LINUX_EFAULT;
            }

            /* Write back actual length (Linux returns full size even if the
             * address was truncated to fit the buffer).
             */
            if (guest_write_small(g, addrlen_gva, &actual_len,
                                  sizeof(actual_len)) < 0) {
                host_fd_ref_close(&host_ref);
                return -LINUX_EFAULT;
            }
        }
    }

    host_fd_ref_close(&host_ref);
    return ret;
}

/* Translate a Linux (level, optname) socket-option pair to the macOS pair for
 * the level dispatch common to setsockopt/getsockopt.
 *
 * Returns true on success with the mac_level and mac_optname out-params set;
 * false when the option is unknown for a recognized level (caller returns
 * -ENOPROTOOPT). Both out-params must be pre-seeded with the Linux values so an
 * unrecognized level passes through unchanged for the host to reject.
 *
 * The small-int options (including all four TCP keepalive/nodelay options) are
 * handled by translate_small_int_sockopt before this is reached, and
 * IP_MTU_DISCOVER / IP_RECVERR are handled by an earlier return, so neither
 * reaches this dispatch.
 */
static bool translate_sockopt_level(int level,
                                    int optname,
                                    int *mac_level,
                                    int *mac_optname)
{
    if (level == LINUX_SOL_SOCKET) {
        *mac_level = SOL_SOCKET;
        *mac_optname = translate_sockopt(optname);
        return *mac_optname >= 0;
    }
    if (level == LINUX_IPPROTO_TCP) {
        *mac_level = IPPROTO_TCP;
        return true;
    }
    if (level == LINUX_IPPROTO_IP) {
        *mac_level = IPPROTO_IP;
        *mac_optname = translate_ip_sockopt_to_mac(optname);
        return *mac_optname >= 0;
    }
    if (level == LINUX_IPPROTO_IPV6) {
        *mac_level = IPPROTO_IPV6;
        if (optname == LINUX_IPV6_V6ONLY)
            *mac_optname = IPV6_V6ONLY;
    }
    return true;
}

static bool cached_setsockopt_may_succeed(int level, int optname)
{
    if (level == LINUX_SOL_SOCKET) {
        switch (optname) {
        case LINUX_SO_KEEPALIVE:
        case LINUX_SO_REUSEADDR:
        case LINUX_SO_REUSEPORT:
        case LINUX_SO_BROADCAST:
        case LINUX_SO_DONTROUTE:
        case LINUX_SO_OOBINLINE:
        case LINUX_SO_RCVLOWAT:
        case LINUX_SO_RCVBUF:
        case LINUX_SO_SNDBUF:
            return true;
        default:
            return false;
        }
    }

    return (level == LINUX_IPPROTO_TCP &&
            (optname == LINUX_TCP_NODELAY || optname == LINUX_TCP_KEEPIDLE ||
             optname == LINUX_TCP_KEEPINTVL || optname == LINUX_TCP_KEEPCNT)) ||
           (level == LINUX_IPPROTO_IP &&
            (optname == LINUX_IP_TOS || optname == LINUX_IP_TTL ||
             optname == LINUX_IP_HDRINCL || optname == LINUX_IP_PKTINFO ||
             optname == LINUX_IP_RECVTTL || optname == LINUX_IP_RECVTOS));
}

static bool readonly_setsockopt(int level, int optname)
{
    return level == LINUX_SOL_SOCKET &&
           (optname == LINUX_SO_TYPE || optname == LINUX_SO_ERROR ||
            optname == LINUX_SO_ACCEPTCONN || optname == LINUX_SO_SNDLOWAT);
}

int64_t sys_setsockopt(guest_t *g,
                       int fd,
                       int level,
                       int optname,
                       uint64_t optval_gva,
                       uint32_t optlen)
{
    /* Netlink sockets are synthetic (no host socket to forward to); their
     * SOL_SOCKET options are emulated per-fd by the netlink layer. Without this
     * dispatch the paths below report EBADF (net_socket_fd_is_valid requires
     * FD_SOCKET), which broke libusb_init()'s setsockopt(SO_PASSCRED) on its
     * NETLINK_KOBJECT_UEVENT monitor socket.
     */
    if (fd_get_type(fd) == FD_NETLINK)
        return netlink_setsockopt(g, fd, level, optname, optval_gva, optlen);

    int small_int_opt = socket_opt_uses_small_int(level, optname);

    /* SO_PASSCRED: emulated entirely in elfuse. Cache the flag value so
     * getsockopt returns it and recvmsg knows to inject SCM_CREDENTIALS. macOS
     * has no equivalent. Do not forward.
     */
    if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_PASSCRED) {
        if (!net_socket_fd_is_valid(fd))
            return -LINUX_EBADF;
        if (optlen == 0 || optlen > sizeof(int))
            return -LINUX_EINVAL;
        int value = 0;
        if (guest_read_small(g, optval_gva, &value, optlen) < 0)
            return -LINUX_EFAULT;
        value = socket_small_int_normalize(level, optname, value);
        net_socket_cached_int_set(fd, LINUX_SOL_SOCKET, LINUX_SO_PASSCRED,
                                  value);
        return 0;
    }

    if (level == LINUX_IPPROTO_IP && optname == LINUX_IP_MTU_DISCOVER) {
        /* P2P networking tools (libp2p, syncthing, WireGuard userland,
         * Tailscale's bundled tailscaled) set IP_MTU_DISCOVER early in connect
         * and abort on -ENOPROTOOPT. macOS has no direct equivalent; accept the
         * option, cache the Linux PMTUD mode for getsockopt round-trip, and
         * where the host can honour it, push the closest IP_DONTFRAG setting
         * onto the underlying socket. Linux PMTUD modes:
         *   0 DONT  / 1 WANT  -> allow fragmentation (DONTFRAG off)
         *   2 DO   / 3 PROBE  / 4 INTERFACE -> set DF (DONTFRAG on)
         *   5 OMIT -> behave like DONT (best-effort)
         */
        if (!net_socket_fd_is_valid(fd))
            return -LINUX_EBADF;
        if (optlen == 0 || optlen > sizeof(int))
            return -LINUX_EINVAL;
        int value = 0;
        if (guest_read_small(g, optval_gva, &value, optlen) < 0)
            return -LINUX_EFAULT;
        net_socket_cached_int_set(fd, LINUX_IPPROTO_IP, LINUX_IP_MTU_DISCOVER,
                                  value);
        host_fd_ref_t hr;
        if (host_fd_ref_open(fd, &hr) == 0) {
            int dontfrag = (value >= 2 && value <= 4) ? 1 : 0;
            (void) setsockopt(hr.fd, IPPROTO_IP, IP_DONTFRAG, &dontfrag,
                              sizeof(dontfrag));
            host_fd_ref_close(&hr);
        }
        return 0;
    }
    if (level == LINUX_IPPROTO_IP && optname == LINUX_IP_RECVERR) {
        /* No macOS equivalent for the Linux extended-error queue. Accept and
         * discard; the queue stays empty, so subsequent recvmsg with
         * MSG_ERRQUEUE returns -EAGAIN as Linux would for a quiescent
         * connection.
         */
        if (!net_socket_fd_is_valid(fd))
            return -LINUX_EBADF;
        if (optlen == 0 || optlen > sizeof(int))
            return -LINUX_EINVAL;
        int value = 0;
        if (guest_read_small(g, optval_gva, &value, optlen) < 0)
            return -LINUX_EFAULT;
        (void) value;
        return 0;
    }

    if (readonly_setsockopt(level, optname)) {
        if (!net_socket_fd_is_valid(fd))
            return -LINUX_EBADF;
        return -LINUX_ENOPROTOOPT;
    }

    if (optlen > 0 && optlen <= sizeof(int) && small_int_opt) {
        int value = 0;
        if (guest_read_small(g, optval_gva, &value, optlen) < 0)
            return -LINUX_EFAULT;
        value = socket_small_int_normalize(level, optname, value);

        int cached_value = 0;
        int cached_mac_level = level, cached_mac_optname = optname;
        if (cached_setsockopt_may_succeed(level, optname) &&
            translate_small_int_sockopt(level, optname, &cached_mac_level,
                                        &cached_mac_optname) &&
            net_socket_cached_int_get(fd, level, optname, &cached_value) &&
            cached_value == value)
            return 0;
    }

    host_fd_ref_t host_ref;
    int64_t ref_err = host_fd_ref_open(fd, &host_ref);
    if (ref_err < 0)
        return ref_err;

    int mac_level = level, mac_optname = optname;

    if (small_int_opt &&
        translate_small_int_sockopt(level, optname, &mac_level, &mac_optname)) {
        goto setsockopt_translated;
    }

    if (!translate_sockopt_level(level, optname, &mac_level, &mac_optname)) {
        host_fd_ref_close(&host_ref);
        return -LINUX_ENOPROTOOPT;
    }

setsockopt_translated:
    if (optlen <= sizeof(int) && small_int_opt) {
        if (optlen == 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
        int value = 0;
        if (guest_read_small(g, optval_gva, &value, optlen) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        value = socket_small_int_normalize(level, optname, value);

        /* The cached-value short-circuit (return 0 when the socket already
         * holds this value) ran before host_fd_ref_open for every small-int
         * option with optlen > 0, so it is not repeated here.
         *
         * Linux accepts shorter optlen for many int-valued options and
         * zero-extends the value. macOS rejects optlen < sizeof(int) with
         * EINVAL (notably for IP_TOS / IP_TTL / IP_PKTINFO / IP_RECVTTL /
         * IP_RECVTOS). The value has already been zero-extended into an int, so
         * always call the host with sizeof(int).
         */
        if (setsockopt(host_ref.fd, mac_level, mac_optname, &value,
                       sizeof(value)) < 0) {
            log_debug("setsockopt(fd=%d, level=%d/%d, opt=%d/%d, len=%u): %s",
                      fd, level, mac_level, optname, mac_optname, optlen,
                      strerror(errno));
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        net_socket_cached_int_set(fd, level, optname, value);
        host_fd_ref_close(&host_ref);
        return 0;
    }

    uint8_t optval[256];
    if (optlen > sizeof(optval)) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EINVAL;
    }
    if (optlen > 0 && guest_read(g, optval_gva, optval, optlen) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    if (setsockopt(host_ref.fd, mac_level, mac_optname, optval,
                   (socklen_t) optlen) < 0) {
        log_debug("setsockopt(fd=%d, level=%d/%d, opt=%d/%d, len=%u): %s", fd,
                  level, mac_level, optname, mac_optname, optlen,
                  strerror(errno));
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }
    host_fd_ref_close(&host_ref);
    return 0;
}

/* Mirrors Linux ip_sockglue copyval: when an IP-level getsockopt has a caller
 * buffer shorter than int and the int-sized value fits in a byte, report and
 * write a single byte. Otherwise leaves actual_len untouched.
 */
static inline uint32_t ip_copyval_clamp(int level,
                                        uint32_t guest_optlen,
                                        int value,
                                        uint32_t actual_len)
{
    if (level == LINUX_IPPROTO_IP && guest_optlen > 0 &&
        guest_optlen < sizeof(int) && value >= 0 && value <= 255)
        return 1;
    return actual_len;
}

/* How many bytes a getsockopt reply may write into the caller's buffer.
 *
 * Not the MIN macro in utils.h: it is a statement expression, which this tree
 * compiles with -Werror against.
 */
static inline uint32_t sockopt_write_len(uint32_t actual_len,
                                         uint32_t guest_optlen)
{
    return actual_len < guest_optlen ? actual_len : guest_optlen;
}

int64_t sys_getsockopt(guest_t *g,
                       int fd,
                       int level,
                       int optname,
                       uint64_t optval_gva,
                       uint64_t optlen_gva)
{
    /* See sys_setsockopt: netlink fds carry emulated SOL_SOCKET options. */
    if (fd_get_type(fd) == FD_NETLINK)
        return netlink_getsockopt(g, fd, level, optname, optval_gva,
                                  optlen_gva);

    uint32_t guest_optlen;
    if (guest_read_small(g, optlen_gva, &guest_optlen, sizeof(guest_optlen)) <
        0)
        return -LINUX_EFAULT;

    /* SO_PEERCRED: synthesize struct ucred from guest identity. macOS has
     * LOCAL_PEERCRED but returns a different struct; fabricate the Linux ucred
     * with the guest's own PID/UID/GID, which is correct for AF_UNIX sockets
     * within the same elfuse instance.
     */
    if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_PEERCRED) {
        if (!net_socket_fd_is_valid(fd))
            return -LINUX_EBADF;
        linux_ucred_t cred = {
            .pid = (int32_t) proc_get_pid(),
            .uid = proc_get_uid(),
            .gid = proc_get_gid(),
        };
        uint32_t out_len =
            sockopt_write_len((uint32_t) sizeof(cred), guest_optlen);
        if (out_len > 0 && guest_write_small(g, optval_gva, &cred, out_len) < 0)
            return -LINUX_EFAULT;
        uint32_t actual_len = sizeof(cred);
        if (guest_write_small(g, optlen_gva, &actual_len, sizeof(actual_len)) <
            0)
            return -LINUX_EFAULT;
        return 0;
    }

    if (level == LINUX_IPPROTO_IP &&
        (optname == LINUX_IP_MTU_DISCOVER || optname == LINUX_IP_RECVERR)) {
        if (!net_socket_fd_is_valid(fd))
            return -LINUX_EBADF;
        if (guest_optlen >= sizeof(int)) {
            /* IP_MTU_DISCOVER round-trips through the per-fd cache so
             * getsockopt reports what the guest last wrote via setsockopt.
             * IP_RECVERR has no cache (the extended-error queue stays
             * permanently empty), so it always reports 1.
             */
            int val = 1;
            if (optname == LINUX_IP_MTU_DISCOVER)
                (void) net_socket_cached_int_get(fd, level, optname, &val);
            uint32_t out_len = sizeof(int);
            if (guest_write_small(g, optval_gva, &val, sizeof(val)) < 0)
                return -LINUX_EFAULT;
            if (guest_write_small(g, optlen_gva, &out_len, sizeof(out_len)) < 0)
                return -LINUX_EFAULT;
        }
        return 0;
    }

    if (socket_opt_uses_small_int(level, optname)) {
        int value = 0;
        if (net_socket_cached_int_get(fd, level, optname, &value)) {
            uint32_t actual_len =
                ip_copyval_clamp(level, guest_optlen, value, sizeof(int));
            uint32_t write_len = sockopt_write_len(actual_len, guest_optlen);
            if (write_len > 0 &&
                guest_write_small(g, optval_gva, &value, write_len) < 0)
                return -LINUX_EFAULT;
            if (guest_write_small(g, optlen_gva, &actual_len,
                                  sizeof(actual_len)) < 0)
                return -LINUX_EFAULT;
            return 0;
        }
    }

    host_fd_ref_t host_ref;
    int64_t ref_err = host_fd_ref_open(fd, &host_ref);
    if (ref_err < 0)
        return ref_err;

    int mac_level = level, mac_optname = optname;
    int small_int_opt = socket_opt_uses_small_int(level, optname);

    if (small_int_opt &&
        translate_small_int_sockopt(level, optname, &mac_level, &mac_optname)) {
        goto getsockopt_translated;
    }

    if (!translate_sockopt_level(level, optname, &mac_level, &mac_optname)) {
        host_fd_ref_close(&host_ref);
        return -LINUX_ENOPROTOOPT;
    }

getsockopt_translated:
    if (guest_read_small(g, optlen_gva, &guest_optlen, sizeof(guest_optlen)) <
        0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    if (small_int_opt) {
        int value = 0;
        socklen_t mac_optlen = sizeof(value);
        uint32_t actual_len, write_len;
        bool used_cache = net_socket_cached_int_get(fd, level, optname, &value);

        if (!used_cache) {
            if (getsockopt(host_ref.fd, mac_level, mac_optname, &value,
                           &mac_optlen) < 0) {
                host_fd_ref_close(&host_ref);
                return linux_errno();
            }

            if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_TYPE)
                value &= 0xF;

            if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_ERROR &&
                value != 0) {
                errno = value;
                value = (int) (-linux_errno());
            }

            net_socket_cached_int_set(fd, level, optname, value);
        }

        actual_len = used_cache ? sizeof(int) : (uint32_t) mac_optlen;
        actual_len = ip_copyval_clamp(level, guest_optlen, value, actual_len);
        write_len = sockopt_write_len(actual_len, guest_optlen);
        if (write_len > 0 &&
            guest_write_small(g, optval_gva, &value, write_len) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        if (guest_write_small(g, optlen_gva, &actual_len, sizeof(actual_len)) <
            0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }

        host_fd_ref_close(&host_ref);
        return 0;
    }

    uint8_t optval[256];
    socklen_t mac_optlen = (socklen_t) guest_optlen;
    if (mac_optlen > sizeof(optval))
        mac_optlen = sizeof(optval);

    if (getsockopt(host_ref.fd, mac_level, mac_optname, optval, &mac_optlen) <
        0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }

    /* SO_TYPE: macOS returns the raw socket type. On Linux, getsockopt SO_TYPE
     * returns the base type without SOCK_NONBLOCK/SOCK_CLOEXEC flags, and the
     * numeric values happen to match (SOCK_STREAM=1, SOCK_DGRAM=2, SOCK_RAW=3).
     * Strip any flag bits for safety.
     */
    if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_TYPE &&
        mac_optlen >= (socklen_t) sizeof(int)) {
        int *type_val = (int *) optval;
        *type_val &= 0xF; /* Keep only the base socket type */
    }

    /* SO_ERROR: macOS returns a macOS errno value; translate to Linux. */
    if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_ERROR &&
        mac_optlen >= (socklen_t) sizeof(int)) {
        int *err_val = (int *) optval;
        if (*err_val != 0) {
            errno = *err_val;
            *err_val = (int) (-linux_errno());
        }
    }

    /* Write at most the caller's buffer, but report the option's real size:
     * Linux getsockopt does that so a caller can detect truncation and retry
     * with a larger buffer. Every write above clamps the same way.
     */
    uint32_t actual_len = (uint32_t) mac_optlen;
    uint32_t write_len = sockopt_write_len(actual_len, guest_optlen);
    if (guest_write_small(g, optval_gva, optval, write_len) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    if (guest_write_small(g, optlen_gva, &actual_len, sizeof(actual_len)) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    host_fd_ref_close(&host_ref);
    return 0;
}

int64_t sys_shutdown(int fd, int how)
{
    host_fd_ref_t host_ref;
    int64_t ref_err = host_fd_ref_open(fd, &host_ref);
    if (ref_err < 0)
        return ref_err;

    /* Shutdown constants are identical on Linux and macOS */
    if (shutdown(host_ref.fd, how) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }
    host_fd_ref_close(&host_ref);
    return 0;
}
