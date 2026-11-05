/*
 * Socket message syscalls
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "proved/iov.h"
#include "utils.h"

#include "proved/cmsg.h"
#include "proved/timespec.h"
#include "syscall/internal.h"
#include "syscall/io.h"
#include "syscall/net.h"
#include "syscall/net-sockopt.h"
#include "syscall/net-abi.h"
#include "syscall/net-absock.h"
#include "syscall/proc.h"
#include "syscall/signal.h"

/* Linux SCM_MAX_FD: maximum number of file descriptors in SCM_RIGHTS */
#define LINUX_SCM_MAX_FD 253

/* Linux only delivers SCM_CREDENTIALS on AF_UNIX sockets even when SO_PASSCRED
 * is set, so PASSCRED toggled on AF_INET / AF_INET6 must stay a no-op.
 */
static bool host_socket_is_unix(int host_fd)
{
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    return getsockname(host_fd, (struct sockaddr *) &ss, &slen) == 0 &&
           ss.ss_family == AF_UNIX;
}

/* Replace each guest fd in an outbound SCM_RIGHTS payload with a host dup the
 * caller owns, made under fd_lock.
 *
 * A dup rather than the slot's raw host fd because the send happens later,
 * outside the lock: a sibling closing the guest fd in between would free the
 * host number for elfuse's own next descriptor, and the peer would be handed
 * that instead. The dup names the same open file description the guest named,
 * so the peer cannot tell the difference. Every entry gets its own dup, even a
 * repeated guest fd, so close_scm_rights_dups can close each one exactly once.
 *
 * On failure every dup made so far is closed and fds is left unusable.
 */
static int translate_scm_rights_fds(int *fds, size_t nfds)
{
    if (nfds > LINUX_SCM_MAX_FD)
        return -LINUX_EINVAL;

    for (size_t i = 0; i < nfds; i++) {
        errno = EBADF;
        int host_fd = fd_to_host_dup(fds[i]);
        if (host_fd < 0) {
            int err = errno == EBADF ? -LINUX_EBADF : -LINUX_ENOMEM;
            for (size_t j = 0; j < i; j++)
                close(fds[j]);
            return err;
        }
        fds[i] = host_fd;
    }
    return 0;
}

/* Close the host dups translate_scm_rights_fds installed in the first len bytes
 * of a translated control buffer. Runs after the send on every path, since the
 * kernel took its own references when the message was queued.
 */
static void close_scm_rights_dups(uint8_t *ctrl, size_t len)
{
    struct msghdr m = {.msg_control = ctrl, .msg_controllen = (socklen_t) len};
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
            continue;
        size_t n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        int *fds = (int *) CMSG_DATA(c);
        for (size_t i = 0; i < n; i++)
            close(fds[i]);
    }
}

static void recvmsg_cleanup_scm_rights(const int *scm_gfds,
                                       const int *scm_hfds,
                                       int scm_nfds)
{
    for (int i = 0; i < scm_nfds; i++) {
        fd_retire_published(scm_gfds[i], scm_hfds[i]);
    }
}

static void recvmsg_close_host_rights(const void *data_src, size_t data_len)
{
    size_t nfds = data_len / sizeof(int);
    const int *fds = (const int *) data_src;
    for (size_t i = 0; i < nfds; i++)
        close(fds[i]);
}

/* Publish each received host descriptor as a guest fd, rewriting fds[] in place
 * to the guest numbers (-1 where allocation failed, after closing the host
 * descriptor). Successes are recorded in the scm_* arrays so a later failure
 * can retire them; the arrays are bounded by scm_cap and scm_nfds accumulates
 * across control messages.
 */
static void recvmsg_install_rights(int *fds,
                                   size_t nfds,
                                   int flags,
                                   int *scm_gfds,
                                   int *scm_hfds,
                                   int *scm_nfds,
                                   int scm_cap)
{
    for (size_t i = 0; i < nfds; i++) {
        int host_recv_fd = fds[i];

        /* A received descriptor belongs to whoever sent it, so elfuse never
         * sets O_NONBLOCK on one: that would mutate a description this process
         * did not create, and a guest that passes fd 0 to itself would leave
         * the launching shell's terminal nonblocking after exit. Marked foreign
         * so a dup of it inherits the same restraint.
         *
         * Which view of the flag is the guest's still has to be decided, and
         * the flag as found answers it. A description already carrying
         * O_NONBLOCK is one elfuse itself owns: every pipe and fifo it opens
         * carries the flag precisely because it emulates blocking on top, and
         * an ordinary program's description does not. Adopting that emulation
         * here sets nothing (the flag is already there) and gives a plain read
         * the wait it asked for. Reading the host flag as the guest's view
         * instead would hand a blocking read a spurious EAGAIN, which a program
         * that never requested O_NONBLOCK has no handling for.
         *
         * What stays wrong is a sender that meant the description to be
         * nonblocking: the receiver sees blocking. The O_NONBLOCK shadow is per
         * process, and this is the survivable direction of that divergence: a
         * wait the sender would not have waited, rather than an error on an fd
         * that has none.
         */
        int recv_fl = fcntl(host_recv_fd, F_GETFL);
        fd_alias_spec_t spec =
            fd_alias_carried(true, recv_fl >= 0 && (recv_fl & O_NONBLOCK));
        int gfd = fd_alloc_alias(&spec, FD_REGULAR, fds[i], NULL);
        if (gfd < 0) {
            close(fds[i]);
            fds[i] = -1;
            continue;
        }
        fds[i] = gfd;
        if (*scm_nfds < scm_cap) {
            scm_gfds[*scm_nfds] = gfd;
            scm_hfds[*scm_nfds] = host_recv_fd;
            (*scm_nfds)++;
        }
        if (flags & LINUX_MSG_CMSG_CLOEXEC)
            fd_table[gfd].linux_flags |= LINUX_O_CLOEXEC;
    }
}

/* Write the peer address and its length back to the guest msghdr.
 *
 * Returns 0 or -LINUX_EFAULT; the caller owns every cleanup.
 */
static int64_t recvmsg_write_name(guest_t *g,
                                  uint64_t msg_gva,
                                  const linux_msghdr_t *lmsg,
                                  const struct sockaddr_storage *mac_sa,
                                  socklen_t mac_namelen)
{
    /* Stays 0 when the host reported no address, and when one could not be
     * converted: either way nothing was written for a length to describe.
     */
    uint32_t nl = 0;
    if (mac_namelen > 0) {
        uint8_t linux_sa[128];
        int out_len =
            net_sockaddr_from_mac((const struct sockaddr *) mac_sa, mac_namelen,
                                  linux_sa, (uint32_t) sizeof(linux_sa));
        if (out_len > 0) {
            /* The length must describe the bytes written, which are the
             * translated address rather than the host one: a pathname socket's
             * host spelling is the longer of the two, so passing the host
             * length on leaves the guest reading past the address it was given.
             * Reported untruncated, per recvmsg(2).
             */
            nl = (uint32_t) out_len;
            uint32_t write_len = nl;
            if (write_len > lmsg->msg_namelen)
                write_len = lmsg->msg_namelen;
            if (guest_write_small(g, lmsg->msg_name, linux_sa, write_len) < 0)
                return -LINUX_EFAULT;
        }
    }
    if (guest_write_small(g, msg_gva + offsetof(linux_msghdr_t, msg_namelen),
                          &nl, sizeof(nl)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* Wire size of a Linux SCM_CREDENTIALS control message: cmsghdr plus ucred,
 * rounded up to the cmsg alignment.
 */
#define SCM_CRED_CMSG_SPACE                                     \
    (((size_t) (CMSG_LINUX_HDR_BYTES + sizeof(linux_ucred_t)) + \
      (CMSG_LINUX_ALIGN - 1)) &                                 \
     ~(size_t) (CMSG_LINUX_ALIGN - 1))

/* Pack an SCM_CREDENTIALS control message carrying this process's identity into
 * dst, which must have room for SCM_CRED_CMSG_SPACE bytes. Zero-fills the
 * alignment tail so no host stack bytes leak to the guest. Injected on recvmsg
 * when the guest set SO_PASSCRED, since macOS has no SCM_CREDENTIALS.
 */
static void build_scm_cred_cmsg(uint8_t *dst)
{
    linux_ucred_t cred = {
        .pid = (int32_t) proc_get_pid(),
        .uid = proc_get_uid(),
        .gid = proc_get_gid(),
    };
    uint64_t cred_cmsg_len = CMSG_LINUX_HDR_BYTES + sizeof(cred);
    int32_t cred_level = 1; /* SOL_SOCKET */
    int32_t cred_type = LINUX_SCM_CREDENTIALS;
    memset(dst, 0, SCM_CRED_CMSG_SPACE);
    memcpy(dst, &cred_cmsg_len, 8);
    memcpy(dst + 8, &cred_level, 4);
    memcpy(dst + 12, &cred_type, 4);
    memcpy(dst + CMSG_LINUX_HDR_BYTES, &cred, sizeof(cred));
}

/* Advance an iovec past bytes already moved, so the next round starts after
 * them.
 *
 * Returns the number of leading entries fully consumed.
 */
static int msg_iov_advance(struct iovec *iov, int iovcnt, size_t moved)
{
    size_t rem = 0;
    int spent = iov_advance_index(iov, iovcnt, moved, &rem);
    if (spent < iovcnt && rem > 0) {
        iov[spent].iov_base = (char *) iov[spent].iov_base + rem;
        iov[spent].iov_len -= rem;
    }
    return spent;
}

int64_t net_send_xfer(const fd_block_state_t *st,
                      int host_fd,
                      struct msghdr *msg,
                      int linux_flags)
{
    uint64_t want = 0;
    for (int i = 0; i < (int) msg->msg_iovlen; i++) {
        if (!iov_total_add(want, msg->msg_iov[i].iov_len, &want))
            return -LINUX_EINVAL;
    }

    bool blocking = want > 0 && sock_op_should_block(st, host_fd, linux_flags);
    int host_flags =
        translate_msg_flags(linux_flags) | (blocking ? MSG_DONTWAIT : 0);
    uint64_t total = 0;
    int spins = 0;
    unsigned backoff = 0;
    for (;;) {
        if (blocking) {
            int64_t waited = io_wait_fd_or_interrupted(host_fd, POLLOUT);
            if (waited < 0)
                return total > 0 ? (int64_t) total : waited;
        }
        ssize_t ret = sendmsg(host_fd, msg, host_flags);
        if (ret < 0) {
            if (!blocking || errno != EAGAIN)
                break;

            /* The wait reports ready on POLLHUP and POLLERR too, so a send that
             * keeps answering EAGAIN would spin a core; back off as io_xfer
             * does, which also puts an interrupt check in the loop.
             */
            if (++spins >= IO_XFER_SPIN_LIMIT) {
                int64_t rc = io_retry_backoff(&backoff);
                if (rc < 0)
                    return total > 0 ? (int64_t) total : rc;
            }
            continue;
        }
        spins = 0;
        backoff = 0;
        total += (uint64_t) ret;

        /* Only a stream send owes the rest. A datagram or seqpacket send is one
         * record and either went whole or failed, and asking the type only
         * after a short send keeps getsockopt off every send that completes.
         */
        if (!blocking || ret == 0 || total == want ||
            !host_socket_is_stream(host_fd))
            return (int64_t) total;

        int spent =
            msg_iov_advance(msg->msg_iov, (int) msg->msg_iovlen, (size_t) ret);
        msg->msg_iov += spent;
        msg->msg_iovlen -= spent;

        /* The first round queued the rights and the address with its bytes;
         * Linux attaches ancillary data to the first segment only, and a second
         * copy would install the descriptors twice at the peer.
         */
        msg->msg_control = NULL;
        msg->msg_controllen = 0;
        msg->msg_name = NULL;
        msg->msg_namelen = 0;
    }

    /* A stream send that moved bytes reports them and raises no SIGPIPE: both
     * unix_stream_sendmsg and tcp_sendmsg signal only when nothing was sent.
     */
    if (total > 0)
        return (int64_t) total;
    if (errno == EPIPE && !(linux_flags & LINUX_MSG_NOSIGNAL))
        signal_queue(LINUX_SIGPIPE);
    return linux_errno();
}

/* Send the no-name, no-control, single-iovec fast path of a msghdr.
 *
 * Returns the byte count or a negative Linux errno, and consumes host_ref
 * either way. net_send_xfer carries the blocking contract.
 */
static int64_t net_send_single_iov(guest_t *g,
                                   const linux_msghdr_t *lmsg,
                                   host_fd_ref_t *host_ref,
                                   const fd_block_state_t *sock_st,
                                   int linux_flags)
{
    struct {
        uint64_t iov_base, iov_len;
    } guest_iov;

    if (guest_read_small(g, lmsg->msg_iov, &guest_iov, sizeof(guest_iov)) < 0) {
        host_fd_ref_close(host_ref);
        return -LINUX_EFAULT;
    }

    void *base = NULL;
    size_t len = 0;
    if (guest_iov.iov_len > 0) {
        uint64_t avail = 0;
        base = guest_ptr_bound(g, guest_iov.iov_base, &avail, MEM_PERM_R,
                               guest_iov.iov_len);
        if (!base) {
            host_fd_ref_close(host_ref);
            return -LINUX_EFAULT;
        }
        len = guest_iov.iov_len;
        if (len > avail)
            len = (size_t) avail;
    }

    struct iovec iov = {.iov_base = base, .iov_len = len};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    int64_t ret = net_send_xfer(sock_st, host_ref->fd, &msg, linux_flags);
    host_fd_ref_close(host_ref);
    return ret;
}

int64_t sys_sendmsg(guest_t *g, int fd, uint64_t msg_gva, int linux_flags)
{
    if (fd_get_type(fd) == FD_NETLINK)
        return netlink_sendmsg(fd, g, msg_gva, linux_flags);

    host_fd_ref_t host_ref;
    fd_block_state_t sock_st;
    int64_t ref_err = host_fd_ref_open_state(fd, &host_ref, &sock_st);
    if (ref_err < 0)
        return ref_err;

    linux_msghdr_t lmsg;
    if (guest_read_small(g, msg_gva, &lmsg, sizeof(lmsg)) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    if ((!lmsg.msg_name || lmsg.msg_namelen == 0) &&
        (!lmsg.msg_control || lmsg.msg_controllen == 0) && lmsg.msg_iovlen == 1)
        return net_send_single_iov(g, &lmsg, &host_ref, &sock_st, linux_flags);

    struct sockaddr_storage mac_sa;
    struct sockaddr *dest_sa = NULL;
    socklen_t dest_len = 0;
    if (lmsg.msg_name && lmsg.msg_namelen > 0) {
        uint8_t linux_sa[128];
        if (lmsg.msg_namelen > sizeof(linux_sa)) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
        if (guest_read(g, lmsg.msg_name, linux_sa, lmsg.msg_namelen) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        int ml =
            net_sockaddr_to_mac(linux_sa, lmsg.msg_namelen, false, &mac_sa);
        if (ml < 0) {
            host_fd_ref_close(&host_ref);
            return ml;
        }
        dest_sa = (struct sockaddr *) &mac_sa;
        dest_len = (socklen_t) ml;
    }

    /* msg_iovlen is uint64_t on Linux; bound it against SYSCALL_IOV_MAX before
     * the int narrowing below so a 64-bit value whose low 32 bits fall inside
     * [0, SYSCALL_IOV_MAX] cannot slip past the cap.
     */
    if (lmsg.msg_iovlen > SYSCALL_IOV_MAX) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EINVAL;
    }
    int send_iovcnt = (int) lmsg.msg_iovlen;

    host_iov_buf_t host_iov;
    int64_t iov_err = host_iov_prepare_msg(g, lmsg.msg_iov, send_iovcnt,
                                           MEM_PERM_R, &host_iov);
    if (iov_err < 0) {
        host_fd_ref_close(&host_ref);
        return iov_err;
    }

    uint8_t linux_ctrl_stack[512], mac_ctrl_stack[512];
    uint8_t *linux_ctrl = linux_ctrl_stack;
    uint8_t *mac_ctrl = mac_ctrl_stack;
    size_t mac_ctrl_size = sizeof(mac_ctrl_stack);
    uint8_t *linux_ctrl_heap = NULL;
    uint8_t *mac_ctrl_heap = NULL;
    uint8_t *ctrl_ptr = NULL;
    socklen_t ctrl_len = 0;

    if (lmsg.msg_control && lmsg.msg_controllen > 0) {
        /* Bound msg_controllen before narrowing it. CMSG_LINUX_CTL_MAX is the
         * precondition cmsg_entry_bounds is proved under, so this check is what
         * makes that proof apply to the walk below.
         */
        if (lmsg.msg_controllen > CMSG_LINUX_CTL_MAX) {
            host_iov_free(&host_iov);
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
        size_t clen = (size_t) lmsg.msg_controllen;
        if (clen > sizeof(linux_ctrl_stack)) {
            linux_ctrl_heap = malloc(clen);
            mac_ctrl_heap = malloc(clen);
            if (!linux_ctrl_heap || !mac_ctrl_heap) {
                free(linux_ctrl_heap);
                free(mac_ctrl_heap);
                host_iov_free(&host_iov);
                host_fd_ref_close(&host_ref);
                return -LINUX_ENOMEM;
            }
            linux_ctrl = linux_ctrl_heap;
            mac_ctrl = mac_ctrl_heap;
            mac_ctrl_size = clen;
        }
        if (guest_read(g, lmsg.msg_control, linux_ctrl, clen) < 0) {
            free(linux_ctrl_heap);
            free(mac_ctrl_heap);
            host_iov_free(&host_iov);
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }

        uint64_t lpos = 0;
        size_t mpos = 0;
        uint64_t lctl_len = lmsg.msg_controllen;

        while (lpos + CMSG_LINUX_HDR_BYTES <= lctl_len) {
            uint64_t lcmsg_len;
            int32_t lcmsg_level, lcmsg_type;
            memcpy(&lcmsg_len, linux_ctrl + lpos, 8);
            memcpy(&lcmsg_level, linux_ctrl + lpos + 8, 4);
            memcpy(&lcmsg_type, linux_ctrl + lpos + 12, 4);

            /* Proved in src/proved/cmsg.h: on success the ldata_len payload
             * bytes at lpos + CMSG_LINUX_HDR_BYTES lie inside linux_ctrl, and
             * next_lpos is strictly past lpos.
             */
            uint64_t ldata_len, next_lpos;
            if (!cmsg_entry_bounds(lpos, lctl_len, lcmsg_len, &ldata_len,
                                   &next_lpos))
                break;

            if (lcmsg_level == 1 && lcmsg_type == LINUX_SCM_CREDENTIALS) {
                lpos = next_lpos;
                continue;
            }

            int mac_level = (lcmsg_level == 1) ? SOL_SOCKET : lcmsg_level;
            int mac_type = lcmsg_type;
            if (lcmsg_level == LINUX_IPPROTO_IP) {
                mac_level = IPPROTO_IP;
                mac_type = translate_ip_cmsg_to_mac(lcmsg_type);
                if (mac_type < 0) {
                    lpos = next_lpos;
                    continue;
                }
            }

            if (mpos + CMSG_SPACE(ldata_len) > mac_ctrl_size)
                break;

            struct msghdr tmsg = {.msg_control = mac_ctrl + mpos,
                                  .msg_controllen = mac_ctrl_size - mpos};
            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&tmsg);
            if (!cmsg)
                break;
            cmsg->cmsg_len = CMSG_LEN(ldata_len);
            cmsg->cmsg_level = mac_level;
            cmsg->cmsg_type = mac_type;
            memcpy(CMSG_DATA(cmsg), linux_ctrl + lpos + CMSG_LINUX_HDR_BYTES,
                   ldata_len);

            if (mac_level == SOL_SOCKET && mac_type == SCM_RIGHTS) {
                int *fds = (int *) CMSG_DATA(cmsg);
                size_t nfds = ldata_len / sizeof(int);
                int rc = translate_scm_rights_fds(fds, nfds);
                if (rc < 0) {
                    close_scm_rights_dups(mac_ctrl, mpos);
                    free(linux_ctrl_heap);
                    free(mac_ctrl_heap);
                    host_iov_free(&host_iov);
                    host_fd_ref_close(&host_ref);
                    return rc;
                }
            }

            mpos += CMSG_SPACE(ldata_len);
            lpos = next_lpos;
        }

        if (mpos > 0) {
            ctrl_ptr = mac_ctrl;
            ctrl_len = (socklen_t) mpos;
        }
    }

    struct msghdr msg = {
        .msg_name = dest_sa,
        .msg_namelen = dest_len,
        .msg_iov = host_iov.iov,
        .msg_iovlen = send_iovcnt,
        .msg_control = ctrl_ptr,
        .msg_controllen = ctrl_len,
        .msg_flags = 0,
    };

    int64_t ret = net_send_xfer(&sock_st, host_ref.fd, &msg, linux_flags);
    close_scm_rights_dups(mac_ctrl, (size_t) ctrl_len);
    free(linux_ctrl_heap);
    free(mac_ctrl_heap);
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return ret;
}

/* The gathering form of MSG_WAITALL for the msghdr paths.
 *
 * Same reason as recv_gathers_waitall, which this defers to: the host does not
 * answer for the flag, and a guest recvmsg(MSG_WAITALL) that reaches it parks
 * the vCPU for good. Stripping the flag alone would fix the hang and leave a
 * blocking recvmsg reporting a short count where Linux waits, so the loop
 * gathers across the iovec with iov_advance_index, the same proved bound the
 * transfer path uses.
 *
 * A caller that asked for ancillary data is excluded rather than gathered. A
 * second round would have to either overwrite the control buffer, losing the
 * SCM_RIGHTS descriptors the first round installed, or refuse it and let the
 * kernel discard them. Neither is worth doing to a message that has already
 * been delivered, so those calls get the flag stripped and a single round --
 * the hang is gone, and MSG_WAITALL with ancillary data still short-counts.
 */
static bool msg_gathers_waitall(int host_fd, int linux_flags, size_t controllen)
{
    if (controllen != 0)
        return false;
    return recv_gathers_waitall(host_fd, linux_flags);
}

/* Total bytes an iovec can still accept. */
static size_t msg_iov_total(const struct iovec *iov, int iovcnt)
{
    size_t total = 0;
    for (int i = 0; i < iovcnt; i++)
        total += iov[i].iov_len;
    return total;
}

/* Over the function-size limit on purpose.
 *
 * The msghdr round trip: read the guest structure, transfer, then write back
 * name, control and flags. The write-back has to see what the read established,
 * and the SCM_RIGHTS arm has to unwind fds it installed.
 */
/* NOLINTNEXTLINE(readability-function-size) */
int64_t sys_recvmsg(guest_t *g, int fd, uint64_t msg_gva, int flags)
{
    if (fd_get_type(fd) == FD_NETLINK)
        return netlink_recvmsg(fd, g, msg_gva, flags);

    host_fd_ref_t host_ref;
    fd_block_state_t sock_st;
    int64_t ref_err = host_fd_ref_open_state(fd, &host_ref, &sock_st);
    if (ref_err < 0)
        return ref_err;

    linux_msghdr_t lmsg;
    if (guest_read_small(g, msg_gva, &lmsg, sizeof(lmsg)) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    int mac_flags = translate_msg_flags(flags);

    if (!lmsg.msg_name && (!lmsg.msg_control || lmsg.msg_controllen == 0) &&
        lmsg.msg_iovlen == 1) {
        struct {
            uint64_t iov_base, iov_len;
        } guest_iov;

        if (guest_read_small(g, lmsg.msg_iov, &guest_iov, sizeof(guest_iov)) <
            0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }

        void *base = NULL;
        size_t len = 0;
        if (guest_iov.iov_len > 0) {
            uint64_t avail = 0;
            base = guest_ptr_bound(g, guest_iov.iov_base, &avail, MEM_PERM_W,
                                   guest_iov.iov_len);
            if (!base) {
                host_fd_ref_close(&host_ref);
                return -LINUX_EFAULT;
            }
            len = guest_iov.iov_len;
            if (len > avail)
                len = (size_t) avail;
        }

        int64_t waited =
            len > 0
                ? net_wait_or_interrupted(&sock_st, host_ref.fd, POLLIN, flags)
                : net_recv_zero_payload_gate(&sock_st, host_ref.fd, flags);
        if (waited < 0) {
            host_fd_ref_close(&host_ref);
            return waited;
        }

        struct iovec host_iov = {
            .iov_base = base,
            .iov_len = len,
        };
        struct msghdr msg = {
            .msg_iov = &host_iov,
            .msg_iovlen = 1,
            .msg_flags = 0,
        };

        /* Retry the EAGAIN a blocking guest socket must not see: elfuse owns
         * O_NONBLOCK on the host descriptor, so it reports one for a readiness
         * a sibling took. MSG_WAITALL is gathered here rather than handed to
         * the host, which does not answer for it (msg_gathers_waitall). This
         * branch carries no ancillary buffer, so the gather is unconditional
         * once the predicate holds.
         */
        bool gather = msg_gathers_waitall(host_ref.fd, flags, 0);
        if (recv_strip_waitall(flags))
            mac_flags &= ~MSG_WAITALL;

        ssize_t ret;
        uint64_t total = 0;
        for (;;) {
            msg.msg_flags = 0;
            ret = recvmsg(host_ref.fd, &msg, mac_flags);

            if (ret > 0 && gather) {
                total += (uint64_t) ret;
                if (total >= len ||
                    !sock_op_should_block(&sock_st, host_ref.fd, flags))
                    break;
                host_iov.iov_base = (char *) base + total;
                host_iov.iov_len = len - total;
                waited = net_wait_or_interrupted(&sock_st, host_ref.fd, POLLIN,
                                                 flags);
                if (waited < 0)
                    break; /* interrupted after moving bytes: report the count
                            */
                continue;
            }

            if (!net_recv_should_retry(&sock_st, host_ref.fd, flags, ret))
                break;
            waited =
                net_wait_or_interrupted(&sock_st, host_ref.fd, POLLIN, flags);
            if (waited < 0) {
                if (total > 0)
                    break;
                host_fd_ref_close(&host_ref);
                return waited;
            }
        }
        if (total > 0)
            ret = (ssize_t) total;
        if (ret < 0) {
            int64_t r = recv_eof_or_errno(host_ref.fd, fd);
            if (r != 0) {
                host_fd_ref_close(&host_ref);
                return r;
            }

            /* SEQPACKET-over-DGRAM EOF: fall through with an empty result so
             * the guest sees msg_controllen 0 and msg_flags 0 like a real EOF.
             */
            ret = 0;
            msg.msg_flags = 0;
        }
        uint64_t zero64 = 0;
        int32_t mflags = mac_to_linux_msg_flags(msg.msg_flags);
        if (guest_write_small(
                g, msg_gva + offsetof(linux_msghdr_t, msg_controllen), &zero64,
                sizeof(zero64)) < 0 ||
            guest_write_small(g, msg_gva + offsetof(linux_msghdr_t, msg_flags),
                              &mflags, sizeof(mflags)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return ret;
    }

    /* See sys_sendmsg above: bound msg_iovlen before the int narrowing. */
    if (lmsg.msg_iovlen > SYSCALL_IOV_MAX) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EINVAL;
    }
    int recv_iovcnt = (int) lmsg.msg_iovlen;

    host_iov_buf_t host_iov;
    int64_t iov_err = host_iov_prepare_msg(g, lmsg.msg_iov, recv_iovcnt,
                                           MEM_PERM_W, &host_iov);
    if (iov_err < 0) {
        host_fd_ref_close(&host_ref);
        return iov_err;
    }
    int64_t waited =
        host_iov_has_payload(&host_iov, recv_iovcnt)
            ? net_wait_or_interrupted(&sock_st, host_ref.fd, POLLIN, flags)
            : net_recv_zero_payload_gate(&sock_st, host_ref.fd, flags);
    if (waited < 0) {
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return waited;
    }

    struct sockaddr_storage mac_sa;
    socklen_t sa_len = sizeof(mac_sa);

    if (lmsg.msg_controllen > CMSG_LINUX_CTL_MAX)
        lmsg.msg_controllen = CMSG_LINUX_CTL_MAX;

    uint8_t mac_ctrl_stack[256];
    uint8_t *mac_ctrl = mac_ctrl_stack;
    uint8_t *mac_ctrl_heap = NULL;
    socklen_t ctrl_alloc = 0;
    bool using_heap_ctrl = false;

    if (lmsg.msg_control && lmsg.msg_controllen > 0) {
        size_t mac_need = lmsg.msg_controllen;
        if (mac_need > sizeof(mac_ctrl_stack)) {
            mac_ctrl_heap = malloc(mac_need);
            if (mac_ctrl_heap) {
                mac_ctrl = mac_ctrl_heap;
                using_heap_ctrl = true;
            } else {
                mac_need = sizeof(mac_ctrl_stack);
            }
        }
        ctrl_alloc =
            (socklen_t) (using_heap_ctrl ? mac_need : sizeof(mac_ctrl_stack));
    }

    struct msghdr msg = {
        .msg_name = lmsg.msg_name ? &mac_sa : NULL,
        .msg_namelen = lmsg.msg_name ? sa_len : 0,
        .msg_iov = host_iov.iov,
        .msg_iovlen = recv_iovcnt,
        .msg_control = ctrl_alloc > 0 ? mac_ctrl : NULL,
        .msg_controllen = ctrl_alloc,
        .msg_flags = 0,
    };

    int scm_gfds[128];
    int scm_hfds[128];
    int scm_nfds = 0;

    /* Retry the EAGAIN a blocking guest socket must not see; see the single-iov
     * branch above.
     */
    bool gather = msg_gathers_waitall(host_ref.fd, flags, ctrl_alloc);
    if (recv_strip_waitall(flags))
        mac_flags &= ~MSG_WAITALL;
    size_t want = gather ? msg_iov_total(msg.msg_iov, (int) msg.msg_iovlen) : 0;

    ssize_t ret;
    uint64_t total = 0;
    for (;;) {
        msg.msg_namelen = lmsg.msg_name ? sa_len : 0;
        msg.msg_controllen = ctrl_alloc;
        msg.msg_flags = 0;
        ret = recvmsg(host_ref.fd, &msg, mac_flags);

        if (ret > 0 && gather) {
            total += (uint64_t) ret;
            if (total >= want ||
                !sock_op_should_block(&sock_st, host_ref.fd, flags))
                break;
            int spent = msg_iov_advance(msg.msg_iov, (int) msg.msg_iovlen,
                                        (size_t) ret);
            msg.msg_iov += spent;
            msg.msg_iovlen -= spent;
            if (msg.msg_iovlen == 0)
                break;

            /* Only the first round may deliver a name; a later one would
             * overwrite it with the same peer's address for no gain.
             */
            msg.msg_name = NULL;
            waited =
                net_wait_or_interrupted(&sock_st, host_ref.fd, POLLIN, flags);
            if (waited < 0)
                break; /* interrupted after moving bytes: report the count */
            continue;
        }

        if (!net_recv_should_retry(&sock_st, host_ref.fd, flags, ret))
            break;
        waited = net_wait_or_interrupted(&sock_st, host_ref.fd, POLLIN, flags);
        if (waited < 0) {
            if (total > 0)
                break;
            free(mac_ctrl_heap);
            host_iov_free(&host_iov);
            host_fd_ref_close(&host_ref);
            return waited;
        }
    }
    if (total > 0)
        ret = (ssize_t) total;
    if (ret < 0) {
        int64_t r = recv_eof_or_errno(host_ref.fd, fd);
        free(mac_ctrl_heap);
        host_iov_free(&host_iov);
        if (r == 0) {
            /* SEQPACKET-over-DGRAM EOF: report an empty control buffer and
             * flags, matching a real 0-length recvmsg. Do not fall through --
             * recvmsg left msg unmodified, so the control loop would walk the
             * stale (uninitialized) mac_ctrl buffer. Surface EFAULT on an
             * unwritable msghdr like the success path.
             */
            uint64_t zero64 = 0;
            uint32_t zero32 = 0;
            int32_t zflags = 0;
            if ((lmsg.msg_name &&
                 guest_write_small(
                     g, msg_gva + offsetof(linux_msghdr_t, msg_namelen),
                     &zero32, sizeof(zero32)) < 0) ||
                guest_write_small(
                    g, msg_gva + offsetof(linux_msghdr_t, msg_controllen),
                    &zero64, sizeof(zero64)) < 0 ||
                guest_write_small(g,
                                  msg_gva + offsetof(linux_msghdr_t, msg_flags),
                                  &zflags, sizeof(zflags)) < 0)
                r = -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return r;
    }

    if (lmsg.msg_name) {
        int64_t name_err =
            recvmsg_write_name(g, msg_gva, &lmsg, &mac_sa, msg.msg_namelen);
        if (name_err < 0) {
            free(mac_ctrl_heap);
            host_iov_free(&host_iov);
            host_fd_ref_close(&host_ref);
            return name_err;
        }
    }

    int ctrl_truncated = 0;
    if (ctrl_alloc > 0 && msg.msg_controllen > 0 && lmsg.msg_control) {
        size_t lctrl_size =
            lmsg.msg_controllen > 512 ? lmsg.msg_controllen : 512;
        uint8_t lctrl_stack[512];
        uint8_t *linux_ctrl = lctrl_stack;
        uint8_t *lctrl_heap = NULL;
        if (lctrl_size > sizeof(lctrl_stack)) {
            lctrl_heap = malloc(lctrl_size);
            if (!lctrl_heap) {
                free(mac_ctrl_heap);
                host_iov_free(&host_iov);
                host_fd_ref_close(&host_ref);
                return -LINUX_ENOMEM;
            }
            linux_ctrl = lctrl_heap;
        }
        size_t lpos = 0;

        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg;
             cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_len < CMSG_LEN(0))
                continue;
            size_t data_len = cmsg->cmsg_len - CMSG_LEN(0);
            if (data_len > lctrl_size - CMSG_LINUX_HDR_BYTES) {
                ctrl_truncated = 1;
                break;
            }
            uint64_t lcmsg_len = CMSG_LINUX_HDR_BYTES + data_len;

            /* Same align-up as cmsg_entry_bounds, in the same subtract-the-
             * remainder form. This direction builds the buffer rather than
             * walking a guest-supplied one, so it is not covered by
             * verify-cmsg; keeping the spelling identical avoids the two
             * directions drifting apart.
             */
            size_t lcmsg_space =
                (size_t) (lcmsg_len + (CMSG_LINUX_ALIGN - 1) -
                          (lcmsg_len + (CMSG_LINUX_ALIGN - 1)) %
                              CMSG_LINUX_ALIGN);

            if (lpos + lcmsg_space > lctrl_size ||
                lpos + lcmsg_space > lmsg.msg_controllen) {
                ctrl_truncated = 1;
                break;
            }

            int32_t llevel =
                (cmsg->cmsg_level == SOL_SOCKET) ? 1 : cmsg->cmsg_level;
            int32_t ltype = cmsg->cmsg_type;
            if (cmsg->cmsg_level == IPPROTO_IP) {
                int translated = translate_ip_cmsg_to_linux(cmsg->cmsg_type);
                if (translated < 0)
                    continue;
                llevel = LINUX_IPPROTO_IP;
                ltype = translated;
            }

            uint8_t data_copy_stack[128];
            uint8_t *data_copy = data_copy_stack;
            uint8_t *data_copy_heap = NULL;
            uint8_t *data_src = CMSG_DATA(cmsg);
            if (cmsg->cmsg_level == SOL_SOCKET &&
                cmsg->cmsg_type == SCM_RIGHTS) {
                if (data_len > LINUX_SCM_MAX_FD * sizeof(int)) {
                    recvmsg_close_host_rights(data_src, data_len);
                    recvmsg_cleanup_scm_rights(scm_gfds, scm_hfds, scm_nfds);
                    free(lctrl_heap);
                    free(mac_ctrl_heap);
                    host_iov_free(&host_iov);
                    host_fd_ref_close(&host_ref);
                    return -LINUX_EINVAL;
                }
                if (data_len > sizeof(data_copy_stack)) {
                    data_copy_heap = malloc(data_len);
                    if (!data_copy_heap) {
                        recvmsg_close_host_rights(data_src, data_len);
                        break;
                    }
                    data_copy = data_copy_heap;
                }
                memcpy(data_copy, data_src, data_len);
                recvmsg_install_rights(
                    (int *) data_copy, data_len / sizeof(int), flags, scm_gfds,
                    scm_hfds, &scm_nfds, (int) ARRAY_SIZE(scm_gfds));
                data_src = data_copy;
            }

            memset(linux_ctrl + lpos, 0, lcmsg_space);
            memcpy(linux_ctrl + lpos, &lcmsg_len, 8);
            memcpy(linux_ctrl + lpos + 8, &llevel, 4);
            memcpy(linux_ctrl + lpos + 12, &ltype, 4);
            memcpy(linux_ctrl + lpos + CMSG_LINUX_HDR_BYTES, data_src,
                   data_len);
            free(data_copy_heap);

            lpos += lcmsg_space;
        }

        int passcred_val = 0;
        if (net_socket_cached_int_get(fd, LINUX_SOL_SOCKET, LINUX_SO_PASSCRED,
                                      &passcred_val) &&
            passcred_val && host_socket_is_unix(host_ref.fd)) {
            if (lpos + SCM_CRED_CMSG_SPACE <= lctrl_size &&
                lpos + SCM_CRED_CMSG_SPACE <= lmsg.msg_controllen) {
                build_scm_cred_cmsg(linux_ctrl + lpos);
                lpos += SCM_CRED_CMSG_SPACE;
            }
        }

        if (lpos > 0) {
            if (guest_write_small(g, lmsg.msg_control, linux_ctrl, lpos) < 0) {
                recvmsg_cleanup_scm_rights(scm_gfds, scm_hfds, scm_nfds);
                free(lctrl_heap);
                free(mac_ctrl_heap);
                host_iov_free(&host_iov);
                host_fd_ref_close(&host_ref);
                return -LINUX_EFAULT;
            }
            uint64_t lctl = lpos;
            if (guest_write_small(
                    g, msg_gva + offsetof(linux_msghdr_t, msg_controllen),
                    &lctl, sizeof(lctl)) < 0) {
                recvmsg_cleanup_scm_rights(scm_gfds, scm_hfds, scm_nfds);
                free(lctrl_heap);
                free(mac_ctrl_heap);
                host_iov_free(&host_iov);
                host_fd_ref_close(&host_ref);
                return -LINUX_EFAULT;
            }
        } else {
            uint64_t zero64 = 0;
            if (guest_write_small(
                    g, msg_gva + offsetof(linux_msghdr_t, msg_controllen),
                    &zero64, sizeof(zero64)) < 0) {
                free(lctrl_heap);
                free(mac_ctrl_heap);
                host_iov_free(&host_iov);
                host_fd_ref_close(&host_ref);
                return -LINUX_EFAULT;
            }
        }
        free(lctrl_heap);
    } else if (lmsg.msg_control && lmsg.msg_controllen > 0) {
        bool injected = false;
        int passcred_val = 0;
        if (net_socket_cached_int_get(fd, LINUX_SOL_SOCKET, LINUX_SO_PASSCRED,
                                      &passcred_val) &&
            passcred_val && host_socket_is_unix(host_ref.fd)) {
            if (SCM_CRED_CMSG_SPACE <= lmsg.msg_controllen &&
                SCM_CRED_CMSG_SPACE <= 64) {
                uint8_t cred_buf[64];
                build_scm_cred_cmsg(cred_buf);
                if (guest_write_small(g, lmsg.msg_control, cred_buf,
                                      SCM_CRED_CMSG_SPACE) == 0) {
                    uint64_t cred_ctl_len = SCM_CRED_CMSG_SPACE;
                    guest_write_small(
                        g, msg_gva + offsetof(linux_msghdr_t, msg_controllen),
                        &cred_ctl_len, sizeof(cred_ctl_len));
                    injected = true;
                }
            }
        }
        if (!injected) {
            uint64_t zero64 = 0;
            guest_write_small(
                g, msg_gva + offsetof(linux_msghdr_t, msg_controllen), &zero64,
                sizeof(zero64));
        }
    } else {
        uint64_t zero64 = 0;
        if (guest_write_small(
                g, msg_gva + offsetof(linux_msghdr_t, msg_controllen), &zero64,
                sizeof(zero64)) < 0) {
            free(mac_ctrl_heap);
            host_iov_free(&host_iov);
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
    }

    int32_t mflags = mac_to_linux_msg_flags(msg.msg_flags);
    if (ctrl_alloc > 0 && ctrl_truncated)
        mflags |= 0x08;
    if (guest_write_small(g, msg_gva + offsetof(linux_msghdr_t, msg_flags),
                          &mflags, sizeof(mflags)) < 0) {
        recvmsg_cleanup_scm_rights(scm_gfds, scm_hfds, scm_nfds);
        free(mac_ctrl_heap);
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    free(mac_ctrl_heap);
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return ret;
}

#define LINUX_MMSGHDR_SIZE 64

static inline int write_linux_mmsghdr_len(guest_t *g,
                                          uint64_t hdr_gva,
                                          uint32_t msg_len)
{
    return guest_write_small(g, hdr_gva + offsetof(linux_mmsghdr_t, msg_len),
                             &msg_len, sizeof(msg_len));
}

int64_t sys_sendmmsg(guest_t *g,
                     int fd,
                     uint64_t mmsg_gva,
                     unsigned int vlen,
                     int flags)
{
    if (vlen == 0)
        return 0;
    if (vlen > 1024)
        vlen = 1024;

    if (vlen == 1) {
        linux_msghdr_t lmsg;
        uint64_t msg_gva = mmsg_gva;
        uint32_t msg_len;
        host_fd_ref_t host_ref;

        fd_block_state_t sock_st;
        int64_t ref_err = host_fd_ref_open_state(fd, &host_ref, &sock_st);
        if (ref_err < 0)
            return ref_err;
        if (guest_read_small(g, msg_gva, &lmsg, sizeof(lmsg)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }

        if ((!lmsg.msg_name || lmsg.msg_namelen == 0) &&
            (!lmsg.msg_control || lmsg.msg_controllen == 0) &&
            lmsg.msg_iovlen == 1) {
            int64_t ret =
                net_send_single_iov(g, &lmsg, &host_ref, &sock_st, flags);
            if (ret < 0)
                return ret;
            msg_len = (uint32_t) ret;
            if (write_linux_mmsghdr_len(g, mmsg_gva, msg_len) < 0)
                return -LINUX_EFAULT;
            return 1;
        }

        host_fd_ref_close(&host_ref);
    }

    /* Once a message has gone out, report the count rather than the error, so a
     * restart never re-sends a delivered message. Only a failure before the
     * first send reaches the guest as an errno.
     */
    unsigned int sent = 0;
    for (unsigned int i = 0; i < vlen; i++) {
        uint64_t hdr_gva = mmsg_gva + (uint64_t) i * LINUX_MMSGHDR_SIZE;
        int64_t ret = sys_sendmsg(g, fd, hdr_gva, flags);
        if (ret < 0)
            return sent > 0 ? (int64_t) sent : ret;
        uint32_t msg_len = (uint32_t) ret;
        if (write_linux_mmsghdr_len(g, hdr_gva, msg_len) < 0)
            return sent > 0 ? (int64_t) sent : -LINUX_EFAULT;
        sent++;
    }
    return (int64_t) sent;
}

int64_t sys_recvmmsg(guest_t *g,
                     int fd,
                     uint64_t mmsg_gva,
                     unsigned int vlen,
                     int flags,
                     uint64_t timeout_gva)
{
    if (vlen == 0)
        return 0;
    if (vlen > 1024)
        vlen = 1024;

    if (vlen == 1 && timeout_gva == 0 && !(flags & LINUX_MSG_WAITFORONE)) {
        linux_msghdr_t lmsg;
        uint64_t msg_gva = mmsg_gva;
        int mac_flags = translate_msg_flags(flags);
        host_fd_ref_t host_ref;

        fd_block_state_t sock_st;
        int64_t ref_err = host_fd_ref_open_state(fd, &host_ref, &sock_st);
        if (ref_err < 0)
            return ref_err;
        if (guest_read_small(g, msg_gva, &lmsg, sizeof(lmsg)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }

        if (!lmsg.msg_name && (!lmsg.msg_control || lmsg.msg_controllen == 0) &&
            lmsg.msg_iovlen == 1) {
            struct {
                uint64_t iov_base, iov_len;
            } guest_iov;
            uint64_t avail = 0;
            void *base = NULL;
            size_t len = 0;
            uint64_t zero64 = 0;

            if (guest_read_small(g, lmsg.msg_iov, &guest_iov,
                                 sizeof(guest_iov)) < 0) {
                host_fd_ref_close(&host_ref);
                return -LINUX_EFAULT;
            }
            if (guest_iov.iov_len > 0) {
                base = guest_ptr_bound(g, guest_iov.iov_base, &avail,
                                       MEM_PERM_W, guest_iov.iov_len);
                if (!base) {
                    host_fd_ref_close(&host_ref);
                    return -LINUX_EFAULT;
                }
                len = guest_iov.iov_len;
                if (len > avail)
                    len = (size_t) avail;
            }

            struct iovec host_iov = {.iov_base = base, .iov_len = len};
            struct msghdr host_msg = {
                .msg_iov = &host_iov,
                .msg_iovlen = 1,
            };
            int64_t waited = len > 0 ? net_wait_or_interrupted(
                                           &sock_st, host_ref.fd, POLLIN, flags)
                                     : net_recv_zero_payload_gate(
                                           &sock_st, host_ref.fd, flags);
            if (waited < 0) {
                host_fd_ref_close(&host_ref);
                return waited;
            }

            /* Retry the EAGAIN a blocking guest socket must not see, and gather
             * MSG_WAITALL rather than hand it to the host; see sys_recvmsg.
             */
            bool gather = msg_gathers_waitall(host_ref.fd, flags, 0);
            if (recv_strip_waitall(flags))
                mac_flags &= ~MSG_WAITALL;

            ssize_t ret;
            uint64_t total = 0;
            for (;;) {
                host_msg.msg_flags = 0;
                ret = recvmsg(host_ref.fd, &host_msg, mac_flags);

                if (ret > 0 && gather) {
                    total += (uint64_t) ret;
                    if (total >= len ||
                        !sock_op_should_block(&sock_st, host_ref.fd, flags))
                        break;
                    host_iov.iov_base = (char *) base + total;
                    host_iov.iov_len = len - total;
                    waited = net_wait_or_interrupted(&sock_st, host_ref.fd,
                                                     POLLIN, flags);
                    if (waited < 0)
                        break;
                    continue;
                }

                if (!net_recv_should_retry(&sock_st, host_ref.fd, flags, ret))
                    break;
                waited = net_wait_or_interrupted(&sock_st, host_ref.fd, POLLIN,
                                                 flags);
                if (waited < 0) {
                    if (total > 0)
                        break;
                    host_fd_ref_close(&host_ref);
                    return waited;
                }
            }
            if (total > 0)
                ret = (ssize_t) total;
            if (ret < 0) {
                int64_t r = recv_eof_or_errno(host_ref.fd, fd);
                if (r != 0) {
                    host_fd_ref_close(&host_ref);
                    return r;
                }

                /* SEQPACKET-over-DGRAM EOF: record one empty message, matching
                 * how the general loop path counts a 0-length recvmsg.
                 */
                ret = 0;
                host_msg.msg_flags = 0;
            }
            uint32_t msg_len = (uint32_t) ret;
            int32_t out_flags =
                (int32_t) mac_to_linux_msg_flags(host_msg.msg_flags);
            if (guest_write_small(
                    g, msg_gva + offsetof(linux_msghdr_t, msg_controllen),
                    &zero64, sizeof(zero64)) < 0 ||
                guest_write_small(g,
                                  msg_gva + offsetof(linux_msghdr_t, msg_flags),
                                  &out_flags, sizeof(out_flags)) < 0 ||
                write_linux_mmsghdr_len(g, mmsg_gva, msg_len) < 0) {
                host_fd_ref_close(&host_ref);
                return -LINUX_EFAULT;
            }
            host_fd_ref_close(&host_ref);
            return 1;
        }

        host_fd_ref_close(&host_ref);
    }

    if (timeout_gva) {
        linux_timespec_t ts;
        if (guest_read_small(g, timeout_gva, &ts, sizeof(ts)) == 0) {
            host_fd_ref_t host_ref;
            int64_t ref_err = host_fd_ref_open(fd, &host_ref);
            if (ref_err < 0)
                return ref_err;
            if (ts.tv_sec < 0 || !RANGE_CHECK(ts.tv_nsec, 0, 1000000000LL)) {
                host_fd_ref_close(&host_ref);
                return -LINUX_EINVAL;
            }

            /* Same conversion as ppoll and pselect6. Truncating turned a
             * sub-millisecond timeout into poll(0) and an immediate EAGAIN.
             *
             * Deliberately the finite conversion, unlike epoll_pwait2: the wait
             * below is one poll with nothing to re-arm it, so a -1 here would
             * block forever with no way back out, on a call the guest asked to
             * bound. timespec_to_poll_ms saturates instead, which is still far
             * past any real timeout but is reached.
             */
            int timeout_ms = timespec_to_poll_ms(ts.tv_sec, ts.tv_nsec);
            struct pollfd pfd = {.fd = host_ref.fd, .events = POLLIN};
            int pr = poll(&pfd, 1, timeout_ms);

            /* However that poll ended, it spent part of a relative timeout the
             * guest supplied, and the per-message loop below carries no bound
             * of its own. Every EINTR exit past this point therefore belongs to
             * a call whose deadline a restart would begin again from zero,
             * including the one that matters most: a poll that reported
             * readable, a sibling that took the datagram, and an interrupted
             * wait inside the first sys_recvmsg.
             */
            syscall_restart_forbid();
            host_fd_ref_close(&host_ref);
            if (pr == 0)
                return -LINUX_EAGAIN;
            if (pr < 0)
                return linux_errno();
        }
    }

    bool waitforone = (flags & LINUX_MSG_WAITFORONE) != 0;
    int msg_flags = flags & ~LINUX_MSG_WAITFORONE;

    unsigned int received = 0;
    for (unsigned int i = 0; i < vlen; i++) {
        uint64_t hdr_gva = mmsg_gva + (uint64_t) i * LINUX_MMSGHDR_SIZE;
        int cur_flags = msg_flags;
        if (waitforone && received > 0)
            cur_flags |= 0x40;
        int64_t ret = sys_recvmsg(g, fd, hdr_gva, cur_flags);
        if (ret < 0)
            return received > 0 ? (int64_t) received : ret;
        uint32_t msg_len = (uint32_t) ret;
        if (write_linux_mmsghdr_len(g, hdr_gva, msg_len) < 0)
            return received > 0 ? (int64_t) received : -LINUX_EFAULT;
        received++;

        /* A zero-length message ends the batch. On a connection-oriented socket
         * it is EOF; the macOS SEQPACKET-over-DGRAM substitute reports that EOF
         * only once (then EAGAIN), so a further blocking iteration would hang
         * waiting for a persistent EOF that never arrives. Stop here, matching
         * the vlen==1 fast path: recvmmsg may return fewer than vlen messages
         * and callers loop for more.
         */
        if (ret == 0)
            break;
    }
    return (int64_t) received;
}
