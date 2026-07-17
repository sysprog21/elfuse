/*
 * AF_NETLINK emulation
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Emulates Linux NETLINK_ROUTE sockets so that glibc's getifaddrs() works.
 * macOS has no AF_NETLINK; netlink emulation synthesizes responses by querying
 * the host via getifaddrs(3) and formatting into Linux netlink message headers
 * (struct nlmsghdr, struct ifinfomsg, struct ifaddrmsg, etc.).
 *
 * Supported operations:
 *   socket(AF_NETLINK, SOCK_RAW|SOCK_DGRAM, NETLINK_ROUTE) -> synthetic fd
 *   bind() -> always succeeds, recording nl_pid and the nl_groups mask
 *   sendmsg(RTM_GETLINK) -> builds interface list from host getifaddrs
 *   sendmsg(RTM_GETADDR) -> builds address list from host getifaddrs
 *   recvmsg() / read() -> returns buffered response data
 *
 * NETLINK_KOBJECT_UEVENT sockets are also accepted, as a silent socket: no
 * uevent is ever synthesized, so the fd never becomes readable, a non-blocking
 * receive reports EAGAIN, and poll() times out. That is exactly the Linux
 * kernel's behavior on a machine with no hotplug activity, and it is enough for
 * libusb_init()'s netlink hotplug monitor (socket + bind(nl_groups=1) +
 * setsockopt(SO_PASSCRED) + a poll loop) to come up. Sends on a uevent socket
 * report -EPERM, matching uevent_net_rcv() for a sender without CAP_SYS_ADMIN
 * (elfuse guests are not privileged over the host's device model). SOL_SOCKET
 * and SOL_NETLINK options on any netlink fd are emulated per-fd in
 * netlink_setsockopt/netlink_getsockopt below.
 *
 * Other protocols return -EAFNOSUPPORT at socket() time.
 */

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "syscall/linux-wire.h"
#include "syscall/internal.h"
#include "syscall/io.h" /* io_wait_fd_timed_or_interrupted */
#include "syscall/net.h"
#include "syscall/proc.h"   /* syscall_restart_forbid, syscall_is_restarted */
#include "runtime/thread.h" /* thread_stop_is_leader_work_only */
#include "proved/netlink.h"
#include "utils.h"
#include <poll.h>

static void netlink_close(int guest_fd);

/* Linux netlink message structures. These structures are defined manually to
 * match the Linux ABI exactly, since macOS has no <linux/netlink.h>. The two
 * headers the walks step over, nlmsghdr_t and rtattr_t, live in
 * proved/netlink.h with NLMSG_HDRLEN, RTA_HDRLEN and the arithmetic
 * verify-netlink proves against them. The reply builders below round with the
 * same netlink_align_up as the walks, so the two cannot round differently.
 */

/* Netlink message types */
#define NLMSG_DONE 3
#define NLMSG_ERROR 2

/* RTM_* types (from linux/rtnetlink.h) */
#define RTM_GETLINK 18
#define RTM_GETADDR 22
#define RTM_NEWLINK 16
#define RTM_NEWADDR 20

/* NLM_F_* flags. Only NLM_F_MULTI is set on synthesized replies; the dump-style
 * request flags (NLM_F_ROOT|NLM_F_MATCH) are recognized in the request but
 * never echoed back, so they have no constants here.
 */
#define NLM_F_MULTI 0x02

/* Interface info message (struct ifinfomsg) */
typedef struct {
    uint8_t ifi_family, __ifi_pad;
    uint16_t ifi_type;   /* ARPHRD_* */
    int32_t ifi_index;   /* Interface index */
    uint32_t ifi_flags;  /* IFF_* flags */
    uint32_t ifi_change; /* IFF_* change mask */
} ifinfomsg_t;

/* Interface address message (struct ifaddrmsg) */
typedef struct {
    uint8_t ifa_family;    /* Address family */
    uint8_t ifa_prefixlen; /* Prefix length */
    uint8_t ifa_flags;     /* Address flags */
    uint8_t ifa_scope;     /* Address scope */
    uint32_t ifa_index;    /* Interface index */
} ifaddrmsg_t;

/* IFLA_* attribute types */
#define IFLA_IFNAME 3
#define IFLA_MTU 4

/* IFA_* attribute types */
#define IFA_ADDRESS 1
#define IFA_LOCAL 2

/* ARPHRD values */
#define ARPHRD_ETHER 1
#define ARPHRD_LOOPBACK 772

/* sockaddr_nl (Linux netlink socket address) */
typedef struct {
    uint16_t nl_family; /* AF_NETLINK */
    uint16_t nl_pad;
    uint32_t nl_pid;    /* Port ID */
    uint32_t nl_groups; /* Multicast groups mask */
} sockaddr_nl_t;

/* Per-socket state. */

#define MAX_NETLINK_FDS 16
#define NETLINK_BUF_SIZE 8192

/* Ceiling on one staged request. Linux bounds a send by sk_sndbuf and reports
 * EMSGSIZE past it; this is that refusal against a fixed buffer. The largest
 * request nl_process_request() reads is an RTM_GETLINK carrying an IFLA_IFNAME
 * filter, an nlmsghdr and an ifinfomsg and an attribute holding IFNAMSIZ.
 */
#define NETLINK_REQ_MAX 512

typedef struct {
    bool in_use;
    int guest_fd; /* Guest fd number */
    /* Allocation order, unique and increasing. A guest fd number outlives the
     * socket that had it: fd_cleanup_entry() runs netlink_close() after the
     * number is already back in the fd table's free pool, so a socket() on
     * another thread can be handed the same number while the previous slot is
     * still in_use. Two slots can therefore carry one guest_fd, and the
     * generation is what tells them apart -- nl_find() answers with the newest
     * (the only one the guest can still reach) and netlink_close() retires the
     * oldest.
     *
     * That pairing is exact rather than approximate. A number is only reissued
     * after the previous holder's close was issued, so the pending closes for a
     * number are always the oldest slots holding it, whatever order the threads
     * running them arrive in; retiring oldest-first therefore never takes down
     * the live socket, and every slot is retired exactly once.
     */
    uint64_t gen;
    uint8_t buf[NETLINK_BUF_SIZE]; /* Response buffer */
    size_t buf_len;                /* Bytes written into buf */
    size_t buf_pos;                /* Current read position */
    uint32_t seq;                  /* Sequence number from last request */
    uint32_t pid;                  /* Bound PID (from bind or auto-assigned) */
    int pipe_wr;                   /* Host pipe write descriptor */
    int pipe_rd;                   /* Host pipe read descriptor */
    int proto;                     /* NETLINK_ROUTE or NETLINK_KOBJECT_UEVENT */
    int sock_type;                 /* SOCK_RAW or SOCK_DGRAM (SO_TYPE) */
    /* Multicast membership, bit n-1 for group n, exactly nlk->groups. Written
     * by bind()'s nl_groups and by NETLINK_ADD/DROP_MEMBERSHIP, and readable
     * through NETLINK_LIST_MEMBERSHIPS. Nothing is ever delivered on a group:
     * this is the record Linux keeps, without the traffic elfuse has no source
     * for.
     */
    uint32_t groups;
    /* nlk->flags: the SOL_NETLINK booleans, one bit each (NL_F_* below). */
    uint32_t nlk_flags;

    /* Emulated SOL_SOCKET option state. There is no host socket behind a
     * netlink fd, so these are pure per-fd caches for getsockopt round-trips.
     * rcvbuf/sndbuf hold the Linux-doubled value getsockopt reports.
     *
     * Every option sk_setsockopt() accepts is answered by sk_getsockopt(), so
     * storing nothing is not the same as accepting the set: a guest that sets
     * SO_BROADCAST and reads it back gets 1 on Linux and would have got 0 here.
     * Inert options are still remembered for exactly that round trip.
     */
    int opt_passcred;
    int opt_rcvbuf;
    int opt_sndbuf;
    int opt_debug;
    int opt_reuseaddr;
    int opt_dontroute;
    int opt_broadcast;
    int opt_keepalive;
    int opt_oobinline;
    int opt_reuseport;
    int opt_rcvlowat;     /* sk_rcvlowat; 0 means the 1 a fresh socket has */
    int opt_linger_onoff; /* struct linger.l_onoff */
    int opt_linger_secs;  /* struct linger.l_linger, in seconds */
    /* SO_RCVTIMEO/SO_SNDTIMEO as sk_rcvtimeo/sk_sndtimeo hold them: a jiffy
     * count, here with HZ pinned at 1000 so a jiffy is a millisecond. Three
     * states, not two, because sock_set_timeout() has three:
     *
     *   0  -- MAX_SCHEDULE_TIMEOUT, wait forever ({0,0} or an out-of-range
     *         tv_sec)
     *   -1 -- do not wait at all, which is what a negative tv_sec stores
     *         (Linux writes a literal 0 jiffies there, and every wait treats
     *         0 jiffies as "poll once and report EAGAIN")
     *   >0 -- that many milliseconds
     *
     * Both 0 and -1 report {0,0} through getsockopt, exactly as
     * sock_get_timeout() does, so the two are distinguishable only by what a
     * blocking receive does.
     *
     * The receive timeout is honored in nl_wait_readable_locked(). The send one
     * is stored and inert, which is not a shortcut: a uevent send is refused
     * with EPERM before it can queue and an rtnetlink request is answered from
     * the host synchronously, so no send on either protocol has a queue to
     * block on and sk_sndtimeo has nothing to bound. It still has to read back.
     */
    int64_t opt_rcvtimeo_ms;
    int64_t opt_sndtimeo_ms;
} netlink_state_t;

/* Linux net.core.rmem_default/wmem_default on a stock kernel: what
 * getsockopt(SO_RCVBUF/SO_SNDBUF) reports before the guest ever sets one.
 */
#define NETLINK_DEFAULT_BUFSIZE 212992

/* Floors for a doubled SO_RCVBUF/SO_SNDBUF. These are Linux's SOCK_MIN_RCVBUF
 * and SOCK_MIN_SNDBUF exactly (include/net/sock.h): TCP_SKB_MIN_TRUESIZE is
 * 2048 + SKB_DATA_ALIGN(sizeof(struct sk_buff)) = 2304 on arm64, the receive
 * floor is that and the send floor is twice it. The two directions do not share
 * a floor, so a guest asking for a small buffer reads back a different number
 * depending on which one it set.
 */
#define NETLINK_MIN_RCVBUF 2304
#define NETLINK_MIN_SNDBUF 4608

/* net.core.rmem_max/wmem_max: sk_setsockopt() clamps the requested size to the
 * sysctl before doubling it, so an absurd request reads back as 2x this rather
 * than as the request.
 */
#define NETLINK_MAX_BUFSIZE 212992

/* The timeout state above is a jiffy count with HZ pinned at 1000, which makes
 * every one of sock_set_timeout()'s numbers land where Linux puts it:
 *
 *   - the cutoff past which a timeout means "forever" is Linux's own,
 *     MAX_SCHEDULE_TIMEOUT/HZ - 1 with MAX_SCHEDULE_TIMEOUT = LONG_MAX. An
 *     earlier microsecond representation put it three orders of magnitude
 *     lower, so a tv_sec of 1e13 -- which a real kernel stores as a finite
 *     timeout and reads back unchanged -- silently became MAX_SCHEDULE_TIMEOUT
 *     and read back as {0,0}. Measured on Linux 6.x/aarch64: tv_sec 1e13,
 *     1e15, 9007199254740992 all read back exactly; 9223372036854775 reads
 *     back {0,0}, which places the cutoff at LONG_MAX/1000 - 1.
 *   - sub-jiffy tv_usec rounds up to a whole jiffy (DIV_ROUND_UP), so a 1500 us
 *     request reads back as 2000 us here and on a HZ=1000 kernel alike.
 *
 * tv_sec * 1000 + 1000 for any accepted tv_sec stays inside int64, so the
 * conversion itself cannot overflow; nl_deadline_add() covers the one place
 * that can, adding this to a clock reading.
 */
#define NETLINK_TIMEO_HZ 1000
#define NETLINK_TIMEO_MAX_SEC (INT64_MAX / NETLINK_TIMEO_HZ - 1)

/* Multicast groups a netlink socket can join, i.e. nlk->ngroups.
 * netlink_kernel_create() floors a family's group count at 32, so
 * NETLINK_KOBJECT_UEVENT -- which registers exactly one group -- still answers
 * NETLINK_ADD_MEMBERSHIP for groups 1..32 and EINVAL past that. Measured: 32
 * joins, 33 is EINVAL, and NETLINK_LIST_MEMBERSHIPS reports a 4-byte bitmap.
 * rtnetlink registers RTNLGRP_MAX, a handful above 32 and moving between
 * releases, so its groups above 32 are the one place this count is short;
 * nothing in scope joins one, and no group delivers anything here regardless.
 */
#define NETLINK_NGROUPS 32

/* The group bitmap as a mask, bit n-1 for group n. The count is a compile-time
 * constant, so the two cases are split by the preprocessor: written as a
 * ternary, the dead arm still shifts a 32-bit value by 32, which is undefined
 * behavior whether or not it can execute.
 */
#if NETLINK_NGROUPS >= 32
#define NL_GROUP_MASK UINT32_MAX
#else
#define NL_GROUP_MASK ((uint32_t) ((1u << NETLINK_NGROUPS) - 1))
#endif

static inline uint32_t nl_group_mask(void)
{
    return NL_GROUP_MASK;
}

/* nlk->flags bits, in Linux's own order (NETLINK_F_*). */
#define NL_F_RECV_PKTINFO 0x01
#define NL_F_BROADCAST_SEND_ERROR 0x02
#define NL_F_RECV_NO_ENOBUFS 0x04
#define NL_F_LISTEN_ALL_NSID 0x08
#define NL_F_CAP_ACK 0x10
#define NL_F_EXT_ACK 0x20
#define NL_F_STRICT_CHK 0x40

static netlink_state_t nl_state[MAX_NETLINK_FDS];
static pthread_mutex_t nl_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t nl_gen_next = 1;

#define NL_FOR_EACH(s) \
    for (netlink_state_t *s = nl_state; s < nl_state + MAX_NETLINK_FDS; s++)

/* Helpers. */

/* Both helpers walk nl_state and must be called with nl_lock held: the table is
 * shared by every guest thread, and a socket() racing another socket() would
 * otherwise scan for a free slot, find the same one, and hand two callers the
 * same state. The live socket behind a guest fd: the newest slot holding that
 * number. An older one, if any, is a socket the guest has already closed and
 * whose teardown has not run yet -- see the generation comment above.
 */
static netlink_state_t *nl_find(int guest_fd)
{
    netlink_state_t *best = NULL;
    NL_FOR_EACH (s)
        if (s->in_use && s->guest_fd == guest_fd &&
            (!best || s->gen > best->gen))
            best = s;
    return best;
}

/* The counterpart for teardown: the oldest slot holding the number. */
static netlink_state_t *nl_find_oldest(int guest_fd)
{
    netlink_state_t *best = NULL;
    NL_FOR_EACH (s)
        if (s->in_use && s->guest_fd == guest_fd &&
            (!best || s->gen < best->gen))
            best = s;
    return best;
}

/* Claim a slot and publish it fully initialized. proto and sock_type are set
 * here rather than by the caller because they are behavior discriminators --
 * proto picks between the rtnetlink emulation and the silent uevent socket --
 * and a slot visible with in_use set but proto not yet written is a slot a
 * concurrent send can read as NETLINK_ROUTE on a uevent fd.
 */
static netlink_state_t *nl_alloc(int guest_fd,
                                 int protocol,
                                 int sock_type,
                                 int pipe_rd,
                                 int pipe_wr)
{
    NL_FOR_EACH (s) {
        if (s->in_use)
            continue;
        memset(s, 0, sizeof(*s));
        s->guest_fd = guest_fd;
        s->pipe_wr = pipe_wr;
        s->pipe_rd = pipe_rd;
        s->proto = protocol;
        s->sock_type = sock_type;
        s->pid = (uint32_t) getpid();
        s->gen = nl_gen_next++;

        /* Last, and after every field the finder reads: in_use is what makes
         * this slot visible to nl_find.
         */
        s->in_use = true;
        return s;
    }
    return NULL;
}

static void netlink_signal_readable(netlink_state_t *ns)
{
    if (ns->pipe_wr != -1) {
        uint8_t dummy = 1;
        (void) write(ns->pipe_wr, &dummy, 1);
    }
}

static void netlink_clear_readable(netlink_state_t *ns)
{
    int host_fd = ns->pipe_rd;
    if (host_fd < 0)
        return;

    uint8_t dummy[128];
    while (read(host_fd, dummy, sizeof(dummy)) > 0) {
        /* Drain non-blocking pipe */
    }
}

/* Append a netlink attribute to the buffer.
 *
 * Returns bytes written. The payload precondition is memcpy's own predicate
 * from Frama-C's string.h, not a hand-written \valid_read. datalen may be 0,
 * and an empty \valid_read range says nothing at all about the pointer, while
 * memcpy still demands \object_pointer on it. Restating the predicate is what
 * keeps the two in step.
 */
/*@
  requires \valid(buf + (0 .. max - 1));
  requires valid_read_or_empty(data, datalen);
  requires \separated(buf + (0 .. max - 1), (char *) data + (0 .. datalen - 1));
  assigns buf[0 .. max - 1];
  ensures \result <= max;
 */
static size_t nl_put_attr(uint8_t *buf,
                          size_t max,
                          uint16_t type,
                          const void *data,
                          uint16_t datalen)
{
    /* Proved in src/proved/netlink.h: on success total is RTA_HDRLEN + datalen
     * and fits the 16-bit wire field, and aligned is at most max. The cast to
     * rta_len is therefore lossless and both writes below land inside max.
     */
    uint64_t total, aligned;
    if (!netlink_attr_extent(datalen, max, &total, &aligned))
        return 0;
    rtattr_t rta = {.rta_len = (uint16_t) total, .rta_type = type};
    memcpy(buf, &rta, sizeof(rta));
    memcpy(buf + RTA_HDRLEN, data, datalen);
    /* Zero padding */
    if (aligned > total)
        memset(buf + total, 0, (size_t) (aligned - total));
    return (size_t) aligned;
}

/* Backfill the nlmsghdr a dump builder reserved at msg_start, now that the
 * message length is known. Every RTM_* dump frames its messages the same way,
 * so the shape is stated here rather than once per builder.
 */
static void nl_finish_msg(const netlink_state_t *ns,
                          uint8_t *buf,
                          size_t msg_start,
                          size_t off,
                          uint16_t type)
{
    nlmsghdr_t hdr = {
        .nlmsg_len = (uint32_t) (off - msg_start),
        .nlmsg_type = type,
        .nlmsg_flags = NLM_F_MULTI,
        .nlmsg_seq = ns->seq,
        .nlmsg_pid = ns->pid,
    };
    memcpy(buf + msg_start, &hdr, sizeof(hdr));
}

/* Terminate a dump with NLMSG_DONE.
 *
 * Returns the new offset, unchanged when the terminator does not fit, which is
 * what the callers already did.
 */
static size_t nl_append_done(const netlink_state_t *ns,
                             uint8_t *buf,
                             size_t off,
                             size_t max)
{
    if (off + NLMSG_HDRLEN > max)
        return off;

    /* The terminator is a bare header, so its own span is its whole length:
     * proved/netlink.h asserts NLMSG_HDRLEN equals sizeof(nlmsghdr_t).
     */
    nl_finish_msg(ns, buf, off, off + NLMSG_HDRLEN, NLMSG_DONE);
    return off + NLMSG_HDRLEN;
}

/* Build RTM_GETLINK response from host getifaddrs(). A non-empty name_filter or
 * non-zero index_filter restricts the reply to one matching link.
 */
static int nl_build_getlink(netlink_state_t *ns,
                            const char *name_filter,
                            uint32_t index_filter)
{
    struct ifaddrs *ifalist, *ifa;
    if (getifaddrs(&ifalist) < 0)
        return -1;

    uint8_t *buf = ns->buf;
    size_t off = 0, max = NETLINK_BUF_SIZE;

    /* Track which interfaces netlink emulation has already emitted (by index).
     * getifaddrs returns one entry per address, but RTM_GETLINK wants one
     * message per interface.
     */
    uint32_t seen[64];
    int nseen = 0;

    for (ifa = ifalist; ifa; ifa = ifa->ifa_next) {
        unsigned int idx = if_nametoindex(ifa->ifa_name);
        if (idx == 0)
            continue;

        if (name_filter[0] && strcmp(ifa->ifa_name, name_filter) != 0)
            continue;
        if (index_filter != 0 && idx != index_filter)
            continue;

        /* Check if already seen */
        bool found = false;
        for (int i = 0; i < nseen; i++) {
            if (seen[i] == idx) {
                found = true;
                break;
            }
        }
        if (found)
            continue;
        if (nseen < 64)
            seen[nseen++] = idx;

        /* Build message: nlmsghdr + ifinfomsg + attributes. Check minimum space
         * before advancing off.
         */
        size_t min_msg = NLMSG_HDRLEN + netlink_align_up(sizeof(ifinfomsg_t));
        if (off + min_msg > max)
            break;
        size_t msg_start = off;
        off += NLMSG_HDRLEN;

        ifinfomsg_t ifi = {0};
        ifi.ifi_family = 0; /* AF_UNSPEC */
        ifi.ifi_type =
            (!strcmp(ifa->ifa_name, "lo0")) ? ARPHRD_LOOPBACK : ARPHRD_ETHER;
        ifi.ifi_index = (int32_t) idx;
        ifi.ifi_flags = ifa->ifa_flags;
        memcpy(buf + off, &ifi, sizeof(ifi));
        off += netlink_align_up(sizeof(ifi));

        /* IFLA_IFNAME */
        size_t namelen = strlen(ifa->ifa_name) + 1;
        size_t n = nl_put_attr(buf + off, max - off, IFLA_IFNAME, ifa->ifa_name,
                               (uint16_t) namelen);
        off += n;

        /* IFLA_MTU: use a reasonable default */
        uint32_t mtu = (ifi.ifi_type == ARPHRD_LOOPBACK) ? 65536 : 1500;
        n = nl_put_attr(buf + off, max - off, IFLA_MTU, &mtu, 4);
        off += n;

        nl_finish_msg(ns, buf, msg_start, off, RTM_NEWLINK);
    }

    freeifaddrs(ifalist);

    off = nl_append_done(ns, buf, off, max);

    ns->buf_len = off;
    ns->buf_pos = 0;
    return 0;
}

/* Build RTM_GETADDR response from host getifaddrs(). */
static int nl_build_getaddr(netlink_state_t *ns)
{
    struct ifaddrs *ifalist, *ifa;
    if (getifaddrs(&ifalist) < 0)
        return -1;

    uint8_t *buf = ns->buf;
    size_t off = 0, max = NETLINK_BUF_SIZE;

    for (ifa = ifalist; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;

        int family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6)
            continue;

        unsigned int idx = if_nametoindex(ifa->ifa_name);
        if (idx == 0)
            continue;

        size_t min_msg = NLMSG_HDRLEN + netlink_align_up(sizeof(ifaddrmsg_t));
        if (off + min_msg > max)
            break;
        size_t msg_start = off;
        off += NLMSG_HDRLEN;

        /* Compute prefix length from netmask */
        uint8_t prefixlen = 0;
        if (ifa->ifa_netmask) {
            if (family == AF_INET) {
                uint32_t mask = ntohl(
                    ((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr.s_addr);
                while (mask & 0x80000000U) {
                    prefixlen++;
                    mask <<= 1;
                }
            } else {
                struct in6_addr *m =
                    &((struct sockaddr_in6 *) ifa->ifa_netmask)->sin6_addr;
                for (int i = 0; i < 16; i++) {
                    uint8_t byte = m->s6_addr[i];
                    while (byte & 0x80) {
                        prefixlen++;
                        byte <<= 1;
                    }
                    if (byte != 0)
                        break;
                }
            }
        }

        int linux_family = (family == AF_INET) ? LINUX_AF_INET : LINUX_AF_INET6;

        ifaddrmsg_t iam = {0};
        iam.ifa_family = (uint8_t) linux_family;
        iam.ifa_prefixlen = prefixlen;
        iam.ifa_scope = 0; /* RT_SCOPE_UNIVERSE */
        iam.ifa_index = (uint32_t) idx;
        memcpy(buf + off, &iam, sizeof(iam));
        off += netlink_align_up(sizeof(iam));

        /* IFA_ADDRESS attribute */
        if (family == AF_INET) {
            struct in_addr *addr =
                &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
            off += nl_put_attr(buf + off, max - off, IFA_ADDRESS, addr, 4);
            /* IFA_LOCAL (same for point-to-point) */
            off += nl_put_attr(buf + off, max - off, IFA_LOCAL, addr, 4);
        } else {
            struct in6_addr *addr =
                &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;
            off += nl_put_attr(buf + off, max - off, IFA_ADDRESS, addr, 16);
        }

        nl_finish_msg(ns, buf, msg_start, off, RTM_NEWADDR);
    }

    freeifaddrs(ifalist);

    off = nl_append_done(ns, buf, off, max);

    ns->buf_len = off;
    ns->buf_pos = 0;
    return 0;
}

/* Public API. */

void netlink_init(void)
{
    memset(nl_state, 0, sizeof(nl_state));
    fd_register_cleanup(FD_NETLINK, netlink_close);
}

int64_t netlink_socket(int protocol, int type)
{
    /* Validate type before protocol, the order Linux validates them in.
     *
     * __sock_create() rejects a flag bit outside SOCK_NONBLOCK|SOCK_CLOEXEC
     * with EINVAL before any family is consulted, then netlink_create() rejects
     * a base type other than SOCK_RAW or SOCK_DGRAM with ESOCKTNOSUPPORT before
     * it looks at the protocol number. Measured on Linux 6.x/aarch64:
     * SOCK_STREAM, SOCK_SEQPACKET and type 0 all report ESOCKTNOSUPPORT(94) on
     * both NETLINK_ROUTE and NETLINK_KOBJECT_UEVENT; SOCK_RAW|0x40000000 and
     * SOCK_DGRAM|0x80 report EINVAL(22); and socket(AF_NETLINK, SOCK_STREAM,
     * 99) reports ESOCKTNOSUPPORT rather than an unknown-family error, which is
     * what pins the order. Accepting SOCK_STREAM here handed a guest a socket
     * whose SO_TYPE it could read back but no kernel would have created.
     */
    if (type &
        ~(LINUX_SOCK_TYPE_MASK | LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC))
        return -LINUX_EINVAL;
    int base_type = type & LINUX_SOCK_TYPE_MASK;
    if (base_type != LINUX_SOCK_RAW && base_type != LINUX_SOCK_DGRAM)
        return -LINUX_ESOCKTNOSUPPORT;

    /* NETLINK_ROUTE gets the rtnetlink dump emulation; NETLINK_KOBJECT_UEVENT
     * gets a silent socket (see the file header). Everything else is refused
     * the way a Linux kernel without that netlink family would refuse it.
     */
    if (protocol != NETLINK_ROUTE && protocol != NETLINK_KOBJECT_UEVENT)
        return -LINUX_EAFNOSUPPORT;

    /* Allocate a pipe fd pair: the read end serves as the "socket" that
     * poll/epoll can wait on. Netlink emulation writes to the write end when
     * response data is buffered.
     */
    int pipefd[2];
    if (pipe(pipefd) < 0)
        return -LINUX_EMFILE;

    if (fd_set_nonblock(pipefd[0]) < 0 || fd_set_nonblock(pipefd[1]) < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -LINUX_EMFILE;
    }

    int gfd = fd_alloc(FD_NETLINK, pipefd[0], netlink_close);
    if (gfd < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -LINUX_EMFILE;
    }

    /* The scan and every field write happen under nl_lock, not just the scan:
     * two guest threads opening netlink sockets at the same instant otherwise
     * both see the same slot free, and the loser's proto/pipe writes land on
     * top of the winner's -- cross-wiring a uevent fd onto rtnetlink state and
     * leaking one of the two pipe pairs. nl_lock is a leaf, so it is dropped
     * again before fd_publish_linux_flags takes fd_lock.
     */
    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns =
        nl_alloc(gfd, protocol, base_type, pipefd[0], pipefd[1]);
    pthread_mutex_unlock(&nl_lock);
    if (!ns) {
        fd_retire_published(gfd, pipefd[0]);
        close(pipefd[1]);
        return -LINUX_ENOMEM;
    }

    /* Linux opens a netlink socket O_RDWR; carry SOCK_NONBLOCK into linux_flags
     * so a non-blocking receive on an empty socket reports EAGAIN instead of
     * parking the caller. libusb's uevent monitor opens with
     * SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC and relies on exactly that.
     */
    fd_publish_linux_flags(
        gfd, LINUX_O_RDWR |
                 ((type & LINUX_SOCK_NONBLOCK) ? LINUX_O_NONBLOCK : 0) |
                 ((type & LINUX_SOCK_CLOEXEC) ? LINUX_O_CLOEXEC : 0));

    return gfd;
}

int64_t netlink_bind(int guest_fd,
                     guest_t *g,
                     uint64_t addr_gva,
                     uint32_t addrlen)
{
    /* Read the address first, then take nl_lock over the lookup and the writes
     * together: a close() racing this bind cannot then free the slot between
     * them and leave the pid on a socket that has since been reused. Reading
     * outside the lock also keeps the guest-memory walk off it, which costs
     * nothing here because the value read is not part of the lookup.
     */
    sockaddr_nl_t snl;
    bool have_addr = addr_gva && addrlen >= sizeof(sockaddr_nl_t) &&
                     guest_read_small(g, addr_gva, &snl, sizeof(snl)) == 0;

    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EBADF;
    }

    if (have_addr) {
        if (snl.nl_pid != 0)
            ns->pid = snl.nl_pid;

        /* netlink_bind() masks the requested groups against nlk->ngroups and
         * records the rest; the subscription is real bookkeeping even where no
         * traffic follows, and NETLINK_LIST_MEMBERSHIPS reads it back.
         */
        ns->groups |= snl.nl_groups & nl_group_mask();
    }

    pthread_mutex_unlock(&nl_lock);
    return 0;
}

/* struct linger and the two timeval spellings as the guest ABI lays them out.
 * SO_LINGER carries two ints; SO_RCVTIMEO/SO_SNDTIMEO carry a
 * __kernel_old_timeval (the _OLD names) or a __kernel_sock_timeval (the _NEW
 * ones), which on LP64 are the same two 64-bit fields.
 */
#define NETLINK_LINGER_LEN 8
#define NETLINK_TIMEVAL_LEN 16

typedef struct {
    int64_t tv_sec;
    int64_t tv_usec;
} nl_timeval_t;

/* Clamp, double and floor a requested SO_RCVBUF/SO_SNDBUF the way
 * sk_setsockopt() does, so a getsockopt round-trip reports what a Linux kernel
 * would. The order is load-bearing in both places: the sysctl clamp comes
 * first, the doubling second, the floor last.
 *
 * The clamp is unsigned (min_t(u32, val, rmem_max)) and that is not an accident
 * either -- a negative request becomes a huge u32 and clamps to the sysctl, so
 * SO_RCVBUF = -1 reads back 425984 rather than the floor.
 */
static int nl_bufsize_store(int value, int floor)
{
    uint32_t clamped = (uint32_t) value;
    if (clamped > NETLINK_MAX_BUFSIZE)
        clamped = NETLINK_MAX_BUFSIZE;
    int doubled = (int) (clamped * 2);
    return (doubled < floor) ? floor : doubled;
}

/* sock_set_timeout(): read a timeval option and store it as a jiffy count.
 *
 * The three states are Linux's three, and the order of the checks is Linux's
 * order. tv_usec outside [0, 1e6) is EDOM first, before tv_sec is looked at at
 * all -- measured: {-1, 500000} is accepted and {-1, -1} is EDOM(33). A
 * negative tv_sec is then not an error but a third answer: Linux writes a
 * literal 0 jiffies, which every wait reads as "do not wait", and getsockopt
 * still reports {0,0}. Storing 0 for it, as an earlier version did, said
 * "forever" instead -- the exact opposite -- and parked a guest that had asked
 * not to be parked. Measured: after SO_RCVTIMEO {-1, 0} a blocking recv on an
 * empty socket returns EAGAIN in 0 ms, while after {0, 0} it blocks until
 * interrupted.
 *
 * An out-of-range tv_sec is MAX_SCHEDULE_TIMEOUT, i.e. forever, and so is
 * {0,0}; both are 0 here.
 */
static int64_t nl_timeout_store(guest_t *g,
                                uint64_t optval_gva,
                                uint32_t optlen,
                                int64_t *out_ms)
{
    if (optlen < NETLINK_TIMEVAL_LEN)
        return -LINUX_EINVAL;

    nl_timeval_t tv;
    if (guest_read_nofault(g, optval_gva, &tv, sizeof(tv)) < 0)
        return -LINUX_EFAULT;

    if (tv.tv_usec < 0 || tv.tv_usec >= 1000000)
        return -LINUX_EDOM;
    if (tv.tv_sec < 0) {
        *out_ms = -1; /* do not wait */
        return 0;
    }
    if (tv.tv_sec >= NETLINK_TIMEO_MAX_SEC ||
        (tv.tv_sec == 0 && tv.tv_usec == 0)) {
        *out_ms = 0; /* MAX_SCHEDULE_TIMEOUT */
        return 0;
    }

    /* tv_sec * HZ + DIV_ROUND_UP(tv_usec, USEC_PER_SEC / HZ): a sub-jiffy
     * remainder rounds up, so a timeout is never shorter than asked for.
     */
    *out_ms = tv.tv_sec * NETLINK_TIMEO_HZ +
              (tv.tv_usec + (1000000 / NETLINK_TIMEO_HZ) - 1) /
                  (1000000 / NETLINK_TIMEO_HZ);
    return 0;
}

/* sock_get_timeout(): a jiffy count back to a timeval. Both "forever" and "do
 * not wait" report {0,0}, which is what makes them indistinguishable to a
 * getsockopt and distinguishable only to a receive.
 */
static void nl_timeout_load(int64_t ms, nl_timeval_t *tv)
{
    if (ms <= 0) {
        tv->tv_sec = 0;
        tv->tv_usec = 0;
        return;
    }
    tv->tv_sec = ms / NETLINK_TIMEO_HZ;
    tv->tv_usec = (ms % NETLINK_TIMEO_HZ) * (1000000 / NETLINK_TIMEO_HZ);
}

/* Minimum optlen for an option whose payload is not an int, checked after
 * sk_setsockopt()'s generic four-byte gate the way Linux checks it: per option,
 * and only a minimum, since an over-long optlen is accepted everywhere.
 */
static uint32_t nl_optlen_min(int optname)
{
    switch (optname) {
    case LINUX_SO_LINGER:
        return NETLINK_LINGER_LEN;
    case LINUX_SO_RCVTIMEO:
    case LINUX_SO_SNDTIMEO:
    case LINUX_SO_RCVTIMEO_NEW:
    case LINUX_SO_SNDTIMEO_NEW:
        return NETLINK_TIMEVAL_LEN;
    default:
        return sizeof(int32_t);
    }
}

/* The SOL_NETLINK optname to nlk->flags bit map, or 0 for an optname that is
 * not one of the flag booleans. Shared by the two halves so a flag that can be
 * set is a flag that can be read, which is the property netlink_getsockopt()
 * has and the earlier blanket ENOPROTOOPT did not.
 */
static uint32_t nl_flag_bit(int optname)
{
    switch (optname) {
    case LINUX_NETLINK_PKTINFO:
        return NL_F_RECV_PKTINFO;
    case LINUX_NETLINK_BROADCAST_ERROR:
        return NL_F_BROADCAST_SEND_ERROR;
    case LINUX_NETLINK_NO_ENOBUFS:
        return NL_F_RECV_NO_ENOBUFS;
    case LINUX_NETLINK_LISTEN_ALL_NSID:
        return NL_F_LISTEN_ALL_NSID;
    case LINUX_NETLINK_CAP_ACK:
        return NL_F_CAP_ACK;
    case LINUX_NETLINK_EXT_ACK:
        return NL_F_EXT_ACK;
    case LINUX_NETLINK_GET_STRICT_CHK:
        return NL_F_STRICT_CHK;
    default:
        return 0;
    }
}

/* setsockopt(SOL_NETLINK, ...).
 *
 * Under the same contract bind() already gives: the membership and the flags
 * are recorded, and nothing is ever delivered on them. That is the honest
 * answer for a libnl or libmnl monitor, which sets NETLINK_EXT_ACK,
 * NETLINK_CAP_ACK and NETLINK_NO_ENOBUFS on the way up and treats a refusal as
 * a broken socket, and it is what a real kernel answers -- measured on Linux
 * 6.x/aarch64 for both NETLINK_ROUTE and NETLINK_KOBJECT_UEVENT:
 *
 *   ADD_MEMBERSHIP/DROP_MEMBERSHIP  set 0, get ENOPROTOOPT
 *   PKTINFO/BROADCAST_ERROR/NO_ENOBUFS/CAP_ACK/EXT_ACK/GET_STRICT_CHK
 *                                   set 0, get the flag back
 *   LISTEN_ALL_NSID                 set EPERM without CAP_NET_ADMIN, get 0
 *   LIST_MEMBERSHIPS                set ENOPROTOOPT, get the bitmap
 *   RX_RING/TX_RING, unknown        ENOPROTOOPT both ways
 *
 * PKTINFO is recorded rather than refused even though no NETLINK_PKTINFO
 * control message is ever produced: refusing it would fail a monitor at setup
 * over ancillary data it does not need, and a recvmsg here reports
 * msg_controllen 0, which is what a kernel with nothing to attach reports too.
 */
static int64_t nl_setsockopt_netlink(guest_t *g,
                                     int guest_fd,
                                     int optname,
                                     uint64_t optval_gva,
                                     uint32_t optlen)
{
    /* netlink_setsockopt() reads the int only when the buffer holds one, and a
     * shorter optlen is not an error: val simply stays 0. Measured: PKTINFO
     * with optlen 3 returns 0 and clears the flag, while ADD_MEMBERSHIP with
     * optlen 3 returns EINVAL -- from the group check below, not a length one.
     */
    int32_t value = 0;
    if (optlen >= sizeof(value) &&
        guest_read_small(g, optval_gva, &value, sizeof(value)) < 0)
        return -LINUX_EFAULT;

    /* The socket is looked up before the optname is judged, as every other
     * option path here does: a closed fd is EBADF whatever it was asked for.
     */
    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EBADF;
    }

    uint32_t flag = nl_flag_bit(optname);
    int64_t ret = 0;
    if (optname == LINUX_NETLINK_LISTEN_ALL_NSID) {
        /* ns_capable(CAP_NET_ADMIN) over the net namespace, which an elfuse
         * guest has no claim on -- the same stance SO_DEBUG takes.
         */
        ret = -LINUX_EPERM;
    } else if (!flag && optname != LINUX_NETLINK_ADD_MEMBERSHIP &&
               optname != LINUX_NETLINK_DROP_MEMBERSHIP) {
        ret = -LINUX_ENOPROTOOPT;
    } else if (flag) {
        if (value)
            ns->nlk_flags |= flag;
        else
            ns->nlk_flags &= ~flag;
    } else if (value <= 0 || (uint32_t) value > NETLINK_NGROUPS) {
        /* !val || val - 1 >= nlk->ngroups. Group numbering is 1-based, so 0 is
         * out of range at the bottom the way NETLINK_NGROUPS + 1 is at the top.
         */
        ret = -LINUX_EINVAL;
    } else {
        uint32_t bit = 1u << (value - 1);
        if (optname == LINUX_NETLINK_ADD_MEMBERSHIP)
            ns->groups |= bit;
        else
            ns->groups &= ~bit;
    }

    pthread_mutex_unlock(&nl_lock);
    return ret;
}

/* getsockopt(SOL_NETLINK, ...). The order of the checks is netlink_getsockopt's
 * own: the length is read and refused if negative, then the optname is
 * classified (an unknown one is ENOPROTOOPT whatever the length), and only then
 * is a short length refused. Unlike SOL_SOCKET, which truncates to what fits,
 * these options write a whole int or nothing.
 */
static int64_t nl_getsockopt_netlink(guest_t *g,
                                     int guest_fd,
                                     int optname,
                                     uint64_t optval_gva,
                                     uint64_t optlen_gva)
{
    int32_t guest_optlen;
    if (guest_read_small(g, optlen_gva, &guest_optlen, sizeof(guest_optlen)) <
        0)
        return -LINUX_EFAULT;
    if (guest_optlen < 0)
        return -LINUX_EINVAL;

    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EBADF;
    }
    uint32_t flag = nl_flag_bit(optname);
    uint32_t groups = ns->groups;
    int32_t value = flag ? !!(ns->nlk_flags & flag) : 0;
    pthread_mutex_unlock(&nl_lock);

    if (!flag && optname != LINUX_NETLINK_LIST_MEMBERSHIPS)
        return -LINUX_ENOPROTOOPT;

    if (optname == LINUX_NETLINK_LIST_MEMBERSHIPS) {
        /* One u32 per 32 groups, written only while a whole word still fits,
         * and the reported length is the full bitmap size either way --
         * ALIGN(BITS_TO_BYTES(ngroups), 4), which is 4 here. Measured: a uevent
         * socket reports 4, and a short optlen still reports 4 having written
         * nothing.
         */
        if (guest_optlen >= (int32_t) sizeof(groups) &&
            guest_write_small(g, optval_gva, &groups, sizeof(groups)) < 0)
            return -LINUX_EFAULT;
        uint32_t need = sizeof(groups);
        if (guest_write_small(g, optlen_gva, &need, sizeof(need)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    if (guest_optlen < (int32_t) sizeof(value))
        return -LINUX_EINVAL;
    uint32_t written = sizeof(value);
    if (guest_write_small(g, optval_gva, &value, sizeof(value)) < 0 ||
        guest_write_small(g, optlen_gva, &written, sizeof(written)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

int64_t netlink_setsockopt(guest_t *g,
                           int guest_fd,
                           int level,
                           int optname,
                           uint64_t optval_gva,
                           uint32_t optlen)
{
    if (level == LINUX_SOL_NETLINK)
        return nl_setsockopt_netlink(g, guest_fd, optname, optval_gva, optlen);
    if (level != LINUX_SOL_SOCKET)
        return -LINUX_ENOPROTOOPT;

    uint32_t need = nl_optlen_min(optname);
    if (optlen >= sizeof(int32_t))
        (void) guest_lazy_faultin(g, optval_gva, optlen < need ? optlen : need);
    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EBADF;
    }

    /* sk_setsockopt() reads an int before it knows which option it has, so a
     * buffer shorter than that is EINVAL and an unreadable one is EFAULT, for
     * every option alike -- including the three whose real payload is longer.
     * Their own length check comes after, which is why SO_LINGER with optlen =
     * 4 is EINVAL rather than a short read.
     */
    if (optlen < sizeof(int32_t)) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EINVAL;
    }
    int32_t value = 0;
    if (guest_read_nofault(g, optval_gva, &value, sizeof(value)) < 0) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EFAULT;
    }
    if (optlen < nl_optlen_min(optname)) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EINVAL;
    }

    int64_t ret = 0;
    switch (optname) {
    case LINUX_SO_PASSCRED:
        /* sk_may_scm_recv() names AF_NETLINK explicitly, so this is a real
         * option on this family rather than a courtesy.
         */
        ns->opt_passcred = !!value;
        break;
    case LINUX_SO_RCVBUF:
        ns->opt_rcvbuf = nl_bufsize_store(value, NETLINK_MIN_RCVBUF);
        break;
    case LINUX_SO_SNDBUF:
        ns->opt_sndbuf = nl_bufsize_store(value, NETLINK_MIN_SNDBUF);
        break;
    case LINUX_SO_DEBUG:
        /* sk_setsockopt(): switching SO_DEBUG on wants CAP_NET_ADMIN, and an
         * elfuse guest holds no capability over the host's network stack.
         * Switching it off is unprivileged, so only a nonzero value refuses.
         */
        if (value)
            ret = -LINUX_EACCES;
        else
            ns->opt_debug = 0;
        break;
    case LINUX_SO_REUSEPORT:
        /* sk_setsockopt(): SO_REUSEPORT is rejected with EOPNOTSUPP on a socket
         * sk_is_inet() disowns, and AF_NETLINK is one. Clearing it is still
         * allowed, the same asymmetry SO_DEBUG has.
         */
        if (value)
            ret = -LINUX_EOPNOTSUPP;
        else
            ns->opt_reuseport = 0;
        break;
    case LINUX_SO_LINGER: {
        int32_t ling[2] = {0, 0};
        if (guest_read_nofault(g, optval_gva, ling, sizeof(ling)) < 0) {
            ret = -LINUX_EFAULT;
            break;
        }

        /* l_onoff = 0 resets the flag and leaves sk_lingertime alone, so a
         * later getsockopt still reports the seconds set by the last enable.
         */
        ns->opt_linger_onoff = ling[0] ? 1 : 0;
        if (ling[0])
            ns->opt_linger_secs = (ling[1] < 0) ? INT_MAX : ling[1];
        break;
    }
    case LINUX_SO_RCVTIMEO:
    case LINUX_SO_RCVTIMEO_NEW:
        ret = nl_timeout_store(g, optval_gva, optlen, &ns->opt_rcvtimeo_ms);
        break;
    case LINUX_SO_SNDTIMEO:
    case LINUX_SO_SNDTIMEO_NEW:
        ret = nl_timeout_store(g, optval_gva, optlen, &ns->opt_sndtimeo_ms);
        break;
    case LINUX_SO_RCVLOWAT:
        /* sk_setsockopt(): netlink has no set_rcvlowat hook, so sk_rcvlowat
         * takes val ?: 1, and a negative val is INT_MAX first.
         */
        ns->opt_rcvlowat = (value < 0) ? INT_MAX : (value ? value : 1);
        break;
    case LINUX_SO_REUSEADDR:
        ns->opt_reuseaddr = !!value;
        break;
    case LINUX_SO_DONTROUTE:
        ns->opt_dontroute = !!value;
        break;
    case LINUX_SO_BROADCAST:
        ns->opt_broadcast = !!value;
        break;
    case LINUX_SO_KEEPALIVE:
        ns->opt_keepalive = !!value;
        break;
    case LINUX_SO_OOBINLINE:
        ns->opt_oobinline = !!value;
        break;
    default:
        /* sock_setsockopt refuses an optname it does not know; pretending an
         * unknown option took effect would hide real consumer bugs. SO_SNDLOWAT
         * arrives here on purpose: 1003.1g 7 makes it unsettable, sk_setsockopt
         * has no case for it, and Linux answers ENOPROTOOPT.
         */
        ret = -LINUX_ENOPROTOOPT;
        break;
    }

    pthread_mutex_unlock(&nl_lock);
    return ret;
}

int64_t netlink_getsockopt(guest_t *g,
                           int guest_fd,
                           int level,
                           int optname,
                           uint64_t optval_gva,
                           uint64_t optlen_gva)
{
    if (level == LINUX_SOL_NETLINK)
        return nl_getsockopt_netlink(g, guest_fd, optname, optval_gva,
                                     optlen_gva);
    if (level != LINUX_SOL_SOCKET)
        return -LINUX_ENOPROTOOPT;

    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EBADF;
    }

    /* sk_getsockopt()'s union v and its lv: the payload is an int unless the
     * option says otherwise, and lv is what caps the write-back below.
     */
    union {
        int32_t val;
        int32_t ling[2];
        nl_timeval_t tv;
    } v;
    memset(&v, 0, sizeof(v));
    uint32_t lv = sizeof(int32_t);

    switch (optname) {
    case LINUX_SO_PASSCRED:
        v.val = ns->opt_passcred;
        break;
    case LINUX_SO_RCVBUF:
        v.val = ns->opt_rcvbuf ? ns->opt_rcvbuf : NETLINK_DEFAULT_BUFSIZE;
        break;
    case LINUX_SO_SNDBUF:
        v.val = ns->opt_sndbuf ? ns->opt_sndbuf : NETLINK_DEFAULT_BUFSIZE;
        break;
    case LINUX_SO_TYPE:
        v.val = ns->sock_type;
        break;
    case LINUX_SO_PROTOCOL:
        v.val = ns->proto;
        break;
    case LINUX_SO_DOMAIN:
        v.val = LINUX_AF_NETLINK;
        break;
    case LINUX_SO_DEBUG:
        v.val = ns->opt_debug;
        break;
    case LINUX_SO_REUSEADDR:
        v.val = ns->opt_reuseaddr;
        break;
    case LINUX_SO_DONTROUTE:
        v.val = ns->opt_dontroute;
        break;
    case LINUX_SO_BROADCAST:
        v.val = ns->opt_broadcast;
        break;
    case LINUX_SO_KEEPALIVE:
        v.val = ns->opt_keepalive;
        break;
    case LINUX_SO_OOBINLINE:
        v.val = ns->opt_oobinline;
        break;
    case LINUX_SO_REUSEPORT:
        v.val = ns->opt_reuseport;
        break;
    case LINUX_SO_RCVLOWAT:
        /* sk_rcvlowat is 1 on a socket nobody has set it on. */
        v.val = ns->opt_rcvlowat ? ns->opt_rcvlowat : 1;
        break;
    case LINUX_SO_SNDLOWAT:
        /* Unsettable, and sk_getsockopt() answers a constant 1. */
        v.val = 1;
        break;
    case LINUX_SO_LINGER:
        lv = NETLINK_LINGER_LEN;
        v.ling[0] = ns->opt_linger_onoff;
        v.ling[1] = ns->opt_linger_secs;
        break;
    case LINUX_SO_RCVTIMEO:
    case LINUX_SO_RCVTIMEO_NEW:
        lv = NETLINK_TIMEVAL_LEN;
        nl_timeout_load(ns->opt_rcvtimeo_ms, &v.tv);
        break;
    case LINUX_SO_SNDTIMEO:
    case LINUX_SO_SNDTIMEO_NEW:
        lv = NETLINK_TIMEVAL_LEN;
        nl_timeout_load(ns->opt_sndtimeo_ms, &v.tv);
        break;
    case LINUX_SO_ERROR:
    case LINUX_SO_ACCEPTCONN:
        v.val = 0;
        break;
    default:
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_ENOPROTOOPT;
    }
    pthread_mutex_unlock(&nl_lock);

    int32_t guest_optlen;
    if (guest_read_small(g, optlen_gva, &guest_optlen, sizeof(guest_optlen)) <
        0)
        return -LINUX_EFAULT;

    /* sock_getsockopt(): a negative optlen is -EINVAL, never a write. */
    if (guest_optlen < 0)
        return -LINUX_EINVAL;

    uint32_t write_len = lv;
    if (write_len > (uint32_t) guest_optlen)
        write_len = guest_optlen;
    if (write_len > 0 && guest_write_small(g, optval_gva, &v, write_len) < 0)
        return -LINUX_EFAULT;

    /* Linux sock_getsockopt() writes back min(len, lv): a short optlen must not
     * grow to claim bytes that were never written, and a long one shrinks to
     * the option's own size rather than reporting the whole buffer.
     */
    uint32_t actual_len = write_len;
    if (guest_write_small(g, optlen_gva, &actual_len, sizeof(actual_len)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* Extract the LinkByName/LinkByIndex filter (ifi_index plus an optional
 * IFLA_IFNAME) from a RTM_GETLINK request. Empty name / zero index = no filter.
 */
/*@
  requires \valid_read(req + (0 .. reqlen - 1));
  requires \valid(name_out + (0 .. name_cap - 1));
  requires \valid(index_out);
  requires name_cap > 0;
  requires reqlen <= NETLINK_LEN_MAX;
  requires \separated(name_out + (0 .. name_cap - 1),
                      req + (0 .. reqlen - 1),
                      index_out);
  assigns name_out[0 .. name_cap - 1], *index_out;
 */
static void nl_parse_link_filter(const uint8_t *req,
                                 size_t reqlen,
                                 char *name_out,
                                 size_t name_cap,
                                 uint32_t *index_out)
{
    name_out[0] = '\0';
    *index_out = 0;

    if (reqlen < NLMSG_HDRLEN + sizeof(ifinfomsg_t))
        return;

    ifinfomsg_t ifi;
    memcpy(&ifi, req + NLMSG_HDRLEN, sizeof(ifi));
    if (ifi.ifi_index > 0)
        *index_out = (uint32_t) ifi.ifi_index;

    uint32_t nlmsg_len;
    memcpy(&nlmsg_len, req, sizeof(nlmsg_len));
    size_t total = (nlmsg_len < reqlen) ? nlmsg_len : reqlen;

    size_t off = NLMSG_HDRLEN + netlink_align_up(sizeof(ifinfomsg_t));

    /* The invariant bounds off itself, not just off relative to total. Without
     * it the C loop test "off + RTA_HDRLEN <= total" is not known to be free of
     * unsigned wrap, and every goal under the loop inherits that doubt.
     */
    /*@
      loop invariant off <= reqlen + NETLINK_ALIGNTO;
      loop assigns off, name_out[0 .. name_cap - 1];
      loop variant total - off;
     */
    while (off + RTA_HDRLEN <= total) {
        rtattr_t rta;
        memcpy(&rta, req + off, sizeof(rta));

        /* Proved in src/proved/netlink.h: on success the payload at off +
         * RTA_HDRLEN for data_len bytes lies inside total, and next_off is
         * strictly past off.
         */
        uint64_t data_len, next_off;
        if (!netlink_rta_bounds(off, total, rta.rta_len, &data_len, &next_off))
            break;
        if (rta.rta_type == IFLA_IFNAME) {
            size_t dlen = (size_t) data_len;
            size_t i = 0;
            /*@
              loop invariant i < name_cap;
              loop assigns i, name_out[0 .. name_cap - 1];
              loop variant dlen - i;
             */
            for (; i < dlen && i + 1 < name_cap && req[off + RTA_HDRLEN + i];
                 i++)
                name_out[i] = (char) req[off + RTA_HDRLEN + i];
            name_out[i] = '\0';
        }
        off = (size_t) next_off;
    }
}

/* Build the reply for one rtnetlink request (already copied into req). Mutates
 * ns->buf/seq.
 *
 * Returns 0 on success (including a built NLMSG_ERROR reply for unsupported
 * types), or a negative LINUX_E* on a build failure. Caller holds nl_lock. req
 * is guaranteed to be at least NLMSG_HDRLEN bytes.
 */
static int nl_process_request(netlink_state_t *ns,
                              const uint8_t *req,
                              size_t reqlen)
{
    nlmsghdr_t req_hdr;
    memcpy(&req_hdr, req, sizeof(req_hdr));
    ns->seq = req_hdr.nlmsg_seq;

    int ret;
    switch (req_hdr.nlmsg_type) {
    case RTM_GETLINK: {
        char name[64];
        uint32_t index;
        nl_parse_link_filter(req, reqlen, name, sizeof(name), &index);
        ret = nl_build_getlink(ns, name, index);
        break;
    }
    case RTM_GETADDR:
        ret = nl_build_getaddr(ns);
        break;
    default:
        /* Unsupported request: return NLMSG_ERROR with EOPNOTSUPP */
        if (NLMSG_HDRLEN + 4 <= NETLINK_BUF_SIZE) {
            size_t off = 0;
            nlmsghdr_t err_hdr = {
                .nlmsg_len = NLMSG_HDRLEN + 4,
                .nlmsg_type = NLMSG_ERROR,
                .nlmsg_seq = ns->seq,
                .nlmsg_pid = ns->pid,
            };
            memcpy(ns->buf + off, &err_hdr, sizeof(err_hdr));
            off += NLMSG_HDRLEN;
            int32_t errcode = -95; /* -EOPNOTSUPP */
            memcpy(ns->buf + off, &errcode, 4);
            ns->buf_len = off + 4;
            ns->buf_pos = 0;
        }
        return 0;
    }

    return (ret < 0) ? -LINUX_EIO : 0;
}

/* A staged guest iovec vector, on the caller's stack for the common count. */
typedef struct {
    linux_iovec_t stack[SYSCALL_IOV_STACK_MAX];
    linux_iovec_t *iov;
    linux_iovec_t *heap; /* non-NULL only when iov was heap-allocated */
} nl_iov_buf_t;

/* Stage the iovcnt guest iovec entries at iov_gva into buf.
 *
 * Both directions want the entries themselves rather than the resolved host
 * pointers host_iov_prepare() builds, since one netlink request and one
 * response each span the whole vector and are staged through ns->buf.
 *
 * Returns 0, or a negative Linux errno. Pair every return with nl_iov_free().
 * iovcnt is bounded by the caller, whose spelling decides what an empty vector
 * means.
 */
static int64_t nl_iov_stage(guest_t *g,
                            uint64_t iov_gva,
                            int iovcnt,
                            nl_iov_buf_t *buf)
{
    buf->iov = buf->stack;
    buf->heap = NULL;
    if (iovcnt > SYSCALL_IOV_STACK_MAX) {
        buf->heap = malloc((size_t) iovcnt * sizeof(*buf->heap));
        if (!buf->heap)
            return -LINUX_ENOMEM;
        buf->iov = buf->heap;
    }

    uint64_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        uint64_t entry_gva = iov_gva + (uint64_t) i * sizeof(*buf->iov);
        if (guest_read_small(g, entry_gva, &buf->iov[i], sizeof(*buf->iov)) < 0)
            return -LINUX_EFAULT;
        if (!iov_total_add(total, buf->iov[i].iov_len, &total))
            return -LINUX_EINVAL;
    }
    return 0;
}

static void nl_iov_free(nl_iov_buf_t *buf)
{
    free(buf->heap);
    buf->heap = NULL;
}

/* Bound msg_iovlen, which is uint64_t on Linux, before the int narrowing, so a
 * 64-bit value whose low 32 bits fall inside the cap cannot slip past it.
 * sys_sendmsg and sys_recvmsg refuse the same count the same way.
 */
static int64_t nl_msg_iovcnt(const linux_msghdr_t *mhdr, int *iovcnt)
{
    if (mhdr->msg_iovlen > SYSCALL_IOV_MAX)
        return -LINUX_EINVAL;
    *iovcnt = (int) mhdr->msg_iovlen;
    return 0;
}

static void nl_prefault_iov(guest_t *g,
                            const linux_iovec_t *iov,
                            int iovcnt,
                            uint64_t limit)
{
    for (int i = 0; i < iovcnt && limit; i++) {
        uint64_t len = iov[i].iov_len < limit ? iov[i].iov_len : limit;
        if (len)
            (void) guest_lazy_faultin(g, iov[i].iov_base, len);
        limit -= len;
    }
}

/* The send half of sendmsg(2), sendto(2), write(2) and writev(2) on a netlink
 * socket.
 *
 * One request spans the whole iovec, so it is gathered before it is parsed. A
 * gathered length between one byte and one nlmsghdr transfers and does nothing:
 * the loop in netlink_rcv_skb() is entered only from nlmsg_total_size(0) bytes
 * up, and the send reports the byte count rather than an error. Measured
 * against Linux 6.18 under qemu-aarch64.
 */
static int64_t netlink_send_iov(int guest_fd,
                                guest_t *g,
                                const linux_iovec_t *iov,
                                int iovcnt)
{
    nl_prefault_iov(g, iov, iovcnt, NETLINK_REQ_MAX);
    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EBADF;
    }

    int64_t result;

    /* A uevent socket is receive-only here. Linux's uevent_net_rcv() refuses a
     * sender without CAP_SYS_ADMIN with -EPERM, and elfuse guests have no
     * authority to fabricate uevents, so every send is that refusal.
     */
    if (ns->proto == NETLINK_KOBJECT_UEVENT) {
        result = -LINUX_EPERM;
        goto out;
    }

    uint64_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len > UINT64_MAX - total) {
            result = -LINUX_EINVAL;
            goto out;
        }
        total += iov[i].iov_len;
    }

    /* Linux's netlink_sendmsg() refuses an empty message before it builds an
     * skb, which is what a sendmsg or a write of nothing reports. No entries at
     * all sums to nothing too. The writev spelling never arrives here empty:
     * do_readv_writev() returns on a zero total above the socket, and
     * netlink_writev() carries that rule.
     */
    if (total == 0) {
        result = -LINUX_ENODATA;
        goto out;
    }

    /* Ahead of the read, the order netlink_sendmsg() checks its length in: an
     * oversized send is refused whatever its buffers hold.
     */
    if (total > NETLINK_REQ_MAX) {
        result = -LINUX_EMSGSIZE;
        goto out;
    }

    if (total < (uint64_t) NLMSG_HDRLEN) {
        result = (int64_t) total;
        goto out;
    }

    /* Every entry is read, so total is the byte count that was validated and
     * parsed, and an unmapped entry anywhere in the vector is EFAULT rather
     * than a report of bytes nothing looked at. An entry of no length reads
     * nothing and validates nothing, which is what Linux does with it.
     *
     * A total of NLMSG_HDRLEN or more rules out an empty vector, so the loop
     * always runs. req is zeroed anyway: cppcheck reads the loop as skippable
     * and calls the parse below an uninitialized read.
     */
    uint8_t req[NETLINK_REQ_MAX] = {0};
    size_t rlen = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (guest_read_nofault(g, iov[i].iov_base, req + rlen,
                               (size_t) iov[i].iov_len) < 0) {
            result = -LINUX_EFAULT;
            goto out;
        }
        rlen += (size_t) iov[i].iov_len;
    }

    bool was_empty = ns->buf_pos >= ns->buf_len;
    int ret = nl_process_request(ns, req, rlen);
    if (ret == 0) {
        if (was_empty && ns->buf_pos < ns->buf_len)
            netlink_signal_readable(ns);
    }
    result = (ret < 0) ? ret : (int64_t) total;

out:
    pthread_mutex_unlock(&nl_lock);
    return result;
}

int64_t netlink_send(int guest_fd, guest_t *g, uint64_t buf_gva, uint64_t len)
{
    linux_iovec_t one = {.iov_base = buf_gva, .iov_len = len};
    return netlink_send_iov(guest_fd, g, &one, 1);
}

int64_t netlink_writev(int guest_fd, guest_t *g, uint64_t iov_gva, int iovcnt)
{
    if (!iov_count_ok(iovcnt))
        return -LINUX_EINVAL;

    nl_iov_buf_t buf;
    int64_t ret = nl_iov_stage(g, iov_gva, iovcnt, &buf);
    if (ret == 0) {
        uint64_t total = 0;
        for (int i = 0; i < iovcnt; i++)
            total += buf.iov[i].iov_len; /* nl_iov_stage bounds the sum */

        /* A vectored write carrying nothing stops in do_readv_writev() before
         * the socket is reached, so it reports 0 where write(2) of nothing
         * reports ENODATA. Measured against Linux 6.18 under qemu-aarch64.
         */
        ret = total == 0 ? 0 : netlink_send_iov(guest_fd, g, buf.iov, iovcnt);
    }
    nl_iov_free(&buf);
    return ret;
}

int64_t netlink_sendmsg(int guest_fd, guest_t *g, uint64_t msg_gva, int flags)
{
    (void) flags;
    linux_msghdr_t mhdr;
    if (guest_read_small(g, msg_gva, &mhdr, sizeof(mhdr)) < 0)
        return -LINUX_EFAULT;

    int iovcnt;
    int64_t ret = nl_msg_iovcnt(&mhdr, &iovcnt);
    if (ret < 0)
        return ret;

    /* ___sys_sendmsg() carries an empty vector down to the socket rather than
     * answering it, so netlink_send_iov() decides this one too.
     */
    nl_iov_buf_t buf;
    ret = nl_iov_stage(g, mhdr.msg_iov, iovcnt, &buf);
    if (ret == 0)
        ret = netlink_send_iov(guest_fd, g, buf.iov, iovcnt);
    nl_iov_free(&buf);
    return ret;
}

/* Milliseconds on CLOCK_MONOTONIC, for the SO_RCVTIMEO deadline. Milliseconds
 * rather than microseconds because the stored timeout is a jiffy count at
 * HZ=1000 and poll() takes milliseconds, so nothing finer survives either end.
 */
static int64_t nl_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* now + timeout, saturating. The largest timeout sock_set_timeout() accepts is
 * within a rounding error of INT64_MAX milliseconds, so a plain add overflows
 * on any machine whose CLOCK_MONOTONIC has advanced at all -- signed overflow,
 * and in practice a deadline in the past, which turns the longest timeout a
 * guest can ask for into an immediate EAGAIN. Saturating keeps it what it reads
 * as: a deadline 292 million years out, indistinguishable from forever and
 * exactly as Linux's LONG_MAX jiffies is.
 */
static int64_t nl_deadline_add(int64_t now_ms, int64_t timeout_ms)
{
    if (timeout_ms > INT64_MAX - now_ms)
        return INT64_MAX;
    return now_ms + timeout_ms;
}

/* restart_block for a netlink receive: the deadline an interrupted wait had
 * left, carried across the SVC restart the dispatcher may perform.
 *
 * Linux restarts an interrupted recvmsg with the timeout it had *remaining*,
 * not with a fresh copy of SO_RCVTIMEO. elfuse's restart re-executes the SVC,
 * so nl_wait_readable_locked() is re-entered from the top and would compute a
 * new deadline from the option -- handing the guest its whole timeout again,
 * once per restart. Stashing the absolute deadline here and adopting it when
 * syscall_is_restarted() says this call is the re-execution keeps the budget
 * the guest was given.
 *
 * Thread-local, and only read when the restart flag is set, so a stash left
 * behind by a wait whose restart never happened cannot be picked up by an
 * unrelated later receive. The fd is part of the match for the same reason.
 */
static _Thread_local int64_t nl_restart_deadline_ms;
static _Thread_local int nl_restart_fd = -1;

/* Block until the netlink receive buffer has data, for at most SO_RCVTIMEO.
 * Called with nl_lock held.
 *
 * On success returns 0 with nl_lock still held and ns valid. On EAGAIN, EINTR,
 * EIO, or if the socket was closed underneath the poll, releases nl_lock and
 * returns the negative Linux errno.
 */
static int64_t nl_wait_readable_locked(netlink_state_t *ns,
                                       int guest_fd,
                                       bool nonblock)
{
    /* Three states, from sock_rcvtimeo(): a negative stored timeout is Linux's
     * 0 jiffies, which means do not wait at all and is the nonblocking answer
     * even on a socket the guest never marked nonblocking.
     */
    bool no_wait = nonblock || ns->opt_rcvtimeo_ms < 0;

    /* The SO_RCVTIMEO deadline is taken once, here, and not refreshed by the
     * waits below. That is skb_recv_datagram()'s shape: sock_rcvtimeo() is read
     * at the top and every wait inside shares the one budget, so a wakeup that
     * finds nothing does not buy the caller another full timeout. A restarted
     * SVC continues the deadline the interrupted attempt was using, for the
     * same reason at a larger scale.
     */
    int64_t deadline_ms = 0;
    if (!no_wait && ns->opt_rcvtimeo_ms > 0) {
        bool resumed = syscall_is_restarted() && nl_restart_fd == guest_fd &&
                       nl_restart_deadline_ms != 0;
        deadline_ms = resumed
                          ? nl_restart_deadline_ms
                          : nl_deadline_add(nl_now_ms(), ns->opt_rcvtimeo_ms);
    }
    nl_restart_deadline_ms = 0;
    nl_restart_fd = -1;

    while (ns->buf_pos >= ns->buf_len) {
        if (no_wait) {
            pthread_mutex_unlock(&nl_lock);
            return -LINUX_EAGAIN;
        }

        int timeout_ms = -1;
        if (deadline_ms) {
            int64_t left_ms = deadline_ms - nl_now_ms();
            if (left_ms <= 0) {
                /* Expired with the buffer still empty: the same EAGAIN the
                 * nonblocking path reports, and released the same way.
                 */
                pthread_mutex_unlock(&nl_lock);
                return -LINUX_EAGAIN;
            }
            timeout_ms = (left_ms > INT_MAX) ? INT_MAX : (int) left_ms;
        }

        int rd_fd = ns->pipe_rd;
        pthread_mutex_unlock(&nl_lock);

        /* Bounded + interrupt-aware: an untimed poll() here has no re-check
         * point, so a worker parked on an AF_NETLINK socket with no incoming
         * messages is invisible to thread_join_workers' poll cap and touches
         * guest memory on an eventual delayed return, well after guest_destroy
         * may have unmapped it.
         */
        int64_t wait_rc =
            io_wait_fd_timed_or_interrupted(rd_fd, POLLIN, timeout_ms);
        if (wait_rc < 0) {
            /* sock_intr_errno(): an interrupted receive reports ERESTARTSYS
             * when the timeout is MAX_SCHEDULE_TIMEOUT and EINTR when it is
             * finite, precisely so a restart cannot hand the caller its whole
             * SO_RCVTIMEO a second time. Same split -- but only over the half
             * of the EINTR the guest can see.
             *
             * io_wait_fd_timed_or_interrupted() reports EINTR for two unrelated
             * reasons. One is a guest-visible signal, and forbidding the
             * restart there is right. The other is the dispatcher's own execve
             * handoff (io.c: the leader leaves the wait so the run loop can
             * reach the handoff), which is invisible to the guest and which
             * syscall.c only restarts while thread_stop_is_leader_work_only()
             * holds. Forbidding unconditionally turned a sibling's execve into
             * an EINTR on a recvmsg with no signal in sight -- an errno Linux
             * cannot produce there. Gate on the same predicate the dispatcher
             * arms on, so only the guest-visible half forbids.
             *
             * The restarted attempt continues this deadline rather than taking
             * a fresh one, which is what Linux's restart_block carries, so the
             * handoff cannot stretch a finite timeout either.
             */
            if (deadline_ms && wait_rc == -LINUX_EINTR) {
                if (thread_stop_is_leader_work_only()) {
                    nl_restart_deadline_ms = deadline_ms;
                    nl_restart_fd = guest_fd;
                } else {
                    syscall_restart_forbid();
                }
            }
            return wait_rc;
        }

        pthread_mutex_lock(&nl_lock);
        netlink_state_t *current_ns = nl_find(guest_fd);
        if (!current_ns || current_ns != ns) {
            pthread_mutex_unlock(&nl_lock);
            return -LINUX_EBADF;
        }

        /* wait_rc == 1 is the timeout slice expiring. Fall through to the loop
         * condition rather than reporting here, so a message that landed in the
         * same instant still wins the race the way a real receive does.
         */
    }
    return 0;
}

/* Return the byte length of the longest run of complete netlink messages that
 * starts at ns->buf_pos and fits within to_copy. Falls back to to_copy when not
 * even one whole message fits (MSG_TRUNC semantics). Called with nl_lock held.
 */
/*@
  requires \valid_read(ns);
  requires ns->buf_pos <= ns->buf_len;
  requires ns->buf_len <= NETLINK_BUF_SIZE;
  requires to_copy <= ns->buf_len - ns->buf_pos;
  assigns \nothing;
  ensures \result <= to_copy;
 */
static size_t nl_complete_span(const netlink_state_t *ns, size_t to_copy)
{
    size_t msg_end = 0, pos = ns->buf_pos;
    /*@
      loop invariant ns->buf_pos <= pos <= ns->buf_len;
      loop invariant msg_end <= to_copy;
      loop assigns pos, msg_end;
      loop variant ns->buf_len - pos;
     */
    while (pos < ns->buf_len && (pos - ns->buf_pos + NLMSG_HDRLEN) <= to_copy) {
        /* memcpy rather than a cast: pos is not guaranteed to sit on a message
         * boundary (see the header), so ns->buf + pos need not be suitably
         * aligned for nlmsghdr_t.
         */
        nlmsghdr_t hdr;
        memcpy(&hdr, ns->buf + pos, sizeof(hdr));

        /* Proved in src/proved/netlink.h: on success span is strictly positive,
         * so this loop advances for any header at all. Before the widening this
         * loop could spin forever on a guest-chosen length; see the header.
         */
        uint64_t span;
        if (!netlink_msg_span(hdr.nlmsg_len, &span))
            break;
        size_t msg_bytes = pos - ns->buf_pos + (size_t) span;
        if (msg_bytes > to_copy)
            break;
        pos += (size_t) span;
        msg_end = pos - ns->buf_pos;
    }
    return msg_end == 0 ? to_copy : msg_end;
}

/* Write the kernel-side sockaddr_nl (nl_pid 0) and its length to the guest at
 * the given addresses. Called with nl_lock held.
 */
static void nl_write_kernel_src(guest_t *g,
                                uint64_t addr_gva,
                                uint64_t namelen_gva)
{
    sockaddr_nl_t snl = {
        .nl_family = LINUX_AF_NETLINK,
        .nl_pid = 0, /* from kernel */
    };
    guest_write_small(g, addr_gva, &snl, sizeof(snl));
    uint32_t namelen = sizeof(sockaddr_nl_t);
    guest_write_small(g, namelen_gva, &namelen, sizeof(namelen));
}

/* The receive half of recvmsg(2), recvfrom(2), read(2) and readv(2) on a
 * netlink socket: drain whole messages, filling every entry in turn.
 *
 * One response spans the whole iovec, so a first entry too small for it does
 * not cap the transfer. nl_complete_span() bounds every spelling alike, so none
 * of them hands out a message split across two calls.
 *
 * Returns the byte count, or a negative Linux errno. Takes nl_lock and releases
 * it before returning. nonblock is sampled before nl_lock so this leaf lock
 * does not nest fd_lock.
 */
static int64_t netlink_recv_iov(int guest_fd,
                                guest_t *g,
                                const linux_iovec_t *iov,
                                int iovcnt,
                                int flags)
{
    bool nonblock = (flags & LINUX_MSG_DONTWAIT) || fd_guest_nonblock(guest_fd);
    nl_prefault_iov(g, iov, iovcnt, NETLINK_BUF_SIZE);
    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EBADF;
    }

    uint64_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len > UINT64_MAX - total) {
            pthread_mutex_unlock(&nl_lock);
            return -LINUX_EINVAL;
        }
        total += iov[i].iov_len;
    }

    if (total == 0) {
        pthread_mutex_unlock(&nl_lock);
        return 0;
    }

    int64_t werr = nl_wait_readable_locked(ns, guest_fd, nonblock);
    if (werr < 0)
        return werr;

    size_t avail = ns->buf_len - ns->buf_pos;
    size_t to_copy = (avail < total) ? avail : (size_t) total;
    size_t msg_end = nl_complete_span(ns, to_copy);

    size_t done = 0;
    for (int i = 0; i < iovcnt && done < msg_end; i++) {
        size_t remain = msg_end - done;
        size_t chunk =
            (iov[i].iov_len < remain) ? (size_t) iov[i].iov_len : remain;
        if (chunk == 0)
            continue;

        /* The count is what landed, not whole entries: guest memory is copied
         * chunk by chunk and a chunk that faults still places the bytes ahead
         * of it, which is what copy_to_iter() counts.
         */
        size_t moved = guest_write_partial_nofault(
            g, iov[i].iov_base, ns->buf + ns->buf_pos, chunk);
        ns->buf_pos += moved;
        done += moved;
        if (moved < chunk) {
            pthread_mutex_unlock(&nl_lock);

            /* Bytes already placed are transferred; reporting EFAULT over them
             * would lose them, since buf_pos has moved past.
             */
            return done ? (int64_t) done : -LINUX_EFAULT;
        }
    }

    if (ns->buf_pos >= ns->buf_len)
        netlink_clear_readable(ns);

    pthread_mutex_unlock(&nl_lock);
    return (int64_t) done;
}

/* recvfrom(2) on a netlink socket: write back a kernel sockaddr_nl (nl_pid 0)
 * when src is requested.
 */
int64_t netlink_recv(int guest_fd,
                     guest_t *g,
                     uint64_t buf_gva,
                     uint64_t len,
                     int flags,
                     uint64_t src_gva,
                     uint64_t addrlen_gva)
{
    linux_iovec_t one = {.iov_base = buf_gva, .iov_len = len};
    int64_t ret = netlink_recv_iov(guest_fd, g, &one, 1, flags);
    if (ret >= 0 && src_gva && addrlen_gva)
        nl_write_kernel_src(g, src_gva, addrlen_gva);
    return ret;
}

/* getsockname(2) on a netlink socket: returns the bound/auto-assigned pid. */
int64_t netlink_getsockname(int guest_fd,
                            guest_t *g,
                            uint64_t addr_gva,
                            uint64_t addrlen_gva)
{
    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return -LINUX_EBADF;
    }
    uint32_t pid = ns->pid;
    pthread_mutex_unlock(&nl_lock);

    uint32_t cap = 0;
    if (guest_read_small(g, addrlen_gva, &cap, sizeof(cap)) < 0)
        return -LINUX_EFAULT;

    sockaddr_nl_t snl = {
        .nl_family = LINUX_AF_NETLINK,
        .nl_pid = pid,
    };
    size_t n = (cap < sizeof(snl)) ? cap : sizeof(snl);
    if (n > 0 && guest_write(g, addr_gva, &snl, n) < 0)
        return -LINUX_EFAULT;

    uint32_t actual = sizeof(snl);
    if (guest_write_small(g, addrlen_gva, &actual, sizeof(actual)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

int64_t netlink_recvmsg(int guest_fd, guest_t *g, uint64_t msg_gva, int flags)
{
    linux_msghdr_t mhdr;
    if (guest_read_small(g, msg_gva, &mhdr, sizeof(mhdr)) < 0)
        return -LINUX_EFAULT;

    int iovcnt;
    int64_t ret = nl_msg_iovcnt(&mhdr, &iovcnt);
    if (ret < 0)
        return ret;

    nl_iov_buf_t buf;
    ret = nl_iov_stage(g, mhdr.msg_iov, iovcnt, &buf);
    if (ret == 0)
        ret = netlink_recv_iov(guest_fd, g, buf.iov, iovcnt, flags);
    nl_iov_free(&buf);
    if (ret < 0)
        return ret;

    if (mhdr.msg_name && mhdr.msg_namelen >= sizeof(sockaddr_nl_t))
        nl_write_kernel_src(g, mhdr.msg_name,
                            msg_gva + offsetof(linux_msghdr_t, msg_namelen));

    int32_t zero_flags = 0;
    guest_write_small(g, msg_gva + offsetof(linux_msghdr_t, msg_flags),
                      &zero_flags, sizeof(zero_flags));
    uint64_t zero_controllen = 0;
    guest_write_small(g, msg_gva + offsetof(linux_msghdr_t, msg_controllen),
                      &zero_controllen, sizeof(zero_controllen));
    return ret;
}

int64_t netlink_readv(int guest_fd, guest_t *g, uint64_t iov_gva, int iovcnt)
{
    if (!iov_count_ok(iovcnt))
        return -LINUX_EINVAL;

    nl_iov_buf_t buf;
    int64_t ret = nl_iov_stage(g, iov_gva, iovcnt, &buf);
    if (ret == 0)
        ret = netlink_recv_iov(guest_fd, g, buf.iov, iovcnt, 0);
    nl_iov_free(&buf);
    return ret;
}

int64_t netlink_read(int guest_fd, guest_t *g, uint64_t buf_gva, uint64_t count)
{
    linux_iovec_t one = {.iov_base = buf_gva, .iov_len = count};
    return netlink_recv_iov(guest_fd, g, &one, 1, 0);
}

static void netlink_close(int guest_fd)
{
    pthread_mutex_lock(&nl_lock);
    netlink_state_t *ns = nl_find_oldest(guest_fd);
    if (!ns) {
        pthread_mutex_unlock(&nl_lock);
        return;
    }
    if (ns->pipe_wr != -1) {
        close(ns->pipe_wr);
        ns->pipe_wr = -1;
    }
    ns->pipe_rd = -1;
    ns->in_use = false;
    pthread_mutex_unlock(&nl_lock);
}
