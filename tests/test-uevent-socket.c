/*
 * NETLINK_KOBJECT_UEVENT silent-socket contract: the surface libusb_init()'s
 * netlink hotplug monitor needs (linux_netlink.c:102-133).
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Asserts, in the order libusb performs them:
 *   socket(AF_NETLINK, SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC,
 *          NETLINK_KOBJECT_UEVENT) succeeds,
 *   bind(nl_groups=1) succeeds (and nl_groups=2, nusb's udev group),
 *   setsockopt(SOL_SOCKET, SO_PASSCRED, 1) succeeds and reads back 1,
 *   getsockopt(SO_RCVBUF/SO_TYPE) report sane values,
 *   a drained socket is not readable: non-blocking recv reports EAGAIN and
 *   poll() times out,
 *   send() to the kernel-side netlink address (nl_pid 0) either fails with
 *   EPERM (elfuse refuses guests the authority to fabricate uevents) or is
 *   swallowed whole (a real Linux kernel's netlink_unicast() to the uevent
 *   handler returns the payload length; the handler's own CAP_SYS_ADMIN
 *   refusal only travels back as an NLMSG_ERROR ack, and a payload shorter
 *   than NLMSG_HDRLEN is skipped silently),
 *   and a NETLINK_ROUTE socket still opens, so the uevent path did not
 *   disturb the rtnetlink emulation.
 *
 * Then the SOL_SOCKET surface sk_setsockopt()/sk_getsockopt() define on any
 * socket, which a netlink fd has to answer the same way:
 *   SO_RCVBUF and SO_SNDBUF clamp to the sysctl, double, and floor at
 *   SOCK_MIN_RCVBUF and SOCK_MIN_SNDBUF -- two different floors, one twice
 *   the other,
 *   SO_RCVTIMEO actually bounds a blocking receive rather than being
 *   swallowed, in all three of sock_set_timeout()'s states (finite, forever,
 *   and the negative tv_sec that means "do not wait"),
 *   the options whose payload is not an int refuse a four-byte optlen,
 *   a getsockopt with a short optlen writes only what it reports and one with
 *   a negative optlen writes nothing at all,
 *   and every option that can be set can be read back.
 *
 * Then netlink_create()'s socket-type validation, and the SOL_NETLINK level:
 * the membership pair, the flag booleans a libnl/libmnl monitor sets on the way
 * up, and the bitmap NETLINK_LIST_MEMBERSHIPS reads back -- all under the same
 * contract bind() gives, recorded and never delivered on.
 *
 * The assertions hold for the elfuse emulation and for a real Linux kernel with
 * no hotplug activity during the run (the test matrix runs this binary under
 * qemu-aarch64 too). Genuine uevents arriving mid-run are tolerated by draining
 * before every readability check.
 *
 * The handful of answers that genuinely differ between the two are not asserted
 * as a disjunction that both lanes pass by accident. on_elfuse below names the
 * lane once, from the one probe whose answer is unambiguous, and each such
 * assertion states the strict outcome for the lane it is running in.
 *
 * Nothing here pins a number a kernel build is free to choose. SOCK_MIN_RCVBUF
 * is 2048 + SKB_DATA_ALIGN(sizeof(struct sk_buff)), which depends on the
 * config, and net.core.rmem_max is a sysctl, so the floors and the clamp are
 * asserted through relations that hold whatever those turn out to be: the send
 * floor is exactly twice the receive floor, and two requests that both exceed
 * the sysctl read back equal.
 */

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* Old kernel headers may predate some of these. The numbers are ABI. */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
#ifndef NETLINK_RX_RING
#define NETLINK_RX_RING 6
#endif
#ifndef NETLINK_LISTEN_ALL_NSID
#define NETLINK_LISTEN_ALL_NSID 8
#endif
#ifndef NETLINK_LIST_MEMBERSHIPS
#define NETLINK_LIST_MEMBERSHIPS 9
#endif
#ifndef NETLINK_CAP_ACK
#define NETLINK_CAP_ACK 10
#endif
#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
#endif
#ifndef NETLINK_GET_STRICT_CHK
#define NETLINK_GET_STRICT_CHK 12
#endif

static int pass, fail;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (cond) {                                                            \
            printf("PASS: %s\n", (msg));                                       \
            pass++;                                                            \
        } else {                                                               \
            printf("FAIL: %s (errno=%d %s)\n", (msg), errno, strerror(errno)); \
            fail++;                                                            \
        }                                                                      \
    } while (0)

/* Read until the socket is empty so a genuine uevent arriving on a real Linux
 * kernel cannot fail the emptiness assertions below.
 */
static void drain(int fd)
{
    char buf[4096];
    while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) >= 0)
        ;
}

/* A bounded retry around an assertion a genuine uevent can spoil. Four attempts
 * rather than a loop on success: a machine with a continuous hotplug stream
 * must fail this test, not spin in it. drain() itself terminates on the first
 * EAGAIN, so the whole thing is finite either way.
 */
#define RETRIES 4

/* Set one int option and read the resulting int back.
 *
 * Returns the readback, or -1 if either half failed.
 */
static int set_get_int(int fd, int optname, int value)
{
    if (setsockopt(fd, SOL_SOCKET, optname, &value, sizeof(value)) != 0)
        return -1;
    int out = -1;
    socklen_t len = sizeof(out);
    if (getsockopt(fd, SOL_SOCKET, optname, &out, &len) != 0 ||
        len != sizeof(int))
        return -1;
    return out;
}

/* The same round trip at SOL_NETLINK, where the flag booleans live.
 *
 * Returns the readback, or -1 if either half failed.
 */
static int set_get_nl(int fd, int optname, int value)
{
    if (setsockopt(fd, SOL_NETLINK, optname, &value, sizeof(value)) != 0)
        return -1;
    int out = -1;
    socklen_t len = sizeof(out);
    if (getsockopt(fd, SOL_NETLINK, optname, &out, &len) != 0 ||
        len != sizeof(int))
        return -1;
    return out;
}

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* The blocking receive below is the one assertion in this file that can hang
 * rather than fail if SO_RCVTIMEO is ignored, which is exactly the bug it
 * exists to catch. The matrix already wraps each binary in timeout(1), but a
 * suite-level kill reports nothing useful, so arm a watchdog that says what
 * happened first.
 */
static void watchdog_fired(int sig)
{
    (void) sig;
    static const char msg[] =
        "FAIL: a blocking recv() never came back (watchdog fired)\n";
    ssize_t n = write(2, msg, sizeof(msg) - 1);
    (void) n;
    _exit(1);
}

/* Two guest threads opening netlink sockets at the same instant used to race:
 * the emulation scanned its socket table, claimed a free slot, and wrote the
 * protocol into it with no lock, so the loser's write could land on the
 * winner's slot and hand one thread a socket carrying the other's protocol.
 * SO_PROTOCOL is the witness -- it reads that exact field back.
 *
 * A race is not a deterministic test, which is why every iteration also has to
 * be cheap: 4 threads x 250 opens gives the interleaving many chances while
 * costing well under a second on either lane.
 */
#define OPENERS 4
#define OPENS_PER_THREAD 250

typedef struct {
    int protocol;
    int mismatches;
    int open_failures;
} opener_arg_t;

static void *opener(void *arg)
{
    opener_arg_t *a = arg;
    for (int i = 0; i < OPENS_PER_THREAD; i++) {
        int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, a->protocol);
        if (s < 0) {
            a->open_failures++;
            continue;
        }
        int proto = -1, type = -1;
        socklen_t l = sizeof(proto);
        if (getsockopt(s, SOL_SOCKET, SO_PROTOCOL, &proto, &l) != 0 ||
            proto != a->protocol)
            a->mismatches++;
        l = sizeof(type);
        if (getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &l) != 0 ||
            type != SOCK_RAW)
            a->mismatches++;
        close(s);
    }
    return NULL;
}

/* Wakes the blocking receive in the huge-SO_RCVTIMEO test by asking the
 * rtnetlink socket for a link dump from a second thread, which is the only way
 * to prove that receive really parked: a timeout that overflowed its deadline
 * reports EAGAIN immediately instead, and one that works reports the dump.
 */
static int poke_fd = -1;

/* Thread body for the sibling-execve case: fail an execve() over and over while
 * the main thread is parked in a receive. The path never exists, so every
 * attempt returns ENOENT and the process image is never replaced -- but each
 * one still asks the dispatcher's leader to leave whatever it is parked in so
 * the run loop can reach the execve handoff, which is exactly the
 * guest-invisible EINTR the receive must not report.
 */
static volatile sig_atomic_t exec_probe_stop;

static void *failing_execve_loop(void *arg)
{
    (void) arg;
    char *const argv[] = {(char *) "/nonexistent-elfuse-exec-probe", NULL};
    char *const envp[] = {NULL};
    while (!exec_probe_stop) {
        struct timespec nap = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
        nanosleep(&nap, NULL);
        (void) execve("/nonexistent-elfuse-exec-probe", argv, envp);
    }
    return NULL;
}

static void *poke_after_delay(void *arg)
{
    (void) arg;
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 300 * 1000 * 1000};
    nanosleep(&delay, NULL);

    struct {
        struct nlmsghdr hdr;
        struct ifinfomsg ifi;
    } req;
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.ifi.ifi_family = AF_UNSPEC;

    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    ssize_t n = sendto(poke_fd, &req, sizeof(req), 0,
                       (struct sockaddr *) &kernel, sizeof(kernel));
    (void) n;
    return NULL;
}

static void test_uevent_basics(int fd, bool on_elfuse)
{
    struct sockaddr_nl snl = {.nl_family = AF_NETLINK, .nl_groups = 1};
    CHECK(bind(fd, (struct sockaddr *) &snl, sizeof(snl)) == 0,
          "bind(nl_groups=1)");

    int one = 1;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) == 0,
          "setsockopt(SO_PASSCRED, 1)");

    int val = -1;
    socklen_t len = sizeof(val);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_PASSCRED, &val, &len) == 0 &&
              val == 1 && len == sizeof(int),
          "getsockopt(SO_PASSCRED) == 1");

    val = 0;
    len = sizeof(val);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, &len) == 0 && val > 0,
          "getsockopt(SO_RCVBUF) > 0");

    val = 0;
    len = sizeof(val);
    CHECK(
        getsockopt(fd, SOL_SOCKET, SO_TYPE, &val, &len) == 0 && val == SOCK_RAW,
        "getsockopt(SO_TYPE) == SOCK_RAW");

    /* No uevent is ever synthesized: an empty socket reports EAGAIN. Retried
     * through drain() for the same reason the poll below is: on a real kernel
     * this fd is subscribed to uevent group 1, and a device event landing in
     * the window between the drain and the recv would otherwise fail a test
     * that is about elfuse's emulation, not about the host being idle.
     */
    char buf[4096];
    int empty = 0;
    for (int i = 0; i < RETRIES && !empty; i++) {
        drain(fd);
        empty =
            recv(fd, buf, sizeof(buf), MSG_DONTWAIT) == -1 && errno == EAGAIN;
    }
    CHECK(empty, "recv(MSG_DONTWAIT) empty -> EAGAIN");

    /* ...and poll() times out. Retried through drain() so a real hotplug event
     * during the run cannot fail the assertion.
     */
    int quiet = 0;
    for (int i = 0; i < RETRIES && !quiet; i++) {
        drain(fd);
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        quiet = poll(&pfd, 1, 200) == 0;
    }
    CHECK(quiet, "poll(200ms) times out on silent socket");

    /* Guests cannot fabricate uevents. elfuse refuses the send outright with
     * EPERM (uevent_net_rcv_skb's answer for a sender without CAP_SYS_ADMIN). A
     * real Linux kernel never surfaces that refusal through sendto():
     * netlink_unicast() to a kernel socket with .input set returns skb->len
     * unconditionally, the handler's -EPERM only comes back as an NLMSG_ERROR
     * ack, and this 14-byte payload is under NLMSG_HDRLEN so netlink_rcv_skb()
     * skips it without even an ack. So: success returning the payload length is
     * the real-kernel outcome, and any failure must be the EPERM refusal.
     */
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    ssize_t s = sendto(fd, "add@/devices/x", 14, 0, (struct sockaddr *) &kernel,
                       sizeof(kernel));
    CHECK(on_elfuse ? (s == -1 && errno == EPERM) : s == 14,
          on_elfuse ? "sendto() on a uevent socket -> EPERM"
                    : "sendto() swallowed whole by a real Linux kernel");

    /* nusb's watch_devices() binds group 2 (udevd's multicast group). */
    int fd2 =
        socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
    struct sockaddr_nl snl2 = {.nl_family = AF_NETLINK, .nl_groups = 2};
    CHECK(fd2 >= 0 && bind(fd2, (struct sockaddr *) &snl2, sizeof(snl2)) == 0,
          "second socket, bind(nl_groups=2)");
    if (fd2 >= 0)
        close(fd2);

    /* The rtnetlink emulation must be undisturbed by the uevent path. */
    int rt = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(rt >= 0, "socket(NETLINK_ROUTE) still works");
    if (rt >= 0)
        close(rt);
}

/* The lane probe from the top of main, asserted rather than merely consulted:
 * an unemulated netlink family is refused either way, and which errno it is
 * refused with is what on_elfuse was read from.
 */
static void test_socket_type_screening(int bogus, int bogus_errno)
{
    errno = bogus_errno;
    CHECK(bogus == -1 &&
              (bogus_errno == EAFNOSUPPORT || bogus_errno == EPROTONOSUPPORT),
          "socket(protocol=99) refused");

    /* netlink_create() takes SOCK_RAW and SOCK_DGRAM and nothing else.
     *
     * __sock_create() screens the flag bits first, so an unknown one is EINVAL
     * before the family is consulted at all; netlink_create() then screens the
     * base type, before the protocol number. Measured on Linux 6.x/aarch64,
     * which is also why socket(SOCK_STREAM, 99) below is ESOCKTNOSUPPORT and
     * not the unknown-family error: the type check runs first.
     */
    int st = socket(AF_NETLINK, SOCK_STREAM, NETLINK_KOBJECT_UEVENT);
    CHECK(st == -1 && errno == ESOCKTNOSUPPORT,
          "socket(SOCK_STREAM) -> ESOCKTNOSUPPORT");
    if (st >= 0)
        close(st);

    int sp = socket(AF_NETLINK, SOCK_SEQPACKET, NETLINK_ROUTE);
    CHECK(sp == -1 && errno == ESOCKTNOSUPPORT,
          "socket(SOCK_SEQPACKET) -> ESOCKTNOSUPPORT");
    if (sp >= 0)
        close(sp);

    int t0s = socket(AF_NETLINK, 0, NETLINK_ROUTE);
    CHECK(t0s == -1 && errno == ESOCKTNOSUPPORT,
          "socket(type=0) -> ESOCKTNOSUPPORT");
    if (t0s >= 0)
        close(t0s);

    int badflag = socket(AF_NETLINK, SOCK_RAW | 0x40000000, NETLINK_ROUTE);
    CHECK(badflag == -1 && errno == EINVAL,
          "socket(SOCK_RAW | unknown flag bit) -> EINVAL");
    if (badflag >= 0)
        close(badflag);

    int order = socket(AF_NETLINK, SOCK_STREAM, 99);
    CHECK(order == -1 && errno == ESOCKTNOSUPPORT,
          "socket(SOCK_STREAM, protocol=99): the type is screened first");
    if (order >= 0)
        close(order);

    int dg = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    CHECK(dg >= 0, "socket(SOCK_DGRAM) is accepted");
    if (dg >= 0)
        close(dg);
}

/* SO_RCVBUF/SO_SNDBUF: two floors, not one
 *
 * sk_setsockopt() clamps the request to net.core.{r,w}mem_max, doubles it, then
 * floors it at SOCK_MIN_RCVBUF or SOCK_MIN_SNDBUF. The two floors are
 * TCP_SKB_MIN_TRUESIZE and twice that, so the send floor is exactly double the
 * receive floor whatever sizeof(struct sk_buff) came out to on this build.
 * Asking for 0 lands on each floor exactly.
 */
static int test_sol_socket_options(bool on_elfuse)
{
    int opt = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    CHECK(opt >= 0, "socket for the SOL_SOCKET option surface");
    if (opt < 0)
        return 1;

    int rcv_floor = set_get_int(opt, SO_RCVBUF, 0);
    int snd_floor = set_get_int(opt, SO_SNDBUF, 0);
    CHECK(rcv_floor > 2048 && snd_floor == 2 * rcv_floor,
          "SO_SNDBUF floor is exactly twice the SO_RCVBUF floor");

    /* A request whose doubled value is under the floor reads back as the floor
     * -- and as its own direction's floor. 1024 doubles to 2048, which is below
     * TCP_SKB_MIN_TRUESIZE on any build; 2000 doubles to 4000, below twice it.
     */
    CHECK(set_get_int(opt, SO_RCVBUF, 1024) == rcv_floor,
          "SO_RCVBUF below the floor reports SOCK_MIN_RCVBUF");
    CHECK(set_get_int(opt, SO_SNDBUF, 2000) == snd_floor,
          "SO_SNDBUF below the floor reports SOCK_MIN_SNDBUF");

    /* The clamp is min_t(u32, val, sysctl), so a negative request is a huge
     * unsigned one and lands on the sysctl, not on the floor. Two requests that
     * both exceed the sysctl therefore read back equal -- which is the
     * assertion, since the sysctl itself is not ours to predict.
     */
    int rcv_neg = set_get_int(opt, SO_RCVBUF, -1);
    int rcv_huge = set_get_int(opt, SO_RCVBUF, INT_MAX);
    CHECK(rcv_neg > rcv_floor && rcv_neg == rcv_huge,
          "SO_RCVBUF = -1 clamps to the sysctl like INT_MAX, not to the floor");

    /* payloads that are not an int
     *
     * sk_setsockopt() reads an int first, so optlen < 4 is EINVAL for every
     * option. SO_LINGER and the two timeouts then check their own length, so an
     * optlen of exactly 4 -- enough for the generic read -- still fails.
     */
    char big[64];
    memset(big, 0, sizeof(big));
    CHECK(
        setsockopt(opt, SOL_SOCKET, SO_LINGER, big, 4) == -1 && errno == EINVAL,
        "setsockopt(SO_LINGER, optlen=4) -> EINVAL");
    CHECK(setsockopt(opt, SOL_SOCKET, SO_RCVTIMEO, big, 4) == -1 &&
              errno == EINVAL,
          "setsockopt(SO_RCVTIMEO, optlen=4) -> EINVAL");
    CHECK(setsockopt(opt, SOL_SOCKET, SO_SNDTIMEO, big, 4) == -1 &&
              errno == EINVAL,
          "setsockopt(SO_SNDTIMEO, optlen=4) -> EINVAL");
    CHECK(setsockopt(opt, SOL_SOCKET, SO_BROADCAST, big, 1) == -1 &&
              errno == EINVAL,
          "setsockopt(optlen=1) -> EINVAL for a plain int option");

    /* The full-length spellings are accepted, and read back. SO_LINGER writes 8
     * bytes and says so; the old code answered ENOPROTOOPT here.
     */
    struct linger lin = {.l_onoff = 1, .l_linger = 7};
    CHECK(setsockopt(opt, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin)) == 0,
          "setsockopt(SO_LINGER, sizeof(struct linger))");
    struct linger back = {.l_onoff = -1, .l_linger = -1};
    socklen_t blen = sizeof(back);
    CHECK(getsockopt(opt, SOL_SOCKET, SO_LINGER, &back, &blen) == 0 &&
              blen == sizeof(struct linger) && back.l_onoff == 1 &&
              back.l_linger == 7,
          "getsockopt(SO_LINGER) round-trips {1, 7} in 8 bytes");

    /* A getsockopt writes what it reports and no more.
     *
     * sock_getsockopt() writes min(len, lv) bytes and reports that same number,
     * so SO_LINGER read into a four-byte window succeeds, writes l_onoff alone,
     * reports 4, and leaves the caller's fifth byte onward untouched. Measured
     * on Linux 6.x/aarch64: rc 0, optlen 4, only the first four bytes written.
     * A caller that trusted a grown optlen would read poison as l_linger.
     */
    unsigned char poison[16];
    memset(poison, 0xAB, sizeof(poison));
    socklen_t plen = 4;
    int prc = getsockopt(opt, SOL_SOCKET, SO_LINGER, poison, &plen);
    int pfirst;
    memcpy(&pfirst, poison, sizeof(pfirst));
    CHECK(prc == 0 && plen == 4 && pfirst == 1 && poison[4] == 0xAB &&
              poison[5] == 0xAB && poison[6] == 0xAB && poison[7] == 0xAB,
          "getsockopt(SO_LINGER, optlen=4) writes 4 bytes and reports 4");

    /* A negative optlen is refused outright, before anything is written. */
    int nval = 0;
    socklen_t nlen = (socklen_t) -1;
    CHECK(getsockopt(opt, SOL_SOCKET, SO_RCVBUF, &nval, &nlen) == -1 &&
              errno == EINVAL,
          "getsockopt(SO_RCVBUF, optlen=-1) -> EINVAL");

    /* An over-long optlen shrinks to the option's own size rather than
     * reporting the buffer it was handed.
     */
    unsigned char roomy[64];
    socklen_t rlen = sizeof(roomy);
    CHECK(getsockopt(opt, SOL_SOCKET, SO_RCVTIMEO, roomy, &rlen) == 0 &&
              rlen == sizeof(struct timeval),
          "getsockopt(SO_RCVTIMEO, optlen=64) reports 16");

    /* SO_RCVTIMEO round-trips through jiffies on Linux, so the readback is the
     * request rounded up to at most one jiffy. HZ is 100 at the lowest, so 200
     * ms cannot grow past 210 ms; elfuse stores microseconds and returns the
     * request unchanged.
     */
    struct timeval tv = {.tv_sec = 0, .tv_usec = 200000};
    CHECK(setsockopt(opt, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0,
          "setsockopt(SO_RCVTIMEO, 200ms)");
    struct timeval rtv = {.tv_sec = -1, .tv_usec = -1};
    socklen_t tlen = sizeof(rtv);
    CHECK(getsockopt(opt, SOL_SOCKET, SO_RCVTIMEO, &rtv, &tlen) == 0 &&
              tlen == sizeof(struct timeval) && rtv.tv_sec == 0 &&
              rtv.tv_usec >= 200000 && rtv.tv_usec <= 210000,
          "getsockopt(SO_RCVTIMEO) reports the 200ms it was given");

    /* tv_usec outside [0, 1000000) is EDOM, which is neither EINVAL nor a
     * silent accept.
     */
    struct timeval bad = {.tv_sec = 0, .tv_usec = 1000000};
    CHECK(setsockopt(opt, SOL_SOCKET, SO_RCVTIMEO, &bad, sizeof(bad)) == -1 &&
              errno == EDOM,
          "setsockopt(SO_RCVTIMEO, tv_usec=1e6) -> EDOM");

    /* options that used to be accepted and then unreadable */
    CHECK(set_get_int(opt, SO_BROADCAST, 1) == 1, "SO_BROADCAST round-trips");
    CHECK(set_get_int(opt, SO_KEEPALIVE, 1) == 1, "SO_KEEPALIVE round-trips");
    CHECK(set_get_int(opt, SO_REUSEADDR, 1) == 1, "SO_REUSEADDR round-trips");
    CHECK(set_get_int(opt, SO_RCVLOWAT, 5) == 5, "SO_RCVLOWAT round-trips");

    int lowat = -1;
    socklen_t llen = sizeof(lowat);
    CHECK(getsockopt(opt, SOL_SOCKET, SO_SNDLOWAT, &lowat, &llen) == 0 &&
              lowat == 1,
          "getsockopt(SO_SNDLOWAT) == 1");

    /* SO_SNDLOWAT has no case in sk_setsockopt at all (1003.1g 7 makes it
     * unsettable), so it falls to the default arm.
     */
    int one_v = 1;
    CHECK(
        setsockopt(opt, SOL_SOCKET, SO_SNDLOWAT, &one_v, sizeof(one_v)) == -1 &&
            errno == ENOPROTOOPT,
        "setsockopt(SO_SNDLOWAT) -> ENOPROTOOPT");

    /* Clearing SO_DEBUG and SO_REUSEPORT is unprivileged and always works.
     * Setting either is refused on an elfuse netlink socket -- a guest holds no
     * CAP_NET_ADMIN over the host and AF_NETLINK is not what sk_is_inet()
     * accepts -- and that half is asserted strictly on the elfuse lane. The
     * qemu lane cannot be held to it: its initramfs boots as root, where
     * CAP_NET_ADMIN makes SO_DEBUG succeed, and the sk_is_inet() guard on
     * SO_REUSEPORT is younger than some kernels this may meet, so there the
     * assertion is the weaker one those two facts leave.
     */
    int zero_v = 0;
    CHECK(setsockopt(opt, SOL_SOCKET, SO_DEBUG, &zero_v, sizeof(zero_v)) == 0,
          "setsockopt(SO_DEBUG, 0) accepted");
    CHECK(
        setsockopt(opt, SOL_SOCKET, SO_REUSEPORT, &zero_v, sizeof(zero_v)) == 0,
        "setsockopt(SO_REUSEPORT, 0) accepted");
    int dbg = setsockopt(opt, SOL_SOCKET, SO_DEBUG, &one_v, sizeof(one_v));
    CHECK(on_elfuse ? (dbg == -1 && errno == EACCES)
                    : (dbg == 0 ? geteuid() == 0 : errno == EACCES),
          "setsockopt(SO_DEBUG, 1) -> EACCES without CAP_NET_ADMIN");
    int rp = setsockopt(opt, SOL_SOCKET, SO_REUSEPORT, &one_v, sizeof(one_v));
    CHECK(on_elfuse ? (rp == -1 && errno == EOPNOTSUPP)
                    : (rp == 0 || errno == EOPNOTSUPP),
          "setsockopt(SO_REUSEPORT, 1) -> EOPNOTSUPP on a non-inet socket");

    close(opt);

    return 0;
}

/* SO_RCVTIMEO bounds a blocking receive
 *
 * A blocking uevent socket bound to no multicast group receives nothing on
 * either world: elfuse never synthesizes a uevent, and a real kernel has
 * nothing to deliver to a subscriber of no groups. With a 200 ms SO_RCVTIMEO
 * the recv must come back EAGAIN rather than parking forever, which is what an
 * accepted-and-discarded timeout would do.
 */
static void test_rcvtimeo_blocking_recv(void)
{
    char buf[4096];

    int blk = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    CHECK(blk >= 0, "blocking socket for the SO_RCVTIMEO wait");
    if (blk >= 0) {
        struct sockaddr_nl nogroups = {.nl_family = AF_NETLINK, .nl_groups = 0};
        (void) bind(blk, (struct sockaddr *) &nogroups, sizeof(nogroups));

        struct timeval wait_tv = {.tv_sec = 0, .tv_usec = 200000};
        CHECK(setsockopt(blk, SOL_SOCKET, SO_RCVTIMEO, &wait_tv,
                         sizeof(wait_tv)) == 0,
              "setsockopt(SO_RCVTIMEO, 200ms) on the blocking socket");

        signal(SIGALRM, watchdog_fired);
        alarm(20);

        /* Bounded retry for the same reason as the drains above: a uevent that
         * somehow reaches this socket makes the recv succeed, and that is the
         * host being busy rather than the timeout being broken.
         */
        int timed_out = 0;
        int64_t elapsed = -1;
        for (int i = 0; i < RETRIES && !timed_out; i++) {
            int64_t t0 = now_ms();
            ssize_t got = recv(blk, buf, sizeof(buf), 0);
            elapsed = now_ms() - t0;
            timed_out = got == -1 && (errno == EAGAIN || errno == EWOULDBLOCK);
        }
        alarm(0);

        CHECK(timed_out, "blocking recv() with SO_RCVTIMEO -> EAGAIN");

        /* At least the timeout (Linux rounds up to a jiffy, never down) and not
         * wildly past it. The upper bound is loose on purpose: it is here to
         * catch a wait that ignored the deadline, not to police scheduling
         * under a loaded qemu.
         */
        CHECK(timed_out && elapsed >= 150 && elapsed < 10000,
              "the SO_RCVTIMEO wait lasted about 200ms");
        close(blk);
    }
}

/* SOL_NETLINK
 *
 * Same contract as bind(): the membership and the flags are recorded, and
 * nothing is ever delivered on them. Every answer below was measured on Linux
 * 6.x/aarch64 against both NETLINK_ROUTE and NETLINK_KOBJECT_UEVENT, so these
 * are strict on both lanes -- except NETLINK_LISTEN_ALL_NSID, which is a
 * capability check and therefore answers by privilege.
 */
static void test_sol_netlink(bool on_elfuse)
{
    int nlopt = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    CHECK(nlopt >= 0, "socket for the SOL_NETLINK option surface");
    if (nlopt >= 0) {
        struct sockaddr_nl nogrp = {.nl_family = AF_NETLINK, .nl_groups = 0};
        (void) bind(nlopt, (struct sockaddr *) &nogrp, sizeof(nogrp));

        int grp = 1;
        CHECK(setsockopt(nlopt, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &grp,
                         sizeof(grp)) == 0,
              "setsockopt(NETLINK_ADD_MEMBERSHIP, 1)");
        CHECK(setsockopt(nlopt, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP, &grp,
                         sizeof(grp)) == 0,
              "setsockopt(NETLINK_DROP_MEMBERSHIP, 1)");

        /* Groups are numbered from 1, and the count is bounded, so 0 is out of
         * range at the bottom exactly as an absurd number is at the top.
         */
        int gzero = 0;
        CHECK(setsockopt(nlopt, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &gzero,
                         sizeof(gzero)) == -1 &&
                  errno == EINVAL,
              "NETLINK_ADD_MEMBERSHIP group 0 -> EINVAL");
        int gbig = 1000000;
        CHECK(setsockopt(nlopt, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &gbig,
                         sizeof(gbig)) == -1 &&
                  errno == EINVAL,
              "NETLINK_ADD_MEMBERSHIP group 1000000 -> EINVAL");
        CHECK(setsockopt(nlopt, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP, &gbig,
                         sizeof(gbig)) == -1 &&
                  errno == EINVAL,
              "NETLINK_DROP_MEMBERSHIP group 1000000 -> EINVAL");

        /* The membership pair is write-only: netlink_getsockopt has no case for
         * either, and the bitmap is read through LIST_MEMBERSHIPS instead.
         */
        int mval = 0;
        socklen_t mlen = sizeof(mval);
        CHECK(getsockopt(nlopt, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &mval,
                         &mlen) == -1 &&
                  errno == ENOPROTOOPT,
              "getsockopt(NETLINK_ADD_MEMBERSHIP) -> ENOPROTOOPT");

        /* The flag booleans a libnl/libmnl monitor sets on the way up. Every
         * one of them sets and reads back, in both directions.
         */
        CHECK(set_get_nl(nlopt, NETLINK_PKTINFO, 1) == 1,
              "NETLINK_PKTINFO round-trips");
        CHECK(set_get_nl(nlopt, NETLINK_BROADCAST_ERROR, 1) == 1,
              "NETLINK_BROADCAST_ERROR round-trips");
        CHECK(set_get_nl(nlopt, NETLINK_NO_ENOBUFS, 1) == 1,
              "NETLINK_NO_ENOBUFS round-trips");
        CHECK(set_get_nl(nlopt, NETLINK_CAP_ACK, 1) == 1,
              "NETLINK_CAP_ACK round-trips");
        CHECK(set_get_nl(nlopt, NETLINK_EXT_ACK, 1) == 1,
              "NETLINK_EXT_ACK round-trips");
        CHECK(set_get_nl(nlopt, NETLINK_GET_STRICT_CHK, 1) == 1,
              "NETLINK_GET_STRICT_CHK round-trips");
        CHECK(set_get_nl(nlopt, NETLINK_EXT_ACK, 0) == 0,
              "NETLINK_EXT_ACK clears again");

        /* Unlike SOL_SOCKET, which truncates to what fits, a flag read wants
         * room for a whole int or reports EINVAL.
         */
        int shortv = 0;
        socklen_t shortl = 3;
        CHECK(getsockopt(nlopt, SOL_NETLINK, NETLINK_CAP_ACK, &shortv,
                         &shortl) == -1 &&
                  errno == EINVAL,
              "getsockopt(NETLINK_CAP_ACK, optlen=3) -> EINVAL");

        /* mmap'd netlink was removed in Linux 4.10; the ring options have
         * reported ENOPROTOOPT ever since, and so does an optname no netlink
         * kernel ever had.
         */
        int one_nl = 1;
        CHECK(setsockopt(nlopt, SOL_NETLINK, NETLINK_RX_RING, &one_nl,
                         sizeof(one_nl)) == -1 &&
                  errno == ENOPROTOOPT,
              "setsockopt(NETLINK_RX_RING) -> ENOPROTOOPT");
        CHECK(setsockopt(nlopt, SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, &one_nl,
                         sizeof(one_nl)) == -1 &&
                  errno == ENOPROTOOPT,
              "setsockopt(NETLINK_LIST_MEMBERSHIPS) -> ENOPROTOOPT");
        CHECK(
            setsockopt(nlopt, SOL_NETLINK, 99, &one_nl, sizeof(one_nl)) == -1 &&
                errno == ENOPROTOOPT,
            "setsockopt(SOL_NETLINK, optname=99) -> ENOPROTOOPT");
        CHECK(setsockopt(nlopt, 999, 1, &one_nl, sizeof(one_nl)) == -1 &&
                  errno == ENOPROTOOPT,
              "setsockopt(unknown level) -> ENOPROTOOPT");

        /* NETLINK_LISTEN_ALL_NSID is ns_capable(CAP_NET_ADMIN). An elfuse guest
         * never holds that over the host, so the refusal is strict on that
         * lane; the qemu initramfs boots as root, where it succeeds.
         */
        int nsid = setsockopt(nlopt, SOL_NETLINK, NETLINK_LISTEN_ALL_NSID,
                              &one_nl, sizeof(one_nl));
        CHECK(on_elfuse ? (nsid == -1 && errno == EPERM)
                        : (nsid == 0 ? geteuid() == 0 : errno == EPERM),
              "NETLINK_LISTEN_ALL_NSID -> EPERM without CAP_NET_ADMIN");

        /* What ADD_MEMBERSHIP recorded is what LIST_MEMBERSHIPS reports, which
         * is the whole of the contract: the join is bookkeeping, and the
         * bookkeeping is readable. The reported length is the bitmap's own
         * size, ALIGN(BITS_TO_BYTES(ngroups), 4) -- 4 for a family whose group
         * count sits at netlink_kernel_create()'s floor of 32.
         */
        int grp2 = 2;
        uint32_t bitmap = 0;
        socklen_t blen2 = sizeof(bitmap);
        int added = setsockopt(nlopt, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                               &grp2, sizeof(grp2));
        int got = getsockopt(nlopt, SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS,
                             &bitmap, &blen2);
        CHECK(added == 0 && got == 0 && blen2 == 4 && (bitmap & 2u),
              "NETLINK_LIST_MEMBERSHIPS shows the group ADD_MEMBERSHIP joined");

        bitmap = 0;
        blen2 = sizeof(bitmap);
        int dropped = setsockopt(nlopt, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
                                 &grp2, sizeof(grp2));
        got = getsockopt(nlopt, SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, &bitmap,
                         &blen2);
        CHECK(dropped == 0 && got == 0 && !(bitmap & 2u),
              "NETLINK_LIST_MEMBERSHIPS drops the group again");

        close(nlopt);
    }
}

/* A negative tv_sec is sock_set_timeout()'s third state
 *
 * Linux stores a literal 0 jiffies for it, which every wait reads as "do not
 * wait": the receive below must report EAGAIN at once even though the socket is
 * blocking and the option reads back as {0,0}, the same thing "wait forever"
 * reads back as. Storing it as forever -- the reading that {0,0} deserves and
 * this does not -- parks the caller instead, which is what the watchdog would
 * catch.
 */
static void test_negative_rcvtimeo(void)
{
    char buf[4096];

    int nw = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    CHECK(nw >= 0, "socket for the negative-timeout receive");
    if (nw >= 0) {
        struct sockaddr_nl nogrp = {.nl_family = AF_NETLINK, .nl_groups = 0};
        (void) bind(nw, (struct sockaddr *) &nogrp, sizeof(nogrp));

        struct timeval neg = {.tv_sec = -1, .tv_usec = 0};
        CHECK(setsockopt(nw, SOL_SOCKET, SO_RCVTIMEO, &neg, sizeof(neg)) == 0,
              "setsockopt(SO_RCVTIMEO, tv_sec=-1) accepted");

        struct timeval negback = {.tv_sec = -9, .tv_usec = -9};
        socklen_t neglen = sizeof(negback);
        CHECK(getsockopt(nw, SOL_SOCKET, SO_RCVTIMEO, &negback, &neglen) == 0 &&
                  negback.tv_sec == 0 && negback.tv_usec == 0,
              "getsockopt after a negative tv_sec reports {0, 0}");

        signal(SIGALRM, watchdog_fired);
        alarm(20);
        int64_t nt0 = now_ms();
        ssize_t ngot = recv(nw, buf, sizeof(buf), 0);
        int64_t nelapsed = now_ms() - nt0;
        alarm(0);
        CHECK(ngot == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
                  nelapsed < 1000,
              "a blocking recv after tv_sec=-1 reports EAGAIN at once");
        close(nw);
    }
}

/* A sibling's execve is not a signal
 *
 * io_wait_fd_timed_or_interrupted() reports EINTR for two unrelated reasons.
 * One is a signal the guest can see. The other is the dispatcher's own execve
 * handoff, which the leader leaves its wait for so the run loop can reach it,
 * and which carries no signal at all. Refusing the SVC restart for both turned
 * a sibling's execve -- even one that fails -- into an EINTR on a recvmsg the
 * guest issued once, an errno Linux cannot produce there. Below, an execve
 * fails every 20 ms for the whole of a two-second SO_RCVTIMEO and the receive
 * still has to come back with EAGAIN at the deadline it was given.
 *
 * The elapsed time is the other half. A restart re-enters the wait from the
 * top, so one that took a fresh copy of SO_RCVTIMEO rather than resuming the
 * deadline would push the return out by two seconds per interruption -- around
 * a hundred of them here -- and the watchdog rather than the upper bound is
 * what would catch it. Resuming the deadline is what Linux's restart_block
 * carries.
 */
static void test_sibling_execve_recv(void)
{
    char buf[4096];

    int xw = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    CHECK(xw >= 0, "socket for the sibling-execve receive");
    if (xw >= 0) {
        struct sockaddr_nl xgrp = {.nl_family = AF_NETLINK, .nl_groups = 0};
        (void) bind(xw, (struct sockaddr *) &xgrp, sizeof(xgrp));

        struct timeval two = {.tv_sec = 2, .tv_usec = 0};
        CHECK(setsockopt(xw, SOL_SOCKET, SO_RCVTIMEO, &two, sizeof(two)) == 0,
              "setsockopt(SO_RCVTIMEO, 2s) for the sibling-execve receive");

        pthread_t execer;
        exec_probe_stop = 0;
        int xspawned = pthread_create(&execer, NULL, failing_execve_loop, NULL);
        CHECK(xspawned == 0, "spawned the failing-execve sibling");
        if (xspawned == 0) {
            signal(SIGALRM, watchdog_fired);
            alarm(30);
            int64_t xt0 = now_ms();
            ssize_t xgot = recv(xw, buf, sizeof(buf), 0);
            int xerr = errno;
            int64_t xelapsed = now_ms() - xt0;
            alarm(0);
            exec_probe_stop = 1;
            pthread_join(execer, NULL);
            errno = xerr;
            CHECK(xgot == -1 && (xerr == EAGAIN || xerr == EWOULDBLOCK) &&
                      xelapsed >= 1900 && xelapsed < 6000,
                  "a failing sibling execve neither interrupts the receive nor "
                  "restarts its timeout");
        }
        close(xw);
    }
}

/* A huge finite SO_RCVTIMEO is finite, and it is huge
 *
 * Linux's cutoff for "so long it means forever" is MAX_SCHEDULE_TIMEOUT/HZ
 * - 1 seconds; a tv_sec of 1e13 is far below it and reads back unchanged
 * (measured), where a cutoff three orders lower turns it into {0,0}. And the
 * deadline such a timeout produces has to survive being added to a clock: an
 * overflowing add lands in the past and turns the longest wait a guest can ask
 * for into an instant EAGAIN. Both halves are asserted -- the readback, and a
 * receive that really does park until a second thread gives it something to
 * read.
 */
static void test_huge_rcvtimeo(void)
{
    char buf[4096];

    poke_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(poke_fd >= 0, "rtnetlink socket for the huge-timeout receive");
    if (poke_fd >= 0) {
        struct sockaddr_nl self = {.nl_family = AF_NETLINK};
        (void) bind(poke_fd, (struct sockaddr *) &self, sizeof(self));

        struct timeval huge = {.tv_sec = (time_t) 10000000000000LL,
                               .tv_usec = 0};
        CHECK(setsockopt(poke_fd, SOL_SOCKET, SO_RCVTIMEO, &huge,
                         sizeof(huge)) == 0,
              "setsockopt(SO_RCVTIMEO, tv_sec=1e13) accepted");

        struct timeval hback = {.tv_sec = -1, .tv_usec = -1};
        socklen_t hlen = sizeof(hback);
        CHECK(
            getsockopt(poke_fd, SOL_SOCKET, SO_RCVTIMEO, &hback, &hlen) == 0 &&
                hback.tv_sec == (time_t) 10000000000000LL && hback.tv_usec == 0,
            "getsockopt reports the 1e13-second timeout unchanged");

        /* The receive below runs with the largest timeout that fits in
         * microseconds rather than the one above, on purpose: a deadline built
         * by adding it to a clock overflows a signed 64-bit microsecond count
         * on any machine that has been up for half an hour, and lands in the
         * past. Nothing about the readback shows that -- only a receive does.
         */
        struct timeval brim = {.tv_sec = (time_t) 9223372036852LL,
                               .tv_usec = 0};
        CHECK(setsockopt(poke_fd, SOL_SOCKET, SO_RCVTIMEO, &brim,
                         sizeof(brim)) == 0 &&
                  getsockopt(poke_fd, SOL_SOCKET, SO_RCVTIMEO, &hback, &hlen) ==
                      0 &&
                  hback.tv_sec == (time_t) 9223372036852LL,
              "SO_RCVTIMEO at the microsecond brim round-trips");

        /* Timed from before the thread starts, not from the recv: the poke is
         * 300 ms after the thread begins, so anything the recv returns is at
         * least that far out however the two are scheduled. A recv that came
         * back sooner did not wait.
         */
        pthread_t poker;
        int64_t ht0 = now_ms();
        int spawned = pthread_create(&poker, NULL, poke_after_delay, NULL);
        CHECK(spawned == 0, "spawned the thread that pokes the rtnetlink fd");
        if (spawned == 0) {
            signal(SIGALRM, watchdog_fired);
            alarm(20);
            ssize_t hgot = recv(poke_fd, buf, sizeof(buf), 0);
            int64_t helapsed = now_ms() - ht0;
            alarm(0);
            pthread_join(poker, NULL);
            CHECK(hgot > 0 && helapsed >= 250,
                  "a huge SO_RCVTIMEO parks the receive instead of expiring");
        }
        close(poke_fd);
        poke_fd = -1;
    }
}

/* Concurrent socket() must not cross-wire two sockets
 *
 * The protocol is a behavior discriminator -- it picks between the rtnetlink
 * emulation and the silent uevent socket -- so a table slot claimed by two
 * threads at once is two guests sharing one socket's identity. SO_PROTOCOL and
 * SO_TYPE read the two fields the race could scramble.
 */
static void test_concurrent_open(void)
{
    opener_arg_t oargs[OPENERS];
    pthread_t othreads[OPENERS];
    int spawned_openers = 0;
    for (int i = 0; i < OPENERS; i++) {
        oargs[i].protocol = (i % 2) ? NETLINK_ROUTE : NETLINK_KOBJECT_UEVENT;
        oargs[i].mismatches = 0;
        oargs[i].open_failures = 0;
        if (pthread_create(&othreads[i], NULL, opener, &oargs[i]) == 0)
            spawned_openers++;
        else
            break;
    }
    int mismatches = 0, open_failures = 0;
    for (int i = 0; i < spawned_openers; i++) {
        pthread_join(othreads[i], NULL);
        mismatches += oargs[i].mismatches;
        open_failures += oargs[i].open_failures;
    }
    CHECK(spawned_openers == OPENERS, "spawned the concurrent-open threads");
    CHECK(open_failures == 0, "every concurrent socket(AF_NETLINK) succeeded");
    CHECK(mismatches == 0,
          "concurrent opens each report their own SO_PROTOCOL and SO_TYPE");
}

int main(void)
{
    /* Line-buffered: the watchdog below _exit()s from a signal handler, which
     * takes any buffered output with it. Without this a hang reports only the
     * watchdog line, and which assertion hung is exactly what is wanted.
     */
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* Which lane is this? The one probe whose two answers cannot be confused:
     * an unemulated netlink family is EAFNOSUPPORT from elfuse and
     * EPROTONOSUPPORT from a kernel that simply has no such family registered.
     * Everything below that differs by lane asks this rather than accepting
     * both answers, so neither lane can pass on the other lane's behavior.
     */
    int bogus = socket(AF_NETLINK, SOCK_RAW, 99);
    int bogus_errno = errno;
    if (bogus >= 0)
        close(bogus);
    bool on_elfuse = bogus == -1 && bogus_errno == EAFNOSUPPORT;

    /* The exact socket() call libusb's netlink monitor makes. */
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                    NETLINK_KOBJECT_UEVENT);
    CHECK(fd >= 0, "socket(NETLINK_KOBJECT_UEVENT)");
    if (fd < 0)
        return 1;

    test_uevent_basics(fd, on_elfuse);
    test_socket_type_screening(bogus, bogus_errno);
    if (test_sol_socket_options(on_elfuse)) {
        close(fd);
        printf("%d passed, %d failed\n", pass, fail);
        return 1;
    }
    test_rcvtimeo_blocking_recv();
    test_sol_netlink(on_elfuse);
    test_negative_rcvtimeo();
    test_sibling_execve_recv();
    test_huge_rcvtimeo();
    test_concurrent_open();

    close(fd);
    printf("%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
