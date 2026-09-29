/*
 * usbdevfs (/dev/bus/usb/BBB/DDD) fd emulation over IOKit
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Where the line numbers below come from: devio.c is drivers/usb/core/devio.c
 * at v6.15, git blob f6ce6e26e0d4, which v6.15 through v6.19 all carry
 * unchanged; ioctl.c is fs/ioctl.c at v6.18; driver.c is
 * drivers/usb/core/driver.c at v6.18; darwin_usb.c is libusb's
 * libusb/os/darwin_usb.c at commit 2611713a. IOUSBLib.h is the IOKit framework
 * header, identical in the MacOSX14.5, MacOSX15.2 and MacOSX15.5 SDKs.
 * netlink.c is this tree.
 *
 * Stage 2: a typed FD_USBDEV fd whose synchronous usbdevfs ioctls are mapped
 * onto IOUSBDeviceInterface650 / IOUSBInterfaceInterface800 plugin calls
 * (research doc D's op table). Semantics mirror drivers/usb/core/devio.c (doc A
 * sections A1 and A2):
 *
 *   - open of any access mode succeeds; read() serves the descriptors blob
 *     (byte-identical to the sysfs descriptors attribute) at a per-open
 *     file position; SEEK_END is -EINVAL (no_seek_end_llseek).
 *   - every usbdevfs ioctl requires a writable fd: O_RDONLY fd -> -EPERM
 *     (devio.c:2608-2609 FMODE_WRITE gate). FIONBIO and FIOASYNC are not
 *     part of that surface: do_vfs_ioctl answers both for every file before
 *     f_op->unlocked_ioctl runs (fs/ioctl.c:507-511), so syscall/io.c answers
 *     them where the kernel does and they never meet this gate.
 *   - CLAIMINTERFACE returns -EBUSY when a macOS kernel driver is bound; the
 *     "kernel driver" test is an IORegistry child of the IOUSBHostInterface
 *     service in the service plane (libusb darwin_usb.c:2761-2785), and the
 *     claim itself is USBInterfaceOpen (kIOReturnExclusiveAccess -> -EBUSY).
 *   - CONTROL/BULK are Linux's sync paths (do_proc_control/do_proc_bulk):
 *     bounce buffers around DeviceRequestTO / Read|WritePipeTO, timeout in ms
 *     (0 = unlimited on both sides), -ETIMEDOUT from
 *     kIOUSBTransactionTimeout, stall -> -EPIPE, and Linux's implicit
 *     claim of the recipient interface (check_ctrlrecip/checkintf).
 *
 * Stage 3 adds async URBs and poll semantics:
 *
 *   - SUBMITURB/DISCARDURB/REAPURB/REAPURBNDELAY (doc A section A3): URB
 *     buffers bounce through host memory (copy-in at submit on the vCPU
 *     thread, copy-out at reap on the vCPU thread); IOKit completions run on
 *     ONE lazily-started host thread driving a CFRunLoop (the libusb darwin
 *     model, doc D section c) fed by CreateDeviceAsyncEventSource /
 *     CreateInterfaceAsyncEventSource. That thread touches only
 *     usbdev-owned host memory (static fd slots + malloc'd URB records),
 *     never guest memory, so it is safe across guest_destroy/exec
 *     (netlink.c:1733-1738 precedent).
 *   - DISCARDURB must kill exactly one URB, but IOKit's AbortPipe aborts
 *     every outstanding transfer on the pipe (doc D mismatch #1). So at most
 *     ONE URB per endpoint is in flight at IOKit at a time; later submissions
 *     queue inside elfuse and are started from the completion callback
 *     (throughput tradeoff, ep0 serialized the same way).
 *   - URBs get no IOKit timeout (0 = infinite): usbfs URBs never time out,
 *     guests cancel with DISCARDURB (kIOReturnAborted -> -ENOENT when
 *     discarding, -ECONNRESET otherwise, mirroring usb_kill_urb vs async
 *     unlink).
 *   - ZERO_PACKET on a maxpacket-multiple OUT issues a synchronous
 *     WritePipe(pipeRef, buf, 0) from the completion callback
 *     (darwin_usb.c:3204-3218). SHORT_NOT_OK is emulated at completion
 *     (-EREMOTEIO on a short IN). Both flags are honored only for their
 *     Linux-defined direction (devio.c:1710-1737). BULK_CONTINUATION is
 *     accepted but its error-cascade unlink has no IOKit counterpart.
 *   - poll()/select()/epoll on the fd: the backing pipe's read end raises
 *     host POLLIN while the fd has a completion to hand back or has been
 *     disconnected -- a level the pipe holds one byte for, not a byte per
 *     completed URB (usbdev_ready_settle_locked); poll.c remaps that to the
 *     guest-visible POLLOUT|POLLWRNORM (devio.c:2833-2847) via the
 *     usbdev_poll_* helpers below.
 *   - Disconnect: IOServiceAddInterestNotification (terminate message) or
 *     kIOReturnNoDevice/NotAttached from any op -- every op translates its
 *     IOKit status through usbdev_ioret_op, the synchronous transfers and the
 *     setup calls included, so an op that observes either of those two codes
 *     originates the disconnect rather than merely reporting it -- marks every
 *     usbfs fd open on that device disconnected, not only the one that
 *     noticed: the walk usbdev_remove does over udev->filelist.
 *     poll -> POLLERR|POLLHUP. What each ioctl answers once that mark is on
 *     the fd, and what it answers on an fd still carrying nothing, is the
 *     recorded table in tests/usbdev-ioctl-departed.tbl rather than a count
 *     here.
 *     usbdev_ioret_device_gone is deliberately narrower than the -ENODEV row
 *     of ioret_neg_errno, which also carries kIOReturnNotOpen: that is what
 *     IOKit answers for a handle nobody has opened yet, so a request arriving
 *     before the lazy USBDeviceOpen draws it from a device plainly still
 *     there. Such a request answers -ENODEV, the way Linux answers for a
 *     device it cannot reach, and does NOT stamp: treating that code as proof
 *     of departure would mark a live fd gone on its first control request.
 *     REAPURB hands back every URB the post-disconnect
 *     kill recovers BEFORE any reap answers -ENODEV, whichever reap flavor
 *     asked first; a non-blocking REAPURBNDELAY issues that kill's aborts,
 *     does not wait for them, and answers -EAGAIN until they land.
 *   - DISCSIGNAL stores signr/context but never delivers the signal (no
 *     async guest-signal injection from the event thread); URB signr is
 *     ignored the same way. ISO URBs are -EINVAL (doc A section A7.4, skipped).
 *
 * Documented stage-2 deviations from Linux:
 *   - USBDEVFS_RESET does not re-enumerate: USBDeviceReEnumerate(0) would
 *     tear down every open plugin handle (doc D "reset" row), so RESET clears
 *     the stall state of all claimed pipes and returns 0. TODO(stage 3+):
 *     full re-enumeration with pending_device adoption.
 *   - Sync BULK on an interrupt endpoint is -EINVAL (Linux converts it to an
 *     interrupt URB; IOKit's ReadPipeTO/WritePipeTO reject interrupt pipes,
 *     IOUSBLib.h "BadArgument if TO on interrupt pipe"). TODO(later): route
 *     through the async path with a watchdog.
 *   - dup()/fork() of an FD_USBDEV fd are refused (-EBADF): IOKit plugin
 *     handles are process-local and the side table is keyed by the guest fd.
 *     TODO(later): explicit dup alias (fuse_dup_fd pattern).
 *   - DISCONNECT/CONNECT/DISCONNECT_CLAIM cannot unbind Apple drivers without
 *     root or the com.apple.vm.device-access entitlement, so a bound kernel
 *     driver yields -EACCES (matching Linux's privileges-dropped answer).
 *   - A printer's GET_DEVICE_ID names its interface in the HIGH byte of
 *     wIndex and an alt setting in the low one, and check_ctrlrecip lets that
 *     one request through untouched: it returns 0 before the index &= 0xff
 *     when the recipient is 0xa1, the request is 0 and
 *     usb_find_alt_setting(actconfig, index >> 8, index & 0xff) has class
 *     USB_CLASS_PRINTER. Both control paths here read wIndex & 0xff as the
 *     interface number for every non-vendor interface recipient, so on a
 *     printer such a request implicitly claims the alt setting's number
 *     instead of the interface's. Demonstrating it needs a printer, so it is
 *     a deviations row rather than a modeled case.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/usb/USB.h>

#include "core/guest.h"
#include "debug/log.h"
#include "runtime/usb-sysfs.h"
#include "syscall/internal.h"
#include "syscall/io.h"
#include "syscall/linux-wire.h"
#include "syscall/proc.h"
#include "syscall/usbdev-fixture.h"
#include "syscall/usbdev-urb.h"
#include "syscall/usbdev.h"
#include "utils.h"

/* usbdevfs wire ABI (LP64; x86_64 == aarch64) */

#define USBDEVFS_CONTROL 0xc0185500u
#define USBDEVFS_BULK 0xc0185502u
#define USBDEVFS_RESETEP 0x80045503u
#define USBDEVFS_SETINTERFACE 0x80085504u
#define USBDEVFS_SETCONFIGURATION 0x80045505u
#define USBDEVFS_GETDRIVER 0x41045508u
#define USBDEVFS_SUBMITURB 0x8038550au
#define USBDEVFS_DISCARDURB 0x0000550bu
#define USBDEVFS_REAPURB 0x4008550cu
#define USBDEVFS_REAPURBNDELAY 0x4008550du
#define USBDEVFS_DISCSIGNAL 0x8010550eu
#define USBDEVFS_CLAIMINTERFACE 0x8004550fu
#define USBDEVFS_RELEASEINTERFACE 0x80045510u
#define USBDEVFS_CONNECTINFO 0x40085511u
#define USBDEVFS_IOCTL 0xc0105512u
#define USBDEVFS_RESET 0x00005514u
#define USBDEVFS_CLEAR_HALT 0x80045515u
#define USBDEVFS_GET_CAPABILITIES 0x8004551au
#define USBDEVFS_DISCONNECT_CLAIM 0x8108551bu
#define USBDEVFS_GET_SPEED 0x0000551fu

/* usbdevfs requests this layer does not serve, written down so that the surface
 * reaches the arm catching the undispatched and not only the dispatched arms.
 * Not so that it is complete: Linux serves more that this file does not name at
 * all -- CLAIM_PORT, RELEASE_PORT, FREE_STREAMS, DROP_PRIVILEGES, CONNINFO_EX,
 * FORBID_SUSPEND and ALLOW_SUSPEND reach the same arm with no code here -- so
 * what the codes below stand for is that arm, not a count of the surface. Each
 * lands in usbdev_ioctl's default arm, and what that arm answers on a device
 * that has gone is a row in tests/usbdev-ioctl-departed.tbl like any other:
 * scripts/gen-usbdev-ioctl-departed.py treats a request defined here and
 * dispatched nowhere as a driver for that arm, and refuses to emit while the
 * arm exists with no row behind it. Adding a case for one of these turns its
 * row into an ordinary dispatched row and changes nothing else.
 */
#define USBDEVFS_HUB_PORTINFO 0x80805513u
#define USBDEVFS_ALLOC_STREAMS 0x8008551cu
#define USBDEVFS_WAIT_FOR_RESUME 0x00005523u

/* Sub-codes of USBDEVFS_IOCTL (_IO('U', 22) / _IO('U', 23)). */
#define USBDEVFS_IOCTL_DISCONNECT 0x00005516
#define USBDEVFS_IOCTL_CONNECT 0x00005517

/* Capability bits (uapi/linux/usbdevice_fs.h:152-161). Every one of them
 * describes the SUBMITURB/REAPURB machinery, so the word names exactly what
 * this engine honors: ZERO_PACKET, which the completion callback emits, and
 * REAP_AFTER_DISCONNECT, since the reap arm answers ahead of the connected
 * gate. BULK_CONTINUATION stays clear because the flag is accepted without its
 * error-cascade unlink, and a guest that read the bit would rely on the
 * cascade; NO_PACKET_SIZE_LIM and BULK_SCATTER_GATHER describe URB splitting
 * IOKit does not expose. MMAP, DROP_PRIVILEGES, CONNINFO_EX and SUSPEND name
 * ioctls this layer does not serve (doc A section A7.7).
 */
#define USBDEVFS_CAP_ZERO_PACKET 0x01u
#define USBDEVFS_CAP_BULK_CONTINUATION 0x02u
#define USBDEVFS_CAP_NO_PACKET_SIZE_LIM 0x04u
#define USBDEVFS_CAP_BULK_SCATTER_GATHER 0x08u
#define USBDEVFS_CAP_REAP_AFTER_DISCONNECT 0x10u
#define USBDEV_CAPS \
    (USBDEVFS_CAP_ZERO_PACKET | USBDEVFS_CAP_REAP_AFTER_DISCONNECT)

#define USBDEVFS_DISCONNECT_CLAIM_IF_DRIVER 0x01u
#define USBDEVFS_DISCONNECT_CLAIM_EXCEPT_DRIVER 0x02u

typedef struct {
    uint8_t bRequestType;
    uint8_t bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
    uint32_t timeout; /* ms; 0 = unlimited */
    uint32_t pad;     /* natural LP64 hole before the pointer */
    uint64_t data;
} linux_usbdevfs_ctrltransfer_t; /* sizeof == 24, data at offset 16 */

typedef struct {
    uint32_t ep;
    uint32_t len;
    uint32_t timeout; /* ms; 0 = unlimited */
    uint32_t pad;
    uint64_t data;
} linux_usbdevfs_bulktransfer_t; /* sizeof == 24, data at offset 16 */

typedef struct {
    uint32_t interface;
    uint32_t altsetting;
} linux_usbdevfs_setinterface_t;

typedef struct {
    uint32_t interface;
    char driver[256];
} linux_usbdevfs_getdriver_t; /* sizeof == 260 */

typedef struct {
    uint32_t devnum;
    uint8_t slow;
    uint8_t pad[3];
} linux_usbdevfs_connectinfo_t; /* sizeof == 8 */

typedef struct {
    int32_t ifno;
    int32_t ioctl_code;
    uint64_t data;
} linux_usbdevfs_ioctl_t; /* sizeof == 16 */

typedef struct {
    uint32_t interface;
    uint32_t flags;
    char driver[256];
} linux_usbdevfs_disconnect_claim_t; /* sizeof == 264 */

/* struct usbdevfs_urb, LP64 (buffer at 16, usercontext at 48, sizeof 56). */
typedef struct {
    uint8_t type;
    uint8_t endpoint;
    uint16_t pad0;
    int32_t status;
    uint32_t flags;
    uint32_t pad1; /* natural hole before the pointer */
    uint64_t buffer;
    int32_t buffer_length;
    int32_t actual_length;
    int32_t start_frame;
    int32_t number_of_packets; /* union with stream_id */
    int32_t error_count;
    uint32_t signr;
    uint64_t usercontext;
} linux_usbdevfs_urb_t;

typedef struct {
    uint32_t signr;
    uint32_t pad;
    uint64_t context;
} linux_usbdevfs_disconnectsignal_t; /* sizeof == 16 */

/* Linux poll bits (asm-generic/poll.h). POLLWRNORM differs from macOS (0x100 vs
 * 0x004), so the guest-facing remap must use these, never the host's <poll.h>
 * values.
 */
#define LINUX_POLLIN 0x0001
#define LINUX_POLLOUT 0x0004
#define LINUX_POLLERR 0x0008
#define LINUX_POLLHUP 0x0010
#define LINUX_POLLNVAL 0x0020
#define LINUX_POLLWRNORM 0x0100

/* do_proc_control caps wLength at PAGE_SIZE (devio.c:1182-1183). */
#define USBDEV_CTRL_MAX 4096

/* usbfs_memory_mb: 16 MB by default (devio.c:134), and not a per-call size cap.
 * It is one module-global allowance for every usbfs transfer in flight, charged
 * by usbfs_increase_memory_usage and given back by usbfs_decrease_memory_usage
 * when the transfer settles (devio.c:145-178). Reading it as a per-call ceiling
 * got both halves wrong: a single request of exactly the allowance was
 * accepted, because only the buffer was measured and the URB was not, and
 * nothing accumulated across calls or across fds, so a guest holding every
 * side-table slot could keep USBDEV_MAX_FDS host buffers of that size alive at
 * once. The per-request half is what the lane asserts: len == the allowance is
 * ENOMEM, len just under it goes through twice, and it survives a faulting
 * transfer, so both refunds land. The across-fd half is what sharing one
 * counter adds, and it is not asserted anywhere -- the loopback model retires a
 * transfer before a second can overlap it, so concurrent charges never meet
 * there. Refusing 32 concurrent 16 MB requests does not show it either: the
 * per-request boundary already refuses every one of them on its own.
 */
#define USBDEV_MEMORY_MAX (16ull * 1024 * 1024)

/* Linux charges len + sizeof(struct urb), so a transfer of exactly the
 * allowance never fits (devio.c:1308). sizeof(struct urb) is kernel-internal
 * and config-dependent, and nothing on this side can observe it; what the model
 * has to reproduce is that the per-transfer charge strictly exceeds the length,
 * which is what decides the boundary case. The constant is named for that job
 * rather than claimed to be the kernel's number.
 */
#define USBDEV_URB_OVERHEAD 192ull

/* do_proc_control's charge, which is not the request's length: the kernel
 * bounces every control transfer through one whole page, so it books PAGE_SIZE
 * + sizeof(struct urb) + sizeof(struct usb_ctrlrequest) whatever wLength says
 * and gives the same amount back (devio.c:1187 and :1269). USBDEV_CTRL_MAX is
 * that page (it is the same devio.c:1185 bound), the URB stands in the way the
 * bulk path's does, and the setup packet is eight bytes in the kernel struct as
 * on the wire.
 */
#define USBDEV_CTRL_CHARGE \
    ((uint64_t) USBDEV_CTRL_MAX + USBDEV_URB_OVERHEAD + 8ull)

/* Bytes charged against USBDEV_MEMORY_MAX, summed across every fd. */
static _Atomic uint64_t usbdev_memory_usage;

/* usbfs_increase_memory_usage (devio.c:146-165): take the whole amount or none
 * of it. The compare-exchange stands in for the kernel's spinlock, and the sum
 * cannot overflow -- the ceiling bounds the accumulator and the caller has
 * already refused a length at INT32_MAX.
 */
static bool usbdev_memory_charge(uint64_t amount)
{
    uint64_t cur =
        atomic_load_explicit(&usbdev_memory_usage, memory_order_relaxed);
    do {
        if (cur + amount > USBDEV_MEMORY_MAX)
            return false;
    } while (!atomic_compare_exchange_weak_explicit(
        &usbdev_memory_usage, &cur, cur + amount, memory_order_acq_rel,
        memory_order_relaxed));
    return true;
}

/* usbfs_decrease_memory_usage (devio.c:168-178). Every exit from a charged
 * transfer owes this call, the error arms included: an allowance that is not
 * given back is one the next transfer never sees again.
 */
static void usbdev_memory_refund(uint64_t amount)
{
    atomic_fetch_sub_explicit(&usbdev_memory_usage, amount,
                              memory_order_release);
}

/* Ceiling on the callback-side ZERO_PACKET write. Linux has no equivalent (the
 * terminating packet is part of the URB, and a URB never times out), but the
 * one event thread this engine runs on carries every fd's completions, so an
 * endpoint that NAKs its ZLP must not be able to stop them.
 */
#define USBDEV_ZLP_TIMEOUT_MS 1000

/* How long an abort has to be answered before the URB it was issued for is
 * given up on and orphaned.
 *
 * Linux needs no such number: usb_kill_urb is synchronous, so usbdev_remove has
 * every URB back before any reaper can run. IOKit's AbortPipe is not, and a
 * wire that answers no abort at all would otherwise leave a disconnected fd
 * owing an answer for ever. It bounds both flavors of reap, which is the whole
 * of what makes -ENODEV reachable after a disconnect: the blocking one waits it
 * out, the non-blocking one cannot wait and so measures it instead.
 */
#define USBDEV_DRAIN_TIMEOUT_MS 2000

/* Milliseconds on CLOCK_MONOTONIC, for the drain deadline a non-blocking caller
 * measures rather than waits out.
 */
static int64_t usbdev_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* side table */

/* claimintf refuses ifnum >= 8 * sizeof(ps->ifclaimed) and ifclaimed is an
 * unsigned long (devio.c:75, :785), so the bound is 64 on every LP64 ABI elfuse
 * emulates, not 32. Between the two an interface number is merely absent, which
 * is -ENOENT from usb_ifnum_to_if, not -EINVAL.
 */
#define USBDEV_MAX_IFACES 64
#define USBDEV_MAX_PIPES 30

typedef struct {
    bool claimed;
    IOUSBInterfaceInterface800 **intf;
    CFRunLoopSourceRef src; /* async event source, on the event runloop */
    /* Orphaned in-flight URBs still referencing intf (async_lock, like the URB
     * lists): a drain timeout unlinks survivors from pending, so a later
     * release rescan finds nothing -- this count is what still proves the IOKit
     * handle must not be released. The late callback decrements it.
     */
    int orphans;
    int npipes;
    uint8_t pipe_ep[USBDEV_MAX_PIPES];   /* pipeRef-1 -> bEndpointAddress */
    uint8_t pipe_type[USBDEV_MAX_PIPES]; /* kUSBControl..kUSBInterrupt */
    uint16_t pipe_mps[USBDEV_MAX_PIPES]; /* wMaxPacketSize (ZLP check) */
} usbdev_iface_t;

typedef enum { URB_QUEUED, URB_INFLIGHT, URB_COMPLETED } urb_state_t;

struct usbdev; /* fwd */

/* One SUBMITURB. Guest data bounces through buf: copy-in at submit and copy-out
 * at reap both happen on the vCPU thread; the completion callback (event
 * thread) touches only this record and its owning static fd slot.
 */
typedef struct usbdev_urb {
    /* Two lists over one record, both under async_lock.
     *
     * next/prev is the fd-wide list, which is the pending list while the record
     * is QUEUED or INFLIGHT and the completed list afterwards; a record is on
     * exactly one of the two, so next is shared and prev is pending-only.
     * ep_next/ep_prev is the per-endpoint FIFO the same pending record sits in,
     * keyed by ep_key.
     *
     * The FIFO is what makes append, unlink and restart O(1). With the fd-wide
     * list alone every completion on one endpoint walked the queue of every
     * other, twice -- once to unlink and once to find the next record to start
     * -- and submit walked it a third time to decide whether the endpoint was
     * busy, all on the one event thread holding async_lock throughout. Measured
     * on the loopback fixture as the median of 31 submit-to-reap round trips on
     * one endpoint against a second endpoint's pending depth: without the FIFO
     * 0.017 ms at depth 0, 0.334 at 20k, 1.848 at 80k and 2.688 at 100k; with
     * it 0.016, 0.025, 0.020 and 0.021. Linux is O(1) both ways
     * (list_move_tail, devio.c:634). How deep that population can go is set by
     * the process-wide byte budget rather than by a URB count, and the three
     * added link words are what moved it: the record grows from 136 to 160
     * bytes, so 104857 zero-length records now fit in the 16 MB allowance where
     * 123361 did.
     */
    struct usbdev_urb *next;
    struct usbdev_urb *prev;
    struct usbdev_urb *ep_next, *ep_prev;

    /* Owning slot (static array, never freed). Atomic because the completion
     * callback has to know which async_lock to take before it can take one, so
     * this is the single field it reads outside the lock; the submitting thread
     * releases it, the event thread acquires it, and ThreadSanitizer -- which
     * cannot see through IODispatchCalloutFromCFMessage -- has an edge to
     * follow instead of a report to file.
     */
    _Atomic(struct usbdev *) u;
    uint64_t userurb;  /* guest pointer to struct usbdevfs_urb (reap key) */
    uint64_t data_gva; /* where IN data lands (urb buffer, +8 for control) */
    uint8_t type;      /* LINUX_URB_TYPE_* */
    uint8_t ep;        /* bEndpointAddress from the urb */
    uint8_t ep_key;    /* per-endpoint FIFO key; 0 = default control pipe */
    uint8_t pipe;      /* pipeRef; 0 = device ep0 */
    bool is_in;
    uint64_t seq;    /* identity a waiter can hold after the record dies */
    size_t charge;   /* bytes booked against the process-wide budget */
    bool discarding; /* DISCARDURB issued: abort reports -ENOENT */

    /* The two halves of an orphan's ownership, and the record is freed when
     * both are clear. orphaned: the drain deadline gave up on this record, its
     * buffer is still owned by an in-flight IOKit transfer and the late
     * callback is what clears it. handback: the same record is on the completed
     * list with the status usb_kill_urb leaves, and a reap (or the close that
     * frees the list) is what clears it. Whichever clears last frees; an
     * ordinary record has neither set and is freed by urb_free_locked.
     */
    bool orphaned;
    bool handback;
    bool zero_packet;    /* OUT + URB_ZERO_PACKET */
    bool short_not_ok;   /* IN + URB_SHORT_NOT_OK */
    bool pipe_interrupt; /* pipe is interrupt-type (no *TO entry points) */
    urb_state_t state;
    int32_t status; /* Linux URB status, valid once COMPLETED */
    uint32_t actual;
    uint32_t data_len; /* bounce buffer length (excludes control setup) */
    uint16_t mps;      /* endpoint wMaxPacketSize for the ZLP check */

    /* Which device handle an ep0 record's orphan pin was taken against, so a
     * late callback for a leaked handle cannot spend a reused slot's count --
     * the job the pointer match does for an interface's pin, which an ep0
     * record cannot do because it names no handle. A serial rather than the
     * pointer because it costs nothing: it sits in the padding ahead of the
     * pointers below. Meaningless unless orphaned is set.
     */
    uint32_t dev_pin;
    IOUSBInterfaceInterface800 **intf; /* pinned at submit; NULL for ep0 */
    uint8_t *buf;                      /* host bounce buffer */
    IOUSBDevRequestTO req;             /* control only */
} usbdev_urb_t;

static inline void urb_owner_store(usbdev_urb_t *rec, struct usbdev *u)
{
    atomic_store_explicit(&rec->u, u, memory_order_release);
}

static inline struct usbdev *urb_owner(const usbdev_urb_t *rec)
{
    return atomic_load_explicit(&rec->u, memory_order_acquire);
}

/* The URB engine charges the same allowance the synchronous transfers charge,
 * because Linux has one: usbfs_memory_usage is a single kernel-wide static
 * (devio.c:143-178). Two counters of 16 MB each would let the async path queue
 * a second budget behind whatever a BULK ioctl already holds.
 *
 * What this path adds is that the bound is a byte count, not a URB count. Both
 * halves matter: a per-fd budget let a second fd queue another 16 MB, and the
 * 256-record backstop this engine shipped first refused a 257th eight-byte URB
 * -- 2 KB against a 16 MB budget -- which is exactly the deep ring libusb's
 * async API builds for bulk streaming. The record itself is charged alongside
 * its buffer so a flood of zero-length URBs is bounded too, the way Linux
 * charges len + sizeof(struct urb).
 */

typedef struct usbdev {
    bool used; /* slot allocated (table lock) */
    bool dead; /* torn down, awaiting slot release (table lock) */
    int refs;  /* live usbdev_acquire pins (table lock) */
    int guest_fd;
    uint64_t generation; /* fd-table generation captured at open (ABA) */
    int busnum, devnum;
    uint32_t location_id;
    unsigned vid, pid; /* modeled identity, re-checked at every lookup */
    char serial[128];
    unsigned speed_code; /* raw registry 'Device Speed' */
    unsigned cfg_value;  /* active bConfigurationValue */
    uint8_t *blob;       /* usbfs descriptors blob (read() source) */
    size_t blob_len;
    off_t pos;   /* read()/lseek() file position */
    int pipe_wr; /* write end of the readiness pipe (holds one token) */
    io_service_t service; /* retained IOUSBDevice service */

    /* ELFUSE_USB_FIXTURE=loopback stands this device up behind the IOKit COM
     * seam instead of a wire. Resolved once, at the first call that needs the
     * device, and then read as a plain field: no path re-reads the environment.
     * service stays IO_OBJECT_NULL for such a device rather than holding a
     * synthetic port, so every IOObjectRelease and the NULL-service guard in
     * usbdev_arm_disconnect_watch stay correct without a special case.
     */
    bool fake;
    IOUSBDeviceInterface650 **dev; /* lazily created device plugin */
    bool dev_open;                 /* USBDeviceOpen succeeded */
    bool dev_open_tried;
    CFRunLoopSourceRef dev_src; /* ep0 async event source (lazy) */
    io_object_t notif;          /* interest notification (disconnect) */
    usbdev_iface_t ifaces[USBDEV_MAX_IFACES];

    /* Lock-free mirrors for cross-fd reads (SETCONFIGURATION's device-wide
     * claim check): claimed_mask mirrors ifaces[].claimed bit-per-interface,
     * devkey names the bound device (nonzero while bound). A handler runs under
     * its own entry lock, and no path takes a second entry lock while holding
     * one -- an entry lock can be held across a whole transfer timeout, so
     * waiting on a peer's would stall this fd for as long as that peer's
     * transfer, and two fds doing it in opposite order would deadlock. Another
     * slot's entry lock is therefore never taken here; the atomics are read
     * instead.
     */
    _Atomic uint64_t claimed_mask;
    _Atomic uint64_t devkey;

    /* Guards every field above except used/dead/refs/guest_fd/generation, which
     * the table lock guards, and the atomic mirrors.
     *
     * Held across the blocking IOKit transfer calls, so two ioctls on one fd
     * serialize. Linux does NOT: do_proc_control and do_proc_bulk drop the
     * device lock around usbfs_start_wait_urb and retake it after
     * (devio.c:1219/1245 and :1337/1357), so a trivial ioctl on the same fd
     * answers while a transfer is in flight. Measured here, a GET_SPEED issued
     * during a 6 s BULK on the same fd waits 5970 ms. Dropping the lock needs
     * the interface handle to be refcounted so a concurrent RELEASEINTERFACE
     * cannot close it under the transfer, which is the async stage's machinery;
     * until then this is a recorded deviation, not the kernel behavior it used
     * to claim to be. What it is not any more is cross-fd: the lock is no
     * longer taken underneath the table lock.
     */
    pthread_mutex_t lock;

    /* --- async URB state, guarded by async_lock, which is never held across a
     * blocking IOKit call: the callback-side ZLP WritePipe drops it first, and
     * the cross-fd disconnect walk takes peers' beneath the table lock on the
     * strength of that. The completion callback and the disconnect notification
     * run on the event thread and take ONLY this lock, so a vCPU thread parked
     * in a sync transfer under the entry lock cannot stall completions on other
     * endpoints. Lock order: lock -> async_lock. pipe_wr may additionally be
     * written under async_lock (teardown sets it to -1 under both locks before
     * closing).
     */
    pthread_mutex_t async_lock;
    pthread_cond_t async_cv; /* completion / in-flight drain */
    usbdev_urb_t *pending_head, *pending_tail;     /* QUEUED + INFLIGHT */
    usbdev_urb_t *completed_head, *completed_tail; /* reapable, FIFO */

    /* The same pending records, split per FIFO key. The head of a key is the
     * oldest record on that endpoint, so it is the INFLIGHT one when the
     * endpoint has one and the next to start otherwise -- which is the whole of
     * what usbdev_kick_ep_locked and SUBMITURB used to walk the fd-wide list to
     * learn. One entry per bEndpointAddress plus the shared ep0 key.
     */
    usbdev_urb_t *ep_head[256], *ep_tail[256];
    int inflight;          /* URB_INFLIGHT count */
    int nurbs;             /* live records (pending + completed) */
    size_t inflight_bytes; /* this slot's share of the global budget */
    uint64_t urb_seq;      /* monotonic record id within the slot */

    /* AbortPipe cancels every transfer outstanding on a pipe, so an endpoint
     * whose own abort is still running may not start the URB behind it:
     * ep_aborting counts the aborts in progress per FIFO key and draining shuts
     * the whole slot for a wholesale kill.
     *
     * An invariant of the paths that abort deliberately, not of the slot. The
     * two that raise it are DISCARDURB and every kill routed through
     * usbdev_abort_urbs_locked; CLEAR_HALT and RESETEP do not, because
     * ClearPipeStallBothEnds aborts the pipe as a side effect of the stall
     * clear and there is no IOKit variant that does not. A queued follower can
     * therefore be started behind a stall clear's abort. The guest-visible half
     * of that gap is the clear-halt-collateral XFAIL in
     * tests/test-usbdev-ioctl.c; closing it needs the count, the release and
     * the kick DISCARDURB spells out around its own abort, so it is recorded
     * here rather than half-raised. usbdev_iface_t.orphans for the device
     * handle: an orphaned ep0 record references u->dev and u->dev_src and
     * nothing else, so the per-interface count cannot speak for it and
     * usbdev_teardown_locked had nothing left to read. A whole-slot drain
     * unlinks the record from pending, so the rescan inside
     * usbdev_kill_urbs_locked comes back clean and reports drained -- measured
     * as close() releasing u->dev with a DeviceRequestAsyncTO still
     * outstanding, no leaking-handle line printed, where the same scenario on
     * an interface endpoint prints one. async_lock, like the URB lists.
     */
    int dev_orphans;

    /* Names the device handle those orphans were taken against: bumped, never
     * reused, every time a handle is published, so a pin recorded against a
     * previous (leaked) handle of this slot cannot match. 0 is "no handle",
     * which no record's pin ever carries.
     */
    uint32_t dev_serial;

    uint16_t ep_aborting[256];
    bool draining;
    bool disc_drained; /* the post-disconnect aborts have been issued */

    /* When the aborts disc_drained records are given up on: they were issued
     * one drain deadline before this. Meaningful only while disc_drained is
     * set, and it is what lets a reap that may not wait still reach the end of
     * the conversation -- see usbdev_do_reap.
     */
    int64_t disc_orphan_at_ms;

    /* The cross-fd disconnect walk still owes this slot a pass. Set by the
     * disconnect stamp, which two of its callers reach with async_lock held,
     * and consumed by usbdev_flush_disc_peers once that lock is gone: the walk
     * takes one peer's async_lock at a time and may not run underneath another.
     * Atomic because it is read outside async_lock.
     */
    _Atomic bool disc_peers_pending;
    bool ready_token;       /* the readiness pipe is holding its one token */
    bool disconnected;      /* device gone; mirrored in usbdev_disc_map */
    uint32_t discsig_signr; /* DISCSIGNAL, stored but never delivered */
    uint64_t discsig_context;
} usbdev_t;

_Static_assert(USBDEV_MAX_IFACES <= 64,
               "claimed_mask carries one bit per interface");

/* The one definition of how the lock-free cross-fd mirrors are reached.
 *
 * claimed_mask and devkey are read without the owning entry lock by
 * usbdev_claimed_elsewhere, which walks the other slots on SETCONFIGURATION
 * while holding its own entry lock, where no second entry lock may be taken.
 * devkey is the publish flag: a binder resets claimed_mask to 0 and then stores
 * the new key, and the reader tests devkey == key before it reads claimed_mask,
 * so the key store releases and the key load acquires. Ordering the
 * claimed_mask reset before the key release is what stops a slot recycled to
 * the same bus/dev from exposing the new key beside a stale nonzero mask left
 * by its previous life, which would be a spurious -EBUSY. The mask's own
 * set/clear ride the same release so a cross-fd reader that already matched an
 * unchanged key still sees a fresh claim; every mutator otherwise runs under
 * the entry lock, which is the whole ordering requirement.
 */
static inline void claimed_mask_set(usbdev_t *u, unsigned bit)
{
    atomic_fetch_or_explicit(&u->claimed_mask, 1ull << bit,
                             memory_order_release);
}

static inline void claimed_mask_clear(usbdev_t *u, unsigned bit)
{
    atomic_fetch_and_explicit(&u->claimed_mask, ~(1ull << bit),
                              memory_order_release);
}

static inline void claimed_mask_reset(usbdev_t *u)
{
    atomic_store_explicit(&u->claimed_mask, 0, memory_order_release);
}

static inline uint64_t claimed_mask_load(const usbdev_t *u)
{
    return atomic_load_explicit(&u->claimed_mask, memory_order_acquire);
}

static inline void devkey_publish(usbdev_t *u, uint64_t key)
{
    atomic_store_explicit(&u->devkey, key, memory_order_release);
}

static inline void devkey_retire(usbdev_t *u)
{
    atomic_store_explicit(&u->devkey, 0, memory_order_release);
}

static inline uint64_t devkey_load(const usbdev_t *u)
{
    return atomic_load_explicit(&u->devkey, memory_order_acquire);
}

/* usbdev_table_lock is never held together with a per-entry lock: a lookup
 * finds its entry under the table lock, drops it, and only then takes the entry
 * lock, because a sync transfer holds an entry lock for a whole timeout and no
 * other fd may wait behind it. What pins the slot across the gap is the refs
 * and dead pair the lookup sets under the table lock, not a nesting. The table
 * lock is also a leaf with respect to fd_lock (never held while taking it, and
 * vice versa). See internal.h's lock order block.
 */
static pthread_mutex_t usbdev_table_lock = PTHREAD_MUTEX_INITIALIZER;
static usbdev_t usbdev_fds[USBDEV_MAX_FDS];
static bool usbdev_ready;

/* Lock-free "this guest fd's usbdev device is gone" map for the poll/epoll
 * remap helpers: they run on hot poll paths and must not queue behind an entry
 * lock held across a blocking sync transfer. Set by the event thread at
 * disconnect, cleared when the guest fd is bound or torn down. A stale bit on a
 * reused fd number is harmless: the helpers check the fd type first, and
 * binding a new usbdev fd clears it.
 */
static _Atomic uint8_t usbdev_disc_map[FD_TABLE_SIZE];

/* Companion map: "this guest fd has a reapable completion". usbfs poll grants
 * POLLOUT|POLLWRNORM only while async_completed is non-empty (devio.c poll);
 * the readiness pipe alone cannot say that, because a disconnect writes a wake
 * byte too. Maintained under async_lock wherever the completed list changes;
 * read lock-free on the poll paths, same discipline as usbdev_disc_map.
 */
static _Atomic uint8_t usbdev_ready_map[FD_TABLE_SIZE];

/* The one definition of how the two lock-free poll maps are reached.
 *
 * Both are published on the event thread under async_lock (disc_map at
 * disconnect in mark_disconnected_locked, ready_map whenever the completed list
 * changes in usbdev_ready_sync) and read with no lock by the poll/epoll remap
 * helpers usbdev_fd_disconnected and usbdev_fd_reapable. The publish releases
 * and the load acquires so a poller that observes the flag also observes the
 * list state behind it. The URB buffer a later REAPURB copies out is not
 * ordered by these: the callback fills it under async_lock and REAPURB
 * re-acquires async_lock to pop it, so that release/acquire pair plus the pipe
 * wake are the real payload synchronization, and the lock-free poller only ever
 * consumes the boolean flag. The clears run on the owning vCPU during bind and
 * teardown with no lock-free reader chasing a cleared bit, so relaxed is
 * enough. Callers pass a range-checked guest fd.
 */
static inline void discmap_set(int gfd)
{
    atomic_store_explicit(&usbdev_disc_map[gfd], 1, memory_order_release);
}

static inline void discmap_clear(int gfd)
{
    atomic_store_explicit(&usbdev_disc_map[gfd], 0, memory_order_relaxed);
}

static inline bool discmap_load(int gfd)
{
    return atomic_load_explicit(&usbdev_disc_map[gfd], memory_order_acquire) !=
           0;
}

static inline void readymap_store(int gfd, bool ready)
{
    atomic_store_explicit(&usbdev_ready_map[gfd], ready, memory_order_release);
}

static inline void readymap_clear(int gfd)
{
    atomic_store_explicit(&usbdev_ready_map[gfd], 0, memory_order_relaxed);
}

static inline bool readymap_load(int gfd)
{
    return atomic_load_explicit(&usbdev_ready_map[gfd], memory_order_acquire) !=
           0;
}

/* IOReturn -> -LINUX_E* (doc D table (b)) */

#ifndef kUSBHostReturnPipeStalled
#define kUSBHostReturnPipeStalled 0xe0005000u
#endif

/* ioret_neg_errno for a guest-visible op on a slot: the same translation, plus
 * the disconnect that a device-gone answer originates.
 *
 * Every op goes through this rather than through the bare translation, because
 * a disconnect is a fact about the device and the fd that noticed it is only
 * whichever one happened to ask first. Defined next to the disconnect machinery
 * below; declared here so the ops above it can use it.
 */
static int64_t usbdev_ioret_op(usbdev_t *u, IOReturn r);
static bool usbdev_ioret_device_gone(IOReturn r);

static int64_t ioret_neg_errno(IOReturn r)
{
    switch ((uint32_t) r) {
    case kIOReturnSuccess:
    case kIOReturnUnderrun: /* short transfer == success for usbfs */
        return 0;
    case kIOUSBPipeStalled:
    case kUSBHostReturnPipeStalled:
        return -LINUX_EPIPE;
    case kIOUSBTransactionTimeout:
        return -LINUX_ETIMEDOUT;
    case kIOReturnNoDevice:
    case kIOReturnNotOpen:
    case kIOReturnNotAttached:
        return -LINUX_ENODEV;
    case kIOReturnOverrun:
        return -LINUX_EOVERFLOW;
    case kIOReturnAborted:
        /* A sync transfer that comes back Aborted was already on the wire
         * (another thread's DISCARDURB/teardown aborted the pipe), so the
         * dispatcher must not re-execute the ioctl and send it again. The flag
         * is thread-local; on the event thread (urb status mapping, never a
         * syscall return) it is dead state and harmless.
         */
        syscall_restart_forbid();
        return -LINUX_EINTR;
    case kIOReturnExclusiveAccess:
    case kIOReturnBusy:
        return -LINUX_EBUSY;
    case kIOReturnNotPermitted:
    case kIOReturnNotPrivileged:
        return -LINUX_EACCES;
    case kIOReturnBadArgument:
        return -LINUX_EINVAL;
    case kIOReturnNoMemory:
    case kIOReturnNoResources:
    case kIOReturnCannotWire:
        return -LINUX_ENOMEM;
    case kIOReturnUnsupported:
        return -LINUX_ENOTTY;
    case kIOUSBUnknownPipeErr:
    case kIOUSBEndpointNotFound:
    case kIOUSBInterfaceNotFound:
        return -LINUX_ENOENT;
    case kIOReturnNotResponding:
        return -LINUX_ETIME;
    default:
        return -LINUX_EPROTO;
    }
}

/* IOKit helpers */

static long usbdev_ioreg_num(io_service_t s, const char *key)
{
    CFStringRef k = CFStringCreateWithCString(kCFAllocatorDefault, key,
                                              kCFStringEncodingUTF8);
    if (!k)
        return -1;
    CFTypeRef v = IORegistryEntryCreateCFProperty(s, k, kCFAllocatorDefault, 0);
    CFRelease(k);
    long n = -1;
    if (v && CFGetTypeID(v) == CFNumberGetTypeID())
        CFNumberGetValue((CFNumberRef) v, kCFNumberLongType, &n);
    if (v)
        CFRelease(v);
    return n;
}

static bool usbdev_ioreg_str(io_service_t s,
                             const char *key,
                             char *out,
                             size_t n)
{
    CFStringRef k = CFStringCreateWithCString(kCFAllocatorDefault, key,
                                              kCFStringEncodingUTF8);
    if (!k)
        return false;
    CFTypeRef v = IORegistryEntryCreateCFProperty(s, k, kCFAllocatorDefault, 0);
    CFRelease(k);
    out[0] = '\0';
    bool ok = false;
    if (v && CFGetTypeID(v) == CFStringGetTypeID())
        ok = CFStringGetCString((CFStringRef) v, out, (CFIndex) n,
                                kCFStringEncodingUTF8) &&
             out[0] != '\0';
    if (v)
        CFRelease(v);
    return ok;
}

/* The modeled bus/dev numbers name a device observed at model-build time; the
 * locationID they map back to names a PORT. If the device was swapped since
 * (unplug + different device into the same port, model not rebuilt), the
 * location lookup happily returns the newcomer. Compare the live registry
 * identity against the modeled one so an open cannot hand the guest a device
 * other than the one its descriptors blob describes.
 */
static bool usbdev_identity_matches(io_service_t svc,
                                    unsigned want_vid,
                                    unsigned want_pid,
                                    const char *want_serial)
{
    long vid = usbdev_ioreg_num(svc, "idVendor");
    long pid = usbdev_ioreg_num(svc, "idProduct");
    if (vid != (long) want_vid || pid != (long) want_pid)
        return false;

    /* "USB Serial Number" is the property name. kUSBSerialNumberString is the
     * SDK macro that spells it (USBSpec.h), and passing the macro's own name as
     * the key made the first lookup unmatchable, so only the fallback ever did
     * anything. One lookup, one spelling.
     */
    char serial[128] = "";
    (void) usbdev_ioreg_str(svc, "USB Serial Number", serial, sizeof(serial));
    return strcmp(serial, want_serial) == 0;
}

/* Retained IOUSBDevice service whose locationID matches, or IO_OBJECT_NULL. */
static io_service_t usbdev_service_for_location(uint32_t location_id)
{
    CFMutableDictionaryRef match = IOServiceMatching("IOUSBDevice");
    if (!match)
        return IO_OBJECT_NULL;
    io_iterator_t it = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, match, &it) !=
        kIOReturnSuccess)
        return IO_OBJECT_NULL;
    io_service_t found = IO_OBJECT_NULL;
    io_service_t svc;
    while ((svc = IOIteratorNext(it))) {
        if (found == IO_OBJECT_NULL &&
            usbdev_ioreg_num(svc, "locationID") == (long) location_id) {
            found = svc; /* keep the iterator's reference */
            continue;
        }
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);
    return found;
}

/* Resolve u->service on first use, or 0 when this port carries no device with
 * the modeled identity.
 *
 * The lookup is deferred rather than done in the constructor because open(2)
 * must not disagree with the names beside it: stat, access and an O_PATH open
 * of the same node are all answered from the model, so requiring live hardware
 * at open time made a plain O_RDONLY the one entry point that reported ENODEV
 * for a node the other four described. It also took the ELFUSE_USB_FIXTURE
 * model, whose devices have no IOKit service at all, out of reach of every
 * assertion about this fd. Deferring moves the missing-device answer onto the
 * operations that actually need the wire, where -ENODEV is what Linux reports
 * for a device that is gone.
 */
static int64_t usbdev_ensure_service(usbdev_t *u)
{
    if (u->fake || u->service != IO_OBJECT_NULL)
        return 0;

    /* Fixture seam (syscall/usbdev-fixture.h), and the only place the flag is
     * set. It answers for one modeled location and identity, so every other
     * device -- including the other ELFUSE_USB_FIXTURE models, whose nodes have
     * no service at all -- takes the registry path below unchanged.
     */
    if (usbdev_fixture_has_device(u->location_id, u->vid, u->pid)) {
        u->fake = true;
        return 0;
    }
    io_service_t svc = usbdev_service_for_location(u->location_id);
    if (svc == IO_OBJECT_NULL)
        return -LINUX_ENODEV;
    if (!usbdev_identity_matches(svc, u->vid, u->pid, u->serial)) {
        /* The port holds some device, but not the modeled one. */
        IOObjectRelease(svc);
        return -LINUX_ENODEV;
    }
    u->service = svc;
    return 0;
}

/* Create u->dev on first use. GetConfigurationDescriptorPtr-class calls and
 * CreateInterfaceIterator need only the plugin, not USBDeviceOpen. Publish a
 * freshly created device handle (entry lock held).
 *
 * Under async_lock for the reason usbdev_claim_locked publishes an interface
 * handle under it: the orphan bookkeeping reads the pair with only that lock
 * held. A stale orphan count belongs to a previous (leaked) handle of this
 * slot, so it starts over at zero beside the handle it counts for.
 */
static void usbdev_publish_dev_locked(usbdev_t *u,
                                      IOUSBDeviceInterface650 **dev)
{
    static _Atomic uint32_t usbdev_dev_serial;
    pthread_mutex_lock(&u->async_lock);
    u->dev = dev;
    u->dev_orphans = 0;
    u->dev_serial =
        atomic_fetch_add_explicit(&usbdev_dev_serial, 1, memory_order_relaxed) +
        1;
    pthread_mutex_unlock(&u->async_lock);
}

static int64_t usbdev_ensure_dev_plugin(usbdev_t *u)
{
    if (u->dev)
        return 0;
    int64_t srv = usbdev_ensure_service(u);
    if (srv < 0)
        return srv;
    if (u->fake) {
        IOUSBDeviceInterface650 **dev = NULL;
        int64_t frc =
            usbdev_fixture_open_device(u->location_id, u->vid, u->pid, &dev);
        if (frc < 0)
            return frc;
        usbdev_publish_dev_locked(u, dev);
        return 0;
    }
    IOCFPlugInInterface **plug = NULL;
    SInt32 score = 0;
    IOReturn r = IOCreatePlugInInterfaceForService(
        u->service, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &plug,
        &score);
    if (r != kIOReturnSuccess || !plug) {
        log_warn("usbdev: device plugin for %d-%d failed 0x%x", u->busnum,
                 u->devnum, r);
        return r == kIOReturnSuccess ? -LINUX_ENOMEM : usbdev_ioret_op(u, r);
    }
    IOUSBDeviceInterface650 **dev = NULL;
    HRESULT hr = (*plug)->QueryInterface(
        plug, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID650), (LPVOID *) &dev);
    (*plug)->Release(plug);
    if (hr != S_OK || !dev)
        return -LINUX_ENOMEM;
    usbdev_publish_dev_locked(u, dev);
    return 0;
}

/* Lazy exclusive device open; kIOReturnExclusiveAccess is tolerated the way
 * libusb tolerates it (device stays usable for ep0 requests and interface
 * claims; only SetConfiguration demands a real open).
 */
static void usbdev_lazy_device_open(usbdev_t *u)
{
    if (u->dev_open || u->dev_open_tried || !u->dev)
        return;
    u->dev_open_tried = true;
    IOReturn r = (*u->dev)->USBDeviceOpen(u->dev);
    if (r == kIOReturnSuccess) {
        u->dev_open = true;
    } else {
        /* Tolerated as a failure, but still translated: a device-gone code here
         * is the same news usbdev_ioret_op stamps everywhere else, and dropping
         * it would leave a caller that only ever takes this path unmarked. What
         * is tolerated is the refusal, not the disconnect.
         */
        (void) usbdev_ioret_op(u, r);
        log_debug("usbdev: USBDeviceOpen %d-%d -> 0x%x (tolerated)", u->busnum,
                  u->devnum, r);
    }
}

/* Iterator over every interface of the device in the active configuration, or
 * IO_OBJECT_NULL. The one place the enumeration is opened, so the invariant
 * below holds for every op that asks the device about its interfaces.
 *
 * Invariant: IO_OBJECT_NULL is never returned without *err saying which of the
 * two answers it is. 0 means the enumeration ran, so the caller's own not-found
 * errno stands; a negative value means the enumeration itself failed and is
 * that failure's errno, which for a device-gone code is the whole answer --
 * Linux's usbdev_do_ioctl gate turns every one of these ops into -ENODEV once
 * connected() is false. A failed enumeration is never "no interface matched":
 * the question was not answered at all.
 */
static io_iterator_t usbdev_iface_iterator(usbdev_t *u, int64_t *err)
{
    *err = usbdev_ensure_dev_plugin(u);
    if (*err < 0)
        return IO_OBJECT_NULL;
    IOUSBFindInterfaceRequest fr = {
        .bInterfaceClass = kIOUSBFindInterfaceDontCare,
        .bInterfaceSubClass = kIOUSBFindInterfaceDontCare,
        .bInterfaceProtocol = kIOUSBFindInterfaceDontCare,
        .bAlternateSetting = kIOUSBFindInterfaceDontCare,
    };
    io_iterator_t it = IO_OBJECT_NULL;
    IOReturn r = (*u->dev)->CreateInterfaceIterator(u->dev, &fr, &it);
    if (r != kIOReturnSuccess) {
        *err = usbdev_ioret_op(u, r);
        return IO_OBJECT_NULL;
    }
    return it;
}

/* Retained IOUSBHostInterface service for bInterfaceNumber ifnum in the active
 * configuration, or IO_OBJECT_NULL. Uses the enumeration above so "exists"
 * means exactly what claimintf's usb_ifnum_to_if means, and carries its err out
 * unchanged: dropping it left these ops answering -ENODATA and -EINVAL (no such
 * interface) on a device that was gone, and left the fd unstamped, so the ioctl
 * after them answered wrongly too.
 */
static io_service_t usbdev_iface_service(usbdev_t *u,
                                         unsigned ifnum,
                                         int64_t *err)
{
    io_iterator_t it = usbdev_iface_iterator(u, err);
    if (it == IO_OBJECT_NULL)
        return IO_OBJECT_NULL;
    io_service_t found = IO_OBJECT_NULL;
    io_service_t svc;
    while ((svc = IOIteratorNext(it))) {
        if (found == IO_OBJECT_NULL &&
            usbdev_ioreg_num(svc, "bInterfaceNumber") == (long) ifnum) {
            found = svc;
            continue;
        }
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);
    return found;
}

/* Put the device question to IOKit, and answer only that: 0 once the
 * enumeration has run, the device's own errno when it could not.
 *
 * Invariant at every caller below: none of them answers anything -- not an
 * interface, not an interface number out of range, not a RESET that touches no
 * pipe -- until the device has been asked in that call. Linux gets it from
 * usbdev_do_ioctl's connected() gate, which reads device state ahead of
 * proc_getdriver, proc_disconnect_claim, proc_ioctl, proc_resetdevice and
 * proc_claiminterface, so the argument checks inside those live behind it; here
 * neither of the two things they read is device state. u->dev is a cached
 * handle usbdev_ensure_dev_plugin hands back without a call, and a claim is
 * this layer's own bookkeeping, which stays true after the device leaves. Only
 * a question to IOKit can come back with a device-gone code, which is what
 * usbdev_ioret_op turns into the -ENODEV and the disconnect stamp the rest of
 * the fd then answers from.
 */
static int64_t usbdev_ensure_dev_reachable(usbdev_t *u)
{
    int64_t err;
    io_iterator_t it = usbdev_iface_iterator(u, &err);
    if (err < 0)
        return err;
    if (it != IO_OBJECT_NULL)
        IOObjectRelease(it);
    return 0;
}

/* "Kernel driver bound" == the interface service has a driver child in the
 * service plane (libusb darwin_usb.c:2761-2785). Fills name (class name,
 * truncated) when one exists.
 *
 * A user client is not a driver. IOKit publishes an
 * AppleUSBHostInterfaceUserClient child for every USBInterfaceOpen, this
 * layer's own included, so taking the first child of any class reported a peer
 * usbfs consumer -- another elfuse process, or another fd of this one -- as a
 * bound host driver, and that answer drove GETDRIVER, DISCONNECT_CLAIM and
 * SETCONFIGURATION. Walk the children and answer for the first one that is not
 * a user client.
 */
static bool usbdev_iface_driver(io_service_t ifs, char *name, size_t n)
{
    io_iterator_t it = IO_OBJECT_NULL;
    if (IORegistryEntryGetChildIterator(ifs, kIOServicePlane, &it) !=
            kIOReturnSuccess ||
        it == IO_OBJECT_NULL)
        return false;
    bool bound = false;
    io_registry_entry_t child;
    while ((child = IOIteratorNext(it))) {
        if (!bound && !IOObjectConformsTo(child, "IOUserClient")) {
            io_name_t cls;
            if (IOObjectGetClass(child, cls) == kIOReturnSuccess)
                str_copy_trunc(name, cls, n);
            else
                str_copy_trunc(name, "unknown", n);
            bound = true;
        }
        IOObjectRelease(child);
    }
    IOObjectRelease(it);
    return bound;
}

/* Returns 0, or the negative Linux errno IOKit's answer maps to: a device
 * pulled out mid-claim answers kIOReturnNoDevice, which is the -ENODEV Linux
 * reports for it, and flattening every failure here into -EIO renamed that as
 * an I/O error. -EIO stays only for a code the map has no entry for.
 */
static int64_t usbdev_build_pipe_map(usbdev_t *u, usbdev_iface_t *fi)
{
    /* Clear the whole map, not just the count: a GetPipeProperties failure at
     * one pipeRef of a SETINTERFACE rebuild used to leave the previous
     * altsetting's address at that index while npipes still covered it, so a
     * later lookup could match a stale address and return a pipeRef that now
     * means a different endpoint.
     */
    fi->npipes = 0;
    memset(fi->pipe_ep, 0, sizeof(fi->pipe_ep));
    memset(fi->pipe_type, 0, sizeof(fi->pipe_type));
    memset(fi->pipe_mps, 0, sizeof(fi->pipe_mps));
    UInt8 ne = 0;
    IOReturn r = (*fi->intf)->GetNumEndpoints(fi->intf, &ne);
    if (r != kIOReturnSuccess) {
        int64_t err = usbdev_ioret_op(u, r);
        return err < 0 ? err : -LINUX_EIO;
    }
    if (ne > USBDEV_MAX_PIPES)
        ne = USBDEV_MAX_PIPES;
    for (UInt8 p = 1; p <= ne; p++) {
        UInt8 dir = 0, num = 0, type = 0, interval = 0;
        UInt16 mps = 0;
        IOReturn pr = (*fi->intf)->GetPipeProperties(fi->intf, p, &dir, &num,
                                                     &type, &mps, &interval);
        if (pr != kIOReturnSuccess) {
            /* A device-gone code is an answer about the device and not about
             * this pipeRef, so it ends the build and is reported: asking the
             * next pipeRef a question already answered leaves a claim that
             * succeeded with a short pipe map, whose SUBMITURB then answers
             * -ENOENT (no such endpoint) where Linux answers -ENODEV. Any other
             * code is about this pipeRef alone -- the map was cleared above, so
             * skipping it leaves no stale address behind -- and the interface
             * keeps the endpoints IOKit did describe.
             */
            int64_t perr = usbdev_ioret_op(u, pr);
            if (usbdev_ioret_device_gone(pr))
                return perr < 0 ? perr : -LINUX_ENODEV;
            continue;
        }
        fi->pipe_ep[p - 1] = (uint8_t) (num | (dir == kUSBIn ? 0x80 : 0));
        fi->pipe_type[p - 1] = type;
        fi->pipe_mps[p - 1] = mps;
        fi->npipes = p;
    }
    return 0;
}

/* async engine: event thread, URB lists, completions
 *
 * One host thread per elfuse process runs a CFRunLoop; per-open-device
 * (CreateDeviceAsyncEventSource) and per-claimed-interface
 * (CreateInterfaceAsyncEventSource) sources are added to it from vCPU threads,
 * exactly libusb's darwin model (darwin_usb.c:1910-1927, 2283-2294). Chosen
 * over the CreateDeviceAsyncPort + mach_msg alternative because the runloop
 * also carries the IONotificationPort for disconnect interest messages with no
 * extra plumbing.
 *
 * The thread is started lazily on the first async submit and never joined: exec
 * keeps the host process (side tables survive), and after guest_destroy the
 * callbacks only touch usbdev-owned host memory (static fd slots, malloc'd URB
 * records, the completion pipe), never guest memory -- the copy-in/copy-out
 * happens on vCPU threads (netlink.c:1733-1738 warning).
 */

#ifndef kIOUSBTransactionReturned
#define kIOUSBTransactionReturned 0xe0004050u
#endif

static pthread_mutex_t usbdev_loop_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t usbdev_loop_cv = PTHREAD_COND_INITIALIZER;
static CFRunLoopRef usbdev_loop; /* set once by the event thread */
static bool usbdev_loop_started;
static IONotificationPortRef usbdev_notify_port; /* loop lock */

static void usbdev_loop_keepalive(void *info)
{
    (void) info;
}

static void *usbdev_loop_main(void *arg)
{
    (void) arg;

    /* A permanent dummy source keeps CFRunLoopRun from returning while no
     * device/interface source is attached.
     */
    CFRunLoopSourceContext ctx = {.perform = usbdev_loop_keepalive};
    CFRunLoopSourceRef keep =
        CFRunLoopSourceCreate(kCFAllocatorDefault, 0, &ctx);
    if (keep)
        CFRunLoopAddSource(CFRunLoopGetCurrent(), keep, kCFRunLoopDefaultMode);
    usbdev_fixture_bind_loop(CFRunLoopGetCurrent());
    pthread_mutex_lock(&usbdev_loop_lock);
    usbdev_loop = CFRunLoopGetCurrent();
    pthread_cond_broadcast(&usbdev_loop_cv);
    pthread_mutex_unlock(&usbdev_loop_lock);
    CFRunLoopRun();

    /* Unreached in practice: the keepalive source pins the loop until the
     * process exits.
     */
    if (keep)
        CFRelease(keep);
    return NULL;
}

/* Start (once) and return the event runloop; NULL only if thread creation
 * failed.
 */
static CFRunLoopRef usbdev_loop_get(void)
{
    pthread_mutex_lock(&usbdev_loop_lock);
    if (!usbdev_loop_started) {
        pthread_t t;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&t, &at, usbdev_loop_main, NULL) == 0)
            usbdev_loop_started = true;
        else
            log_warn("usbdev: event thread creation failed");
        pthread_attr_destroy(&at);
    }
    while (usbdev_loop_started && !usbdev_loop)
        pthread_cond_wait(&usbdev_loop_cv, &usbdev_loop_lock);
    CFRunLoopRef l = usbdev_loop;
    pthread_mutex_unlock(&usbdev_loop_lock);
    return l;
}

/* The runloop if the event thread already exists; never starts it. */
static CFRunLoopRef usbdev_loop_current(void)
{
    pthread_mutex_lock(&usbdev_loop_lock);
    CFRunLoopRef l = usbdev_loop;
    pthread_mutex_unlock(&usbdev_loop_lock);
    return l;
}

static IONotificationPortRef usbdev_notify_get(void)
{
    CFRunLoopRef loop = usbdev_loop_get();
    if (!loop)
        return NULL;
    pthread_mutex_lock(&usbdev_loop_lock);
    if (!usbdev_notify_port) {
        usbdev_notify_port = IONotificationPortCreate(kIOMainPortDefault);
        if (usbdev_notify_port)
            CFRunLoopAddSource(
                loop, IONotificationPortGetRunLoopSource(usbdev_notify_port),
                kCFRunLoopDefaultMode);
    }
    IONotificationPortRef p = usbdev_notify_port;
    pthread_mutex_unlock(&usbdev_loop_lock);
    return p;
}

/* The two IOKit codes that mean the device is gone rather than that this
 * transfer failed. Every site that sees one owes the fd a disconnect stamp, so
 * the test is written once rather than at each site: the three that can see it
 * are SUBMITURB's start, the completion callback, and the queued follower's
 * start, and the third one did not agree with the other two.
 */
static bool usbdev_ioret_device_gone(IOReturn r)
{
    return (uint32_t) r == (uint32_t) kIOReturnNoDevice ||
           (uint32_t) r == (uint32_t) kIOReturnNotAttached;
}

static void usbdev_ready_settle_locked(usbdev_t *u, int pipe_rd);

/* Event-thread-safe disconnect stamp: async_lock only, no guest memory. Wakes
 * pollers by raising the readiness level (the remap turns the wake into
 * POLLERR|POLLHUP) and REAPURB waiters via the cv. Disconnect is one-way, so
 * the token it takes is never given back -- which is what an unmaskable
 * POLLERR|POLLHUP that stays raised needs.
 */
static void usbdev_mark_disconnected_locked(usbdev_t *u)
{
    if (!u->disconnected) {
        u->disconnected = true;

        /* guest_fd is table-lock-guarded; this unlocked read races only with
         * teardown, which clears the map bit again afterwards.
         */
        int gfd = u->guest_fd;
        if (RANGE_CHECK(gfd, 0, FD_TABLE_SIZE))
            discmap_set(gfd);
        usbdev_ready_settle_locked(u, -1);
        pthread_cond_broadcast(&u->async_cv);

        /* The device is gone, not this fd's view of it, so every other usbfs fd
         * open on it owes the same stamp. That walk cannot run from here (this
         * is called with async_lock held, and the walk takes peers'), so what
         * this does is record the debt.
         */
        atomic_store_explicit(&u->disc_peers_pending, true,
                              memory_order_release);
    }
}

/* Stamp every OTHER usbfs fd open on this device, which is what a disconnect
 * actually is: usbdev_remove walks udev->filelist and marks each open file
 * before it wakes anything, so a second fd on the same node sees POLLERR|
 * POLLHUP and -ENODEV without having had to touch the device itself. Here the
 * stamp used to be written only where it was noticed -- the terminate watch is
 * armed from SUBMITURB alone, and the three other sites are the async engine's
 * -- so an fd that never submitted an async URB was told nothing: measured,
 * poll revents 0x0000 and GET_CAPABILITIES 0 on a device whose sibling fd had
 * already been given 0x0018 and -ENODEV.
 *
 * usbdev_table_lock, held by the caller, is what stops a slot from being torn
 * down and reused between the devkey match and the stamp; the peers' async
 * locks are taken one at a time beneath it and never two at once, so this adds
 * no order beyond the table -> async nesting usbdev_interest_cb already has.
 * The entry locks are not taken at all, for the reason usbdev_claimed_elsewhere
 * gives: one can be held across a whole transfer timeout.
 */
static void usbdev_mark_key_disconnected_tlocked(uint64_t key,
                                                 const usbdev_t *skip)
{
    if (!key)
        return;
    for (int i = 0; i < USBDEV_MAX_FDS; i++) {
        usbdev_t *o = &usbdev_fds[i];
        if (o == skip || !o->used || o->dead || devkey_load(o) != key)
            continue;
        pthread_mutex_lock(&o->async_lock);
        usbdev_mark_disconnected_locked(o);

        /* Stamped by this walk, so it owes no walk of its own: the device is
         * covered, and leaving the debt set would have every peer re-run it.
         */
        atomic_store_explicit(&o->disc_peers_pending, false,
                              memory_order_relaxed);
        pthread_mutex_unlock(&o->async_lock);
    }
}

/* Keyed by the slot, for every caller that still has a live one. */
static void usbdev_mark_peers_disconnected_tlocked(usbdev_t *u)
{
    atomic_store_explicit(&u->disc_peers_pending, false, memory_order_relaxed);
    usbdev_mark_key_disconnected_tlocked(devkey_load(u), u);
}

/* Pay off whatever the stamp recorded, from a caller holding neither async_lock
 * nor the table lock. Cheap enough to sit on every ioctl's way out
 * (usbdev_release): one relaxed exchange when there is nothing to do.
 */
static void usbdev_flush_disc_peers(usbdev_t *u)
{
    if (!atomic_exchange_explicit(&u->disc_peers_pending, false,
                                  memory_order_acq_rel))
        return;
    pthread_mutex_lock(&usbdev_table_lock);
    usbdev_mark_peers_disconnected_tlocked(u);
    pthread_mutex_unlock(&usbdev_table_lock);
}

/* Take a slot's unpaid peer-walk debt, and the devkey the walk needs, off it
 * before teardown retires both.
 *
 * usbdev_flush_disc_peers cannot serve a closing fd. It needs the table lock,
 * which never nests under an entry lock, so it can only run after the entry
 * lock is dropped -- by which time usbdev_teardown_locked has cleared
 * disc_peers_pending and called devkey_retire, so the flush read a false debt
 * and, had it read a true one, an empty key. Both flushes on the close paths
 * were therefore dead by construction. Reading the pair out first, while the
 * slot is still whole, is what makes them do the work their comments claim: the
 * debt is answered from the key rather than from the slot, which by then may
 * already have been reused for somebody else's device.
 */
static uint64_t usbdev_take_disc_debt(usbdev_t *u)
{
    if (!atomic_exchange_explicit(&u->disc_peers_pending, false,
                                  memory_order_acq_rel))
        return 0;
    return devkey_load(u);
}

/* Pay what usbdev_take_disc_debt took, from a caller holding no lock at all. */
static void usbdev_pay_disc_debt(uint64_t key, const usbdev_t *skip)
{
    if (!key)
        return;
    pthread_mutex_lock(&usbdev_table_lock);
    usbdev_mark_key_disconnected_tlocked(key, skip);
    pthread_mutex_unlock(&usbdev_table_lock);
}

static void usbdev_mark_disconnected(usbdev_t *u)
{
    pthread_mutex_lock(&u->async_lock);
    usbdev_mark_disconnected_locked(u);
    pthread_mutex_unlock(&u->async_lock);
}

/* Declared above ioret_neg_errno. async_lock must not be held (this takes it);
 * the entry lock may be, which is the state every op call site is in. The peer
 * walk the stamp records is paid on the way out, in usbdev_release.
 */
static int64_t usbdev_ioret_op(usbdev_t *u, IOReturn r)
{
    if (usbdev_ioret_device_gone(r))
        usbdev_mark_disconnected(u);
    return ioret_neg_errno(r);
}

/* Refcon layout and the reason for it: usbdev-urb.h. */
static void *usbdev_watch_token(const usbdev_t *u)
{
    return (void *) usbdev_watch_pack((unsigned) (u - usbdev_fds),
                                      u->generation);
}

static void usbdev_interest_cb(void *refcon,
                               io_service_t service,
                               natural_t msg,
                               void *arg)
{
    (void) service;
    (void) arg;
    if (msg != kIOMessageServiceIsTerminated)
        return;

    /* Re-validate the token before marking: used/generation are table-lock
     * fields, and holding the table lock here also orders this against a
     * concurrent teardown + slot reuse (table -> async is the documented order,
     * so the nested mark is safe).
     */
    unsigned idx;
    uint64_t gen;
    if (!usbdev_watch_unpack((uintptr_t) refcon, &idx, &gen))
        return;
    usbdev_t *u = &usbdev_fds[idx];
    pthread_mutex_lock(&usbdev_table_lock);

    if (u->used && (u->generation & USBDEV_WATCH_GEN_MASK) == gen) {
        /* dead is what the peer walk already tests beside used, and here it
         * guards the stamp alone. A slot whose fd has closed still holds its
         * generation until the table releases it, so a terminate arriving in
         * that window stamps a slot that no longer answers for anything. What
         * outlives the slot is not the flag but the map: the mark writes
         * usbdev_disc_map under this slot's guest fd number, and
         * usbdev_teardown_locked has already cleared both by the time the mark
         * lands, so the bit stays set under an fd number that is free for
         * reuse. Measured on the loopback fixture: a close blocked in the 2 s
         * drain, a terminate delivered underneath it, and the next open handed
         * the same guest fd -- a different node, with no device of its own --
         * polled POLLERR|POLLHUP (0x0018) 3/3, where the same run with the
         * terminate armed past the drain polled 0x0000 3/3. The errno is not
         * the tell: CLAIMINTERFACE answers -ENODEV in both runs, because the
         * node the reused fd number landed on carries no IOKit device at all.
         */
        if (!u->dead)
            usbdev_mark_disconnected(u);

        /* The walk is not guarded. It stamps the device's OTHER fds, which are
         * live whatever this slot's state is, and a closing fd is the last one
         * that can tell them -- a sync-only peer on the same node arms no watch
         * of its own, so the departure reaches it by this route or not at all.
         * Skipping it measured 0x0000 3/3 on such a peer for a device that was
         * gone. devkey_retire runs inside the teardown the drain above has not
         * reached yet, so the key the walk needs is still on the slot; once the
         * teardown has run the key reads 0 and the walk returns at once.
         *
         * In place rather than through usbdev_flush_disc_peers: the table lock
         * this needs is already held here and is not recursive.
         */
        usbdev_mark_peers_disconnected_tlocked(u);
    }
    pthread_mutex_unlock(&usbdev_table_lock);
}

/* Register the terminate-interest notification (entry lock held). Best effort:
 * kIOReturnNoDevice detection on ops is the fallback.
 */
static void usbdev_arm_disconnect_watch(usbdev_t *u)
{
    if (u->notif != IO_OBJECT_NULL)
        return;
    if (u->fake) {
        /* Same callback, same packed token: what changes is who posts the
         * terminate message.
         */
        usbdev_fixture_watch(u->location_id, usbdev_interest_cb,
                             usbdev_watch_token(u));
        return;
    }
    if (u->service == IO_OBJECT_NULL)
        return;
    IONotificationPortRef port = usbdev_notify_get();
    if (!port)
        return;
    if (IOServiceAddInterestNotification(
            port, u->service, kIOGeneralInterest, usbdev_interest_cb,
            usbdev_watch_token(u), &u->notif) != kIOReturnSuccess)
        u->notif = IO_OBJECT_NULL;
}

/* Create + attach the ep0 async event source (entry lock held). */
static int64_t usbdev_ensure_dev_async(usbdev_t *u)
{
    int64_t rc = usbdev_ensure_dev_plugin(u);
    if (rc < 0)
        return rc;
    usbdev_lazy_device_open(u);
    if (u->dev_src)
        return 0;
    CFRunLoopRef loop = usbdev_loop_get();
    if (!loop)
        return -LINUX_ENOMEM;
    CFRunLoopSourceRef src = NULL;
    IOReturn r = (*u->dev)->CreateDeviceAsyncEventSource(u->dev, &src);
    if (r != kIOReturnSuccess || !src)
        return r == kIOReturnSuccess ? -LINUX_ENOMEM : usbdev_ioret_op(u, r);
    CFRunLoopAddSource(loop, src, kCFRunLoopDefaultMode);
    u->dev_src = src;
    usbdev_arm_disconnect_watch(u);
    return 0;
}

/* Create + attach the interface async event source (entry lock held; fi is
 * claimed).
 */
static int64_t usbdev_ensure_iface_async(usbdev_t *u, usbdev_iface_t *fi)
{
    if (fi->src)
        return 0;
    CFRunLoopRef loop = usbdev_loop_get();
    if (!loop)
        return -LINUX_ENOMEM;
    CFRunLoopSourceRef src = NULL;
    IOReturn r = (*fi->intf)->CreateInterfaceAsyncEventSource(fi->intf, &src);
    if (r != kIOReturnSuccess || !src)
        return r == kIOReturnSuccess ? -LINUX_ENOMEM : usbdev_ioret_op(u, r);
    CFRunLoopAddSource(loop, src, kCFRunLoopDefaultMode);
    fi->src = src;
    usbdev_arm_disconnect_watch(u);
    return 0;
}

/* URB lists (async_lock held) */

static void urb_list_append(usbdev_urb_t **head,
                            usbdev_urb_t **tail,
                            usbdev_urb_t *rec)
{
    rec->next = NULL;
    if (*tail)
        (*tail)->next = rec;
    else
        *head = rec;
    *tail = rec;
}

/* Append to the pending list and to its endpoint's FIFO, both at the tail, so
 * each list is in submission order (async_lock held).
 */
static void urb_pending_append(usbdev_t *u, usbdev_urb_t *rec)
{
    rec->next = NULL;
    rec->prev = u->pending_tail;
    if (u->pending_tail)
        u->pending_tail->next = rec;
    else
        u->pending_head = rec;
    u->pending_tail = rec;

    uint8_t key = rec->ep_key;
    rec->ep_next = NULL;
    rec->ep_prev = u->ep_tail[key];
    if (u->ep_tail[key])
        u->ep_tail[key]->ep_next = rec;
    else
        u->ep_head[key] = rec;
    u->ep_tail[key] = rec;
}

/* Take a record off both pending lists. A record that is on neither is left
 * alone, which the head test is what decides: every caller here holds a record
 * it took from the pending list, and the test costs one compare (async_lock
 * held).
 */
static void urb_pending_unlink(usbdev_t *u, usbdev_urb_t *rec)
{
    if (!rec->prev && u->pending_head != rec)
        return;
    if (rec->prev)
        rec->prev->next = rec->next;
    else
        u->pending_head = rec->next;
    if (rec->next)
        rec->next->prev = rec->prev;
    else
        u->pending_tail = rec->prev;
    rec->next = rec->prev = NULL;

    uint8_t key = rec->ep_key;
    if (rec->ep_prev)
        rec->ep_prev->ep_next = rec->ep_next;
    else if (u->ep_head[key] == rec)
        u->ep_head[key] = rec->ep_next;
    if (rec->ep_next)
        rec->ep_next->ep_prev = rec->ep_prev;
    else if (u->ep_tail[key] == rec)
        u->ep_tail[key] = rec->ep_prev;
    rec->ep_next = rec->ep_prev = NULL;
}

static void urb_free_locked(usbdev_t *u, usbdev_urb_t *rec)
{
    u->nurbs--;
    u->inflight_bytes -= rec->charge;
    usbdev_memory_refund(rec->charge);
    free(rec->buf);
    free(rec);
}

/* Restate the fd's readiness -- the lock-free reapable map and the readiness
 * pipe -- after anything that can have moved either term (async_lock held).
 *
 * INVARIANT, restored before async_lock is dropped and true of every live
 * usbdevfs fd: the readiness pipe holds exactly one byte while completed_head
 * is non-empty or the fd is disconnected, and no bytes otherwise. It is a
 * level, not a running count of completions.
 *
 * A byte per completion cannot carry that. There is no URB-count cap, only the
 * process-wide byte budget, and a zero-length URB costs just
 * sizeof(usbdev_urb_t) against it, so far more records fit than the pipe has
 * room for bytes; a nonblocking write whose byte does not fit leaves its record
 * reapable with nothing readable behind it, and poll, select and epoll then
 * answer 0 for an fd that would reap at once. One token is never the byte that
 * does not fit, and needs no room it has not already taken.
 *
 * Only a reap lowers the level, and only it holds the pipe's read end (the fd
 * table owns it); the callers that can only raise it -- a completion, a
 * disconnect -- pass -1. Teardown drops the pipe rather than draining it, and
 * clears the flag with pipe_wr.
 */
static void usbdev_ready_settle_locked(usbdev_t *u, int pipe_rd)
{
    /* The unlocked guest_fd read races only teardown, which re-clears the bit,
     * the usbdev_mark_disconnected_locked pattern.
     */
    int gfd = u->guest_fd;
    if (RANGE_CHECK(gfd, 0, FD_TABLE_SIZE))
        readymap_store(gfd, u->completed_head != NULL);

    bool want = u->completed_head != NULL || u->disconnected;
    if (want == u->ready_token)
        return;
    if (want) {
        char b = 0;
        if (u->pipe_wr >= 0 && write(u->pipe_wr, &b, 1) == 1)
            u->ready_token = true;
    } else if (pipe_rd >= 0) {
        /* Never blocks: the token is known present, and both ends are
         * nonblocking anyway.
         */
        char b;
        if (read(pipe_rd, &b, 1) == 1)
            u->ready_token = false;
    }
}

/* Move rec to the completed list and raise readiness (async_lock held). */
static void urb_complete_locked(usbdev_t *u, usbdev_urb_t *rec, int32_t status)
{
    rec->status = status;
    rec->state = URB_COMPLETED;
    urb_list_append(&u->completed_head, &u->completed_tail, rec);
    usbdev_ready_settle_locked(u, -1);
}

/* kIOReturn -> Linux URB status (doc D table (b); differs from the sync ioctl
 * map in the Aborted row: DISCARDURB = usb_kill_urb = -ENOENT, any other abort
 * = async unlink = -ECONNRESET).
 */
static int32_t usbdev_urb_status(const usbdev_urb_t *rec, IOReturn r)
{
    switch ((uint32_t) r) {
    case kIOReturnSuccess:
    case kIOReturnUnderrun: /* short transfer == success */
        return 0;
    case kIOReturnAborted:
    case kIOUSBTransactionReturned:
        return rec->discarding ? -LINUX_ENOENT : -LINUX_ECONNRESET;
    case kIOReturnNoDevice:
    case kIOReturnNotOpen:
    case kIOReturnNotAttached:
        return -LINUX_ENODEV;
    default:
        return (int32_t) ioret_neg_errno(r);
    }
}

static void usbdev_async_cb(void *refcon, IOReturn result, void *arg0);

/* Hand rec to IOKit. Called with async_lock held: the async entry points do not
 * block, and their callbacks arrive later on the event thread.
 */
static IOReturn usbdev_urb_start(usbdev_urb_t *rec)
{
    usbdev_t *u = urb_owner(rec);
    if (rec->type == LINUX_URB_TYPE_CONTROL) {
        rec->req.pData = rec->buf;
        if (rec->pipe == 0)
            return (*u->dev)->DeviceRequestAsyncTO(u->dev, &rec->req,
                                                   usbdev_async_cb, rec);
        return (*rec->intf)
            ->ControlRequestAsyncTO(rec->intf, rec->pipe, &rec->req,
                                    usbdev_async_cb, rec);
    }

    /* Interrupt pipes reject the *TO entry points (IOUSBLib.h: BadArgument);
     * bulk gets the TO variants with 0 = infinite, matching usbfs URBs that
     * never time out. A BULK URB on an interrupt endpoint lands here with
     * pipe_interrupt set, i.e. Linux's silent bulk->interrupt conversion
     * (devio.c:1718-1721).
     */
    if (rec->pipe_interrupt) {
        if (rec->is_in)
            return (*rec->intf)
                ->ReadPipeAsync(rec->intf, rec->pipe, rec->buf, rec->data_len,
                                usbdev_async_cb, rec);
        return (*rec->intf)
            ->WritePipeAsync(rec->intf, rec->pipe, rec->buf, rec->data_len,
                             usbdev_async_cb, rec);
    }
    if (rec->is_in)
        return (*rec->intf)
            ->ReadPipeAsyncTO(rec->intf, rec->pipe, rec->buf, rec->data_len, 0,
                              0, usbdev_async_cb, rec);
    return (*rec->intf)
        ->WritePipeAsyncTO(rec->intf, rec->pipe, rec->buf, rec->data_len, 0, 0,
                           usbdev_async_cb, rec);
}

/* Restart the FIFO on one endpoint key: submit the oldest QUEUED record if the
 * endpoint may start one (usbdev_ep_may_start); locally fail records IOKit
 * refuses (async_lock held).
 */
static void usbdev_kick_ep_locked(usbdev_t *u, uint8_t key)
{
    for (;;) {
        /* The FIFO's head is the oldest record on this endpoint, so it is the
         * one in flight when the endpoint has one and the next to start
         * otherwise. Reading it is what replaced a walk of every other
         * endpoint's queue.
         */
        usbdev_urb_t *head = u->ep_head[key];
        bool inflight = head && head->state == URB_INFLIGHT;
        usbdev_urb_t *next = inflight ? NULL : head;
        if (!usbdev_ep_may_start(u->draining, u->ep_aborting[key], inflight))
            return;
        if (!next)
            return;
        IOReturn ir = usbdev_urb_start(next);
        if (ir == kIOReturnSuccess) {
            next->state = URB_INFLIGHT;
            u->inflight++;
            return;
        }

        /* A follower that starts after the device has gone is the same event
         * SUBMITURB and the completion callback stamp, and it used to be the
         * one site that only wrote the URB's -ENODEV: pollers then saw no
         * POLLERR|POLLHUP and a later ioctl passed the disconnected gate.
         */
        if (usbdev_ioret_device_gone(ir))
            usbdev_mark_disconnected_locked(u);

        /* The completion map, not the syscall map: a start that comes back
         * Aborted is a canceled URB, and Linux writes -ECONNRESET/-ENOENT into
         * urb->status for that. ioret_neg_errno's -EINTR is a syscall return
         * value the kernel never puts in a URB.
         */
        int32_t st = usbdev_urb_status(next, ir);
        urb_pending_unlink(u, next);
        urb_complete_locked(u, next, st ? st : -LINUX_EPROTO);
    }
}

/* Give the handles an orphan pins back: the late callback has arrived, so IOKit
 * owns neither the buffer nor the interface any more (async_lock held).
 *
 * Whether the record itself may be freed is the other half of the ownership --
 * a handed-back orphan is still on the completed list waiting for a reap -- so
 * this only clears orphaned and leaves that to the caller.
 */
static void urb_orphan_retire_locked(usbdev_t *u, usbdev_urb_t *rec)
{
    /* Un-pin the owning handle: the interface's for a record that named one,
     * the device's for an ep0 record, which names none. The pointer match
     * cannot hit a reused slot's interface: an orphan's handle is leaked, never
     * freed, so no later claim can be allocated at the same address.
     */
    if (rec->intf) {
        for (int i = 0; i < USBDEV_MAX_IFACES; i++) {
            if (u->ifaces[i].intf == rec->intf && u->ifaces[i].orphans > 0) {
                u->ifaces[i].orphans--;
                break;
            }
        }
    } else if (rec->dev_pin == u->dev_serial && u->dev_orphans > 0) {
        u->dev_orphans--;
    }
    rec->orphaned = false;
}

/* Free an orphaned record: a drain timeout already unlinked it and settled the
 * slot's counters, and the slot may since have been reused by a new open, so
 * this frees only what the record owns -- no counters, no disconnect map, no
 * readiness token (async_lock held).
 *
 * Called only once both halves of the ownership are clear, which is why it
 * takes no slot: there may no longer be one this record belongs to.
 */
static void urb_free_orphan_locked(usbdev_urb_t *rec)
{
    /* The process-wide charge outlives the drain deadline because the memory
     * does: it is given back here, with the buffer it was taken for. A charge
     * that never comes back is a transfer whose callback never arrived, which
     * is the honest answer rather than a leak.
     */
    usbdev_memory_refund(rec->charge);
    free(rec->buf);
    free(rec);
}

/* The late callback's end of an orphan: retire the pins, and free the record
 * unless it is still on the completed list owing the guest an answer
 * (async_lock held).
 */
static void urb_orphan_callback_locked(usbdev_t *u, usbdev_urb_t *rec)
{
    urb_orphan_retire_locked(u, rec);
    if (!rec->handback)
        urb_free_orphan_locked(rec);
}

/* A reap or a close taking a handed-back orphan off the completed list: free it
 * unless IOKit still owes its callback (async_lock held).
 */
static void urb_handback_taken_locked(usbdev_urb_t *rec)
{
    rec->handback = false;
    if (!rec->orphaned)
        urb_free_orphan_locked(rec);
}

/* IOKit completion (event thread). arg0 carries the transferred byte count for
 * pipe reads/writes and wLenDone for device requests.
 */
static void usbdev_async_cb(void *refcon, IOReturn result, void *arg0)
{
    usbdev_urb_t *rec = refcon;
    usbdev_t *u = urb_owner(rec);
    pthread_mutex_lock(&u->async_lock);
    if (rec->orphaned) {
        urb_orphan_callback_locked(u, rec);
        pthread_mutex_unlock(&u->async_lock);
        return;
    }
    if (usbdev_ioret_device_gone(result))
        usbdev_mark_disconnected_locked(u);

    /* The transferred count is a device-supplied number; Linux's HCDs bound
     * urb->actual_length by transfer_buffer_length and so does this.
     */
    rec->actual =
        usbdev_urb_clamp_actual((uint64_t) (uintptr_t) arg0, rec->data_len);
    int32_t st = usbdev_urb_status(rec, result);
    if (st == 0 && rec->short_not_ok && rec->actual < rec->data_len)
        st = -LINUX_EREMOTEIO; /* URB_SHORT_NOT_OK, devio.c error-codes */

    /* ZLP: a maxpacket-multiple OUT gets its terminating zero-length packet as
     * a separate WritePipe from the callback (darwin_usb.c:3204-3218). Two
     * things the first cut of this got wrong, both of them the whole process's
     * problem rather than this URB's: the untimed entry point on an endpoint
     * that NAKs never returns, and there is one event thread for every usbdevfs
     * fd in the process, so a wedge there stops all completions and every
     * SUBMITURB/DISCARDURB/REAPURB waiting on this async_lock. It is issued
     * with the lock dropped and with a bounded timeout, and a ZLP that fails
     * lands in the URB's status the way it does on Linux, where the terminating
     * packet is part of the URB rather than a second transfer.
     */
    if (usbdev_urb_needs_zlp(st, rec->zero_packet, rec->pipe, rec->data_len,
                             rec->mps)) {
        IOUSBInterfaceInterface800 **intf = rec->intf;
        uint8_t pipe = rec->pipe;
        uint8_t *buf = rec->buf;
        pthread_mutex_unlock(&u->async_lock);
        IOReturn zr = (*intf)->WritePipeTO(
            intf, pipe, buf, 0, USBDEV_ZLP_TIMEOUT_MS, USBDEV_ZLP_TIMEOUT_MS);
        pthread_mutex_lock(&u->async_lock);
        if (rec->orphaned) {
            urb_orphan_callback_locked(u, rec);
            pthread_mutex_unlock(&u->async_lock);
            usbdev_flush_disc_peers(u);
            return;
        }
        if (zr != kIOReturnSuccess) {
            st = usbdev_urb_status(rec, zr);
            if (st == 0)
                st = -LINUX_EPROTO;
        }
    }
    urb_pending_unlink(u, rec);
    u->inflight--;
    uint8_t key = rec->ep_key;
    urb_complete_locked(u, rec, st);
    usbdev_kick_ep_locked(u, key);
    pthread_cond_broadcast(&u->async_cv);
    pthread_mutex_unlock(&u->async_lock);

    /* Both stamps this callback can leave -- its own device-gone test and the
     * one usbdev_kick_ep_locked writes when a follower's start finds the device
     * gone -- run with async_lock held, so the cross-fd walk they owe is paid
     * here.
     */
    usbdev_flush_disc_peers(u);
}

/* The abort half of a kill: retire every matching QUEUED record as killed
 * (-ENOENT, usb_kill_urb) and issue the AbortPipe calls the INFLIGHT ones need,
 * without waiting for the callbacks those provoke. Answers whether anything was
 * left in flight for a drain to wait on. Entry lock held.
 *
 * Split out from usbdev_kill_urbs_locked because the aborts are what recovers
 * the URBs and the wait is only how a caller learns that they landed, and one
 * caller -- a non-blocking REAPURBNDELAY -- may issue the first and must not
 * perform the second.
 */
static bool usbdev_abort_urbs_locked(usbdev_t *u,
                                     IOUSBInterfaceInterface800 **intf)
{
    pthread_mutex_lock(&u->async_lock);

    /* Shut every endpoint's FIFO for the whole abort-and-drain: a completion
     * arriving mid-kill must not start a queued URB behind the AbortPipe that
     * is still running for the one ahead of it.
     */
    u->draining = true;
    usbdev_urb_t *r = u->pending_head;
    bool any_inflight = false;
    while (r) {
        usbdev_urb_t *nx = r->next;
        bool match = intf == NULL || r->intf == intf;
        if (match && r->state == URB_QUEUED) {
            urb_pending_unlink(u, r);
            urb_complete_locked(u, r, -LINUX_ENOENT);
        } else if (match && r->state == URB_INFLIGHT) {
            r->discarding = true;
            any_inflight = true;
        }
        r = nx;
    }
    pthread_mutex_unlock(&u->async_lock);

    if (any_inflight) {
        if (intf == NULL && u->dev && u->dev_src)
            (void) (*u->dev)->USBDeviceAbortPipeZero(u->dev);
        for (int i = 0; i < USBDEV_MAX_IFACES; i++) {
            usbdev_iface_t *fi = &u->ifaces[i];
            if (!fi->claimed || (intf != NULL && fi->intf != intf))
                continue;
            for (int p = 1; p <= fi->npipes; p++)
                (void) (*fi->intf)->AbortPipe(fi->intf, (UInt8) p);
        }
    }
    return any_inflight;
}

/* Reopen every endpoint FIFO the shutter closed. All 256 keys and not only the
 * ones a pass touched: the endpoints needing a restart are precisely the ones
 * the kill did not match. async_lock held.
 */
static void usbdev_restart_eps_locked(usbdev_t *u)
{
    u->draining = false;
    for (unsigned k = 0; k < 256; k++)
        usbdev_kick_ep_locked(u, (uint8_t) k);
}

/* Give up on every INFLIGHT URB matching intf whose abort was not answered
 * inside the drain deadline: unlink it, settle the slot's accounting and mark
 * it orphaned, so what is left of the pending list is what the wire may still
 * answer for. async_lock held.
 *
 * The one implementation of "the deadline passed", because both flavors of reap
 * have to leave the slot in the same state on the far side of it: a blocking
 * caller reaches here by waiting the deadline out, a non-blocking one by
 * measuring it. What that state is, is the reason each step is here.
 *
 * The slot's own counters are settled now rather than in the late callback,
 * which sees orphaned and frees only the record, so a reused slot's counters
 * are never touched by it. The record leaves pending, so a later kill or
 * teardown scan cannot re-find it and wait another deadline. The owning handle
 * is pinned by an orphan count -- the interface's, or the device's for an ep0
 * record that names no interface -- because a whole-device kill unlinks the
 * record where the per-interface release rescan would have found it (B1). The
 * process-wide budget is not settled here: usbdev_memory_usage accounts live
 * bytes, and r->buf is still allocated and still owned by an in-flight IOKit
 * transfer, so it is refunded where that buffer is released, in
 * urb_free_orphan_locked.
 *
 * The URB is handed back, which is the whole of CAP_REAP_AFTER_DISCONNECT and
 * the one path where it did not hold: the record was unlinked and marked and
 * never appended to the completed list, so the same pass that gave up on it
 * answered -ENODEV with the URB pointer still unreturned. Linux's
 * destroy_all_async completes every pending URB into async_completed before any
 * reaper can run, and usb_kill_urb leaves -ENOENT in each, which is what this
 * writes. The record stays alive behind the handback until IOKit's callback
 * arrives, so the guest gets its pointer back without the late callback ever
 * meeting a freed record.
 *
 * Every FIFO is reopened, and not only the ones this pass touched: an endpoint
 * whose leader completed during the drain took the orphaned early return in
 * usbdev_async_cb, which starts nothing, so it is left with a queued URB, none
 * in flight and no later event to restart it -- its REAPURB never returns.
 */
static void urb_orphan_locked(usbdev_t *u, usbdev_urb_t *r)
{
    urb_pending_unlink(u, r);
    u->inflight--;
    u->nurbs--;
    u->inflight_bytes -= r->charge;
    r->orphaned = true;
    if (r->intf) {
        for (int fi_i = 0; fi_i < USBDEV_MAX_IFACES; fi_i++) {
            if (u->ifaces[fi_i].claimed && u->ifaces[fi_i].intf == r->intf) {
                u->ifaces[fi_i].orphans++;
                break;
            }
        }
    } else {
        r->dev_pin = u->dev_serial;
        u->dev_orphans++;
    }
    r->handback = true;
    urb_complete_locked(u, r, -LINUX_ENOENT);
}

static void usbdev_orphan_stalled_locked(usbdev_t *u,
                                         IOUSBInterfaceInterface800 **intf)
{
    int n = 0;
    usbdev_urb_t *r = u->pending_head;
    while (r) {
        usbdev_urb_t *nx = r->next;
        if ((intf == NULL || r->intf == intf) && r->state == URB_INFLIGHT) {
            urb_orphan_locked(u, r);
            n++;
        }
        r = nx;
    }
    if (n)
        log_warn("usbdev: %d in-flight URB(s) did not drain; orphaned", n);
    usbdev_restart_eps_locked(u);
}

/* Abort and drain every URB whose interface matches intf (NULL = all, including
 * ep0). QUEUED records complete as killed and stay reapable; INFLIGHT ones are
 * aborted and drained through the callback.
 *
 * Returns false when the drain timed out: survivors were orphaned (the late
 * callback frees them) and the caller must NOT release the IOKit handles they
 * still reference. Entry lock held.
 */
static bool usbdev_kill_urbs_locked(usbdev_t *u,
                                    IOUSBInterfaceInterface800 **intf)
{
    (void) usbdev_abort_urbs_locked(u, intf);

    /* Invariant: this wait and the ceiling usbdev_do_reap measures are the same
     * USBDEV_DRAIN_TIMEOUT_MS, so a change to it moves both. They are not the
     * same clock -- pthread_cond_timedwait wants CLOCK_REALTIME and the ceiling
     * is CLOCK_MONOTONIC -- which is why neither is written as an offset from
     * the other.
     */
    struct timespec deadline;
    timespec_deadline_in_ms(&deadline, USBDEV_DRAIN_TIMEOUT_MS);
    pthread_mutex_lock(&u->async_lock);
    usbdev_urb_t *r;
    for (;;) {
        bool busy = false;
        for (r = u->pending_head; r; r = r->next) {
            if ((intf == NULL || r->intf == intf) && r->state == URB_INFLIGHT) {
                busy = true;
                break;
            }
        }
        if (!busy)
            break;
        if (pthread_cond_timedwait(&u->async_cv, &u->async_lock, &deadline) ==
            ETIMEDOUT) {
            usbdev_orphan_stalled_locked(u, intf);
            pthread_mutex_unlock(&u->async_lock);
            return false;
        }
    }

    /* A per-interface kill leaves other interfaces' queues intact; restart them
     * now that the aborts are done.
     */
    usbdev_restart_eps_locked(u);
    pthread_mutex_unlock(&u->async_lock);
    return true;
}

/* Issue a whole-slot kill's aborts and come straight back.
 *
 * Linux's proc_reapurbnonblock pops async_getcompleted and answers -EAGAIN or
 * -ENODEV: no kill and no wait, because usbdev_remove has already run
 * destroy_all_async by the time any reap can see the disconnect. IOKit delivers
 * nothing of its own when a device terminates, so this engine owes that kill at
 * the first reap that finds the completion list empty -- but running the whole
 * of it inline made a non-blocking ioctl sit out the 2 s drain deadline holding
 * async_lock against every SUBMITURB and DISCARDURB on the fd (measured against
 * a wedged endpoint: REAPURBNDELAY returned -ENODEV after 2006 ms). The aborts
 * are what recovers the URBs and they return promptly; the wait is only how the
 * caller learns the callbacks landed, and this caller is not allowed to want
 * that. Whatever the aborts retire is reapable on a later pass.
 *
 * Reopening the FIFOs immediately is safe here where it would not be mid-kill:
 * every QUEUED record is already retired above, and SUBMITURB on a disconnected
 * fd is -ENODEV, so the shutter has nothing left to hold back. Entry lock held.
 */
static void usbdev_abort_urbs_nowait_locked(usbdev_t *u)
{
    (void) usbdev_abort_urbs_locked(u, NULL);
    pthread_mutex_lock(&u->async_lock);
    usbdev_restart_eps_locked(u);
    pthread_mutex_unlock(&u->async_lock);
}

/* Kill the URBs a device-state change is about to invalidate the handles of,
 * and answer whether the change may go ahead: 0 to proceed, -EBUSY to refuse.
 *
 * The decision belongs here rather than at each call site because the two sites
 * that retire handles have to agree, and did not: SETINTERFACE renumbers the
 * interface's pipeRefs and SETCONFIGURATION tears the whole pipe table down, so
 * an undrained transfer is outstanding at IOKit against a handle the change is
 * about to retire either way, yet SETCONFIGURATION discarded the answer and
 * changed the device anyway. A drain that misses its 2 s deadline is already an
 * abnormal path, so it is refused rather than papered over. Entry lock held.
 */
static int64_t usbdev_drain_for_change(usbdev_t *u,
                                       IOUSBInterfaceInterface800 **intf,
                                       const char *what)
{
    if (usbdev_kill_urbs_locked(u, intf))
        return 0;
    log_warn("usbdev: %s refused: URBs did not drain", what);
    return -LINUX_EBUSY;
}

/* Free every reapable completion (fd close: Linux frees unreaped completed URBs
 * too). Entry lock held.
 */
static void usbdev_free_completed(usbdev_t *u)
{
    pthread_mutex_lock(&u->async_lock);
    while (u->completed_head) {
        usbdev_urb_t *rec = u->completed_head;
        u->completed_head = rec->next;
        if (!u->completed_head)
            u->completed_tail = NULL;
        if (rec->handback)
            urb_handback_taken_locked(rec);
        else
            urb_free_locked(u, rec);
    }
    usbdev_ready_settle_locked(u, -1);
    pthread_mutex_unlock(&u->async_lock);
}

/* claim / release (entry lock held) */

static int64_t usbdev_claim_locked(usbdev_t *u, unsigned ifnum)
{
    if (ifnum >= USBDEV_MAX_IFACES)
        return -LINUX_EINVAL; /* claimintf devio.c:788-789 */
    usbdev_iface_t *fi = &u->ifaces[ifnum];
    if (fi->claimed)
        return 0; /* already ours */

    /* Invariant: a claim this call creates is created against a device the call
     * has just reached. The two answers above create none -- the number bound
     * and the already-ours short-circuit -- and neither asks; what stands
     * behind each of them is the row of that name in
     * tests/usbdev-ioctl-departed.tbl.
     *
     * Ahead of the branch below rather than inside either arm, because only one
     * arm asks the device on its own: the registry arm's usbdev_iface_service
     * runs the enumeration, and the fixture arm collapses the whole lookup into
     * one seam call. usbdev_ensure_dev_plugin stood here and asked nothing --
     * it hands back a cached handle -- so once that arm existed a device that
     * had gone granted the claim, and every op that claims implicitly through
     * usbdev_pipe_for_ep answered from it: measured on a departed loopback
     * device, CLAIMINTERFACE, CLEAR_HALT, RESETEP and SETINTERFACE all returned
     * 0 with the fd left unstamped, where Linux's connected() gate makes all
     * four -ENODEV.
     */
    int64_t drc = usbdev_ensure_dev_reachable(u);
    if (drc < 0)
        return drc;

    IOUSBInterfaceInterface800 **intf = NULL;
    if (u->fake) {
        /* One branch for the service lookup, the plugin and USBInterfaceOpen at
         * once: all three are IOKit calls with no separately interesting
         * answer, and what the lane is about starts after the claim.
         */
        int64_t frc = usbdev_fixture_open_iface(u->location_id, ifnum, &intf);
        if (frc < 0)
            return frc;
        goto claimed;
    }

    int64_t serr;
    io_service_t ifs = usbdev_iface_service(u, ifnum, &serr);
    if (ifs == IO_OBJECT_NULL)
        return serr < 0 ? serr : -LINUX_ENOENT;

    /* Linux: a bound kernel driver makes CLAIMINTERFACE -EBUSY
     * (usb_driver_claim_interface, driver.c:558). macOS arbitration is
     * per-IOKit-object and dynamic rather than per-device and static, so the
     * bound driver is not the question: USBInterfaceOpen answers
     * kIOReturnExclusiveAccess exactly while that driver holds that interface,
     * and succeeds while it is idle. Attempt the open and map what IOKit
     * answers. Pre-refusing on the mere presence of a driver child refused work
     * macOS grants -- the ESP32-S3's CDC data interface opens whenever nothing
     * holds /dev/cu.usbmodem1101 -- and it did so from a registry snapshot that
     * no live host state corresponds to.
     */
    IOCFPlugInInterface **plug = NULL;
    SInt32 score = 0;
    IOReturn r = IOCreatePlugInInterfaceForService(
        ifs, kIOUSBInterfaceUserClientTypeID, kIOCFPlugInInterfaceID, &plug,
        &score);
    IOObjectRelease(ifs);
    if (r != kIOReturnSuccess || !plug)
        return r == kIOReturnSuccess ? -LINUX_ENOMEM : usbdev_ioret_op(u, r);
    HRESULT hr = (*plug)->QueryInterface(
        plug, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID800),
        (LPVOID *) &intf);
    (*plug)->Release(plug);
    if (hr != S_OK || !intf)
        return -LINUX_ENOMEM;

    r = (*intf)->USBInterfaceOpen(intf);
    if (r != kIOReturnSuccess) {
        (*intf)->Release(intf);
        int64_t e = usbdev_ioret_op(u, r);
        return e == 0 ? -LINUX_EBUSY : e;
    }

claimed:
    /* Publish under async_lock: the late-callback orphan scan reads intf and
     * orphans with only that lock held. A stale orphan count belongs to a
     * previous (leaked) handle of this slot, so it starts over at zero.
     */
    pthread_mutex_lock(&u->async_lock);
    fi->intf = intf;
    fi->orphans = 0;
    pthread_mutex_unlock(&u->async_lock);
    int64_t maprc = usbdev_build_pipe_map(u, fi);
    if (maprc < 0) {
        (*intf)->USBInterfaceClose(intf);
        (*intf)->Release(intf);
        pthread_mutex_lock(&u->async_lock);
        fi->intf = NULL;
        pthread_mutex_unlock(&u->async_lock);
        return maprc;
    }
    fi->claimed = true;
    claimed_mask_set(u, ifnum);
    return 0;
}

static int64_t usbdev_release_locked(usbdev_t *u, unsigned ifnum)
{
    if (ifnum >= USBDEV_MAX_IFACES)
        return -LINUX_EINVAL;
    usbdev_iface_t *fi = &u->ifaces[ifnum];
    if (!fi->claimed) {
        /* releaseintf checks usb_ifnum_to_if first: a nonexistent interface is
         * -ENOENT, an existing unclaimed one -EINVAL (devio.c:815-833).
         */
        int64_t drc = usbdev_ensure_dev_plugin(u);
        if (drc < 0)
            return drc;
        int64_t serr;
        io_service_t ifs = usbdev_iface_service(u, ifnum, &serr);
        if (ifs == IO_OBJECT_NULL)
            return serr < 0 ? serr : -LINUX_ENOENT;
        IOObjectRelease(ifs);
        return -LINUX_EINVAL;
    }

    /* proc_releaseinterface kills the interface's URBs, through
     * destroy_async_on_interface once releaseintf has succeeded
     * (devio.c:2305-2317); releaseintf itself only drops the driver claim and
     * kills nothing. The kill is a usb_kill_urb each, so they stay reapable
     * with -ENOENT.
     */
    bool drained = usbdev_kill_urbs_locked(u, fi->intf);

    /* A whole-device drain timeout (fd teardown) orphaned this interface's
     * survivors after unlinking them from pending, so the rescan above came
     * back clean in under a wait; only the orphan count still knows the handle
     * is referenced (B1).
     */
    pthread_mutex_lock(&u->async_lock);
    if (fi->orphans != 0)
        drained = false;
    pthread_mutex_unlock(&u->async_lock);
    if (fi->src) {
        CFRunLoopRef loop = usbdev_loop_current();
        if (loop && drained)
            CFRunLoopRemoveSource(loop, fi->src, kCFRunLoopDefaultMode);
        if (drained)
            CFRelease(fi->src);
        fi->src = NULL;
    }
    if (drained) {
        (*fi->intf)->USBInterfaceClose(fi->intf);
        (*fi->intf)->Release(fi->intf);
    } else {
        /* Orphaned in-flight URBs still reference the handle and its event
         * source; leak both rather than hand the late callback a freed plugin.
         */
        log_warn("usbdev: leaking interface %u handle (undrained URBs)", ifnum);
    }
    pthread_mutex_lock(&u->async_lock);
    fi->intf = NULL;
    pthread_mutex_unlock(&u->async_lock);
    fi->claimed = false;
    claimed_mask_clear(u, ifnum);
    fi->npipes = 0;
    return 0;
}

/* CLAIMINTERFACE and RELEASEINTERFACE as ops of their own, which is not the
 * same question as the implicit claim usbdev_pipe_for_ep and check_ctrlrecip
 * take on a transfer's behalf.
 *
 * An interface this fd already holds is answered above out of this layer's own
 * bookkeeping, which stays true after the device leaves. For an implicit claim
 * that is right and costs nothing: the transfer behind it is what asks, and it
 * asks a moment later. For these two the claim is the whole op, so there is no
 * transfer behind it and the answer was the stale one -- measured with an fd
 * that took its claim before the device left and armed no disconnect watch,
 * CLAIMINTERFACE and RELEASEINTERFACE both returned 0 with the fd unstamped and
 * poll silent, where proc_claiminterface and proc_releaseinterface sit behind
 * usbdev_do_ioctl's connected() gate and Linux answers -ENODEV. The rows are
 * CLAIMINTERFACE_HELD and RELEASEINTERFACE_HELD.
 *
 * Only that arm asks. An unheld number reaches usbdev_ensure_dev_reachable
 * inside the claim, or usbdev_iface_service inside the release, so nothing here
 * enumerates twice; and the interface-number bound stays ahead of the question,
 * which is the deviation docs/internals.md records and CLAIMINTERFACE_BOUND
 * pins.
 *
 * Not on the teardown path: usbdev_teardown_locked and the USBDEVFS_IOCTL
 * unbind call usbdev_release_locked directly, so a close still drops the claim
 * and closes the handle on a device that has gone. Entry lock held.
 */
static int64_t usbdev_claim_ioctl(usbdev_t *u, unsigned ifnum)
{
    if (ifnum < USBDEV_MAX_IFACES && u->ifaces[ifnum].claimed)
        return usbdev_ensure_dev_reachable(u);
    return usbdev_claim_locked(u, ifnum);
}

static int64_t usbdev_release_ioctl(usbdev_t *u, unsigned ifnum)
{
    if (ifnum < USBDEV_MAX_IFACES && u->ifaces[ifnum].claimed) {
        int64_t drc = usbdev_ensure_dev_reachable(u);
        if (drc < 0)
            return drc;
    }
    return usbdev_release_locked(u, ifnum);
}

/* usbdev_ep_owner_iface's two failures, kept apart because Linux answers them
 * differently: an endpoint no altsetting carries is -ENOENT (findintfep's own
 * return), while one whose owning interface number is past the claim bitmap is
 * -EINVAL (checkintf, devio.c:845-846).
 */
#define USBDEV_EP_OWNER_NONE (-1)
#define USBDEV_EP_OWNER_OUT_OF_RANGE (-2)

/* findintfep (devio.c:856-879): which interface of the active config carries
 * bEndpointAddress ep, searching every altsetting. Parsed from the descriptors
 * blob.
 *
 * Returns USBDEV_EP_OWNER_NONE when not found, or USBDEV_EP_OWNER_OUT_OF_RANGE
 * when the endpoint is carried by an interface number this layer cannot
 * represent. Never returns a number ifaces[] does not hold.
 */
static int usbdev_ep_owner_iface(const usbdev_t *u, uint8_t ep)
{
    const uint8_t *b = u->blob;
    size_t len = u->blob_len;
    size_t off = 18;
    while (off + 9 <= len && b[off + 1] == 0x02 /* CONFIG */) {
        size_t total = (size_t) b[off + 2] | ((size_t) b[off + 3] << 8);
        if (total < 9 || off + total > len)
            break;
        bool active = b[off + 5] == (uint8_t) u->cfg_value;
        if (active) {
            size_t p = off + 9;
            int cur_if = USBDEV_EP_OWNER_NONE;
            while (p + 2 <= off + total && b[p] >= 2) {
                uint8_t dlen = b[p], dtype = b[p + 1];
                if (p + dlen > off + total)
                    break;
                if (dtype == 0x04 && dlen >= 9) { /* INTERFACE */
                    /* bInterfaceNumber is a device-supplied byte with the whole
                     * 0..255 range behind it, and ifaces[] is 64 entries, the
                     * width of the unsigned long checkintf bounds against. The
                     * range test belongs here, where the number enters from the
                     * descriptor, not at the array index below it: a device
                     * declaring bInterfaceNumber 200 with a matching endpoint
                     * read up to 191 entries past ifaces[] before the bound
                     * inside usbdev_claim_locked ever ran, and nothing attached
                     * to a developer's machine declares such a number, so no
                     * fixture and no sanitizer run on real hardware could reach
                     * it. Out of range is carried rather than dropped so the
                     * lookup still answers what checkintf answers.
                     */
                    cur_if = b[p + 2] < USBDEV_MAX_IFACES
                                 ? (int) b[p + 2]
                                 : USBDEV_EP_OWNER_OUT_OF_RANGE;
                } else if (dtype == 0x05 && dlen >= 7 && /* ENDPOINT */
                           b[p + 2] == ep && cur_if != USBDEV_EP_OWNER_NONE) {
                    return cur_if;
                }
                p += dlen;
            }
        }
        off += total;
    }
    return USBDEV_EP_OWNER_NONE;
}

/* Resolve ep -> (claimed iface, pipeRef), implicitly claiming the owner
 * interface the way checkintf does for the sync paths. -ENOENT when no
 * altsetting of the active config carries the endpoint.
 */
static int64_t usbdev_pipe_for_ep(usbdev_t *u,
                                  unsigned int ep,
                                  usbdev_iface_t **fi_out,
                                  uint8_t *pipe_out)
{
    /* findintfep rejects everything outside USB_DIR_IN|0xf before it looks at
     * anything (devio.c:860). The check belongs here rather than in each
     * caller: BULK and the control endpoint recipient had it and CLEAR_HALT and
     * RESETEP did not, so a malformed address fell out of the lookup as -ENOENT
     * on two of the four entry points onto the same question.
     *
     * The argument is the caller's whole unsigned int, as Linux tests it. The
     * ioctls carry a 32-bit endpoint word and narrowing it to a byte first
     * meant the test only ever saw eight bits, so ep 0x183 and ep 0x01000083
     * both passed as 0x83 and the transfer went to an endpoint the caller did
     * not name.
     */
    if (ep & ~0x8fu)
        return -LINUX_EINVAL;
    uint8_t ep8 = (uint8_t) ep;
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < USBDEV_MAX_IFACES; i++) {
            usbdev_iface_t *fi = &u->ifaces[i];
            if (!fi->claimed)
                continue;
            for (int p = 0; p < fi->npipes; p++) {
                if (fi->pipe_ep[p] == ep8) {
                    *fi_out = fi;
                    *pipe_out = (uint8_t) (p + 1);
                    return 0;
                }
            }
        }
        if (pass == 1)
            break;
        int owner = usbdev_ep_owner_iface(u, ep8);
        if (owner == USBDEV_EP_OWNER_OUT_OF_RANGE)
            return -LINUX_EINVAL; /* checkintf devio.c:842 */
        if (owner == USBDEV_EP_OWNER_NONE)
            return -LINUX_ENOENT;
        if (u->ifaces[owner].claimed)
            return -LINUX_ENOENT; /* claimed but ep not in current alt */
        int64_t rc = usbdev_claim_locked(u, (unsigned) owner);
        if (rc < 0)
            return rc;
    }
    return -LINUX_ENOENT;
}

/* check_ctrlrecip's endpoint-recipient arm (devio.c:905-933) for the control
 * paths: wIndex is masked to its low byte first, exactly like Linux.
 */
static int64_t usbdev_check_ep_recip(usbdev_t *u, uint16_t wIndex)
{
    /* The mask stays: check_ctrlrecip narrows wIndex to its low byte itself
     * (devio.c:904) before calling findintfep, so the reserved-bit test the
     * lookup runs on its whole argument is meant to see eight bits here and
     * thirty-two on the ioctls that carry an endpoint word.
     */
    uint8_t index = (uint8_t) (wIndex & 0xff);

    /* The default control endpoint belongs to no interface: allowed with no
     * claim and no lookup (devio.c:909-911) -- lsusb -v sends GET_STATUS to
     * endpoint 0 this way.
     */
    if ((index & 0x7f) == 0)
        return 0;

    usbdev_iface_t *fi = NULL;
    uint8_t pipe = 0;
    int64_t rc = usbdev_pipe_for_ep(u, index, &fi, &pipe);
    if (rc == -LINUX_ENOENT) {
        /* Some Win apps pass the endpoint number where the address (with its
         * direction bit) belongs; Linux flips the direction, warns, and lets
         * the request through (devio.c:913-928).
         */
        rc = usbdev_pipe_for_ep(u, index ^ 0x80, &fi, &pipe);
        if (rc == 0)
            log_warn(
                "usbdev: control recipient requests ep %02x but needs "
                "%02x",
                index, index ^ 0x80);
    }
    return rc;
}

/* side-table lookup */

/* Drop one pin, releasing the slot when the last pin leaves a dead entry. */
static void usbdev_unref(usbdev_t *u)
{
    pthread_mutex_lock(&usbdev_table_lock);
    if (--u->refs == 0 && u->dead) {
        u->used = false;
        u->dead = false;
        u->guest_fd = -1;
        u->generation = 0;
    }
    pthread_mutex_unlock(&usbdev_table_lock);
}

/* Find the entry for guest fd and return it with its lock held and one pin
 * taken; NULL when the fd is not a live FD_USBDEV fd (or was closed+reused:
 * generation mismatch).
 *
 * The pin, rather than taking the entry lock under the table lock, is what
 * keeps the slot from being reallocated between the two. Nesting them meant a
 * thread whose sync transfer held the entry lock also held the table lock on
 * every other thread's behalf, so one BULK with the "unlimited" timeout=0 that
 * usbdevfs documents wedged every usbdevfs fd in the process -- lookups on
 * unrelated fds, opens of other devices, and close(), which needs the same
 * table lock. Measured: an 18.6 s close() of an unrelated fd behind one 20 s
 * transfer. The in-code claim that this "briefly" stalled other fds' lookups
 * was neither brief nor bounded. The side-table half, for a caller that already
 * holds the fd-table snapshot the entry has to answer for -- one that pinned a
 * descriptor from it, say. Taking a second snapshot inside here instead would
 * prove the generation against a window of its own, so a close and reopen in
 * between would hand back the entry of the new description while the caller
 * went on using the old one's descriptor. The whole point of the parameter is
 * that this proves the caller's window and not another.
 */
static usbdev_t *usbdev_acquire_snap(int fd, const fd_entry_t *snap)
{
    usbdev_t *u = NULL;
    pthread_mutex_lock(&usbdev_table_lock);
    for (int i = 0; i < USBDEV_MAX_FDS; i++) {
        if (usbdev_fds[i].used && !usbdev_fds[i].dead &&
            usbdev_fds[i].guest_fd == fd &&
            usbdev_fds[i].generation == snap->generation) {
            u = &usbdev_fds[i];
            u->refs++;
            break;
        }
    }
    pthread_mutex_unlock(&usbdev_table_lock);
    if (!u)
        return NULL;
    pthread_mutex_lock(&u->lock);
    if (u->dead) {
        pthread_mutex_unlock(&u->lock);
        usbdev_unref(u);
        return NULL;
    }
    return u;
}

static usbdev_t *usbdev_acquire(int fd)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap) || snap.type != FD_USBDEV)
        return NULL;
    return usbdev_acquire_snap(fd, &snap);
}

/* Unlock and unpin an entry usbdev_acquire returned.
 *
 * The cross-fd disconnect walk is paid off in between, which is the whole
 * reason this is not two calls at each site: it needs the entry lock gone (it
 * takes the table lock, which never nests under an entry lock) and the pin
 * still held (it reads this slot's devkey). Every ioctl that can stamp a
 * disconnect leaves through here.
 */
static void usbdev_release(usbdev_t *u)
{
    pthread_mutex_unlock(&u->lock);
    usbdev_flush_disc_peers(u);
    usbdev_unref(u);
}

static void usbdev_teardown_locked(usbdev_t *u)
{
    /* Async teardown first: kill/drain every URB (release close: Linux kills
     * pending and frees completed, devio.c:1092-1128), then the notification
     * and the ep0 event source, so no callback can arrive for this slot after
     * the handles go away.
     */
    bool drained = usbdev_kill_urbs_locked(u, NULL);

    /* The device handle's half of the same question usbdev_release_locked asks
     * of an interface's: a whole-slot drain timeout unlinks its survivors, so
     * the rescan inside the kill comes back clean and only the orphan count
     * still knows u->dev and u->dev_src are referenced.
     */
    pthread_mutex_lock(&u->async_lock);
    if (u->dev_orphans != 0)
        drained = false;
    pthread_mutex_unlock(&u->async_lock);
    usbdev_free_completed(u);
    if (u->fake)
        usbdev_fixture_unwatch(usbdev_watch_token(u));
    if (u->notif != IO_OBJECT_NULL) {
        IOObjectRelease(u->notif);
        u->notif = IO_OBJECT_NULL;
    }
    if (u->dev_src) {
        CFRunLoopRef loop = usbdev_loop_current();
        if (loop && drained)
            CFRunLoopRemoveSource(loop, u->dev_src, kCFRunLoopDefaultMode);
        if (drained)
            CFRelease(u->dev_src);
        u->dev_src = NULL;
    }
    for (int i = 0; i < USBDEV_MAX_IFACES; i++)
        if (u->ifaces[i].claimed)
            (void) usbdev_release_locked(u, (unsigned) i);
    if (u->dev) {
        if (drained) {
            if (u->dev_open)
                (*u->dev)->USBDeviceClose(u->dev);
            (*u->dev)->Release(u->dev);
        } else {
            log_warn("usbdev: leaking device handle (undrained URBs)");
        }
        u->dev = NULL;
    }
    u->dev_open = false;
    u->dev_open_tried = false;
    if (u->service != IO_OBJECT_NULL) {
        IOObjectRelease(u->service);
        u->service = IO_OBJECT_NULL;
    }
    u->fake = false;

    /* Orphaned callbacks skip the pipe write, so closing it here is safe even
     * on the timeout path; -1 under async_lock keeps the callback's check and
     * this close ordered.
     */
    pthread_mutex_lock(&u->async_lock);
    int pw = u->pipe_wr;
    u->pipe_wr = -1;

    /* The pipe goes with the fd, so the token goes with it; the four disconnect
     * fields reset together here for the same reason they do in the open path.
     * Clearing disc_peers_pending is a slot reset, not a payment -- a caller
     * with a debt to settle takes it with usbdev_take_disc_debt before calling
     * this, because the walk it owes cannot run under the entry lock.
     */
    u->ready_token = false;
    u->disconnected = false;
    u->disc_drained = false;
    u->disc_orphan_at_ms = 0;
    atomic_store_explicit(&u->disc_peers_pending, false, memory_order_relaxed);
    pthread_mutex_unlock(&u->async_lock);
    if (pw >= 0)
        close(pw);
    free(u->blob);
    u->blob = NULL;

    /* Retire the lock-free mirrors last so no cross-fd reader can match a slot
     * that is mid-teardown.
     */
    claimed_mask_reset(u);
    devkey_retire(u);
}

static void usbdev_fd_cleanup(int guest_fd)
{
    /* The fd-table slot is already closed and free when this runs
     * (fd_cleanup_entry is called outside fd_lock), so a sibling thread's
     * open() can have won the same fd number and bound a second entry here
     * before this call arrives, and both entries then answer to it. Matching on
     * the number alone tore down whichever sat at the lower index -- about half
     * the time the NEW one, whose guest fd was still open and which then
     * reported EBADF on every use. The lane below drives 8000 open/read/close
     * rounds across four threads: with the tiebreak removed it loses fds on
     * every run (281, 313 and 371 over three), and none with it. The count is a
     * race and varies; that it is never zero without the tiebreak is the point.
     *
     * fd_alloc stamps a globally monotonic generation, so among entries that
     * answer to one fd number the closing one is always the one with the
     * smaller generation. The cleanup vtable is void(*)(int) and hands over no
     * snapshot, so that ordering is what identifies the entry.
     */
    pthread_mutex_lock(&usbdev_table_lock);
    usbdev_t *u = NULL;
    for (int i = 0; i < USBDEV_MAX_FDS; i++) {
        usbdev_t *o = &usbdev_fds[i];
        if (!o->used || o->dead || o->guest_fd != guest_fd)
            continue;
        if (!u || o->generation < u->generation)
            u = o;
    }
    if (!u) {
        pthread_mutex_unlock(&usbdev_table_lock);
        return;
    }
    u->dead = true;
    u->refs++;
    pthread_mutex_unlock(&usbdev_table_lock);

    /* Outside the table lock: a sync transfer in flight on this fd holds the
     * entry lock, and waiting for it here must not block every other fd.
     *
     * The debt comes off the slot before the teardown that would clear it and
     * retire the devkey the walk needs, and is paid once the entry lock is
     * down: a stamp this fd took and had not yet published -- an async
     * callback's, between its own unlock and its own flush -- still has peers
     * to tell, and the closing fd is the one that will never ask again.
     */
    pthread_mutex_lock(&u->lock);
    uint64_t debt = usbdev_take_disc_debt(u);
    usbdev_teardown_locked(u);
    pthread_mutex_unlock(&u->lock);
    usbdev_pay_disc_debt(debt, u);

    /* Clear the poll maps before the slot is released, and only while no live
     * entry answers to this fd number. fd_cleanup_entry runs after the number
     * is free for reuse, so a sibling's open() can already have bound a new
     * usbdevfs fd here; clearing unconditionally erased that fd's disconnect
     * bit and left its poll/select/epoll silent for good, and clearing after
     * usbdev_unref left the same window open against a freshly reused slot.
     */
    if (RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE)) {
        pthread_mutex_lock(&usbdev_table_lock);
        bool live = false;
        for (int i = 0; i < USBDEV_MAX_FDS; i++) {
            usbdev_t *o = &usbdev_fds[i];
            if (o != u && o->used && !o->dead && o->guest_fd == guest_fd)
                live = true;
        }
        if (!live) {
            discmap_clear(guest_fd);
            readymap_clear(guest_fd);
        }
        pthread_mutex_unlock(&usbdev_table_lock);
    }
    usbdev_unref(u);
}

void usbdev_init(void)
{
    pthread_mutex_lock(&usbdev_table_lock);
    if (!usbdev_ready) {
        for (int i = 0; i < USBDEV_MAX_FDS; i++) {
            memset(&usbdev_fds[i], 0, sizeof(usbdev_fds[i]));
            usbdev_fds[i].guest_fd = -1;
            usbdev_fds[i].pipe_wr = -1;
            usbdev_fds[i].notif = IO_OBJECT_NULL;
            pthread_mutex_init(&usbdev_fds[i].lock, NULL);
            pthread_mutex_init(&usbdev_fds[i].async_lock, NULL);
            pthread_cond_init(&usbdev_fds[i].async_cv, NULL);
        }
        usbdev_ready = true;
    }
    pthread_mutex_unlock(&usbdev_table_lock);
    fd_register_cleanup(FD_USBDEV, usbdev_fd_cleanup);
}

/* constructor */

/* Test seam: ELFUSE_USBDEV_OPEN_FAULT names one step of the open path and makes
 * it fail the way the host can, because none of the three failures the
 * constructor has to tell apart can be provoked from a guest.
 *
 *   info  the model lookup fails with ENOMEM rather than ENODEV
 *   blob  the descriptor copy fails with ENOMEM
 *   pipe  the readiness pipe cannot be created (ENFILE)
 *
 * Resolved once per process into an enum and cached, the shape
 * fd_identity_window_delay uses in syscall/fs-stat.c, so an open on the
 * failure-free path costs one relaxed load rather than a walk of the
 * environment for every stage it passes. tests/test-usbdev-ioctl.c drives all
 * three.
 */
typedef enum {
    USBDEV_FAULT_UNREAD = -1,
    USBDEV_FAULT_NONE = 0,
    USBDEV_FAULT_INFO,
    USBDEV_FAULT_BLOB,
    USBDEV_FAULT_PIPE,
} usbdev_open_fault_t;

static usbdev_open_fault_t usbdev_open_fault(void)
{
    static _Atomic int cached = USBDEV_FAULT_UNREAD;
    int v = atomic_load_explicit(&cached, memory_order_relaxed);
    if (v == USBDEV_FAULT_UNREAD) {
        const char *env = getenv("ELFUSE_USBDEV_OPEN_FAULT");
        v = USBDEV_FAULT_NONE;
        if (env && !strcmp(env, "info"))
            v = USBDEV_FAULT_INFO;
        else if (env && !strcmp(env, "blob"))
            v = USBDEV_FAULT_BLOB;
        else if (env && !strcmp(env, "pipe"))
            v = USBDEV_FAULT_PIPE;
        atomic_store_explicit(&cached, v, memory_order_relaxed);
    }
    return (usbdev_open_fault_t) v;
}

/* Widen one of the two windows usbdev_open_path leaves around the publish, off
 * unless the named variable holds a positive microsecond count. Same shape and
 * the same reasoning as fd_identity_window_delay in syscall/fs-stat.c: both
 * windows are real and a few instructions wide, and what the entry has to
 * survive is a guest that closes -- or closes and reopens -- a fd number it
 * predicted inside one of them. tests/test-usbdev-ioctl.c drives both.
 */
static void usbdev_window_delay(const char *name, _Atomic long *cached)
{
    long v = atomic_load_explicit(cached, memory_order_relaxed);
    if (v < 0) { /* -1 = unread */
        const char *env = getenv(name);
        long long n = env ? strtoll(env, NULL, 10) : 0;
        v = (n > 0 && n < 1000000) ? (long) n : 0;
        atomic_store_explicit(cached, v, memory_order_relaxed);
    }
    if (v > 0)
        usleep((useconds_t) v);
}

/* Between fd_alloc handing back the number and the side table binding it: the
 * entry is not yet findable by fd number, so a close lands on nothing.
 */
static void usbdev_publish_window_delay(void)
{
    static _Atomic long cached = -1;
    usbdev_window_delay("ELFUSE_USBDEV_PUBLISH_DELAY_US", &cached);
}

/* Between the bind and the recheck that follows it: the entry is findable and
 * therefore also freeable, so the close can reap it and a sibling open can take
 * the slot back before the recheck runs.
 */
static void usbdev_retire_window_delay(void)
{
    static _Atomic long cached = -1;
    usbdev_window_delay("ELFUSE_USBDEV_RETIRE_DELAY_US", &cached);
}

/* Retire an entry whose guest fd was closed before the entry could be found by
 * fd number. Claims it the way usbdev_fd_cleanup does -- dead under the table
 * lock, one reference held across the teardown -- so a cleanup arriving from
 * the other side can only claim it once.
 *
 * u is a raw pointer into static slot storage, and by the time this runs the
 * allocation it named can already be gone: the close reaps the entry,
 * usbdev_unref frees the slot, and a sibling usbdev_open_path binds its own
 * live fd there. Reading the slot is therefore always defined but never proof
 * of identity, so the claim is the whole tuple the caller allocated rather than
 * "not dead": used and alive, this fd number, this generation. Testing !dead
 * alone marked the sibling's entry dead, freed its blob and closed its pipe,
 * and the sibling's still-open fd answered EBADF on every read and ioctl -- the
 * failure usbdev_fd_cleanup's generation tiebreak exists to avoid, reintroduced
 * on the other side of the same window.
 */
static void usbdev_retire_unpublished(usbdev_t *u, int guest_fd, uint64_t gen)
{
    pthread_mutex_lock(&usbdev_table_lock);
    bool mine =
        u->used && !u->dead && u->guest_fd == guest_fd && u->generation == gen;
    if (mine) {
        u->dead = true;
        u->refs++;
    }
    pthread_mutex_unlock(&usbdev_table_lock);
    if (!mine)
        return;
    pthread_mutex_lock(&u->lock);
    uint64_t debt = usbdev_take_disc_debt(u);
    usbdev_teardown_locked(u);
    pthread_mutex_unlock(&u->lock);
    usbdev_pay_disc_debt(debt, u);
    usbdev_unref(u);
}

/* The rule every failure in usbdev_open_path answers to: carry the errno the
 * step that failed set, and translate exactly one of them. ENODEV is the model
 * saying nothing answers to this address, which is the ENOENT open(2) owes for
 * a name with nothing behind it. Every other errno means something else --
 * ENOMEM from an allocation, whatever mkdtemp or mkdir reported while the
 * scratch tree was being built -- and inventing ENOENT for those told the guest
 * a node was missing whenever the host was merely out of memory. Anything added
 * here later carries its errno the same way.
 */
static int64_t usbdev_open_errno(void)
{
    return errno == ENODEV ? -LINUX_ENOENT : linux_errno();
}

static bool usbdev_parse_node(const char *path, int *bus, int *dev)
{
    unsigned b, d;
    char tail;
    if (sscanf(path, "/dev/bus/usb/%3u/%3u%c", &b, &d, &tail) != 2)
        return false;

    /* Reject non-canonical spellings the tree never lists ("/dev/bus/usb/1/1"
     * still parses above; the scratch tree only carries %03d names, and the
     * stage-1 stat intercept agrees, so keep both views consistent).
     */
    char canon[64];
    snprintf(canon, sizeof(canon), "/dev/bus/usb/%03u/%03u", b, d);
    if (strcmp(canon, path) != 0)
        return false;
    *bus = (int) b;
    *dev = (int) d;
    return true;
}

int64_t usbdev_open_path(const char *path, int linux_flags)
{
    int bus, dev;
    if (!usbdev_parse_node(path, &bus, &dev))
        return INT64_MIN;

    /* O_PATH fds carry no I/O capability; the stage-1 placeholder (blob fd
     * typed FD_PATH, stat-stamped) serves them without burning a slot here.
     */
    if (linux_flags & LINUX_O_PATH)
        return INT64_MIN;

    /* Existence is decided before the flags are. A name that spells a node but
     * addresses no device is ENOENT whatever the caller asked for -- the kernel
     * refuses O_DIRECTORY only once the lookup has produced an inode -- and
     * answering ENOTDIR from the spelling alone let a sysroot file planted at
     * /dev/bus/usb/<unused bus>/001 turn every O_DIRECTORY open into the host's
     * answer for it, where open(2) without the flag reported ENOENT.
     */
    usb_sysfs_devinfo_t info;
    bool have_info;
    if (usbdev_open_fault() == USBDEV_FAULT_INFO) {
        errno = ENOMEM;
        have_info = false;
    } else {
        have_info = usb_sysfs_device_info(bus, dev, &info) == 0;
    }
    if (!have_info)
        return usbdev_open_errno();
    if (linux_flags & LINUX_O_DIRECTORY)
        return -LINUX_ENOTDIR;
    size_t blob_len = 0;
    uint8_t *blob;
    if (usbdev_open_fault() == USBDEV_FAULT_BLOB) {
        errno = ENOMEM;
        blob = NULL;
    } else {
        blob = usb_sysfs_descriptors_dup(bus, dev, &blob_len);
    }
    if (!blob)
        return usbdev_open_errno();

    /* The IOKit service is resolved on first use, not here: see
     * usbdev_ensure_service for why open(2) must not be the one entry point
     * onto this node that demands live hardware.
     */

    usbdev_t *u = NULL;
    pthread_mutex_lock(&usbdev_table_lock);
    for (int i = 0; i < USBDEV_MAX_FDS; i++) {
        if (!usbdev_fds[i].used) {
            u = &usbdev_fds[i];
            u->used = true;
            u->dead = false;
            u->refs = 0;
            u->guest_fd = -1;
            u->generation = 0;
            break;
        }
    }
    pthread_mutex_unlock(&usbdev_table_lock);
    if (!u) {
        free(blob);
        return -LINUX_ENOMEM;
    }

    /* Stays {-1, -1} when pipe() itself fails: the error arm below must not
     * close two indeterminate descriptors (netlink_socket's split).
     */
    int pipefd[2] = {-1, -1};
    bool pipe_ok;
    if (usbdev_open_fault() == USBDEV_FAULT_PIPE) {
        errno = ENFILE;
        pipe_ok = false;
    } else {
        pipe_ok = pipe(pipefd) == 0 && fd_set_nonblock(pipefd[0]) == 0 &&
                  fd_set_nonblock(pipefd[1]) == 0;
    }
    if (!pipe_ok) {
        /* Read the errno before the unwind: close() and pthread_mutex_lock()
         * may both set it. Reporting EMFILE unconditionally named the guest's
         * own descriptor limit for a failure that is the host's -- ENFILE, or
         * whatever fcntl reported -- and the guest cannot act on a limit it has
         * not reached.
         */
        int64_t err = linux_errno();
        if (pipefd[0] >= 0) {
            close(pipefd[0]);
            close(pipefd[1]);
        }
        pthread_mutex_lock(&usbdev_table_lock);
        u->used = false;
        pthread_mutex_unlock(&usbdev_table_lock);
        free(blob);
        return err;
    }
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

    pthread_mutex_lock(&u->lock);
    u->busnum = bus;
    u->devnum = dev;
    u->location_id = info.location_id;
    u->vid = info.vid;
    u->pid = info.pid;
    str_copy_trunc(u->serial, info.serial, sizeof(u->serial));
    u->speed_code = info.speed_code;
    u->cfg_value = info.cfg_value;
    u->blob = blob;
    u->blob_len = blob_len;
    u->pos = 0;
    u->pipe_wr = pipefd[1];
    u->service = IO_OBJECT_NULL;
    u->fake = false;
    u->dev = NULL;
    u->dev_orphans = 0;
    u->dev_serial = 0;
    u->dev_open = false;
    u->dev_open_tried = false;
    u->dev_src = NULL;
    u->notif = IO_OBJECT_NULL;
    memset(u->ifaces, 0, sizeof(u->ifaces));
    claimed_mask_reset(u);
    /* Nonzero while bound; equal for every fd open on the same device node. */
    devkey_publish(
        u, (1ull << 63) | ((uint64_t) (uint32_t) bus << 32) | (uint32_t) dev);
    u->pending_head = u->pending_tail = NULL;
    memset(u->ep_head, 0, sizeof(u->ep_head));
    memset(u->ep_tail, 0, sizeof(u->ep_tail));
    u->completed_head = u->completed_tail = NULL;
    u->inflight = 0;
    u->nurbs = 0;
    u->inflight_bytes = 0;
    u->ready_token = false;

    /* All four fields of the disconnect state, together: a slot whose previous
     * open drained after a disconnect would otherwise start this open with the
     * drain already claimed, and this open's own disconnect would issue no
     * aborts; a deadline left behind would have this open's first reap after a
     * disconnect orphan URBs the aborts had not been given their deadline to
     * answer for; an unpaid peer-walk debt left behind would have this open's
     * first ioctl stamp the whole device off the previous open's disconnect.
     * Nothing else clears them outside teardown -- usbdev_init zeroes the table
     * once, at startup.
     */
    u->disconnected = false;
    u->disc_drained = false;
    u->disc_orphan_at_ms = 0;
    atomic_store_explicit(&u->disc_peers_pending, false, memory_order_relaxed);
    u->discsig_signr = 0;
    u->discsig_context = 0;
    pthread_mutex_unlock(&u->lock);

    /* fd_alloc_from's out_gen, not a later read of the slot: the generation has
     * to be this allocation's own stamp, captured inside the fd_lock section
     * that stamped it. Re-deriving it after the slot was publishable read
     * whatever generation the number carried by then, which in the interleaving
     * below is a sibling allocation's -- see the publish.
     */
    uint64_t gen = 0;
    int guest_fd =
        fd_alloc_from(0, FD_USBDEV, pipefd[0], usbdev_fd_cleanup, &gen);
    if (guest_fd < 0) {
        close(pipefd[0]);
        pthread_mutex_lock(&u->lock);
        usbdev_teardown_locked(u);
        pthread_mutex_unlock(&u->lock);
        pthread_mutex_lock(&usbdev_table_lock);
        u->used = false;
        pthread_mutex_unlock(&usbdev_table_lock);
        return -LINUX_EMFILE;
    }

    /* Before anything else this fd number can be polled through: the previous
     * owner's cleanup runs after the number is free for reuse, so a bit it left
     * behind would make a brand-new healthy fd report POLLERR|POLLHUP.
     */
    if (RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE)) {
        discmap_clear(guest_fd);
        readymap_clear(guest_fd);
    }

    /* Stamp the node path so /proc/self/fd/N readlink reports the guest
     * spelling (stage-1 mechanism), and publish the fd's flags.
     */
    pthread_mutex_lock(&fd_lock);
    if (fd_table[guest_fd].type == FD_USBDEV &&
        fd_table[guest_fd].host_fd == pipefd[0])
        str_copy_trunc(fd_table[guest_fd].proc_path, path,
                       sizeof(fd_table[guest_fd].proc_path));
    pthread_mutex_unlock(&fd_lock);
    fd_publish_linux_flags(guest_fd, linux_flags);

    usbdev_publish_window_delay();
    pthread_mutex_lock(&usbdev_table_lock);
    u->guest_fd = guest_fd;
    u->generation = gen;
    pthread_mutex_unlock(&usbdev_table_lock);
    usbdev_retire_window_delay();

    /* Two windows, one identity.
     *
     * usbdev_fd_cleanup matches on guest_fd, which was -1 for everything above
     * the bind, so a close arriving before it found no entry to tear down and
     * left this one holding its table slot, its descriptor blob and the write
     * end of the pipe for the life of the process. The entry is findable now,
     * so ask the fd table whether the number is still the one that was
     * allocated: a generation that has moved, or a slot that is no longer this
     * type, means the close already came and went and this entry has to retire
     * itself. Both reads are taken outside usbdev_table_lock, which never nests
     * fd_lock. The fd number is still what open(2) returns -- the guest closed
     * it, which is its own race to lose, and Linux hands back a number a
     * sibling thread can have closed just as readily.
     *
     * What makes the retire land on this allocation and no other is the tuple,
     * and three facts about it rather than the shape of the code. Slot storage
     * is static and never freed, so reading u after the slot has been recycled
     * is defined. used, dead, guest_fd and generation are all written and read
     * under usbdev_table_lock, so the four are read as one value. And
     * fd_next_generation (fdtable.c:331) is a globally monotonic counter
     * stamped inside the allocating fd_lock section, so gen here is this
     * allocation's own number and can never be handed out again -- which is why
     * no two live entries can present the same {guest_fd, generation}, why
     * usbdev_acquire's match on that pair names exactly one entry, and why the
     * claim below can only reach the entry this call created. Both windows
     * follow from it: a close-and-reopen before the bind cannot make gen equal
     * the reopener's stamp, and a reap-and-reuse after the bind cannot make the
     * recycled slot answer to it.
     */
    if (fd_current_generation(guest_fd) != gen ||
        fd_get_type(guest_fd) != FD_USBDEV)
        usbdev_retire_unpublished(u, guest_fd, gen);
    return guest_fd;
}

/* read / lseek / fstat */

/* The two capability bits, derived the way the kernel derives them, once.
 *
 * OPEN_FMODE (fs.h:3631) is (flags + 1) & O_ACCMODE, not a comparison against
 * O_RDONLY: access modes 0, 1 and 2 give FMODE_READ, FMODE_WRITE and both, and
 * access mode 3 gives neither. Mode 3 is reachable -- open(2) takes it, and
 * ACC_MODE(3) asks the 0666 node for read plus write, which it grants -- so
 * Linux hands back a descriptor that can do nothing: vfs_read and vfs_write
 * answer EBADF and every usbdevfs ioctl answers EPERM.
 *
 * Each gate here used to test the access mode against O_RDONLY or O_WRONLY on
 * its own, so all four agreed on modes 0, 1 and 2 and all four were wrong on
 * mode 3: the fd read the descriptors blob and was handed the whole ioctl set.
 * One derivation with four callers is what keeps the fourth case from having to
 * be remembered four times.
 */
#define USBDEV_FMODE_READ 1u
#define USBDEV_FMODE_WRITE 2u

static unsigned usbdev_fmode(int linux_flags)
{
    return (unsigned) (((linux_flags & LINUX_O_ACCMODE) + 1) & 3);
}

static void usbdev_prefault_read_locked(usbdev_t *u,
                                        guest_t *g,
                                        uint64_t buf_gva,
                                        uint64_t count)
{
    uint64_t len = count < u->blob_len ? count : u->blob_len;
    if (!len)
        return;

    /* The acquire reference survives close; recheck the blob after relocking.
     */
    pthread_mutex_unlock(&u->lock);
    (void) guest_lazy_faultin(g, buf_gva, len);
    pthread_mutex_lock(&u->lock);
}

int64_t usbdev_read(int fd, guest_t *g, uint64_t buf_gva, uint64_t count)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap) || snap.type != FD_USBDEV)
        return -LINUX_EBADF;
    if (!(usbdev_fmode(snap.linux_flags) & USBDEV_FMODE_READ))
        return -LINUX_EBADF; /* vfs: read needs FMODE_READ */
    /* usbdev_read serves nothing once the device is gone (-ENODEV,
     * devio.c:323-325); lseek keeps working, as its llseek has no gate.
     */
    if (usbdev_fd_disconnected(fd))
        return -LINUX_ENODEV;
    usbdev_t *u = usbdev_acquire_snap(fd, &snap);
    if (!u)
        return -LINUX_EBADF;
    usbdev_prefault_read_locked(u, g, buf_gva, count);
    int64_t ret;
    if (!u->blob) {
        ret = -LINUX_EBADF;
    } else if ((uint64_t) u->pos >= u->blob_len || count == 0) {
        ret = 0;
    } else {
        size_t avail = u->blob_len - (size_t) u->pos;
        size_t n = count < avail ? (size_t) count : avail;
        if (guest_write_nofault(g, buf_gva, u->blob + u->pos, n) < 0) {
            ret = -LINUX_EFAULT;
        } else {
            u->pos += (off_t) n;
            ret = (int64_t) n;
        }
    }
    usbdev_release(u);
    return ret;
}

/* pread(2)/preadv(2) arm: the same descriptors blob, served at the caller's
 * offset. A positional read never moves the fd position (vfs pread), a negative
 * offset is -EINVAL (ksys_pread64 refuses it before the fd lookup, so it
 * outranks even -EBADF), and count 0 reads nothing.
 */
int64_t usbdev_pread(int fd,
                     guest_t *g,
                     uint64_t buf_gva,
                     uint64_t count,
                     int64_t offset)
{
    if (offset < 0)
        return -LINUX_EINVAL;
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap) || snap.type != FD_USBDEV)
        return -LINUX_EBADF;
    if (!(usbdev_fmode(snap.linux_flags) & USBDEV_FMODE_READ))
        return -LINUX_EBADF; /* vfs: read needs FMODE_READ */
    /* Same -ENODEV gate as usbdev_read: no read path serves a gone device. */
    if (usbdev_fd_disconnected(fd))
        return -LINUX_ENODEV;
    usbdev_t *u = usbdev_acquire_snap(fd, &snap);
    if (!u)
        return -LINUX_EBADF;
    usbdev_prefault_read_locked(u, g, buf_gva, count);
    int64_t ret;
    if (!u->blob) {
        ret = -LINUX_EBADF;
    } else if ((uint64_t) offset >= u->blob_len || count == 0) {
        ret = 0;
    } else {
        size_t avail = u->blob_len - (size_t) offset;
        size_t n = count < avail ? (size_t) count : avail;
        if (guest_write_nofault(g, buf_gva, u->blob + offset, n) < 0)
            ret = -LINUX_EFAULT;
        else
            ret = (int64_t) n;
    }
    usbdev_release(u);
    return ret;
}

int64_t usbdev_lseek_fd(int fd, int64_t offset, int whence)
{
    if (fd_get_type(fd) != FD_USBDEV)
        return INT64_MIN;
    usbdev_t *u = usbdev_acquire(fd);
    if (!u)
        return -LINUX_EBADF;
    int64_t ret;
    int64_t base;
    switch (whence) {
    case 0: /* SEEK_SET */
        base = 0;
        break;
    case 1: /* SEEK_CUR */
        base = u->pos;
        break;
    default: /* SEEK_END and friends: no_seek_end_llseek -> -EINVAL */
        usbdev_release(u);
        return -LINUX_EINVAL;
    }

    /* generic_file_llseek_size rejects a result that does not fit off_t
     * (-EINVAL). Computing it first is signed overflow, and it is reachable:
     * lseek(fd, INT64_MAX, SEEK_SET) followed by lseek(fd, 1, SEEK_CUR) wraps
     * negative.
     */
    int64_t npos;
    if (__builtin_add_overflow(base, offset, &npos) || npos < 0) {
        ret = -LINUX_EINVAL;
    } else {
        u->pos = (off_t) npos;
        ret = npos;
    }
    usbdev_release(u);
    return ret;
}

/* usbdevfs has no write op, so vfs_write answers -EBADF for a descriptor with
 * no FMODE_WRITE and -EINVAL for every other one (FMODE_CAN_WRITE), in that
 * order. write(2) had this and writev, pwrite and pwritev did not, so those
 * three fell through to the host descriptor behind the fd -- the read end of
 * the readiness pipe -- and answered -EBADF for a writable fd.
 *
 * Returns the Linux errno; the caller has already established the fd type.
 */
int64_t usbdev_write_refused(int fd)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap) || snap.type != FD_USBDEV)
        return -LINUX_EBADF;
    if (!(usbdev_fmode(snap.linux_flags) & USBDEV_FMODE_WRITE))
        return -LINUX_EBADF;
    return -LINUX_EINVAL;
}

/* The read half of the same question, for the empty-vector arm in io.c that has
 * to answer the direction test without going through usbdev_read. 0 when the
 * descriptor can read, -EBADF when it cannot.
 */
int64_t usbdev_read_refused(int fd)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap) || snap.type != FD_USBDEV)
        return -LINUX_EBADF;
    return (usbdev_fmode(snap.linux_flags) & USBDEV_FMODE_READ) ? 0
                                                                : -LINUX_EBADF;
}

int64_t usbdev_fstat(int fd, struct stat *st)
{
    usbdev_t *u = usbdev_acquire(fd);
    if (!u)
        return -LINUX_EBADF;
    int bus = u->busnum, dev = u->devnum;
    usbdev_release(u);
    if (usb_sysfs_node_stat(bus, dev, st) < 0)
        return -LINUX_ENODEV;
    return 0;
}

/* ioctl handlers (entry lock held unless noted) */

static int64_t usbdev_do_control(usbdev_t *u,
                                 guest_t *g,
                                 linux_usbdevfs_ctrltransfer_t ct)
{
    /* check_ctrlrecip (devio.c:878-935) runs before the wLength cap
     * (devio.c:1177-1183): a request naming an interface or endpoint the device
     * does not have is -ENOENT however long it is. Capping first answered
     * -EINVAL for requests Linux rejects by recipient.
     *
     * Vendor-type requests bypass the recipient check; interface/endpoint
     * recipients implicitly claim the owning interface first.
     */
    if ((ct.bRequestType & 0x60) != 0x40) {
        unsigned recip = ct.bRequestType & 0x1f;
        if (recip == 1) { /* interface */
            int64_t rc = usbdev_claim_locked(u, ct.wIndex & 0xff);
            if (rc < 0)
                return rc;
        } else if (recip == 2) { /* endpoint */
            int64_t rc = usbdev_check_ep_recip(u, ct.wIndex);
            if (rc < 0)
                return rc;
        }
    }
    if (ct.wLength > USBDEV_CTRL_MAX)
        return -LINUX_EINVAL;

    /* The allowance, taken where do_proc_control takes it: after the recipient
     * check and the wLength cap, before the buffer this transfer bounces
     * through, and given back on every exit from here down. Charging nothing
     * here was the one synchronous path outside the allowance: measured with
     * 16771328 bytes in flight, a sync BULK was refused -ENOMEM and a sync
     * CONTROL of wLength 4096 went through and reported 4096. Every exit below
     * the charge is a single one for that reason, the way the bulk path's is.
     */
    if (!usbdev_memory_charge(USBDEV_CTRL_CHARGE))
        return -LINUX_ENOMEM;

    uint8_t *buf = NULL;
    bool in = (ct.bRequestType & 0x80) != 0;
    int64_t ret = usbdev_ensure_dev_plugin(u);
    if (ret >= 0) {
        usbdev_lazy_device_open(u);
        ret = 0;
        if (ct.wLength > 0) {
            buf = malloc(ct.wLength);
            if (!buf)
                ret = -LINUX_ENOMEM;
        }
    }
    if (ret >= 0 && !in && ct.wLength > 0 &&
        guest_read_nofault(g, ct.data, buf, ct.wLength) < 0)
        ret = -LINUX_EFAULT;
    if (ret >= 0) {
        IOUSBDevRequestTO req = {
            .bmRequestType = ct.bRequestType,
            .bRequest = ct.bRequest,
            .wValue = ct.wValue,
            .wIndex = ct.wIndex,
            .wLength = ct.wLength,
            .pData = buf,
            .noDataTimeout = ct.timeout,
            .completionTimeout = ct.timeout,
        };
        IOReturn r = (*u->dev)->DeviceRequestTO(u->dev, &req);
        if ((uint32_t) r == (uint32_t) kIOReturnNotOpen && !u->dev_open) {
            /* Some requests demand an open device; retry once after opening. */
            IOReturn ro = (*u->dev)->USBDeviceOpen(u->dev);
            if (ro == kIOReturnSuccess) {
                u->dev_open = true;
                r = (*u->dev)->DeviceRequestTO(u->dev, &req);
            }
        }
        int64_t err = usbdev_ioret_op(u, r);
        if (err < 0) {
            /* On -ETIMEDOUT/-EINTR partial IN data is NOT copied out
             * (devio.c:1230).
             */
            ret = err;
        } else {
            int64_t actlen = req.wLenDone;
            ret = in && actlen > 0 &&
                          guest_write_nofault(g, ct.data, buf,
                                              (size_t) actlen) < 0
                      ? -LINUX_EFAULT
                      : actlen;
        }
    }
    free(buf);
    usbdev_memory_refund(USBDEV_CTRL_CHARGE);
    return ret;
}

static int64_t usbdev_do_bulk(usbdev_t *u,
                              guest_t *g,
                              linux_usbdevfs_bulktransfer_t bt)
{
    /* do_proc_bulk resolves and claims the endpoint's interface before it looks
     * at the length (devio.c:1289-1298), so an absent endpoint is -ENOENT
     * whatever the length says. Checking the length first answered -ENOMEM and
     * -EINVAL for requests Linux rejects by endpoint.
     */
    usbdev_iface_t *fi;
    uint8_t pipe;
    int64_t rc = usbdev_pipe_for_ep(u, bt.ep, &fi, &pipe);
    if (rc < 0)
        return rc;

    /* proc_bulk: only a near-INT_MAX length is malformed (-EINVAL,
     * devio.c:1298); a merely-too-large one fails the usbfs_memory_mb allowance
     * with -ENOMEM (devio.c:1308-1316).
     */
    if (bt.len >= (uint32_t) INT32_MAX)
        return -LINUX_EINVAL;

    uint8_t type = fi->pipe_type[pipe - 1];
    if (type == kUSBInterrupt) {
        /* Linux converts BULK-on-interrupt-ep to an interrupt URB
         * (devio.c:1327); ReadPipeTO/WritePipeTO reject interrupt pipes.
         * TODO(later): async submit + timed wait.
         */
        log_warn("usbdev: sync BULK on interrupt ep 0x%02x unsupported", bt.ep);
        return -LINUX_EINVAL;
    }
    if (type != kUSBBulk)
        return -LINUX_EINVAL; /* control/iso ep: proc_bulk EINVAL */

    /* The allowance, taken where Linux takes it: immediately before the buffer
     * this transfer needs (devio.c:1308-1316), and given back on every exit
     * from here down. The arms above answer EINVAL and run before the charge,
     * so their order is unchanged; everything below is charged, which is why
     * the OUT path's guest_read failure now joins the single exit instead of
     * returning from the middle.
     */
    uint64_t charge = (uint64_t) bt.len + USBDEV_URB_OVERHEAD;
    if (!usbdev_memory_charge(charge))
        return -LINUX_ENOMEM;

    uint8_t *buf = NULL;
    if (bt.len > 0) {
        buf = malloc(bt.len);
        if (!buf) {
            usbdev_memory_refund(charge);
            return -LINUX_ENOMEM;
        }
    }
    int64_t ret;
    if (bt.ep & 0x80) {
        UInt32 size = bt.len;
        IOReturn r = (*fi->intf)->ReadPipeTO(fi->intf, pipe, buf, &size,
                                             bt.timeout, bt.timeout);
        int64_t err = usbdev_ioret_op(u, r);
        if (err < 0) {
            ret = err; /* partial data not copied on error, as Linux */
        } else if (size > 0 && guest_write_nofault(g, bt.data, buf, size) < 0) {
            ret = -LINUX_EFAULT;
        } else {
            ret = size;
        }
    } else if (bt.len > 0 && guest_read_nofault(g, bt.data, buf, bt.len) < 0) {
        ret = -LINUX_EFAULT;
    } else {
        IOReturn r = (*fi->intf)->WritePipeTO(fi->intf, pipe, buf, bt.len,
                                              bt.timeout, bt.timeout);
        if ((uint32_t) r == (uint32_t) kIOReturnUnderrun) {
            /* WritePipeTO has no out-length, so the count actually sent is not
             * recoverable here. ioret_neg_errno folds Underrun into success for
             * the IN path, where IOKit does report the length; folding it here
             * would report a short write as a complete one.
             */
            log_warn("usbdev: short bulk OUT on ep 0x%02x, length unknown",
                     bt.ep);
            ret = -LINUX_EIO;
        } else {
            int64_t err = usbdev_ioret_op(u, r);
            ret = err < 0 ? err : bt.len;
        }
    }
    free(buf);
    usbdev_memory_refund(charge);
    return ret;
}

/* Whether another usbfs fd open on this device holds ifnum. Reads the lock-free
 * mirrors for the reason usbdev_claimed_elsewhere does: the caller holds its
 * own entry lock, and no path takes a second one.
 */
static bool usbdev_iface_claimed_elsewhere(const usbdev_t *u, unsigned ifnum)
{
    if (ifnum >= USBDEV_MAX_IFACES)
        return false;
    uint64_t key = devkey_load(u);
    for (int i = 0; i < USBDEV_MAX_FDS; i++) {
        const usbdev_t *o = &usbdev_fds[i];
        if (o == u)
            continue;
        if (devkey_load(o) == key &&
            (claimed_mask_load(o) & (1ull << ifnum)) != 0)
            return true;
    }
    return false;
}

static int64_t usbdev_do_getdriver(usbdev_t *u, guest_t *g, uint64_t arg)
{
    linux_usbdevfs_getdriver_t gd;
    if (guest_read_nofault(g, arg, &gd, sizeof(gd)) < 0)
        return -LINUX_EFAULT;

    /* Ahead of everything below: an interface question about a device that is
     * not reachable is -ENODEV, not "no driver" (devio.c's connected() gate).
     */
    int64_t drc = usbdev_ensure_dev_reachable(u);
    if (drc < 0)
        return drc;

    /* proc_getdriver: no such interface and no driver are the same answer,
     * -ENODATA (devio.c:1445-1446); usb_ifnum_to_if has no range error.
     */
    if (gd.interface >= USBDEV_MAX_IFACES)
        return -LINUX_ENODATA;
    memset(gd.driver, 0, sizeof(gd.driver));

    /* usbfs is one driver device-wide, so an interface another usbfs fd holds
     * reports usbfs here too, exactly as intf->dev.driver would.
     */
    if (u->ifaces[gd.interface].claimed ||
        usbdev_iface_claimed_elsewhere(u, gd.interface)) {
        str_copy_trunc(gd.driver, "usbfs", sizeof(gd.driver));
    } else {
        int64_t serr;
        io_service_t ifs = usbdev_iface_service(u, gd.interface, &serr);
        if (ifs == IO_OBJECT_NULL)
            return serr < 0 ? serr : -LINUX_ENODATA; /* usb_ifnum_to_if NULL */
        bool bound = usbdev_iface_driver(ifs, gd.driver, sizeof(gd.driver));
        IOObjectRelease(ifs);
        if (!bound)
            return -LINUX_ENODATA;
    }
    if (guest_write_nofault(g, arg, &gd, sizeof(gd)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

static int64_t usbdev_do_setinterface(usbdev_t *u, guest_t *g, uint64_t arg)
{
    linux_usbdevfs_setinterface_t si;
    if (guest_read_nofault(g, arg, &si, sizeof(si)) < 0)
        return -LINUX_EFAULT;
    int64_t rc = usbdev_claim_locked(u, si.interface); /* implicit claim */
    if (rc < 0)
        return rc;

    /* usb_altnum_to_altsetting compares the interface's __u8 bAlternateSetting
     * against the caller's unsigned argument (usb.c:391), so a value above 255
     * matches no altsetting and usb_set_interface answers -EINVAL
     * (message.c:1548). SetAlternateInterface takes a UInt8, and narrowing into
     * it made altsetting 256 select setting 0: an argument Linux refuses
     * changed the interface instead. Checked after the claim, because
     * proc_setintf runs checkintf before usb_set_interface (devio.c:1533-1539)
     * and a claim failure is the answer the guest gets first.
     */
    if (si.altsetting > 0xff)
        return -LINUX_EINVAL;
    usbdev_iface_t *fi = &u->ifaces[si.interface];

    /* proc_setintf kills the interface's URBs before switching altsettings
     * (devio.c:1529-1544); in-flight pipeRefs die with the old pipe table.
     */
    rc = usbdev_drain_for_change(u, fi->intf, "SETINTERFACE");
    if (rc < 0)
        return rc;
    IOReturn r =
        (*fi->intf)->SetAlternateInterface(fi->intf, (UInt8) si.altsetting);
    if (r != kIOReturnSuccess) {
        int64_t err = usbdev_ioret_op(u, r);
        log_debug("usbdev: SetAlternateInterface(%u, %u) -> 0x%x", si.interface,
                  si.altsetting, r);

        /* usb_set_interface answers -EINVAL for an altsetting the interface
         * does not have (usb_find_alt_setting NULL, message.c). IOKit's code
         * for that is not in the errno table, so it arrived as the map's
         * default -EPROTO, an errno no usbfs caller expects from an argument
         * mistake. Rewrite the two answers that can mean "bad altsetting" and
         * pass every other one through, so a device-loss or aborted-transfer
         * answer keeps its own meaning.
         */
        if (err == -LINUX_ENOENT || err == -LINUX_EPROTO)
            err = -LINUX_EINVAL;
        return err;
    }
    return usbdev_build_pipe_map(u, fi);
}

/* proc_setconfig's claim check is device-wide (usb_interface_claimed,
 * devio.c:1561-1576): a claim through ANY usbfs open of this device blocks
 * SetConfiguration, not only one through the calling fd. The caller holds its
 * own entry lock and no path takes a second one, so the other slots' entry
 * locks cannot be taken here; their lock-free mirrors are read instead.
 */
static bool usbdev_claimed_elsewhere(usbdev_t *u)
{
    uint64_t key = devkey_load(u);
    for (int i = 0; i < USBDEV_MAX_FDS; i++) {
        usbdev_t *o = &usbdev_fds[i];
        if (o == u)
            continue;
        if (devkey_load(o) == key && claimed_mask_load(o) != 0)
            return true;
    }
    return false;
}

static int64_t usbdev_do_setconfiguration(usbdev_t *u, guest_t *g, uint64_t arg)
{
    uint32_t cfg;
    if (guest_read_nofault(g, arg, &cfg, sizeof(cfg)) < 0)
        return -LINUX_EFAULT;
    /* -1/0 -> unconfigure (message.c:2064); SetConfiguration(0) does that. */
    if (cfg == 0xffffffffu)
        cfg = 0;
    if (cfg > 255)
        return -LINUX_EINVAL;

    /* proc_setconfig: -EBUSY when ANY interface of the device is claimed -- by
     * this fd, by another usbfs fd, or by a bound host driver
     * (devio.c:1561-1578).
     */
    for (int i = 0; i < USBDEV_MAX_IFACES; i++)
        if (u->ifaces[i].claimed)
            return -LINUX_EBUSY;
    if (usbdev_claimed_elsewhere(u))
        return -LINUX_EBUSY;

    /* A bound host (Apple) driver claims its interface exactly like a Linux
     * driver would (usb_interface_claimed covers every driver, not just usbfs):
     * one iterator pass over the device's interfaces.
     *
     * Invariant: an enumeration that did not run is that failure's answer, not
     * "no driver is bound". Discarding it here let a departed device reach
     * SetConfiguration with bound == false, and SETCONFIGURATION then answered
     * whatever the wire made of a config change on a device that was gone,
     * stamping nothing -- where Linux's connected() gate answers -ENODEV. It is
     * also the only check standing between a bound host driver and a
     * configuration change.
     */
    int64_t rc;
    io_iterator_t it = usbdev_iface_iterator(u, &rc);
    if (rc < 0)
        return rc;
    bool bound = false;
    io_service_t svc;
    while ((svc = IOIteratorNext(it))) {
        char drv[64];
        if (!bound && usbdev_iface_driver(svc, drv, sizeof(drv)))
            bound = true;
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);
    if (bound)
        return -LINUX_EBUSY;
    usbdev_lazy_device_open(u);
    if (!u->dev_open)
        return -LINUX_EBUSY; /* exclusive holder elsewhere */

    /* usb_set_configuration -> usb_disable_device kills every URB on the
     * device, ep0 included. The -EBUSY check above only looks at interfaces,
     * and the default control pipe is exactly the queue no interface claim
     * covers, so a control URB could otherwise ride across the change.
     */
    rc = usbdev_drain_for_change(u, NULL, "SETCONFIGURATION");
    if (rc < 0)
        return rc;
    IOReturn r = (*u->dev)->SetConfiguration(u->dev, (UInt8) cfg);
    if (r != kIOReturnSuccess) {
        int64_t err = usbdev_ioret_op(u, r);
        return err == -LINUX_ENOENT ? -LINUX_EINVAL : err;
    }
    u->cfg_value = cfg;
    return 0;
}

static int64_t usbdev_do_clear_halt(usbdev_t *u, guest_t *g, uint64_t arg)
{
    uint32_t ep;
    if (guest_read_nofault(g, arg, &ep, sizeof(ep)) < 0)
        return -LINUX_EFAULT;
    usbdev_iface_t *fi;
    uint8_t pipe;
    int64_t rc = usbdev_pipe_for_ep(u, ep, &fi, &pipe);
    if (rc < 0)
        return rc;

    /* ClearPipeStallBothEnds == CLEAR_FEATURE(ENDPOINT_HALT) + host-side toggle
     * reset (IOUSBLib.h:2927-2942), exactly usb_clear_halt on the wire.
     *
     * It also aborts whatever is outstanding on that pipe, and IOKit exposes no
     * variant that does not. Linux's check_reset_of_active_ep (devio.c:
     * 1382-1394) only dev_warn()s and leaves the queue alone, so an async URB
     * parked on the endpoint survives a CLEAR_HALT there and reaps -ECONNRESET
     * here. libusb calls libusb_clear_halt between transfers, so this is
     * reachable in ordinary use; it is a printed XFAIL in
     * tests/test-usbdev-ioctl.c and a bullet in the deviations list under USB
     * Device Passthrough in docs/internals.md -- not a row of the Deviations
     * From Linux table further down, which does not carry it -- rather than
     * something the engine can fix.
     */
    return usbdev_ioret_op(u,
                           (*fi->intf)->ClearPipeStallBothEnds(fi->intf, pipe));
}

static int64_t usbdev_do_resetep(usbdev_t *u, guest_t *g, uint64_t arg)
{
    /* proc_resetep is a host-side toggle/seq reset only (message.c:1377).
     * ClearPipeStallBothEnds is the closest IOKit equivalent (it also sends the
     * wire CLEAR_FEATURE, a benign superset).
     */
    return usbdev_do_clear_halt(u, g, arg);
}

static int64_t usbdev_do_disconnect_claim(usbdev_t *u, guest_t *g, uint64_t arg)
{
    linux_usbdevfs_disconnect_claim_t dc;
    if (guest_read_nofault(g, arg, &dc, sizeof(dc)) < 0)
        return -LINUX_EFAULT;

    /* Ahead of the interface-number check, not merely ahead of the interface
     * answer: usbdev_do_ioctl's connected() gate runs before
     * proc_disconnect_claim is entered at all, so a device that is gone is
     * -ENODEV for every interface number, in range or out of it.
     */
    int64_t drc = usbdev_ensure_dev_reachable(u);
    if (drc < 0)
        return drc;

    /* proc_disconnect_claim has no range check of its own: usb_ifnum_to_if
     * answers for the number and a NULL result is -EINVAL (devio.c:2467-2469),
     * which is the opposite of claimintf's -ENOENT for the same shape.
     */
    if (dc.interface >= USBDEV_MAX_IFACES)
        return -LINUX_EINVAL;
    dc.driver[sizeof(dc.driver) - 1] = '\0';

    char drv[256] = "";
    bool bound = false;
    if (u->ifaces[dc.interface].claimed ||
        usbdev_iface_claimed_elsewhere(u, dc.interface)) {
        str_copy_trunc(drv, "usbfs", sizeof(drv));
        bound = true;
    } else {
        int64_t serr;
        io_service_t ifs = usbdev_iface_service(u, dc.interface, &serr);
        if (ifs == IO_OBJECT_NULL)
            return serr < 0 ? serr : -LINUX_EINVAL;
        bound = usbdev_iface_driver(ifs, drv, sizeof(drv));
        IOObjectRelease(ifs);
    }
    if (bound) {
        if ((dc.flags & USBDEVFS_DISCONNECT_CLAIM_IF_DRIVER) &&
            strcmp(dc.driver, drv) != 0)
            return -LINUX_EBUSY;
        if ((dc.flags & USBDEVFS_DISCONNECT_CLAIM_EXCEPT_DRIVER) &&
            strcmp(dc.driver, drv) == 0)
            return -LINUX_EBUSY;
        if (strcmp(drv, "usbfs") != 0) {
            /* A real (Apple) driver would need whole-device capture, which
             * requires root or com.apple.vm.device-access; mirror the
             * privileges-dropped Linux answer (devio.c:2475-2476).
             */
            return -LINUX_EACCES;
        }
    }
    return usbdev_claim_locked(u, dc.interface);
}

static int64_t usbdev_do_driver_ioctl(usbdev_t *u, guest_t *g, uint64_t arg)
{
    linux_usbdevfs_ioctl_t ic;
    if (guest_read_nofault(g, arg, &ic, sizeof(ic)) < 0)
        return -LINUX_EFAULT;

    /* Ahead of the interface-number check, for the reason
     * usbdev_do_disconnect_claim gives: connected() runs before proc_ioctl,
     * which then repeats it for itself before it looks the number up.
     */
    int64_t drc = usbdev_ensure_dev_reachable(u);
    if (drc < 0)
        return drc;
    if (ic.ifno < 0 || ic.ifno >= USBDEV_MAX_IFACES)
        return -LINUX_EINVAL;
    unsigned ifnum = (unsigned) ic.ifno;
    switch ((uint32_t) ic.ioctl_code) {
    case USBDEVFS_IOCTL_DISCONNECT: {
        if (u->ifaces[ifnum].claimed)
            return usbdev_release_locked(u, ifnum); /* unbind "usbfs" */
        if (usbdev_iface_claimed_elsewhere(u, ifnum)) {
            /* Linux releases the usbfs claim whichever open made it and answers
             * 0. The claim here is another fd's IOKit handle, which this one
             * cannot close (documented gap).
             */
            return -LINUX_EBUSY;
        }
        int64_t serr;
        io_service_t ifs = usbdev_iface_service(u, ifnum, &serr);
        if (ifs == IO_OBJECT_NULL)
            return serr < 0 ? serr : -LINUX_EINVAL;
        char drv[64];
        bool bound = usbdev_iface_driver(ifs, drv, sizeof(drv));
        IOObjectRelease(ifs);
        if (!bound)
            return -LINUX_ENODATA;
        return -LINUX_EACCES; /* cannot unbind Apple drivers non-root */
    }
    case USBDEVFS_IOCTL_CONNECT: {
        /* proc_ioctl: an interface that already has a driver is -EBUSY, and
         * only a free one reaches device_attach (devio.c:2362-2368). Re-attach
         * itself stays out of reach -- IOKit rematches on its own schedule --
         * but answering -EACCES for the bound case reported the wrong reason
         * for a call Linux never gets that far with.
         */
        if (u->ifaces[ifnum].claimed ||
            usbdev_iface_claimed_elsewhere(u, ifnum))
            return -LINUX_EBUSY;
        int64_t serr;
        io_service_t ifs = usbdev_iface_service(u, ifnum, &serr);
        if (ifs == IO_OBJECT_NULL)
            return serr < 0 ? serr : -LINUX_EINVAL;
        char drv[64];
        bool bound = usbdev_iface_driver(ifs, drv, sizeof(drv));
        IOObjectRelease(ifs);
        if (bound)
            return -LINUX_EBUSY;
        return -LINUX_EACCES; /* device_attach needs the host's consent */
    }
    default:
        return -LINUX_ENOTTY;
    }
}

/* async URB ioctls */

/* SUBMITURB (proc_do_submiturb, doc A section A3). Entry lock held. */
static int64_t usbdev_do_submiturb(usbdev_t *u,
                                   guest_t *g,
                                   uint64_t arg,
                                   linux_usbdevfs_urb_t uu)
{
    /* The flags mask, USBFS_XFER_MAX and the null buffer, in the kernel's order
     * (usbdev-urb.h). A negative buffer_length is covered by the unsigned
     * compare, exactly as it is in devio.c:1647.
     */
    int64_t argrc = usbdev_urb_arg_check(uu.type, uu.flags, uu.buffer_length,
                                         uu.buffer == 0);
    if (argrc < 0)
        return argrc;

    bool is_in;
    uint32_t data_len;
    uint64_t data_gva;
    usbdev_iface_t *fi = NULL;
    uint8_t pipe = 0;
    bool pipe_interrupt = false;
    uint16_t mps = 0;
    IOUSBDevRequestTO req;
    memset(&req, 0, sizeof(req));

    /* Resolve the endpoint before the per-type checks, and before the control
     * arm's own length rule. proc_do_submiturb runs findintfep + checkintf +
     * ep_to_host_endpoint at devio.c:1651-1661 and only then switches on the
     * type, so an endpoint that does not exist is -ENOENT no matter how
     * malformed the rest of the request is. pr-c's synchronous do_proc_bulk
     * already carries that rule in a comment of its own; the async path was
     * written the other way round and answered -EINVAL for requests Linux
     * rejects by endpoint. Default-control-pipe URBs skip the lookup, which is
     * the same exemption the kernel writes at devio.c:1651.
     */
    bool ep0_control =
        uu.type == LINUX_URB_TYPE_CONTROL && (uu.endpoint & 0x7f) == 0;
    if (!ep0_control) {
        int64_t rc = usbdev_pipe_for_ep(u, uu.endpoint, &fi, &pipe);
        if (rc < 0)
            return rc;
    }

    switch (uu.type) {
    case LINUX_URB_TYPE_CONTROL:
    case LINUX_URB_TYPE_BULK:
    case LINUX_URB_TYPE_INTERRUPT:
        break;
    case LINUX_URB_TYPE_ISO:
        log_warn("usbdev: ISO URBs unsupported (doc A section A7.4)");
        return -LINUX_EINVAL;
    default:
        return -LINUX_EINVAL;
    }

    /* Accepted and never raised: elfuse has no async guest-signal injection
     * from the event thread, so the completion signal proc_do_submiturb arms
     * (async_completed -> kill_pid_usb_asyncio, devio.c:657) is a documented
     * gap, printed as an XFAIL by tests/test-usbdev-ioctl.c beside
     * DISCSIGNAL's.
     */
    if (uu.signr)
        log_warn(
            "usbdev: URB completion signal %u accepted but never delivered",
            uu.signr);

    if (uu.type == LINUX_URB_TYPE_CONTROL) {
        /* Buffer = 8-byte setup + wLength data (devio.c:1671-1683). */
        uint8_t setup[8];
        if (uu.buffer_length < 8)
            return -LINUX_EINVAL;
        if (guest_read_nofault(g, uu.buffer, setup, sizeof(setup)) < 0)
            return -LINUX_EFAULT;
        uint16_t wLength = (uint16_t) (setup[6] | (setup[7] << 8));
        if ((uint32_t) uu.buffer_length - 8 < wLength)
            return -LINUX_EINVAL;

        /* check_ctrlrecip: vendor requests bypass; IF/EP recipients claim the
         * owning interface implicitly (devio.c:881-938).
         */
        if ((setup[0] & 0x60) != 0x40) {
            unsigned recip = setup[0] & 0x1f;
            uint16_t wIndex = (uint16_t) (setup[4] | (setup[5] << 8));
            if (recip == 1) {
                int64_t rc = usbdev_claim_locked(u, wIndex & 0xff);
                if (rc < 0)
                    return rc;
            } else if (recip == 2) {
                int64_t rc = usbdev_check_ep_recip(u, wIndex);
                if (rc < 0)
                    return rc;
            }
        }

        /* Zero-length control IN is an OUT for the transfer's purposes
         * (devio.c:1690-1696).
         */
        is_in = (setup[0] & 0x80) != 0 && wLength != 0;
        data_len = wLength;
        data_gva = uu.buffer + 8;
        req.bmRequestType = setup[0];
        req.bRequest = setup[1];
        req.wValue = (UInt16) (setup[2] | (setup[3] << 8));
        req.wIndex = (UInt16) (setup[4] | (setup[5] << 8));
        req.wLength = wLength;
        req.noDataTimeout = 0; /* usbfs URBs never time out */
        req.completionTimeout = 0;
        if (!ep0_control) {
            if (fi->pipe_type[pipe - 1] != kUSBControl)
                return -LINUX_EINVAL;
            int64_t rc = usbdev_ensure_iface_async(u, fi);
            if (rc < 0)
                return rc;
        } else {
            int64_t rc = usbdev_ensure_dev_async(u);
            if (rc < 0)
                return rc;
        }
    } else {
        is_in = (uu.endpoint & 0x80) != 0;
        uint8_t ptype = fi->pipe_type[pipe - 1];
        if (uu.type == LINUX_URB_TYPE_BULK) {
            if (ptype != kUSBBulk && ptype != kUSBInterrupt)
                return -LINUX_EINVAL; /* control/iso ep (devio.c:1715-1717) */
        } else {
            if (ptype != kUSBInterrupt)
                return -LINUX_EINVAL;
        }
        pipe_interrupt = ptype == kUSBInterrupt;
        int64_t rc = usbdev_ensure_iface_async(u, fi);
        if (rc < 0)
            return rc;
        data_len = (uint32_t) uu.buffer_length;
        data_gva = uu.buffer;
        mps = fi->pipe_mps[pipe - 1];
    }

    /* One process-wide byte budget, no URB-count cap (usbdev-urb.h). */
    size_t charge = data_len + sizeof(usbdev_urb_t);
    if (!usbdev_memory_charge(charge))
        return -LINUX_ENOMEM;
    pthread_mutex_lock(&u->async_lock);
    u->nurbs++;
    u->inflight_bytes += charge;
    pthread_mutex_unlock(&u->async_lock);

    usbdev_urb_t *rec = calloc(1, sizeof(*rec));
    uint8_t *buf = NULL;
    if (rec && data_len > 0)
        buf = malloc(data_len);
    if (!rec || (data_len > 0 && !buf)) {
        free(buf);
        free(rec);
        pthread_mutex_lock(&u->async_lock);
        u->nurbs--;
        u->inflight_bytes -= charge;
        pthread_mutex_unlock(&u->async_lock);
        usbdev_memory_refund(charge);
        return -LINUX_ENOMEM;
    }
    if (!is_in && data_len > 0 &&
        guest_read_nofault(g, data_gva, buf, data_len) < 0) {
        free(buf);
        free(rec);
        pthread_mutex_lock(&u->async_lock);
        u->nurbs--;
        u->inflight_bytes -= charge;
        pthread_mutex_unlock(&u->async_lock);
        usbdev_memory_refund(charge);
        return -LINUX_EFAULT;
    }

    urb_owner_store(rec, u);
    rec->charge = charge;
    rec->userurb = arg;
    rec->data_gva = data_gva;
    rec->type = uu.type;
    rec->ep = uu.endpoint;
    /* Both ep0 directions share the default control pipe: one FIFO key. */
    rec->ep_key =
        (uu.type == LINUX_URB_TYPE_CONTROL && (uu.endpoint & 0x7f) == 0)
            ? 0
            : uu.endpoint;
    rec->pipe = pipe;
    rec->intf = fi ? fi->intf : NULL;
    rec->is_in = is_in;

    /* Direction-mismatched flags are ignored, not rejected (devio.c honors
     * SHORT_NOT_OK for IN and ZERO_PACKET for OUT only, 1710-1737).
     */
    rec->short_not_ok = is_in && (uu.flags & LINUX_URB_SHORT_NOT_OK) != 0;
    rec->zero_packet = !is_in && (uu.flags & LINUX_URB_ZERO_PACKET) != 0;
    rec->pipe_interrupt = pipe_interrupt;
    rec->state = URB_QUEUED;
    rec->data_len = data_len;
    rec->mps = mps;
    rec->buf = buf;
    rec->req = req;

    pthread_mutex_lock(&u->async_lock);
    rec->seq = ++u->urb_seq;
    bool busy = u->ep_head[rec->ep_key] != NULL;
    urb_pending_append(u, rec);
    if (usbdev_ep_may_start(u->draining, u->ep_aborting[rec->ep_key], busy)) {
        /* Endpoint idle: hand it to IOKit now. Queued follow-ups start from the
         * completion callback (one in-flight URB per endpoint keeps DISCARDURB
         * per-URB, see file header).
         */
        IOReturn ir = usbdev_urb_start(rec);
        if (ir != kIOReturnSuccess) {
            urb_pending_unlink(u, rec);
            urb_free_locked(u, rec);
            pthread_mutex_unlock(&u->async_lock);
            if (usbdev_ioret_device_gone(ir))
                usbdev_mark_disconnected(u);

            /* proc_do_submiturb has no -EINTR arm: an abort racing the start is
             * a canceled transfer, not an interrupted syscall, and
             * ioret_neg_errno's Aborted row is the syscall map.
             */
            int64_t e = (uint32_t) ir == (uint32_t) kIOReturnAborted
                            ? -LINUX_EPROTO
                            : ioret_neg_errno(ir);
            return e < 0 ? e : -LINUX_EPROTO;
        }
        rec->state = URB_INFLIGHT;
        u->inflight++;
    }
    pthread_mutex_unlock(&u->async_lock);
    return 0;
}

/* DISCARDURB (proc_unlinkurb): arg is the user URB pointer. Entry lock held. A
 * QUEUED record completes locally as killed (-ENOENT); an INFLIGHT one is
 * flagged and aborted.
 *
 * Two things IOKit does not give for free. AbortPipe cancels everything
 * outstanding on the pipe, not one transfer, so the endpoint's FIFO is shut for
 * the duration of the abort (ep_aborting) -- without that the target could
 * complete normally inside the unlock window, the callback would start the
 * queued follower, and the abort would land on the follower instead: measured
 * at a few per hundred thousand naturally, and reproducibly with the window
 * widened, as the discarded URB reporting success and its innocent successor
 * -ECONNRESET. And AbortPipe is asynchronous where the kernel call on this path
 * is synchronous, so this waits for the record to leave the pending list before
 * returning, which is what makes a REAPURBNDELAY issued straight after the
 * discard find the URB the way it does on Linux.
 *
 * Which kernel call that is has been read the wrong way round twice, so it is
 * written out here rather than left to the name: proc_unlinkurb calls
 * usb_kill_urb, NOT usb_unlink_urb. usb_unlink_urb is the asynchronous one
 * ("Success is indicated by returning -EINPROGRESS, at which time the URB will
 * probably not yet have been given back"); usb_kill_urb is the one that waits
 * ("It is guaranteed that upon return all completion handlers will have
 * finished and the URB will be totally idle"), and it is the one DISCARDURB
 * reaches. So waiting here is what matches Linux and returning early is what
 * would diverge from it -- a guest that cancels and then reaps gets its URB on
 * both, and libusb_cancel_transfer blocks for the transfer's lifetime on Linux
 * too.
 *
 * The deliberate divergence is the bound, not the wait: usb_kill_urb never
 * gives up, and this gives up after 2 s, logs, and leaves the record flagged
 * and still reapable when its completion arrives. Trading an unbounded stall of
 * a vCPU thread against a wire that may never answer is the same call
 * usbdev_drain_for_change makes, and it is the discard-latency XFAIL printed by
 * tests/test-usbdev-ioctl.c plus a bullet in the deviations list under USB
 * Device Passthrough in docs/internals.md, which is prose there and not a row
 * of the Deviations From Linux table below it.
 */
static int64_t usbdev_do_discardurb(usbdev_t *u, uint64_t arg)
{
    pthread_mutex_lock(&u->async_lock);
    usbdev_urb_t *rec = u->pending_head;
    while (rec && (rec->userurb != arg || rec->discarding))
        rec = rec->next;
    if (!rec) {
        pthread_mutex_unlock(&u->async_lock);

        /* Not this fd's URB, and possibly not this fd's device either. The scan
         * above reads the pending list and nothing else, which is this layer's
         * own bookkeeping and stays true after the device leaves, so a departed
         * device answered -EINVAL with the fd left unstamped where
         * proc_unlinkurb sits behind usbdev_do_ioctl's connected() gate and
         * Linux answers -ENODEV. libusb_cancel_transfer hands its return
         * straight to the application, so an unplug arrived there as
         * LIBUSB_ERROR_NOT_FOUND -- "the transfer is already complete" -- and
         * not as LIBUSB_ERROR_NO_DEVICE. Row DISCARDURB.
         *
         * Only on this arm: a discard that finds its record goes on to
         * AbortPipe, which puts the question to the device itself, so the
         * cancel a guest actually issues pays nothing for this.
         */
        int64_t drc = usbdev_ensure_dev_reachable(u);
        return drc < 0 ? drc : -LINUX_EINVAL; /* not pending */
    }
    if (rec->state == URB_QUEUED) {
        urb_pending_unlink(u, rec);
        urb_complete_locked(u, rec, -LINUX_ENOENT);
        pthread_mutex_unlock(&u->async_lock);
        return 0;
    }
    rec->discarding = true;
    uint8_t pipe = rec->pipe;
    uint8_t key = rec->ep_key;
    uint64_t seq = rec->seq;
    IOUSBInterfaceInterface800 **intf = rec->intf;
    u->ep_aborting[key]++;
    pthread_mutex_unlock(&u->async_lock);

    /* The interface handle cannot be released concurrently: release paths need
     * the entry lock this thread holds.
     */
    IOReturn ar = pipe == 0 ? (*u->dev)->USBDeviceAbortPipeZero(u->dev)
                            : (*intf)->AbortPipe(intf, pipe);

    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;
    pthread_mutex_lock(&u->async_lock);
    if (u->ep_aborting[key] > 0)
        u->ep_aborting[key]--;

    /* An abort that answers kIOReturnNoDevice aborted nothing, and both of
     * these used to discard it: the record stayed URB_INFLIGHT in pending, the
     * fd was never stamped, and the wait below sat out its whole two seconds
     * before returning 0 to a guest whose following REAPURB then never
     * returned. Measured with a device-gone abort: DISCARDURB rc=0 after 2006
     * ms, fd unstamped, REAPURB killed at 20 s.
     *
     * Two things are owed. The stamp, because usbdev_arm_disconnect_watch names
     * kIOReturnNoDevice detection on ops as its fallback and this is such an op
     * -- the same reason usbdev_kick_ep_locked stamps when a start answers it.
     * And the URB, because proc_unlinkurb is usb_kill_urb, which always leaves
     * the URB reapable; a cancel that hands nothing back is the one thing this
     * path may not do.
     *
     * It is handed back as an orphan rather than completed outright, which is
     * the same answer the drain deadline gives a record it has given up on and
     * for the same reason: the refusal says the user client has no device
     * behind it, not that IOKit has forgotten the transfer, so the record is
     * reapable at once while the buffer and the handles it references stay
     * pinned until a callback that may never come. Completing it outright would
     * let the reap free a record IOKit still holds the address of.
     */
    if (usbdev_ioret_device_gone(ar)) {
        usbdev_mark_disconnected_locked(u);
        for (usbdev_urb_t *r = u->pending_head; r; r = r->next) {
            if (r->seq != seq)
                continue;
            if (r->state == URB_INFLIGHT)
                urb_orphan_locked(u, r);
            break;
        }
        pthread_cond_broadcast(&u->async_cv);
    }
    for (;;) {
        bool still = false;
        for (usbdev_urb_t *r = u->pending_head; r; r = r->next) {
            if (r->seq == seq) {
                still = true;
                break;
            }
        }
        if (!still)
            break;

        /* Bounded, because a wire that never answers must not park the vCPU
         * thread forever: the record stays flagged and its completion is still
         * reapable when it arrives.
         */
        if (pthread_cond_timedwait(&u->async_cv, &u->async_lock, &deadline) ==
            ETIMEDOUT) {
            log_warn("usbdev: DISCARDURB abort did not settle in 2s");
            break;
        }
    }
    usbdev_kick_ep_locked(u, key);
    pthread_mutex_unlock(&u->async_lock);
    return 0;
}

/* Copy one completion back to the guest (vCPU thread): IN data into the urb's
 * buffer, then status/actual_length/error_count into the guest urb, then the
 * userurb pointer into *arg (processcompl, devio.c:2043-2079). Runs under the
 * entry lock, so nothing here faults: SUBMITURB faulted in the urb and its
 * buffer, and usbdev_do_reap faults in the slot arg names.
 */
static int64_t usbdev_reap_copyout(guest_t *g, usbdev_urb_t *rec, uint64_t arg)
{
    if (rec->is_in && rec->actual > 0 &&
        guest_write_nofault(
            g, rec->data_gva, rec->buf,
            rec->actual < rec->data_len ? rec->actual : rec->data_len) < 0)
        return -LINUX_EFAULT;
    int32_t st = rec->status;
    int32_t act = (int32_t) rec->actual;
    int32_t ec = 0;
    if (guest_write_nofault(
            g, rec->userurb + offsetof(linux_usbdevfs_urb_t, status), &st,
            sizeof(st)) < 0 ||
        guest_write_nofault(
            g, rec->userurb + offsetof(linux_usbdevfs_urb_t, actual_length),
            &act, sizeof(act)) < 0 ||
        guest_write_nofault(
            g, rec->userurb + offsetof(linux_usbdevfs_urb_t, error_count), &ec,
            sizeof(ec)) < 0)
        return -LINUX_EFAULT;
    if (guest_write_nofault(g, arg, &rec->userurb, sizeof(rec->userurb)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* Between the fd-table window a reap pass opens and the side-table lookup that
 * has to answer for it, off unless ELFUSE_USBDEV_REAP_DELAY_US is set. The
 * window is a few instructions wide unaided; what lives in it is a sibling's
 * close and reopen of the fd number, which used to give this pass an entry from
 * the new description and a readiness pipe from the old one.
 */
static void usbdev_reap_window_delay(void)
{
    static _Atomic long cached = -1;
    usbdev_window_delay("ELFUSE_USBDEV_REAP_DELAY_US", &cached);
}

/* REAPURB / REAPURBNDELAY. Called WITHOUT the entry lock held so a blocked reap
 * never stalls submits or discards; each pass revalidates the fd. Blocking
 * follows reap_as (devio.c:2081-2102) and the proc_reapurb that calls it
 * (devio.c:2104-2119): reap_as wakes on completion or disconnect and returns
 * what it found, and proc_reapurb turns an empty return into -EINTR without
 * restart on a signal and -ENODEV once disconnected and drained
 * (REAP_AFTER_DISCONNECT).
 */
static int64_t usbdev_do_reap(guest_t *g, int fd, uint64_t arg, bool block)
{
    (void) guest_lazy_faultin(g, arg, sizeof(uint64_t));
    for (;;) {
        /* The slot's record and the descriptor behind it, out of ONE fd_lock
         * window. They are two facts about one open file description: the
         * readiness settled below is settled on this fd's pipe, and the wait
         * parks on it. Read separately -- a bare fd_snapshot here and another
         * inside usbdev_acquire, each proving the generation against its own
         * window -- a sibling's close and reopen in between answered from the
         * new description's entry while still holding the old one's pipe
         * number, so the reap settled readiness against, and waited on,
         * whatever had taken that number. Same shape and the same fix as
         * sys_fstatfs (syscall/fs-stat.c); the pin also replaces the dup this
         * used to take for the wait.
         */
        fd_entry_t snap;
        host_fd_ref_t ready;
        int64_t rerr = host_fd_ref_open_entry(fd, &ready, &snap);
        if (rerr < 0)
            return rerr;
        if (snap.type != FD_USBDEV) {
            host_fd_ref_close(&ready);
            return -LINUX_EBADF;
        }
        usbdev_reap_window_delay();
        usbdev_t *u = usbdev_acquire_snap(fd, &snap);
        if (!u) {
            host_fd_ref_close(&ready);
            return -LINUX_EBADF;
        }
        pthread_mutex_lock(&u->async_lock);
        usbdev_urb_t *rec = u->completed_head;
        if (rec) {
            u->completed_head = rec->next;
            if (!u->completed_head)
                u->completed_tail = NULL;
        }
        bool disc = u->disconnected;
        bool pending = u->pending_head != NULL;

        /* REAP_AFTER_DISCONNECT, as one invariant: after a disconnect, every
         * URB still in flight is handed back before any reap answers -ENODEV,
         * whichever reap flavor got here first. That is what the capability bit
         * promises, and -ENODEV is therefore decided by "nothing is left out"
         * -- the pending list -- and never by a flag recording that some
         * earlier pass did some work.
         *
         * Linux gets the invariant for free: usbdev_remove runs
         * destroy_all_async -- a synchronous usb_kill_urb per URB -- before it
         * wakes the reapers, so by the time any reap can observe the disconnect
         * the pending list is already empty and -ENODEV cannot be premature.
         * IOKit delivers nothing of its own when the device terminates
         * (measured: three URBs outstanding at terminate, zero callbacks in the
         * next three seconds, and the same URBs recovered in 1 ms by close()'s
         * AbortPipe), so this engine has to issue that kill itself, and the
         * aborts it issues land asynchronously. The window Linux does not have
         * -- disconnected, aborts issued, URBs not back yet -- is therefore
         * real here, and the answer inside it is -EAGAIN for a non-blocking
         * reap and a wait for a blocking one. Neither is -ENODEV, because the
         * URBs are still coming.
         *
         * Two separate decisions, which is the bug this shape exists to keep
         * fixed. disc_drained is a one-shot for ISSUING the aborts, so they go
         * out once; it is not permission to report the device drained. When it
         * was both, a REAPURBNDELAY -- which issues aborts and by contract
         * cannot wait for them -- latched it and every later reap, blocking
         * included, then answered -ENODEV with the URBs still in flight: an
         * ordinary libusb event loop polls non-blocking first, so that was the
         * common path, not a corner. Measured with ep81:never plus terminate:
         * REAPURBNDELAY rc=-19 urb=(nil), then REAPURB rc=-19 in 0 ms, with the
         * URB only arriving 400 ms later.
         */
        bool abort_now = !rec && disc && !u->disc_drained && pending;
        if (abort_now) {
            u->disc_drained = true;
            u->disc_orphan_at_ms = usbdev_now_ms() + USBDEV_DRAIN_TIMEOUT_MS;
        }

        /* A blocking pass drains whatever is still out, latch or no latch: the
         * aborts are idempotent, and this is what makes the invariant hold for
         * a blocking reap that arrives behind a non-blocking one.
         */
        bool drain = abort_now || (!rec && disc && pending && block);

        /* The other half of that invariant: every reap flavor reaches the end
         * of the conversation, and reaches it inside one drain deadline of the
         * aborts. Neither flavor may answer -ENODEV while a URB may still come
         * back, and neither may go on refusing to answer once no URB can.
         *
         * The blocking flavor gets the second half from the wait it takes
         * below, which times out and orphans. A non-blocking one may not wait
         * for anything, so it measures the same deadline instead of waiting it
         * out: the aborts went out at disc_orphan_at_ms minus one deadline, and
         * past it the wire has had exactly as long to answer them as a blocking
         * reap would have given it. Without this the only thing that empties
         * pending is the blocking arm's wait, so a wire that answers no abort
         * left a REAPURBNDELAY loop returning -EAGAIN for ever while poll held
         * POLLERR|POLLHUP -- measured against ep81:wedge(600000) as 1958386
         * -EAGAIN and no -ENODEV in 4 s, where Linux's proc_reapurbnonblock
         * answers connected(ps) ? -EAGAIN : -ENODEV and the guest tears down.
         */
        bool overdue = !rec && disc && pending && !block && u->disc_drained &&
                       usbdev_now_ms() >= u->disc_orphan_at_ms;
        if (overdue) {
            usbdev_orphan_stalled_locked(u, NULL);
            pending = u->pending_head != NULL;

            /* Whatever it handed back is reapable now, and this pass is the one
             * that has to see it: rec was read before the orphaning, so leaving
             * it alone answered -ENODEV below on the same pass that completed
             * the URB, with the pointer never returned. Measured with
             * ep02:wedge(600000) plus a terminate: REAPURBNDELAY -> -ENODEV
             * after 2037 ms, URBs handed back 0.
             */
            rec = u->completed_head;
            if (rec) {
                u->completed_head = rec->next;
                if (!u->completed_head)
                    u->completed_tail = NULL;
            }
        }

        /* Settle the readiness level under the same lock that dequeued: the
         * emptiness this reads is the emptiness it acted on, where a decision
         * taken outside the lock would race a completion arriving behind it and
         * strand the token it just wrote.
         */
        usbdev_ready_settle_locked(u, ready.fd);
        pthread_mutex_unlock(&u->async_lock);
        if (rec) {
            int64_t ret = usbdev_reap_copyout(g, rec, arg);
            pthread_mutex_lock(&u->async_lock);

            /* An orphan handed back by usbdev_orphan_stalled_locked settled the
             * slot's counters when the deadline gave up on it and may still be
             * owned by an in-flight IOKit transfer, so it is not this slot's to
             * account for or, while that is true, to free.
             */
            if (rec->handback)
                urb_handback_taken_locked(rec);
            else
                urb_free_locked(u, rec);
            pthread_mutex_unlock(&u->async_lock);
            usbdev_release(u);
            host_fd_ref_close(&ready);
            return ret;
        }
        if (drain) {
            /* A blocking reap may wait for the callbacks the aborts provoke,
             * and does: it loops and hands back what they retire. A
             * REAPURBNDELAY may not wait for anything at all, so it issues the
             * same aborts and lets a later pass collect them -- see
             * usbdev_abort_urbs_nowait_locked. Either way the loop continues,
             * so a record the aborts retired immediately (a QUEUED one) is
             * handed back rather than reported as nothing left.
             *
             * Both are bounded by the same drain deadline and both orphan what
             * misses it, which empties the pending list: that is what stops a
             * wire which answers no abort from parking a blocking REAPURB or
             * spinning a non-blocking one for good, and it is why the -ENODEV
             * below is reachable at all on such a wire. The blocking arm spends
             * the deadline in usbdev_kill_urbs_locked's wait; the non-blocking
             * arm has already spent it above, having measured it rather than
             * waited.
             */
            if (block)
                (void) usbdev_kill_urbs_locked(u, NULL);
            else
                usbdev_abort_urbs_nowait_locked(u);
            usbdev_release(u);
            host_fd_ref_close(&ready);
            continue; /* hand the drained completions out on the next pass */
        }
        usbdev_release(u);

        /* Drained is the whole of the -ENODEV condition. A disconnected fd with
         * URBs still out has not finished answering for them yet, so it owes
         * -EAGAIN (proc_reapurbnonblock's other arm) rather than the end of the
         * conversation. Neither flavor can sit in that state past the drain
         * deadline: the blocking one takes the drain arm above and the
         * non-blocking one has orphaned what the deadline gave up on, so
         * pending is empty here in both cases and -ENODEV is due.
         */
        if (disc && !pending) {
            host_fd_ref_close(&ready);
            return -LINUX_ENODEV;
        }
        if (!block) {
            host_fd_ref_close(&ready);
            return -LINUX_EAGAIN;
        }

        /* The pin is what makes waiting on this number safe: a sibling's
         * close() after the entry lock is dropped frees the guest fd, and a
         * wait on the raw host number would park on whatever object took it.
         * The loop revalidates the guest fd after the wake.
         */
        int64_t rc = io_wait_fd_or_interrupted(ready.fd, POLLIN);
        host_fd_ref_close(&ready);
        if (rc < 0) {
            /* proc_reapurb returns -EINTR with no restart (devio.c:2116-2117);
             * reap_as itself only breaks out of the wait and returns a pointer.
             */
            syscall_restart_forbid();
            return rc;
        }
    }
}

/* poll/select/epoll remap helpers (see poll.c call sites) */

bool usbdev_fd_disconnected(int guest_fd)
{
    return RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE) && discmap_load(guest_fd);
}

bool usbdev_fd_reapable(int guest_fd)
{
    return RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE) && readymap_load(guest_fd);
}

bool usbdev_poll_host_events(int guest_fd,
                             short guest_events,
                             short *host_events)
{
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap) || snap.type != FD_USBDEV)
        return false;

    /* The host interest is always POLLIN on the completion pipe: the fd never
     * carries guest-readable bytes, and a disconnect mid-wait wakes the parked
     * poll through the readiness level usbdev_mark_disconnected raises -- and
     * then holds, so a poll that arrives after the disconnect is woken by the
     * same token rather than by a byte of its own -- even when the guest asked
     * for nothing the pipe can signal (POLLERR|POLLHUP are unmaskable,
     * devio.c:2842-2845). usbdev_poll_guest_revents filters what the guest
     * actually sees, and the callers re-block when a wake maps to nothing
     * guest-visible.
     */
    (void) guest_events;
    *host_events = POLLIN;
    return true;
}

short usbdev_poll_guest_revents(int guest_fd,
                                short guest_events,
                                short host_revents)
{
    /* usbdev_poll gates EPOLLOUT|EPOLLWRNORM on FMODE_WRITE (devio.c:2840), so
     * this is the same capability the ioctl and write gates read, not a test
     * against O_RDONLY: access mode 3 is not O_RDONLY and carries no
     * FMODE_WRITE either, and testing the literal reported the fd writable
     * where Linux does not.
     */
    fd_entry_t snap;
    bool writable = fd_snapshot(guest_fd, &snap) && snap.type == FD_USBDEV &&
                    (usbdev_fmode(snap.linux_flags) & USBDEV_FMODE_WRITE);
    short out = 0;
    if (usbdev_fd_disconnected(guest_fd))
        out |= LINUX_POLLERR | LINUX_POLLHUP; /* devio.c:2842-2845 */
    /* POLLOUT|POLLWRNORM only while a completion is actually reapable
     * (async_completed non-empty, devio.c poll): the pipe also carries the
     * disconnect wake, and a disconnect with nothing left to reap must report
     * ERR|HUP alone.
     */
    if (writable && (host_revents & POLLIN) && usbdev_fd_reapable(guest_fd))
        out |= LINUX_POLLOUT | LINUX_POLLWRNORM;
    /* do_pollfd masks by demanded events plus the unmaskable bits. */
    return (short) (out & (guest_events | LINUX_POLLERR | LINUX_POLLHUP |
                           LINUX_POLLNVAL));
}

/* Registry 'Device Speed' -> USB_SPEED_* enum (ch9.h:1217-1222): the ioctl's
 * return value, not an out parameter.
 */
static int64_t usbdev_speed_enum(unsigned code)
{
    switch (code) {
    case 0:
        return 1; /* LOW */
    case 1:
        return 2; /* FULL */
    case 2:
        return 3; /* HIGH */
    case 3:
        return 5; /* SUPER */
    case 4:
    case 5:
        return 6; /* SUPER_PLUS */
    default:
        return 2;
    }
}

/* The requests do_vfs_ioctl answers for every file before it calls
 * f_op->unlocked_ioctl, so on Linux they never reach usbfs, never meet its
 * FMODE_WRITE gate and never meet its connected() gate. io.c answers FIONBIO
 * and FIOASYNC ahead of this file for the same reason, and this is the rest of
 * that set.
 *
 * This layer models none of the ten and answers -ENOTTY to all of them. For
 * eight that is not what Linux answers: each of those arms is reached there and
 * answers for itself, off the superblock the node sits on, off CAP_SYS_ADMIN,
 * or off the argument. Which two agree and what the other eight give instead is
 * measured rather than reasoned from the identifier, and is recorded beside the
 * -ENOTTY in check_vfs_ioctls, tests/test-usbdev-ioctl.c: that lane drives all
 * ten on a read-only and on a writable fd and prints the eight as XFAIL. No
 * sentence here repeats those values, because the last one that tried got two
 * of them wrong.
 *
 * What is not in it: FIONREAD, which do_vfs_ioctl hands to vfs_ioctl for
 * anything that is not a regular file, so it does reach usbfs; and the
 * FS_IOC_*FLAGS and FS_IOC_FS*XATTR arms, which answer -ENOIOCTLCMD for an
 * inode carrying no fileattr operations and are retried through vfs_ioctl. Both
 * meet the gate below, and should.
 */
static bool usbdev_vfs_answers_first(uint32_t request)
{
    switch (request) {
    case LINUX_FIOQSIZE:
    case LINUX_FIGETBSZ:
    case LINUX_FIFREEZE:
    case LINUX_FITHAW:
    case LINUX_FS_IOC_FIEMAP:
    case LINUX_FICLONE:
    case LINUX_FICLONERANGE:
    case LINUX_FIDEDUPERANGE:
    case LINUX_FS_IOC_GETFSUUID:
    case LINUX_FS_IOC_GETFSSYSFSPATH:
        return true;
    default:
        return false;
    }
}

static size_t usbdev_ioctl_arg_size(uint32_t request)
{
    switch (request) {
    case USBDEVFS_CLAIMINTERFACE:
    case USBDEVFS_RELEASEINTERFACE:
    case USBDEVFS_SETCONFIGURATION:
    case USBDEVFS_CLEAR_HALT:
    case USBDEVFS_RESETEP:
    case USBDEVFS_GET_CAPABILITIES:
        return sizeof(uint32_t);
    case USBDEVFS_SETINTERFACE:
        return sizeof(linux_usbdevfs_setinterface_t);
    case USBDEVFS_GETDRIVER:
        return sizeof(linux_usbdevfs_getdriver_t);
    case USBDEVFS_CONNECTINFO:
        return sizeof(linux_usbdevfs_connectinfo_t);
    case USBDEVFS_DISCONNECT_CLAIM:
        return sizeof(linux_usbdevfs_disconnect_claim_t);
    case USBDEVFS_IOCTL:
        return sizeof(linux_usbdevfs_ioctl_t);
    case USBDEVFS_DISCSIGNAL:
        return sizeof(linux_usbdevfs_disconnectsignal_t);
    default:
        return 0;
    }
}

int64_t usbdev_ioctl(guest_t *g, int fd, uint64_t request, uint64_t arg)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap) || snap.type != FD_USBDEV)
        return -LINUX_EBADF;

    /* Ahead of everything below, because Linux never puts any of it to these:
     * they are answered before f_op->unlocked_ioctl runs, so neither the
     * FMODE_WRITE gate nor the device question is theirs to meet. Two answers
     * move because this sits here and not lower down: on a device that is
     * present a read-only fd now gets -ENOTTY where the gate below had made it
     * -EPERM, and on a device that has gone a writable fd gets -ENOTTY where
     * that gate and the ask in the default arm had both made it -ENODEV.
     * check_vfs_ioctls in tests/test-usbdev-ioctl.c drives the first on both
     * access modes and tests/test-usbdev-ioctl-departed.c the second, so this
     * moving below the gate fails a lane rather than passing quietly.
     */
    if (usbdev_vfs_answers_first((uint32_t) request))
        return -LINUX_ENOTTY;

    /* Every usbdev ioctl needs FMODE_WRITE (devio.c:2608-2609). */
    if (!(usbdev_fmode(snap.linux_flags) & USBDEV_FMODE_WRITE))
        return -LINUX_EPERM;

    /* The reaps manage their own locking: a blocked REAPURB must not hold the
     * entry lock against concurrent SUBMITURB/DISCARDURB, and they stay usable
     * after disconnect (devio.c:2613-2636).
     */
    if ((uint32_t) request == USBDEVFS_REAPURB ||
        (uint32_t) request == USBDEVFS_REAPURBNDELAY)
        return usbdev_do_reap(g, fd, arg,
                              (uint32_t) request == USBDEVFS_REAPURB);

    linux_usbdevfs_ctrltransfer_t ct = {0};
    linux_usbdevfs_bulktransfer_t bt = {0};
    linux_usbdevfs_urb_t uu = {0};
    int copy_rc = 0;
    if ((uint32_t) request == USBDEVFS_CONTROL) {
        copy_rc = guest_read(g, arg, &ct, sizeof(ct));
        if (copy_rc == 0 && ct.wLength && ct.wLength <= USBDEV_CTRL_MAX)
            (void) guest_lazy_faultin(g, ct.data, ct.wLength);
    } else if ((uint32_t) request == USBDEVFS_BULK) {
        copy_rc = guest_read(g, arg, &bt, sizeof(bt));
        if (copy_rc == 0 && bt.len &&
            bt.len <= USBDEV_MEMORY_MAX - USBDEV_URB_OVERHEAD)
            (void) guest_lazy_faultin(g, bt.data, bt.len);
    } else if ((uint32_t) request == USBDEVFS_SUBMITURB) {
        /* The reap writes the status and data back under the entry lock, so it
         * relies on this fault-in too.
         */
        copy_rc = guest_read(g, arg, &uu, sizeof(uu));
        if (copy_rc == 0 && uu.buffer_length > 0 &&
            (uint32_t) uu.buffer_length <=
                USBDEV_MEMORY_MAX - sizeof(usbdev_urb_t))
            (void) guest_lazy_faultin(g, uu.buffer,
                                      (uint32_t) uu.buffer_length);
    } else {
        size_t len = usbdev_ioctl_arg_size((uint32_t) request);
        if (len)
            (void) guest_lazy_faultin(g, arg, len);
    }

    usbdev_t *u = usbdev_acquire_snap(fd, &snap);
    if (!u)
        return -LINUX_EBADF;

    /* usbdev_ioctl's connected() gate. What it reads is what this fd has been
     * told: the mark arrives from the terminate watch, from a peer's walk when
     * some other fd on the node was told first, or from this fd's own next call
     * into IOKit. open(2) resolves no service (usbdev_ensure_service says why),
     * so an fd opened after the device left starts every call with nothing on
     * it, and what closes that window is the op itself putting the question to
     * the device.
     *
     * Not every op does, and this comment does not say which. That count was
     * written down wrong twice. What each arm below answers on a device that
     * has gone, what Linux answers, and which differences are deliberate is
     * tests/usbdev-ioctl-departed.tbl: one row per request, joined against this
     * dispatch by scripts/gen-usbdev-ioctl-departed.py so an arm added here
     * cannot escape the table, and driven by
     * tests/test-usbdev-ioctl-departed.c, which fails both when a recorded gap
     * widens and when one quietly closes. Running that lane prints the table.
     *
     * The default arm is in that join too, through the request codes defined at
     * the top of this file and dispatched nowhere, because a sentence asserting
     * over every arm that cannot be checked against the arm that catches the
     * rest is how the -ENOTTY that arm used to answer here survived a table
     * built to find exactly that.
     */
    bool disc;
    pthread_mutex_lock(&u->async_lock);
    disc = u->disconnected;
    pthread_mutex_unlock(&u->async_lock);
    if (disc) {
        usbdev_release(u);
        return -LINUX_ENODEV;
    }

    int64_t ret;
    switch ((uint32_t) request) {
    case USBDEVFS_CLAIMINTERFACE: {
        uint32_t ifnum;
        ret = guest_read_nofault(g, arg, &ifnum, sizeof(ifnum)) < 0
                  ? -LINUX_EFAULT
                  : usbdev_claim_ioctl(u, ifnum);
        break;
    }
    case USBDEVFS_RELEASEINTERFACE: {
        uint32_t ifnum;
        ret = guest_read_nofault(g, arg, &ifnum, sizeof(ifnum)) < 0
                  ? -LINUX_EFAULT
                  : usbdev_release_ioctl(u, ifnum);
        break;
    }
    case USBDEVFS_SETINTERFACE:
        ret = usbdev_do_setinterface(u, g, arg);
        break;
    case USBDEVFS_SETCONFIGURATION:
        ret = usbdev_do_setconfiguration(u, g, arg);
        break;
    case USBDEVFS_CLEAR_HALT:
        ret = usbdev_do_clear_halt(u, g, arg);
        break;
    case USBDEVFS_RESETEP:
        ret = usbdev_do_resetep(u, g, arg);
        break;
    case USBDEVFS_GETDRIVER:
        ret = usbdev_do_getdriver(u, g, arg);
        break;
    case USBDEVFS_GET_CAPABILITIES: {
        uint32_t caps = USBDEV_CAPS;
        ret = guest_write_nofault(g, arg, &caps, sizeof(caps)) < 0
                  ? -LINUX_EFAULT
                  : 0;
        break;
    }
    case USBDEVFS_GET_SPEED:
        ret = usbdev_speed_enum(u->speed_code);
        break;
    case USBDEVFS_CONNECTINFO: {
        linux_usbdevfs_connectinfo_t ci = {
            .devnum = (uint32_t) u->devnum,
            .slow = u->speed_code == 0,
        };
        ret = guest_write_nofault(g, arg, &ci, sizeof(ci)) < 0 ? -LINUX_EFAULT
                                                               : 0;
        break;
    }
    case USBDEVFS_CONTROL:
        ret = copy_rc < 0 ? -LINUX_EFAULT : usbdev_do_control(u, g, ct);
        break;
    case USBDEVFS_BULK:
        ret = copy_rc < 0 ? -LINUX_EFAULT : usbdev_do_bulk(u, g, bt);
        break;
    case USBDEVFS_RESET: {
        /* Stage-2 deviation (see file header): clear stalls on every claimed
         * pipe instead of re-enumerating.
         *
         * usb_reset_device kills every URB on the device first, so the guest
         * gets all of them back. Doing the stall clears alone left the URB
         * behind whichever pipe IOKit happened to abort reported as canceled
         * and the queue behind it stranded -- one of three returned in a
         * measured run.
         *
         * A per-pipe clear that fails is logged, not returned: the stall clears
         * are the substitute, not the operation the guest asked for, and this
         * board answers kIOUSBTransactionTimeout on the CDC data interface's
         * pipes for a device usb_reset_device would reset without complaint.
         * Reporting that would refuse a RESET Linux performs, which is a worse
         * answer than the silence.
         *
         * The one caller that does not go through usbdev_drain_for_change, and
         * deliberately: a drain that misses its deadline means a transfer is
         * wedged, which is the state a guest issues RESET to get out of, and
         * usb_reset_device is a recovery path that never refuses for that
         * reason. Nothing here retires a handle an orphan holds either -- a
         * stall clear leaves the pipeRefs where they are, unlike SETINTERFACE
         * and SETCONFIGURATION -- so proceeding costs the orphans nothing.
         */

        /* The device question first, and unconditionally. The only IOKit calls
         * this op makes are the aborts inside the kill below and the stall
         * clears after it, and it makes neither with nothing claimed and
         * nothing in flight, so RESET on a departed device ran to the end and
         * answered 0 -- measured on a fresh fd of a terminated loopback device,
         * rc=0 with revents 0x0. libusb_reset_device is the canonical recovery
         * call, so the guest's NO_DEVICE branch was the one branch an unplug
         * could not reach. Linux answers -ENODEV: connected() runs before
         * proc_resetdevice.
         */
        int64_t rrc = usbdev_ensure_dev_reachable(u);
        if (rrc < 0) {
            ret = rrc;
            break;
        }
        (void) usbdev_kill_urbs_locked(u, NULL);
        for (int i = 0; i < USBDEV_MAX_IFACES; i++) {
            usbdev_iface_t *fi = &u->ifaces[i];
            if (!fi->claimed)
                continue;
            for (int p = 1; p <= fi->npipes; p++) {
                IOReturn r =
                    (*fi->intf)->ClearPipeStallBothEnds(fi->intf, (UInt8) p);
                if (r != kIOReturnSuccess) {
                    /* The clear is logged rather than returned, but its status
                     * is still translated, so a device that leaves between the
                     * gate above and this loop is still originated here rather
                     * than only on the next op. The gate is what carries the
                     * -ENODEV answer; this carries the stamp for the window
                     * after it.
                     */
                    (void) usbdev_ioret_op(u, r);
                    log_warn("usbdev: RESET: pipe %d stall clear -> 0x%x", p,
                             r);
                }
            }
        }
        log_debug(
            "usbdev: RESET emulated as URB kill + pipe-stall clear (no "
            "re-enumeration)");
        ret = 0;
        break;
    }
    case USBDEVFS_DISCONNECT_CLAIM:
        ret = usbdev_do_disconnect_claim(u, g, arg);
        break;
    case USBDEVFS_IOCTL:
        ret = usbdev_do_driver_ioctl(u, g, arg);
        break;
    case USBDEVFS_SUBMITURB:
        ret = copy_rc < 0 ? -LINUX_EFAULT : usbdev_do_submiturb(u, g, arg, uu);
        break;
    case USBDEVFS_DISCARDURB:
        ret = usbdev_do_discardurb(u, arg);
        break;
    case USBDEVFS_DISCSIGNAL: {
        /* Stored for fidelity but never delivered (file header): elfuse has no
         * async guest-signal injection from the event thread.
         */
        linux_usbdevfs_disconnectsignal_t ds;
        if (guest_read_nofault(g, arg, &ds, sizeof(ds)) < 0) {
            ret = -LINUX_EFAULT;
        } else {
            u->discsig_signr = ds.signr;
            u->discsig_context = ds.context;
            if (ds.signr)
                log_warn(
                    "usbdev: DISCSIGNAL %u accepted but will not be "
                    "delivered",
                    ds.signr);
            ret = 0;
        }
        break;
    }
    default:
        /* The device question outranks the unknown request, because Linux's
         * connected() gate runs ahead of usbdev_do_ioctl's switch
         * (devio.c:2638) and the -ENOTTY is that switch's default. So a
         * usbdevfs cmd this layer does not serve answered -ENOTTY and stamped
         * nothing on a departed device, where Linux answers -ENODEV with
         * POLLERR|POLLHUP: measured on a terminated loopback device,
         * HUB_PORTINFO, ALLOC_STREAMS and WAIT_FOR_RESUME were all -1/ENOTTY
         * with revents 0x0 on the asking fd and on a peer. libusb reads the
         * difference -- ENOTTY on ALLOC_STREAMS is NOT_SUPPORTED, ENODEV is
         * NO_DEVICE -- so an unplug read as "this kernel has no streams" and
         * never expired.
         *
         * The gate at the top of this function is not enough for it: what that
         * reads is what this fd has been told, and an arm that reaches no wire
         * never tells it anything. This arm asks.
         *
         * It asks only for requests that would have reached usbfs.
         * usbdev_vfs_answers_first takes the rest above the gate, because for
         * those Linux never reaches the code that could ask.
         */
        ret = usbdev_ensure_dev_reachable(u);
        if (ret >= 0)
            ret = -LINUX_ENOTTY;
        break;
    }
    usbdev_release(u);
    return ret;
}
