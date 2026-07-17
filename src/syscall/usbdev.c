/*
 * usbdevfs (/dev/bus/usb/BBB/DDD) fd emulation over IOKit
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Stage 2: a typed FD_USBDEV fd whose synchronous usbdevfs ioctls are mapped
 * onto IOUSBDeviceInterface650 / IOUSBInterfaceInterface800 plugin calls
 * (research doc D's op table). Semantics mirror drivers/usb/core/devio.c (doc A
 * sections A1 and A2):
 *
 *   - open of any access mode succeeds; read() serves the descriptors blob
 *     (byte-identical to the sysfs `descriptors` attribute) at a per-open
 *     file position; SEEK_END is -EINVAL (no_seek_end_llseek).
 *   - every ioctl requires a writable fd: O_RDONLY fd -> -EPERM
 *     (devio.c:2605-2606 FMODE_WRITE gate).
 *   - CLAIMINTERFACE returns -EBUSY when a macOS kernel driver is bound; the
 *     "kernel driver" test is an IORegistry child of the IOUSBHostInterface
 *     service in the service plane (libusb darwin_usb.c:2746-2770), and the
 *     claim itself is USBInterfaceOpen (kIOReturnExclusiveAccess -> -EBUSY).
 *   - CONTROL/BULK are Linux's sync paths (do_proc_control/do_proc_bulk):
 *     bounce buffers around DeviceRequestTO / Read|WritePipeTO, timeout in ms
 *     (0 = unlimited on both sides), -ETIMEDOUT from
 *     kIOUSBTransactionTimeout, stall -> -EPIPE, and Linux's implicit
 *     claim of the recipient interface (check_ctrlrecip/checkintf).
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
 *   - SUBMITURB/DISCARDURB/REAPURB* are -ENOTTY until stage 3.
 *   - dup()/fork() of an FD_USBDEV fd are refused (-EBADF): IOKit plugin
 *     handles are process-local and the side table is keyed by the guest fd.
 *     TODO(later): explicit dup alias (fuse_dup_fd pattern).
 *   - DISCONNECT/CONNECT/DISCONNECT_CLAIM cannot unbind Apple drivers without
 *     root or the com.apple.vm.device-access entitlement, so a bound kernel
 *     driver yields -EACCES (matching Linux's privileges-dropped answer).
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/usb/USB.h>

#include "core/guest.h"
#include "debug/log.h"
#include "runtime/usb-sysfs.h"
#include "syscall/internal.h"
#include "syscall/linux-wire.h"
#include "syscall/proc.h"
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

/* Sub-codes of USBDEVFS_IOCTL (_IO('U', 22) / _IO('U', 23)). */
#define USBDEVFS_IOCTL_DISCONNECT 0x00005516
#define USBDEVFS_IOCTL_CONNECT 0x00005517

/* Capability bits (uapi/linux/usbdevice_fs.h:152-161). Every one of them
 * describes the SUBMITURB/REAPURB machinery: ZERO_PACKET and BULK_CONTINUATION
 * are URB flags, NO_PACKET_SIZE_LIM and BULK_SCATTER_GATHER are properties of
 * how a URB is split, REAP_AFTER_DISCONNECT is about reaping. Stage 2 answers
 * -ENOTTY to all of those ioctls, so it advertises none of it and reports 0;
 * the async stage raises the word as it lands each one. MMAP, DROP_PRIVILEGES,
 * CONNINFO_EX and SUSPEND stay clear for the same reason (doc A section A7.7).
 */
#define USBDEVFS_CAP_ZERO_PACKET 0x01u
#define USBDEVFS_CAP_BULK_CONTINUATION 0x02u
#define USBDEVFS_CAP_NO_PACKET_SIZE_LIM 0x04u
#define USBDEVFS_CAP_BULK_SCATTER_GATHER 0x08u
#define USBDEVFS_CAP_REAP_AFTER_DISCONNECT 0x10u
#define USBDEV_CAPS 0u

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

/* side table */

/* No usbfs limit corresponds to this: Linux allocates a usb_dev_state per open.
 * The fixed table is a stage-2 simplification, so exhaustion is spelled -ENOMEM
 * -- a kernel-side resource shortfall -- rather than -EMFILE, which would tell
 * the guest its own descriptor limit is exhausted when it is not.
 */
#define USBDEV_MAX_FDS 32

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
    int npipes;
    uint8_t pipe_ep[USBDEV_MAX_PIPES];   /* pipeRef-1 -> bEndpointAddress */
    uint8_t pipe_type[USBDEV_MAX_PIPES]; /* kUSBControl..kUSBInterrupt */
} usbdev_iface_t;

typedef struct {
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
    int pipe_wr; /* write end of the readiness pipe (stage-3 completions) */
    io_service_t service;          /* retained IOUSBDevice service */
    IOUSBDeviceInterface650 **dev; /* lazily created device plugin */
    bool dev_open;                 /* USBDeviceOpen succeeded */
    bool dev_open_tried;
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

/* IOReturn -> -LINUX_E* (doc D table (b)) */

#ifndef kUSBHostReturnPipeStalled
#define kUSBHostReturnPipeStalled 0xe0005000u
#endif

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
         * (another thread's teardown aborted the pipe), so the dispatcher must
         * not re-execute the ioctl and send it again.
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
    if (u->service != IO_OBJECT_NULL)
        return 0;
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
 * CreateInterfaceIterator need only the plugin, not USBDeviceOpen.
 */
static int64_t usbdev_ensure_dev_plugin(usbdev_t *u)
{
    if (u->dev)
        return 0;
    int64_t srv = usbdev_ensure_service(u);
    if (srv < 0)
        return srv;
    IOCFPlugInInterface **plug = NULL;
    SInt32 score = 0;
    IOReturn r = IOCreatePlugInInterfaceForService(
        u->service, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &plug,
        &score);
    if (r != kIOReturnSuccess || !plug) {
        log_warn("usbdev: device plugin for %d-%d failed 0x%x", u->busnum,
                 u->devnum, r);
        return r == kIOReturnSuccess ? -LINUX_ENOMEM : ioret_neg_errno(r);
    }
    IOUSBDeviceInterface650 **dev = NULL;
    HRESULT hr = (*plug)->QueryInterface(
        plug, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID650), (LPVOID *) &dev);
    (*plug)->Release(plug);
    if (hr != S_OK || !dev)
        return -LINUX_ENOMEM;
    u->dev = dev;
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
    if (r == kIOReturnSuccess)
        u->dev_open = true;
    else
        log_debug("usbdev: USBDeviceOpen %d-%d -> 0x%x (tolerated)", u->busnum,
                  u->devnum, r);
}

/* Retained IOUSBHostInterface service for bInterfaceNumber ifnum in the active
 * configuration, or IO_OBJECT_NULL. Uses CreateInterfaceIterator so "exists"
 * means exactly what claimintf's usb_ifnum_to_if means.
 */
static io_service_t usbdev_iface_service(usbdev_t *u, unsigned ifnum)
{
    if (usbdev_ensure_dev_plugin(u) < 0)
        return IO_OBJECT_NULL;
    IOUSBFindInterfaceRequest fr = {
        .bInterfaceClass = kIOUSBFindInterfaceDontCare,
        .bInterfaceSubClass = kIOUSBFindInterfaceDontCare,
        .bInterfaceProtocol = kIOUSBFindInterfaceDontCare,
        .bAlternateSetting = kIOUSBFindInterfaceDontCare,
    };
    io_iterator_t it = IO_OBJECT_NULL;
    if ((*u->dev)->CreateInterfaceIterator(u->dev, &fr, &it) !=
        kIOReturnSuccess)
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

/* "Kernel driver bound" == the interface service has a driver child in the
 * service plane (libusb darwin_usb.c:2746-2770). Fills name (class name,
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
static int64_t usbdev_build_pipe_map(usbdev_iface_t *fi)
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
    UInt8 ne = 0;
    IOReturn r = (*fi->intf)->GetNumEndpoints(fi->intf, &ne);
    if (r != kIOReturnSuccess) {
        int64_t err = ioret_neg_errno(r);
        return err < 0 ? err : -LINUX_EIO;
    }
    if (ne > USBDEV_MAX_PIPES)
        ne = USBDEV_MAX_PIPES;
    for (UInt8 p = 1; p <= ne; p++) {
        UInt8 dir = 0, num = 0, type = 0, interval = 0;
        UInt16 mps = 0;
        if ((*fi->intf)->GetPipeProperties(fi->intf, p, &dir, &num, &type, &mps,
                                           &interval) != kIOReturnSuccess)
            continue;
        fi->pipe_ep[p - 1] = (uint8_t) (num | (dir == kUSBIn ? 0x80 : 0));
        fi->pipe_type[p - 1] = type;
        fi->npipes = p;
    }
    return 0;
}

/* claim / release (entry lock held) */

static int64_t usbdev_claim_locked(usbdev_t *u, unsigned ifnum)
{
    if (ifnum >= USBDEV_MAX_IFACES)
        return -LINUX_EINVAL; /* claimintf devio.c:786 */
    usbdev_iface_t *fi = &u->ifaces[ifnum];
    if (fi->claimed)
        return 0; /* already ours */

    /* Ahead of the interface lookup so a device that is not there answers
     * -ENODEV rather than "no such interface".
     */
    int64_t drc = usbdev_ensure_dev_plugin(u);
    if (drc < 0)
        return drc;

    io_service_t ifs = usbdev_iface_service(u, ifnum);
    if (ifs == IO_OBJECT_NULL)
        return -LINUX_ENOENT;

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
        return r == kIOReturnSuccess ? -LINUX_ENOMEM : ioret_neg_errno(r);
    IOUSBInterfaceInterface800 **intf = NULL;
    HRESULT hr = (*plug)->QueryInterface(
        plug, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID800),
        (LPVOID *) &intf);
    (*plug)->Release(plug);
    if (hr != S_OK || !intf)
        return -LINUX_ENOMEM;

    r = (*intf)->USBInterfaceOpen(intf);
    if (r != kIOReturnSuccess) {
        (*intf)->Release(intf);
        int64_t e = ioret_neg_errno(r);
        return e == 0 ? -LINUX_EBUSY : e;
    }
    fi->intf = intf;
    int64_t maprc = usbdev_build_pipe_map(fi);
    if (maprc < 0) {
        (*intf)->USBInterfaceClose(intf);
        (*intf)->Release(intf);
        fi->intf = NULL;
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
        io_service_t ifs = usbdev_iface_service(u, ifnum);
        if (ifs == IO_OBJECT_NULL)
            return -LINUX_ENOENT;
        IOObjectRelease(ifs);
        return -LINUX_EINVAL;
    }
    (*fi->intf)->USBInterfaceClose(fi->intf);
    (*fi->intf)->Release(fi->intf);
    fi->intf = NULL;
    fi->claimed = false;
    claimed_mask_clear(u, ifnum);
    fi->npipes = 0;
    return 0;
}

/* usbdev_ep_owner_iface's two failures, kept apart because Linux answers them
 * differently: an endpoint no altsetting carries is -ENOENT (findintfep's own
 * return), while one whose owning interface number is past the claim bitmap is
 * -EINVAL (checkintf, devio.c:842).
 */
#define USBDEV_EP_OWNER_NONE (-1)
#define USBDEV_EP_OWNER_OUT_OF_RANGE (-2)

/* findintfep (devio.c:853-876): which interface of the active config carries
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
 * was neither brief nor bounded.
 */
static usbdev_t *usbdev_acquire_generation(int fd, uint64_t generation)
{
    usbdev_t *u = NULL;
    pthread_mutex_lock(&usbdev_table_lock);
    for (int i = 0; i < USBDEV_MAX_FDS; i++) {
        if (usbdev_fds[i].used && !usbdev_fds[i].dead &&
            usbdev_fds[i].guest_fd == fd &&
            usbdev_fds[i].generation == generation) {
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
    return usbdev_acquire_generation(fd, snap.generation);
}

/* Unlock and unpin an entry usbdev_acquire returned. */
static void usbdev_release(usbdev_t *u)
{
    pthread_mutex_unlock(&u->lock);
    usbdev_unref(u);
}

static void usbdev_teardown_locked(usbdev_t *u)
{
    for (int i = 0; i < USBDEV_MAX_IFACES; i++)
        if (u->ifaces[i].claimed)
            (void) usbdev_release_locked(u, (unsigned) i);
    if (u->dev) {
        if (u->dev_open)
            (*u->dev)->USBDeviceClose(u->dev);
        (*u->dev)->Release(u->dev);
        u->dev = NULL;
    }
    u->dev_open = false;
    u->dev_open_tried = false;
    if (u->service != IO_OBJECT_NULL) {
        IOObjectRelease(u->service);
        u->service = IO_OBJECT_NULL;
    }
    if (u->pipe_wr >= 0) {
        close(u->pipe_wr);
        u->pipe_wr = -1;
    }
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
     */
    pthread_mutex_lock(&u->lock);
    usbdev_teardown_locked(u);
    pthread_mutex_unlock(&u->lock);
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
            pthread_mutex_init(&usbdev_fds[i].lock, NULL);
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
    usbdev_teardown_locked(u);
    pthread_mutex_unlock(&u->lock);
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
    u->dev = NULL;
    u->dev_open = false;
    u->dev_open_tried = false;
    memset(u->ifaces, 0, sizeof(u->ifaces));
    claimed_mask_reset(u);
    /* Nonzero while bound; equal for every fd open on the same device node. */
    devkey_publish(
        u, (1ull << 63) | ((uint64_t) (uint32_t) bus << 32) | (uint32_t) dev);
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
    usbdev_t *u = usbdev_acquire_generation(fd, snap.generation);
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
    usbdev_t *u = usbdev_acquire_generation(fd, snap.generation);
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

    int64_t rc = usbdev_ensure_dev_plugin(u);
    if (rc < 0)
        return rc;
    usbdev_lazy_device_open(u);

    uint8_t *buf = NULL;
    if (ct.wLength > 0) {
        buf = malloc(ct.wLength);
        if (!buf)
            return -LINUX_ENOMEM;
    }
    bool in = (ct.bRequestType & 0x80) != 0;
    if (!in && ct.wLength > 0 &&
        guest_read_nofault(g, ct.data, buf, ct.wLength) < 0) {
        free(buf);
        return -LINUX_EFAULT;
    }

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
    int64_t err = ioret_neg_errno(r);
    if (err < 0) {
        /* On -ETIMEDOUT/-EINTR partial IN data is NOT copied out
         * (devio.c:1227).
         */
        free(buf);
        return err;
    }
    int64_t actlen = req.wLenDone;
    if (in && actlen > 0 &&
        guest_write_nofault(g, ct.data, buf, (size_t) actlen) < 0) {
        free(buf);
        return -LINUX_EFAULT;
    }
    free(buf);
    return actlen;
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
        int64_t err = ioret_neg_errno(r);
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
            int64_t err = ioret_neg_errno(r);
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
    int64_t drc = usbdev_ensure_dev_plugin(u);
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
        io_service_t ifs = usbdev_iface_service(u, gd.interface);
        if (ifs == IO_OBJECT_NULL)
            return -LINUX_ENODATA; /* usb_ifnum_to_if NULL */
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
    IOReturn r =
        (*fi->intf)->SetAlternateInterface(fi->intf, (UInt8) si.altsetting);
    if (r != kIOReturnSuccess) {
        int64_t err = ioret_neg_errno(r);
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
    return usbdev_build_pipe_map(fi);
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
    int64_t rc = usbdev_ensure_dev_plugin(u);
    if (rc < 0)
        return rc;

    /* A bound host (Apple) driver claims its interface exactly like a Linux
     * driver would (usb_interface_claimed covers every driver, not just usbfs):
     * one iterator pass over the device's interfaces.
     */
    IOUSBFindInterfaceRequest fr = {
        .bInterfaceClass = kIOUSBFindInterfaceDontCare,
        .bInterfaceSubClass = kIOUSBFindInterfaceDontCare,
        .bInterfaceProtocol = kIOUSBFindInterfaceDontCare,
        .bAlternateSetting = kIOUSBFindInterfaceDontCare,
    };
    io_iterator_t it = IO_OBJECT_NULL;
    if ((*u->dev)->CreateInterfaceIterator(u->dev, &fr, &it) ==
        kIOReturnSuccess) {
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
    }
    usbdev_lazy_device_open(u);
    if (!u->dev_open)
        return -LINUX_EBUSY; /* exclusive holder elsewhere */
    IOReturn r = (*u->dev)->SetConfiguration(u->dev, (UInt8) cfg);
    if (r != kIOReturnSuccess) {
        int64_t err = ioret_neg_errno(r);
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
     * reset (IOUSBLib.h:2928-2941), exactly usb_clear_halt.
     */
    return ioret_neg_errno((*fi->intf)->ClearPipeStallBothEnds(fi->intf, pipe));
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

    /* proc_disconnect_claim has no range check of its own: usb_ifnum_to_if
     * answers for the number and a NULL result is -EINVAL (devio.c:2467-2469),
     * which is the opposite of claimintf's -ENOENT for the same shape.
     */
    if (dc.interface >= USBDEV_MAX_IFACES)
        return -LINUX_EINVAL;
    dc.driver[sizeof(dc.driver) - 1] = '\0';
    int64_t drc = usbdev_ensure_dev_plugin(u);
    if (drc < 0)
        return drc;

    char drv[256] = "";
    bool bound = false;
    if (u->ifaces[dc.interface].claimed ||
        usbdev_iface_claimed_elsewhere(u, dc.interface)) {
        str_copy_trunc(drv, "usbfs", sizeof(drv));
        bound = true;
    } else {
        io_service_t ifs = usbdev_iface_service(u, dc.interface);
        if (ifs == IO_OBJECT_NULL)
            return -LINUX_EINVAL;
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
    if (ic.ifno < 0 || ic.ifno >= USBDEV_MAX_IFACES)
        return -LINUX_EINVAL;
    unsigned ifnum = (unsigned) ic.ifno;
    int64_t drc = usbdev_ensure_dev_plugin(u);
    if (drc < 0)
        return drc;
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
        io_service_t ifs = usbdev_iface_service(u, ifnum);
        if (ifs == IO_OBJECT_NULL)
            return -LINUX_EINVAL;
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
        io_service_t ifs = usbdev_iface_service(u, ifnum);
        if (ifs == IO_OBJECT_NULL)
            return -LINUX_EINVAL;
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
    default:
        return 0;
    }
}

int64_t usbdev_ioctl(guest_t *g, int fd, uint64_t request, uint64_t arg)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap) || snap.type != FD_USBDEV)
        return -LINUX_EBADF;
    /* Every usbdev ioctl needs FMODE_WRITE (devio.c:2605-2606). */
    if (!(usbdev_fmode(snap.linux_flags) & USBDEV_FMODE_WRITE))
        return -LINUX_EPERM;

    linux_usbdevfs_ctrltransfer_t ct = {0};
    linux_usbdevfs_bulktransfer_t bt = {0};
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
    } else {
        size_t len = usbdev_ioctl_arg_size((uint32_t) request);
        if (len)
            (void) guest_lazy_faultin(g, arg, len);
    }

    usbdev_t *u = usbdev_acquire_generation(fd, snap.generation);
    if (!u)
        return -LINUX_EBADF;

    int64_t ret;
    switch ((uint32_t) request) {
    case USBDEVFS_CLAIMINTERFACE: {
        uint32_t ifnum;
        ret = guest_read_nofault(g, arg, &ifnum, sizeof(ifnum)) < 0
                  ? -LINUX_EFAULT
                  : usbdev_claim_locked(u, ifnum);
        break;
    }
    case USBDEVFS_RELEASEINTERFACE: {
        uint32_t ifnum;
        ret = guest_read_nofault(g, arg, &ifnum, sizeof(ifnum)) < 0
                  ? -LINUX_EFAULT
                  : usbdev_release_locked(u, ifnum);
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
         * pipe instead of re-enumerating, and report success.
         */
        for (int i = 0; i < USBDEV_MAX_IFACES; i++) {
            usbdev_iface_t *fi = &u->ifaces[i];
            if (!fi->claimed)
                continue;
            for (int p = 1; p <= fi->npipes; p++)
                (void) (*fi->intf)->ClearPipeStallBothEnds(fi->intf, (UInt8) p);
        }
        log_debug(
            "usbdev: RESET emulated as pipe-stall clear (no "
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
        log_warn("usbdev: SUBMITURB not implemented (stage 3)");
        ret = -LINUX_ENOTTY;
        break;
    case USBDEVFS_DISCARDURB:
    case USBDEVFS_REAPURB:
    case USBDEVFS_REAPURBNDELAY:
    case USBDEVFS_DISCSIGNAL:
        log_debug("usbdev: async URB ioctl 0x%llx not implemented (stage 3)",
                  (unsigned long long) request);
        ret = -LINUX_ENOTTY;
        break;
    default:
        ret = -LINUX_ENOTTY;
        break;
    }
    usbdev_release(u);
    return ret;
}
