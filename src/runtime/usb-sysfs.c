/*
 * Synthetic /dev/bus/usb + /sys/bus/usb built from the IOKit registry
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Stage 1 of the usbdevfs emulation. Enumerates IOUSBHostDevice registry
 * entries without opening any device (device properties come from
 * IORegistryEntryCreateCFProperty; raw configuration descriptors come from
 * GetConfigurationDescriptorPtr, which is documented to need no open) and
 * materializes:
 *
 *   /sys/bus/usb/devices/<bus>-<ports>          device attr dirs
 *   /sys/bus/usb/devices/<bus>-<ports>:<c>.<i>  interface attr dirs
 *   /dev/bus/usb/BBB/DDD                        char-device nodes
 *
 * as scratch directories of real host files (the ensure_syscpu_dir pattern,
 * procemu.c). The /dev nodes are 0444 regular placeholder files on disk; the
 * stat intercept reports them as char major 189 minor (bus-1)*128+(dev-1), and
 * the open intercept diverts them (the /dev/pts placeholder trick).
 *
 * Layout deviation from Linux, by design: the /sys/bus/usb/devices entries are
 * directories, not symlinks into /sys/devices/... . realpath() of an entry
 * canonicalizes to itself, which libusb (opens attrs relative to the entry) and
 * nusb (canonicalize() of the entry path) both tolerate.
 *
 * /dev/bus/usb/BBB/DDD opens: since stage 2, every non-O_PATH open is served by
 * the typed FD_USBDEV constructor (syscall/usbdev.c) before this intercept
 * runs; the node branch here only backs O_PATH opens with a synthetic blob fd
 * (the FD_PATH + stat-stamp path). The blob it serves and the FD_USBDEV read()
 * view are the same bytes (usb_sysfs_descriptors_dup).
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>

#include "debug/log.h"
#include "runtime/procemu-internal.h"
#include "runtime/procemu.h"
#include "runtime/usb-desc.h"
#include "runtime/usb-fixture.h"
#include "runtime/usb-ioreg.h"
#include "runtime/usb-sysfs.h"
#include "syscall/internal.h"
#include "syscall/linux-wire.h"
#include "syscall/path.h"
#include "utils.h"

#define USB_MAJOR 189
#define USB_MAX_PORTS 6 /* locationID has six port nibbles below the bus */

/* First usb_devs[] allocation; it doubles from here as the registry is walked.
 * Not a ceiling: usbfs itself caps only at 127 devices per bus, and a chain of
 * hubs can put more than any fixed guess on one machine. A truncated model
 * would silently lose devices from both the /dev/bus/usb and the /sys views.
 */
#define USB_DEVS_INIT_CAP 16

typedef struct {
    int busnum;
    int devnum;
    uint32_t location_id;
    char name[40];    /* "2-1.4" */
    char devpath[32]; /* "1.4" */
    unsigned vid, pid, bcd_device, bcd_usb;
    unsigned dev_class, dev_subclass, dev_protocol;
    unsigned num_configs, max_packet0, cfg_value, speed_code;
    unsigned i_manufacturer, i_product, i_serial;
    char manufacturer[128], product[128], serial[128];
    uint8_t *blob; /* device descriptor + raw config descriptors */
    size_t blob_len;
} usb_dev_t;

static pthread_mutex_t usb_lock = PTHREAD_MUTEX_INITIALIZER;
static bool usb_tree_ok;
static char usb_sys_dir[64]; /* scratch root == /sys */
/* usb_sys_dir with every symlink resolved (/tmp itself is one on macOS). The
 * containment test below compares against this, never against the unresolved
 * spelling, or /tmp -> /private/tmp alone would fail it.
 */
static char usb_sys_real[PATH_MAX];
static char usb_dev_dir[64];        /* scratch root == /dev/bus     */
static char usb_dev_real[PATH_MAX]; /* usb_dev_dir resolved, likewise */
static usb_dev_t *usb_devs;         /* grown on demand; see USB_DEVS_INIT_CAP */
static int usb_ndevs;
static int usb_devs_cap;
static pid_t usb_owner_pid;

/* Port path from locationID nibbles below the top (bus) byte; empty for a root
 * hub (nusb parse_location_id).
 *
 * Returns the number of ports written.
 */
static int location_ports(uint32_t loc, unsigned ports[USB_MAX_PORTS])
{
    int n = 0;
    for (int shift = 20; shift >= 0 && n < USB_MAX_PORTS; shift -= 4) {
        unsigned nib = (loc >> shift) & 0xf;
        if (nib == 0)
            break;
        ports[n++] = nib;
    }
    return n;
}

static uint16_t get_le16(const uint8_t *p)
{
    return (uint16_t) (p[0] | (p[1] << 8));
}

/* Append every raw configuration descriptor (bus order, wTotalLength each) to
 * the device-descriptor blob. Uses the device user-client plug-in, which does
 * NOT open the device: GetConfigurationDescriptorPtr is explicitly documented
 * as not requiring an open (IOUSBLib.h "no open needed").
 */
static int append_config_descriptors(io_service_t svc, usb_dev_t *d)
{
    IOCFPlugInInterface **plug = NULL;
    SInt32 score = 0;
    IOReturn kr = IOCreatePlugInInterfaceForService(
        svc, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &plug,
        &score);
    if (kr != kIOReturnSuccess || !plug) {
        log_warn(
            "usb-sysfs: device plug-in failed for %s (0x%x); "
            "descriptors blob has device descriptor only",
            d->name, kr);
        return -1;
    }
    IOUSBDeviceInterface650 **dev = NULL;
    HRESULT hr = (*plug)->QueryInterface(
        plug, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID650), (LPVOID *) &dev);
    IODestroyPlugInInterface(plug);
    if (hr || !dev) {
        log_warn("usb-sysfs: QueryInterface(650) failed for %s", d->name);
        return -1;
    }

    int rc = 0;
    for (unsigned i = 0; i < d->num_configs; i++) {
        IOUSBConfigurationDescriptorPtr cfg = NULL;
        kr = (*dev)->GetConfigurationDescriptorPtr(dev, (UInt8) i, &cfg);
        if (kr != kIOReturnSuccess || !cfg) {
            log_warn(
                "usb-sysfs: GetConfigurationDescriptorPtr(%u) failed "
                "for %s (0x%x)",
                i, d->name, kr);
            rc = -1;
            continue;
        }
        const uint8_t *raw = (const uint8_t *) cfg;
        uint16_t total = get_le16(raw + 2); /* wTotalLength, bus order */
        if (total < 9)
            continue;
        uint8_t *nb = realloc(d->blob, d->blob_len + total);
        if (!nb) {
            rc = -1;
            break;
        }
        memcpy(nb + d->blob_len, raw, total);
        d->blob = nb;
        d->blob_len += total;
    }
    (*dev)->Release(dev);
    return rc;
}

/* Synthesize the 18-byte little-endian device descriptor from registry
 * properties (macOS exposes no raw device descriptor; usbfs read() fixes
 * multibyte fields to host endianness, which on LE hosts is the wire image:
 * devio.c:331-353).
 */
static void build_device_descriptor(const usb_dev_t *d, uint8_t out[18])
{
    out[0] = 18;
    out[1] = 1; /* DEVICE */
    out[2] = (uint8_t) (d->bcd_usb & 0xff);
    out[3] = (uint8_t) (d->bcd_usb >> 8);
    out[4] = (uint8_t) d->dev_class;
    out[5] = (uint8_t) d->dev_subclass;
    out[6] = (uint8_t) d->dev_protocol;
    out[7] = (uint8_t) d->max_packet0;
    out[8] = (uint8_t) (d->vid & 0xff);
    out[9] = (uint8_t) (d->vid >> 8);
    out[10] = (uint8_t) (d->pid & 0xff);
    out[11] = (uint8_t) (d->pid >> 8);
    out[12] = (uint8_t) (d->bcd_device & 0xff);
    out[13] = (uint8_t) (d->bcd_device >> 8);
    out[14] = (uint8_t) d->i_manufacturer;
    out[15] = (uint8_t) d->i_product;
    out[16] = (uint8_t) d->i_serial;
    out[17] = (uint8_t) d->num_configs;
}

/* Make room for one more entry, doubling the table when it is full.
 *
 * The new tail is zeroed because model_build fills an entry field by field and
 * relies on the rest (blob, blob_len, the string buffers) starting empty, the
 * way the file-static array used to give it for free.
 *
 * Returns false only when the allocation fails; the caller stops the walk and
 * says so rather than dropping devices quietly.
 */
static bool usb_devs_reserve(void)
{
    if (usb_ndevs < usb_devs_cap)
        return true;
    int cap = usb_devs_cap ? usb_devs_cap * 2 : USB_DEVS_INIT_CAP;
    usb_dev_t *grown = realloc(usb_devs, (size_t) cap * sizeof(*grown));
    if (!grown)
        return false;
    memset(grown + usb_devs_cap, 0,
           (size_t) (cap - usb_devs_cap) * sizeof(*grown));
    usb_devs = grown;
    usb_devs_cap = cap;
    return true;
}

static void model_clear(void)
{
    for (int i = 0; i < usb_ndevs; i++) {
        free(usb_devs[i].blob);
        usb_devs[i].blob = NULL;
    }
    usb_ndevs = 0;
}

/* model_clear plus the table itself, for the teardown paths: a rescan keeps the
 * allocation and refills it, but process exit must not leave it held.
 */
static void model_release(void)
{
    model_clear();
    free(usb_devs);
    usb_devs = NULL;
    usb_devs_cap = 0;
}

/* One fixture device before it is emitted: the scalar parameters model_build
 * turns into a usb_dev_t. Kept as plain data so the allocation that backs the
 * device stays lexically inside model_build, next to the compaction free, the
 * way the IOKit branch already carries its malloc.
 */
typedef struct {
    int busnum;
    int port;
    int devnum;
    unsigned vid;
    unsigned pid;
    unsigned nifaces;

    /* bInterfaceNumber of the first interface; each further one counts up from
     * it. Normally 0, so the numbers are 0, 1, ... and match the array
     * positions. The knob exists because bInterfaceNumber is a device-supplied
     * byte with the whole 0..255 range behind it while the consumers of it are
     * sized for far fewer, and no device anyone can plug in declares a large
     * one, so without a fixture that can emit one there is no way to assert
     * what happens when a device does.
     */
    unsigned ifnum_base;

    /* The endpoints every interface of this device carries, or NULL for the
     * default of one bulk IN per interface (0x81, 0x82, ...). The loopback
     * device needs a real OUT and a real interrupt IN, and the IOKit half has
     * to report the same set, so the table is shared rather than written twice
     * (runtime/usb-fixture.h).
     */
    const usb_fixture_ep_t *eps;
    unsigned neps;
} usb_fixture_spec_t;

/* The number of interface descriptors is the only thing that varies the blob
 * length: an 18-byte device descriptor, one configuration header, then one
 * interface descriptor per interface.
 */
static size_t usb_fixture_blob_len(const usb_fixture_spec_t *s)
{
    unsigned neps = s->neps ? s->neps : 1;
    return USB_DEVICE_DESC_LEN + USB_CONFIG_DESC_LEN +
           (size_t) s->nifaces *
               (USB_INTERFACE_DESC_LEN + (size_t) neps * USB_ENDPOINT_DESC_LEN);
}

/* Fill @d from @s, writing the device, configuration and interface descriptors
 * into @d->blob, which the caller has already allocated to
 * usb_fixture_blob_len(@s->nifaces). No allocation happens here, so ownership
 * of the blob stays with the caller.
 */
static void usb_fixture_fill(usb_dev_t *d, const usb_fixture_spec_t *s)
{
    size_t blob_len = d->blob_len;
    uint8_t *blob = d->blob;
    memset(d, 0, sizeof(*d));
    d->blob = blob;
    d->blob_len = blob_len;
    d->busnum = s->busnum;
    d->devnum = s->devnum;
    d->location_id =
        ((uint32_t) (s->busnum - 1) << 24) | ((uint32_t) s->port << 4);
    d->vid = s->vid;
    d->pid = s->pid;
    d->bcd_usb = 0x0200;
    d->bcd_device = 0x0100;
    d->max_packet0 = 64;
    d->num_configs = 1;
    d->speed_code = 1;
    d->cfg_value = 1;
    snprintf(d->devpath, sizeof(d->devpath), "%d", s->port);
    snprintf(d->name, sizeof(d->name), "%d-%d", s->busnum, s->port);

    unsigned neps = s->neps ? s->neps : 1;
    size_t if_total =
        USB_INTERFACE_DESC_LEN + (size_t) neps * USB_ENDPOINT_DESC_LEN;
    size_t cfg_total = USB_CONFIG_DESC_LEN + (size_t) s->nifaces * if_total;
    build_device_descriptor(d, blob);
    uint8_t *c = blob + USB_DEVICE_DESC_LEN;
    c[0] = USB_CONFIG_DESC_LEN;
    c[1] = USB_DT_CONFIG;
    c[2] = (uint8_t) (cfg_total & 0xff);
    c[3] = (uint8_t) (cfg_total >> 8);
    c[4] = (uint8_t) s->nifaces; /* bNumInterfaces */
    c[5] = 1;                    /* bConfigurationValue */
    c[6] = 0;                    /* iConfiguration */
    c[7] = 0x80;                 /* bmAttributes: bus powered */
    c[8] = 50;                   /* bMaxPower: 100 mA */
    for (unsigned i = 0; i < s->nifaces; i++) {
        uint8_t *q = c + USB_CONFIG_DESC_LEN + (size_t) i * if_total;
        q[0] = USB_INTERFACE_DESC_LEN;
        q[1] = USB_DT_INTERFACE;
        unsigned ifnum = s->ifnum_base + i;
        q[2] = (uint8_t) ifnum; /* bInterfaceNumber */
        q[3] = 0;               /* bAlternateSetting */
        q[4] = (uint8_t) neps;  /* bNumEndpoints */
        q[5] = 0xff;            /* bInterfaceClass: vendor-specific */
        q[6] = 0x00;
        q[7] = 0x00;
        q[8] = 0;

        /* The endpoint the interface descriptor above says it has. Without it
         * the blob was self-contradictory, and every endpoint-addressed
         * usbdevfs path (BULK, CLEAR_HALT, RESETEP, the control endpoint
         * recipient) had nothing to resolve against, so the fixture could not
         * reach the code that decides between "no such endpoint" and "bad
         * argument". Bulk IN, one per interface: 0x81, 0x82, ...
         */
        for (unsigned k = 0; k < neps; k++) {
            uint8_t *e =
                q + USB_INTERFACE_DESC_LEN + (size_t) k * USB_ENDPOINT_DESC_LEN;
            e[0] = USB_ENDPOINT_DESC_LEN;
            e[1] = USB_DT_ENDPOINT;
            e[2] = s->eps ? s->eps[k].addr : (uint8_t) (0x81 + i);
            e[3] = s->eps ? s->eps[k].attr : 0x02;
            uint16_t mps = s->eps ? s->eps[k].mps : 0x40;
            e[4] = (uint8_t) (mps & 0xff);
            e[5] = (uint8_t) (mps >> 8);
            e[6] = s->eps ? s->eps[k].interval : 0;
        }
    }
}

/* Fill @specs (capacity @cap) with the canned device set behind
 * ELFUSE_USB_FIXTURE and return how many were written, so the device-half
 * assertions (descriptor byte-identity, dev/rdev/minor, bNumInterfaces vs the
 * emitted interface-dir count, subsystem-link resolution) run on a host with no
 * USB device attached.
 *
 * Default: bus1/dev1 with two interfaces, bus2/dev1 with one, exercising the
 * per-bus minor arithmetic across two buses.
 *
 * ELFUSE_USB_FIXTURE=overflow: 129 address-less devices on bus 1 plus one on
 * bus 2, all routed through the fallback devnum assignment. It is the
 * regression fixture for the devnum cap -- without the cap bus1's 129th device
 * takes devnum 129 and shares minor 128 with bus2's first, so the cap must drop
 * everything past devnum 127.
 *
 * ELFUSE_USB_FIXTURE=badifnum: the default set plus /dev/bus/usb/001/002, whose
 * one interface declares bInterfaceNumber 200 and carries endpoint 0x81. It is
 * a malformed descriptor only in the sense that no sane device emits one: every
 * byte is well formed and the range is the field's own, which is why nothing
 * short of a fixture reaches the paths that index by that number. Added as a
 * separate mode rather than to the default set so the lanes that walk the tree
 * keep the device list they were written against.
 *
 * ELFUSE_USB_FIXTURE=loopback: the default set plus /dev/bus/usb/003/001, the
 * one device with an IOKit answer behind it (syscall/usbdev-fixture.c). It
 * carries interface 2 with bulk OUT 0x02, bulk IN 0x81 and interrupt IN 0x83,
 * the endpoints the out-of-tree board driver uses, and the addresses come from
 * runtime/usb-fixture.h so the descriptor blob here and GetPipeProperties there
 * cannot drift. The default devices stay in the set, and stay service-less, so
 * the fd-contract lane answers the same thing in this mode as in the default
 * one.
 */
static int usb_fixture_specs(usb_fixture_spec_t *specs, int cap)
{
    const char *mode = getenv("ELFUSE_USB_FIXTURE");
    int n = 0;
    if (mode && !strcmp(mode, "overflow")) {
        for (int port = 1; port <= 129 && n < cap; port++)
            specs[n++] = (usb_fixture_spec_t) {1, port, 0,    0x1d6b, 0x0002,
                                               1, 0,    NULL, 0};
        if (n < cap)
            specs[n++] =
                (usb_fixture_spec_t) {2, 1, 0, 0x2109, 0x0100, 1, 0, NULL, 0};
        return n;
    }
    if (n < cap)
        specs[n++] =
            (usb_fixture_spec_t) {1, 1, 1, 0x1d6b, 0x0002, 2, 0, NULL, 0};
    if (n < cap)
        specs[n++] =
            (usb_fixture_spec_t) {2, 1, 1, 0x2109, 0x0100, 1, 0, NULL, 0};
    if (mode && !strcmp(mode, "badifnum") && n < cap)
        specs[n++] =
            (usb_fixture_spec_t) {1, 2, 2, 0x1d6b, 0x0002, 1, 200, NULL, 0};
    if (mode && !strcmp(mode, "loopback") && n < cap)
        specs[n++] = (usb_fixture_spec_t) {
            USB_FIXTURE_LOOPBACK_BUS,    USB_FIXTURE_LOOPBACK_PORT,
            USB_FIXTURE_LOOPBACK_DEVNUM, USB_FIXTURE_LOOPBACK_VID,
            USB_FIXTURE_LOOPBACK_PID,    1,
            USB_FIXTURE_LOOPBACK_IFNUM,  usb_fixture_loopback_eps,
            USB_FIXTURE_LOOPBACK_NEPS};
    return n;
}

#define USB_FIXTURE_MAX 130

/* Enumerate the IOKit registry into usb_devs[].
 *
 * Known boundary -- no usbN root-hub entries. macOS does not publish root hubs
 * as USB devices: the IOUSBDevice/IOUSBHostDevice match returns only downstream
 * devices, and the controllers are IOUSBHostController objects that carry no
 * device descriptor to synthesize one from. The tree therefore has no
 * /sys/bus/usb/devices/usbN entries and no parent link from a device to its
 * bus. libusb enumerates each device independently and leaves parent_dev NULL,
 * and nusb skips names without a port path, so both still list every device;
 * what is lost is topology, so `lsusb -t` prints each device without the bus
 * row above it. The nports == 0 skip below is the matching guard: such an entry
 * could only be named "<bus>-" with an empty port path.
 */
static void model_build(void)
{
    model_clear();

    /* Test seam: a canned model, host-independent, so the device-half coverage
     * runs without hardware. Off in every normal run (the env var is unset), so
     * production still enumerates only the real IOKit registry.
     */
    if (getenv("ELFUSE_USB_FIXTURE")) {
        usb_fixture_spec_t specs[USB_FIXTURE_MAX];
        int n = usb_fixture_specs(specs, USB_FIXTURE_MAX);
        for (int k = 0; k < n; k++) {
            if (!usb_devs_reserve())
                break;
            usb_dev_t *d = &usb_devs[usb_ndevs];

            /* Allocate here, in the same procedure as the compaction free
             * below, so the blob's ownership is the registry branch's: a
             * canned-model allocation stashed in a callee would read to the
             * leak analyzer as unowned once it escaped into usb_devs[].
             */
            d->blob = malloc(usb_fixture_blob_len(&specs[k]));
            if (!d->blob)
                continue;
            d->blob_len = usb_fixture_blob_len(&specs[k]);
            usb_fixture_fill(d, &specs[k]);
            usb_ndevs++;
        }
        goto assign_devnums; /* run the same fallback+cap the registry path does
                              */
    }

    CFMutableDictionaryRef match = IOServiceMatching("IOUSBDevice");
    if (!match)
        return;
    io_iterator_t it = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, match, &it) !=
        kIOReturnSuccess)
        return;

    io_service_t svc;
    while ((svc = IOIteratorNext(it))) {
        /* Reserve before the entry pointer below is taken, so the growth can
         * never move the table out from under it mid-iteration.
         */
        if (!usb_devs_reserve()) {
            log_warn(
                "usb: cannot grow the device table past %d entries; "
                "the USB tree is truncated",
                usb_ndevs);
            IOObjectRelease(svc);
            break;
        }
        long loc = usb_ioreg_num(svc, "locationID");
        long vid = usb_ioreg_num(svc, "idVendor");
        long pid = usb_ioreg_num(svc, "idProduct");
        if (loc < 0 || vid < 0 || pid < 0) {
            IOObjectRelease(svc);
            continue;
        }
        unsigned ports[USB_MAX_PORTS];
        int nports = location_ports((uint32_t) loc, ports);
        if (nports == 0) { /* unnameable: no port path (see above) */
            IOObjectRelease(svc);
            continue;
        }
        bool dup = false;
        for (int i = 0; i < usb_ndevs; i++)
            if (usb_devs[i].location_id == (uint32_t) loc)
                dup = true;
        if (dup) {
            IOObjectRelease(svc);
            continue;
        }

        usb_dev_t *d = &usb_devs[usb_ndevs];
        memset(d, 0, sizeof(*d));
        d->location_id = (uint32_t) loc;

        /* macOS bus indices (locationID top byte) start at 0; Linux busnums are
         * 1-based (minor arithmetic and BBB names break at bus 0), so shift by
         * one. Deviation from a literal locationID>>24 is deliberate and
         * stable: the top byte is constant per controller.
         */
        d->busnum = (int) ((uint32_t) loc >> 24) + 1;
        long addr = usb_ioreg_num(svc, "USB Address");
        if (addr < 0)
            addr = usb_ioreg_num(svc, "kUSBAddress");
        d->devnum = addr > 0 && addr < 128 ? (int) addr : 0;
        d->vid = (unsigned) vid & 0xffff;
        d->pid = (unsigned) pid & 0xffff;

        long v;
        d->bcd_device =
            (v = usb_ioreg_num(svc, "bcdDevice")) >= 0 ? (unsigned) v : 0;
        d->bcd_usb =
            (v = usb_ioreg_num(svc, "bcdUSB")) >= 0 ? (unsigned) v : 0x0200;
        d->dev_class =
            (v = usb_ioreg_num(svc, "bDeviceClass")) >= 0 ? (unsigned) v : 0;
        d->dev_subclass =
            (v = usb_ioreg_num(svc, "bDeviceSubClass")) >= 0 ? (unsigned) v : 0;
        d->dev_protocol =
            (v = usb_ioreg_num(svc, "bDeviceProtocol")) >= 0 ? (unsigned) v : 0;
        d->num_configs = (v = usb_ioreg_num(svc, "bNumConfigurations")) > 0
                             ? (unsigned) v
                             : 1;
        d->max_packet0 =
            (v = usb_ioreg_num(svc, "bMaxPacketSize0")) > 0 ? (unsigned) v : 64;
        d->speed_code =
            (v = usb_ioreg_num(svc, "Device Speed")) >= 0 ? (unsigned) v : 1;
        d->i_manufacturer =
            (v = usb_ioreg_num(svc, "iManufacturer")) > 0 ? (unsigned) v : 0;
        d->i_product =
            (v = usb_ioreg_num(svc, "iProduct")) > 0 ? (unsigned) v : 0;
        d->i_serial =
            (v = usb_ioreg_num(svc, "iSerialNumber")) > 0 ? (unsigned) v : 0;
        d->cfg_value = (v = usb_ioreg_num(svc, "kUSBCurrentConfiguration")) > 0
                           ? (unsigned) v
                           : 0;

        if (!usb_ioreg_str(svc, "kUSBVendorString", d->manufacturer,
                           sizeof(d->manufacturer)))
            usb_ioreg_str(svc, "USB Vendor Name", d->manufacturer,
                          sizeof(d->manufacturer));
        if (!usb_ioreg_str(svc, "kUSBProductString", d->product,
                           sizeof(d->product)))
            usb_ioreg_str(svc, "USB Product Name", d->product,
                          sizeof(d->product));
        if (!usb_ioreg_str(svc, "kUSBSerialNumberString", d->serial,
                           sizeof(d->serial)))
            usb_ioreg_str(svc, "USB Serial Number", d->serial,
                          sizeof(d->serial));

        /* "<bus>-<port[.port]*>" (usb.c:704-726) and devpath */
        size_t off = 0;
        for (int i = 0; i < nports; i++)
            off += (size_t) snprintf(d->devpath + off, sizeof(d->devpath) - off,
                                     "%s%u", i ? "." : "", ports[i]);
        snprintf(d->name, sizeof(d->name), "%d-%s", d->busnum, d->devpath);

        d->blob = malloc(18);
        if (!d->blob) {
            IOObjectRelease(svc);
            continue;
        }
        d->blob_len = 18;
        append_config_descriptors(svc, d);
        build_device_descriptor(d, d->blob);

        /* Fall back to the first config's bConfigurationValue when the registry
         * has no current-configuration key. Byte 5 is bConfigurationValue only
         * once the record is known to be a configuration header, so the same
         * two-field check the descriptor walk applies is applied here rather
         * than reading the field out of whatever the device happened to send.
         */
        if (d->cfg_value == 0 &&
            d->blob_len >= USB_DEVICE_DESC_LEN + USB_CONFIG_DESC_LEN &&
            d->blob[USB_DEVICE_DESC_LEN] == USB_CONFIG_DESC_LEN &&
            d->blob[USB_DEVICE_DESC_LEN + 1] == USB_DT_CONFIG)
            d->cfg_value = d->blob[USB_DEVICE_DESC_LEN + 5];
        if (d->cfg_value == 0)
            d->cfg_value = 1;

        usb_ndevs++;
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);

assign_devnums:
    /* Fallback devnum assignment: stable 1..n per bus in locationID order for
     * devices without a 'USB Address' property, avoiding taken numbers.
     */
    for (int pass = 0; pass < usb_ndevs; pass++) {
        int best = -1;
        for (int i = 0; i < usb_ndevs; i++) {
            if (usb_devs[i].devnum != 0)
                continue;
            if (best < 0 ||
                usb_devs[i].location_id < usb_devs[best].location_id)
                best = i;
        }
        if (best < 0)
            break;
        int devnum = 1;
        for (int again = 1; again;) {
            again = 0;
            for (int i = 0; i < usb_ndevs; i++)
                if (i != best && usb_devs[i].busnum == usb_devs[best].busnum &&
                    usb_devs[i].devnum == devnum) {
                    devnum++;
                    again = 1;
                }
        }
        if (devnum > 127) {
            /* usbfs numbers devices 1..127 per bus: devnum-1 is the low 7 bits
             * of the minor (usb_minor()), so a 128th device on one bus would
             * take the first minor of the next bus (bus1 devnum129 and bus2
             * devnum1 both map to minor 128). The registry-address path already
             * clamps to <128; cap the fallback the same way and drop the
             * overflow rather than alias a node onto another bus's range.
             */
            log_warn(
                "usb: bus %d already holds 127 devices; dropping the device at "
                "locationID 0x%08x (usbfs caps devnum at 127)",
                usb_devs[best].busnum, (unsigned) usb_devs[best].location_id);
            usb_devs[best].devnum = -1; /* tombstone; compacted out below */
            continue;
        }
        usb_devs[best].devnum = devnum;
    }

    /* Compact the tombstones the cap left behind so no later pass, emit, or
     * lookup sees a devnum < 1.
     */
    int kept = 0;
    for (int i = 0; i < usb_ndevs; i++) {
        if (usb_devs[i].devnum >= 1) {
            if (kept != i)
                usb_devs[kept] = usb_devs[i];
            kept++;
        } else {
            free(usb_devs[i].blob);
            usb_devs[i].blob = NULL;
        }
    }
    usb_ndevs = kept;
}

/* scratch tree construction */

static int usb_write_file(const char *dir,
                          const char *name,
                          const void *data,
                          size_t len)
{
    char path[256];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >=
        (int) sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0444);
    if (fd < 0)
        return -1;
    const uint8_t *p = data;
    size_t left = len;
    while (left > 0) {
        ssize_t n = write(fd, p, left);
        if (n < 0 && errno == EINTR)
            continue; /* retry like syscpu_write_file: a stray signal must
                       * not abort a one-shot tree build
                       */
        if (n <= 0) {
            close(fd);
            return -1;
        }
        p += n;
        left -= (size_t) n;
    }
    close(fd);
    return 0;
}

__attribute__((format(printf, 3, 4))) static int usb_write_fmt(const char *dir,
                                                               const char *name,
                                                               const char *fmt,
                                                               ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
        n = 0;
    if ((size_t) n >= sizeof(buf))
        n = (int) sizeof(buf) - 1;
    return usb_write_file(dir, name, buf, (size_t) n);
}

/* sysfs speed strings (sysfs.c:145-178) keyed by the registry's Device Speed
 * code (USB.h: 0 Low, 1 Full, 2 High, 3 Super, 4 Super+, 5 Super+x2).
 */
static const char *speed_string(unsigned code)
{
    switch (code) {
    case 0:
        return "1.5";
    case 1:
        return "12";
    case 2:
        return "480";
    case 3:
        return "5000";
    case 4:
        return "10000";
    case 5:
        return "20000";
    default:
        return "12";
    }
}

static int usb_minor(const usb_dev_t *d)
{
    return (d->busnum - 1) * 128 + (d->devnum - 1);
}

/* Locate the active configuration descriptor inside the blob: the one whose
 * bConfigurationValue matches cfg_value, else the first. Every "current
 * configuration's attributes" reader (bNumInterfaces, bmAttributes, bMaxPower,
 * the interface dirs) must go through this, or the attribute files and the
 * emitted :c.i directories can describe two different configurations.
 *
 * Returns the descriptor with *len_out set, or NULL when the blob carries none.
 */
static const uint8_t *active_config(const usb_dev_t *d, size_t *len_out)
{
    return usb_desc_active_config(d->blob, d->blob_len, d->cfg_value, len_out);
}

/* Emit one interface dir <name>:<cfg>.<if> per bInterfaceNumber (alternate
 * setting 0) of the active configuration, parsed from the raw config descriptor
 * already in the blob -- registry children vanish under capture, so they are
 * deliberately not consulted.
 */
static void emit_interface_dirs(const char *devices_dir, const usb_dev_t *d)
{
    size_t cfg_len = 0;
    const uint8_t *cfg = active_config(d, &cfg_len);
    if (!cfg)
        return;

    /* The blob is device-supplied, so the walk is a bounded iteration that can
     * only ever stop early (usb-desc.h), never step off the end of cfg_len.
     * usb_desc_interfaces owns the selection -- alternate setting 0, first
     * appearance of each bInterfaceNumber -- and is sized to the whole byte
     * range the field can hold, so no number is dropped for being large.
     */
    const uint8_t *ifaces[USB_DESC_INTERFACES_MAX];
    bool truncated = false;
    size_t stop_off = 0;
    size_t nif = usb_desc_interfaces(cfg, cfg_len, ifaces, ARRAY_SIZE(ifaces),
                                     &truncated, &stop_off);
    if (truncated)
        log_warn(
            "usb-sysfs: %s: config descriptor truncated after %zu of %zu bytes",
            d->name, stop_off, cfg_len);

    for (size_t i = 0; i < nif; i++) {
        const uint8_t *q = ifaces[i];
        unsigned ifnum = q[2], alt = q[3], neps = q[4];
        unsigned icls = q[5], isub = q[6], ipro = q[7];
        char idir[256];
        if (snprintf(idir, sizeof(idir), "%s/%s:%u.%u", devices_dir, d->name,
                     d->cfg_value, ifnum) >= (int) sizeof(idir) ||
            mkdir(idir, 0755) != 0)
            continue;
        usb_write_fmt(idir, "bInterfaceNumber", "%02x\n", ifnum);
        usb_write_fmt(idir, "bAlternateSetting", "%2d\n", alt);
        usb_write_fmt(idir, "bNumEndpoints", "%02x\n", neps);
        usb_write_fmt(idir, "bInterfaceClass", "%02x\n", icls);
        usb_write_fmt(idir, "bInterfaceSubClass", "%02x\n", isub);
        usb_write_fmt(idir, "bInterfaceProtocol", "%02x\n", ipro);
        char ilink[300];
        if (snprintf(ilink, sizeof(ilink), "%s/subsystem", idir) <
            (int) sizeof(ilink))
            symlink("../../../usb", ilink);
        usb_write_fmt(idir, "uevent",
                      "DEVTYPE=usb_interface\n"
                      "PRODUCT=%x/%x/%x\n"
                      "TYPE=%u/%u/%u\n"
                      "INTERFACE=%u/%u/%u\n"
                      "MODALIAS=usb:v%04Xp%04Xd%04Xdc%02Xdsc%02Xdp%02X"
                      "ic%02Xisc%02Xip%02Xin%02X\n",
                      d->vid, d->pid, d->bcd_device, d->dev_class,
                      d->dev_subclass, d->dev_protocol, icls, isub, ipro,
                      d->vid, d->pid, d->bcd_device, d->dev_class,
                      d->dev_subclass, d->dev_protocol, icls, isub, ipro,
                      ifnum);
    }
}

static void emit_device_dir(const char *devices_dir, const usb_dev_t *d)
{
    char dir[256];
    if (snprintf(dir, sizeof(dir), "%s/%s", devices_dir, d->name) >=
        (int) sizeof(dir))
        return;
    if (mkdir(dir, 0755) < 0)
        return;

    usb_write_fmt(dir, "busnum", "%d\n", d->busnum);
    usb_write_fmt(dir, "devnum", "%d\n", d->devnum);
    usb_write_fmt(dir, "devpath", "%s\n", d->devpath);
    usb_write_fmt(dir, "idVendor", "%04x\n", d->vid);
    usb_write_fmt(dir, "idProduct", "%04x\n", d->pid);
    usb_write_fmt(dir, "bcdDevice", "%04x\n", d->bcd_device);
    usb_write_fmt(dir, "bDeviceClass", "%02x\n", d->dev_class);
    usb_write_fmt(dir, "bDeviceSubClass", "%02x\n", d->dev_subclass);
    usb_write_fmt(dir, "bDeviceProtocol", "%02x\n", d->dev_protocol);
    usb_write_fmt(dir, "bNumConfigurations", "%u\n", d->num_configs);
    usb_write_fmt(dir, "bMaxPacketSize0", "%u\n", d->max_packet0);
    usb_write_fmt(dir, "bConfigurationValue", "%u\n", d->cfg_value);
    usb_write_fmt(dir, "version", "%2x.%02x\n", d->bcd_usb >> 8,
                  d->bcd_usb & 0xff);
    usb_write_fmt(dir, "speed", "%s\n", speed_string(d->speed_code));
    usb_write_fmt(dir, "dev", "%d:%d\n", USB_MAJOR, usb_minor(d));

    /* Current configuration's attributes (sysfs.c:29-88, 782-786), read from
     * the same descriptor emit_interface_dirs walks.
     *
     * All four are written on every device, including when the blob carried no
     * usable configuration at all. Linux's dev_attr_grp has no .is_visible
     * (sysfs.c:815-817), so these files exist on every USB device directory and
     * a value the kernel cannot supply shows up as a zero-length read; writing
     * only the ones whose value is known would answer ENOENT where Linux
     * answers "nothing", which is a different fact about the device. See
     * usb_desc_actconfig_attrs for the rest of the rule.
     *
     * cfg_string is NULL here, and that is the whole of what this stage can
     * say. iConfiguration names a string descriptor, and a string descriptor is
     * fetched over an ep0 control transfer on an open device -- which this
     * layer deliberately does not do. IOKit offers no way around it: an
     * IOUSBHostDevice registry entry publishes iManufacturer, iProduct and
     * iSerialNumber together with the three strings the family caches for them
     * ("USB Vendor Name", "USB Product Name", kUSBSerialNumberString), but it
     * publishes neither an iConfiguration index nor any configuration string,
     * and IOUSBDeviceInterface has no cached-string call to stand in for the
     * transfer the way GetConfigurationDescriptorPtr stands in for fetching a
     * configuration descriptor.
     *
     * A NULL cfg_string is not a lie about the device, and this is why the file
     * stays present and empty rather than being left out: usb_cache_string
     * returns NULL "if the index is 0 or the string could not be read", so
     * every device here takes the second of Linux's own two paths to an empty
     * configuration. Known deviation, and a fidelity gap rather than a
     * correctness one: a device whose iConfiguration is non-zero and whose
     * string descriptor is readable shows that string on Linux and shows
     * nothing here. Closing it needs the ep0 path.
     */
    size_t cfg_len = 0;
    const uint8_t *cfg = active_config(d, &cfg_len);
    usb_actconfig_attrs_t actcfg;

    /* bMaxPower is in 2 mA units below SuperSpeed and 8 mA at and above it
     * (usb_get_max_power); speed_code is IOKit's "Device Speed", whose 3 is
     * SuperSpeed.
     */
    usb_desc_actconfig_attrs(cfg, cfg_len, d->speed_code >= 3 ? 8 : 2, NULL,
                             &actcfg);
    usb_write_file(dir, "bNumInterfaces", actcfg.num_interfaces,
                   strlen(actcfg.num_interfaces));
    usb_write_file(dir, "bmAttributes", actcfg.bm_attributes,
                   strlen(actcfg.bm_attributes));
    usb_write_file(dir, "bMaxPower", actcfg.max_power,
                   strlen(actcfg.max_power));
    usb_write_file(dir, "configuration", actcfg.configuration,
                   strlen(actcfg.configuration));

    /* Downstream port count. Hub descriptors need a control transfer on an open
     * device, which stage 1 deliberately does not do, so every device reports
     * the non-hub value. Known deviation: a hub's real port count is not
     * modeled, and neither is the parent/child topology that would use it.
     */
    usb_write_fmt(dir, "maxchild", "%d\n", 0);

    /* Lane counts (hub.c:3036-3041): SuperSpeed+ Gen 2x2 -- the registry's
     * Device Speed 5 -- runs two lanes each way, everything else one.
     */
    unsigned lanes = d->speed_code == 5 ? 2 : 1;
    usb_write_fmt(dir, "rx_lanes", "%u\n", lanes);
    usb_write_fmt(dir, "tx_lanes", "%u\n", lanes);
    if (d->manufacturer[0])
        usb_write_fmt(dir, "manufacturer", "%s\n", d->manufacturer);
    if (d->product[0])
        usb_write_fmt(dir, "product", "%s\n", d->product);
    if (d->serial[0])
        usb_write_fmt(dir, "serial", "%s\n", d->serial);
    usb_write_fmt(dir, "uevent",
                  "MAJOR=%d\n"
                  "MINOR=%d\n"
                  "DEVNAME=bus/usb/%03d/%03d\n"
                  "DEVTYPE=usb_device\n"
                  "DRIVER=usb\n"
                  "PRODUCT=%x/%x/%x\n"
                  "TYPE=%u/%u/%u\n"
                  "BUSNUM=%03d\n"
                  "DEVNUM=%03d\n",
                  USB_MAJOR, usb_minor(d), d->busnum, d->devnum, d->vid, d->pid,
                  d->bcd_device, d->dev_class, d->dev_subclass, d->dev_protocol,
                  d->busnum, d->devnum);
    usb_write_file(dir, "descriptors", d->blob, d->blob_len);

    /* libudev derives the subsystem from readlink(<dev>/subsystem) and keeps
     * only its basename; the relative target also resolves inside the scratch
     * tree (devices/<name>/../../../usb == bus/usb).
     */
    char linkpath[300];
    if (snprintf(linkpath, sizeof(linkpath), "%s/subsystem", dir) <
        (int) sizeof(linkpath))
        symlink("../../../usb", linkpath);

    emit_interface_dirs(devices_dir, d);
}

static void usb_remove_tree(const char *dir, int depth)
{
    if (depth > 6)
        return;
    DIR *dp = opendir(dir);
    if (dp) {
        struct dirent *ent;
        while ((ent = readdir(dp))) {
            if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
                continue;
            char path[512];
            if (snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name) >=
                (int) sizeof(path))
                continue;
            struct stat st;
            if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode))
                usb_remove_tree(path, depth + 1);
            else
                unlink(path);
        }
        closedir(dp);
    }
    rmdir(dir);
}

static void usb_tree_cleanup(void)
{
    pthread_mutex_lock(&usb_lock);
    if (usb_tree_ok && usb_owner_pid == getpid()) {
        usb_remove_tree(usb_sys_dir, 0);
        usb_remove_tree(usb_dev_dir, 0);
    }
    usb_tree_ok = false;
    model_release();
    pthread_mutex_unlock(&usb_lock);
}

/* One-shot build under usb_lock (the ensure_syscpu_dir pattern). The model is a
 * boot-time snapshot: hotplug support would clear usb_tree_ok here so the next
 * call re-enumerates, once something (the uevent layer) can observe
 * attach/detach and call in.
 * Returns 0 with both scratch roots valid, or -1 with errno set.
 */
static int ensure_usb_tree(void)
{
    if (usb_tree_ok)
        return 0;

    str_copy_trunc(usb_sys_dir, "/tmp/elfuse-usbsys-XXXXXX",
                   sizeof(usb_sys_dir));
    if (!mkdtemp(usb_sys_dir)) {
        usb_sys_dir[0] = '\0';
        return -1;
    }
    if (!realpath(usb_sys_dir, usb_sys_real)) {
        int saved = errno;
        usb_remove_tree(usb_sys_dir, 0);
        usb_sys_dir[0] = usb_sys_real[0] = '\0';
        errno = saved;
        return -1;
    }
    str_copy_trunc(usb_dev_dir, "/tmp/elfuse-usbdev-XXXXXX",
                   sizeof(usb_dev_dir));
    if (!mkdtemp(usb_dev_dir)) {
        usb_remove_tree(usb_sys_dir, 0);
        usb_sys_dir[0] = usb_dev_dir[0] = usb_sys_real[0] = '\0';
        return -1;
    }
    if (!realpath(usb_dev_dir, usb_dev_real)) {
        int saved = errno;
        usb_remove_tree(usb_sys_dir, 0);
        usb_remove_tree(usb_dev_dir, 0);
        usb_sys_dir[0] = usb_dev_dir[0] = usb_sys_real[0] = usb_dev_real[0] =
            '\0';
        errno = saved;
        return -1;
    }

    model_build();

    char devices_dir[128];
    {
        char sub[128];
        snprintf(sub, sizeof(sub), "%s/bus", usb_sys_dir);
        if (mkdir(sub, 0755) < 0)
            goto fail;
        snprintf(sub, sizeof(sub), "%s/bus/usb", usb_sys_dir);
        if (mkdir(sub, 0755) < 0)
            goto fail;
    }
    snprintf(devices_dir, sizeof(devices_dir), "%s/bus/usb/devices",
             usb_sys_dir);
    if (mkdir(devices_dir, 0755) < 0)
        goto fail;
    char usbdir[128];
    snprintf(usbdir, sizeof(usbdir), "%s/usb", usb_dev_dir);
    if (mkdir(usbdir, 0755) < 0)
        goto fail;

    for (int i = 0; i < usb_ndevs; i++) {
        const usb_dev_t *d = &usb_devs[i];
        emit_device_dir(devices_dir, d);

        char busdir[160];
        if (snprintf(busdir, sizeof(busdir), "%s/%03d", usbdir, d->busnum) >=
            (int) sizeof(busdir))
            continue;
        if (mkdir(busdir, 0755) < 0 && errno != EEXIST)
            continue;
        char node[8];
        snprintf(node, sizeof(node), "%03d", d->devnum);
        /* Placeholder: 0444 empty regular file; open/stat divert it. */
        usb_write_file(busdir, node, "", 0);
    }

    static bool atexit_armed;
    if (!atexit_armed) {
        atexit(usb_tree_cleanup);
        atexit_armed = true;
    }
    usb_owner_pid = getpid();
    usb_tree_ok = true;
    return 0;

fail:;
    int saved = errno;
    usb_remove_tree(usb_sys_dir, 0);
    usb_remove_tree(usb_dev_dir, 0);
    usb_sys_dir[0] = usb_dev_dir[0] = usb_sys_real[0] = usb_dev_real[0] = '\0';
    model_release();
    errno = saved;
    return -1;
}

/* path classification */

typedef enum {
    USB_PATH_NONE,
    USB_PATH_DEV_BUS,      /* /dev/bus            */
    USB_PATH_DEV_USB,      /* /dev/bus/usb        */
    USB_PATH_DEV_BUSNUM,   /* /dev/bus/usb/BBB    */
    USB_PATH_DEV_NODE,     /* /dev/bus/usb/BBB/DDD */
    USB_PATH_DEV_NODE_SUB, /* the node used as a directory: BBB/DDD/ or /x */
    USB_PATH_DEV_ABSENT,   /* under /dev/bus/usb but no such device */
    USB_PATH_DEV_FOREIGN,  /* under /dev/bus but on no bus we model */
    USB_PATH_SYS,          /* /sys[/suffix] (whole sysfs view) */
} usb_path_kind_t;

/* Parse exactly three decimal digits followed by '\0' or '/'. */
static int parse_ddd(const char *s, const char **rest)
{
    if (!isdigit((unsigned char) s[0]) || !isdigit((unsigned char) s[1]) ||
        !isdigit((unsigned char) s[2]))
        return -1;
    if (s[3] != '\0' && s[3] != '/')
        return -1;
    *rest = s + 3;
    return (s[0] - '0') * 100 + (s[1] - '0') * 10 + (s[2] - '0');
}

/* Skip one or more '/' and report whether anything follows. */
static const char *skip_slashes(const char *s)
{
    while (*s == '/')
        s++;
    return s;
}

static usb_path_kind_t classify_path(const char *path,
                                     int *bus_out,
                                     int *dev_out,
                                     const char **sys_suffix_out)
{
    if (path_prefix_match(path, "/sys", 4)) {
        /* /sys/devices/system/cpu stays with the syscpu stub, which the procemu
         * dispatchers consult before this layer.
         */
        if (path_prefix_match(path, "/sys/devices/system/cpu", 23))
            return USB_PATH_NONE;
        const char *sfx = skip_slashes(path + 4);
        *sys_suffix_out = sfx;
        return USB_PATH_SYS;
    }
    if (!path_prefix_match(path, "/dev/bus", 8))
        return USB_PATH_NONE;

    const char *p = skip_slashes(path + 8);
    if (!*p)
        return USB_PATH_DEV_BUS;
    if (strncmp(p, "usb", 3) != 0 || (p[3] != '\0' && p[3] != '/'))
        return USB_PATH_DEV_FOREIGN;
    p = skip_slashes(p + 3);
    if (!*p)
        return USB_PATH_DEV_USB;
    const char *rest;
    int bus = parse_ddd(p, &rest);
    if (bus < 0)
        return USB_PATH_DEV_ABSENT;
    rest = skip_slashes(rest);
    if (!*rest) {
        *bus_out = bus;
        return USB_PATH_DEV_BUSNUM;
    }
    const char *rest2;
    int dev = parse_ddd(rest, &rest2);
    if (dev < 0)
        return USB_PATH_DEV_ABSENT;
    *bus_out = bus;
    *dev_out = dev;

    /* Any separator after the node -- a bare trailing slash included, which is
     * why this tests rest2 itself rather than what survives skip_slashes -- is
     * the node being used as a directory. Linux answers ENOTDIR for that, but
     * only once the node exists; a missing node still reports ENOENT, so the
     * decision is deferred to the lookup rather than made here.
     */
    if (rest2[0] != '\0')
        return USB_PATH_DEV_NODE_SUB;
    return USB_PATH_DEV_NODE;
}

/* True when a folded /sys-relative suffix names something under the one subtree
 * this layer synthesizes, /sys/bus/usb. It gates a single decision: what to do
 * when a /sys name resolves to nothing in the scratch tree. Under /sys/bus/usb
 * an absence is authoritative -- a missing device is ENOENT, the way a real
 * sysfs answers -- so this returns true and the caller keeps the ENOENT.
 * Anywhere else under /sys (/sys/class, /sys/devices, /sys/kernel, a bus other
 * than usb) we model nothing, so a miss must not be reported as ENOENT: that
 * would shadow a populated sysroot /sys. This returns false there and the
 * caller reports PROC_NOT_INTERCEPTED so the sysroot backing answers.
 *
 * The /sys root and its /sys/bus parent are not "owned" by this test, but they
 * exist as real directories in the scratch tree, so they resolve and are served
 * before this test is ever consulted; only the resolve-failure path asks it.
 * The @suffix arrives with '.'/'..' folded, so "bus/usb/../class" is "class"
 * and correctly disowned, while "bus/usb/devices/1-1" stays ours.
 */
static bool usb_sys_suffix_owned(const char *suffix)
{
    /* Exactly the bus/usb directory, or a name that continues it past a '/'.
     * Spelled with whole-string compares rather than a suffix[7] index so the
     * boundary byte is never read on its own -- the folded builder output that
     * reaches here is NUL-terminated, but an explicit index past the compared
     * prefix reads to the analyzer as a maybe-uninitialized byte.
     */
    return !strcmp(suffix, "bus/usb") || !strncmp(suffix, "bus/usb/", 8);
}

static usb_dev_t *find_dev(int busnum, int devnum)
{
    for (int i = 0; i < usb_ndevs; i++)
        if (usb_devs[i].busnum == busnum && usb_devs[i].devnum == devnum)
            return &usb_devs[i];
    return NULL;
}

static bool bus_exists(int busnum)
{
    for (int i = 0; i < usb_ndevs; i++)
        if (usb_devs[i].busnum == busnum)
            return true;
    return false;
}

/* classify_path's answer for the /dev/bus-relative name @folded. */
static usb_path_kind_t usb_dev_kind(const char *folded, int *bus)
{
    char path[LINUX_PATH_MAX];
    int dev = 0;
    const char *sfx = "";
    int n = snprintf(path, sizeof(path), "/dev/bus/%s", folded);
    if (n < 0 || (size_t) n >= sizeof(path))
        return USB_PATH_NONE;
    return classify_path(path, bus, &dev, &sfx);
}

/* Whether @folded starts with a usbfs node. */
static bool usb_dev_names_node(const char *folded)
{
    int bus = 0;
    usb_path_kind_t kind = usb_dev_kind(folded, &bus);
    return kind == USB_PATH_DEV_NODE || kind == USB_PATH_DEV_NODE_SUB;
}

/* Whether @folded names a directory the layer serves. Caller holds usb_lock
 * after ensure_usb_tree().
 */
static bool usb_dev_names_dir(const char *folded)
{
    int bus = 0;
    usb_path_kind_t kind = usb_dev_kind(folded, &bus);
    return kind == USB_PATH_DEV_USB ||
           (kind == USB_PATH_DEV_BUSNUM && bus_exists(bus));
}

/* Fold '.' and '..' in a /sys- or, with @dev, a /dev/bus-relative suffix,
 * lexically; a name that folds above its root is not this layer's. On /sys the
 * fold decides only that, and usb_sys_resolve_suffix builds the served path.
 * With @dev a '..' after a usbfs node stops the fold and the rest is kept as
 * written, since Linux applies '..' only to a directory. A trailing slash
 * survives, so an attribute used as a directory reports ENOTDIR.
 *
 * Returns 1 with @out filled, 0 when the walk climbs above the root, -1 when
 * the result does not fit. With @rest, under usb_lock after ensure_usb_tree(),
 * a '..' pops only a directory usb_dev_names_dir accepts, and *@rest is left on
 * what follows a climbing '..'. A '..' that meets any other name returns 0 with
 * that name in @out, and *@rest on the '..' when the name is outside
 * /dev/bus/usb, NULL otherwise. Without @rest no lock is held, and any other
 * name is popped unchecked.
 */
static int usb_suffix_normalize(const char *suffix,
                                bool dev,
                                char *out,
                                size_t outsz,
                                const char **rest)
{
    size_t len = 0;
    size_t marks[64];
    size_t depth = 0;

    out[0] = '\0';
    for (const char *p = suffix; *p;) {
        const char *seg = p;
        while (*p && *p != '/')
            p++;
        size_t seglen = (size_t) (p - seg);
        while (*p == '/')
            p++;
        if (seglen == 0 || (seglen == 1 && seg[0] == '.'))
            continue;
        if (seglen == 2 && seg[0] == '.' && seg[1] == '.') {
            if (depth == 0) {
                if (rest)
                    *rest = p;
                return 0; /* above the root */
            }
            if (rest && !usb_dev_names_dir(out)) {
                int bus = 0;
                bool foreign = usb_dev_kind(out, &bus) == USB_PATH_DEV_FOREIGN;
                *rest = foreign ? seg : NULL;
                return 0;
            }
            if (dev && usb_dev_names_node(out)) {
                size_t rlen = strlen(seg); /* this '..' and all after it */
                if (len + 1 + rlen + 1 > outsz)
                    return -1;
                out[len++] = '/';
                memcpy(out + len, seg, rlen + 1);
                return 1;
            }
            len = marks[--depth];
            out[len] = '\0';
            continue;
        }
        if (depth >= ARRAY_SIZE(marks))
            return -1;
        marks[depth++] = len;
        if (len + (len ? 1 : 0) + seglen + 1 > outsz)
            return -1;
        if (len)
            out[len++] = '/';
        memcpy(out + len, seg, seglen);
        len += seglen;
        out[len] = '\0';
    }

    /* Preserve a trailing slash only when something remains to apply it to;
     * "/sys/bus/.." folds to /sys itself, which is a directory either way.
     */
    if (len > 0 && suffix[0] && suffix[strlen(suffix) - 1] == '/') {
        if (len + 2 > outsz)
            return -1;
        out[len++] = '/';
        out[len] = '\0';
    }
    return 1;
}

/* Synthetic stat identities, mirroring procemu.c's PROC_SYNTH_DEV scheme with a
 * distinct device so /sys/bus/usb nodes never collide with /proc ones.
 */
#define USB_SYNTH_DEV ((dev_t) 0x5553)

/* st_ino identifies the object, not the spelling that reached it: hashing the
 * caller's path handed /sys/bus/usb/devices and /sys/bus/usb/devices/../devices
 * two different inodes for one directory, which is a thing no filesystem does
 * and which every (st_dev, st_ino) same-file test -- realpath loop detection,
 * find -L, hardlink accounting -- would believe. Callers pass the canonical
 * spelling built by usb_canon_path.
 */
static ino_t usb_synth_ino(const char *canon)
{
    uint64_t h = fnv1a64(canon, strlen(canon));
    h &= 0x7fffffffffffffffULL;
    return (ino_t) (h ? h : 1);
}

/* One spelling per object: the guest-visible path with '.'/'..' already folded
 * (the suffix arrives normalized) and any trailing slash dropped.
 */
static void usb_canon_path(usb_path_kind_t kind,
                           const char *sfx,
                           int bus,
                           int dev,
                           char *out,
                           size_t outsz)
{
    switch (kind) {
    case USB_PATH_SYS:
        if (*sfx)
            snprintf(out, outsz, "/sys/%s", sfx);
        else
            str_copy_trunc(out, "/sys", outsz);
        break;
    case USB_PATH_DEV_BUS:
        str_copy_trunc(out, "/dev/bus", outsz);
        break;
    case USB_PATH_DEV_USB:
        str_copy_trunc(out, "/dev/bus/usb", outsz);
        break;
    case USB_PATH_DEV_BUSNUM:
        snprintf(out, outsz, "/dev/bus/usb/%03d", bus);
        break;
    case USB_PATH_DEV_NODE:
    case USB_PATH_DEV_NODE_SUB:
        snprintf(out, outsz, "/dev/bus/usb/%03d/%03d", bus, dev);
        break;
    case USB_PATH_DEV_ABSENT:
    case USB_PATH_DEV_FOREIGN:
    case USB_PATH_NONE:
        str_copy_trunc(out, "/dev/bus", outsz);
        break;
    }
    size_t n = strlen(out);
    while (n > 1 && out[n - 1] == '/')
        out[--n] = '\0';
}

static void fill_synth_dir(struct stat *st, const char *canon)
{
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFDIR | 0755;
    st->st_nlink = 2;
    st->st_dev = USB_SYNTH_DEV;
    st->st_ino = usb_synth_ino(canon);
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_blksize = 4096;
}

static void fill_synth_file(struct stat *st, const char *canon)
{
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFREG | 0444;
    st->st_nlink = 1;
    st->st_dev = USB_SYNTH_DEV;
    st->st_ino = usb_synth_ino(canon);
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_blksize = 4096;
}

static void fill_synth_chardev(struct stat *st,
                               const char *canon,
                               const usb_dev_t *d)
{
    memset(st, 0, sizeof(*st));

    /* 0666 rather than udev's root:root 0660 policy: the single-user guest must
     * be able to open its own device nodes, which is what a desktop Linux
     * spells as a uaccess ACL for the seat owner. The owner reported below is
     * the host user, and the guest's own uid need not equal it, so 0664 left
     * access(W_OK) answering EACCES for a node that open(O_RDWR) then served --
     * the two entry points onto one permission question disagreeing. Stage 1
     * had no writable open to disagree with; stage 2 does.
     */
    st->st_mode = S_IFCHR | 0666;
    st->st_nlink = 1;
    st->st_dev = USB_SYNTH_DEV;
    st->st_ino = usb_synth_ino(canon);
    st->st_uid = getuid();
    st->st_gid = getgid();

    /* macOS dev_t encoding (major<<24 | minor); translate_stat converts.
     * Composed in uint32_t: dev_t is a signed 32-bit int here, so shifting
     * major 189 left by 24 lands in the sign bit and is undefined -- the SDK's
     * own makedev() has the same defect, which is why the encoding is spelled
     * out rather than borrowed.
     */
    st->st_rdev =
        (dev_t) (((uint32_t) USB_MAJOR << 24) | (uint32_t) usb_minor(d));
    st->st_blksize = 4096;
    st->st_size = (off_t) d->blob_len;
}

/* Synthetic descriptor-blob fd (the proc_synthetic_fd pattern): unlinked temp
 * file so lseek/pread work.
 */
static int usb_blob_fd(const usb_dev_t *d)
{
    char template[] = "/tmp/elfuse-usbnode-XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0)
        return -1;
    unlink(template);
    const uint8_t *p = d->blob;
    size_t left = d->blob_len;
    while (left > 0) {
        ssize_t n = write(fd, p, left);
        if (n < 0 && errno == EINTR)
            continue; /* retry like syscpu_write_file: a stray signal must
                       * not abort a one-shot tree build
                       */
        if (n <= 0) {
            close(fd);
            return -1;
        }
        p += n;
        left -= (size_t) n;
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

/* intercept entry points */

/* Shared entry-point preamble: fold the name, then decide whose it is, before
 * any lock is taken. Both halves fold; see the /dev/bus arm below and
 * usb_suffix_normalize for what the fold is and is not.
 *
 * *sfx_out receives the /sys suffix as the guest spelled it -- unfolded,
 * because usb_sys_resolve_suffix has to see the '..' in their original
 * positions to order them against the symlinks they follow. `norm` holds the
 * folded spelling, which decides only whether the name is ours.
 *
 * Every name whose spelling alone settles ownership is settled here, so that no
 * entry point re-derives it: a /sys name that folds above /sys, a /dev/bus name
 * that folds above /dev/bus, and a /dev/bus name on a bus we do not model all
 * leave as USB_PATH_NONE, and every caller reports PROC_NOT_INTERCEPTED. See
 * docs/internals.md, "Ownership Of `/sys` And `/dev/bus` Names", for why a name
 * we do not serve must fall through rather than answer ENOENT.
 *
 * The one ours/not-ours question this cannot answer is the /sys name that has
 * to be resolved first; usb_resolve_or_disown owns that half.
 *
 * Returns the kind, or USB_PATH_NONE when the folded path is not ours; *err_out
 * non-zero means classify itself failed (ENAMETOOLONG) and the caller must
 * report it rather than pass the path on.
 */
static usb_path_kind_t classify_and_normalize(const char *path,
                                              int *bus_out,
                                              int *dev_out,
                                              const char **sfx_out,
                                              char *norm,
                                              size_t normsz,
                                              int *err_out)
{
    *err_out = 0;

    /* Fold the /dev/bus suffix before classify_path reads it, so both halves of
     * the layer reach ownership the same way: /dev/bus/usb/../other/f is the
     * backing's file and /dev/bus/other/../usb/001/001 is the synthetic node
     * (matrix columns dev-fold-out and dev-fold-in).
     *
     * The result is written into norm, which the /sys arm below would use for
     * its own folded suffix; the two never both run, and classify_path's
     * sys_suffix_out is only set on the /sys arm, so it keeps pointing into
     * live storage either way.
     *
     * A suffix that folds away above /dev/bus leaves as USB_PATH_NONE, the same
     * answer the /sys arm gives a name that climbs above /sys: the layer serves
     * nothing there and the caller reports PROC_NOT_INTERCEPTED.
     */
    if (path_prefix_match(path, "/dev/bus", 8)) {
        char folded[LINUX_PATH_MAX];
        int frc = usb_suffix_normalize(skip_slashes(path + 8), true, folded,
                                       sizeof(folded), NULL);
        if (frc < 0) {
            *err_out = ENAMETOOLONG;
            return USB_PATH_NONE;
        }
        if (frc == 0)
            return USB_PATH_NONE; /* climbed above /dev/bus; not ours */
        int n = folded[0] ? snprintf(norm, normsz, "/dev/bus/%s", folded)
                          : snprintf(norm, normsz, "/dev/bus");
        if (n < 0 || (size_t) n >= normsz) {
            *err_out = ENAMETOOLONG;
            return USB_PATH_NONE;
        }
        path = norm;
    }

    usb_path_kind_t kind = classify_path(path, bus_out, dev_out, sfx_out);
    if (kind == USB_PATH_DEV_FOREIGN)
        return USB_PATH_NONE; /* another bus's /dev/bus subtree; not ours */
    if (kind != USB_PATH_SYS)
        return kind;
    int rc = usb_suffix_normalize(*sfx_out, false, norm, normsz, NULL);
    if (rc < 0) {
        *err_out = ENAMETOOLONG;
        return USB_PATH_NONE;
    }
    if (rc == 0)
        return USB_PATH_NONE; /* climbed above /sys; not ours */
    return USB_PATH_SYS;
}

static bool usb_root_contains(const char *root, const char *canonical)
{
    size_t rootlen = strlen(root);
    return rootlen != 0 && !strncmp(canonical, root, rootlen) &&
           (canonical[rootlen] == '\0' || canonical[rootlen] == '/');
}

static bool usb_sys_contained(const char *canonical)
{
    return usb_root_contains(usb_sys_real, canonical);
}

/* Resolve a host path inside the sysfs scratch tree and prove the result is
 * still inside it, so the caller can open it with symlinks followed.
 *
 * Following is safe because the links are ours -- emit_* writes them with fixed
 * relative targets into a tree the guest cannot write -- so procemu.c's "do not
 * follow symlinks the guest created" has nothing to bite on, and a positive
 * containment check replaces the blanket refusal.
 *
 * The escape guarantee: the suffix arrives lexically folded, so host_path
 * cannot climb out on its own and a symlink is the only way out; realpath()
 * resolves every one of them, leaf and intermediate alike, and the canonical
 * result is tested against the canonical root. A path that resolved outside is
 * reported absent. The open still passes O_NOFOLLOW, which closes the swap
 * window on the final component; a symlink spun into an intermediate directory
 * between the resolve and the open would still be followed, and that residual
 * TOCTOU is unreachable -- a sysrooted guest cannot name the host scratch tree
 * to plant one, and a sysroot-less guest already has the host filesystem.
 *
 * Returns 0 with `out` filled, or -1 with errno set (realpath's errno, or
 * ENOENT for a path that resolved outside the tree).
 */
static int usb_sys_resolve(const char *host_path, char *out, size_t outsz)
{
    char resolved[PATH_MAX];
    if (!realpath(host_path, resolved))
        return -1;
    if (!usb_sys_contained(resolved)) {
        log_warn("usb-sysfs: %s resolves outside the tree; refusing",
                 host_path);
        errno = ENOENT;
        return -1;
    }
    if (str_copy_trunc(out, resolved, outsz) >= outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* Resolve a /sys-relative suffix to a host path inside the scratch tree, the
 * way the kernel resolves it: each component is applied to what the previous
 * one resolved to, so a '..' after a symlink pops the *target's* parent.
 *
 * This is what makes <dev>/subsystem/.. name /sys/bus, the way Linux does,
 * rather than the device directory a lexical fold would have kept it in. The
 * lexical fold in usb_suffix_normalize decides only whether the name is ours.
 *
 * realpath() performs the whole walk -- symlinks in the leaf and in every
 * intermediate component, and '..' in kernel order -- and its canonical result
 * is tested against the canonical root. That containment test is the sole
 * escape authority, which is why the raw, unfolded suffix is safe to hand it.
 *
 * `nofollow` keeps the semantics O_NOFOLLOW and lstat need: everything up to
 * the final component is resolved and contained, and the leaf is appended
 * without being followed and contained again afterwards. A '.' or '..' leaf is
 * not held back -- it cannot be a symlink, and it is the one leaf whose
 * reattachment can move the name (see below).
 *
 * *canon_out receives the resolved location as a /sys-relative suffix, so the
 * synthetic identity is keyed on the object rather than on the spelling.
 *
 * Returns 0, or -1 with errno set (realpath's errno, or ENOENT for a path that
 * resolved outside the tree).
 */
static int usb_sys_resolve_suffix(const char *raw_sfx,
                                  bool nofollow,
                                  char *host_out,
                                  size_t host_sz,
                                  char *canon_out,
                                  size_t canon_sz)
{
    char joined[PATH_MAX];
    int n = *raw_sfx ? snprintf(joined, sizeof(joined), "%s/%s", usb_sys_dir,
                                raw_sfx)
                     : snprintf(joined, sizeof(joined), "%s", usb_sys_dir);
    if (n < 0 || (size_t) n >= sizeof(joined)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    char resolved[PATH_MAX];
    char leaf[NAME_MAX + 1];
    leaf[0] = '\0';

    if (nofollow && *raw_sfx) {
        /* Split off the final component, resolve the rest, reattach it. A
         * trailing slash means the caller is using the name as a directory, so
         * there is no unfollowed leaf to protect and the whole path resolves.
         */
        size_t jlen = strlen(joined);
        if (joined[jlen - 1] != '/') {
            char *slash = strrchr(joined, '/');
            if (!slash) {
                errno = EINVAL;
                return -1;
            }
            if (strlen(slash + 1) >= sizeof(leaf)) {
                errno = ENAMETOOLONG;
                return -1;
            }

            /* '.' and '..' are never symlinks, so there is nothing for
             * O_NOFOLLOW to protect -- and holding one back turns the walk
             * inside out: the prefix is contained, the dot-dot is reattached to
             * the *canonical* result afterwards, and one applied to the tree
             * root then names the host directory the root sits in. The
             * containment test has already run and does not run again, so that
             * spelling leaves the tree. Let the whole path go to
             * usb_sys_resolve, which resolves the dot-dot in kernel order and
             * tests what it actually reached.
             */
            const char *last = slash + 1;
            bool dots = !strcmp(last, ".") || !strcmp(last, "..");
            if (!dots) {
                str_copy_trunc(leaf, last, sizeof(leaf));
                *slash = '\0';
            }
        }
    }

    if (usb_sys_resolve(joined, resolved, sizeof(resolved)) < 0)
        return -1;

    if (leaf[0]) {
        size_t rl = strlen(resolved);
        if (rl + 1 + strlen(leaf) + 1 > sizeof(resolved)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        resolved[rl] = '/';
        str_copy_trunc(resolved + rl + 1, leaf, sizeof(resolved) - rl - 1);

        /* Reattaching is the one step that can move the name after the
         * containment test ran, so the test is applied to what the caller will
         * actually be handed rather than to the prefix it was derived from. It
         * stays the single authority: no spelling reaches a caller without
         * having passed it last.
         */
        if (!usb_sys_contained(resolved)) {
            log_warn("usb-sysfs: %s resolves outside the tree; refusing",
                     resolved);
            errno = ENOENT;
            return -1;
        }

        /* Probe the leaf that was reattached without being walked. Without this
         * the nofollow resolve succeeds for every name whose *parent* exists --
         * the scratch /sys root exists, so "/sys/class" resolved -- and the
         * caller's ours/not-ours escape hatch, which only the failure path
         * consults, was never reached. The lstat that followed then failed
         * ENOENT and that became the answer, shadowing a populated sysroot for
         * lstat, open(O_NOFOLLOW) and readlink while stat and plain open (which
         * resolve the leaf too, and so fail here) fell through correctly.
         *
         * lstat, not stat: a symlink leaf is the object the caller named.
         */
        struct stat leaf_st;
        if (lstat(resolved, &leaf_st) < 0) {
            if (!errno)
                errno = ENOENT;
            return -1;
        }
    }

    if (str_copy_trunc(host_out, resolved, host_sz) >= host_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* usb_sys_resolve proved `resolved` is usb_sys_real or below it, so the
     * remainder after the root is exactly the /sys-relative spelling.
     */
    const char *rel = resolved + strlen(usb_sys_real);
    while (*rel == '/')
        rel++;
    if (str_copy_trunc(canon_out, rel, canon_sz) >= canon_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* Resolve a /sys name and settle, in one place, whether this layer answers for
 * it at all -- the resolve half of the fall-through decision classify_and_
 * normalize makes for every other name. Every /sys entry point goes through
 * here so none of them can disagree about which names are ours.
 *
 * Returns true with @host_out and @canon_out filled.
 *
 * Returns false with *err_out set to 0 when the name is not ours (the caller
 * reports PROC_NOT_INTERCEPTED so the sysroot backing answers), or to an errno
 * when the name is ours and the resolve genuinely failed. An absence under
 * /sys/bus/usb is authoritative -- that subtree is the one thing this layer
 * synthesizes -- so it comes back as ENOENT rather than as a fall-through.
 */
static bool usb_resolve_or_disown(const char *raw_sfx,
                                  const char *norm,
                                  bool nofollow,
                                  char *host_out,
                                  size_t host_sz,
                                  char *canon_out,
                                  size_t canon_sz,
                                  int *err_out)
{
    if (usb_sys_resolve_suffix(raw_sfx, nofollow, host_out, host_sz, canon_out,
                               canon_sz) == 0) {
        *err_out = 0;
        return true;
    }
    int reserr = errno;
    *err_out = (reserr == ENOENT && !usb_sys_suffix_owned(norm)) ? 0 : reserr;
    return false;
}

int usb_sysfs_guest_path_for_fd(int host_fd, char *out, size_t outsz)
{
    char host_path[PATH_MAX];
    if (fcntl(host_fd, F_GETPATH, host_path) < 0)
        return 0;

    pthread_mutex_lock(&usb_lock);
    int rc = 0;

    /* Containment proved the remainder after the root is either empty or starts
     * with '/', so the guest root plus it is the guest spelling.
     */
    const char *root = NULL, *guest = NULL;
    if (usb_root_contains(usb_sys_real, host_path)) {
        root = usb_sys_real;
        guest = "/sys";
    } else if (usb_root_contains(usb_dev_real, host_path)) {
        root = usb_dev_real;
        guest = "/dev/bus";
    }
    if (root) {
        int n = snprintf(out, outsz, "%s%s", guest, host_path + strlen(root));
        rc = (n > 0 && (size_t) n < outsz) ? 1 : 0;
    }
    pthread_mutex_unlock(&usb_lock);
    return rc;
}

/* What an intercept entry point returns for a path the USB tree does not own:
 * PROC_NOT_INTERCEPTED normally, or -1 with errno set when the path was ours in
 * shape but malformed. Stated once so the three entry points cannot drift.
 */
static int usb_not_intercepted(int cerr)
{
    if (cerr) {
        errno = cerr;
        return -1;
    }
    return PROC_NOT_INTERCEPTED;
}

int usb_sysfs_intercept_open(const char *path, int linux_flags, int mode)
{
    int bus = 0, dev = 0, cerr = 0;
    const char *sfx = NULL;
    char norm[LINUX_PATH_MAX];
    usb_path_kind_t kind = classify_and_normalize(path, &bus, &dev, &sfx, norm,
                                                  sizeof(norm), &cerr);
    if (kind == USB_PATH_NONE)
        return usb_not_intercepted(cerr);

    pthread_mutex_lock(&usb_lock);
    int rc = -1;
    int err = 0;
    if (ensure_usb_tree() < 0) {
        err = errno;
        goto out;
    }

    switch (kind) {
    case USB_PATH_SYS: {
        bool nofollow = (linux_flags & LINUX_O_NOFOLLOW) != 0;
        int accmode = translate_open_flags(linux_flags) & O_ACCMODE;
        bool mutating = accmode != O_RDONLY ||
                        (linux_flags & (LINUX_O_CREAT | LINUX_O_TRUNC));
        char host_path[PATH_MAX], canon_sfx[PATH_MAX];

        /* Resolve in kernel order first: '..' after a symlink has to pop the
         * target's parent before anything is decided about the name.
         */
        int reserr = 0;
        if (!usb_resolve_or_disown(sfx, norm, nofollow, host_path,
                                   sizeof(host_path), canon_sfx,
                                   sizeof(canon_sfx), &reserr)) {
            /* Not ours: hand it back to the sysroot backing instead of
             * shadowing it with ENOENT.
             */
            if (!reserr) {
                pthread_mutex_unlock(&usb_lock);
                return PROC_NOT_INTERCEPTED;
            }

            /* A create names something that does not exist yet, so the resolve
             * failing is expected there and says nothing about the request. It
             * is still a mutating open of a read-only tree, which is what the
             * guest has to be told -- not the ENOENT of the name it picked.
             */
            err = mutating ? EACCES : reserr;
            goto out;
        }

        /* O_NOFOLLOW on a symlink is ELOOP, and Linux decides that before it
         * looks at the access mode: open("<dev>/subsystem", O_WRONLY |
         * O_NOFOLLOW) is ELOOP on a real sysfs, not the EISDIR the link's
         * target would earn (measured on /sys/class/net/lo/subsystem, 6.19).
         * Deciding the read-only refusal first would answer for the target of a
         * link the caller explicitly asked not to follow. O_PATH is the
         * documented exception: O_PATH|O_NOFOLLOW names the link itself.
         */
        if (nofollow && !(linux_flags & LINUX_O_PATH)) {
            struct stat lst;
            if (lstat(host_path, &lst) == 0 && S_ISLNK(lst.st_mode)) {
                err = ELOOP;
                goto out;
            }
        }

        /* Read-only tree, syscpu contract: reject mutating opens -- with the
         * errno Linux gives, which depends on what the name resolves to. A
         * sysfs directory answers EISDIR, because open(2) refuses write access
         * to a directory before it ever consults permissions; a sysfs attribute
         * is a mode 0444 regular file, so it answers EACCES.
         */
        if (mutating) {
            struct stat wst;
            err = (stat(host_path, &wst) == 0 && S_ISDIR(wst.st_mode)) ? EISDIR
                                                                       : EACCES;
            goto out;
        }

        /* In the follow case the leaf is already resolved and by construction
         * not a symlink, so O_NOFOLLOW changes nothing on the intended path and
         * closes the swap window on that final component only: open(2) re-walks
         * the resolved path string, so a symlink spun into an intermediate
         * directory after the resolve would still be followed. That residual
         * window is unreachable (a sysrooted guest cannot name the scratch tree
         * to plant one; see usb_sys_resolve above).
         *
         * In the nofollow case the flags are passed through untouched: the
         * guest's intent is already encoded there, and O_PATH|O_NOFOLLOW maps
         * to macOS O_SYMLINK -- "open the link itself" -- which OR-ing
         * O_NOFOLLOW back in would turn into an ELOOP.
         */
        int oflags = translate_open_flags(linux_flags);
        if (!nofollow)
            oflags |= O_NOFOLLOW;
        rc = open(host_path, oflags, mode);
        if (rc < 0)
            err = errno;
        goto out;
    }
    case USB_PATH_DEV_BUS:
        rc = proc_open_dir_fd(usb_dev_dir, linux_flags);
        if (rc < 0)
            err = errno;
        goto out;
    case USB_PATH_DEV_USB:
    case USB_PATH_DEV_BUSNUM: {
        char host_path[256];
        int n;
        if (kind == USB_PATH_DEV_USB)
            n = snprintf(host_path, sizeof(host_path), "%s/usb", usb_dev_dir);
        else {
            if (!bus_exists(bus)) {
                err = ENOENT;
                goto out;
            }
            n = snprintf(host_path, sizeof(host_path), "%s/usb/%03d",
                         usb_dev_dir, bus);
        }
        if (n < 0 || (size_t) n >= sizeof(host_path)) {
            err = ENAMETOOLONG;
            goto out;
        }
        rc = proc_open_dir_fd(host_path, linux_flags);
        if (rc < 0)
            err = errno;
        goto out;
    }
    case USB_PATH_DEV_NODE_SUB:
        err = find_dev(bus, dev) ? ENOTDIR : ENOENT;
        goto out;
    case USB_PATH_DEV_NODE: {
        usb_dev_t *d = find_dev(bus, dev);
        if (!d) {
            err = ENOENT;
            goto out;
        }
        if (linux_flags & LINUX_O_DIRECTORY) {
            err = ENOTDIR;
            goto out;
        }
        int accmode = translate_open_flags(linux_flags) & O_ACCMODE;
        if (accmode != O_RDONLY) {
            /* Unreachable through sys_openat_path: usbdev_open_path claims
             * every non-O_PATH open of a node before proc_intercept_open runs
             * (stage 2, syscall/usbdev.c). Kept as a guard for any other caller
             * of the intercept.
             */
            log_warn(
                "usb-sysfs: writable open of %s bypassed the FD_USBDEV "
                "constructor",
                path);
            err = EACCES;
            goto out;
        }
        rc = usb_blob_fd(d);
        if (rc < 0)
            err = errno;
        goto out;
    }
    case USB_PATH_DEV_ABSENT:
        err = ENOENT;
        goto out;
    case USB_PATH_DEV_FOREIGN:
    case USB_PATH_NONE:
        break; /* folded to USB_PATH_NONE by classify_and_normalize */
    }

out:
    pthread_mutex_unlock(&usb_lock);
    if (rc < 0)
        errno = err ? err : EIO;
    return rc;
}

int usb_sysfs_intercept_stat(const char *path, struct stat *st, bool follow)
{
    int bus = 0, dev = 0, cerr = 0;
    const char *sfx = NULL;
    char norm[LINUX_PATH_MAX];
    usb_path_kind_t kind = classify_and_normalize(path, &bus, &dev, &sfx, norm,
                                                  sizeof(norm), &cerr);
    if (kind == USB_PATH_NONE)
        return usb_not_intercepted(cerr);

    pthread_mutex_lock(&usb_lock);
    int rc = -1;
    int err = 0;
    if (ensure_usb_tree() < 0) {
        err = errno;
        goto out;
    }

    char canon[LINUX_PATH_MAX];
    usb_canon_path(kind, sfx ? sfx : "", bus, dev, canon, sizeof(canon));

    switch (kind) {
    case USB_PATH_SYS: {
        if (!*sfx) {
            fill_synth_dir(st, canon);
            rc = 0;
            goto out;
        }

        /* Resolve in kernel order, and only then decide what was named: with
         * `follow` the leaf symlink is resolved too, so stat() of a subsystem
         * link reports the directory it points at, the way it does on Linux.
         * lstat() (follow == false) still reports the link itself.
         */
        char host_path[PATH_MAX], canon_sfx[PATH_MAX];
        int reserr = 0;
        if (!usb_resolve_or_disown(sfx, norm, !follow, host_path,
                                   sizeof(host_path), canon_sfx,
                                   sizeof(canon_sfx), &reserr)) {
            /* Not ours: let the sysroot backing answer rather than shadow it
             * with ENOENT, so stat and open agree on it.
             */
            if (!reserr) {
                pthread_mutex_unlock(&usb_lock);
                return PROC_NOT_INTERCEPTED;
            }
            err = reserr;
            goto out;
        }
        usb_canon_path(kind, canon_sfx, bus, dev, canon, sizeof(canon));

        struct stat host_st;
        if (lstat(host_path, &host_st) < 0) {
            err = errno;
            goto out;
        }
        if (S_ISDIR(host_st.st_mode))
            fill_synth_dir(st, canon);
        else if (S_ISLNK(host_st.st_mode)) {
            /* Only reachable with follow == false; the follow case resolved the
             * link away above.
             */
            fill_synth_file(st, canon);
            st->st_mode = S_IFLNK | 0777;
            st->st_size = host_st.st_size;
        } else {
            fill_synth_file(st, canon);
            st->st_size = host_st.st_size; /* attrs read as sized files */
        }
        rc = 0;
        goto out;
    }
    case USB_PATH_DEV_BUS:
    case USB_PATH_DEV_USB:
        fill_synth_dir(st, canon);
        rc = 0;
        goto out;
    case USB_PATH_DEV_BUSNUM:
        if (!bus_exists(bus)) {
            err = ENOENT;
            goto out;
        }
        fill_synth_dir(st, canon);
        rc = 0;
        goto out;
    case USB_PATH_DEV_NODE_SUB:
        err = find_dev(bus, dev) ? ENOTDIR : ENOENT;
        goto out;
    case USB_PATH_DEV_NODE: {
        usb_dev_t *d = find_dev(bus, dev);
        if (!d) {
            err = ENOENT;
            goto out;
        }
        fill_synth_chardev(st, canon, d);
        rc = 0;
        goto out;
    }
    case USB_PATH_DEV_ABSENT:
        err = ENOENT;
        goto out;
    case USB_PATH_DEV_FOREIGN:
    case USB_PATH_NONE:
        break; /* folded to USB_PATH_NONE by classify_and_normalize */
    }

out:
    pthread_mutex_unlock(&usb_lock);
    if (rc < 0)
        errno = err ? err : EIO;
    return rc;
}

int usb_sysfs_intercept_readlink(const char *path, char *buf, size_t bufsiz)
{
    int bus = 0, dev = 0, cerr = 0;
    const char *sfx = NULL;
    char norm[LINUX_PATH_MAX];
    usb_path_kind_t kind = classify_and_normalize(path, &bus, &dev, &sfx, norm,
                                                  sizeof(norm), &cerr);
    if (kind == USB_PATH_NONE)
        return usb_not_intercepted(cerr);

    if (kind == USB_PATH_SYS) {
        /* The scratch tree holds real symlinks for `subsystem` entries;
         * readlink passes their targets through. Plain dirs/files answer EINVAL
         * and missing paths ENOENT, exactly as sysfs would.
         */
        pthread_mutex_lock(&usb_lock);
        int rc = -1;
        int err = 0;
        if (ensure_usb_tree() < 0) {
            err = errno;
        } else if (!*sfx) {
            err = EINVAL; /* /sys itself is a directory */
        } else {
            /* The same resolution the open and stat paths use, for the same two
             * reasons. The suffix arrives as the guest spelled it, so a '..'
             * behind a `subsystem` link still has to be applied to what that
             * link resolved to; and usb_sys_resolve_suffix carries the only
             * containment check in this layer. Joining the raw suffix onto the
             * scratch root instead would let a name whose lexical fold stays
             * inside resolve, through the link, onto a host symlink outside the
             * tree and report its target to the guest.
             *
             * nofollow, because readlink names the link itself and never the
             * object behind it.
             */
            char host_path[PATH_MAX], canon_sfx[PATH_MAX];
            if (!usb_resolve_or_disown(sfx, norm, true, host_path,
                                       sizeof(host_path), canon_sfx,
                                       sizeof(canon_sfx), &err)) {
                /* Not ours: fall through to the sysroot backing rather than
                 * shadow it, as the open and stat paths do.
                 */
                if (!err) {
                    pthread_mutex_unlock(&usb_lock);
                    return PROC_NOT_INTERCEPTED;
                }
            } else {
                ssize_t n = readlink(host_path, buf, bufsiz);
                if (n < 0)
                    err = errno;
                else
                    rc = (int) n;
            }
        }
        pthread_mutex_unlock(&usb_lock);
        if (rc < 0)
            errno = err ? err : EIO;
        return rc;
    }

    struct stat st;
    int rc = usb_sysfs_intercept_stat(path, &st, false);
    if (rc == PROC_NOT_INTERCEPTED)
        return PROC_NOT_INTERCEPTED;
    if (rc < 0)
        return -1; /* errno already set (ENOENT etc.) */
    /* The /dev/bus tree holds real dirs and device nodes, never symlinks. */
    errno = EINVAL;
    return -1;
}

/* True when @sfx (a /sys-relative spelling) names one of the `subsystem`
 * symlinks this layer materializes. Caller holds usb_lock and has run
 * ensure_usb_tree().
 *
 * The name alone is not enough: /sys/bus/usb/devices/9-9/subsystem names no
 * link at all when there is no device 9-9, and rewriting a walk through a link
 * that does not exist would turn a Linux ENOENT into a successful lookup
 * somewhere else entirely.
 */
static bool usb_sys_is_subsystem_link(const char *sfx)
{
    char host[PATH_MAX];
    int n = snprintf(host, sizeof(host), "%s/%s", usb_sys_dir, sfx);
    if (n < 0 || (size_t) n >= sizeof(host))
        return false;
    struct stat st;
    return lstat(host, &st) == 0 && S_ISLNK(st.st_mode);
}

int usb_sysfs_resolve_guest_path(const char *guest_path,
                                 char *out,
                                 size_t outsz)
{
    /* Every `subsystem` link this layer plants sits under /sys/bus/usb/devices,
     * so nothing else can move a walk, and a path that cannot contain one is
     * rejected before the tree is touched.
     */
    if (strncmp(guest_path, "/sys/bus/usb/devices/", 21) != 0 ||
        !strstr(guest_path, "/subsystem"))
        return 0;

    pthread_mutex_lock(&usb_lock);
    int rc = 0;
    if (ensure_usb_tree() < 0)
        goto out;

    char rel[LINUX_PATH_MAX];
    size_t len = 0;
    size_t marks[64];
    size_t depth = 0;
    bool rewrote = false;
    rel[0] = '\0';

    for (const char *p = guest_path + 5; *p;) {
        const char *seg = p;
        while (*p && *p != '/')
            p++;
        size_t seglen = (size_t) (p - seg);
        const char *after = p;
        while (*after == '/')
            after++;
        p = after;

        if (seglen == 0 || (seglen == 1 && seg[0] == '.'))
            continue;
        if (seglen == 2 && seg[0] == '.' && seg[1] == '.') {
            if (depth == 0)
                goto out; /* above /sys; not a name this layer can place */
            len = marks[--depth];
            rel[len] = '\0';
            continue;
        }
        if (depth >= ARRAY_SIZE(marks))
            goto out;
        marks[depth++] = len;
        if (len + (len ? 1 : 0) + seglen + 1 > sizeof(rel))
            goto out;
        if (len)
            rel[len++] = '/';
        memcpy(rel + len, seg, seglen);
        len += seglen;
        rel[len] = '\0';

        /* A `subsystem` link with nothing after it is the object the caller
         * named, and lstat/readlink/O_NOFOLLOW have to keep seeing the link
         * itself, so only a link the walk continues through is substituted.
         * What it is substituted with is where it points -- every one of them
         * points at /sys/bus/usb -- so the components that follow are applied
         * to the target, which is what makes `subsystem/..` name /sys/bus the
         * way the kernel does.
         */
        if (*p && seglen == 9 && !memcmp(seg, "subsystem", 9)) {
            if (!usb_sys_is_subsystem_link(rel))
                goto out;
            memcpy(rel, "bus/usb", 8);
            len = 7;
            depth = 2;
            marks[0] = 0;
            marks[1] = 3;
            rewrote = true;
        }
    }

    if (!rewrote)
        goto out;

    /* A trailing slash survives: it is what makes a non-directory named as a
     * directory report ENOTDIR, and the rewrite must not answer that question.
     */
    const char *tail = guest_path[strlen(guest_path) - 1] == '/' ? "/" : "";
    int n = snprintf(out, outsz, "/sys%s%s%s", len ? "/" : "", rel, tail);
    rc = (n > 0 && (size_t) n < outsz) ? 1 : 0;

out:
    pthread_mutex_unlock(&usb_lock);
    return rc;
}

bool usb_sysfs_stops_fold(const char *guest_path)
{
    if (!path_prefix_match(guest_path, "/dev/bus", 8))
        return false;
    int bus = 0, dev = 0;
    const char *sfx = "";
    usb_path_kind_t kind = classify_path(guest_path, &bus, &dev, &sfx);
    return kind != USB_PATH_DEV_BUS && kind != USB_PATH_DEV_USB;
}

bool usb_sysfs_node_path(const char *guest_path, char *out, size_t outsz)
{
    int bus = 0, dev = 0, cerr = 0;
    const char *sfx = NULL;
    return path_prefix_match(guest_path, "/dev/bus", 8) &&
           !path_dir_required(guest_path) &&
           classify_and_normalize(guest_path, &bus, &dev, &sfx, out, outsz,
                                  &cerr) == USB_PATH_DEV_NODE;
}

int usb_sysfs_resolve_dev_climb(const char *guest_path,
                                char *out,
                                size_t outsz,
                                const char **dotdot)
{
    if (!path_prefix_match(guest_path, "/dev/bus", 8) ||
        !strstr(guest_path, ".."))
        return 0;
    char folded[LINUX_PATH_MAX];
    const char *rest = NULL;
    int frc = -1;
    pthread_mutex_lock(&usb_lock);
    if (ensure_usb_tree() == 0)
        frc = usb_suffix_normalize(skip_slashes(guest_path + 8), true, folded,
                                   sizeof(folded), &rest);
    pthread_mutex_unlock(&usb_lock);
    if (frc != 0)
        return 0;

    /* A '..' after a name outside /dev/bus/usb: that name is the backing's. */
    if (rest && folded[0]) {
        int n = snprintf(out, outsz, "/dev/bus/%s", folded);
        if (n < 0 || (size_t) n >= outsz)
            return 0;
        *dotdot = rest;
        return 2;
    }

    /* The walk stopped at a '..' it does not apply. */
    if (!rest) {
        int bus = 0;
        usb_path_kind_t kind = usb_dev_kind(folded, &bus);
        if (kind != USB_PATH_DEV_BUSNUM && kind != USB_PATH_DEV_ABSENT)
            return 0;
        errno = ENOENT;
        return -1;
    }

    /* A further '..' climbs /dev, and one past it stays at the root as on
     * Linux; left in the name, it reaches the backing as /dev/.., where no
     * intercept matches what it lands on.
     */
    const char *dir = "/dev";
    while (rest[0] == '.' && rest[1] == '.' &&
           (rest[2] == '/' || rest[2] == '\0')) {
        dir = "";
        rest = skip_slashes(rest + 2);
    }

    /* When the climb ends the name, the rewrite ends in '.', so rmdir and
     * rename fail rather than act on the directory reached, with EINVAL on a
     * sysroot where Linux gives ENOTEMPTY and EBUSY for a final '..'.
     */
    int n = snprintf(out, outsz, "%s/%s", dir, *rest ? rest : ".");
    return n > 0 && (size_t) n < outsz ? 1 : 0;
}

bool usb_sysfs_dir_unions_backing(const char *guest_path)
{
    int bus = 0, dev = 0, cerr = 0;
    const char *sfx = NULL;
    char norm[LINUX_PATH_MAX];
    usb_path_kind_t kind = classify_and_normalize(guest_path, &bus, &dev, &sfx,
                                                  norm, sizeof(norm), &cerr);
    if (kind == USB_PATH_DEV_BUS)
        return true;
    if (kind != USB_PATH_SYS)
        return false;

    /* The same ownership test the lookup path uses, so the listing and the
     * lookups can never disagree about which names this layer answers for.
     */
    return !usb_sys_suffix_owned(norm);
}

uint8_t *usb_sysfs_descriptors_dup(int busnum, int devnum, size_t *len_out)
{
    pthread_mutex_lock(&usb_lock);
    uint8_t *copy = NULL;
    if (ensure_usb_tree() == 0) {
        usb_dev_t *d = find_dev(busnum, devnum);
        if (d) {
            copy = malloc(d->blob_len);
            if (copy) {
                memcpy(copy, d->blob, d->blob_len);
                *len_out = d->blob_len;
            }
        } else {
            errno = ENODEV;
        }
    }
    pthread_mutex_unlock(&usb_lock);
    return copy;
}

int usb_sysfs_device_info(int busnum, int devnum, usb_sysfs_devinfo_t *out)
{
    pthread_mutex_lock(&usb_lock);
    int rc = -1;
    if (ensure_usb_tree() == 0) {
        usb_dev_t *d = find_dev(busnum, devnum);
        if (d) {
            out->location_id = d->location_id;
            out->speed_code = d->speed_code;
            out->cfg_value = d->cfg_value;
            out->minor = usb_minor(d);
            out->blob_len = d->blob_len;
            out->vid = d->vid;
            out->pid = d->pid;
            str_copy_trunc(out->serial, d->serial, sizeof(out->serial));
            rc = 0;
        } else {
            errno = ENODEV;
        }
    }
    pthread_mutex_unlock(&usb_lock);
    return rc;
}

int usb_sysfs_node_stat(int busnum, int devnum, struct stat *st)
{
    pthread_mutex_lock(&usb_lock);
    int rc = -1;
    if (ensure_usb_tree() == 0) {
        usb_dev_t *d = find_dev(busnum, devnum);
        if (d) {
            char node[64];
            snprintf(node, sizeof(node), "/dev/bus/usb/%03d/%03d", busnum,
                     devnum);
            fill_synth_chardev(st, node, d);
            rc = 0;
        } else {
            errno = ENODEV;
        }
    }
    pthread_mutex_unlock(&usb_lock);
    return rc;
}
