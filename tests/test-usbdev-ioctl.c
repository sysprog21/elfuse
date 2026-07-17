/*
 * The usbdevfs descriptor's contract, without hardware
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Code under test: src/syscall/usbdev.c, plus the write-family and lseek arms
 * in src/syscall/io.c and src/syscall/fs.c.
 *
 * This lane runs against ELFUSE_USB_FIXTURE, whose devices are modeled but have
 * no IOKit service behind them. That is the whole point: it is exactly the
 * shape of a device the model knows about and the machine cannot reach, so
 * every answer below is deterministic on any host, plugged in or not. What it
 * covers is the half of usbdevfs that is decided before the wire -- the file
 * contract (read, pread, lseek, the write family, fstat, dup), the ioctl gates
 * (FMODE_WRITE, unknown codes), and every argument the kernel validates from
 * the descriptors it already has (interface numbers, endpoint addresses,
 * transfer lengths, and the order those checks run in). The half that needs a
 * device -- a real claim, a real transfer, arbitration against a bound host
 * driver -- cannot be asserted here and is not pretended to be.
 *
 * Where elfuse knowingly answers something other than Linux, the case is
 * printed as an XFAIL carrying both values rather than dropped, so the gap
 * stays visible in the lane's own output.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define NODE "/dev/bus/usb/001/001"

/* Only ELFUSE_USB_FIXTURE=badifnum stands this one up: one interface declaring
 * bInterfaceNumber 200, carrying endpoint 0x81.
 */
#define BAD_IFNUM_NODE "/dev/bus/usb/001/002"

/* The default fixture's second device, on the other bus. A race that leaves the
 * wrong entry answering one fd number is invisible while both entries describe
 * the same device, so the reopen half of the publish-window races opens this
 * one and reads its idVendor back.
 */
#define OTHER_NODE "/dev/bus/usb/002/001"
#define OTHER_VID 0x2109
#define NODE_VID 0x1d6b
#define USB_MAJOR 189

#ifndef RWF_APPEND
#define RWF_APPEND 0x00000010
#endif

/* pwritev2 by hand rather than through the C library: the guest's libc reports
 * EOPNOTSUPP for any failing pwritev2 carrying a nonzero flag, whatever the
 * kernel said, and the assertions below are about what the kernel said. The
 * sixth argument is the high half of the offset, zero on a 64-bit ABI.
 */
static long pwritev2_raw(int fd,
                         const struct iovec *iov,
                         int iovcnt,
                         long offset,
                         int flags)
{
    return syscall(SYS_pwritev2, (long) fd, (long) iov, (long) iovcnt, offset,
                   0L, (long) flags);
}

/* uapi/linux/usbdevice_fs.h, spelled out rather than included: the guest
 * sysroot need not carry the header, and the numbers are part of the contract
 * under test.
 */
#define USBDEVFS_CONTROL 0xc0185500u
#define USBDEVFS_BULK 0xc0185502u
#define USBDEVFS_RESETEP 0x80045503u
#define USBDEVFS_SETINTERFACE 0x80085504u
#define USBDEVFS_SETCONFIGURATION 0x80045505u
#define USBDEVFS_GETDRIVER 0x41045508u
#define USBDEVFS_DISCARDURB 0x0000550bu
#define USBDEVFS_RESET 0x00005514u
#define USBDEVFS_CLEAR_HALT 0x80045515u
#define USBDEVFS_DISCONNECT 0x00005516u
#define USBDEVFS_CONNECT 0x00005517u
#define USBDEVFS_CLAIMINTERFACE 0x8004550fu
#define USBDEVFS_RELEASEINTERFACE 0x80045510u
#define USBDEVFS_CONNECTINFO 0x40085511u
#define USBDEVFS_IOCTL 0xc0105512u
#define USBDEVFS_SUBMITURB 0x8038550au
#define USBDEVFS_GET_CAPABILITIES 0x8004551au
#define USBDEVFS_DISCONNECT_CLAIM 0x8108551bu
#define USBDEVFS_GET_SPEED 0x0000551fu

struct ctrltransfer {
    uint8_t bRequestType, bRequest;
    uint16_t wValue, wIndex, wLength;
    uint32_t timeout;
    void *data;
};

struct bulktransfer {
    unsigned int ep, len, timeout;
    void *data;
};

struct setinterface {
    unsigned int interface, altsetting;
};

struct getdriver {
    unsigned int interface;
    char driver[256];
};

struct usbdevfs_ioctl {
    int ifno, ioctl_code;
    void *data;
};

struct disconnect_claim {
    unsigned int interface, flags;
    char driver[256];
};

/* ioctl(2) collapses every failure onto -1; the assertions below are about
 * which errno, so report it as a negative value the way the kernel does.
 */
static long io(int fd, unsigned long req, void *arg)
{
    int r = ioctl(fd, req, arg);
    return r < 0 ? -errno : r;
}

static void check_open_agrees(void)
{
    printf("test-usbdev-ioctl: the node's three permission answers\n");

    /* One node, three entry points onto "may this guest write it". Stage 1 had
     * no writable open to disagree with; stage 2 does, and a 0664 node owned by
     * a uid the guest does not have made access(W_OK) refuse what open(O_RDWR)
     * then served.
     */
    TEST("access(R_OK) on the node");
    EXPECT_EQ(access(NODE, R_OK), 0, "access R_OK");
    TEST("access(W_OK) on the node");
    EXPECT_EQ(access(NODE, W_OK), 0, "access W_OK");

    int rw = open(NODE, O_RDWR);
    TEST("open(O_RDWR) on the node");
    EXPECT_TRUE(rw >= 0, "open O_RDWR");

    /* The constructor resolves its IOKit device on first use, not at open, so a
     * modeled device with nothing behind it still opens and still reads.
     */
    int ro = open(NODE, O_RDONLY);
    TEST("open(O_RDONLY) on the node");
    EXPECT_TRUE(ro >= 0, "open O_RDONLY");

    unsigned char buf[64];
    ssize_t n = ro >= 0 ? read(ro, buf, sizeof(buf)) : -1;
    TEST("read serves the descriptors blob");
    EXPECT_TRUE(n >= 18 && buf[0] == 18 && buf[1] == 1, "blob device desc");

    struct stat st;
    TEST("fstat reports char 189:minor");
    EXPECT_TRUE(ro >= 0 && fstat(ro, &st) == 0 && S_ISCHR(st.st_mode) &&
                    major(st.st_rdev) == USB_MAJOR && minor(st.st_rdev) == 0,
                "fstat rdev");

    TEST("dup of a usbdevfs fd is EBADF");
    EXPECT_ERRNO(dup(ro), EBADF, "dup");

    if (rw >= 0)
        close(rw);
    if (ro >= 0)
        close(ro);
}

/* Linux: vfs_write checks FMODE_WRITE before FMODE_CAN_WRITE, so an O_RDONLY fd
 * is EBADF and a writable one EINVAL -- from write, writev, pwrite and pwritev
 * alike. Only write() answered that here; the other three reached the readiness
 * pipe behind the fd and reported its EBADF for a writable fd.
 */
static void check_write_family(void)
{
    printf("\ntest-usbdev-ioctl: the write family\n");
    char b[8] = {0};
    struct iovec iov[2] = {{b, 4}, {b + 4, 4}};

    int rw = open(NODE, O_RDWR);
    if (rw < 0) {
        TEST("writable open for the write family");
        FAIL("open O_RDWR");
        return;
    }
    TEST("write on a writable fd is EINVAL");
    EXPECT_ERRNO(write(rw, b, 4), EINVAL, "write");
    TEST("writev on a writable fd is EINVAL");
    EXPECT_ERRNO(writev(rw, iov, 2), EINVAL, "writev");
    TEST("pwrite on a writable fd is EINVAL");
    EXPECT_ERRNO(pwrite(rw, b, 4, 0), EINVAL, "pwrite");
    TEST("pwritev on a writable fd is EINVAL");
    EXPECT_ERRNO(pwritev(rw, iov, 2, 0), EINVAL, "pwritev");
    close(rw);

    int ro = open(NODE, O_RDONLY);
    if (ro < 0) {
        TEST("read-only open for the write family");
        FAIL("open O_RDONLY");
        return;
    }
    TEST("write on a read-only fd is EBADF");
    EXPECT_ERRNO(write(ro, b, 4), EBADF, "write ro");
    TEST("writev on a read-only fd is EBADF");
    EXPECT_ERRNO(writev(ro, iov, 2), EBADF, "writev ro");
    TEST("pwrite on a read-only fd is EBADF");
    EXPECT_ERRNO(pwrite(ro, b, 4, 0), EBADF, "pwrite ro");
    TEST("pwritev on a read-only fd is EBADF");
    EXPECT_ERRNO(pwritev(ro, iov, 2, 0), EBADF, "pwritev ro");

    /* Every ioctl needs FMODE_WRITE (devio.c:2605), and that gate is ahead of
     * everything else, including the device lookup.
     */
    uint32_t caps = 0;
    TEST("an ioctl on a read-only fd is EPERM");
    EXPECT_EQ(io(ro, USBDEVFS_GET_CAPABILITIES, &caps), -EPERM, "ro ioctl");
    close(ro);
}

static void check_seek(void)
{
    printf("\ntest-usbdev-ioctl: the file position\n");
    int fd = open(NODE, O_RDWR);
    if (fd < 0) {
        TEST("open for the seek contract");
        FAIL("open");
        return;
    }
    TEST("SEEK_END is EINVAL");
    EXPECT_ERRNO(lseek(fd, 0, SEEK_END), EINVAL, "SEEK_END");
    TEST("SEEK_SET to INT64_MAX is allowed");
    EXPECT_EQ(lseek(fd, INT64_MAX, SEEK_SET), INT64_MAX, "SEEK_SET max");

    /* One past it is not: the sum used to be computed before the range test,
     * which is signed overflow, and it wrapped to a negative position.
     */
    TEST("one byte past INT64_MAX is EINVAL");
    EXPECT_ERRNO(lseek(fd, 1, SEEK_CUR), EINVAL, "SEEK_CUR overflow");
    TEST("the failed seek left the position alone");
    EXPECT_EQ(lseek(fd, 0, SEEK_CUR), INT64_MAX, "position after EINVAL");

    unsigned char a[8], b[8];
    TEST("pread does not move the position");
    EXPECT_TRUE(pread(fd, a, sizeof(a), 0) == (ssize_t) sizeof(a) &&
                    lseek(fd, 0, SEEK_CUR) == INT64_MAX,
                "pread position");
    TEST("read past the blob is EOF, not an error");
    EXPECT_EQ(read(fd, b, sizeof(b)), 0, "read at INT64_MAX");
    close(fd);
}

/* claimintf refuses ifnum >= 8 * sizeof(unsigned long) -- 64, not 32. Between
 * the two, an interface number is merely absent, which is a question about the
 * device rather than about the argument.
 */
static void check_interface_bound(void)
{
    printf("\ntest-usbdev-ioctl: the interface-number bound\n");
    int fd = open(NODE, O_RDWR);
    if (fd < 0) {
        TEST("open for the interface bound");
        FAIL("open");
        return;
    }
    uint32_t n63 = 63, n64 = 64;
    TEST("CLAIMINTERFACE 64 is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_CLAIMINTERFACE, &n64), -EINVAL, "claim 64");
    TEST("CLAIMINTERFACE 63 is not an argument error");
    EXPECT_EQ(io(fd, USBDEVFS_CLAIMINTERFACE, &n63), -ENODEV, "claim 63");
    TEST("RELEASEINTERFACE 64 is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_RELEASEINTERFACE, &n64), -EINVAL, "release 64");
    TEST("RELEASEINTERFACE 63 is not an argument error");
    EXPECT_EQ(io(fd, USBDEVFS_RELEASEINTERFACE, &n63), -ENODEV, "release 63");

    struct setinterface si = {.interface = 63, .altsetting = 0};
    TEST("SETINTERFACE 63 is not an argument error");
    EXPECT_EQ(io(fd, USBDEVFS_SETINTERFACE, &si), -ENODEV, "setinterface 63");
    si.interface = 64;
    TEST("SETINTERFACE 64 is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_SETINTERFACE, &si), -EINVAL, "setinterface 64");

    /* bAlternateSetting is a byte, so 256 matches no altsetting of any device
     * and usb_set_interface answers EINVAL (usb.c:391, message.c:1548). What
     * the fixture can assert is the order: proc_setintf claims the interface
     * before it validates the altsetting (devio.c:1533-1539), so the claim
     * answers first and a check hoisted above the claim would show up here. The
     * effect of the argument itself needs a device that can be claimed and is
     * asserted against the board, where altsetting 256 used to be narrowed to
     * setting 0 and took effect.
     */
    si.interface = 0;
    si.altsetting = 256;
    TEST("SETINTERFACE reports the claim before the altsetting");
    EXPECT_EQ(io(fd, USBDEVFS_SETINTERFACE, &si), -ENODEV,
              "setinterface alt 256");
    si.interface = 64;
    TEST("an interface past the bound outranks the altsetting");
    EXPECT_EQ(io(fd, USBDEVFS_SETINTERFACE, &si), -EINVAL,
              "setinterface 64/256");

    struct disconnect_claim dc;
    memset(&dc, 0, sizeof(dc));
    dc.interface = 64;
    TEST("DISCONNECT_CLAIM 64 is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_DISCONNECT_CLAIM, &dc), -EINVAL, "dc 64");

    struct usbdevfs_ioctl ic = {
        .ifno = 64, .ioctl_code = (int) USBDEVFS_DISCONNECT, .data = NULL};
    TEST("USBDEVFS_IOCTL ifno 64 is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_IOCTL, &ic), -EINVAL, "usbdevfs_ioctl 64");
    close(fd);
}

/* findintfep rejects a malformed endpoint address before it looks at anything,
 * and do_proc_bulk resolves the endpoint before it looks at the length. Both
 * orderings are observable, and both were the other way round: a length error
 * outranked an absent endpoint, and two of the four entry points onto the
 * endpoint lookup had no reserved-bit test of their own.
 */
static void check_endpoint_arguments(void)
{
    printf("\ntest-usbdev-ioctl: endpoint addresses and check order\n");
    int fd = open(NODE, O_RDWR);
    if (fd < 0) {
        TEST("open for the endpoint arguments");
        FAIL("open");
        return;
    }
    char scratch[64];
    struct bulktransfer bt = {
        .ep = 0x05, .len = 32u * 1024 * 1024, .timeout = 10, .data = scratch};
    TEST("BULK on an absent ep outranks a too-large length");
    EXPECT_EQ(io(fd, USBDEVFS_BULK, &bt), -ENOENT, "bulk absent ep 32M");
    bt.len = 0x7fffffffu;
    TEST("BULK on an absent ep outranks a malformed length");
    EXPECT_EQ(io(fd, USBDEVFS_BULK, &bt), -ENOENT, "bulk absent ep INT_MAX");
    bt.len = 8;
    TEST("BULK on an absent ep is ENOENT");
    EXPECT_EQ(io(fd, USBDEVFS_BULK, &bt), -ENOENT, "bulk absent ep");
    bt.ep = 0x30;
    TEST("BULK on a reserved-bit ep is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_BULK, &bt), -EINVAL, "bulk reserved ep");

    uint32_t ep = 0x30;
    TEST("CLEAR_HALT on a reserved-bit ep is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_CLEAR_HALT, &ep), -EINVAL, "clear_halt 0x30");
    TEST("RESETEP on a reserved-bit ep is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_RESETEP, &ep), -EINVAL, "resetep 0x30");
    ep = 0x05;
    TEST("CLEAR_HALT on an absent ep is ENOENT");
    EXPECT_EQ(io(fd, USBDEVFS_CLEAR_HALT, &ep), -ENOENT, "clear_halt 0x05");

    /* findintfep tests the caller's whole unsigned int, not its low byte
     * (devio.c:860), and CLEAR_HALT, RESETEP and BULK all carry a 32-bit
     * endpoint word. Narrowed to a byte before the test, 0x183 became 0x83 and
     * 0x181 became the fixture device's own 0x81, so the lookup answered about
     * an endpoint the caller had not named -- and on hardware the stall clear
     * reached it.
     */
    ep = 0x183;
    TEST("CLEAR_HALT above the address byte is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_CLEAR_HALT, &ep), -EINVAL, "clear_halt 0x183");
    ep = 0x01000083;
    TEST("RESETEP with high bits set is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_RESETEP, &ep), -EINVAL, "resetep 0x01000083");
    bt.ep = 0x181;
    bt.len = 8;
    TEST("BULK above the address byte is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_BULK, &bt), -EINVAL, "bulk 0x181");

    struct ctrltransfer ct = {.bRequestType = 0x82, /* IN, standard, endpoint */
                              .bRequest = 0,
                              .wValue = 0,
                              .wIndex = 0x05,
                              .wLength = 8192,
                              .timeout = 10,
                              .data = scratch};
    TEST("CONTROL recipient check outranks the wLength cap");
    EXPECT_EQ(io(fd, USBDEVFS_CONTROL, &ct), -ENOENT, "control absent ep");
    ct.wIndex = 0x30;
    ct.wLength = 8;
    TEST("CONTROL on a reserved-bit ep is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_CONTROL, &ct), -EINVAL, "control reserved ep");

    /* The wider test must not spread to the control path: check_ctrlrecip masks
     * wIndex to its low byte before findintfep ever sees it (devio.c:904), so
     * 0x0181 still names endpoint 0x81 and still resolves to its interface,
     * which without a device behind it is -ENODEV rather than -EINVAL.
     */
    ct.bRequestType = 0x82;
    ct.wIndex = 0x0181;
    ct.wLength = 8;
    TEST("CONTROL folds wIndex to its low byte");
    EXPECT_EQ(io(fd, USBDEVFS_CONTROL, &ct), -ENODEV, "control wIndex 0x181");

    /* The cap itself still applies once the recipient is not the question. */
    ct.bRequestType = 0x80; /* IN, standard, device */
    ct.wIndex = 0;
    ct.wLength = 8192;
    TEST("CONTROL over 4096 bytes is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_CONTROL, &ct), -EINVAL, "control wLength");
    close(fd);
}

/* The two orderings the positional and vector write paths owe Linux, both of
 * them ahead of anything this descriptor has to say about itself:
 *
 *   ksys_pwrite64 and do_pwritev test pos < 0 before they look the descriptor
 *   up (read_write.c), so a negative offset is EINVAL even on a descriptor that
 *   owes EBADF for having no write op. usbdev_pread already ordered the two
 *   this way and the write side did not.
 *
 *   vfs_readv and vfs_writev test FMODE_READ/FMODE_WRITE, then FMODE_CAN_*,
 *   before an empty vector returns 0 (read_write.c), so direction still
 *   decides. An empty vector used to return 0 on this fd for every direction,
 *   and pwritev2(RWF_APPEND) had no dispatch at all: it reached the readiness
 *   pipe and answered for that instead.
 */
static void check_offset_and_vector_edges(void)
{
    printf("\ntest-usbdev-ioctl: negative offsets and empty vectors\n");
    int ro = open(NODE, O_RDONLY);
    int rw = open(NODE, O_RDWR);
    int wo = open(NODE, O_WRONLY);
    if (ro < 0 || rw < 0 || wo < 0) {
        TEST("three opens for the offset and vector edges");
        FAIL("open");
        goto out;
    }

    char b[8] = {0};
    struct iovec iov = {b, sizeof(b)};

    TEST("pwrite at a negative offset is EINVAL");
    EXPECT_ERRNO(pwrite(ro, b, 4, -1), EINVAL, "pwrite -1");
    TEST("pwritev at a negative offset is EINVAL");
    EXPECT_ERRNO(pwritev(ro, &iov, 1, -1), EINVAL, "pwritev -1");

    TEST("readv of nothing on a write-only fd is EBADF");
    EXPECT_ERRNO(readv(wo, &iov, 0), EBADF, "readv 0");
    TEST("preadv of nothing on a write-only fd is EBADF");
    EXPECT_ERRNO(preadv(wo, &iov, 0, 0), EBADF, "preadv 0");
    TEST("readv of nothing on a readable fd is 0");
    EXPECT_EQ(readv(ro, &iov, 0), 0, "readv 0 ro");

    TEST("pwritev2 of nothing on a read-only fd is EBADF");
    EXPECT_ERRNO(pwritev2_raw(ro, &iov, 0, 0, 0), EBADF, "pwritev2 0 ro");
    TEST("pwritev2 of nothing on a writable fd is EINVAL");
    EXPECT_ERRNO(pwritev2_raw(rw, &iov, 0, 0, 0), EINVAL, "pwritev2 0 rw");
    TEST("pwritev2(RWF_APPEND) on a writable fd is EINVAL");
    EXPECT_ERRNO(pwritev2_raw(rw, &iov, 1, -1, RWF_APPEND), EINVAL,
                 "pwritev2 append rw");
    TEST("pwritev2(RWF_APPEND) on a read-only fd is EBADF");
    EXPECT_ERRNO(pwritev2_raw(ro, &iov, 1, -1, RWF_APPEND), EBADF,
                 "pwritev2 append ro");

out:
    if (ro >= 0)
        close(ro);
    if (rw >= 0)
        close(rw);
    if (wo >= 0)
        close(wo);
}

/* An endpoint whose owning interface number is one this layer cannot hold.
 *
 * bInterfaceNumber is a device-supplied byte with the whole 0..255 range behind
 * it, and the endpoint lookup uses it to index a 64-entry array, so a device
 * declaring 200 read 191 entries past the end -- device-controlled input, and
 * unreachable from any attached device, which is why it needs a fixture that
 * emits one. checkintf refuses exactly this number for exactly this reason
 * (devio.c:842), so EINVAL is the answer both before and after the bound: what
 * changes is that nothing reads out of bounds first, which is visible under
 * -fsanitize=array-bounds and nowhere else.
 */
static void check_malformed_interface_number(void)
{
    printf("\ntest-usbdev-ioctl: an interface number the table cannot hold\n");
    int fd = open(BAD_IFNUM_NODE, O_RDWR);
    if (fd < 0) {
        TEST("open of the malformed-descriptor node");
        FAIL("open");
        return;
    }

    /* Assert the fixture carries what this is about, so the lane cannot go
     * quietly vacuous if the mode ever stops emitting it. Device descriptor 18
     * bytes, configuration header 9, then the interface descriptor.
     */
    unsigned char blob[64];
    ssize_t n = read(fd, blob, sizeof(blob));
    TEST("the fixture declares bInterfaceNumber 200");
    EXPECT_TRUE(n >= 27 + 9 && blob[27 + 1] == 0x04 && blob[27 + 2] == 200,
                "fixture interface number");
    TEST("the fixture carries that interface's endpoint");
    EXPECT_TRUE(n >= 36 + 7 && blob[36 + 1] == 0x05 && blob[36 + 2] == 0x81,
                "fixture endpoint");

    uint32_t ep = 0x81;
    TEST("CLEAR_HALT on an ep owned by interface 200 is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_CLEAR_HALT, &ep), -EINVAL, "clear_halt owner");
    TEST("RESETEP on an ep owned by interface 200 is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_RESETEP, &ep), -EINVAL, "resetep owner");

    char scratch[64];
    struct bulktransfer bt = {
        .ep = 0x81, .len = 8, .timeout = 10, .data = scratch};
    TEST("BULK on an ep owned by interface 200 is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_BULK, &bt), -EINVAL, "bulk owner");

    struct ctrltransfer ct = {.bRequestType = 0x82, /* IN, standard, endpoint */
                              .bRequest = 0,
                              .wValue = 0,
                              .wIndex = 0x81,
                              .wLength = 8,
                              .timeout = 10,
                              .data = scratch};
    TEST("CONTROL to an ep owned by interface 200 is EINVAL");
    EXPECT_EQ(io(fd, USBDEVFS_CONTROL, &ct), -EINVAL, "control owner");

    /* An endpoint no interface carries is still merely absent. */
    ep = 0x82;
    TEST("an ep no interface carries is still ENOENT");
    EXPECT_EQ(io(fd, USBDEVFS_CLEAR_HALT, &ep), -ENOENT, "clear_halt absent");
    close(fd);
}

/* Each open-time failure keeps its own errno. ENODEV -- nothing answers to this
 * address -- is the one that becomes the ENOENT open(2) owes for a name with
 * nothing behind it; a resource failure reported as ENOENT told the guest a
 * node was missing when the host had merely run out of something.
 */
static void check_open_failure_errno(const char *stage)
{
    printf("\ntest-usbdev-ioctl: a failed open reports what failed (%s)\n",
           stage);
    int want = strcmp(stage, "pipe") == 0 ? ENFILE : ENOMEM;
    TEST("the failure keeps its own errno");
    EXPECT_ERRNO(open(NODE, O_RDWR), want, stage);
}

/* How many fds the side table can hold at once, measured by filling it. */
static int count_table_slots(void)
{
    enum { CAP = 64 };
    int fds[CAP];
    int n = 0;
    for (; n < CAP; n++) {
        fds[n] = open(NODE, O_RDWR);
        if (fds[n] < 0)
            break;
    }
    for (int i = 0; i < n; i++)
        close(fds[i]);
    return n;
}

static int race_fd = -1;
static int race_sibling = -1;
static const char *race_reopen_node;

static void *race_closer(void *unused)
{
    (void) unused;
    usleep(4000);
    close(race_fd);
    if (race_reopen_node)
        race_sibling = open(race_reopen_node, O_RDWR);
    return NULL;
}

/* idVendor from the descriptors blob the fd serves (device descriptor bytes
 * 8..9, little endian). Which device an fd is bound to is the only thing that
 * tells two live entries apart, so the races read it rather than counting.
 */
static int fd_vid(int fd)
{
    unsigned char d[18];
    if (fd < 0 || pread(fd, d, sizeof(d), 0) != (ssize_t) sizeof(d))
        return -1;
    return d[8] | (d[9] << 8);
}

/* A close that lands between fd_alloc publishing the guest fd and the side
 * table binding it. The teardown hook matches on the fd number, which is still
 * unbound inside that window, so the close found no entry, tore nothing down,
 * and the slot, its descriptor blob and the write end of its pipe stayed held
 * for the life of the process. Counted rather than observed directly: the table
 * is fixed, so a leaked slot is one fewer simultaneous open.
 *
 * The window is a few instructions wide unaided, so this runs under
 * ELFUSE_USBDEV_PUBLISH_DELAY_US. The fd number the closer aims at is the one
 * the next open must take: the lowest free number, which is the one a probe
 * open just gave back.
 */
static void check_publish_race(void)
{
    printf("\ntest-usbdev-ioctl: a close inside the publish window\n");
    int before = count_table_slots();
    int rounds = 0;
    for (int i = 0; i < 4; i++) {
        int probe = open(NODE, O_RDWR);
        if (probe < 0)
            break;
        race_fd = probe;
        close(probe);
        pthread_t t;
        if (pthread_create(&t, NULL, race_closer, NULL) != 0)
            break;
        int fd = open(NODE, O_RDWR);
        pthread_join(t, NULL);
        if (fd >= 0)
            close(fd);
        rounds++;
    }
    int after = count_table_slots();
    TEST("the table held slots to race for");
    EXPECT_TRUE(before > 1 && rounds == 4, "race preconditions");
    TEST("a close inside the publish window leaks no slot");
    EXPECT_EQ(after, before, "slots after the race");
    printf("  slots: %d before, %d after %d rounds\n", before, after, rounds);
}

/* The same window, with the close followed by a reopen of the number it freed.
 *
 * The generation this open publishes has to be the one fd_alloc stamped for it.
 * Re-derived from the fd table after the slot was already publishable, it was
 * whatever the number carried by then -- and inside this window that is the
 * reopening thread's stamp. Two entries then held the identical {guest_fd,
 * generation}, so the guard that retires an unbound entry compared equal and
 * retired nothing, and usbdev_acquire, which matches on that same pair,
 * answered from whichever sat at the lower index. Both consequences are
 * asserted: the fd reads the device it was actually opened on, and the entry
 * that lost the number gives its slot back.
 *
 * The reopen deliberately names the other bus, because two entries describing
 * one device are indistinguishable by anything the guest can read.
 */
static void check_publish_window_reopen(void)
{
    printf(
        "\ntest-usbdev-ioctl: a close and reopen inside the publish window\n");
    int before = count_table_slots();
    int probe = open(NODE, O_RDWR);
    if (probe < 0) {
        TEST("probe open for the reopen race");
        FAIL("open");
        return;
    }
    race_fd = probe;
    race_sibling = -1;
    race_reopen_node = OTHER_NODE;
    close(probe);

    pthread_t t;
    if (pthread_create(&t, NULL, race_closer, NULL) != 0) {
        TEST("closer thread for the reopen race");
        FAIL("pthread_create");
        return;
    }
    int fd = open(NODE, O_RDWR);
    pthread_join(t, NULL);
    race_reopen_node = NULL;

    int sib = race_sibling;
    TEST("the reopen took the number the close freed");
    EXPECT_TRUE(fd >= 0 && sib == fd, "same fd number");

    /* The reopener owns the number now, so the entry that answers to it must be
     * the one it opened -- the other bus's device, not this one's.
     */
    TEST("the fd answers for the device it was reopened on");
    EXPECT_EQ(fd_vid(sib), OTHER_VID, "idVendor");

    if (sib >= 0)
        close(sib);
    if (fd >= 0 && fd != sib)
        close(fd);
    int after = count_table_slots();
    TEST("the entry that lost the number gives its slot back");
    EXPECT_EQ(after, before, "slots after the race");
    printf("  slots: %d before, %d after\n", before, after);
}

/* The window on the other side of the bind: the entry is findable, so the close
 * reaps it and usbdev_unref frees the slot, and a sibling open can take that
 * same slot and bind its own live fd before this open's recheck runs.
 *
 * The recheck then sees a generation that has moved and retires -- and claiming
 * the entry on "not dead" alone claimed the sibling's, marked it dead, freed
 * its descriptor blob and closed its pipe. The sibling's fd was never closed
 * and answered EBADF on every read and ioctl from then on. Nothing about the
 * slot's contents can distinguish the two allocations; only the tuple the
 * caller allocated can, which is what the retire path now claims on.
 */
static void check_retire_window_race(void)
{
    printf("\ntest-usbdev-ioctl: a close and reopen after the bind\n");
    int before = count_table_slots();
    int probe = open(NODE, O_RDWR);
    if (probe < 0) {
        TEST("probe open for the retire race");
        FAIL("open");
        return;
    }
    race_fd = probe;
    race_sibling = -1;
    race_reopen_node = NODE;
    close(probe);

    pthread_t t;
    if (pthread_create(&t, NULL, race_closer, NULL) != 0) {
        TEST("closer thread for the retire race");
        FAIL("pthread_create");
        return;
    }
    int fd = open(NODE, O_RDWR);
    pthread_join(t, NULL);
    race_reopen_node = NULL;

    int sib = race_sibling;
    TEST("the reopen took the number the close freed");
    EXPECT_TRUE(fd >= 0 && sib == fd, "same fd number");

    /* Both assertions are about the sibling's fd, which was never closed. */
    unsigned char d[18];
    TEST("the reopened fd still reads its descriptors");
    EXPECT_TRUE(sib >= 0 && pread(sib, d, sizeof(d), 0) == (ssize_t) sizeof(d),
                "pread on the live sibling");
    TEST("the reopened fd still answers its ioctls");
    EXPECT_EQ(io(sib, USBDEVFS_GET_SPEED, NULL), 2, "get_speed"); /* FULL */

    if (sib >= 0)
        close(sib);
    if (fd >= 0 && fd != sib)
        close(fd);
    int after = count_table_slots();
    TEST("neither entry leaks its slot");
    EXPECT_EQ(after, before, "slots after the race");
    printf("  slots: %d before, %d after\n", before, after);
}

static void check_answers_without_a_device(void)
{
    printf("\ntest-usbdev-ioctl: what is answered from the model\n");
    int fd = open(NODE, O_RDWR);
    if (fd < 0) {
        TEST("open for the model-served ioctls");
        FAIL("open");
        return;
    }

    /* Every capability bit names part of the URB machinery this stage answers
     * ENOTTY for, so the word is 0 until that machinery lands.
     */
    uint32_t caps = 0xffffffffu;
    TEST("GET_CAPABILITIES reports no URB capabilities");
    EXPECT_TRUE(io(fd, USBDEVFS_GET_CAPABILITIES, &caps) == 0 && caps == 0,
                "caps");

    size_t lazy_len = 8UL << 20;
    uint8_t *lazy = mmap(NULL, lazy_len, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST("ioctl and pread into untouched mappings");
    if (lazy == MAP_FAILED) {
        FAIL("lazy mmap");
    } else {
        uint32_t *lazy_caps = (uint32_t *) (lazy + (2UL << 20));
        EXPECT_TRUE(io(fd, USBDEVFS_GET_CAPABILITIES, lazy_caps) == 0 &&
                        *lazy_caps == 0 &&
                        pread(fd, lazy + (4UL << 20), 18, 0) == 18,
                    "lazy USB output failed");
        munmap(lazy, lazy_len);
    }

    TEST("GET_SPEED returns the enum as its value");
    EXPECT_EQ(io(fd, USBDEVFS_GET_SPEED, NULL), 2, "get_speed"); /* FULL */

    struct {
        uint32_t devnum;
        uint32_t slow;
    } ci = {0, 0};
    TEST("CONNECTINFO reports the devnum");
    EXPECT_TRUE(io(fd, USBDEVFS_CONNECTINFO, &ci) == 0 && ci.devnum == 1 &&
                    ci.slow == 0,
                "connectinfo");

    TEST("an unknown ioctl is ENOTTY");
    EXPECT_EQ(io(fd, 0x00005563u /* _IO('U', 99) */, NULL), -ENOTTY,
              "unknown ioctl");
    TEST("SUBMITURB is ENOTTY at this stage");
    EXPECT_EQ(io(fd, USBDEVFS_SUBMITURB, NULL), -ENOTTY, "submiturb");
    TEST("DISCARDURB is ENOTTY at this stage");
    EXPECT_EQ(io(fd, USBDEVFS_DISCARDURB, NULL), -ENOTTY, "discardurb");

    /* Everything that has to reach the wire says so, with the errno Linux uses
     * for a device that is not there.
     */
    struct getdriver gd;
    memset(&gd, 0, sizeof(gd));
    TEST("GETDRIVER without a device is ENODEV");
    EXPECT_EQ(io(fd, USBDEVFS_GETDRIVER, &gd), -ENODEV, "getdriver");

    uint32_t cfg = 1;
    TEST("SETCONFIGURATION without a device is ENODEV");
    EXPECT_EQ(io(fd, USBDEVFS_SETCONFIGURATION, &cfg), -ENODEV, "setconfig");

    struct disconnect_claim dc;
    memset(&dc, 0, sizeof(dc));
    TEST("DISCONNECT_CLAIM without a device is ENODEV");
    EXPECT_EQ(io(fd, USBDEVFS_DISCONNECT_CLAIM, &dc), -ENODEV, "dc");

    struct usbdevfs_ioctl ic = {
        .ifno = 0, .ioctl_code = (int) USBDEVFS_CONNECT, .data = NULL};
    TEST("USBDEVFS_IOCTL CONNECT without a device is ENODEV");
    EXPECT_EQ(io(fd, USBDEVFS_IOCTL, &ic), -ENODEV, "connect");
    close(fd);
}

/* FIONBIO and FIOASYNC never reach a file's own ioctl handler on Linux:
 * do_vfs_ioctl answers both for every file before it calls f_op->unlocked_ioctl
 * (fs/ioctl.c:818-822), so they also never meet usbdevfs's FMODE_WRITE gate.
 * Sent into it here they came back EPERM on a read-only fd and ENOTTY on a
 * writable one, while fcntl(F_SETFL) on the same descriptor set O_NONBLOCK and
 * F_GETFL reported it: two entry points onto one flag, disagreeing about it.
 *
 * Measured on Linux (gcc:14, a char device and a plain file, access modes 0, 1,
 * 2 and 3): FIONBIO(1) is 0 and sets O_NONBLOCK in every one of them;
 * FIOASYNC(1) is ENOTTY and FIOASYNC(0) is 0, because ioctl_fioasync only
 * consults f_op->fasync when the request would change the FASYNC state and
 * usbdev_file_operations declares none (devio.c:2846-2856).
 */
static void check_vfs_ioctls(void)
{
    printf("\ntest-usbdev-ioctl: the two ioctls the vfs answers first\n");
    const int modes[2] = {O_RDONLY, O_RDWR};
    const char *names[2] = {"read-only", "writable"};
    for (int i = 0; i < 2; i++) {
        int fd = open(NODE, modes[i]);
        if (fd < 0) {
            TEST("open for the vfs ioctls");
            FAIL("open");
            return;
        }
        int one = 1, zero = 0;
        char t[64];

        /* The access mode must not be consulted: the kernel has already
         * answered by the time the file's own gate would run.
         */
        snprintf(t, sizeof(t), "FIONBIO on a %s fd is 0", names[i]);
        TEST(t);
        EXPECT_EQ(io(fd, FIONBIO, &one), 0, "fionbio");
        snprintf(t, sizeof(t), "and O_NONBLOCK is set on the %s fd", names[i]);
        TEST(t);
        EXPECT_TRUE((fcntl(fd, F_GETFL) & O_NONBLOCK) != 0, "F_GETFL");

        /* The other entry point onto the same flag has to agree with it. */
        snprintf(t, sizeof(t), "FIONBIO(0) clears it on the %s fd", names[i]);
        TEST(t);
        EXPECT_TRUE(io(fd, FIONBIO, &zero) == 0 &&
                        (fcntl(fd, F_GETFL) & O_NONBLOCK) == 0,
                    "fionbio 0");
        snprintf(t, sizeof(t), "F_SETFL then agrees on the %s fd", names[i]);
        TEST(t);
        EXPECT_TRUE(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0 &&
                        (fcntl(fd, F_GETFL) & O_NONBLOCK) != 0,
                    "F_SETFL");

        /* No .fasync, so arming is refused and asking for the state it already
         * has is granted. It must not reach the O_ASYNC arm in sys_ioctl, which
         * would arm a SIGIO watcher the kernel refuses to arm.
         */
        snprintf(t, sizeof(t), "FIOASYNC(1) on a %s fd is ENOTTY", names[i]);
        TEST(t);
        EXPECT_EQ(io(fd, FIOASYNC, &one), -ENOTTY, "fioasync 1");
        snprintf(t, sizeof(t), "FIOASYNC(0) on a %s fd is 0", names[i]);
        TEST(t);
        EXPECT_EQ(io(fd, FIOASYNC, &zero), 0, "fioasync 0");
        close(fd);
    }

    /* get_user runs first in both kernel helpers, so a bad argument pointer
     * outranks every other answer, the access mode included.
     */
    int fd = open(NODE, O_RDONLY);
    if (fd >= 0) {
        TEST("FIONBIO with a bad argument is EFAULT");
        EXPECT_EQ(io(fd, FIONBIO, (void *) 8), -EFAULT, "fionbio efault");
        TEST("FIOASYNC with a bad argument is EFAULT");
        EXPECT_EQ(io(fd, FIOASYNC, (void *) 8), -EFAULT, "fioasync efault");
        close(fd);
    }
}

/* Every gate on this descriptor derives its capability bits the way OPEN_FMODE
 * does, or none of them do.
 *
 * OPEN_FMODE (fs.h:3631) is (flags + 1) & O_ACCMODE: access modes 0, 1 and 2
 * give FMODE_READ, FMODE_WRITE and both, and access mode 3 gives neither. Mode
 * 3 is reachable -- open(2) takes it and ACC_MODE(3) asks this 0666 node for
 * read plus write, which it grants -- so Linux hands back a descriptor that can
 * do nothing. Measured on Linux for a char device and a plain file: the open
 * succeeds and read, pread and write are all EBADF.
 *
 * Each gate here tested the access mode against O_RDONLY or O_WRONLY on its
 * own, so all four agreed on modes 0, 1 and 2 and all four were wrong on mode
 * 3: the fd read the descriptors blob and was handed the whole ioctl set.
 */
static void check_access_mode_three(void)
{
    printf("\ntest-usbdev-ioctl: an access mode with neither capability\n");
    int fd = open(NODE, 3);
    TEST("open with access mode 3 succeeds");
    EXPECT_TRUE(fd >= 0, "open");
    if (fd < 0)
        return;

    char b[8] = {0};
    struct iovec empty = {b, 0};
    TEST("read on it is EBADF");
    EXPECT_ERRNO(read(fd, b, 4), EBADF, "read");
    TEST("pread on it is EBADF");
    EXPECT_ERRNO(pread(fd, b, 4, 0), EBADF, "pread");
    TEST("an empty readv on it is EBADF");
    EXPECT_ERRNO(readv(fd, &empty, 1), EBADF, "readv");
    TEST("write on it is EBADF, not EINVAL");
    EXPECT_ERRNO(write(fd, b, 4), EBADF, "write");
    TEST("pwrite on it is EBADF, not EINVAL");
    EXPECT_ERRNO(pwrite(fd, b, 4, 0), EBADF, "pwrite");
    TEST("an empty writev on it is EBADF");
    EXPECT_ERRNO(writev(fd, &empty, 1), EBADF, "writev");

    struct {
        uint32_t devnum;
        uint32_t slow;
    } ci = {0, 0};
    TEST("an ioctl on it is EPERM");
    EXPECT_EQ(io(fd, USBDEVFS_CONNECTINFO, &ci), -EPERM, "connectinfo");

    /* The two the vfs answers before the gate are unaffected by it. */
    int one = 1;
    TEST("FIONBIO on it is still 0");
    EXPECT_EQ(io(fd, FIONBIO, &one), 0, "fionbio");
    close(fd);
}

/* usbfs_memory_mb is one allowance for every transfer in flight, not a per-call
 * size cap.
 *
 * usbfs_increase_memory_usage charges len + sizeof(struct urb) against a
 * module-global total and usbfs_decrease_memory_usage gives it back when the
 * transfer settles (devio.c:145-178, charged at devio.c:1308). Read as a
 * per-call ceiling it got both halves wrong: a single request of exactly the
 * allowance was accepted, where Linux always refuses it because the URB itself
 * is charged too, and nothing accumulated across calls or across fds at all --
 * measured before the counter, 32 threads each asking for 16 MB on its own fd:
 * 32 accepted, none refused, and 32 refused and none accepted after.
 *
 * The three assertions below pin what one thread can decide on its own: the
 * boundary a per-call cap gets wrong, and the two exits that owe the allowance
 * back. Whether the sum across concurrent fds is bounded is the same counter
 * seen from outside, and it needs overlapping transfers to observe, so it stays
 * a measurement rather than a lane assertion.
 *
 * The device this needs is one whose interface can actually be claimed, which
 * the service-less fixture has none of: the claim answers ENODEV and the length
 * checks are never reached. So this runs where there is one -- the loopback
 * model, and hardware -- and says so when there is not.
 */
#define ALLOWANCE (16u * 1024 * 1024)
#define LOOPBACK_NODE "/dev/bus/usb/003/001"
#define LOOPBACK_IFNUM 2
#define LOOPBACK_EP_OUT 0x02

static long bulk_of(int fd, unsigned int len, void *data)
{
    struct bulktransfer bt = {
        .ep = LOOPBACK_EP_OUT, .len = len, .timeout = 20000, .data = data};
    return io(fd, USBDEVFS_BULK, &bt);
}

static void check_transfer_allowance(void)
{
    printf("\ntest-usbdev-ioctl: the in-flight transfer allowance\n");
    int fd = open(LOOPBACK_NODE, O_RDWR);
    if (fd < 0) {
        printf(
            "  no claimable device in this model, so the allowance is not\n"
            "  reachable here: the claim answers ENODEV before any length is\n"
            "  looked at. Covered by the loopback lane and on hardware.\n");
        return;
    }
    unsigned int ifn = LOOPBACK_IFNUM;
    if (io(fd, USBDEVFS_CLAIMINTERFACE, &ifn) != 0) {
        TEST("claim for the allowance checks");
        FAIL("claiminterface");
        close(fd);
        return;
    }
    void *big = malloc(ALLOWANCE);
    if (!big) {
        TEST("buffer for the allowance checks");
        FAIL("malloc");
        close(fd);
        return;
    }
    memset(big, 0xa5, ALLOWANCE);

    /* The URB is charged alongside the buffer, so the whole allowance never
     * fits. A per-call size cap accepted this.
     */
    TEST("a transfer of the whole allowance is ENOMEM");
    EXPECT_EQ(bulk_of(fd, ALLOWANCE, big), -ENOMEM, "len == allowance");

    /* Just under it must still go through, twice: the second is the one that
     * proves the first gave its charge back.
     */
    unsigned int under = ALLOWANCE - 4096;
    TEST("a transfer just under it is accepted");
    EXPECT_EQ(bulk_of(fd, under, big), (long) under, "len just under");
    TEST("and again, so the allowance came back");
    EXPECT_EQ(bulk_of(fd, under, big), (long) under, "second transfer");

    /* The error arms owe it back too. A bad buffer fails after the charge is
     * taken, so a leak here is invisible until the next large transfer.
     */
    TEST("a faulting transfer is EFAULT");
    EXPECT_EQ(bulk_of(fd, under, (void *) 8), -EFAULT, "bad buffer");
    TEST("and the allowance came back from that too");
    EXPECT_EQ(bulk_of(fd, under, big), (long) under, "after the fault");

    free(big);
    close(fd);
}

/* The side table is fixed and Linux's is not, so exhaustion is a deviation.
 * Assert the two things that are still contract: the limit reports a
 * kernel-side shortfall rather than the guest's own fd limit, and a closed fd
 * gives its slot back.
 */
static void check_table_exhaustion(void)
{
    printf("\ntest-usbdev-ioctl: the side table's own limit\n");
    enum { CAP = 64 };
    int fds[CAP];
    int n = 0, err = 0;
    for (; n < CAP; n++) {
        fds[n] = open(NODE, O_RDWR);
        if (fds[n] < 0) {
            err = errno;
            break;
        }
    }
    TEST("simultaneous opens hit a bounded limit");
    EXPECT_TRUE(n > 0 && n < CAP, "table limit reached");
    TEST("exhaustion is ENOMEM, not the guest's EMFILE");
    EXPECT_EQ(err, ENOMEM, "exhaustion errno");

    int reclaimed = -1;
    if (n > 0) {
        close(fds[0]);
        reclaimed = open(NODE, O_RDWR);
        fds[0] = reclaimed;
    }
    TEST("a closed fd gives its table slot back");
    EXPECT_TRUE(reclaimed >= 0, "slot reclaimed");
    for (int i = 0; i < n; i++)
        if (fds[i] >= 0)
            close(fds[i]);
    printf("  XFAIL open-limit: Linux unbounded, elfuse %d simultaneous\n", n);
}

/* The teardown hook is handed a bare fd number, and by the time it runs the
 * fd-table slot is already free, so a sibling thread's open can be holding the
 * same number with a second, live entry. Matching on the number alone tore down
 * whichever entry sat lower in the table, about half the time the live one, and
 * the thread that had just opened it saw EBADF.
 */
#define CHURN_THREADS 4
#define CHURN_ROUNDS 2000

static int churn_bad;

static void *churn(void *unused)
{
    (void) unused;
    unsigned char buf[18];
    for (int i = 0; i < CHURN_ROUNDS; i++) {
        int fd = open(NODE, O_RDWR);
        if (fd < 0)
            continue; /* table full for a moment; not what is under test */
        if (read(fd, buf, sizeof(buf)) < 0)
            __atomic_fetch_add(&churn_bad, 1, __ATOMIC_RELAXED);
        close(fd);
    }
    return NULL;
}

static void check_close_identity(void)
{
    printf("\ntest-usbdev-ioctl: close tears down the entry it named\n");
    pthread_t t[CHURN_THREADS];
    int started = 0;
    for (int i = 0; i < CHURN_THREADS; i++)
        if (pthread_create(&t[i], NULL, churn, NULL) == 0)
            started++;
    for (int i = 0; i < started; i++)
        pthread_join(t[i], NULL);
    TEST("a freshly opened fd is never torn down");
    EXPECT_TRUE(started == CHURN_THREADS && churn_bad == 0, "churn EBADF");
    printf("  churn: %d threads x %d rounds, %d fds lost\n", started,
           CHURN_ROUNDS, churn_bad);
}

/* Deviations this stage keeps deliberately: printed with both values so the gap
 * is in the lane's output rather than only in the commit message.
 */
static void print_known_gaps(void)
{
    printf("\ntest-usbdev-ioctl: recorded gaps\n");
    int fd = open(NODE, O_RDWR);
    if (fd >= 0) {
        long r = io(fd, USBDEVFS_RESET, NULL);
        printf(
            "  XFAIL reset: Linux re-enumerates the port, elfuse clears "
            "claimed pipes' stalls and returns %ld\n",
            r);
        long speed = io(fd, USBDEVFS_GET_SPEED, NULL);
        printf(
            "  XFAIL disconnect-gate: Linux answers ENODEV for every ioctl "
            "once the device is gone, elfuse still serves GET_SPEED, "
            "CONNECTINFO, GET_CAPABILITIES and read() from the open-time "
            "model (GET_SPEED here: %ld)\n",
            speed);
        close(fd);
    }
    printf(
        "  XFAIL driver-name: Linux GETDRIVER reports the driver's name "
        "(cdc_acm), elfuse reports the IOKit class (AppleUSBACMControl), and "
        "DISCONNECT_CLAIM's name filters compare against it\n");
    printf(
        "  XFAIL short-bulk-out: Linux reports the byte count actually sent, "
        "elfuse has no length from WritePipeTO and reports EIO\n");
}

int main(void)
{
    printf("test-usbdev-ioctl: the usbdevfs fd contract without hardware\n\n");

    /* Every expectation below is written against the model ELFUSE_USB_FIXTURE
     * supplies, which is what makes the answers the same on any host. Run
     * without it the layer enumerates whatever is plugged in, the node is a
     * real device rather than the modeled one, and the checks that ask the
     * model a question disagree for a reason that has nothing to do with what
     * they test. Say the precondition once rather than eight times in the voice
     * of a defect.
     */
    const char *mode = getenv("ELFUSE_USB_FIXTURE");
    if (!mode) {
        printf(
            "  this lane is written against ELFUSE_USB_FIXTURE=1, which\n"
            "  make check sets. Without it the answers come from whatever\n"
            "  is attached. Nothing below was run.\n");
        return 1;
    }

    /* Five runs of this binary force one failure or one window each, and each
     * asserts only what its knob is about: everything else below describes a
     * healthy open on the default model and would be measuring the knob.
     */
    const char *fault = getenv("ELFUSE_USBDEV_OPEN_FAULT");
    if (fault) {
        check_open_failure_errno(fault);
        SUMMARY("test-usbdev-ioctl");
        return fails > 0 ? 1 : 0;
    }
    if (getenv("ELFUSE_USBDEV_PUBLISH_DELAY_US")) {
        check_publish_race();
        check_publish_window_reopen();
        SUMMARY("test-usbdev-ioctl");
        return fails > 0 ? 1 : 0;
    }
    if (getenv("ELFUSE_USBDEV_RETIRE_DELAY_US")) {
        check_retire_window_race();
        SUMMARY("test-usbdev-ioctl");
        return fails > 0 ? 1 : 0;
    }
    if (!strcmp(mode, "badifnum")) {
        check_malformed_interface_number();
        SUMMARY("test-usbdev-ioctl");
        return fails > 0 ? 1 : 0;
    }

    check_open_agrees();
    check_write_family();
    check_seek();
    check_interface_bound();
    check_endpoint_arguments();
    check_offset_and_vector_edges();
    check_answers_without_a_device();
    check_vfs_ioctls();
    check_access_mode_three();
    check_transfer_allowance();
    check_table_exhaustion();
    check_close_identity();
    print_known_gaps();

    SUMMARY("test-usbdev-ioctl");
    return fails > 0 ? 1 : 0;
}
