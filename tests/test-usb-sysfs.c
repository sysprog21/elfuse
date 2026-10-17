/*
 * The synthetic USB tree's contract, and the two views that must agree
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Code under test: src/runtime/usb-sysfs.c, plus the sysfs and /dev/bus statfs
 * arms in src/syscall/fs-stat.c, and path_rebuild_under and the /dev/bus climb
 * rewrite in path_translate_at (src/syscall/path.c).
 *
 * Two halves. The first asserts what holds with no USB device attached at all:
 * SYSFS_MAGIC from statfs and fstatfs alike, the read-only open contract, and
 * the ENOENT/EINVAL/ENOTDIR answers for paths the tree does not carry. Those
 * run everywhere, so a machine with an empty bus still regression-tests the
 * path layer.
 *
 * The second half walks whatever devices are present and asserts the identities
 * that can only be checked against a real one -- above all that the
 * `descriptors` attribute and a read() of the matching /dev/bus/usb node return
 * the same bytes, which is the invariant Linux keeps between sysfs and usbfs
 * and the one a second blob generator would silently break, and that the
 * `subsystem` links the tree emits are reachable the way Linux makes them
 * reachable: followed on a plain open, ELOOP only when the caller asked for
 * O_NOFOLLOW, and readable as a target either way.
 *
 * The /dev/bus name checks at the end use the fixture's devices, which the lane
 * always provides.
 *
 * A run with no devices is not a pass by default: the device count is printed,
 * so a lane that quietly stopped covering the second half is visible rather
 * than merely green.
 *
 * What the second half cannot cover, whatever is plugged in: an attribute value
 * this layer never produces. `configuration` is the case in point -- it needs a
 * configuration whose iConfiguration is non-zero *and* a string descriptor read
 * over ep0, and no device can supply the second half of that to a layer that
 * opens nothing. Asserting the value here would only ever assert the empty
 * case, so the rule itself is asserted in test-usb-desc-host.c against
 * synthesized descriptors, which runs both branches on any host, and what stays
 * here are the two facts a real device can falsify: that the attribute exists,
 * and that it is empty whenever iConfiguration is 0.
 */

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define SYSFS_MAGIC 0x62656572
#define USB_MAJOR 189
#define DEVICES_DIR "/sys/bus/usb/devices"

/* Read a whole file into a fresh buffer; *out is set on success and the caller
 * frees it.
 *
 * Returns the byte count, or -1 with the buffer untouched.
 *
 * The buffer grows instead of stopping at a fixed cap. A fixed one had to
 * answer "the file was this long" and "the read stopped here" with the same
 * number, and the two-view compare below reads that number as a length: two
 * blobs whose difference lies past the cap compared equal and the assertion
 * passed on a prefix. A descriptors blob is bounded by the device, not by us --
 * wTotalLength is 16-bit and bNumConfigurations is a byte -- so there is no
 * honest constant to pick, and the compare must see whatever the file holds.
 */
static ssize_t slurp(const char *path, unsigned char **out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    size_t cap = 4096, off = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) {
        close(fd);
        return -1;
    }
    for (;;) {
        if (off == cap) {
            unsigned char *grown = realloc(buf, cap * 2);
            if (!grown) {
                free(buf);
                close(fd);
                return -1;
            }
            buf = grown;
            cap *= 2;
        }
        ssize_t n = read(fd, buf + off, cap - off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            free(buf);
            close(fd);
            return -1;
        }
        if (n == 0)
            break;
        off += (size_t) n;
    }
    close(fd);
    *out = buf;
    return (ssize_t) off;
}

/* Read a small text attribute, trimming the trailing newline. A value that does
 * not fit is an error, not a prefix: every attribute this reads is a short
 * fixed-shape string, so one that overflowed is a fact worth failing on.
 */
static int attr_str(const char *dir, const char *name, char *out, size_t cap)
{
    char path[512];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int) sizeof(path))
        return -1;
    unsigned char *raw = NULL;
    ssize_t n = slurp(path, &raw);
    if (n < 0)
        return -1;
    if ((size_t) n >= cap) {
        free(raw);
        return -1;
    }
    memcpy(out, raw, (size_t) n);
    free(raw);
    out[n] = '\0';
    if (n > 0 && out[n - 1] == '\n')
        out[n - 1] = '\0';
    return 0;
}

/* EXPECT_TRUE for an assertion that compares two values it already holds.
 *
 * FAIL prints the global errno, which is only meaningful when the assertion
 * just made a failing syscall. For a value comparison it prints whatever the
 * last failure anywhere left behind: this file's CI log once reported a
 * configuration mismatch as "(errno=13)", the EACCES from the writable-open
 * check several assertions earlier, which reads as an attribute that could not
 * be opened rather than one that held the wrong bytes. Clearing errno first
 * makes such a report say errno=0 -- and still lets a syscall inside cond set
 * it, so a genuine failure is not hidden.
 */
#define EXPECT_VALUE(cond, msg) \
    do {                        \
        errno = 0;              \
        EXPECT_TRUE(cond, msg); \
    } while (0)

static void check_tree_contract(void)
{
    struct statfs sfs;
    struct stat st;
    int fd;

    /* libusb gates its whole sysfs path on this, and a wrong answer sends it
     * down the usbfs directory scan instead.
     */
    TEST("statfs(/sys) reports SYSFS_MAGIC");
    EXPECT_TRUE(
        statfs("/sys", &sfs) == 0 && (unsigned) sfs.f_type == SYSFS_MAGIC,
        "statfs /sys f_type");

    /* Same fact, other entry point: systemd's sd-device reopens a chased
     * syspath and gates on fstatfs, so the two must not disagree.
     */
    TEST("fstatfs of a /sys fd agrees with statfs");
    fd = open("/sys", O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        FAIL("open /sys");
    } else {
        EXPECT_TRUE(
            fstatfs(fd, &sfs) == 0 && (unsigned) sfs.f_type == SYSFS_MAGIC,
            "fstatfs /sys f_type");
        close(fd);
    }

    TEST("statfs of an absent /sys path is ENOENT");
    EXPECT_TRUE(statfs("/sys/elfuse-no-such-node", &sfs) < 0 && errno == ENOENT,
                "statfs absent /sys path");

    TEST("/sys/bus/usb/devices is a directory");
    EXPECT_TRUE(stat(DEVICES_DIR, &st) == 0 && S_ISDIR(st.st_mode),
                "stat " DEVICES_DIR);

    /* The tree is read-only; a mutating open must say so rather than land on
     * the scratch directory backing it.
     */
    TEST("a writable open under /sys is EACCES");
    fd = open(DEVICES_DIR "/elfuse-probe", O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) {
        close(fd);
        FAIL("a create under /sys succeeded");
    } else {
        EXPECT_TRUE(errno == EACCES, "EACCES for a create under /sys");
    }

    TEST("readlink of a /sys directory is EINVAL");
    char lbuf[256];
    EXPECT_TRUE(
        readlink(DEVICES_DIR, lbuf, sizeof(lbuf)) < 0 && errno == EINVAL,
        "readlink a directory");

    /* '..' is a legal sysfs component. Rejecting it outright answered EACCES
     * for a path Linux resolves, so the fold has to land back on the same
     * directory rather than on an error.
     */
    TEST("'..' inside a /sys path folds");
    struct stat plain, dotted;
    EXPECT_TRUE(stat(DEVICES_DIR, &plain) == 0 &&
                    stat("/sys/bus/usb/devices/../devices", &dotted) == 0 &&
                    plain.st_ino == dotted.st_ino,
                "folded path is the same directory");

    TEST("an absurd bus number is ENOENT");
    EXPECT_TRUE(open("/dev/bus/usb/999/001", O_RDONLY) < 0 && errno == ENOENT,
                "open bus 999");

    /* usbfs names are always three digits; a shorter spelling is not the same
     * file with leading zeros stripped, it is a path that does not exist.
     */
    TEST("a non-3-digit node name is ENOENT");
    EXPECT_TRUE(open("/dev/bus/usb/2/1", O_RDONLY) < 0 && errno == ENOENT,
                "open /dev/bus/usb/2/1");

    TEST("/dev/bus/usb is a directory");
    EXPECT_TRUE(stat("/dev/bus/usb", &st) == 0 && S_ISDIR(st.st_mode),
                "stat /dev/bus/usb");

    /* Which filesystem answers is decided by what the name resolves to, not by
     * how it was spelled. "/sys/../sys" is /sys once the kernel has folded it,
     * and Linux reports SYSFS_MAGIC for it (measured, 6.19: f_type 0x62656572).
     * Classifying the folded name and then probing the raw one asked two
     * questions of two spellings and answered ENOENT for a directory that
     * exists. systemd and libusb both reach sysfs through paths they assembled,
     * so the unfolded spelling is not a curiosity.
     */
    TEST("statfs of an unfolded /sys spelling still reports SYSFS_MAGIC");
    EXPECT_TRUE(statfs("/sys/../sys", &sfs) == 0 &&
                    (unsigned) sfs.f_type == SYSFS_MAGIC,
                "statfs /sys/../sys");

    TEST("statfs of a /sys path through '.' reports SYSFS_MAGIC");
    EXPECT_TRUE(statfs("/sys/./bus/usb/../usb", &sfs) == 0 &&
                    (unsigned) sfs.f_type == SYSFS_MAGIC,
                "statfs /sys/./bus/usb/../usb");

    /* Same rule for a relative name: it resolves against the cwd before the
     * filesystem is chosen, so statfs("sys") from / is statfs("/sys"). A gate
     * that required a leading '/' sent every relative walker to the host, which
     * has no /sys at all.
     */
    TEST("statfs of a relative sysfs name resolves against the cwd");
    {
        char saved[512];
        const char *cwd = getcwd(saved, sizeof(saved));
        if (chdir("/") < 0) {
            FAIL("chdir /");
        } else {
            errno = 0;
            EXPECT_TRUE(statfs("sys", &sfs) == 0 &&
                            (unsigned) sfs.f_type == SYSFS_MAGIC,
                        "statfs sys from /");
        }

        /* Only the cwd-is-/ case is asserted: chdir into the synthetic tree is
         * not served at all here (chdir("/sys") is ENOENT), which is a
         * different gap and not this one.
         */
        if (cwd)
            (void) !chdir(cwd);
    }

    /* O_DIRECTORY|O_CREAT is rejected in build_open_flags(), before the path is
     * resolved: EINVAL for an existing directory, an absent name and a
     * synthetic directory alike (measured on 6.19; macOS open(2) agrees, so
     * only the intercepts answered otherwise). A synthetic directory reporting
     * EISDIR describes a lookup the kernel never performed.
     */
    static const char *const dircreate[] = {
        "/sys",         "/sys/bus/usb/devices", "/sys/bus/usb/devices/absent",
        "/dev/bus/usb", "/proc/self",
    };
    for (size_t i = 0; i < sizeof(dircreate) / sizeof(dircreate[0]); i++) {
        TEST("O_DIRECTORY|O_CREAT is EINVAL, not EISDIR");
        errno = 0;
        fd = open(dircreate[i], O_RDONLY | O_DIRECTORY | O_CREAT, 0644);
        if (fd >= 0) {
            close(fd);
            printf("      %s opened\n", dircreate[i]);
            FAIL("O_DIRECTORY|O_CREAT succeeded");
        } else {
            int got = errno;
            char why[600];
            snprintf(why, sizeof(why), "%s answered errno=%d", dircreate[i],
                     got);
            EXPECT_VALUE(got == EINVAL, why);
        }

        /* O_PATH is the exception, and the reason the pair cannot simply be
         * refused: under O_PATH the kernel masks the flags down to
         * O_DIRECTORY|O_NOFOLLOW|O_PATH, so the creation bit is gone before the
         * pair is tested and the open succeeds on a directory (measured on
         * 6.19). Refusing it too would break a descriptor systemd's chase()
         * takes on every directory it walks.
         */
        TEST("O_PATH|O_DIRECTORY|O_CREAT still opens a directory");
        errno = 0;
        int pfd = open(dircreate[i], O_RDONLY | O_PATH | O_DIRECTORY | O_CREAT);
        bool absent = strstr(dircreate[i], "absent") != NULL;
        if (pfd >= 0) {
            close(pfd);
            char why[600];
            snprintf(why, sizeof(why), "%s opened", dircreate[i]);
            EXPECT_VALUE(!absent, why);
        } else {
            int got = errno;
            char why[600];
            snprintf(why, sizeof(why), "%s answered errno=%d, wanted %s",
                     dircreate[i], got, absent ? "ENOENT" : "success");
            EXPECT_VALUE(absent && got == ENOENT, why);
        }
    }
}

/* The reader this file's two-view compare rests on.
 *
 * A descriptors blob is bounded by the device -- wTotalLength is 16-bit and
 * bNumConfigurations is a byte -- so a reader with a fixed cap has to answer
 * "the file was this long" and "I stopped here" with the same number. It did,
 * and the compare read that number as a length: two blobs differing only past
 * the cap reported equal lengths and an equal prefix, and the assertion passed
 * without ever seeing the tail. Asserted on files this test writes, because no
 * attached device produces a blob that large and the property must hold
 * whatever is plugged in.
 */
static void check_slurp_reads_whole_files(void)
{
    const size_t len = 70000; /* past the 65536 the fixed cap stopped at */
    char pa[] = "/tmp/elfuse-usb-slurp-a-XXXXXX";
    char pb[] = "/tmp/elfuse-usb-slurp-b-XXXXXX";
    unsigned char *a = NULL, *b = NULL;

    TEST("slurp fixtures are writable");
    int fa = mkstemp(pa), fb = mkstemp(pb);
    if (fa < 0 || fb < 0) {
        FAIL("mkstemp");
        goto out;
    }
    PASS();

    for (size_t off = 0; off < len; off++) {
        unsigned char byte = (unsigned char) (off & 0xff);
        /* The two files differ in exactly one byte, and it is the last one. */
        unsigned char bbyte =
            (off == len - 1) ? (unsigned char) (byte ^ 0xff) : byte;
        if (write(fa, &byte, 1) != 1 || write(fb, &bbyte, 1) != 1)
            break;
    }
    close(fa);
    close(fb);
    fa = fb = -1;

    ssize_t na = slurp(pa, &a), nb = slurp(pb, &b);
    char why[128];
    snprintf(why, sizeof(why), "read %zd and %zd of %zu bytes", na, nb, len);
    TEST("slurp reports the whole file, not the prefix it stopped at");
    EXPECT_VALUE(na == (ssize_t) len && nb == (ssize_t) len, why);

    TEST("two blobs differing only past 64 KiB do not compare equal");
    EXPECT_VALUE(
        !(na > 0 && na == nb && a && b && memcmp(a, b, (size_t) na) == 0),
        "the tail difference is seen");

out:
    if (fa >= 0)
        close(fa);
    if (fb >= 0)
        close(fb);
    free(a);
    free(b);
    unlink(pa);
    unlink(pb);
}

/* The `subsystem` link is how libudev and pyserial's list_ports_linux prove a
 * node is USB-backed: they readlink it, or walk through it, and keep the
 * basename. Linux opens it as the directory it points at, so a tree that
 * refuses to follow its own links is unreachable to exactly the consumers this
 * layer exists for. `what` names the entry kind in the failure line, because
 * the device and interface dirs sit at different depths and only one of them
 * being wrong is the interesting outcome.
 */
static void check_subsystem_link(const char *dir, const char *what)
{
    char path[600];
    if (snprintf(path, sizeof(path), "%s/subsystem", dir) >=
        (int) sizeof(path)) {
        TEST("subsystem path fits");
        FAIL("path too long");
        return;
    }

    TEST("open follows the subsystem link to a directory");
    struct stat st;
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("      %s: open %s: %s\n", what, path, strerror(errno));
        FAIL("open subsystem");
    } else {
        EXPECT_TRUE(fstat(fd, &st) == 0 && S_ISDIR(st.st_mode),
                    "subsystem opens as a directory");
        close(fd);
    }

    /* The guest asking for O_NOFOLLOW is the one case where refusing is right,
     * and it is what tells the two behaviors apart: before the fix every open
     * answered this way.
     */
    TEST("O_NOFOLLOW on the subsystem link is ELOOP");
    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd >= 0) {
        close(fd);
        FAIL("O_NOFOLLOW followed the link");
    } else {
        EXPECT_TRUE(errno == ELOOP, "ELOOP for O_NOFOLLOW");
    }

    /* Same flag, write side. O_NOFOLLOW on a symlink is ELOOP before the access
     * mode is looked at -- measured on a real /sys/class/net/lo/ subsystem
     * under 6.19, where O_WRONLY|O_NOFOLLOW is ELOOP and plain O_WRONLY is
     * EISDIR. Answering the read-only refusal first describes the directory the
     * link points at, for a caller that said not to go there.
     */
    TEST("a writable O_NOFOLLOW open of the subsystem link is ELOOP");
    fd = open(path, O_WRONLY | O_NOFOLLOW);
    if (fd >= 0) {
        close(fd);
        FAIL("writable O_NOFOLLOW succeeded");
    } else {
        EXPECT_TRUE(errno == ELOOP, "ELOOP before EISDIR");
    }

    TEST("a writable open that follows the link is EISDIR");
    fd = open(path, O_WRONLY);
    if (fd >= 0) {
        close(fd);
        FAIL("writable open succeeded");
    } else {
        EXPECT_TRUE(errno == EISDIR, "EISDIR for the directory behind it");
    }

    /* What the descriptor holds, and therefore where a relative walk off it
     * starts. Linux gives a followed open the target: /proc/self/fd/N names the
     * directory, and openat(fd, "..") pops the *target's* parent -- which is
     * how systemd's chase() and libudev step from a device up into /sys/bus. A
     * descriptor stamped with the link's own spelling restarts every such walk
     * from the device directory instead.
     */
    static const char busdir[] = "/sys/bus/usb";

    for (int opath = 0; opath <= 1; opath++) {
        int oflags = opath ? O_PATH : (O_RDONLY | O_DIRECTORY);
        fd = open(path, oflags);
        TEST(opath ? "an O_PATH fd on the link names the directory it resolves "
                     "to"
                   : "a followed fd on the link names the directory it "
                     "resolves to");
        if (fd < 0) {
            FAIL("open subsystem for the identity check");
            continue;
        }
        char fdpath[64], seen[600];
        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
        ssize_t sn = readlink(fdpath, seen, sizeof(seen) - 1);
        if (sn < 0) {
            FAIL("readlink /proc/self/fd");
        } else {
            seen[sn] = '\0';
            char why[1300];
            snprintf(why, sizeof(why), "fd names \"%s\", wanted \"%s\"", seen,
                     busdir);
            EXPECT_VALUE(!strcmp(seen, busdir), why);
        }

        TEST(opath ? "openat(\"..\") off the O_PATH fd pops the target's parent"
                   : "openat(\"..\") off the followed fd pops the target's "
                     "parent");
        int up = openat(fd, "..", O_RDONLY | O_DIRECTORY);
        if (up < 0) {
            FAIL("openat .. off the subsystem fd");
        } else {
            /* By name, not by inode: a path stat of this tree reports a
             * synthesized st_ino while fstat of an opened descriptor reports
             * the scratch directory's own, so the two never compare equal for
             * any path. The name is what the walkers act on anyway.
             */
            char upfd[64], upname[600];
            snprintf(upfd, sizeof(upfd), "/proc/self/fd/%d", up);
            ssize_t un = readlink(upfd, upname, sizeof(upname) - 1);
            if (un < 0) {
                FAIL("readlink /proc/self/fd of the parent");
            } else {
                upname[un] = '\0';
                char why[1300];
                snprintf(why, sizeof(why),
                         "'..' landed on \"%s\", wanted \"/sys/bus\"", upname);
                EXPECT_VALUE(!strcmp(upname, "/sys/bus"), why);
            }
            close(up);
        }
        close(fd);
    }

    /* The other half of the same rule: O_PATH|O_NOFOLLOW is the spelling that
     * asks for the link itself, and it must keep naming the link.
     */
    TEST("O_PATH|O_NOFOLLOW still names the link, not its target");
    fd = open(path, O_PATH | O_NOFOLLOW);
    if (fd < 0) {
        FAIL("O_PATH|O_NOFOLLOW open");
    } else {
        char fdpath[64], seen[600];
        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
        ssize_t sn = readlink(fdpath, seen, sizeof(seen) - 1);
        if (sn < 0) {
            FAIL("readlink /proc/self/fd");
        } else {
            seen[sn] = '\0';
            char why[1300];
            snprintf(why, sizeof(why), "fd names \"%s\", wanted \"%s\"", seen,
                     path);
            EXPECT_VALUE(!strcmp(seen, path), why);
        }
        close(fd);
    }

    /* kernfs installs .poll on every sysfs file (sysfs_file_operations), so
     * epoll_ctl(ADD) on an attribute is 0 on Linux -- measured for net/lo/mtu,
     * net/lo/uevent and virtual/net/lo/type alike on 6.19. udev-style readers
     * arm `uevent` before they read it, and EPERM there reads as "this file can
     * never be polled".
     */
    char attr[620];
    snprintf(attr, sizeof(attr), "%s/uevent", dir);
    TEST("a sysfs attribute can be added to an epoll set");
    int afd = open(attr, O_RDONLY);
    int epfd = epoll_create1(0);
    if (afd < 0 || epfd < 0) {
        FAIL("open the attribute / epoll_create1");
    } else {
        struct epoll_event ev = {.events = EPOLLIN, .data = {.fd = afd}};
        EXPECT_TRUE(epoll_ctl(epfd, EPOLL_CTL_ADD, afd, &ev) == 0,
                    "epoll_ctl ADD on a sysfs attribute");
    }
    if (afd >= 0)
        close(afd);
    if (epfd >= 0)
        close(epfd);

    /* The same link reached the other two ways a path walker reaches it. Both
     * ran through the forced-O_NOFOLLOW open before the fix, so both answered
     * ELOOP; libudev opens by dirfd, and O_PATH is how a resolver pins a
     * component it means to walk through rather than read.
     */
    TEST("openat with a dirfd follows the subsystem link");
    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
        FAIL("open the parent dir");
    } else {
        fd = openat(dfd, "subsystem", O_RDONLY);
        if (fd < 0) {
            printf("      %s: openat subsystem: %s\n", what, strerror(errno));
            FAIL("openat subsystem");
        } else {
            EXPECT_TRUE(fstat(fd, &st) == 0 && S_ISDIR(st.st_mode),
                        "openat subsystem is a directory");
            close(fd);
        }
        close(dfd);
    }

    /* Only that the open succeeds: fstat of the resulting descriptor still
     * answers link-shaped, because the stat intercept takes a path and no
     * follow flag and so cannot tell stat from lstat (usb-sysfs.c, the S_ISLNK
     * arm). That is a separate deviation from this one, and asserting a
     * directory here would be asserting a fix this change does not make.
     */
    TEST("O_PATH on the subsystem link is not ELOOP");
    fd = open(path, O_PATH);
    if (fd < 0) {
        printf("      %s: O_PATH subsystem: %s\n", what, strerror(errno));
        FAIL("O_PATH subsystem");
    } else {
        PASS();
        close(fd);
    }

    /* Following must not have replaced the link with a directory: libudev reads
     * the target, never opens it.
     */
    TEST("readlink of the subsystem link still reports its target");
    char lbuf[256];
    ssize_t n = readlink(path, lbuf, sizeof(lbuf) - 1);
    if (n < 0) {
        FAIL("readlink subsystem");
    } else {
        lbuf[n] = '\0';
        EXPECT_TRUE(!strcmp(lbuf, "../../../usb"), "subsystem target");
    }
}

/* '..' applied after the `subsystem` link must not walk out of the tree.
 *
 * The link resolves to the tree's own /sys/bus/usb, so the '..' chain climbs
 * /sys/bus, then /sys, and the next one would leave. Every name that resolves
 * out there has to be refused, on the readlink path as much as on open and
 * stat: readlink hands a string back without opening anything, which is exactly
 * why it is the easy one to leave behind, and a target string is still the
 * guest learning about a host object it was never given.
 *
 * Two shapes, and they are not the same test. One appends a component after the
 * chain, so the whole prefix is resolved and refused before the leaf is ever
 * consulted. The other ends *at* the '..', which is the shape that escaped: a
 * resolver that holds the last component back to keep O_NOFOLLOW honest
 * resolves the prefix, proves it contained, and then reattaches a '..' to it --
 * and one applied to the tree root names the host directory the root sits in,
 * with no containment test left to run. The suite passed 68/68 while that was
 * live, because it only ever asked the first shape.
 *
 * A symlink is planted in the directory the escape lands in, under a name
 * mkstemp reserved, so concurrent lanes cannot collide on it: a fixed name made
 * three of eight parallel runs fail on the plant rather than on the contract
 * ("escape probe not planted (File exists)"). A pid suffix does not do it here
 * -- every guest starts at pid 1, so all eight lanes spell the same name; the
 * uniqueness has to come from the filesystem that holds the plant. The plant is
 * what makes the assertions non-vacuous, and it is used two ways: readlink of
 * it by its own name must succeed, so a plant that never got created cannot be
 * mistaken for a refusal; and it must not appear in anything the tree hands
 * back, which is how the escaping shape is caught -- a descriptor opened on the
 * escape lists the planted name, naming the host directory it reached rather
 * than merely being "some directory".
 */
static void check_link_containment(const char *dir)
{
    char probe[] = "/tmp/elfuse-usb-escape-probe-XXXXXX";
    const char *plantname = probe + 5; /* past "/tmp/" */
    static const char planted[] = "/elfuse-usb-escape-target";

    TEST("escape probe is plantable");
    int slot = mkstemp(probe);
    if (slot < 0) {
        FAIL("mkstemp");
        return;
    }
    close(slot);
    unlink(probe);
    if (symlink(planted, probe) < 0) {
        FAIL("symlink");
        return;
    }
    PASS();

    /* The plant is live and reachable by its own name. Without this the two
     * refusals below could both be reporting an absent file.
     */
    TEST("escape probe is planted and readable by its own name");
    char pbuf[256];
    ssize_t pn = readlink(probe, pbuf, sizeof(pbuf) - 1);
    if (pn < 0) {
        FAIL("readlink of the plant");
        goto done;
    }
    pbuf[pn] = '\0';
    EXPECT_TRUE(!strcmp(pbuf, planted), "plant target");

    /* Shape one: a component after the chain. */
    char path[700];
    /* probe + 4 drops the leading "/tmp", which the '..' chain re-enters. */
    int n =
        snprintf(path, sizeof(path), "%s/subsystem/../../..%s", dir, probe + 4);
    if (n < 0 || (size_t) n >= sizeof(path))
        goto done;

    TEST("'..' after subsystem cannot readlink out of the tree");
    char lbuf[256];
    ssize_t rn = readlink(path, lbuf, sizeof(lbuf) - 1);
    if (rn >= 0) {
        lbuf[rn] = '\0';
        printf("      escaped: %s -> %s\n", path, lbuf);
        FAIL("readlink left the tree");
    } else {
        EXPECT_TRUE(errno == ENOENT, "escape answers ENOENT");
    }

    /* open and stat resolve through the same helper; assert them here too so
     * one lane covers all three entry points rather than trusting agreement.
     */
    TEST("'..' after subsystem cannot open out of the tree");
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd >= 0) {
        close(fd);
        FAIL("open left the tree");
    } else {
        EXPECT_TRUE(errno == ENOENT || errno == ELOOP, "escape refused");
    }

    TEST("'..' after subsystem cannot lstat out of the tree");
    struct stat est;
    EXPECT_TRUE(lstat(path, &est) < 0 && errno == ENOENT, "escape is ENOENT");

    /* Shape two: the chain itself, with nothing appended.
     *
     * Each depth is pinned to the object Linux resolves it to, by identity
     * rather than by errno: one '..' after the link is /sys/bus and two is
     * /sys, both of which the tree carries, and the third leaves the tree
     * altogether. Asserting only "not an escape" would pass for a resolver that
     * refused all three, which would break every relative walk through the
     * link; asserting the identity says the resolution is right as well as
     * contained.
     */
    struct stat sys_st, bus_st;
    bool have_roots =
        stat("/sys", &sys_st) == 0 && stat("/sys/bus", &bus_st) == 0;
    TEST("/sys and /sys/bus are stat-able, so the depths below mean something");
    EXPECT_TRUE(have_roots, "tree roots");

    for (int depth = 1; depth <= 4 && have_roots; depth++) {
        char chain[700];
        int cn = snprintf(chain, sizeof(chain), "%s/subsystem", dir);
        for (int i = 0; i < depth && cn > 0 && (size_t) cn < sizeof(chain); i++)
            cn += snprintf(chain + cn, sizeof(chain) - (size_t) cn, "/..");
        if (cn < 0 || (size_t) cn >= sizeof(chain))
            break;

        const struct stat *want = depth == 1   ? &bus_st
                                  : depth == 2 ? &sys_st
                                               : NULL;
        char why[800];
        struct stat cst;
        snprintf(why, sizeof(why), "%s resolves to %s", chain,
                 want ? (depth == 1 ? "/sys/bus" : "/sys") : "nothing");

        TEST("a trailing '..' chain resolves inside the tree or not at all");
        errno = 0;
        int src = stat(chain, &cst);
        if (want)
            EXPECT_TRUE(src == 0 && cst.st_dev == want->st_dev &&
                            cst.st_ino == want->st_ino,
                        why);
        else
            EXPECT_TRUE(src < 0 && errno == ENOENT, why);

        /* The loud half: if it opened, say which directory it opened by looking
         * for the plant in it.
         */
        TEST("a trailing '..' chain cannot open a host directory");
        int cfd = open(chain, O_RDONLY | O_NOFOLLOW);
        if (cfd < 0) {
            EXPECT_TRUE(!want, why);
            continue;
        }
        bool found = false;
        DIR *cd = fdopendir(cfd);
        if (!cd) {
            close(cfd);
            FAIL("fdopendir on the opened chain");
            continue;
        }
        struct dirent *e;
        while ((e = readdir(cd))) {
            if (!strcmp(e->d_name, plantname))
                found = true;
        }
        closedir(cd);
        if (found) {
            printf("      escaped: %s lists the planted %s\n", chain,
                   plantname);
            FAIL("the opened directory is the host's, not the tree's");
        } else {
            EXPECT_TRUE(want != NULL, why);
        }
    }

done:
    unlink(probe);
}

/* Locate the active configuration inside a raw `descriptors` blob.
 *
 * Deliberately a second implementation rather than a call into
 * runtime/usb-desc.c: a test that reuses the code under test cannot catch that
 * code agreeing with itself. Walks configuration headers only -- bLength 9 and
 * bDescriptorType 2 -- and steps by wTotalLength, so a blob whose config
 * under-reports its span ends the walk instead of matching an interface
 * descriptor's bytes.
 *
 * Returns a pointer into blob, or NULL.
 */
static const unsigned char *active_cfg(const unsigned char *blob,
                                       size_t len,
                                       unsigned want_value)
{
    const unsigned char *first = NULL;
    size_t off = 18; /* past the device descriptor */
    while (len - off >= 9 && off < len) {
        const unsigned char *p = blob + off;
        if (p[0] != 9 || p[1] != 2)
            break;
        size_t total = (size_t) (p[2] | (p[3] << 8));
        if (total < 9)
            break;
        if (total > len - off)
            total = len - off;
        if (!first)
            first = p;
        if (p[5] == (unsigned char) want_value)
            return p;
        off += total;
    }
    return first;
}

/* sysfs `speed` string -> the bMaxPower unit Linux scales by (usb_get_max_power
 * uses 8 mA at SuperSpeed and above, 2 mA below it).
 */
static unsigned max_power_unit(const char *speed)
{
    return atoi(speed) >= 5000 ? 8 : 2;
}

/* Assertions that need a device. Returns the number examined. */
static int check_devices(void)
{
    DIR *dp = opendir(DEVICES_DIR);
    if (!dp)
        return 0;

    int ndev = 0;
    struct dirent *ent;
    while ((ent = readdir(dp))) {
        /* Device entries only: interfaces carry a ':' and are checked through
         * the bNumInterfaces count below.
         */
        if (ent->d_name[0] == '.' || strchr(ent->d_name, ':'))
            continue;
        char dir[512];
        if (snprintf(dir, sizeof(dir), "%s/%s", DEVICES_DIR, ent->d_name) >=
            (int) sizeof(dir))
            continue;
        ndev++;

        char busbuf[64], devbuf[64], val[128];
        if (attr_str(dir, "busnum", busbuf, sizeof(busbuf)) < 0 ||
            attr_str(dir, "devnum", devbuf, sizeof(devbuf)) < 0) {
            TEST("device carries busnum and devnum");
            FAIL("missing busnum/devnum");
            continue;
        }
        int busnum = atoi(busbuf), devnum = atoi(devbuf);

        /* The five attributes lsusb -t reads. Their absence is not a crash, it
         * is a warning per device and a topology listing with holes in it.
         *
         * bmAttributes, bMaxPower and configuration are checked against the
         * device's own `descriptors` blob rather than merely for being present:
         * each is a field copied out of the active configuration descriptor, so
         * the blob is the only thing that can say whether the right byte was
         * copied. Asserting shape alone -- "parses as hex", "is present" --
         * passes for a wrong value and for a garbage string alike.
         */
        unsigned char *blob = NULL;
        char cfgpath[600];
        ssize_t blen = -1;
        if (snprintf(cfgpath, sizeof(cfgpath), "%s/descriptors", dir) <
            (int) sizeof(cfgpath))
            blen = slurp(cfgpath, &blob);

        char cfgvalbuf[64], speedbuf[64];
        const unsigned char *cfg = NULL;
        if (blen > 0 && attr_str(dir, "bConfigurationValue", cfgvalbuf,
                                 sizeof(cfgvalbuf)) == 0)
            cfg = active_cfg(blob, (size_t) blen, (unsigned) atoi(cfgvalbuf));

        TEST("bmAttributes equals the active config descriptor's byte");
        if (!cfg) {
            FAIL("no active configuration in descriptors");
        } else {
            char *end = NULL;
            long got = attr_str(dir, "bmAttributes", val, sizeof(val)) == 0
                           ? strtol(val, &end, 16)
                           : -1;

            /* endptr, not just the value: strtol returns 0 for a string with no
             * digits at all, which is what made the old check unfalsifiable.
             */
            EXPECT_VALUE(
                end && end != val && *end == '\0' && got == (long) cfg[7],
                "bmAttributes matches descriptor");
        }

        TEST("bMaxPower equals the descriptor field scaled by the speed unit");
        if (!cfg || attr_str(dir, "speed", speedbuf, sizeof(speedbuf)) != 0) {
            FAIL("no active configuration or speed");
        } else if (attr_str(dir, "bMaxPower", val, sizeof(val)) != 0) {
            FAIL("bMaxPower missing");
        } else {
            char expect[64];
            snprintf(expect, sizeof(expect), "%umA",
                     (unsigned) cfg[8] * max_power_unit(speedbuf));
            EXPECT_VALUE(!strcmp(val, expect), "bMaxPower matches descriptor");
        }

        /* configuration against iConfiguration, in the one direction Linux
         * actually guarantees.
         *
         * An earlier version of this asserted the biconditional -- empty
         * exactly when iConfiguration is 0 -- and that is not Linux's rule.
         * configuration_show emits nothing whenever actconfig->string is NULL
         * (sysfs.c:83-84), and usb_cache_string returns NULL "if the index is 0
         * or the string could not be read" (message.c:1074-1075). An empty
         * configuration therefore means "no cached string", which a non-zero
         * iConfiguration does not rule out: a device that NAKs its own string
         * descriptor reads empty on real sysfs too, so the biconditional fails
         * against Linux itself. It failed here for the same reason -- this
         * layer has no ep0 and so never has a string -- and that made it look
         * like an implementation bug when the assertion was the wrong one.
         *
         * What does hold in both directions is the index-0 half: index 0
         * short-circuits usb_cache_string before any transfer, so a non-empty
         * configuration on a configuration with no string index is a value this
         * layer invented. That is the falsifiable claim, and it is what stays.
         *
         * The other branch -- a non-zero index whose string was read -- has no
         * device here to produce it (both attached devices report
         * iConfiguration 0) and no code path to produce it either. It is
         * covered against a synthesized descriptor in test-usb-desc-host.c.
         */
        TEST("configuration is empty when iConfiguration is 0");
        if (!cfg) {
            FAIL("no active configuration in descriptors");
        } else if (attr_str(dir, "configuration", val, sizeof(val)) != 0) {
            FAIL("configuration missing");
        } else {
            char why[256];
            snprintf(why, sizeof(why),
                     "iConfiguration=%u but configuration reads \"%s\"",
                     (unsigned) cfg[6], val);
            EXPECT_VALUE(cfg[6] != 0 || val[0] == '\0', why);
        }

        /* Presence, separately from contents. Linux keeps these four in
         * dev_attr_grp (sysfs.c:782-786), an attribute group with no
         * .is_visible (sysfs.c:815-817), so they exist on every USB device
         * directory whether or not the kernel has a value to put in them -- a
         * value it lacks is a zero-length read, never an ENOENT. Emitting them
         * only when the descriptor parsed, or leaving `configuration` out
         * because no string could be fetched, would both be caught here.
         */
        TEST("the four active-config attributes are all present");
        {
            static const char *const names[] = {
                "bNumInterfaces", "bmAttributes", "bMaxPower", "configuration"};
            const char *absent = NULL;
            for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
                if (attr_str(dir, names[i], val, sizeof(val)) != 0)
                    absent = names[i];
            char why[128];
            snprintf(why, sizeof(why), "%s is absent, not empty",
                     absent ? absent : "?");
            EXPECT_TRUE(!absent, why);
        }

        /* An attribute this tree really does not carry answers ENOENT, the way
         * sysfs answers for a name that is not an attribute. The read path has
         * no business reporting EACCES for an absent file: the tree's EACCES is
         * the read-only refusal of a *mutating* open, and the two must not be
         * confusable -- a reader probing for an optional attribute takes ENOENT
         * as "not supported" and EACCES as "supported but denied".
         */
        TEST("an absent device attribute is ENOENT, not EACCES");
        {
            char probe[600];
            snprintf(probe, sizeof(probe), "%s/elfuse-no-such-attribute", dir);
            EXPECT_ERRNO(open(probe, O_RDONLY), ENOENT, "absent attr errno");
        }

        TEST("maxchild is present and numeric");
        EXPECT_TRUE(attr_str(dir, "maxchild", val, sizeof(val)) == 0 &&
                        val[0] >= '0' && val[0] <= '9',
                    "maxchild");

        TEST("rx_lanes is at least one");
        EXPECT_TRUE(
            attr_str(dir, "rx_lanes", val, sizeof(val)) == 0 && atoi(val) >= 1,
            "rx_lanes");

        TEST("tx_lanes is at least one");
        EXPECT_TRUE(
            attr_str(dir, "tx_lanes", val, sizeof(val)) == 0 && atoi(val) >= 1,
            "tx_lanes");

        /* bNumInterfaces and the emitted :c.i directories describe the same
         * configuration, so they have to count the same. Reading the attribute
         * off the first config while the directories came from the active one
         * would show up right here.
         */
        TEST("bNumInterfaces matches the interface dirs");
        int declared = -1;
        if (attr_str(dir, "bNumInterfaces", val, sizeof(val)) == 0)
            declared = atoi(val);
        int seen = 0;
        char ifdir[600];
        ifdir[0] = '\0';
        DIR *idp = opendir(DEVICES_DIR);
        if (idp) {
            size_t nlen = strlen(ent->d_name);
            struct dirent *ient;
            while ((ient = readdir(idp))) {
                if (!strncmp(ient->d_name, ent->d_name, nlen) &&
                    ient->d_name[nlen] == ':') {
                    seen++;
                    if (!ifdir[0])
                        snprintf(ifdir, sizeof(ifdir), "%s/%s", DEVICES_DIR,
                                 ient->d_name);
                }
            }
            closedir(idp);
        }
        EXPECT_EQ(seen, declared, "interface dir count");

        /* Both depths carry a `subsystem` link, and both are walked in the
         * field: libudev from the interface, pyserial from the device.
         */
        check_subsystem_link(dir, "device");
        if (ifdir[0])
            check_subsystem_link(ifdir, "interface");
        check_link_containment(dir);

        /* The dev attribute, the node's name, and the node's own st_rdev are
         * three spellings of one identity.
         */
        TEST("dev attribute matches the node's rdev");
        char node[64];
        snprintf(node, sizeof(node), "/dev/bus/usb/%03d/%03d", busnum, devnum);
        struct stat nst;
        int want_minor = (busnum - 1) * 128 + (devnum - 1);
        char want_dev[64];
        snprintf(want_dev, sizeof(want_dev), "%d:%d", USB_MAJOR, want_minor);
        EXPECT_TRUE(attr_str(dir, "dev", val, sizeof(val)) == 0 &&
                        !strcmp(val, want_dev) && stat(node, &nst) == 0 &&
                        S_ISCHR(nst.st_mode) &&
                        (int) major(nst.st_rdev) == USB_MAJOR &&
                        (int) minor(nst.st_rdev) == want_minor,
                    "dev / node / rdev agree");

        /* The invariant this whole layer rests on: one blob, two views. */
        TEST("descriptors and the node read the same bytes");
        unsigned char *a = NULL, *b = NULL;
        char dpath[600];
        snprintf(dpath, sizeof(dpath), "%s/descriptors", dir);
        ssize_t na = slurp(dpath, &a);
        ssize_t nb = slurp(node, &b);
        EXPECT_TRUE(
            na > 0 && na == nb && a && b && memcmp(a, b, (size_t) na) == 0,
            "byte-identical descriptor blobs");

        /* The device descriptor is the first 18 bytes of that blob, and its
         * idVendor/idProduct have to be the ones sysfs advertises.
         */
        TEST("the blob's device descriptor matches idVendor/idProduct");
        unsigned vid = 0, pid = 0;
        if (attr_str(dir, "idVendor", val, sizeof(val)) == 0)
            vid = (unsigned) strtoul(val, NULL, 16);
        if (attr_str(dir, "idProduct", val, sizeof(val)) == 0)
            pid = (unsigned) strtoul(val, NULL, 16);
        EXPECT_TRUE(a && na >= 18 && a[0] == 18 && a[1] == 1 &&
                        (unsigned) (a[8] | (a[9] << 8)) == vid &&
                        (unsigned) (a[10] | (a[11] << 8)) == pid,
                    "device descriptor header");

        /* A char device used as a directory is ENOTDIR on Linux, whichever way
         * the extra component is spelled. Answering ENOENT, or worse handing
         * back the blob, tells a path walker the wrong thing about the node.
         */
        TEST("a trailing slash on the node is ENOTDIR");
        char trail[80];
        snprintf(trail, sizeof(trail), "%s/", node);
        EXPECT_TRUE(open(trail, O_RDONLY) < 0 && errno == ENOTDIR,
                    "open node with a trailing slash");

        TEST("a component below the node is ENOTDIR");
        snprintf(trail, sizeof(trail), "%s/anything", node);
        EXPECT_TRUE(open(trail, O_RDONLY) < 0 && errno == ENOTDIR,
                    "open below the node");

        TEST("O_DIRECTORY on the node is ENOTDIR");
        EXPECT_TRUE(open(node, O_RDONLY | O_DIRECTORY) < 0 && errno == ENOTDIR,
                    "O_DIRECTORY on a char device");

        /* The usbdevfs fd now serves writable opens, and it has to keep the
         * one-blob invariant: reading it must still return exactly what the
         * descriptors attribute does, or the two views have drifted apart the
         * moment a second generator appeared.
         */
        TEST("a writable open of the node serves the same blob");
        int wfd = na > 0 ? open(node, O_RDWR) : -1;
        if (wfd < 0) {
            FAIL("O_RDWR on the node");
        } else {
            /* One byte over the attribute's length, so a node serving more than
             * the attribute does is a failure rather than a prefix that
             * silently compares equal.
             */
            size_t cap = (size_t) na + 1;
            unsigned char *w = malloc(cap);
            ssize_t nw = 0;
            if (!w) {
                FAIL("malloc");
            } else {
                while ((size_t) nw < cap) {
                    ssize_t r = read(wfd, w + nw, cap - (size_t) nw);
                    if (r < 0 && errno == EINTR)
                        continue;
                    if (r <= 0)
                        break;
                    nw += r;
                }
                EXPECT_TRUE(nw == na && memcmp(w, a, (size_t) na) == 0,
                            "usbdevfs fd read matches descriptors");
                free(w);
            }
            close(wfd);
        }

        free(a);
        free(b);
        free(blob);
    }
    closedir(dp);
    return ndev;
}

/* Whether /proc/self/fd/@fd reads back as @want. */
static bool fd_names(int fd, const char *want)
{
    char link[32], buf[128];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, buf, sizeof(buf) - 1);
    if (n < 0)
        return false;
    buf[n] = '\0';
    return !strcmp(buf, want);
}

/* A /dev/bus directory reached through '..' is named by the directory in getcwd
 * and in /proc/self/fd, as Linux names it, not by the spelling.
 */
static void check_dev_bus_names(void)
{
    char cwd[64];

    TEST("getcwd after chdir /dev/bus/usb/001/.. is /dev/bus/usb");
    EXPECT_TRUE(chdir("/dev/bus/usb/001/..") == 0 && getcwd(cwd, sizeof(cwd)) &&
                    !strcmp(cwd, "/dev/bus/usb"),
                "chdir(\"/dev/bus/usb/001/..\"), then getcwd");
    if (chdir("/") != 0)
        FAIL("chdir back to /");

    TEST("/dev/bus/usb/001/../001/ opens as /dev/bus/usb/001");
    int fd = open("/dev/bus/usb/001/../001/", O_RDONLY | O_DIRECTORY);
    EXPECT_TRUE(fd >= 0 && fd_names(fd, "/dev/bus/usb/001"),
                "readlink of the descriptor");
    if (fd >= 0)
        close(fd);

    /* path_rebuild_under folds a relative name against a /dev/bus cwd or dirfd
     * up to a usbfs node or a missing /dev/bus/usb name, so every other '..' is
     * applied before any entry point or stamp sees the name.
     */
    TEST("getcwd after chdir(\"..\") from /dev/bus/usb/001 is /dev/bus/usb");
    EXPECT_TRUE(chdir("/dev/bus/usb/001") == 0 && chdir("..") == 0 &&
                    getcwd(cwd, sizeof(cwd)) && !strcmp(cwd, "/dev/bus/usb"),
                "chdir(\"..\"), then getcwd");

    TEST("open(\".\") in a /dev/bus/usb cwd names /dev/bus/usb");
    fd = open(".", O_RDONLY | O_DIRECTORY);
    EXPECT_TRUE(fd >= 0 && fd_names(fd, "/dev/bus/usb"),
                "readlink of the descriptor");
    if (fd >= 0)
        close(fd);

    if (chdir("/") != 0)
        FAIL("chdir back to /");

    TEST("a '..' chain from a /dev/bus/usb/001 dirfd names it");
    int dfd = open("/dev/bus/usb/001", O_RDONLY | O_DIRECTORY);
    fd = dfd < 0
             ? -1
             : openat(dfd, "../001/../001/../001/../001/../001/../001/../001",
                      O_RDONLY | O_DIRECTORY);
    EXPECT_TRUE(fd >= 0 && fd_names(fd, "/dev/bus/usb/001"),
                "readlink of the descriptor");
    if (fd >= 0)
        close(fd);
    if (dfd >= 0)
        close(dfd);
}

/* Whether @a and @b describe the same file. */
static bool same_inode(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

/* Whether @path names the same file as @want. */
static bool same_file(const char *path, const struct stat *want)
{
    struct stat st;
    return stat(path, &st) == 0 && same_inode(&st, want);
}

/* A '..' out of /dev/bus lands in /dev however the name is reached, and a
 * further '..' climbs on from there.
 */
static void check_dotdot_leaves_bus(void)
{
    static const char *const nulls[] = {
        "/dev/bus/../null",           "/dev/bus/../bus/../null",
        "/dev/bus/.././bus/../null",  "/dev/bus/../../dev/null",
        "/dev/bus/../../../dev/null", "/dev/bus/../../dev/bus/../null",
    };
    static const char *const climbs[][2] = {
        {"/dev/bus/usb/001/../../..", "/dev"},
        {"/dev/bus/../..", "/"},
        {"/dev/bus/../../dev/bus/usb", "/dev/bus/usb"},
        {"/dev/bus/usb/001/../../../../sys/bus/usb/devices",
         "/sys/bus/usb/devices"},
        {"/dev/bus/../../proc/self/status", "/proc/self/status"},
        {"/dev/bus/../../../proc/self/status", "/proc/self/status"},
    };
    struct stat dev_st, null_st, st;
    char what[96], cwd[64];

    TEST("/dev and /dev/null are stat-able");
    if (stat("/dev", &dev_st) != 0 || stat("/dev/null", &null_st) != 0) {
        FAIL("stat");
        return;
    }
    PASS();

    for (size_t i = 0; i < sizeof(nulls) / sizeof(nulls[0]); i++) {
        snprintf(what, sizeof(what), "%s is /dev/null", nulls[i]);
        TEST(what);
        EXPECT_TRUE(same_file(nulls[i], &null_st), nulls[i]);
    }

    TEST("/dev/bus/.. is /dev");
    EXPECT_TRUE(same_file("/dev/bus/..", &dev_st), "stat(\"/dev/bus/..\")");

    for (size_t i = 0; i < sizeof(climbs) / sizeof(climbs[0]); i++) {
        snprintf(what, sizeof(what), "%s is %s", climbs[i][0], climbs[i][1]);
        TEST(what);
        EXPECT_TRUE(
            stat(climbs[i][1], &st) == 0 && same_file(climbs[i][0], &st),
            climbs[i][0]);
    }

    TEST("a '..' out through a bus no device has is ENOENT");
    EXPECT_ERRNO(stat("/dev/bus/usb/099/../../../null", &st), ENOENT,
                 "stat(\"/dev/bus/usb/099/../../../null\")");

    TEST("../null against a /dev/bus dirfd is /dev/null");
    int dfd = open("/dev/bus", O_RDONLY | O_DIRECTORY);
    EXPECT_TRUE(dfd >= 0 && fstatat(dfd, "../null", &st, 0) == 0 &&
                    same_inode(&st, &null_st),
                "fstatat(/dev/bus, \"../null\")");
    if (dfd >= 0)
        close(dfd);

    TEST("chdir .. from /dev/bus reaches /dev");
    if (chdir("/dev/bus") != 0 || chdir("..") != 0)
        FAIL("chdir /dev/bus, then ..");
    else if (!getcwd(cwd, sizeof(cwd)) || strcmp(cwd, "/dev"))
        FAIL("getcwd after chdir ..");
    else if (!same_file("null", &null_st))
        FAIL("stat(\"null\") in /dev");
    else
        PASS();
    if (chdir("/") != 0)
        FAIL("chdir back to /");

    TEST("chdir /dev/bus/usb/001/../../.. reaches /dev");
    if (chdir("/dev/bus/usb/001/../../..") != 0)
        FAIL("chdir /dev/bus/usb/001/../../..");
    else if (!getcwd(cwd, sizeof(cwd)) || strcmp(cwd, "/dev"))
        FAIL("getcwd after chdir /dev/bus/usb/001/../../..");
    else
        PASS();
    if (chdir("/") != 0)
        FAIL("chdir back to /");
}

/* openat of @rel from the host directory @dir, which the host refuses and
 * openat retries through the guest spelling: @err when it is not 0, else a
 * descriptor.
 */
static void check_hostdir_openat(const char *dir, const char *rel, int err)
{
    char what[96];
    snprintf(what, sizeof(what), "openat(%s, \"%s\") %s", dir, rel,
             !err             ? "opens"
             : err == ENOTDIR ? "is ENOTDIR"
             : err == ENOENT  ? "is ENOENT"
                              : "fails");
    TEST(what);
    int hfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (hfd < 0) {
        FAIL(dir);
        return;
    }
    errno = 0;
    int fd = openat(hfd, rel, O_RDONLY | O_DIRECTORY);
    EXPECT_TRUE(err ? fd < 0 && errno == err : fd >= 0, what);
    if (fd >= 0)
        close(fd);
    close(hfd);
}

/* A '..' after a usbfs node is ENOTDIR however the name is reached, and a node
 * reached through any other '..' opens as itself; chdir and fchdir publish the
 * cwd through different code.
 */
static void check_node_dotdot_relative(void)
{
    struct stat st;
    struct statfs sfs;

    TEST("a '..' after a node used as a directory is ENOTDIR");
    EXPECT_ERRNO(stat("/dev/bus/usb/001/001/x/..", &st), ENOTDIR,
                 "stat(\"/dev/bus/usb/001/001/x/..\")");

    TEST("statfs through a usbfs node to /sys is ENOTDIR");
    EXPECT_ERRNO(statfs("/dev/bus/usb/001/001/../../../../../sys", &sfs),
                 ENOTDIR,
                 "statfs(\"/dev/bus/usb/001/001/../../../../../sys\")");

    int dfd = open("/dev/bus/usb/001", O_RDONLY | O_DIRECTORY);
    TEST("\"001/..\" against a /dev/bus/usb/001 dirfd is ENOTDIR");
    if (dfd < 0) {
        FAIL("open /dev/bus/usb/001");
        return;
    }
    EXPECT_ERRNO(fstatat(dfd, "001/..", &st, 0), ENOTDIR,
                 "fstatat(/dev/bus/usb/001, \"001/..\")");

    TEST("\"001/..\" in a /dev/bus/usb/001 cwd from chdir is ENOTDIR");
    if (chdir("/dev/bus/usb/001") != 0)
        FAIL("chdir /dev/bus/usb/001");
    else
        EXPECT_ERRNO(stat("001/..", &st), ENOTDIR, "stat(\"001/..\")");

    TEST("\"001/..\" in a /dev/bus/usb/001 cwd from fchdir is ENOTDIR");
    if (chdir("/") != 0 || fchdir(dfd) != 0)
        FAIL("fchdir /dev/bus/usb/001");
    else
        EXPECT_ERRNO(stat("001/..", &st), ENOTDIR, "stat(\"001/..\")");
    if (chdir("/") != 0)
        FAIL("chdir back to /");

    TEST("\"001/\" against a /dev/bus/usb/001 dirfd is ENOTDIR");
    EXPECT_ERRNO(openat(dfd, "001/", O_RDWR), ENOTDIR,
                 "openat(/dev/bus/usb/001, \"001/\", O_RDWR)");

    /* Every other '..' is still applied before the layer sees the name, so
     * usbdev_open_path, which takes only the canonical spelling, gets it.
     */
    TEST("\"../001/001\" against a /dev/bus/usb/001 dirfd opens read-write");
    int fd = openat(dfd, "../001/001", O_RDWR);
    EXPECT_TRUE(fd >= 0, "openat(/dev/bus/usb/001, \"../001/001\", O_RDWR)");
    if (fd >= 0)
        close(fd);

    /* An absolute name keeps its '..' through path translation, so
     * sys_openat_path folds it for usbdev_open_path.
     */
    TEST("/dev/bus/usb/001/../001/001 opens read-write as the node");
    fd = open("/dev/bus/usb/001/../001/001", O_RDWR);
    EXPECT_TRUE(fd >= 0 && fd_names(fd, "/dev/bus/usb/001/001"),
                "open(\"/dev/bus/usb/001/../001/001\", O_RDWR)");
    if (fd >= 0)
        close(fd);

    TEST("an O_PATH open through '..' is named as the node");
    fd = open("/dev/bus/usb/001/../001/001", O_PATH);
    EXPECT_TRUE(fd >= 0 && fd_names(fd, "/dev/bus/usb/001/001"),
                "open(\"/dev/bus/usb/001/../001/001\", O_PATH)");
    if (fd >= 0)
        close(fd);

    TEST("/dev/bus/usb/001/../001/001/. is ENOTDIR");
    EXPECT_ERRNO(open("/dev/bus/usb/001/../001/001/.", O_RDWR), ENOTDIR,
                 "open(\"/dev/bus/usb/001/../001/001/.\", O_RDWR)");

    TEST("a climb from a /dev/bus/usb/001 dirfd reaches /sys");
    fd = openat(dfd, "../../../../sys/bus/usb/devices", O_RDONLY | O_DIRECTORY);
    EXPECT_TRUE(fd >= 0, "openat(/dev/bus/usb/001, \"../../../../sys/...\")");
    if (fd >= 0)
        close(fd);
    close(dfd);

    /* The retry folds the name up to the node, so the node is not folded away
     * and a walk from / or out of /dev still reaches the layer.
     */
    check_hostdir_openat("/dev", "bus/usb/001/001/..", ENOTDIR);
    check_hostdir_openat("/", "dev/bus/usb/001/001/..", ENOTDIR);
    check_hostdir_openat("/dev", "../dev/bus/usb/001/001/..", ENOTDIR);
    check_hostdir_openat("/", "dev/bus/usb/001", 0);
}

/* A '..' after a missing /dev/bus/usb name is ENOENT, absolute or relative to a
 * cwd, a dirfd or a host directory, as Linux fails the walk at the missing
 * name.
 */
static void check_dotdot_after_missing(void)
{
    static const char *const names[] = {
        "/dev/bus/usb/099/../001/001",
        "/dev/bus/usb/foo/../001/001",
        "/dev/bus/usb/001/foo/../001",
        "/dev/bus/usb/../usb/099/../001/001",
        "/dev/bus/../bus/usb/099/../001/001",
    };
    static const char *const relative[] = {
        "099/../001/001",
        "099/../../../null",
        "foo/..",
    };
    struct stat st;
    char what[96];

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(what, sizeof(what), "%s is ENOENT", names[i]);
        TEST(what);
        EXPECT_ERRNO(stat(names[i], &st), ENOENT, names[i]);
    }

    TEST("a read-write open of /dev/bus/usb/099/../001/001 is ENOENT");
    EXPECT_ERRNO(open("/dev/bus/usb/099/../001/001", O_RDWR), ENOENT,
                 "open(\"/dev/bus/usb/099/../001/001\", O_RDWR)");

    for (size_t i = 0; i < sizeof(relative) / sizeof(relative[0]); i++) {
        snprintf(what, sizeof(what), "\"%s\" in a /dev/bus/usb cwd is ENOENT",
                 relative[i]);
        TEST(what);
        if (chdir("/dev/bus/usb") != 0)
            FAIL("chdir /dev/bus/usb");
        else
            EXPECT_ERRNO(stat(relative[i], &st), ENOENT, relative[i]);
        if (chdir("/") != 0)
            FAIL("chdir back to /");
    }

    TEST("chdir(\"099/..\") in a /dev/bus/usb cwd is ENOENT");
    if (chdir("/dev/bus/usb") != 0)
        FAIL("chdir /dev/bus/usb");
    else
        EXPECT_ERRNO(chdir("099/.."), ENOENT, "chdir(\"099/..\")");
    if (chdir("/") != 0)
        FAIL("chdir back to /");

    check_hostdir_openat("/", "dev/bus/usb/099/../001", ENOENT);

    int dfd = open("/dev/bus/usb/001", O_RDONLY | O_DIRECTORY);
    TEST("\"../099/../001/001\" against a /dev/bus/usb/001 dirfd is ENOENT");
    if (dfd < 0) {
        FAIL("open /dev/bus/usb/001");
        return;
    }
    EXPECT_ERRNO(fstatat(dfd, "../099/../001/001", &st, 0), ENOENT,
                 "fstatat(/dev/bus/usb/001, \"../099/../001/001\")");

    TEST("\"../001/001\" against a /dev/bus/usb/001 dirfd is the node");
    EXPECT_TRUE(fstatat(dfd, "../001/001", &st, 0) == 0 && S_ISCHR(st.st_mode),
                "fstatat(/dev/bus/usb/001, \"../001/001\")");

    TEST(
        "\"../099/../001/001\" in a /dev/bus/usb/001 cwd from fchdir is "
        "ENOENT");
    if (fchdir(dfd) != 0)
        FAIL("fchdir /dev/bus/usb/001");
    else
        EXPECT_ERRNO(stat("../099/../001/001", &st), ENOENT,
                     "stat(\"../099/../001/001\")");
    if (chdir("/") != 0)
        FAIL("chdir back to /");
    close(dfd);
}

int main(void)
{
    printf("test-usb-sysfs: synthetic USB tree contract\n");

    check_tree_contract();
    check_slurp_reads_whole_files();
    int ndev = check_devices();
    check_dev_bus_names();
    check_dotdot_leaves_bus();
    check_node_dotdot_relative();
    check_dotdot_after_missing();

    /* Stated, not implied: the second half is only as strong as the bus it ran
     * against, and a zero here means those assertions did not execute.
     */
    printf("  devices examined: %d\n", ndev);

    SUMMARY("test-usb-sysfs");
    return fails > 0 ? 1 : 0;
}
