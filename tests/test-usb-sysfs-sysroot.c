/*
 * The synthetic USB /sys view sharing /sys with a populated sysroot
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Code under test: the /sys ours/not-ours split in src/runtime/usb-sysfs.c, the
 * /sys + /dev/bus arms of sys_fchdir (src/syscall/fs.c) and
 * resolve_proc_cwd_path (src/syscall/path.c), the /dev/bus climb rewrite in
 * usb_sysfs_resolve_dev_climb and path_translate_at, and the backing '..' in
 * path_backing_dotdot.
 *
 * Run under --sysroot over a tree that carries a real /sys skeleton
 * (/sys/class/net/eth0/address, /sys/kernel/mm/transparent_hugepage/enabled,
 * /sys/devices/system/node/online) and with ELFUSE_USB_FIXTURE set so the USB
 * tree carries two deterministic devices with no hardware attached.
 *
 * Four regressions are pinned here.
 *
 * F1: the USB layer synthesizes only /sys/bus/usb. A name it does not model
 * (everything under /sys/class, /sys/kernel, /sys/devices) must fall through to
 * the sysroot rather than be answered ENOENT, which would shadow the backing
 * /sys and leave the layer self-contradicting -- access() reading the sysroot
 * file as present while open() reports it absent. The cubic behavior that must
 * survive: /sys/bus/usb still serves the synthetic tree, and its attributes are
 * still epoll-addable (a real sysfs attribute is pollable through kernfs).
 *
 * F2: a descriptor opened on a synthetic /sys or /dev/bus directory is stamped
 * with the guest spelling. fchdir() onto it must publish that spelling as the
 * virtual cwd, or getcwd leaks the /tmp scratch location, a relative create
 * lands in the read-only tree, and fstatfs reports the /tmp filesystem instead
 * of sysfs. The cubic behavior that must survive: a relative walk resolved
 * against that cwd still reaches the synthetic attributes.
 *
 * F3: a '..' out of /dev/bus that ends the name must not let rmdir or rename
 * act on the sysroot's /dev, which the lane leaves empty, and one that lands in
 * /sys must reach the sysroot's files there.
 *
 * F4: a '..' after a sysroot /dev/bus directory fails with EACCES unless the
 * guest's IDs and groups may search it or the guest is root. F3 needs /dev
 * empty, so the lane adds directories at modes 000, 010 and 100 and runs the
 * guest with the argument search as uid 4242, then with search root under
 * --fakeroot.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define SYSFS_MAGIC 0x62656572

/* Read a whole small file; returns bytes read or -1. */
static ssize_t read_file(const char *path, char *buf, size_t bufsz)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, bufsz - 1);
    close(fd);
    if (n >= 0)
        buf[n] = '\0';
    return n;
}

static bool dir_has_entry(const char *dir, const char *name)
{
    DIR *d = opendir(dir);
    if (!d)
        return false;
    bool found = false;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, name)) {
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

/* may_lookup in fs/namei.c asks for search permission on the directory before
 * each component, a '..' included, and generic_permission lets root search any
 * directory.
 */
static void expect_search(int rc,
                          const struct stat *st,
                          const struct stat *want,
                          bool allowed,
                          const char *msg)
{
    if (!allowed)
        EXPECT_ERRNO(rc, EACCES, msg);
    else
        EXPECT_TRUE(
            rc == 0 && st->st_dev == want->st_dev && st->st_ino == want->st_ino,
            msg);
}

static void check_dotdot_search(bool root)
{
    struct stat node, bus, st;

    TEST("the guest is root only in the root run");
    EXPECT_TRUE((geteuid() == 0) == root, "geteuid()");

    TEST("/dev/bus/usb/001/001 is a char device");
    EXPECT_TRUE(stat("/dev/bus/usb/001/001", &node) == 0 &&
                    S_ISCHR(node.st_mode) && stat("/dev/bus", &bus) == 0,
                "stat(\"/dev/bus/usb/001/001\")");

    TEST("/dev/bus/other/../usb/001/001 is EACCES, the node for root");
    expect_search(stat("/dev/bus/other/../usb/001/001", &st), &st, &node, root,
                  "stat(\"/dev/bus/other/../usb/001/001\")");

    TEST("/dev/bus/other/.. is EACCES, /dev/bus for root");
    expect_search(stat("/dev/bus/other/..", &st), &st, &bus, root,
                  "stat(\"/dev/bus/other/..\")");

    int dfd = open("/dev/bus", O_RDONLY | O_DIRECTORY);
    TEST("\"other/../usb/001/001\" against a /dev/bus dirfd likewise");
    if (dfd < 0) {
        FAIL("open /dev/bus");
    } else {
        expect_search(fstatat(dfd, "other/../usb/001/001", &st, 0), &st, &node,
                      root, "fstatat(/dev/bus, \"other/../usb/001/001\")");
        close(dfd);
    }

    TEST("\"other/../usb/001/001\" in a /dev/bus cwd likewise");
    if (chdir("/dev/bus") != 0)
        FAIL("chdir /dev/bus");
    else
        expect_search(stat("other/../usb/001/001", &st), &st, &node, root,
                      "stat(\"other/../usb/001/001\")");

    /* grp's group is the host user's, which getgroups reports to a guest that
     * is not root, and its owner, the host user, has no x bit there.
     */
    TEST("/dev/bus/grp/../usb/001/001 is the node at mode 010");
    expect_search(stat("/dev/bus/grp/../usb/001/001", &st), &st, &node, true,
                  "stat(\"/dev/bus/grp/../usb/001/001\")");
    if (!root)
        return;

    /* Linux judges a lookup by the fsuid, which follows the euid. */
    TEST("/dev/bus/own/../usb/001/001 is EACCES with euid 4242");
    if (seteuid(4242) != 0) {
        FAIL("seteuid(4242)");
    } else {
        expect_search(stat("/dev/bus/own/../usb/001/001", &st), &st, &node,
                      false, "stat(\"/dev/bus/own/../usb/001/001\")");
        if (seteuid(0) != 0)
            FAIL("seteuid(0)");
    }

    /* The search is judged by the owner stat reports after a chown. */
    TEST("/dev/bus/own/../usb/001/001 is the node once own is 4242's");
    if (chown("/dev/bus/own", 4242, 4242) != 0 || seteuid(4242) != 0) {
        FAIL("chown or seteuid");
    } else {
        expect_search(stat("/dev/bus/own/../usb/001/001", &st), &st, &node,
                      true, "stat(\"/dev/bus/own/../usb/001/001\")");
        if (seteuid(0) != 0)
            FAIL("seteuid(0)");
    }
}

int main(int argc, char **argv)
{
    char buf[256];

    if (argc > 1 && !strcmp(argv[1], "search")) {
        bool root = argc > 2 && !strcmp(argv[2], "root");
        check_dotdot_search(root);
        SUMMARY(root ? "test-usb-sysfs-sysroot search root"
                     : "test-usb-sysfs-sysroot search");
        return fails ? 1 : 0;
    }

    printf(
        "test-usb-sysfs-sysroot: /sys fall-through and fchdir containment\n");

    /* F1: sysroot-backed /sys names reach the sysroot again */

    TEST("a /sys attribute we do not model opens from the sysroot");
    {
        ssize_t n = read_file("/sys/class/net/eth0/address", buf, sizeof(buf));
        if (n < 0)
            FAIL("open/read /sys/class/net/eth0/address");
        else if (strcmp(buf, "02:42:ac:11:00:02\n") != 0)
            FAIL("wrong /sys/class/net/eth0/address content");
        else
            PASS();
    }

    TEST("access() and open() agree on the sysroot /sys file");
    {
        int a = access("/sys/class/net/eth0/address", R_OK);
        int fd = open("/sys/class/net/eth0/address", O_RDONLY);
        if (a == 0 && fd >= 0)
            PASS();
        else
            FAIL("access/open disagree (readable but unopenable)");
        if (fd >= 0)
            close(fd);
    }

    TEST("readdir(/sys/class) lists the sysroot's entries");
    EXPECT_TRUE(dir_has_entry("/sys/class", "net"),
                "/sys/class did not list net");

    TEST("/sys/kernel attribute reaches the sysroot");
    EXPECT_TRUE(read_file("/sys/kernel/mm/transparent_hugepage/enabled", buf,
                          sizeof(buf)) > 0,
                "open /sys/kernel/mm/transparent_hugepage/enabled");

    TEST("/sys/devices attribute reaches the sysroot");
    EXPECT_TRUE(
        read_file("/sys/devices/system/node/online", buf, sizeof(buf)) > 0,
        "open /sys/devices/system/node/online");

    /* F1 cubic: /sys/bus/usb is still ours and still pollable */

    TEST("/sys/bus/usb/devices still serves the synthetic tree");
    {
        struct stat st;
        if (stat("/sys/bus/usb/devices", &st) == 0 && S_ISDIR(st.st_mode))
            PASS();
        else
            FAIL("stat /sys/bus/usb/devices");
    }

    TEST("a synthetic USB attribute reads its value");
    {
        ssize_t n =
            read_file("/sys/bus/usb/devices/1-1/idVendor", buf, sizeof(buf));
        if (n < 0)
            FAIL("open /sys/bus/usb/devices/1-1/idVendor");
        else if (strcmp(buf, "1d6b\n") != 0)
            FAIL("wrong idVendor");
        else
            PASS();
    }

    TEST("a synthetic USB attribute is still epoll-addable");
    {
        int afd = open("/sys/bus/usb/devices/1-1/idVendor", O_RDONLY);
        int ep = epoll_create1(0);
        struct epoll_event ev = {.events = EPOLLIN};
        int rc = -1;
        if (afd >= 0 && ep >= 0)
            rc = epoll_ctl(ep, EPOLL_CTL_ADD, afd, &ev);
        if (rc == 0)
            PASS();
        else
            FAIL("epoll_ctl ADD on a sysfs attribute (cubic 3862484162)");
        if (afd >= 0)
            close(afd);
        if (ep >= 0)
            close(ep);
    }

    /* A missing name under the subtree we own stays ENOENT, not a fall-through
     * (nothing in the sysroot carries it either, but the answer is ours).
     */
    TEST("a missing device under /sys/bus/usb is ENOENT");
    EXPECT_ERRNO(open("/sys/bus/usb/devices/9-9/idVendor", O_RDONLY), ENOENT,
                 "missing owned name should be ENOENT");

    /* F2: fchdir onto a synthetic /sys directory is contained */

    TEST("fchdir onto /sys/bus/usb/devices keeps the guest cwd");
    {
        int fd = open("/sys/bus/usb/devices", O_RDONLY | O_DIRECTORY);
        char cwd[256];
        if (fd < 0) {
            FAIL("open /sys/bus/usb/devices O_DIRECTORY");
        } else if (fchdir(fd) < 0) {
            FAIL("fchdir onto /sys/bus/usb/devices");
            close(fd);
        } else if (!getcwd(cwd, sizeof(cwd))) {
            FAIL("getcwd after fchdir");
            close(fd);
        } else if (strcmp(cwd, "/sys/bus/usb/devices") != 0) {
            FAIL("getcwd leaked the scratch tree location");
            close(fd);
        } else {
            PASS();
            close(fd);
        }
    }

    /* cwd is /sys/bus/usb/devices from here on. */

    TEST("a relative create against the /sys cwd cannot write the tree");
    EXPECT_ERRNO(open("intruder", O_WRONLY | O_CREAT, 0644), EACCES,
                 "relative O_CREAT should be refused, not land in the tree");

    TEST("fstatfs of a fd opened at the /sys cwd reports sysfs");
    {
        int fd = open(".", O_RDONLY | O_DIRECTORY);
        struct statfs sfs;
        if (fd < 0) {
            FAIL("open . at /sys cwd");
        } else if (fstatfs(fd, &sfs) < 0) {
            FAIL("fstatfs");
            close(fd);
        } else if ((unsigned) sfs.f_type != SYSFS_MAGIC) {
            FAIL("fstatfs did not report SYSFS_MAGIC (leaked /tmp fs)");
            close(fd);
        } else {
            PASS();
            close(fd);
        }
    }

    TEST("a relative walk against the /sys cwd reaches the attribute");
    {
        ssize_t n = read_file("1-1/idVendor", buf, sizeof(buf));
        if (n > 0 && strcmp(buf, "1d6b\n") == 0)
            PASS();
        else
            FAIL("relative 1-1/idVendor against the /sys cwd");
    }

    /* Linux refuses to remove or rename a final '..' (do_rmdir and do_renameat2
     * in fs/namei.c), whatever it resolves to.
     */
    TEST("rmdir and rename of /dev/bus/.. leave /dev in place");
    {
        struct stat st;
        if (rmdir("/dev/bus/..") == 0 ||
            rename("/dev/bus/..", "/dev-moved") == 0)
            FAIL("a final '..' out of /dev/bus was acted on");
        else if (stat("/dev", &st) != 0 || !S_ISDIR(st.st_mode))
            FAIL("stat(\"/dev\")");
        else
            PASS();
    }

    /* path_translate_at runs usb_sysfs_resolve_dev_climb before
     * usb_sysfs_resolve_guest_path, which applies a '..' after a subsystem link
     * to the link's target.
     */
    TEST(
        "a climb out of /dev/bus through a subsystem link reaches the sysroot");
    {
        ssize_t n = read_file(
            "/dev/bus/../../sys/bus/usb/devices/1-1/"
            "subsystem/../../class/net/eth0/address",
            buf, sizeof(buf));
        if (n < 0 || strcmp(buf, "02:42:ac:11:00:02\n") != 0)
            FAIL("read /sys/class/net/eth0/address through the climb");
        else
            PASS();
    }

    SUMMARY("test-usb-sysfs-sysroot");
    return fails ? 1 : 0;
}
