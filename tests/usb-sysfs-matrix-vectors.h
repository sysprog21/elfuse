/*
 * Measured Linux answers for tests/test-usb-sysfs-matrix.c
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Recorded on Linux, not reasoned about: docker gcc:14 (aarch64, kernel 7.0)
 * over a real sysfs, with /dev/bus/other/f created and /dev/bus/usb/001/001
 * mknod'd as char 189:0. See the header comment in the test for the exact
 * command; MATRIX_RECORD=1 prints this block.
 *
 * Columns, in order, with the path each names:
 *
 *   synth-dir   /sys/bus/usb/devices
 *               a directory the layer synthesizes
 *   back-sys    /sys/class
 *               a /sys name only the backing has
 *   back-dev    /dev/bus/other/f
 *               a /dev/bus name only the backing has
 *   subsys      <dev>/subsystem, discovered
 *               a subsystem symlink
 *   escape      /sys/class/../../etc/hostname
 *               a '..' chain out of the tree
 *   escape-syn  /sys/bus/usb/../../../etc/hostname
 *               the same, through the synthetic subtree
 *   usb-node    /dev/bus/usb/001/001
 *               a usbfs device node
 *   absent      /sys/no-such-name-here
 *               absent on both sides
 *   long-sys    a >63-byte spelling of an attribute, discovered
 *               longer than the virtual-path stamp a descriptor carries
 *   sys-root    /sys
 *               synthetic and backed at once
 *   dev-bus     /dev/bus
 *               synthetic and backed at once
 *   shadow      /dev/bus/usb/099/001
 *               a backing name planted inside a subtree this layer owns
 *   subsys-out  <dev>/subsystem/../pci, discovered
 *               a walk through the subsystem link and back out of the one
 *               subtree this layer owns
 *   dev-fold-out /dev/bus/usb/../other/f
 *               back-dev's file, spelled through the subtree this layer owns
 *   dev-fold-in /dev/bus/other/../usb/001/001
 *               usb-node's node, spelled through a bus this layer does not
 *               model
 *   sys-fold-in /sys/class/../bus/usb/devices
 *               synth-dir's directory, spelled through a /sys name only the
 *               backing has
 *   dev-climb   /dev/bus/usb/001/../../..
 *               out of /dev/bus over the layer's directories
 *   dev-climb-f /dev/bus/other/f/../../../null
 *               the same, after back-dev's file
 *   node-dotdot /dev/bus/usb/001/001/..
 *               usb-node's node followed by '..'
 *   shadow-dotdot /dev/bus/usb/099/../../other/f
 *               back-dev's file, spelled through shadow's bus directory,
 *               which only the backing has
 *
 * Two markers appear in the table.
 *
 * "-" is a cell the recording host cannot present, so no Linux value exists to
 * hold the guest to. All eight are the usb node, four under each of its two
 * spellings: a mknod'd node with no usb device behind it cannot be opened there
 * (the container's device cgroup answers EPERM, and an unbound minor would
 * answer ENODEV anyway), so open, open_nofollow, openat and epoll_ctl on it
 * were never measured. Every other usb-node and dev-fold-in cell is measured --
 * they come from the node's directory entry rather than from opening it.
 *
 * "?" is a cell whose Linux value was measured and that elfuse knowingly does
 * not meet; the lane prints it as XFAIL instead of failing. They fall in two
 * columns, escape-syn and sys-fold-in, and both are one fact seen from opposite
 * ends: a folded /sys spelling that crosses this layer's boundary cannot
 * re-enter path translation, whichever way it crosses.
 *
 * escape-syn is a '..' chain that walks through the synthetic subtree and back
 * out, which cannot be resolved here. The lexical fold recognizes that the name
 * leaves /sys and hands it to the host walk, but the host walk has to traverse
 * /sys/bus/usb, which exists only inside this layer: the lane's sysroot /sys
 * carries no bus/usb. The name therefore answers ENOENT where Linux resolves
 * it. Fixing it means having the folded spelling re-enter path translation,
 * which is a path-layer change rather than an ownership one. The neighboring
 * escape column, whose chain transits only backing directories, is asserted
 * normally.
 *
 * sys-fold-in is the same fact walked the other way, and it is the /sys mirror
 * of dev-fold-in. /sys/class/../bus/usb/devices folds to a name this layer owns
 * and does serve, so ownership is decided correctly, but the resolve that
 * follows joins the unfolded suffix onto the scratch tree, which has no class,
 * so the lookup fails and the layer reports its own authoritative ENOENT.
 * Eighteen entry points answer E2 where Linux resolves the name. statfs is the
 * one cell that matches, and it matches because its test is the lexical /sys
 * prefix rather than a lookup. The listing side says the same thing from the
 * other end: /sys lists bus and /sys/class/.. does not.
 *
 * The /sys half cannot be repaired by folding before classify, as the /dev half
 * is: usb_sys_resolve_suffix has to see the '..' in their original positions to
 * order them against the subsystem symlinks. Making these cells green means
 * having the folded spelling re-enter path translation, the same path-layer
 * change escape-syn needs.
 */

/* clang-format off */
/*                       synth-dir  back-sys  back-dev  subsys  escape  escape-syn  usb-node  absent  long-sys  sys-root  dev-bus  shadow  subsys-out  dev-fold-out  dev-fold-in  sys-fold-in  dev-climb  dev-climb-f  node-dotdot  shadow-dotdot */
/* open               */ {"ok",      "ok",     "ok",     "ok",   "ok",   "?ok",      "-",      "E2",   "ok",     "ok",     "ok",    "E2",   "ok",       "ok",         "-",         "?ok",       "ok",      "E20",       "E20",       "E2"},
/* open_nofollow      */ {"ok",      "ok",     "ok",     "E40",  "ok",   "?ok",      "-",      "E2",   "ok",     "ok",     "ok",    "E2",   "ok",       "ok",         "-",         "?ok",       "ok",      "E20",       "E20",       "E2"},
/* openat_dirfd       */ {"ok",      "ok",     "ok",     "ok",   "ok",   "?ok",      "-",      "E2",   "ok",     "skip",   "ok",    "skip", "ok",       "ok",         "-",         "?ok",       "ok",      "skip",      "skip",      "skip"},
/* stat               */ {"ok:d",    "ok:d",   "ok:f",   "ok:d", "ok:f", "?ok:f",    "ok:c",   "E2",   "ok:f",   "ok:d",   "ok:d",  "E2",   "ok:d",     "ok:f",       "ok:c",      "?ok:d",     "ok:d",    "E20",       "E20",       "E2"},
/* lstat              */ {"ok:d",    "ok:d",   "ok:f",   "ok:l", "ok:f", "?ok:f",    "ok:c",   "E2",   "ok:f",   "ok:d",   "ok:d",  "E2",   "ok:d",     "ok:f",       "ok:c",      "?ok:d",     "ok:d",    "E20",       "E20",       "E2"},
/* fstatat_nofollow   */ {"ok:d",    "ok:d",   "ok:f",   "ok:l", "ok:f", "?ok:f",    "ok:c",   "E2",   "ok:f",   "ok:d",   "ok:d",  "E2",   "ok:d",     "ok:f",       "ok:c",      "?ok:d",     "ok:d",    "E20",       "E20",       "E2"},
/* fstatat_dirfd      */ {"ok:d",    "ok:d",   "ok:f",   "ok:d", "ok:f", "?ok:f",    "ok:c",   "E2",   "ok:f",   "skip",   "ok:d",  "skip", "ok:d",     "ok:f",       "ok:c",      "?ok:d",     "ok:d",    "skip",      "skip",      "skip"},
/* statx              */ {"ok:d",    "ok:d",   "ok:f",   "ok:d", "ok:f", "?ok:f",    "ok:c",   "E2",   "ok:f",   "ok:d",   "ok:d",  "E2",   "ok:d",     "ok:f",       "ok:c",      "?ok:d",     "ok:d",    "E20",       "E20",       "E2"},
/* access             */ {"ok",      "ok",     "ok",     "ok",   "ok",   "?ok",      "ok",     "E2",   "ok",     "ok",     "ok",    "E2",   "ok",       "ok",         "ok",        "?ok",       "ok",      "E20",       "E20",       "E2"},
/* faccessat_nofollow */ {"ok",      "ok",     "ok",     "ok",   "ok",   "?ok",      "ok",     "E2",   "ok",     "ok",     "ok",    "E2",   "ok",       "ok",         "ok",        "?ok",       "ok",      "E20",       "E20",       "E2"},
/* readlink           */ {"E22",     "E22",    "E22",    "ok",   "E22",  "?E22",     "E22",    "E2",   "E22",    "E22",    "E22",   "E2",   "E22",      "E22",        "E22",       "?E22",      "E22",     "E20",       "E20",       "E2"},
/* readlinkat_dirfd   */ {"E22",     "E22",    "E22",    "ok",   "E22",  "?E22",     "E22",    "E2",   "E22",    "skip",   "E22",   "skip", "E22",      "E22",        "E22",       "?E22",      "E22",     "skip",      "skip",      "skip"},
/* getdents64         */ {"ok",      "ok",     "E20",    "ok",   "E20",  "?E20",     "E20",    "E2",   "E20",    "ok",     "ok",    "E2",   "ok",       "E20",        "E20",       "?ok",       "ok",      "E20",       "E20",       "E2"},
/* statfs             */ {"sysfs",   "sysfs",  "other",  "sysfs","other","?other",   "other",  "E2",   "sysfs",  "sysfs",  "other", "E2",   "sysfs",    "other",      "other",     "sysfs",     "other",   "E20",       "E20",       "E2"},
/* fstatfs            */ {"sysfs",   "sysfs",  "other",  "sysfs","other","?other",   "other",  "E2",   "sysfs",  "sysfs",  "other", "E2",   "sysfs",    "other",      "other",     "?sysfs",    "other",   "E20",       "E20",       "E2"},
/* fstat_type         */ {"ok:d",    "ok:d",   "ok:f",   "ok:l", "ok:f", "?ok:f",    "ok:c",   "E2",   "ok:f",   "ok:d",   "ok:d",  "E2",   "ok:d",     "ok:f",       "ok:c",      "?ok:d",     "ok:d",    "E20",       "E20",       "E2"},
/* chdir              */ {"ok",      "ok",     "E20",    "ok",   "E20",  "?E20",     "E20",    "E2",   "E20",    "ok",     "ok",    "E2",   "ok",       "E20",        "E20",       "?ok",       "ok",      "E20",       "E20",       "E2"},
/* fchdir             */ {"ok",      "ok",     "E20",    "ok",   "E20",  "?E20",     "E20",    "E2",   "E20",    "ok",     "ok",    "E2",   "ok",       "E20",        "E20",       "?ok",       "ok",      "E20",       "E20",       "E2"},
/* epoll_ctl          */ {"E1",      "E1",     "E1",     "E1",   "E1",   "?E1",      "-",      "E2",   "ok",     "E1",     "E1",    "E2",   "E1",       "E1",         "-",         "?E1",       "E1",      "E20",       "E20",       "E2"},
/* union_listing      */ {"n/a",     "n/a",    "n/a",    "n/a",  "n/a",  "n/a",      "n/a",    "n/a",  "n/a",    "all",    "all",   "n/a",  "n/a",      "n/a",        "n/a",       "n/a",       "n/a",     "n/a",       "n/a",       "n/a"},
    /* clang-format on */
