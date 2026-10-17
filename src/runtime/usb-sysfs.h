/*
 * Synthetic /dev/bus/usb + /sys/bus/usb built from the IOKit registry
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Stage 1 of the usbdevfs emulation: enumeration only. The IOKit registry is
 * read without opening any device (GetConfigurationDescriptorPtr needs no
 * open), and the result is materialized as two scratch-dir trees that the
 * procemu interceptors expose as /sys/bus/usb and /dev/bus/usb.
 *
 * The intercept functions follow the procemu contract:
 *   open:      host fd on match, -1 with errno on error,
 *              PROC_NOT_INTERCEPTED (-2) when the path is not ours.
 *   stat:      0 on match (st filled), -1 with errno, -2 not ours.
 *   readlink:  link length on match, -1 with errno, -2 not ours.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

struct guest;

int usb_sysfs_intercept_open(const char *path, int linux_flags, int mode);

/* `follow` selects stat() vs lstat() semantics for a symlink leaf: with it set,
 * a `subsystem` link reports the directory it resolves to, as on Linux; without
 * it the link itself is reported.
 */
int usb_sysfs_intercept_stat(const char *path, struct stat *st, bool follow);
int usb_sysfs_intercept_readlink(const char *path, char *buf, size_t bufsiz);

/* True when @guest_path names a directory this layer serves but does not own,
 * so its listing has to be the union of the synthetic entries and whatever the
 * host/sysroot backing carries under the same name.
 *
 * /sys and /dev/bus exist on both sides: a Linux sysroot has class/, devices/,
 * kernel/ under /sys and other buses under /dev/bus, while this layer adds only
 * bus/usb and usb. Serving the synthetic directory alone made getdents64
 * replace that listing rather than extend it, so `ls /sys` saw an almost-empty
 * sysfs while every hidden name stayed openable by its exact path --
 * enumeration and direct access disagreed.
 *
 * False for the one subtree this layer does own, /sys/bus/usb and /dev/bus/usb:
 * there an absence is authoritative (lookup answers ENOENT rather than falling
 * through), so the listing has to be authoritative too.
 */
bool usb_sysfs_dir_unions_backing(const char *guest_path);

/* Rewrite @guest_path into the canonical guest spelling of the object it names,
 * when its walk passes *through* one of the synthetic `subsystem` symlinks this
 * layer plants and continues past it.
 *
 * Those links are the only way a /sys walk can leave this layer's subtree
 * without saying so lexically: `<dev>/subsystem` points at /sys/bus/usb, so
 * `<dev>/subsystem/../pci` names /sys/bus/pci, exactly as the kernel resolves
 * it. Deciding ownership on the lexical fold instead reads that name as
 * `<dev>/pci`, claims it as ours because it starts with bus/usb, and answers
 * ENOENT -- shadowing a populated backing /sys/bus/pci that the *listing* of
 * `<dev>/subsystem/..` had just offered. Resolving first, once, in the path
 * layer, is what keeps the listing and every lookup answering from the same
 * name.
 *
 * A link named as the final component is left alone: it is the object the
 * caller asked for, and lstat, readlink and O_NOFOLLOW must keep seeing it.
 *
 * Returns 1 with @out filled, or 0 when no rewrite applies (including when the
 * link named does not exist, so a missing device stays ENOENT).
 */
int usb_sysfs_resolve_guest_path(const char *guest_path,
                                 char *out,
                                 size_t outsz);

/* Whether a fold of a relative name stops at the folded guest name @guest_path:
 * every name under /dev/bus/usb except /dev/bus/usb itself and a bus directory
 * the layer has, since Linux applies '..' only to a directory that exists. It
 * takes usb_lock to look a bus directory up.
 */
bool usb_sysfs_stops_fold(const char *guest_path);

/* The canonical /dev/bus/usb/BBB/DDD spelling of @guest_path when it names a
 * usbfs node once its '.' and '..' are folded as the stat intercept folds them.
 * usbdev_open_path takes only that spelling. A name that ends in the directory
 * requirement path_dir_required reports is left to the intercepts, which answer
 * ENOTDIR for a node.
 *
 * Returns true with @out filled, or false when @guest_path names no node or the
 * folded name does not fit @outsz.
 */
bool usb_sysfs_node_path(const char *guest_path, char *out, size_t outsz);

/* Rewrite a /dev/bus name that climbs out of /dev/bus with '..', popping only
 * directories the layer serves, to /dev followed by what comes after the '..'
 * that climbed, or to /dev/. when nothing does. Those directories are the
 * layer's, and the macOS host has no /dev/bus at all, so the '..' cannot be
 * left to the backing. A further '..' is applied to /dev and stops at the root.
 * A '..' after a bus no device has, or after a name under /dev/bus/usb that is
 * not a bus or device number, fails the walk, as on Linux; one after a node, a
 * name below a node or a name outside /dev/bus/usb is left as written.
 *
 * Returns 1 with @out filled, 0 when nothing is rewritten, or -1 with errno set
 * to ENOENT for a '..' that fails the walk.
 */
int usb_sysfs_resolve_dev_climb(const char *guest_path,
                                char *out,
                                size_t outsz);

/* Malloc'd copy of the usbfs descriptors blob (18-byte little-endian device
 * descriptor followed by every raw configuration descriptor in index order) for
 * the device at busnum/devnum. This is the exact byte sequence read() returns
 * on the /dev/bus/usb node and on the sysfs `descriptors` attribute; stage 2's
 * usbdevfs fd constructor must serve reads from this generator so the two views
 * stay byte-identical.
 *
 * Returns the blob (caller frees) with *len_out set, or NULL with errno set
 * (ENODEV when no such device).
 */
uint8_t *usb_sysfs_descriptors_dup(int busnum, int devnum, size_t *len_out);

/* The guest /sys or /dev/bus spelling of the object an open descriptor holds,
 * for stamping a synthetic identity on it.
 *
 * The name the guest opened is not always the name it got: a subsystem link
 * opened for following names the directory it resolves to, and every relative
 * openat off that descriptor must walk from there. Asking the descriptor
 * instead of the request is what makes the two agree: F_GETPATH reports the
 * link's own path for the O_PATH|O_NOFOLLOW open that deliberately named the
 * link, and the target's path for every open that followed it. Under /dev/bus
 * the request may spell a '..' the layer applied, and the descriptor names the
 * directory it reached.
 *
 * Returns 1 with @out filled, or 0 when the descriptor is in neither synthetic
 * tree (including when the trees do not exist).
 */
int usb_sysfs_guest_path_for_fd(int host_fd, char *out, size_t outsz);

/* Identity snapshot of one enumerated device, for the stage-2 usbdevfs fd
 * (syscall/usbdev.c): location_id keys the IOKit service lookup, speed_code is
 * the raw registry 'Device Speed' code, cfg_value the active
 * bConfigurationValue, minor the usbfs char-dev minor. vid/pid/serial carry the
 * modeled identity so the fd constructor can verify the service it looked up by
 * location is still the device this bus/dev number was modeled from (locationID
 * names the port, not the device).
 */
typedef struct {
    uint32_t location_id;
    unsigned speed_code;
    unsigned cfg_value;
    int minor;
    size_t blob_len;
    unsigned vid, pid;
    char serial[128]; /* "" when the device reports none */
} usb_sysfs_devinfo_t;

/* Fill *out for the device at busnum/devnum.
 *
 * Returns 0, or -1 with errno set (ENODEV when no such device).
 */
int usb_sysfs_device_info(int busnum, int devnum, usb_sysfs_devinfo_t *out);

/* Synthesize the char-dev stat for /dev/bus/usb/BBB/DDD (same bytes the path
 * stat intercept reports).
 *
 * Returns 0, or -1 with errno set.
 */
int usb_sysfs_node_stat(int busnum, int devnum, struct stat *st);
