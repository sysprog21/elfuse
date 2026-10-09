/*
 * Shared guest/host path handling
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

#include "syscall/internal.h"

typedef enum {
    PATH_TR_NONE = 0,
    PATH_TR_NOFOLLOW = 1u << 0,
    PATH_TR_CREATE = 1u << 1,
    PATH_TR_CREATE_PARENTS = 1u << 2,
} path_translate_flags_t;

/* AT_SYMLINK_NOFOLLOW, already extracted by the caller as a plain int/bool,
 * translated to the matching PATH_TR flag. Callers pass either a raw "flags &
 * LINUX_AT_SYMLINK_NOFOLLOW" or an already-named nofollow bool.
 */
static inline path_translate_flags_t path_tr_nofollow(int nofollow)
{
    return nofollow ? PATH_TR_NOFOLLOW : PATH_TR_NONE;
}

typedef struct {
    const char *guest_path;
    const char *intercept_path;
    const char *host_path;
    int proc_resolved;
    bool fuse_path;

    /* Path was rewritten into the /dev/shm host backing dir. Follow-capable
     * callers must force nofollow; see dev_shm_resolve_path() in procemu.c.
     */
    bool is_dev_shm;
    char proc_path[LINUX_PATH_MAX];
    char guest_buf[LINUX_PATH_MAX];
    char host_buf[LINUX_PATH_MAX];
} path_translation_t;

/* Host dirfd for a *at() call on a translated path. A shm redirect gives an
 * absolute host path, so use AT_FDCWD (POSIX ignores dirfd for absolute paths).
 */
static inline host_fd_t path_translation_dirfd(const path_translation_t *tx,
                                               const host_fd_ref_t *ref)
{
    return tx->is_dev_shm ? AT_FDCWD : ref->fd;
}

/* A FUSE-backed path has no host file behind it, so a path op that cannot be
 * served over the FUSE transport answers ENOSYS.
 *
 * Returns INT64_MIN when the translation is not FUSE-backed, which is the
 * caller's cue to carry on.
 */
static inline int64_t reject_unsupported_fuse_path_op(
    const path_translation_t *tx)
{
    return tx && tx->fuse_path ? -LINUX_ENOSYS : INT64_MIN;
}

/* Force AT_SYMLINK_NOFOLLOW on the *at metadata calls for a shm redirect. One
 * choke point for the never-follow invariant; see dev_shm_resolve_path().
 */
static inline int path_translation_at_flags(const path_translation_t *tx,
                                            int at_flags)
{
    return tx->is_dev_shm ? (at_flags | AT_SYMLINK_NOFOLLOW) : at_flags;
}

/* True when path equals prefix exactly, or extends it with '/'. Avoids the
 * surprise where "/sys/devices/system/cpufoo" would match a bare strncmp on
 * "/sys/devices/system/cpu" and pull an unrelated path through the intercept
 * layer.
 */
bool path_prefix_match(const char *path, const char *prefix, size_t plen);

/* Whether @path ends in the directory requirement Linux attaches to a trailing
 * slash or a final ".": the name has to resolve to a directory, and a final
 * symlink is followed to get there.
 */
bool path_dir_required(const char *path);

/* @path without that requirement, into @buf when there was one to take off, or
 * @path itself when there was not. The intercepts match names literally and
 * enforce the requirement for themselves; getcwd reports the directory.
 */
const char *path_bare_name(const char *path, char *buf, size_t bufsz);

/* Advance *pathp to the next '/'-separated component, skipping empty segments
 * from repeated slashes.
 *
 * Returns true with the component (not NUL-terminated) reported through comp
 * and len, leaving *pathp at its end; returns false once only slashes or the
 * terminating NUL remain.
 *
 * Inline beside path_component_copy, its usual companion, so a leaf module can
 * walk a path without linking the rest of the translation layer.
 */
static inline bool path_next_component(const char **pathp,
                                       const char **comp,
                                       size_t *len)
{
    const char *p = *pathp;

    while (*p == '/')
        p++;
    if (*p == '\0') {
        *pathp = p;
        return false;
    }

    *comp = p;
    while (*p != '\0' && *p != '/')
        p++;
    *len = (size_t) (p - *comp);
    *pathp = p;
    return true;
}

/* Copy a counted component (not NUL-terminated, as path_next_component reports)
 * into dst and NUL-terminate it.
 *
 * Returns 0, or -1 with errno set to ENAMETOOLONG when the component does not
 * fit. dst is typically a NAME_MAX+1 buffer, so this also unifies the "len >
 * NAME_MAX" and "len >= sizeof(dst)" bound checks the callers used to spell
 * inconsistently.
 */
static inline int path_component_copy(char *dst,
                                      size_t dstsz,
                                      const char *comp,
                                      size_t len)
{
    if (len >= dstsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(dst, comp, len);
    dst[len] = '\0';
    return 0;
}

bool path_might_use_open_intercept(const char *path);
bool path_might_use_stat_intercept(const char *path);

/* Whether Linux gives the file behind this intercepted path a poll method.
 * epoll_ctl asks it because fstat describes elfuse's staging file rather than
 * the file the guest named. Enumerates the same surface as
 * path_might_use_open_intercept and belongs next to it: an intercept added to
 * one without the other is a target answered from the wrong object.
 */
bool path_intercept_poll_capable(const char *path);
int path_check_intercept_access(const struct stat *st, int mode, int flags);

/* Resolve a guest path against dirfd into every spelling a syscall handler
 * needs, and fill tx with them.
 *
 * This is the one place a guest name becomes a host name. A handler that
 * reaches the host with a path it assembled itself has bypassed the sysroot
 * redirect and the containment check together.
 *
 *                         ┌────────────┐
 *                         │ guest path │
 *                         └────────────┘
 *                                │
 *                    ┌───────────▾──────────┐
 *                    │ proc or FUSE rewrite │
 *                    └──────────────────────┘
 *           ┌──────────────────┘ │ └─────────────────┐
 *           │                    │                   │
 *           │                   ┌┘                   │
 *   ┌───────▾──────┐   ┌────────▾────────┐   ┌───────▾───────┐
 *   │ dev/shm leaf │   │ sysroot resolve │   │ fd magic link │
 *   └──────────────┘   └─────────────────┘   └───────────────┘
 *           │                   └┐                   └─┐
 *           │                    │                     │
 *          ┌┘                    │                     │
 *   ┌──────▾──────┐   ┌──────────▾──────────┐   ┌──────▾──────┐
 *   │ backing dir │   │ containment recheck │   │ the fd path │
 *   └─────────────┘   └─────────────────────┘   └─────────────┘
 *                                │
 *                        ┌───────▾───────┐
 *                        │ casefold walk │
 *                        └───────────────┘
 *
 * tx carries three spellings and they are not interchangeable. guest_path is
 * what the guest asked for, after the /proc and FUSE rewrites; intercept_path
 * is what the synthetic-filesystem intercepts match against; host_path is what
 * reaches a macOS syscall. Only host_path moves down the pipeline.
 *
 * The two side arms return with host_path already final, skipping sysroot
 * resolution deliberately rather than by omission; each says why where it is
 * taken. flags choose which sysroot resolver runs (create, nofollow, or
 * follow), and the same choice decides whether the casefold walk follows its
 * final component. The last two steps run for a relative path only: an absolute
 * one was already contained by the resolver and has no dirfd to be measured
 * against.
 *
 * Returns 0 with tx filled, or -1 with errno set. A NULL path is not an error;
 * every spelling comes back NULL and the caller's own AT_EMPTY_PATH handling
 * decides what that means.
 */
int path_translate_at(guest_fd_t dirfd,
                      const char *path,
                      unsigned int flags,
                      path_translation_t *tx);

/* Longest symlink chain a resolution may follow before reporting ELOOP, as
 * Linux does (include/linux/namei.h). Shared so the path layer and the sysroot
 * resolvers cannot disagree about when a chain has gone on too long.
 */
#ifndef MAXSYMLINKS
#define MAXSYMLINKS 40
#endif

/* Splice a symlink target back into a path being resolved: @target followed by
 * whatever of the original path was left unconsumed. @prefix is prepended for a
 * relative target only, and names the directory holding the link; pass NULL
 * when the caller re-anchors another way. One copy, because the concatenation
 * is where a spliced path could be silently shortened into a different one.
 *
 * Returns 0, or -1 with errno set to ENAMETOOLONG.
 */
int path_splice_link_target(const char *prefix,
                            size_t prefix_len,
                            const char *target,
                            const char *rest,
                            char *out,
                            size_t outsz);

/* Convert a host path to the guest path naming the same object: strip the
 * sysroot prefix, and decode any component the volume made elfuse store under
 * an escape. The result is what the guest must be shown for its own cwd, and it
 * has to be a path the guest can hand straight back to chdir(2).
 *
 * Returns 0, or -1 with errno set to ENAMETOOLONG when @out is too small.
 */
int path_host_to_guest(const char *host_path, char *out, size_t outsz);

/* True when the directory behind @host_dirfd is one whose entries elfuse may
 * have stored escaped: a folding sysroot is configured and the directory's
 * canonical host path lies under it. One answer per directory read, not per
 * entry: the answer is a property of the directory, and F_GETPATH is a syscall.
 * When the fd's path cannot be read the answer is false: decoding is a claim
 * that elfuse wrote the name, so it needs the directory proven inside the
 * sysroot, or a foreign escape-shaped entry decodes into a phantom name no
 * lookup can resolve. The directory-unlinked-while-open failure lists nothing
 * either way, and the residual cost of failing closed, a live in-sysroot
 * directory that lost its path showing stored spellings, at least shows names
 * that open.
 */
bool path_dirent_dir_holds_escapes(host_fd_t host_dirfd);

/* Decode one on-disk entry name to the guest-visible spelling.
 * @dir_holds_escapes is the caller's per-directory answer from
 * path_dirent_dir_holds_escapes(); when false every name means itself.
 * Returns 0, or -1 with errno set: ENAMETOOLONG for a host name no guest dirent
 * or event buffer could carry, which is the one failure a caller with real
 * arguments sees; a missing argument is EINVAL.
 */
int path_translate_dirent_name(bool dir_holds_escapes,
                               const char *host_name,
                               char *guest_name,
                               size_t guest_name_sz);

/* Rebase a relative path against a host directory fd into the guest-visible
 * absolute spelling (F_GETPATH + sysroot strip + dot-folding).
 *
 * Returns 1 with out filled, 0 when no mapping exists. See path.c for the
 * chase() rationale.
 */
int path_rebase_hostdirfd(int host_dirfd,
                          const char *rel,
                          char *out,
                          size_t outsz);

int resolve_proc_at_path(guest_fd_t dirfd,
                         const char *path,
                         char *out,
                         size_t outsz);
int resolve_proc_dirfd_path(guest_fd_t dirfd,
                            const char *path,
                            char *out,
                            size_t outsz);
int sys_path_has_symlink(guest_fd_t dirfd, const char *path);

const char *path_resolve_sysroot_path(const char *path,
                                      char *buf,
                                      size_t bufsz);
const char *path_resolve_sysroot_nofollow_path(const char *path,
                                               char *buf,
                                               size_t bufsz);
const char *path_resolve_sysroot_create_path(const char *path,
                                             char *buf,
                                             size_t bufsz,
                                             bool create_parents);

bool path_openat2_stays_beneath(const char *path, bool clamp_at_root);
int path_openat2_normalize_in_root(const char *path, char *out, size_t outsz);
bool path_openat2_is_fd_magiclink_anchor(guest_fd_t dirfd, const char *path);
int path_openat2_resolved_within_root(guest_fd_t dirfd,
                                      const char *path,
                                      uint64_t oflags,
                                      bool in_root);

/* Returns 1 if resolving path against dirfd would cross a mount boundary from
 * the guest's perspective, 0 if it stays inside the same logical filesystem,
 * and -1 with errno set on dirfd lookup failures. Mount classes are: regular
 * guest filesystem, /proc, /dev, /sys, /tmp, /dev/shm, and each live or
 * tombstoned FUSE mount (keyed by mount_id). The walker classifies every
 * intermediate prefix as it advances, so transient excursions through /proc
 * that lexically resolve back into the root class still surface as a crossing.
 * Symlink components are expanded inline against the host-walk fd when possible
 * so a link whose target lives in a different class is caught at the precheck.
 *
 * When out_start_class is non-NULL it is populated with the dirfd's mount class
 * on every non-error return so the caller can re-run the check against the
 * actually opened fd via path_openat2_check_fd_xdev. The post-open check is
 * what closes the symlink bypass for callers that do not also set
 * RESOLVE_NO_SYMLINKS: the precheck's fstatat walk probes each component by its
 * stored spelling, and on a case-fold sysroot that spelling can change between
 * the precheck and the open, so the kernel may follow a link the walker did
 * not, and only F_GETPATH on the resulting fd reveals the real landing site.
 *
 * Known gaps (best-effort by design):
 * - path_host_to_guest strips the configured sysroot prefix with
 *    a case-sensitive strncmp; on case-insensitive macOS volumes a
 *    differently-cased F_GETPATH could fail to strip and the dirfd is
 *    then classified as the root class. Sysroots that happen to live
 *    under /proc, /dev, or /sys on the host are not supported.
 * - A sibling vCPU that chdir(2)s, dup3(2)s over dirfd, or mounts /
 *    unmounts a FUSE filesystem between this check and the subsequent
 *    sys_openat may shift the resolution into a different mount class
 *    without the cross being detected. The race window is narrow and
 *    the guest is in elfuse's trust domain.
 */
int path_openat2_crosses_mount(guest_fd_t dirfd,
                               const char *path,
                               bool in_root,
                               int *out_start_class);

/* Post-open verification for RESOLVE_NO_XDEV. Reads the host-side canonical
 * path of the just-opened guest fd via fcntl(F_GETPATH), strips the sysroot
 * prefix, and classifies the result against the start class captured by
 * path_openat2_crosses_mount.
 *
 * Returns 1 if the resolved fd sits in a different mount class than the
 * resolution started in, 0 if it stays in the same class, -1 with errno set on
 * lookup failures (e.g. fd closed, F_GETPATH refused). Catches the
 * symlink-driven crossings that the string-only precheck misses by design.
 */
int path_openat2_check_fd_xdev(int guest_fd, int start_class);

/* Parse a numeric procfs component the way Linux's name_to_int() does: decimal
 * digits only, so no sign, no leading whitespace, and no leading zero unless
 * the name is "0" itself. The kernel runs both the pid and the fd component
 * through it, so both get the same rules here. strtol() accepts all three
 * spellings, which made "/proc/self/fd/+3", "/proc/self/fd/03", "/proc/self/fd/
 * 3" and the matching pid forms resolve here while Linux reports ENOENT for
 * each.
 *
 * Returns the value, or -1 when the name is not that shape. The caller applies
 * its own upper bound and errno.
 */
int path_parse_proc_name(const char *name);

/* The guest descriptor an absolute fd magic link names, or -1 when the path is
 * not that shape. Unlike path_fd_magiclink_open this hands back the guest fd
 * number itself, for callers that need the table entry rather than the object:
 * opening one of these paths produces a second name for a description the
 * process already holds, so the new slot has to inherit that entry's answers
 * instead of probing (see fd_alias_host_shared).
 */
int path_fd_magiclink_guest_fd(const char *path);

/* Fill *ref with a reference to the descriptor an absolute fd magic link names
 * ("/proc/self/fd/<n>", the own-pid spelling, "/dev/fd/<n>", "/dev/std*").
 *
 * Returns 0, or -1 when the path is not that shape or its descriptor is not
 * backed by a plain host object. On success the caller must hand *ref to
 * host_fd_ref_close and must not close ref->fd itself: this is the guest's own
 * descriptor, borrowed, not a private duplicate. Closing it directly would shut
 * the guest's fd, and on a file the guest has locked it would drop every record
 * lock the process holds on it.
 *
 * Metadata syscalls should act on this rather than on the translated pathname.
 * Linux resolves the magic link inside the syscall, so nothing can redirect it;
 * resolving to a pathname and operating on it a moment later can land on a
 * different inode if the file is renamed, or unlinked and recreated, in
 * between.
 */
int path_fd_magiclink_open(const char *path, host_fd_ref_t *ref);

/* The same, and *entry is the table entry the reference was taken on, read
 * under the same fd_lock hold. For a caller whose answer depends on what the
 * descriptor carries, such as its seals. *entry is unspecified on -1.
 */
int path_fd_magiclink_open_entry(const char *path,
                                 host_fd_ref_t *ref,
                                 fd_entry_t *entry);
