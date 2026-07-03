/* Shared helpers for the OCI subsystem
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * One home for the error-reporting and filesystem-walk helpers that every
 * OCI translation unit used to carry its own copy of. Error strings follow
 * the subsystem-wide convention: *err (when non-NULL) points at a static
 * string or at a thread-local buffer that stays valid until the next
 * formatted-error call from the same thread; callers consume it before
 * making further OCI calls.
 */

#pragma once

#include <errno.h>
#include <stddef.h>

/* Record a static error message and errno, returning -1 so call sites can
 * `return set_err(...)` in one expression. err may be NULL.
 */
static inline int set_err(const char **err, const char *msg, int err_no)
{
    if (err)
        *err = msg;
    errno = err_no;
    return -1;
}

/* Point *err at a static message (no errno side effect, no return value);
 * the void-returning twin of set_err for callers that manage errno
 * themselves.
 */
void oci_err_static(const char **err, const char *msg);

/* Format into a thread-local buffer and point *err at it. The buffer is
 * shared per-thread across the OCI subsystem: the string stays valid until
 * the next oci_err_fmt call from the same thread.
 */
__attribute__((format(printf, 2, 3))) void oci_err_fmt(const char **err,
                                                       const char *fmt,
                                                       ...);

/* mkdir -p: create every directory along path with mode 0755. An existing
 * directory at any level is fine; an existing non-directory fails with
 * ENOTDIR. Returns 0 on success, -1 with errno set otherwise.
 */
int oci_mkdir_p(const char *path);

/* Recursively remove a file, symlink, or directory tree. Symlinks are
 * removed, never followed (lstat discipline). Returns 0 on success or when
 * path was already absent; -1 with errno set on any unexpected IO error.
 * Designed for staging/scratch cleanup, not as a general-purpose rm.
 */
int oci_rm_recursive(const char *path);

/* oci_rm_recursive relative to dirfd: remove the entry named 'name'
 * (file, symlink, or directory tree) without ever resolving 'name' or
 * any descendant through a symlink (fstatat / unlinkat / openat with
 * AT_SYMLINK_NOFOLLOW / O_NOFOLLOW throughout). Returns 0 on success or
 * when the entry was already absent; -1 with errno set otherwise.
 */
int oci_rm_recursive_at(int dirfd, const char *name);
