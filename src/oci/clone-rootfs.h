/* OCI per-run rootfs via clonefile(2)
 *
 * Implements APFS clonefile-based copy-up: each `elfuse oci clone`
 * invocation gets a fresh directory tree cloned from the immutable
 * image sysroot. APFS file-level CoW makes the clone nearly O(1) at
 * start, and only modified files allocate new blocks.
 *
 * Apple's clonefile(2) is recursive across directories since macOS
 * 10.12. Hardlinks inside the source tree survive the clone metadata
 * pass; cross-tree hardlinks back to the immutable image are NOT
 * created, so the layer applier must materialize intra-image
 * hardlinks via link(2) rather than relying on the clone.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stddef.h>
#include <time.h>

/* Clone the immutable image directory at src_image_dir into a fresh
 * run directory under volume_root/runs/. On success *out_run_dir
 * receives a heap-allocated absolute path (caller frees) and returns
 * 0. On failure returns -1 with errno set and *err populated.
 *
 * Errors:
 *   ENOTSUP   the volume does not support APFS clones (non-APFS
 *             scratch or a future fs without clonefile)
 *   ENOSPC    sparsebundle full
 *   EACCES    volume read-only or run_dir creation denied
 *   ENAMETOOLONG  generated run_dir path overflows the buffer
 */
int oci_clone_rootfs(const char *src_image_dir,
                     const char *volume_root,
                     char **out_run_dir,
                     const char **err);

/* Recursively remove a run directory previously returned by
 * oci_clone_rootfs. Best effort: returns 0 on full removal, -1 on
 * the first irrecoverable error.
 */
int oci_clone_rootfs_remove(const char *run_dir, const char **err);

/* Sweep volume_root/runs/ for stale clones older than older_than
 * (epoch seconds). Currently a stub returning 0; `elfuse oci prune`
 * does not yet call this, and a future change will walk the
 * directory for real.
 */
int oci_clone_rootfs_gc(const char *volume_root,
                        time_t older_than,
                        const char **err);
