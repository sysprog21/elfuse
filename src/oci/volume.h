/* OCI sysroot volume provisioning
 *
 * `oci unpack` needs a case-sensitive APFS filesystem for layers whose
 * paths differ only by case. On macOS the default boot volume is
 * case-insensitive, so elfuse provisions its own sparsebundle at
 * <home>/Library/Application Support/elfuse/sysroots.sparsebundle and
 * mounts it at <home>/Library/Application Support/elfuse/sysroots/.
 *
 * The bootstrap delegates to src/core/sysroot.h (PR #33) so the
 * hdiutil orchestration stays in one place; this module adds the
 * default-location resolver and the case-sensitivity gate that
 * `--volume DIR` overrides must pass.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

/* Resolve and provision the OCI sysroot volume.
 *
 * override_dir:
 *   NULL  -> use the default location under $HOME/Library/Application
 *            Support/elfuse/sysroots/, creating a sparsebundle and
 *            attaching it on first use. Subsequent calls reuse the
 *            existing mount point.
 *   non-NULL -> validate via sysroot_probe_case_sensitivity and accept
 *               only if the host directory is case-sensitive. Returns
 *               -1 with errno=EINVAL and *err set otherwise.
 *
 * On success, *out_volume_root is set to a heap-allocated absolute
 * path (caller frees with free). On failure returns -1 with errno set
 * and *err pointing to a static description.
 */
int oci_volume_ensure(const char *override_dir,
                      char **out_volume_root,
                      const char **err);

/* Create or verify a subdirectory under the volume root. Used to
 * provision `images/`, `runs/`, and `images/.staging/`. Returns 0 on
 * success and writes the resolved absolute path into *out_path (caller
 * frees). Returns -1 with errno set and *err populated on failure.
 */
int oci_volume_subdir(const char *volume_root,
                      const char *name,
                      char **out_path,
                      const char **err);

/* One entry yielded by oci_volume_list_unpacked: an absolute path to
 * an unpacked image tree (no trailing slash). Owned by the enclosing
 * list and freed via oci_volume_list_free.
 */
typedef struct {
    char **items;
    size_t count;
} oci_volume_list_t;

/* Enumerate every unpacked image tree under <volume_root>/images/.
 * Filters: only entries shaped sha256-<lowercase-hex> are returned;
 * the .staging/ subdirectory and any dotfiles are skipped silently.
 * Returns 0 on success with *out populated; an empty store yields
 * count == 0 and items == NULL. A missing or unreachable volume_root
 * is treated as the empty case (count == 0) rather than an error so
 * that fresh stores without any unpacked sysroots can be enumerated
 * without disturbing the volume provisioning path. Returns -1 with
 * errno set and *err populated on IO failure traversing an existing
 * images/ directory.
 */
int oci_volume_list_unpacked(const char *volume_root,
                             oci_volume_list_t *out,
                             const char **err);

/* Release every item path in list and zero the struct. Safe on a
 * zero-initialised list and on NULL.
 */
void oci_volume_list_free(oci_volume_list_t *list);
