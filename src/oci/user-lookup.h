/* OCI image-config User field resolver
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the OCI image-spec User field (issue #31) beyond the
 * numeric shapes runspec.c alone accepts. The User string the image
 * carries is one of seven shapes:
 *
 *   ""              -> caller treats as has_creds=false (no override).
 *   "uid"           -> numeric uid; gid defaults to uid (matches the
 *                      "primary group falls through to user id" convention
 *                      runc applies when no NSS resolution is available).
 *   "uid:gid"       -> both numeric.
 *   "name"          -> rootfs/etc/passwd lookup; gid is the primary gid
 *                      from the passwd entry's fourth field.
 *   "name:group"    -> passwd lookup + rootfs/etc/group lookup.
 *   "uid:group"     -> numeric uid + group lookup.
 *   "name:gid"      -> passwd lookup + numeric gid.
 *
 * All-ASCII-digit tokens are parsed numerically even when a same-named
 * passwd entry exists (runc semantics: the digit form wins). This avoids
 * surprising lookups against images that happen to ship a "1234" account.
 *
 * Symbolic forms require a rootfs path so the resolver can read
 * rootfs/etc/passwd and rootfs/etc/group. When rootfs is NULL the
 * resolver still accepts the two pure-numeric shapes; any symbolic token
 * returns -1 with err set so the caller can route the failure to its
 * own diagnostic. A symbolic form with a rootfs whose /etc/passwd is
 * missing also fails closed (no silent fallback to root): the typical
 * cause is the image config naming an account the unpacked layers do
 * not actually carry, and silent fallback would mask that.
 *
 * The function is pure-C, host-native, and does not touch HVF. It is
 * suitable for both pre-launch resolution (the runspec hookup adds a
 * rootfs_for_nss field that points at the per-run clone-rootfs) and for
 * direct unit tests against scratch /tmp rootfses.
 */

#ifndef ELFUSE_OCI_USER_LOOKUP_H
#define ELFUSE_OCI_USER_LOOKUP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Resolve user_str (the OCI image-config User field or the elfuse oci run
 * --user override) to numeric uid/gid.
 *
 * rootfs is the directory the symbolic lookup treats as "/" (typically the
 * per-run clone-rootfs). Passing NULL is allowed for pure-numeric callers;
 * any symbolic component then returns -1 with err set to a diagnostic that
 * names the offending token.
 *
 * Returns 0 on success with *uid_out / *gid_out populated. Returns -1 with
 * errno=EINVAL and *err pointing at a thread-local diagnostic on any parse
 * or lookup failure. The diagnostic pointer stays valid until the next
 * call from the same thread.
 */
int oci_user_lookup(const char *rootfs,
                    const char *user_str,
                    uint32_t *uid_out,
                    uint32_t *gid_out,
                    const char **err);

#ifdef __cplusplus
}
#endif

#endif /* ELFUSE_OCI_USER_LOOKUP_H */
