/* OCI guest PATH resolver inside a cloned rootfs
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Resolves a guest argv[0] against the merged guest PATH while keeping the
 * lookup contained inside the per-run cloned rootfs. The function is the
 * pre-launch bridge between oci_runspec_build (which decides what argv
 * and what PATH the guest should see) and elfuse_launch (which expects
 * a host filesystem path to open):
 *
 *   - host_path is the absolute host path elfuse should open() to load
 *     the guest binary. It is the candidate exactly as found via PATH or
 *     directly via argv0; symlinks are NOT collapsed because the guest
 *     loader (and any execve() the guest runs internally) want to see the
 *     name they were invoked under, not the real path. Containment checks
 *     do use realpath internally; only the result handed back to the caller
 *     stays in symlink form.
 *
 *   - guest_path is the guest-absolute path the guest itself thinks it is
 *     running (for argv0[0], for /proc/self/exe, for whatever a tool wants
 *     to learn about its own name). For PATH-search results it is
 *     <PATH_entry>/<argv0>; for direct-mode results it is argv0 itself
 *     (absolute) or cwd_guest/argv0 (relative with '/').
 *
 * Containment policy: every candidate path is fed to realpath(3) and the
 * resolved absolute path must equal sysroot_dir or start with
 * sysroot_dir + '/'. Symlink chains that resolve outside the sysroot are
 * silently skipped (the PATH search continues) so a malicious or sloppy
 * image layer cannot trick elfuse into loading a host-side binary. This
 * matches how Docker's runc treats escape symlinks: drop them from the
 * search instead of failing the entire launch.
 *
 * Executability is decided by host stat(2) (follows symlinks) against
 * st_mode & 0111. PATH search records the first found-but-not-executable
 * candidate and surfaces EACCES if no later entry succeeds, mirroring
 * execvp's "first noexec wins" behaviour.
 *
 * The module deliberately does NOT reuse src/syscall/path.c's
 * path_translate_at: that resolver is tied to the running guest's live
 * sysroot/cwd plumbing, while this resolver runs before the vCPU starts
 * and therefore needs a self-contained containment check.
 */

#pragma once

/* Resolve argv0 against PATH inside sysroot_dir.
 *
 * sysroot_dir must exist and be a directory; it is realpath'd once at
 * entry so the containment check is stable across symlinks in the
 * sysroot prefix itself. argv0 follows POSIX execvp semantics: when it
 * contains '/' the PATH is bypassed and argv0 is resolved directly
 * (absolute argv0 as a guest-absolute path, relative argv0 anchored to
 * cwd_guest). When argv0 has no '/', path_env is split on ':' and each
 * entry is treated as a guest-absolute directory (empty entries fall
 * back to cwd_guest, matching POSIX).
 *
 * cwd_guest may be NULL; "/" is used in that case. path_env may be NULL
 * or empty for the no-slash argv0 path -- the result is then a clean
 * ENOENT with an empty searched-dirs annotation.
 *
 * On success returns 0 and writes heap-allocated *out_host_path and
 * *out_guest_path. The caller frees both. On failure returns -1 with
 * errno set (ENOENT for "not found", EACCES for "found but not
 * executable", EINVAL for argument errors, ENOMEM for allocation) and
 * leaves *out_host_path / *out_guest_path NULL. *err points at a
 * diagnostic string; the pointer is valid until the next call from this
 * thread. The diagnostic carries argv0 verbatim (quoted) and, for PATH
 * search misses, a colon-separated list of the directories that were
 * actually probed.
 */
int oci_path_resolve(const char *sysroot_dir,
                     const char *argv0,
                     const char *path_env,
                     const char *cwd_guest,
                     char **out_host_path,
                     char **out_guest_path,
                     const char **err);

/* Expand a shebang chain on an already-resolved executable.
 *
 * host_path points at the malloc'd host path oci_path_resolve handed back
 * for argv[0]; argv points at the malloc'd NULL-terminated guest argv whose
 * argv[0] is the matching guest-absolute path. When the file at *host_path
 * starts with "#!", the interpreter (and its single optional argument) is
 * resolved inside sysroot_dir under the same containment policy as
 * oci_path_resolve and prepended to *argv, and *host_path is swapped for
 * the interpreter's host path -- the same argv rewrite execve(2) performs.
 * Chains recurse up to 5 interpreter levels, matching the standalone
 * loader's limit in main.c.
 *
 * Returns 0 on success -- including the common "not a script" case, which
 * leaves *host_path and *argv untouched. Returns -1 with errno set (ELOOP
 * for recursion overflow, ENOEXEC for a malformed shebang line, or as set
 * by the interpreter resolution) and *err pointing at a diagnostic with
 * the same lifetime rules as oci_path_resolve.
 */
int oci_shebang_expand(const char *sysroot_dir,
                       const char *cwd_guest,
                       char **host_path,
                       char ***argv,
                       const char **err);
