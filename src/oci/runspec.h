/* OCI launch-spec resolver for elfuse oci run
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Folds an image-config runtime block (User, WorkingDir, Entrypoint, Cmd,
 * Env) together with elfuse oci run CLI overrides into the concrete launch
 * bundle: guest cwd, argv, envp, and optional uid/gid credentials. The
 * module is pure data: no filesystem access, no PATH lookup, no syscalls.
 * That keeps the override matrix and the Env merge policy verifiable by a
 * unit test that constructs an oci_image_runtime_t literal directly.
 *
 * PATH search and rootfs materialization happen downstream, in
 * path-resolve and run. This builder treats argv[0] as opaque; the
 * caller downstream is responsible for resolving the host path the
 * guest will actually load.
 *
 * Override matrix (issue #31 acceptance 2): --entrypoint replaces the
 * image Entrypoint and the image Cmd is dropped whenever CLI
 * positional arguments are provided or --entrypoint is set. The
 * "image has neither Entrypoint nor Cmd and the CLI supplied no
 * positional arguments" case is the only hard-fail in the argv
 * assembly path.
 *
 * Env merge (issue #31 acceptance 3) starts from the image Env array,
 * applies CLI -e overrides (KEY=VAL set-or-replace; bare KEY imports the
 * matching host environ value when present and otherwise drops silently),
 * auto-imports TERM from the host when the merged Env has no TERM, injects
 * the Linux PAM-default PATH when no PATH key has been set, and finally
 * forces container=elfuse so systemd-style sandbox detection works
 * regardless of what the image declared. CLI overrides whose KEY starts
 * with DYLD_ hard-fail with EINVAL: DYLD_* is a macOS-only loader contract
 * and has no meaning inside the guest. Image-provided DYLD_* entries pass
 * through (aarch64 Linux ignores them); reviewers can escalate to strip
 * if needed.
 *
 * WorkingDir defaults to "/" when neither the image nor the CLI sets it.
 * Relative paths and any path containing a ".." segment hard-fail with
 * EINVAL; sysroot containment is enforced later by the path-resolve module
 * and the syscall layer.
 *
 * User accepts the seven shapes the OCI image-spec defines: empty (no
 * override), "uid", "uid:gid", "name", "name:group", "uid:group", and
 * "name:gid". Symbolic forms (anything other than the two pure-numeric
 * shapes) require flags->rootfs_for_nss; the resolver reads
 * <rootfs>/etc/passwd and <rootfs>/etc/group through oci_user_lookup
 * (see src/oci/user-lookup.h). When rootfs_for_nss is NULL the resolver
 * still accepts the pure-numeric forms; a symbolic token then returns
 * EINVAL so unit tests can hold runspec to its "pure data" contract by
 * passing NULL. CLI --user takes precedence over the image User; both
 * shapes go through the same lookup.
 *
 * Error reporting: on failure, the function writes a pointer into *err
 * that names what went wrong. The pointer is valid until the next call
 * from this thread. Static messages (the fixed strings) and dynamic
 * messages (those that quote the bad value) share the same lifetime
 * contract so the caller does not need to branch.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "manifest.h"

/* CLI overrides assembled by the oci run argument parser. NULL fields mean
 * "no override; defer to the image config". env_overrides is the literal
 * sequence of -e arguments (KEY=VAL or bare KEY); the merge logic below
 * walks it in order. positional_argv is the IMAGE-trailing argv tail
 * (everything after the image reference on the command line).
 */
typedef struct {
    const char *entrypoint_override;
    const char *const *env_overrides;
    size_t nenv_overrides;
    const char *workdir_override;
    const char *user_override;
    int positional_argc;
    const char *const *positional_argv;
    /* Directory the symbolic User resolver treats as "/" when reading
     * /etc/passwd and /etc/group. NULL keeps the builder pure-data: any
     * symbolic User token then returns EINVAL.
     */
    const char *rootfs_for_nss;
} oci_runspec_flags_t;

/* Resolved launch bundle. cwd is always set (defaults to "/"). argv and
 * envp are NULL-terminated heap arrays of heap strings. has_creds is
 * false when neither the image nor the CLI named a User; in that case the
 * caller leaves the host uid/gid untouched and uid/gid in this struct are
 * meaningless.
 */
typedef struct {
    char *cwd;
    char **argv;
    char **envp;
    uint32_t uid;
    uint32_t gid;
    bool has_creds;
} oci_runspec_t;

/* Resolve image runtime config + CLI overrides into a launch bundle.
 *
 * cfg may be NULL (treated as "image config has no runtime block": all
 * fields absent). flags must be non-NULL but may be zero-initialised.
 * host_environ is a NULL-terminated environ-shaped pointer for KEY=VAL
 * lookups; pass the process environ. out must be non-NULL; on entry it
 * is overwritten verbatim. On success returns 0 and out owns all heap
 * storage (call oci_runspec_free to release). On failure returns -1
 * with errno set (EINVAL for policy violations, ENOMEM for allocation
 * failures), *out left zeroed (safe to pass to oci_runspec_free), and
 * *err pointing at the diagnostic message.
 */
int oci_runspec_build(const oci_image_runtime_t *cfg,
                      const oci_runspec_flags_t *flags,
                      const char *const *host_environ,
                      oci_runspec_t *out,
                      const char **err);

/* Release any heap fields. Safe on zero-initialised structs and on NULL. */
void oci_runspec_free(oci_runspec_t *spec);
