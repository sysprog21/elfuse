/* elfuse oci run -- launch a guest binary from a pulled OCI image
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Closes the loop: unpack + clone-rootfs + image-config parse +
 * runspec build + PATH resolve + elfuse_launch under one subcommand.
 * The user runs an OCI image directly, with the image's
 * Entrypoint/Cmd/Env/WorkingDir/User honored as configured by the
 * image producer and overridable by the elfuse CLI.
 *
 * Dependencies:
 *
 *   - oci_unpack               -- layers -> image sysroot under the
 *                                  APFS sysroot volume
 *   - oci_clone_rootfs         -- clonefile-based per-run rootfs
 *   - oci_image_config_parse
 *   - oci_runspec_build        -- folds image config + CLI flags into
 *                                  argv/envp/cwd/uid bundle
 *   - oci_path_resolve         -- argv0 + PATH -> host_path/guest_path
 *                                  with sysroot containment
 *   - elfuse_launch            -- VM bring-up shared with main()
 *
 * Lifetime / cleanup contract:
 *
 *   - oci_run owns its intermediate state (run_dir, parsed manifest /
 *     config blobs, oci_runspec_t, resolved host_argv0). It frees
 *     everything before returning.
 *   - On success it removes the clone dir unless opts->keep_rootfs is
 *     set. On launch failure (elfuse_launch returns non-zero) it still
 *     removes the clone dir by default so a failed run does not leave
 *     stale clones on the volume.
 *   - host cwd is saved and restored across the call. The launch
 *     itself chdir's into <run_dir><spec.cwd> so the guest sees its
 *     WorkingDir as cwd.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "core/launch.h"

#include "manifest.h"
#include "ref.h"
#include "runspec.h"
#include "store.h"

/* Flags assembled by oci_cli_run from the elfuse oci run command line.
 * store_dir / volume_dir override the default Library/Application
 * Support paths; clone_name reserves a slot for a future deterministic
 * run-dir naming option that oci_clone_rootfs does not yet support,
 * so the field is currently ignored. spec carries every
 * runspec-relevant override (Entrypoint, -e, -w, -u, IMAGE, ARGV tail);
 * it is forwarded verbatim to oci_runspec_build.
 */
typedef struct {
    const char *store_dir;
    const char *volume_dir;
    oci_runspec_flags_t spec;
    bool keep_rootfs;
    const char *clone_name;
} oci_run_options_t;

/* `elfuse oci run` subcommand entry. Argument parsing, ref parse, store
 * open, oci_run dispatch. Returns a process exit code (0 success, 1 on
 * runtime failure, 2 on usage / argument error to match the rest of
 * src/oci/cli.c).
 */
int oci_cli_run(int argc, char **argv);

/* Programmatic entry: drive the full unpack -> clone -> runspec -> path
 * resolve -> elfuse_launch pipeline against an already-opened store and
 * parsed ref. host_environ is forwarded to oci_runspec_build for the
 * Env merge policy; pass the process environ. *err is populated with a
 * static diagnostic on failure; the pointer is valid until the next
 * call (or until oci_runspec_build / oci_path_resolve overwrite their
 * own thread-local buffer for a different diagnostic class).
 *
 * Returns:
 *   >= 0   exit code of the guest binary
 *    -1   pre-launch failure (unpack, clone, parse, runspec, path
 *         resolve, or directory materialization)
 */
int oci_run(oci_store_t *store,
            const oci_ref_t *ref,
            const oci_run_options_t *opts,
            const char *const *host_environ,
            const char **err);

/* Test hook: swap the underlying launch backend. Pass NULL to restore
 * the default (elfuse_launch). The override is process-global and
 * exists only so unit tests can run the orchestrator without spinning
 * up a real HVF VM. Production code must never call this.
 */
typedef int (*oci_run_launch_fn_t)(const launch_args_t *args);
void oci_run_set_launch_for_testing(oci_run_launch_fn_t fn);

/* Test hook: drive the manifest-resolution step (load blob, classify
 * index vs leaf, drill linux/arm64 on index, parse) in isolation. The
 * production caller is oci_run; this hook exists so unit tests can
 * verify the multi-arch index-walk without spinning up an APFS
 * sysroot volume. Output ownership matches the production internal
 * helper: caller frees *out_body and *out_mf via free() and
 * oci_manifest_free() respectively. Production code must use oci_run.
 */
int oci_run_resolve_image_manifest_for_testing(oci_store_t *store,
                                               const char *digest_str,
                                               char **out_body,
                                               size_t *out_len,
                                               oci_manifest_t *out_mf,
                                               const char **err);
