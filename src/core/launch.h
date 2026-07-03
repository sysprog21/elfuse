/* elfuse VM launch entry: post-CLI bring-up + run loop + teardown
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * elfuse_launch is the single entry point for "run a guest binary in a
 * fresh HVF VM until it exits". It is shared between main() (legacy
 * positional-ELF CLI) and the oci run orchestrator. The function
 * owns the guest_t, the vCPU, the GDB stub, and the run loop; it does NOT
 * own the elf_path / sysroot / guest_argv heap copies or the
 * sysroot_mount the host CLI may have provisioned -- those stay with the
 * caller so behaviors that need the original CLI argv (proctitle
 * rewriting, --create-sysroot detach on exit, host cwd save+restore)
 * remain coherent regardless of how the launch was kicked off.
 *
 * Lifetime / ownership contract:
 *
 *   - The caller owns every pointer in launch_args_t. elfuse_launch reads
 *     them and does not free them; const-qualified pointers stay valid
 *     for the duration of the call.
 *   - envp may be NULL; the host process environ is used in that case.
 *   - guest_argv is the NULL-terminated string array the guest sees as
 *     its argv. It must already be heap-copied because the caller may
 *     have clobbered the original CLI argv with proctitle.
 *   - has_creds=false means "inherit the host uid/gid"; uid/gid are
 *     ignored. has_creds=true forces the elfuse guest identity model
 *     via proc_set_ids.
 *   - cwd_guest reserves a slot for oci run to set
 *     the guest's initial working directory. main()'s legacy positional-
 *     ELF path passes NULL and the guest inherits the host cwd, matching
 *     pre-refactor behavior.
 *   - fork_child_fd / vfork_notify_fd are forwarded for future
 *     fork-child-routed launches; main() currently dispatches the
 *     fork-child path before reaching elfuse_launch and so passes -1.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    /* Host filesystem path to the guest ELF (absolute). */
    const char *elf_path;
    /* Host filesystem path to the sysroot the guest sees as / (absolute),
     * or NULL when the guest runs without a sysroot.
     */
    const char *sysroot;
    /* NULL-terminated guest argv shape. guest_argc is the count of
     * non-NULL entries (matches the legacy main() call shape).
     */
    int guest_argc;
    const char **guest_argv;
    /* NULL-terminated guest environ. NULL means "use host environ". */
    const char **envp;
    /* Override host uid/gid when true. Set from the image User field
     * when the oci run orchestrator resolves credentials; main()'s
     * legacy path leaves it false.
     */
    bool has_creds;
    uint32_t uid;
    uint32_t gid;
    /* Guest-absolute initial working directory. NULL inherits the host
     * cwd. Wired up by the oci run orchestrator.
     */
    const char *cwd_guest;
    /* GDB Remote Serial Protocol port. 0 disables the stub. */
    int gdb_port;
    bool gdb_stop_on_entry;
    /* Per-iteration vCPU run timeout. 0 disables (no alarm()). */
    int timeout_sec;
    /* Fork-child IPC handles. -1 means "not a fork child". main()'s
     * --fork-child dispatch handles the >= 0 case before reaching
     * elfuse_launch; oci run never sets these.
     */
    int fork_child_fd;
    int vfork_notify_fd;
    bool verbose;
} launch_args_t;

/* Bring up the guest VM, run it to exit / signal / timeout, tear down,
 * return the exit code. Returns 1 on bring-up failure (with a log
 * message) and the guest's exit status otherwise.
 */
int elfuse_launch(const launch_args_t *args);
