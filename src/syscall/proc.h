/*
 * Process state and management
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Owns all static process state (PIDs, shim blob, ELF path, cmdline, process
 * table). Provides accessor functions so other modules (runtime/forkipc,
 * syscall/exec, runtime/procemu) can interact with this state without direct
 * access.
 *
 * Also contains wait4/waitid and the vCPU run loop.
 */

#pragma once

#include <Hypervisor/Hypervisor.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/types.h>

#include "core/guest.h"
#include "core/elf.h"

/* Process state. */

/* Initialize the process subsystem. */
void proc_init(void);

/* Get/set current guest PID and PPID. */
int64_t proc_get_pid(void);
int64_t proc_get_ppid(void);

/* Linux child-subreaper state, published through the fork-family registry. */
void proc_set_child_subreaper(bool enabled);
bool proc_get_child_subreaper(void);

typedef struct {
    const char *path;
    size_t len;
    bool locked;
} proc_cwd_view_t;

int proc_acquire_cwd_view(proc_cwd_view_t *view);
void proc_release_cwd_view(proc_cwd_view_t *view);
int proc_cwd_refresh(void);
void proc_cwd_set_virtual(const char *path);
void proc_cwd_invalidate(void);

/* Store shim blob pointer/size (called from main.c at startup). Avoids
 * #including shim_blob.h in this module.
 */
void proc_set_shim(const unsigned char *blob, unsigned int len);

/* Like proc_set_shim but takes ownership of the malloc'd blob. Used by
 * fork_child_main which allocates the blob from IPC.
 */
void proc_set_shim_owned(unsigned char *blob, unsigned int len);

/* Get shim blob pointer (for exec and fork IPC). */
const unsigned char *proc_get_shim_blob(void);
unsigned int proc_get_shim_size(void);

/* Store the current ELF binary path for /proc/self/exe emulation. Called from
 * main.c at startup and after execve.
 */
void proc_set_elf_path(const char *path);

/* Get the stored ELF binary path.
 *
 * Returns NULL if not set. The returned pointer references shared mutable state
 * and is safe only for boolean tests; callers that consume the string must use
 * proc_elf_path_snapshot.
 */
const char *proc_get_elf_path(void);

/* Copy the stored ELF binary path into out.
 *
 * Returns true on success, false if no path is set or outsz is too small.
 * Locked against concurrent proc_set_elf_path() so the returned content is
 * consistent.
 */
bool proc_elf_path_snapshot(char *out, size_t outsz);

/* Store the absolute path of the elfuse binary itself. Used to spawn fork/clone
 * children. Set once at startup via _NSGetExecutablePath().
 */
void proc_set_elfuse_path(const char *path);

/* Get the stored elfuse binary path. Returns NULL if not set. */
const char *proc_get_elfuse_path(void);

/* Process-wide feature gate for x86_64-via-Rosetta support. */
void proc_set_rosetta_enabled(bool enabled);
bool proc_rosetta_enabled(void);

/* Runtime indicator: true once the guest_t has been initialized in rosetta
 * mode. Distinct from proc_rosetta_enabled which reflects the user opt-in. Code
 * paths that lack direct guest_t access (proc_intercept_readlink) can branch on
 * the runtime state without threading g through every signature.
 */
void proc_set_rosetta_active(bool active);
bool proc_rosetta_active(void);

/* Process-wide feature gate for fakeroot mode. */
void proc_set_fakeroot_enabled(bool enabled);
bool proc_fakeroot_enabled(void);

/* Opt-in escape hatch letting a guest-initiated exec enter fakeroot mode.
 * Without it fakeroot can only be turned on before the first image runs
 * (--fakeroot / ELFUSE_FAKEROOT), so a guest shell has no way to raise
 * privilege for a single command the way sudo does on Linux.
 *
 * path names the one executable allowed to make that transition, as an absolute
 * path resolved the way the guest resolves paths: under --sysroot the sysroot
 * spelling and the host spelling of one file both name that file, because the
 * match is on file identity rather than on the string (see
 * proc_fakeroot_exec_path). Returns false without arming anything for NULL, an
 * empty string, a relative path, or one that does not fit.
 *
 * Startup only. The stored path is read without a lock by every vCPU thread
 * that reaches execve, so this must be called before any of them exists;
 * calling it later is a data race.
 */
bool proc_set_fakeroot_exec_path(const char *path);

/* The configured fakeroot exec path, or NULL when none was armed.
 *
 * The caller resolves and stats it to compare against the file it actually
 * opened, so any spelling that reaches that file elevates and a spelling that
 * reaches a different file does not. What elevates is therefore an inode, not a
 * name: replacing the file at the configured path replaces what elevates, and
 * moving the marked executable away disarms the hatch.
 *
 * The elevation this feeds is not per-command. Nothing ever clears the fakeroot
 * gate, so the marked image, everything it execs afterwards, and everything it
 * forks all stay root -- the same shape as a sudo child, not a one-shot.
 */
const char *proc_fakeroot_exec_path(void);

/* Stage the initial guest credentials (--user) before proc_init.
 * proc_identity_init applies them in place of the GUEST_UID/GUEST_GID
 * defaults, so the auxv AT_UID/AT_GID snapshot taken by build_linux_stack
 * matches what getuid()/getgid() later report. The staged value is consumed
 * by the next proc_identity_init, so it applies to a single bring-up only.
 */
void proc_set_initial_ids(uint32_t uid, uint32_t gid);

/* Drop a staged --user value that no proc_identity_init consumed. A launch
 * that fails between proc_set_initial_ids and proc_init would otherwise
 * leave the value staged, and the next bring-up in the same host process
 * would apply the failed launch's identity instead of the defaults.
 */
void proc_clear_initial_ids(void);

/* Store the guest command line for /proc/self/cmdline emulation. argv is a
 * NULL-terminated array of strings.
 */
void proc_set_cmdline(int argc, const char **argv);

/* Set cmdline from a raw pre-formatted buffer (NUL-separated args). Used by
 * fork_child_main to restore parent's cmdline from IPC.
 */
void proc_set_cmdline_raw(const char *buf, size_t len);

/* Get the stored cmdline buffer and its length. Returns NULL if not set. */
const char *proc_get_cmdline(size_t *len_out);

/* Store the guest environment for /proc/self/environ emulation. envp is a
 * NULL-terminated array of "KEY=val" strings.
 */
void proc_set_environ(const char **envp);

/* Get the stored environ buffer (NUL-separated). Returns NULL if not set. */
const char *proc_get_environ(size_t *len_out);

/* Store the guest auxiliary vector for /proc/self/auxv emulation. data is the
 * raw auxv key-value pairs as pushed on the stack.
 */
void proc_set_auxv(const void *data, size_t len);

/* Get the stored auxv buffer. Returns NULL if not set. */
const void *proc_get_auxv(size_t *len_out);

/* Set guest identity (called from fork_child_main). */
void proc_set_identity(int64_t pid, int64_t ppid);

/* Session / process-group state. Accessors are lock-free (_Atomic); syscall
 * writers serialize with session_lock.
 */
int64_t proc_get_sid(void);
int64_t proc_get_pgid(void);
int64_t proc_get_fg_pgrp(void);

/* Publish the current pgid/sid pair into the shim cache while holding
 * session_lock. Use this at cache initialization points so an external snapshot
 * cannot overwrite a newer setpgid/setsid publish.
 */
void proc_publish_pgsid_snapshot(guest_t *g);

/* Restore session/pgid from fork IPC. */
void proc_set_session(int64_t sid, int64_t pgid);

/* Refresh pgid from the fork-family registry after a parent-side setpgid. */
void proc_set_pgid_from_registry(guest_t *g, int64_t pgid);

/* setsid: create new session and publish pgid/sid cache under session_lock.
 * Returns SID or -LINUX_EPERM.
 */
int64_t proc_sys_setsid(guest_t *g);

/* setpgid: set process group and publish pgid/sid cache under session_lock.
 * Returns 0 or negative errno.
 */
int64_t proc_sys_setpgid(guest_t *g, int64_t pid, int64_t pgid);

/* getsid: query session ID. Returns SID or -LINUX_ESRCH. */
int64_t proc_sys_getsid(int64_t pid);

/* TTY job control. */
void proc_set_fg_pgrp(int64_t pgrp);
void proc_set_ctty(int has_ctty);

/* Emulated UID/GID accessors. */
uint32_t proc_get_uid(void);
uint32_t proc_get_euid(void);
uint32_t proc_get_suid(void);
uint32_t proc_get_gid(void);
uint32_t proc_get_egid(void);
uint32_t proc_get_sgid(void);

/* Linux setuid semantics for non-root processes: setuid(@uid) : set euid only
 * (non-root cannot change ruid/suid) setreuid(r,e) : swap real/effective within
 * {ruid, euid, suid} setresuid(r,e,s) : set any combination within {ruid, euid,
 * suid}
 * Returns 0 on success, -EPERM if transition is not allowed.
 */
int64_t proc_sys_setuid(uint32_t uid);
int64_t proc_sys_setgid(uint32_t gid);
int64_t proc_sys_setreuid(uint32_t ruid, uint32_t euid);
int64_t proc_sys_setregid(uint32_t rgid, uint32_t egid);
int64_t proc_sys_setresuid(uint32_t ruid, uint32_t euid, uint32_t suid);
int64_t proc_sys_setresgid(uint32_t rgid, uint32_t egid, uint32_t sgid);

/* Restore UID/GID state from fork IPC. */
void proc_set_ids(uint32_t uid,
                  uint32_t euid,
                  uint32_t suid,
                  uint32_t gid,
                  uint32_t egid,
                  uint32_t sgid);

/* Emulated nice value for setpriority/getpriority coherence. */
int32_t proc_get_nice(void);
void proc_set_nice(int32_t val);
bool proc_pid_alive(int pid);

/* setpriority/getpriority: only PRIO_PROCESS is modeled. getpriority accepts
 * any live task ID but reports the process-global emulated nice value.
 * setpriority is kept self-only until elfuse tracks per-task nice state.
 * setpriority clamps prio to [-20, 19]. getpriority returns 20-nice (always
 * > 0 per Linux convention).
 */
int64_t proc_sys_setpriority(int which, int who, int prio);
int64_t proc_sys_getpriority(int which, int who);

/* rseq abort: check if the thread is inside a restartable sequence critical
 * section and abort it. Called from signal delivery and vCPU preemption.
 * Returns: 0 = no active critical section (or no rseq registered)
 *           1 = PC redirected to abort_ip (*pc updated)
 *          -1 = signature mismatch (caller should deliver SIGSEGV)
 * Always clears rseq_cs pointer in the guest struct rseq.
 */
int rseq_try_abort(guest_t *g,
                   uint64_t rseq_gva,
                   uint32_t rseq_signature,
                   uint64_t *pc);

/* Allocate next guest PID (called from sys_clone). */
int64_t proc_alloc_pid(void);

/* Store the sysroot path for absolute guest path resolution. Pass NULL to
 * clear.
 */
void proc_set_sysroot(const char *path);

/* Get the stored sysroot path.
 *
 * Returns NULL if not set.
 *
 * The returned pointer aliases a static buffer mutated by proc_set_sysroot()
 * under a private lock; callers that only test for NULL are safe, but any
 * caller that reads the string content must use proc_sysroot_snapshot() instead
 * to avoid a torn read against a concurrent chroot.
 */
const char *proc_get_sysroot(void);

/* Copy the current sysroot into out (NUL-terminated) under the same lock that
 * serializes proc_set_sysroot().
 *
 * Returns true if a sysroot is configured and fits in outsz; false if unset,
 * truncating, or out/outsz is invalid (in which case out[0] is set to '\0' when
 * possible).
 */
bool proc_sysroot_snapshot(char *out, size_t outsz);
void proc_set_sysroot_casefold(bool enabled);
bool proc_sysroot_casefold_enabled(void);

/* Resolve an absolute guest path through the stored sysroot.
 *
 * Returns buf when a sysroot-backed file exists, and also when the path names a
 * temp root or a guest system directory, both of which resolve there whether or
 * not they exist. Returns path unchanged when no sysroot applies or when any
 * other sysroot-backed path does not exist, or NULL if sysroot path
 * construction would truncate or escape containment checks.
 */
const char *proc_resolve_sysroot_path(const char *path,
                                      char *buf,
                                      size_t bufsz);

/* Resolve an absolute guest path through the stored sysroot for operations that
 * must not follow the final path component (readlinkat, O_NOFOLLOW,
 * AT_SYMLINK_NOFOLLOW).
 */
const char *proc_resolve_sysroot_nofollow_path(const char *path,
                                               char *buf,
                                               size_t bufsz);

/* Resolve an absolute guest path through the stored sysroot for operations that
 * may create the final path. Unlike proc_resolve_sysroot_path(), this prefixes
 * sysroot paths even when the final component does not exist.
 */
const char *proc_resolve_sysroot_create_path(const char *path,
                                             char *buf,
                                             size_t bufsz,
                                             bool create_parents);

/* execve. */

/* Return value sentinel from syscall_dispatch (returns int):
 *   0 = continue, 1 = exit, SYSCALL_EXEC_HAPPENED = exec/sigreturn.
 * Also used as int64_t return from sc_xxx handlers where it must not collide
 * with valid syscall returns (>=0), Linux errno (-1..-4095), or
 * SC_EXIT_SENTINEL (INT64_MIN | code). -0x10000 is outside all these ranges and
 * fits in int.
 */
#define SYSCALL_EXEC_HAPPENED (-0x10000)

/* Process table (for fork/clone children). */

typedef struct {
    bool active;       /* Slot is visible to guest wait operations */
    bool reserved;     /* Fork admission reserved this slot before spawn */
    pid_t host_pid;    /* macOS process ID of child elfuse instance */
    int64_t guest_pid; /* Guest-visible PID assigned to child */
    int64_t pgid;      /* Child's process group, inherited at fork and updated
                        * by a parent-side setpgid(child, ...)
                        */
    bool exited;       /* Child has exited */
    int exit_status;   /* wait status (as returned by waitpid) */
    bool rusage_valid;
    bool rusage_accounted;
    bool host_waitable; /* false for a child adopted from another host parent */
    /* Terminal status was taken from the lifecycle registry before wait4()
     * could observe the zombie, so the host process still needs reaping. Set
     * only for host_waitable children; see proc_deferred_reap_poll().
     */
    bool host_reap_pending;
    struct rusage rusage;
} proc_entry_t;

/* Reserve bookkeeping before creating a helper process. A successful
 * reservation guarantees proc_register_child() can make the child visible
 * after fork IPC completes. Returns 0 or a negative Linux errno.
 */
int proc_reserve_child(int64_t guest_pid, int64_t pgid);

/* Commit a previously reserved child after fork IPC is ready to release it.
 * Returns 0 or a negative Linux errno if the reservation was lost or the
 * lifecycle registry could not be updated.
 */
int proc_register_child(pid_t host_pid, int64_t guest_pid, int64_t pgid);

/* Roll back a reservation (or a just-committed entry on final IPC failure). */
void proc_cancel_child(int64_t guest_pid);

/* Mark a child as exited by host PID (for CLONE_VFORK wait). */
void proc_mark_child_exited(pid_t host_pid, int status);

/* Accumulate a reaped guest child's rusage into the cutime/cstime counters
 * that times(2) reports. Call at every host reap of a proc_table child; never
 * for emulator helper subprocesses.
 */
void proc_children_cpu_add(const struct rusage *ru);

/* Read the accumulated guest-children CPU time, in microseconds. */
void proc_children_cpu_us(uint64_t *utime_us, uint64_t *stime_us);

/* Write a macOS struct rusage to guest memory as linux_rusage_t. The field
 * layout matches on LP64; ru_maxrss is converted from macOS bytes to Linux
 * kilobytes. Returns the guest_write_small result (0 on success, negative on
 * fault).
 */
int write_rusage_to_guest(guest_t *g, uint64_t gva, const struct rusage *ru);

/* Collect host PIDs of active (non-exited) fork children. Writes up to max_pids
 * entries into out[].
 *
 * Returns the count written.
 */
int proc_get_child_pids(pid_t *out, int max_pids);

/* Collect host PIDs of this process's direct, active (non-exited) fork children
 * from the process table only. Unlike proc_get_child_pids it does NOT sweep the
 * host for same-binary processes, so it cannot reach unrelated elfuse
 * instances. Writes up to max_pids entries into out[]; returns the count
 * written.
 */
int proc_get_direct_child_pids(pid_t *out, int max_pids);

/* One signalable fork-family member: host pid for delivery plus guest pid so
 * the transport record can be tagged and a recycled host pid cannot misapply
 * the signal to an unrelated guest.
 */
typedef struct {
    pid_t host_pid;
    int64_t guest_pid;
} proc_signal_target_t;

/* Pass as the pgid_filter to proc_get_namespace_targets to collect every
 * fork-family member regardless of process group (kill(-1) broadcast).
 */
#define PROC_PGID_ANY ((int64_t) -1)

/* Collect every live process in this elfuse fork family from the namespace
 * registry, excluding the caller. When pgid_filter is PROC_PGID_ANY all members
 * are returned; otherwise only those whose tracked process group matches.
 * Writes up to max entries into out[]; returns the count written.
 */
int proc_get_namespace_targets(proc_signal_target_t *out,
                               int max,
                               int64_t pgid_filter);

/* Publish the caller's current guest pid/pgid to the fork-family registry. */
void proc_registry_publish_self(void);

/* Reap only children whose shared lifecycle entry is already terminal. */
void proc_autoreap_exited_children(void);

/* Pull authoritative PPID state into a newly bootstrapped fork child. */
void proc_lifecycle_sync_self(guest_t *g);

/* Notify the guest parent that this process reached a terminal state. Called
 * by fork-child teardown before the host process exits.
 */
void proc_process_exit(int wait_status);

/* Pull a parent-published pgid update into this process's local identity. */
void proc_registry_sync_self_pgid(guest_t *g);

/* Record the process group of a direct child (parent-side setpgid).
 *
 * Returns 0 if the child was found and updated, -1 otherwise.
 */
int proc_set_child_pgid(int64_t guest_pid, int64_t pgid);

/* Look up a guest PID in the child process table.
 * Returns the host PID if found and still active, or -1.
 */
pid_t proc_guest_to_host_pid(int64_t gpid);

/* Look up a host PID in the child process table, falling back to the
 * cross-process registry so the rest of the fork family (grandchildren,
 * siblings' descendants) resolves too. Returns the guest PID if @host_pid is
 * a live member of this guest's fork family, or -1 otherwise (e.g. the lock
 * holder is an unrelated host process).
 */
int64_t proc_host_to_guest_pid(pid_t host_pid);

/* Queue a Linux guest signal in a fork-child elfuse process. target_guest_pid
 * tags the transport record so the receiver drops it if its host pid was
 * recycled onto a different guest.
 *
 * Returns 0 on success or -1 with errno set.
 */
int proc_send_guest_signal(pid_t host_pid,
                           int64_t target_guest_pid,
                           int signum);

/* Block the vCPU-preemption signals (SIGUSR2 doorbell, SIGALRM timeout) on the
 * calling thread and start the dedicated sigwait thread that consumes them.
 * Call once from the main thread before any vCPU thread is created; the
 * posix_spawn fork-child re-runs it in its own process.
 *
 * Returns 0 on success, -1 if the sigwait thread cannot be started (fatal for
 * this process).
 */
int proc_preempt_init(void);

/* Syscall handlers. */
int64_t sys_pidfd_open(guest_t *g, int64_t pid, unsigned int flags);
int64_t sys_pidfd_send_signal(guest_t *g,
                              int pidfd,
                              int sig,
                              uint64_t info_gva,
                              unsigned int flags);

/* ptrace. */

/* Linux ptrace syscall implementation. Supports SEIZE, CONT, INTERRUPT,
 * GETREGSET, and SETREGSET (sufficient for two-process JIT architectures).
 * Returns 0 on success or negative Linux errno.
 */
int64_t sys_ptrace(guest_t *g,
                   uint64_t request,
                   int64_t pid,
                   uint64_t addr,
                   uint64_t data);

/* wait. */

/* Wait for child process. Returns child guest PID or negative errno. */
int64_t sys_wait4(guest_t *g,
                  int pid,
                  uint64_t status_gva,
                  int options,
                  uint64_t rusage_gva);

/* waitid: wait for child process using idtype/id semantics. Fills siginfo_t at
 * infop_gva on success.
 */
int64_t sys_waitid(guest_t *g,
                   int idtype,
                   int64_t id,
                   uint64_t infop_gva,
                   int options);

/* exit_group coordination. */

/* Request process-wide exit and let worker loops observe the shared code. */
void proc_request_exit_group(int code);
void proc_clear_exit_group(void);
int proc_exit_group_requested(void);

/* vCPU run loop. */

/* Request that the current host thread's HVC #6 run loop returns after the
 * active handler completes. Safe for concurrent HVC #6 handlers because the
 * request is thread-local and consumed only by the current vcpu_run_loop().
 */
void proc_request_hvc6_yield(void);

/* Optional embedder hook. Called on the vCPU owner thread at host boundaries
 * (before each hv_vcpu_run() entry or re-entry).
 *
 * Stop semantics:
 * Return nonzero to stop the loop. A nonzero tick return is propagated
 * and returned as the run loop's exit code.
 *
 * Cooperative-only timing:
 * The tick is only checked at host boundaries, not during guest execution.
 * A guest spinning entirely in EL0 without VM-exiting will never trigger
 * the tick, meaning a tick-initiated hook cannot interrupt a runaway guest.
 * To force interruption of a runaway guest, use hv_vcpus_exit().
 *
 * Concurrency and lifetime:
 * When a single vcpu_run_hooks_t and its opaque data are shared across
 * multiple vCPUs, the tick function will be invoked concurrently from
 * multiple host threads and must be thread-safe. The run loop does not keep
 * a copy of the hooks structure and dereferences it every iteration; the
 * caller must ensure the hooks structure and opaque lifetime extend until
 * all run loops return.
 */
typedef int (*vcpu_run_loop_tick_fn)(guest_t *g, void *opaque);

typedef struct vcpu_run_hooks {
    vcpu_run_loop_tick_fn tick;
    void *opaque;
} vcpu_run_hooks_t;

/* Run the vCPU execution loop.
 *
 * Returns the exit code.
 *
 * When timeout_sec > 0 (main thread): uses alarm() for per-iteration safety
 * timeout. When timeout_sec == 0 (worker thread): skips alarm() (SIGALRM is
 * process-wide). Workers are terminated by exit_group via hv_vcpus_exit(). Both
 * modes check proc_exit_group_requested.
 */
int vcpu_run_loop(hv_vcpu_t vcpu,
                  hv_vcpu_exit_t *vexit,
                  guest_t *g,
                  bool verbose,
                  int timeout_sec,
                  int *wait_status_out);
int vcpu_run_loop_with_hooks(hv_vcpu_t vcpu,
                             hv_vcpu_exit_t *vexit,
                             guest_t *g,
                             bool verbose,
                             int timeout_sec,
                             int *wait_status_out,
                             const vcpu_run_hooks_t *hooks);
