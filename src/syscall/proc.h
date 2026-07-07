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

#include <stdio.h>

#include <Hypervisor/Hypervisor.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "core/guest.h"
#include "core/elf.h"

/* Process state. */

/* Initialize the process subsystem. */
void proc_init(void);

/* Get/set current guest PID and PPID. */
int64_t proc_get_pid(void);
int64_t proc_get_ppid(void);

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

/* setpriority/getpriority: only PRIO_PROCESS for self. setpriority clamps prio
 * to [-20, 19]. getpriority returns 20-nice (always > 0 per Linux convention).
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
 * Returns path unchanged when no sysroot applies or when the sysroot-backed
 * path does not exist, buf when a sysroot-backed file exists, or NULL if
 * sysroot path construction would truncate or escape containment checks.
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

#define PROC_TABLE_SIZE 64

typedef struct {
    bool active;       /* Slot is in use */
    pid_t host_pid;    /* macOS process ID of child elfuse instance */
    int64_t guest_pid; /* Guest-visible PID assigned to child */
    bool exited;       /* Child has exited */
    int exit_status;   /* wait status (as returned by waitpid) */
} proc_entry_t;

/* Register a child process in the process table.
 * Returns 0 on success, -1 if the table is full.
 */
int proc_register_child(pid_t host_pid, int64_t guest_pid);

/* Mark a child as exited by host PID (for CLONE_VFORK wait). */
void proc_mark_child_exited(pid_t host_pid, int status);

/* Collect host PIDs of active (non-exited) fork children. Writes up to max_pids
 * entries into out[].
 *
 * Returns the count written.
 */
int proc_get_child_pids(pid_t *out, int max_pids);

/* Look up a guest PID in the child process table.
 * Returns the host PID if found and still active, or -1.
 */
pid_t proc_guest_to_host_pid(int64_t gpid);

/* Queue a Linux guest signal in a fork-child elfuse process.
 * Returns 0 on success or -1 with errno set.
 */
int proc_send_guest_signal(pid_t host_pid, int signum);

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

/* Dump the vCPU exit-reason accounting (total returns, VTIMER masks, spurious
 * cancels, null-exit share) to stderr. Intended for the process-exit path when
 * runtime-stats are enabled (ELFUSE_SHIM_STATS or ELFUSE_RUNTIME_STATS, via
 * shim_globals_stats_enabled()); counters stay zero when the gate is unset.
 */
void proc_dump_vcpu_exit_stats(void);
void proc_dump_vcpu_exit_stats_json(FILE *out);
void proc_reset_vcpu_exit_stats(void);

/* vCPU run loop. */

/* Request that the current host thread's HVC #6 run loop returns after the
 * active handler completes. Safe for concurrent HVC #6 handlers because the
 * request is thread-local and consumed only by the current vcpu_run_loop().
 */
void proc_request_hvc6_yield(void);

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
                  int timeout_sec);
