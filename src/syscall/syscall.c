/* Linux aarch64 syscall dispatch
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Dispatch table, sc_xxx adapter wrappers, fast-path read/write, and the main
 * syscall_dispatch() entry point. Core infrastructure and syscall
 * implementations live in focused modules:
 *   syscall/fdtable.c:   FD table, bitmap allocator, alloc/close/snapshot
 *   syscall/translate.c: errno/flag translation (macOS <-> Linux)
 *   syscall/mem.c:       brk, mmap, munmap, mprotect, mremap, madvise, msync
 *   syscall/fs.c:        filesystem operations
 *   syscall/io.c:        read/write, ioctl, splice, sendfile
 *   syscall/poll.c:      ppoll, pselect6, epoll (kqueue emulation)
 *   syscall/fd.c:        eventfd, signalfd, timerfd (special FD types)
 *   syscall/time.c:      clock, nanosleep, timers
 *   syscall/sys.c:       uname, getrandom, sysinfo, resource limits
 *   syscall/proc.c:      fork/exec/wait, process management
 *   syscall/signal.c:    signal delivery, rt_sigaction
 *   syscall/net.c:       socket networking
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/file.h> /* flock() */
#include <dirent.h>
#include <limits.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>

#include "debug/log.h"
#include "utils.h"

#include "runtime/forkipc.h"
#include "runtime/futex.h"

#include "syscall/abi.h"
#include "syscall/exec.h"
#include "syscall/fd.h"
#include "syscall/fuse.h"
#include "syscall/fs.h"
#include "syscall/inotify.h"
#include "syscall/internal.h"
#include "syscall/io.h"
#include "syscall/mem.h"
#include "syscall/net.h"
#include "syscall/poll.h"
#include "syscall/path.h"
#include "syscall/proc.h"
#include "syscall/proc-pidfd.h"
#include "syscall/signal.h"
#include "syscall/sys.h"
#include "syscall/sysvipc.h"
#include "syscall/time.h"

#include "core/shim-globals.h"

#include "debug/syscall-hist.h"

/* Generated from src/syscall/dispatch.tbl into $(BUILD_DIR). */
#include "dispatch.h"

/* HV_SYS_REG_ACTLR_EL1 was added in the macOS 15 (Sequoia) SDK. Older SDKs
 * (e.g., the Nix-pinned apple-sdk-14.4) lack the enumerator. The encoding is
 * stable: op0=3, op1=0, CRn=1, CRm=0, op2=1 -> 0xc081. Hypervisor.framework
 * exposes ACTLR_EL1 only on hardware/OS combinations where the bit is
 * meaningful (Apple Silicon TSO toggle); older platforms simply leave actlr at
 * 0, which falls through to PR_SET_MEM_MODEL_DEFAULT.
 *
 * The guard checks the SDK version rather than the macro presence: on macOS 15+
 * the symbol is an enumerator (not a #define), so a plain #ifndef would always
 * fire and shadow the SDK name with a macro of the same spelling.
 */
#if __MAC_OS_X_VERSION_MAX_ALLOWED < 150000
#define HV_SYS_REG_ACTLR_EL1 ((hv_sys_reg_t) 0xc081)
#endif


void syscall_init(void)
{
    fdtable_init();
    signal_init();
    /* Mirror signal_init's attention_guest reset for the fd/urandom bitmap
     * singleton in shim-globals. Defends against a stale parent-process pointer
     * surviving across posix_spawn re-init.
     */
    shim_globals_reset_singleton();

    /* Initialize special FD subsystems (eventfd, signalfd, timerfd, inotify).
     * Must happen before any guest code runs so that concurrent CLONE_THREAD
     * callers do not race on lazy init.
     */
    eventfd_init();
    signalfd_init();
    timerfd_init();
    inotify_init();
    netlink_init();
    fuse_init();
    pidfd_init();
    io_init();
    fd_register_cleanup(FD_URANDOM, urandom_fd_cleanup);
    wakeup_pipe_init();
}

/* Memory syscall implementations (sys_brk, sys_mmap, sys_mremap, etc.) are in
 * syscall/mem.c. FD table in syscall/fdtable.c. Errno/flag translation in
 * syscall/translate.c.
 */

/* Syscall handler table. */

/* Each sc_xxx wrapper adapts one (or a group of fall-through) case(s) from the
 * old switch into a uniform signature.
 *
 * Returns int64_t result, or a sentinel: SYSCALL_EXEC_HAPPENED for
 * exec/sigreturn, (INT64_MIN | code) for exit/exit_group. Wrappers that need
 * mmap_lock acquire it internally. Wrappers that need the vCPU handle use
 * current_thread->vcpu.
 */
typedef int64_t (*syscall_handler_t)(guest_t *g,
                                     uint64_t x0,
                                     uint64_t x1,
                                     uint64_t x2,
                                     uint64_t x3,
                                     uint64_t x4,
                                     uint64_t x5,
                                     bool verbose);

/* Exit sentinel: high bits mark this as an exit, low 8 bits carry the code.
 * Cannot collide with SYSCALL_EXEC_HAPPENED (-0x10000): exit sentinel has
 * INT64_MIN's sign bit set, exec sentinel does not.
 */
#define SC_EXIT_SENTINEL INT64_MIN

/* Wrapper macros.
 *
 * These macros eliminate the boilerplate of ~120 sc_xxx wrappers that follow
 * one of three patterns:
 *
 *   SC_FORWARD(name, expr): cast args and forward to sys_xxx / signal_xxx
 *   SC_LOCKED(name, expr):  same, but hold mmap_lock during the call
 *   SC_STUB(name, val):     return a constant (alias for SC_FORWARD)
 *
 * All parameters are marked (void) to suppress -Wunused-parameter. The body
 * expression may reference g, x0-x5, and verbose freely.
 */

/* clang-format off */
#define SC_FORWARD(name, body)                                                \
    static int64_t name(guest_t *g, uint64_t x0, uint64_t x1, uint64_t x2,    \
                        uint64_t x3, uint64_t x4, uint64_t x5, bool verbose)  \
    {                                                                         \
        (void) g; (void) x0; (void) x1; (void) x2;                            \
        (void) x3; (void) x4; (void) x5; (void) verbose;                      \
        return (body);                                                        \
    }

#define SC_LOCKED(name, body)                                                 \
    static int64_t name(guest_t *g, uint64_t x0, uint64_t x1, uint64_t x2,    \
                        uint64_t x3, uint64_t x4, uint64_t x5, bool verbose)  \
    {                                                                         \
        (void) g; (void) x0; (void) x1; (void) x2;                            \
        (void) x3; (void) x4; (void) x5; (void) verbose;                      \
        pthread_mutex_lock(&mmap_lock);                                       \
        int64_t r = (body);                                                   \
        pthread_mutex_unlock(&mmap_lock);                                     \
        return r;                                                             \
    }

#define SC_STUB(name, val) SC_FORWARD(name, (val))

/* Bracket setuid/setgid family invocations so concurrent shim-fast-path readers
 * cannot observe stale credentials. The host-side proc_sys_* mutators flip the
 * _Atomic credential slots inside proc-identity.c; the shim cache must reflect
 * that under the same atomic window.
 *
 * Sequence: OR ATTN_BIT_CRED -> mutator -> on success publish_creds -> AND
 * ~ATTN_BIT_CRED. The OR-only update preserves whatever ATTN_BIT_SIGTIMER state
 * the HVC #5 epilogue's recompute may have set or cleared in parallel; AND-only
 * clear at the end leaves the SIGTIMER lane alone. Earlier revisions wrote the
 * full word, which let a sibling's recompute drop the flag to zero mid-publish
 * and reopened the torn-cred race the bracket was meant to close.
 *
 * Implemented as a statement-expression macro so the SC_FORWARD body stays a
 * single expression and the mutator runs after the attention raise as part of
 * normal C sequencing.
 */
#define CRED_BRACKETED(g_, mutator_)                                       \
    __extension__({                                                        \
        guest_t *_g = (g_);                                                \
        shim_globals_attn_or(_g, ATTN_BIT_CRED);                           \
        int64_t _rc = (mutator_);                                          \
        if (_rc == 0)                                                      \
            shim_globals_publish_creds(_g, proc_get_uid(), proc_get_euid(),\
                                       proc_get_gid(), proc_get_egid());   \
        shim_globals_attn_and(_g, ~ATTN_BIT_CRED);                         \
        _rc;                                                               \
    })

/* sc_xxx forwarding wrappers: thin adapters that unpack the syscall ABI
 * argument tuple (x0..x5) into a sys_xxx() call.
 */

/* I/O */
SC_FORWARD(sc_write,     sys_write(g, (int) x0, x1, x2))
SC_FORWARD(sc_read,      sys_read(g, (int) x0, x1, x2))
SC_FORWARD(sc_openat,    sys_openat(g, (int) x0, x1, (int) x2, (int) x3))
SC_FORWARD(sc_close,     sys_close((int) x0))
SC_FORWARD(sc_readv,     sys_readv(g, (int) x0, x1, (int) x2))
SC_FORWARD(sc_writev,    sys_writev(g, (int) x0, x1, (int) x2))
SC_FORWARD(sc_pread64,   sys_pread64(g, (int) x0, x1, x2, (int64_t) x3))
SC_FORWARD(sc_pwrite64,  sys_pwrite64(g, (int) x0, x1, x2, (int64_t) x3))
SC_FORWARD(sc_ioctl,     sys_ioctl(g, (int) x0, x1, x2))
SC_FORWARD(sc_preadv,    sys_preadv(g, (int) x0, x1, (int) x2, (int64_t) x3))
SC_FORWARD(sc_pwritev,   sys_pwritev(g, (int) x0, x1, (int) x2, (int64_t) x3))
/* aarch64 LP64 raw ABI: x3=pos_l (full 64-bit offset), x4=pos_h (0), x5=flags
 */
SC_FORWARD(sc_preadv2,   sys_preadv2(g, (int) x0, x1, (int) x2, (int64_t) x3, (int) x5))
SC_FORWARD(sc_pwritev2,  sys_pwritev2(g, (int) x0, x1, (int) x2, (int64_t) x3, (int) x5))
SC_FORWARD(sc_sendfile,  sys_sendfile(g, (int) x0, (int) x1, x2, x3))
SC_FORWARD(sc_splice,    sys_splice(g, (int) x0, x1, (int) x2, x3, (size_t) x4, (unsigned int) x5))
SC_FORWARD(sc_vmsplice,  sys_vmsplice(g, (int) x0, x1, (unsigned long) x2, (unsigned int) x3))
SC_FORWARD(sc_tee,       sys_tee((int) x0, (int) x1, (size_t) x2, (unsigned int) x3))
SC_FORWARD(sc_copy_file_range, sys_copy_file_range(g, (int) x0, x1, (int) x2, x3, x4, (unsigned int) x5))
SC_FORWARD(sc_lseek,     sys_lseek((int) x0, (int64_t) x1, (int) x2))

/* Filesystem */
SC_FORWARD(sc_fstat,       sys_fstat(g, (int) x0, x1))
SC_FORWARD(sc_newfstatat,  sys_newfstatat(g, (int) x0, x1, x2, (int) x3))
SC_FORWARD(sc_statfs,      sys_statfs(g, x0, x1))
SC_FORWARD(sc_fstatfs,     sys_fstatfs(g, (int) x0, x1))
SC_FORWARD(sc_statx,       sys_statx(g, (int) x0, x1, (int) x2, (unsigned int) x3, x4))
SC_FORWARD(sc_mkdirat,     sys_mkdirat(g, (int) x0, x1, (int) x2))
SC_FORWARD(sc_unlinkat,    sys_unlinkat(g, (int) x0, x1, (int) x2))
SC_FORWARD(sc_renameat,    sys_renameat2(g, (int) x0, x1, (int) x2, x3, 0))
SC_FORWARD(sc_renameat2,   sys_renameat2(g, (int) x0, x1, (int) x2, x3, (int) x4))
SC_FORWARD(sc_readlinkat,  sys_readlinkat(g, (int) x0, x1, x2, x3))
SC_FORWARD(sc_mknodat,     sys_mknodat(g, (int) x0, x1, (int) x2, (int) x3))
SC_FORWARD(sc_symlinkat,   sys_symlinkat(g, x0, (int) x1, x2))
SC_FORWARD(sc_linkat,      sys_linkat(g, (int) x0, x1, (int) x2, x3, (int) x4))
SC_FORWARD(sc_mount,       sys_mount(g, x0, x1, x2, (unsigned long) x3, x4))
SC_FORWARD(sc_fchmod,      sys_fchmod((int) x0, (uint32_t) x1))

/* Linux fchmodat (SYS 53) is 3-arg: dirfd, path, mode. The flags parameter was
 * added in fchmodat2 (SYS 452). x3 contains garbage from the caller's register
 * state.
 */
SC_FORWARD(sc_fchmodat,    sys_fchmodat(g, (int) x0, x1, (uint32_t) x2, 0))
SC_FORWARD(sc_fchmodat2,   sys_fchmodat(g, (int) x0, x1, (uint32_t) x2, (int) x3))
SC_FORWARD(sc_fchownat,    sys_fchownat(g, (int) x0, x1, (uint32_t) x2, (uint32_t) x3, (int) x4))
SC_FORWARD(sc_fchown,      sys_fchown((int) x0, (uint32_t) x1, (uint32_t) x2))
SC_FORWARD(sc_utimensat,   sys_utimensat(g, (int) x0, x1, x2, (int) x3))
/* Linux faccessat (SYS 48) is 3-arg: dirfd, path, mode. The flags parameter was
 * added in faccessat2 (SYS 439). x3 contains garbage from the caller's register
 * state.
 */
SC_FORWARD(sc_faccessat,   sys_faccessat(g, (int) x0, x1, (int) x2, 0))
SC_FORWARD(sc_faccessat2,  sys_faccessat(g, (int) x0, x1, (int) x2, (int) x3))
SC_FORWARD(sc_ftruncate,   sys_ftruncate((int) x0, (int64_t) x1))
SC_FORWARD(sc_truncate,    sys_truncate(g, x0, (int64_t) x1))
SC_FORWARD(sc_fallocate,   sys_fallocate((int) x0, (int) x1, (int64_t) x2, (int64_t) x3))
SC_FORWARD(sc_getcwd,      sys_getcwd(g, x0, x1))
SC_FORWARD(sc_chdir,       sys_chdir(g, x0))
SC_FORWARD(sc_fchdir,      sys_fchdir((int) x0))
SC_FORWARD(sc_chroot,      sys_chroot(g, x0))
SC_FORWARD(sc_umask,       (int64_t) umask((mode_t) x0))
SC_FORWARD(sc_getdents64,  sys_getdents64(g, (int) x0, x1, x2))

/* FD operations */
SC_FORWARD(sc_dup,         sys_dup((int) x0))
SC_FORWARD(sc_dup3,        sys_dup3((int) x0, (int) x1, (int) x2))
SC_FORWARD(sc_fcntl,       sys_fcntl(g, (int) x0, (int) x1, x2))
SC_FORWARD(sc_pipe2,       sys_pipe2(g, x0, (int) x1))
SC_FORWARD(sc_close_range, sys_close_range((unsigned int) x0, (unsigned int) x1, (unsigned int) x2))

/* Extended attributes */
SC_FORWARD(sc_getxattr,       sys_getxattr(g, x0, x1, x2, x3, 0))
SC_FORWARD(sc_lgetxattr,      sys_getxattr(g, x0, x1, x2, x3, 1))
SC_FORWARD(sc_setxattr,       sys_setxattr(g, x0, x1, x2, x3, (int) x4, 0))
SC_FORWARD(sc_lsetxattr,      sys_setxattr(g, x0, x1, x2, x3, (int) x4, 1))
SC_FORWARD(sc_listxattr,      sys_listxattr(g, x0, x1, x2, 0))
SC_FORWARD(sc_llistxattr,     sys_listxattr(g, x0, x1, x2, 1))
SC_FORWARD(sc_removexattr,    sys_removexattr(g, x0, x1, 0))
SC_FORWARD(sc_lremovexattr,   sys_removexattr(g, x0, x1, 1))
SC_FORWARD(sc_fgetxattr,      sys_fgetxattr(g, (int) x0, x1, x2, x3))
SC_FORWARD(sc_fsetxattr,      sys_fsetxattr(g, (int) x0, x1, x2, x3, (int) x4))
SC_FORWARD(sc_flistxattr,     sys_flistxattr(g, (int) x0, x1, x2))
SC_FORWARD(sc_fremovexattr,   sys_fremovexattr(g, (int) x0, x1))

/* Networking */
SC_FORWARD(sc_socket,      sys_socket(g, (int) x0, (int) x1, (int) x2))
SC_FORWARD(sc_socketpair,  sys_socketpair(g, (int) x0, (int) x1, (int) x2, x3))
SC_FORWARD(sc_bind,        sys_bind(g, (int) x0, x1, (uint32_t) x2))
SC_FORWARD(sc_listen,      sys_listen((int) x0, (int) x1))
SC_FORWARD(sc_accept,      sys_accept(g, (int) x0, x1, x2))
SC_FORWARD(sc_accept4,     sys_accept4(g, (int) x0, x1, x2, (int) x3))
SC_FORWARD(sc_connect,     sys_connect(g, (int) x0, x1, (uint32_t) x2))
SC_FORWARD(sc_getsockname, sys_getsockname(g, (int) x0, x1, x2))
SC_FORWARD(sc_getpeername, sys_getpeername(g, (int) x0, x1, x2))
SC_FORWARD(sc_sendto,      sys_sendto(g, (int) x0, x1, x2, (int) x3, x4, (uint32_t) x5))
SC_FORWARD(sc_recvfrom,    sys_recvfrom(g, (int) x0, x1, x2, (int) x3, x4, x5))
SC_FORWARD(sc_setsockopt,  sys_setsockopt(g, (int) x0, (int) x1, (int) x2, x3, (uint32_t) x4))
SC_FORWARD(sc_getsockopt,  sys_getsockopt(g, (int) x0, (int) x1, (int) x2, x3, x4))
SC_FORWARD(sc_shutdown,    sys_shutdown((int) x0, (int) x1))
SC_FORWARD(sc_sendmsg,     sys_sendmsg(g, (int) x0, x1, (int) x2))
SC_FORWARD(sc_recvmsg,     sys_recvmsg(g, (int) x0, x1, (int) x2))
SC_FORWARD(sc_sendmmsg,    sys_sendmmsg(g, (int) x0, x1, (unsigned int) x2, (int) x3))
SC_FORWARD(sc_recvmmsg,    sys_recvmmsg(g, (int) x0, x1, (unsigned int) x2, (int) x3, x4))

/* Poll / epoll */
SC_FORWARD(sc_ppoll,          sys_ppoll(g, x0, (uint32_t) x1, x2, x3))
SC_FORWARD(sc_pselect6,       sys_pselect6(g, (int) x0, x1, x2, x3, x4, x5))
SC_FORWARD(sc_epoll_create1,  sys_epoll_create1((int) x0))
SC_FORWARD(sc_epoll_ctl,      sys_epoll_ctl(g, (int) x0, (int) x1, (int) x2, x3))
SC_FORWARD(sc_epoll_pwait,    sys_epoll_pwait(g, (int) x0, x1, (int) x2, (int) x3, x4))

/* Special FDs */
SC_FORWARD(sc_eventfd2,          sys_eventfd2((unsigned int) x0, (int) x1))
SC_FORWARD(sc_signalfd4,         sys_signalfd4(g, (int) x0, x1, x2, (int) x3))
SC_FORWARD(sc_timerfd_create,    sys_timerfd_create((int) x0, (int) x1))
SC_FORWARD(sc_timerfd_settime,   sys_timerfd_settime(g, (int) x0, (int) x1, x2, x3))
SC_FORWARD(sc_timerfd_gettime,   sys_timerfd_gettime(g, (int) x0, x1))
SC_FORWARD(sc_inotify_init1,     sys_inotify_init1((int) x0))
SC_FORWARD(sc_inotify_add_watch, sys_inotify_add_watch(g, (int) x0, x1, (uint32_t) x2))
SC_FORWARD(sc_inotify_rm_watch,  sys_inotify_rm_watch((int) x0, (int) x1))

/* Time */
SC_FORWARD(sc_clock_gettime,    sys_clock_gettime(g, (int) x0, x1))
SC_FORWARD(sc_clock_getres,     sys_clock_getres(g, (int) x0, x1))
SC_FORWARD(sc_nanosleep,        sys_nanosleep(g, x0, x1))
SC_FORWARD(sc_clock_nanosleep,  sys_clock_nanosleep(g, (int) x0, (int) x1, x2, x3))
SC_FORWARD(sc_gettimeofday,     sys_gettimeofday(g, x0, x1))
SC_FORWARD(sc_setitimer,        sys_setitimer(g, (int) x0, x1, x2))
SC_FORWARD(sc_getitimer,        sys_getitimer(g, (int) x0, x1))

/* Signals */
SC_FORWARD(sc_rt_sigaction,   signal_rt_sigaction(g, (int) x0, x1, x2, x3))
SC_FORWARD(sc_rt_sigprocmask, signal_rt_sigprocmask(g, (int) x0, x1, x2, x3))
SC_FORWARD(sc_sigaltstack,    signal_sigaltstack(g, x0, x1))
SC_FORWARD(sc_rt_sigsuspend,  signal_rt_sigsuspend(g, x0, x1))
SC_FORWARD(sc_rt_sigpending,  signal_rt_sigpending(g, x0, x1))

/* System info */
SC_FORWARD(sc_uname,     sys_uname(g, x0))
SC_FORWARD(sc_getrandom, sys_getrandom(g, x0, x1, (unsigned int) x2))
SC_FORWARD(sc_getcpu,    sys_getcpu(g, x0, x1, x2))
SC_FORWARD(sc_sysinfo,   sys_sysinfo(g, x0))
SC_FORWARD(sc_prlimit64, sys_prlimit64(g, (int) x0, (int) x1, x2, x3))
SC_FORWARD(sc_getrlimit, sys_prlimit64(g, 0, (int) x0, 0, x1))
SC_FORWARD(sc_setrlimit, sys_prlimit64(g, 0, (int) x0, x1, 0))
SC_FORWARD(sc_getgroups, sys_getgroups(g, (int) x0, x1))
SC_FORWARD(sc_getrusage, sys_getrusage(g, (int) x0, x1))
SC_FORWARD(sc_sched_getaffinity,    sys_sched_getaffinity(g, (int) x0, x1, x2))
SC_FORWARD(sc_sched_getscheduler,   sys_sched_getscheduler((int) x0))
SC_FORWARD(sc_sched_getparam,       sys_sched_getparam(g, (int) x0, x1))
SC_FORWARD(sc_sched_setscheduler,   sys_sched_setscheduler(g, (int) x0, (int) x1, x2))
SC_FORWARD(sc_sched_setparam,       sys_sched_setparam(g, (int) x0, x1))
SC_FORWARD(sc_sched_get_priority_min, sys_sched_get_priority_min((int) x0))
SC_FORWARD(sc_sched_get_priority_max, sys_sched_get_priority_max((int) x0))
SC_FORWARD(sc_sched_rr_get_interval,  sys_sched_rr_get_interval(g, (int) x0, x1))

/* Process identity is modeled as one Linux process inside this elfuse instance.
 */
SC_FORWARD(sc_exit,    SC_EXIT_SENTINEL | ((int) x0 & 0xFF))
SC_FORWARD(sc_getpid,  proc_get_pid())
SC_FORWARD(sc_getppid, proc_get_ppid())
SC_FORWARD(sc_getpgid, ((int) x0 == 0 || (int) x0 == (int) proc_get_pid()) ? proc_get_pgid() : -LINUX_ESRCH)
SC_FORWARD(sc_setsid,  proc_sys_setsid(g))
SC_FORWARD(sc_getsid,  proc_sys_getsid((int64_t) x0))
SC_FORWARD(sc_gettid,  current_thread ? current_thread->guest_tid : proc_get_pid())

/* pidfd */
SC_FORWARD(sc_pidfd_open,        sys_pidfd_open(g, (int64_t) x0, (unsigned int) x1))
SC_FORWARD(sc_pidfd_send_signal, sys_pidfd_send_signal(g, (int) x0, (int) x1, x2, (unsigned int) x3))
SC_FORWARD(sc_pidfd_getfd,       -LINUX_ENOSYS)

/* Process-management calls that need child tables or wait semantics. */
SC_FORWARD(sc_wait4,  sys_wait4(g, (int) x0, x1, (int) x2, x3))

/* waitid has a 5th arg (struct rusage *) on aarch64; fill with zeros since
 * guest memory does not track per-child resource usage.
 */
static inline int64_t sc_waitid_impl(guest_t *g, uint64_t x0, uint64_t x1,
                                     uint64_t x2, uint64_t x3, uint64_t x4)
{
    int64_t r = sys_waitid(g, (int) x0, (int64_t) x1, x2, (int) x3);
    if (r == 0 && x4) {
        linux_rusage_t ru;
        memset(&ru, 0, sizeof(ru));
        guest_write_small(g, x4, &ru, sizeof(ru));
    }
    return r;
}
SC_FORWARD(sc_waitid, sc_waitid_impl(g, x0, x1, x2, x3, x4))

/* Futex */
SC_FORWARD(sc_futex, sys_futex(g, x0, (int) x1, (uint32_t) x2, x3, x4, (uint32_t) x5))

/* Sync.
 *
 * Linux sync(2) flushes all dirty buffers. Forwarding to host sync() stalls
 * because the guest slab is mmap'd MAP_SHARED to internal tempfile (g->shm_fd)
 * for the CoW fork fast path: a global flush has to walk multi-GB of
 * demand-paged dirty pages from that tempfile, plus the same from any other
 * elfuse process running on the host. The slab tempfile is implementation
 * detail; the guest never opened it. Iterate the guest fd table and the region
 * overlay backing fds, dup each under its lock, release the lock, and fsync the
 * dups outside any guest lock so a slow disk cannot stall concurrent mmap/fd
 * operations on other threads. fsync on non-regular fds returns EINVAL on
 * macOS, which is benign and ignored. Always returns 0 to mirror sync(2)'s
 * "void" spirit.
 */
/* Inline fallback: under malloc failure the bulk-dup path cannot proceed, so
 * iterate one fd at a time, dupping under the matching lock and fsync outside
 * it. Slower (acquires/releases fd_lock per regular fd) but keeps sync(2)
 * honest under memory pressure instead of silently no-opping.
 */
static void sc_sync_fdtable_inline(void)
{
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        pthread_mutex_lock(&fd_lock);
        int t = fd_table[i].type;
        int duped = -1;
        if (t == FD_REGULAR || t == FD_DIR)
            duped = dup(fd_table[i].host_fd);
        pthread_mutex_unlock(&fd_lock);
        if (duped < 0)
            continue;
        (void) fsync(duped);
        close(duped);
    }
}

static void sc_sync_regions_inline(guest_t *g)
{
    /* Region count can change under us once mmap_lock is released, so
     * resnapshot under the lock each iteration; the i index is a live cursor
     * into g->regions[] so a concurrent insertion (always at the sorted
     * position) cannot make us skip an entry permanently.
     */
    for (int i = 0;; i++) {
        pthread_mutex_lock(&mmap_lock);
        if (i >= g->nregions) {
            pthread_mutex_unlock(&mmap_lock);
            break;
        }
        const guest_region_t *r = &g->regions[i];
        int duped = -1;
        if (r->shared && r->backing_fd >= 0)
            duped = dup(r->backing_fd);
        pthread_mutex_unlock(&mmap_lock);
        if (duped < 0)
            continue;
        (void) fsync(duped);
        close(duped);
    }
}

static int64_t sc_sync_impl(guest_t *g)
{
    size_t cap = FD_TABLE_SIZE + GUEST_MAX_REGIONS;
    int *hosts = malloc(cap * sizeof(int));
    if (!hosts) {
        sc_sync_fdtable_inline();
        sc_sync_regions_inline(g);
        return 0;
    }
    int n = 0;

    pthread_mutex_lock(&fd_lock);
    for (int i = 0; i < FD_TABLE_SIZE && n < (int) cap; i++) {
        int t = fd_table[i].type;
        if (t != FD_REGULAR && t != FD_DIR)
            continue;
        int duped = dup(fd_table[i].host_fd);
        if (duped < 0)
            continue;
        hosts[n++] = duped;
    }
    pthread_mutex_unlock(&fd_lock);

    pthread_mutex_lock(&mmap_lock);
    for (int i = 0; i < g->nregions && n < (int) cap; i++) {
        const guest_region_t *r = &g->regions[i];
        if (!r->shared || r->backing_fd < 0)
            continue;
        int duped = dup(r->backing_fd);
        if (duped < 0)
            continue;
        hosts[n++] = duped;
    }
    pthread_mutex_unlock(&mmap_lock);

    /* fsync each dup outside both locks so a slow disk does not stall
     * concurrent FD or memory operations on other threads.
     */
    for (int i = 0; i < n; i++) {
        (void) fsync(hosts[i]);
        close(hosts[i]);
    }
    free(hosts);
    return 0;
}
SC_FORWARD(sc_sync, sc_sync_impl(g))

/* SysV IPC */
SC_FORWARD(sc_shmget, sys_shmget(g, (int32_t) x0, x1, (int) x2))
SC_LOCKED(sc_shmdt,   sys_shmdt(g, x0))
SC_FORWARD(sc_shmctl, sys_shmctl(g, (int) x0, (int) x1, x2))
SC_FORWARD(sc_semget, sys_semget(g, (int32_t) x0, (int) x1, (int) x2))
SC_FORWARD(sc_semop,  sys_semop(g, (int) x0, x1, (unsigned) x2))
SC_FORWARD(sc_semctl, sys_semctl(g, (int) x0, (int) x1, (int) x2, x3))
SC_FORWARD(sc_msgget, sys_msgget(g, (int32_t) x0, (int) x1))
SC_FORWARD(sc_msgsnd, sys_msgsnd(g, (int) x0, x1, x2, (int) x3))
SC_FORWARD(sc_msgrcv, sys_msgrcv(g, (int) x0, x1, x2, (int64_t) x3, (int) x4))
SC_FORWARD(sc_msgctl, sys_msgctl(g, (int) x0, (int) x1, x2))

/* Locked forwarding wrappers (hold mmap_lock). */

SC_LOCKED(sc_brk,      sys_brk(g, x0))
SC_LOCKED(sc_munmap,   sys_munmap(g, x0, x1))
SC_LOCKED(sc_mprotect, sys_mprotect(g, x0, x1, (int) x2))
SC_LOCKED(sc_madvise,  sys_madvise(g, x0, x1, (int) x2))
SC_LOCKED(sc_msync,    sys_msync(g, x0, x1, (int) x2))
SC_LOCKED(sc_shmat,    sys_shmat(g, (int) x0, x1, (int) x2))

/* Constant stubs. */

SC_FORWARD(sc_getuid,   (int64_t) proc_get_uid())
SC_FORWARD(sc_geteuid,  (int64_t) proc_get_euid())
SC_FORWARD(sc_getgid,   (int64_t) proc_get_gid())
SC_FORWARD(sc_getegid,  (int64_t) proc_get_egid())
SC_FORWARD(sc_setuid,   CRED_BRACKETED(g, proc_sys_setuid((uint32_t) x0)))
SC_FORWARD(sc_setgid,   CRED_BRACKETED(g, proc_sys_setgid((uint32_t) x0)))
SC_FORWARD(sc_setreuid,  CRED_BRACKETED(g, proc_sys_setreuid((uint32_t) x0, (uint32_t) x1)))
SC_FORWARD(sc_setregid,  CRED_BRACKETED(g, proc_sys_setregid((uint32_t) x0, (uint32_t) x1)))
SC_FORWARD(sc_setresuid, CRED_BRACKETED(g, proc_sys_setresuid((uint32_t) x0, (uint32_t) x1, (uint32_t) x2)))
SC_FORWARD(sc_setresgid, CRED_BRACKETED(g, proc_sys_setresgid((uint32_t) x0, (uint32_t) x1, (uint32_t) x2)))

/* setfs{uid,gid}: Linux returns the previous fs{uid,gid} and only mutates state
 * on a permitted transition. elfuse does not track fsuid separately from euid,
 * so report the current e{uid,gid} and ignore the change. procps brackets /proc
 * walks with setfsuid(uid)/setfsuid(0); both calls observe a stable cred
 * snapshot, which is what it needs.
 */
SC_FORWARD(sc_setfsuid, (int64_t) proc_get_euid())
SC_FORWARD(sc_setfsgid, (int64_t) proc_get_egid())
SC_FORWARD(sc_setpgid, proc_sys_setpgid(g, (int64_t) x0, (int64_t) x1))
SC_STUB(sc_fadvise64,           0)
SC_STUB(sc_sync_file_range,     0)
SC_STUB(sc_sched_yield,         (sched_yield(), 0))
SC_STUB(sc_mlock,               0)
SC_STUB(sc_munlock,             0)
SC_STUB(sc_mlockall,            0)
SC_STUB(sc_munlockall,          0)
SC_STUB(sc_set_mempolicy,       0)
SC_STUB(sc_io_destroy,          -LINUX_EINVAL)
SC_STUB(sc_sethostname,         -LINUX_EPERM)
SC_STUB(sc_mincore,             -LINUX_ENOSYS)
/* clang-format on */

SC_FORWARD(sc_setpriority, proc_sys_setpriority((int) x0, (int) x1, (int) x2))
SC_FORWARD(sc_getpriority, proc_sys_getpriority((int) x0, (int) x1))

/* get_mempolicy: return MPOL_DEFAULT. Single-node machine, no NUMA. */
static int64_t sc_get_mempolicy(guest_t *g,
                                uint64_t x0,
                                uint64_t x1,
                                uint64_t x2,
                                uint64_t x3,
                                uint64_t x4,
                                uint64_t x5,
                                bool verbose)
{
    (void) x2;
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    /* x0 = int __user *policy, x1 = unsigned long __user *nmask */
    if (x0) {
        int32_t policy = 0; /* MPOL_DEFAULT */
        if (guest_write_small(g, x0, &policy, sizeof(policy)) < 0)
            return -LINUX_EFAULT;
    }
    if (x1) {
        /* Clear the nodemask (one word, node 0 only) */
        uint64_t nmask = 1; /* node 0 */
        if (guest_write_small(g, x1, &nmask, sizeof(nmask)) < 0)
            return -LINUX_EFAULT;
    }
    return 0;
}

/* capset: unprivileged process cannot set capabilities. */
SC_FORWARD(sc_capset, -LINUX_EPERM)

/* sched_setaffinity: accept masks that include CPU 0, reject empty masks. */
static int64_t sc_sched_setaffinity(guest_t *g,
                                    uint64_t x0,
                                    uint64_t x1,
                                    uint64_t x2,
                                    uint64_t x3,
                                    uint64_t x4,
                                    uint64_t x5,
                                    bool verbose)
{
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    int pid = (int) x0;
    uint64_t cpusetsize = x1, mask_gva = x2;
    /* Only self */
    if (pid != 0 && pid != (int) proc_get_pid())
        return -LINUX_ESRCH;
    if (cpusetsize == 0)
        return -LINUX_EINVAL;
    /* Linux accepts short masks as long as at least one supplied bit is set.
     * elfuse only supports CPU 0, so require bit 0 in the first byte.
     */
    if (cpusetsize > sizeof(uint64_t))
        cpusetsize = sizeof(uint64_t);
    uint64_t mask = 0;
    if (guest_read_small(g, mask_gva, &mask, cpusetsize) < 0)
        return -LINUX_EFAULT;
    if (!(mask & 1))
        return -LINUX_EINVAL;
    return 0;
}

/* Callback for thread_for_each: force-exit each worker vCPU. Skips the calling
 * thread. Used by exit_group and membarrier.
 */
static void thread_force_exit_cb(thread_entry_t *t, void *ctx)
{
    (void) ctx;
    if (t == current_thread)
        return;
    hv_vcpus_exit(&t->vcpu, 1);
}

/* membarrier: real implementation with barrier semantics. */

#define MEMBARRIER_CMD_QUERY 0
#define MEMBARRIER_CMD_GLOBAL (1 << 0)
#define MEMBARRIER_CMD_GLOBAL_EXPEDITED (1 << 1)
#define MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED (1 << 2)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED (1 << 3)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED (1 << 4)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE (1 << 5)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE (1 << 6)

#define MEMBARRIER_SUPPORTED_CMDS                              \
    (MEMBARRIER_CMD_GLOBAL | MEMBARRIER_CMD_GLOBAL_EXPEDITED | \
     MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED |                \
     MEMBARRIER_CMD_PRIVATE_EXPEDITED |                        \
     MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED |               \
     MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE |              \
     MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE)

static int64_t sc_membarrier(guest_t *g,
                             uint64_t x0,
                             uint64_t x1,
                             uint64_t x2,
                             uint64_t x3,
                             uint64_t x4,
                             uint64_t x5,
                             bool verbose)
{
    (void) g;
    (void) x2;
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    int cmd = (int) x0;
    /* x1 = flags, must be 0 */
    if ((int) x1 != 0)
        return -LINUX_EINVAL;
    switch (cmd) {
    case MEMBARRIER_CMD_QUERY:
        return MEMBARRIER_SUPPORTED_CMDS;
    case MEMBARRIER_CMD_GLOBAL:
    case MEMBARRIER_CMD_GLOBAL_EXPEDITED:
    case MEMBARRIER_CMD_PRIVATE_EXPEDITED:
    case MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE:
        /* Issue full barrier on this thread, force context switch on others */
        __sync_synchronize();
        thread_for_each(thread_force_exit_cb, NULL);
        return 0;
    case MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED:
    case MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED:
    case MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE:
        /* Registration is a no-op; all commands are always supported */
        return 0;
    default:
        return -LINUX_EINVAL;
    }
}

/* Complex handlers (non-trivial logic). */

static int64_t sc_exit_group(guest_t *g,
                             uint64_t x0,
                             uint64_t x1,
                             uint64_t x2,
                             uint64_t x3,
                             uint64_t x4,
                             uint64_t x5,
                             bool verbose)
{
    (void) g;
    (void) x1;
    (void) x2;
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    proc_request_exit_group((int) x0);
    wakeup_pipe_signal();
    thread_for_each(thread_force_exit_cb, NULL);
    thread_join_workers();
    return SC_EXIT_SENTINEL | ((int) x0 & 0xFF);
}

static int64_t sc_set_tid_address(guest_t *g,
                                  uint64_t x0,
                                  uint64_t x1,
                                  uint64_t x2,
                                  uint64_t x3,
                                  uint64_t x4,
                                  uint64_t x5,
                                  bool verbose)
{
    (void) g;
    (void) x1;
    (void) x2;
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    if (current_thread) {
        current_thread->clear_child_tid = x0;
        return current_thread->guest_tid;
    }
    return proc_get_pid();
}

static int64_t sc_mmap(guest_t *g,
                       uint64_t x0,
                       uint64_t x1,
                       uint64_t x2,
                       uint64_t x3,
                       uint64_t x4,
                       uint64_t x5,
                       bool verbose)
{
    pthread_mutex_lock(&mmap_lock);
    int64_t r = sys_mmap(g, x0, x1, (int) x2, (int) x3, (int) x4, (int64_t) x5);
    pthread_mutex_unlock(&mmap_lock);
    log_debug("  mmap(0x%llx, 0x%llx) \xe2\x86\x92 0x%llx",
              (unsigned long long) x0, (unsigned long long) x1,
              (unsigned long long) (uint64_t) r);
    return r;
}

static int64_t sc_mremap(guest_t *g,
                         uint64_t x0,
                         uint64_t x1,
                         uint64_t x2,
                         uint64_t x3,
                         uint64_t x4,
                         uint64_t x5,
                         bool verbose)
{
    (void) x5;
    pthread_mutex_lock(&mmap_lock);
    int64_t r = sys_mremap(g, x0, x1, x2, (int) x3, x4);
    pthread_mutex_unlock(&mmap_lock);
    log_debug("  mremap(0x%llx, 0x%llx, 0x%llx, 0x%x) \xe2\x86\x92 0x%llx",
              (unsigned long long) x0, (unsigned long long) x1,
              (unsigned long long) x2, (int) x3,
              (unsigned long long) (uint64_t) r);
    return r;
}

static int64_t sc_kill(guest_t *g,
                       uint64_t x0,
                       uint64_t x1,
                       uint64_t x2,
                       uint64_t x3,
                       uint64_t x4,
                       uint64_t x5,
                       bool verbose)
{
    (void) g;
    (void) x2;
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    int sig = (int) x1, pid = (int) x0;
    int64_t our_pid = proc_get_pid();
    if (sig < 0 || sig > LINUX_NSIG)
        return -LINUX_EINVAL;
    if (sig == 0) {
        int64_t r = (pid == (int) our_pid || pid == 0 || pid == -1 ||
                     pid == -(int) our_pid)
                        ? 0
                        : -LINUX_ESRCH;
        if (r == -LINUX_ESRCH) {
            pid_t hpid = proc_guest_to_host_pid((int64_t) pid);
            if (hpid > 0)
                r = (kill(hpid, 0) == 0) ? 0 : -LINUX_ESRCH;
        }
        return r;
    }
    if (pid == (int) our_pid || pid == 0 || pid == -1 ||
        pid == -(int) our_pid) {
        signal_queue(sig);
        return 0;
    }
    pid_t hpid = proc_guest_to_host_pid((int64_t) pid);
    if (hpid > 0)
        return (proc_send_guest_signal(hpid, sig) == 0) ? 0 : linux_errno();
    return -LINUX_ESRCH;
}

static int64_t sc_tgkill(guest_t *g,
                         uint64_t x0,
                         uint64_t x1,
                         uint64_t x2,
                         uint64_t x3,
                         uint64_t x4,
                         uint64_t x5,
                         bool verbose)
{
    (void) g;
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    int sig = (int) x2, tid = (int) x1;
    if (sig < 0 || sig > LINUX_NSIG)
        return -LINUX_EINVAL;
    thread_entry_t *target = thread_find((int64_t) tid);
    if (!target) {
        if (tid == (int) proc_get_pid())
            target = current_thread;
    }
    if (target) {
        if (sig > 0)
            signal_queue(sig);
        return 0;
    }
    return -LINUX_ESRCH;
}

static int64_t sc_rt_tgsigqueueinfo(guest_t *g,
                                    uint64_t x0,
                                    uint64_t x1,
                                    uint64_t x2,
                                    uint64_t x3,
                                    uint64_t x4,
                                    uint64_t x5,
                                    bool verbose)
{
    (void) x4;
    (void) x5;
    int tgid = (int) x0, tid = (int) x1, sig = (int) x2;
    uint64_t uinfo_gva = x3;
    (void) tgid;
    if (sig < 1 || sig > LINUX_NSIG)
        return -LINUX_EINVAL;
    thread_entry_t *target = thread_find((int64_t) tid);
    if (!target) {
        if (tid == (int) proc_get_pid())
            target = current_thread;
    }
    if (!target)
        return -LINUX_ESRCH;
    linux_siginfo_t info;
    memset(&info, 0, sizeof(info));
    if (uinfo_gva && guest_read_small(g, uinfo_gva, &info, sizeof(info)) < 0) {
        log_debug(
            "rt_tgsigqueueinfo(tgid=%d, tid=%d, sig=%d, "
            "uinfo=0x%llx [unreadable])",
            tgid, tid, sig, (unsigned long long) uinfo_gva);
        return -LINUX_EFAULT;
    }
    if (uinfo_gva) {
        bool is_fault =
            (sig == LINUX_SIGTRAP || sig == LINUX_SIGSEGV ||
             sig == LINUX_SIGBUS || sig == LINUX_SIGFPE || sig == LINUX_SIGILL);
        if (is_fault && info.si_code > 0) {
            uint64_t fault_addr;
            memcpy(&fault_addr, &info.si_pid, sizeof(fault_addr));
            signal_set_fault_info(info.si_code, fault_addr, 0);
            log_debug(
                "rt_tgsigqueueinfo(tgid=%d, tid=%d, sig=%d, "
                "si_code=%d, fault_addr=0x%llx)",
                tgid, tid, sig, info.si_code, (unsigned long long) fault_addr);
        } else
            log_debug("rt_tgsigqueueinfo(tgid=%d, tid=%d, sig=%d, si_code=%d)",
                      tgid, tid, sig, info.si_code);
    }
    /* Queued signals carry sigval in si_value for both standard and RT signals;
     * standard signals still coalesce to one pending instance.
     */
    if (uinfo_gva) {
        int32_t si_int = 0;
        memcpy(&si_int, &info.si_value, sizeof(si_int));
        uint64_t si_ptr = 0;
        memcpy(&si_ptr, &info.si_value, sizeof(si_ptr));
        signal_queue_info(sig, info.si_code, info.si_pid,
                          (uint32_t) info.si_uid, si_int, si_ptr);
    } else {
        signal_queue(sig);
    }
    return 0;
}

/* rt_sigqueueinfo(pid, sig, info) -- POSIX sigqueue() in glibc/musl uses this.
 *
 * The first argument is documented as a process identifier, but real Linux is
 * permissive: kill_pid_info() looks pid up in the task table and routes the
 * signal through PIDTYPE_TGID, so a thread id that resolves to a task succeeds
 * and the signal lands in that task's thread-group pending set. Foreign pids
 * that match no task return -ESRCH.
 *
 * elfuse mirrors this by forwarding to sc_rt_tgsigqueueinfo with
 * tgid==tid==pid: the downstream thread_find() lookup accepts any guest
 * thread's tid (collapsing to the single guest tgid), the proc_get_pid()
 * fallback accepts the main thread's tid, and unknown pids fall through to
 * -ESRCH. signal_queue_info() then queues process-wide so the routing semantics
 * match Linux even though the lookup goes through the per-thread table.
 *
 * Earlier review feedback flagged "incorrectly accepting thread ids" and
 * recommended a strict pid==tgid gate; that gate was tried and rejected because
 * the qemu/Linux reference accepts the same tids.
 */
static int64_t sc_rt_sigqueueinfo(guest_t *g,
                                  uint64_t x0,
                                  uint64_t x1,
                                  uint64_t x2,
                                  uint64_t x3,
                                  uint64_t x4,
                                  uint64_t x5,
                                  bool verbose)
{
    (void) x3;
    (void) x4;
    (void) x5;
    return sc_rt_tgsigqueueinfo(g, x0, x0, x1, x2, 0, 0, verbose);
}

static int64_t sc_rt_sigreturn(guest_t *g,
                               uint64_t x0,
                               uint64_t x1,
                               uint64_t x2,
                               uint64_t x3,
                               uint64_t x4,
                               uint64_t x5,
                               bool verbose)
{
    (void) x0;
    (void) x1;
    (void) x2;
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    int ret = signal_rt_sigreturn(current_thread->vcpu, g);
    return (ret == SYSCALL_EXEC_HAPPENED) ? SYSCALL_EXEC_HAPPENED : ret;
}

static int64_t sc_prctl(guest_t *g,
                        uint64_t x0,
                        uint64_t x1,
                        uint64_t x2,
                        uint64_t x3,
                        uint64_t x4,
                        uint64_t x5,
                        bool verbose)
{
    (void) x5;
    (void) verbose;
    switch ((int) x0) {
    case LINUX_PR_SET_NAME:
    case LINUX_PR_GET_NAME:
        return 0;
    case LINUX_PR_SET_PDEATHSIG:
        return 0;
    case LINUX_PR_GET_PDEATHSIG: {
        int32_t sig = 0;
        if (x1 && guest_write_small(g, x1, &sig, sizeof(sig)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }
    case LINUX_PR_SET_NO_NEW_PRIVS:
        return 0;
    case LINUX_PR_GET_NO_NEW_PRIVS:
        return 1;
    case LINUX_PR_SET_DUMPABLE:
        return 0;
    case LINUX_PR_GET_DUMPABLE:
        return 1;
    case LINUX_PR_SET_CHILD_SUBREAPER:
        /* Accept silently. elfuse's process model already reaps all children
         * within the VM; the flag has no additional effect.
         */
        return 0;
    case LINUX_PR_GET_CHILD_SUBREAPER: {
        /* Always report "subreaper is set," consistent with the
         * accept-and-ignore behavior of PR_SET_CHILD_SUBREAPER.
         */
        int32_t val = 1;
        if (x1 && guest_write_small(g, x1, &val, sizeof(val)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }
    case LINUX_PR_CAPBSET_READ:
        /* Match the guest sysroot's capability namespace. Linux rejects
         * undefined capability numbers with EINVAL, and userspace probes
         * CAP_LAST_CAP by walking upward until the first failure.
         */
        return (x1 <= LINUX_CAP_LAST_CAP) ? 1 : -LINUX_EINVAL;
    case LINUX_PR_SET_VMA:
        /* PR_SET_VMA with PR_SET_VMA_ANON_NAME: accept and ignore. Android and
         * memory profiling tools use this to name anonymous mmap regions. The
         * name is purely advisory.
         */
        if ((int) x1 == LINUX_PR_SET_VMA_ANON_NAME)
            return 0;
        return -LINUX_EINVAL;
    case LINUX_PR_SET_MEM_MODEL:
        return -LINUX_EINVAL;
    case LINUX_PR_GET_MEM_MODEL:
        if (x1 || x2 || x3 || x4)
            return -LINUX_EINVAL;
        if (current_thread) {
            uint64_t actlr = 0;
            hv_vcpu_get_sys_reg(current_thread->vcpu, HV_SYS_REG_ACTLR_EL1,
                                &actlr);
            return (actlr & (1ULL << 1)) ? LINUX_PR_SET_MEM_MODEL_TSO
                                         : LINUX_PR_SET_MEM_MODEL_DEFAULT;
        }
        return LINUX_PR_SET_MEM_MODEL_DEFAULT;
    default:
        return -LINUX_ENOSYS;
    }
}

static int64_t sc_set_robust_list(guest_t *g,
                                  uint64_t x0,
                                  uint64_t x1,
                                  uint64_t x2,
                                  uint64_t x3,
                                  uint64_t x4,
                                  uint64_t x5,
                                  bool verbose)
{
    (void) g;
    (void) x2;
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    if (x1 != 24)
        return -LINUX_EINVAL;
    if (current_thread)
        current_thread->robust_list_head = x0;
    return 0;
}

static int64_t sc_get_robust_list(guest_t *g,
                                  uint64_t x0,
                                  uint64_t x1,
                                  uint64_t x2,
                                  uint64_t x3,
                                  uint64_t x4,
                                  uint64_t x5,
                                  bool verbose)
{
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    int64_t target_pid = (int64_t) (int) x0;
    if (target_pid != 0 && target_pid != proc_get_pid() &&
        (!current_thread || target_pid != current_thread->guest_tid))
        return -LINUX_ESRCH;
    uint64_t head_val = current_thread ? current_thread->robust_list_head : 0;
    uint64_t len_val = 24;
    if (x1 && guest_write_small(g, x1, &head_val, sizeof(head_val)) < 0)
        return -LINUX_EFAULT;
    if (x2 && guest_write_small(g, x2, &len_val, sizeof(len_val)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* rseq: restartable sequences registration with per-thread state.
 *
 * struct rseq layout (Linux 4.18+, 32 bytes minimum):
 *   offset 0:  cpu_id_start (u32): current CPU ID
 *   offset 4:  cpu_id (u32):      same, volatile access
 *   offset 8:  rseq_cs (u64):     pointer to active rseq_cs descriptor
 *   offset 16: flags (u32):       per-thread flags
 *
 * struct rseq_cs layout (set by userspace before critical section):
 *   offset 0:  version (u32)
 *   offset 4:  flags (u32)
 *   offset 8:  start_ip (u64)
 *   offset 16: post_commit_offset (u64)
 *   offset 24: abort_ip (u64)
 */
#define RSEQ_FLAG_UNREGISTER 1

static int64_t sc_rseq(guest_t *g,
                       uint64_t x0,
                       uint64_t x1,
                       uint64_t x2,
                       uint64_t x3,
                       uint64_t x4,
                       uint64_t x5,
                       bool verbose)
{
    (void) x4;
    (void) x5;
    (void) verbose;
    uint64_t rseq_addr = x0;
    uint32_t rseq_len = (uint32_t) x1, flags = (uint32_t) x2;
    uint32_t sig = (uint32_t) x3;

    if (flags & ~(uint32_t) RSEQ_FLAG_UNREGISTER)
        return -LINUX_EINVAL;
    if (rseq_len < 32)
        return -LINUX_EINVAL;

    thread_entry_t *t = current_thread;
    if (!t)
        return -LINUX_EINVAL;

    if (flags & RSEQ_FLAG_UNREGISTER) {
        /* Unregistration: addr must match current registration */
        if (t->rseq_gva == 0)
            return -LINUX_EINVAL;
        if (t->rseq_gva != rseq_addr || t->rseq_signature != sig)
            return -LINUX_EINVAL;
        t->rseq_gva = 0;
        t->rseq_len = 0;
        t->rseq_signature = 0;
        return 0;
    }

    /* Registration */
    if (t->rseq_gva != 0)
        return -LINUX_EBUSY; /* Already registered */

    /* Write initial rseq fields: cpu_id_start=0, cpu_id=0, rseq_cs=0, flags=0
     */
    uint32_t cpu_id = 0;
    uint64_t rseq_cs = 0;
    uint32_t rseq_flags = 0;
    if (guest_write_small(g, rseq_addr + 0, &cpu_id, sizeof(cpu_id)) < 0 ||
        guest_write_small(g, rseq_addr + 4, &cpu_id, sizeof(cpu_id)) < 0 ||
        guest_write_small(g, rseq_addr + 8, &rseq_cs, sizeof(rseq_cs)) < 0 ||
        guest_write_small(g, rseq_addr + 16, &rseq_flags, sizeof(rseq_flags)) <
            0)
        return -LINUX_EFAULT;

    t->rseq_gva = rseq_addr;
    t->rseq_len = rseq_len;
    t->rseq_signature = sig;
    return 0;
}

static int64_t sc_flock(guest_t *g,
                        uint64_t x0,
                        uint64_t x1,
                        uint64_t x2,
                        uint64_t x3,
                        uint64_t x4,
                        uint64_t x5,
                        bool verbose)
{
    (void) g;
    (void) x2;
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_io((int) x0, &host_ref);
    if (err < 0)
        return err;
    int64_t ret = flock(host_ref.fd, (int) x1) < 0 ? linux_errno() : 0;
    host_fd_ref_close(&host_ref);
    return ret;
}

/* fsync and fdatasync: macOS has no fdatasync(), so both call fsync() */
static int64_t sc_fsync_common(guest_t *g,
                               uint64_t x0,
                               uint64_t x1,
                               uint64_t x2,
                               uint64_t x3,
                               uint64_t x4,
                               uint64_t x5,
                               bool verbose)
{
    (void) g;
    (void) x1;
    (void) x2;
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_io((int) x0, &host_ref);
    if (err < 0)
        return err;
    int64_t ret = (fsync(host_ref.fd) < 0) ? linux_errno() : 0;
    host_fd_ref_close(&host_ref);
    return ret;
}
#define sc_fsync sc_fsync_common
#define sc_fdatasync sc_fsync_common

/* getresuid/getresgid: write emulated real/effective/saved IDs to guest ptrs */
static int64_t sc_getresid_write(guest_t *g,
                                 uint64_t x0,
                                 uint64_t x1,
                                 uint64_t x2,
                                 uint32_t r,
                                 uint32_t e,
                                 uint32_t s)
{
    if ((x0 && guest_write_small(g, x0, &r, sizeof(r)) < 0) ||
        (x1 && guest_write_small(g, x1, &e, sizeof(e)) < 0) ||
        (x2 && guest_write_small(g, x2, &s, sizeof(s)) < 0))
        return -LINUX_EFAULT;
    return 0;
}

SC_FORWARD(sc_getresuid,
           sc_getresid_write(g,
                             x0,
                             x1,
                             x2,
                             proc_get_uid(),
                             proc_get_euid(),
                             proc_get_suid()))
SC_FORWARD(sc_getresgid,
           sc_getresid_write(g,
                             x0,
                             x1,
                             x2,
                             proc_get_gid(),
                             proc_get_egid(),
                             proc_get_sgid()))

static int64_t sc_personality(guest_t *g,
                              uint64_t x0,
                              uint64_t x1,
                              uint64_t x2,
                              uint64_t x3,
                              uint64_t x4,
                              uint64_t x5,
                              bool verbose)
{
    (void) g;
    (void) x1;
    (void) x2;
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    if (x0 == 0xFFFFFFFFULL || x0 == 0)
        return 0;
    return -LINUX_EINVAL;
}

static int64_t sc_capget(guest_t *g,
                         uint64_t x0,
                         uint64_t x1,
                         uint64_t x2,
                         uint64_t x3,
                         uint64_t x4,
                         uint64_t x5,
                         bool verbose)
{
    (void) x2;
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    if (!x0)
        return -LINUX_EFAULT;
    uint32_t hdr[2];
    if (guest_read_small(g, x0, hdr, sizeof(hdr)) < 0)
        return -LINUX_EFAULT;
    if (hdr[0] != 0x20080522) {
        hdr[0] = 0x20080522;
        guest_write_small(g, x0, hdr, sizeof(hdr));
        return -LINUX_EINVAL;
    }
    if (x1) {
        uint32_t data[6] = {0};
        if (guest_write_small(g, x1, data, sizeof(data)) < 0)
            return -LINUX_EFAULT;
    }
    return 0;
}

static int64_t sc_memfd_create(guest_t *g,
                               uint64_t x0,
                               uint64_t x1,
                               uint64_t x2,
                               uint64_t x3,
                               uint64_t x4,
                               uint64_t x5,
                               bool verbose)
{
    (void) x2;
    (void) x3;
    (void) x4;
    (void) x5;
    (void) verbose;
    if (!x0)
        return -LINUX_EFAULT;

    const unsigned int flags = (unsigned int) x1;

    char first = '\0';
    if (guest_read_small(g, x0, &first, sizeof(first)) < 0)
        return -LINUX_EFAULT;

    char template[] = "/tmp/elfuse-memfd-XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0)
        return linux_errno();
    unlink(template);
    int gfd = fd_alloc(FD_REGULAR, fd, NULL);
    if (gfd < 0) {
        close(fd);
        return linux_errno();
    }
    if (flags & LINUX_MFD_CLOEXEC)
        fd_table[gfd].linux_flags |= LINUX_O_CLOEXEC;
    fd_table[gfd].seals =
        (flags & LINUX_MFD_ALLOW_SEALING) ? 0 : LINUX_F_SEAL_SEAL;
    return gfd;
}

/* openat2 RESOLVE_* flags (from Linux include/uapi/linux/openat2.h). */
#define RESOLVE_NO_XDEV 0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS 0x04
#define RESOLVE_BENEATH 0x08
#define RESOLVE_IN_ROOT 0x10
#define RESOLVE_CACHED 0x20
#define RESOLVE_ALL                                                  \
    (RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | \
     RESOLVE_BENEATH | RESOLVE_IN_ROOT | RESOLVE_CACHED)

/* Linux openat2() treats the user-supplied open_how size as an ABI version. The
 * first published layout has three u64 fields (flags, mode, resolve), so v0 is
 * 24 bytes. Bytes beyond that are future extension fields: all-zero tails are
 * ignored, nonzero tails return E2BIG. Keep the same page-sized upper bound
 * Linux applies before checking the tail.
 */
#define OPEN_HOW_SIZE_VER0 24
#define OPEN_HOW_MAX_SIZE 4096

static int64_t openat2_check_zero_tail(guest_t *g,
                                       uint64_t how_gva,
                                       uint64_t size)
{
    if (size == OPEN_HOW_SIZE_VER0)
        return 0;

    uint64_t off = OPEN_HOW_SIZE_VER0;
    while (off < size) {
        uint8_t tail[64];
        size_t chunk = (size_t) (size - off);
        if (chunk > sizeof(tail))
            chunk = sizeof(tail);
        if (how_gva > UINT64_MAX - off ||
            guest_read_small(g, how_gva + off, tail, chunk) < 0)
            return -LINUX_EFAULT;
        for (size_t i = 0; i < chunk; i++) {
            if (tail[i] != 0)
                return -LINUX_E2BIG;
        }
        off += chunk;
    }
    return 0;
}

static bool openat2_flags_valid(uint64_t flags, uint64_t mode)
{
    const uint64_t known_flags =
        LINUX_O_ACCMODE | LINUX_O_CREAT | LINUX_O_EXCL | LINUX_O_NOCTTY |
        LINUX_O_TRUNC | LINUX_O_APPEND | LINUX_O_NONBLOCK | LINUX_O_DSYNC |
        LINUX_O_ASYNC | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW | LINUX_O_DIRECT |
        LINUX_O_LARGEFILE | LINUX_O_NOATIME | LINUX_O_CLOEXEC | LINUX_O_SYNC |
        LINUX_O_PATH | LINUX___O_TMPFILE;

    if (flags & ~known_flags)
        return false;
    if ((flags & LINUX_O_PATH) &&
        (flags & ~(LINUX_O_PATH | LINUX_O_CLOEXEC | LINUX_O_DIRECTORY |
                   LINUX_O_NOFOLLOW)))
        return false;
    if (flags & LINUX___O_TMPFILE)
        return false;
    if ((flags & (LINUX_O_DIRECTORY | LINUX_O_CREAT)) ==
        (LINUX_O_DIRECTORY | LINUX_O_CREAT))
        return false;
    if (mode & ~07777ULL)
        return false;
    if (mode != 0 && !(flags & LINUX_O_CREAT))
        return false;

    return true;
}

static int64_t sc_openat2(guest_t *g,
                          uint64_t x0,
                          uint64_t x1,
                          uint64_t x2,
                          uint64_t x3,
                          uint64_t x4,
                          uint64_t x5,
                          bool verbose)
{
    (void) x4;
    (void) x5;
    (void) verbose;
    if (x3 < OPEN_HOW_SIZE_VER0)
        return -LINUX_EINVAL;
    if (x3 > OPEN_HOW_MAX_SIZE)
        return -LINUX_E2BIG;
    uint64_t how[3];
    if (guest_read_small(g, x2, how, sizeof(how)) < 0)
        return -LINUX_EFAULT;
    int64_t tail_rc = openat2_check_zero_tail(g, x2, x3);
    if (tail_rc < 0)
        return tail_rc;

    uint64_t oflags = how[0], mode = how[1];
    uint64_t resolve = how[2];

    if (!openat2_flags_valid(oflags, mode))
        return -LINUX_EINVAL;
    if (resolve & ~(uint64_t) RESOLVE_ALL)
        return -LINUX_EINVAL;
    if ((resolve & RESOLVE_BENEATH) && (resolve & RESOLVE_IN_ROOT))
        return -LINUX_EINVAL;

    /* RESOLVE_CACHED asks the kernel to satisfy lookup from cache only. elfuse
     * has no dentry cache, so report EAGAIN and let the guest retry without
     * this constraint.
     */
    if (resolve & RESOLVE_CACHED)
        return -LINUX_EAGAIN;

    /* For RESOLVE_NO_SYMLINKS, RESOLVE_NO_MAGICLINKS, RESOLVE_BENEATH,
     * RESOLVE_IN_ROOT, RESOLVE_NO_XDEV: read the guest path and enforce
     * constraints before opening.
     */
    if (resolve & (RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
                   RESOLVE_BENEATH | RESOLVE_IN_ROOT | RESOLVE_NO_XDEV)) {
        char path[LINUX_PATH_MAX];
        if (guest_read_str(g, x1, path, sizeof(path)) < 0)
            return -LINUX_EFAULT;

        if ((resolve & (RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)) &&
            path_openat2_is_fd_magiclink_anchor((int) x0, path))
            return -LINUX_ELOOP;

        if (resolve & RESOLVE_NO_SYMLINKS) {
            if (sys_path_has_symlink((int) x0, path) < 0) {
                if (errno == ELOOP)
                    return -LINUX_ELOOP;
                return linux_errno();
            }
            oflags |= LINUX_O_NOFOLLOW;
        }

        if (resolve & RESOLVE_BENEATH) {
            if (path[0] == '/')
                return -LINUX_EXDEV;
        }

        if ((resolve & RESOLVE_BENEATH) &&
            !path_openat2_stays_beneath(path, false))
            return -LINUX_EXDEV;

        if ((resolve & RESOLVE_IN_ROOT) &&
            !path_openat2_stays_beneath(path, true))
            return -LINUX_EXDEV;

        int no_xdev_start_class = -1;
        if (resolve & RESOLVE_NO_XDEV) {
            /* /proc/self/fd/N, /proc/<self_pid>/fd/N, and /dev/fd/N all
             * traverse fd magic links into whatever mount holds the target fd.
             * Reject the normalized anchor up front because procemu can stamp
             * the resulting fd with the symbolic proc/dev path, hiding the real
             * landing mount from the post-open class check.
             */
            if (path_openat2_is_fd_magiclink_anchor((int) x0, path))
                return -LINUX_EXDEV;
            int crossed = path_openat2_crosses_mount(
                (int) x0, path, (resolve & RESOLVE_IN_ROOT) != 0,
                &no_xdev_start_class);
            if (crossed < 0)
                return linux_errno();
            if (crossed > 0)
                return -LINUX_EXDEV;
        }

        if (resolve & (RESOLVE_BENEATH | RESOLVE_IN_ROOT)) {
            if (path_openat2_resolved_within_root(
                    (int) x0, path, oflags, (resolve & RESOLVE_IN_ROOT) != 0) <
                0) {
                if (errno == EXDEV)
                    return -LINUX_EXDEV;
                return linux_errno();
            }
        }

        int64_t opened;
        if (resolve & RESOLVE_IN_ROOT) {
            char rooted[LINUX_PATH_MAX];
            if (path_openat2_normalize_in_root(path, rooted, sizeof(rooted)) <
                0) {
                return -LINUX_ENAMETOOLONG;
            }
            opened =
                sys_openat_path(g, (int) x0, rooted, (int) oflags, (int) mode);
        } else {
            /* Reuse the precheck-validated path[] rather than re-reading from
             * guest VA x1, so a sibling vCPU cannot swap the string between the
             * constraint checks above and the actual open.
             */
            opened =
                sys_openat_path(g, (int) x0, path, (int) oflags, (int) mode);
        }
        if (opened >= 0 && (resolve & RESOLVE_NO_XDEV) &&
            no_xdev_start_class >= 0) {
            /* The string walker cannot see symlinks that the kernel followed
             * during the actual open (sysroot case-fold sidecar shadows hide
             * the link node from the precheck's fstatat walk). Re-classify the
             * opened fd's resolved host path; if it landed in a different mount
             * class, drop the fd and return EXDEV. This also tightens the
             * precheck-vs-open TOCTOU window since the post-check sees the
             * exact path the kernel resolved.
             *
             * Fail closed on post-check errors: a fd whose class cannot be
             * derived must not silently bypass the NO_XDEV contract.
             */
            int crossed =
                path_openat2_check_fd_xdev((int) opened, no_xdev_start_class);
            if (crossed < 0) {
                int err = linux_errno();
                sys_close((int) opened);
                return err;
            }
            if (crossed > 0) {
                sys_close((int) opened);
                return -LINUX_EXDEV;
            }
        }
        return opened;
    }

    return sys_openat(g, (int) x0, x1, (int) oflags, (int) mode);
}

static int64_t sc_epoll_pwait2(guest_t *g,
                               uint64_t x0,
                               uint64_t x1,
                               uint64_t x2,
                               uint64_t x3,
                               uint64_t x4,
                               uint64_t x5,
                               bool verbose)
{
    (void) x5;
    (void) verbose;
    int timeout_ms = -1;
    if (x3) {
        linux_timespec_t ts;
        if (guest_read_small(g, x3, &ts, sizeof(ts)) < 0)
            return -LINUX_EFAULT;
        timeout_ms = (ts.tv_sec > 2000000)
                         ? -1
                         : (int) (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
    }
    return sys_epoll_pwait(g, (int) x0, x1, (int) x2, timeout_ms, x4);
}

static int64_t sc_execve(guest_t *g,
                         uint64_t x0,
                         uint64_t x1,
                         uint64_t x2,
                         uint64_t x3,
                         uint64_t x4,
                         uint64_t x5,
                         bool verbose)
{
    (void) x3;
    (void) x4;
    (void) x5;
    pthread_mutex_lock(&mmap_lock);
    int64_t r = sys_execve(current_thread->vcpu, g, x0, x1, x2, verbose, NULL);
    pthread_mutex_unlock(&mmap_lock);
    return r;
}

static int64_t sc_execveat(guest_t *g,
                           uint64_t x0,
                           uint64_t x1,
                           uint64_t x2,
                           uint64_t x3,
                           uint64_t x4,
                           uint64_t x5,
                           bool verbose)
{
    (void) x5;
    hv_vcpu_t vcpu = current_thread->vcpu;
    int dirfd = (int) x0, flags = (int) x4;

    /* Resolve the target path before taking mmap_lock (path resolution may call
     * fd_to_host / openat which do not need mmap_lock).
     */
    uint64_t path_gva = x1;
    char resolved[LINUX_PATH_MAX];
    bool need_resolve = false;

    if (dirfd == LINUX_AT_FDCWD && !(flags & LINUX_AT_EMPTY_PATH)) {
        /* path_gva is already x1, use directly */
    } else if (flags & LINUX_AT_EMPTY_PATH) {
        host_fd_ref_t dir_ref;
        if (host_fd_ref_open(dirfd, &dir_ref) < 0)
            return -LINUX_EBADF;
        if (fcntl(dir_ref.fd, F_GETPATH, resolved) < 0) {
            host_fd_ref_close(&dir_ref);
            return -LINUX_ENOENT;
        }
        host_fd_ref_close(&dir_ref);
        need_resolve = true;
    } else {
        char pathname[LINUX_PATH_MAX];
        if (guest_read_str(g, x1, pathname, sizeof(pathname)) < 0)
            return -LINUX_EFAULT;
        host_fd_ref_t dir_ref;
        if (host_fd_ref_open(dirfd, &dir_ref) < 0)
            return -LINUX_EBADF;
        int tmp_fd = openat(dir_ref.fd, pathname, O_RDONLY);
        if (tmp_fd < 0) {
            host_fd_ref_close(&dir_ref);
            return linux_errno();
        }
        if (fcntl(tmp_fd, F_GETPATH, resolved) < 0) {
            close(tmp_fd);
            host_fd_ref_close(&dir_ref);
            return -LINUX_ENOENT;
        }
        close(tmp_fd);
        host_fd_ref_close(&dir_ref);
        need_resolve = true;
    }

    pthread_mutex_lock(&mmap_lock);
    int64_t r;
    if (need_resolve) {
        /* Use the host-resolved path directly so execveat does not copy a host
         * pathname back into guest memory.
         */
        r = sys_execve(vcpu, g, 0, x2, x3, verbose, resolved);
    } else {
        r = sys_execve(vcpu, g, path_gva, x2, x3, verbose, NULL);
    }
    pthread_mutex_unlock(&mmap_lock);
    return r;
}

static int64_t sc_clone(guest_t *g,
                        uint64_t x0,
                        uint64_t x1,
                        uint64_t x2,
                        uint64_t x3,
                        uint64_t x4,
                        uint64_t x5,
                        bool verbose)
{
    (void) x5;
    log_debug(
        "clone(flags=0x%llx, stack=0x%llx, ptid=0x%llx, "
        "tls=0x%llx, ctid=0x%llx)",
        (unsigned long long) x0, (unsigned long long) x1,
        (unsigned long long) x2, (unsigned long long) x3,
        (unsigned long long) x4);
    return sys_clone(current_thread->vcpu, g, x0, x1, 0, 0, x2, x3, x4,
                     verbose);
}

static int64_t sc_clone3(guest_t *g,
                         uint64_t x0,
                         uint64_t x1,
                         uint64_t x2,
                         uint64_t x3,
                         uint64_t x4,
                         uint64_t x5,
                         bool verbose)
{
    (void) x2;
    (void) x3;
    (void) x4;
    (void) x5;
    log_debug("clone3(args=0x%llx, size=%llu)", (unsigned long long) x0,
              (unsigned long long) x1);
    return sys_clone3(current_thread->vcpu, g, x0, x1, verbose);
}

static int64_t sc_ptrace(guest_t *g,
                         uint64_t x0,
                         uint64_t x1,
                         uint64_t x2,
                         uint64_t x3,
                         uint64_t x4,
                         uint64_t x5,
                         bool verbose)
{
    (void) x4;
    (void) x5;
    log_debug("ptrace(request=0x%llx, pid=%lld, addr=0x%llx, data=0x%llx)",
              (unsigned long long) x0, (long long) (int64_t) x1,
              (unsigned long long) x2, (unsigned long long) x3);
    return sys_ptrace(g, x0, (int64_t) x1, x2, x3);
}

static int64_t sc_futex_waitv(guest_t *g,
                              uint64_t x0,
                              uint64_t x1,
                              uint64_t x2,
                              uint64_t x3,
                              uint64_t x4,
                              uint64_t x5,
                              bool verbose)
{
    (void) x5;
    (void) verbose;
    return sys_futex_waitv(g, x0, (uint32_t) x1, (uint32_t) x2, x3, (int) x4);
}

/* Generated dispatch table. */

#define SC_TABLE_SIZE 512

#if SC_MAX_SYSCALL_NUM >= SC_TABLE_SIZE
#error "SC_TABLE_SIZE must exceed SC_MAX_SYSCALL_NUM"
#endif

#if defined(ELFUSE_NR_EMBEDDER_HVC6) && (ELFUSE_NR_EMBEDDER_HVC6 + 0 > 0)
_Static_assert(ELFUSE_NR_EMBEDDER_HVC6 > SC_TABLE_SIZE,
               "ELFUSE_NR_EMBEDDER_HVC6 must be outside syscall_table");
#define ELFUSE_ROSETTA_EMBEDDER_SYSCALL 1
#endif

typedef struct {
    syscall_handler_t handler;
    bool needs_extra_regs;
} syscall_entry_t;

/* clang-format off */
static const syscall_entry_t syscall_table[SC_TABLE_SIZE] = {
#define _(nr, sc_handler, extra) \
    [nr] = { .handler = sc_handler, .needs_extra_regs = (extra) != 0 },
    SYSCALL_TABLE_ENTRIES(_)
#undef _
};

/* clang-format on */


/* Main dispatch. */

static int fast_scalar_syscall_result(int nr, uint64_t x0, int64_t *result)
{
    switch (nr) {
    case SYS_getpid:
        *result = proc_get_pid();
        return 1;
    case SYS_getppid:
        *result = proc_get_ppid();
        return 1;
    case SYS_gettid:
        *result = current_thread ? current_thread->guest_tid : proc_get_pid();
        return 1;
    case SYS_getpgid:
        *result = ((int) x0 == 0 || (int) x0 == (int) proc_get_pid())
                      ? proc_get_pgid()
                      : -LINUX_ESRCH;
        return 1;
    case SYS_getuid:
        *result = (int64_t) proc_get_uid();
        return 1;
    case SYS_geteuid:
        *result = (int64_t) proc_get_euid();
        return 1;
    case SYS_getgid:
        *result = (int64_t) proc_get_gid();
        return 1;
    case SYS_getegid:
        *result = (int64_t) proc_get_egid();
        return 1;
    case SYS_fadvise64:
    case SYS_mlock:
    case SYS_munlock:
        *result = 0;
        return 1;
    case SYS_capset:
        *result = -LINUX_EPERM;
        return 1;
    case SYS_io_destroy:
        *result = -LINUX_EINVAL;
        return 1;
    case SYS_sethostname:
        *result = -LINUX_EPERM;
        return 1;
    case SYS_mincore:
        *result = -LINUX_ENOSYS;
        return 1;
    default:
        return 0;
    }
}

int syscall_dispatch(hv_vcpu_t vcpu, guest_t *g, int *exit_code, bool verbose)
{
    uint64_t x0, x1, x2, x3, x4, x5, x8;

    hv_vcpu_get_reg(vcpu, HV_REG_X8, &x8);
    x0 = 0;
    x1 = 0;
    x2 = 0;
    x3 = 0;
    x4 = 0;
    x5 = 0;

    int64_t result = -LINUX_ENOSYS;
    bool should_exit = false;

    /* Fast-path hot syscalls: bypass the full dispatch for trivial process
     * identity queries and short helper cases. Skips the table lookup and
     * wrapper call, but NOT the X0 writeback / TLBI / signal checks that follow
     * it.
     *
     * Single-threaded guests can use the raw host fd directly because there is
     * no concurrent close() race. Multi-threaded guests still dup the fd under
     * fd_lock to prevent TOCTOU races with CLONE_THREAD siblings.
     */
    int nr = (int) x8;
    const syscall_entry_t *entry = NULL;

    /* Per-syscall histogram for the dynamic-linker bring-up storm. Zero when
     * disabled so the bottom-of-dispatch record path is a single branch.
     */
    uint64_t hist_start_ns = syscall_hist_now_ns();

    if (!verbose) {
        if (nr == SYS_getpid || nr == SYS_getppid || nr == SYS_gettid ||
            nr == SYS_getpgid || nr == SYS_getuid || nr == SYS_geteuid ||
            nr == SYS_getgid || nr == SYS_getegid || nr == SYS_fadvise64 ||
            nr == SYS_mlock || nr == SYS_munlock || nr == SYS_capset ||
            nr == SYS_io_destroy || nr == SYS_sethostname ||
            nr == SYS_mincore) {
            if (nr == SYS_getpgid)
                hv_vcpu_get_reg(vcpu, HV_REG_X0, &x0);
            if (fast_scalar_syscall_result(nr, x0, &result))
                goto fast_done;
        }
        if (nr == SYS_read || nr == SYS_write) {
            hv_vcpu_get_reg(vcpu, HV_REG_X0, &x0);
            hv_vcpu_get_reg(vcpu, HV_REG_X1, &x1);
            hv_vcpu_get_reg(vcpu, HV_REG_X2, &x2);
            int fd = (int) x0;
            if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
                goto slow_path;

            /* Pre-filter: only fast-path fd types that map 1:1 to host
             * read/write. This read is racy but benign; if the type changed,
             * fd_to_host_dup will either fail or the slow path handles it
             * correctly on fallthrough.
             */
            int tp = fd_table[fd].type;
            if (tp != FD_REGULAR && tp != FD_STDIO && tp != FD_PIPE &&
                tp != FD_SOCKET)
                goto slow_path;

            /* Proc-backed fds may need synthetic read/write handling (for
             * example, oom_* rereads recompute content on each read and proc
             * dirfds steer relative *at() resolution). Keep them on the slow
             * path so the proc interceptors run.
             */
            if (fd_table[fd].proc_path[0] != '\0')
                goto slow_path;

            host_fd_ref_t host_ref;
            if (host_fd_ref_open(fd, &host_ref) != 0)
                goto slow_path;

            /* Check seals after dup; the fd is still valid */
            if (nr == SYS_write && (fd_table[fd].seals & LINUX_F_SEAL_WRITE)) {
                host_fd_ref_close(&host_ref);
                goto slow_path;
            }
            uint64_t count = x2;
            if (count == 0) {
                host_fd_ref_close(&host_ref);
                goto slow_path;
            }

            /* read() writes into the buffer (needs W); write() reads from the
             * buffer (needs R).
             */
            int perms = (nr == SYS_read) ? MEM_PERM_W : MEM_PERM_R;
            uint64_t avail = 0;
            void *buf = guest_ptr_bound(g, x1, &avail, perms, count);
            if (!buf || avail < count) {
                host_fd_ref_close(&host_ref);
                goto slow_path;
            }

            ssize_t ret = (nr == SYS_read) ? read(host_ref.fd, buf, count)
                                           : write(host_ref.fd, buf, count);
            host_fd_ref_close(&host_ref);
            if (ret >= 0) {
                result = ret;
                goto fast_done;
            }
            result = linux_errno();
            goto fast_done;
        }
    }

slow_path:
    entry = RANGE_CHECK(nr, 0, SC_TABLE_SIZE) ? &syscall_table[nr] : NULL;

/*
 * Private embedder pseudo-syscall for translated guests.
 *
 * This is not a Linux syscall number. Translated x86_64 guests cannot issue
 * native AArch64 HVC instructions, so elfuse uses this private build-selected
 * syscall number as the translated counterpart to HVC 6.
 *
 * This path is gated on g->is_rosetta so native AArch64 guests cannot reach the
 * embedder hook through SVC.
 *
 * Layout:
 *   x8 = ELFUSE_ROSETTA_EMBEDDER_SYSCALL
 *   x0 = embedder call number
 *   x1 = guest virtual address of uint64_t args[8]
 */
#ifdef ELFUSE_ROSETTA_EMBEDDER_SYSCALL
    if (g->is_rosetta && nr == ELFUSE_NR_EMBEDDER_HVC6 && g->hvc6_handler) {
        uint64_t call_nr = 0;
        uint64_t args_gva = 0;
        hv_vcpu_get_reg(vcpu, HV_REG_X0, &call_nr);
        hv_vcpu_get_reg(vcpu, HV_REG_X1, &args_gva);
        uint64_t guest_args[8] = {0};
        if (guest_read_small(g, args_gva, guest_args, sizeof(guest_args)) < 0) {
            result = -LINUX_EFAULT;
        } else {
            result = g->hvc6_handler(call_nr, guest_args, g->hvc6_userdata);
        }
        goto fast_done;
    }
#endif

    hv_vcpu_get_reg(vcpu, HV_REG_X0, &x0);
    hv_vcpu_get_reg(vcpu, HV_REG_X1, &x1);
    hv_vcpu_get_reg(vcpu, HV_REG_X2, &x2);

    if (verbose || !entry || !entry->handler || entry->needs_extra_regs) {
        hv_vcpu_get_reg(vcpu, HV_REG_X3, &x3);
        hv_vcpu_get_reg(vcpu, HV_REG_X4, &x4);
        hv_vcpu_get_reg(vcpu, HV_REG_X5, &x5);
    }

    if (verbose) {
        uint64_t elr = 0;
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &elr);
        log_debug(
            "syscall %llu@0x%llx(0x%llx, 0x%llx, 0x%llx, 0x%llx, "
            "0x%llx, 0x%llx)",
            (unsigned long long) x8,
            (unsigned long long) (elr >= 4 ? elr - 4 : elr),
            (unsigned long long) x0, (unsigned long long) x1,
            (unsigned long long) x2, (unsigned long long) x3,
            (unsigned long long) x4, (unsigned long long) x5);
    }

    /* Table-driven dispatch */
    if (entry && entry->handler) {
        result = entry->handler(g, x0, x1, x2, x3, x4, x5, verbose);
        /* Check for exit sentinel */
        if ((result & ~0xFFLL) == SC_EXIT_SENTINEL) {
            *exit_code = (int) (result & 0xFF);
            should_exit = true;
            result = 0; /* Not written back, but keep clean */
        } else if (result == SYSCALL_EXEC_HAPPENED) {
            if (hist_start_ns) {
                /* Guard the subtraction: syscall_hist_now_ns returns 0 if
                 * clock_gettime fails. An unsigned 0 minus a non-zero start
                 * would underflow to a huge value and pollute the histogram
                 * with a bogus latency sample.
                 */
                uint64_t hist_end_ns = syscall_hist_now_ns();
                if (hist_end_ns >= hist_start_ns)
                    syscall_hist_record(nr, hist_end_ns - hist_start_ns);
                syscall_hist_freeze("frozen at first execve");
            }
            return SYSCALL_EXEC_HAPPENED;
        }
    } else {
        log_warn(
            "unimplemented syscall %llu "
            "(x0=0x%llx, x1=0x%llx, x2=0x%llx, x3=0x%llx, "
            "x4=0x%llx, x5=0x%llx)",
            (unsigned long long) x8, (unsigned long long) x0,
            (unsigned long long) x1, (unsigned long long) x2,
            (unsigned long long) x3, (unsigned long long) x4,
            (unsigned long long) x5);
        result = -LINUX_ENOSYS;
    }


fast_done:
    if (!should_exit) {
        /* Verbose: log syscall return value and file paths */
        if (verbose) {
            log_debug("  -> %lld (0x%llx)", (long long) result,
                      (unsigned long long) (uint64_t) result);
            /* Log path-bearing syscalls. */
            if ((int) x8 == SYS_openat || (int) x8 == SYS_readlinkat ||
                (int) x8 == SYS_faccessat || (int) x8 == SYS_newfstatat ||
                (int) x8 == SYS_unlinkat || (int) x8 == SYS_mkdirat ||
                (int) x8 == SYS_fchmodat || (int) x8 == SYS_fchownat) {
                char pathbuf[256];
                if (guest_read_str(g, x1, pathbuf, sizeof(pathbuf)) >= 0)
                    log_debug("  path=\"%s\"", pathbuf);
            } else if ((int) x8 == SYS_renameat || (int) x8 == SYS_renameat2 ||
                       (int) x8 == SYS_linkat || (int) x8 == SYS_symlinkat) {
                char path_a[256];
                char path_b[256];
                uint64_t a_gva = ((int) x8 == SYS_symlinkat) ? x0 : x1;
                uint64_t b_gva = ((int) x8 == SYS_symlinkat) ? x2 : x3;
                if (guest_read_str(g, a_gva, path_a, sizeof(path_a)) >= 0 &&
                    guest_read_str(g, b_gva, path_b, sizeof(path_b)) >= 0)
                    log_debug("  path=\"%s\" -> \"%s\"", path_a, path_b);
            }
        }
        /* Write result back to X0 */
        hv_vcpu_set_reg(vcpu, HV_REG_X0, (uint64_t) result);

        /* Signal the shim to flush TLB if this vCPU modified page tables.
         * Protocol after HVC #5 lives in tlbi_request_emit_to_vcpu (see
         * src/core/guest.h); the helper also handles the HVC #11 EL0-fault
         * lazy-materialize path so both call sites use the same wire codes.
         * Must call the emit helper because the shim reads X8 unconditionally
         * on return; the pre-syscall X8 is the syscall number (always non-zero)
         * and would spuriously TLBI on every return.
         *
         * cpu_tlbi_req is a per-vCPU TLS slot, so this read needs no lock and
         * cannot be drained or torn by another vCPU's epilogue.
         */
        tlbi_request_emit_to_vcpu(vcpu);
    }

    if (hist_start_ns) {
        uint64_t hist_end_ns = syscall_hist_now_ns();
        if (hist_end_ns >= hist_start_ns)
            syscall_hist_record(nr, hist_end_ns - hist_start_ns);
    }

    return should_exit;
}
