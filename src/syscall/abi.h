/* Linux aarch64 syscall dispatch
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <Hypervisor/Hypervisor.h>
#include <stdbool.h>
#include <stdint.h>
#include "core/guest.h"
#include "core/elf.h"

/* Linux aarch64 syscall numbers. */
/* Sorted numerically for easy lookup. Reference:
 * include/uapi/asm-generic/unistd.h in Linux source.
 */
#define SYS_io_destroy 1
#define SYS_getcwd 17
#define SYS_epoll_create1 20
#define SYS_epoll_ctl 21
#define SYS_epoll_pwait 22
#define SYS_dup 23
#define SYS_dup3 24
#define SYS_fcntl 25
#define SYS_ioctl 29
#define SYS_inotify_init1 26
#define SYS_inotify_add_watch 27
#define SYS_inotify_rm_watch 28
#define SYS_flock 32
#define SYS_mknodat 33
#define SYS_mkdirat 34
#define SYS_unlinkat 35
#define SYS_symlinkat 36
#define SYS_linkat 37
#define SYS_renameat 38
#define SYS_mount 40
#define SYS_truncate 45
#define SYS_statfs 43
#define SYS_fstatfs 44
#define SYS_ftruncate 46
#define SYS_fallocate 47
#define SYS_faccessat 48
#define SYS_chdir 49
#define SYS_fchdir 50
#define SYS_fchmod 52
#define SYS_fchmodat 53
#define SYS_fchownat 54
#define SYS_fchown 55
#define SYS_openat 56
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_getdents64 61
#define SYS_lseek 62
#define SYS_read 63
#define SYS_write 64
#define SYS_readv 65
#define SYS_writev 66
#define SYS_pread64 67
#define SYS_pwrite64 68
#define SYS_splice 76
#define SYS_tee 77
#define SYS_vmsplice 75
#define SYS_sendfile 71
#define SYS_pselect6 72
#define SYS_ppoll 73
#define SYS_readlinkat 78
#define SYS_newfstatat 79
#define SYS_fstat 80
#define SYS_timerfd_create 85
#define SYS_timerfd_settime 86
#define SYS_timerfd_gettime 87
#define SYS_sync 81
#define SYS_fsync 82
#define SYS_fdatasync 83
#define SYS_sync_file_range 84
#define SYS_utimensat 88
#define SYS_exit 93
#define SYS_exit_group 94
#define SYS_waitid 95
#define SYS_set_tid_address 96
#define SYS_futex 98
#define SYS_set_robust_list 99
#define SYS_getitimer 102
#define SYS_setitimer 103
#define SYS_nanosleep 101
#define SYS_clock_gettime 113
#define SYS_clock_getres 114
#define SYS_clock_nanosleep 115
#define SYS_sched_setparam 118
#define SYS_sched_setscheduler 119
#define SYS_sched_getscheduler 120
#define SYS_sched_getparam 121
#define SYS_sched_setaffinity 122
#define SYS_sched_getaffinity 123
#define SYS_sched_yield 124
#define SYS_sched_get_priority_max 125
#define SYS_sched_get_priority_min 126
#define SYS_sched_rr_get_interval 127
#define SYS_kill 129
#define SYS_tgkill 131
#define SYS_sigaltstack 132
#define SYS_rt_sigsuspend 133
#define SYS_rt_sigaction 134
#define SYS_rt_sigprocmask 135
#define SYS_rt_sigpending 136
#define SYS_rt_sigqueueinfo 138
#define SYS_rt_sigreturn 139
#define SYS_setpriority 140
#define SYS_getpriority 141
#define SYS_setregid 143
#define SYS_setgid 144
#define SYS_setreuid 145
#define SYS_setuid 146
#define SYS_setresuid 147
#define SYS_getresuid 148
#define SYS_setresgid 149
#define SYS_getresgid 150
#define SYS_setfsuid 151
#define SYS_setfsgid 152
#define SYS_setpgid 154
#define SYS_getpgid 155
#define SYS_getsid 156
#define SYS_setsid 157
#define SYS_getgroups 158
#define SYS_uname 160
#define SYS_getrlimit 163
#define SYS_setrlimit 164
#define SYS_getrusage 165
#define SYS_umask 166
#define SYS_prctl 167
#define SYS_gettimeofday 169
#define SYS_getpid 172
#define SYS_getppid 173
#define SYS_getuid 174
#define SYS_geteuid 175
#define SYS_getgid 176
#define SYS_getegid 177
#define SYS_gettid 178
#define SYS_sysinfo 179
#define SYS_socket 198
#define SYS_socketpair 199
#define SYS_bind 200
#define SYS_listen 201
#define SYS_accept 202
#define SYS_connect 203
#define SYS_getsockname 204
#define SYS_getpeername 205
#define SYS_sendto 206
#define SYS_recvfrom 207
#define SYS_setsockopt 208
#define SYS_getsockopt 209
#define SYS_shutdown 210
#define SYS_sendmsg 211
#define SYS_recvmsg 212
#define SYS_accept4 242
#define SYS_clone 220
#define SYS_execve 221
#define SYS_brk 214
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_mprotect 226
#define SYS_mremap 216
#define SYS_madvise 233
#define SYS_wait4 260
#define SYS_prlimit64 261
#define SYS_syncfs 267
#define SYS_renameat2 276
#define SYS_getrandom 278
#define SYS_execveat 281
#define SYS_copy_file_range 285
#define SYS_statx 291
#define SYS_rseq 293
/* xattr syscalls (numbers match aarch64 asm-generic/unistd.h) */
#define SYS_setxattr 5
#define SYS_lsetxattr 6
#define SYS_fsetxattr 7
#define SYS_getxattr 8
#define SYS_lgetxattr 9
#define SYS_fgetxattr 10
#define SYS_listxattr 11
#define SYS_llistxattr 12
#define SYS_flistxattr 13
#define SYS_removexattr 14
#define SYS_lremovexattr 15
#define SYS_fremovexattr 16
/* chroot */
#define SYS_chroot 51
/* network batch I/O */
#define SYS_recvmmsg 243
#define SYS_sendmmsg 269
/* file advisory */
#define SYS_fadvise64 223
/* vectored positioned I/O */
#define SYS_preadv 69
#define SYS_pwritev 70
#define SYS_preadv2 286
#define SYS_pwritev2 287
/* misc */
#define SYS_sethostname 161
#define SYS_getcpu 168
#define SYS_memfd_create 279
#define SYS_membarrier 283
#define SYS_mlock 228
#define SYS_munlock 229
#define SYS_msync 227
#define SYS_mincore 232
#define SYS_eventfd2 19
#define SYS_signalfd4 74
#define SYS_rt_tgsigqueueinfo 240
#define SYS_pidfd_send_signal 424
#define SYS_pidfd_open 434
#define SYS_clone3 435
#define SYS_close_range 436
#define SYS_pidfd_getfd 438
#define SYS_ptrace 117
#define SYS_personality 92
#define SYS_capget 90
#define SYS_capset 91
#define SYS_get_robust_list 100
#define SYS_openat2 437
#define SYS_faccessat2 439
#define SYS_epoll_pwait2 441
#define SYS_futex_waitv 449
#define SYS_fchmodat2 452
/* memory locking */
#define SYS_mlockall 230
#define SYS_munlockall 231
/* memory policy stubs */
#define SYS_get_mempolicy 236
#define SYS_set_mempolicy 237
/* System V IPC */
#define SYS_msgget 186
#define SYS_msgctl 187
#define SYS_msgrcv 188
#define SYS_msgsnd 189
#define SYS_semget 190
#define SYS_semctl 191
#define SYS_semop 193
#define SYS_shmget 194
#define SYS_shmctl 195
#define SYS_shmat 196
#define SYS_shmdt 197

/* Linux ptrace constants. */
#define LINUX_PTRACE_CONT 7
#define LINUX_PTRACE_GETREGSET 0x4204
#define LINUX_PTRACE_SETREGSET 0x4205
#define LINUX_PTRACE_SEIZE 0x4206
#define LINUX_PTRACE_INTERRUPT 0x4207
#define LINUX_NT_PRSTATUS 1

/* Linux aarch64 user_pt_regs: matches the kernel's struct user_pt_regs. Used by
 * PTRACE_GETREGSET/SETREGSET with NT_PRSTATUS to exchange GPR state between
 * tracer and tracee threads.
 */
typedef struct {
    uint64_t regs[31]; /* X0-X30 */
    uint64_t sp;       /* SP_EL0 */
    uint64_t pc;       /* ELR_EL1 */
    uint64_t pstate;   /* SPSR_EL1 */
} linux_user_pt_regs_t;

/* Emulated guest identity: all UID/GID variants return these values. */
#define GUEST_UID 1000
#define GUEST_GID 1000

/* Linux errno values. */
#define LINUX_EPERM 1
#define LINUX_ENOENT 2
#define LINUX_ESRCH 3
#define LINUX_EINTR 4
#define LINUX_EIO 5
#define LINUX_E2BIG 7
#define LINUX_ENOEXEC 8
#define LINUX_EBADF 9
#define LINUX_EAGAIN 11 /* Also EWOULDBLOCK */
#define LINUX_ENOMEM 12
#define LINUX_EACCES 13
#define LINUX_EFAULT 14
#define LINUX_EBUSY 16
#define LINUX_EEXIST 17
#define LINUX_EXDEV 18
#define LINUX_ENODEV 19
#define LINUX_ENOTDIR 20
#define LINUX_EINVAL 22
#define LINUX_EMFILE 24
#define LINUX_ENOTTY 25
#define LINUX_EFBIG 27
#define LINUX_ENOSPC 28
#define LINUX_ESPIPE 29
#define LINUX_ERANGE 34
#define LINUX_EDEADLK 35
#define LINUX_ENAMETOOLONG 36
#define LINUX_ENOLCK 37
#define LINUX_ENOSYS 38
#define LINUX_ENOTEMPTY 39
#define LINUX_ELOOP 40
#define LINUX_ENOPROTOOPT 92
#define LINUX_ECHILD 10
#define LINUX_EOPNOTSUPP 95
#define LINUX_EOVERFLOW 75
#define LINUX_ECONNREFUSED 111
#define LINUX_ECONNRESET 104
#define LINUX_ECONNABORTED 103
#define LINUX_EISCONN 106
#define LINUX_ENOTCONN 107
#define LINUX_EADDRINUSE 98
#define LINUX_EADDRNOTAVAIL 99
#define LINUX_ENETUNREACH 101
#define LINUX_EHOSTUNREACH 113
#define LINUX_EINPROGRESS 115
#define LINUX_EALREADY 114
#define LINUX_EAFNOSUPPORT 97
#define LINUX_EMSGSIZE 90
#define LINUX_ENOTSOCK 88
#define LINUX_EDESTADDRREQ 89
#define LINUX_EPROTOTYPE 91
#define LINUX_ETIMEDOUT 110
#define LINUX_ENOBUFS 105
#define LINUX_EPROTONOSUPPORT 93
#define LINUX_ESOCKTNOSUPPORT 94
#define LINUX_ENETDOWN 100
#define LINUX_ENETRESET 102
#define LINUX_ESHUTDOWN 108
#define LINUX_ETOOMANYREFS 109
#define LINUX_EDQUOT 122
#define LINUX_ESTALE 116
#define LINUX_ENOTRECOVERABLE 131
#define LINUX_EOWNERDEAD 130
/* Additional errno values needed for complete macOS->Linux mapping */
#define LINUX_ENOMSG 42     /* No message of desired type */
#define LINUX_ENOLINK 67    /* Link has been severed */
#define LINUX_EPROTO 71     /* Protocol error */
#define LINUX_EMULTIHOP 72  /* Multihop attempted */
#define LINUX_EILSEQ 84     /* Illegal byte sequence */
#define LINUX_EHOSTDOWN 112 /* Host is down */
#define LINUX_ENODATA 61    /* No data available (xattr missing, stream) */

/* Linux FD flags. */
#define LINUX_FD_CLOEXEC 1

/* Linux ioctl constants. Linux and macOS use different ioctl numbers for the
 * same operations. Linux terminal ioctls use 0x54xx (from
 * asm-generic/ioctls.h). macOS equivalents are in <sys/ioctl.h> and
 * <sys/ttycom.h>. Translation is done in syscall_io.c:sys_ioctl().
 */
#define LINUX_TCGETS 0x5401     /* -> macOS TIOCGETA (tcgetattr) */
#define LINUX_TCSETS 0x5402     /* -> macOS TIOCSETA (tcsetattr TCSANOW) */
#define LINUX_TCSETSW 0x5403    /* -> macOS TIOCSETAW (tcsetattr TCSADRAIN) */
#define LINUX_TCSETSF 0x5404    /* -> macOS TIOCSETAF (tcsetattr TCSAFLUSH) */
#define LINUX_TIOCGPGRP 0x540F  /* -> macOS TIOCGPGRP (same semantics) */
#define LINUX_TIOCSPGRP 0x5410  /* -> macOS TIOCSPGRP (same semantics) */
#define LINUX_TIOCSCTTY 0x540E  /* -> macOS TIOCSCTTY (same semantics) */
#define LINUX_TIOCGWINSZ 0x5413 /* -> macOS TIOCGWINSZ (same struct) */
#define LINUX_TIOCSWINSZ 0x5414 /* -> macOS TIOCSWINSZ (same struct) */
#define LINUX_FIONREAD 0x541B   /* -> macOS FIONREAD (same semantics) */
#define LINUX_FIONBIO 0x5421    /* set/clear O_NONBLOCK (arg: int *) */
#define LINUX_FIONCLEX 0x5450   /* clear close-on-exec on fd */
#define LINUX_FIOCLEX 0x5451    /* set close-on-exec on fd */
#define LINUX_TIOCNOTTY 0x5422  /* -> macOS TIOCNOTTY (same semantics) */
#define LINUX_TIOCGSID 0x5429   /* -> macOS TIOCGSID (same semantics) */
/* termios2 variant (adds c_ispeed/c_ospeed) */
#define LINUX_TCGETS2 0x802c542a
#define LINUX_TCSETS2 0x402c542b  /* termios2 set (TCSANOW) */
#define LINUX_TCSETSW2 0x402c542c /* termios2 set (TCSADRAIN) */
#define LINUX_TCSETSF2 0x402c542d /* termios2 set (TCSAFLUSH) */
/* Pseudoterminal multiplexer ioctls. The numeric encodings match Linux
 * include/uapi/asm-generic/ioctls.h regardless of architecture. macOS exposes
 * an equivalent /dev/ptmx and unlockpt(3); ptsname(3) returns /dev/ttysNNN.
 */
#define LINUX_TIOCGPTN 0x80045430   /* _IOR('T', 0x30, unsigned int) */
#define LINUX_TIOCSPTLCK 0x40045431 /* _IOW('T', 0x31, int) */
#define LINUX_TIOCGPTPEER 0x5441    /* _IO('T', 0x41); arg is open flags */

/* Linux open flags. */
#define LINUX_O_RDONLY 0x0000
#define LINUX_O_WRONLY 0x0001
#define LINUX_O_RDWR 0x0002
/* O_ACCMODE is the mask covering O_RDONLY, O_WRONLY, O_RDWR. The urandom read
 * fast-path bitmap and the dup-alias metadata both need this mask to isolate
 * the access-mode bits from the other LINUX_O_* flags.
 */
#define LINUX_O_ACCMODE 0x0003
#define LINUX_O_CREAT 0x0040
#define LINUX_O_EXCL 0x0080
#define LINUX_O_NOCTTY 0x0100
#define LINUX_O_TRUNC 0x0200
#define LINUX_O_APPEND 0x0400
#define LINUX_O_NONBLOCK 0x0800
#define LINUX_O_DSYNC 0x1000
#define LINUX_O_ASYNC 0x2000
/* aarch64-linux open flag values (from asm-generic/fcntl.h). These differ from
 * x86_64-linux values.
 */
#define LINUX_O_DIRECTORY 0x4000  /* 040000 octal */
#define LINUX_O_NOFOLLOW 0x8000   /* 0100000 octal */
#define LINUX_O_DIRECT 0x10000    /* 0200000 octal */
#define LINUX_O_LARGEFILE 0x20000 /* 0400000 octal, ignored on LP64 */
#define LINUX_O_NOATIME 0x40000   /* 01000000 octal */
#define LINUX_O_CLOEXEC 0x80000   /* 02000000 octal */
#define LINUX_O_SYNC 0x101000     /* __O_SYNC | O_DSYNC */
#define LINUX_O_PATH 0x200000     /* 010000000 octal */
#define LINUX___O_TMPFILE 0x400000
#define LINUX_O_TMPFILE (LINUX___O_TMPFILE | LINUX_O_DIRECTORY)

/* Linux fallocate(2) mode bits (linux/falloc.h). PUNCH_HOLE requires the caller
 * to also set KEEP_SIZE per the manpage; collapse/insert/zero/unshare range
 * modes are recognised numerically but elsewhere unsupported.
 */
#define LINUX_FALLOC_FL_KEEP_SIZE 0x01
#define LINUX_FALLOC_FL_PUNCH_HOLE 0x02

/* Linux AT_* constants. */
#define LINUX_AT_FDCWD (-100)
#define LINUX_AT_SYMLINK_NOFOLLOW 0x100
#define LINUX_AT_REMOVEDIR 0x200 /* for unlinkat */
#define LINUX_AT_EACCESS \
    0x200 /* for faccessat (same value, context-dependent) */
#define LINUX_AT_SYMLINK_FOLLOW 0x400
#define LINUX_AT_NO_AUTOMOUNT 0x800
#define LINUX_AT_EMPTY_PATH 0x1000

/* Linux utimensat/futimens timestamp selector constants. */
#define LINUX_UTIME_NOW 0x3fffffff
#define LINUX_UTIME_OMIT 0x3ffffffe

/* statx() sync mode bits. AT_STATX_SYNC_AS_STAT == 0; the FORCE/DONT variants
 * are accepted and ignored (host fstatat is implicitly synchronous).
 */
#define LINUX_AT_STATX_FORCE_SYNC 0x2000
#define LINUX_AT_STATX_DONT_SYNC 0x4000
#define LINUX_AT_STATX_SYNC_TYPE 0x6000

/* Linux prctl operations. */
#define LINUX_PR_SET_PDEATHSIG 1
#define LINUX_PR_GET_PDEATHSIG 2
#define LINUX_PR_GET_DUMPABLE 3
#define LINUX_PR_SET_DUMPABLE 4
#define LINUX_PR_SET_NAME 15
#define LINUX_PR_GET_NAME 16
#define LINUX_PR_SET_NO_NEW_PRIVS 38
#define LINUX_PR_GET_NO_NEW_PRIVS 39
#define LINUX_PR_SET_CHILD_SUBREAPER 36
#define LINUX_PR_GET_CHILD_SUBREAPER 37
#define LINUX_PR_CAPBSET_READ 23
#define LINUX_CAP_LAST_CAP 40
#define LINUX_PR_SET_VMA 0x53564d41 /* "SVMA" */
#define LINUX_PR_SET_VMA_ANON_NAME 0
/* PR_SET_MEM_MODEL / PR_GET_MEM_MODEL: per-thread memory ordering control. On
 * Apple Silicon, setting model to TSO enables Total Store Ordering via
 * ACTLR_EL1.EnTSO, giving ARM64 loads/stores x86-style memory ordering. From
 * Asahi Linux: include/uapi/linux/prctl.h (not in mainline Linux).
 */
#define LINUX_PR_SET_MEM_MODEL 0x4d4d444c /* "MMDL" in ASCII */
#define LINUX_PR_GET_MEM_MODEL 0x6d4d444c /* "mMDL" in ASCII */
#define LINUX_PR_SET_MEM_MODEL_DEFAULT 0
#define LINUX_PR_SET_MEM_MODEL_TSO 1

/* Linux mmap flags. */
#define LINUX_PROT_NONE 0x0
#define LINUX_PROT_READ 0x1
#define LINUX_PROT_WRITE 0x2
#define LINUX_PROT_EXEC 0x4

#define LINUX_MAP_SHARED 0x01
#define LINUX_MAP_PRIVATE 0x02
#define LINUX_MAP_FIXED 0x10
#define LINUX_MAP_ANONYMOUS 0x20
#define LINUX_MAP_NORESERVE 0x4000
#define LINUX_MAP_FIXED_NOREPLACE 0x100000

/* Linux msync flags. */
#define LINUX_MS_ASYNC 0x1
#define LINUX_MS_INVALIDATE 0x2
#define LINUX_MS_SYNC 0x4

/* Linux mremap flags. */
#define LINUX_MREMAP_MAYMOVE 1
#define LINUX_MREMAP_FIXED 2
#define LINUX_MREMAP_DONTUNMAP 4

/* Linux madvise advice values. */
#define LINUX_MADV_NORMAL 0
#define LINUX_MADV_RANDOM 1
#define LINUX_MADV_SEQUENTIAL 2
#define LINUX_MADV_WILLNEED 3
#define LINUX_MADV_DONTNEED 4
#define LINUX_MADV_FREE 8
#define LINUX_MADV_HUGEPAGE 14
#define LINUX_MADV_NOHUGEPAGE 15
#define LINUX_MADV_COLD 20
#define LINUX_MADV_PAGEOUT 21

/* Linux struct stat (aarch64). */
typedef struct {
    uint64_t st_dev, st_ino;
    uint32_t st_mode, st_nlink, st_uid, st_gid;
    uint64_t st_rdev, __pad1;
    int64_t st_size;
    int32_t st_blksize, __pad2;
    int64_t st_blocks, st_atime_sec;
    int64_t st_atime_nsec;
    int64_t st_mtime_sec, st_mtime_nsec, st_ctime_sec, st_ctime_nsec;
    uint32_t __unused4, __unused5;
} linux_stat_t;

/* Linux struct utsname. */
#define LINUX_UTSNAME_LEN 65

typedef struct {
    char sysname[LINUX_UTSNAME_LEN], nodename[LINUX_UTSNAME_LEN];
    char release[LINUX_UTSNAME_LEN], version[LINUX_UTSNAME_LEN];
    char machine[LINUX_UTSNAME_LEN], domainname[LINUX_UTSNAME_LEN];
} linux_utsname_t;

/* Linux struct timespec. */
typedef struct {
    int64_t tv_sec, tv_nsec;
} linux_timespec_t;

/* Linux struct timeval (aarch64). */
typedef struct {
    int64_t tv_sec, tv_usec;
} linux_timeval_t;

/* Linux scheduling policies (asm-generic/sched.h). */
#define LINUX_SCHED_NORMAL 0
#define LINUX_SCHED_FIFO 1
#define LINUX_SCHED_RR 2
#define LINUX_SCHED_BATCH 3
#define LINUX_SCHED_IDLE 5
#define LINUX_SCHED_DEADLINE 6
#define LINUX_SCHED_RESET_ON_FORK 0x40000000

/* Linux struct sched_param (POSIX); only sched_priority is exposed. */
typedef struct {
    int32_t sched_priority;
} linux_sched_param_t;

/* Linux struct statfs (aarch64). */
typedef struct {
    int64_t f_type, f_bsize;
    uint64_t f_blocks, f_bfree, f_bavail, f_files, f_ffree;
    int32_t f_fsid[2];
    int64_t f_namelen, f_frsize, f_flags;
    int64_t f_spare[4];
} linux_statfs_t;

/* Linux iovec. */
typedef struct {
    uint64_t iov_base; /* Guest pointer */
    uint64_t iov_len;
} linux_iovec_t;

/* Linux struct sysinfo. */
typedef struct {
    int64_t uptime;
    uint64_t loads[3]; /* 1, 5, 15 minute load averages * 65536 */
    uint64_t totalram, freeram, sharedram, bufferram, totalswap, freeswap;
    uint16_t procs, pad;
    uint32_t pad2;
    uint64_t totalhigh, freehigh;
    uint32_t mem_unit;
    char _f[4]; /* Padding to 64 bytes on LP64 */
} linux_sysinfo_t;

/* Linux struct rusage. */
typedef struct {
    linux_timeval_t ru_utime, ru_stime;
    int64_t ru_maxrss, ru_ixrss;
    int64_t ru_idrss, ru_isrss;
    int64_t ru_minflt, ru_majflt;
    int64_t ru_nswap, ru_inblock;
    int64_t ru_oublock, ru_msgsnd, ru_msgrcv, ru_nsignals, ru_nvcsw, ru_nivcsw;
} linux_rusage_t;

/* Linux struct rlimit64. */
typedef struct {
    uint64_t rlim_cur, rlim_max;
} linux_rlimit64_t;

/* Linux struct utmpx (aarch64 LP64). */
/* Matches musl's struct utmpx layout. Used for /var/run/utmp synthesis. On
 * LP64: short=2, int=4, long=8, sizeof(struct timeval)=16.
 * sizeof(linux_utmpx_t) == 400 (396 data + 4 trailing padding).
 */
#define LINUX_UT_LINESIZE 32
#define LINUX_UT_NAMESIZE 32
#define LINUX_UT_HOSTSIZE 256
#define LINUX_USER_PROCESS 7

typedef struct {
    int16_t ut_type;                 /*   0: 2 */
    int16_t __ut_pad1;               /*   2: 2 */
    int32_t ut_pid;                  /*   4: 4 */
    char ut_line[LINUX_UT_LINESIZE]; /*   8: 32 */
    char ut_id[4];                   /*  40: 4 */
    char ut_user[LINUX_UT_NAMESIZE]; /*  44: 32 */
    char ut_host[LINUX_UT_HOSTSIZE]; /*  76: 256 */
    int16_t ut_exit_term;            /* 332: 2 */
    int16_t ut_exit_exit;            /* 334: 2 */
    int64_t ut_session;              /* 336: 8 */
    int64_t ut_tv_sec;               /* 344: 8 */
    int64_t ut_tv_usec;              /* 352: 8 */
    uint32_t ut_addr_v6[4];          /* 360: 16 */
    char __ut_reserved[20];          /* 376: 20 */
    /* sizeof = 396, padded to 400 for 8-byte alignment */
} linux_utmpx_t;

/* Linux struct pollfd. */
typedef struct {
    int32_t fd;
    int16_t events, revents;
} linux_pollfd_t;

/* Linux struct statx (aarch64). */
typedef struct {
    uint32_t stx_mask, stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink, stx_uid, stx_gid;
    uint16_t stx_mode, __spare0;
    uint64_t stx_ino, stx_size, stx_blocks, stx_attributes_mask;
    /* struct statx_timestamp: tv_sec(8) + tv_nsec(4) + __reserved(4) */
    int64_t stx_atime_sec;
    uint32_t stx_atime_nsec, __atime_pad;
    int64_t stx_btime_sec;
    uint32_t stx_btime_nsec, __btime_pad;
    int64_t stx_ctime_sec;
    uint32_t stx_ctime_nsec, __ctime_pad;
    int64_t stx_mtime_sec;
    uint32_t stx_mtime_nsec, __mtime_pad;
    uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
    uint64_t stx_mnt_id;
    uint64_t __spare2[13];
} linux_statx_t;

/* statx mask bits */
#define STATX_TYPE 0x0001U
#define STATX_MODE 0x0002U
#define STATX_NLINK 0x0004U
#define STATX_UID 0x0008U
#define STATX_GID 0x0010U
#define STATX_ATIME 0x0020U
#define STATX_MTIME 0x0040U
#define STATX_CTIME 0x0080U
#define STATX_INO 0x0100U
#define STATX_SIZE 0x0200U
#define STATX_BLOCKS 0x0400U
#define STATX_BASIC_STATS 0x07FFU
#define STATX_BTIME 0x0800U

/* FD table. */
#define FD_TABLE_SIZE 1024

#define FD_CLOSED 0
#define FD_STDIO 1
#define FD_REGULAR 2
#define FD_DIR 3
#define FD_PIPE 4
#define FD_SOCKET 5
#define FD_EPOLL 6
#define FD_TIMERFD 7
#define FD_EVENTFD 8
#define FD_SIGNALFD 9
#define FD_INOTIFY 10
#define FD_PATH 11
#define FD_NETLINK 12
#define FD_PIDFD 13
#define FD_FUSE_DEV 14
#define FD_FUSE_FILE 15
#define FD_FUSE_DIR 16
#define FD_URANDOM 17
#define FD_VIRTUAL_PATH_MAX 64

/* File sealing flags (F_SEAL_*) for memfd_create. Tracked per-FD. */
#define LINUX_F_SEAL_SEAL 0x0001
#define LINUX_F_SEAL_SHRINK 0x0002
#define LINUX_F_SEAL_GROW 0x0004
#define LINUX_F_SEAL_WRITE 0x0008
#define LINUX_F_SEAL_FUTURE_WRITE 0x0010

/* memfd_create flags (MFD_*). */
#define LINUX_MFD_CLOEXEC 0x0001U
#define LINUX_MFD_ALLOW_SEALING 0x0002U

/* fcntl sealing commands */
#define LINUX_F_ADD_SEALS 1033
#define LINUX_F_GET_SEALS 1034

/* Socket option cache indices. Keep in sync with SOCK_OPT_COUNT. */
enum {
    SOCK_OPT_KEEPALIVE,
    SOCK_OPT_REUSEADDR,
    SOCK_OPT_ACCEPTCONN,
    SOCK_OPT_REUSEPORT,
    SOCK_OPT_BROADCAST,
    SOCK_OPT_DONTROUTE,
    SOCK_OPT_OOBINLINE,
    SOCK_OPT_RCVLOWAT,
    SOCK_OPT_SNDLOWAT,
    SOCK_OPT_RCVBUF,
    SOCK_OPT_SNDBUF,
    SOCK_OPT_TYPE,
    SOCK_OPT_TCP_NODELAY,
    SOCK_OPT_TCP_KEEPIDLE,
    SOCK_OPT_TCP_KEEPCNT,
    SOCK_OPT_TCP_KEEPINTVL,
    SOCK_OPT_IPV6_V6ONLY,
    SOCK_OPT_PASSCRED,
    SOCK_OPT_IP_TOS,
    SOCK_OPT_IP_TTL,
    SOCK_OPT_IP_HDRINCL,
    SOCK_OPT_IP_PKTINFO,
    SOCK_OPT_IP_RECVTTL,
    SOCK_OPT_IP_RECVTOS,
    /* IP_MTU_DISCOVER value stored verbatim so getsockopt round-trips the Linux
     * PMTUD mode the guest set. The host accepts the value but does not honour
     * every Linux mode; see sys_setsockopt for the IP_DONTFRAG translation for
     * the modes macOS supports.
     */
    SOCK_OPT_IP_MTU_DISCOVER,
    SOCK_OPT_COUNT
};

typedef struct {
    uint32_t valid; /* Bitmask: bit N set = sock_val[N] is cached */
    int val[SOCK_OPT_COUNT];
} sock_opt_cache_t;

typedef struct {
    int type;            /* FD_CLOSED, FD_STDIO, FD_REGULAR, FD_DIR */
    int host_fd;         /* Underlying macOS file descriptor */
    uint64_t generation; /* Bumped each time this guest fd slot is reused. Lets
                          * long-lived references (e.g. epoll registrations)
                          * detect a close+reopen ABA where the slot now holds a
                          * different open file. */
    int linux_flags;     /* Linux open flags (for CLOEXEC tracking) */
    void *dir;           /* DIR* for FD_DIR entries (NULL otherwise) */
    char proc_path[FD_VIRTUAL_PATH_MAX]; /* Virtual /proc dir root for *at */
    int seals; /* F_SEAL_* bits (non-zero only for memfd_create fds) */
    sock_opt_cache_t sock; /* Socket option cache (zeroed for non-sockets) */
    void (*cleanup)(int guest_fd); /* Type-specific teardown (NULL if none) */
} fd_entry_t;

/* Inline socket option cache accessors. */
static inline int sock_opt_get(const fd_entry_t *e, int idx, int *value)
{
    if ((unsigned) idx >= SOCK_OPT_COUNT)
        return 0;
    if (e->sock.valid & (1u << idx)) {
        *value = e->sock.val[idx];
        return 1;
    }
    return 0;
}

static inline void sock_opt_set(fd_entry_t *e, int idx, int value)
{
    if ((unsigned) idx >= SOCK_OPT_COUNT)
        return;
    e->sock.valid |= (1u << idx);
    e->sock.val[idx] = value;
}

static inline void sock_opt_clear(fd_entry_t *e)
{
    e->sock.valid = 0;
}

/* API. */

/* Initialize the syscall subsystem (FD table, etc.) */
void syscall_init(void);

/* Dispatch a syscall. Reads X8 (nr) and X0-X5 (args) from vCPU registers.
 * Writes result back to X0. Sets *exit_code if the process should exit.
 * Returns 0 to continue, 1 to exit.
 */
int syscall_dispatch(hv_vcpu_t vcpu, guest_t *g, int *exit_code, bool verbose);
