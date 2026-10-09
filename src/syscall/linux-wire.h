/*
 * Linux aarch64 wire-format ABI: errno, flags, structs, FD table
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split out of syscall/abi.h: this half is what nearly every syscall
 * implementation file actually needs (errno values, open/mmap/AT_* flags, the
 * wire-format structs, the FD table). abi.h keeps only the SYS_* dispatch
 * numbers and the dispatch entry points, which just two files in the tree
 * (syscall.c, debug/syscall-hist.c) ever reference.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

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
#define LINUX_EISDIR 21
#define LINUX_EINVAL 22
#define LINUX_EMFILE 24
#define LINUX_ENOTTY 25
#define LINUX_EFBIG 27
#define LINUX_ENOSPC 28
#define LINUX_ESPIPE 29
#define LINUX_EDOM 33
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
#define LINUX_EREMOTEIO 121 /* Remote I/O error (usbfs URB_SHORT_NOT_OK) */
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
#define LINUX_EPIPE 32      /* Broken pipe; also usbfs endpoint stall */
#define LINUX_ETIME 62      /* Timer expired (USB device not responding) */

/* Linux FD flags. */
#define LINUX_FD_CLOEXEC 1

/* Linux ioctl constants. Linux and macOS use different ioctl numbers for the
 * same operations. Linux terminal ioctls use 0x54xx (from
 * asm-generic/ioctls.h). macOS equivalents are in <sys/ioctl.h> and
 * <sys/ttycom.h>. Translation is done in io.c:sys_ioctl().
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
#define LINUX_TIOCPKT 0x5420    /* -> macOS TIOCPKT (same int flag) */
#define LINUX_FIONREAD 0x541B   /* -> macOS FIONREAD (same semantics) */
#define LINUX_FIONBIO 0x5421    /* set/clear O_NONBLOCK (arg: int *) */
#define LINUX_FIONCLEX 0x5450   /* clear close-on-exec on fd */
#define LINUX_FIOCLEX 0x5451    /* set close-on-exec on fd */
#define LINUX_FIOASYNC 0x5452   /* set/clear O_ASYNC (arg: int *) */
#define LINUX_TIOCNOTTY 0x5422  /* -> macOS TIOCNOTTY (same semantics) */
#define LINUX_TIOCGSID 0x5429   /* -> macOS TIOCGSID (same semantics) */

/* The rest of what do_vfs_ioctl answers for every file before it calls
 * f_op->unlocked_ioctl (fs/ioctl.c), beside FIONBIO and FIOASYNC above. Nothing
 * here serves them; the numbers exist so a file's own ioctl handler can tell a
 * request that reaches it from one that never does. FIONREAD is not among them:
 * do_vfs_ioctl hands that one to vfs_ioctl for anything that is not a regular
 * file. Neither are the FS_IOC_*FLAGS and FS_IOC_FS*XATTR arms, which answer
 * -ENOIOCTLCMD for an inode with no fileattr operations and are retried through
 * vfs_ioctl.
 */
#define LINUX_FIOQSIZE 0x5460             /* bytes behind the inode */
#define LINUX_FIGETBSZ 0x00000002         /* the superblock's block size */
#define LINUX_FIFREEZE 0xC0045877         /* freeze the filesystem */
#define LINUX_FITHAW 0xC0045878           /* thaw it */
#define LINUX_FS_IOC_FIEMAP 0xC020660B    /* map an inode's extents */
#define LINUX_FICLONE 0x40049409          /* reflink a whole file */
#define LINUX_FICLONERANGE 0x4020940D     /* reflink a range of one */
#define LINUX_FIDEDUPERANGE 0xC0189436    /* dedupe a range against others */
#define LINUX_FS_IOC_GETFSUUID 0x80111500 /* the superblock's UUID */
#define LINUX_FS_IOC_GETFSSYSFSPATH 0x80811501 /* its sysfs path */

/* Serial line control. Linux encodes the argument in the ioctl arg word itself;
 * macOS has no ioctl form and exposes tcsendbreak/tcdrain/tcflush/tcflow.
 */
#define LINUX_TCSBRK 0x5409   /* arg 0: tcsendbreak; nonzero: tcdrain (glibc) */
#define LINUX_TCXONC 0x540A   /* arg 0..3 -> tcflow TCOOFF/TCOON/TCIOFF/TCION */
#define LINUX_TCFLSH 0x540B   /* arg 0..2 -> tcflush TCI/TCO/TCIOFLUSH */
#define LINUX_TIOCEXCL 0x540C /* -> macOS TIOCEXCL (same semantics) */
#define LINUX_TIOCNXCL 0x540D /* -> macOS TIOCNXCL (same semantics) */
#define LINUX_TIOCOUTQ 0x5411 /* -> macOS TIOCOUTQ (int *) */
#define LINUX_TCSBRKP 0x5425  /* POSIX tcsendbreak; arg is duration */
#define LINUX_TIOCSBRK 0x5427 /* -> macOS TIOCSBRK (break on) */
#define LINUX_TIOCCBRK 0x5428 /* -> macOS TIOCCBRK (break off) */

/* Modem control lines. TIOCM_* bit values (LE=0x001 DTR=0x002 RTS=0x004
 * ST=0x008 SR=0x010 CTS=0x020 CAR=0x040 RNG=0x080 DSR=0x100) are identical on
 * Linux (asm-generic/termios.h) and macOS (sys/ttycom.h), so the int travels
 * as-is.
 */
#define LINUX_TIOCMGET 0x5415 /* -> macOS TIOCMGET (int *) */
#define LINUX_TIOCMBIS 0x5416 /* -> macOS TIOCMBIS (int *) */
#define LINUX_TIOCMBIC 0x5417 /* -> macOS TIOCMBIC (int *) */
#define LINUX_TIOCMSET 0x5418 /* -> macOS TIOCMSET (int *) */
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
/* Linux network interface ioctls. */
#define LINUX_SIOCGIFHWADDR 0x8927 /* get hardware address (struct ifreq) */
#define LINUX_IFNAMSIZ 16
#define LINUX_ARPHRD_ETHER 1
#define LINUX_ARPHRD_LOOPBACK 772

/* Linux socket message flags (uapi linux/socket.h; the same values on every
 * Linux architecture). These are the flags argument to send/recv and their
 * msghdr variants, and are unrelated to the SysV LINUX_MSG_* constants in
 * src/syscall/sysvipc.c, which are msgrcv's msgflg.
 */
#define LINUX_MSG_OOB 0x01
#define LINUX_MSG_PEEK 0x02
#define LINUX_MSG_DONTWAIT 0x40
#define LINUX_MSG_WAITALL 0x100
#define LINUX_MSG_DONTROUTE 0x04
#define LINUX_MSG_CTRUNC 0x08
#define LINUX_MSG_TRUNC 0x20
#define LINUX_MSG_EOR 0x80
#define LINUX_MSG_NOSIGNAL 0x4000
#define LINUX_MSG_WAITFORONE 0x10000
#define LINUX_MSG_CMSG_CLOEXEC 0x40000000

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

/* _LINUX_CAPABILITY_VERSION_3, the only version elfuse's capget accepts (Linux
 * still takes the two deprecated ones). A guest asking for another gets this
 * one written back with EINVAL, which is how Linux tells it which version to
 * retry with. sc_capset refuses every call with EPERM and never reads the
 * header, so it has no use for this.
 */
#define LINUX_CAPABILITY_VERSION_3 0x20080522
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
#define LINUX_MAP_SHARED_VALIDATE 0x03
#define LINUX_MAP_TYPE 0x0f
#define LINUX_MAP_FIXED 0x10
#define LINUX_MAP_ANONYMOUS 0x20
#define LINUX_MAP_NORESERVE 0x4000
#define LINUX_MAP_FIXED_NOREPLACE 0x100000

/* Every flag a MAP_SHARED_VALIDATE mapping may carry here: Linux's
 * LEGACY_MAP_MASK (DENYWRITE, EXECUTABLE, GROWSDOWN, LOCKED, NORESERVE,
 * POPULATE, NONBLOCK, STACK, HUGETLB, the huge page size field, and the four
 * named above) plus MAP_FIXED_NOREPLACE. What is left is MAP_SYNC, which needs
 * a DAX file, and bits nothing defines.
 */
#define LINUX_MAP_VALIDATE_MASK                                          \
    (LINUX_MAP_TYPE | LINUX_MAP_FIXED | LINUX_MAP_ANONYMOUS | 0x0100 |   \
     0x0800 | 0x1000 | 0x2000 | LINUX_MAP_NORESERVE | 0x8000 | 0x10000 | \
     0x20000 | 0x40000 | LINUX_MAP_FIXED_NOREPLACE | (0x3f << 26))

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

/* Linux struct utmpx (aarch64 LP64). Matches musl's struct utmpx layout. Used
 * for /var/run/utmp synthesis. On LP64: short=2, int=4, long=8, sizeof(struct
 * timeval)=16. sizeof(linux_utmpx_t) == 400 (396 data + 4 trailing padding).
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

/* FD table. The bound itself lives in elfuse-limits.h, which is also where the
 * host descriptor reserve is derived from it; two copies of the same 1024 would
 * be a legal redefinition rather than a build error, so this includes it.
 */
#include "elfuse-limits.h"

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
#define FD_USBDEV 18
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
#define LINUX_MFD_HUGETLB 0x0004U
#define LINUX_MFD_NOEXEC_SEAL 0x0008U
#define LINUX_MFD_EXEC 0x0010U

/* The huge page size rides in the top bits and means something only beside
 * MFD_HUGETLB.
 */
#define LINUX_MFD_HUGE_MASK (0x3fU << 26)

/* fcntl sealing commands */
#define LINUX_F_ADD_SEALS 1033
#define LINUX_F_GET_SEALS 1034

/* f_owner_ex.type values for F_SETOWN_EX / F_GETOWN_EX (Linux uapi). */
#define LINUX_F_OWNER_TID 0
#define LINUX_F_OWNER_PID 1
#define LINUX_F_OWNER_PGRP 2

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
    /* Read lock-free in per-syscall validity gates (e.g. type == FD_CLOSED) and
     * written under fd_lock at open/close. _Atomic makes those lock-free reads
     * well-defined against the locked writes (a plain int would be a data race,
     * flagged by ThreadSanitizer); plain read/write syntax stays atomic under
     * C11. A stale read only affects a guest racing open/close/op on the same
     * fd number, which is a guest-level bug.
     */
    _Atomic int type; /* FD_CLOSED, FD_STDIO, FD_REGULAR, FD_DIR */
    int host_fd;      /* Underlying macOS file descriptor */

    /* Refcount pinning host_fd open across a concurrent syscall, created on
     * first borrow and NULL until then. This slot holds one reference and each
     * in-flight borrower holds another; the last release closes host_fd. Not an
     * ABI field: elfuse-internal, and declared here only because the fd table
     * entry is.
     *
     * fd_mark_closed_unlocked detaches this pointer without releasing it, so
     * the slot's reference travels in the snapshot the caller took first and is
     * released by fd_cleanup_entry. See fd_host_ref_acquire in internal.h.
     */
    struct fd_lifetime *lifetime;
    uint64_t ofd_id; /* Shared by dup aliases of one open file description */
    uint64_t generation; /* Bumped each time this guest fd slot is reused. Lets
                          * long-lived references (e.g. epoll registrations)
                          * detect a close+reopen ABA where the slot now holds a
                          * different open file.
                          */
    int linux_flags;     /* Linux open flags (for CLOEXEC tracking) */
    void *dir;           /* dir_stream_t* for FD_DIR entries, opaque instance
                          * pointer for FD_EPOLL entries (NULL otherwise)
                          */
    char proc_path[FD_VIRTUAL_PATH_MAX]; /* Virtual /proc dir root for *at */

    /* Linux gives the file this path intercept stands for a poll method, so
     * epoll_ctl accepts it. Recorded at open because fstat cannot recover it
     * later: an intercepted tree is served from elfuse's own staging file, and
     * the host object then describes the staging rather than the file the guest
     * named. False for every non-intercepted open, where the host object is the
     * file and answers for itself. path_intercept_poll_capable decides it.
     */
    bool path_poll_capable;
    int seals;      /* F_SEAL_* bits (non-zero only for memfd_create fds) */
    bool can_block; /* host read/write on this fd may block (pipe, socket, fifo,
                     * char/tty); false for regular files and directories. Set
                     * once at allocation via fstat so the interruptible wait
                     * path can skip fds that never block.
                     */
    bool foreign_description; /* The open file description behind this fd came
                               * from outside elfuse -- the launcher's stdio,
                               * or an alias of it -- so its status flags are
                               * not elfuse's to change. Inherited by every
                               * alias; see fd_init_entry.
                               */
    bool nonblock_owned; /* elfuse set O_NONBLOCK on the host fd and emulates
                          * the guest's blocking semantics on top of it, so
                          * linux_flags -- not the host flag -- is what the
                          * guest asked for. See fd_init_entry.
                          */
    int32_t fasync_owner_type; /* FASYNC_OWNER_* recipient kind (0 = none) */
    int32_t fasync_owner;      /* pid/pgrp/tid for SIGIO/SIGURG delivery */
    sock_opt_cache_t sock; /* Socket option cache (zeroed for non-sockets) */
    void (*cleanup)(int guest_fd); /* Type-specific teardown (NULL if none) */
} fd_entry_t;

/* Inline socket option cache accessors. */
static inline bool sock_opt_get(const fd_entry_t *e, int idx, int *value)
{
    if ((unsigned) idx >= SOCK_OPT_COUNT)
        return false;
    if (e->sock.valid & (1u << idx)) {
        *value = e->sock.val[idx];
        return true;
    }
    return false;
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
