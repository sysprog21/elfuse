/*
 * System V IPC syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * shmget, shmat, shmdt, shmctl, semget, semop, semctl, msgget, msgsnd, msgrcv,
 * msgctl. Forwards to macOS SysV IPC with structure translation.
 *
 * shmat limitation: HVF guest memory cannot directly map host shm segments.
 * Data is copied between host shm and guest memory on attach/detach. True
 * cross-process shared semantics require a more complex synchronization scheme.
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

#include "utils.h"

#include "syscall/sysvipc.h"
#include "syscall/linux-wire.h"
#include "syscall/internal.h"
#include "syscall/io.h" /* io_retry_backoff */
#include "syscall/mem.h"

/* Linux SysV IPC constants. */

/* IPC commands (same on Linux and macOS) */
#define LINUX_IPC_RMID 0
#define LINUX_IPC_SET 1
#define LINUX_IPC_STAT 2
#define LINUX_IPC_INFO 3

/* shm-specific Linux commands */
#define LINUX_SHM_INFO 14
#define LINUX_SHM_STAT 13
#define LINUX_SHM_LOCK 11
#define LINUX_SHM_UNLOCK 12

/* shm attach flags (same on Linux and macOS) */
#define LINUX_SHM_RDONLY 010000

/* Linux semctl commands (differ from macOS!) */
#define LINUX_GETVAL 12
#define LINUX_SETVAL 16
#define LINUX_GETALL 13
#define LINUX_SETALL 17
#define LINUX_GETPID 11
#define LINUX_GETNCNT 14
#define LINUX_GETZCNT 15
#define LINUX_SEM_INFO 19
#define LINUX_SEM_STAT 18

/* Linux ipc64_perm (aarch64 LP64). */
typedef struct {
    int32_t key;        /*  0 */
    uint32_t uid;       /*  4 */
    uint32_t gid;       /*  8 */
    uint32_t cuid;      /* 12 */
    uint32_t cgid;      /* 16 */
    uint32_t mode;      /* 20 */
    uint16_t seq;       /* 24 */
    uint16_t __pad2;    /* 26 */
    uint32_t __pad3;    /* 28 */
    uint64_t __unused1; /* 32 */
    uint64_t __unused2; /* 40 */
} linux_ipc64_perm_t;   /* 48 bytes */

/* Linux shmid_ds (aarch64 LP64). */
typedef struct {
    linux_ipc64_perm_t shm_perm; /*  0: 48 */
    uint64_t shm_segsz;          /* 48 */
    int64_t shm_atime;           /* 56 */
    int64_t shm_dtime;           /* 64 */
    int64_t shm_ctime;           /* 72 */
    int32_t shm_cpid;            /* 80 */
    int32_t shm_lpid;            /* 84 */
    uint64_t shm_nattch;         /* 88 */
    uint64_t __unused4;          /* 96 */
    uint64_t __unused5;          /* 104 */
} linux_shmid_ds_t;              /* 112 bytes */

/* Linux semid_ds (aarch64 LP64). */
typedef struct {
    linux_ipc64_perm_t sem_perm; /*  0: 48 */
    int64_t sem_otime;           /* 48 */
    int64_t sem_ctime;           /* 56 */
    uint64_t sem_nsems;          /* 64 */
    uint64_t __unused3;          /* 72 */
    uint64_t __unused4;          /* 80 */
} linux_semid_ds_t;              /* 88 bytes */

/* Linux struct sembuf (same layout on macOS) */
typedef struct {
    uint16_t sem_num;
    int16_t sem_op, sem_flg;
} linux_sembuf_t;

/* Linux msqid_ds (aarch64 LP64). */
typedef struct {
    linux_ipc64_perm_t msg_perm; /*  0: 48 */
    int64_t msg_stime;           /* 48 */
    int64_t msg_rtime;           /* 56 */
    int64_t msg_ctime;           /* 64 */
    uint64_t msg_cbytes;         /* 72 */
    uint64_t msg_qnum;           /* 80 */
    uint64_t msg_qbytes;         /* 88 */
    int32_t msg_lspid;           /* 96 */
    int32_t msg_lrpid;           /* 100 */
    uint64_t __unused4;          /* 104 */
    uint64_t __unused5;          /* 112 */
} linux_msqid_ds_t;              /* 120 bytes */

/* Linux IPC_NOWAIT (same value on both platforms) */
#define LINUX_IPC_NOWAIT 04000

/* Linux MSG_NOERROR flag (same on both platforms) */
#define LINUX_MSG_NOERROR 010000

/* Linux MSG_EXCEPT / MSG_COPY (Linux-specific extensions) */
#define LINUX_MSG_EXCEPT 020000
#define LINUX_MSG_COPY 040000

/* shmat tracking table. */

#define MAX_SHM_ATTACH 64

typedef struct {
    bool active;
    int shmid;
    void *host_addr;    /* shmat() return on host */
    uint64_t guest_gva; /* guest virtual address */
    uint64_t size;      /* segment size */
    bool rdonly;        /* attached read-only */
} shm_attach_t;

static shm_attach_t shm_table[MAX_SHM_ATTACH];
static pthread_mutex_t shm_lock = PTHREAD_MUTEX_INITIALIZER;

#define SHM_FOR_EACH(e) \
    for (shm_attach_t *e = shm_table; e < shm_table + MAX_SHM_ATTACH; e++)

/* Helper: macOS ipc_perm -> Linux ipc64_perm. */

static void mac_to_linux_ipc_perm(const struct ipc_perm *mac,
                                  linux_ipc64_perm_t *lin)
{
    memset(lin, 0, sizeof(*lin));
    lin->key = mac->_key;
    lin->uid = mac->uid;
    lin->gid = mac->gid;
    lin->cuid = mac->cuid;
    lin->cgid = mac->cgid;
    lin->mode = mac->mode;
    lin->seq = mac->_seq;
}

/* Helper: Linux ipc64_perm -> macOS ipc_perm. */

static void linux_to_mac_ipc_perm(const linux_ipc64_perm_t *lin,
                                  struct ipc_perm *mac)
{
    memset(mac, 0, sizeof(*mac));
    mac->_key = lin->key;
    mac->uid = (uid_t) lin->uid;
    mac->gid = (gid_t) lin->gid;
    mac->cuid = (uid_t) lin->cuid;
    mac->cgid = (gid_t) lin->cgid;
    mac->mode = (unsigned short) lin->mode;
    mac->_seq = (unsigned short) lin->seq;
}

/* Helper: translate Linux semctl cmd -> macOS. */

static int translate_semctl_cmd(int linux_cmd)
{
    switch (linux_cmd) {
    case LINUX_IPC_RMID:
        return IPC_RMID;
    case LINUX_IPC_SET:
        return IPC_SET;
    case LINUX_IPC_STAT:
        return IPC_STAT;
    case LINUX_GETVAL:
        return GETVAL;
    case LINUX_SETVAL:
        return SETVAL;
    case LINUX_GETALL:
        return GETALL;
    case LINUX_SETALL:
        return SETALL;
    case LINUX_GETPID:
        return GETPID;
    case LINUX_GETNCNT:
        return GETNCNT;
    case LINUX_GETZCNT:
        return GETZCNT;
    default:
        return -1;
    }
}

/* Shared memory. */

int64_t sys_shmget(guest_t *g, int32_t key, uint64_t size, int shmflg)
{
    (void) g;

    /* IPC_CREAT, IPC_EXCL, IPC_PRIVATE, and permission bits are the same
     * numeric values on Linux and macOS. Pass through directly.
     */
    int id = shmget((key_t) key, (size_t) size, shmflg);
    if (id < 0)
        return linux_errno();
    return id;
}

int64_t sys_shmat(guest_t *g, int shmid, uint64_t shmaddr_gva, int shmflg)
{
    /* Get segment size from host */
    struct shmid_ds info;
    if (shmctl(shmid, IPC_STAT, &info) < 0)
        return linux_errno();

    size_t seg_size = info.shm_segsz;
    if (seg_size == 0)
        return -LINUX_EINVAL;

    bool rdonly = (shmflg & LINUX_SHM_RDONLY) != 0;

    /* Attach on host side */
    void *host_addr = shmat(shmid, NULL, rdonly ? SHM_RDONLY : 0);
    if (host_addr == (void *) -1)
        return linux_errno();

    /* Allocate guest memory via anonymous mmap. shmaddr_gva hint is ignored for
     * simplicity; SysV SHM always lets the allocator choose. A MAP_FIXED path
     * could be added if programs depend on it.
     */
    (void) shmaddr_gva;

    /* Always allocate RW initially so the code can copy shm content in. For
     * SHM_RDONLY, downgrade to read-only via mprotect after the copy.
     */
    int64_t gva =
        sys_mmap_anon(g, 0, seg_size, LINUX_PROT_READ | LINUX_PROT_WRITE);
    if (gva < 0) {
        shmdt(host_addr);
        return gva; /* propagate mmap error */
    }

    /* Copy host shm content into guest memory. sys_shmat runs under mmap_lock
     * (SC_LOCKED), so the resolve-time lazy fault-in inside guest_write would
     * self-deadlock on it; materialize the fresh anonymous mapping through the
     * locked variant first.
     */
    guest_lazy_faultin_locked(g, (uint64_t) gva, seg_size);
    if (guest_write(g, (uint64_t) gva, host_addr, seg_size) < 0) {
        shmdt(host_addr);
        return -LINUX_EFAULT;
    }

    /* Downgrade to read-only for SHM_RDONLY via the standard mprotect path,
     * which handles L2->L3 block splitting and TLBI correctly.
     */
    if (rdonly)
        sys_mprotect(g, (uint64_t) gva, PAGE_ALIGN_UP(seg_size),
                     LINUX_PROT_READ);

    /* Track the attachment */
    pthread_mutex_lock(&shm_lock);
    shm_attach_t *entry = NULL;
    SHM_FOR_EACH (e) {
        if (!e->active) {
            entry = e;
            break;
        }
    }
    if (!entry) {
        pthread_mutex_unlock(&shm_lock);
        shmdt(host_addr);
        return -LINUX_ENOMEM;
    }
    entry->active = true;
    entry->shmid = shmid;
    entry->host_addr = host_addr;
    entry->guest_gva = (uint64_t) gva;
    entry->size = seg_size;
    entry->rdonly = rdonly;
    pthread_mutex_unlock(&shm_lock);

    return gva;
}

int64_t sys_shmdt(guest_t *g, uint64_t shmaddr_gva)
{
    pthread_mutex_lock(&shm_lock);
    shm_attach_t *match = NULL;
    SHM_FOR_EACH (e) {
        if (e->active && e->guest_gva == shmaddr_gva) {
            match = e;
            break;
        }
    }
    if (!match) {
        pthread_mutex_unlock(&shm_lock);
        return -LINUX_EINVAL;
    }

    shm_attach_t entry = *match;
    match->active = false;
    pthread_mutex_unlock(&shm_lock);

    /* Write back guest modifications to host shm (unless read-only) */
    if (!entry.rdonly) {
        /* Read guest memory back to host shm buffer. Same SC_LOCKED
         * self-deadlock hazard as the shmat copy-in: pages the guest never
         * touched may still be unmaterialized.
         */
        guest_lazy_faultin_locked(g, entry.guest_gva, entry.size);
        guest_read(g, entry.guest_gva, entry.host_addr, entry.size);
    }

    /* Detach host shm */
    shmdt(entry.host_addr);

    /* Guest memory remains allocated (no munmap). Linux shmdt does not
     * guarantee immediate unmap either; the pages become undefined. A real
     * implementation would munmap the guest region here.
     */

    return 0;
}

int64_t sys_shmctl(guest_t *g, int shmid, int cmd, uint64_t buf_gva)
{
    switch (cmd) {
    case LINUX_IPC_STAT: {
        struct shmid_ds mac_ds;
        if (shmctl(shmid, IPC_STAT, &mac_ds) < 0)
            return linux_errno();

        linux_shmid_ds_t lin_ds;
        memset(&lin_ds, 0, sizeof(lin_ds));
        mac_to_linux_ipc_perm(&mac_ds.shm_perm, &lin_ds.shm_perm);
        lin_ds.shm_segsz = mac_ds.shm_segsz;
        lin_ds.shm_atime = mac_ds.shm_atime;
        lin_ds.shm_dtime = mac_ds.shm_dtime;
        lin_ds.shm_ctime = mac_ds.shm_ctime;
        lin_ds.shm_cpid = mac_ds.shm_cpid;
        lin_ds.shm_lpid = mac_ds.shm_lpid;
        lin_ds.shm_nattch = mac_ds.shm_nattch;

        if (guest_write_small(g, buf_gva, &lin_ds, sizeof(lin_ds)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    case LINUX_IPC_SET: {
        linux_shmid_ds_t lin_ds;
        if (guest_read_small(g, buf_gva, &lin_ds, sizeof(lin_ds)) < 0)
            return -LINUX_EFAULT;

        struct shmid_ds mac_ds;
        memset(&mac_ds, 0, sizeof(mac_ds));

        /* Only uid, gid, mode are writable via IPC_SET */
        linux_to_mac_ipc_perm(&lin_ds.shm_perm, &mac_ds.shm_perm);

        if (shmctl(shmid, IPC_SET, &mac_ds) < 0)
            return linux_errno();
        return 0;
    }

    case LINUX_IPC_RMID:
        if (shmctl(shmid, IPC_RMID, NULL) < 0)
            return linux_errno();
        return 0;

    case LINUX_IPC_INFO:
    case LINUX_SHM_INFO:
    case LINUX_SHM_STAT:
        /* IPC_INFO/SHM_INFO/SHM_STAT are Linux-specific and have no direct
         * macOS equivalent.
         *
         * Return EINVAL rather than ENOSYS to match what a
         * restricted-permission kernel would do.
         */
        return -LINUX_EINVAL;

    case LINUX_SHM_LOCK:
    case LINUX_SHM_UNLOCK:
        /* SHM_LOCK/UNLOCK: no-op, memory is always resident in HVF */
        return 0;

    default:
        return -LINUX_EINVAL;
    }
}

/* Semaphores. */

int64_t sys_semget(guest_t *g, int32_t key, int nsems, int semflg)
{
    (void) g;
    int id = semget((key_t) key, nsems, semflg);
    if (id < 0)
        return linux_errno();
    return id;
}

/* Largest set this can walk; semctl GETALL fills a caller array. */
#define SEMOP_MAX_SEMS 1024

/* Outcomes of the walk below that are not an operation index. */
#define SEMOP_BLOCKER_NONE (-1)    /* Every operation could proceed */
#define SEMOP_BLOCKER_UNKNOWN (-2) /* The values could not be read */

/* Semaphores in the set, or SEMOP_BLOCKER_UNKNOWN.
 *
 * Split from the walk because a set cannot be resized, so this is read once per
 * semop rather than once per retry: the walk runs again on every pass of the
 * polling loop, and re-asking the kernel for a constant on each one is a
 * syscall spent to learn nothing.
 */
static int semop_read_nsems(int semid)
{
    struct semid_ds info;
    if (semctl(semid, 0, IPC_STAT, &info) < 0)
        return SEMOP_BLOCKER_UNKNOWN;

    int nsems = (int) info.sem_nsems;
    if (nsems <= 0 || nsems > SEMOP_MAX_SEMS)
        return SEMOP_BLOCKER_UNKNOWN;
    return nsems;
}

/* Index of the operation that cannot proceed against the current values.
 *
 * This repeats the walk the kernel makes before it decides to block: a positive
 * operation always proceeds, a zero operation needs the value already at zero,
 * and a negative one needs enough units to take. Linux answers EAGAIN when the
 * operation it stopped on carries IPC_NOWAIT, and blocks otherwise, so which
 * one stopped it is the whole question.
 *
 * Returns SEMOP_BLOCKER_NONE when nothing blocked, and SEMOP_BLOCKER_UNKNOWN
 * when the values could not be read, which a set granting alter but not read
 * permission does while its operations still apply.
 *
 * The caller keeps waiting on either, rather than answering EAGAIN from a
 * result it cannot back up. That trade has a cost worth naming: a mixed set on
 * a set it may alter but not read never gets the refusal Linux would have given
 * it, and waits instead. Answering EAGAIN there would be inventing a refusal in
 * every other case the probe cannot read, which is the more common one.
 *
 * nsems is resolved once per semop by the caller, since a set cannot be
 * resized. The values are re-read on every pass, because those are what move.
 *
 * They can move between this read and the failed semop it explains, so the
 * operation named here can differ from the one the host actually stopped on.
 * Usually that costs a retry: applying the set is still one atomic host call,
 * and the next pass re-reads. The case it gets wrong is a set whose true
 * blocker carries IPC_NOWAIT while a concurrent change makes a blocking
 * operation look like the blocker, where the caller waits and Linux would have
 * answered EAGAIN. It resolves as soon as one pass reads a consistent set.
 */
static int semop_first_blocker(int semid,
                               const struct sembuf *sops,
                               unsigned nsops,
                               int nsems)
{
    unsigned short vals[SEMOP_MAX_SEMS];
    if (nsems <= 0 || semctl(semid, 0, GETALL, vals) < 0)
        return SEMOP_BLOCKER_UNKNOWN;

    /* Widened because a positive operation may carry the running value past
     * what a semaphore can hold, and the walk only needs the comparisons to
     * stay honest until it reaches the operation that stops it.
     */
    int cur[SEMOP_MAX_SEMS];
    for (int i = 0; i < nsems; i++)
        cur[i] = (int) vals[i];

    for (unsigned i = 0; i < nsops; i++) {
        int num = sops[i].sem_num;
        if (num < 0 || num >= nsems) {
            /* Out of range: the host semop owns that error */
            return SEMOP_BLOCKER_UNKNOWN;
        }

        int op = sops[i].sem_op;
        if (op > 0) {
            cur[num] += op;
        } else if (op == 0) {
            if (cur[num] != 0)
                return (int) i;
        } else {
            if (cur[num] < -op)
                return (int) i;
            cur[num] += op;
        }
    }

    return SEMOP_BLOCKER_NONE;
}

int64_t sys_semop(guest_t *g, int semid, uint64_t sops_gva, unsigned nsops)
{
    if (nsops == 0 || nsops > 256)
        return -LINUX_EINVAL;

    /* Linux and macOS struct sembuf are layout-compatible */
    struct sembuf sops[256];
    size_t len = nsops * sizeof(struct sembuf);

    if (guest_read(g, sops_gva, sops, len) < 0)
        return -LINUX_EFAULT;

    /* Every set polls, mixed or not. A blocking semop parks the vCPU thread in
     * a host call no teardown wake reaches, so nothing here may enter one, and
     * a set that mixes IPC_NOWAIT with blocking operations would otherwise have
     * to. The copy carries the flag on every operation so the host still
     * applies the set atomically or not at all; sops keeps the guest's own
     * flags, which is what decides whether a refusal is owed to the caller now.
     */
    struct sembuf poll_sops[256];
    bool any_nowait = false;
    for (unsigned i = 0; i < nsops; i++) {
        poll_sops[i] = sops[i];
        poll_sops[i].sem_flg |= IPC_NOWAIT;
        if (sops[i].sem_flg & IPC_NOWAIT)
            any_nowait = true;
    }

    /* Resolved on the first probe, which only a set carrying IPC_NOWAIT ever
     * makes, so an all-blocking set pays nothing for it.
     */
    int nsems = 0;

    unsigned backoff = 0;
    for (;;) {
        if (semop(semid, poll_sops, nsops) == 0)
            return 0;
        if (errno != EAGAIN)
            return linux_errno();

        /* The set did not apply. Linux owes EAGAIN only when the operation that
         * stopped it is itself IPC_NOWAIT; when a blocking one stopped it the
         * caller waits, whatever flags the rest of the set carries.
         */
        if (any_nowait) {
            if (nsems == 0)
                nsems = semop_read_nsems(semid);
            int blocker = semop_first_blocker(semid, sops, nsops, nsems);
            if (blocker >= 0 && (sops[blocker].sem_flg & IPC_NOWAIT))
                return -LINUX_EAGAIN;
        }
        int64_t wait_rc = io_retry_backoff(&backoff);
        if (wait_rc < 0)
            return wait_rc;
    }
}

int64_t sys_semctl(guest_t *g, int semid, int semnum, int cmd, uint64_t arg)
{
    switch (cmd) {
    case LINUX_IPC_RMID:
        if (semctl(semid, 0, IPC_RMID) < 0)
            return linux_errno();
        return 0;

    case LINUX_GETVAL: {
        int val = semctl(semid, semnum, GETVAL);
        if (val < 0)
            return linux_errno();
        return val;
    }

    case LINUX_SETVAL: {
        /* arg is the value directly (union semun.val) */
        int val = (int) arg;
        if (semctl(semid, semnum, SETVAL, val) < 0)
            return linux_errno();
        return 0;
    }

    case LINUX_GETALL: {
        /* arg is guest pointer to unsigned short array */
        struct semid_ds info;
        if (semctl(semid, 0, IPC_STAT, &info) < 0)
            return linux_errno();

        int nsems = (int) info.sem_nsems;
        if (nsems <= 0 || nsems > 1024)
            return -LINUX_EINVAL;

        size_t vals_len = (size_t) nsems * sizeof(unsigned short);
        unsigned short *vals = malloc(vals_len);
        if (!vals)
            return -LINUX_ENOMEM;
        if (semctl(semid, 0, GETALL, vals) < 0) {
            int err = linux_errno();
            free(vals);
            return err;
        }

        if (guest_write(g, arg, vals, vals_len) < 0) {
            free(vals);
            return -LINUX_EFAULT;
        }
        free(vals);
        return 0;
    }

    case LINUX_SETALL: {
        struct semid_ds info;
        if (semctl(semid, 0, IPC_STAT, &info) < 0)
            return linux_errno();

        int nsems = (int) info.sem_nsems;
        if (nsems <= 0 || nsems > 1024)
            return -LINUX_EINVAL;

        size_t vals_len = (size_t) nsems * sizeof(unsigned short);
        unsigned short *vals = malloc(vals_len);
        if (!vals)
            return -LINUX_ENOMEM;
        if (guest_read(g, arg, vals, vals_len) < 0) {
            free(vals);
            return -LINUX_EFAULT;
        }

        if (semctl(semid, 0, SETALL, vals) < 0)
            return free(vals), linux_errno();
        free(vals);
        return 0;
    }

    case LINUX_IPC_STAT: {
        struct semid_ds mac_ds;
        if (semctl(semid, 0, IPC_STAT, &mac_ds) < 0)
            return linux_errno();

        linux_semid_ds_t lin_ds;
        memset(&lin_ds, 0, sizeof(lin_ds));
        mac_to_linux_ipc_perm(&mac_ds.sem_perm, &lin_ds.sem_perm);
        lin_ds.sem_otime = mac_ds.sem_otime;
        lin_ds.sem_ctime = mac_ds.sem_ctime;
        lin_ds.sem_nsems = mac_ds.sem_nsems;

        if (guest_write_small(g, arg, &lin_ds, sizeof(lin_ds)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    case LINUX_IPC_SET: {
        linux_semid_ds_t lin_ds;
        if (guest_read_small(g, arg, &lin_ds, sizeof(lin_ds)) < 0)
            return -LINUX_EFAULT;

        struct semid_ds mac_ds;
        memset(&mac_ds, 0, sizeof(mac_ds));
        linux_to_mac_ipc_perm(&lin_ds.sem_perm, &mac_ds.sem_perm);

        if (semctl(semid, 0, IPC_SET, &mac_ds) < 0)
            return linux_errno();
        return 0;
    }

    case LINUX_GETPID:
    case LINUX_GETNCNT:
    case LINUX_GETZCNT: {
        int mac_cmd = translate_semctl_cmd(cmd);
        int val = semctl(semid, semnum, mac_cmd);
        if (val < 0)
            return linux_errno();
        return val;
    }

    case LINUX_IPC_INFO:
    case LINUX_SEM_INFO:
    case LINUX_SEM_STAT:
        return -LINUX_EINVAL;

    default:
        return -LINUX_EINVAL;
    }
}

/* Message queues. */

int64_t sys_msgget(guest_t *g, int32_t key, int msgflg)
{
    (void) g;
    int id = msgget((key_t) key, msgflg);
    if (id < 0)
        return linux_errno();
    return id;
}

/* Max message size for stack allocation; larger messages use malloc. */
#define MSG_STACK_THRESHOLD 4096

int64_t sys_msgsnd(guest_t *g,
                   int msqid,
                   uint64_t msgp_gva,
                   uint64_t msgsz,
                   int msgflg)
{
    /* Linux msgsnd msgp layout: long mtype followed by msgsz bytes of message
     * text. Total read from guest = sizeof(long) + msgsz.
     */
    if (msgsz > 65536)
        return -LINUX_EINVAL;

    size_t total = sizeof(long) + (size_t) msgsz;
    char stack_buf[MSG_STACK_THRESHOLD + sizeof(long)];
    char *heap = NULL;
    char *buf = stack_buf;
    if (total > sizeof(stack_buf)) {
        heap = malloc(total);
        if (!heap)
            return -LINUX_ENOMEM;
        buf = heap;
    }

    int64_t result;
    if (guest_read(g, msgp_gva, buf, total) < 0) {
        result = -LINUX_EFAULT;
        goto out;
    }

    /* The mtype field is a 64-bit long on aarch64-linux. macOS also uses long
     * (64-bit on arm64). Direct passthrough.
     */
    int flags = 0;
    if (msgflg & LINUX_IPC_NOWAIT)
        flags |= IPC_NOWAIT;

    result =
        (msgsnd(msqid, buf, (size_t) msgsz, flags) < 0) ? linux_errno() : 0;
out:
    free(heap);
    return result;
}

int64_t sys_msgrcv(guest_t *g,
                   int msqid,
                   uint64_t msgp_gva,
                   uint64_t msgsz,
                   int64_t msgtyp,
                   int msgflg)
{
    if (msgsz > 65536)
        return -LINUX_EINVAL;

    /* MSG_EXCEPT and MSG_COPY are Linux-specific queue selection modes. macOS
     * cannot emulate either with a native msgrcv call.
     */
    if (msgflg & (LINUX_MSG_COPY | LINUX_MSG_EXCEPT))
        return -LINUX_ENOSYS;

    int flags = 0;
    if (msgflg & LINUX_IPC_NOWAIT)
        flags |= IPC_NOWAIT;
    if (msgflg & LINUX_MSG_NOERROR)
        flags |= MSG_NOERROR;

    size_t total = sizeof(long) + (size_t) msgsz;
    char stack_buf[MSG_STACK_THRESHOLD + sizeof(long)];
    char *heap = NULL;
    char *buf = stack_buf;
    if (total > sizeof(stack_buf)) {
        heap = malloc(total);
        if (!heap)
            return -LINUX_ENOMEM;
        buf = heap;
    }

    int64_t result;
    ssize_t ret = msgrcv(msqid, buf, (size_t) msgsz, (long) msgtyp, flags);
    if (ret < 0) {
        result = linux_errno();
        goto out;
    }

    /* Write back mtype + received bytes to guest */
    size_t write_len = sizeof(long) + (size_t) ret;
    if (guest_write(g, msgp_gva, buf, write_len) < 0)
        result = -LINUX_EFAULT;
    else
        result = ret;

out:
    free(heap);
    return result;
}

int64_t sys_msgctl(guest_t *g, int msqid, int cmd, uint64_t buf_gva)
{
    switch (cmd) {
    case LINUX_IPC_STAT: {
        struct msqid_ds mac_ds;
        if (msgctl(msqid, IPC_STAT, &mac_ds) < 0)
            return linux_errno();

        linux_msqid_ds_t lin_ds;
        memset(&lin_ds, 0, sizeof(lin_ds));
        mac_to_linux_ipc_perm(&mac_ds.msg_perm, &lin_ds.msg_perm);
        lin_ds.msg_stime = mac_ds.msg_stime;
        lin_ds.msg_rtime = mac_ds.msg_rtime;
        lin_ds.msg_ctime = mac_ds.msg_ctime;
        lin_ds.msg_cbytes = mac_ds.msg_cbytes;
        lin_ds.msg_qnum = mac_ds.msg_qnum;
        lin_ds.msg_qbytes = mac_ds.msg_qbytes;
        lin_ds.msg_lspid = mac_ds.msg_lspid;
        lin_ds.msg_lrpid = mac_ds.msg_lrpid;

        if (guest_write_small(g, buf_gva, &lin_ds, sizeof(lin_ds)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    case LINUX_IPC_SET: {
        linux_msqid_ds_t lin_ds;
        if (guest_read_small(g, buf_gva, &lin_ds, sizeof(lin_ds)) < 0)
            return -LINUX_EFAULT;

        struct msqid_ds mac_ds;
        memset(&mac_ds, 0, sizeof(mac_ds));
        linux_to_mac_ipc_perm(&lin_ds.msg_perm, &mac_ds.msg_perm);
        mac_ds.msg_qbytes = (msglen_t) lin_ds.msg_qbytes;

        if (msgctl(msqid, IPC_SET, &mac_ds) < 0)
            return linux_errno();
        return 0;
    }

    case LINUX_IPC_RMID:
        if (msgctl(msqid, IPC_RMID, NULL) < 0)
            return linux_errno();
        return 0;

    case LINUX_IPC_INFO:
    default:
        return -LINUX_EINVAL;
    }
}
