/*
 * Virtual chown overlay (fakeroot-style)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "runtime/fork-state.h"
#include "syscall/chown-overlay.h"

/* Open-chained hash table on (dev, ino). The stat fast path has to stay cheap,
 * so an atomic entry counter lets chown_overlay_apply skip the lock entirely
 * when nothing has been recorded yet (the common case before any guest chown).
 * Once the table is non-empty, readers (apply, send) take the lock in shared
 * mode and writers (set, clear, recv) take it exclusively, so stat-heavy
 * workloads scale across vCPU threads instead of serializing on a global mutex.
 */
#define CHOWN_OVERLAY_BUCKETS 512u

/* Wire-format guardrail. 24 bytes per record (dev, ino, uid, gid), so the cap
 * bounds the recv-side allocation regardless of what the IPC stream claims. 1M
 * entries is far above any plausible package-installer workload (dpkg etc.) but
 * small enough that a corrupted count cannot allocate gigabytes.
 */
#define CHOWN_OVERLAY_MAX_ENTRIES (1u << 20)

typedef struct overlay_entry {
    struct overlay_entry *next;
    uint64_t dev;
    uint64_t ino;
    uint32_t uid;
    uint32_t gid;
} overlay_entry_t;

static overlay_entry_t *buckets[CHOWN_OVERLAY_BUCKETS];
static pthread_rwlock_t overlay_lock = PTHREAD_RWLOCK_INITIALIZER;
static _Atomic size_t entry_count = 0;

/* fnv-1a-style mix; (dev, ino) is unique per host file but ino values cluster
 * low so spread before masking.
 */
static unsigned int bucket_index(uint64_t dev, uint64_t ino)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    h = (h ^ dev) * 0x100000001b3ULL;
    h = (h ^ ino) * 0x100000001b3ULL;
    return (unsigned int) ((h ^ (h >> 32)) & (CHOWN_OVERLAY_BUCKETS - 1));
}

static overlay_entry_t *find_locked(uint64_t dev, uint64_t ino)
{
    unsigned int idx = bucket_index(dev, ino);
    for (overlay_entry_t *e = buckets[idx]; e; e = e->next) {
        if (e->dev == dev && e->ino == ino)
            return e;
    }
    return NULL;
}

static void remove_locked(uint64_t dev, uint64_t ino)
{
    unsigned int idx = bucket_index(dev, ino);
    overlay_entry_t **prev = &buckets[idx];
    for (overlay_entry_t *e = *prev; e; prev = &e->next, e = e->next) {
        if (e->dev == dev && e->ino == ino) {
            *prev = e->next;
            free(e);
            atomic_fetch_sub_explicit(&entry_count, 1, memory_order_release);
            break;
        }
    }
}

static void clear_all_locked(void)
{
    for (unsigned int i = 0; i < CHOWN_OVERLAY_BUCKETS; i++) {
        overlay_entry_t *e = buckets[i];
        while (e) {
            overlay_entry_t *next = e->next;
            free(e);
            e = next;
        }
        buckets[i] = NULL;
    }
    atomic_store_explicit(&entry_count, 0, memory_order_release);
}

int chown_overlay_set(uint64_t dev,
                      uint64_t ino,
                      uint32_t new_owner,
                      uint32_t new_group,
                      uint32_t cur_uid,
                      uint32_t cur_gid)
{
    int rc = 0;

    pthread_rwlock_wrlock(&overlay_lock);

    overlay_entry_t *e = find_locked(dev, ino);
    if (!e) {
        uint32_t next_uid = new_owner == (uint32_t) -1 ? cur_uid : new_owner;
        uint32_t next_gid = new_group == (uint32_t) -1 ? cur_gid : new_group;
        if (next_uid == cur_uid && next_gid == cur_gid)
            goto out;

        e = calloc(1, sizeof(*e));
        if (!e) {
            rc = -1;
            goto out;
        }
        e->dev = dev;
        e->ino = ino;

        /* Initialise with the sentinel (uint32_t)-1, meaning "no override
         * recorded for this field yet". The apply path skips sentinel fields,
         * so a partial chown that only touches one of uid/gid does not corrupt
         * the other field with a stale physical host value.
         */
        e->uid = (uint32_t) -1;
        e->gid = (uint32_t) -1;
        unsigned int idx = bucket_index(dev, ino);
        e->next = buckets[idx];
        buckets[idx] = e;
        atomic_fetch_add_explicit(&entry_count, 1, memory_order_release);
    }

    /* Linux chown semantic: -1 means "do not change this field". */
    if (new_owner != (uint32_t) -1)
        e->uid = new_owner;
    if (new_group != (uint32_t) -1)
        e->gid = new_group;

    /* A sentinel field means "keep whatever cur reports". Resolve before
     * comparing so the no-op check is evaluated in the guest-virtual ID space
     * on both sides.
     */
    uint32_t effective_uid = e->uid == (uint32_t) -1 ? cur_uid : e->uid;
    uint32_t effective_gid = e->gid == (uint32_t) -1 ? cur_gid : e->gid;
    if (effective_uid == cur_uid && effective_gid == cur_gid)
        remove_locked(dev, ino);

out:
    pthread_rwlock_unlock(&overlay_lock);
    return rc;
}

void chown_overlay_clear(uint64_t dev, uint64_t ino)
{
    /* Skipping the lock when the table is empty saves one rwlock op when no
     * overrides exist.
     */
    if (atomic_load_explicit(&entry_count, memory_order_acquire) == 0)
        return;

    pthread_rwlock_wrlock(&overlay_lock);

    remove_locked(dev, ino);

    pthread_rwlock_unlock(&overlay_lock);
}

void chown_overlay_apply(struct stat *st)
{
    if (atomic_load_explicit(&entry_count, memory_order_acquire) == 0)
        return;

    pthread_rwlock_rdlock(&overlay_lock);

    overlay_entry_t *e =
        find_locked((uint64_t) st->st_dev, (uint64_t) st->st_ino);
    if (e) {
        /* Skip sentinel fields: (uint32_t)-1 means "no override recorded" for
         * that field, so leave the host value untouched.
         */
        if (e->uid != (uint32_t) -1)
            st->st_uid = e->uid;
        if (e->gid != (uint32_t) -1)
            st->st_gid = e->gid;
    }

    pthread_rwlock_unlock(&overlay_lock);
}

/* Wire format: uint32_t count, followed by count records of { uint64_t dev;
 * uint64_t ino; uint32_t uid; uint32_t gid; }. Matches the in-memory layout so
 * the child can install the table without an intermediate translation step.
 */
typedef struct {
    uint64_t dev;
    uint64_t ino;
    uint32_t uid;
    uint32_t gid;
} overlay_wire_t;

int chown_overlay_send(int ipc_sock)
{
    pthread_rwlock_rdlock(&overlay_lock);

    size_t n = atomic_load_explicit(&entry_count, memory_order_acquire);

    /* The cap is well above any realistic chown-heavy workload (dpkg). Hitting
     * it indicates a runaway table or a bug, not a legitimate parent; refuse to
     * truncate-on-success and fail the fork so the caller sees the problem.
     */
    if (n > CHOWN_OVERLAY_MAX_ENTRIES) {
        pthread_rwlock_unlock(&overlay_lock);
        return -1;
    }
    uint32_t count = (uint32_t) n;

    if (fork_ipc_write_all(ipc_sock, &count, sizeof(count)) < 0) {
        pthread_rwlock_unlock(&overlay_lock);
        return -1;
    }
    if (count == 0) {
        pthread_rwlock_unlock(&overlay_lock);
        return 0;
    }

    uint32_t emitted = 0;
    for (unsigned int i = 0; i < CHOWN_OVERLAY_BUCKETS; i++) {
        for (overlay_entry_t *e = buckets[i]; e; e = e->next) {
            overlay_wire_t w = {
                .dev = e->dev,
                .ino = e->ino,
                .uid = e->uid,
                .gid = e->gid,
            };
            if (fork_ipc_write_all(ipc_sock, &w, sizeof(w)) < 0) {
                pthread_rwlock_unlock(&overlay_lock);
                return -1;
            }
            emitted++;
        }
    }

    /* entry_count under the rwlock cannot drift; emitted must equal the count
     * we wrote.
     */
    int rc = (emitted == count) ? 0 : -1;
    pthread_rwlock_unlock(&overlay_lock);
    return rc;
}

int chown_overlay_recv(int ipc_sock)
{
    uint32_t count;
    if (fork_ipc_read_all(ipc_sock, &count, sizeof(count)) < 0)
        return -1;
    if (count > CHOWN_OVERLAY_MAX_ENTRIES)
        return -1;

    /* Read every record into a transient buffer before touching the live table.
     * Keeps the rwlock free for siblings during the blocking IO, and a partial
     * read just drops the buffer without leaving a half-built table behind.
     */
    overlay_wire_t *records = NULL;
    if (count > 0) {
        records = calloc(count, sizeof(*records));
        if (!records)
            return -1;
        if (fork_ipc_read_all(ipc_sock, records,
                              (size_t) count * sizeof(*records)) < 0) {
            free(records);
            return -1;
        }
    }

    pthread_rwlock_wrlock(&overlay_lock);
    clear_all_locked();

    for (uint32_t i = 0; i < count; i++) {
        overlay_entry_t *e = calloc(1, sizeof(*e));
        if (!e) {
            clear_all_locked();
            pthread_rwlock_unlock(&overlay_lock);
            free(records);
            return -1;
        }
        e->dev = records[i].dev;
        e->ino = records[i].ino;
        e->uid = records[i].uid;
        e->gid = records[i].gid;
        unsigned int idx = bucket_index(e->dev, e->ino);
        e->next = buckets[idx];
        buckets[idx] = e;
        atomic_fetch_add_explicit(&entry_count, 1, memory_order_release);
    }

    pthread_rwlock_unlock(&overlay_lock);
    free(records);
    return 0;
}
