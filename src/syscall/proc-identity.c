/* Process identity and session state
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "syscall/abi.h"
#include "core/shim-globals.h"
#include "syscall/proc-identity.h"
#include "syscall/proc.h"

static _Atomic int64_t guest_pid = 1, parent_pid = 0;
static _Atomic uint32_t emu_uid = GUEST_UID, emu_euid = GUEST_UID;
static _Atomic uint32_t emu_suid = GUEST_UID, emu_gid = GUEST_GID;
static _Atomic uint32_t emu_egid = GUEST_GID, emu_sgid = GUEST_GID;
static _Atomic int32_t emu_nice = 0;

static pthread_mutex_t session_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic int64_t guest_sid = 1, guest_pgid = 1;
static _Atomic int64_t guest_fg_pgrp = 1;
static _Atomic int32_t guest_has_ctty = 1;

static uint32_t proc_identity_env_u32(const char *name, uint32_t fallback)
{
    const char *value = getenv(name);
    if (!value || !*value)
        return fallback;

    errno = 0;
    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed > UINT32_MAX)
        return fallback;
    return (uint32_t) parsed;
}

void proc_identity_init(void)
{
    uint32_t initial_uid = proc_identity_env_u32("ELFUSE_GUEST_UID", GUEST_UID);
    uint32_t initial_gid = proc_identity_env_u32("ELFUSE_GUEST_GID", GUEST_GID);

    guest_pid = 1;
    parent_pid = 0;
    emu_uid = initial_uid;
    emu_euid = initial_uid;
    emu_suid = initial_uid;
    emu_gid = initial_gid;
    emu_egid = initial_gid;
    emu_sgid = initial_gid;
    emu_nice = 0;
    guest_sid = 1;
    guest_pgid = 1;
    guest_fg_pgrp = 1;
    guest_has_ctty = 1;
}

int64_t proc_get_pid(void)
{
    return guest_pid;
}

int64_t proc_get_ppid(void)
{
    return parent_pid;
}

uint32_t proc_get_uid(void)
{
    return emu_uid;
}

uint32_t proc_get_euid(void)
{
    return emu_euid;
}

uint32_t proc_get_suid(void)
{
    return emu_suid;
}

uint32_t proc_get_gid(void)
{
    return emu_gid;
}

uint32_t proc_get_egid(void)
{
    return emu_egid;
}

uint32_t proc_get_sgid(void)
{
    return emu_sgid;
}

static bool uid_is_permitted(uint32_t val)
{
    return val == emu_uid || val == emu_euid || val == emu_suid;
}

static bool gid_is_permitted(uint32_t val)
{
    return val == emu_gid || val == emu_egid || val == emu_sgid;
}

int64_t proc_sys_setuid(uint32_t uid)
{
    bool privileged = (emu_euid == 0);
    if (!privileged && !uid_is_permitted(uid))
        return -LINUX_EPERM;
    if (privileged) {
        emu_uid = uid;
        emu_suid = uid;
    }
    emu_euid = uid;
    return 0;
}

int64_t proc_sys_setgid(uint32_t gid)
{
    bool privileged = (emu_euid == 0);
    if (!privileged && !gid_is_permitted(gid))
        return -LINUX_EPERM;
    if (privileged) {
        emu_gid = gid;
        emu_sgid = gid;
    }
    emu_egid = gid;
    return 0;
}

#define DEFINE_SETRE(suffix, real, eff, saved, perm_fn)                 \
    int64_t proc_sys_setre##suffix(uint32_t r, uint32_t e)              \
    {                                                                   \
        uint32_t old_real = real;                                       \
        bool privileged = (emu_euid == 0);                              \
        if (!privileged && r != (uint32_t) -1 && r != real && r != eff) \
            return -LINUX_EPERM;                                        \
        if (!privileged && e != (uint32_t) -1 && !perm_fn(e))           \
            return -LINUX_EPERM;                                        \
        if (r != (uint32_t) -1)                                         \
            real = r;                                                   \
        if (e != (uint32_t) -1) {                                       \
            eff = e;                                                    \
            if (r != (uint32_t) -1 || e != old_real)                    \
                saved = e;                                              \
        }                                                               \
        return 0;                                                       \
    }

DEFINE_SETRE(uid, emu_uid, emu_euid, emu_suid, uid_is_permitted)
DEFINE_SETRE(gid, emu_gid, emu_egid, emu_sgid, gid_is_permitted)

#undef DEFINE_SETRE

#define DEFINE_SETRES(suffix, real, eff, saved, perm_fn)                \
    int64_t proc_sys_setres##suffix(uint32_t r, uint32_t e, uint32_t s) \
    {                                                                   \
        bool privileged = (emu_euid == 0);                              \
        if (!privileged && r != (uint32_t) -1 && !perm_fn(r))           \
            return -LINUX_EPERM;                                        \
        if (!privileged && e != (uint32_t) -1 && !perm_fn(e))           \
            return -LINUX_EPERM;                                        \
        if (!privileged && s != (uint32_t) -1 && !perm_fn(s))           \
            return -LINUX_EPERM;                                        \
        if (r != (uint32_t) -1)                                         \
            real = r;                                                   \
        if (e != (uint32_t) -1)                                         \
            eff = e;                                                    \
        if (s != (uint32_t) -1)                                         \
            saved = s;                                                  \
        return 0;                                                       \
    }

DEFINE_SETRES(uid, emu_uid, emu_euid, emu_suid, uid_is_permitted)
DEFINE_SETRES(gid, emu_gid, emu_egid, emu_sgid, gid_is_permitted)

#undef DEFINE_SETRES

void proc_set_ids(uint32_t uid,
                  uint32_t euid,
                  uint32_t suid,
                  uint32_t gid,
                  uint32_t egid,
                  uint32_t sgid)
{
    emu_uid = uid;
    emu_euid = euid;
    emu_suid = suid;
    emu_gid = gid;
    emu_egid = egid;
    emu_sgid = sgid;
}

int32_t proc_get_nice(void)
{
    return emu_nice;
}

void proc_set_nice(int32_t val)
{
    emu_nice = val;
}

int64_t proc_sys_setpriority(int which, int who, int prio)
{
    if (which != 0)
        return -LINUX_EINVAL;
    if (who != 0 && who != (int) guest_pid)
        return -LINUX_ESRCH;
    if (prio < -20)
        prio = -20;
    if (prio > 19)
        prio = 19;
    emu_nice = prio;
    return 0;
}

int64_t proc_sys_getpriority(int which, int who)
{
    if (which != 0)
        return -LINUX_EINVAL;
    if (who != 0 && who != (int) guest_pid)
        return -LINUX_ESRCH;
    return 20 - emu_nice;
}

int64_t proc_get_sid(void)
{
    return guest_sid;
}

int64_t proc_get_pgid(void)
{
    return guest_pgid;
}

static void proc_publish_pgsid_locked(guest_t *g)
{
    shim_globals_publish_pgsid(g, guest_pgid, guest_sid);
}

void proc_publish_pgsid_snapshot(guest_t *g)
{
    pthread_mutex_lock(&session_lock);
    proc_publish_pgsid_locked(g);
    pthread_mutex_unlock(&session_lock);
}

int64_t proc_get_fg_pgrp(void)
{
    return guest_fg_pgrp;
}

void proc_set_session(int64_t sid, int64_t pgid)
{
    guest_sid = sid;
    guest_pgid = pgid;
    guest_fg_pgrp = pgid;
}

void proc_set_fg_pgrp(int64_t pgrp)
{
    guest_fg_pgrp = pgrp;
}

void proc_set_ctty(int has_ctty)
{
    guest_has_ctty = has_ctty;
}

int64_t proc_sys_setsid(guest_t *g)
{
    int64_t pid = guest_pid;

    pthread_mutex_lock(&session_lock);
    if (guest_pgid == pid) {
        pthread_mutex_unlock(&session_lock);
        return -LINUX_EPERM;
    }

    guest_sid = pid;
    guest_pgid = pid;
    guest_fg_pgrp = pid;
    guest_has_ctty = 0;
    proc_publish_pgsid_locked(g);
    pthread_mutex_unlock(&session_lock);
    return pid;
}

int64_t proc_sys_setpgid(guest_t *g, int64_t pid, int64_t pgid)
{
    int64_t self = guest_pid;

    if (pid == 0)
        pid = self;
    if (pgid == 0)
        pgid = pid;
    if (pid != self)
        return 0;

    pthread_mutex_lock(&session_lock);
    if (guest_sid == self && guest_pgid == self) {
        pthread_mutex_unlock(&session_lock);
        return -LINUX_EPERM;
    }

    guest_pgid = pgid;
    proc_publish_pgsid_locked(g);
    pthread_mutex_unlock(&session_lock);
    return 0;
}

int64_t proc_sys_getsid(int64_t pid)
{
    int64_t self = guest_pid;

    if (pid == 0 || pid == self)
        return guest_sid;
    return -LINUX_ESRCH;
}

void proc_set_identity(int64_t pid, int64_t ppid)
{
    guest_pid = pid;
    parent_pid = ppid;
}
