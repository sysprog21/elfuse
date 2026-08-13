/*
 * Host-side unit test for ELFUSE_FAKEROOT environment overrides and the
 * --user staging protocol.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The staging cases are regression guards for the proc_set_initial_ids
 * contract in proc.h. No launcher performs two bring-ups in one host
 * process, so a regression shows up as the wrong uid/gid below rather than
 * as a launch failure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "syscall/proc.h"
#include "syscall/proc-identity.h"
#include "syscall/linux-wire.h"

/* Mock shim_globals_publish_pgsid to avoid linking the entire guest shim
 * subsystem
 */
void shim_globals_publish_pgsid(guest_t *g, int64_t pgid, int64_t sid);
void shim_globals_publish_pgsid(guest_t *g, int64_t pgid, int64_t sid)
{
    (void) g;
    (void) pgid;
    (void) sid;
}

int thread_tid_alive(int64_t tid);
int thread_tid_alive(int64_t tid)
{
    (void) tid;
    return 0;
}

int main(void)
{
    /* Test 1: Fallback case (fakeroot disabled) */
    unsetenv("ELFUSE_FAKEROOT");
    proc_set_fakeroot_enabled(false);
    proc_identity_init();

    assert(proc_get_uid() == GUEST_UID);
    assert(proc_get_euid() == GUEST_UID);
    assert(proc_get_suid() == GUEST_UID);
    assert(proc_get_gid() == GUEST_GID);
    assert(proc_get_egid() == GUEST_GID);
    assert(proc_get_sgid() == GUEST_GID);
    assert(proc_fakeroot_enabled() == false);

    /* Test 2: Enable via API */
    proc_set_fakeroot_enabled(true);
    proc_identity_init();

    assert(proc_get_uid() == 0);
    assert(proc_get_euid() == 0);
    assert(proc_get_suid() == 0);
    assert(proc_get_gid() == 0);
    assert(proc_get_egid() == 0);
    assert(proc_get_sgid() == 0);
    assert(proc_fakeroot_enabled() == true);

    /* Test 3: Enable via Env Var (ELFUSE_FAKEROOT=1) */
    proc_set_fakeroot_enabled(false);
    setenv("ELFUSE_FAKEROOT", "1", 1);

    bool fakeroot = false;
    const char *fakeroot_env = getenv("ELFUSE_FAKEROOT");
    if (fakeroot_env && strcmp(fakeroot_env, "1") == 0)
        fakeroot = true;
    proc_set_fakeroot_enabled(fakeroot);
    proc_identity_init();

    assert(proc_get_uid() == 0);
    assert(proc_get_gid() == 0);
    assert(proc_fakeroot_enabled() == true);

    /* Test 4: Env Var other than 1 should not enable fakeroot */
    setenv("ELFUSE_FAKEROOT", "0", 1);
    fakeroot = false;
    fakeroot_env = getenv("ELFUSE_FAKEROOT");
    if (fakeroot_env && strcmp(fakeroot_env, "1") == 0)
        fakeroot = true;
    proc_set_fakeroot_enabled(fakeroot);
    proc_identity_init();
    assert(proc_get_uid() == GUEST_UID);
    assert(proc_get_gid() == GUEST_GID);
    assert(proc_fakeroot_enabled() == false);

    /* Test 5: consume-once. A leftover would leak one launch's --user into
     * the next launch of the same host process.
     */
    proc_set_fakeroot_enabled(false);
    proc_set_initial_ids(1234, 5678);
    proc_identity_init();
    assert(proc_get_uid() == 1234);
    assert(proc_get_euid() == 1234);
    assert(proc_get_suid() == 1234);
    assert(proc_get_gid() == 5678);
    assert(proc_get_egid() == 5678);
    assert(proc_get_sgid() == 5678);

    proc_identity_init();
    assert(proc_get_uid() == GUEST_UID);
    assert(proc_get_gid() == GUEST_GID);

    /* Test 6: the elfuse_launch fail path drops the staging
     * (proc_clear_initial_ids contract in proc.h).
     */
    proc_set_initial_ids(1234, 5678);
    proc_clear_initial_ids();
    proc_identity_init();
    assert(proc_get_uid() == GUEST_UID);
    assert(proc_get_euid() == GUEST_UID);
    assert(proc_get_gid() == GUEST_GID);
    assert(proc_get_egid() == GUEST_GID);

    printf("test-identity-override-host: PASS\n");
    return 0;
}
