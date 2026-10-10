/*
 * Lookup and removal agree on a guest /tmp path
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guest paths under /tmp, /var/tmp, and ~/.ccache are force-redirected into the
 * sysroot so a guest's temp files avoid host case-collisions. Whatever a guest
 * can see at such a path, it must also be able to remove: a file it can stat
 * and read it must be able to unlink and rename, a directory it can stat it
 * must be able to rmdir, and every name a directory listing reports must stat.
 *
 * The regression this pins: only creates were redirected. Lookups fell back to
 * the literal host path, so a /tmp entry present on the host but absent from
 * the sysroot was visible to stat and open, while unlink, rmdir, and rename
 * (all create-resolved) addressed the sysroot and returned ENOENT for it. The
 * entry was readable but not removable, and rm -rf of such a directory failed
 * midway with "No such file or directory" despite -f, because readdir listed a
 * child that the following unlink could not resolve. Redirecting only the
 * children left the same disagreement on the directory itself: a listing of
 * /tmp enumerated host entries whose names no longer resolved.
 *
 * Code under test: sys_unlinkat, sys_renameat2, and sys_getdents64 in
 * src/syscall/fs.c over the resolvers in src/syscall/proc-state.c.
 *
 * The harness (mk/tests.mk) stages a directory under the host's own /tmp, so
 * the guest addresses it through the redirect, and passes:
 *
 *   argv[1]  a guest /tmp directory, absent from the sysroot, holding regular
 *            file `f`, subdirectory `d`, and regular file `r` to rename.
 *
 * The harness then checks placement from the host side: the staging directory
 * still holds exactly those three entries, and the sysroot gained the
 * redirected directory. It asserts at directory granularity because a
 * case-insensitive sysroot may store a leaf under its escaped spelling, so the
 * guest side proves the file itself by reading its bytes back.
 *
 * The invariants are one-directional on purpose: a path the guest cannot see at
 * all is trivially consistent, since there is nothing to remove. The defect is
 * the disagreement, not which way it is resolved.
 */

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

/* True when the entry at @path is not visible to the guest at all. Only an
 * absent entry counts: any other lstat errno (ELOOP, EACCES, ENAMETOOLONG) is a
 * resolver fault the test must surface, so the entry reads as visible and the
 * operation that follows reports the real error. lstat, not stat, so this is
 * the same visibility notion listing_resolves() checks against.
 */
static bool invisible(const char *path)
{
    struct stat st;
    if (lstat(path, &st) == 0)
        return false;
    return errno == ENOENT || errno == ENOTDIR;
}

/* Create @path, write a known byte, then reopen and read it back. Reading
 * through a second open is what proves the redirect sends both operations to
 * the same file, which a create alone does not.
 */
static bool round_trips(const char *path)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0)
        return false;
    bool ok = write(fd, "k", 1) == 1;
    if (close(fd) != 0)
        return false;
    if (!ok)
        return false;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;
    char c = '\0';
    ok = read(fd, &c, 1) == 1 && c == 'k';
    if (close(fd) != 0)
        return false;
    return ok;
}

/* Every name a directory listing reports must resolve for a following lstat,
 * which is what a recursive remove does between readdir and unlink. lstat, not
 * stat, so a dangling symlink staged by an unrelated host process does not read
 * as a disagreement. An absent directory reports no names and so cannot
 * disagree with anything; any other opendir errno is a resolver fault and
 * fails. readdir and lstat share one resolver here, so this check supplements
 * the unlink, rmdir, and rename lanes below, which are the genuine regression
 * catchers. Reports the offending name, or the unopenable directory itself,
 * through @offender.
 */
static bool listing_resolves(const char *dir,
                             char *offender,
                             size_t offender_sz)
{
    DIR *d = opendir(dir);
    if (!d) {
        if (errno == ENOENT || errno == ENOTDIR)
            return true;
        snprintf(offender, offender_sz, "%s", dir);
        return false;
    }

    bool consistent = true;
    struct dirent *de;
    while (consistent && (de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;

        char path[PATH_MAX];
        struct stat st;
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        if (lstat(path, &st) != 0) {
            snprintf(offender, offender_sz, "%s", de->d_name);
            consistent = false;
        }
    }
    closedir(d);
    return consistent;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <guest-tmp-dir>\n", argv[0]);
        return 2;
    }
    const char *dir = argv[1];
    char p[PATH_MAX], q[PATH_MAX];

    printf("test-sysroot-tmp-remove: lookup and removal agree under /tmp\n");

    /* Runs before anything is created, while the sysroot still has no /tmp of
     * its own. That is the state in which an unredirected lookup falls through
     * to the host and enumerates entries the guest cannot address.
     */
    TEST("a /tmp listing resolves");
    char offender[NAME_MAX + 1] = "";
    bool listed_ok = listing_resolves("/tmp", offender, sizeof(offender));
    char msg[sizeof(offender) + 64];
    snprintf(msg, sizeof(msg), "/tmp listing disagreed at %s", offender);
    EXPECT_TRUE(listed_ok, msg);

    TEST("a stat-visible /tmp file unlinks");
    snprintf(p, sizeof(p), "%s/f", dir);
    EXPECT_TRUE(invisible(p) || unlink(p) == 0,
                "visible file could not be unlinked");

    TEST("a stat-visible /tmp directory rmdir's");
    snprintf(p, sizeof(p), "%s/d", dir);
    EXPECT_TRUE(invisible(p) || rmdir(p) == 0,
                "visible directory could not be removed");

    TEST("a stat-visible /tmp file renames");
    snprintf(p, sizeof(p), "%s/r", dir);
    snprintf(q, sizeof(q), "%s/r2", dir);
    EXPECT_TRUE(invisible(p) || rename(p, q) == 0,
                "visible file could not be renamed");

    /* The other half of the contract: a guest's own /tmp file, which the create
     * resolver places in the sysroot, must remain removable. This is the common
     * case any workload depends on; a fix that made the host-visible entry
     * invisible must not have broken it.
     */
    TEST("a guest-created /tmp file round-trips");
    snprintf(p, sizeof(p), "%s/made", dir);
    int fd = open(p, O_CREAT | O_WRONLY, 0644);
    EXPECT_TRUE(fd >= 0 && close(fd) == 0 && unlink(p) == 0,
                "guest-created file could not be created then unlinked");

    /* Left behind for the harness, which asserts the sysroot gained the
     * redirected directory while the host staging directory gained nothing.
     * Without that, the checks above would also be satisfied by a guest that
     * reached nothing at all.
     */
    TEST("a guest-created /tmp file reads back");
    snprintf(p, sizeof(p), "%s/kept", dir);
    EXPECT_TRUE(round_trips(p), "guest-created file did not read back");

    SUMMARY("test-sysroot-tmp-remove");
    return fails > 0 ? 1 : 0;
}
