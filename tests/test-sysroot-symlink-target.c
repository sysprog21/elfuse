/*
 * Following a symlink whose target names an escaped file
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A relative symlink target stores the bytes the guest gave it, and
 * readlink(2) hands them back. On a folding sysroot that puts the target and
 * the disk out of step, because a name the volume cannot hold as itself is
 * stored escaped; handing the stored bytes to the host kernel then looks for
 * a name that is not there. An absolute target cannot even be stored
 * verbatim: anything following the link natively resolves it from the host
 * root rather than the sysroot, so creation rewrites it to a target relative
 * to the link's own directory (sys_symlinkat in src/syscall/fs.c). readlink
 * reports that rewritten spelling, the one visible divergence, because
 * nothing on disk tells a rewritten target from a relative one the guest
 * wrote.
 *
 * Following therefore happens in the guest's namespace: the target is resolved
 * as a guest path, through the same sysroot-or-host dispatch every other guest
 * path takes. An absolute target consequently behaves exactly like the same
 * absolute path typed by the guest: inside the sysroot when it is there, on
 * the host when it is not and the path is not a guest system directory.
 *
 * Code under test: the symlink handling in src/syscall/casefold-walk.c and the
 * splice in src/syscall/proc-state.c. A regression shows up as ENOENT for a
 * file the guest can see with readlink and lstat, which is how a rootfs with
 * ordinary symlinks stops working.
 *
 * Intermediate components are followed whichever call is made; only the final
 * one honors nofollow, which is what path_resolution(7) requires. Run under
 * --sysroot.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test-harness.h"
#include "test-util.h"

int passes = 0, fails = 0;

#define DIR_T "/symlink-target"

static void at(char *out, size_t outsz, const char *name)
{
    snprintf(out, outsz, "%s/%s", DIR_T, name);
}

/* Create @name holding @text, and return the path it was created at. */
static const char *make_file(const char *name, const char *text)
{
    static char path[PATH_MAX];

    at(path, sizeof(path), name);
    if (file_write(path, text) < 0)
        return NULL;
    return path;
}

static int link_to(const char *target, const char *name)
{
    char path[PATH_MAX];

    at(path, sizeof(path), name);
    unlink(path);
    return symlink(target, path);
}

/* Read through @name, following whatever links it passes. */
static int reads(const char *name, const char *want)
{
    char path[PATH_MAX];

    at(path, sizeof(path), name);
    return file_content_is(path, want);
}

int main(void)
{
    char path[PATH_MAX];
    char buf[PATH_MAX];
    struct stat st;
    ssize_t n;

    printf("test-sysroot-symlink-target: following escaped link targets\n");

    TEST("fixture setup");
    EXPECT_TRUE(mkdir(DIR_T, 0755) == 0 || errno == EEXIST, "mkdir");

    /* "Target.One" needs escaping; "plain" does not. Both are created by the
     * guest, so the difference is purely how the volume stores them.
     */
    TEST("stage an escaped target and a fold-stable one");
    EXPECT_TRUE(
        make_file("Target.One", "escaped") && make_file("plain", "literal"),
        "create targets");

    TEST("a relative target naming an escaped file is followed");
    EXPECT_TRUE(link_to("Target.One", "rel-escaped") == 0, "symlink");
    TEST("  and reads through to it");
    EXPECT_TRUE(reads("rel-escaped", "escaped") == 0, "content");

    /* The case that already worked. Kept so a fix cannot trade one for the
     * other.
     */
    TEST("a relative target naming a fold-stable file still follows");
    EXPECT_TRUE(link_to("plain", "rel-plain") == 0, "symlink");
    TEST("  and reads through to it");
    EXPECT_TRUE(reads("rel-plain", "literal") == 0, "content");

    TEST("an absolute target inside the sysroot is followed");
    at(path, sizeof(path), "Target.One");
    EXPECT_TRUE(link_to(path, "abs-escaped") == 0, "symlink");
    TEST("  and reads through to it");
    EXPECT_TRUE(reads("abs-escaped", "escaped") == 0, "content");

    TEST("a staged host symlink is followed");
    EXPECT_TRUE(stat("/host-home-link", &st) == 0 && S_ISDIR(st.st_mode),
                "stat follows host link");

    /* readlink reports the disk. A relative target is stored verbatim, so
     * the guest's own bytes come back; an absolute one was rewritten at
     * symlink() time to the sysroot-relative spelling (see the header), and
     * that spelling is what comes back. The link here sits one directory
     * below the guest root, so the rewrite is ".." plus the absolute target.
     */
    TEST("readlink returns a relative target verbatim");
    at(path, sizeof(path), "rel-escaped");
    n = readlink(path, buf, sizeof(buf) - 1);
    if (n < 0) {
        FAIL("readlink");
    } else {
        buf[n] = '\0';
        EXPECT_TRUE(!strcmp(buf, "Target.One"), "bytes must round-trip");
    }

    TEST("readlink reports the rewrite of an absolute target");
    at(path, sizeof(path), "abs-escaped");
    n = readlink(path, buf, sizeof(buf) - 1);
    if (n < 0) {
        FAIL("readlink");
    } else {
        char want[PATH_MAX];
        buf[n] = '\0';
        snprintf(want, sizeof(want), "..%s/%s", DIR_T, "Target.One");
        EXPECT_TRUE(!strcmp(buf, want), "expected the rewritten spelling");
    }

    TEST("lstat sees the link, not the target");
    EXPECT_TRUE(lstat(path, &st) == 0 && S_ISLNK(st.st_mode), "lstat");

    TEST("stat sees the target, not the link");
    EXPECT_TRUE(stat(path, &st) == 0 && S_ISREG(st.st_mode), "stat");

    /* An intermediate link is followed whatever the final component asks for,
     * which is what separates "do not follow the last component" from "do not
     * follow anything".
     */
    TEST("a link used as an intermediate component is followed");
    EXPECT_TRUE(mkdir(DIR_T "/Sub.Dir", 0755) == 0 || errno == EEXIST, "mkdir");
    at(path, sizeof(path), "Sub.Dir/Leaf.Name");
    EXPECT_TRUE(file_write(path, "under") == 0, "create leaf");
    TEST("  through the link");
    EXPECT_TRUE(link_to("Sub.Dir", "dir-link") == 0 &&
                    reads("dir-link/Leaf.Name", "under") == 0,
                "content through an intermediate link");

    TEST("nofollow still applies to the final component only");
    at(path, sizeof(path), "dir-link/Leaf.Name");
    EXPECT_TRUE(lstat(path, &st) == 0 && S_ISREG(st.st_mode),
                "the intermediate link must still be followed");

    TEST("a chain of three links is followed");
    EXPECT_TRUE(link_to("rel-escaped", "chain-b") == 0 &&
                    link_to("chain-b", "chain-c") == 0 &&
                    reads("chain-c", "escaped") == 0,
                "content through a chain");

    /* Excess '..' in a target clamps at the guest root (path_resolution(7)).
     * The spliced path escapes the sysroot lexically unless the resolver
     * collapses it after every splice, and the containment guard then
     * misreports the escape as ELOOP for a path Linux resolves.
     */
    TEST("a target climbing past the root is clamped");
    EXPECT_TRUE(
        link_to("../../../../../../symlink-target/Target.One", "updot") == 0 &&
            reads("updot", "escaped") == 0,
        "content through an over-climbing target");

    /* Regression guards for the link budget, green at introduction: exactly
     * MAXSYMLINKS (40) links resolve and the 41st reports ELOOP, matching
     * Linux (path_resolution(7)). An off-by-one in either direction flips
     * exactly one of the pair.
     */
    TEST("a 40-link chain resolves");
    {
        char prev[64] = "Target.One";
        bool chain_ok = true;

        for (int i = 1; i <= 40 && chain_ok; i++) {
            char name[64];

            snprintf(name, sizeof(name), "hop%02d", i);
            chain_ok = link_to(prev, name) == 0;
            snprintf(prev, sizeof(prev), "%s", name);
        }
        EXPECT_TRUE(chain_ok && reads("hop40", "escaped") == 0,
                    "40 links should resolve");
    }

    TEST("a 41-link chain reports ELOOP");
    EXPECT_TRUE(link_to("hop40", "hop41") == 0, "symlink");
    at(path, sizeof(path), "hop41");
    EXPECT_ERRNO(open(path, O_RDONLY), ELOOP, "should be ELOOP");

    /* Bounded, and with the errno Linux uses. An unbounded walk would hang or
     * exhaust a buffer instead.
     */
    TEST("a self-referential link reports ELOOP");
    EXPECT_TRUE(link_to("self", "self") == 0, "symlink");
    at(path, sizeof(path), "self");
    EXPECT_ERRNO(open(path, O_RDONLY), ELOOP, "should be ELOOP");

    TEST("a two-link cycle reports ELOOP");
    EXPECT_TRUE(
        link_to("cyc-b", "cyc-a") == 0 && link_to("cyc-a", "cyc-b") == 0,
        "symlinks");
    at(path, sizeof(path), "cyc-a");
    EXPECT_ERRNO(open(path, O_RDONLY), ELOOP, "should be ELOOP");

    TEST("a dangling target reports ENOENT");
    EXPECT_TRUE(link_to("No.Such.Name", "dangling") == 0, "symlink");
    at(path, sizeof(path), "dangling");
    EXPECT_ERRNO(open(path, O_RDONLY), ENOENT, "should be ENOENT");

    TEST("a dangling link is still visible to lstat and readlink");
    EXPECT_TRUE(lstat(path, &st) == 0 && S_ISLNK(st.st_mode) &&
                    readlink(path, buf, sizeof(buf) - 1) > 0,
                "the link itself exists");

    /* Operations that do not follow must keep working on the link, since a
     * fix that resolved targets everywhere would break removing a dangling one.
     */
    TEST("unlink removes the link, not its target");
    at(path, sizeof(path), "rel-escaped");
    EXPECT_TRUE(unlink(path) == 0, "unlink");
    TEST("  and the target survives");
    EXPECT_TRUE(reads("Target.One", "escaped") == 0, "target still there");

    /* Creating below an intermediate link has to follow it too, and the create
     * resolver is separate code from the lookup one, the same split that let
     * a wrong-case create escape once already. The new file must appear in the
     * directory the link names, not beside the link.
     */
    TEST("a create below an intermediate link follows it");
    at(path, sizeof(path), "dir-link/Made.Here");
    EXPECT_TRUE(file_write(path, "made") == 0, "create through the link");
    TEST("  and it landed in the directory the link names");
    EXPECT_TRUE(reads("Sub.Dir/Made.Here", "made") == 0,
                "content at the target");

    TEST("mkdir below an intermediate link follows it");
    at(path, sizeof(path), "dir-link/Made.Dir");
    EXPECT_TRUE(mkdir(path, 0755) == 0 || errno == EEXIST, "mkdir");
    TEST("  and it landed in the directory the link names");
    at(path, sizeof(path), "Sub.Dir/Made.Dir");
    EXPECT_TRUE(stat(path, &st) == 0 && S_ISDIR(st.st_mode), "dir at target");

    /* And the same through a descriptor, which is the third resolver: a tree
     * walker reaches every name this way and never builds an absolute path.
     */
    TEST("a dirfd-relative path through a link follows it");
    {
        int dirfd = open(DIR_T, O_RDONLY | O_DIRECTORY);
        char buf2[64];
        ssize_t got;
        int f = -1;

        if (dirfd < 0) {
            FAIL("open dirfd");
        } else if ((f = openat(dirfd, "dir-link/Leaf.Name", O_RDONLY)) < 0) {
            FAIL("openat through an intermediate link");
        } else if ((got = read(f, buf2, sizeof(buf2) - 1)) <= 0) {
            FAIL("read");
        } else {
            buf2[got] = '\0';
            EXPECT_TRUE(!strcmp(buf2, "under"), "wrong file through the dirfd");
        }
        if (f >= 0)
            close(f);
        if (dirfd >= 0)
            close(dirfd);
    }

    /* The final component itself may be the link. The follow decision belongs
     * to the caller (openat without O_NOFOLLOW follows, fstatat with
     * AT_SYMLINK_NOFOLLOW does not), and the dirfd-relative walk has to honor
     * it exactly as the absolute spellings above do. A regression hands the
     * stored target bytes to the host kernel instead: ENOENT for an escaped
     * target, and an absolute target resolved from the host's root.
     */
    TEST("a dirfd-relative final link with a relative target is followed");
    {
        int dirfd = open(DIR_T, O_RDONLY | O_DIRECTORY);
        char buf2[64];
        struct stat st2;
        ssize_t got;
        int f = -1;

        if (dirfd < 0) {
            FAIL("open dirfd");
        } else if (symlinkat("Target.One", dirfd, "final-rel") != 0) {
            FAIL("symlinkat");
        } else if ((f = openat(dirfd, "final-rel", O_RDONLY)) < 0) {
            FAIL("openat through a final link");
        } else if ((got = read(f, buf2, sizeof(buf2) - 1)) <= 0) {
            FAIL("read");
        } else {
            buf2[got] = '\0';
            EXPECT_TRUE(!strcmp(buf2, "escaped"),
                        "wrong file through the link");
        }
        if (f >= 0)
            close(f);

        TEST("  fstatat follows it");
        EXPECT_TRUE(dirfd >= 0 && fstatat(dirfd, "final-rel", &st2, 0) == 0 &&
                        S_ISREG(st2.st_mode),
                    "fstatat should reach the target");

        TEST("  and nofollow still sees the link itself");
        EXPECT_TRUE(
            dirfd >= 0 &&
                fstatat(dirfd, "final-rel", &st2, AT_SYMLINK_NOFOLLOW) == 0 &&
                S_ISLNK(st2.st_mode),
            "nofollow should stop at the link");

        TEST("a dirfd-relative final link with an absolute target is followed");
        f = -1;
        if (dirfd < 0) {
            FAIL("open dirfd");
        } else if (symlinkat(DIR_T "/Target.One", dirfd, "final-abs") != 0) {
            FAIL("symlinkat");
        } else if ((f = openat(dirfd, "final-abs", O_RDONLY)) < 0) {
            FAIL("openat through a final link");
        } else if ((got = read(f, buf2, sizeof(buf2) - 1)) <= 0) {
            FAIL("read");
        } else {
            buf2[got] = '\0';
            EXPECT_TRUE(!strcmp(buf2, "escaped"),
                        "wrong file through the link");
        }
        if (f >= 0)
            close(f);

        /* Creates through the descriptor must cross the link too. Create is
         * a separate resolver from lookup, and the descriptor-relative walk
         * is a separate entry point from the absolute one; the absolute
         * create-below-a-link cases above pass while this one regresses
         * whenever the two entry points map the create flag differently:
         * the create then aims at the host-literal path instead of landing
         * inside the sysroot, per openat(2)'s dirfd rule and
         * path_resolution(7)'s follow rule for intermediate components.
         */
        TEST("a dirfd-relative create below an intermediate link");
        f = -1;
        if (dirfd < 0) {
            FAIL("open dirfd");
        } else if ((f = openat(dirfd, "dir-link/New.File", O_CREAT | O_WRONLY,
                               0644)) < 0) {
            FAIL("openat O_CREAT through the link");
        } else if (write(f, "made-rel", 8) != 8) {
            FAIL("write");
        } else {
            TEST("  and it landed in the directory the link names");
            EXPECT_TRUE(reads("Sub.Dir/New.File", "made-rel") == 0,
                        "content at the target");
        }
        if (f >= 0)
            close(f);

        TEST("a dirfd-relative mkdir below an intermediate link");
        if (dirfd < 0) {
            FAIL("open dirfd");
        } else if (mkdirat(dirfd, "dir-link/New.Dir", 0755) != 0) {
            FAIL("mkdirat through the link");
        } else {
            TEST("  and it landed in the directory the link names");
            at(path, sizeof(path), "Sub.Dir/New.Dir");
            EXPECT_TRUE(stat(path, &st) == 0 && S_ISDIR(st.st_mode),
                        "dir at the target");
        }

        /* Create and lookup must agree through the link: a name the lookup
         * finds is one O_EXCL refuses.
         */
        TEST("O_EXCL through the link sees the existing leaf");
        errno = 0;
        f = openat(dirfd, "dir-link/Leaf.Name", O_CREAT | O_EXCL | O_WRONLY,
                   0644);
        if (f >= 0) {
            close(f);
            FAIL("O_EXCL created over an existing file");
        } else {
            EXPECT_ERRNO(-1, EEXIST, "should be EEXIST");
        }

        if (dirfd >= 0)
            close(dirfd);
    }

    SUMMARY("test-sysroot-symlink-target");
    return fails > 0 ? 1 : 0;
}
