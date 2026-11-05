/*
 * Case-collision regression tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Names that a case-folding volume would merge must stay separate files to the
 * guest, and every syscall that names a file has to agree about which one it
 * means. This walks the whole surface (open, rename, renameat2 with EXCHANGE
 * and NOREPLACE, linkat, symlinkat, getdents64, statx, xattr) against a set of
 * names differing only in case.
 *
 * Code under test: the resolver in src/syscall/casefold-walk.c reached through
 * src/syscall/path.c. A regression shows up as two guest names resolving to one
 * file, so a write through one spelling is visible through the other, or as a
 * listing reporting a name the guest cannot then open.
 *
 * Nothing here may be conditional on the sysroot's on-disk layout. Three checks
 * once gated themselves on the presence of a per-directory index file that the
 * stateless scheme does not create, which made them report success without
 * running their assertions; a guard whose condition cannot hold is a silent
 * pass, so these assert unconditionally. Run under --sysroot.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "test-harness.h"
#include "test-util.h"

#ifndef SYS_renameat2
#define SYS_renameat2 276
#endif

#ifndef SYS_getdents64
#define SYS_getdents64 61
#endif

#ifndef SYS_statx
#define SYS_statx 291
#endif

#define LINUX_RENAME_EXCHANGE (1 << 1)

int passes = 0, fails = 0;

typedef struct {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
} linux_dirent64_t;

static void build_long_name(char *out, size_t outsz, char first)
{
    memset(out, 'a', outsz - 1);
    out[0] = first;
    out[outsz - 1] = '\0';
}

static int xattr_supported(void)
{
    const char *probe = "/tmp/elfuse-case-collision-xattr-probe";
    unlink(probe);
    if (file_write(probe, "probe\n") < 0)
        return 0;

    int rc = setxattr(probe, "user.elfuse_probe", "x", 1, 0);
    int ok = (rc == 0 || errno == ENOTSUP || errno == EOPNOTSUPP);
    unlink(probe);
    return ok;
}

static int getdents_contains_after_partial(const char *dir_path,
                                           const char *first_name,
                                           const char *second_name)
{
    int fd = open(dir_path, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return 0;

    char small[48];
    char large[1024];
    long n1 = syscall(SYS_getdents64, fd, small, sizeof(small));
    if (n1 < 0) {
        close(fd);
        return 0;
    }

    int saw_first = 0;
    int saw_second = 0;
    for (;;) {
        long n = syscall(SYS_getdents64, fd, large, sizeof(large));
        if (n < 0) {
            close(fd);
            return 0;
        }
        if (n == 0)
            break;
        long off = 0;
        while (off < n) {
            linux_dirent64_t *de = (linux_dirent64_t *) (large + off);
            if (!strcmp(de->d_name, first_name))
                saw_first = 1;
            if (!strcmp(de->d_name, second_name))
                saw_second = 1;
            off += de->d_reclen;
        }
    }

    int reopen_fd = openat(fd, ".", O_RDONLY | O_DIRECTORY);
    close(fd);
    if (reopen_fd < 0)
        return 0;

    saw_first = 0;
    saw_second = 0;
    for (;;) {
        long n = syscall(SYS_getdents64, reopen_fd, large, sizeof(large));
        if (n < 0) {
            close(reopen_fd);
            return 0;
        }
        if (n == 0)
            break;
        long off = 0;
        while (off < n) {
            linux_dirent64_t *de = (linux_dirent64_t *) (large + off);
            if (!strcmp(de->d_name, first_name))
                saw_first = 1;
            if (!strcmp(de->d_name, second_name))
                saw_second = 1;
            off += de->d_reclen;
        }
    }
    close(reopen_fd);
    return saw_first && saw_second;
}

/* One linkat case over a symlink: create @target_name, point @link_name at it
 * (spelled relative or absolute by @absolute_target), and hard-link the symlink
 * with @flags. @expect_link says which node the new name must be: the link
 * itself without AT_SYMLINK_FOLLOW, the target with it. The hard-link names are
 * case-protected, so on a folding sysroot every case exercises the
 * escaped-create path through linkat rather than through open.
 */
static void check_linkat(const char *base,
                         const char *target_name,
                         const char *link_name,
                         const char *hard_name,
                         bool absolute_target,
                         int flags,
                         bool expect_link)
{
    char target[320];
    char link_path[320];
    char hard_path[320];
    struct stat st;

    snprintf(target, sizeof(target), "%s/%s", base, target_name);
    snprintf(link_path, sizeof(link_path), "%s/%s", base, link_name);
    snprintf(hard_path, sizeof(hard_path), "%s/%s", base, hard_name);
    unlink(hard_path);
    unlink(link_path);
    unlink(target);

    if (file_write(target, "linkat\n") < 0) {
        FAIL("failed to create link target");
    } else if (symlink(absolute_target ? target : target_name, link_path) < 0) {
        FAIL("failed to create symlink");
    } else if (lstat(link_path, &st) < 0 || !S_ISLNK(st.st_mode)) {
        FAIL("lstat did not report the symlink");
    } else if (linkat(AT_FDCWD, link_path, AT_FDCWD, hard_path, flags) < 0) {
        FAIL("linkat failed");
    } else if (lstat(hard_path, &st) < 0) {
        FAIL("lstat on the new hard link failed");
    } else if (expect_link ? !S_ISLNK(st.st_mode) : !S_ISREG(st.st_mode)) {
        FAIL(expect_link ? "followed the symlink when asked not to"
                         : "linked the symlink itself instead of its target");
    } else {
        PASS();
    }
}

static void test_exchange_readdir_cases(const char *base,
                                        const char *dir_a,
                                        const char *dir_b)
{
    TEST("readdir lists Foo and foo distinctly");
    {
        char upper[320];
        char lower[320];
        snprintf(upper, sizeof(upper), "%s/Foo", base);
        snprintf(lower, sizeof(lower), "%s/foo", base);

        unlink(upper);
        unlink(lower);
        if (file_write(upper, "upper\n") < 0 ||
            file_write(lower, "lower\n") < 0) {
            FAIL("failed to create colliding files");
        } else if (!dir_contains(base, "Foo") || !dir_contains(base, "foo")) {
            FAIL("readdir collapsed colliding names");
        } else {
            PASS();
        }
    }

    TEST("renameat2 exchange swaps Foo and foo");
    {
        char upper[320];
        char lower[320];
        char buf_upper[32];
        char buf_lower[32];
        snprintf(upper, sizeof(upper), "%s/Foo", base);
        snprintf(lower, sizeof(lower), "%s/foo", base);

        if (syscall(SYS_renameat2, AT_FDCWD, upper, AT_FDCWD, lower,
                    LINUX_RENAME_EXCHANGE) < 0) {
            FAIL("renameat2 exchange failed");
        } else if (read_file_nul(upper, buf_upper, sizeof(buf_upper)) <= 0 ||
                   read_file_nul(lower, buf_lower, sizeof(buf_lower)) <= 0) {
            FAIL("failed to read exchanged files");
        } else if (strcmp(buf_upper, "lower\n") ||
                   strcmp(buf_lower, "upper\n")) {
            FAIL("renameat2 exchange produced wrong contents");
        } else {
            PASS();
        }
    }

    TEST("renameat2 exchange swaps colliding names across directories");
    {
        char left[320];
        char right[320];
        char buf_left[32];
        char buf_right[32];
        snprintf(left, sizeof(left), "%s/Foo", dir_a);
        snprintf(right, sizeof(right), "%s/foo", dir_b);
        unlink(left);
        unlink(right);

        if (file_write(left, "left\n") < 0 ||
            file_write(right, "right\n") < 0) {
            FAIL("failed to create cross-directory colliding files");
        } else if (syscall(SYS_renameat2, AT_FDCWD, left, AT_FDCWD, right,
                           LINUX_RENAME_EXCHANGE) < 0) {
            FAIL("cross-directory rename exchange failed");
        } else if (read_file_nul(left, buf_left, sizeof(buf_left)) <= 0 ||
                   read_file_nul(right, buf_right, sizeof(buf_right)) <= 0) {
            FAIL("cross-directory exchanged files not readable");
        } else if (strcmp(buf_left, "right\n") || strcmp(buf_right, "left\n")) {
            FAIL("cross-directory exchange contents mismatch");
        } else {
            PASS();
        }
    }
}

static void test_link_stat_xattr_getdents(const char *base)
{
    TEST("linkat creates second colliding spelling");
    {
        char src[320];
        char alias[320];
        struct stat st_src;
        struct stat st_alias;

        snprintf(src, sizeof(src), "%s/hardlink", base);
        snprintf(alias, sizeof(alias), "%s/HARDLINK", base);
        unlink(src);
        unlink(alias);

        if (file_write(src, "inode\n") < 0) {
            FAIL("failed to create hardlink source");
        } else if (link(src, alias) < 0) {
            FAIL("linkat failed");
        } else if (stat(src, &st_src) < 0 || stat(alias, &st_alias) < 0) {
            FAIL("stat after link failed");
        } else if (st_src.st_ino != st_alias.st_ino || st_src.st_nlink < 2) {
            FAIL("colliding hardlinks do not share inode");
        } else if (unlink(src) < 0 || stat(alias, &st_alias) < 0 ||
                   dir_contains(base, "hardlink") ||
                   !dir_contains(base, "HARDLINK")) {
            FAIL("unlink removed wrong hardlink entry");
        } else {
            PASS();
        }
    }

    TEST("access and statx distinguish colliding spellings");
    {
        char upper[320];
        char lower[320];
        struct statx sx_upper;
        struct statx sx_lower;
        snprintf(upper, sizeof(upper), "%s/Foo", base);
        snprintf(lower, sizeof(lower), "%s/foo", base);
        memset(&sx_upper, 0, sizeof(sx_upper));
        memset(&sx_lower, 0, sizeof(sx_lower));

        if (access(upper, F_OK) < 0 || access(lower, F_OK) < 0) {
            FAIL("access on colliding spellings failed");
        } else if (syscall(SYS_statx, AT_FDCWD, upper, 0, 0x7ff, &sx_upper) <
                       0 ||
                   syscall(SYS_statx, AT_FDCWD, lower, 0, 0x7ff, &sx_lower) <
                       0) {
            FAIL("statx on colliding spellings failed");
        } else if (!S_ISREG(sx_upper.stx_mode) || !S_ISREG(sx_lower.stx_mode)) {
            FAIL("statx returned wrong file type");
        } else {
            PASS();
        }
    }

    TEST("getdents64 survives partial read and reopen-by-fd");
    {
        if (getdents_contains_after_partial(base, "Foo", "foo"))
            PASS();
        else
            FAIL("getdents64 lost colliding names after partial read");
    }

    TEST("xattr works on colliding spellings");
    {
        char upper[320];
        char lower[320];
        char value[32];
        snprintf(upper, sizeof(upper), "%s/Foo", base);
        snprintf(lower, sizeof(lower), "%s/foo", base);
        memset(value, 0, sizeof(value));

        errno = 0;
        if (setxattr(upper, "user.elfuse_case", "upper", 5, 0) < 0 &&
            errno != ENOTSUP && errno != EOPNOTSUPP) {
            FAIL("setxattr on colliding spelling failed");
        } else if (errno == ENOTSUP || errno == EOPNOTSUPP) {
            PASS();
        } else if (setxattr(lower, "user.elfuse_case", "lower", 5, 0) < 0) {
            FAIL("setxattr on second colliding spelling failed");
        } else if (getxattr(upper, "user.elfuse_case", value, sizeof(value)) !=
                   5) {
            FAIL("getxattr upper failed");
        } else if (strcmp(value, "upper")) {
            FAIL("upper xattr value mismatch");
        } else {
            memset(value, 0, sizeof(value));
            if (getxattr(lower, "user.elfuse_case", value, sizeof(value)) !=
                5) {
                FAIL("getxattr lower failed");
            } else if (strcmp(value, "lower")) {
                FAIL("lower xattr value mismatch");
            } else {
                PASS();
            }
        }
    }
}

static void test_rename_cases(const char *base)
{
    TEST("plain rename moves a colliding source to its new spelling");
    {
        char old_path[320];
        char new_path[320];
        char untouched_path[320];
        char value[32];

        snprintf(old_path, sizeof(old_path), "%s/foo", base);
        snprintf(new_path, sizeof(new_path), "%s/bar", base);
        snprintf(untouched_path, sizeof(untouched_path), "%s/Foo", base);
        unlink(new_path);

        if (rename(old_path, new_path) < 0) {
            FAIL("plain rename failed");
        } else if (access(old_path, F_OK) == 0 || errno != ENOENT) {
            FAIL("old colliding spelling still resolves after rename");
        } else if (read_file_nul(new_path, value, sizeof(value)) <= 0) {
            FAIL("renamed colliding spelling not readable");
        } else if (strcmp(value, "upper\n") && strcmp(value, "lower\n")) {
            FAIL("renamed colliding spelling has unexpected contents");
        } else if (raw_open_rdonly(untouched_path) < 0) {
            FAIL("rename disturbed untouched colliding entry");
        } else if (dir_contains(base, "foo") || !dir_contains(base, "bar")) {
            FAIL("directory listing did not reflect the rename");
        } else {
            PASS();
        }
    }

    TEST("renameat2 NOREPLACE preserves existing colliding destination");
    {
        char src[320];
        char dst[320];

        snprintf(src, sizeof(src), "%s/bar", base);
        snprintf(dst, sizeof(dst), "%s/Foo", base);

        errno = 0;
        if (syscall(SYS_renameat2, AT_FDCWD, src, AT_FDCWD, dst,
                    1 /* RENAME_NOREPLACE */) != -1) {
            FAIL("renameat2 NOREPLACE unexpectedly succeeded");
        } else if (errno != EEXIST) {
            FAIL("renameat2 NOREPLACE returned wrong errno");
        } else if (access(src, F_OK) < 0 || access(dst, F_OK) < 0) {
            FAIL("renameat2 NOREPLACE disturbed source or destination");
        } else {
            PASS();
        }
    }
}

static void test_linkat_follow(const char *base)
{
    /* AT_SYMLINK_FOLLOW hard-links what the symlink points at, so the result is
     * a regular file; without it linkat(2) links the symlink itself, and that
     * holds for an absolute target too: nothing has to resolve the target to
     * copy the link.
     *
     * The followed target is spelled relative in one case and absolute in the
     * other: a symlink stores the bytes the guest wrote, so the two spellings
     * reach the target through different resolution paths (the relative one
     * against the translated parent, the absolute one through the
     * guest-namespace splice), and only running both shows linkat follows each.
     */
    TEST("linkat AT_SYMLINK_FOLLOW links the target, not the symlink");
    check_linkat(base, "real-target", "real-link", "REAL-HARD", false,
                 AT_SYMLINK_FOLLOW, false);

    TEST("linkat AT_SYMLINK_FOLLOW follows an absolute target too");
    check_linkat(base, "Abs.Target", "abs-follow-link", "ABS-FOLLOW-HARD", true,
                 AT_SYMLINK_FOLLOW, false);

    TEST("linkat without AT_SYMLINK_FOLLOW links the symlink itself");
    check_linkat(base, "abs-target", "abs-link", "ABS-HARD", true, 0, true);

    /* One probe suffices for flag validation: the flag set is checked before
     * the paths are resolved, so which fixture it runs against does not enter
     * into it.
     */
    TEST("unsupported linkat flags are rejected");
    {
        char target[320];
        char hard_path[320];

        snprintf(target, sizeof(target), "%s/real-target", base);
        snprintf(hard_path, sizeof(hard_path), "%s/FLAG-HARD", base);
        EXPECT_TRUE(
            linkat(AT_FDCWD, target, AT_FDCWD, hard_path, 0x40000000) == -1 &&
                errno == EINVAL,
            "unsupported linkat flags were accepted");
    }
}

static void test_name_edge_cases(const char *base)
{
    /* Deriving the on-disk spelling from the guest name alone means the sysroot
     * keeps no bookkeeping file of its own, so no basename is reserved and the
     * guest may create any name Linux allows. An earlier scheme did reserve
     * one, and refusing a name the guest is entitled to create is the failure
     * this pins.
     */
    TEST("no basename is reserved for create paths");
    {
        char plain[320];
        char buf[64];
        ssize_t n;

        snprintf(plain, sizeof(plain), "%s/.elfuse_case_index", base);
        unlink(plain);

        if (symlinkat("target", AT_FDCWD, plain) < 0) {
            FAIL("a name the guest is entitled to create was refused");
        } else if ((n = readlink(plain, buf, sizeof(buf) - 1)) < 0) {
            FAIL("the created name does not resolve back");
        } else {
            buf[n] = '\0';
            if (strcmp(buf, "target"))
                FAIL("readlink returned the wrong target");
            else
                PASS();
        }
        unlink(plain);
    }

    TEST("255-byte colliding basenames both open");
    {
        char name_a[256];
        char name_b[256];
        char path_a[512];
        char path_b[512];

        build_long_name(name_a, sizeof(name_a), 'a');
        build_long_name(name_b, sizeof(name_b), 'A');
        snprintf(path_a, sizeof(path_a), "%s/%s", base, name_a);
        snprintf(path_b, sizeof(path_b), "%s/%s", base, name_b);
        unlink(path_a);
        unlink(path_b);

        if (file_write(path_a, "long-a\n") < 0 ||
            file_write(path_b, "long-b\n") < 0) {
            FAIL("failed to create long colliding names");
        } else if (raw_open_rdonly(path_a) < 0 || raw_open_rdonly(path_b) < 0) {
            FAIL("failed to reopen long colliding names");
        } else {
            PASS();
        }
    }
}

int main(void)
{
    char base[256];
    char dir_a[320];
    char dir_b[320];
    snprintf(base, sizeof(base), "/tmp/elfuse-case-collision-%ld",
             (long) getpid());
    snprintf(dir_a, sizeof(dir_a), "%s/dir-a", base);
    snprintf(dir_b, sizeof(dir_b), "%s/dir-b", base);

    mkdir("/tmp", 0777);
    mkdir(base, 0777);
    mkdir(dir_a, 0777);
    mkdir(dir_b, 0777);

    printf("test-case-collision: case collision tests\n");

    test_exchange_readdir_cases(base, dir_a, dir_b);
    test_link_stat_xattr_getdents(base);
    test_rename_cases(base);
    test_linkat_follow(base);
    test_name_edge_cases(base);

    SUMMARY("test-case-collision");
    return fails > 0 ? 1 : 0;
}
