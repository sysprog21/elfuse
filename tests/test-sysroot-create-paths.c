/*
 * Sysroot create-path routing regression tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "test-harness.h"
#include "test-util.h"

int passes = 0, fails = 0;

static int write_file(const char *path, const char *contents)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0)
        return -1;
    int rc = write_fd_all(fd, contents, strlen(contents));
    close(fd);
    return rc;
}

static int xattr_probe(const char *path)
{
    errno = 0;
    int rc = setxattr(path, "user.elfuse_probe", "x", 1, 0);
    if (rc == 0) {
        removexattr(path, "user.elfuse_probe");
        return 1;
    }
    if (errno == ENOTSUP || errno == EOPNOTSUPP)
        return 0;
    return -1;
}

static void test_tmp_redirect_and_fallback(const char *guest_tmp_path,
                                           const char *mounted_host_tmp_path,
                                           const char *host_fallback_path)
{
    char buf[256];

    TEST("root create path stays inside sysroot");
    {
        const char *roots[] = {"/", "///"};
        bool ok = true;
        for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
            errno = 0;
            if (mkdir(roots[i], 0777) == 0 || errno != EEXIST) {
                ok = false;
                break;
            }
        }
        if (ok)
            PASS();
        else
            FAIL("mkdir root path returned wrong result");
    }

    TEST("/tmp create is redirected into sysroot");
    {
        if (write_file(guest_tmp_path, "tmp-redir\n") < 0) {
            FAIL("write via guest /tmp path failed");
        } else if (read_file_nul(guest_tmp_path, buf, sizeof(buf)) <= 0) {
            FAIL("read back via guest /tmp path failed");
        } else if (strcmp(buf, "tmp-redir\n")) {
            FAIL("guest /tmp file contents mismatch");
        } else if (read_file_nul(mounted_host_tmp_path, buf, sizeof(buf)) <=
                   0) {
            FAIL("mounted sysroot tmp path not created");
        } else if (strcmp(buf, "tmp-redir\n")) {
            FAIL("mounted sysroot tmp file contents mismatch");
        } else {
            PASS();
        }
    }

    TEST("trailing-slash mkdir resolves against the real parent");
    {
        /* Issue #100: a trailing slash made the parent-existence check split
         * the target off itself, so the create wrongly fell back / returned
         * EEXIST instead of creating the directory in the sysroot.
         */
        const char *parent = "/tmp/elfuse-trailing-slash";
        const char *child = "/tmp/elfuse-trailing-slash/child/";
        struct stat st;
        rmdir("/tmp/elfuse-trailing-slash/child");
        rmdir(parent);
        if (mkdir(parent, 0777) < 0 && errno != EEXIST) {
            FAIL("parent mkdir failed");
        } else if (mkdir(child, 0777) < 0) {
            FAIL("trailing-slash mkdir failed");
        } else if (stat("/tmp/elfuse-trailing-slash/child", &st) < 0 ||
                   !S_ISDIR(st.st_mode)) {
            FAIL("trailing-slash target is not a directory");
        } else {
            rmdir("/tmp/elfuse-trailing-slash/child");
            rmdir(parent);
            PASS();
        }
    }

    TEST("non-sysroot absolute create falls back to host");
    {
        if (write_file(host_fallback_path, "host-fallback\n") < 0) {
            FAIL("host fallback create failed");
        } else if (read_file_nul(host_fallback_path, buf, sizeof(buf)) <= 0) {
            FAIL("host fallback readback failed");
        } else if (strcmp(buf, "host-fallback\n")) {
            FAIL("host fallback file contents mismatch");
        } else {
            PASS();
        }
    }
}

static void test_relative_xattr(void)
{
    TEST("relative xattr uses guest cwd");
    {
        const char *rel_dir = "/tmp/elfuse-sysroot-create-paths";
        const char *rel_file = "rel-xattr.txt";
        char value[32];
        memset(value, 0, sizeof(value));

        if (chdir(rel_dir) < 0) {
            FAIL("chdir into redirected tmp dir failed");
        } else if (write_file(rel_file, "cwd\n") < 0) {
            FAIL("relative file create in guest cwd failed");
        } else {
            int probe = xattr_probe(rel_file);
            if (probe < 0) {
                FAIL("relative xattr probe failed");
            } else if (probe == 0) {
                PASS();
            } else if (setxattr(rel_file, "user.elfuse_relx", "cwd", 3, 0) <
                       0) {
                FAIL("relative setxattr failed");
            } else if (getxattr(rel_file, "user.elfuse_relx", value,
                                sizeof(value)) != 3) {
                FAIL("relative getxattr failed");
            } else if (strcmp(value, "cwd")) {
                FAIL("relative xattr value mismatch");
            } else {
                PASS();
            }
        }
    }
}

static void test_create_symlink_escape(const char *mounted_sysroot_root,
                                       const char *host_fallback_path)
{
    TEST("redirected /tmp create rejects sysroot symlink escape");
    {
        char sysroot_tmp[512];
        char escape_dir[512];
        char guest_escape_path[512];
        char host_escape_file[512];
        char *slash;

        if (snprintf(sysroot_tmp, sizeof(sysroot_tmp), "%s/tmp",
                     mounted_sysroot_root) >= (int) sizeof(sysroot_tmp) ||
            snprintf(escape_dir, sizeof(escape_dir), "%s",
                     host_fallback_path) >= (int) sizeof(escape_dir) ||
            snprintf(guest_escape_path, sizeof(guest_escape_path),
                     "/tmp/escape-check/file.txt") >=
                (int) sizeof(guest_escape_path)) {
            FAIL("symlink escape paths too long");
        } else {
            slash = strrchr(escape_dir, '/');
            if (!slash) {
                FAIL("host fallback path has no parent directory");
                goto symlink_escape_done;
            }
            *slash = '\0';
            if (snprintf(host_escape_file, sizeof(host_escape_file),
                         "%s/escape-check/file.txt",
                         escape_dir) >= (int) sizeof(host_escape_file)) {
                FAIL("symlink escape paths too long");
            } else if (unlink("/tmp/elfuse-sysroot-create-paths/file.txt") <
                           0 &&
                       errno != ENOENT) {
                FAIL("failed to remove redirected tmp test file");
            } else if (unlink(
                           "/tmp/elfuse-sysroot-create-paths/rel-xattr.txt") <
                           0 &&
                       errno != ENOENT) {
                FAIL("failed to remove redirected tmp xattr test file");
            } else if (rmdir("/tmp/elfuse-sysroot-create-paths") < 0 &&
                       errno != ENOENT) {
                FAIL("failed to remove redirected tmp test directory");
            } else if (rmdir(sysroot_tmp) < 0) {
                FAIL("failed to remove sysroot tmp dir before symlink test");
            } else if (symlink(escape_dir, sysroot_tmp) < 0) {
                FAIL("failed to install sysroot tmp symlink");
            } else {
                errno = 0;
                if (write_file(guest_escape_path, "escape\n") == 0) {
                    FAIL("redirected /tmp create followed symlink escape");
                } else if (access(host_escape_file, F_OK) == 0) {
                    FAIL("redirected /tmp create escaped into host path");
                } else {
                    PASS();
                }
            }
        }
    symlink_escape_done:;
    }
}

static void test_unlink_paths(const char *mounted_sysroot_root,
                              const char *host_fallback_path)
{
    TEST("failed unlink does not create redirected parent dirs");
    {
        char sysroot_tmp[512];
        char guest_missing_path[512];

        if (snprintf(sysroot_tmp, sizeof(sysroot_tmp), "%s/tmp",
                     mounted_sysroot_root) >= (int) sizeof(sysroot_tmp) ||
            snprintf(guest_missing_path, sizeof(guest_missing_path),
                     "/tmp/unlink-missing/file.txt") >=
                (int) sizeof(guest_missing_path)) {
            FAIL("unlink side-effect paths too long");
        } else if (unlink(sysroot_tmp) < 0 && errno != ENOENT) {
            FAIL("failed to remove sysroot tmp symlink before unlink test");
        } else if (unlink("/tmp/unlink-missing/file.txt") < 0 &&
                   errno != ENOENT) {
            FAIL("failed to remove previous redirected tmp file");
        } else if (rmdir("/tmp/unlink-missing") < 0 && errno != ENOENT) {
            FAIL("failed to remove previous redirected tmp directory");
        } else if (unlink(guest_missing_path) == 0) {
            FAIL("unlink unexpectedly succeeded for missing redirected path");
        } else if (access(sysroot_tmp, F_OK) == 0) {
            FAIL("failed unlink created redirected tmp parent");
        } else {
            PASS();
        }
    }

    TEST("failed unlink rejects redirected tmp symlink escape");
    {
        char sysroot_tmp[512];
        char escape_dir[512];
        char guest_missing_path[512];
        char host_escape_file[512];
        char *slash;

        if (snprintf(sysroot_tmp, sizeof(sysroot_tmp), "%s/tmp",
                     mounted_sysroot_root) >= (int) sizeof(sysroot_tmp) ||
            snprintf(escape_dir, sizeof(escape_dir), "%s",
                     host_fallback_path) >= (int) sizeof(escape_dir) ||
            snprintf(guest_missing_path, sizeof(guest_missing_path),
                     "/tmp/unlink-escape.txt") >=
                (int) sizeof(guest_missing_path)) {
            FAIL("unlink symlink escape paths too long");
        } else {
            slash = strrchr(escape_dir, '/');
            if (!slash) {
                FAIL("host fallback path has no parent directory");
                goto unlink_symlink_escape_done;
            }
            *slash = '\0';
            if (snprintf(host_escape_file, sizeof(host_escape_file),
                         "%s/unlink-escape.txt",
                         escape_dir) >= (int) sizeof(host_escape_file)) {
                FAIL("unlink symlink escape paths too long");
            } else if (unlink(sysroot_tmp) < 0 && errno != ENOENT) {
                FAIL(
                    "failed to remove sysroot tmp path before unlink escape "
                    "test");
            } else if (symlink(escape_dir, sysroot_tmp) < 0) {
                FAIL(
                    "failed to install sysroot tmp symlink for unlink escape "
                    "test");
            } else if (unlink(guest_missing_path) == 0) {
                FAIL(
                    "unlink unexpectedly succeeded for redirected symlink "
                    "path");
            } else if (access(host_escape_file, F_OK) == 0) {
                FAIL("unlink followed redirected tmp symlink escape");
            } else {
                PASS();
            }
        }
    unlink_symlink_escape_done:
        unlink(sysroot_tmp);
        mkdir(sysroot_tmp, 0755);
    }
}

static void test_nonexistent_parent(const char *mounted_sysroot_root)
{
    TEST("open file in non-existent parent returns ENOENT, not ELOOP");
    {
        int fd = open("/etc/nonexistent_parent_dir_123/sub/file.txt",
                      O_CREAT | O_WRONLY, 0644);
        EXPECT_ERRNO(fd, ENOENT,
                     "open on non-existent parent failed to return ENOENT");
        if (fd >= 0)
            close(fd);
    }

    TEST("open file in non-existent parent TOCTOU race stress pass");
    {
        char race_dir[512];
        char race_file[512];
        snprintf(race_dir, sizeof(race_dir), "%s/tmp/race_dir",
                 mounted_sysroot_root);
        snprintf(race_file, sizeof(race_file), "/tmp/race_dir/file.txt");

        pid_t pid = fork();
        if (pid < 0)
            FAIL("fork failed");
        else if (pid == 0) {
            /* Child process: continuously create and delete the directory */
            while (1) {
                mkdir(race_dir, 0755);
                rmdir(race_dir);
            }
            _exit(0);
        }

        bool hit_eloop = false;
        int iterations = 0;
        while (iterations < 10000) {
            iterations++;
            int fd = open("/tmp/race_dir/file.txt", O_CREAT | O_WRONLY, 0644);
            if (fd >= 0) {
                close(fd);
                unlink("/tmp/race_dir/file.txt");
            } else if (errno == ELOOP) {
                hit_eloop = true;
                break;
            }
        }

        kill(pid, SIGKILL);
        int status;
        waitpid(pid, &status, 0);

        /* Cleanup guest paths */
        unlink("/tmp/race_dir/file.txt");
        rmdir("/tmp/race_dir");

        /* Cleanup host paths inside sysroot */
        char host_race_file[512], host_race_dir[512];
        snprintf(host_race_file, sizeof(host_race_file),
                 "%s/tmp/race_dir/file.txt", mounted_sysroot_root);
        snprintf(host_race_dir, sizeof(host_race_dir), "%s/tmp/race_dir",
                 mounted_sysroot_root);
        unlink(host_race_file);
        rmdir(host_race_dir);

        /* The host-escape half of this assertion lives in the harness
         * (mk/tests.mk). Guest /tmp is sysroot-backed for lookups as well as
         * creates, so a stat of /tmp/race_dir from in here reports on the
         * sysroot copy the lines above just deleted and can never observe a
         * host artifact, whether or not the race produced one.
         */
        EXPECT_TRUE(!hit_eloop, "TOCTOU race returned ELOOP");
    }
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr,
                "usage: %s <guest-tmp-path> <mounted-host-tmp-path> "
                "<host-fallback-path> <mounted-sysroot-root>\n",
                argv[0]);
        return 2;
    }

    const char *guest_tmp_path = argv[1];
    const char *mounted_host_tmp_path = argv[2];
    const char *host_fallback_path = argv[3];
    const char *mounted_sysroot_root = argv[4];

    printf("test-sysroot-create-paths: create-path routing tests\n");

    test_tmp_redirect_and_fallback(guest_tmp_path, mounted_host_tmp_path,
                                   host_fallback_path);
    test_relative_xattr();
    test_create_symlink_escape(mounted_sysroot_root, host_fallback_path);
    test_unlink_paths(mounted_sysroot_root, host_fallback_path);
    test_nonexistent_parent(mounted_sysroot_root);

    SUMMARY("test-sysroot-create-paths");
    return fails > 0 ? 1 : 0;
}
