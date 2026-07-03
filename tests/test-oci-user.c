/* OCI image-config User resolver unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Native macOS test program. Builds a scratch rootfs under /tmp with
 * synthetic /etc/passwd and /etc/group fixtures, then drives
 * oci_user_lookup across the seven User shapes the OCI image-spec
 * defines plus the policy edges (numeric-name collision, missing
 * passwd, name-not-found, invalid characters, NULL-rootfs symbolic
 * rejection).
 *
 * The fixtures cover the layout typical container base images ship:
 * mixed root / system / app accounts, blank lines, comments, and a
 * stray numeric-named account ("1234") that tests the runc semantics
 * for digit-token precedence.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "oci/user-lookup.h"

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

static int g_total = 0;
static int g_passed = 0;

static void report_pass(const char *name)
{
    g_total++;
    g_passed++;
    printf("  " GREEN "OK" RESET "   %s\n", name);
}

__attribute__((format(printf, 2, 3))) static void report_fail(const char *name,
                                                              const char *fmt,
                                                              ...)
{
    g_total++;
    char detail[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    printf("  " RED "FAIL" RESET " %s: %s\n", name, detail);
}

static int write_file(const char *path, const char *body)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    size_t n = strlen(body);
    if (write(fd, body, n) != (ssize_t) n) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static void rmrf(const char *path)
{
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
    (void) system(cmd);
}

/* Build a scratch rootfs at /tmp/elfuse-user-XXXXXX with the supplied
 * /etc/passwd and /etc/group bodies. Either body pointer may be NULL to
 * skip writing that file (used for the missing-passwd case). Returns 0
 * on success; the caller frees the rootfs via rmrf when done.
 */
static int make_rootfs(char *out,
                       size_t cap,
                       const char *passwd_body,
                       const char *group_body)
{
    snprintf(out, cap, "/tmp/elfuse-user-XXXXXX");
    if (!mkdtemp(out))
        return -1;
    char etc[256];
    snprintf(etc, sizeof(etc), "%s/etc", out);
    if (mkdir(etc, 0755) < 0)
        return -1;
    if (passwd_body) {
        char path[512];
        snprintf(path, sizeof(path), "%s/etc/passwd", out);
        if (write_file(path, passwd_body) < 0)
            return -1;
    }
    if (group_body) {
        char path[512];
        snprintf(path, sizeof(path), "%s/etc/group", out);
        if (write_file(path, group_body) < 0)
            return -1;
    }
    return 0;
}

/* Fixture matches the shape Alpine / Debian base images carry. */
static const char *const PASSWD_BODY =
    "root:x:0:0:root:/root:/bin/sh\n"
    "\n"
    "# system accounts below\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "nginx:x:101:103:nginx user:/var/lib/nginx:/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "1234:x:50:50:digit account:/home/digit:/bin/sh\n"
    "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n";

static const char *const GROUP_BODY =
    "root:x:0:\n"
    "# group fixture\n"
    "daemon:x:1:\n"
    "adm:x:4:alice\n"
    "nginx:x:103:\n"
    "www-data:x:33:\n"
    "wheel:x:10:alice\n"
    "users:x:100:\n";

static void test_numeric_uid_only(void)
{
    const char *name = "numeric '1000' -> uid=1000, gid=1000, no passwd touch";
    uint32_t uid = 0xdead, gid = 0xdead;
    const char *err = NULL;
    /* NULL rootfs intentional: numeric forms must not touch the fs. */
    int rc = oci_user_lookup(NULL, "1000", &uid, &gid, &err);
    if (rc != 0 || uid != 1000 || gid != 1000) {
        report_fail(name, "rc=%d uid=%u gid=%u err=%s", rc, uid, gid,
                    err ? err : "(nil)");
    } else {
        report_pass(name);
    }
}

static void test_numeric_uid_gid(void)
{
    const char *name = "numeric '1000:5000' -> uid=1000, gid=5000";
    uint32_t uid = 0, gid = 0;
    const char *err = NULL;
    int rc = oci_user_lookup(NULL, "1000:5000", &uid, &gid, &err);
    if (rc != 0 || uid != 1000 || gid != 5000) {
        report_fail(name, "rc=%d uid=%u gid=%u err=%s", rc, uid, gid,
                    err ? err : "(nil)");
    } else {
        report_pass(name);
    }
}

static void test_symbolic_name_lookup(void)
{
    const char *name = "symbolic 'nginx' -> uid=101, gid=103 (primary)";
    char rootfs[64];
    if (make_rootfs(rootfs, sizeof(rootfs), PASSWD_BODY, GROUP_BODY) < 0) {
        report_fail(name, "make_rootfs failed: errno=%d", errno);
        return;
    }
    uint32_t uid = 0, gid = 0;
    const char *err = NULL;
    int rc = oci_user_lookup(rootfs, "nginx", &uid, &gid, &err);
    if (rc != 0 || uid != 101 || gid != 103) {
        report_fail(name, "rc=%d uid=%u gid=%u err=%s", rc, uid, gid,
                    err ? err : "(nil)");
    } else {
        report_pass(name);
    }
    rmrf(rootfs);
}

static void test_symbolic_name_with_groupname(void)
{
    const char *name = "'nginx:adm' -> uid=101, gid=4 (adm)";
    char rootfs[64];
    if (make_rootfs(rootfs, sizeof(rootfs), PASSWD_BODY, GROUP_BODY) < 0) {
        report_fail(name, "make_rootfs failed: errno=%d", errno);
        return;
    }
    uint32_t uid = 0, gid = 0;
    const char *err = NULL;
    int rc = oci_user_lookup(rootfs, "nginx:adm", &uid, &gid, &err);
    if (rc != 0 || uid != 101 || gid != 4) {
        report_fail(name, "rc=%d uid=%u gid=%u err=%s", rc, uid, gid,
                    err ? err : "(nil)");
    } else {
        report_pass(name);
    }
    rmrf(rootfs);
}

static void test_numeric_uid_with_groupname(void)
{
    const char *name = "'500:wheel' -> uid=500, gid=10 (wheel)";
    char rootfs[64];
    if (make_rootfs(rootfs, sizeof(rootfs), PASSWD_BODY, GROUP_BODY) < 0) {
        report_fail(name, "make_rootfs failed: errno=%d", errno);
        return;
    }
    uint32_t uid = 0, gid = 0;
    const char *err = NULL;
    int rc = oci_user_lookup(rootfs, "500:wheel", &uid, &gid, &err);
    if (rc != 0 || uid != 500 || gid != 10) {
        report_fail(name, "rc=%d uid=%u gid=%u err=%s", rc, uid, gid,
                    err ? err : "(nil)");
    } else {
        report_pass(name);
    }
    rmrf(rootfs);
}

static void test_symbolic_name_with_numeric_gid(void)
{
    const char *name = "'nginx:42' -> uid=101, gid=42";
    char rootfs[64];
    if (make_rootfs(rootfs, sizeof(rootfs), PASSWD_BODY, GROUP_BODY) < 0) {
        report_fail(name, "make_rootfs failed: errno=%d", errno);
        return;
    }
    uint32_t uid = 0, gid = 0;
    const char *err = NULL;
    int rc = oci_user_lookup(rootfs, "nginx:42", &uid, &gid, &err);
    if (rc != 0 || uid != 101 || gid != 42) {
        report_fail(name, "rc=%d uid=%u gid=%u err=%s", rc, uid, gid,
                    err ? err : "(nil)");
    } else {
        report_pass(name);
    }
    rmrf(rootfs);
}

static void test_missing_passwd_returns_einval(void)
{
    const char *name =
        "missing /etc/passwd with symbolic User -> EINVAL with diagnostic";
    char rootfs[64];
    if (make_rootfs(rootfs, sizeof(rootfs), NULL, NULL) < 0) {
        report_fail(name, "make_rootfs failed: errno=%d", errno);
        return;
    }
    uint32_t uid = 0, gid = 0;
    const char *err = NULL;
    errno = 0;
    int rc = oci_user_lookup(rootfs, "nginx", &uid, &gid, &err);
    if (rc != -1) {
        report_fail(name, "rc=%d (want -1)", rc);
    } else if (!err || !strstr(err, "/etc/passwd")) {
        report_fail(name, "err=%s (want '/etc/passwd' substring)",
                    err ? err : "(nil)");
    } else {
        report_pass(name);
    }
    rmrf(rootfs);
}

static void test_name_not_in_passwd(void)
{
    const char *name = "symbolic 'unknown' not in passwd -> ENOENT";
    char rootfs[64];
    if (make_rootfs(rootfs, sizeof(rootfs), PASSWD_BODY, GROUP_BODY) < 0) {
        report_fail(name, "make_rootfs failed: errno=%d", errno);
        return;
    }
    uint32_t uid = 0, gid = 0;
    const char *err = NULL;
    errno = 0;
    int rc = oci_user_lookup(rootfs, "ghost", &uid, &gid, &err);
    if (rc != -1) {
        report_fail(name, "rc=%d (want -1)", rc);
    } else if (errno != ENOENT) {
        report_fail(name, "errno=%d (want ENOENT)", errno);
    } else if (!err || !strstr(err, "'ghost'")) {
        report_fail(name, "err=%s (want 'ghost' substring)",
                    err ? err : "(nil)");
    } else {
        report_pass(name);
    }
    rmrf(rootfs);
}

static void test_digits_win_over_name_collision(void)
{
    /* The fixture has "1234:x:50:50:..." in passwd. The runc semantics
     * say "treat the token as numeric when it is all digits"; the user
     * therefore sees uid=1234 (not the looked-up uid=50). */
    const char *name = "'1234' parses as numeric uid=1234 (digit-form wins)";
    char rootfs[64];
    if (make_rootfs(rootfs, sizeof(rootfs), PASSWD_BODY, GROUP_BODY) < 0) {
        report_fail(name, "make_rootfs failed: errno=%d", errno);
        return;
    }
    uint32_t uid = 0, gid = 0;
    const char *err = NULL;
    int rc = oci_user_lookup(rootfs, "1234", &uid, &gid, &err);
    if (rc != 0 || uid != 1234 || gid != 1234) {
        report_fail(name, "rc=%d uid=%u gid=%u err=%s", rc, uid, gid,
                    err ? err : "(nil)");
    } else {
        report_pass(name);
    }
    rmrf(rootfs);
}

static void test_null_rootfs_with_symbolic_rejected(void)
{
    const char *name = "NULL rootfs + symbolic 'nginx' -> EINVAL no-rootfs";
    uint32_t uid = 0, gid = 0;
    const char *err = NULL;
    errno = 0;
    int rc = oci_user_lookup(NULL, "nginx", &uid, &gid, &err);
    if (rc != -1) {
        report_fail(name, "rc=%d (want -1)", rc);
    } else if (errno != EINVAL) {
        report_fail(name, "errno=%d (want EINVAL)", errno);
    } else if (!err || !strstr(err, "no rootfs")) {
        report_fail(name, "err=%s (want 'no rootfs' substring)",
                    err ? err : "(nil)");
    } else {
        report_pass(name);
    }
}

static void test_invalid_name_chars_rejected(void)
{
    const char *name = "name with '/' rejected before any lookup";
    char rootfs[64];
    if (make_rootfs(rootfs, sizeof(rootfs), PASSWD_BODY, GROUP_BODY) < 0) {
        report_fail(name, "make_rootfs failed: errno=%d", errno);
        return;
    }
    uint32_t uid = 0, gid = 0;
    const char *err = NULL;
    errno = 0;
    int rc = oci_user_lookup(rootfs, "bad/name", &uid, &gid, &err);
    if (rc != -1 || errno != EINVAL || !err ||
        !strstr(err, "invalid character")) {
        report_fail(name, "rc=%d errno=%d err=%s", rc, errno,
                    err ? err : "(nil)");
    } else {
        report_pass(name);
    }
    rmrf(rootfs);
}

static void test_empty_user_string(void)
{
    const char *name = "empty User string -> EINVAL";
    uint32_t uid = 0, gid = 0;
    const char *err = NULL;
    errno = 0;
    int rc = oci_user_lookup(NULL, "", &uid, &gid, &err);
    if (rc != -1 || errno != EINVAL || !err || !strstr(err, "empty")) {
        report_fail(name, "rc=%d errno=%d err=%s", rc, errno,
                    err ? err : "(nil)");
    } else {
        report_pass(name);
    }
}

int main(void)
{
    printf("== test-oci-user ==\n");
    test_numeric_uid_only();
    test_numeric_uid_gid();
    test_symbolic_name_lookup();
    test_symbolic_name_with_groupname();
    test_numeric_uid_with_groupname();
    test_symbolic_name_with_numeric_gid();
    test_missing_passwd_returns_einval();
    test_name_not_in_passwd();
    test_digits_win_over_name_collision();
    test_null_rootfs_with_symbolic_rejected();
    test_invalid_name_chars_rejected();
    test_empty_user_string();
    printf("\n%d/%d passed\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
