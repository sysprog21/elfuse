/* OCI runtime-files injection unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Native macOS test program. Builds scratch run directories under
 * /tmp, drives oci_runtime_files_inject against each shape (empty
 * /etc, pre-existing symlink, pre-existing regular file), then
 * asserts the three target files end up with the expected content.
 *
 * The /etc/resolv.conf check accepts either the scutil-collected
 * nameservers or the 8.8.8.8 / 1.1.1.1 fallback so the suite stays
 * green on machines with no configured DNS (e.g. lab VMs).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oci/runtime-files.h"

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

static int total = 0;
static int passed = 0;

static void report_pass(const char *name)
{
    total++;
    passed++;
    printf("  " GREEN "OK" RESET "   %s\n", name);
}

__attribute__((format(printf, 2, 3))) static void report_fail(const char *name,
                                                              const char *fmt,
                                                              ...)
{
    total++;
    char detail[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    printf("  " RED "FAIL" RESET " %s: %s\n", name, detail);
}

static int read_file(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    size_t off = 0;
    while (off + 1 < cap) {
        ssize_t r = read(fd, buf + off, cap - 1 - off);
        if (r < 0) {
            close(fd);
            return -1;
        }
        if (r == 0)
            break;
        off += (size_t) r;
    }
    close(fd);
    buf[off] = '\0';
    return (int) off;
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

static int make_run_dir(char *out, size_t cap)
{
    snprintf(out, cap, "/tmp/elfuse-rf-XXXXXX");
    if (!mkdtemp(out))
        return -1;
    return 0;
}

static void test_inject_into_empty_etc(void)
{
    const char *name = "inject creates /etc and three files";
    char run_dir[64];
    if (make_run_dir(run_dir, sizeof(run_dir)) < 0) {
        report_fail(name, "mkdtemp failed: errno=%d", errno);
        return;
    }
    const char *err = NULL;
    if (oci_runtime_files_inject(run_dir, &err) < 0) {
        report_fail(name, "inject rc<0 err=%s", err ? err : "(nil)");
        goto out;
    }
    struct stat st;
    char path[256];
    snprintf(path, sizeof(path), "%s/etc/resolv.conf", run_dir);
    if (lstat(path, &st) < 0 || !S_ISREG(st.st_mode)) {
        report_fail(name, "resolv.conf missing/not regular");
        goto out;
    }
    snprintf(path, sizeof(path), "%s/etc/hosts", run_dir);
    if (lstat(path, &st) < 0 || !S_ISREG(st.st_mode)) {
        report_fail(name, "hosts missing/not regular");
        goto out;
    }
    snprintf(path, sizeof(path), "%s/etc/hostname", run_dir);
    if (lstat(path, &st) < 0 || !S_ISREG(st.st_mode)) {
        report_fail(name, "hostname missing/not regular");
        goto out;
    }
    report_pass(name);
out:
    rmrf(run_dir);
}

static void test_inject_overwrites_symlink(void)
{
    const char *name = "inject overwrites pre-existing symlink";
    char run_dir[64];
    if (make_run_dir(run_dir, sizeof(run_dir)) < 0) {
        report_fail(name, "mkdtemp failed: errno=%d", errno);
        return;
    }
    char etc[256];
    snprintf(etc, sizeof(etc), "%s/etc", run_dir);
    if (mkdir(etc, 0755) < 0) {
        report_fail(name, "mkdir etc failed: errno=%d", errno);
        goto out;
    }
    char link_path[256];
    snprintf(link_path, sizeof(link_path), "%s/etc/resolv.conf", run_dir);
    /* Image-shipped dangling symlink: points off the rootfs at a
     * /run/systemd/resolve target the guest will never have.
     */
    if (symlink("/run/systemd/resolve/stub-resolv.conf", link_path) < 0) {
        report_fail(name, "symlink failed: errno=%d", errno);
        goto out;
    }
    const char *err = NULL;
    if (oci_runtime_files_inject(run_dir, &err) < 0) {
        report_fail(name, "inject rc<0 err=%s", err ? err : "(nil)");
        goto out;
    }
    struct stat st;
    if (lstat(link_path, &st) < 0) {
        report_fail(name, "resolv.conf missing after inject");
        goto out;
    }
    if (S_ISLNK(st.st_mode)) {
        report_fail(name, "resolv.conf is still a symlink");
        goto out;
    }
    if (!S_ISREG(st.st_mode)) {
        report_fail(name, "resolv.conf is not a regular file");
        goto out;
    }
    report_pass(name);
out:
    rmrf(run_dir);
}

static void test_inject_overwrites_regular(void)
{
    const char *name = "inject overwrites pre-existing regular file";
    char run_dir[64];
    if (make_run_dir(run_dir, sizeof(run_dir)) < 0) {
        report_fail(name, "mkdtemp failed: errno=%d", errno);
        return;
    }
    char etc[256];
    snprintf(etc, sizeof(etc), "%s/etc", run_dir);
    if (mkdir(etc, 0755) < 0) {
        report_fail(name, "mkdir etc failed");
        goto out;
    }
    char hosts_path[256];
    snprintf(hosts_path, sizeof(hosts_path), "%s/etc/hosts", run_dir);
    if (write_file(hosts_path, "127.0.0.1 image-default\n") < 0) {
        report_fail(name, "seed hosts failed");
        goto out;
    }
    const char *err = NULL;
    if (oci_runtime_files_inject(run_dir, &err) < 0) {
        report_fail(name, "inject rc<0 err=%s", err ? err : "(nil)");
        goto out;
    }
    char buf[1024];
    int n = read_file(hosts_path, buf, sizeof(buf));
    if (n < 0) {
        report_fail(name, "read hosts failed");
        goto out;
    }
    if (strstr(buf, "image-default")) {
        report_fail(name, "image-default content survived");
        goto out;
    }
    if (!strstr(buf, "host.elfuse.internal")) {
        report_fail(name, "synthesised host marker missing");
        goto out;
    }
    report_pass(name);
out:
    rmrf(run_dir);
}

static void test_hostname_is_fixed_string(void)
{
    const char *name = "/etc/hostname is exactly \"elfuse\\n\"";
    char run_dir[64];
    if (make_run_dir(run_dir, sizeof(run_dir)) < 0) {
        report_fail(name, "mkdtemp failed");
        return;
    }
    const char *err = NULL;
    if (oci_runtime_files_inject(run_dir, &err) < 0) {
        report_fail(name, "inject rc<0 err=%s", err ? err : "(nil)");
        goto out;
    }
    char path[256];
    snprintf(path, sizeof(path), "%s/etc/hostname", run_dir);
    char buf[64];
    int n = read_file(path, buf, sizeof(buf));
    if (n < 0) {
        report_fail(name, "read failed");
        goto out;
    }
    if (n != 7 || memcmp(buf, "elfuse\n", 7) != 0) {
        report_fail(name, "got len=%d body=%.*s", n, n, buf);
        goto out;
    }
    report_pass(name);
out:
    rmrf(run_dir);
}

static void test_hosts_contains_required(void)
{
    const char *name = "/etc/hosts has localhost and host.elfuse.internal";
    char run_dir[64];
    if (make_run_dir(run_dir, sizeof(run_dir)) < 0) {
        report_fail(name, "mkdtemp failed");
        return;
    }
    const char *err = NULL;
    if (oci_runtime_files_inject(run_dir, &err) < 0) {
        report_fail(name, "inject rc<0 err=%s", err ? err : "(nil)");
        goto out;
    }
    char path[256];
    snprintf(path, sizeof(path), "%s/etc/hosts", run_dir);
    char buf[1024];
    int n = read_file(path, buf, sizeof(buf));
    if (n < 0) {
        report_fail(name, "read failed");
        goto out;
    }
    if (!strstr(buf, "127.0.0.1") || !strstr(buf, "localhost")) {
        report_fail(name, "missing 127.0.0.1 / localhost: %.*s", n, buf);
        goto out;
    }
    if (!strstr(buf, "host.elfuse.internal")) {
        report_fail(name, "missing host.elfuse.internal: %.*s", n, buf);
        goto out;
    }
    if (!strstr(buf, "::1")) {
        report_fail(name, "missing ::1 row: %.*s", n, buf);
        goto out;
    }
    report_pass(name);
out:
    rmrf(run_dir);
}

static void test_resolv_has_nameserver(void)
{
    const char *name =
        "/etc/resolv.conf contains a nameserver line (scutil or fallback)";
    char run_dir[64];
    if (make_run_dir(run_dir, sizeof(run_dir)) < 0) {
        report_fail(name, "mkdtemp failed");
        return;
    }
    const char *err = NULL;
    if (oci_runtime_files_inject(run_dir, &err) < 0) {
        report_fail(name, "inject rc<0 err=%s", err ? err : "(nil)");
        goto out;
    }
    char path[256];
    snprintf(path, sizeof(path), "%s/etc/resolv.conf", run_dir);
    char buf[4096];
    int n = read_file(path, buf, sizeof(buf));
    if (n < 0) {
        report_fail(name, "read failed");
        goto out;
    }
    /* Walk lines; at least one must begin with "nameserver ". */
    bool found = false;
    const char *p = buf;
    while (p < buf + n) {
        const char *eol = strchr(p, '\n');
        size_t L = eol ? (size_t) (eol - p) : (size_t) (buf + n - p);
        if (L >= 11 && memcmp(p, "nameserver ", 11) == 0) {
            found = true;
            break;
        }
        if (!eol)
            break;
        p = eol + 1;
    }
    if (!found) {
        report_fail(name, "no nameserver line: %.*s", n, buf);
        goto out;
    }
    report_pass(name);
out:
    rmrf(run_dir);
}

int main(void)
{
    printf("oci_runtime_files_inject\n");
    test_inject_into_empty_etc();
    test_inject_overwrites_symlink();
    test_inject_overwrites_regular();
    test_hostname_is_fixed_string();
    test_hosts_contains_required();
    test_resolv_has_nameserver();
    printf("\nResults: %d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
