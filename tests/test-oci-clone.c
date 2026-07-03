/* OCI clonefile-based per-run rootfs unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Native macOS test program. Provisions a src dir under /tmp (which
 * sits on the same APFS data volume as the test runner), clones it
 * via oci_clone_rootfs, then verifies APFS CoW semantics: writing to
 * the clone does not perturb the source. The test skips with a clear
 * message if clonefile reports ENOTSUP (e.g. /tmp on a future
 * non-APFS scratch), so the suite stays clean on hostile environments
 * rather than red.
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

#include "oci/clone-rootfs.h"

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define YELLOW "\033[1;33m"
#define RESET "\033[0m"

static int total = 0;
static int passed = 0;

static void report_pass(const char *name)
{
    total++;
    passed++;
    printf("  " GREEN "OK" RESET "   %s\n", name);
}

static void report_skip(const char *name, const char *reason)
{
    printf("  " YELLOW "SKIP" RESET " %s: %s\n", name, reason);
}

static void report_fail(const char *name, const char *fmt, ...)
{
    total++;
    char detail[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    printf("  " RED "FAIL" RESET " %s: %s\n", name, detail);
}

static int write_file(const char *path, const char *contents)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    size_t n = strlen(contents);
    if (write(fd, contents, n) != (ssize_t) n) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static bool file_has(const char *path, const char *want)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    char buf[128];
    size_t got = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[got] = '\0';
    return strcmp(buf, want) == 0;
}

static void test_clone_cow(void)
{
    char src[] = "/tmp/elfuse-clone-src-XXXXXX";
    if (!mkdtemp(src)) {
        report_fail("clone CoW", "mkdtemp src failed: errno=%d", errno);
        return;
    }
    /* Populate the source: one file in the root, one in a subdir. */
    char path[1024];
    snprintf(path, sizeof(path), "%s/hello", src);
    if (write_file(path, "original\n") < 0) {
        report_fail("clone CoW", "write hello failed");
        goto out_src;
    }
    snprintf(path, sizeof(path), "%s/sub", src);
    if (mkdir(path, 0755) < 0) {
        report_fail("clone CoW", "mkdir sub failed");
        goto out_src;
    }
    snprintf(path, sizeof(path), "%s/sub/nested", src);
    if (write_file(path, "nested data\n") < 0) {
        report_fail("clone CoW", "write nested failed");
        goto out_src;
    }

    /* volume_root for the test: a fresh tmp dir. clonefile only needs
     * src and dst on the same volume; /tmp on macOS is APFS data.
     */
    char vol[] = "/tmp/elfuse-clone-vol-XXXXXX";
    if (!mkdtemp(vol)) {
        report_fail("clone CoW", "mkdtemp vol failed");
        goto out_src;
    }

    char *run = NULL;
    const char *err = NULL;
    int rc = oci_clone_rootfs(src, vol, &run, &err);
    if (rc < 0 && errno == ENOTSUP) {
        report_skip("clone CoW", "clonefile ENOTSUP on this volume");
        goto out_vol;
    }
    if (rc != 0 || !run) {
        report_fail("clone CoW", "rc=%d err=%s", rc, err ? err : "(nil)");
        goto out_vol;
    }

    /* Verify the clone has the same content. */
    snprintf(path, sizeof(path), "%s/hello", run);
    if (!file_has(path, "original\n")) {
        report_fail("clone CoW", "clone hello missing or wrong");
        goto out_run;
    }
    snprintf(path, sizeof(path), "%s/sub/nested", run);
    if (!file_has(path, "nested data\n")) {
        report_fail("clone CoW", "clone sub/nested wrong");
        goto out_run;
    }

    /* Mutate the clone; source must be untouched. */
    snprintf(path, sizeof(path), "%s/hello", run);
    if (write_file(path, "mutated\n") < 0) {
        report_fail("clone CoW", "mutate clone hello failed");
        goto out_run;
    }
    snprintf(path, sizeof(path), "%s/hello", src);
    if (!file_has(path, "original\n")) {
        report_fail("clone CoW", "source hello was mutated (CoW broken)");
        goto out_run;
    }
    report_pass("clone preserves CoW: clone-side write leaves source intact");

out_run:
    oci_clone_rootfs_remove(run, NULL);
    free(run);
out_vol: {
    char runs_dir[1024];
    snprintf(runs_dir, sizeof(runs_dir), "%s/runs", vol);
    rmdir(runs_dir);
    rmdir(vol);
}
out_src: {
    char p[1024];
    snprintf(p, sizeof(p), "%s/hello", src);
    unlink(p);
    snprintf(p, sizeof(p), "%s/sub/nested", src);
    unlink(p);
    snprintf(p, sizeof(p), "%s/sub", src);
    rmdir(p);
    rmdir(src);
}
}

static void test_clone_new_file_isolated(void)
{
    /* Positive direction: a brand-new file written inside the
     * clone must not surface in the immutable source. The existing
     * test_clone_cow covers mutate-in-place; this case isolates the
     * "touch /hello" wording from issue #31 acceptance 1 so a
     * future regression in clonefile or in the run-dir layout cannot
     * pass without one of the two checks failing.
     */
    char src[] = "/tmp/elfuse-clone-new-src-XXXXXX";
    if (!mkdtemp(src)) {
        report_fail("clone new-file isolation", "mkdtemp src failed: errno=%d",
                    errno);
        return;
    }
    char path[1024];
    snprintf(path, sizeof(path), "%s/preexisting", src);
    if (write_file(path, "kept\n") < 0) {
        report_fail("clone new-file isolation", "write preexisting failed");
        goto out_src;
    }

    char vol[] = "/tmp/elfuse-clone-new-vol-XXXXXX";
    if (!mkdtemp(vol)) {
        report_fail("clone new-file isolation", "mkdtemp vol failed");
        goto out_src;
    }

    char *run = NULL;
    const char *err = NULL;
    int rc = oci_clone_rootfs(src, vol, &run, &err);
    if (rc < 0 && errno == ENOTSUP) {
        report_skip("clone new-file isolation",
                    "clonefile ENOTSUP on this volume");
        goto out_vol;
    }
    if (rc != 0 || !run) {
        report_fail("clone new-file isolation", "rc=%d err=%s", rc,
                    err ? err : "(nil)");
        goto out_vol;
    }

    snprintf(path, sizeof(path), "%s/hello", run);
    if (write_file(path, "fresh\n") < 0) {
        report_fail("clone new-file isolation",
                    "write hello in clone failed: errno=%d", errno);
        goto out_run;
    }
    if (!file_has(path, "fresh\n")) {
        report_fail("clone new-file isolation", "clone hello readback wrong");
        goto out_run;
    }

    snprintf(path, sizeof(path), "%s/hello", src);
    struct stat st;
    if (stat(path, &st) == 0) {
        report_fail("clone new-file isolation",
                    "source dir now has hello (clone leaked)");
        goto out_run;
    }
    if (errno != ENOENT) {
        report_fail("clone new-file isolation",
                    "source hello stat unexpected errno=%d", errno);
        goto out_run;
    }
    report_pass("clone new-file does not leak into source");

out_run:
    snprintf(path, sizeof(path), "%s/hello", run);
    unlink(path);
    oci_clone_rootfs_remove(run, NULL);
    free(run);
out_vol: {
    char runs_dir[1024];
    snprintf(runs_dir, sizeof(runs_dir), "%s/runs", vol);
    rmdir(runs_dir);
    rmdir(vol);
}
out_src: {
    char p[1024];
    snprintf(p, sizeof(p), "%s/preexisting", src);
    unlink(p);
    rmdir(src);
}
}

static void test_clone_unlink_preserves_src(void)
{
    /* Negative direction: an unlink inside the clone must not
     * propagate to the source. Together with test_clone_cow's mutate
     * check and test_clone_new_file_isolated's create check this pins
     * the three operations a real guest "touch /hello && rm /etc/foo"
     * exercise hits during an oci run.
     */
    char src[] = "/tmp/elfuse-clone-unlink-src-XXXXXX";
    if (!mkdtemp(src)) {
        report_fail("clone unlink isolation", "mkdtemp src failed: errno=%d",
                    errno);
        return;
    }
    char path[1024];
    snprintf(path, sizeof(path), "%s/persist", src);
    if (write_file(path, "stays\n") < 0) {
        report_fail("clone unlink isolation", "write persist failed");
        goto out_src;
    }

    char vol[] = "/tmp/elfuse-clone-unlink-vol-XXXXXX";
    if (!mkdtemp(vol)) {
        report_fail("clone unlink isolation", "mkdtemp vol failed");
        goto out_src;
    }

    char *run = NULL;
    const char *err = NULL;
    int rc = oci_clone_rootfs(src, vol, &run, &err);
    if (rc < 0 && errno == ENOTSUP) {
        report_skip("clone unlink isolation",
                    "clonefile ENOTSUP on this volume");
        goto out_vol;
    }
    if (rc != 0 || !run) {
        report_fail("clone unlink isolation", "rc=%d err=%s", rc,
                    err ? err : "(nil)");
        goto out_vol;
    }

    snprintf(path, sizeof(path), "%s/persist", run);
    if (unlink(path) < 0) {
        report_fail("clone unlink isolation",
                    "unlink in clone failed: errno=%d", errno);
        goto out_run;
    }
    struct stat st;
    if (stat(path, &st) == 0) {
        report_fail("clone unlink isolation", "clone persist survived unlink");
        goto out_run;
    }

    snprintf(path, sizeof(path), "%s/persist", src);
    if (!file_has(path, "stays\n")) {
        report_fail("clone unlink isolation",
                    "source persist missing or wrong after clone unlink");
        goto out_run;
    }
    report_pass("clone unlink leaves source intact");

out_run:
    oci_clone_rootfs_remove(run, NULL);
    free(run);
out_vol: {
    char runs_dir[1024];
    snprintf(runs_dir, sizeof(runs_dir), "%s/runs", vol);
    rmdir(runs_dir);
    rmdir(vol);
}
out_src: {
    char p[1024];
    snprintf(p, sizeof(p), "%s/persist", src);
    unlink(p);
    rmdir(src);
}
}

static void test_remove_empty(void)
{
    /* Removing a non-existent path is a no-op (errno=ENOENT short-
     * circuit in oci_clone_rootfs_remove). The contract is the
     * cleaner returns 0 instead of surfacing an error so a CLI flow
     * can call remove unconditionally.
     */
    const char *err = NULL;
    int rc = oci_clone_rootfs_remove("/tmp/elfuse-no-such-clone", &err);
    if (rc != 0)
        report_fail("remove missing path", "rc=%d err=%s", rc,
                    err ? err : "(nil)");
    else
        report_pass("remove on missing path is a no-op");
}

static void test_gc_stub(void)
{
    const char *err = NULL;
    int rc = oci_clone_rootfs_gc("/tmp", 0, &err);
    if (rc != 0)
        report_fail("gc stub returns 0", "rc=%d err=%s", rc,
                    err ? err : "(nil)");
    else
        report_pass("gc stub returns 0 (a future change will sweep)");
}

int main(void)
{
    printf("oci_clone_rootfs\n");
    test_clone_cow();
    test_clone_new_file_isolated();
    test_clone_unlink_preserves_src();
    test_remove_empty();
    test_gc_stub();
    printf("\nResults: %d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
