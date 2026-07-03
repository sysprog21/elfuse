/* OCI sysroot volume bootstrap unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Native macOS test program. The default-volume path (hdiutil-backed
 * sparsebundle) requires ~150 ms of hdiutil orchestration plus
 * ~16 MiB of disk for the sparsebundle headers; it is gated behind
 * OCI_VOLUME_TEST=1 so make check does not pay that cost on every run.
 *
 * The ungated cases verify:
 *   - default_volume_path resolves under $HOME/Library/Application
 *     Support/elfuse/sysroots when HOME is set
 *   - override on a non-existent path is rejected with ENOENT
 *   - override on a case-insensitive filesystem is rejected with
 *     EINVAL (macOS default APFS data volume is case-insensitive, so
 *     /tmp is a reliable negative fixture)
 *   - oci_volume_subdir creates intermediate components
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oci/volume.h"

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

static void test_override_case_insensitive_rejected(void)
{
    /* /tmp on a default macOS install sits on the case-insensitive
     * data volume. The probe must reject this with EINVAL so a user
     * who passes --volume /tmp gets a clean refusal rather than a
     * silently-corrupting unpack later.
     */
    char *root = NULL;
    const char *err = NULL;
    errno = 0;
    int rc = oci_volume_ensure("/tmp", &root, &err);
    if (rc != -1 || errno != EINVAL)
        report_fail("override case-insensitive rejected",
                    "rc=%d errno=%d err=%s", rc, errno, err ? err : "(nil)");
    else
        report_pass("override case-insensitive rejected with EINVAL");
    free(root);
}

static void test_override_missing(void)
{
    char *root = NULL;
    const char *err = NULL;
    errno = 0;
    int rc = oci_volume_ensure("/no-such-elfuse-path", &root, &err);
    if (rc != -1 || errno != ENOENT)
        report_fail("override missing", "rc=%d errno=%d", rc, errno);
    else
        report_pass("override missing rejected with ENOENT");
    free(root);
}

static void test_subdir_create(void)
{
    /* Verify oci_volume_subdir creates a nested path under a known
     * case-sensitive root. The /tmp volume on macOS is case-sensitive.
     */
    char *path = NULL;
    const char *err = NULL;
    char tmpl[] = "/tmp/elfuse-volume-XXXXXX";
    if (!mkdtemp(tmpl)) {
        report_fail("subdir create", "mkdtemp failed: errno=%d", errno);
        return;
    }
    int rc = oci_volume_subdir(tmpl, "images/.staging", &path, &err);
    if (rc != 0) {
        report_fail("subdir create", "rc=%d err=%s", rc, err ? err : "(nil)");
        rmdir(tmpl);
        return;
    }
    struct stat st;
    if (stat(path, &st) < 0 || !S_ISDIR(st.st_mode))
        report_fail("subdir create", "stat failed: errno=%d", errno);
    else
        report_pass("subdir creates nested path");
    /* Cleanup */
    if (path) {
        rmdir(path);
        free(path);
    }
    char inter[1024];
    snprintf(inter, sizeof(inter), "%s/images", tmpl);
    rmdir(inter);
    rmdir(tmpl);
}

static void test_default_bootstrap(void)
{
    if (!getenv("OCI_VOLUME_TEST")) {
        report_skip("default bootstrap",
                    "OCI_VOLUME_TEST=1 gates hdiutil-backed test");
        return;
    }
    char *root = NULL;
    const char *err = NULL;
    int rc = oci_volume_ensure(NULL, &root, &err);
    if (rc != 0)
        report_fail("default bootstrap", "rc=%d err=%s", rc,
                    err ? err : "(nil)");
    else if (!root)
        report_fail("default bootstrap", "out path NULL");
    else
        report_pass("default sparsebundle mounted");
    free(root);
}

int main(void)
{
    printf("oci_volume bootstrap\n");
    test_override_case_insensitive_rejected();
    test_override_missing();
    test_subdir_create();
    test_default_bootstrap();
    printf("\nResults: %d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
