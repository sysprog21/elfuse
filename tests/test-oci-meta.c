/* OCI sidecar metadata unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Native macOS test program. Exercises record / lookup / remove plus
 * write + re-read round-trips through .elfuse-meta.json so the bit
 * widths of uid, gid, and the 12-bit Linux mode (rwx + setuid/setgid/
 * sticky) survive serialization.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "oci/layer-meta.h"

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

static void test_record_lookup(void)
{
    oci_meta_table_t *t = oci_meta_table_new();
    if (!t) {
        report_fail("record/lookup: table_new", "OOM");
        return;
    }
    if (oci_meta_record(t, "/etc/hostname", 0, 0, 0100644) < 0 ||
        oci_meta_record(t, "/usr/bin/sudo", 0, 0, 0104755) < 0 ||
        oci_meta_record(t, "/tmp", 1000, 1000, 0101777) < 0) {
        report_fail("record/lookup", "record returned -1");
        oci_meta_table_free(t);
        return;
    }
    if (oci_meta_count(t) != 3) {
        report_fail("record/lookup", "count=%zu", oci_meta_count(t));
        oci_meta_table_free(t);
        return;
    }
    uint64_t uid = 0;
    uint64_t gid = 0;
    uint32_t mode = 0;
    if (oci_meta_lookup(t, "/usr/bin/sudo", &uid, &gid, &mode) != 0 ||
        uid != 0 || gid != 0 || mode != 0104755) {
        report_fail("record/lookup: setuid mode", "uid=%llu gid=%llu mode=%o",
                    uid, gid, mode);
        oci_meta_table_free(t);
        return;
    }
    if (oci_meta_lookup(t, "/tmp", NULL, NULL, &mode) != 0 || mode != 0101777) {
        report_fail("record/lookup: sticky mode", "mode=%o", mode);
        oci_meta_table_free(t);
        return;
    }
    errno = 0;
    if (oci_meta_lookup(t, "/nope", NULL, NULL, NULL) != -1 ||
        errno != ENOENT) {
        report_fail("record/lookup: miss reports ENOENT", "errno=%d", errno);
        oci_meta_table_free(t);
        return;
    }
    report_pass("record / lookup / count / miss-ENOENT");
    oci_meta_table_free(t);
}

static void test_record_overwrite(void)
{
    oci_meta_table_t *t = oci_meta_table_new();
    oci_meta_record(t, "/usr/bin/foo", 100, 100, 0644);
    oci_meta_record(t, "/usr/bin/foo", 0, 0, 0755);
    uint64_t uid = 999;
    uint32_t mode = 0;
    oci_meta_lookup(t, "/usr/bin/foo", &uid, NULL, &mode);
    if (uid != 0 || mode != 0755 || oci_meta_count(t) != 1)
        report_fail("record overwrite", "uid=%llu mode=%o count=%zu", uid, mode,
                    oci_meta_count(t));
    else
        report_pass("record overwrite is idempotent");
    oci_meta_table_free(t);
}

static void test_remove(void)
{
    oci_meta_table_t *t = oci_meta_table_new();
    oci_meta_record(t, "/a", 0, 0, 0644);
    oci_meta_record(t, "/b", 0, 0, 0644);
    oci_meta_record(t, "/c", 0, 0, 0644);
    oci_meta_remove(t, "/b");
    if (oci_meta_count(t) != 2) {
        report_fail("remove: count after", "count=%zu", oci_meta_count(t));
        oci_meta_table_free(t);
        return;
    }
    errno = 0;
    if (oci_meta_lookup(t, "/b", NULL, NULL, NULL) != -1 || errno != ENOENT) {
        report_fail("remove: looked-up after removal", "errno=%d", errno);
        oci_meta_table_free(t);
        return;
    }
    if (oci_meta_lookup(t, "/a", NULL, NULL, NULL) != 0 ||
        oci_meta_lookup(t, "/c", NULL, NULL, NULL) != 0) {
        report_fail("remove: siblings still present", "");
        oci_meta_table_free(t);
        return;
    }
    oci_meta_remove(t, "/missing"); /* no-op must not crash */
    report_pass("remove + no-op on missing path");
    oci_meta_table_free(t);
}

static void test_roundtrip(void)
{
    char root[] = "/tmp/elfuse-meta-XXXXXX";
    if (!mkdtemp(root)) {
        report_fail("roundtrip: mkdtemp", "errno=%d", errno);
        return;
    }
    oci_meta_table_t *t = oci_meta_table_new();
    oci_meta_record(t, "/etc/passwd", 0, 0, 0100644);
    oci_meta_record(t, "/usr/bin/sudo", 0, 0, 0104755); /* setuid */
    oci_meta_record(t, "/var/run", 0, 0, 040755);
    oci_meta_record(t, "/tmp", 0, 0, 0101777); /* sticky */
    const char *err = NULL;
    if (oci_meta_write(t, root, &err) < 0) {
        report_fail("roundtrip: write", "%s", err ? err : "(null)");
        oci_meta_table_free(t);
        return;
    }
    oci_meta_table_free(t);

    oci_meta_table_t *back = NULL;
    if (oci_meta_read(root, &back, &err) < 0) {
        report_fail("roundtrip: read", "%s", err ? err : "(null)");
        return;
    }
    if (oci_meta_count(back) != 4) {
        report_fail("roundtrip: count", "%zu", oci_meta_count(back));
        oci_meta_table_free(back);
        return;
    }
    uint32_t mode = 0;
    oci_meta_lookup(back, "/usr/bin/sudo", NULL, NULL, &mode);
    if (mode != 0104755) {
        report_fail("roundtrip: setuid preserved", "mode=%o", mode);
        oci_meta_table_free(back);
        return;
    }
    oci_meta_lookup(back, "/tmp", NULL, NULL, &mode);
    if (mode != 0101777) {
        report_fail("roundtrip: sticky preserved", "mode=%o", mode);
        oci_meta_table_free(back);
        return;
    }
    report_pass("write + read roundtrip preserves setuid/sticky");
    oci_meta_table_free(back);

    /* Cleanup */
    char path[1024];
    snprintf(path, sizeof(path), "%s/.elfuse-meta.json", root);
    unlink(path);
    rmdir(root);
}

static void test_read_missing(void)
{
    char root[] = "/tmp/elfuse-meta-empty-XXXXXX";
    if (!mkdtemp(root)) {
        report_fail("read missing: mkdtemp", "errno=%d", errno);
        return;
    }
    oci_meta_table_t *back = NULL;
    const char *err = NULL;
    errno = 0;
    int rc = oci_meta_read(root, &back, &err);
    if (rc != -1 || errno != ENOENT)
        report_fail("read missing: ENOENT", "rc=%d errno=%d", rc, errno);
    else
        report_pass("read missing reports ENOENT");
    if (back)
        oci_meta_table_free(back);
    rmdir(root);
}

static void test_read_malformed(void)
{
    char root[] = "/tmp/elfuse-meta-bad-XXXXXX";
    if (!mkdtemp(root)) {
        report_fail("read malformed: mkdtemp", "errno=%d", errno);
        return;
    }
    char path[1024];
    snprintf(path, sizeof(path), "%s/.elfuse-meta.json", root);
    FILE *f = fopen(path, "w");
    if (!f) {
        report_fail("read malformed: fopen", "errno=%d", errno);
        rmdir(root);
        return;
    }
    fprintf(f, "{ not json");
    fclose(f);
    oci_meta_table_t *back = NULL;
    const char *err = NULL;
    errno = 0;
    int rc = oci_meta_read(root, &back, &err);
    if (rc != -1 || errno != EINVAL)
        report_fail("read malformed: EINVAL", "rc=%d errno=%d", rc, errno);
    else
        report_pass("read malformed JSON rejected with EINVAL");
    if (back)
        oci_meta_table_free(back);
    unlink(path);
    rmdir(root);
}

int main(void)
{
    printf("oci_meta sidecar\n");
    test_record_lookup();
    test_record_overwrite();
    test_remove();
    test_roundtrip();
    test_read_missing();
    test_read_malformed();
    printf("\nResults: %d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
