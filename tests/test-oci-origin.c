/* OCI origin sidecar unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Native macOS test program. Exercises oci_origin_write against a
 * scratch directory and verifies the resulting .elfuse-origin.json by
 * parsing it back through cJSON: the field shape, the diff-id array
 * length, and that re-writing into the same directory overwrites the
 * file atomically (caller can read the new contents).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include "oci/origin-meta.h"

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
    __attribute__((format(printf, 2, 3)));
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

/* Create a fresh scratch directory under /tmp. Returns a heap path the
 * caller frees; aborts the test on failure.
 */
static char *make_scratch(const char *prefix)
{
    char tmpl[256];
    snprintf(tmpl, sizeof(tmpl), "/tmp/%s-XXXXXX", prefix);
    char *dup = strdup(tmpl);
    if (!dup) {
        fprintf(stderr, "scratch strdup OOM\n");
        exit(2);
    }
    if (!mkdtemp(dup)) {
        fprintf(stderr, "mkdtemp(%s): %s\n", dup, strerror(errno));
        free(dup);
        exit(2);
    }
    return dup;
}

static void rmrf(const char *path)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    (void) system(cmd);
}

/* Slurp <root>/.elfuse-origin.json into a heap buffer. Returns NULL on
 * error; caller frees on success.
 */
static char *slurp_origin(const char *root)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/.elfuse-origin.json", root);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return NULL;
    }
    char *buf = malloc((size_t) st.st_size + 1);
    if (!buf) {
        close(fd);
        return NULL;
    }
    ssize_t got = read(fd, buf, (size_t) st.st_size);
    close(fd);
    if (got != st.st_size) {
        free(buf);
        return NULL;
    }
    buf[got] = '\0';
    return buf;
}

static void test_single_diff_roundtrip(void)
{
    char *scratch = make_scratch("elfuse-origin");
    char *diff[] = {
        (char *) "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        NULL,
    };
    const char *err = NULL;
    if (oci_origin_write(
            scratch,
            "sha256:"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            diff, &err) < 0) {
        report_fail("single diff roundtrip: write", "err=%s",
                    err ? err : strerror(errno));
        rmrf(scratch);
        free(scratch);
        return;
    }
    char *body = slurp_origin(scratch);
    if (!body) {
        report_fail("single diff roundtrip: slurp", "%s", strerror(errno));
        rmrf(scratch);
        free(scratch);
        return;
    }
    cJSON *root = cJSON_Parse(body);
    free(body);
    if (!root) {
        report_fail("single diff roundtrip: parse", "cJSON_Parse failed");
        rmrf(scratch);
        free(scratch);
        return;
    }
    cJSON *md = cJSON_GetObjectItemCaseSensitive(root, "manifest_digest");
    cJSON *cd = cJSON_GetObjectItemCaseSensitive(root, "config_digest");
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "layer_diffids");
    if (!cJSON_IsString(md) || !cJSON_IsString(cd) || !cJSON_IsArray(arr)) {
        report_fail("single diff roundtrip: field types", "shape invalid");
        cJSON_Delete(root);
        rmrf(scratch);
        free(scratch);
        return;
    }
    if (strcmp(md->valuestring,
               "sha256:"
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
               "a") != 0) {
        report_fail("single diff roundtrip: manifest_digest", "got %s",
                    md->valuestring);
        cJSON_Delete(root);
        rmrf(scratch);
        free(scratch);
        return;
    }
    if (strcmp(cd->valuestring,
               "sha256:"
               "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
               "b") != 0) {
        report_fail("single diff roundtrip: config_digest", "got %s",
                    cd->valuestring);
        cJSON_Delete(root);
        rmrf(scratch);
        free(scratch);
        return;
    }
    if (cJSON_GetArraySize(arr) != 1) {
        report_fail("single diff roundtrip: diff array size", "size=%d",
                    cJSON_GetArraySize(arr));
        cJSON_Delete(root);
        rmrf(scratch);
        free(scratch);
        return;
    }
    cJSON *first = cJSON_GetArrayItem(arr, 0);
    if (!cJSON_IsString(first) || strcmp(first->valuestring,
                                         "sha256:"
                                         "1111111111111111111111111111111111111"
                                         "111111111111111111111111111") != 0) {
        report_fail("single diff roundtrip: diff[0]", "wrong");
        cJSON_Delete(root);
        rmrf(scratch);
        free(scratch);
        return;
    }
    cJSON_Delete(root);
    report_pass("single diff roundtrip");
    rmrf(scratch);
    free(scratch);
}

static void test_multi_diff_preserves_order(void)
{
    char *scratch = make_scratch("elfuse-origin");
    char *diff[] = {
        (char *) "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        (char *) "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        (char *) "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        NULL,
    };
    const char *err = NULL;
    if (oci_origin_write(
            scratch,
            "sha256:"
            "abababababababababababababababababababababababababababababababab",
            "sha256:"
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            diff, &err) < 0) {
        report_fail("multi diff order: write", "err=%s",
                    err ? err : strerror(errno));
        rmrf(scratch);
        free(scratch);
        return;
    }
    char *body = slurp_origin(scratch);
    cJSON *root = body ? cJSON_Parse(body) : NULL;
    free(body);
    if (!root) {
        report_fail("multi diff order: parse", "no JSON");
        rmrf(scratch);
        free(scratch);
        return;
    }
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "layer_diffids");
    if (!cJSON_IsArray(arr) || cJSON_GetArraySize(arr) != 3) {
        report_fail("multi diff order: size", "size=%d",
                    cJSON_GetArraySize(arr));
        cJSON_Delete(root);
        rmrf(scratch);
        free(scratch);
        return;
    }
    const char *want[3] = {
        "sha256:"
        "1111111111111111111111111111111111111111111111111111111111111111",
        "sha256:"
        "2222222222222222222222222222222222222222222222222222222222222222",
        "sha256:"
        "3333333333333333333333333333333333333333333333333333333333333333",
    };
    for (int i = 0; i < 3; i++) {
        cJSON *e = cJSON_GetArrayItem(arr, i);
        if (!cJSON_IsString(e) || strcmp(e->valuestring, want[i]) != 0) {
            report_fail("multi diff order: element", "i=%d got=%s", i,
                        e && cJSON_IsString(e) ? e->valuestring : "(?)");
            cJSON_Delete(root);
            rmrf(scratch);
            free(scratch);
            return;
        }
    }
    cJSON_Delete(root);
    report_pass("multi diff order preserved");
    rmrf(scratch);
    free(scratch);
}

static void test_empty_diff_serializes(void)
{
    char *scratch = make_scratch("elfuse-origin");
    char *empty[] = {NULL};
    const char *err = NULL;
    if (oci_origin_write(
            scratch,
            "sha256:"
            "0101010101010101010101010101010101010101010101010101010101010101",
            "sha256:"
            "0202020202020202020202020202020202020202020202020202020202020202",
            empty, &err) < 0) {
        report_fail("empty diff serialize", "err=%s",
                    err ? err : strerror(errno));
        rmrf(scratch);
        free(scratch);
        return;
    }
    char *body = slurp_origin(scratch);
    cJSON *root = body ? cJSON_Parse(body) : NULL;
    free(body);
    if (!root) {
        report_fail("empty diff serialize: parse", "no JSON");
        rmrf(scratch);
        free(scratch);
        return;
    }
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "layer_diffids");
    if (!cJSON_IsArray(arr) || cJSON_GetArraySize(arr) != 0) {
        report_fail("empty diff serialize", "array size=%d",
                    cJSON_GetArraySize(arr));
        cJSON_Delete(root);
        rmrf(scratch);
        free(scratch);
        return;
    }
    cJSON_Delete(root);
    report_pass("empty diff_ids serializes as []");
    rmrf(scratch);
    free(scratch);
}

static void test_rewrite_overwrites(void)
{
    char *scratch = make_scratch("elfuse-origin");
    char *first[] = {
        (char *) "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        NULL,
    };
    char *second[] = {
        (char *) "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        (char *) "sha256:6666666666666666666666666666666666666666666666666666666666666666",
        NULL,
    };
    const char *err = NULL;
    if (oci_origin_write(
            scratch,
            "sha256:"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            first, &err) < 0) {
        report_fail("rewrite overwrite: first write", "err=%s",
                    err ? err : strerror(errno));
        rmrf(scratch);
        free(scratch);
        return;
    }
    if (oci_origin_write(
            scratch,
            "sha256:"
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "sha256:"
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            second, &err) < 0) {
        report_fail("rewrite overwrite: second write", "err=%s",
                    err ? err : strerror(errno));
        rmrf(scratch);
        free(scratch);
        return;
    }
    char *body = slurp_origin(scratch);
    cJSON *root = body ? cJSON_Parse(body) : NULL;
    free(body);
    if (!root) {
        report_fail("rewrite overwrite: parse", "no JSON");
        rmrf(scratch);
        free(scratch);
        return;
    }
    cJSON *md = cJSON_GetObjectItemCaseSensitive(root, "manifest_digest");
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "layer_diffids");
    if (!cJSON_IsString(md) ||
        strcmp(md->valuestring,
               "sha256:"
               "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
               "e") != 0 ||
        !cJSON_IsArray(arr) || cJSON_GetArraySize(arr) != 2) {
        report_fail("rewrite overwrite: second-write fields", "stale state");
        cJSON_Delete(root);
        rmrf(scratch);
        free(scratch);
        return;
    }
    cJSON_Delete(root);

    /* The .tmp companion must be cleaned up by the atomic rename. A
     * lingering .tmp would mean the rename never happened or a future
     * partial write left state behind.
     */
    char tmp_path[1024];
    snprintf(tmp_path, sizeof(tmp_path), "%s/.elfuse-origin.json.tmp", scratch);
    struct stat st;
    if (lstat(tmp_path, &st) == 0) {
        report_fail("rewrite overwrite: tmp cleanup", ".tmp still exists");
        rmrf(scratch);
        free(scratch);
        return;
    }
    report_pass("rewrite overwrites previous origin file");
    rmrf(scratch);
    free(scratch);
}

static void test_null_guards(void)
{
    char *diff[] = {NULL};
    const char *err = NULL;
    errno = 0;
    if (oci_origin_write(NULL, "sha256:aa", "sha256:bb", diff, &err) != -1 ||
        errno != EINVAL) {
        report_fail("null guards: NULL root_dir", "errno=%d", errno);
        return;
    }
    err = NULL;
    errno = 0;
    if (oci_origin_write("/tmp", NULL, "sha256:bb", diff, &err) != -1 ||
        errno != EINVAL) {
        report_fail("null guards: NULL manifest_digest", "errno=%d", errno);
        return;
    }
    err = NULL;
    errno = 0;
    if (oci_origin_write("/tmp", "sha256:aa", NULL, diff, &err) != -1 ||
        errno != EINVAL) {
        report_fail("null guards: NULL config_digest", "errno=%d", errno);
        return;
    }
    err = NULL;
    errno = 0;
    if (oci_origin_write("", "sha256:aa", "sha256:bb", diff, &err) != -1 ||
        errno != EINVAL) {
        report_fail("null guards: empty root_dir", "errno=%d", errno);
        return;
    }
    report_pass("null / empty guards report EINVAL");
}

static void test_null_diff_array(void)
{
    /* A NULL diff_ids pointer is equivalent to an empty array; the
     * unpack call-site passes whatever rootfs.diff_ids resolved to, and
     * a conforming image-config always populates the field. The helper
     * should still accept NULL for robustness.
     */
    char *scratch = make_scratch("elfuse-origin");
    const char *err = NULL;
    if (oci_origin_write(
            scratch,
            "sha256:"
            "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "sha256:"
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            NULL, &err) < 0) {
        report_fail("null diff array", "err=%s", err ? err : strerror(errno));
        rmrf(scratch);
        free(scratch);
        return;
    }
    char *body = slurp_origin(scratch);
    cJSON *root = body ? cJSON_Parse(body) : NULL;
    free(body);
    if (!root) {
        report_fail("null diff array: parse", "no JSON");
        rmrf(scratch);
        free(scratch);
        return;
    }
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "layer_diffids");
    if (!cJSON_IsArray(arr) || cJSON_GetArraySize(arr) != 0) {
        report_fail("null diff array: shape", "size=%d",
                    cJSON_GetArraySize(arr));
        cJSON_Delete(root);
        rmrf(scratch);
        free(scratch);
        return;
    }
    cJSON_Delete(root);
    report_pass("NULL diff_ids treated as []");
    rmrf(scratch);
    free(scratch);
}

int main(void)
{
    printf("oci_origin sidecar\n");
    test_single_diff_roundtrip();
    test_multi_diff_preserves_order();
    test_empty_diff_serializes();
    test_rewrite_overwrites();
    test_null_guards();
    test_null_diff_array();
    printf("\nResults: %d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
