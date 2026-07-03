/* OCI layer applier unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Native macOS test program. Builds tar streams in memory, drives them
 * through oci_layer_apply into a freshly-mkdtemp'd root, and verifies
 * filesystem state via lstat / readlink. The fixtures cover the full
 * asymmetric subset the applier accepts: regular files, directories, symlinks
 * (legal + escape), hardlinks (legal + missing target), whiteouts,
 * opaque whiteouts, the unsupported-type rejection path, and the
 * `..` traversal rejection.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oci/layer-apply.h"
#include "oci/layer-meta.h"
#include "oci/tar.h"

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

/* --- tar payload builder (shared shape with test-oci-tar.c) -------- */

#define BLOCK 512

typedef struct {
    uint8_t *buf;
    size_t len;
    size_t cap;
} bb_t;

static void bb_init(bb_t *b)
{
    b->buf = NULL;
    b->len = 0;
    b->cap = 0;
}
static void bb_free(bb_t *b)
{
    free(b->buf);
    b->buf = NULL;
    b->len = b->cap = 0;
}
static void bb_grow(bb_t *b, size_t want)
{
    if (b->cap >= want)
        return;
    size_t nc = b->cap == 0 ? 1024 : b->cap;
    while (nc < want)
        nc *= 2;
    b->buf = realloc(b->buf, nc);
    b->cap = nc;
}
static void bb_append(bb_t *b, const void *src, size_t n)
{
    bb_grow(b, b->len + n);
    memcpy(b->buf + b->len, src, n);
    b->len += n;
}
static void bb_zero(bb_t *b, size_t n)
{
    bb_grow(b, b->len + n);
    memset(b->buf + b->len, 0, n);
    b->len += n;
}

static void write_octal(uint8_t *field, size_t len, uint64_t value)
{
    memset(field, '0', len);
    field[len - 1] = '\0';
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%llo", (unsigned long long) value);
    size_t n = strlen(tmp);
    if (n >= len)
        n = len - 1;
    memcpy(field + (len - 1 - n), tmp, n);
}

static void compute_chksum(uint8_t *block)
{
    memset(block + 148, ' ', 8);
    uint32_t sum = 0;
    for (size_t i = 0; i < BLOCK; i++)
        sum += block[i];
    write_octal(block + 148, 7, sum);
    block[148 + 6] = '\0';
    block[148 + 7] = ' ';
}

static void append_entry(bb_t *b,
                         const char *name,
                         uint64_t size,
                         uint32_t mode,
                         char typeflag,
                         const char *linkname,
                         const void *payload)
{
    uint8_t block[BLOCK] = {0};
    size_t nl = strlen(name);
    if (nl > 100)
        nl = 100;
    memcpy(block, name, nl);
    write_octal(block + 100, 8, mode & 07777);
    write_octal(block + 108, 8, 0);
    write_octal(block + 116, 8, 0);
    write_octal(block + 124, 12, size);
    write_octal(block + 136, 12, 0);
    block[156] = (uint8_t) typeflag;
    if (linkname) {
        size_t ll = strlen(linkname);
        if (ll > 100)
            ll = 100;
        memcpy(block + 157, linkname, ll);
    }
    memcpy(block + 257, "ustar", 6);
    memcpy(block + 263, "00", 2);
    compute_chksum(block);
    bb_append(b, block, BLOCK);
    if (payload && size > 0) {
        bb_append(b, payload, (size_t) size);
        size_t pad = (BLOCK - (size % BLOCK)) % BLOCK;
        bb_zero(b, pad);
    }
}

/* --- byte source for the tar reader -------------------------------- */

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
} src_t;
static ssize_t src_read(void *ctx, void *buf, size_t cap)
{
    src_t *s = ctx;
    size_t left = s->len - s->pos;
    if (left == 0)
        return 0;
    size_t take = left < cap ? left : cap;
    memcpy(buf, s->buf + s->pos, take);
    s->pos += take;
    return (ssize_t) take;
}

/* --- helpers ------------------------------------------------------- */

static char *make_root(void)
{
    char *root = strdup("/tmp/elfuse-layer-XXXXXX");
    if (!mkdtemp(root)) {
        free(root);
        return NULL;
    }
    return root;
}

static int rm_rf(const char *path)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    return system(cmd);
}

static bool file_has_contents(const char *path, const char *want)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    char buf[256];
    size_t got = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[got] = '\0';
    return strcmp(buf, want) == 0;
}

/* --- test cases ---------------------------------------------------- */

static void test_basic_apply(void)
{
    char *root = make_root();
    if (!root) {
        report_fail("basic apply", "mkdtemp");
        return;
    }
    bb_t b;
    bb_init(&b);
    /* etc/ dir, etc/hostname file, lib/ dir, lib/foo symlink to ./bar,
     * etc/hostname2 hardlink to etc/hostname.
     */
    append_entry(&b, "etc", 0, 0755, '5', NULL, NULL);
    append_entry(&b, "etc/hostname", 14, 0644, '0', NULL, "hello, world!\n");
    append_entry(&b, "lib", 0, 0755, '5', NULL, NULL);
    append_entry(&b, "lib/foo", 0, 0777, '2', "./bar", NULL);
    append_entry(&b, "etc/hostname2", 0, 0644, '1', "etc/hostname", NULL);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    oci_layer_apply_stats_t st = {0};
    oci_meta_table_t *meta = oci_meta_table_new();
    const char *err = NULL;
    int rc = oci_layer_apply(r, root, &st, meta, &err);
    if (rc != 0) {
        report_fail("basic apply", "rc=%d err=%s", rc, err ? err : "(nil)");
        goto out;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/etc/hostname", root);
    if (!file_has_contents(path, "hello, world!\n")) {
        report_fail("basic apply", "etc/hostname contents wrong");
        goto out;
    }
    snprintf(path, sizeof(path), "%s/lib/foo", root);
    char tgt[64];
    ssize_t n = readlink(path, tgt, sizeof(tgt) - 1);
    if (n < 0) {
        report_fail("basic apply", "lib/foo readlink errno=%d", errno);
        goto out;
    }
    tgt[n] = '\0';
    if (strcmp(tgt, "./bar") != 0) {
        report_fail("basic apply", "lib/foo target=%s", tgt);
        goto out;
    }
    /* hardlink inode parity */
    struct stat a, h;
    snprintf(path, sizeof(path), "%s/etc/hostname", root);
    if (lstat(path, &a) < 0)
        goto out;
    snprintf(path, sizeof(path), "%s/etc/hostname2", root);
    if (lstat(path, &h) < 0)
        goto out;
    if (a.st_ino != h.st_ino) {
        report_fail("basic apply", "hardlink inode mismatch");
        goto out;
    }
    if (st.files != 1 || st.dirs != 2 || st.symlinks != 1 ||
        st.hardlinks != 1) {
        report_fail("basic apply", "stats wrong f=%zu d=%zu s=%zu h=%zu",
                    st.files, st.dirs, st.symlinks, st.hardlinks);
        goto out;
    }
    report_pass("basic apply (file/dir/symlink/hardlink)");
out:
    oci_tar_reader_free(r);
    oci_meta_table_free(meta);
    bb_free(&b);
    rm_rf(root);
    free(root);
}

static void test_symlink_escape_rejected(void)
{
    char *root = make_root();
    if (!root) {
        report_fail("symlink escape", "mkdtemp");
        return;
    }
    bb_t b;
    bb_init(&b);
    append_entry(&b, "escape", 0, 0777, '2', "../../../etc/passwd", NULL);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    const char *err = NULL;
    errno = 0;
    int rc = oci_layer_apply(r, root, NULL, NULL, &err);
    if (rc != -1 || errno != ELOOP)
        report_fail("symlink escape rejected", "rc=%d errno=%d err=%s", rc,
                    errno, err ? err : "(nil)");
    else
        report_pass("symlink escape rejected with ELOOP");
    oci_tar_reader_free(r);
    bb_free(&b);
    rm_rf(root);
    free(root);
}

static void test_symlink_parent_traversal_rejected(void)
{
    /* Two chained symlinks that each pass the lexical target check
     * compose into a parent redirect pointing outside the unpack root:
     * a/b -> ".." resolves to the root itself, so the symlink a/b/c is
     * physically created at <root>/c where its target "../etc" escapes.
     * The later regular entry a/b/c/x would then land in the escaped
     * directory. The per-component no-follow walk must refuse to
     * traverse the symlink at b instead.
     */
    char scratch[] = "/tmp/elfuse-layer-XXXXXX";
    if (!mkdtemp(scratch)) {
        report_fail("symlink parent traversal", "mkdtemp");
        return;
    }
    char root[512], outside[512];
    snprintf(root, sizeof(root), "%s/root", scratch);
    snprintf(outside, sizeof(outside), "%s/etc", scratch);
    if (mkdir(root, 0755) < 0 || mkdir(outside, 0755) < 0) {
        report_fail("symlink parent traversal", "mkdir scaffolding");
        rm_rf(scratch);
        return;
    }

    bb_t b;
    bb_init(&b);
    append_entry(&b, "a", 0, 0755, '5', NULL, NULL);
    append_entry(&b, "a/b", 0, 0777, '2', "..", NULL);
    append_entry(&b, "a/b/c", 0, 0777, '2', "../etc", NULL);
    append_entry(&b, "a/b/c/x", 6, 0644, '0', NULL, "pwned\n");
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    const char *err = NULL;
    errno = 0;
    int rc = oci_layer_apply(r, root, NULL, NULL, &err);
    char escaped[600];
    snprintf(escaped, sizeof(escaped), "%s/etc/x", scratch);
    struct stat st;
    if (rc != -1)
        report_fail("symlink parent traversal", "rc=%d err=%s", rc,
                    err ? err : "(nil)");
    else if (lstat(escaped, &st) == 0)
        report_fail("symlink parent traversal", "file escaped the root");
    else
        report_pass("symlink parent-component traversal rejected");
    oci_tar_reader_free(r);
    bb_free(&b);
    rm_rf(scratch);
}

static void test_hardlink_through_symlink_rejected(void)
{
    /* A symlink already on disk under the root (e.g. left by a lower
     * layer applied before containment hardened) must not let a
     * hardlink entry resolve its target through it and pull a host
     * file back into the guest tree for readback.
     */
    char scratch[] = "/tmp/elfuse-layer-XXXXXX";
    if (!mkdtemp(scratch)) {
        report_fail("hardlink through symlink", "mkdtemp");
        return;
    }
    char root[512], secret[512], sub[600];
    snprintf(root, sizeof(root), "%s/root", scratch);
    snprintf(secret, sizeof(secret), "%s/host-secret", scratch);
    if (mkdir(root, 0755) < 0) {
        report_fail("hardlink through symlink", "mkdir root");
        rm_rf(scratch);
        return;
    }
    FILE *f = fopen(secret, "w");
    if (!f) {
        report_fail("hardlink through symlink", "create host file");
        rm_rf(scratch);
        return;
    }
    fputs("top secret\n", f);
    fclose(f);
    snprintf(sub, sizeof(sub), "%s/a", root);
    if (mkdir(sub, 0755) < 0) {
        report_fail("hardlink through symlink", "mkdir a");
        rm_rf(scratch);
        return;
    }
    snprintf(sub, sizeof(sub), "%s/a/b", root);
    if (symlink("../..", sub) < 0) {
        report_fail("hardlink through symlink", "plant symlink");
        rm_rf(scratch);
        return;
    }

    bb_t b;
    bb_init(&b);
    append_entry(&b, "stolen", 0, 0644, '1', "a/b/host-secret", NULL);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    const char *err = NULL;
    errno = 0;
    int rc = oci_layer_apply(r, root, NULL, NULL, &err);
    char stolen[600];
    snprintf(stolen, sizeof(stolen), "%s/stolen", root);
    struct stat st;
    if (rc != -1)
        report_fail("hardlink through symlink", "rc=%d err=%s", rc,
                    err ? err : "(nil)");
    else if (lstat(stolen, &st) == 0)
        report_fail("hardlink through symlink", "host file was linked in");
    else
        report_pass("hardlink target through symlink rejected");
    oci_tar_reader_free(r);
    bb_free(&b);
    rm_rf(scratch);
}

static void test_symlink_abs_target_rewritten(void)
{
    char *root = make_root();
    if (!root) {
        report_fail("abs symlink rewrite", "mkdtemp");
        return;
    }
    bb_t b;
    bb_init(&b);
    /* Alpine-style applet links: /bin/sh -> /bin/busybox (same dir) and
     * /usr/bin/env -> /bin/busybox (needs ../.. climb). Both absolute in
     * the tar; both must land relative on disk so host-side resolution
     * stays inside the unpacked tree.
     */
    append_entry(&b, "bin", 0, 0755, '5', NULL, NULL);
    append_entry(&b, "bin/busybox", 5, 0755, '0', NULL, "fake\n");
    append_entry(&b, "bin/sh", 0, 0777, '2', "/bin/busybox", NULL);
    append_entry(&b, "usr", 0, 0755, '5', NULL, NULL);
    append_entry(&b, "usr/bin", 0, 0755, '5', NULL, NULL);
    append_entry(&b, "usr/bin/env", 0, 0777, '2', "/bin/busybox", NULL);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    oci_layer_apply_stats_t st = {0};
    const char *err = NULL;
    int rc = oci_layer_apply(r, root, &st, NULL, &err);
    if (rc != 0) {
        report_fail("abs symlink rewrite", "rc=%d err=%s", rc,
                    err ? err : "(nil)");
        goto out;
    }
    char path[512];
    char tgt[128];
    ssize_t n;
    snprintf(path, sizeof(path), "%s/bin/sh", root);
    n = readlink(path, tgt, sizeof(tgt) - 1);
    if (n < 0) {
        report_fail("abs symlink rewrite", "bin/sh readlink errno=%d", errno);
        goto out;
    }
    tgt[n] = '\0';
    if (strcmp(tgt, "busybox") != 0) {
        report_fail("abs symlink rewrite", "bin/sh target=%s (want busybox)",
                    tgt);
        goto out;
    }
    snprintf(path, sizeof(path), "%s/usr/bin/env", root);
    n = readlink(path, tgt, sizeof(tgt) - 1);
    if (n < 0) {
        report_fail("abs symlink rewrite", "usr/bin/env readlink errno=%d",
                    errno);
        goto out;
    }
    tgt[n] = '\0';
    if (strcmp(tgt, "../../bin/busybox") != 0) {
        report_fail("abs symlink rewrite",
                    "usr/bin/env target=%s (want ../../bin/busybox)", tgt);
        goto out;
    }
    /* Both links must resolve to the payload from within the tree. */
    snprintf(path, sizeof(path), "%s/bin/sh", root);
    if (!file_has_contents(path, "fake\n")) {
        report_fail("abs symlink rewrite", "bin/sh does not resolve");
        goto out;
    }
    snprintf(path, sizeof(path), "%s/usr/bin/env", root);
    if (!file_has_contents(path, "fake\n")) {
        report_fail("abs symlink rewrite", "usr/bin/env does not resolve");
        goto out;
    }
    report_pass("absolute symlink targets rewritten relative");
out:
    oci_tar_reader_free(r);
    bb_free(&b);
    rm_rf(root);
    free(root);
}

static void test_hardlink_missing_target(void)
{
    char *root = make_root();
    if (!root) {
        report_fail("hardlink missing", "mkdtemp");
        return;
    }
    bb_t b;
    bb_init(&b);
    append_entry(&b, "alias", 0, 0644, '1', "no/such/path", NULL);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    const char *err = NULL;
    errno = 0;
    int rc = oci_layer_apply(r, root, NULL, NULL, &err);
    if (rc != -1 || errno != ENOLINK)
        report_fail("hardlink missing target", "rc=%d errno=%d err=%s", rc,
                    errno, err ? err : "(nil)");
    else
        report_pass("hardlink missing target rejected with ENOLINK");
    oci_tar_reader_free(r);
    bb_free(&b);
    rm_rf(root);
    free(root);
}

static void test_whiteout_removes_upper_entry(void)
{
    char *root = make_root();
    if (!root) {
        report_fail("whiteout", "mkdtemp");
        return;
    }
    bb_t b;
    bb_init(&b);
    /* Upper layer creates "removed", then whiteout deletes it. */
    append_entry(&b, "removed", 5, 0644, '0', NULL, "data\n");
    append_entry(&b, ".wh.removed", 0, 0644, '0', NULL, NULL);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    oci_layer_apply_stats_t st = {0};
    oci_meta_table_t *meta = oci_meta_table_new();
    const char *err = NULL;
    int rc = oci_layer_apply(r, root, &st, meta, &err);
    if (rc != 0) {
        report_fail("whiteout", "rc=%d err=%s", rc, err ? err : "(nil)");
        goto out;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/removed", root);
    struct stat sb;
    if (lstat(path, &sb) == 0) {
        report_fail("whiteout", "removed still present");
        goto out;
    }
    if (st.whiteouts != 1) {
        report_fail("whiteout", "stats whiteouts=%zu", st.whiteouts);
        goto out;
    }
    report_pass("whiteout removes upper entry");
out:
    oci_tar_reader_free(r);
    oci_meta_table_free(meta);
    bb_free(&b);
    rm_rf(root);
    free(root);
}

static void test_opaque_whiteout_clears_directory(void)
{
    char *root = make_root();
    if (!root) {
        report_fail("opaque", "mkdtemp");
        return;
    }
    bb_t b;
    bb_init(&b);
    /* Upper layer populates dir/, then opaque marker clears its
     * existing contents. After the marker, layer adds dir/kept.
     */
    append_entry(&b, "dir", 0, 0755, '5', NULL, NULL);
    append_entry(&b, "dir/old", 4, 0644, '0', NULL, "old\n");
    append_entry(&b, "dir/.wh..wh..opq", 0, 0644, '0', NULL, NULL);
    append_entry(&b, "dir/kept", 5, 0644, '0', NULL, "new!\n");
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    oci_layer_apply_stats_t st = {0};
    oci_meta_table_t *meta = oci_meta_table_new();
    const char *err = NULL;
    int rc = oci_layer_apply(r, root, &st, meta, &err);
    if (rc != 0) {
        report_fail("opaque", "rc=%d err=%s", rc, err ? err : "(nil)");
        goto out;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/dir/old", root);
    struct stat sb;
    if (lstat(path, &sb) == 0) {
        report_fail("opaque", "dir/old still present after opaque");
        goto out;
    }
    snprintf(path, sizeof(path), "%s/dir/kept", root);
    if (!file_has_contents(path, "new!\n")) {
        report_fail("opaque", "dir/kept missing or wrong contents");
        goto out;
    }
    if (st.opaques != 1) {
        report_fail("opaque", "stats opaques=%zu", st.opaques);
        goto out;
    }
    report_pass("opaque whiteout clears dir + later entries kept");
out:
    oci_tar_reader_free(r);
    oci_meta_table_free(meta);
    bb_free(&b);
    rm_rf(root);
    free(root);
}

/* raw-tar mode preserves .wh.<name> markers on disk
 * instead of executing the upper-layer deletion. The marker lands as a
 * 0-byte regular file at its tar path; stats->whiteouts stays at zero
 * because the entry is counted as a regular file (which is what it is
 * on disk).
 */
static void test_raw_tar_preserves_whiteout_marker(void)
{
    char *root = make_root();
    if (!root) {
        report_fail("raw-tar whiteout", "mkdtemp");
        return;
    }
    bb_t b;
    bb_init(&b);
    /* The fixture matches the overlay whiteout test so the contrast is
     * direct: raw-tar mode keeps both files, overlay mode would delete
     * the second after writing the first.
     */
    append_entry(&b, "removed", 5, 0644, '0', NULL, "data\n");
    append_entry(&b, ".wh.removed", 0, 0644, '0', NULL, NULL);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    oci_layer_apply_stats_t st = {0};
    oci_meta_table_t *meta = oci_meta_table_new();
    const char *err = NULL;
    int rc = oci_layer_apply_raw_tar(r, root, &st, meta, &err);
    if (rc != 0) {
        report_fail("raw-tar whiteout", "rc=%d err=%s", rc,
                    err ? err : "(nil)");
        goto out;
    }
    char path[512];
    /* The whiteout marker must exist as a regular zero-length file. */
    snprintf(path, sizeof(path), "%s/.wh.removed", root);
    struct stat sb;
    if (lstat(path, &sb) < 0) {
        report_fail("raw-tar whiteout", ".wh.removed missing errno=%d", errno);
        goto out;
    }
    if (!S_ISREG(sb.st_mode) || sb.st_size != 0) {
        report_fail("raw-tar whiteout", ".wh.removed not 0-byte regular");
        goto out;
    }
    /* The target file the marker would have deleted in overlay mode
     * stays untouched because the marker did not execute.
     */
    snprintf(path, sizeof(path), "%s/removed", root);
    if (!file_has_contents(path, "data\n")) {
        report_fail("raw-tar whiteout", "removed missing or wrong contents");
        goto out;
    }
    if (st.whiteouts != 0 || st.files != 2) {
        report_fail("raw-tar whiteout", "stats f=%zu w=%zu (want f=2 w=0)",
                    st.files, st.whiteouts);
        goto out;
    }
    /* The marker must also appear in the per-layer meta sidecar so the
     * assembler can carry uid/gid/mode through to work_dir. */
    if (oci_meta_lookup(meta, ".wh.removed", NULL, NULL, NULL) < 0) {
        report_fail("raw-tar whiteout", "meta entry for .wh.removed missing");
        goto out;
    }
    report_pass("raw-tar mode preserves whiteout marker as 0-byte file");
out:
    oci_tar_reader_free(r);
    oci_meta_table_free(meta);
    bb_free(&b);
    rm_rf(root);
    free(root);
}

/* raw-tar mode preserves .wh..wh..opq markers on disk
 * instead of clearing the marker's directory. Sibling entries in the
 * same directory survive because the opaque branch is bypassed.
 */
static void test_raw_tar_preserves_opaque_marker(void)
{
    char *root = make_root();
    if (!root) {
        report_fail("raw-tar opaque", "mkdtemp");
        return;
    }
    bb_t b;
    bb_init(&b);
    append_entry(&b, "dir", 0, 0755, '5', NULL, NULL);
    append_entry(&b, "dir/old", 4, 0644, '0', NULL, "old\n");
    append_entry(&b, "dir/.wh..wh..opq", 0, 0644, '0', NULL, NULL);
    append_entry(&b, "dir/kept", 5, 0644, '0', NULL, "new!\n");
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    oci_layer_apply_stats_t st = {0};
    oci_meta_table_t *meta = oci_meta_table_new();
    const char *err = NULL;
    int rc = oci_layer_apply_raw_tar(r, root, &st, meta, &err);
    if (rc != 0) {
        report_fail("raw-tar opaque", "rc=%d err=%s", rc, err ? err : "(nil)");
        goto out;
    }
    char path[512];
    /* dir/.wh..wh..opq must exist as a regular zero-length file. */
    snprintf(path, sizeof(path), "%s/dir/.wh..wh..opq", root);
    struct stat sb;
    if (lstat(path, &sb) < 0 || !S_ISREG(sb.st_mode) || sb.st_size != 0) {
        report_fail("raw-tar opaque", "opaque marker missing or wrong shape");
        goto out;
    }
    /* dir/old must NOT have been cleared by the opaque branch. */
    snprintf(path, sizeof(path), "%s/dir/old", root);
    if (!file_has_contents(path, "old\n")) {
        report_fail("raw-tar opaque", "dir/old cleared by opaque branch");
        goto out;
    }
    snprintf(path, sizeof(path), "%s/dir/kept", root);
    if (!file_has_contents(path, "new!\n")) {
        report_fail("raw-tar opaque", "dir/kept missing");
        goto out;
    }
    if (st.opaques != 0 || st.dirs != 1 || st.files != 3) {
        report_fail("raw-tar opaque",
                    "stats d=%zu f=%zu o=%zu (want d=1 f=3 o=0)", st.dirs,
                    st.files, st.opaques);
        goto out;
    }
    report_pass("raw-tar mode preserves opaque marker and siblings");
out:
    oci_tar_reader_free(r);
    oci_meta_table_free(meta);
    bb_free(&b);
    rm_rf(root);
    free(root);
}

/* a tar without any whiteout markers goes through raw-tar
 * mode identically to overlay mode. This is the cache-populate happy
 * path: most layers carry only content, and raw-tar's dispatch must
 * not regress them.
 */
static void test_raw_tar_regular_entries_match_overlay(void)
{
    char *root = make_root();
    if (!root) {
        report_fail("raw-tar regulars", "mkdtemp");
        return;
    }
    bb_t b;
    bb_init(&b);
    append_entry(&b, "etc", 0, 0755, '5', NULL, NULL);
    append_entry(&b, "etc/hostname", 14, 0644, '0', NULL, "hello, world!\n");
    append_entry(&b, "lib", 0, 0755, '5', NULL, NULL);
    append_entry(&b, "lib/foo", 0, 0777, '2', "./bar", NULL);
    append_entry(&b, "etc/hostname2", 0, 0644, '1', "etc/hostname", NULL);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    oci_layer_apply_stats_t st = {0};
    oci_meta_table_t *meta = oci_meta_table_new();
    const char *err = NULL;
    int rc = oci_layer_apply_raw_tar(r, root, &st, meta, &err);
    if (rc != 0) {
        report_fail("raw-tar regulars", "rc=%d err=%s", rc,
                    err ? err : "(nil)");
        goto out;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/etc/hostname", root);
    if (!file_has_contents(path, "hello, world!\n")) {
        report_fail("raw-tar regulars", "etc/hostname wrong");
        goto out;
    }
    snprintf(path, sizeof(path), "%s/lib/foo", root);
    char tgt[64];
    ssize_t n = readlink(path, tgt, sizeof(tgt) - 1);
    if (n < 0) {
        report_fail("raw-tar regulars", "lib/foo readlink errno=%d", errno);
        goto out;
    }
    tgt[n] = '\0';
    if (strcmp(tgt, "./bar") != 0) {
        report_fail("raw-tar regulars", "lib/foo target=%s", tgt);
        goto out;
    }
    struct stat a, h;
    snprintf(path, sizeof(path), "%s/etc/hostname", root);
    if (lstat(path, &a) < 0)
        goto out;
    snprintf(path, sizeof(path), "%s/etc/hostname2", root);
    if (lstat(path, &h) < 0)
        goto out;
    if (a.st_ino != h.st_ino) {
        report_fail("raw-tar regulars", "hardlink inode mismatch");
        goto out;
    }
    if (st.files != 1 || st.dirs != 2 || st.symlinks != 1 ||
        st.hardlinks != 1) {
        report_fail("raw-tar regulars", "stats f=%zu d=%zu s=%zu h=%zu",
                    st.files, st.dirs, st.symlinks, st.hardlinks);
        goto out;
    }
    report_pass("raw-tar mode passes regular entries through unchanged");
out:
    oci_tar_reader_free(r);
    oci_meta_table_free(meta);
    bb_free(&b);
    rm_rf(root);
    free(root);
}

static void test_unsupported_type_rejected(void)
{
    char *root = make_root();
    if (!root) {
        report_fail("unsupported", "mkdtemp");
        return;
    }
    bb_t b;
    bb_init(&b);
    /* typeflag '3' is char device; the applier must refuse. */
    append_entry(&b, "dev/foo", 0, 0644, '3', NULL, NULL);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    const char *err = NULL;
    errno = 0;
    int rc = oci_layer_apply(r, root, NULL, NULL, &err);
    if (rc != -1 || errno != ENOTSUP)
        report_fail("unsupported type rejected", "rc=%d errno=%d", rc, errno);
    else
        report_pass("unsupported type rejected with ENOTSUP");
    oci_tar_reader_free(r);
    bb_free(&b);
    rm_rf(root);
    free(root);
}

static void test_path_join_traversal(void)
{
    char buf[256];
    const char *err = NULL;
    errno = 0;
    int rc = oci_path_join_safe("/tmp/elfuse-root", "etc/../../escape", buf,
                                sizeof(buf), &err);
    if (rc != -1 || errno != EINVAL)
        report_fail("path join .. rejected", "rc=%d errno=%d", rc, errno);
    else
        report_pass("path join rejects .. segment with EINVAL");
}

static void test_path_join_absolute(void)
{
    char buf[256];
    const char *err = NULL;
    errno = 0;
    int rc = oci_path_join_safe("/tmp/elfuse-root", "/etc/foo", buf,
                                sizeof(buf), &err);
    if (rc != -1 || errno != EINVAL)
        report_fail("path join absolute rejected", "rc=%d errno=%d", rc, errno);
    else
        report_pass("path join rejects absolute guest path with EINVAL");
}

static void test_symlink_check_safe(void)
{
    /* Relative target inside the root: OK. */
    if (oci_symlink_target_check("lib", "../etc/hostname") != 0) {
        report_fail("symlink check safe", "rejected legal target");
        return;
    }
    /* Absolute target = root-relative: OK. */
    if (oci_symlink_target_check("etc", "/usr/bin/echo") != 0) {
        report_fail("symlink check safe", "rejected absolute-as-root target");
        return;
    }
    report_pass("symlink target check accepts legal targets");
}

int main(void)
{
    printf("oci_layer_apply\n");
    test_basic_apply();
    test_symlink_escape_rejected();
    test_symlink_parent_traversal_rejected();
    test_hardlink_through_symlink_rejected();
    test_symlink_abs_target_rewritten();
    test_hardlink_missing_target();
    test_whiteout_removes_upper_entry();
    test_opaque_whiteout_clears_directory();
    test_raw_tar_preserves_whiteout_marker();
    test_raw_tar_preserves_opaque_marker();
    test_raw_tar_regular_entries_match_overlay();
    test_unsupported_type_rejected();
    test_path_join_traversal();
    test_path_join_absolute();
    test_symlink_check_safe();
    printf("\nResults: %d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
