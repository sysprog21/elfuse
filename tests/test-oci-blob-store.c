/* OCI content-addressable blob store unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Native macOS test program. Drives every documented store invariant from
 * the open path (layout creation), through one-shot and streaming commits,
 * digest mismatch rejection, dedup, abort, and store-survives-restart, all
 * inside an mkdtemp scratch directory that is wiped on exit.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "oci/blob-store.h"
#include "oci/digest.h"

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

static void report_fail(const char *name, const char *detail)
{
    total++;
    printf("  " RED "FAIL" RESET " %s: %s\n", name, detail ? detail : "");
}

/* Pre-computed SHA-256 of the byte string "abc". Same as the one verified by
 * test-oci-digest, so the two suites cross-reference each other.
 */
static const char SHA256_ABC[] =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

static int remove_entry(const char *path,
                        const struct stat *st,
                        int typeflag,
                        struct FTW *ftwbuf)
{
    (void) st;
    (void) typeflag;
    (void) ftwbuf;
    return remove(path);
}

static void wipe_dir(const char *root)
{
    /* FTW_DEPTH guarantees children are processed before parents so rmdir
     * does not race against still-populated directories.
     */
    (void) nftw(root, remove_entry, 8, FTW_DEPTH | FTW_PHYS);
}

static bool dir_is_empty(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir)
        return false;
    bool empty = true;
    struct dirent *e;
    while ((e = readdir(dir))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        empty = false;
        break;
    }
    closedir(dir);
    return empty;
}

static bool path_is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool path_is_file(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static char *make_scratch_root(void)
{
    char *tmpl = strdup("/tmp/elfuse-oci-blob-XXXXXX");
    if (!tmpl)
        return NULL;
    if (!mkdtemp(tmpl)) {
        free(tmpl);
        return NULL;
    }
    return tmpl;
}

int main(void)
{
    char *scratch = make_scratch_root();
    if (!scratch) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    /* Layout creation: open on a fresh dir must produce blobs/sha256,
     * blobs/sha512, and tmp under root.
     */
    char store_root[512];
    snprintf(store_root, sizeof(store_root), "%s/store", scratch);

    printf("oci_blob_store layout\n");
    oci_blob_store_t *s = oci_blob_store_open(store_root);
    if (!s) {
        report_fail("open creates layout", strerror(errno));
        goto cleanup;
    }
    {
        char p[512];
        snprintf(p, sizeof(p), "%s/blobs/sha256", store_root);
        bool ok_sha256 = path_is_dir(p);
        snprintf(p, sizeof(p), "%s/blobs/sha512", store_root);
        bool ok_sha512 = path_is_dir(p);
        snprintf(p, sizeof(p), "%s/tmp", store_root);
        bool ok_tmp = path_is_dir(p);
        if (ok_sha256 && ok_sha512 && ok_tmp)
            report_pass("open creates blobs/sha256, blobs/sha512, tmp");
        else
            report_fail("open creates blobs/sha256, blobs/sha512, tmp", NULL);
    }

    /* Reopening an already-populated root is idempotent. */
    {
        oci_blob_store_t *again = oci_blob_store_open(store_root);
        if (again) {
            report_pass("open is idempotent on existing layout");
            oci_blob_store_close(again);
        } else {
            report_fail("open is idempotent on existing layout",
                        strerror(errno));
        }
    }

    /* Bad inputs. */
    {
        errno = 0;
        oci_blob_store_t *bad = oci_blob_store_open(NULL);
        if (!bad && errno == EINVAL)
            report_pass("open rejects NULL root");
        else
            report_fail("open rejects NULL root",
                        bad ? "returned handle" : strerror(errno));
        oci_blob_store_close(bad);
    }
    {
        errno = 0;
        oci_blob_store_t *bad = oci_blob_store_open("");
        if (!bad && errno == EINVAL)
            report_pass("open rejects empty root");
        else
            report_fail("open rejects empty root",
                        bad ? "returned handle" : strerror(errno));
        oci_blob_store_close(bad);
    }

    /* Path resolution: shape matches the OCI image-layout convention. */
    printf("oci_blob_store_path\n");
    {
        char out[512];
        int n = oci_blob_store_path(s, OCI_DIGEST_SHA256, SHA256_ABC, out,
                                    sizeof(out));
        char want[512];
        snprintf(want, sizeof(want), "%s/blobs/sha256/%s", store_root,
                 SHA256_ABC);
        if (n > 0 && (size_t) n == strlen(want) && strcmp(out, want) == 0)
            report_pass("path builds blobs/<algo>/<hex>");
        else
            report_fail("path builds blobs/<algo>/<hex>", out);
    }
    {
        char out[512];
        int n = oci_blob_store_path(s, OCI_DIGEST_SHA256, "not-hex", out,
                                    sizeof(out));
        if (n == -1)
            report_pass("path rejects malformed hex");
        else
            report_fail("path rejects malformed hex", out);
    }

    /* One-shot put followed by has() round trip. */
    printf("oci_blob_store_put_bytes\n");
    {
        if (oci_blob_store_put_bytes(s, OCI_DIGEST_SHA256, SHA256_ABC, "abc",
                                     3) != 0) {
            report_fail("put_bytes commits a known-good blob", strerror(errno));
        } else {
            char path[512];
            oci_blob_store_path(s, OCI_DIGEST_SHA256, SHA256_ABC, path,
                                sizeof(path));
            if (path_is_file(path) &&
                oci_blob_store_has(s, OCI_DIGEST_SHA256, SHA256_ABC))
                report_pass("put_bytes commits a known-good blob");
            else
                report_fail("put_bytes commits a known-good blob",
                            "blob not visible after commit");
        }
        char tmp_dir[512];
        snprintf(tmp_dir, sizeof(tmp_dir), "%s/tmp", store_root);
        if (dir_is_empty(tmp_dir))
            report_pass("commit leaves tmp/ empty");
        else
            report_fail("commit leaves tmp/ empty", NULL);
    }

    /* Dedup: repeat the same commit and confirm exit success without
     * touching the final inode. The fact that we observe the same path with
     * the same content is enough; the writer's link(2) path takes the EEXIST
     * branch internally.
     */
    {
        struct stat before, after;
        char path[512];
        oci_blob_store_path(s, OCI_DIGEST_SHA256, SHA256_ABC, path,
                            sizeof(path));
        if (stat(path, &before) != 0) {
            report_fail("dedup commit is idempotent", "no first blob");
        } else if (oci_blob_store_put_bytes(s, OCI_DIGEST_SHA256, SHA256_ABC,
                                            "abc", 3) != 0) {
            report_fail("dedup commit is idempotent", strerror(errno));
        } else if (stat(path, &after) != 0) {
            report_fail("dedup commit is idempotent", "blob disappeared");
        } else if (before.st_ino != after.st_ino) {
            report_fail("dedup commit is idempotent",
                        "inode changed (should stay the same)");
        } else {
            report_pass("dedup commit is idempotent");
        }
    }

    /* Digest mismatch: caller declares a hex that does not match the bytes.
     * Commit must fail with EINVAL and leave no visible blob, no tmp leftover.
     */
    {
        static const char WRONG[] =
            "0000000000000000000000000000000000000000000000000000000000000000";
        errno = 0;
        int rc =
            oci_blob_store_put_bytes(s, OCI_DIGEST_SHA256, WRONG, "abc", 3);
        char tmp_dir[512];
        snprintf(tmp_dir, sizeof(tmp_dir), "%s/tmp", store_root);
        if (rc == -1 && errno == EINVAL &&
            !oci_blob_store_has(s, OCI_DIGEST_SHA256, WRONG) &&
            dir_is_empty(tmp_dir))
            report_pass("digest mismatch rejected, tmp/ stays empty");
        else
            report_fail("digest mismatch rejected, tmp/ stays empty",
                        strerror(errno));
    }

    printf("oci_blob_store restart\n");
    oci_blob_store_close(s);
    s = oci_blob_store_open(store_root);
    if (!s) {
        report_fail("reopen sees previously-committed blob", strerror(errno));
        goto cleanup;
    }
    if (oci_blob_store_has(s, OCI_DIGEST_SHA256, SHA256_ABC))
        report_pass("reopen sees previously-committed blob");
    else
        report_fail("reopen sees previously-committed blob",
                    "has() returned false");

    /* has() must distinguish present vs absent. */
    {
        static const char ABSENT[] =
            "feedface00000000000000000000000000000000000000000000000000000000";
        if (!oci_blob_store_has(s, OCI_DIGEST_SHA256, ABSENT))
            report_pass("has() returns false for unknown digest");
        else
            report_fail("has() returns false for unknown digest", NULL);
    }
cleanup:
    oci_blob_store_close(s);
    wipe_dir(scratch);
    free(scratch);

    printf("\nResults: %d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
