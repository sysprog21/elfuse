/* OCI rebuild-cache unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives oci_rebuild_cache against scratch stores plus a fixture
 * <volume>/images/sha256-<hex>/ tree assembled via mkdir + sentinel content +
 * oci_origin_write. The helper is exercised through its public C surface;
 * the CLI shape is smoke-tested separately by tests/test-oci-compat.sh.
 *
 * Cases (9):
 *   1. empty volume - scanned=0, no error
 *   2. single tree, commit - stack entry written; origin sidecar stripped
 *   3. single tree, dry-run - stats report would-rebuild but disk untouched
 *   4. tree whose terminating ChainID is already cached - skipped_cached=1
 *   5. tree with no .elfuse-origin.json - skipped_no_origin=1
 *   6. tree with malformed origin JSON - skipped_bad_origin=1
 *   7. tree with empty diff_ids array - skipped_empty_diffids=1
 *   8. two trees, two rounds - first round rebuilt=2, second round
 *      skipped_cached=2 (idempotency)
 *   9. three-layer chain - oci_chainid_compute applied step by step matches
 *      the path the rebuilt entry lands at (off-by-one guard)
 */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "oci/digest.h"
#include "oci/origin-meta.h"
#include "oci/rebuild-cache.h"
#include "oci/store.h"

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

static void report_fail(const char *name, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void report_fail(const char *name, const char *fmt, ...)
{
    g_total++;
    printf("  " RED "FAIL" RESET " %s", name);
    if (fmt && *fmt) {
        printf(": ");
        va_list ap;
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }
    printf("\n");
}

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
    (void) nftw(root, remove_entry, 8, FTW_DEPTH | FTW_PHYS);
}

static char *make_scratch_root(void)
{
    char tmpl[] = "/tmp/elfuse-test-oci-rebuild-XXXXXX";
    if (!mkdtemp(tmpl))
        return NULL;
    return strdup(tmpl);
}

/* Synthetic diff_id producer: "sha256:0000...000<N>" with N a single hex
 * digit. id must be in [1, 15] so the trailing nibble fits a single hex
 * digit. The dedup walker and the ChainID hasher treat the input string as
 * opaque, so the test does not have to compute SHA-256 over a real tar
 * payload.
 */
static char *diff_id_n(int id)
{
    char *r = malloc(OCI_DIGEST_HEX_MAX + 16);
    if (!r)
        return NULL;
    snprintf(r, OCI_DIGEST_HEX_MAX + 16,
             "sha256:0000000000000000000000000000000000000000000000000000000"
             "00000000%x",
             id & 0xf);
    return r;
}

/* Build <volume_root>/images/sha256-<hex_tag>/ and seed it with one
 * sentinel file plus an origin sidecar. mkdir failures except EEXIST abort
 * the test fixture so the caller does not have to thread an error through
 * every helper site.
 */
static bool seed_unpacked_tree(const char *volume_root,
                               const char *hex_tag,
                               const char *manifest_digest,
                               const char *config_digest,
                               char *const *diff_ids,
                               const char *sentinel_relpath,
                               const char *sentinel_body)
{
    char images[1024];
    snprintf(images, sizeof(images), "%s/images", volume_root);
    if (mkdir(volume_root, 0755) < 0 && errno != EEXIST)
        return false;
    if (mkdir(images, 0755) < 0 && errno != EEXIST)
        return false;
    char tree[1024];
    snprintf(tree, sizeof(tree), "%s/sha256-%s", images, hex_tag);
    if (mkdir(tree, 0755) < 0 && errno != EEXIST)
        return false;
    if (sentinel_relpath) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", tree, sentinel_relpath);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0)
            return false;
        if (sentinel_body) {
            size_t len = strlen(sentinel_body);
            if (write(fd, sentinel_body, len) != (ssize_t) len) {
                close(fd);
                return false;
            }
        }
        close(fd);
    }
    return oci_origin_write(tree, manifest_digest, config_digest, diff_ids,
                            NULL) == 0;
}

/* Compute the terminating ChainID for diff_ids via the same primitive
 * rebuild-cache uses. NULL-terminated array. Returns a heap-allocated
 * canonical chain string (caller frees), or NULL on failure.
 */
static char *compute_terminal_chain_str(char *const *diff_ids)
{
    if (!diff_ids || !diff_ids[0])
        return NULL;
    char buf_a[OCI_DIGEST_HEX_MAX + 16];
    char buf_b[OCI_DIGEST_HEX_MAX + 16];
    char *cur = buf_a;
    char *nxt = buf_b;
    if (oci_chainid_compute(NULL, diff_ids[0], cur, sizeof(buf_a)) < 0)
        return NULL;
    for (size_t i = 1; diff_ids[i]; i++) {
        if (oci_chainid_compute(cur, diff_ids[i], nxt, sizeof(buf_b)) < 0)
            return NULL;
        char *tmp = cur;
        cur = nxt;
        nxt = tmp;
    }
    return strdup(cur);
}

static int path_exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0 ? 1 : 0;
}

/* Compose <store_root>/layers/stacks/sha256/<hex>/ for chain_id. */
static void stack_dir_for(const char *store_root,
                          const char *chain_id,
                          char *out,
                          size_t cap)
{
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(chain_id, &algo, hex)) {
        out[0] = '\0';
        return;
    }
    snprintf(out, cap, "%s/layers/stacks/%s/%s", store_root,
             oci_digest_algo_name(algo), hex);
}

/* Case 1: empty volume_root --------------------------------------- */

static void case_empty_volume(const char *scratch)
{
    const char *name = "rebuild-cache: empty volume reports scanned=0";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-empty-store", scratch);
    char volume[1024];
    snprintf(volume, sizeof(volume), "%s/case-empty-volume", scratch);
    mkdir(volume, 0755);

    oci_store_t *store = oci_store_open(root);
    oci_rebuild_cache_options_t opts = {.commit = true};
    const char *err = NULL;
    int rc = oci_rebuild_cache(store, volume, &opts, &err);
    if (rc != 0)
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
    else if (opts.trees_scanned != 0)
        report_fail(name, "scanned=%zu (want 0)", opts.trees_scanned);
    else if (opts.trees_rebuilt != 0)
        report_fail(name, "rebuilt=%zu (want 0)", opts.trees_rebuilt);
    else
        report_pass(name);

    oci_store_close(store);
}

/* Case 2: single tree, commit ------------------------------------- */

static void case_single_tree_commit(const char *scratch)
{
    const char *name = "rebuild-cache: single tree commit writes stack entry";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-single-store", scratch);
    char volume[1024];
    snprintf(volume, sizeof(volume), "%s/case-single-volume", scratch);

    char *d1 = diff_id_n(1);
    char *diffs[] = {d1, NULL};
    seed_unpacked_tree(
        volume,
        "aa11111111111111111111111111111111111111111111111111111111111111",
        "sha256:111111111111111111111111111111111111111111111111111111111"
        "1111111",
        "sha256:222222222222222222222222222222222222222222222222222222222"
        "2222222",
        diffs, "hello.txt", "world\n");

    oci_store_t *store = oci_store_open(root);
    oci_rebuild_cache_options_t opts = {.commit = true};
    int rc = oci_rebuild_cache(store, volume, &opts, NULL);

    char *expected_chain = compute_terminal_chain_str(diffs);
    char stack_dir[1024];
    stack_dir_for(root, expected_chain, stack_dir, sizeof(stack_dir));
    char hello_in_stack[1024];
    snprintf(hello_in_stack, sizeof(hello_in_stack), "%s/hello.txt", stack_dir);
    char origin_in_stack[1024];
    snprintf(origin_in_stack, sizeof(origin_in_stack), "%s/.elfuse-origin.json",
             stack_dir);

    if (rc != 0)
        report_fail(name, "rc=%d", rc);
    else if (opts.trees_scanned != 1)
        report_fail(name, "scanned=%zu (want 1)", opts.trees_scanned);
    else if (opts.trees_rebuilt != 1)
        report_fail(name, "rebuilt=%zu (want 1)", opts.trees_rebuilt);
    else if (opts.stack_entries_added != 1)
        report_fail(name, "entries_added=%zu (want 1)",
                    opts.stack_entries_added);
    else if (!path_exists(stack_dir))
        report_fail(name, "stack dir missing: %s", stack_dir);
    else if (!path_exists(hello_in_stack))
        report_fail(name, "sentinel file not copied into stack entry: %s",
                    hello_in_stack);
    else if (path_exists(origin_in_stack))
        report_fail(name, "origin sidecar leaked into stack entry: %s",
                    origin_in_stack);
    else
        report_pass(name);

    free(expected_chain);
    free(d1);
    oci_store_close(store);
}

/* Case 3: dry-run does not touch disk ----------------------------- */

static void case_dry_run_no_disk(const char *scratch)
{
    const char *name = "rebuild-cache: dry-run reports without writing";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-dry-store", scratch);
    char volume[1024];
    snprintf(volume, sizeof(volume), "%s/case-dry-volume", scratch);

    char *d1 = diff_id_n(3);
    char *diffs[] = {d1, NULL};
    seed_unpacked_tree(
        volume,
        "bb22222222222222222222222222222222222222222222222222222222222222",
        "sha256:333333333333333333333333333333333333333333333333333333333"
        "3333333",
        "sha256:444444444444444444444444444444444444444444444444444444444"
        "4444444",
        diffs, NULL, NULL);

    oci_store_t *store = oci_store_open(root);
    oci_rebuild_cache_options_t opts = {.commit = false};
    int rc = oci_rebuild_cache(store, volume, &opts, NULL);

    char *expected_chain = compute_terminal_chain_str(diffs);
    char stack_dir[1024];
    stack_dir_for(root, expected_chain, stack_dir, sizeof(stack_dir));

    if (rc != 0)
        report_fail(name, "rc=%d", rc);
    else if (opts.trees_rebuilt != 1)
        report_fail(name, "rebuilt=%zu (want 1)", opts.trees_rebuilt);
    else if (opts.stack_entries_added != 1)
        report_fail(name, "entries_added=%zu (want 1)",
                    opts.stack_entries_added);
    else if (path_exists(stack_dir))
        report_fail(name, "stack dir created by dry-run: %s", stack_dir);
    else
        report_pass(name);

    free(expected_chain);
    free(d1);
    oci_store_close(store);
}

/* Case 4: tree whose chain is already cached --------------------- */

static void case_already_cached(const char *scratch)
{
    const char *name = "rebuild-cache: already-cached tree is skipped";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-cached-store", scratch);
    char volume[1024];
    snprintf(volume, sizeof(volume), "%s/case-cached-volume", scratch);

    char *d1 = diff_id_n(5);
    char *diffs[] = {d1, NULL};
    seed_unpacked_tree(
        volume,
        "cc33333333333333333333333333333333333333333333333333333333333333",
        "sha256:555555555555555555555555555555555555555555555555555555555"
        "5555555",
        "sha256:666666666666666666666666666666666666666666666666666666666"
        "6666666",
        diffs, NULL, NULL);

    oci_store_t *store = oci_store_open(root);

    /* Pre-seed the stack cache entry so rebuild's stack_has probe fires. */
    char *expected_chain = compute_terminal_chain_str(diffs);
    char stack_dir[1024];
    stack_dir_for(root, expected_chain, stack_dir, sizeof(stack_dir));
    mkdir(stack_dir, 0755);

    oci_rebuild_cache_options_t opts = {.commit = true};
    int rc = oci_rebuild_cache(store, volume, &opts, NULL);

    if (rc != 0)
        report_fail(name, "rc=%d", rc);
    else if (opts.trees_scanned != 1)
        report_fail(name, "scanned=%zu (want 1)", opts.trees_scanned);
    else if (opts.trees_skipped_cached != 1)
        report_fail(name, "skipped_cached=%zu (want 1)",
                    opts.trees_skipped_cached);
    else if (opts.trees_rebuilt != 0)
        report_fail(name, "rebuilt=%zu (want 0)", opts.trees_rebuilt);
    else
        report_pass(name);

    free(expected_chain);
    free(d1);
    oci_store_close(store);
}

/* Case 5: tree without origin sidecar ---------------------------- */

static void case_missing_origin(const char *scratch)
{
    const char *name = "rebuild-cache: tree without origin sidecar is skipped";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-noorigin-store", scratch);
    char volume[1024];
    snprintf(volume, sizeof(volume), "%s/case-noorigin-volume", scratch);

    char images[1024];
    snprintf(images, sizeof(images), "%s/images", volume);
    mkdir(volume, 0755);
    mkdir(images, 0755);
    char tree[1024];
    snprintf(tree, sizeof(tree),
             "%s/"
             "sha256-dd44444444444444444444444444444444444444444444444444444444"
             "444444",
             images);
    mkdir(tree, 0755);

    oci_store_t *store = oci_store_open(root);
    oci_rebuild_cache_options_t opts = {.commit = true};
    int rc = oci_rebuild_cache(store, volume, &opts, NULL);

    if (rc != 0)
        report_fail(name, "rc=%d", rc);
    else if (opts.trees_skipped_no_origin != 1)
        report_fail(name, "skipped_no_origin=%zu (want 1)",
                    opts.trees_skipped_no_origin);
    else if (opts.trees_rebuilt != 0)
        report_fail(name, "rebuilt=%zu (want 0)", opts.trees_rebuilt);
    else
        report_pass(name);

    oci_store_close(store);
}

/* Case 6: tree with malformed origin JSON ------------------------ */

static void case_malformed_origin(const char *scratch)
{
    const char *name = "rebuild-cache: malformed origin sidecar is skipped";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-bad-store", scratch);
    char volume[1024];
    snprintf(volume, sizeof(volume), "%s/case-bad-volume", scratch);

    char images[1024];
    snprintf(images, sizeof(images), "%s/images", volume);
    mkdir(volume, 0755);
    mkdir(images, 0755);
    char tree[1024];
    snprintf(tree, sizeof(tree),
             "%s/"
             "sha256-ee55555555555555555555555555555555555555555555555555555555"
             "555555",
             images);
    mkdir(tree, 0755);
    char sidecar[1024];
    snprintf(sidecar, sizeof(sidecar), "%s/.elfuse-origin.json", tree);
    FILE *f = fopen(sidecar, "w");
    fputs("not-json", f);
    fclose(f);

    oci_store_t *store = oci_store_open(root);
    oci_rebuild_cache_options_t opts = {.commit = true};
    int rc = oci_rebuild_cache(store, volume, &opts, NULL);

    if (rc != 0)
        report_fail(name, "rc=%d", rc);
    else if (opts.trees_skipped_bad_origin != 1)
        report_fail(name, "skipped_bad_origin=%zu (want 1)",
                    opts.trees_skipped_bad_origin);
    else if (opts.trees_rebuilt != 0)
        report_fail(name, "rebuilt=%zu (want 0)", opts.trees_rebuilt);
    else
        report_pass(name);

    oci_store_close(store);
}

/* Case 7: tree with empty diff_ids array ------------------------- */

static void case_empty_diffids(const char *scratch)
{
    const char *name = "rebuild-cache: empty diff_ids array is skipped";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-empty-diff-store", scratch);
    char volume[1024];
    snprintf(volume, sizeof(volume), "%s/case-empty-diff-volume", scratch);

    char *empty_diffs[] = {NULL};
    seed_unpacked_tree(
        volume,
        "ff66666666666666666666666666666666666666666666666666666666666666",
        "sha256:777777777777777777777777777777777777777777777777777777777"
        "7777777",
        "sha256:888888888888888888888888888888888888888888888888888888888"
        "8888888",
        empty_diffs, NULL, NULL);

    oci_store_t *store = oci_store_open(root);
    oci_rebuild_cache_options_t opts = {.commit = true};
    int rc = oci_rebuild_cache(store, volume, &opts, NULL);

    if (rc != 0)
        report_fail(name, "rc=%d", rc);
    else if (opts.trees_skipped_empty_diffids != 1)
        report_fail(name, "skipped_empty_diffids=%zu (want 1)",
                    opts.trees_skipped_empty_diffids);
    else if (opts.trees_rebuilt != 0)
        report_fail(name, "rebuilt=%zu (want 0)", opts.trees_rebuilt);
    else
        report_pass(name);

    oci_store_close(store);
}

/* Case 8: two trees rebuilt then idempotent ---------------------- */

static void case_two_trees_idempotent(const char *scratch)
{
    const char *name = "rebuild-cache: second pass is idempotent";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-idem-store", scratch);
    char volume[1024];
    snprintf(volume, sizeof(volume), "%s/case-idem-volume", scratch);

    char *d1 = diff_id_n(9);
    char *d2 = diff_id_n(10);
    char *diffs_a[] = {d1, NULL};
    char *diffs_b[] = {d2, NULL};
    seed_unpacked_tree(
        volume,
        "1a77777777777777777777777777777777777777777777777777777777777777",
        "sha256:999999999999999999999999999999999999999999999999999999999"
        "9999999",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaa",
        diffs_a, NULL, NULL);
    seed_unpacked_tree(
        volume,
        "2b88888888888888888888888888888888888888888888888888888888888888",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbb",
        "sha256:ccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        "ccccccc",
        diffs_b, NULL, NULL);

    oci_store_t *store = oci_store_open(root);

    oci_rebuild_cache_options_t opts1 = {.commit = true};
    int rc1 = oci_rebuild_cache(store, volume, &opts1, NULL);

    oci_rebuild_cache_options_t opts2 = {.commit = true};
    int rc2 = oci_rebuild_cache(store, volume, &opts2, NULL);

    if (rc1 != 0 || rc2 != 0)
        report_fail(name, "rc1=%d rc2=%d", rc1, rc2);
    else if (opts1.trees_rebuilt != 2)
        report_fail(name, "round1 rebuilt=%zu (want 2)", opts1.trees_rebuilt);
    else if (opts1.stack_entries_added != 2)
        report_fail(name, "round1 entries_added=%zu (want 2)",
                    opts1.stack_entries_added);
    else if (opts2.trees_scanned != 2)
        report_fail(name, "round2 scanned=%zu (want 2)", opts2.trees_scanned);
    else if (opts2.trees_rebuilt != 0)
        report_fail(name, "round2 rebuilt=%zu (want 0)", opts2.trees_rebuilt);
    else if (opts2.trees_skipped_cached != 2)
        report_fail(name, "round2 skipped_cached=%zu (want 2)",
                    opts2.trees_skipped_cached);
    else
        report_pass(name);

    free(d1);
    free(d2);
    oci_store_close(store);
}

/* Case 9: three-layer chain ChainID matches the on-disk path ------ */

static void case_three_layer_chain_path(const char *scratch)
{
    const char *name =
        "rebuild-cache: three-layer ChainID matches stack entry path";
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-chain-store", scratch);
    char volume[1024];
    snprintf(volume, sizeof(volume), "%s/case-chain-volume", scratch);

    char *d1 = diff_id_n(1);
    char *d2 = diff_id_n(2);
    char *d3 = diff_id_n(3);
    char *diffs[] = {d1, d2, d3, NULL};
    seed_unpacked_tree(
        volume,
        "ab99999999999999999999999999999999999999999999999999999999999999",
        "sha256:ddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        "ddddddd",
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        "eeeeeee",
        diffs, NULL, NULL);

    oci_store_t *store = oci_store_open(root);
    oci_rebuild_cache_options_t opts = {.commit = true};
    int rc = oci_rebuild_cache(store, volume, &opts, NULL);

    /* Recompute the chain independently of rebuild-cache.c so a mismatch
     * surfaces if the per-step composition order ever drifts.
     */
    char step1[OCI_DIGEST_HEX_MAX + 16];
    char step2[OCI_DIGEST_HEX_MAX + 16];
    char step3[OCI_DIGEST_HEX_MAX + 16];
    int e1 = oci_chainid_compute(NULL, d1, step1, sizeof(step1));
    int e2 = oci_chainid_compute(step1, d2, step2, sizeof(step2));
    int e3 = oci_chainid_compute(step2, d3, step3, sizeof(step3));
    char stack_dir[1024];
    stack_dir_for(root, step3, stack_dir, sizeof(stack_dir));

    if (rc != 0 || e1 < 0 || e2 < 0 || e3 < 0)
        report_fail(name, "rc=%d chain rc=%d,%d,%d", rc, e1, e2, e3);
    else if (opts.trees_rebuilt != 1)
        report_fail(name, "rebuilt=%zu (want 1)", opts.trees_rebuilt);
    else if (!path_exists(stack_dir))
        report_fail(name, "expected stack dir not on disk: %s", stack_dir);
    else
        report_pass(name);

    free(d1);
    free(d2);
    free(d3);
    oci_store_close(store);
}

int main(void)
{
    char *scratch = make_scratch_root();
    if (!scratch) {
        fprintf(stderr, "scratch root mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }
    printf("OCI rebuild-cache unit tests (scratch=%s)\n", scratch);

    case_empty_volume(scratch);
    case_single_tree_commit(scratch);
    case_dry_run_no_disk(scratch);
    case_already_cached(scratch);
    case_missing_origin(scratch);
    case_malformed_origin(scratch);
    case_empty_diffids(scratch);
    case_two_trees_idempotent(scratch);
    case_three_layer_chain_path(scratch);

    wipe_dir(scratch);
    free(scratch);

    printf("\nResults: %d/%d passed\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
