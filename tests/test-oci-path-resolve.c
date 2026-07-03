/* OCI guest PATH resolver unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Builds a tiny fake sysroot under a tmpdir and drives oci_path_resolve
 * against it. Each case is responsible for setting up exactly the files
 * and symlinks it needs and for asserting on the returned host_path /
 * guest_path / errno / err text. The test is offline and does not spawn
 * any guest processes; the regular files are zero-byte but chmod'd to
 * mark them executable so probe_candidate's stat-based check fires.
 *
 * Tree layout used across cases (one shared scratch per main()):
 *
 *   <scratch>/
 *     bin/
 *       busybox       (regular, +x)
 *       ls -> busybox (relative symlink, internal)
 *       noexec        (regular, mode 0644)
 *     usr/bin/
 *       escape -> ../../../etc/passwd  (escape symlink)
 *     usr/local/bin/                  (empty -- exists for searched-dirs)
 *     home/app/
 *       local-tool    (regular, +x, used for relative argv0 case)
 *
 * Cases:
 *   1. PATH search finds /bin/busybox under PATH=/usr/local/bin:/bin
 *   2. PATH search follows /bin/ls symlink to busybox but keeps the
 *      symlink-as-found in host_path / guest_path
 *   3. PATH search miss reports ENOENT plus the colon-joined searched-dirs
 *      list (no escape entry leaks into the list)
 *   4. PATH search finds the noexec candidate, reports EACCES with the
 *      argv0 quoted, and the directory still appears in the searched list
 *   5. Escape symlink in /usr/bin/escape silently skipped; PATH search
 *      continues into /bin where the binary lives
 *   6. argv0 with absolute path bypasses PATH search and resolves direct
 *   7. argv0 with absolute path to noexec produces EACCES (no searched
 *      annotation in err)
 *   8. argv0 with absolute path that does not exist produces ENOENT
 *   9. argv0 with leading "./" anchors to cwd_guest
 *  10. Empty PATH with argv0 lacking '/' produces ENOENT with empty
 *      searched annotation
 */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oci/path-resolve.h"

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

/* On macOS /tmp is a symlink to /private/tmp; oci_path_resolve realpaths
 * sysroot_dir on entry so the host_path it returns uses the canonical
 * prefix. Returning the realpath here keeps the test's assert-equal
 * comparisons honest without having to teach each case about the
 * /private/tmp expansion.
 */
static char *make_scratch_root(void)
{
    char tmpl[] = "/tmp/elfuse-test-oci-path-resolve-XXXXXX";
    if (!mkdtemp(tmpl))
        return NULL;
    char *real = realpath(tmpl, NULL);
    if (real)
        return real;
    return strdup(tmpl);
}

static void make_dir(const char *root, const char *rel)
{
    char path[2048];
    snprintf(path, sizeof(path), "%s/%s", root, rel);
    /* Recursive mkdir so callers can hand over nested paths. */
    char *p = path + strlen(root) + 1;
    for (; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(path, 0755);
            *p = '/';
        }
    }
    mkdir(path, 0755);
}

static void make_file(const char *root, const char *rel, mode_t mode)
{
    char path[2048];
    snprintf(path, sizeof(path), "%s/%s", root, rel);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        close(fd);
        chmod(path, mode);
    }
}

static void make_symlink(const char *root,
                         const char *target,
                         const char *rel_linkname)
{
    char path[2048];
    snprintf(path, sizeof(path), "%s/%s", root, rel_linkname);
    unlink(path);
    symlink(target, path);
}

static void make_script(const char *root, const char *rel, const char *content)
{
    char path[2048];
    snprintf(path, sizeof(path), "%s/%s", root, rel);
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(content, f);
        fclose(f);
        chmod(path, 0755);
    }
}

/* Heap-allocated NULL-terminated guest argv, ownership shaped exactly like
 * what oci_run hands to oci_shebang_expand (array and elements malloc'd).
 */
static char **make_argv2(const char *a0, const char *a1)
{
    char **v = (char **) calloc(3, sizeof(char *));
    if (!v)
        return NULL;
    v[0] = strdup(a0);
    if (a1)
        v[1] = strdup(a1);
    return v;
}

static void free_argv(char **v)
{
    for (int i = 0; v && v[i]; i++)
        free(v[i]);
    free(v);
}

static void build_fake_sysroot(const char *root)
{
    make_dir(root, "bin");
    make_dir(root, "usr/bin");
    make_dir(root, "usr/local/bin");
    make_dir(root, "home/app");
    make_file(root, "bin/busybox", 0755);
    make_file(root, "bin/noexec", 0644);
    make_file(root, "home/app/local-tool", 0755);
    make_symlink(root, "busybox", "bin/ls");
    make_symlink(root, "../../../etc/passwd", "usr/bin/escape");
    make_script(root, "entry.sh", "#!/bin/busybox\necho hi\n");
    make_script(root, "entry-arg.sh", "#!/bin/busybox -x\n");
    make_script(root, "entry-chain.sh", "#!/entry.sh\n");
    make_script(root, "entry-loop.sh", "#!/entry-loop.sh\n");
    make_script(root, "entry-missing.sh", "#!/no/such/interp\n");
    make_script(root, "entry-escape.sh", "#!/usr/bin/escape\n");
}

static bool contains(const char *haystack, const char *needle)
{
    return haystack && needle && strstr(haystack, needle) != NULL;
}

/* Helper: assert host_path equals "<root>/<expected_rel>" and guest_path
 * equals "/<expected_rel>". Returns true on match, false on mismatch and
 * also reports failure via the caller's name.
 */
static bool assert_paths_eq(const char *name,
                            const char *root,
                            const char *host_path,
                            const char *guest_path,
                            const char *expected_rel)
{
    char expected_host[2048];
    char expected_guest[2048];
    snprintf(expected_host, sizeof(expected_host), "%s/%s", root, expected_rel);
    snprintf(expected_guest, sizeof(expected_guest), "/%s", expected_rel);
    if (!host_path || strcmp(host_path, expected_host) != 0) {
        report_fail(name, "host_path=%s want %s",
                    host_path ? host_path : "(null)", expected_host);
        return false;
    }
    if (!guest_path || strcmp(guest_path, expected_guest) != 0) {
        report_fail(name, "guest_path=%s want %s",
                    guest_path ? guest_path : "(null)", expected_guest);
        return false;
    }
    return true;
}

/* ── Case 1: PATH search finds /bin/busybox ───────────────────────── */

static void case_path_search_finds_regular(const char *root)
{
    const char *name = "path: PATH search resolves bare argv0 to /bin/busybox";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    int rc = oci_path_resolve(root, "busybox", "/usr/local/bin:/bin", "/",
                              &host, &guest, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(null)");
    } else if (assert_paths_eq(name, root, host, guest, "bin/busybox")) {
        report_pass(name);
    }
    free(host);
    free(guest);
}

/* ── Case 2: PATH search follows internal symlink ─────────────────── */

static void case_path_search_follows_internal_symlink(const char *root)
{
    const char *name =
        "path: PATH search via /bin/ls (symlink to busybox) keeps symlink"
        " in host_path";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    int rc = oci_path_resolve(root, "ls", "/bin", "/", &host, &guest, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(null)");
    } else if (assert_paths_eq(name, root, host, guest, "bin/ls")) {
        report_pass(name);
    }
    free(host);
    free(guest);
}

/* ── Case 3: PATH search miss with searched-dirs annotation ───────── */

static void case_path_search_miss(const char *root)
{
    const char *name =
        "path: PATH search miss reports ENOENT with searched-dirs list";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    errno = 0;
    int rc = oci_path_resolve(root, "missing-prog", "/usr/local/bin:/bin", "/",
                              &host, &guest, &err);
    if (rc != -1) {
        report_fail(name, "rc=%d (want -1)", rc);
    } else if (errno != ENOENT) {
        report_fail(name, "errno=%d (want ENOENT)", errno);
    } else if (host || guest) {
        report_fail(name, "host_path/guest_path leaked on failure");
    } else if (!err || !contains(err, "'missing-prog'") ||
               !contains(err, "searched: /usr/local/bin:/bin")) {
        report_fail(name, "err=%s", err ? err : "(null)");
    } else {
        report_pass(name);
    }
    free(host);
    free(guest);
}

/* ── Case 4: PATH search finds noexec, returns EACCES ─────────────── */

static void case_path_search_noexec(const char *root)
{
    const char *name =
        "path: PATH search finds /bin/noexec but returns EACCES with"
        " argv0 quoted";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    errno = 0;
    int rc = oci_path_resolve(root, "noexec", "/bin", "/", &host, &guest, &err);
    if (rc != -1) {
        report_fail(name, "rc=%d (want -1)", rc);
    } else if (errno != EACCES) {
        report_fail(name, "errno=%d (want EACCES)", errno);
    } else if (!err || !contains(err, "'noexec'") ||
               !contains(err, "not executable")) {
        report_fail(name, "err=%s", err ? err : "(null)");
    } else {
        report_pass(name);
    }
    free(host);
    free(guest);
}

/* ── Case 5: escape symlink is silently skipped ──────────────────── */

static void case_path_search_escape_skipped(const char *root)
{
    const char *name =
        "path: escape symlink /usr/bin/escape silently skipped, search"
        " continues into /bin";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    /* argv0=busybox; if the search were to honor /usr/bin/escape it would
     * either fail or find /etc/passwd. The correct outcome is a hit on
     * /bin/busybox via the second PATH entry.
     */
    int rc = oci_path_resolve(root, "busybox", "/usr/bin:/bin", "/", &host,
                              &guest, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(null)");
    } else if (assert_paths_eq(name, root, host, guest, "bin/busybox")) {
        report_pass(name);
    }
    free(host);
    free(guest);
}

/* Bonus: argv0=escape itself with PATH=/usr/bin must NOT resolve to
 * /etc/passwd. The escape is filtered out and the search reports a clean
 * miss. The miss diagnostic must still list /usr/bin as probed (it was
 * walked, just contributed no hit).
 */
static void case_path_search_escape_argv0(const char *root)
{
    const char *name =
        "path: argv0=escape resolves to nothing because the symlink is"
        " filtered";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    errno = 0;
    int rc =
        oci_path_resolve(root, "escape", "/usr/bin", "/", &host, &guest, &err);
    if (rc != -1) {
        report_fail(name, "rc=%d (want -1)", rc);
    } else if (errno != ENOENT) {
        report_fail(name, "errno=%d (want ENOENT)", errno);
    } else if (!err || !contains(err, "'escape'")) {
        report_fail(name, "err=%s", err ? err : "(null)");
    } else {
        report_pass(name);
    }
    free(host);
    free(guest);
}

/* ── Case 6: argv0 with absolute path bypasses PATH ──────────────── */

static void case_direct_absolute(const char *root)
{
    const char *name =
        "path: absolute argv0 '/bin/busybox' bypasses PATH and resolves"
        " directly";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    int rc =
        oci_path_resolve(root, "/bin/busybox", NULL, "/", &host, &guest, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(null)");
    } else if (assert_paths_eq(name, root, host, guest, "bin/busybox")) {
        report_pass(name);
    }
    free(host);
    free(guest);
}

/* ── Case 7: absolute argv0 to noexec produces EACCES, no searched ─ */

static void case_direct_absolute_noexec(const char *root)
{
    const char *name =
        "path: absolute argv0 '/bin/noexec' returns EACCES without"
        " searched-dirs suffix";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    errno = 0;
    int rc =
        oci_path_resolve(root, "/bin/noexec", NULL, "/", &host, &guest, &err);
    if (rc != -1) {
        report_fail(name, "rc=%d (want -1)", rc);
    } else if (errno != EACCES) {
        report_fail(name, "errno=%d (want EACCES)", errno);
    } else if (!err || !contains(err, "/bin/noexec") ||
               contains(err, "searched:")) {
        report_fail(name, "err=%s", err ? err : "(null)");
    } else {
        report_pass(name);
    }
    free(host);
    free(guest);
}

/* ── Case 8: absolute argv0 that doesn't exist ───────────────────── */

static void case_direct_absolute_missing(const char *root)
{
    const char *name =
        "path: absolute argv0 '/bin/none' produces ENOENT without PATH"
        " suffix";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    errno = 0;
    int rc =
        oci_path_resolve(root, "/bin/none", NULL, "/", &host, &guest, &err);
    if (rc != -1 || errno != ENOENT || !err || !contains(err, "/bin/none") ||
        contains(err, "searched:")) {
        report_fail(name, "rc=%d errno=%d err=%s", rc, errno,
                    err ? err : "(null)");
    } else {
        report_pass(name);
    }
    free(host);
    free(guest);
}

/* ── Case 9: relative argv0 (with '/') anchors to cwd_guest ──────── */

static void case_direct_relative_with_cwd(const char *root)
{
    const char *name =
        "path: relative argv0 './local-tool' anchors to cwd_guest";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    int rc = oci_path_resolve(root, "./local-tool", NULL, "/home/app", &host,
                              &guest, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(null)");
    } else if (!host || !contains(host, "/home/app/./local-tool")) {
        report_fail(name, "host_path=%s", host ? host : "(null)");
    } else if (!guest || !contains(guest, "/home/app/./local-tool")) {
        report_fail(name, "guest_path=%s", guest ? guest : "(null)");
    } else {
        report_pass(name);
    }
    free(host);
    free(guest);
}

/* ── Case 10: empty PATH with bare argv0 ─────────────────────────── */

static void case_empty_path(const char *root)
{
    const char *name =
        "path: bare argv0 with empty PATH yields ENOENT with empty"
        " searched annotation";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    errno = 0;
    int rc = oci_path_resolve(root, "busybox", NULL, "/", &host, &guest, &err);
    if (rc != -1 || errno != ENOENT || !err || !contains(err, "'busybox'") ||
        !contains(err, "PATH is empty")) {
        report_fail(name, "rc=%d errno=%d err=%s", rc, errno,
                    err ? err : "(null)");
    } else {
        report_pass(name);
    }
    free(host);
    free(guest);
}

static void case_shebang_expands_interpreter(const char *root)
{
    const char *name = "shebang: interpreter prepended, host swapped";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    if (oci_path_resolve(root, "/entry.sh", NULL, "/", &host, &guest, &err) !=
        0) {
        report_fail(name, "setup resolve failed: %s", err ? err : "(null)");
        return;
    }
    char **argv = make_argv2(guest, "arg1");
    int rc = oci_shebang_expand(root, "/", &host, &argv, &err);
    if (rc != 0 || !argv[0] || strcmp(argv[0], "/bin/busybox") != 0 ||
        !argv[1] || strcmp(argv[1], "/entry.sh") != 0 || !argv[2] ||
        strcmp(argv[2], "arg1") != 0 || argv[3] ||
        !contains(host, "/bin/busybox")) {
        report_fail(name, "rc=%d argv0=%s argv1=%s host=%s err=%s", rc,
                    argv && argv[0] ? argv[0] : "(null)",
                    argv && argv[1] ? argv[1] : "(null)",
                    host ? host : "(null)", err ? err : "(null)");
    } else {
        report_pass(name);
    }
    free_argv(argv);
    free(host);
    free(guest);
}

static void case_shebang_optional_argument(const char *root)
{
    const char *name = "shebang: optional interpreter argument kept";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    if (oci_path_resolve(root, "/entry-arg.sh", NULL, "/", &host, &guest,
                         &err) != 0) {
        report_fail(name, "setup resolve failed: %s", err ? err : "(null)");
        return;
    }
    char **argv = make_argv2(guest, NULL);
    int rc = oci_shebang_expand(root, "/", &host, &argv, &err);
    if (rc != 0 || !argv[0] || strcmp(argv[0], "/bin/busybox") != 0 ||
        !argv[1] || strcmp(argv[1], "-x") != 0 || !argv[2] ||
        strcmp(argv[2], "/entry-arg.sh") != 0 || argv[3]) {
        report_fail(name, "rc=%d argv=[%s,%s,%s] err=%s", rc,
                    argv && argv[0] ? argv[0] : "(null)",
                    argv && argv[1] ? argv[1] : "(null)",
                    argv && argv[2] ? argv[2] : "(null)", err ? err : "(null)");
    } else {
        report_pass(name);
    }
    free_argv(argv);
    free(host);
    free(guest);
}

static void case_shebang_not_a_script(const char *root)
{
    const char *name = "shebang: non-script left untouched";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    if (oci_path_resolve(root, "/bin/busybox", NULL, "/", &host, &guest,
                         &err) != 0) {
        report_fail(name, "setup resolve failed: %s", err ? err : "(null)");
        return;
    }
    char **argv = make_argv2(guest, NULL);
    char *host_before = host;
    int rc = oci_shebang_expand(root, "/", &host, &argv, &err);
    if (rc != 0 || host != host_before || !argv[0] ||
        strcmp(argv[0], "/bin/busybox") != 0 || argv[1]) {
        report_fail(name, "rc=%d host=%s argv0=%s", rc, host ? host : "(null)",
                    argv && argv[0] ? argv[0] : "(null)");
    } else {
        report_pass(name);
    }
    free_argv(argv);
    free(host);
    free(guest);
}

static void case_shebang_chain_recurses(const char *root)
{
    const char *name = "shebang: two-level chain resolves innermost first";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    if (oci_path_resolve(root, "/entry-chain.sh", NULL, "/", &host, &guest,
                         &err) != 0) {
        report_fail(name, "setup resolve failed: %s", err ? err : "(null)");
        return;
    }
    char **argv = make_argv2(guest, NULL);
    int rc = oci_shebang_expand(root, "/", &host, &argv, &err);
    if (rc != 0 || !argv[0] || strcmp(argv[0], "/bin/busybox") != 0 ||
        !argv[1] || strcmp(argv[1], "/entry.sh") != 0 || !argv[2] ||
        strcmp(argv[2], "/entry-chain.sh") != 0 || argv[3]) {
        report_fail(name, "rc=%d argv=[%s,%s,%s] err=%s", rc,
                    argv && argv[0] ? argv[0] : "(null)",
                    argv && argv[1] ? argv[1] : "(null)",
                    argv && argv[2] ? argv[2] : "(null)", err ? err : "(null)");
    } else {
        report_pass(name);
    }
    free_argv(argv);
    free(host);
    free(guest);
}

static void case_shebang_loop_hits_depth_cap(const char *root)
{
    const char *name = "shebang: self-referential chain fails with ELOOP";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    if (oci_path_resolve(root, "/entry-loop.sh", NULL, "/", &host, &guest,
                         &err) != 0) {
        report_fail(name, "setup resolve failed: %s", err ? err : "(null)");
        return;
    }
    char **argv = make_argv2(guest, NULL);
    errno = 0;
    int rc = oci_shebang_expand(root, "/", &host, &argv, &err);
    if (rc != -1 || errno != ELOOP || !err ||
        !contains(err, "shebang recursion")) {
        report_fail(name, "rc=%d errno=%d err=%s", rc, errno,
                    err ? err : "(null)");
    } else {
        report_pass(name);
    }
    free_argv(argv);
    free(host);
    free(guest);
}

static void case_shebang_missing_interpreter(const char *root)
{
    const char *name = "shebang: missing interpreter surfaces ENOENT";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    if (oci_path_resolve(root, "/entry-missing.sh", NULL, "/", &host, &guest,
                         &err) != 0) {
        report_fail(name, "setup resolve failed: %s", err ? err : "(null)");
        return;
    }
    char **argv = make_argv2(guest, NULL);
    errno = 0;
    int rc = oci_shebang_expand(root, "/", &host, &argv, &err);
    if (rc != -1 || errno != ENOENT) {
        report_fail(name, "rc=%d errno=%d err=%s", rc, errno,
                    err ? err : "(null)");
    } else {
        report_pass(name);
    }
    free_argv(argv);
    free(host);
    free(guest);
}

static void case_shebang_escape_interpreter_rejected(const char *root)
{
    const char *name = "shebang: interpreter escaping sysroot rejected";
    char *host = NULL, *guest = NULL;
    const char *err = NULL;
    if (oci_path_resolve(root, "/entry-escape.sh", NULL, "/", &host, &guest,
                         &err) != 0) {
        report_fail(name, "setup resolve failed: %s", err ? err : "(null)");
        return;
    }
    char **argv = make_argv2(guest, NULL);
    int rc = oci_shebang_expand(root, "/", &host, &argv, &err);
    if (rc != -1) {
        report_fail(name, "rc=%d (want -1) argv0=%s", rc,
                    argv && argv[0] ? argv[0] : "(null)");
    } else {
        report_pass(name);
    }
    free_argv(argv);
    free(host);
    free(guest);
}

int main(void)
{
    char *root = make_scratch_root();
    if (!root) {
        fprintf(stderr, "scratch mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }
    printf("OCI path-resolve unit tests (scratch=%s)\n", root);

    build_fake_sysroot(root);

    case_path_search_finds_regular(root);
    case_path_search_follows_internal_symlink(root);
    case_path_search_miss(root);
    case_path_search_noexec(root);
    case_path_search_escape_skipped(root);
    case_path_search_escape_argv0(root);
    case_direct_absolute(root);
    case_direct_absolute_noexec(root);
    case_direct_absolute_missing(root);
    case_direct_relative_with_cwd(root);
    case_empty_path(root);
    case_shebang_expands_interpreter(root);
    case_shebang_optional_argument(root);
    case_shebang_not_a_script(root);
    case_shebang_chain_recurses(root);
    case_shebang_loop_hits_depth_cap(root);
    case_shebang_missing_interpreter(root);
    case_shebang_escape_interpreter_rejected(root);

    wipe_dir(root);
    free(root);

    printf("\nResults: %d/%d passed\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
