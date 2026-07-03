/* OCI per-run /etc host-truth injection
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * See runtime-files.h for the contract. Implementation walks the
 * three target leaves under <run_dir>/etc/ in turn, unlinking any
 * pre-existing inode first so a symlink left by the image (the
 * common case for /etc/resolv.conf) cannot dangle past the
 * injection.
 *
 * The nameserver list for resolv.conf is harvested by spawning
 * /usr/sbin/scutil --dns and line-walking its stdout for the
 * "  nameserver[N] : <ip>" pattern. The reader uses posix_spawnp
 * with a pipe, mirroring src/core/sysroot.c's spawn_capture_stdout
 * helper; duplicating the ~40 lines here keeps the oci module's
 * lifetime story self-contained instead of hoisting a host-only
 * helper into a public header.
 */

#include "runtime-files.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/* Loop-write the full payload; EINTR retries and short writes are
 * folded back into another write call. Returns 0 on success, -1 with
 * errno preserved on the failing call.
 */
static int write_full(int fd, const char *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t) w;
    }
    return 0;
}

/* mkdir <run_dir>/etc 0755; tolerate EEXIST iff it is a directory. */
static int ensure_etc_dir(const char *run_dir, const char **err)
{
    char etc_path[4096];
    int n = snprintf(etc_path, sizeof(etc_path), "%s/etc", run_dir);
    if (n < 0 || (size_t) n >= sizeof(etc_path)) {
        oci_err_static(err, "runtime-files: <run_dir>/etc path overflow");
        errno = ENAMETOOLONG;
        return -1;
    }
    if (mkdir(etc_path, 0755) == 0)
        return 0;
    if (errno != EEXIST) {
        int saved = errno;
        oci_err_fmt(err, "runtime-files: mkdir %s failed: %s", etc_path,
                    strerror(saved));
        errno = saved;
        return -1;
    }
    struct stat st;
    if (lstat(etc_path, &st) < 0) {
        int saved = errno;
        oci_err_fmt(err, "runtime-files: lstat %s failed: %s", etc_path,
                    strerror(saved));
        errno = saved;
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        oci_err_fmt(err, "runtime-files: %s exists but is not a directory",
                    etc_path);
        errno = ENOTDIR;
        return -1;
    }
    return 0;
}

/* Build <run_dir>/etc/<leaf>, remove any pre-existing inode (file or
 * symlink) at that path, then open a fresh file for write. Returns
 * the new fd on success, -1 with *err set and errno preserved on
 * failure.
 */
static int open_etc_overwrite(const char *run_dir,
                              const char *leaf,
                              const char **err)
{
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/etc/%s", run_dir, leaf);
    if (n < 0 || (size_t) n >= sizeof(path)) {
        oci_err_fmt(err, "runtime-files: path for /etc/%s too long", leaf);
        errno = ENAMETOOLONG;
        return -1;
    }
    if (unlink(path) < 0 && errno != ENOENT) {
        int saved = errno;
        oci_err_fmt(err, "runtime-files: unlink %s failed: %s", path,
                    strerror(saved));
        errno = saved;
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        int saved = errno;
        oci_err_fmt(err, "runtime-files: open %s failed: %s", path,
                    strerror(saved));
        errno = saved;
        return -1;
    }
    return fd;
}

/* Append a nameserver string to the dedup list. Returns 0 on success,
 * -1 with errno=ENOMEM on allocation failure. Duplicates are
 * silently dropped so resolver #1's primary appears once even when
 * scutil prints "nameserver[0]" twice for IPv4 + IPv6 of the same
 * interface.
 */
static int push_nameserver(char ***list,
                           size_t *n,
                           size_t *cap,
                           const char *ip,
                           size_t iplen)
{
    for (size_t i = 0; i < *n; i++) {
        size_t e = strlen((*list)[i]);
        if (e == iplen && memcmp((*list)[i], ip, iplen) == 0)
            return 0;
    }
    if (*n + 1 > *cap) {
        size_t newcap = *cap ? *cap * 2 : 4;
        char **np = realloc(*list, newcap * sizeof(*np));
        if (!np) {
            errno = ENOMEM;
            return -1;
        }
        *list = np;
        *cap = newcap;
    }
    char *dup = malloc(iplen + 1);
    if (!dup) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(dup, ip, iplen);
    dup[iplen] = '\0';
    (*list)[(*n)++] = dup;
    return 0;
}

/* Parse one line of scutil --dns output. The relevant shape is:
 *
 *     "  nameserver[0] : 192.168.1.1"
 *     "  nameserver[1] : 2001:db8::1"
 *
 * Anything else is ignored. The IP literal is the trailing token
 * after the colon, with surrounding whitespace stripped. Validation
 * is intentionally loose: scutil is the source of truth, so any
 * non-empty token after "nameserver[N] :" is taken at face value.
 */
static void parse_scutil_line(const char *line,
                              size_t len,
                              char ***list,
                              size_t *n,
                              size_t *cap)
{
    const char *p = line;
    const char *end = line + len;
    while (p < end && isspace((unsigned char) *p))
        p++;
    static const char prefix[] = "nameserver[";
    size_t plen = sizeof(prefix) - 1;
    if ((size_t) (end - p) < plen)
        return;
    if (memcmp(p, prefix, plen) != 0)
        return;
    p += plen;
    while (p < end && *p != ']')
        p++;
    if (p >= end || *p != ']')
        return;
    p++;
    while (p < end && isspace((unsigned char) *p))
        p++;
    if (p >= end || *p != ':')
        return;
    p++;
    while (p < end && isspace((unsigned char) *p))
        p++;
    const char *ip = p;
    while (p < end && !isspace((unsigned char) *p))
        p++;
    if (p == ip)
        return;
    (void) push_nameserver(list, n, cap, ip, (size_t) (p - ip));
}

/* Run /usr/sbin/scutil --dns, capture stdout, harvest nameservers.
 * Returns 0 on success with *out_list / *out_n populated (out_list
 * may be NULL when out_n == 0). Returns -1 on any spawn / read /
 * wait failure so the caller can fall back to a known-good set.
 */
static int scutil_collect_nameservers(char ***out_list, size_t *out_n)
{
    *out_list = NULL;
    *out_n = 0;

    int pipefd[2] = {-1, -1};
    if (pipe(pipefd) < 0)
        return -1;

    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipefd[0]);
    posix_spawn_file_actions_addclose(&actions, pipefd[1]);

    char *const argv[] = {(char *) "/usr/sbin/scutil", (char *) "--dns", NULL};
    pid_t pid = -1;
    int spawn_ret = posix_spawn(&pid, argv[0], &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(pipefd[1]);
    if (spawn_ret != 0) {
        close(pipefd[0]);
        errno = spawn_ret;
        return -1;
    }

    /* Drain stdout. scutil --dns output is bounded by the number of
     * resolver entries macOS keeps; 16 KiB is comfortable for any
     * realistic host.
     */
    char buf[16384];
    size_t off = 0;
    bool drained = true;
    while (off + 1 < sizeof(buf)) {
        ssize_t r = read(pipefd[0], buf + off, sizeof(buf) - 1 - off);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            drained = false;
            break;
        }
        if (r == 0)
            break;
        off += (size_t) r;
    }
    /* Best-effort drain past the cap so the child does not block on
     * SIGPIPE; the parser only sees the first 16 KiB anyway.
     */
    if (drained) {
        char dump[4096];
        while (read(pipefd[0], dump, sizeof(dump)) > 0) {
        }
    }
    close(pipefd[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;

    char **list = NULL;
    size_t n = 0;
    size_t cap = 0;
    buf[off] = '\0';
    char *line = buf;
    char *p = buf;
    while (p < buf + off) {
        if (*p == '\n') {
            parse_scutil_line(line, (size_t) (p - line), &list, &n, &cap);
            line = p + 1;
        }
        p++;
    }
    if (line < buf + off)
        parse_scutil_line(line, (size_t) ((buf + off) - line), &list, &n, &cap);

    *out_list = list;
    *out_n = n;
    return 0;
}

static int write_resolv_conf(const char *run_dir, const char **err)
{
    int fd = open_etc_overwrite(run_dir, "resolv.conf", err);
    if (fd < 0)
        return -1;

    char **ns_list = NULL;
    size_t ns_n = 0;
    bool used_fallback = false;
    if (scutil_collect_nameservers(&ns_list, &ns_n) < 0 || ns_n == 0)
        used_fallback = true;

    int rc = 0;
    if (used_fallback) {
        static const char fallback[] =
            "nameserver 8.8.8.8\n"
            "nameserver 1.1.1.1\n";
        if (write_full(fd, fallback, sizeof(fallback) - 1) < 0)
            rc = -1;
    } else {
        for (size_t i = 0; i < ns_n; i++) {
            char line[128];
            int n = snprintf(line, sizeof(line), "nameserver %s\n", ns_list[i]);
            if (n < 0 || (size_t) n >= sizeof(line)) {
                /* Skip oversized entries silently; scutil should never
                 * print one but the loop must not abort on a bad
                 * resolver string.
                 */
                continue;
            }
            if (write_full(fd, line, (size_t) n) < 0) {
                rc = -1;
                break;
            }
        }
    }

    int saved = errno;
    for (size_t i = 0; i < ns_n; i++)
        free(ns_list[i]);
    free(ns_list);

    if (rc < 0) {
        oci_err_fmt(err, "runtime-files: write resolv.conf failed: %s",
                    strerror(saved));
        close(fd);
        errno = saved;
        return -1;
    }
    if (close(fd) < 0) {
        int e = errno;
        oci_err_fmt(err, "runtime-files: close resolv.conf failed: %s",
                    strerror(e));
        errno = e;
        return -1;
    }
    return 0;
}

static int write_hosts(const char *run_dir, const char **err)
{
    static const char body[] =
        "127.0.0.1   localhost\n"
        "::1         localhost ip6-localhost "
        "ip6-loopback\n"
        "ff02::1     ip6-allnodes\n"
        "ff02::2     ip6-allrouters\n"
        "127.0.0.1   host.elfuse.internal\n";
    int fd = open_etc_overwrite(run_dir, "hosts", err);
    if (fd < 0)
        return -1;
    if (write_full(fd, body, sizeof(body) - 1) < 0) {
        int saved = errno;
        oci_err_fmt(err, "runtime-files: write hosts failed: %s",
                    strerror(saved));
        close(fd);
        errno = saved;
        return -1;
    }
    if (close(fd) < 0) {
        int e = errno;
        oci_err_fmt(err, "runtime-files: close hosts failed: %s", strerror(e));
        errno = e;
        return -1;
    }
    return 0;
}

static int write_hostname(const char *run_dir, const char **err)
{
    static const char body[] = "elfuse\n";
    int fd = open_etc_overwrite(run_dir, "hostname", err);
    if (fd < 0)
        return -1;
    if (write_full(fd, body, sizeof(body) - 1) < 0) {
        int saved = errno;
        oci_err_fmt(err, "runtime-files: write hostname failed: %s",
                    strerror(saved));
        close(fd);
        errno = saved;
        return -1;
    }
    if (close(fd) < 0) {
        int e = errno;
        oci_err_fmt(err, "runtime-files: close hostname failed: %s",
                    strerror(e));
        errno = e;
        return -1;
    }
    return 0;
}

int oci_runtime_files_inject(const char *run_dir, const char **err)
{
    if (err)
        *err = NULL;
    if (!run_dir || !*run_dir) {
        oci_err_static(err, "runtime-files: NULL/empty run_dir");
        errno = EINVAL;
        return -1;
    }
    if (ensure_etc_dir(run_dir, err) < 0)
        return -1;
    if (write_resolv_conf(run_dir, err) < 0)
        return -1;
    if (write_hosts(run_dir, err) < 0)
        return -1;
    if (write_hostname(run_dir, err) < 0)
        return -1;
    return 0;
}
