/* OCI image-config User field resolver
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Header rationale: see user-lookup.h. This module reads rootfs/etc/passwd
 * and rootfs/etc/group as plain text files. The format is the historic
 * colon-separated layout (passwd: name:passwd:uid:gid:gecos:home:shell;
 * group: name:passwd:gid:members). NSS modules (libnss_systemd, sssd,
 * LDAP) are intentionally out of scope: this module is capped at
 * static-passwd resolution.
 *
 * The reader bounds each file at 1 MiB. Container base images carry
 * /etc/passwd between 200 B and 60 KiB; a multi-MiB file is either a
 * misconfigured layer or a deliberately hostile image and resolving
 * either further would only push the failure to a later stage.
 *
 * Token validation rejects embedded NUL, newline, colon, or slash in
 * symbolic names. Names are capped at 32 bytes (LOGIN_NAME_MAX on glibc
 * and the practical ceiling that runc accepts). The validation is the
 * minimum needed to keep the line walker from misinterpreting unusual
 * input; it is not a security boundary because the User string comes
 * from the image config which is already a trust input upstream.
 */

#include "user-lookup.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Bound symbolic names below LOGIN_NAME_MAX so the line walker does not
 * have to allocate. The 32-byte cap matches runc's reject threshold.
 */
#define USER_NAME_MAX 32

static bool is_all_digits(const char *s, size_t n)
{
    if (n == 0)
        return false;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
    }
    return true;
}

/* Bounded uint32 parse. Returns 0 on success, -1 if the token is empty,
 * not all-digit, or overflows.
 */
static int parse_u32(const char *s, size_t n, uint32_t *out)
{
    if (n == 0)
        return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return -1;
        v = v * 10 + (uint64_t) (s[i] - '0');
        if (v > UINT32_MAX)
            return -1;
    }
    *out = (uint32_t) v;
    return 0;
}

/* Symbolic name validation. Reject empty, oversized, and any character
 * that would derail the line walker (':' as the field separator, '\n'
 * as the line separator, '/' to keep the name from looking like a path
 * fragment, and '\0' because the name comes from a NUL-terminated C
 * string and an embedded NUL signals upstream corruption).
 */
static int validate_name(const char *s, size_t n, const char **err)
{
    if (n == 0) {
        oci_err_static(err, "user-lookup: empty name token");
        return -1;
    }
    if (n > USER_NAME_MAX) {
        oci_err_fmt(err, "user-lookup: name token exceeds %d bytes",
                    USER_NAME_MAX);
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char) s[i];
        if (c == '\0' || c == '\n' || c == ':' || c == '/') {
            oci_err_fmt(
                err, "user-lookup: invalid character 0x%02x in name token", c);
            return -1;
        }
    }
    return 0;
}

/* Join two heap path fragments with a single '/'. The caller frees the
 * result. Returns NULL on allocation failure.
 */
static char *path_join(const char *a, const char *b)
{
    size_t alen = strlen(a);
    size_t blen = strlen(b);
    bool a_has_slash = alen > 0 && a[alen - 1] == '/';
    bool b_has_slash = blen > 0 && b[0] == '/';
    size_t total = alen + blen + 1;
    if (!a_has_slash && !b_has_slash)
        total++;
    char *r = malloc(total);
    if (!r)
        return NULL;
    if (a_has_slash && b_has_slash) {
        memcpy(r, a, alen);
        memcpy(r + alen, b + 1, blen - 1);
        r[alen + blen - 1] = '\0';
    } else if (a_has_slash || b_has_slash) {
        memcpy(r, a, alen);
        memcpy(r + alen, b, blen);
        r[alen + blen] = '\0';
    } else {
        memcpy(r, a, alen);
        r[alen] = '/';
        memcpy(r + alen + 1, b, blen);
        r[alen + blen + 1] = '\0';
    }
    return r;
}

/* Read a small text file fully into a heap buffer. Caps the file at
 * 1 MiB; anything larger is rejected so a hostile image cannot pin
 * elfuse on the read.
 */
#define USER_DB_MAX_BYTES (1u << 20)

static int read_file_bounded(const char *path,
                             char **out_buf,
                             size_t *out_len,
                             const char **err)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        int saved = errno;
        oci_err_fmt(err, "user-lookup: open %s: %s", path, strerror(saved));
        errno = saved;
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int saved = errno;
        oci_err_fmt(err, "user-lookup: fstat %s: %s", path, strerror(saved));
        close(fd);
        errno = saved;
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        oci_err_fmt(err, "user-lookup: %s is not a regular file", path);
        close(fd);
        errno = EINVAL;
        return -1;
    }
    if ((uint64_t) st.st_size > USER_DB_MAX_BYTES) {
        oci_err_fmt(err, "user-lookup: %s exceeds %u-byte cap", path,
                    USER_DB_MAX_BYTES);
        close(fd);
        errno = EFBIG;
        return -1;
    }
    size_t len = (size_t) st.st_size;
    char *buf = malloc(len + 1);
    if (!buf) {
        oci_err_static(err, "user-lookup: out of memory reading database");
        close(fd);
        errno = ENOMEM;
        return -1;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            int saved = errno;
            free(buf);
            oci_err_fmt(err, "user-lookup: read %s: %s", path, strerror(saved));
            close(fd);
            errno = saved;
            return -1;
        }
        if (n == 0)
            break;
        off += (size_t) n;
    }
    close(fd);
    buf[off] = '\0';
    *out_buf = buf;
    *out_len = off;
    return 0;
}

/* Find the next end-of-line from p within [p, end). Returns a pointer to
 * the '\n' if present, otherwise end. The caller advances past the
 * separator on its own.
 */
static const char *line_end(const char *p, const char *end)
{
    const char *q = memchr(p, '\n', (size_t) (end - p));
    return q ? q : end;
}

/* Test whether the line at [p, eol) has at least `idx + 1` colon-separated
 * fields and bind field_starts / field_lens to the first `n_fields` of
 * them. Returns the actual count of fields seen (which may be fewer than
 * requested if the line is truncated).
 */
static size_t split_fields(const char *p,
                           const char *eol,
                           const char **field_starts,
                           size_t *field_lens,
                           size_t n_fields)
{
    size_t count = 0;
    const char *cursor = p;
    while (count < n_fields) {
        field_starts[count] = cursor;
        const char *colon = memchr(cursor, ':', (size_t) (eol - cursor));
        if (colon) {
            field_lens[count] = (size_t) (colon - cursor);
            count++;
            cursor = colon + 1;
        } else {
            field_lens[count] = (size_t) (eol - cursor);
            count++;
            break;
        }
    }
    return count;
}

/* Look up `name` in rootfs/etc/passwd. On match writes the numeric uid and
 * primary gid (the fourth field) and returns 0. Returns -1 with errno
 * preserved and *err set when:
 *   - rootfs/etc/passwd is missing or unreadable (returns ENOENT / EIO via
 *     the read helper).
 *   - the name is absent from the file (returns ENOENT with a diagnostic
 *     naming the missing account).
 *   - a matching line has a non-numeric uid or gid field (returns EINVAL).
 */
static int lookup_passwd_by_name(const char *rootfs,
                                 const char *name,
                                 size_t name_len,
                                 uint32_t *uid_out,
                                 uint32_t *primary_gid_out,
                                 const char **err)
{
    char *path = path_join(rootfs, "etc/passwd");
    if (!path) {
        oci_err_static(err, "user-lookup: out of memory");
        errno = ENOMEM;
        return -1;
    }
    char *buf = NULL;
    size_t buf_len = 0;
    if (read_file_bounded(path, &buf, &buf_len, err) < 0) {
        int saved = errno;
        free(path);
        errno = saved;
        return -1;
    }
    free(path);

    const char *p = buf;
    const char *end = buf + buf_len;
    while (p < end) {
        const char *eol = line_end(p, end);
        if (p == eol) {
            p = (eol < end) ? eol + 1 : end;
            continue;
        }
        if (*p == '#') {
            p = (eol < end) ? eol + 1 : end;
            continue;
        }
        const char *fs[4] = {0};
        size_t fl[4] = {0};
        size_t got = split_fields(p, eol, fs, fl, 4);
        if (got >= 4 && fl[0] == name_len &&
            memcmp(fs[0], name, name_len) == 0) {
            uint32_t uid_v = 0, gid_v = 0;
            if (parse_u32(fs[2], fl[2], &uid_v) < 0) {
                oci_err_fmt(err,
                            "user-lookup: passwd entry for '%.*s' has"
                            " non-numeric uid",
                            (int) name_len, name);
                free(buf);
                errno = EINVAL;
                return -1;
            }
            if (parse_u32(fs[3], fl[3], &gid_v) < 0) {
                oci_err_fmt(err,
                            "user-lookup: passwd entry for '%.*s' has"
                            " non-numeric primary gid",
                            (int) name_len, name);
                free(buf);
                errno = EINVAL;
                return -1;
            }
            *uid_out = uid_v;
            *primary_gid_out = gid_v;
            free(buf);
            return 0;
        }
        p = (eol < end) ? eol + 1 : end;
    }
    free(buf);
    oci_err_fmt(err, "user-lookup: user '%.*s' not found in /etc/passwd",
                (int) name_len, name);
    errno = ENOENT;
    return -1;
}

/* Look up `name` in rootfs/etc/group. On match writes the gid (third
 * field) and returns 0. Same failure modes as lookup_passwd_by_name.
 */
static int lookup_group_by_name(const char *rootfs,
                                const char *name,
                                size_t name_len,
                                uint32_t *gid_out,
                                const char **err)
{
    char *path = path_join(rootfs, "etc/group");
    if (!path) {
        oci_err_static(err, "user-lookup: out of memory");
        errno = ENOMEM;
        return -1;
    }
    char *buf = NULL;
    size_t buf_len = 0;
    if (read_file_bounded(path, &buf, &buf_len, err) < 0) {
        int saved = errno;
        free(path);
        errno = saved;
        return -1;
    }
    free(path);

    const char *p = buf;
    const char *end = buf + buf_len;
    while (p < end) {
        const char *eol = line_end(p, end);
        if (p == eol) {
            p = (eol < end) ? eol + 1 : end;
            continue;
        }
        if (*p == '#') {
            p = (eol < end) ? eol + 1 : end;
            continue;
        }
        const char *fs[3] = {0};
        size_t fl[3] = {0};
        size_t got = split_fields(p, eol, fs, fl, 3);
        if (got >= 3 && fl[0] == name_len &&
            memcmp(fs[0], name, name_len) == 0) {
            uint32_t gid_v = 0;
            if (parse_u32(fs[2], fl[2], &gid_v) < 0) {
                oci_err_fmt(err,
                            "user-lookup: group entry for '%.*s' has"
                            " non-numeric gid",
                            (int) name_len, name);
                free(buf);
                errno = EINVAL;
                return -1;
            }
            *gid_out = gid_v;
            free(buf);
            return 0;
        }
        p = (eol < end) ? eol + 1 : end;
    }
    free(buf);
    oci_err_fmt(err, "user-lookup: group '%.*s' not found in /etc/group",
                (int) name_len, name);
    errno = ENOENT;
    return -1;
}

/* Resolve the left-hand token. Caller guarantees [s, s+n) is the token
 * span (no surrounding whitespace, no embedded colon). On success uid_out
 * is set; primary_gid_out is set only when the token resolved via passwd
 * (i.e. the token was symbolic) so the gid-resolution stage can use it
 * as the implicit gid when no explicit gid was supplied.
 *
 * primary_gid_set is the flag that signals "passwd gave us a gid".
 */
static int resolve_user_token(const char *rootfs,
                              const char *s,
                              size_t n,
                              uint32_t *uid_out,
                              uint32_t *primary_gid_out,
                              bool *primary_gid_set,
                              const char **err)
{
    *primary_gid_set = false;
    if (is_all_digits(s, n)) {
        if (parse_u32(s, n, uid_out) < 0) {
            oci_err_fmt(err, "user-lookup: uid '%.*s' overflows uint32",
                        (int) n, s);
            errno = EINVAL;
            return -1;
        }
        return 0;
    }
    if (validate_name(s, n, err) < 0) {
        errno = EINVAL;
        return -1;
    }
    if (!rootfs) {
        oci_err_fmt(err,
                    "user-lookup: symbolic User '%.*s' but no rootfs"
                    " available for /etc/passwd lookup",
                    (int) n, s);
        errno = EINVAL;
        return -1;
    }
    if (lookup_passwd_by_name(rootfs, s, n, uid_out, primary_gid_out, err) <
        0) {
        return -1;
    }
    *primary_gid_set = true;
    return 0;
}

/* Resolve the right-hand token (the gid half). Same shape as the
 * user-token resolver, but on the group database.
 */
static int resolve_group_token(const char *rootfs,
                               const char *s,
                               size_t n,
                               uint32_t *gid_out,
                               const char **err)
{
    if (is_all_digits(s, n)) {
        if (parse_u32(s, n, gid_out) < 0) {
            oci_err_fmt(err, "user-lookup: gid '%.*s' overflows uint32",
                        (int) n, s);
            errno = EINVAL;
            return -1;
        }
        return 0;
    }
    if (validate_name(s, n, err) < 0) {
        errno = EINVAL;
        return -1;
    }
    if (!rootfs) {
        oci_err_fmt(err,
                    "user-lookup: symbolic group '%.*s' but no rootfs"
                    " available for /etc/group lookup",
                    (int) n, s);
        errno = EINVAL;
        return -1;
    }
    return lookup_group_by_name(rootfs, s, n, gid_out, err);
}

int oci_user_lookup(const char *rootfs,
                    const char *user_str,
                    uint32_t *uid_out,
                    uint32_t *gid_out,
                    const char **err)
{
    if (err)
        *err = NULL;
    if (!user_str || !*user_str) {
        oci_err_static(err, "user-lookup: empty User string");
        errno = EINVAL;
        return -1;
    }
    if (!uid_out || !gid_out) {
        oci_err_static(err, "user-lookup: NULL uid_out / gid_out");
        errno = EINVAL;
        return -1;
    }
    size_t total = strlen(user_str);
    const char *colon = memchr(user_str, ':', total);
    const char *uid_tok = user_str;
    size_t uid_len = colon ? (size_t) (colon - user_str) : total;
    const char *gid_tok = colon ? colon + 1 : NULL;
    size_t gid_len = colon ? total - (size_t) (colon - user_str) - 1 : 0;

    if (uid_len == 0) {
        oci_err_fmt(err, "user-lookup: empty uid token in '%s'", user_str);
        errno = EINVAL;
        return -1;
    }
    if (colon && gid_len == 0) {
        oci_err_fmt(err, "user-lookup: empty gid token in '%s'", user_str);
        errno = EINVAL;
        return -1;
    }

    uint32_t uid_v = 0;
    uint32_t primary_gid = 0;
    bool primary_gid_set = false;
    if (resolve_user_token(rootfs, uid_tok, uid_len, &uid_v, &primary_gid,
                           &primary_gid_set, err) < 0) {
        return -1;
    }

    uint32_t gid_v = 0;
    if (colon) {
        if (resolve_group_token(rootfs, gid_tok, gid_len, &gid_v, err) < 0)
            return -1;
    } else if (primary_gid_set) {
        /* symbolic User "name" with no explicit gid: take passwd's primary
         * gid (matches runc / Docker behavior). */
        gid_v = primary_gid;
    } else {
        /* numeric uid with no explicit gid: gid defaults to uid (preserves
         * runspec.c's numeric-User behavior). */
        gid_v = uid_v;
    }

    *uid_out = uid_v;
    *gid_out = gid_v;
    return 0;
}
