/* OCI image reference parser
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * See ref.h for the grammar and design notes. The parser is split into:
 *   1. find the optional @digest suffix and validate it
 *   2. find the optional :tag suffix on the remainder
 *   3. split the rest into registry vs path using the containerd domain rule
 *   4. apply Docker defaults (docker.io, library/, latest)
 *   5. validate every component against the OCI character class rules
 */

#include "ref.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define DEFAULT_REGISTRY "docker.io"
#define DEFAULT_LIBRARY_NAMESPACE "library"
#define DEFAULT_TAG "latest"

#define MAX_REFERENCE_LEN 4096
#define MAX_TAG_LEN 128

static char *strndup_local(const char *src, size_t n)
{
    char *dst = (char *) malloc(n + 1);
    if (!dst)
        return NULL;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return dst;
}

static void set_err(const char **slot, const char *msg)
{
    if (slot)
        *slot = msg;
}

static bool is_lower_alnum(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

static bool is_path_separator(char c)
{
    return c == '.' || c == '_' || c == '-';
}

/* Validate one path component against [a-z0-9]+ (([._-]|__) [a-z0-9]+)*.
 * Empty components and uppercase letters are rejected.
 */
static bool valid_path_component(const char *s, size_t len)
{
    if (len == 0)
        return false;
    if (!is_lower_alnum(s[0]) || !is_lower_alnum(s[len - 1]))
        return false;

    size_t i = 0;
    while (i < len) {
        if (is_lower_alnum(s[i])) {
            i++;
            continue;
        }
        /* Separator run per the distribution-spec grammar
         * [a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*: a run of one-or-more '-', a
         * single '.' or '_', or exactly "__". Anything else (e.g. "a..b",
         * "a___b") is rejected. Note dashes may repeat ("my--repo") but
         * dots and underscores may not.
         */
        if (s[i] == '-') {
            while (i < len && s[i] == '-')
                i++;
        } else if (s[i] == '_' && i + 1 < len && s[i + 1] == '_') {
            i += 2;
        } else if (is_path_separator(s[i])) {
            i++;
        } else {
            return false;
        }
        if (i >= len || !is_lower_alnum(s[i]))
            return false;
    }
    return true;
}

/* Validate a multi-component path (components separated by '/'). */
static bool valid_repository_path(const char *s, size_t len)
{
    if (len == 0)
        return false;
    size_t start = 0;
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '/') {
            if (!valid_path_component(s + start, i - start))
                return false;
            start = i + 1;
        }
    }
    return valid_path_component(s + start, len - start);
}

/* Domain detection per containerd: a leading slash component is a registry
 * only when it contains '.' or ':', or when it is exactly "localhost".
 */
static bool looks_like_domain(const char *s, size_t len)
{
    if (len == 9 && memcmp(s, "localhost", 9) == 0)
        return true;
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '.' || s[i] == ':')
            return true;
    }
    return false;
}

/* Portable rightmost-match: Darwin libc does not ship memrchr. */
static const char *memrchr_local(const char *s, int c, size_t n)
{
    while (n > 0) {
        n--;
        if ((unsigned char) s[n] == (unsigned char) c)
            return s + n;
    }
    return NULL;
}

/* Validate a registry host[:port]. The host portion is permissive (DNS
 * label rules plus IPv6 brackets are not enforced) but uppercase letters
 * are accepted because hostnames are case-insensitive. The optional port
 * suffix must be a 1..5 digit decimal number.
 */
static bool valid_registry(const char *s, size_t len)
{
    if (len == 0)
        return false;
    /* Reject embedded whitespace or path separators outright. */
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char) s[i];
        if (c <= ' ' || c == '/' || c == '@')
            return false;
    }
    /* If there is a ':' it must be followed by 1..5 decimal digits and must
     * be the last colon (IPv6 in brackets is not yet supported).
     */
    const char *colon = memchr(s, ':', len);
    if (colon) {
        size_t host_len = (size_t) (colon - s);
        size_t port_len = len - host_len - 1;
        if (host_len == 0 || port_len == 0 || port_len > 5)
            return false;
        for (size_t i = 0; i < port_len; i++) {
            if (colon[1 + i] < '0' || colon[1 + i] > '9')
                return false;
        }
    }
    return true;
}

static bool valid_tag(const char *s, size_t len)
{
    if (len == 0 || len > MAX_TAG_LEN)
        return false;
    /* First char: word character (letter, digit, underscore). */
    unsigned char c0 = (unsigned char) s[0];
    if (!isalnum(c0) && c0 != '_')
        return false;
    for (size_t i = 1; i < len; i++) {
        unsigned char c = (unsigned char) s[i];
        if (!isalnum(c) && c != '_' && c != '.' && c != '-')
            return false;
    }
    return true;
}

static bool is_lower_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/* Validate "<algo>:<hex>" with algo in {sha256, sha512}. The hex digits are
 * required to be lowercase per the OCI image-spec descriptor canonicalisation
 * rules; uppercase encodings would otherwise cause silent dedup misses in
 * the local store.
 */
static bool valid_digest(const char *s, size_t len, const char **err_msg)
{
    const char *colon = memchr(s, ':', len);
    if (!colon) {
        set_err(err_msg, "digest missing ':' separator");
        return false;
    }
    size_t algo_len = (size_t) (colon - s);
    size_t hex_len = len - algo_len - 1;

    size_t expected_hex;
    if (algo_len == 6 && memcmp(s, "sha256", 6) == 0) {
        expected_hex = 64;
    } else if (algo_len == 6 && memcmp(s, "sha512", 6) == 0) {
        expected_hex = 128;
    } else {
        set_err(err_msg, "digest algorithm must be sha256 or sha512");
        return false;
    }
    if (hex_len != expected_hex) {
        set_err(err_msg, "digest hex length does not match algorithm");
        return false;
    }
    for (size_t i = 0; i < hex_len; i++) {
        if (!is_lower_hex(colon[1 + i])) {
            set_err(err_msg, "digest hex must be lowercase 0-9 a-f");
            return false;
        }
    }
    return true;
}

void oci_ref_free(oci_ref_t *ref)
{
    if (!ref)
        return;
    free(ref->registry);
    free(ref->repository);
    free(ref->tag);
    free(ref->digest);
    ref->registry = NULL;
    ref->repository = NULL;
    ref->tag = NULL;
    ref->digest = NULL;
}

int oci_ref_parse(const char *input, oci_ref_t *out, const char **err_msg)
{
    set_err(err_msg, NULL);
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));

    if (!input) {
        set_err(err_msg, "reference is NULL");
        return -1;
    }
    size_t total = strlen(input);
    if (total == 0) {
        set_err(err_msg, "reference is empty");
        return -1;
    }
    if (total > MAX_REFERENCE_LEN) {
        set_err(err_msg, "reference exceeds 4096 characters");
        return -1;
    }

    /* Step 1: split off "@digest" (rightmost '@' wins because '@' cannot
     * legally appear elsewhere in a well-formed reference).
     */
    const char *digest_start = NULL;
    size_t digest_len = 0;
    const char *at = memchr(input, '@', total);
    if (at) {
        /* Reject multiple '@' separators outright. */
        const char *second =
            memchr(at + 1, '@', total - (size_t) (at + 1 - input));
        if (second) {
            set_err(err_msg, "reference contains multiple '@' separators");
            return -1;
        }
        digest_start = at + 1;
        digest_len = total - (size_t) (digest_start - input);
        if (digest_len == 0) {
            set_err(err_msg, "digest is empty after '@'");
            return -1;
        }
        if (!valid_digest(digest_start, digest_len, err_msg))
            return -1;
        total = (size_t) (at - input);
        if (total == 0) {
            set_err(err_msg, "reference has no name before '@'");
            return -1;
        }
    }

    /* Step 2: peel off ":tag" if present. The tag separator is the rightmost
     * ':' that follows the last '/' (a colon before any '/' belongs to the
     * registry's port).
     */
    const char *tag_start = NULL;
    size_t tag_len = 0;
    size_t name_len = total;
    const char *last_slash = memrchr_local(input, '/', total);
    const char *scan_from = last_slash ? last_slash + 1 : input;
    const char *scan_end = input + total;
    const char *tag_colon =
        memchr(scan_from, ':', (size_t) (scan_end - scan_from));
    if (tag_colon) {
        tag_start = tag_colon + 1;
        tag_len = total - (size_t) (tag_start - input);
        if (tag_len == 0) {
            set_err(err_msg, "tag is empty after ':'");
            return -1;
        }
        if (!valid_tag(tag_start, tag_len)) {
            set_err(err_msg, "tag has invalid characters or length");
            return -1;
        }
        name_len = (size_t) (tag_colon - input);
        if (name_len == 0) {
            set_err(err_msg, "reference has no name before ':'");
            return -1;
        }
    }

    /* Step 3: split name into [registry "/"] path. */
    const char *registry_start = NULL;
    size_t registry_len = 0;
    const char *path_start = input;
    size_t path_len = name_len;

    const char *first_slash = memchr(input, '/', name_len);
    if (first_slash) {
        size_t head_len = (size_t) (first_slash - input);
        if (looks_like_domain(input, head_len)) {
            registry_start = input;
            registry_len = head_len;
            path_start = first_slash + 1;
            path_len = name_len - head_len - 1;
            if (path_len == 0) {
                set_err(err_msg, "reference has no repository after registry");
                return -1;
            }
        }
    }

    /* Step 4: validate path components and detect single-segment defaults. */
    if (!valid_repository_path(path_start, path_len)) {
        set_err(err_msg,
                "repository path has invalid component (lowercase letters,"
                " digits, '.', '_', '-' only)");
        return -1;
    }

    if (registry_len > 0 && !valid_registry(registry_start, registry_len)) {
        set_err(err_msg, "registry host has invalid characters");
        return -1;
    }

    /* Step 5: materialise the canonical fields. */
    out->registry = registry_len > 0
                        ? strndup_local(registry_start, registry_len)
                        : strdup(DEFAULT_REGISTRY);
    if (!out->registry)
        goto oom;

    /* Registry hostnames are case-insensitive (DNS), so "Docker.io" must
     * resolve to the docker.io default namespace just like "docker.io".
     */
    bool needs_library_prefix =
        strcasecmp(out->registry, DEFAULT_REGISTRY) == 0 &&
        memchr(path_start, '/', path_len) == NULL;
    if (needs_library_prefix) {
        size_t prefix_len = strlen(DEFAULT_LIBRARY_NAMESPACE);
        size_t total_len = prefix_len + 1 + path_len;
        out->repository = (char *) malloc(total_len + 1);
        if (!out->repository)
            goto oom;
        memcpy(out->repository, DEFAULT_LIBRARY_NAMESPACE, prefix_len);
        out->repository[prefix_len] = '/';
        memcpy(out->repository + prefix_len + 1, path_start, path_len);
        out->repository[total_len] = '\0';
    } else {
        out->repository = strndup_local(path_start, path_len);
        if (!out->repository)
            goto oom;
    }

    if (tag_len > 0) {
        out->tag = strndup_local(tag_start, tag_len);
        if (!out->tag)
            goto oom;
    } else if (digest_len == 0) {
        out->tag = strdup(DEFAULT_TAG);
        if (!out->tag)
            goto oom;
    }

    if (digest_len > 0) {
        out->digest = strndup_local(digest_start, digest_len);
        if (!out->digest)
            goto oom;
    }

    return 0;

oom:
    set_err(err_msg, "out of memory");
    oci_ref_free(out);
    return -1;
}

char *oci_ref_canonical(const oci_ref_t *ref)
{
    if (!ref || !ref->registry || !ref->repository)
        return NULL;
    size_t reg_len = strlen(ref->registry);
    size_t repo_len = strlen(ref->repository);
    size_t tag_len = ref->tag ? strlen(ref->tag) : 0;
    size_t dig_len = ref->digest ? strlen(ref->digest) : 0;
    size_t total = reg_len + 1 + repo_len + (tag_len ? tag_len + 1 : 0) +
                   (dig_len ? dig_len + 1 : 0) + 1;
    char *buf = (char *) malloc(total);
    if (!buf)
        return NULL;
    char *p = buf;
    memcpy(p, ref->registry, reg_len);
    p += reg_len;
    *p++ = '/';
    memcpy(p, ref->repository, repo_len);
    p += repo_len;
    if (tag_len) {
        *p++ = ':';
        memcpy(p, ref->tag, tag_len);
        p += tag_len;
    }
    if (dig_len) {
        *p++ = '@';
        memcpy(p, ref->digest, dig_len);
        p += dig_len;
    }
    *p = '\0';
    return buf;
}

char *oci_ref_canonical_name(const oci_ref_t *ref)
{
    if (!ref || !ref->registry || !ref->repository || !ref->tag) {
        errno = EINVAL;
        return NULL;
    }
    size_t reg_len = strlen(ref->registry);
    size_t repo_len = strlen(ref->repository);
    size_t tag_len = strlen(ref->tag);
    size_t total = reg_len + 1 + repo_len + 1 + tag_len + 1;
    char *buf = (char *) malloc(total);
    if (!buf) {
        errno = ENOMEM;
        return NULL;
    }
    char *p = buf;
    memcpy(p, ref->registry, reg_len);
    p += reg_len;
    *p++ = '/';
    memcpy(p, ref->repository, repo_len);
    p += repo_len;
    *p++ = ':';
    memcpy(p, ref->tag, tag_len);
    p += tag_len;
    *p = '\0';
    return buf;
}
