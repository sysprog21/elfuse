/* OCI guest PATH resolver: argv0 + PATH + cwd_guest -> host_path/guest_path
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implementation notes that did not fit in the header:
 *
 * The candidate probe order matters. Each PATH entry is probed in turn.
 * The first entry whose candidate exists, contains, and is executable
 * wins (returns success immediately, like execvp). If no entry succeeds
 * but at least one entry was found-and-contained-but-not-executable, the
 * call surfaces EACCES with the rejected argv0 quoted. Otherwise the
 * call surfaces ENOENT with the directories actually probed listed in
 * the diagnostic so the operator can tell whether PATH itself was wrong
 * or whether the binary just is not in the image.
 *
 * "Probed" specifically means "the candidate had a realpath that landed
 * inside the sysroot". Escape symlinks and broken chains do NOT show up
 * in the searched-dirs annotation: they were directories that exist on
 * the guest side but contributed no host candidate, which is closer to
 * what an operator who reads the error wants to see.
 *
 * realpath(3) is used once for sysroot_dir (so the prefix is canonical
 * regardless of whether the caller passed it with or without trailing
 * slashes or with intermediate symlinks) and once per probed candidate
 * (so the containment check sees the post-symlink path). Both calls
 * pass NULL for the resolved-path argument and let libc allocate.
 */

#include "path-resolve.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "core/elf.h"
#include "util.h"

/* Geometric-grow string buffer used to assemble the searched-dirs list
 * for the ENOENT diagnostic. Keeping it separate from runspec's strvec
 * because the surface area here is small enough that introducing a
 * cross-module utility header would be over-engineering for a two-call
 * use case.
 */
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} sbuf_t;

static int sbuf_append(sbuf_t *s, const char *str)
{
    size_t add = strlen(str);
    if (s->len + add + 1 > s->cap) {
        size_t newcap = s->cap ? s->cap : 64;
        while (newcap < s->len + add + 1)
            newcap *= 2;
        char *np = realloc(s->buf, newcap);
        if (!np)
            return -1;
        s->buf = np;
        s->cap = newcap;
    }
    memcpy(s->buf + s->len, str, add);
    s->len += add;
    s->buf[s->len] = '\0';
    return 0;
}

/* Concatenate two path components, normalising the slash boundary. NULL
 * inputs propagate as NULL so call sites can chain without an extra
 * branch per step.
 */
static char *path_join(const char *a, const char *b)
{
    if (!a || !b)
        return NULL;
    size_t alen = strlen(a);
    size_t blen = strlen(b);
    char *r = malloc(alen + blen + 2);
    if (!r)
        return NULL;
    bool a_has_trailing = alen > 0 && a[alen - 1] == '/';
    bool b_has_leading = blen > 0 && b[0] == '/';
    if (a_has_trailing && b_has_leading) {
        memcpy(r, a, alen);
        memcpy(r + alen, b + 1, blen - 1);
        r[alen + blen - 1] = '\0';
    } else if (!a_has_trailing && !b_has_leading && alen > 0 && blen > 0) {
        memcpy(r, a, alen);
        r[alen] = '/';
        memcpy(r + alen + 1, b, blen);
        r[alen + 1 + blen] = '\0';
    } else {
        memcpy(r, a, alen);
        memcpy(r + alen, b, blen);
        r[alen + blen] = '\0';
    }
    return r;
}

/* True when real_candidate equals real_sysroot or sits below it. Both
 * arguments are absolute paths produced by realpath(3) so no trailing
 * slash normalisation is needed on the candidate side; real_sysroot
 * keeps any trailing slash stripped (realpath never adds one, but the
 * defensive check below handles a caller that mutated it).
 */
static bool path_within_sysroot(const char *real_candidate,
                                const char *real_sysroot)
{
    size_t slen = strlen(real_sysroot);
    while (slen > 1 && real_sysroot[slen - 1] == '/')
        slen--;
    if (strncmp(real_candidate, real_sysroot, slen) != 0)
        return false;
    char trailing = real_candidate[slen];
    return trailing == '\0' || trailing == '/';
}

enum probe_result {
    PROBE_OK = 0,
    PROBE_NOEXEC = 1,
    PROBE_ESCAPE = 2,
    PROBE_MISS = 3,
};

/* Probe one host candidate. The realpath()-based containment check runs
 * first so escape symlinks never reach the stat() call. The stat()
 * itself follows symlinks (POSIX stat semantics), matching how execvp
 * would observe the candidate.
 */
static enum probe_result probe_candidate(const char *host_path,
                                         const char *real_sysroot)
{
    char *real = realpath(host_path, NULL);
    if (!real)
        return PROBE_MISS;
    bool contained = path_within_sysroot(real, real_sysroot);
    free(real);
    if (!contained)
        return PROBE_ESCAPE;
    struct stat st;
    if (stat(host_path, &st) < 0)
        return PROBE_MISS;
    if (!S_ISREG(st.st_mode))
        return PROBE_MISS;
    if ((st.st_mode & 0111) == 0)
        return PROBE_NOEXEC;
    return PROBE_OK;
}

/* Direct-mode resolve: argv0 contains '/' so the PATH is bypassed.
 * Absolute argv0 maps to <sysroot><argv0>; relative argv0 anchors to
 * cwd_guest.
 */
static int resolve_direct(const char *real_sysroot,
                          const char *argv0,
                          const char *cwd_guest,
                          char **out_host_path,
                          char **out_guest_path,
                          const char **err)
{
    char *guest_path = NULL;
    if (argv0[0] == '/')
        guest_path = strdup(argv0);
    else
        guest_path = path_join(cwd_guest, argv0);
    if (!guest_path) {
        oci_err_static(err, "out of memory building guest path");
        errno = ENOMEM;
        return -1;
    }
    char *host_path = path_join(real_sysroot, guest_path);
    if (!host_path) {
        free(guest_path);
        oci_err_static(err, "out of memory building host path");
        errno = ENOMEM;
        return -1;
    }
    enum probe_result probe = probe_candidate(host_path, real_sysroot);
    if (probe == PROBE_OK) {
        *out_host_path = host_path;
        *out_guest_path = guest_path;
        return 0;
    }
    if (probe == PROBE_NOEXEC) {
        oci_err_fmt(err, "'%s' is not executable inside sysroot", argv0);
        errno = EACCES;
    } else if (probe == PROBE_ESCAPE) {
        oci_err_fmt(err, "'%s' resolves outside sysroot (refusing escape)",
                    argv0);
        errno = ENOENT;
    } else {
        oci_err_fmt(err, "cannot find '%s' inside sysroot", argv0);
        errno = ENOENT;
    }
    free(host_path);
    free(guest_path);
    return -1;
}

/* PATH-search resolve: walk path_env in order, returning the first
 * executable candidate. Tracks the first NOEXEC for the late EACCES
 * diagnostic and a sbuf_t of probed directories for the late ENOENT
 * diagnostic.
 */
static int resolve_path_search(const char *real_sysroot,
                               const char *argv0,
                               const char *path_env,
                               const char *cwd_guest,
                               char **out_host_path,
                               char **out_guest_path,
                               const char **err)
{
    if (!path_env || !*path_env) {
        oci_err_fmt(err,
                    "cannot find '%s' on PATH inside sysroot (PATH is"
                    " empty)",
                    argv0);
        errno = ENOENT;
        return -1;
    }

    sbuf_t searched = {0};
    char *first_noexec_argv0 = NULL;
    int rc = -1;

    const char *p = path_env;
    while (*p) {
        const char *colon = strchr(p, ':');
        size_t elen = colon ? (size_t) (colon - p) : strlen(p);
        char entry[PATH_MAX];
        if (elen >= sizeof(entry)) {
            p = colon ? colon + 1 : p + elen;
            continue;
        }
        memcpy(entry, p, elen);
        entry[elen] = '\0';
        p = colon ? colon + 1 : p + elen;

        char *guest_dir;
        if (elen == 0)
            guest_dir = strdup(cwd_guest);
        else if (entry[0] == '/')
            guest_dir = strdup(entry);
        else
            guest_dir = path_join(cwd_guest, entry);
        if (!guest_dir) {
            oci_err_static(err, "out of memory building PATH entry");
            errno = ENOMEM;
            goto cleanup;
        }

        char *guest_path = path_join(guest_dir, argv0);
        char *host_path =
            guest_path ? path_join(real_sysroot, guest_path) : NULL;
        if (!guest_path || !host_path) {
            free(guest_path);
            free(host_path);
            free(guest_dir);
            oci_err_static(err, "out of memory building host candidate");
            errno = ENOMEM;
            goto cleanup;
        }

        enum probe_result probe = probe_candidate(host_path, real_sysroot);
        if (probe == PROBE_OK) {
            *out_host_path = host_path;
            *out_guest_path = guest_path;
            free(guest_dir);
            rc = 0;
            goto cleanup;
        }
        if (probe == PROBE_NOEXEC) {
            if (searched.len)
                if (sbuf_append(&searched, ":") < 0)
                    goto oom_in_loop;
            if (sbuf_append(&searched, guest_dir) < 0)
                goto oom_in_loop;
            if (!first_noexec_argv0)
                first_noexec_argv0 = guest_path;
            else
                free(guest_path);
            free(host_path);
            free(guest_dir);
            continue;
        }
        if (probe == PROBE_MISS) {
            if (searched.len)
                if (sbuf_append(&searched, ":") < 0)
                    goto oom_in_loop_full;
            if (sbuf_append(&searched, guest_dir) < 0)
                goto oom_in_loop_full;
        }
        free(guest_path);
        free(host_path);
        free(guest_dir);
        continue;

    oom_in_loop_full:
        free(guest_path);
    oom_in_loop:
        free(host_path);
        free(guest_dir);
        oci_err_static(err, "out of memory recording PATH entry");
        errno = ENOMEM;
        goto cleanup;
    }

    if (first_noexec_argv0) {
        oci_err_fmt(err, "'%s' is not executable inside sysroot", argv0);
        errno = EACCES;
        free(first_noexec_argv0);
    } else {
        oci_err_fmt(err,
                    "cannot find '%s' on PATH inside sysroot (searched:"
                    " %s)",
                    argv0, searched.buf ? searched.buf : "");
        errno = ENOENT;
    }

cleanup:
    /* On success the saved first_noexec_argv0 has already been freed (it
     * stays NULL because the OK branch hit first). On failure with no
     * NOEXEC seen the same logic applies. The dual-free pattern here
     * avoids leaking when a PATH miss happened to also have a noexec
     * earlier in the walk.
     */
    if (rc == 0 && first_noexec_argv0)
        free(first_noexec_argv0);
    free(searched.buf);
    return rc;
}

int oci_path_resolve(const char *sysroot_dir,
                     const char *argv0,
                     const char *path_env,
                     const char *cwd_guest,
                     char **out_host_path,
                     char **out_guest_path,
                     const char **err)
{
    if (out_host_path)
        *out_host_path = NULL;
    if (out_guest_path)
        *out_guest_path = NULL;
    if (err)
        *err = NULL;

    if (!sysroot_dir || !argv0 || !*argv0 || !out_host_path ||
        !out_guest_path) {
        oci_err_static(err, "oci_path_resolve: NULL argument or empty argv0");
        errno = EINVAL;
        return -1;
    }
    if (!cwd_guest || !*cwd_guest)
        cwd_guest = "/";

    char *real_sysroot = realpath(sysroot_dir, NULL);
    if (!real_sysroot) {
        oci_err_fmt(err, "sysroot not accessible: %s", sysroot_dir);
        /* errno preserved by realpath */
        return -1;
    }

    int rc;
    if (strchr(argv0, '/')) {
        rc = resolve_direct(real_sysroot, argv0, cwd_guest, out_host_path,
                            out_guest_path, err);
    } else {
        rc = resolve_path_search(real_sysroot, argv0, path_env, cwd_guest,
                                 out_host_path, out_guest_path, err);
    }

    free(real_sysroot);
    return rc;
}
/* Depth cap shared with the standalone loader's shebang loop in main.c:
 * a divergence would make `elfuse oci run IMAGE script` and
 * `elfuse <script>` accept different interpreter chains.
 */
#define SHEBANG_MAX_DEPTH 5

int oci_shebang_expand(const char *sysroot_dir,
                       const char *cwd_guest,
                       char **host_path,
                       char ***argv,
                       const char **err)
{
    if (err)
        *err = NULL;
    if (!sysroot_dir || !host_path || !*host_path || !argv || !*argv) {
        oci_err_static(err, "oci_shebang_expand: NULL argument");
        errno = EINVAL;
        return -1;
    }

    for (int depth = 0; depth < SHEBANG_MAX_DEPTH; depth++) {
        char interp[4096];
        char arg[4096];
        int rc = elf_read_shebang(*host_path, interp, sizeof(interp), arg,
                                  sizeof(arg));
        if (rc == 0)
            return 0;
        if (rc < 0) {
            oci_err_fmt(err, "invalid shebang line in '%s'", *host_path);
            errno = -rc;
            return -1;
        }

        char *interp_host = NULL;
        char *interp_guest = NULL;
        if (oci_path_resolve(sysroot_dir, interp, NULL, cwd_guest, &interp_host,
                             &interp_guest, err) < 0)
            return -1; /* err and errno set by the resolver */

        /* Prepend interpreter (+ optional argument) to the guest argv,
         * keeping the script path in place as the interpreter's operand.
         */
        bool has_arg = (arg[0] != '\0');
        int add = has_arg ? 2 : 1;
        int argc = 0;
        while ((*argv)[argc])
            argc++;
        char **new_argv =
            calloc((size_t) argc + (size_t) add + 1, sizeof(char *));
        char *arg_copy = has_arg ? strdup(arg) : NULL;
        if (!new_argv || (has_arg && !arg_copy)) {
            free(new_argv);
            free(arg_copy);
            free(interp_host);
            free(interp_guest);
            oci_err_static(err, "out of memory expanding shebang argv");
            errno = ENOMEM;
            return -1;
        }
        new_argv[0] = interp_guest;
        if (has_arg)
            new_argv[1] = arg_copy;
        memcpy(new_argv + add, *argv, ((size_t) argc + 1) * sizeof(char *));
        free(*argv); /* elements transferred to new_argv */
        *argv = new_argv;

        free(*host_path);
        *host_path = interp_host;
    }

    oci_err_fmt(err, "too many levels of shebang recursion (max %d) in '%s'",
                SHEBANG_MAX_DEPTH, *host_path);
    errno = ELOOP;
    return -1;
}
