/* OCI launch-spec resolver: image runtime + CLI overrides -> argv/envp/...
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure-data merge. No filesystem touches. The translation unit deliberately
 * carries its own small string-vector helpers instead of pulling in
 * src/utils.h: the rest of elfuse uses arena-style allocation patterns
 * tied to the guest VM lifetime, but a runspec lives across an
 * elfuse oci run invocation and ships back to the caller via
 * oci_runspec_t. Owning every char* with plain malloc/free makes that
 * lifetime contract auditable.
 */

#include "runspec.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "user-lookup.h"

/* Diagnostic scratch. Thread-local so concurrent oci_runspec_build calls
 * (one per --keep run dir, in a future multiplexed oci run) do not clobber
 * each other's err pointer. Buffer size is generous enough for the
 * longest dynamic message: the rejected User value plus the fixed
 * pointer text.
 */
static _Thread_local char runspec_err_buf[512];

static const char *set_err_static(const char **err, const char *msg)
{
    if (err)
        *err = msg;
    return msg;
}

static const char *set_err_fmt(const char **err, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static const char *set_err_fmt(const char **err, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(runspec_err_buf, sizeof(runspec_err_buf), fmt, ap);
    va_end(ap);
    if (err)
        *err = runspec_err_buf;
    return runspec_err_buf;
}

/* Min-grow string vector. Always NUL-terminates the backing array when
 * finalized so the result is environ/argv-shaped.
 */
typedef struct {
    char **items;
    size_t n;
    size_t cap;
} strvec_t;

static int strvec_reserve(strvec_t *v, size_t need)
{
    if (need <= v->cap)
        return 0;
    size_t newcap = v->cap ? v->cap : 8;
    while (newcap < need)
        newcap *= 2;
    char **np = realloc(v->items, newcap * sizeof(*np));
    if (!np)
        return -1;
    v->items = np;
    v->cap = newcap;
    return 0;
}

/* Append a heap string to the vector, taking ownership. On allocation
 * failure the input pointer stays unfreed (caller frees on cleanup).
 */
static int strvec_push_take(strvec_t *v, char *s_owned)
{
    if (strvec_reserve(v, v->n + 1) < 0)
        return -1;
    v->items[v->n++] = s_owned;
    return 0;
}

static int strvec_push_strdup(strvec_t *v, const char *s)
{
    char *d = strdup(s);
    if (!d)
        return -1;
    if (strvec_push_take(v, d) < 0) {
        free(d);
        return -1;
    }
    return 0;
}

/* Hand the items array to the caller as a NULL-terminated argv/envp.
 * Resets the vector so subsequent free is a no-op.
 */
static int strvec_finalize(strvec_t *v, char ***out)
{
    char **arr = realloc(v->items, (v->n + 1) * sizeof(*arr));
    if (!arr)
        return -1;
    arr[v->n] = NULL;
    *out = arr;
    v->items = NULL;
    v->n = 0;
    v->cap = 0;
    return 0;
}

static void strvec_free(strvec_t *v)
{
    if (!v || !v->items)
        return;
    for (size_t i = 0; i < v->n; i++)
        free(v->items[i]);
    free(v->items);
    v->items = NULL;
    v->n = 0;
    v->cap = 0;
}

/* Return length of the KEY portion of a "KEY=VAL" or bare "KEY" string. */
static size_t env_key_len(const char *kv)
{
    const char *eq = strchr(kv, '=');
    return eq ? (size_t) (eq - kv) : strlen(kv);
}

static ssize_t env_lookup_idx(const strvec_t *v,
                              const char *key,
                              size_t key_len)
{
    for (size_t i = 0; i < v->n; i++) {
        const char *e = v->items[i];
        size_t elen = env_key_len(e);
        if (elen == key_len && memcmp(e, key, key_len) == 0)
            return (ssize_t) i;
    }
    return -1;
}

/* Set-or-replace env entry by KEY (computed from kv_owned's pre-'=' prefix).
 * Takes ownership of kv_owned. On replace, the old entry is freed. On
 * allocation failure, kv_owned is freed and -1 is returned.
 */
static int env_set_take(strvec_t *v, char *kv_owned)
{
    size_t klen = env_key_len(kv_owned);
    ssize_t idx = env_lookup_idx(v, kv_owned, klen);
    if (idx >= 0) {
        free(v->items[idx]);
        v->items[idx] = kv_owned;
        return 0;
    }
    if (strvec_push_take(v, kv_owned) < 0) {
        free(kv_owned);
        return -1;
    }
    return 0;
}

static int env_set_strdup(strvec_t *v, const char *kv)
{
    char *d = strdup(kv);
    if (!d)
        return -1;
    return env_set_take(v, d);
}

/* Build "KEY=VAL" on the heap from the two halves and feed it through
 * env_set_take. Used for host-import and TERM auto-import paths where
 * the source is not already a single KEY=VAL string.
 */
static int env_set_pair(strvec_t *v, const char *key, const char *val)
{
    size_t klen = strlen(key);
    size_t vlen = strlen(val);
    char *kv = malloc(klen + 1 + vlen + 1);
    if (!kv)
        return -1;
    memcpy(kv, key, klen);
    kv[klen] = '=';
    memcpy(kv + klen + 1, val, vlen);
    kv[klen + 1 + vlen] = '\0';
    return env_set_take(v, kv);
}

static const char *host_env_lookup(const char *const *host_environ,
                                   const char *key,
                                   size_t key_len)
{
    if (!host_environ)
        return NULL;
    for (size_t i = 0; host_environ[i]; i++) {
        const char *e = host_environ[i];
        size_t elen = env_key_len(e);
        if (elen == key_len && memcmp(e, key, key_len) == 0 && e[elen] == '=') {
            return e + elen + 1;
        }
    }
    return NULL;
}

/* "set" in the override matrix means "non-NULL array containing at least
 * one entry". Explicit empty arrays ([]) count as "unset" so an image
 * Cmd=[] does not produce a zero-length argv when paired with Entrypoint.
 */
static bool runtime_arr_is_set(char *const *arr)
{
    return arr != NULL && arr[0] != NULL;
}

/* WorkingDir must be absolute and free of ".." path components. Empty
 * segments (consecutive slashes, trailing slash) are tolerated; the
 * caller-side path materialization will normalize them.
 */
static int validate_workdir(const char *s)
{
    if (!s || s[0] != '/')
        return -1;
    const char *p = s + 1;
    while (*p) {
        const char *next = strchr(p, '/');
        size_t seg_len = next ? (size_t) (next - p) : strlen(p);
        if (seg_len == 2 && p[0] == '.' && p[1] == '.')
            return -1;
        if (!next)
            break;
        p = next + 1;
    }
    return 0;
}

/* Resolve credentials from CLI --user override, then image User, then
 * host inheritance. Both sources route through oci_user_lookup so the
 * numeric / symbolic / mixed shapes are handled uniformly; the only
 * difference between the two paths is the diagnostic prefix so a caller
 * can tell whether the bad value came from their CLI flag or from the
 * pulled image. Symbolic resolution requires flags->rootfs_for_nss; a
 * NULL rootfs causes the helper to reject any symbolic token, preserving
 * the "pure data" contract for callers that have not unpacked a rootfs.
 */
static int resolve_user(const oci_image_runtime_t *cfg,
                        const oci_runspec_flags_t *flags,
                        oci_runspec_t *out,
                        const char **err)
{
    if (flags->user_override) {
        const char *lookup_err = NULL;
        if (oci_user_lookup(flags->rootfs_for_nss, flags->user_override,
                            &out->uid, &out->gid, &lookup_err) < 0) {
            int saved = errno;
            set_err_fmt(err, "--user '%s': %s", flags->user_override,
                        lookup_err ? lookup_err : "lookup failed");
            errno = saved ? saved : EINVAL;
            return -1;
        }
        out->has_creds = true;
        return 0;
    }
    if (cfg && cfg->user && *cfg->user) {
        const char *lookup_err = NULL;
        if (oci_user_lookup(flags->rootfs_for_nss, cfg->user, &out->uid,
                            &out->gid, &lookup_err) < 0) {
            int saved = errno;
            set_err_fmt(err, "User '%s': %s", cfg->user,
                        lookup_err ? lookup_err : "lookup failed");
            errno = saved ? saved : EINVAL;
            return -1;
        }
        out->has_creds = true;
        return 0;
    }
    out->has_creds = false;
    return 0;
}

static int resolve_workdir(const oci_image_runtime_t *cfg,
                           const oci_runspec_flags_t *flags,
                           oci_runspec_t *out,
                           const char **err)
{
    const char *chosen = NULL;
    if (flags->workdir_override) {
        chosen = flags->workdir_override;
    } else if (cfg && cfg->working_dir && *cfg->working_dir) {
        chosen = cfg->working_dir;
    } else {
        chosen = "/";
    }
    if (validate_workdir(chosen) < 0) {
        set_err_fmt(err, "WorkingDir must be absolute and not contain '..': %s",
                    chosen);
        errno = EINVAL;
        return -1;
    }
    out->cwd = strdup(chosen);
    if (!out->cwd) {
        set_err_static(err, "out of memory allocating cwd");
        errno = ENOMEM;
        return -1;
    }
    return 0;
}

/* Argv build follows the override matrix documented in runspec.h. The
 * matrix collapses to: --entrypoint clobbers everything (Cmd dropped,
 * image Entrypoint dropped, [override] ++ CLI args); otherwise image
 * Entrypoint and Cmd combine with the CLI tail using "CLI args drop Cmd
 * but keep Entrypoint" precedence.
 */
static int build_argv(const oci_image_runtime_t *cfg,
                      const oci_runspec_flags_t *flags,
                      oci_runspec_t *out,
                      const char **err)
{
    strvec_t argv = {0};
    int rc = -1;

    if (flags->entrypoint_override) {
        if (strvec_push_strdup(&argv, flags->entrypoint_override) < 0)
            goto oom;
        for (int i = 0; i < flags->positional_argc; i++) {
            if (strvec_push_strdup(&argv, flags->positional_argv[i]) < 0)
                goto oom;
        }
    } else if (cfg && runtime_arr_is_set(cfg->entrypoint)) {
        for (char *const *p = cfg->entrypoint; *p; p++) {
            if (strvec_push_strdup(&argv, *p) < 0)
                goto oom;
        }
        if (flags->positional_argc > 0) {
            for (int i = 0; i < flags->positional_argc; i++) {
                if (strvec_push_strdup(&argv, flags->positional_argv[i]) < 0)
                    goto oom;
            }
        } else if (cfg && runtime_arr_is_set(cfg->cmd)) {
            for (char *const *p = cfg->cmd; *p; p++) {
                if (strvec_push_strdup(&argv, *p) < 0)
                    goto oom;
            }
        }
    } else {
        if (flags->positional_argc > 0) {
            for (int i = 0; i < flags->positional_argc; i++) {
                if (strvec_push_strdup(&argv, flags->positional_argv[i]) < 0)
                    goto oom;
            }
        } else if (cfg && runtime_arr_is_set(cfg->cmd)) {
            for (char *const *p = cfg->cmd; *p; p++) {
                if (strvec_push_strdup(&argv, *p) < 0)
                    goto oom;
            }
        } else {
            set_err_static(err,
                           "image has no entrypoint or cmd; pass one on"
                           " the CLI");
            errno = EINVAL;
            goto done;
        }
    }

    if (strvec_finalize(&argv, &out->argv) < 0)
        goto oom;
    rc = 0;
    goto done;

oom:
    set_err_static(err, "out of memory building argv");
    errno = ENOMEM;
done:
    strvec_free(&argv);
    return rc;
}

#define LINUX_DEFAULT_PATH \
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

/* Apply the Env merge policy described in runspec.h. The build proceeds
 * in stages so the merge order matches the spec: image Env first, CLI
 * overrides second, then defaults (TERM, PATH, container). DYLD_ rejection
 * runs before any allocation per CLI override so the failing key is
 * reported with no half-applied state.
 */
static int build_envp(const oci_image_runtime_t *cfg,
                      const oci_runspec_flags_t *flags,
                      const char *const *host_environ,
                      oci_runspec_t *out,
                      const char **err)
{
    strvec_t env = {0};
    int rc = -1;

    if (cfg && cfg->env) {
        for (char *const *p = cfg->env; *p; p++) {
            if (env_set_strdup(&env, *p) < 0)
                goto oom;
        }
    }

    for (size_t i = 0; i < flags->nenv_overrides; i++) {
        const char *kv = flags->env_overrides[i];
        if (!kv)
            continue;
        if (strncmp(kv, "DYLD_", 5) == 0) {
            size_t klen = env_key_len(kv);
            char key_only[64];
            size_t copy =
                klen < sizeof(key_only) - 1 ? klen : sizeof(key_only) - 1;
            memcpy(key_only, kv, copy);
            key_only[copy] = '\0';
            set_err_fmt(err,
                        "--env: refusing to set DYLD_* (macOS-only ABI):"
                        " %s",
                        key_only);
            errno = EINVAL;
            goto done;
        }
        const char *eq = strchr(kv, '=');
        if (eq) {
            if (env_set_strdup(&env, kv) < 0)
                goto oom;
        } else {
            size_t klen = strlen(kv);
            const char *hv = host_env_lookup(host_environ, kv, klen);
            if (hv) {
                if (env_set_pair(&env, kv, hv) < 0)
                    goto oom;
            }
        }
    }

    if (env_lookup_idx(&env, "TERM", 4) < 0) {
        const char *host_term = host_env_lookup(host_environ, "TERM", 4);
        if (host_term) {
            if (env_set_pair(&env, "TERM", host_term) < 0)
                goto oom;
        }
    }
    if (env_lookup_idx(&env, "PATH", 4) < 0) {
        if (env_set_strdup(&env, LINUX_DEFAULT_PATH) < 0)
            goto oom;
    }
    if (env_set_strdup(&env, "container=elfuse") < 0)
        goto oom;

    if (strvec_finalize(&env, &out->envp) < 0)
        goto oom;
    rc = 0;
    goto done;

oom:
    set_err_static(err, "out of memory building envp");
    errno = ENOMEM;
done:
    strvec_free(&env);
    return rc;
}

int oci_runspec_build(const oci_image_runtime_t *cfg,
                      const oci_runspec_flags_t *flags,
                      const char *const *host_environ,
                      oci_runspec_t *out,
                      const char **err)
{
    if (err)
        *err = NULL;
    if (!flags || !out) {
        set_err_static(err, "oci_runspec_build: NULL flags or out");
        errno = EINVAL;
        return -1;
    }
    memset(out, 0, sizeof(*out));

    if (resolve_user(cfg, flags, out, err) < 0)
        goto fail;
    if (resolve_workdir(cfg, flags, out, err) < 0)
        goto fail;
    if (build_argv(cfg, flags, out, err) < 0)
        goto fail;
    if (build_envp(cfg, flags, host_environ, out, err) < 0)
        goto fail;
    return 0;

fail:
    oci_runspec_free(out);
    memset(out, 0, sizeof(*out));
    return -1;
}

void oci_runspec_free(oci_runspec_t *spec)
{
    if (!spec)
        return;
    free(spec->cwd);
    spec->cwd = NULL;
    if (spec->argv) {
        for (char **p = spec->argv; *p; p++)
            free(*p);
        free(spec->argv);
        spec->argv = NULL;
    }
    if (spec->envp) {
        for (char **p = spec->envp; *p; p++)
            free(*p);
        free(spec->envp);
        spec->envp = NULL;
    }
    spec->uid = 0;
    spec->gid = 0;
    spec->has_creds = false;
}
