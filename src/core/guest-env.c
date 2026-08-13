/*
 * Guest environment vector construction for the launch flags
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implementation of guest_env_build (contract and rationale in guest-env.h).
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug/log.h"
#include "utils.h"

#include "core/guest-env.h"

/* Name length of an override token: everything before the first '=', or the
 * whole token for a bare "KEY". Zero means an empty variable name.
 */
static size_t override_key_len(const char *ov)
{
    const char *eq = strchr(ov, '=');
    return eq ? (size_t) (eq - ov) : strlen(ov);
}

/* Name length of a "KEY=VALUE" entry, or 0 when @entry is not one: it carries
 * no '=', or its name is empty. Both make the entry unmatchable by an
 * override, which is why guest_env_build drops rather than forwards them.
 */
static size_t entry_key_len(const char *entry)
{
    const char *eq = strchr(entry, '=');
    return eq ? (size_t) (eq - entry) : 0;
}

/* Index in @envp[0 .. @n) of the entry naming @key (of length @klen), or -1.
 * The @klen'th byte decides the match: "PATH" must not find "PATH_EXTRA=...".
 * That read is in bounds because it happens only after strncmp matched all
 * @klen bytes, none of which is a NUL.
 */
static int env_find(char *const *envp, int n, const char *key, size_t klen)
{
    for (int i = 0; i < n; i++)
        if (!strncmp(envp[i], key, klen) && envp[i][klen] == '=')
            return i;
    return -1;
}

/* Value a bare "KEY" override imports, or NULL when @host_env[0 .. @n_host)
 * does not set it. getenv(3) over an explicit vector, so no global environ is
 * consulted. @n_host of 0 covers a NULL @host_env without dereferencing it.
 */
static const char *host_lookup(char *const *host_env,
                               int n_host,
                               const char *key,
                               size_t klen)
{
    int i = env_find(host_env, n_host, key, klen);
    return i < 0 ? NULL : host_env[i] + klen + 1;
}

int guest_env_build(char *const *host_env,
                    char *const *overrides,
                    int n_overrides,
                    bool clear_env,
                    char ***out_envp,
                    int *out_n)
{
    if (n_overrides == 0 && !clear_env) {
        *out_envp = NULL;
        *out_n = 0;
        return 0;
    }

    int n_host = 0;
    if (host_env)
        while (host_env[n_host])
            n_host++;

    /* Exact upper bound: the base contributes at most every host entry, each
     * override appends at most once (a replace and a skipped import append
     * none), plus the NULL terminator.
     */
    int cap = 1 + n_overrides + (clear_env ? 0 : n_host);
    char **envp = calloc((size_t) cap, sizeof(char *));
    if (!envp) {
        log_error("out of memory");
        return -1;
    }
    int n = 0;

    if (!clear_env) {
        for (int i = 0; i < n_host; i++) {
            size_t klen = entry_key_len(host_env[i]);
            /* env_find() rescans envp[0 .. n) per entry, so this is
             * quadratic over an environment of tens of entries. A hash would
             * cost more to build than the scan costs to run at that size.
             */
            if (klen == 0 || env_find(envp, n, host_env[i], klen) >= 0)
                continue;
            envp[n] = strdup(host_env[i]);
            if (!envp[n]) {
                log_error("out of memory");
                goto fail;
            }
            n++;
        }
    }

    for (int i = 0; i < n_overrides; i++) {
        const char *ov = overrides[i];
        size_t klen = override_key_len(ov);
        if (klen == 0) {
            log_error("invalid --env entry \"%s\": empty variable name", ov);
            goto fail;
        }

        char *entry;
        if (ov[klen] == '=') {
            entry = strdup(ov);
        } else {
            const char *val = host_lookup(host_env, n_host, ov, klen);
            if (!val)
                continue;
            size_t need = klen + 1 + strlen(val) + 1;
            entry = malloc(need);
            if (entry)
                snprintf(entry, need, "%s=%s", ov, val);
        }
        if (!entry) {
            log_error("out of memory");
            goto fail;
        }

        int slot = env_find(envp, n, ov, klen);
        if (slot >= 0) {
            free(envp[slot]);
            envp[slot] = entry;
        } else {
            envp[n++] = entry;
        }
    }

    envp[n] = NULL;
    *out_envp = envp;
    *out_n = n;
    return 0;

fail:
    strv_free((const char **) envp, n);
    return -1;
}
