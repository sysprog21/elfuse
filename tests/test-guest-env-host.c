/*
 * Native-host cross product for the guest environment merge
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Runs the guest_env_build cross product (base x override spelling x name
 * already present) against a reference merge plus per-cell structural
 * invariants, pinning `docker run -e`. The vector reaching a live guest is
 * tests/test-launch-flags.sh. Native macOS binary; no HVF entitlement needed.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug/log.h"
#include "host-test-util.h"
#include "utils.h"

#include "core/guest-env.h"

/* Dummy log implementation to avoid linking debug/log.o. Where the stub in
 * test-shebang-host.c prints, this one discards: refusal is the expected
 * outcome in hundreds of cells, and echoing each would bury the failures.
 */
void log_impl(int level, const char *file, int line, const char *fmt, ...)
{
    (void) level;
    (void) file;
    (void) line;
    (void) fmt;
}

/* ---- the oracle -------------------------------------------------------- */

enum { MODEL_MAX = 32, MODEL_ENTRY_MAX = 256 };

typedef struct {
    char name[MODEL_MAX][MODEL_ENTRY_MAX]; /* insertion-ordered names */
    char value[MODEL_MAX][MODEL_ENTRY_MAX];
    int n;
    bool refused; /* an override named nothing */
} model_t;

/* Split "KEY=VALUE" at the first '='. Returns false when @s is not one:
 * no '=' at all, or an empty name.
 */
static bool model_split(const char *s, char *name, char *value)
{
    const char *eq = strchr(s, '=');
    if (!eq || eq == s)
        return false;
    size_t klen = (size_t) (eq - s);
    if (klen >= MODEL_ENTRY_MAX || strlen(eq + 1) >= MODEL_ENTRY_MAX)
        return false;
    memcpy(name, s, klen);
    name[klen] = '\0';
    strcpy(value, eq + 1);
    return true;
}

static int model_index(const model_t *m, const char *name)
{
    for (int i = 0; i < m->n; i++) {
        if (!strcmp(m->name[i], name))
            return i;
    }
    return -1;
}

static void model_set(model_t *m, const char *name, const char *value)
{
    int i = model_index(m, name);
    if (i < 0) {
        if (m->n == MODEL_MAX) {
            /* Raise MODEL_MAX rather than let the oracle drop an entry: a
             * silent truncation here reads as the implementation inventing an
             * extra entry.
             */
            fprintf(stderr, "oracle overflow: raise MODEL_MAX past %d\n",
                    MODEL_MAX);
            exit(2);
        }
        i = m->n++;
        snprintf(m->name[i], MODEL_ENTRY_MAX, "%s", name);
    }
    snprintf(m->value[i], MODEL_ENTRY_MAX, "%s", value);
}

/* The launcher's value for @name, or NULL. First match wins, as getenv(3). */
static const char *model_host_value(char *const *host_env, const char *name)
{
    if (!host_env)
        return NULL;
    for (int i = 0; host_env[i]; i++) {
        char n[MODEL_ENTRY_MAX], v[MODEL_ENTRY_MAX];
        if (model_split(host_env[i], n, v) && !strcmp(n, name))
            return host_env[i] + strlen(name) + 1;
    }
    return NULL;
}

/* Reference merge. Builds the environment as an insertion-ordered name list,
 * so position comes from when a name was first seen rather than from which
 * slot the implementation happened to reuse.
 */
static void model_build(model_t *m,
                        char *const *host_env,
                        const char *const *overrides,
                        int n_overrides,
                        bool clear_env)
{
    memset(m, 0, sizeof(*m));

    if (!clear_env && host_env) {
        for (int i = 0; host_env[i]; i++) {
            char n[MODEL_ENTRY_MAX], v[MODEL_ENTRY_MAX];
            if (!model_split(host_env[i], n, v))
                continue; /* names nothing an override could replace */
            if (model_index(m, n) >= 0)
                continue; /* a repeat of a name already taken */
            model_set(m, n, v);
        }
    }

    for (int i = 0; i < n_overrides; i++) {
        const char *ov = overrides[i];
        const char *eq = strchr(ov, '=');
        if (eq == ov || (!eq && !*ov)) {
            m->refused = true;
            return;
        }
        if (eq) {
            char n[MODEL_ENTRY_MAX], v[MODEL_ENTRY_MAX];
            model_split(ov, n, v);
            model_set(m, n, v);
        } else {
            const char *hv = model_host_value(host_env, ov);
            if (hv)
                model_set(m, ov, hv);
        }
    }
}

/* ---- structural invariants --------------------------------------------- */

/* Hold @envp to what every returned vector owes regardless of the cell:
 * NULL-terminated at @n, every entry a well-formed "KEY=VALUE", no name twice.
 * The oracle cannot catch a vector that agrees with it entry-for-entry and is
 * still malformed past @n.
 */
static void check_structure(char **envp, int n, const char *cell)
{
    char detail[512];

    if (envp[n] != NULL) {
        snprintf(detail, sizeof(detail), "%s: envp[%d] is not NULL", cell, n);
        host_check(false, "structure", detail);
        return;
    }
    for (int i = 0; i < n; i++) {
        const char *eq = strchr(envp[i], '=');
        if (!eq || eq == envp[i]) {
            snprintf(detail, sizeof(detail), "%s: entry %d \"%s\" has no name",
                     cell, i, envp[i]);
            host_check(false, "structure", detail);
            return;
        }
        size_t klen = (size_t) (eq - envp[i]);
        for (int j = 0; j < i; j++) {
            if (!strncmp(envp[j], envp[i], klen) && envp[j][klen] == '=') {
                snprintf(detail, sizeof(detail),
                         "%s: entries %d and %d share a name (\"%s\", \"%s\")",
                         cell, j, i, envp[j], envp[i]);
                host_check(false, "structure", detail);
                return;
            }
        }
    }
    host_ok();
}

/* ---- the product ------------------------------------------------------- */

/* One base per way a host vector can be awkward. */
static char *base_plain[] = {(char *) "A=1", (char *) "B=2", (char *) "C=3",
                             NULL};
/* The one base separating a name the launcher set to "" from one it never
 * set: the alphabet's bare "A" imports "A=" here instead of being skipped.
 */
static char *base_emptyval[] = {(char *) "A=", (char *) "B=2", NULL};
static char *base_dup[] = {(char *) "A=first", (char *) "B=2",
                           (char *) "A=second", NULL};
static char *base_noeq[] = {(char *) "WEIRD", (char *) "A=1", NULL};
static char *base_emptyname[] = {(char *) "=orphan", (char *) "A=1", NULL};
static char *base_prefix[] = {(char *) "A=1", (char *) "AB=2", (char *) "ABC=3",
                              NULL};
static char *base_empty[] = {NULL};

static const struct {
    const char *name;
    char *const *v;
} bases[] = {
    {"null", NULL},
    {"empty", base_empty},
    {"plain", base_plain},
    {"empty-value", base_emptyval},
    {"dup-name", base_dup},
    {"no-eq", base_noeq},
    {"empty-name", base_emptyname},
    {"prefix", base_prefix},
};

/* One token per branch of the merge. The refused "=VAL" is in the product so
 * a rejection lands at every base and at either override position, not only
 * at the single base named_cells reaches.
 */
static const char *const alphabet[] = {
    "NEW=x",   "A=over",  "A=",          "A=a=b", "A",
    "MISSING", "AB=over", "WEIRD=fixed", "=VAL",
};
enum { ALPHA_N = (int) (sizeof(alphabet) / sizeof(alphabet[0])) };

/* Run one cell and hold it to the oracle and the invariants. */
static void run_cell(char *const *host_env,
                     const char *base_name,
                     const char *const *ovs,
                     int n_ovs,
                     bool clear_env)
{
    char cell[256];
    int off = snprintf(cell, sizeof(cell), "base=%s clear=%d ovs=[", base_name,
                       clear_env);
    for (int i = 0; i < n_ovs && off < (int) sizeof(cell); i++)
        off += snprintf(cell + off, sizeof(cell) - (size_t) off, "%s%s",
                        i ? "," : "", ovs[i]);
    snprintf(cell + off, sizeof(cell) - (size_t) off, "]");

    model_t want;
    model_build(&want, host_env, ovs, n_ovs, clear_env);

    char **envp = (char **) 0xdeadbeef; /* must be left untouched on refusal */
    int n = -1;
    int rc = guest_env_build(host_env, (char *const *) ovs, n_ovs, clear_env,
                             &envp, &n);

    char detail[1024];

    if (want.refused) {
        if (rc != -1 || envp != (char **) 0xdeadbeef || n != -1) {
            snprintf(detail, sizeof(detail),
                     "%s: want refusal leaving outputs untouched, got rc=%d",
                     cell, rc);
            host_check(false, "refuse", detail);
        } else {
            host_ok();
        }
        return;
    }

    if (rc != 0) {
        snprintf(detail, sizeof(detail), "%s: rc=%d, want 0", cell, rc);
        host_check(false, "build", detail);
        return;
    }

    /* NULL envp means "use the host environ", so every other cell owes a
     * real vector, --clear-env with no override included: build_linux_stack
     * counts envc itself.
     */
    if (n_ovs == 0 && !clear_env) {
        if (envp != NULL || n != 0) {
            snprintf(detail, sizeof(detail),
                     "%s: want NULL envp and n=0, got envp=%p n=%d", cell,
                     (void *) envp, n);
            host_check(false, "passthrough", detail);
        } else {
            host_ok();
        }
        return;
    }

    if (envp == NULL) {
        snprintf(detail, sizeof(detail), "%s: envp is NULL", cell);
        host_check(false, "build", detail);
        return;
    }

    check_structure(envp, n, cell);

    if (n != want.n) {
        snprintf(detail, sizeof(detail), "%s: %d entries, want %d", cell, n,
                 want.n);
        host_check(false, "count", detail);
    } else {
        bool same = true;
        for (int i = 0; i < n && same; i++) {
            char expect[MODEL_ENTRY_MAX * 2];
            snprintf(expect, sizeof(expect), "%s=%s", want.name[i],
                     want.value[i]);
            if (strcmp(envp[i], expect)) {
                snprintf(detail, sizeof(detail),
                         "%s: entry %d is \"%s\", want \"%s\"", cell, i,
                         envp[i], expect);
                host_check(false, "entry", detail);
                same = false;
            }
        }
        if (same)
            host_ok();
    }

    strv_free((const char **) envp, n);
}

/* ---- cells the product cannot spell ------------------------------------ */

static void named_cells(void)
{
    /* The empty variable names the alphabet cannot carry. "=VAL" is in it, so
     * the product already refuses that spelling at every base and at either
     * override position; "=" and "" reach the same refusal through the
     * bare-token arm of override_key_len, which no product cell reaches.
     */
    static const char *const bad[] = {"=", ""};
    for (int i = 0; i < (int) (sizeof(bad) / sizeof(bad[0])); i++) {
        char **envp = (char **) 0xdeadbeef;
        int n = -1;
        char detail[128];
        snprintf(detail, sizeof(detail), "override \"%s\" was accepted",
                 bad[i]);
        host_check(guest_env_build(base_plain, (char *const *) &bad[i], 1,
                                   false, &envp, &n) == -1 &&
                       envp == (char **) 0xdeadbeef && n == -1,
                   "empty variable name", detail);
    }

    /* strv_free's documented no-op. A crash here fails the run outright. */
    strv_free(NULL, 0);
    strv_free(NULL, 7);
    host_check(true, "strv_free(NULL)", "");
}

int main(void)
{
    int n_bases = (int) (sizeof(bases) / sizeof(bases[0]));

    for (int b = 0; b < n_bases; b++) {
        for (int c = 0; c < 2; c++) {
            bool clear = c != 0;
            run_cell(bases[b].v, bases[b].name, NULL, 0, clear);
            for (int i = 0; i < ALPHA_N; i++) {
                const char *one[] = {alphabet[i]};
                run_cell(bases[b].v, bases[b].name, one, 1, clear);
                for (int j = 0; j < ALPHA_N; j++) {
                    const char *two[] = {alphabet[i], alphabet[j]};
                    run_cell(bases[b].v, bases[b].name, two, 2, clear);
                }
            }
        }
    }

    named_cells();

    return host_summary("test-guest-env-host");
}
